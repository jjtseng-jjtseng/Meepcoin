// Synthetic-only pilot checks. No Docker, WSL, daemon, listener, miner, or browser is started.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { genesisGate, runPilot, trajectoryVerdict, validatePilotConfig } from './honest_launch_pilot.mjs';

const G = 1790562480;
const HASH = 'a'.repeat(64);
const cfgRaw = Object.freeze({
  repoCommit: 'b'.repeat(40), variantId: 'freshpilot', genesisTimestamp: G,
  genesisHash: HASH, artifactDir: '/home/tseng/meepcoin-freshpilot-20260928',
  buildManifestSha256: 'c'.repeat(64), image: 'meepcoin-build:freshpilot',
  expectedImageId: `sha256:${'d'.repeat(64)}`, wslDistro: 'Ubuntu', uid: 1000, gid: 1000,
  ports: { rpcA: 28481, p2pA: 28480, rpcB: 28491, p2pB: 28490 },
  threadsA: 2, threadsB: 2, budgetSeconds: 60,
  evidenceDir: 'C:\\Users\\tseng\\meepcoin-pilot-runs\\freshpilot-01',
});

test('closed configuration requires distinct private ports, bounded threads, and a one-use evidence path', () => {
  const parsed = validatePilotConfig(cfgRaw);
  assert.equal(parsed.a.profile, 'private-exclusive-peer-natural');
  assert.equal(parsed.b.fixedDifficulty, undefined);
  for (const bad of [
    { ...cfgRaw, threadsA: 9 },
    { ...cfgRaw, budgetSeconds: 86401 },
    { ...cfgRaw, ports: { ...cfgRaw.ports, rpcB: cfgRaw.ports.rpcA } },
    { ...cfgRaw, extra: 'unknown' },
    { ...cfgRaw, evidenceDir: 'C:\\Users\\tseng\\meepcoin\\results\\x' },
  ]) assert.throws(() => validatePilotConfig(bad));
});

test('both matching genesis headers are required within the prospective age bound', () => {
  const h = { height: 0, timestamp: G, hash: HASH };
  assert.equal(genesisGate([h, h], G, HASH, G + 1800), 1800);
  assert.throws(() => genesisGate([h, h], G, HASH, G + 1801));
  assert.throws(() => genesisGate([h, { ...h, hash: 'b'.repeat(64) }], G, HASH, G + 1));
  assert.throws(() => genesisGate([h, h], G, HASH, G - 1));
});

test('height 61 must appear in both canonical histories and agree to count as observed feasibility', () => {
  const a = [{ height: 61, hash: HASH }];
  assert.equal(trajectoryVerdict(a, a, 'BOTH_AT_HEIGHT_61').agreementAt61, true);
  assert.equal(trajectoryVerdict(a, [{ height: 60, hash: HASH }], 'FIXED_WALL_BUDGET').reachedCompletePostGenesisWindow, false);
  assert.equal(trajectoryVerdict(a, [{ height: 61, hash: 'b'.repeat(64) }], 'BOTH_AT_HEIGHT_61').agreementAt61, false);
  assert.equal(trajectoryVerdict(a, a, 'FIXED_WALL_BUDGET').observedBeforeBudget, false);
});

function fakeRun({ failB = false, stalled = false, failClose = false } = {}) {
  let now = (G + 10) * 1000;
  const root = mkdtempSync(join(tmpdir(), 'meep-honest-pilot-test-'));
  const evidenceDir = join(root, 'run');
  const close = [];
  let started = 0;
  const active = new Set();
  const calls = [];
  // The production CLI's path policy is tested above; the core receives an injected disposable
  // directory here so a test cannot write into the operator's real evidence parent.
  const cfg = { ...validatePilotConfig(cfgRaw), raw: { ...cfgRaw, evidenceDir } };
  const api = {
    info: async () => ({ height: started === 2 && !stalled ? 62 : 1,
      tip: started === 2 && !stalled ? `${61}`.padStart(64, '0') : HASH, synchronized: true,
      incoming: 1, outgoing: 1 }),
    header: async () => ({ height: 0, timestamp: G, hash: HASH }),
    headers: async (_port, topHeight) => Array.from({ length: topHeight + 1 }, (_, height) => ({ height,
      hash: height === 0 ? HASH : `${height}`.padStart(64, '0') })),
    post: async (port, path) => {
      calls.push([port, path]);
      if (path === '/start_mining') {
        if (failB && port === cfg.b.rpcPort) throw new Error('synthetic B refusal');
        started += 1;
        active.add(port);
      }
      if (path === '/stop_mining') active.delete(port);
      if (path === '/mining_status') return { active: active.has(port),
        threads_count: port === cfg.a.rpcPort ? cfg.raw.threadsA : cfg.raw.threadsB };
      return { status: 'OK' };
    },
  };
  const options = {
    preflight: async () => ({ synthetic: true }), clock: () => now,
    sleep: async (ms) => { now += ms; }, api,
    observeLink: async () => ({ ok: true, linked: true, bad: [] }),
    startDaemon: async ({ config }) => ({ runDir: config.runDir, config, imageId: config.expectedImageId,
      listeners: [], closed: false, close() {
        if (failClose && config.rpcPort === cfg.b.rpcPort) throw new Error('synthetic close failure');
        this.closed = true; close.push(config.rpcPort);
      } }),
  };
  return { cfg, options, root, evidenceDir, close, calls };
}

test('synthetic success consumes one directory, checks two daemons, stops both and records a non-attack verdict', async () => {
  const f = fakeRun();
  try {
    const result = await runPilot(f.cfg, f.options);
    assert.equal(result.verdict.agreementAt61, true);
    assert.equal(result.verdict.interpretation, 'FEASIBILITY_OBSERVED_NOT_ATTACK_RESULT');
    assert.deepEqual(f.close.sort(), [f.cfg.a.rpcPort, f.cfg.b.rpcPort].sort());
    assert.equal(f.calls.filter(([, path]) => path === '/start_mining').length, 2);
    assert.equal(f.calls.filter(([, path]) => path === '/stop_mining').length, 2);
    assert.equal(existsSync(join(f.evidenceDir, 'reservation.json')), true);
    const observationBytes = readFileSync(join(f.evidenceDir, 'observation.json'));
    const observation = JSON.parse(observationBytes);
    assert.equal(observation.final, false);
    assert.equal(observation.cleanupConfirmed, false);
    assert.equal(observation.report.verdict.agreementAt61, true);
    assert.equal(result.observationSha256, createHash('sha256').update(observationBytes).digest('hex'));
    assert.equal(existsSync(join(f.evidenceDir, 'result.json')), true);
    assert.match(readFileSync(join(f.evidenceDir, 'events.jsonl'), 'utf8'), /MINING_STARTED/);
    await assert.rejects(runPilot(f.cfg, f.options), /EEXIST/);
    assert.equal(f.calls.filter(([, path]) => path === '/start_mining').length, 2);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test('synthetic second-miner failure keeps reservation and closes both owned daemons', async () => {
  const f = fakeRun({ failB: true });
  try {
    await assert.rejects(runPilot(f.cfg, f.options), /synthetic B refusal/);
    assert.equal(existsSync(join(f.evidenceDir, 'reservation.json')), true);
    assert.equal(existsSync(join(f.evidenceDir, 'result.json')), false);
    assert.equal(existsSync(join(f.evidenceDir, 'observation.json')), false);
    assert.deepEqual(f.close.sort(), [f.cfg.a.rpcPort, f.cfg.b.rpcPort].sort());
    // The second start raised after entering transport; it may have taken effect.
    assert.equal(f.calls.filter(([, path]) => path === '/stop_mining').length, 2);
    assert.match(readFileSync(join(f.evidenceDir, 'events.jsonl'), 'utf8'), /FAILURE/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test('fixed budget ends a stalled honest pilot without turning it into a security negative', async () => {
  const f = fakeRun({ stalled: true });
  try {
    const result = await runPilot(f.cfg, f.options);
    assert.equal(result.stopReason, 'FIXED_WALL_BUDGET');
    assert.equal(result.verdict.observedBeforeBudget, false);
    assert.equal(result.verdict.interpretation, 'FEASIBILITY_INCOMPLETE_OR_DIVERGENT_NOT_ATTACK_RESULT');
    assert.deepEqual(f.close.sort(), [f.cfg.a.rpcPort, f.cfg.b.rpcPort].sort());
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test('interruption after two starts stops both miners and both owned daemons', async () => {
  const f = fakeRun({ stalled: true });
  const controller = new AbortController();
  const sleep = f.options.sleep;
  f.options.sleep = async (ms) => { await sleep(ms); controller.abort(); };
  f.options.signal = controller.signal;
  try {
    await assert.rejects(runPilot(f.cfg, f.options), /interrupted/);
    assert.equal(f.calls.filter(([, path]) => path === '/stop_mining').length, 2);
    assert.deepEqual(f.close.sort(), [f.cfg.a.rpcPort, f.cfg.b.rpcPort].sort());
    assert.equal(existsSync(join(f.evidenceDir, 'result.json')), false);
    assert.equal(existsSync(join(f.evidenceDir, 'observation.json')), false);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

test('an unconfirmed daemon close cannot leave a green result', async () => {
  const f = fakeRun({ failClose: true });
  try {
    await assert.rejects(runPilot(f.cfg, f.options), /not confirmed closed/);
    assert.equal(existsSync(join(f.evidenceDir, 'result.json')), false);
    const observation = JSON.parse(readFileSync(join(f.evidenceDir, 'observation.json'), 'utf8'));
    assert.equal(observation.final, false);
    assert.equal(observation.cleanupConfirmed, false);
    assert.equal(observation.report.verdict.agreementAt61, true);
    assert.match(readFileSync(join(f.evidenceDir, 'cleanup.json'), 'utf8'), /synthetic close failure/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});
