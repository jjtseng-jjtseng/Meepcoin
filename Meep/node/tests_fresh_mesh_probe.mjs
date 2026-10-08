import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateMeshProbeConfig, runMeshProbe, observeMesh } from './fresh_mesh_probe.mjs';
import { DAEMON_PROFILES } from '../pool/dev/local_daemon.mjs';

const H = (letter) => letter.repeat(64);
const RAW = Object.freeze({
  runId: 'meshprobe-20260929-offline',
  evidenceDir: 'C:\\Users\\tseng\\meepcoin-mesh-probe-runs\\meshprobe-20260929-offline',
  repoCommit: 'a'.repeat(40), artifactDir: '/home/tseng/meepcoin-mesh-probe-build',
  buildManifestSha256: H('b'), genesisHash: H('c'), genesisTimestamp: 1790662770,
  variantId: 'probe-variant', image: 'meepcoin-build:probe',
  expectedImageId: `sha256:${H('d')}`, wslDistro: 'Ubuntu', uid: 1000, gid: 1000,
  ports: { rpcA: 59180, p2pA: 59181, rpcB: 59190, p2pB: 59191,
    rpcC: 59200, p2pC: 59201 },
});

test('closed one-use config yields three different owned directories and only two named peers each', () => {
  const cfg = validateMeshProbeConfig(RAW);
  assert.equal(cfg.a.profile, DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL);
  assert.deepEqual(cfg.a.exclusivePeerP2pPorts, [59191, 59201]);
  assert.deepEqual(cfg.b.exclusivePeerP2pPorts, [59181, 59201]);
  assert.deepEqual(cfg.c.exclusivePeerP2pPorts, [59181, 59191]);
  assert.equal(new Set([cfg.a.runDir, cfg.b.runDir, cfg.c.runDir]).size, 3);
  for (const changed of [
    { runId: 'wrong' },
    { evidenceDir: 'C:\\Users\\tseng\\meepcoin-mesh-probe-runs\\different' },
    { ports: { ...RAW.ports, rpcC: RAW.ports.rpcA } },
    { ports: { ...RAW.ports, unexpected: 59202 } },
    { expectedImageId: 'bad' },
  ]) assert.throws(() => validateMeshProbeConfig({ ...RAW, ...changed }));
});

test('one shared socket-table snapshot is attributed to three process PIDs', async () => {
  const row = (pid, local, peer) => `ESTAB 0 0 127.0.0.1:${local} 127.0.0.1:${peer} users:(("meepcoind",pid=${pid},fd=7))`;
  const table = [row(1, 41000, 59191), row(2, 59191, 41000),
    row(1, 41001, 59201), row(3, 59201, 41001),
    row(2, 42000, 59201), row(3, 59201, 42000)].join('\n');
  let reads = 0;
  const resources = [1, 2, 3].map((linuxPid, i) => ({ linuxPid,
    config: { rpcPort: [59180, 59190, 59200][i], p2pPort: [59181, 59191, 59201][i] },
    observeSocketTable: async () => { reads += 1; return table; },
  }));
  const verdict = await observeMesh(resources);
  assert.equal(reads, 1);
  assert.deepEqual(verdict, { ok: true, linked: true, links: ['A-B', 'A-C', 'B-C'], bad: [] });
  resources[0].observeSocketTable = async () => null;
  assert.equal((await observeMesh(resources)).linked, false);
});

function disposable() {
  const root = mkdtempSync(join(tmpdir(), 'meep-mesh-probe-test-'));
  const exact = resolve(root);
  const parent = resolve(tmpdir());
  assert.equal(dirname(exact), parent);
  assert.match(basename(exact), /^meep-mesh-probe-test-[A-Za-z0-9]+$/);
  return { evidenceDir: join(root, 'one-use'), close: () => rmSync(exact, { recursive: true }) };
}

function harness(evidenceDir, { loseLink = false } = {}) {
  const checked = validateMeshProbeConfig(RAW);
  const cfg = { ...checked, raw: { ...checked.raw, evidenceDir } };
  const resources = [];
  let t = 1_000_000;
  let samples = 0;
  const startDaemon = async ({ config }) => {
    const r = { config, runDir: config.runDir, containerName: `test-${resources.length}`,
      imageId: RAW.expectedImageId, linuxPid: resources.length + 1, listeners: [], closed: false,
      shutdownOutcome: { gracefulProtocolShutdown: true },
      async close() { this.closed = true; } };
    resources.push(r);
    return r;
  };
  const api = { info: async () => ({ height: 1, tip: RAW.genesisHash, synchronized: true }),
    header: async () => ({ height: 0, hash: RAW.genesisHash }),
    enableReceiverVerificationLog: async (port) => ({ port,
      categories: '*:WARNING,verify:ERROR,global:INFO' }) };
  const deps = { startDaemon, api, identityPreflight: async () => ({ verified: true }),
    machinePreflight: async () => ({ privatePortsFree: Object.values(RAW.ports) }),
    observe: async () => { samples += 1; return loseLink && samples >= 2
      ? { ok: true, linked: false, links: ['A-B'], bad: [] }
      : { ok: true, linked: true, links: ['A-B', 'A-C', 'B-C'], bad: [] }; },
    clock: () => t, sleep: async (ms) => { t += ms; },
    preserveLog: async ({ destination }) => {
      writeFileSync(destination, 'owned daemon log\n', { flag: 'wx' });
      return { bytes: 17, sha256: 'e'.repeat(64) };
    },
  };
  return { cfg, deps, resources };
}

test('a complete bounded no-mining observation seals evidence only after all three close', async () => {
  const d = disposable();
  try {
    const h = harness(d.evidenceDir);
    const result = await runMeshProbe(h.cfg, h.deps);
    assert.equal(result.linked, true);
    assert.equal(result.cleanupConfirmed, true);
    assert.equal(result.logsPreserved, true);
    assert.equal(h.resources.length, 3);
    assert.equal(h.resources.every((r) => r.closed), true);
    assert.match(readFileSync(join(d.evidenceDir, 'events.jsonl'), 'utf8'), /MESH_SAMPLE/);
    assert.equal(JSON.parse(readFileSync(join(d.evidenceDir, 'reservation.json'), 'utf8')).state,
      'CONSUMED_ONE_USE');
    await assert.rejects(runMeshProbe(h.cfg, h.deps), /EEXIST/);
  } finally { d.close(); }
});

test('a lost link records failure and still closes all three without inventing success', async () => {
  const d = disposable();
  try {
    const h = harness(d.evidenceDir, { loseLink: true });
    const result = await runMeshProbe(h.cfg, h.deps);
    assert.equal(result.linked, false);
    assert.equal(result.cleanupConfirmed, true);
    assert.match(result.failure.message, /link was lost/);
    assert.equal(h.resources.every((r) => r.closed), true);
  } finally { d.close(); }
});

test('a second-daemon startup failure adopts its resource and closes both owned daemons', async () => {
  const d = disposable();
  try {
    const h = harness(d.evidenceDir);
    const start = h.deps.startDaemon;
    h.deps.startDaemon = async (args) => {
      const resource = await start(args);
      if (h.resources.length === 2) throw Object.assign(new Error('synthetic startup failure'), { resource });
      return resource;
    };
    const result = await runMeshProbe(h.cfg, h.deps);
    assert.equal(result.linked, false);
    assert.equal(result.cleanupConfirmed, false);
    assert.equal(h.resources.length, 2);
    assert.equal(h.resources.every((r) => r.closed), true);
    assert.match(result.failure.message, /startup failure/);
  } finally { d.close(); }
});

test('the daemon-only probe has no miner, wallet, template, or block-submission path', () => {
  const source = readFileSync(fileURLToPath(new URL('./fresh_mesh_probe.mjs', import.meta.url)), 'utf8')
    .replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
  for (const forbidden of ['new Worker(', 'runFreshMiner(', 'start_mining', 'submit_block',
    'transfer(', 'wallet-rpc', 'get_block_template']) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
});
