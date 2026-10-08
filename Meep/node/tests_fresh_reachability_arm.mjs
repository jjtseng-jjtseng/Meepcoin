import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { enableReceiverVerificationLog, validateReachabilityConfig,
  runReachabilityArm } from './fresh_reachability_arm.mjs';

const VERIFY_CATEGORIES = '*:WARNING,verify:ERROR,global:INFO';

const blockHash = (h) => h === 0 ? 'a'.repeat(64) : h.toString(16).padStart(64, '0');
const canonical = Array.from({ length: 91 }, (_, h) => ({
  height: h, hash: blockHash(h), prev_hash: blockHash(h - 1), timestamp: 1790000000 + h,
}));

function config(id = 'reach-test-one') {
  return { arm: 'CONTROL', artifactDir: '/home/tseng/meepcoin-testbuild', budgetSeconds: 3600,
    buildManifestSha256: 'a'.repeat(64),
    evidenceDir: `C:\\Users\\tseng\\meepcoin-reachability-runs\\${id}`,
    expectedImageId: `sha256:${'b'.repeat(64)}`, genesisHash: blockHash(0),
    genesisTimestamp: 1790000000, gid: 1000, image: 'meepcoin-build:test', pairId: 'pair-one',
    ports: { p2pA: 58581, p2pB: 58591, rpcA: 58580, rpcB: 58590 },
    repoCommit: 'd'.repeat(40), runId: id, uid: 1000, variantId: 'variant-one', wslDistro: 'Ubuntu' };
}

test('closed config rejects nonprivate, malformed, or over-budget launch requests', () => {
  assert.ok(validateReachabilityConfig(config()).a.runDir.startsWith('/home/tseng/meepcoin-private-run-'));
  for (const change of [
    { arm: 'HONEST' }, { budgetSeconds: 21601 }, { evidenceDir: 'C:\\Users\\tseng\\other' },
    { image: 'other:latest' }, { genesisHash: 'bad' }, { ports: { ...config().ports, rpcB: 58580 } },
  ]) assert.throws(() => validateReachabilityConfig({ ...config(), ...change }));
});

test('receiver verification logging requires an exact daemon acknowledgement', async () => {
  const requests = [];
  const send = async (port, path, body) => {
    requests.push({ port, path, body });
    return { status: 'OK', categories: VERIFY_CATEGORIES };
  };
  assert.deepEqual(await enableReceiverVerificationLog(58580, send),
    { port: 58580, categories: VERIFY_CATEGORIES });
  assert.deepEqual(requests, [{ port: 58580, path: '/set_log_categories',
    body: { categories: VERIFY_CATEGORIES } }]);
  for (const response of [null, {}, { status: 'OK' },
    { status: 'ERROR', categories: VERIFY_CATEGORIES },
    { status: 'OK', categories: '*:WARNING,verify:FATAL,global:INFO' }]) {
    await assert.rejects(() => enableReceiverVerificationLog(58580, async () => response),
      /did not confirm receiver verification logging/);
  }
});

test('mocked complete arm reserves once, starts honest workers first, seals observation after cleanup', async (t) => {
  const base = mkdtempSync(join(tmpdir(), 'meep-reach-test-'));
  const evidenceDir = join(base, 'one-use-run');
  t.after(() => {
    assert.ok(resolve(base).startsWith(resolve(tmpdir()) + '\\')
      || resolve(base).startsWith(resolve(tmpdir()) + '/'));
    rmSync(base, { recursive: true, force: false });
  });
  let now = 1790000010000;
  let thirdStarted = false;
  const started = [];
  const loggingPorts = [];
  const routes = [];
  const resources = [];
  const a = { rpcPort: 58580, runDir: '/home/tseng/meepcoin-private-run-aaaaaaaaa', imageId: 'sha256:' + 'b'.repeat(64),
    listeners: [], }; const b = { ...a, rpcPort: 58590, runDir: '/home/tseng/meepcoin-private-run-bbbbbbbbb' };
  const raw = { ...config(), evidenceDir };
  const fakeInfo = () => thirdStarted
    ? { height: 91, tip: blockHash(90), synchronized: true }
    : { height: 1, tip: blockHash(0), synchronized: true };
  const result = await runReachabilityArm({ raw, a, b }, {
    clock: () => now, sleep: async (ms) => { now += ms; },
    preflight: async () => ({ checked: true }),
    machinePreflight: async () => ({ privatePortsFree: Object.values(raw.ports) }),
    startDaemon: async ({ config: dc, limits }) => {
      assert.ok(limits.probeTimeoutMs > 4 * 60_000);
      assert.ok(limits.stopGraceSeconds >= 4 * 60);
      const resource = { runDir: dc.runDir, imageId: a.imageId, listeners: [], closed: false,
        async close() { this.closed = true; } };
      resources.push(resource); return resource;
    },
    observeLink: async () => ({ ok: true, linked: true, bad: [] }),
    api: {
      info: async () => fakeInfo(),
      header: async (_port, h) => canonical[h],
      headers: async (_port, h) => canonical.slice(0, h + 1),
      enableReceiverVerificationLog: async (port) => {
        assert.equal(started.length, 0, 'logging must precede miners');
        loggingPorts.push(port);
        return { port, categories: VERIFY_CATEGORIES };
      },
    },
    makeWorker: ({ role, port, peerPort }) => {
      started.push(role);
      routes.push({ role, port, peerPort });
      if (role === 'third') thirdStarted = true;
      let exited = false;
      return { role, started: true, firstHash: true, get exited() { return exited; }, exitCode: 0,
        get result() { return exited ? { role, actualHashes: 1 } : null; },
        failure: null, stop() { exited = true; }, async terminate() { exited = true; return 0; } };
    },
    copyLog: async ({ destination }) => {
      writeFileSync(destination, 'mock log', { flag: 'wx' });
      return { bytes: 8, sha256: createHash('sha256').update('mock log').digest('hex') };
    },
  });
  assert.deepEqual(started, ['h1', 'h2', 'third']);
  assert.deepEqual(loggingPorts, [58580, 58590]);
  assert.deepEqual(routes, [
    { role: 'h1', port: 58580, peerPort: 58590 },
    { role: 'h2', port: 58590, peerPort: 58580 },
    { role: 'third', port: 58580, peerPort: 58590 },
  ]);
  assert.equal(resources.length, 2);
  assert.equal(result.cleanupConfirmed, true);
  assert.equal(result.stopReason, 'BOTH_AT_HEIGHT_CAP');
  assert.equal(result.interpretation, 'DESCRIPTIVE_ONLY_PENDING_CROSS_NODE_REJECTION_AUDIT');
  assert.equal(existsSync(join(evidenceDir, 'result.json')), true);
  assert.equal(JSON.parse(readFileSync(join(evidenceDir, 'reservation.json'), 'utf8')).state, 'CONSUMED_ONE_USE');
  await assert.rejects(() => runReachabilityArm({ raw, a, b }, {
    clock: () => now, preflight: async () => ({}),
    machinePreflight: async () => ({}),
  }), /genesis is already stale|EEXIST/);
});

test('wrong block zero consumes reservation, closes both daemons, and cannot publish a final result', async (t) => {
  const base = mkdtempSync(join(tmpdir(), 'meep-reach-fail-'));
  const evidenceDir = join(base, 'one-use-run');
  t.after(() => {
    assert.ok(resolve(base).startsWith(resolve(tmpdir()) + '\\')
      || resolve(base).startsWith(resolve(tmpdir()) + '/'));
    rmSync(base, { recursive: true, force: false });
  });
  const raw = { ...config('reach-test-fail'), evidenceDir };
  const a = { rpcPort: 58580, runDir: '/home/tseng/meepcoin-private-run-aaaaaaaaa' };
  const b = { rpcPort: 58590, runDir: '/home/tseng/meepcoin-private-run-bbbbbbbbb' };
  const closed = [];
  await assert.rejects(() => runReachabilityArm({ raw, a, b }, {
    clock: () => 1790000010000, preflight: async () => ({}),
    machinePreflight: async () => ({}),
    startDaemon: async ({ config: dc }) => ({ runDir: dc.runDir, imageId: raw.expectedImageId,
      listeners: [], closed: false, async close() { this.closed = true; closed.push(this.runDir); } }),
    api: { info: async () => ({ height: 1 }),
      header: async () => ({ height: 0, hash: 'f'.repeat(64), timestamp: raw.genesisTimestamp }),
      enableReceiverVerificationLog: async (port) => ({ port, categories: VERIFY_CATEGORIES }),
    },
    copyLog: async ({ destination }) => {
      writeFileSync(destination, 'mock log', { flag: 'wx' });
      return { bytes: 8, sha256: createHash('sha256').update('mock log').digest('hex') };
    },
  }), /genesis mismatch/);
  assert.equal(closed.length, 2);
  assert.equal(existsSync(join(evidenceDir, 'reservation.json')), true);
  assert.equal(existsSync(join(evidenceDir, 'cleanup.json')), true);
  assert.equal(existsSync(join(evidenceDir, 'result.json')), false);
});

test('unconfirmed receiver logging consumes the reservation and stops before mining', async (t) => {
  const base = mkdtempSync(join(tmpdir(), 'meep-reach-log-refusal-'));
  const evidenceDir = join(base, 'one-use-run');
  t.after(() => {
    assert.ok(resolve(base).startsWith(resolve(tmpdir()) + '\\')
      || resolve(base).startsWith(resolve(tmpdir()) + '/'));
    rmSync(base, { recursive: true, force: false });
  });
  const raw = { ...config('reach-test-log-refusal'), evidenceDir };
  const a = { rpcPort: 58580, runDir: '/home/tseng/meepcoin-private-run-aaaaaaaaa' };
  const b = { rpcPort: 58590, runDir: '/home/tseng/meepcoin-private-run-bbbbbbbbb' };
  const closed = [];
  let workers = 0;
  await assert.rejects(() => runReachabilityArm({ raw, a, b }, {
    clock: () => 1790000010000, preflight: async () => ({}),
    machinePreflight: async () => ({}),
    startDaemon: async ({ config: dc }) => ({ runDir: dc.runDir, imageId: raw.expectedImageId,
      listeners: [], closed: false, async close() { this.closed = true; closed.push(this.runDir); } }),
    api: { enableReceiverVerificationLog: async (port) => ({ port,
      categories: port === 58580 ? VERIFY_CATEGORIES : '*:WARNING,verify:FATAL,global:INFO' }) },
    makeWorker: () => { workers++; throw new Error('worker must not start'); },
    copyLog: async ({ destination }) => {
      writeFileSync(destination, 'mock log', { flag: 'wx' });
      return { bytes: 8, sha256: createHash('sha256').update('mock log').digest('hex') };
    },
  }), /receiver verification logs were not confirmed/);
  assert.equal(workers, 0);
  assert.equal(closed.length, 2);
  assert.equal(existsSync(join(evidenceDir, 'reservation.json')), true);
  assert.equal(existsSync(join(evidenceDir, 'result.json')), false);
});

test('machine preflight refusal does not consume an attempt or launch a daemon', async (t) => {
  const base = mkdtempSync(join(tmpdir(), 'meep-reach-preflight-'));
  t.after(() => {
    assert.ok(resolve(base).startsWith(resolve(tmpdir()) + '\\')
      || resolve(base).startsWith(resolve(tmpdir()) + '/'));
    rmSync(base, { recursive: true, force: false });
  });
  const evidenceDir = join(base, 'not-created');
  let launched = false;
  await assert.rejects(() => runReachabilityArm({ raw: { ...config('reach-test-preflight'),
    evidenceDir }, a: {}, b: {} }, {
    clock: () => 1790000010000, preflight: async () => ({}),
    machinePreflight: async () => { throw new Error('competing miner process present'); },
    startDaemon: async () => { launched = true; throw new Error('should not launch'); },
  }), /competing miner process present/);
  assert.equal(launched, false);
  assert.equal(existsSync(evidenceDir), false);
});
