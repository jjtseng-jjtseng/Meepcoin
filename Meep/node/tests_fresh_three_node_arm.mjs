import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { validateThreeNodeArmConfig, validateThreeNodeRunConfig, validateThreeNodeAssignedSlot,
  validateThreeNodeSeriesFreeze, threeNodeSeriesFor,
  observeThreeNodeBoundary, runThreeNodeArm, claimThreeNodeSlot, checkWslPortInventory,
  threeNodeEnvironmentPreflight } from './fresh_three_node_arm.mjs';
import { verifyThreeNodeEvidence } from './verify_three_node_evidence.mjs';
import { DAEMON_PROFILES } from '../pool/dev/local_daemon.mjs';

const H = (h) => h.toString(16).padStart(64, '0');
const GENESIS = H(0);
const VERIFY = '*:WARNING,verify:ERROR,global:INFO';
const CHAIN = Array.from({ length: 91 }, (_, height) => ({
  height, hash: H(height), prev_hash: H(height - 1), timestamp: 1790000000 + height,
}));
const RAW = Object.freeze({ arm: 'ATTACK', artifactDir: '/home/tseng/meepcoin-testbuild',
  budgetSeconds: 21600, buildManifestSha256: 'a'.repeat(64),
  evidenceDir: 'C:\\Users\\tseng\\meepcoin-three-node-runs\\threenode-test-one',
  expectedImageId: `sha256:${'b'.repeat(64)}`, genesisHash: GENESIS,
  genesisTimestamp: 1790000000, gid: 1000, image: 'meepcoin-build:test',
  pairId: 'test-pair-one', ports: { p2pA: 59481, p2pB: 59491, p2pC: 59501,
    rpcA: 59480, rpcB: 59490, rpcC: 59500 },
  repoCommit: 'd'.repeat(40), runId: 'threenode-test-one', uid: 1000,
  variantId: 'variant-one', wslDistro: 'Ubuntu', seriesFreezeSha256: 'e'.repeat(64) });

test('both campaign assignment tables are deeply immutable across imported callers', () => {
  for (const prefix of ['fresh3', 'fresh3v2']) {
    const raw = { runId: `${prefix}-20260930t120000z-c1` };
    const series = threeNodeSeriesFor(raw);
    const original = JSON.stringify(series.slots);
    assert.equal(Object.isFrozen(series.slots), true);
    for (const assigned of Object.values(series.slots)) {
      assert.equal(Object.isFrozen(assigned), true);
      assert.equal(Object.isFrozen(assigned.ports), true);
      assert.throws(() => { assigned.ports[0] = 12345; }, TypeError);
      assert.throws(() => { assigned.pairId = 'changed'; }, TypeError);
      assert.throws(() => { assigned.arm = 'changed'; }, TypeError);
    }
    assert.throws(() => { series.slots.C1 = {}; }, TypeError);
    assert.equal(JSON.stringify(threeNodeSeriesFor(raw).slots), original);
    const first = prefix === 'fresh3v2' ? 60480 : 59480;
    assert.equal(validateThreeNodeAssignedSlot({ ...raw, arm: 'CONTROL',
      pairId: `${prefix}-pair1`, ports: { rpcA: first, p2pA: first + 1,
        rpcB: first + 10, p2pB: first + 11, rpcC: first + 20, p2pC: first + 21 } }, 'C1'), true);
  }
});

test('v2 campaign has disjoint fixed root, slots, document identities and freeze', (t) => {
  const raw = { ...RAW, arm: 'CONTROL', pairId: 'fresh3v2-pair1',
    runId: 'fresh3v2-20260930t120000z-c1',
    evidenceDir: 'C:\\Users\\tseng\\meepcoin-three-node-v2-runs\\fresh3v2-20260930t120000z-c1',
    ports: { rpcA: 60480, p2pA: 60481, rpcB: 60490, p2pB: 60491, rpcC: 60500, p2pC: 60501 } };
  assert.equal(validateThreeNodeRunConfig(validateThreeNodeArmConfig(raw)), true);
  assert.equal(validateThreeNodeAssignedSlot(raw, 'C1'), true);
  for (const [slot, arm, pairId, first] of [
    ['A1', 'ATTACK', 'fresh3v2-pair1', 60580],
    ['A2', 'ATTACK', 'fresh3v2-pair2', 60680],
    ['C2', 'CONTROL', 'fresh3v2-pair2', 60780],
  ]) {
    const assigned = { ...raw, arm, pairId, runId: `fresh3v2-20260930t120000z-${slot.toLowerCase()}`,
      ports: { rpcA: first, p2pA: first + 1, rpcB: first + 10, p2pB: first + 11,
        rpcC: first + 20, p2pC: first + 21 } };
    assigned.evidenceDir = `${threeNodeSeriesFor(assigned).root}\\${assigned.runId}`;
    assert.equal(validateThreeNodeRunConfig(validateThreeNodeArmConfig(assigned)), true);
    assert.equal(validateThreeNodeAssignedSlot(assigned, slot), true);
    assert.throws(() => claimThreeNodeSlot(assigned, disposable(t)), /ENOENT/,
      'later v2 slots cannot launch without prior independent audits');
  }
  const series = threeNodeSeriesFor(raw);
  assert.equal(series.protocol, 'FRESH_LAUNCH_THREE_NODE_V2_PROTOCOL.md');
  assert.notEqual(series.root, threeNodeSeriesFor(RAW).root);
  assert.throws(() => validateThreeNodeArmConfig({ ...raw,
    evidenceDir: `${threeNodeSeriesFor(RAW).root}\\${raw.runId}` }), /evidence directory/);
  assert.throws(() => validateThreeNodeAssignedSlot({ ...raw, pairId: 'fresh3-pair1' }, 'C1'), /arm or pair/);
  assert.throws(() => validateThreeNodeAssignedSlot({ ...raw, ports: RAW.ports }, 'C1'), /six ports/);
  assert.throws(() => validateThreeNodeAssignedSlot({ ...raw,
    runId: 'fresh3v2-20260930t120000z-c1-retry' }, 'C1'), /run ID/);
  const protocol = Buffer.from('prospective v2 protocol');
  const schedule = Buffer.from('prospective v2 schedule');
  const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
  const freeze = { schema: series.freezeSchema, status: 'AUTHORIZED', repoCommit: raw.repoCommit,
    builderImageId: raw.expectedImageId, protocolSha256: digest(protocol), scheduleSha256: digest(schedule),
    seriesId: 'fresh3v2-20260930', evidenceRoot: series.root, windowRecoveryLimit: 8 };
  const check = (f, r = raw) => {
    const bytes = Buffer.from(JSON.stringify(f));
    return validateThreeNodeSeriesFreeze({ ...r, seriesFreezeSha256: digest(bytes) }, bytes, protocol, schedule);
  };
  assert.equal(check(freeze), true);
  for (const change of [{ schema: 'meepcoin-three-node-series-freeze/1' },
    { seriesId: 'fresh3-20260929' }, { evidenceRoot: threeNodeSeriesFor(RAW).root },
    { windowRecoveryLimit: 9 }, { windowRecoveryLimit: null }])
    assert.throws(() => check({ ...freeze, ...change }));
  assert.throws(() => check(freeze, RAW), /authorized freeze/);
  const root = disposable(t);
  claimThreeNodeSlot(raw, root);
  assert.throws(() => claimThreeNodeSlot(raw, root), /EEXIST/);
});

function disposable(t) {
  const root = mkdtempSync(join(tmpdir(), 'meep-three-node-test-'));
  const exact = resolve(root);
  assert.equal(dirname(exact), resolve(tmpdir()));
  t.after(() => rmSync(exact, { recursive: true }));
  return join(exact, 'one-use');
}

function harness(evidenceDir, { loseMesh = false, loseMeshBeforeThird = false,
  badLogging = false, thirdFails = false } = {}) {
  const checked = validateThreeNodeArmConfig(RAW);
  const cfg = { ...checked, raw: { ...checked.raw, evidenceDir } };
  const resources = [];
  const workers = [];
  const routes = [];
  const logPorts = [];
  let now = 1790000010000;
  let thirdStarted = false;
  let observations = 0;
  const state = () => thirdStarted
    ? { height: 91, tip: H(90), synchronized: true }
    : { height: 1, tip: GENESIS, synchronized: true };
  const deps = {
    validateConfig: () => true, // disposable evidence path replaces the production one-use path
    claimSlot: () => true, // disposable evidence path has no production slot ledger
    preflight: async () => ({ pinned: true }),
    machinePreflight: async () => ({ privatePortsFree: Object.values(RAW.ports) }),
    clock: () => now,
    sleep: async (ms) => { now += ms; },
    startDaemon: async ({ config, limits }) => {
      assert.ok(limits.stopGraceSeconds >= 360);
      const r = { config, runDir: config.runDir, containerName: `test-${resources.length}`,
        imageId: RAW.expectedImageId, linuxPid: resources.length + 1, listeners: [],
        closed: false, shutdownOutcome: { gracefulProtocolShutdown: true },
        async close() { this.closed = true; } };
      resources.push(r);
      return r;
    },
    observe: async () => {
      observations += 1;
      return (loseMesh && thirdStarted && observations >= 3)
        || (loseMeshBeforeThird && !thirdStarted && observations >= 2)
        ? { ok: true, linked: false, links: ['A-B'], bad: [] }
        : { ok: true, linked: true, links: ['A-B', 'A-C', 'B-C'], bad: [] };
    },
    api: {
      info: async () => state(),
      header: async (_port, height) => CHAIN[height],
      headers: async (_port, height) => CHAIN.slice(0, height + 1),
      enableReceiverVerificationLog: async (port) => {
        assert.equal(workers.length, 0, 'all logging acknowledgements precede mining');
        logPorts.push(port);
        return { port, categories: badLogging && port === RAW.ports.rpcC ? 'wrong' : VERIFY };
      },
    },
    makeWorker: ({ role, mode, port, peerPort }) => {
      routes.push({ role, mode, port, peerPort });
      if (role === 'third') thirdStarted = true;
      let exited = false;
      const worker = { role, started: true, firstHash: true,
        get failure() { return thirdFails && role === 'third' ? { code: 'synthetic' } : null; },
        get exited() { return exited; }, exitCode: 0,
        get result() { return exited ? { role, actualHashes: 1 } : null; },
        stop() { exited = true; }, async terminate() { exited = true; return 0; } };
      workers.push(worker);
      return worker;
    },
    preserveLog: async ({ destination }) => {
      writeFileSync(destination, 'mock daemon log\n', { flag: 'wx' });
      return { bytes: 16, sha256: createHash('sha256').update('mock daemon log\n').digest('hex') };
    },
  };
  return { cfg, deps, resources, workers, routes, logPorts };
}

test('closed config creates three distinct natural-mesh daemons and refuses malformed scope', () => {
  const cfg = validateThreeNodeArmConfig(RAW);
  assert.equal(validateThreeNodeRunConfig(cfg), true);
  assert.equal(cfg.c.profile, DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL);
  assert.deepEqual(cfg.c.exclusivePeerP2pPorts, [59481, 59491]);
  assert.equal(new Set([cfg.a.runDir, cfg.b.runDir, cfg.c.runDir]).size, 3);
  for (const change of [
    { arm: 'HONEST' }, { evidenceDir: 'C:\\Users\\tseng\\other' },
    { budgetSeconds: 3600 }, { budgetSeconds: 21601 },
    { ports: { ...RAW.ports, rpcC: RAW.ports.rpcA } },
    { image: 'remote:latest' }, { expectedImageId: 'bad' },
  ]) assert.throws(() => validateThreeNodeArmConfig({ ...RAW, ...change }));
  assert.throws(() => validateThreeNodeRunConfig({ ...cfg,
    c: { ...cfg.c, rpcPort: cfg.a.rpcPort } }));
});

test('WSL port preflight refuses a listener before a one-use reservation', async () => {
  assert.equal(checkWslPortInventory('', RAW.ports).listenerCount, 0);
  assert.throws(() => checkWslPortInventory(
    'LISTEN 0 4096 127.0.0.1:59480 0.0.0.0:*\n', RAW.ports), /WSL private ports occupied: 59480/);
  assert.throws(() => checkWslPortInventory(
    'LISTEN 0 4096 [::]:59501 [::]:*\n', RAW.ports), /WSL private ports occupied: 59501/);
  assert.throws(() => checkWslPortInventory('unexpected output\n', RAW.ports), /malformed/);
  let calls = 0;
  const cfg = validateThreeNodeArmConfig(RAW);
  await assert.rejects(threeNodeEnvironmentPreflight(cfg,
    async () => { calls += 1; return { privatePortsFree: Object.values(RAW.ports) }; },
    async (distro) => {
      assert.equal(distro, 'Ubuntu');
      return 'LISTEN 0 4096 0.0.0.0:59481 0.0.0.0:*\n';
    }), /WSL private ports occupied/);
  assert.equal(calls, 1);
});

test('headless slot gate freezes condition, pair, ports, and one-use name', () => {
  const slots = [
    ['C1', 'CONTROL', 'fresh3-pair1', 59480],
    ['A1', 'ATTACK', 'fresh3-pair1', 59580],
    ['A2', 'ATTACK', 'fresh3-pair2', 59680],
    ['C2', 'CONTROL', 'fresh3-pair2', 59780],
  ];
  for (const [slot, arm, pairId, firstPort] of slots) {
    const ports = { rpcA: firstPort, p2pA: firstPort + 1,
      rpcB: firstPort + 10, p2pB: firstPort + 11,
      rpcC: firstPort + 20, p2pC: firstPort + 21 };
    const raw = { ...RAW, arm, pairId, ports,
      runId: `fresh3-20260929t120000z-${slot.toLowerCase()}` };
    assert.equal(validateThreeNodeAssignedSlot(raw, slot), true);
    assert.throws(() => validateThreeNodeAssignedSlot({ ...raw, arm: arm === 'CONTROL' ? 'ATTACK' : 'CONTROL' }, slot), /arm or pair/);
    assert.throws(() => validateThreeNodeAssignedSlot({ ...raw, ports: { ...ports, rpcC: 59999 } }, slot), /six ports/);
    assert.throws(() => validateThreeNodeAssignedSlot({ ...raw, runId: `${raw.runId}-retry` }, slot), /run ID/);
  }
  assert.throws(() => validateThreeNodeAssignedSlot(RAW, 'X1'), /not in/);
});

test('headless freeze gate binds reviewed source, builder, and both protocol documents', () => {
  const protocol = Buffer.from('protocol');
  const schedule = Buffer.from('schedule');
  const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
  const freeze = { schema: 'meepcoin-three-node-series-freeze/1', status: 'AUTHORIZED',
    repoCommit: RAW.repoCommit, builderImageId: RAW.expectedImageId,
    protocolSha256: digest(protocol), scheduleSha256: digest(schedule) };
  const bytes = Buffer.from(JSON.stringify(freeze));
  const raw = { ...RAW, seriesFreezeSha256: digest(bytes) };
  assert.equal(validateThreeNodeSeriesFreeze(raw, bytes, protocol, schedule), true);
  assert.throws(() => validateThreeNodeSeriesFreeze(raw, bytes, protocol,
    Buffer.from('changed')), /series source, builder, or protocol/);
  assert.throws(() => validateThreeNodeSeriesFreeze(raw,
    Buffer.from(JSON.stringify({ ...freeze, builderImageId: `sha256:${'f'.repeat(64)}` })),
    protocol, schedule), /external series freeze differs/);
});

test('one-use series slot cannot be reclaimed with a fresh run ID', (t) => {
  const root = disposable(t);
  const raw = { ...RAW, arm: 'CONTROL', pairId: 'fresh3-pair1',
    runId: 'fresh3-20260929t120000z-c1' };
  assert.throws(() => claimThreeNodeSlot({ ...raw, arm: 'ATTACK' }, root), /arm or pair/);
  assert.throws(() => claimThreeNodeSlot({ ...raw,
    runId: 'fresh3-20260929t120000z-a1', arm: 'ATTACK',
    ports: { rpcA: 59580, p2pA: 59581, rpcB: 59590, p2pB: 59591,
      rpcC: 59600, p2pC: 59601 } }, root), /ENOENT/);
  const path = claimThreeNodeSlot(raw, root);
  const claim = JSON.parse(readFileSync(join(path, 'claim.json'), 'utf8'));
  assert.equal(claim.slot, 'C1');
  assert.equal(claim.state, 'CONSUMED_ONE_USE');
  assert.throws(() => claimThreeNodeSlot({ ...raw,
    runId: 'fresh3-20260929t120001z-c1' }, root), /EEXIST/);
});

test('each boundary sample checks the three owned listener sets as well as the shared peer table', async () => {
  const configs = validateThreeNodeArmConfig(RAW);
  const nodes = [configs.a, configs.b, configs.c];
  let listenerReads = 0;
  let peerReads = 0;
  const listeners = (extra = '') => nodes.map((config, i) => [
    `tcp LISTEN 0 128 127.0.0.1:${config.rpcPort} 0.0.0.0:* users:(("meepcoind",pid=${i + 1},fd=1))`,
    `tcp LISTEN 0 128 127.0.0.1:${config.p2pPort} 0.0.0.0:* users:(("meepcoind",pid=${i + 1},fd=2))`,
  ].join('\n')).join('\n') + extra;
  let table = listeners();
  const resources = nodes.map((config, i) => ({ config, linuxPid: i + 1,
    async observeSocketTable() { peerReads += 1; return ''; },
    async observeListenerTable() { listenerReads += 1; return table; },
  }));
  const baseline = await observeThreeNodeBoundary(resources);
  assert.equal(baseline.ok, true);
  assert.equal(baseline.linked, false);
  assert.deepEqual(baseline.listeners.map((x) => x.verdict.ok), [true, true, true]);
  assert.equal(peerReads, 1);
  assert.equal(listenerReads, 1);

  table = listeners(`\ntcp LISTEN 0 128 0.0.0.0:59999 0.0.0.0:* users:(("meepcoind",pid=3,fd=3))`);
  const refused = await observeThreeNodeBoundary(resources);
  assert.equal(refused.ok, false);
  assert.match(refused.bad.join('; '), /C: listener unexpected_listener/);
  assert.equal(peerReads, 2);
  assert.equal(listenerReads, 2);

  table = null;
  const unobservable = await observeThreeNodeBoundary(resources);
  assert.equal(unobservable.ok, false);
  assert.match(unobservable.bad.join('; '), /listener unobservable/);
  await assert.rejects(observeThreeNodeBoundary(resources.slice(0, 2)), /exactly three/);
});

test('complete mocked arm routes minority through C and seals only after three clean exits', async (t) => {
  const h = harness(disposable(t));
  const result = await runThreeNodeArm(h.cfg, h.deps);
  assert.deepEqual(h.routes.map((r) => [r.role, r.port, r.peerPort]), [
    ['h1', 59480, 59490], ['h2', 59490, 59480], ['third', 59500, 59480],
  ]);
  assert.deepEqual(h.logPorts, [59480, 59490, 59500]);
  assert.equal(h.resources.every((r) => r.closed), true);
  assert.equal(result.cleanupConfirmed, true);
  assert.equal(result.stopReason, 'ALL_AT_HEIGHT_CAP');
  assert.deepEqual(Object.keys(result.nodes), ['A', 'B', 'C']);
  assert.equal(result.interpretation, 'DESCRIPTIVE_ONLY_PENDING_RECEIVER_VERDICT_AUDIT');
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'result.json')), true);
  const resultPath = join(h.cfg.raw.evidenceDir, 'result.json');
  const pinnedResultSha256 = createHash('sha256').update(readFileSync(resultPath)).digest('hex');
  const audit = verifyThreeNodeEvidence(h.cfg.raw.evidenceDir, pinnedResultSha256);
  assert.equal(audit.ok, true);
  assert.equal(audit.scientificVerdict, 'NOT_EVALUATED');
  assert.deepEqual(audit.receiverScreen.candidates, []);
  assert.equal(audit.receiverScreen.scope, 'CANDIDATE_SCREEN_ONLY');
  const events = readFileSync(join(h.cfg.raw.evidenceDir, 'events.jsonl'), 'utf8');
  assert.match(events, /FULL_MESH_VERIFIED/);
  assert.match(events, /PRE_THIRD_MESH/);
  assert.match(events, /TOPOLOGY_SAMPLE/);
  assert.match(events, /POST_STOP_SAMPLE/);
  const phases = events.trim().split('\n').map((line) => JSON.parse(line).phase);
  assert.equal(phases.filter((phase) => phase === 'POST_STOP_SAMPLE').length, 120);
  assert.equal(phases.filter((phase) => phase === 'POST_STOP_CHAIN_SAMPLE').length, 40);
  await assert.rejects(runThreeNodeArm(h.cfg, h.deps), /EEXIST/);
});

test('offline evidence audit refuses unpinned, changed, extra, or structurally forged evidence', async (t) => {
  const h = harness(disposable(t));
  await runThreeNodeArm(h.cfg, h.deps);
  const root = h.cfg.raw.evidenceDir;
  const resultPath = join(root, 'result.json');
  const pin = createHash('sha256').update(readFileSync(resultPath)).digest('hex');
  assert.throws(() => verifyThreeNodeEvidence(root, undefined), /external result SHA-256 pin/);
  assert.throws(() => verifyThreeNodeEvidence(root, '0'.repeat(64)), /result differs from external pin/);
  const logPath = join(root, 'daemon-A.log');
  writeFileSync(logPath, 'changed daemon log\n');
  assert.throws(() => verifyThreeNodeEvidence(root, pin), /daemon-A.log/);
  writeFileSync(logPath, 'mock daemon log\n');
  writeFileSync(join(root, 'extra.txt'), 'unlisted');
  assert.throws(() => verifyThreeNodeEvidence(root, pin), /file inventory/);
  rmSync(join(root, 'extra.txt'));
  const cleanupPath = join(root, 'cleanup.json');
  const originalCleanup = readFileSync(cleanupPath);
  const originalResult = readFileSync(resultPath);
  const cleanup = JSON.parse(originalCleanup.toString('utf8'));
  cleanup.closeResults[0].runDir = '/home/tseng/meepcoin-private-run-foreign';
  writeFileSync(cleanupPath, JSON.stringify(cleanup));
  const wrongCleanupResult = JSON.parse(originalResult.toString('utf8'));
  wrongCleanupResult.cleanupSha256 = createHash('sha256').update(readFileSync(cleanupPath)).digest('hex');
  writeFileSync(resultPath, JSON.stringify(wrongCleanupResult));
  const wrongCleanupPin = createHash('sha256').update(readFileSync(resultPath)).digest('hex');
  assert.throws(() => verifyThreeNodeEvidence(root, wrongCleanupPin), /owned daemon shutdown/);
  writeFileSync(cleanupPath, originalCleanup);
  writeFileSync(resultPath, originalResult);
  const observationPath = join(root, 'observation.json');
  const originalObservation = readFileSync(observationPath);
  const wrongGenesisObservation = JSON.parse(originalObservation.toString('utf8'));
  wrongGenesisObservation.nodes.A.canonical[0].timestamp += 1;
  writeFileSync(observationPath, JSON.stringify(wrongGenesisObservation));
  const wrongGenesisResult = JSON.parse(originalResult.toString('utf8'));
  wrongGenesisResult.nodes.A.canonical[0].timestamp += 1;
  wrongGenesisResult.observationSha256 = createHash('sha256').update(readFileSync(observationPath)).digest('hex');
  writeFileSync(resultPath, JSON.stringify(wrongGenesisResult));
  const wrongGenesisPin = createHash('sha256').update(readFileSync(resultPath)).digest('hex');
  assert.throws(() => verifyThreeNodeEvidence(root, wrongGenesisPin), /wrong pinned genesis/);
  writeFileSync(observationPath, originalObservation);
  writeFileSync(resultPath, originalResult);
  const eventsPath = join(root, 'events.jsonl');
  const originalEvents = readFileSync(eventsPath);
  const events = originalEvents.toString('utf8').trim().split('\n').map((line) => JSON.parse(line));
  events.find((event) => event.phase === 'PRE_THIRD_MESH').states[0].synchronized = false;
  writeFileSync(eventsPath, events.map((event) => JSON.stringify(event)).join('\n') + '\n');
  const wrongMeshResult = JSON.parse(originalResult.toString('utf8'));
  wrongMeshResult.eventsSha256 = createHash('sha256').update(readFileSync(eventsPath)).digest('hex');
  writeFileSync(resultPath, JSON.stringify(wrongMeshResult));
  const wrongMeshPin = createHash('sha256').update(readFileSync(resultPath)).digest('hex');
  assert.throws(() => verifyThreeNodeEvidence(root, wrongMeshPin), /pre-third synchronization/);
  writeFileSync(eventsPath, originalEvents);
  writeFileSync(resultPath, originalResult);
  const result = JSON.parse(readFileSync(resultPath, 'utf8'));
  result.nodes.A.canonical[1].prev_hash = 'f'.repeat(64);
  writeFileSync(resultPath, JSON.stringify(result));
  const forgedPin = createHash('sha256').update(readFileSync(resultPath)).digest('hex');
  assert.throws(() => verifyThreeNodeEvidence(root, forgedPin), /rewrote the pre-cleanup observation/);
});

test('lost private mesh fails the arm and closes all three, without publishing a result', async (t) => {
  const h = harness(disposable(t), { loseMesh: true });
  await assert.rejects(runThreeNodeArm(h.cfg, h.deps), /full mesh lost/);
  assert.equal(h.resources.every((r) => r.closed), true);
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'result.json')), false);
  assert.match(readFileSync(join(h.cfg.raw.evidenceDir, 'events.jsonl'), 'utf8'), /FAILURE/);
});

test('lost mesh after honest first hashes refuses third miner and cleans owned daemons', async (t) => {
  const h = harness(disposable(t), { loseMeshBeforeThird: true });
  await assert.rejects(runThreeNodeArm(h.cfg, h.deps), /full mesh lost before third miner start/);
  assert.deepEqual(h.routes.map((r) => r.role), ['h1', 'h2']);
  assert.equal(h.resources.every((r) => r.closed), true);
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'result.json')), false);
  assert.match(readFileSync(join(h.cfg.raw.evidenceDir, 'events.jsonl'), 'utf8'), /PRE_THIRD_MESH/);
});

test('unrecorded pre-third mesh check cannot start the third miner', async (t) => {
  const h = harness(disposable(t));
  h.deps.appendEvent = (path, line) => {
    if (line.includes('"phase":"PRE_THIRD_MESH"')) throw new Error('synthetic full disk');
    appendFileSync(path, line);
  };
  await assert.rejects(runThreeNodeArm(h.cfg, h.deps), /event evidence write failed/);
  assert.deepEqual(h.routes.map((r) => r.role), ['h1', 'h2']);
  assert.equal(h.resources.every((r) => r.closed), true);
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'result.json')), false);
});

test('bad third-daemon logging stops before any worker starts and preserves cleanup', async (t) => {
  const h = harness(disposable(t), { badLogging: true });
  await assert.rejects(runThreeNodeArm(h.cfg, h.deps), /log acknowledgements/);
  assert.equal(h.routes.length, 0);
  assert.equal(h.resources.every((r) => r.closed), true);
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'result.json')), false);
});

test('third worker failure stops the arm and closes all daemons', async (t) => {
  const h = harness(disposable(t), { thirdFails: true });
  await assert.rejects(runThreeNodeArm(h.cfg, h.deps), /miner failed during arm/);
  assert.equal(h.resources.every((r) => r.closed), true);
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'result.json')), false);
});

test('partial third-daemon startup adopts the failing resource and cleans all owned daemons', async (t) => {
  const h = harness(disposable(t));
  const start = h.deps.startDaemon;
  h.deps.startDaemon = async (args) => {
    const resource = await start(args);
    if (h.resources.length === 3) throw Object.assign(new Error('third startup failed'), { resource });
    return resource;
  };
  await assert.rejects(runThreeNodeArm(h.cfg, h.deps), /third startup failed/);
  assert.equal(h.resources.length, 3);
  assert.equal(h.resources.every((r) => r.closed), true);
  assert.equal(h.routes.length, 0);
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'result.json')), false);
});

test('missing third daemon log cannot produce a final result despite clean shutdown', async (t) => {
  const h = harness(disposable(t));
  const preserve = h.deps.preserveLog;
  h.deps.preserveLog = async (args) => {
    if (args.destination.endsWith('daemon-C.log')) throw new Error('synthetic missing log');
    return preserve(args);
  };
  await assert.rejects(runThreeNodeArm(h.cfg, h.deps), /three daemon logs were not preserved/);
  assert.equal(h.resources.every((r) => r.closed), true);
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'result.json')), false);
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'cleanup.json')), true);
});

test('an event-write failure latches and still closes all three daemons without a result', async (t) => {
  const h = harness(disposable(t));
  h.deps.appendEvent = (path, line) => {
    if (line.includes('ALL_MINERS_STARTED')) throw new Error('synthetic full disk');
    appendFileSync(path, line);
  };
  await assert.rejects(runThreeNodeArm(h.cfg, h.deps), /event evidence write failed/);
  assert.equal(h.resources.every((r) => r.closed), true);
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'cleanup.json')), true);
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'result.json')), false);
});

test('a cleanup-event write failure cannot publish a green result after shutdown', async (t) => {
  const h = harness(disposable(t));
  h.deps.appendEvent = (path, line) => {
    if (line.includes('"phase":"CLEANUP"')) throw new Error('synthetic cleanup write failure');
    appendFileSync(path, line);
  };
  await assert.rejects(runThreeNodeArm(h.cfg, h.deps), /event evidence write failed/);
  assert.equal(h.resources.every((r) => r.closed), true);
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'cleanup.json')), true);
  assert.equal(existsSync(join(h.cfg.raw.evidenceDir, 'result.json')), false);
});

test('preflight refusal happens before reservation or daemon launch', async (t) => {
  const evidenceDir = disposable(t);
  const h = harness(evidenceDir);
  h.deps.machinePreflight = async () => { throw new Error('competing miner'); };
  await assert.rejects(runThreeNodeArm(h.cfg, h.deps), /competing miner/);
  assert.equal(existsSync(evidenceDir), false);
  assert.equal(h.resources.length, 0);
});
