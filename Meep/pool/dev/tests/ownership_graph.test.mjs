// ONE ownership graph, and a shutdown that cannot be raced.
//
// Regression testing reproduced three separate ways for a resource to be lost or wrongly declared released:
//
//   * a LATE verifier -- one whose initialization finished after shutdown began -- was stored in
//     `retainedLateVerifier`, which retryClose() never visited and the success predicate never
//     checked. Retry reported `closed`, `retained` went null, and the resource's own `closed` was
//     still false. The handle was gone and the pool said it had finished.
//   * `close()` resolving was treated as release. A forceClose() that fulfilled without the
//     resource's `closed` becoming true made shutdown succeed over an un-reaped child.
//   * retryClose() started a SECOND runShutdown while the first was still running, so two teardown
//     sequences raced the same child -- two QUITs, two escalations, two sets of WSL probes.
//
// The contract now: every verifier-shaped resource the pool has ever created is in one collection;
// membership ends only on a positive `closed === true`; shutdown succeeds only when the collection
// is empty; retry visits all of it; and close()/retryClose() share one in-flight attempt.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { startDevPool } from '../server.mjs';
import { EXIT_PROTOCOL_ANOMALY, createShutdownController } from '../cli_shutdown.mjs';
import { HELPER_PROTOCOL_VERSION } from '../native_helper.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitUntil(fn, { timeoutMs = 10_000, everyMs = 20, label = 'condition' } = {}) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    if (await fn()) return true;
    if (Date.now() > end) throw new Error(`timed out waiting for ${label}`);
    await sleep(everyMs);
  }
}

/**
 * A verifier whose release behaviour the test controls exactly.
 *
 * `closed` is a real, separate fact from "close() returned", which is the whole point: several of
 * these deliberately RESOLVE their teardown without ever becoming closed.
 */
function controllable({ label = 'v', failClose = false, failForce = false, forceLies = false } = {}) {
  const state = { closeCalls: 0, forceCalls: 0, beginCloseCalls: 0 };
  let released = false;
  let closing = false;
  const self = {
    label,
    state,
    hashCalls: 0,
    wasmHeapBytes: () => 1,
    nativeAlgorithmBytes: () => null,
    async verify() { throw new Error('not used'); },
    beginClose() { state.beginCloseCalls++; closing = true; },
    async close() {
      state.closeCalls++;
      closing = true;
      if (self.failClose) throw new Error(`${label}: modelled teardown failure`);
      released = true;
    },
    async forceClose() {
      state.forceCalls++;
      closing = true;
      if (self.failForce) throw new Error(`${label}: modelled escalation failure`);
      // forceLies: resolve successfully but never actually confirm release. This is the exact
      // shape of "the call returned, so we assumed the child was gone".
      if (!self.forceLies) released = true;
    },
    get closed() { return released; },
    get closing() { return closing; },
    failClose,
    failForce,
    forceLies,
  };
  return self;
}

// ---------------------------------------------------------------- late resources

test('a LATE verifier whose teardown fails is retained, and retry actually reaches it',
  { timeout: 60_000 }, async (t) => {
    const late = controllable({ label: 'late', failClose: true, failForce: true });
    let releaseInit = null;
    const initGate = new Promise((r) => { releaseInit = r; });

    const pool = await startDevPool({
      port: 0,
      // Resolves only after shutdown has started: the classic "late" resource.
      verifierFactory: async () => { await initGate; return late; },
    });
    t.after(async () => { late.failClose = false; late.failForce = false; await pool.retryClose().catch(() => {}); });

    const ws = new WebSocket(pool.wsUrl);
    t.after(() => { try { ws.close(); } catch { /* gone */ } });
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('open failed')); });
    ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
    await sleep(150);
    ws.send(JSON.stringify({ type: 'start_request' }));
    await waitUntil(() => pool.verifierState === 'initializing', { label: 'initialization' });

    const closing = pool.close().then(() => 'closed', (e) => `failed: ${e.message}`);
    await sleep(100);
    releaseInit(); // the verifier arrives mid-shutdown
    const first = await closing;

    assert.match(first, /^failed:/, 'a resource that could not be released must fail the close');
    assert.equal(pool.verifierState, 'close_failed');
    assert.equal(late.closed, false);
    assert.equal(pool.retainedVerifier, late, 'the LATE resource is what is retained');
    assert.equal(pool.retainedResources.length, 1);
    assert.ok(late.state.closeCalls >= 1 && late.state.forceCalls >= 1, 'both attempts were made');

    // Now let it be releasable, and retry. The old retryClose() never visited a late resource at
    // all: it reported closed while this object was still open.
    const before = { close: late.state.closeCalls, force: late.state.forceCalls };
    late.failClose = false;
    late.failForce = false;
    await pool.retryClose();

    assert.ok(late.state.closeCalls > before.close || late.state.forceCalls > before.force,
      'the retry must actually CALL the retained resource, not just change a state string');
    assert.equal(late.closed, true, 'and it is really closed now');
    assert.equal(pool.verifierState, 'closed');
    assert.deepEqual(pool.retainedResources, []);
    assert.equal(pool.retainedVerifier, null);
  });

test('a forceClose that resolves WITHOUT confirming release keeps the shutdown failed',
  { timeout: 60_000 }, async (t) => {
    // "The call returned" is not "the child is gone". This resource's escalation fulfils happily
    // and never sets closed; the pool must not read that as success.
    const liar = controllable({ label: 'liar', failClose: true, forceLies: true });
    const pool = await startDevPool({ port: 0, verifierFactory: async () => liar });
    t.after(async () => { liar.forceLies = false; liar.failClose = false; await pool.retryClose().catch(() => {}); });

    const ws = new WebSocket(pool.wsUrl);
    t.after(() => { try { ws.close(); } catch { /* gone */ } });
    await new Promise((res) => { ws.onopen = res; });
    ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
    await sleep(150);
    ws.send(JSON.stringify({ type: 'start_request' }));
    await waitUntil(() => pool.verifier !== null, { label: 'a ready verifier' });

    await assert.rejects(() => pool.close(),
      (err) => /never confirmed|not confirmed released/.test(err.message),
      'a teardown that returned without releasing is a FAILURE');
    assert.equal(pool.verifierState, 'close_failed');
    assert.equal(liar.closed, false);
    assert.equal(pool.retainedVerifier, liar, 'and the handle is still reachable');
  });

test('a ready resource and a late resource are both released, each exactly once',
  { timeout: 60_000 }, async (t) => {
    const ready = controllable({ label: 'ready' });
    const late = controllable({ label: 'late' });
    let handedOut = 0;
    let releaseInit = null;
    const initGate = new Promise((r) => { releaseInit = r; });

    const pool = await startDevPool({
      port: 0,
      verifierFactory: async () => {
        handedOut++;
        if (handedOut === 1) return ready;
        await initGate;
        return late;
      },
    });

    const ws = new WebSocket(pool.wsUrl);
    t.after(() => { try { ws.close(); } catch { /* gone */ } });
    await new Promise((res) => { ws.onopen = res; });
    ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
    await sleep(150);
    ws.send(JSON.stringify({ type: 'start_request' }));
    await waitUntil(() => pool.verifier === ready, { label: 'the ready verifier' });

    // Force a second initialization to be in flight when shutdown starts: drop the ready one the
    // way a fault would, then ask again.
    pool.injectVerifierFault(new Error('make room for a second initialization'));
    await sleep(50);

    const closing = pool.close().then(() => 'closed', (e) => `failed: ${e.message}`);
    releaseInit();
    const outcome = await closing;

    assert.equal(outcome, 'closed');
    assert.equal(ready.closed, true, 'the ready resource was released');
    assert.equal(ready.state.closeCalls, 1, 'exactly once');
    assert.deepEqual(pool.retainedResources, [], 'and nothing is left owned');
  });

// ---------------------------------------------------------------- serialization

test('close() and retryClose() share ONE teardown; they never race the same resource',
  { timeout: 60_000 }, async (t) => {
    // The old retryClose() called runShutdown() unconditionally, so a retry issued while a close
    // was still running produced two concurrent teardowns of the same child.
    let inTeardown = 0;
    let maxConcurrent = 0;
    const slow = controllable({ label: 'slow' });
    const originalClose = slow.close.bind(slow);
    slow.close = async () => {
      inTeardown++;
      maxConcurrent = Math.max(maxConcurrent, inTeardown);
      await sleep(400);
      try { return await originalClose(); } finally { inTeardown--; }
    };

    const pool = await startDevPool({ port: 0, verifierFactory: async () => slow });
    t.after(() => pool.close().catch(() => {}));

    const ws = new WebSocket(pool.wsUrl);
    t.after(() => { try { ws.close(); } catch { /* gone */ } });
    await new Promise((res) => { ws.onopen = res; });
    ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
    await sleep(150);
    ws.send(JSON.stringify({ type: 'start_request' }));
    await waitUntil(() => pool.verifier === slow, { label: 'a ready verifier' });

    const a = pool.close();
    const b = pool.retryClose();
    const c = pool.close();
    await Promise.allSettled([a, b, c]);

    assert.equal(maxConcurrent, 1, 'at most ONE teardown sequence may run at a time');
    assert.equal(slow.state.closeCalls, 1, 'and the resource was torn down once, not three times');
    assert.equal(slow.state.forceCalls, 0, 'with no spurious escalation');
    assert.equal(pool.verifierState, 'closed');
  });

test('a retry issued during a failing close joins it rather than starting a second escalation',
  { timeout: 60_000 }, async (t) => {
    let concurrentForce = 0;
    let maxConcurrentForce = 0;
    const stubborn = controllable({ label: 'stubborn', failClose: true });
    const originalForce = stubborn.forceClose.bind(stubborn);
    stubborn.forceClose = async () => {
      concurrentForce++;
      maxConcurrentForce = Math.max(maxConcurrentForce, concurrentForce);
      await sleep(300);
      try { return await originalForce(); } finally { concurrentForce--; }
    };

    const pool = await startDevPool({ port: 0, verifierFactory: async () => stubborn });
    t.after(() => pool.close().catch(() => {}));
    const ws = new WebSocket(pool.wsUrl);
    t.after(() => { try { ws.close(); } catch { /* gone */ } });
    await new Promise((res) => { ws.onopen = res; });
    ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
    await sleep(150);
    ws.send(JSON.stringify({ type: 'start_request' }));
    await waitUntil(() => pool.verifier === stubborn, { label: 'a ready verifier' });

    const closing = pool.close().catch((e) => e);
    await sleep(50);
    const retrying = pool.retryClose().catch((e) => e);
    await Promise.allSettled([closing, retrying]);

    assert.equal(maxConcurrentForce, 1, 'escalation is never run twice concurrently on one child');
    // The graceful attempt failed, escalation succeeded, so the pool ends up closed and empty.
    assert.equal(stubborn.closed, true);
    assert.deepEqual(pool.retainedResources, []);
  });

// ---------------------------------------------------------------- provisional ownership

test('a startup whose cleanup could not be confirmed is RETAINED, and blocks a later Start',
  { timeout: 60_000 }, async (t) => {
    // A factory that rejects while a child's fate is unknown has lost the only reference to a
    // process nobody will ever clean up. The handles come back on the error and the pool adopts
    // them; until they are released, another Start would just add a second unknown child.
    const stranded = controllable({ label: 'native helper (handshake failed)', failClose: true, failForce: true });
    let attempts = 0;
    const pool = await startDevPool({
      port: 0,
      verifierFactory: async () => {
        attempts++;
        const err = new Error('helper handshake failed');
        err.name = 'PartialVerifierError';
        err.resources = [{ label: stranded.label, resource: stranded }];
        throw err;
      },
    });
    t.after(async () => { stranded.failClose = false; stranded.failForce = false; await pool.retryClose().catch(() => {}); });

    const got = [];
    const ws = new WebSocket(pool.wsUrl);
    t.after(() => { try { ws.close(); } catch { /* gone */ } });
    await new Promise((res) => { ws.onopen = res; });
    ws.onmessage = (e) => got.push(JSON.parse(e.data));
    ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
    await sleep(150);

    ws.send(JSON.stringify({ type: 'start_request' }));
    await waitUntil(() => got.some((m) => m.type === 'mining_unavailable'), { label: 'the failure' });
    assert.equal(attempts, 1);
    assert.equal(pool.retainedVerifier, stranded,
      'a rejected startup must not be assumed to have produced nothing');
    assert.equal(pool.retainedResources.length, 1);

    // A second Start must not stack another unknown child on top of it.
    got.length = 0;
    ws.send(JSON.stringify({ type: 'start_request' }));
    await waitUntil(() => got.some((m) => m.type === 'mining_unavailable'), { label: 'the refusal' });
    assert.equal(attempts, 1, 'no second startup while a resource is unreleased');
    assert.match(String(got.find((m) => m.type === 'mining_unavailable').detail), /unreleased resource/);

    // And once it can be released, retry clears it and Start works again.
    stranded.failClose = false;
    stranded.failForce = false;
    await pool.retryClose();
    assert.deepEqual(pool.retainedResources, []);
    assert.equal(stranded.closed, true);
  });

// ---------------------------------------------------------------- the REAL partial-startup path
//
// The regression above injects an object already shaped like a PartialVerifierError. That proves
// the SERVER adopts a shaped error; it proves nothing about the path that produces one. The chain
// that actually matters is:
//
//   createDualVerifier -> startNativeHelper (real child, real HELLO) -> a startup refusal
//     -> abandonPartial -> forceClose -> an obstructed probe -> release NOT confirmed
//     -> PartialVerifierError carrying the real live handle -> the pool adopts it
//
// Every link here is production code. The only things the test controls are the child (a fake
// helper that greets with the wrong build-source identity) and the WSL probe channel (obstructed,
// then released on command) -- both legitimate nested seams, neither able to disable the safety
// wiring.

const OWN_BOOT = '3c1d2e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f';
let ownScratch;

test('a REAL partial startup retains the REAL handle, blocks Start, and later releases it',
  { timeout: 120_000 }, async (t) => {
    ownScratch = mkdtempSync(join(tmpdir(), 'meep-partial-'));
    t.after(async () => {
      for (let i = 0; i < 10 && existsSync(ownScratch); i++) {
        try { rmSync(ownScratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* retry */ }
        await sleep(200);
      }
      if (existsSync(ownScratch)) console.error(`# LEFTOVER TEMP DIRECTORY NOT REMOVED: ${ownScratch}`);
    });

    // A real child that completes a real HELLO -- canonical distro and boot id, so the boot-identity
    // anchor succeeds -- and then reports a build-source identity that is not this working tree's.
    // The pool refuses it, which is where the partial-startup path begins.
    const file = join(ownScratch, 'stale-helper.mjs');
    writeFileSync(file,
      `process.stdout.write('HELLO ${HELPER_PROTOCOL_VERSION} 4242 ' + process.argv[2]`
      + ` + ' 2 60 Ubuntu ${OWN_BOOT} ${'0'.repeat(64)}\\n');\nsetTimeout(() => {}, 120000);\n`,
      'utf8');

    // THE CONTROLLED OBSTRUCTION. While obstructed, every /proc question fails -- which is
    // INSPECTION_FAILED, which is not absence, which must retain the resource.
    let obstructed = true;
    const probeCalls = [];
    const wslRunner = (args) => {
      probeCalls.push(args);
      // The startup anchor must succeed, or the run never reaches the source-identity refusal.
      if (args.includes('cat') && !args.some((a) => a.endsWith('/cmdline'))) {
        return { ok: true, code: 0, stdout: Buffer.from(`${OWN_BOOT}\n`, 'latin1'), reason: null };
      }
      if (obstructed) {
        return { ok: false, code: null, stdout: Buffer.alloc(0), reason: 'controlled obstruction: cannot inspect' };
      }
      if (args.includes('ls')) {
        return { ok: true, code: 2, stdout: Buffer.from('/proc/self\n', 'latin1'), reason: null };
      }
      return { ok: true, code: 1, stdout: Buffer.from(`${OWN_BOOT}\n`, 'latin1'), reason: null };
    };

    let spawns = 0;
    const pool = await startDevPool({
      port: 0,
      helperPath: process.execPath,
      helperOptions: {
        useWsl: true,
        wslRunner,
        limits: { probeTimeoutMs: 400, signalTimeoutMs: 400, quitTimeoutMs: 400, startupTimeoutMs: 8000 },
        spawnFn: (cmd) => {
          spawns++;
          return spawn(process.execPath, [file, cmd.args.at(-1)], {
            stdio: ['pipe', 'pipe', 'pipe'], shell: false,
          });
        },
      },
    });
    t.after(async () => { obstructed = false; await pool.retryClose().catch(() => {}); });

    const got = [];
    const ws = new WebSocket(pool.wsUrl);
    t.after(() => { try { ws.close(); } catch { /* gone */ } });
    await new Promise((res) => { ws.onopen = res; });
    ws.onmessage = (e) => got.push(JSON.parse(e.data));
    ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
    await sleep(200);

    ws.send(JSON.stringify({ type: 'start_request' }));
    await waitUntil(() => got.some((m) => m.type === 'mining_unavailable'), { label: 'the startup failure' });
    assert.equal(spawns, 1, 'exactly one real child was launched');
    assert.ok(probeCalls.length > 0, 'and the real cleanup path really did probe');

    // THE ACTUAL HANDLE IS VISIBLE. Not a stand-in: the live native-helper object, with the Linux
    // pid and the per-launch token it greeted with.
    const retained = pool.retainedVerifier;
    assert.ok(retained, 'a rejected startup must not be assumed to have produced nothing');
    assert.equal(pool.retainedResources.length, 1);
    assert.equal(pool.retainedResources[0].resource, retained, 'the graph holds that exact object');
    assert.equal(retained.closed, false, 'and it is honestly not released');
    assert.equal(retained.linuxPid, 4242, 'it is the real helper handle from the real HELLO');
    assert.match(retained.token, /^[0-9a-f]{16}$/, 'carrying the real per-launch token');
    assert.equal(typeof retained.forceClose, 'function', 'and it is still operable');

    // A SECOND START IS REFUSED. Stacking another unknown child on an unreleased one is exactly
    // how an invisible process happens.
    got.length = 0;
    ws.send(JSON.stringify({ type: 'start_request' }));
    await waitUntil(() => got.some((m) => m.type === 'mining_unavailable'), { label: 'the refusal' });
    assert.equal(spawns, 1, 'no second startup while a resource is unreleased');
    assert.match(String(got.find((m) => m.type === 'mining_unavailable').detail), /unreleased resource/);

    // CLOSE IS NOT FALSELY SUCCESSFUL. The obstruction is still in place, so nothing may claim
    // release -- neither the helper handle nor the pool.
    let closeErr = null;
    try { await pool.close(); } catch (err) { closeErr = err; }
    assert.ok(closeErr, 'a close that could not confirm release must fail, not resolve');
    assert.match(closeErr.message, /cannot inspect|could not be confirmed|not confirmed/);
    assert.equal(retained.closed, false, 'the handle is still owned');
    assert.equal(pool.retainedResources.length, 1, 'and still visible for a retry');

    // AND RETRY REACHES THAT EXACT HANDLE once the obstruction is removed.
    obstructed = false;
    await pool.retryClose();
    assert.equal(retained.closed, true, 'the retry released the very resource that was retained');
    assert.deepEqual(pool.retainedResources, [], 'and the ownership graph is empty');
  });

// ---------------------------------------------------------------- an anomaly outlives a retry
//
// server.runShutdown() cleared `shutdownAnomalies` at the start of EVERY attempt. So a first
// attempt could release resource A abnormally, record it, DELETE A from the ownership graph, and
// still fail because resource B was retained -- and the retry, finding A already gone, could never
// rediscover the anomaly and returned a perfectly clean result. The CLI retries automatically, so
// a genuinely abnormal shutdown became exit 0. The ledger is now append-only for the lifetime of
// the pool: a retry may ADD facts, never remove one that already happened.

/** Released cleanly at the process level, but reporting an abnormal protocol transcript. */
function abnormalButReleased(label) {
  let released = false;
  return {
    label,
    hashCalls: 0,
    wasmHeapBytes: () => 1,
    nativeAlgorithmBytes: () => null,
    async verify() { throw new Error('not used'); },
    beginClose() {},
    async close() { released = true; },          // resolves; the anomaly is in the outcome
    async forceClose() { released = true; },
    get closed() { return released; },
    get closing() { return true; },
    get shutdownOutcome() {
      return {
        physicalReleaseConfirmed: released,
        gracefulProtocolShutdown: false,
        reason: 'native helper: helper exited without sending BYE',
      };
    },
  };
}

/** Releases on the first attempt, with a clean protocol transcript. */
function cleanlyReleased(label) {
  let released = false;
  return {
    label,
    hashCalls: 0,
    wasmHeapBytes: () => 1,
    nativeAlgorithmBytes: () => null,
    async verify() { throw new Error('not used'); },
    beginClose() {},
    async close() { released = true; },
    async forceClose() { released = true; },
    get closed() { return released; },
    get closing() { return true; },
    get shutdownOutcome() {
      return { physicalReleaseConfirmed: released, gracefulProtocolShutdown: true, reason: null };
    },
  };
}

/** Owned after the first attempt; released cleanly on a later one. */
function stubbornThenClean(label, failFor = 1) {
  let released = false;
  let attempts = 0;
  return {
    label,
    hashCalls: 0,
    wasmHeapBytes: () => 1,
    nativeAlgorithmBytes: () => null,
    async verify() { throw new Error('not used'); },
    beginClose() {},
    async close() {
      attempts++;
      if (attempts <= failFor) throw new Error(`${label}: modelled attempt-${attempts} failure`);
      released = true;
    },
    async forceClose() {
      if (attempts <= failFor) throw new Error(`${label}: modelled attempt-${attempts} escalation failure`);
      released = true;
    },
    get closed() { return released; },
    get closing() { return true; },
    get shutdownOutcome() {
      return { physicalReleaseConfirmed: released, gracefulProtocolShutdown: true, reason: null };
    },
  };
}

/** Own two resources at once through the real PartialVerifierError adoption path. */
async function poolOwningBoth(t, A, B) {
  const pool = await startDevPool({
    port: 0,
    verifierFactory: async () => {
      const err = new Error('startup failed with unconfirmed cleanup');
      err.name = 'PartialVerifierError';
      err.resources = [{ label: A.label, resource: A }, { label: B.label, resource: B }];
      throw err;
    },
  });
  const got = [];
  const ws = new WebSocket(pool.wsUrl);
  t.after(() => { try { ws.close(); } catch { /* gone */ } });
  await new Promise((res) => { ws.onopen = res; });
  ws.onmessage = (e) => got.push(JSON.parse(e.data));
  ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
  await sleep(150);
  ws.send(JSON.stringify({ type: 'start_request' }));
  await waitUntil(() => got.some((m) => m.type === 'mining_unavailable'), { label: 'the adoption' });
  assert.equal(pool.retainedResources.length, 2, 'both handles are owned');
  return pool;
}

test('an abnormal-but-released resource keeps its anomaly across a retry that succeeds',
  { timeout: 60_000 }, async (t) => {
    const A = abnormalButReleased('verifier');
    const B = stubbornThenClean('late verifier');
    const pool = await poolOwningBoth(t, A, B);
    t.after(() => pool.retryClose().catch(() => {}));

    // Attempt 1: A is released (abnormally) and LEAVES the graph; B keeps the pool owned.
    const first = await pool.close().then(() => 'closed', (e) => `failed: ${e.message}`);
    assert.match(first, /^failed:/, 'the first attempt cannot succeed while B is owned');
    assert.equal(A.closed, true, 'A is physically gone');
    assert.equal(B.closed, false, 'B is not');
    assert.equal(pool.shutdownOutcome.protocolAnomalies.length, 1, 'A\'s anomaly was recorded');

    // Attempt 2: B releases and the shutdown succeeds -- and A's anomaly MUST still be there,
    // even though A itself has long since left the ownership graph.
    const result = await pool.retryClose();
    assert.deepEqual(pool.retainedResources, [], 'everything is released now');
    const anomalies = pool.shutdownOutcome.protocolAnomalies;
    assert.equal(anomalies.length, 1, `exactly once, not erased and not duplicated; saw ${JSON.stringify(anomalies)}`);
    assert.match(anomalies[0].reason, /exited without sending BYE/);
    assert.equal(pool.shutdownOutcome.gracefulProtocolShutdown, false,
      'a successful retry does not make an earlier abnormal release clean');
    if (result) {
      assert.equal(result.gracefulProtocolShutdown, false, 'and the returned result says so too');
      assert.equal(result.protocolAnomalies.length, 1);
    }
  });

test('the CLI retry path still exits nonzero, and repeated retries do not duplicate the anomaly',
  { timeout: 60_000 }, async (t) => {
    const A = abnormalButReleased('verifier');
    const B = stubbornThenClean('late verifier', 2); // fails the first two attempts
    const pool = await poolOwningBoth(t, A, B);
    t.after(() => pool.retryClose().catch(() => {}));

    const errs = []; const exits = [];
    const ctl = createShutdownController({
      pool,
      log: () => {},
      error: (x) => errs.push(String(x)),
      exit: (code) => exits.push(code),
      wait: () => Promise.resolve(),
    });
    await ctl.requestShutdown('SIGINT');

    assert.deepEqual(pool.retainedResources, [], 'the retries did eventually release everything');
    assert.deepEqual(exits, [EXIT_PROTOCOL_ANOMALY],
      `an automatic retry must not launder an abnormal release into success; stderr ${JSON.stringify(errs)}`);
    assert.ok(errs.some((line) => /exited without sending BYE/.test(line)),
      'and the operator is told which resource and why');

    // Idempotent: several more retries add nothing.
    await pool.retryClose().catch(() => {});
    await pool.retryClose().catch(() => {});
    assert.equal(pool.shutdownOutcome.protocolAnomalies.length, 1,
      'an append-only ledger still has to be deduplicated');
  });

// A FAILED CLOSE ATTEMPT IS NOT A PROTOCOL ANOMALY.
//
// `protocolAnomalies` answers one question: did a resource let go abnormally? A close attempt that
// FAILED is a different fact -- it is in `failures`, it fails that shutdown, the CLI exits nonzero
// for it, and retrying it until the resource is positively released is this pool's documented,
// tested behaviour. A revision of the sustained-rotation slice began opening a fresh anomaly row for
// such a resource, which made an ordinary retried teardown a permanent anomaly and put a second row
// in a ledger the two tests above require to hold exactly one. Facts about a handle that ALREADY has
// a row still belong on that row, and nothing is erased either way.
test('a stubborn resource that a retry releases is a failure, not a permanent protocol anomaly',
  { timeout: 60_000 }, async (t) => {
    const B = stubbornThenClean('late verifier');
    // Owned through the same real partial-startup adoption path the tests above use. The companion
    // handle releases cleanly on the first attempt and contributes no anomaly of its own.
    const pool = await poolOwningBoth(t, cleanlyReleased('spare verifier'), B);
    t.after(() => pool.retryClose().catch(() => {}));

    const first = await pool.close().then(() => 'closed', (e) => `failed: ${e.message}`);
    assert.match(first, /^failed:/, 'the first attempt must fail while B is unreleased');
    assert.equal(B.closed, false);
    assert.deepEqual(pool.shutdownOutcome.protocolAnomalies, [],
      'a merely stubborn resource opened a protocol-anomaly row');
    assert.equal(pool.shutdownOutcome.physicalReleaseConfirmed, false,
      'the failed attempt is still reported, through release confirmation and closeFailure');
    assert.ok(pool.closeFailure, 'the failed attempt left no failure to report');

    const retried = await pool.retryClose();
    assert.equal(B.closed, true);
    assert.deepEqual(pool.retainedResources, []);
    assert.deepEqual(pool.shutdownOutcome.protocolAnomalies, [],
      'a released-on-retry resource must not leave an anomaly behind');
    assert.equal(pool.shutdownOutcome.gracefulProtocolShutdown, true,
      'nothing here let go abnormally, so the final verdict is clean');
    if (retried) assert.deepEqual(retried.protocolAnomalies, []);
  });

// The other half of the rule -- a handle that already HAS a row keeps accumulating facts on that one
// row, including a failed escalation -- is exercised by the rotation-release path in
// pool/dev/tests/sustained_pool.test.mjs ('failed pre-drain force stays owned and retry never
// re-enters abandoned close'), which is where a resource can acquire a row before the sweep reaches
// it. It is deliberately not duplicated here.
