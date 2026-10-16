// Ownership prerequisites for a child-process verifier.
//
// The Wasm verifier is synchronous, which hides four ownership defects that a native helper would
// expose immediately:
//
//   A1  shutdown drained session operations BEFORE telling the verifier to stop. For a verifier
//       whose requests are answered by a child process that is a deadlock: close waits for the
//       operation, the operation waits for the request, the request only settles when verifier
//       shutdown begins, and shutdown was queued behind the drain.
//   A2  a failed teardown cleared the only handle to the resource and latched a permanently
//       rejected promise, so nothing could ever finish the cleanup.
//   A3  the async HTTP handler promise was untracked, so close() could report success while a GET
//       was still being served.
//   A4  a throwing logger prevented the connection close and produced an unhandled rejection.
//
// These are all about who owns what and when, so the tests below inject fake verifiers whose
// timing the test controls. The real Wasm verifier is used only where the timing is irrelevant.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createConnection } from 'node:net';

import { startDevPool } from '../server.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitUntil(fn, { timeoutMs = 8000, everyMs = 20, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await fn()) return true;
    if (Date.now() > deadline) return false;
    await sleep(everyMs);
  }
}

/**
 * A verifier shaped like the coming native helper: verify() returns a promise that is resolved by
 * NOTHING except beginClose(). If shutdown does not initiate cancellation before draining, the
 * drain can never finish.
 */
function childShapedVerifier({ failClose = false } = {}) {
  // Cancellation carries `cancelled: true`, exactly as the real verifiers do (verifier.mjs's
  // VerifierCancelledError and native_helper.mjs's HelperFaultError both set it). This is not a
  // convenience for the test: the session distinguishes "we asked this to stop" -- which must
  // reach a client that is being disconnected anyway as SILENCE -- from "the child died", which
  // must be reported. A fake that dropped the flag would be modelling a verifier the pool does
  // not have.
  const cancellation = () => Object.assign(new Error('verifier cancelled'), { cancelled: true });
  const pending = new Set();
  let closing = false;
  let released = false;
  const state = { beginCloseCalls: 0, closeCalls: 0, forceCloseCalls: 0, verifyCalls: 0 };
  return {
    state,
    hashCalls: 0,
    wasmHeapBytes: () => 48_562_176,
    async verify() {
      state.verifyCalls++;
      if (closing) throw cancellation();
      // Settles ONLY via beginClose(). No unrelated gate the test can open instead.
      return new Promise((_resolve, reject) => { pending.add(reject); });
    },
    beginClose() {
      state.beginCloseCalls++;
      if (closing) return;
      closing = true;
      for (const reject of pending) reject(cancellation());
      pending.clear();
    },
    async close() {
      state.closeCalls++;
      this.beginClose();
      if (failClose && state.forceCloseCalls === 0) throw new Error('modelled teardown failure');
      released = true;
    },
    async forceClose() {
      state.forceCloseCalls++;
      this.beginClose();
      released = true;
    },
    get closed() { return released; },
    get closing() { return closing; },
  };
}

// ---------------------------------------------------------------- A1

test('A1: close initiates verifier cancellation BEFORE draining operations', { timeout: 60_000 }, async (t) => {
  const fake = childShapedVerifier();
  const pool = await startDevPool({ port: 0, verifierFactory: async () => fake });
  let ws = null;
  t.after(() => { try { ws?.close(); } catch { /* gone */ } });
  t.after(() => pool.close().catch(() => {}));

  const got = [];
  ws = new WebSocket(pool.wsUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('open failed')); });
  ws.onmessage = (e) => got.push(JSON.parse(e.data));
  ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
  assert.ok(await waitUntil(() => got.some((m) => m.type === 'job'), { label: 'a job' }));
  const hello = got.find((m) => m.type === 'server_hello');
  const job = got.find((m) => m.type === 'job');
  ws.send(JSON.stringify({ type: 'start_request' }));
  assert.ok(await waitUntil(() => got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));

  got.length = 0;
  ws.send(JSON.stringify({
    type: 'submit_share', jobId: job.jobId, workerId: hello.workerId,
    nonce: pool.fixture.qualifyingNonce.toString(16).padStart(8, '0'),
  }));
  assert.ok(await waitUntil(() => fake.state.verifyCalls === 1, { label: 'the verify request' }));
  assert.equal(pool.pendingOperationCount, 1, 'the operation is admitted and cannot finish on its own');

  // The ONLY thing that can settle that request is beginClose(). If close() drains first, this
  // never resolves. A bounded outer race turns the old deadlock into a clear failure.
  const closed = await Promise.race([
    pool.close().then(() => 'closed', (e) => `rejected: ${e.message}`),
    sleep(6000).then(() => 'DEADLOCK: close never resolved'),
  ]);
  assert.equal(closed, 'closed', closed);
  assert.ok(fake.state.beginCloseCalls >= 1, 'cancellation was initiated');
  assert.equal(fake.closed, true, 'and final teardown completed');
  assert.equal(pool.pendingOperationCount, 0, 'every admitted operation settled');
  assert.equal(pool.verifierState, 'closed');

  await sleep(150);
  assert.equal(got.filter((m) => m.type === 'share_accepted').length, 0, 'no late accept');
  assert.equal(got.filter((m) => m.type === 'share_rejected').length, 0, 'and no late reject to a disposed client');
});

test('A1: shutdown does not wait forever for an initialization that never completes', { timeout: 60_000 }, async (t) => {
  let aborted = false;
  const pool = await startDevPool({
    port: 0,
    // A startup that only ever finishes by being aborted.
    verifierFactory: ({ signal }) => new Promise((_res, rej) => {
      signal.addEventListener('abort', () => { aborted = true; rej(new Error('startup aborted')); });
    }),
  });
  t.after(() => pool.close().catch(() => {}));

  pool.ensureVerifier().catch(() => {});
  await waitUntil(() => pool.verifierState === 'initializing', { label: 'initialization starting' });

  const outcome = await Promise.race([
    pool.close().then(() => 'closed', (e) => `rejected: ${e.message}`),
    sleep(6000).then(() => 'HUNG: close waited on a startup that never finishes'),
  ]);
  assert.equal(outcome, 'closed', outcome);
  assert.equal(aborted, true, 'the startup was aborted rather than awaited indefinitely');
  assert.equal(pool.verifierState, 'closed');
});

// ---------------------------------------------------------------- A2

test('A2: a failed teardown keeps the handle and allows a retry', { timeout: 60_000 }, async (t) => {
  const fake = childShapedVerifier({ failClose: true });
  const pool = await startDevPool({ port: 0, verifierFactory: async () => fake });
  t.after(() => pool.close().catch(() => {}));
  await pool.ensureVerifier();

  // The graceful close fails; escalation is attempted once and succeeds here.
  await pool.close();
  assert.equal(fake.state.closeCalls, 1);
  assert.equal(fake.state.forceCloseCalls, 1, 'escalation was attempted on the exact resource');
  assert.equal(fake.closed, true, 'and the resource really was released');
  assert.equal(pool.verifierState, 'closed');
});

test('A2: an unreleasable resource is reported, retained, and retryable', { timeout: 60_000 }, async (t) => {
  let allowRelease = false;
  let released = false;
  const stubborn = {
    hashCalls: 0,
    wasmHeapBytes: () => 48_562_176,
    async verify() { throw new Error('not used'); },
    beginClose() {},
    async close() { if (!allowRelease) throw new Error('child would not exit'); released = true; },
    async forceClose() { if (!allowRelease) throw new Error('escalation also failed'); released = true; },
    get closed() { return released; },
    get closing() { return true; },
  };
  const pool = await startDevPool({ port: 0, verifierFactory: async () => stubborn });
  t.after(() => pool.close().catch(() => {}));
  await pool.ensureVerifier();

  await assert.rejects(() => pool.close(), /shutdown could not be confirmed/);
  assert.equal(pool.verifierState, 'close_failed', 'an unconfirmed shutdown is not called closed');
  assert.equal(stubborn.closed, false);
  // THE HANDLE IS NOT DISCARDED. Production still owns it; no external test reference is needed.
  assert.equal(pool.retainedVerifier, stubborn, 'the pool still exposes the resource it owns');
  assert.match(pool.closeFailure.message, /child would not exit/);

  // A retry can finish the job once the underlying problem clears.
  allowRelease = true;
  await pool.retryClose();
  assert.equal(stubborn.closed, true, 'the retry released the resource');
  assert.equal(pool.verifierState, 'closed');
  assert.equal(pool.retainedVerifier, null);
});

test('A2: the verifier does not claim closed when release failed', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close().catch(() => {}));
  const v = await pool.ensureVerifier();
  assert.equal(v.closed, false);
  v.beginClose('test');
  assert.equal(v.closing, true, 'cancellation began');
  assert.equal(v.closed, false, 'but nothing is released yet');
  await v.close();
  assert.equal(v.closed, true, 'closed is only true after release is confirmed');
});

test('A2: verify() fails closed once cancellation has begun', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close().catch(() => {}));
  const v = await pool.ensureVerifier();
  v.beginClose('test cancellation');
  // The stable contract is the error TYPE, not the reason text the caller happened to pass.
  await assert.rejects(
    () => v.verify(0, pool.fixture.targetBytes),
    (err) => err.name === 'VerifierCancelledError' && err.cancelled === true,
  );
});

// ---------------------------------------------------------------- A3

test('A3: close waits for an in-flight async HTTP handler', { timeout: 60_000 }, async (t) => {
  let release;
  const gate = new Promise((r) => { release = r; });
  let entered = false;
  const pool = await startDevPool({
    port: 0,
    // A hook the production handler awaits before serving; models the async file read.
    beforeStaticRead: async () => { entered = true; await gate; },
  });
  t.after(() => pool.close().catch(() => {}));

  const request = fetch(`${pool.url}/`).catch(() => null);
  assert.ok(await waitUntil(() => entered, { label: 'the handler starting' }));
  assert.equal(pool.pendingHttpHandlerCount, 1, 'the pool owns the in-flight handler');

  let resolved = false;
  const closing = pool.close().then(() => { resolved = true; });
  await sleep(500);
  assert.equal(resolved, false, 'close must not resolve while an HTTP handler is still running');

  release();
  await closing;
  assert.equal(resolved, true);
  assert.equal(pool.pendingHttpHandlerCount, 0, 'the handler was drained');
  assert.equal(pool.verifierState, 'closed');
  await request;
});

test('A3: no new HTTP work is admitted once shutdown has begun', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close().catch(() => {}));
  await pool.close();
  assert.equal(pool.pendingHttpHandlerCount, 0);
  assert.equal(pool.httpServer.listening, false);
});

// ---------------------------------------------------------------- A4

test('A4: a throwing logger cannot defeat connection cleanup', { timeout: 60_000 }, async (t) => {
  const unhandled = [];
  const onUnhandled = (err) => unhandled.push(err);
  process.on('unhandledRejection', onUnhandled);
  t.after(() => process.off('unhandledRejection', onUnhandled));

  let logCalls = 0;
  const pool = await startDevPool({
    port: 0,
    log: () => { logCalls++; throw new Error('logger exploded'); },
    // Force the internal-error path that logs and then closes the connection.
    verifierFactory: async () => { throw new Error('verifier unavailable'); },
  });
  let ws = null;
  t.after(() => { try { ws?.close(); } catch { /* gone */ } });
  t.after(() => pool.close().catch(() => {}));

  const got = [];
  ws = new WebSocket(pool.wsUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('open failed')); });
  ws.onmessage = (e) => got.push(JSON.parse(e.data));
  ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
  await waitUntil(() => got.some((m) => m.type === 'job'), { label: 'a job' });
  // start_request drives ensureVerifier -> failure -> audit log (which throws).
  ws.send(JSON.stringify({ type: 'start_request' }));
  assert.ok(await waitUntil(() => got.some((m) => m.type === 'mining_unavailable'), { label: 'mining_unavailable' }),
    'the client is still told, even though the logger threw');
  assert.ok(logCalls > 0, 'the throwing logger really was called');

  // Shutdown still completes, and no unhandled rejection escaped.
  await pool.close();
  assert.equal(pool.verifierState, 'closed');
  await sleep(150);
  assert.deepEqual(unhandled.map((e) => e?.message), [], 'a throwing logger must not leak an unhandled rejection');
});
