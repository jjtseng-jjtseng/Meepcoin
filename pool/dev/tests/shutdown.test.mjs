// Lifecycle-edge defects that must be closed before the pool owns a native child process:
//
//   * a peer that disappears with a plain TCP FIN;
//   * a close() that is not a completion barrier -- for a half-written HTTP request, for an
//     already-admitted verification, or for the verifier's own asynchronous teardown.
//
// The last three share one shape: close() returned while something the pool owns was still
// running. Survivable for a synchronous Wasm free; not survivable for a child process, so the
// barrier is established now.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createConnection } from 'node:net';

import { startDevPool } from '../server.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitUntil(fn, { timeoutMs = 8000, everyMs = 25, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await fn()) return true;
    if (Date.now() > deadline) return false;
    await sleep(everyMs);
  }
}

/** A real RFC 6455 upgrade over a raw socket, so the test controls exactly how it ends. */
function rawUpgrade(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    let data = '';
    const socket = createConnection({ host, port }, () => {
      socket.write(
        'GET /ws HTTP/1.1\r\n'
        + `Host: ${host}:${port}\r\n`
        + 'Upgrade: websocket\r\nConnection: Upgrade\r\n'
        + 'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
      );
    });
    socket.on('data', (chunk) => {
      data += chunk.toString('binary');
      if (data.includes('\r\n\r\n')) resolve({ socket, upgraded: data.startsWith('HTTP/1.1 101') });
    });
    socket.on('error', () => {});
  });
}

// ---------------------------------------------------------------- raw TCP EOF

test('a peer that sends a plain TCP FIN is cleaned up', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close());

  const c = await rawUpgrade(pool.port);
  assert.equal(c.upgraded, true, 'the handshake succeeded');
  await sleep(150);
  assert.equal(pool.sessions.size, 1, 'a live session exists');

  // FIN only: no WebSocket CLOSE frame. The server socket becomes readableEnded but stays
  // writable and fires NEITHER 'close' NOR 'error', which is exactly why this leaked.
  c.socket.end();

  const cleaned = await waitUntil(() => pool.sessions.size === 0, { label: 'session cleanup' });
  assert.ok(cleaned, `session was retained after FIN (sessions=${pool.sessions.size})`);
  assert.equal(pool.sessions.size, 0, 'no retained session');
  c.socket.destroy();
});

test('repeated FIN peers do not accumulate sessions or job subscriptions', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close());

  for (let i = 0; i < 5; i++) {
    const c = await rawUpgrade(pool.port);
    await sleep(80);
    c.socket.end();
    await sleep(80);
    c.socket.destroy();
  }
  const cleaned = await waitUntil(() => pool.sessions.size === 0, { label: 'all sessions cleaned' });
  assert.ok(cleaned, `sessions accumulated: ${pool.sessions.size}`);

  // A retained session would still hold a job subscription and be written to on the next issue.
  assert.doesNotThrow(() => pool.jobs.issue());
  assert.equal(pool.sessions.size, 0);

  // And the pool still serves a later valid connection normally.
  const got = [];
  const ws = new WebSocket(pool.wsUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = () => reject(new Error('open failed')); });
  ws.onmessage = (e) => got.push(JSON.parse(e.data));
  ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
  assert.ok(await waitUntil(() => got.some((m) => m.type === 'job'), { label: 'a job for a later client' }));
  const closed = new Promise((r) => { ws.onclose = r; });
  ws.close();
  await closed;
});

test('a WebSocket CLOSE frame and a destroyed socket are still cleaned up', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close());

  const closeFrame = (() => {
    const h = Buffer.alloc(2);
    h[0] = 0x88;
    h[1] = 0x80 | 2;
    const mask = Buffer.from([1, 2, 3, 4]);
    const payload = Buffer.alloc(2);
    payload.writeUInt16BE(1000, 0);
    const masked = Buffer.alloc(2);
    for (let i = 0; i < 2; i++) masked[i] = payload[i] ^ mask[i & 3];
    return Buffer.concat([h, mask, masked]);
  })();

  for (const [label, act] of [['WS CLOSE frame', (s) => s.write(closeFrame)], ['destroy', (s) => s.destroy()]]) {
    const c = await rawUpgrade(pool.port);
    await sleep(120);
    act(c.socket);
    assert.ok(await waitUntil(() => pool.sessions.size === 0, { label }), `${label} left ${pool.sessions.size}`);
    c.socket.destroy();
  }
});

// ---------------------------------------------------------------- close() as a barrier

test('close() joins an initialization that is still running', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close());
  const init = pool.ensureVerifier();
  init.catch(() => {}); // the caller's promise; close owns the instance
  assert.equal(pool.verifierState, 'initializing', 'a real ~1s Wasm build is under way');

  await pool.close();

  // CONTRACT CHANGE, deliberately: shutdown no longer BLOCKS behind the ~1.4 s Wasm build, it
  // ABORTS it. Waiting was the old, weaker guarantee (and would be unacceptable for a child whose
  // startup may never finish). What must hold is that nothing survives: no verifier is left
  // allocated, the state is terminal, and it never moves afterwards.
  assert.equal(pool.verifierState, 'closed', 'a stable terminal state at close return');
  assert.equal(pool.verifier, null, 'no verifier survives an aborted initialization');
  assert.equal(pool.closing, true);

  const stateAtReturn = pool.verifierState;
  await sleep(2500);
  assert.equal(pool.verifierState, stateAtReturn, 'the state must not move after close resolved');
  assert.equal(pool.verifier, null, 'and no verifier may appear afterwards');
});

test('close() is single-flight: concurrent and repeated callers join one shutdown', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close());
  pool.ensureVerifier().catch(() => {});

  const a = pool.close();
  const b = pool.close();
  assert.equal(a, b, 'the same shutdown promise is handed to every caller');
  await Promise.all([a, b, pool.close()]);

  assert.equal(pool.verifierState, 'closed');
  assert.equal(pool.verifier, null);
  assert.equal(pool.sessions.size, 0);
  assert.equal(pool.httpServer.listening, false, 'the listener is closed');
  await pool.close(); // still idempotent afterwards
  assert.equal(pool.verifierState, 'closed');
});

test('ensureVerifier refuses once shutdown has begun', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close());
  const closing = pool.close();
  await assert.rejects(() => pool.ensureVerifier(), /shutting down/);
  await closing;
  await assert.rejects(() => pool.ensureVerifier(), /shutting down/);
  assert.equal(pool.verifierInitCount, 0, 'no initialization was ever started');
  assert.equal(pool.verifierState, 'closed');
});

test('close() with no verifier is still terminal and idempotent', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close());
  assert.equal(pool.verifierState, 'uninitialized');
  await pool.close();
  await pool.close();
  assert.equal(pool.verifierState, 'closed');
  assert.equal(pool.verifier, null);
  assert.equal(pool.httpServer.listening, false);
});

test('close() after a verifier is fully ready tears it down exactly once', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close()); // never leave a listener open if an assertion throws
  const v = await pool.ensureVerifier();
  assert.equal(pool.verifierState, 'ready');
  let closes = 0;
  const realClose = v.close.bind(v);
  v.close = async () => { closes++; return realClose(); };
  await pool.close();
  assert.equal(closes, 1, 'torn down exactly once');
  await pool.close();
  assert.equal(closes, 1, 'and not again on a repeated close');
  assert.equal(pool.verifierState, 'closed');
});


// ---------------------------------------------------------------- an uncooperative HTTP peer

test('a half-written HTTP request cannot hold shutdown open', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  const port = pool.port;
  let client = null;
  // Destroy the client even if an assertion throws, so a failure cannot wedge the runner.
  t.after(() => { try { client?.destroy(); } catch { /* already gone */ } });
  t.after(() => pool.close());

  client = createConnection({ host: '127.0.0.1', port });
  client.on('error', () => {});
  await new Promise((resolve, reject) => {
    client.once('connect', resolve);
    client.once('error', reject);
  });
  // A request line and a header name, and then nothing: no CRLFCRLF, ever. Node's own header
  // timeout is minutes away, so waiting for this peer is not a bounded shutdown.
  client.write('GET / HTTP/1.1\r\nHost:');
  await sleep(200);
  assert.equal(pool.openSocketCount, 1, 'the pool is tracking the raw socket it accepted');

  const t0 = Date.now();
  await pool.close();
  const elapsed = Date.now() - t0;

  assert.ok(elapsed < 2000, `close() took ${elapsed} ms; it must not wait on an uncooperative peer`);
  assert.equal(pool.openSocketCount, 0, 'no tracked socket survives shutdown');
  assert.equal(pool.httpServer.listening, false);
  assert.equal(pool.verifierState, 'closed');

  // The port is genuinely free again: rebinding it proves the listener really let go.
  const rebound = await startDevPool({ port, verifierMode: 'wasm' });
  try {
    assert.equal(rebound.port, port, 'the port can be rebound immediately');
  } finally {
    await rebound.close();
  }
});

// ---------------------------------------------------------------- an admitted verification

test('close() waits for a verification it already admitted', { timeout: 80_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  let ws = null;
  t.after(() => { try { ws?.close(); } catch { /* already closed */ } });
  t.after(() => pool.close());

  const got = [];
  ws = new WebSocket(pool.wsUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = () => reject(new Error('open failed')); });
  ws.onmessage = (e) => got.push(JSON.parse(e.data));

  ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
  assert.ok(await waitUntil(() => got.some((m) => m.type === 'job'), { label: 'a job' }));
  const hello = got.find((m) => m.type === 'server_hello');
  const job = got.find((m) => m.type === 'job');

  ws.send(JSON.stringify({ type: 'start_request' }));
  assert.ok(await waitUntil(() => pool.verifierState === 'ready', { label: 'the verifier', timeoutMs: 30_000 }));

  // Gate the REAL verify() so the operation is provably admitted and provably unfinished.
  let releaseVerify;
  const verifyGate = new Promise((r) => { releaseVerify = r; });
  let entered = false;
  const realVerify = pool.verifier.verify.bind(pool.verifier);
  pool.verifier.verify = async (...args) => {
    entered = true;
    await verifyGate;
    return realVerify(...args);
  };

  got.length = 0;
  const nonceHex = pool.fixture.qualifyingNonce.toString(16).padStart(8, '0');
  ws.send(JSON.stringify({ type: 'submit_share', jobId: job.jobId, nonce: nonceHex, workerId: hello.workerId }));
  assert.ok(await waitUntil(() => entered, { label: 'the verification starting' }));
  assert.equal(pool.pendingOperationCount, 1, 'the pool owns the admitted operation');

  let resolved = false;
  const closing = pool.close().then(() => { resolved = true; });
  await sleep(600);
  assert.equal(resolved, false, 'close() must NOT resolve while an admitted verification is running');
  assert.notEqual(pool.verifierState, 'closed', 'and must not claim a terminal state yet');
  assert.ok(pool.verifier !== null, 'the verifier must not be torn down under a running operation');

  releaseVerify();
  await closing;
  assert.equal(resolved, true);
  assert.equal(pool.pendingOperationCount, 0, 'every admitted operation settled before close returned');
  assert.equal(pool.verifierState, 'closed');
  assert.equal(pool.verifier, null);

  // The share was submitted into a pool that was shutting down: it must not have been accepted,
  // and nothing may be emitted after the session was disposed.
  await sleep(200);
  assert.equal(got.filter((m) => m.type === 'share_accepted').length, 0, 'no late acceptance');
  assert.equal(pool.stats.accepted, 0, 'and none recorded');
});

// ---------------------------------------------------------------- async verifier teardown

test('close() waits for the verifier asynchronous teardown', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close());
  const verifier = await pool.ensureVerifier();

  let releaseTeardown;
  const teardownGate = new Promise((r) => { releaseTeardown = r; });
  let started = 0;
  let finished = 0;
  const realClose = verifier.close.bind(verifier);
  // Model what a native child process shutdown will look like: genuinely asynchronous.
  verifier.close = async () => {
    started++;
    await teardownGate;
    finished++;
    return realClose();
  };

  let resolved = false;
  const closing = pool.close().then(() => { resolved = true; });
  await sleep(400);
  assert.equal(started, 1, 'teardown was started');
  assert.equal(finished, 0, 'and has not finished');
  assert.equal(resolved, false, 'close() must not resolve before teardown completes');
  assert.notEqual(pool.verifierState, 'closed', 'and must not claim success early');

  // A repeated caller while teardown is pending joins the SAME shutdown.
  assert.equal(pool.close(), pool.close(), 'still single-flight during teardown');

  releaseTeardown();
  await closing;
  assert.equal(finished, 1, 'teardown completed');
  assert.equal(started, 1, 'and ran exactly once despite repeated close() calls');
  assert.equal(pool.verifierState, 'closed');
  await pool.close();
  assert.equal(started, 1, 'a later close does not tear down again');
});

test('a verifier close() is idempotent and awaitable more than once', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close());
  const verifier = await pool.ensureVerifier();
  assert.equal(verifier.closed, false);
  await verifier.close();
  assert.equal(verifier.closed, true);
  await verifier.close();
  await Promise.all([verifier.close(), verifier.close()]);
  assert.equal(verifier.closed, true, 'repeated awaits are safe');
});

test('a failed teardown is reported, not papered over as a clean close', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  // close() is single-flight, so re-awaiting it here re-raises the SAME intentional rejection.
  // That is the behaviour under test; the cleanup hook must not turn it into a test failure.
  t.after(() => pool.close().catch(() => {}));
  const verifier = await pool.ensureVerifier();
  const realClose = verifier.close.bind(verifier);
  verifier.close = async () => { throw new Error('child process would not exit'); };

  await assert.rejects(() => pool.close(), /shutdown could not be confirmed/);
  assert.equal(pool.verifierState, 'close_failed',
    'an unconfirmed shutdown must NOT be labelled closed');
  await realClose(); // release the real resource for this test process
});
