// One complete local mining loop, end to end, with nothing stubbed on the wire:
//
//   real loopback server on an ephemeral port
//     -> real WebSocket handshake and framing (Node's own client, not our encoder)
//       -> real server-issued synthetic job
//         -> real MeepHash-W v2 Wasm search in a separate thread
//           -> submission of jobId + nonce + workerId only
//             -> real server-side recomputation
//               -> share_accepted
//                 -> everything shut down and proved shut down
//
// Bounded by construction: a 16-nonce window at roughly 17 ms per hash. Nothing here sleeps
// waiting for a timeout to expire.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createConnection } from 'node:net';

import { startDevPool } from '../server.mjs';
import { nonceToHex } from '../../../web-miner/lib/shared/target.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SEARCH_WORKER = resolve(__dirname, '../../../web-miner/tools/node_search_worker.mjs');

/** Resolve when `predicate` is satisfied by one of the messages received so far. */
function waitFor(messages, predicate, label, timeoutMs = 20_000) {
  return new Promise((resolvePromise, reject) => {
    const timer = setInterval(() => {
      const hit = messages.find(predicate);
      if (hit) {
        clearInterval(timer);
        clearTimeout(bail);
        resolvePromise(hit);
      }
    }, 10);
    const bail = setTimeout(() => {
      clearInterval(timer);
      reject(new Error(`timed out waiting for ${label}; saw ${JSON.stringify(messages.map((m) => m.type))}`));
    }, timeoutMs);
  });
}

/** True if something is listening on host:port. Used to prove the server really stopped. */
function isListening(host, port) {
  return new Promise((resolvePromise) => {
    const socket = createConnection({ host, port });
    const done = (value) => {
      socket.destroy();
      resolvePromise(value);
    };
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
    setTimeout(() => done(false), 1500);
  });
}

test('a browser-shaped client mines one accepted share against the local pool', { timeout: 85_000 }, async (t) => {
  const timeline = [];
  const mark = (label) => timeline.push(`${label} @${Date.now() - t0}ms`);
  const t0 = Date.now();

  // ---- server -------------------------------------------------------------
  // Single-build mode ON PURPOSE. This test is about the browser-shaped end-to-end path, and
  // pinning it here keeps `npm run test:slice` runnable on a machine that has not built the native
  // helper (which is deliberately not committed). The dual cross-check has its own end-to-end
  // acceptance test in pool/dev/tests/dual_verifier.test.mjs.
  const pool = await startDevPool({ host: '127.0.0.1', port: 0, nonceRange: 16, verifierMode: 'wasm' });
  mark('server listening');
  let socket = null;
  let worker = null;

  t.after(async () => {
    try { worker?.terminate(); } catch { /* already gone */ }
    try { socket?.close(); } catch { /* already closed */ }
    await pool.close();
  });

  assert.equal(pool.httpServer.address().address, '127.0.0.1', 'loopback only');
  // THE CONSENT BOUNDARY, server side: no Wasm module, no dataset, no hash before Start.
  assert.equal(pool.verifier, null, 'no verifier exists before anyone presses Start');
  assert.equal(pool.verifierState, 'uninitialized');
  assert.equal(pool.serverHashCalls, 0, 'and zero MeepHash-W calls');
  assert.equal(pool.verifierInitCount, 0);

  // ---- socket -------------------------------------------------------------
  const received = [];
  socket = new WebSocket(pool.wsUrl);
  const sentFrames = [];
  const send = (obj) => {
    sentFrames.push(obj);
    socket.send(JSON.stringify(obj));
  };
  socket.onmessage = (event) => received.push(JSON.parse(event.data));
  await new Promise((resolvePromise, reject) => {
    socket.onopen = resolvePromise;
    socket.onerror = () => reject(new Error('WebSocket failed to open'));
  });
  mark('websocket open');

  send({ type: 'client_hello', protocolVersion: 1, clientVersion: 'e2e/0' });
  const hello = await waitFor(received, (m) => m.type === 'server_hello', 'server_hello');
  const job = await waitFor(received, (m) => m.type === 'job', 'job');
  mark('job received');

  assert.match(hello.workerId, /^w-\d+-[0-9a-f]{8}$/);
  assert.match(hello.notice, /no coins or rewards/);
  assert.equal(job.algorithm, 'meephash-w-v2-frozen-synthetic');
  assert.equal(job.targetHexLE.length, 64);
  assert.equal(job.nonceRange, 16);
  assert.equal(job.targetBytes, undefined, 'the server keeps its target bytes to itself');
  assert.equal(pool.verifier, null, 'issuing a job still costs no Wasm and no hashing');
  assert.equal(pool.serverHashCalls, 0);

  // ---- the Start handshake -----------------------------------------------
  send({ type: 'start_request' });
  const readyMsg = await waitFor(received, (m) => m.type === 'mining_ready' || m.type === 'mining_unavailable', 'mining_ready');
  mark('server verifier ready');
  assert.equal(readyMsg.type, 'mining_ready');
  assert.ok(readyMsg.verifierWasmHeapBytes > 40 * 1024 * 1024, 'the pool discloses its own allocation');
  assert.equal(pool.verifierState, 'ready');
  assert.equal(pool.verifierInitCount, 1, 'exactly one server verifier');
  assert.equal(pool.serverHashCalls, 0, 'and it has still hashed nothing');

  // ---- hashing in its own thread, on the real Wasm ------------------------
  const workerEvents = [];
  const found = [];
  worker = new Worker(SEARCH_WORKER, { workerData: { job } });
  worker.on('message', (msg) => {
    workerEvents.push(msg);
    if (msg.ev === 'found') found.push(msg);
  });
  const workerFailure = new Promise((_, reject) => {
    worker.on('error', reject);
    worker.on('exit', (code) => {
      if (code !== 0 && code !== 1) reject(new Error(`search worker exited with code ${code}`));
    });
  });

  const ready = await Promise.race([waitFor(workerEvents, (m) => m.ev === 'ready', 'worker ready'), workerFailure]);
  mark('wasm dataset built in worker');
  assert.match(ready.wasmModulePath.replace(/\\/g, '/'), /meepow\/wasm\/meepow\.mjs$/,
    'the worker loaded the identity-pinned MeepHash-W build');
  assert.ok(ready.wasmHeapBytes > 40 * 1024 * 1024,
    `worker Wasm heap ${ready.wasmHeapBytes} B should hold the 32 MiB dataset + 8 MiB scratchpad`);

  const finished = await Promise.race([waitFor(workerEvents, (m) => m.ev === 'finished', 'worker finished'), workerFailure]);
  mark(`worker finished ${finished.hashes} hashes`);
  assert.equal(finished.hashes, 16, 'the worker scanned exactly the issued window');
  assert.equal(finished.wasmHashCalls, 16, 'and every one of those was a real Wasm hash');
  assert.equal(finished.exhausted, true);
  assert.equal(found.length, 1, 'exactly one nonce in the window meets the target');
  assert.equal(found[0].nonce, pool.fixture.qualifyingNonce,
    'client and server independently agree which nonce wins');
  assert.equal(found[0].hashHexLE, pool.fixture.qualifyingHashHexLE,
    'the client hash matches the committed v2 vector the server read its target from');
  assert.equal(pool.serverHashCalls, 0,
    'the client did all that hashing without the server doing any');

  // ---- submission ---------------------------------------------------------
  const before = pool.serverHashCalls;
  send({ type: 'submit_share', jobId: job.jobId, nonce: found[0].nonceHex, workerId: hello.workerId });
  const accepted = await waitFor(received, (m) => m.type === 'share_accepted' || m.type === 'share_rejected', 'a verdict');
  mark('share verdict received');

  assert.deepEqual(Object.keys(sentFrames.at(-1)).sort(), ['jobId', 'nonce', 'type', 'workerId'],
    'the submission carries no client hash');
  assert.equal(accepted.type, 'share_accepted');
  assert.equal(accepted.serverRecomputed, true);
  assert.equal(accepted.nonce, nonceToHex(pool.fixture.qualifyingNonce));
  assert.equal(accepted.hashHexLE, pool.fixture.qualifyingHashHexLE);
  assert.equal(accepted.hashHexLE, job.targetHexLE, 'accepted by the hash <= target equality case');
  const afterVerify = pool.serverHashCalls;
  assert.equal(afterVerify, before + 1,
    'the server recomputed the share exactly once from its own job context');
  assert.equal(pool.stats.accepted, 1);
  assert.equal(pool.stats.rejected, 0);

  // The demonstration is terminal: one accepted share ends it, and no fresh-looking job is
  // pushed, because every job here would repeat the same synthetic context.
  const done = await waitFor(received, (m) => m.type === 'demo_complete', 'demo_complete');
  assert.match(done.notice, /press Start again/i);
  assert.equal(pool.jobs.active(), null, 'the job is consumed');
  assert.equal(received.filter((m) => m.type === 'job').length, 1, 'exactly one job was ever issued');

  // ---- shutdown, and proof of shutdown ------------------------------------
  const exitCode = await new Promise((resolvePromise) => {
    worker.on('exit', resolvePromise);
    worker.terminate();
  });
  worker = null;
  mark(`worker exited (${exitCode})`);

  const closed = new Promise((resolvePromise) => { socket.onclose = resolvePromise; });
  socket.close();
  await closed;
  socket = null;
  mark('socket closed');

  await pool.close();
  assert.equal(await isListening('127.0.0.1', pool.port), false,
    'the port must be free: nothing is still listening');
  assert.equal(pool.sessions.size, 0, 'every per-connection session was disposed');
  mark('server closed');

  // Printed so the run is auditable rather than just green.
  console.log('  e2e evidence:');
  console.log('    server pre-Start     verifier=null, hashCalls=0, state=uninitialized');
  console.log(`    server verifier heap ${readyMsg.verifierWasmHeapBytes} B, created by start_request only`);
  console.log(`    wasm module          ${ready.wasmModulePath}`);
  console.log(`    worker wasm heap     ${ready.wasmHeapBytes} B (${(ready.wasmHeapBytes / 1048576).toFixed(1)} MiB)`);
  console.log(`    job id               ${job.jobId}  generation ${job.generation}`);
  console.log(`    target (LE hex)      ${job.targetHexLE}`);
  console.log(`    winning nonce        ${found[0].nonce} (${found[0].nonceHex})`);
  console.log(`    client hash   (LE)   ${found[0].hashHexLE}`);
  console.log(`    server recomputed    ${accepted.hashHexLE}`);
  // Captured at verification time: pool.close() has since freed the verifier, so reading the
  // live counter here would report 0 and misrepresent what happened.
  console.log(`    server hash calls    ${before} -> ${afterVerify} (exactly one for this share)`);
  console.log(`    client wasm hashes   ${finished.wasmHashCalls}`);
  console.log(`    timeline             ${timeline.join(' | ')}`);
});

test('the server survives a client that disconnects mid-session', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0 });
  t.after(() => pool.close());

  const socket = new WebSocket(pool.wsUrl);
  await new Promise((r, j) => { socket.onopen = r; socket.onerror = () => j(new Error('open failed')); });
  socket.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(pool.sessions.size, 1);

  const closed = new Promise((r) => { socket.onclose = r; });
  socket.close();
  await closed;
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(pool.sessions.size, 0, 'the session is disposed when the socket goes away');

  // And a fresh client can still connect and be served.
  const second = new WebSocket(pool.wsUrl);
  await new Promise((r, j) => { second.onopen = r; second.onerror = () => j(new Error('open failed')); });
  const got = [];
  second.onmessage = (e) => got.push(JSON.parse(e.data));
  second.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
  await waitFor(got, (m) => m.type === 'job', 'a job for the second client');
  second.close();
});

test('a WebSocket upgrade from a foreign Origin is refused', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0 });
  t.after(() => pool.close());

  // Node's WebSocket client sets no Origin, so the header is forged at the HTTP layer.
  const refused = await new Promise((resolvePromise) => {
    const socket = createConnection({ host: '127.0.0.1', port: pool.port }, () => {
      socket.write(
        'GET /ws HTTP/1.1\r\n'
        + `Host: 127.0.0.1:${pool.port}\r\n`
        + 'Upgrade: websocket\r\nConnection: Upgrade\r\n'
        + 'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
        + 'Origin: https://evil.example\r\n\r\n',
      );
    });
    let data = '';
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      if (data.includes('\r\n')) {
        socket.destroy();
        resolvePromise(data.split('\r\n')[0]);
      }
    });
    socket.on('error', () => resolvePromise('error'));
  });
  assert.match(refused, /403/, `expected a 403, got ${refused}`);
});
