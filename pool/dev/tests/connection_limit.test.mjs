// Raw TCP admission is bounded before any HTTP request or WebSocket/session work. This is
// intentionally tested with peers that send no bytes: they model the resource-exhaustion shape
// that an HTTP-only or WebSocket-only limit would miss.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createConnection } from 'node:net';
import { once } from 'node:events';

import { startDevPool } from '../server.mjs';
import { availablePort } from './available_port.mjs';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitUntil(predicate, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    if (predicate()) return;
    await sleep(10);
  }
  assert.fail('timed out waiting for socket state');
}

async function openRaw(port) {
  const socket = createConnection({ host: '127.0.0.1', port });
  socket.on('error', () => {});
  await once(socket, 'connect');
  return socket;
}

async function expectClosed(socket, timeoutMs = 3000) {
  if (socket.closed || socket.destroyed) return;
  await Promise.race([
    once(socket, 'close'),
    sleep(timeoutMs).then(() => assert.fail('socket stayed open past its deadline')),
  ]);
}

test('invalid raw-connection limits fail before listening', async () => {
  const port = await availablePort();
  for (const value of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '2', 1025]) {
    await assert.rejects(
      () => startDevPool({ port, limits: { maxConnections: value } }),
      /limits\.maxConnections must be a safe integer from 1 through 1024/,
      `must refuse ${String(value)}`,
    );
  }

  // Every refusal happened before listen(): the exact fixed port remains available.
  const probe = createServer();
  await new Promise((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(port, '127.0.0.1', resolve);
  });
  await new Promise((resolve) => probe.close(resolve));
});

test('raw TCP cap refuses overflow before HTTP or WebSocket work and frees capacity', async () => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm', limits: { maxConnections: 2 } });
  const clients = [];
  try {
    const first = await openRaw(pool.port);
    const second = await openRaw(pool.port);
    clients.push(first, second);
    await waitUntil(() => pool.openSocketCount === 2);

    const overflow = await openRaw(pool.port);
    clients.push(overflow);
    await expectClosed(overflow);

    assert.equal(pool.maxConnections, 2);
    assert.equal(pool.openSocketCount, 2, 'overflow was never admitted');
    assert.equal(pool.stats.connectionRefusals, 1);
    assert.equal(pool.stats.connections, 0, 'no WebSocket session was constructed');
    assert.equal(pool.stats.requests.length, 0, 'no HTTP request was parsed');
    assert.equal(pool.verifierInitCount, 0, 'no hashing resource was constructed');

    first.destroy();
    await waitUntil(() => pool.openSocketCount === 1);

    const replacement = await openRaw(pool.port);
    clients.push(replacement);
    await waitUntil(() => pool.openSocketCount === 2);
    await sleep(50);
    assert.equal(replacement.destroyed, false, 'released capacity admits one replacement');
    assert.equal(pool.stats.connectionRefusals, 1, 'admission did not count as a refusal');

    await pool.close();
    await Promise.all(clients.map((socket) => expectClosed(socket)));
    assert.equal(pool.openSocketCount, 0, 'shutdown drained every admitted raw socket');
  } finally {
    for (const socket of clients) socket.destroy();
    await pool.close().catch(() => {});
  }
});

test('an unfinished HTTP peer expires, while an upgraded mining socket stays live',
  { timeout: 20_000 }, async () => {
    const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
    const raw = await openRaw(pool.port);
    // A partial request exercises the absolute header deadline rather than an ordinary idle
    // keep-alive timeout. It must never reach the request handler.
    raw.write('GET / HTTP/1.1\r\nHost: 127.0.0.1');

    const ws = new WebSocket(pool.wsUrl);
    await new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = () => reject(new Error('WebSocket upgrade failed'));
    });

    try {
      await expectClosed(raw, 8_000);
      assert.equal(pool.stats.requests.length, 0, 'the incomplete request was never handled');
      assert.equal(pool.stats.incompleteRequestTimeouts, 1, 'the pool-owned deadline fired once');
      assert.equal(pool.sessions.size, 1, 'the upgraded connection has its session');

      // Longer than the five-second pre-request deadline. It must not become a hidden
      // mining-session timeout after a successful upgrade.
      await sleep(5_500);
      assert.equal(ws.readyState, WebSocket.OPEN, 'an upgraded mining connection remains live');
      assert.equal(pool.verifierInitCount, 0, 'an idle connection starts no hashing resource');
    } finally {
      raw.destroy();
      const closed = new Promise((resolve) => { ws.onclose = resolve; });
      ws.close();
      await closed;
      await pool.close();
    }
  });
