// Bytes that arrive in the SAME TCP segment as the WebSocket upgrade request.
//
// Node hands those to the 'upgrade' handler as `head`. If the application's message and close
// handlers are installed AFTER that buffer is decoded, a coalesced client_hello is silently
// dropped and a coalesced CLOSE leaves a dead session behind. Both were real defects; these are
// real loopback TCP regressions for them, not decoder mocks.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createConnection } from 'node:net';
import { randomBytes } from 'node:crypto';

import { startDevPool } from '../server.mjs';
import { attachWebSocketServer } from '../ws.mjs';
import { createServer } from 'node:http';

/** One masked, final client frame, exactly as a browser would send it. */
function clientFrame(opcode, payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  const header = Buffer.alloc(body.length < 126 ? 2 : 4);
  header[0] = 0x80 | opcode;
  header[1] = 0x80 | (body.length < 126 ? body.length : 126);
  if (body.length >= 126) header.writeUInt16BE(body.length, 2);
  const mask = randomBytes(4);
  const masked = Buffer.alloc(body.length);
  for (let i = 0; i < body.length; i++) masked[i] = body[i] ^ mask[i & 3];
  return Buffer.concat([header, mask, masked]);
}

function closeFrame(code = 1000) {
  const payload = Buffer.alloc(2);
  payload.writeUInt16BE(code, 0);
  return clientFrame(0x8, payload);
}

function handshakeBytes(port) {
  return Buffer.from(
    'GET /ws HTTP/1.1\r\n'
    + `Host: 127.0.0.1:${port}\r\n`
    + 'Upgrade: websocket\r\nConnection: Upgrade\r\n'
    + 'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
    'utf8',
  );
}

/** Send the handshake and `extra` in ONE write, so `extra` lands in Node's upgrade head. */
function coalescedConnect(port, extra, { waitMs = 500 } = {}) {
  return new Promise((resolve) => {
    let data = '';
    const socket = createConnection({ host: '127.0.0.1', port }, () => {
      socket.write(Buffer.concat([handshakeBytes(port), extra]));
    });
    socket.on('data', (chunk) => { data += chunk.toString('binary'); });
    socket.on('error', () => {});
    setTimeout(() => {
      socket.destroy();
      resolve({ upgraded: data.startsWith('HTTP/1.1 101'), raw: data });
    }, waitMs);
  });
}

test('a client_hello coalesced with the upgrade is processed exactly once', async (t) => {
  const pool = await startDevPool({ port: 0 });
  t.after(() => pool.close());

  const hello = clientFrame(0x1, JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
  const { upgraded } = await coalescedConnect(pool.port, hello);
  assert.equal(upgraded, true, 'the handshake still succeeds');

  assert.equal(pool.sessions.size, 1, 'exactly one session');
  const [session] = pool.sessions;
  assert.equal(session.authorized, true, 'the coalesced hello must NOT be dropped');
  assert.match(session.workerId, /^w-\d+-[0-9a-f]{8}$/, 'and it must have been issued a workerId');
});

test('a coalesced hello is not processed twice', async (t) => {
  const pool = await startDevPool({ port: 0 });
  t.after(() => pool.close());

  const hello = clientFrame(0x1, JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
  await coalescedConnect(pool.port, hello);
  const [session] = pool.sessions;
  // A second hello on one connection is refused, so a double-processed head would show up as a
  // rejection here.
  assert.equal(session.rejected, 0, 'the hello was handled exactly once');
  assert.equal(session.accepted, 0);
});

test('a CLOSE coalesced with the upgrade leaves zero retained sessions', async (t) => {
  const pool = await startDevPool({ port: 0 });
  t.after(() => pool.close());

  const { upgraded } = await coalescedConnect(pool.port, closeFrame(), { waitMs: 700 });
  assert.equal(upgraded, true);
  assert.equal(pool.sessions.size, 0, 'a dead connection must not retain a session');
  assert.equal(pool.stats.connections, 1, 'the connection was seen, then cleaned up');
});

test('a hello followed by a CLOSE, all in one write, is handled then cleaned up', async (t) => {
  const pool = await startDevPool({ port: 0 });
  t.after(() => pool.close());

  const both = Buffer.concat([
    clientFrame(0x1, JSON.stringify({ type: 'client_hello', protocolVersion: 1 })),
    closeFrame(),
  ]);
  await coalescedConnect(pool.port, both, { waitMs: 700 });
  assert.equal(pool.sessions.size, 0, 'no retained session');
});

test('two individually legal large frames in one TCP delivery are both processed', async (t) => {
  const server = createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise((r) => server.close(r)));
  const received = [];
  attachWebSocketServer(server, {
    path: '/ws',
    onConnection: (conn) => conn.onMessage((payload) => received.push(payload.toString('utf8'))),
  });
  const first = 'a'.repeat(2200);
  const second = 'b'.repeat(2200);
  const both = Buffer.concat([clientFrame(0x1, first), clientFrame(0x1, second)]);
  assert.ok(both.length > 4096 + 14, 'the combined delivery exceeds the single-frame buffer cap');
  const { upgraded } = await coalescedConnect(server.address().port, both, { waitMs: 400 });
  assert.equal(upgraded, true);
  assert.deepEqual(received, [first, second]);
});

test('job listeners are released when a coalesced-CLOSE connection is cleaned up', async (t) => {
  const pool = await startDevPool({ port: 0 });
  t.after(() => pool.close());

  // Each live session registers one job listener. If a dead session were retained, its listener
  // would be too -- and would still receive (and try to send on) new jobs forever.
  for (let i = 0; i < 3; i++) await coalescedConnect(pool.port, closeFrame(), { waitMs: 400 });
  assert.equal(pool.sessions.size, 0);

  // Issuing a job must not throw or write to any dead connection.
  assert.doesNotThrow(() => pool.jobs.issue());
  assert.equal(pool.sessions.size, 0);
});

test('an oversized frame coalesced with the upgrade is refused, not buffered', async (t) => {
  const pool = await startDevPool({ port: 0 });
  t.after(() => pool.close());

  // Declares a 100000-byte payload in the header and sends nothing more.
  const header = Buffer.alloc(8);
  header[0] = 0x81;
  header[1] = 0xfe; // masked + 126 (16-bit length)
  header.writeUInt16BE(65535, 2);
  randomBytes(4).copy(header, 4);
  await coalescedConnect(pool.port, header, { waitMs: 500 });
  assert.equal(pool.sessions.size, 0, 'the connection is closed and its session released');
});

// ---------------------------------------------------------------- onClosed after close

test('a close handler registered after the connection died still fires', async () => {
  // Directly exercises the ordering guarantee ws.mjs now provides: the application may register
  // its cleanup at any point during onConnection, including after the head has already closed
  // the socket in a future refactor.
  const server = createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  let fired = 0;
  let sawClosedFlag = null;
  attachWebSocketServer(server, {
    path: '/ws',
    onConnection: (conn) => {
      conn.close(1000, 'immediately');
      sawClosedFlag = conn.closed;
      conn.onClosed(() => { fired++; });
    },
  });

  await coalescedConnect(port, Buffer.alloc(0), { waitMs: 400 });
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(sawClosedFlag, true, 'the connection really was already closed');
  assert.equal(fired, 1, 'a late-registered close handler must still run exactly once');
  await new Promise((r) => server.close(r));
});

test('an onConnection that throws closes the socket instead of leaking it', async () => {
  const server = createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  const ws = attachWebSocketServer(server, {
    path: '/ws',
    onConnection: () => { throw new Error('application setup failed'); },
  });

  await coalescedConnect(port, clientFrame(0x1, '{"type":"ping"}'), { waitMs: 400 });
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(ws.connections.size, 0, 'a connection the application could not set up is closed');
  await new Promise((r) => server.close(r));
});
