import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import { attachWebSocketServer } from '../ws.mjs';

function connectedSocket() {
  const server = new EventEmitter();
  const socket = new EventEmitter();
  const writes = [];
  socket.writableLength = 0;
  socket.setNoDelay = () => {};
  socket.write = (bytes) => {
    writes.push(Buffer.from(bytes));
    socket.writableLength += Buffer.byteLength(bytes);
    return socket.writableLength < 16 * 1024;
  };
  socket.destroy = () => { socket.destroyed = true; socket.emit('close'); };
  let connection;
  const ws = attachWebSocketServer(server, {
    onConnection: (conn) => { connection = conn; },
  });
  server.emit('upgrade', {
    url: '/ws',
    method: 'GET',
    headers: {
      upgrade: 'websocket',
      connection: 'Upgrade',
      'sec-websocket-version': '13',
      'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
    },
  }, socket, Buffer.alloc(0));
  assert.ok(connection, 'handshake established a connection');
  return { socket, writes, connection, ws };
}

test('a slow reader cannot accumulate an unbounded outbound WebSocket queue', () => {
  const { socket, writes, connection, ws } = connectedSocket();
  let closed = 0;
  connection.onClosed(() => { closed++; });

  let accepted = 0;
  while (accepted < 100 && connection.sendText('x'.repeat(4000))) accepted++;
  assert.ok(accepted > 1, 'transient socket backpressure below the bound is allowed');
  assert.ok(accepted < 100, 'the slow client is disconnected before the queue grows without limit');
  assert.equal(connection.closed, true);
  assert.equal(socket.destroyed, true);
  assert.equal(closed, 1);
  assert.equal(ws.connections.size, 0);
  assert.ok(socket.writableLength <= 64 * 1024 + 125, 'only a bounded close frame may follow the capped queue');
  assert.equal(connection.sendText('later'), false, 'a closed client receives no further writes');
  assert.equal(writes.at(-1)[0] & 0x0f, 0x8, 'the last frame is the close frame');
});
