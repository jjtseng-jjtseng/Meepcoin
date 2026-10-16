// A deliberately minimal RFC 6455 server for the local development pool.
//
// Why hand-written instead of a dependency: this repository has no JavaScript dependencies at
// all, and the surface this slice needs is tiny -- small unfragmented text frames from a browser
// on loopback, capped at the 4096 bytes that pool/protocol/pool_message.hpp already specifies.
// Writing it out keeps the slice installable with nothing but Node, keeps every byte reviewable,
// and lets the frame decoder be unit-tested directly. If the protocol later needs
// fragmentation, permessage-deflate or compression, adopt a maintained library (`ws`) rather
// than growing this file.
//
// It is STRICT and fails closed. Anything it does not need is a protocol error with a close
// code, not a best-effort guess:
//   * client frames must be masked            (RFC 6455 5.1)
//   * reserved bits must be zero
//   * only text, close, ping and pong frames are accepted; binary and continuation are refused
//   * fragmented frames are refused
//   * control frames must be final and <= 125 bytes
//   * anything over the message cap closes with 1009 from its declared length, without
//     accumulating an oversized partial payload across TCP deliveries

import { createHash } from 'node:crypto';

export const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export const OPCODE = Object.freeze({ TEXT: 0x1, CLOSE: 0x8, PING: 0x9, PONG: 0xa });

export const CLOSE = Object.freeze({
  NORMAL: 1000,
  GOING_AWAY: 1001,
  PROTOCOL_ERROR: 1002,
  UNSUPPORTED_DATA: 1003,
  POLICY_VIOLATION: 1008,
  MESSAGE_TOO_BIG: 1009,
  INTERNAL_ERROR: 1011,
});

// A peer that stops reading must not turn recurring job broadcasts into an unbounded Node
// writable queue. This is a connection-local memory bound, not a per-message protocol limit.
const MAX_OUTBOUND_BUFFER_BYTES = 64 * 1024;

/** Sec-WebSocket-Accept for a client key (RFC 6455 4.2.2). */
export function computeAcceptKey(secWebSocketKey) {
  return createHash('sha1').update(secWebSocketKey + WS_GUID).digest('base64');
}

/** Encode one final, unmasked server->client frame. */
export function encodeFrame(opcode, payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload ?? '', 'utf8');
  const len = body.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeUInt32BE(0, 2);
    header.writeUInt32BE(len, 6);
  }
  header[0] = 0x80 | (opcode & 0x0f); // FIN = 1
  return Buffer.concat([header, body]);
}

export function encodeCloseFrame(code, reason = '') {
  const reasonBuf = Buffer.from(String(reason).slice(0, 100), 'utf8');
  const payload = Buffer.alloc(2 + reasonBuf.length);
  payload.writeUInt16BE(code, 0);
  reasonBuf.copy(payload, 2);
  return encodeFrame(OPCODE.CLOSE, payload);
}

/**
 * Decode as many complete client->server frames as `buffer` holds.
 *
 * Returns `{ frames, rest, error }`. `error` is `{ code, reason }` and, when set, the caller must
 * close the connection: the decoder does not try to resynchronise a stream it has rejected.
 */
export function decodeFrames(buffer, maxPayloadBytes) {
  const frames = [];
  let offset = 0;

  for (;;) {
    if (buffer.length - offset < 2) break;

    const b0 = buffer[offset];
    const b1 = buffer[offset + 1];
    const fin = (b0 & 0x80) !== 0;
    const rsv = b0 & 0x70;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let payloadLen = b1 & 0x7f;
    let cursor = offset + 2;

    if (rsv !== 0) {
      return { frames, rest: buffer.subarray(offset), error: { code: CLOSE.PROTOCOL_ERROR, reason: 'reserved bits set' } };
    }
    if (!masked) {
      // RFC 6455 5.1: a server MUST close on an unmasked client frame.
      return { frames, rest: buffer.subarray(offset), error: { code: CLOSE.PROTOCOL_ERROR, reason: 'client frame not masked' } };
    }
    if (opcode !== OPCODE.TEXT && opcode !== OPCODE.CLOSE && opcode !== OPCODE.PING && opcode !== OPCODE.PONG) {
      return { frames, rest: buffer.subarray(offset), error: { code: CLOSE.UNSUPPORTED_DATA, reason: `opcode 0x${opcode.toString(16)} not supported` } };
    }
    if (!fin) {
      return { frames, rest: buffer.subarray(offset), error: { code: CLOSE.UNSUPPORTED_DATA, reason: 'fragmented frames not supported' } };
    }
    const isControl = opcode === OPCODE.CLOSE || opcode === OPCODE.PING || opcode === OPCODE.PONG;

    if (payloadLen === 126) {
      if (buffer.length - cursor < 2) break;
      payloadLen = buffer.readUInt16BE(cursor);
      cursor += 2;
    } else if (payloadLen === 127) {
      if (buffer.length - cursor < 8) break;
      const hi = buffer.readUInt32BE(cursor);
      const lo = buffer.readUInt32BE(cursor + 4);
      cursor += 8;
      if (hi !== 0) {
        return { frames, rest: buffer.subarray(offset), error: { code: CLOSE.MESSAGE_TOO_BIG, reason: 'payload length exceeds limit' } };
      }
      payloadLen = lo;
    }

    if (isControl && payloadLen > 125) {
      return { frames, rest: buffer.subarray(offset), error: { code: CLOSE.PROTOCOL_ERROR, reason: 'control frame too long' } };
    }
    // The cap is checked against the DECLARED length, so an oversized message is refused from its
    // header and its body is never buffered.
    if (payloadLen > maxPayloadBytes) {
      return { frames, rest: buffer.subarray(offset), error: { code: CLOSE.MESSAGE_TOO_BIG, reason: `payload ${payloadLen} > ${maxPayloadBytes}` } };
    }

    if (buffer.length - cursor < 4) break;
    const mask = buffer.subarray(cursor, cursor + 4);
    cursor += 4;

    if (buffer.length - cursor < payloadLen) break;
    const payload = Buffer.allocUnsafe(payloadLen);
    for (let i = 0; i < payloadLen; i++) payload[i] = buffer[cursor + i] ^ mask[i & 3];
    cursor += payloadLen;

    frames.push({ opcode, payload });
    offset = cursor;
  }

  return { frames, rest: buffer.subarray(offset), error: null };
}

/** The most bytes a partial frame can legitimately occupy before its payload cap applies. */
export function maxFrameHeaderBytes() {
  return 14; // 2 + 8 extended length + 4 mask
}

/**
 * Attach a WebSocket endpoint to an existing http.Server.
 *
 * `isOriginAllowed(origin)` gates the handshake. Origin is a MINOR abuse control only: any
 * non-browser client can send whatever Origin it likes, so it is never treated as
 * authentication. See docs/LOCAL_BROWSER_MINER_SLICE.md.
 */
export function attachWebSocketServer(httpServer, {
  path = '/ws',
  maxMessageBytes = 4096,
  isOriginAllowed = () => true,
  onConnection,
}) {
  const connections = new Set();

  function onUpgrade(req, socket, head) {
    const reject = (status, message) => {
      socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      socket.destroy();
      void message;
    };

    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      return reject('400 Bad Request', 'bad url');
    }
    if (url.pathname !== path) return reject('404 Not Found', 'unknown ws path');
    if (req.method !== 'GET') return reject('405 Method Not Allowed', 'not GET');
    if (String(req.headers.upgrade || '').toLowerCase() !== 'websocket') return reject('400 Bad Request', 'not websocket');
    if (!String(req.headers.connection || '').toLowerCase().split(/\s*,\s*/).includes('upgrade')) {
      return reject('400 Bad Request', 'missing Connection: Upgrade');
    }
    if (String(req.headers['sec-websocket-version']) !== '13') return reject('400 Bad Request', 'bad version');
    const key = req.headers['sec-websocket-key'];
    if (typeof key !== 'string' || Buffer.from(key, 'base64').length !== 16) {
      return reject('400 Bad Request', 'bad Sec-WebSocket-Key');
    }
    if (!isOriginAllowed(req.headers.origin)) return reject('403 Forbidden', 'origin not allowed');

    socket.setNoDelay(true);
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n'
      + 'Upgrade: websocket\r\n'
      + 'Connection: Upgrade\r\n'
      + `Sec-WebSocket-Accept: ${computeAcceptKey(key)}\r\n\r\n`,
    );

    const conn = makeConnection(socket, maxMessageBytes);
    connections.add(conn);
    conn.onClosed(() => connections.delete(conn));

    // ORDER MATTERS. `head` holds bytes that arrived in the SAME TCP segment as the upgrade
    // request -- a browser or any client is free to coalesce the handshake with its first frame.
    // The application must therefore install its message and close handlers BEFORE those bytes
    // are decoded, or a coalesced client_hello is silently dropped and a coalesced CLOSE leaves a
    // dead session behind.
    try {
      onConnection(conn, req);
    } catch {
      // A connection the application could not set up must not be left half-open.
      conn.close(CLOSE.INTERNAL_ERROR, 'connection setup failed');
      return;
    }
    if (head && head.length) conn.feed(head);
  }

  httpServer.on('upgrade', onUpgrade);

  return {
    connections,
    closeAll(code = CLOSE.GOING_AWAY, reason = 'server shutting down') {
      for (const conn of [...connections]) conn.close(code, reason);
    },
  };
}

function makeConnection(socket, maxMessageBytes) {
  const maxBuffered = maxMessageBytes + maxFrameHeaderBytes();
  let buffer = Buffer.alloc(0);
  let closed = false;
  const handlers = { message: [], close: [] };

  function emit(name, arg) {
    for (const fn of handlers[name]) {
      try {
        fn(arg);
      } catch {
        // A handler that throws must not take down the connection loop or the server.
      }
    }
  }

  function destroy() {
    if (closed) return;
    closed = true;
    buffer = Buffer.alloc(0);
    socket.destroy();
    // Snapshot and clear, so cleanup runs exactly once even if destroy() races with itself via
    // the socket's own 'close'/'error' events.
    const toNotify = handlers.close.splice(0, handlers.close.length);
    for (const fn of toNotify) {
      try {
        fn();
      } catch {
        // a cleanup handler that throws must not take down the server
      }
    }
  }

  function close(code = CLOSE.NORMAL, reason = '') {
    if (closed) return;
    try {
      socket.write(encodeCloseFrame(code, reason));
    } catch {
      // socket already gone
    }
    destroy();
  }

  function feed(chunk) {
    if (closed) return;
    // TCP delivery boundaries are not WebSocket frame boundaries. A single data event (or the
    // upgrade head) may contain several legal frames whose *combined* size exceeds the cap.
    // Decode bounded slices so the cap applies to each partial frame, not the whole delivery.
    let offset = 0;
    while (offset < chunk.length && !closed) {
      const room = maxBuffered - buffer.length;
      if (room <= 0) {
        close(CLOSE.MESSAGE_TOO_BIG, 'buffered frame exceeds limit');
        return;
      }
      const end = Math.min(chunk.length, offset + room);
      const slice = chunk.subarray(offset, end);
      buffer = buffer.length ? Buffer.concat([buffer, slice]) : slice;
      offset = end;
      const { frames, rest, error } = decodeFrames(buffer, maxMessageBytes);
      buffer = Buffer.from(rest);
      for (const frame of frames) {
        if (closed) return;
        if (frame.opcode === OPCODE.TEXT) {
          emit('message', frame.payload);
        } else if (frame.opcode === OPCODE.PING) {
          try {
            socket.write(encodeFrame(OPCODE.PONG, frame.payload));
          } catch {
            destroy();
            return;
          }
        } else if (frame.opcode === OPCODE.CLOSE) {
          close(CLOSE.NORMAL, '');
          return;
        }
        // PONG frames are unsolicited keepalives; nothing to do.
      }
      if (error) {
        close(error.code, error.reason);
        return;
      }
    }
  }

  socket.on('data', feed);
  // 'end' is the one that matters and is easy to miss. An HTTP-upgraded socket is HALF-OPEN: a
  // peer that sends a plain TCP FIN without a WebSocket CLOSE frame makes the server socket
  // readableEnded, but it stays writable and fires NEITHER 'close' NOR 'error'. Without this
  // listener such a peer is retained forever -- its connection, its session and its job
  // subscriptions -- and they accumulate one per disconnect. Treating readable EOF as terminal
  // routes it into the same idempotent destroy() as every other ending.
  socket.on('end', destroy);
  socket.on('error', destroy);
  socket.on('close', destroy);

  return {
    socket,
    feed,
    get closed() {
      return closed;
    },
    sendText(text) {
      if (closed) return false;
      try {
        const frame = encodeFrame(OPCODE.TEXT, Buffer.from(text, 'utf8'));
        if (socket.writableLength + frame.length > MAX_OUTBOUND_BUFFER_BYTES) {
          close(CLOSE.POLICY_VIOLATION, 'outbound queue full');
          return false;
        }
        socket.write(frame);
        return true;
      } catch {
        destroy();
        return false;
      }
    },
    sendJson(obj) {
      return this.sendText(JSON.stringify(obj));
    },
    close,
    onMessage(fn) {
      handlers.message.push(fn);
    },
    onClosed(fn) {
      if (closed) {
        // Registering after the connection has already gone must still fire, or a late-installed
        // cleanup handler leaks its session. Scheduled rather than called inline so the caller is
        // not re-entered from inside its own registration.
        queueMicrotask(() => {
          try {
            fn();
          } catch {
            // a cleanup handler that throws must not escape
          }
        });
        return;
      }
      handlers.close.push(fn);
    },
  };
}
