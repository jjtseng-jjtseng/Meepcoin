// The hand-written RFC 6455 frame layer. Because this replaces a library, its refusals are
// tested directly rather than only through the server.

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { decodeFrames, encodeFrame, encodeCloseFrame, computeAcceptKey, OPCODE, CLOSE } from '../ws.mjs';

const MAX = 4096;

/** Build a client->server frame the way a browser does: masked, single, final. */
function clientFrame(opcode, payload, { masked = true, fin = true, rsv = 0, forceLen = null } = {}) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  const len = forceLen ?? body.length;
  let header;
  if (len < 126 && forceLen === null) {
    header = Buffer.alloc(2);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeUInt32BE(Math.floor(len / 2 ** 32), 2);
    header.writeUInt32BE(len >>> 0, 6);
  }
  header[0] = (fin ? 0x80 : 0) | (rsv << 4) | opcode;
  if (!masked) return Buffer.concat([header, body]);
  header[1] |= 0x80;
  const mask = randomBytes(4);
  const masked_ = Buffer.allocUnsafe(body.length);
  for (let i = 0; i < body.length; i++) masked_[i] = body[i] ^ mask[i & 3];
  return Buffer.concat([header, mask, masked_]);
}

test('the handshake accept key matches RFC 6455 section 1.3', () => {
  assert.equal(computeAcceptKey('dGhlIHNhbXBsZSBub25jZQ=='), 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
});

test('decodes a masked text frame', () => {
  const { frames, error, rest } = decodeFrames(clientFrame(OPCODE.TEXT, '{"type":"ping"}'), MAX);
  assert.equal(error, null);
  assert.equal(frames.length, 1);
  assert.equal(frames[0].opcode, OPCODE.TEXT);
  assert.equal(frames[0].payload.toString('utf8'), '{"type":"ping"}');
  assert.equal(rest.length, 0);
});

test('decodes several frames arriving in one TCP chunk', () => {
  const buf = Buffer.concat([
    clientFrame(OPCODE.TEXT, 'one'),
    clientFrame(OPCODE.TEXT, 'two'),
    clientFrame(OPCODE.PING, 'p'),
  ]);
  const { frames, error } = decodeFrames(buf, MAX);
  assert.equal(error, null);
  assert.deepEqual(frames.map((f) => f.opcode), [OPCODE.TEXT, OPCODE.TEXT, OPCODE.PING]);
  assert.equal(frames[1].payload.toString('utf8'), 'two');
});

test('holds an incomplete frame instead of misreading it', () => {
  const whole = clientFrame(OPCODE.TEXT, 'hello world');
  for (let cut = 1; cut < whole.length; cut++) {
    const { frames, error, rest } = decodeFrames(whole.subarray(0, cut), MAX);
    assert.equal(error, null, `cut at ${cut} must not error`);
    assert.equal(frames.length, 0, `cut at ${cut} must yield no frame`);
    assert.equal(rest.length, cut, 'the partial bytes are kept for the next chunk');
  }
  // The same bytes reassembled decode correctly.
  assert.equal(decodeFrames(whole, MAX).frames[0].payload.toString('utf8'), 'hello world');
});

test('decodes the 126-byte extended-length form', () => {
  const payload = 'x'.repeat(300);
  const { frames, error } = decodeFrames(clientFrame(OPCODE.TEXT, payload), MAX);
  assert.equal(error, null);
  assert.equal(frames[0].payload.length, 300);
});

test('an unmasked client frame is a protocol error (RFC 6455 5.1)', () => {
  const { error } = decodeFrames(clientFrame(OPCODE.TEXT, 'hi', { masked: false }), MAX);
  assert.equal(error.code, CLOSE.PROTOCOL_ERROR);
  assert.match(error.reason, /not masked/);
});

test('reserved bits set is a protocol error', () => {
  const { error } = decodeFrames(clientFrame(OPCODE.TEXT, 'hi', { rsv: 4 }), MAX);
  assert.equal(error.code, CLOSE.PROTOCOL_ERROR);
  assert.match(error.reason, /reserved/);
});

test('fragmented frames are refused rather than reassembled', () => {
  const { error } = decodeFrames(clientFrame(OPCODE.TEXT, 'part', { fin: false }), MAX);
  assert.equal(error.code, CLOSE.UNSUPPORTED_DATA);
  assert.match(error.reason, /fragmented/);
});

test('binary and continuation opcodes are refused', () => {
  for (const opcode of [0x0, 0x2, 0x3, 0xb, 0xf]) {
    const { error } = decodeFrames(clientFrame(opcode, 'x'), MAX);
    assert.equal(error.code, CLOSE.UNSUPPORTED_DATA, `opcode 0x${opcode.toString(16)}`);
  }
});

test('an oversized payload is refused from its header, before the body is buffered', () => {
  // Declares 100000 bytes but sends none: the decoder must reject on the declared length alone.
  const header = clientFrame(OPCODE.TEXT, Buffer.alloc(0), { forceLen: 100000 });
  const { error, frames } = decodeFrames(header, MAX);
  assert.equal(frames.length, 0);
  assert.equal(error.code, CLOSE.MESSAGE_TOO_BIG);
  assert.match(error.reason, /100000 > 4096/);
});

test('a 64-bit length with a non-zero high word is refused', () => {
  const header = Buffer.alloc(14);
  header[0] = 0x81;
  header[1] = 0xff; // masked + 127
  header.writeUInt32BE(1, 2); // high word non-zero
  header.writeUInt32BE(0, 6);
  const { error } = decodeFrames(header, MAX);
  assert.equal(error.code, CLOSE.MESSAGE_TOO_BIG);
});

test('a payload exactly at the cap is accepted; one byte more is refused', () => {
  const ok = clientFrame(OPCODE.TEXT, Buffer.alloc(MAX, 0x61));
  assert.equal(decodeFrames(ok, MAX).error, null);
  assert.equal(decodeFrames(ok, MAX).frames[0].payload.length, MAX);

  const tooBig = clientFrame(OPCODE.TEXT, Buffer.alloc(MAX + 1, 0x61));
  assert.equal(decodeFrames(tooBig, MAX).error.code, CLOSE.MESSAGE_TOO_BIG);
});

test('an over-long control frame is a protocol error', () => {
  const { error } = decodeFrames(clientFrame(OPCODE.PING, Buffer.alloc(126)), MAX);
  assert.equal(error.code, CLOSE.PROTOCOL_ERROR);
  assert.match(error.reason, /control frame too long/);
});

test('frames decoded before a bad one are still returned, and the rest is not resynchronised', () => {
  const buf = Buffer.concat([clientFrame(OPCODE.TEXT, 'good'), clientFrame(OPCODE.TEXT, 'bad', { masked: false })]);
  const { frames, error } = decodeFrames(buf, MAX);
  assert.equal(frames.length, 1);
  assert.equal(frames[0].payload.toString('utf8'), 'good');
  assert.equal(error.code, CLOSE.PROTOCOL_ERROR);
});

test('server frames are final and unmasked, with the right length form', () => {
  const short = encodeFrame(OPCODE.TEXT, 'hi');
  assert.equal(short[0], 0x81, 'FIN + text');
  assert.equal(short[1], 2, 'unmasked, length 2');

  const medium = encodeFrame(OPCODE.TEXT, 'x'.repeat(200));
  assert.equal(medium[1], 126);
  assert.equal(medium.readUInt16BE(2), 200);

  const large = encodeFrame(OPCODE.TEXT, 'x'.repeat(70000));
  assert.equal(large[1], 127);
  assert.equal(large.readUInt32BE(2), 0);
  assert.equal(large.readUInt32BE(6), 70000);
});

test('close frames carry a big-endian code and a bounded reason', () => {
  const f = encodeCloseFrame(CLOSE.MESSAGE_TOO_BIG, 'x'.repeat(500));
  const payloadLen = f[1] & 0x7f;
  assert.ok(payloadLen <= 125, 'a close frame must stay a valid control frame');
  assert.equal(f.readUInt16BE(2), 1009);
});
