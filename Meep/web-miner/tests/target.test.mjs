// 32-byte little-endian target comparison: the one rule both the browser and the pool obey.
// Cross-checked against an independent BigInt implementation over random inputs.

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import {
  meetsTargetLE,
  leBytesToBigInt,
  bytesToHex,
  hexToBytes,
  nonceToHex,
} from '../lib/shared/target.js';

const ZERO = new Uint8Array(32);
const MAX = new Uint8Array(32).fill(0xff);

/** Little-endian 32-byte encoding of a BigInt. */
function le(v) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

test('exact equality passes (meepow/src/target.hpp: "exactly equal passes")', () => {
  const t = le(0x0123456789abcdefn * 12345n);
  assert.equal(meetsTargetLE(t, t), true);
  assert.equal(meetsTargetLE(ZERO, ZERO), true);
  assert.equal(meetsTargetLE(MAX, MAX), true);
});

test('one unit below the target passes, one unit above fails', () => {
  const target = le((1n << 200n) + 42n);
  assert.equal(meetsTargetLE(le((1n << 200n) + 41n), target), true, 'target-1 must pass');
  assert.equal(meetsTargetLE(le((1n << 200n) + 43n), target), false, 'target+1 must fail');
});

test('boundary carries across limb edges', () => {
  // 2^64-1 -> 2^64 crosses the first 64-bit limb; 2^192 crosses into the most significant one.
  for (const edge of [1n << 64n, 1n << 128n, 1n << 192n]) {
    const target = le(edge);
    assert.equal(meetsTargetLE(le(edge - 1n), target), true, `${edge}-1 must pass`);
    assert.equal(meetsTargetLE(le(edge), target), true, `${edge} must pass by equality`);
    assert.equal(meetsTargetLE(le(edge + 1n), target), false, `${edge}+1 must fail`);
  }
});

test('all-zero target accepts only the all-zero hash', () => {
  assert.equal(meetsTargetLE(ZERO, ZERO), true);
  assert.equal(meetsTargetLE(le(1n), ZERO), false);
  assert.equal(meetsTargetLE(MAX, ZERO), false);
});

test('all-0xff target accepts every hash', () => {
  assert.equal(meetsTargetLE(ZERO, MAX), true);
  assert.equal(meetsTargetLE(MAX, MAX), true);
  assert.equal(meetsTargetLE(le((1n << 255n) + 7n), MAX), true);
});

test('most-significant byte dominates (little-endian, not big-endian)', () => {
  // If the comparison read these big-endian, the verdicts would invert.
  const hash = new Uint8Array(32);
  hash[0] = 0xff; // least significant byte
  const target = new Uint8Array(32);
  target[31] = 0x01; // most significant byte
  assert.equal(meetsTargetLE(hash, target), true);
  assert.equal(meetsTargetLE(target, hash), false);
});

test('agrees with an independent BigInt comparison on 2000 random pairs', () => {
  for (let i = 0; i < 2000; i++) {
    const h = new Uint8Array(randomBytes(32));
    const t = new Uint8Array(randomBytes(32));
    const expected = leBytesToBigInt(h) <= leBytesToBigInt(t);
    assert.equal(meetsTargetLE(h, t), expected, `mismatch at iteration ${i}`);
  }
});

test('agrees with BigInt on near-miss pairs that differ in one byte', () => {
  for (let i = 0; i < 32; i++) {
    for (const delta of [-1, 1]) {
      const t = new Uint8Array(randomBytes(32));
      t[i] = 0x80;
      const h = Uint8Array.from(t);
      h[i] = 0x80 + delta;
      assert.equal(meetsTargetLE(h, t), leBytesToBigInt(h) <= leBytesToBigInt(t), `byte ${i} delta ${delta}`);
    }
  }
});

test('rejects wrongly sized inputs instead of guessing', () => {
  assert.throws(() => meetsTargetLE(new Uint8Array(31), ZERO), RangeError);
  assert.throws(() => meetsTargetLE(ZERO, new Uint8Array(33)), RangeError);
});

test('hex round-trips in little-endian storage order', () => {
  const bytes = new Uint8Array(randomBytes(32));
  assert.deepEqual(hexToBytes(bytesToHex(bytes)), bytes);
  const known = new Uint8Array([0x0e, 0x81, 0x9d, 0xd2]);
  assert.equal(bytesToHex(known), '0e819dd2', 'index 0 must be the first hex pair');
});

test('hex parsing is strict', () => {
  assert.throws(() => hexToBytes('abc'), RangeError);      // odd length
  assert.throws(() => hexToBytes('AB'), RangeError);       // uppercase
  assert.throws(() => hexToBytes('zz'), RangeError);       // not hex
  assert.throws(() => hexToBytes(42), TypeError);
});

test('nonces encode as exactly 8 lowercase hex chars (pool/protocol/pool_message.hpp)', () => {
  assert.equal(nonceToHex(0), '00000000');
  assert.equal(nonceToHex(15), '0000000f');
  assert.equal(nonceToHex(0xffffffff), 'ffffffff');
  assert.throws(() => nonceToHex(-1), RangeError);
  assert.throws(() => nonceToHex(0x1_0000_0000), RangeError);
  assert.throws(() => nonceToHex(1.5), RangeError);
});
