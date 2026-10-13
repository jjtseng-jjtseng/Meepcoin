// 256-bit target arithmetic shared by the browser miner and the local development pool server.
//
// This is the ONE implementation of the comparison used on both sides of the wire, so the client
// and the server cannot silently disagree about what "meets the target" means. It mirrors
// meepow/src/target.hpp exactly: hashes and targets are 32-byte LITTLE-ENDIAN 256-bit integers,
// compared most-significant limb first, and an exactly-equal hash PASSES (spec §10).
//
// The server is still the only authority: the browser uses this to decide what is worth
// submitting, the server uses it to decide what is accepted.

export const HASH_BYTES = 32;

/** Bytes -> lowercase hex, in storage (little-endian) order. */
export function bytesToHex(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0');
  return s;
}

/** Strict lowercase-hex -> bytes. Throws on odd length, uppercase, or non-hex characters. */
export function hexToBytes(hex) {
  if (typeof hex !== 'string') throw new TypeError('hex must be a string');
  if (hex.length % 2 !== 0) throw new RangeError('hex length must be even');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const c0 = hex.charCodeAt(2 * i);
    const c1 = hex.charCodeAt(2 * i + 1);
    const h = hexNibble(c0);
    const l = hexNibble(c1);
    if (h < 0 || l < 0) throw new RangeError('hex must be lowercase 0-9a-f');
    out[i] = (h << 4) | l;
  }
  return out;
}

function hexNibble(code) {
  if (code >= 0x30 && code <= 0x39) return code - 0x30; // 0-9
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10; // a-f
  return -1;
}

/** True iff `hash` <= `target`, both 32-byte little-endian. Equality passes (meepow/src/target.hpp). */
export function meetsTargetLE(hash, target) {
  if (hash.length !== HASH_BYTES || target.length !== HASH_BYTES) {
    throw new RangeError('hash and target must both be 32 bytes');
  }
  // Little-endian storage: index 31 is the most significant byte.
  for (let i = HASH_BYTES - 1; i >= 0; i--) {
    if (hash[i] < target[i]) return true;
    if (hash[i] > target[i]) return false;
  }
  return true; // exactly equal passes
}

/**
 * True iff `a` >= `b`, both 32-byte little-endian 256-bit integers.
 *
 * The one place this matters: a share target must never be HARDER than the block target. Share
 * difficulty <= network difficulty means numerically shareTarget >= blockTarget, so every block is
 * also a share. The browser checks this before it allocates anything for a job that claims share
 * work, and refuses the job rather than searching a target it cannot justify.
 */
export function targetAtLeastLE(a, b) {
  if (a.length !== HASH_BYTES || b.length !== HASH_BYTES) {
    throw new RangeError('both targets must be 32 bytes');
  }
  for (let i = HASH_BYTES - 1; i >= 0; i--) {
    if (a[i] > b[i]) return true;
    if (a[i] < b[i]) return false;
  }
  return true;                       // equal is allowed: share difficulty may equal the network's
}

/** Reference-only: 32 little-endian bytes as a BigInt. Used to cross-check meetsTargetLE in tests. */
export function leBytesToBigInt(u8) {
  let v = 0n;
  for (let i = u8.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(u8[i]);
  return v;
}

/** 8 lowercase hex characters, as required by pool/protocol/pool_message.hpp. */
export function nonceToHex(nonce) {
  if (!Number.isInteger(nonce) || nonce < 0 || nonce > 0xffffffff) {
    throw new RangeError('nonce must be a uint32');
  }
  return nonce.toString(16).padStart(8, '0');
}
