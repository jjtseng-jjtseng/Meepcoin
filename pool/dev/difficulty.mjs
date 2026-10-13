// Exact difficulty -> 256-bit target conversion, mirroring the daemon's own rule.
//
// WHAT THE DAEMON ACTUALLY DOES, read from src/cryptonote_basic/difficulty.cpp in the committed
// daemon source. It does NOT compute a target and compare. It multiplies:
//
//   check_hash_64(hash, difficulty)   -- 256x64 multiply, passes iff nothing carries out of 256 bits
//   check_hash_128(hash, difficulty)  -- `hashVal * difficulty <= max256bit` for difficulty > 2^64
//   check_hash(hash, difficulty)      -- picks one of the two at the 2^64 boundary
//
// Both are the same predicate written twice: `hash * difficulty <= 2^256 - 1`. Dividing it out,
// that is exactly `hash <= floor((2^256 - 1) / difficulty)`, which is the target this module
// derives. meetsTargetLE() in web-miner/lib/shared/target.js then applies `hash <= target` with
// equality PASSING, which is the same boundary. targetsAgreeWithDaemonRule() below proves the
// equivalence rather than asserting it, and the tests exercise the exact boundary and off-by-one.
//
// WHY wide_difficulty AND NOT difficulty. get_block_template returns BOTH: `difficulty` is a
// uint64 and `wide_difficulty` is a hex string that carries the full 128-bit value. Reading the
// uint64 one through JSON gives a JavaScript Number, which silently rounds above 2^53 -- so a
// difficulty of 2^60 + 1 would become 2^60 and the derived target would be wrong. This module
// refuses the lossy path: it parses the wide string with BigInt and never falls back.

/** 2^256 - 1. The largest value a 256-bit hash can take, and the numerator of the target. */
export const MAX_256 = (1n << 256n) - 1n;

/** The daemon's own 64-bit boundary (difficulty.cpp `max64bit`). */
export const MAX_64 = (1n << 64n) - 1n;

export class DifficultyError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = 'DifficultyError';
    this.detail = detail ?? '';
  }
}

/**
 * Parse a daemon `wide_difficulty` into an exact BigInt.
 *
 * The daemon serialises it as a hex string, conventionally `0x`-prefixed. A plain decimal string
 * and a BigInt are also accepted because the mock transport and the committed block vectors use
 * them. A Number is accepted ONLY when it is a safe integer: above 2^53 the value has already been
 * rounded before this function can see it, and silently deriving a target from a rounded
 * difficulty is precisely the bug this refuses to have.
 */
export function parseWideDifficulty(value) {
  let v;
  if (typeof value === 'bigint') {
    v = value;
  } else if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new DifficultyError('difficulty must be an integer');
    if (!Number.isSafeInteger(value)) {
      throw new DifficultyError(
        'difficulty exceeds Number.MAX_SAFE_INTEGER; use the daemon\'s wide_difficulty string',
        { value },
      );
    }
    v = BigInt(value);
  } else if (typeof value === 'string') {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) {
      v = BigInt(s);
    } else if (/^(0|[1-9][0-9]*)$/.test(s)) {
      v = BigInt(s);
    } else {
      throw new DifficultyError('difficulty string must be 0x-hex or canonical decimal', { value });
    }
  } else {
    throw new DifficultyError('difficulty must be a bigint, safe-integer number, or string');
  }

  if (v <= 0n) throw new DifficultyError('difficulty must be a nonzero positive integer', { value });
  // A difficulty above 2^128-1 cannot come from this daemon: difficulty_type is a 128-bit
  // multiprecision integer. Refuse rather than derive a target for a value the chain cannot hold.
  if (v > (1n << 128n) - 1n) {
    throw new DifficultyError('difficulty exceeds the daemon\'s 128-bit difficulty_type', { value });
  }
  return v;
}

/**
 * The 256-bit target for `difficulty`: floor((2^256 - 1) / difficulty).
 *
 * Equivalent to the daemon's multiply-and-check-for-carry, proven by targetsAgreeWithDaemonRule().
 */
export function targetForDifficulty(difficulty) {
  const d = parseWideDifficulty(difficulty);
  return MAX_256 / d;
}

/** A 256-bit BigInt as exactly 32 LITTLE-ENDIAN bytes -- the storage order meepow uses. */
export function bigIntToLeBytes32(v) {
  if (typeof v !== 'bigint') throw new TypeError('value must be a bigint');
  if (v < 0n || v > MAX_256) throw new RangeError('value does not fit in 256 bits');
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/** 32 little-endian bytes back to a BigInt. */
export function leBytes32ToBigInt(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new RangeError('expected exactly 32 bytes');
  }
  let v = 0n;
  for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

/**
 * The full conversion a job needs: difficulty -> { difficulty, target, targetBytes, targetHexLE }.
 *
 * targetBytes is the 32 little-endian bytes the browser and the server both compare against, and
 * targetHexLE is those bytes as lowercase hex in the SAME storage order (hex(target[0]) first),
 * matching meepow/src/target.hpp and the committed vectors' `target_le_hex`.
 */
export function targetFromWideDifficulty(wideDifficulty) {
  const difficulty = parseWideDifficulty(wideDifficulty);
  const target = MAX_256 / difficulty;
  const targetBytes = bigIntToLeBytes32(target);
  let hex = '';
  for (let i = 0; i < 32; i++) hex += targetBytes[i].toString(16).padStart(2, '0');
  return { difficulty, target, targetBytes, targetHexLE: hex };
}

/**
 * The daemon's predicate, written directly: `hash * difficulty <= 2^256 - 1`.
 *
 * Present so the tests can assert that comparing against our derived target gives the SAME answer
 * as the daemon's multiply for every case they try, including both sides of the boundary. This is
 * a reference implementation for verification, not the hot path.
 */
export function daemonCheckHash(hashLeBytes, difficulty) {
  const h = leBytes32ToBigInt(hashLeBytes);
  const d = parseWideDifficulty(difficulty);
  return h * d <= MAX_256;
}

/**
 * True iff comparing `hashLeBytes` against the derived target agrees with the daemon's multiply.
 *
 * Both sides are computed here so a test can sweep values and assert agreement without
 * re-deriving either rule.
 */
export function targetsAgreeWithDaemonRule(hashLeBytes, difficulty) {
  const h = leBytes32ToBigInt(hashLeBytes);
  const d = parseWideDifficulty(difficulty);
  const viaTarget = h <= MAX_256 / d;
  const viaDaemon = h * d <= MAX_256;
  return { agree: viaTarget === viaDaemon, viaTarget, viaDaemon };
}
