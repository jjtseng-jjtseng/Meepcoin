// Server-owned allocation of the reserved miner-transaction bytes used to personalize work.
//
// This is deliberately a tiny synchronous component.  One pool process mints one random 96-bit
// namespace, then appends a monotonically increasing 32-bit counter.  The resulting 16 bytes are
// unique for the lifetime of that allocator without keeping an ever-growing replay set.  A fresh
// process gets a fresh namespace, so restart reuse would additionally require a 96-bit random
// namespace collision.
//
// The value is an internal work identifier, not a password.  It must never be accepted from a
// browser or placed in the browser job projection: the full personalized block stays server-side.

import { randomBytes } from 'node:crypto';

export const EXTRA_NONCE_BYTES = 16;
const NAMESPACE_BYTES = 12;
const COUNTER_MAX = (1n << 32n) - 1n;
const ALLOWED_KEYS = new Set(['mintNamespace', 'initialCounter']);

export class ExtraNonceAllocatorError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ExtraNonceAllocatorError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new ExtraNonceAllocatorError(code, message);
}

function exactNamespace(value) {
  if (!(value instanceof Uint8Array) || value.byteLength !== NAMESPACE_BYTES) {
    fail('bad_namespace', `mintNamespace must return exactly ${NAMESPACE_BYTES} bytes`);
  }
  return Buffer.from(value);
}

/**
 * Create one allocation domain.  `mintNamespace` and `initialCounter` are dependency seams for
 * deterministic tests; production callers omit both.
 */
export function createExtraNonceAllocator(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    fail('bad_options', 'allocator options must be a plain object');
  }
  for (const key of Reflect.ownKeys(options)) {
    if (typeof key !== 'string' || !ALLOWED_KEYS.has(key)) {
      fail('bad_options', `unexpected allocator option ${String(key).slice(0, 40)}`);
    }
  }
  const mintNamespace = options.mintNamespace ?? (() => randomBytes(NAMESPACE_BYTES));
  if (typeof mintNamespace !== 'function') fail('bad_options', 'mintNamespace must be a function');
  const namespace = exactNamespace(mintNamespace());
  let next = options.initialCounter ?? 0n;
  if (typeof next !== 'bigint' || next < 0n || next > COUNTER_MAX) {
    fail('bad_options', 'initialCounter must be an unsigned 32-bit bigint');
  }

  return Object.freeze({
    reserveSize: EXTRA_NONCE_BYTES,
    issue() {
      if (next > COUNTER_MAX) fail('exhausted', 'the extra-nonce allocation domain is exhausted');
      const value = Buffer.alloc(EXTRA_NONCE_BYTES);
      namespace.copy(value, 0);
      value.writeUInt32BE(Number(next), NAMESPACE_BYTES);
      next += 1n;
      return value.toString('hex');
    },
  });
}
