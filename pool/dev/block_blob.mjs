// Canonical CryptoNote block-header parsing: locate the nonce, zero it, patch it.
//
// GROUNDED IN THE DAEMON, NOT GUESSED. src/crypto/meep-hash.cpp::nonce_offset() defines the
// layout the proof-of-work depends on:
//
//   varint major_version
//   varint minor_version
//   varint timestamp
//   32 bytes prev_id
//   4 bytes nonce, LITTLE-ENDIAN uint32     <- offset = (bytes consumed by the 3 varints) + 32
//
// meep_slow_hash() then splits the blob it is given into (template with those 4 bytes zeroed,
// nonce) and hashes them separately. So the browser's hashing template is the blob with the nonce
// zeroed, and the nonce is supplied alongside -- which is exactly what the committed block vectors
// record as `blob_nonce_zeroed` / `nonce`.
//
// NO MAGIC OFFSET. Nothing here uses a fixed index, a search for a byte pattern, or a
// client-supplied offset. The offset is derived from the blob every time.
//
// STRICTER THAN THE DAEMON, DELIBERATELY. The daemon's skip_varint() walks continuation bits and
// accepts an overlong or non-canonical encoding; on a malformed blob it gives up and hashes the
// whole thing with nonce 0. This parser REFUSES instead: overlong encodings, values that overflow
// 64 bits, truncation, and a blob too short to hold prev_id + nonce are all errors.
//
// That asymmetry is safe in this direction and only this direction. We refuse to mine something
// the daemon might have accepted, which costs a job; we never accept something the daemon would
// reject. For every WELL-FORMED blob -- which is all a daemon actually issues -- the two agree on
// the offset, and the tests check that against the committed vectors.

/** A CryptoNote varint is at most 10 bytes for a 64-bit value. */
export const MAX_VARINT_BYTES = 10;

/** prev_id is a 32-byte hash; the nonce is a fixed 4-byte little-endian uint32. */
export const PREV_ID_BYTES = 32;
export const NONCE_BYTES = 4;

/** A block blob larger than this is refused before anything scans it. */
export const MAX_BLOB_BYTES = 1 << 20;

export class BlockBlobError extends Error {
  constructor(message, reason, detail) {
    super(message);
    this.name = 'BlockBlobError';
    this.reason = reason;
    this.detail = detail ?? '';
  }
}

function fail(reason, message, detail) {
  throw new BlockBlobError(message, reason, detail);
}

/**
 * Read one canonical CryptoNote varint at `off`.
 *
 * Returns { value: bigint, next: number }. Rejects:
 *   - truncation (the buffer ends mid-varint)
 *   - overlong encodings (a non-minimal representation, i.e. a final byte of 0 in a multi-byte
 *     varint -- two different byte strings must not decode to the same number)
 *   - anything that does not fit in 64 bits
 */
export function readVarint(bytes, off) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('bytes must be a Uint8Array');
  if (!Number.isInteger(off) || off < 0) throw new RangeError('offset must be a non-negative integer');

  let value = 0n;
  let shift = 0n;
  let i = off;
  let consumed = 0;

  for (;;) {
    if (i >= bytes.length) fail('truncated_varint', `varint at offset ${off} is truncated`);
    if (consumed >= MAX_VARINT_BYTES) {
      fail('varint_too_long', `varint at offset ${off} exceeds ${MAX_VARINT_BYTES} bytes`);
    }
    const b = bytes[i];
    i += 1;
    consumed += 1;

    const payload = BigInt(b & 0x7f);
    // Reject before shifting: a 10th byte may only contribute the single remaining bit.
    if (shift >= 64n && payload !== 0n) {
      fail('varint_overflow', `varint at offset ${off} does not fit in 64 bits`);
    }
    if (shift === 63n && payload > 1n) {
      fail('varint_overflow', `varint at offset ${off} does not fit in 64 bits`);
    }
    value |= payload << shift;

    if ((b & 0x80) === 0) {
      // Canonical form: a multi-byte varint must not end in a byte that contributes nothing.
      if (consumed > 1 && b === 0x00) {
        fail('varint_not_canonical', `varint at offset ${off} is overlong (trailing zero group)`);
      }
      return { value, next: i, bytes: consumed };
    }
    shift += 7n;
  }
}

/**
 * Locate the 4-byte nonce field in a block blob, by parsing the header.
 *
 * Works for BOTH the hashing blob and the full block template blob: the header prefix is identical
 * in each (the committed vectors confirm the nonce sits at the same offset in both), because the
 * full block is the same header followed by the miner transaction and tx hashes.
 *
 * @returns {{offset:number, majorVersion:bigint, minorVersion:bigint, timestamp:bigint}}
 */
export function findNonceOffset(blob) {
  if (!(blob instanceof Uint8Array)) throw new TypeError('blob must be a Uint8Array');
  if (blob.length === 0) fail('empty_blob', 'block blob is empty');
  if (blob.length > MAX_BLOB_BYTES) {
    fail('blob_too_large', `block blob is ${blob.length} bytes, over the ${MAX_BLOB_BYTES} limit`);
  }

  const major = readVarint(blob, 0);
  const minor = readVarint(blob, major.next);
  const timestamp = readVarint(blob, minor.next);

  const offset = timestamp.next + PREV_ID_BYTES;
  // The daemon requires prev_id AND the nonce to fit: `off + 32 + 4 > len` is its refusal.
  if (offset + NONCE_BYTES > blob.length) {
    fail('blob_too_short',
      `block blob is ${blob.length} bytes; the header needs ${offset + NONCE_BYTES}`,
      { offset });
  }
  return {
    offset,
    majorVersion: major.value,
    minorVersion: minor.value,
    timestamp: timestamp.value,
  };
}

/** The little-endian uint32 nonce currently stored in `blob`. */
export function readNonce(blob, offset = findNonceOffset(blob).offset) {
  if (offset + NONCE_BYTES > blob.length) fail('blob_too_short', 'nonce does not fit');
  return (
    (blob[offset] |
      (blob[offset + 1] << 8) |
      (blob[offset + 2] << 16) |
      (blob[offset + 3] << 24)) >>> 0
  );
}

/**
 * A COPY of `blob` with the 4 nonce bytes zeroed -- the hashing template.
 *
 * The input is never mutated: the server keeps the original private, and a caller that accidentally
 * held a reference must not see it change underneath.
 */
export function zeroNonce(blob) {
  const { offset } = findNonceOffset(blob);
  const out = blob.slice();
  out[offset] = 0;
  out[offset + 1] = 0;
  out[offset + 2] = 0;
  out[offset + 3] = 0;
  return { blob: out, offset };
}

/**
 * A COPY of `blob` with `nonce` written little-endian into the nonce field.
 *
 * This is the last step before a submission: the server patches its PRIVATE full-block blob and
 * hands that copy to submit_block. Returning a copy rather than mutating in place means the
 * server's immutable template survives, so a rejected submission has not damaged it.
 */
export function patchNonce(blob, nonce) {
  if (!Number.isInteger(nonce) || nonce < 0 || nonce > 0xffffffff) {
    throw new RangeError('nonce must be a uint32');
  }
  const { offset } = findNonceOffset(blob);
  const out = blob.slice();
  out[offset] = nonce & 0xff;
  out[offset + 1] = (nonce >>> 8) & 0xff;
  out[offset + 2] = (nonce >>> 16) & 0xff;
  out[offset + 3] = (nonce >>> 24) & 0xff;
  return { blob: out, offset };
}

/**
 * Return a COPY with a canonical uint64 timestamp varint. This only changes header bytes;
 * it does not establish that the new timestamp is legal for any particular chain or clock.
 * Varint length may change, so callers must re-parse the nonce offset after this operation.
 */
export function patchTimestamp(blob, timestamp) {
  if (typeof timestamp !== 'bigint' || timestamp < 0n || timestamp > 0xffffffffffffffffn) {
    throw new RangeError('timestamp must be a uint64 bigint');
  }
  findNonceOffset(blob); // Validate the complete original header before slicing it.
  const major = readVarint(blob, 0);
  const minor = readVarint(blob, major.next);
  const oldTimestamp = readVarint(blob, minor.next);
  const encoded = [];
  let remaining = timestamp;
  do {
    const byte = Number(remaining & 0x7fn);
    remaining >>= 7n;
    encoded.push(remaining === 0n ? byte : byte | 0x80);
  } while (remaining !== 0n);
  const nextLength = blob.length - (oldTimestamp.next - minor.next) + encoded.length;
  if (nextLength > MAX_BLOB_BYTES) fail('blob_too_large', 'patched blob exceeds size limit');
  const out = new Uint8Array(nextLength);
  out.set(blob.subarray(0, minor.next), 0);
  out.set(encoded, minor.next);
  out.set(blob.subarray(oldTimestamp.next), minor.next + encoded.length);
  const updatedHeader = findNonceOffset(out); // Ensure the shifted parent and nonce still fit.
  return { blob: out, oldTimestamp: oldTimestamp.value, nonceOffset: updatedHeader.offset };
}

/** Strict lowercase-hex -> bytes, with an explicit byte cap. */
export function hexToBlob(hex, { maxBytes = MAX_BLOB_BYTES, what = 'blob' } = {}) {
  if (typeof hex !== 'string') fail('bad_hex', `${what} must be a hex string`);
  if (hex.length === 0) fail('bad_hex', `${what} is empty`);
  if (hex.length % 2 !== 0) fail('bad_hex', `${what} hex length must be even`);
  if (hex.length / 2 > maxBytes) fail('blob_too_large', `${what} is ${hex.length / 2} bytes, over ${maxBytes}`);
  if (!/^[0-9a-f]+$/.test(hex)) fail('bad_hex', `${what} must be lowercase hex`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Bytes -> lowercase hex, storage order. */
export function blobToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}
