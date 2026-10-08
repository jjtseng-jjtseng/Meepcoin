// Exact difficulty arithmetic, canonical header/nonce parsing, and the server-authoritative job.
//
// Every expected value here comes from the COMMITTED daemon-produced block vectors or from the
// daemon's own rule in src/cryptonote_basic/difficulty.cpp, never from the code under test.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  MAX_256, bigIntToLeBytes32, daemonCheckHash, leBytes32ToBigInt, parseWideDifficulty,
  targetForDifficulty, targetFromWideDifficulty, targetsAgreeWithDaemonRule,
} from '../difficulty.mjs';
import {
  MAX_BLOB_BYTES, blobToHex, findNonceOffset, hexToBlob, patchNonce, patchTimestamp,
  readNonce, readVarint, zeroNonce,
} from '../block_blob.mjs';
import {
  SERVER_ONLY_FIELDS, createRealTemplateJob, fullBlockBlobOf, hashingContextFor,
  hashingTemplateOf, targetBytesOf, toClientJobMessage,
} from '../real_template.mjs';
import { meetsTargetLE } from '../../../web-miner/lib/shared/target.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, '../../..');
const VECTORS = JSON.parse(
  readFileSync(resolve(REPO, 'meepow/vectors/block_vectors_v16_devnet.json'), 'utf8'),
).vectors;

const V0 = VECTORS[0];
const V1 = VECTORS[1];

/** A template input shaped exactly like get_block_template output, from a committed vector. */
function inputFrom(v, over = {}) {
  return {
    height: v.height,
    seedHashHex: v.epoch_key,
    wideDifficulty: String(v.difficulty),
    blockhashingBlobHex: v.block_hashing_blob,
    blocktemplateBlobHex: v.full_block_blob,
    nonceStart: 0,
    nonceRange: 1 << 16,
    ...over,
  };
}

/**
 * The pinned issuance, so the CONTENT identity tests vary only the field under test.
 *
 * IT IS NOT A TEMPLATE INPUT. `issuanceId` was removed from the input schema: a security-relevant
 * identity does not belong in the same object as the daemon-derived template values, where a caller
 * assembling that object from data it does not fully control could supply one by accident. The
 * `mintIssuanceId` DEPENDENCY seam below is the only way in, and production leaves it at its
 * crypto.randomBytes default.
 */
const PINNED_ISSUANCE = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

/** A job on a fixed clock, so issuedAtMs/expiresAtMs do not vary between constructions. */
function jobFrom(v, over = {}, atMs = 1000, issuanceId = PINNED_ISSUANCE) {
  const { issuanceId: overIssuance, ...templateInput } = over;
  return createRealTemplateJob(inputFrom(v, templateInput), {
    now: () => atMs,
    mintIssuanceId: () => overIssuance ?? issuanceId,
  });
}

// ---------------------------------------------------------------------------- difficulty
test('the derived target matches the committed vectors exactly', () => {
  for (const v of VECTORS) {
    const { targetHexLE } = targetFromWideDifficulty(String(v.difficulty));
    assert.equal(targetHexLE, v.target_le_hex, `difficulty ${v.difficulty}`);
  }
});

test('target is floor((2^256-1)/difficulty) and agrees with the daemon multiply', () => {
  for (const d of [1n, 2n, 3n, 500n, 1000003n, (1n << 32n) + 7n, (1n << 63n) - 1n]) {
    assert.equal(targetForDifficulty(d), MAX_256 / d);
    // At the target itself and one below, the daemon rule must agree with `hash <= target`.
    const t = MAX_256 / d;
    for (const h of [0n, 1n, t - 1n, t]) {
      const r = targetsAgreeWithDaemonRule(bigIntToLeBytes32(h), d);
      assert.ok(r.agree, `disagreement at difficulty ${d}, hash ${h}`);
      assert.equal(r.viaTarget, true, `hash ${h} <= target should pass at difficulty ${d}`);
    }
  }
});

test('the boundary passes and one above it fails, on both rules', () => {
  const d = 500n;
  const t = MAX_256 / d;
  // EXACTLY the target passes (meepow/src/target.hpp: equality passes).
  assert.equal(daemonCheckHash(bigIntToLeBytes32(t), d), true);
  assert.equal(meetsTargetLE(bigIntToLeBytes32(t), bigIntToLeBytes32(t)), true);
  // One above fails, on both.
  assert.equal(daemonCheckHash(bigIntToLeBytes32(t + 1n), d), false);
  assert.equal(meetsTargetLE(bigIntToLeBytes32(t + 1n), bigIntToLeBytes32(t)), false);
  const r = targetsAgreeWithDaemonRule(bigIntToLeBytes32(t + 1n), d);
  assert.ok(r.agree && r.viaTarget === false);
});

test('difficulties above 2^64 use the wide path and still agree', () => {
  for (const d of [(1n << 64n), (1n << 64n) + 1n, (1n << 100n), (1n << 127n) - 1n]) {
    const t = targetForDifficulty(d);
    assert.equal(t, MAX_256 / d);
    for (const h of [t, t + 1n, 0n]) {
      const r = targetsAgreeWithDaemonRule(bigIntToLeBytes32(h), d);
      assert.ok(r.agree, `disagreement at difficulty ${d}, hash ${h}`);
    }
    // The boundary is still exactly at the target.
    assert.equal(daemonCheckHash(bigIntToLeBytes32(t), d), true);
    assert.equal(daemonCheckHash(bigIntToLeBytes32(t + 1n), d), false);
  }
});

test('lossy difficulty inputs are refused, not silently rounded', () => {
  assert.throws(() => parseWideDifficulty(0), /nonzero positive/);
  assert.throws(() => parseWideDifficulty(-5n), /nonzero positive/);
  assert.throws(() => parseWideDifficulty(1.5), /must be an integer/);
  // THE HAZARD: a uint64 difficulty that arrived through JSON as a rounded Number.
  assert.throws(() => parseWideDifficulty(2 ** 53 + 1), /MAX_SAFE_INTEGER/);
  assert.throws(() => parseWideDifficulty('12abc'), /0x-hex or canonical decimal/);
  assert.throws(() => parseWideDifficulty('007'), /0x-hex or canonical decimal/);
  assert.throws(() => parseWideDifficulty(1n << 128n), /128-bit/);
  // The wide string form the daemon actually sends survives exactly.
  assert.equal(parseWideDifficulty('0x1fffffffffffffff'), 0x1fffffffffffffffn);
  assert.equal(parseWideDifficulty('18446744073709551617'), 18446744073709551617n);
});

test('little-endian encoding round-trips and is the storage order the vectors use', () => {
  const t = MAX_256 / 500n;
  const bytes = bigIntToLeBytes32(t);
  assert.equal(leBytes32ToBigInt(bytes), t);
  assert.equal(blobToHex(bytes), V1.target_le_hex);
  assert.throws(() => bigIntToLeBytes32(MAX_256 + 1n), /256 bits/);
});

// ---------------------------------------------------------------------------- blob parsing
test('the nonce offset is derived, and matches the committed vectors for both blobs', () => {
  for (const v of VECTORS) {
    const hashing = hexToBlob(v.block_hashing_blob);
    const full = hexToBlob(v.full_block_blob);
    assert.equal(findNonceOffset(hashing).offset, v.nonce_offset_bytes, `hashing blob h=${v.height}`);
    assert.equal(findNonceOffset(full).offset, v.nonce_offset_bytes, `full blob h=${v.height}`);
    assert.equal(readNonce(hashing), v.nonce);
    assert.equal(readNonce(full), v.nonce);
    // And zeroing reproduces the committed nonce-zeroed blob byte for byte.
    assert.equal(blobToHex(zeroNonce(hashing).blob), v.blob_nonce_zeroed);
  }
});

test('patchNonce round-trips and never mutates its input', () => {
  const original = hexToBlob(V1.blob_nonce_zeroed);
  const snapshot = original.slice();
  const { blob: patched } = patchNonce(original, V1.nonce);
  assert.deepEqual(original, snapshot, 'the input blob was mutated');
  assert.equal(readNonce(patched), V1.nonce);
  assert.equal(blobToHex(patched), V1.block_hashing_blob);
  // Little-endian, explicitly.
  const { blob: b } = patchNonce(original, 0x01020304);
  const off = findNonceOffset(b).offset;
  assert.deepEqual([...b.slice(off, off + 4)], [0x04, 0x03, 0x02, 0x01]);
});

test('timestamp replacement changes only the canonical varint, even across width boundaries', () => {
  const original = hexToBlob(V1.full_block_blob);
  const snapshot = original.slice();
  const first = readVarint(original, 0);
  const second = readVarint(original, first.next);
  const oldTime = readVarint(original, second.next);
  const originalNonce = readNonce(original);
  const expectedEncodings = [
    [0n, [0x00]],
    [127n, [0x7f]],
    [128n, [0x80, 0x01]],
    [16383n, [0xff, 0x7f]],
    [16384n, [0x80, 0x80, 0x01]],
    [(1n << 64n) - 1n, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]],
  ];
  for (const [timestamp, expectedBytes] of expectedEncodings) {
    const { blob, oldTimestamp, nonceOffset } = patchTimestamp(original, timestamp);
    const newTime = readVarint(blob, second.next);
    assert.equal(oldTimestamp, oldTime.value);
    assert.equal(newTime.value, timestamp);
    assert.deepEqual([...blob.subarray(second.next, newTime.next)], expectedBytes,
      'the timestamp must have the independently expected canonical LEB128 bytes');
    assert.equal(nonceOffset, findNonceOffset(blob).offset);
    assert.equal(readNonce(blob), originalNonce);
    assert.deepEqual(blob.subarray(0, second.next), original.subarray(0, second.next));
    assert.deepEqual(blob.subarray(newTime.next), original.subarray(oldTime.next),
      'parent, nonce and entire block body must be unchanged');
    assert.deepEqual(patchTimestamp(blob, oldTime.value).blob, original,
      'restoring the timestamp must restore the exact original blob');
  }
  assert.deepEqual(original, snapshot, 'the source blob must remain unchanged');
});

test('paired timestamp replacement keeps daemon hashing/full templates coherent', () => {
  const timestamp = 16384n;
  const hashing = patchTimestamp(hexToBlob(V1.block_hashing_blob), timestamp);
  const full = patchTimestamp(hexToBlob(V1.full_block_blob), timestamp);
  const job = jobFrom(V1, {
    blockhashingBlobHex: blobToHex(hashing.blob),
    blocktemplateBlobHex: blobToHex(full.blob),
  });
  assert.equal(findNonceOffset(hashingTemplateOf(job)).timestamp, timestamp);
  assert.equal(findNonceOffset(fullBlockBlobOf(job)).timestamp, timestamp);
  assert.equal(readNonce(fullBlockBlobOf(job)), V1.nonce);
  assert.notEqual(job.contentDigest, jobFrom(V1).contentDigest);
  assert.throws(() => jobFrom(V1, { blockhashingBlobHex: blobToHex(hashing.blob) }),
    (e) => e.reason === 'blob_mismatch', 'changing only one blob must be refused');
});

test('timestamp replacement refuses lossy inputs, malformed blobs and oversized output', () => {
  const valid = hexToBlob(V1.full_block_blob);
  for (const timestamp of [-1n, 1n << 64n, 1, Number.MAX_SAFE_INTEGER + 1, '123']) {
    assert.throws(() => patchTimestamp(valid, timestamp), /uint64 bigint/);
  }
  assert.throws(() => patchTimestamp(Uint8Array.from([0x80]), 1n),
    (e) => e.reason === 'truncated_varint');
  const atLimit = new Uint8Array(MAX_BLOB_BYTES);
  assert.throws(() => patchTimestamp(atLimit, 128n),
    (e) => e.reason === 'blob_too_large');
});

test('malformed varints and blobs are refused', () => {
  // truncated: continuation bit set, then the buffer ends
  assert.throws(() => readVarint(Uint8Array.from([0x80]), 0), /truncated/);
  // overlong: a multi-byte varint ending in a byte that contributes nothing
  assert.throws(() => readVarint(Uint8Array.from([0x80, 0x00]), 0), /overlong/);
  // overflow: more than 64 bits of payload
  assert.throws(
    () => readVarint(Uint8Array.from([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]), 0),
    /exceeds 10 bytes|does not fit in 64 bits/,
  );
  assert.throws(
    () => readVarint(Uint8Array.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]), 0),
    /does not fit in 64 bits/,
  );
  // canonical single byte still works
  assert.equal(readVarint(Uint8Array.from([0x10]), 0).value, 16n);

  // a blob too short to hold prev_id + nonce. Asserted on the structured `reason`, not on the
  // message wording, so rephrasing an error cannot quietly turn this check off.
  assert.throws(() => findNonceOffset(Uint8Array.from([0x10, 0x10, 0x01])),
    (e) => e.reason === 'blob_too_short');
  assert.throws(() => findNonceOffset(new Uint8Array(0)), (e) => e.reason === 'empty_blob');
  // hex hygiene
  assert.throws(() => hexToBlob('AABB'), /lowercase hex/);
  assert.throws(() => hexToBlob('abc'), /even/);
  assert.throws(() => hexToBlob(''), /empty/);
});

test('a real blob truncated by one byte is refused rather than mis-parsed', () => {
  const full = hexToBlob(V0.block_hashing_blob);
  const short = full.slice(0, V0.nonce_offset_bytes + 3); // one byte short of the nonce
  assert.throws(() => findNonceOffset(short), (e) => e.reason === 'blob_too_short');
});

// ---------------------------------------------------------------------------- the job
test('a real job binds the committed context and derives the committed target', () => {
  const job = jobFrom(V1);
  assert.equal(job.kind, 'real');
  assert.equal(job.height, BigInt(V1.height));
  assert.equal(job.seedHashHex, V1.epoch_key);
  assert.equal(job.epochKeyHex, V1.epoch_key, 'epoch key defaults to the seed hash, as the daemon does');
  assert.equal(job.targetHexLE, V1.target_le_hex);
  assert.equal(job.hashingTemplateHex, V1.blob_nonce_zeroed);
  assert.equal(job.hashingNonceOffset, V1.nonce_offset_bytes);
  assert.equal(job.fullNonceOffset, V1.nonce_offset_bytes);
  // The PARSED major version is carried, so calc_pow is never told a default.
  assert.equal(job.majorVersion, V1.major_version);
  assert.match(job.contentDigest, /^[0-9a-f]{64}$/);
  assert.match(job.authDigest, /^[0-9a-f]{64}$/);
  assert.notEqual(job.contentDigest, job.authDigest);
  assert.ok(job.jobId.startsWith('realjob-'));
});

test('CONTENT identity is stable, AUTHORIZATION identity is per issuance', () => {
  const a = jobFrom(V1);
  const b = jobFrom(V1);                       // same content, same issuance token, same clock
  assert.equal(a.contentDigest, b.contentDigest);
  assert.equal(a.jobId, b.jobId);

  // Same content, DIFFERENT issuance -> different job identity. This is the defect that let a
  // candidate authorized against one issuance be replayed into another.
  const c = jobFrom(V1, {}, 1000, 'b'.repeat(32));
  assert.equal(c.contentDigest, a.contentDigest, 'content identity should not depend on the issuance');
  assert.notEqual(c.jobId, a.jobId, 'a new issuance must produce a new job identity');

  // Same content and issuance token, DIFFERENT issue time -> different job identity.
  const d = jobFrom(V1, {}, 2000);
  assert.equal(d.contentDigest, a.contentDigest);
  assert.notEqual(d.jobId, a.jobId, 'issuedAtMs is not bound into the job identity');

  // Same content and issuance, DIFFERENT ttl -> different expiry -> different job identity.
  const e = createRealTemplateJob(inputFrom(V1, { ttlMs: 30000 }), { now: () => 1000 });
  assert.equal(e.contentDigest, a.contentDigest);
  assert.notEqual(e.jobId, a.jobId, 'expiresAtMs is not bound into the job identity');
});

test('template clocks must be non-negative safe integers and expiry must remain safe', () => {
  for (const value of [-1, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(
      () => createRealTemplateJob(inputFrom(V1), { now: () => value }),
      (error) => error?.reason === 'bad_field',
    );
  }
  assert.throws(
    () => createRealTemplateJob(inputFrom(V1, { ttlMs: 1000 }), {
      now: () => Number.MAX_SAFE_INTEGER - 999,
    }),
    (error) => error?.reason === 'bad_field',
  );
});

test('a minted issuanceId is unpredictable and not reused', () => {
  const seen = new Set();
  for (let i = 0; i < 8; i++) {
    const input = inputFrom(V1);
    delete input.issuanceId;                  // let the module mint one
    const j = createRealTemplateJob(input, { now: () => 1000 });
    assert.match(j.issuanceId, /^[0-9a-f]{32}$/);
    assert.equal(seen.has(j.issuanceId), false, 'a minted issuanceId repeated');
    seen.add(j.issuanceId);
  }
  assert.equal(seen.size, 8);
});

test('job identity changes when ANY bound field changes', () => {
  const base = jobFrom(V1);
  const contentVariants = {
    height: { height: V1.height + 1 },
    difficulty: { wideDifficulty: String(V1.difficulty + 1) },
    // NOT V0.epoch_key: heights 0..2112 all share the genesis epoch key, so that would not differ.
    seed: { seedHashHex: 'a'.repeat(64) },
    epochKey: { epochKeyHex: 'b'.repeat(64) },
  };
  for (const [name, over] of Object.entries(contentVariants)) {
    const other = jobFrom(V1, over);
    assert.notEqual(other.contentDigest, base.contentDigest, `${name} did not change contentDigest`);
    assert.notEqual(other.jobId, base.jobId, `${name} did not change the job id`);
  }
  // Authorization-only fields: the CONTENT is the same work, the issuance is a different grant.
  for (const [name, over] of Object.entries({
    nonceStart: { nonceStart: 1 },
    nonceRange: { nonceRange: (1 << 16) + 1 },
    seedHeight: { seedHeight: 2048 },
  })) {
    const other = jobFrom(V1, over);
    assert.notEqual(other.jobId, base.jobId, `${name} did not change the job id`);
  }
  // One byte of the full block, everything else identical.
  const tampered = hexToBlob(V1.full_block_blob);
  tampered[tampered.length - 1] ^= 0x01;
  const other = jobFrom(V1, { blocktemplateBlobHex: blobToHex(tampered) });
  assert.notEqual(other.contentDigest, base.contentDigest, 'full block bytes are not bound');
});

test('the browser-bound message carries no server-only field', () => {
  const job = jobFrom(V1);
  const msg = toClientJobMessage(job);
  const json = JSON.stringify(msg);

  for (const f of SERVER_ONLY_FIELDS) {
    assert.equal(Object.prototype.hasOwnProperty.call(msg, f), false, `${f} leaked into the client message`);
  }
  assert.equal(json.includes(V1.full_block_blob), false, 'the full block blob reached the client');
  assert.equal(json.includes(String(V1.difficulty)), false, 'the raw difficulty reached the client');
  assert.equal(msg.hashingTemplateHex, V1.blob_nonce_zeroed);
  assert.equal(msg.targetHexLE, V1.target_le_hex);
  assert.equal(typeof msg.height, 'string');
  assert.equal(msg.height, String(V1.height));
  // The browser needs the issuance to echo back; it is an authorization token, not a secret key.
  assert.equal(msg.issuanceId, job.issuanceId);
});

// ------------------------------------------------------------------- the bytes are not reachable
test('no mutable byte array is exposed on the job object', () => {
  const job = jobFrom(V1);
  for (const key of Object.keys(job)) {
    assert.equal(job[key] instanceof Uint8Array, false,
      `job.${key} exposes a mutable Uint8Array; Object.freeze does not protect its contents`);
  }
});

test('mutating EVERY returned array leaves the private state untouched', () => {
  const job = jobFrom(V1);
  const expectedContent = job.contentDigest;
  const expectedId = job.jobId;

  // Wreck every copy the module will hand out.
  targetBytesOf(job).fill(0xff);
  hashingTemplateOf(job).fill(0xff);
  fullBlockBlobOf(job).fill(0xff);
  const ctx = hashingContextFor(job);
  ctx.template.fill(0xff);
  ctx.epochKey.fill(0xff);
  ctx.seedHash.fill(0xff);

  // Fetch fresh copies: they must be the originals.
  assert.equal(blobToHex(hashingTemplateOf(job)), V1.blob_nonce_zeroed);
  assert.equal(blobToHex(fullBlockBlobOf(job)), V1.full_block_blob);
  assert.equal(blobToHex(targetBytesOf(job)), V1.target_le_hex);
  const ctx2 = hashingContextFor(job);
  assert.equal(blobToHex(ctx2.template), V1.blob_nonce_zeroed);
  assert.equal(blobToHex(ctx2.epochKey), V1.epoch_key);
  assert.equal(blobToHex(ctx2.seedHash), V1.epoch_key);
  // And the identities did not move.
  assert.equal(job.contentDigest, expectedContent);
  assert.equal(job.jobId, expectedId);
  assert.equal(job.targetHexLE, V1.target_le_hex);
});

test('each accessor returns a DISTINCT copy, not a shared buffer', () => {
  const job = jobFrom(V1);
  const a = hashingTemplateOf(job);
  const b = hashingTemplateOf(job);
  assert.notEqual(a, b, 'the same array object was handed out twice');
  a[0] ^= 0xff;
  assert.notEqual(a[0], b[0]);
});

test('the accessors refuse an object that is not one of our jobs', () => {
  assert.throws(() => targetBytesOf({ kind: 'real' }), /not a real-template job/);
  assert.throws(() => fullBlockBlobOf(null), /not a real-template job/);
});

// ---------------------------------------------------------------------------- input validation
test('malformed template inputs are refused by a closed schema', () => {
  assert.throws(() => jobFrom(V1, { surprise: 1 }), /unexpected field surprise/);
  assert.throws(() => jobFrom(V1, { seedHashHex: 'abcd' }), /64 lowercase hex/);
  assert.throws(() => jobFrom(V1, { seedHashHex: V1.epoch_key.toUpperCase() }), /64 lowercase hex/);
  assert.throws(() => jobFrom(V1, { wideDifficulty: '0' }), /nonzero positive/);
  assert.throws(() => jobFrom(V1, { height: 2 ** 53 + 1 }), /MAX_SAFE_INTEGER/);
  assert.throws(() => jobFrom(V1, { nonceRange: 0 }), /nonceRange/);
  assert.throws(() => jobFrom(V1, { nonceStart: 0xffffffff, nonceRange: 2 }), /past the end/);
  assert.throws(() => createRealTemplateJob(null), /must be an object/);
  assert.throws(() => jobFrom(V1, { majorVersion: 15 }), /does not match the block header/);
});

test('issuanceId is NOT a template input, and the mint seam is validated like any other', () => {
  // An issuance supplied with the template is now an unknown key, refused by the closed schema --
  // not quietly honoured, and not quietly ignored either.
  assert.throws(
    () => createRealTemplateJob(
      { ...inputFrom(V1), issuanceId: 'c'.repeat(32) },
      { now: () => 1000 },
    ),
    /unexpected field issuanceId/,
  );

  // The dependency seam works and is the only way to a deterministic identity.
  assert.equal(jobFrom(V1, {}, 1000, 'c'.repeat(32)).issuanceId, 'c'.repeat(32));

  // A seam that mints a malformed identity is refused exactly as a malformed input would have been:
  // exactly 32 lowercase hex, not 31, not 33, not uppercase, not a non-hex string.
  for (const bad of ['NOTHEX', 'ab', 'a'.repeat(31), 'a'.repeat(33), 'A'.repeat(32), '', 42, null]) {
    assert.throws(
      () => createRealTemplateJob(inputFrom(V1), { now: () => 1000, mintIssuanceId: () => bad }),
      /issuanceId must be/,
      String(bad),
    );
  }

  // The default seam mints 32 lowercase hex, and two jobs never share one.
  const a = createRealTemplateJob(inputFrom(V1), { now: () => 1000 });
  const b = createRealTemplateJob(inputFrom(V1), { now: () => 1000 });
  assert.match(a.issuanceId, /^[0-9a-f]{32}$/);
  assert.notEqual(a.issuanceId, b.issuanceId, 'two issuances of the same template shared an identity');
});

test('two blobs that disagree about the header are refused', () => {
  // The hazard: hashing one header and submitting a different one. This is a NECESSARY check, not a
  // sufficient one -- what actually binds the submitted block to the verified PoW input is the
  // readback pow_hash comparison in block_run.mjs.
  assert.ok(jobFrom(V0).jobId);
  assert.throws(
    () => jobFrom(V1, { blocktemplateBlobHex: V0.full_block_blob }),
    /different headers|differ at header byte/,
  );
});

test('a uint64 height beyond Number range survives as a string', () => {
  const big = '18446744073709551615';
  const job = jobFrom(V1, { height: big });
  assert.equal(job.height, (1n << 64n) - 1n);
  assert.equal(toClientJobMessage(job).height, big);
});
