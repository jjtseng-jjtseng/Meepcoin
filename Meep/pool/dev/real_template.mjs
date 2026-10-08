// The server-authoritative REAL block-template job.
//
// Deliberately a SEPARATE representation from the synthetic fixture in jobs.mjs. Overloading that
// one would have made "a synthetic share was accepted" and "a daemon accepted a block" the same
// shape, and those must never be confusable.
//
// TWO IDENTITIES, NOT ONE
//
//   contentDigest  -- a stable fingerprint of the immutable TEMPLATE CONTENT. Two issuances of the
//                     same template share it. Useful for "is this the same work?".
//   jobId          -- the AUTHORIZATION identity. It binds contentDigest AND a server-minted
//                     one-use issuanceId, the issue/expiry times, the seed height, the parsed major
//                     version, the nonce bounds and the target. Re-issuing identical content
//                     therefore produces a DIFFERENT jobId.
//
// Conflating the two was a real defect: two issuances of the same template with different TTLs got
// the same jobId, so a candidate authorized against the first could be replayed into the second.
//
// THE BYTES ARE NOT REACHABLE FROM THE JOB OBJECT
//
// Object.freeze() on a job freezes the OBJECT; it cannot make a Uint8Array's contents immutable.
// An earlier revision exposed `targetBytes`, `hashingTemplate` and `fullBlockBlob` directly, so any
// caller could rewrite the target or the block being submitted while contentDigest -- computed
// once, at construction -- stayed reassuringly unchanged.
//
// The bytes now live in a module-private WeakMap keyed by the job object. Nothing on the job
// exposes them. Every accessor returns a FRESH COPY, so mutating what you are given changes
// nothing. That is a real boundary, not a naming convention, and the tests mutate every returned
// array and assert the internals did not move.
//
// THE TRUST BOUNDARY
//
//   Disclosed to the browser: jobId, issuanceId, the hashing context (epoch key, seed hash, height,
//   nonce-zeroed hashing blob), the target, a bounded nonce window, a deadline. A browser cannot
//   search without these and they are public chain data once the block publishes.
//
//   Never disclosed: the FULL BLOCK BLOB, the difficulty, the nonce offsets, the mining address.
//   The full block plus a winning nonce IS a submittable block.
//
//   A client may say back only: jobId, issuanceId, workerId, runGeneration, nonce.

import { createHash, randomBytes } from 'node:crypto';

import { targetFromWideDifficulty } from './difficulty.mjs';
import {
  MAX_BLOB_BYTES, blobToHex, findNonceOffset, hexToBlob, readNonce, zeroNonce,
} from './block_blob.mjs';

/** The algorithm label for a REAL template. Distinct from the synthetic one, on purpose. */
export const REAL_ALGORITHM_LABEL = 'meephash-w-v2-frozen-real-template';

export const DEFAULT_REAL_NONCE_RANGE = 1 << 16;
export const MAX_REAL_NONCE_RANGE = 1 << 24;
export const DEFAULT_REAL_TTL_MS = 2 * 60 * 1000;

const HEX64 = /^[0-9a-f]{64}$/;
const U64_MAX = (1n << 64n) - 1n;

/**
 * The private bytes, keyed by the job object. Module-scoped and not exported, so the only way to
 * reach them is through the copy-returning accessors below.
 */
const PRIVATE = new WeakMap();

export class RealTemplateError extends Error {
  constructor(message, reason, detail) {
    super(message);
    this.name = 'RealTemplateError';
    this.reason = reason;
    this.detail = detail ?? '';
  }
}

function bad(reason, message, detail) {
  throw new RealTemplateError(message, reason, detail);
}

function requireHex64(value, what) {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    bad('bad_field', `${what} must be exactly 64 lowercase hex characters`);
  }
  return value;
}

/** An exact uint64 from a number / bigint / canonical decimal string. Never a rounded Number. */
function requireU64(value, what) {
  let v;
  if (typeof value === 'bigint') v = value;
  else if (typeof value === 'number') {
    if (!Number.isInteger(value)) bad('bad_field', `${what} must be an integer`);
    if (!Number.isSafeInteger(value)) {
      bad('bad_field', `${what} exceeds Number.MAX_SAFE_INTEGER; pass a bigint or decimal string`);
    }
    v = BigInt(value);
  } else if (typeof value === 'string') {
    if (!/^(0|[1-9][0-9]*)$/.test(value)) bad('bad_field', `${what} must be a canonical decimal string`);
    v = BigInt(value);
  } else {
    bad('bad_field', `${what} must be a number, bigint or decimal string`);
  }
  if (v < 0n || v > U64_MAX) bad('bad_field', `${what} must fit in an unsigned 64-bit integer`);
  return v;
}

function requireU32(value, what, { min = 0, max = 0xffffffff } = {}) {
  if (!Number.isInteger(value) || value < min || value > max) {
    bad('bad_field', `${what} must be an integer in [${min}, ${max}]`);
  }
  return value;
}

/** The exact set of fields a caller may supply. An unknown key is an error, not something ignored. */
const ALLOWED_INPUT_KEYS = new Set([
  'height', 'seedHashHex', 'epochKeyHex', 'wideDifficulty',
  'blockhashingBlobHex', 'blocktemplateBlobHex',
  'nonceStart', 'nonceRange', 'ttlMs', 'majorVersion', 'seedHeight', 'note',
  // OPT-IN, trusted startup configuration only. See the share-target note below.
  'shareDifficulty',
]);

/**
 * Build ONE immutable-content, single-issuance real-template job.
 *
 * `input.epochKeyHex` is OPTIONAL and defaults to `seedHashHex`. Not a guess: the daemon's
 * meep_slow_hash() (src/crypto/meep-hash.cpp) receives one `seedhash` and uses it for BOTH
 * mv2::Dataset::create(key) and mv2::Hasher::create(..., seed, ...), and every row of the committed
 * meepow/vectors/block_vectors_v16_devnet.json has epoch_key == delayed_seed_input.
 *
 * `issuanceId` is ALWAYS MINTED HERE as 16 crypto.randomBytes, i.e. 32 lowercase hex characters. It
 * is a ONE-USE REPLAY/CAPABILITY IDENTIFIER, not user authentication: holding it shows the bearer was
 * handed this issuance of this template, so a candidate cannot be replayed into a different one. Any
 * local program that can receive a job also receives it.
 *
 * IT IS NOT AN INPUT FIELD. `input.issuanceId` used to be accepted, which put a security-relevant
 * identity in the same bag as the daemon-derived template values -- so a caller building a job from
 * a data structure it did not fully control could supply one by accident. The ONLY way to obtain a
 * deterministic issuance is the `mintIssuanceId` DEPENDENCY seam in the second argument, which is
 * separate from the template input, named for what it is, and used by tests. The minted value is
 * validated the same way whatever produced it.
 */
export function createRealTemplateJob(input, {
  now = () => Date.now(),
  idPrefix = 'realjob',
  mintIssuanceId = () => randomBytes(16).toString('hex'),
} = {}) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    bad('bad_schema', 'template input must be an object');
  }
  for (const key of Object.keys(input)) {
    if (!ALLOWED_INPUT_KEYS.has(key)) bad('bad_schema', `unexpected field ${String(key).slice(0, 40)}`);
  }

  const height = requireU64(input.height, 'height');
  const seedHashHex = requireHex64(input.seedHashHex, 'seedHashHex');
  const epochKeyHex = input.epochKeyHex === undefined
    ? seedHashHex
    : requireHex64(input.epochKeyHex, 'epochKeyHex');

  // The FULL 128-bit difficulty, from the wide string. A lossy uint64 is refused upstream.
  const { difficulty, targetBytes, targetHexLE } = targetFromWideDifficulty(input.wideDifficulty);

  /**
   * THE SHARE TARGET, and the inequality that defines it.
   *
   * Share difficulty <= network difficulty, therefore the numeric share target >= the block target,
   * therefore EVERY BLOCK IS ALSO A SHARE and a share is not necessarily a block. Omit it and the
   * share target IS the block target: the job is then byte-for-byte what this module has always
   * produced, including its authorization digest and job id.
   *
   * It belongs to the AUTHORIZATION identity, not the content identity: the same template content
   * issued at a different share difficulty is a different capability over the same work.
   */
  const shareConfigured = input.shareDifficulty !== undefined && input.shareDifficulty !== null;
  let shareDifficulty = difficulty;
  let shareTargetBytes = targetBytes;
  let shareTargetHexLE = targetHexLE;
  if (shareConfigured) {
    const raw = input.shareDifficulty;
    if (typeof raw !== 'bigint' && !Number.isSafeInteger(raw)) {
      bad('bad_field', 'shareDifficulty must be a bigint or a safe integer');
    }
    shareDifficulty = BigInt(raw);
    if (shareDifficulty < 1n) bad('bad_field', 'shareDifficulty must be at least 1');
    if (shareDifficulty > difficulty) {
      bad('bad_field', 'shareDifficulty must not exceed the template difficulty');
    }
    const derived = targetFromWideDifficulty(`0x${shareDifficulty.toString(16)}`);
    shareTargetBytes = derived.targetBytes;
    shareTargetHexLE = derived.targetHexLE;
  }

  const hashingBlob = hexToBlob(input.blockhashingBlobHex, { what: 'blockhashing_blob' });
  const fullBlob = hexToBlob(input.blocktemplateBlobHex, { what: 'blocktemplate_blob' });
  if (hashingBlob.length > MAX_BLOB_BYTES || fullBlob.length > MAX_BLOB_BYTES) {
    bad('blob_too_large', 'a template blob exceeds the size limit');
  }

  // Parse BOTH blobs independently: they are different lengths and the daemon builds them
  // separately, so assuming one offset applies to the other would be the kind of guess this module
  // exists to avoid.
  const hashingHeader = findNonceOffset(hashingBlob);
  const fullHeader = findNonceOffset(fullBlob);

  // A NECESSARY BUT NOT SUFFICIENT precondition. Matching headers mean the two blobs at least agree
  // about version, timestamp and previous block. They do NOT prove that the full block's
  // proof-of-work input is the hashing blob -- the hashing blob replaces the transaction list with
  // a merkle root, and this module does not re-derive that. What actually proves the correspondence
  // is the post-submission readback: the daemon recomputes the PoW of the block it STORED and we
  // require it to equal the hash all three parties agreed on. See block_run.mjs.
  if (hashingHeader.majorVersion !== fullHeader.majorVersion
    || hashingHeader.minorVersion !== fullHeader.minorVersion
    || hashingHeader.timestamp !== fullHeader.timestamp) {
    bad('blob_mismatch', 'the hashing blob and the full block blob have different headers');
  }
  for (let i = 0; i < hashingHeader.offset; i++) {
    if (hashingBlob[i] !== fullBlob[i]) {
      bad('blob_mismatch', `hashing blob and full block blob differ at header byte ${i}`);
    }
  }

  // The PARSED major version is authoritative and is carried on the job. It is what calc_pow must
  // be told; defaulting it to a constant at the call site would silently mis-describe any future
  // template built at a different version.
  const majorVersion = Number(hashingHeader.majorVersion);
  if (!Number.isInteger(majorVersion) || majorVersion < 0 || majorVersion > 255) {
    bad('bad_field', 'the block header major version is out of range');
  }
  if (input.majorVersion !== undefined) {
    const declared = requireU32(input.majorVersion, 'majorVersion', { max: 255 });
    if (declared !== majorVersion) bad('blob_mismatch', 'majorVersion does not match the block header');
  }

  const { blob: hashingTemplate } = zeroNonce(hashingBlob);

  const nonceStart = input.nonceStart === undefined ? 0 : requireU32(input.nonceStart, 'nonceStart');
  const nonceRange = input.nonceRange === undefined
    ? DEFAULT_REAL_NONCE_RANGE
    : requireU32(input.nonceRange, 'nonceRange', { min: 1, max: MAX_REAL_NONCE_RANGE });
  if (nonceStart + nonceRange > 0x100000000) {
    bad('bad_field', 'nonce window runs past the end of the uint32 nonce space');
  }

  const ttlMs = input.ttlMs === undefined
    ? DEFAULT_REAL_TTL_MS
    : requireU32(input.ttlMs, 'ttlMs', { min: 1000, max: 60 * 60 * 1000 });

  const seedHeight = input.seedHeight === undefined ? null : requireU64(input.seedHeight, 'seedHeight');

  // MINTED, NEVER SUPPLIED WITH THE TEMPLATE. `mintIssuanceId` is the dependency seam and the only
  // way a deterministic value can get in; the default is 16 cryptographically random bytes. The
  // result is validated regardless of which produced it, so a test seam cannot install a malformed
  // identity either.
  const issuanceId = mintIssuanceId();
  if (typeof issuanceId !== 'string' || !/^[0-9a-f]{32}$/.test(issuanceId)) {
    bad('bad_field', 'issuanceId must be exactly 32 lowercase hex characters (16 random bytes)');
  }

  const issuedAtMs = now();
  if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs < 0) {
    bad('bad_field', 'the clock must return a non-negative safe integer');
  }
  const expiresAtMs = issuedAtMs + ttlMs;
  if (!Number.isSafeInteger(expiresAtMs)) {
    bad('bad_field', 'the template expiry exceeds the safe integer time range');
  }

  // CONTENT identity: what the work IS. Two issuances of the same template share this.
  const contentDigest = createHash('sha256').update([
    'meepcoin-real-template-content/2',
    REAL_ALGORITHM_LABEL,
    `height=${height.toString()}`,
    `majorVersion=${majorVersion}`,
    `epochKey=${epochKeyHex}`,
    `seedHash=${seedHashHex}`,
    `difficulty=${difficulty.toString()}`,
    `target=${targetHexLE}`,
    `hashingTemplate=${blobToHex(hashingTemplate)}`,
    `fullBlock=${blobToHex(fullBlob)}`,
    `hashingNonceOffset=${hashingHeader.offset}`,
    `fullNonceOffset=${fullHeader.offset}`,
  ].join('\n'), 'utf8').digest('hex');

  // AUTHORIZATION identity: which issuance of that work this is. Everything that affects whether a
  // candidate is allowed to act, not merely what it hashes.
  const authDigest = createHash('sha256').update([
    'meepcoin-real-template-auth/2',
    `content=${contentDigest}`,
    `issuance=${issuanceId}`,
    `issuedAtMs=${issuedAtMs}`,
    `expiresAtMs=${expiresAtMs}`,
    `seedHeight=${seedHeight === null ? 'null' : seedHeight.toString()}`,
    `nonceStart=${nonceStart}`,
    `nonceRange=${nonceRange}`,
    // Appended ONLY when a share target was configured, so a legacy job's authorization digest --
    // and therefore its job id -- is exactly what it was before share work existed.
    ...(shareConfigured ? [`shareDifficulty=${shareDifficulty.toString()}`, `shareTarget=${shareTargetHexLE}`] : []),
  ].join('\n'), 'utf8').digest('hex');

  const job = {
    kind: 'real',
    algorithm: REAL_ALGORITHM_LABEL,
    jobId: `${idPrefix}-${authDigest.slice(0, 32)}`,
    issuanceId,
    contentDigest,
    authDigest,

    height,
    seedHeight,
    majorVersion,
    epochKeyHex,
    seedHashHex,

    difficulty,
    targetHexLE,
    // Equal to difficulty/targetHexLE unless a share target was configured. `shareWork` is the one
    // flag a caller should branch on.
    shareDifficulty,
    shareTargetHexLE,
    shareWork: shareConfigured,

    hashingTemplateHex: blobToHex(hashingTemplate),
    hashingNonceOffset: hashingHeader.offset,
    fullNonceOffset: fullHeader.offset,
    templateNonce: readNonce(fullBlob, fullHeader.offset),

    nonceStart,
    nonceRange,
    issuedAtMs,
    expiresAtMs,
    note: typeof input.note === 'string' ? input.note.slice(0, 200) : '',
  };

  // The bytes go here and NOWHERE on the job object. Reaching them requires one of the copy-only
  // accessors below, and what those hand back is a copy.
  PRIVATE.set(job, {
    targetBytes,
    shareTargetBytes,
    hashingTemplate,
    fullBlockBlob: fullBlob,
    epochKey: hexToBlob(epochKeyHex),
    seedHash: hexToBlob(seedHashHex),
  });

  // Freezes the OBJECT so a field cannot be reassigned. It says nothing about array contents --
  // which is precisely why no array is on it.
  return Object.freeze(job);
}

function privateOf(job) {
  const p = PRIVATE.get(job);
  if (!p) bad('not_a_job', 'this object is not a real-template job created by this module');
  return p;
}

/** The 32-byte target, as a fresh copy. Mutating it changes nothing. */
export function targetBytesOf(job) {
  return privateOf(job).targetBytes.slice();
}

/**
 * The 32-byte SHARE target, as a fresh copy. Identical to the block target unless a share
 * difficulty was configured, in which case it is numerically greater (an easier target).
 */
export function shareTargetBytesOf(job) {
  return privateOf(job).shareTargetBytes.slice();
}

/** The nonce-zeroed hashing template, as a fresh copy. */
export function hashingTemplateOf(job) {
  return privateOf(job).hashingTemplate.slice();
}

/**
 * The FULL BLOCK blob, as a fresh copy.
 *
 * Server-side only. Nothing that builds a browser-bound message may call this, and
 * toClientJobMessage() below does not.
 */
export function fullBlockBlobOf(job) {
  return privateOf(job).fullBlockBlob.slice();
}

/** Field names that must NEVER appear in a browser-bound message. */
export const SERVER_ONLY_FIELDS = Object.freeze([
  'fullBlockBlob', 'blocktemplateBlobHex', 'blocktemplate_blob',
  'fullNonceOffset', 'hashingNonceOffset', 'templateNonce',
  'miningAddress', 'wallet_address',
  'difficulty', 'wideDifficulty', 'wide_difficulty',
  'targetBytes', 'hashingTemplate', 'authDigest',
]);

/**
 * The ONLY projection of a real job that may reach a browser.
 *
 * Built by naming each field explicitly rather than by deleting fields from the job, so a future
 * field added to the job is absent here by default instead of leaking by default.
 */
export function toClientJobMessage(job) {
  return {
    type: 'real_job',
    jobId: job.jobId,
    issuanceId: job.issuanceId,
    contentDigest: job.contentDigest,
    algorithm: job.algorithm,
    height: job.height.toString(),          // decimal STRING: a uint64 must not ride on a Number
    majorVersion: job.majorVersion,
    epochKeyHex: job.epochKeyHex,
    seedHashHex: job.seedHashHex,
    hashingTemplateHex: job.hashingTemplateHex,
    targetHexLE: job.targetHexLE,
    // THE SHARE TARGET IS PROJECTED ONLY FOR AN OPTED-IN JOB, and it is always the server's own:
    // the browser never chooses a target. A legacy job carries neither field, so its message is
    // byte-for-byte what it has always been.
    ...(job.shareWork === true
      ? { shareWork: true, shareTargetHexLE: job.shareTargetHexLE }
      : {}),
    nonceStart: job.nonceStart,
    nonceRange: job.nonceRange,
    expiresAtMs: job.expiresAtMs,
    notice: 'real MeepCoin block template - the full block stays on the server',
  };
}

/** The hashing context a verifier is initialised from. Fresh copies, every time. */
export function hashingContextFor(job) {
  const p = privateOf(job);
  return {
    epochKey: p.epochKey.slice(),
    seedHash: p.seedHash.slice(),
    height: job.height,
    template: p.hashingTemplate.slice(),
  };
}
