// Server-side personalization of one daemon block template.
//
// A real pool must not give every browser the same work.  The daemon can reserve bytes inside the
// miner transaction; the pool writes a unique value there, then asks the canonical native block
// parser to derive the corresponding hashing blob.  Only that derived hashing context reaches the
// browser.  The full block and the reserved-region facts remain server-side.
//
// This module deliberately does NOT launch a converter or allocate extra nonces.  Those are separate
// ownership/state boundaries.  It is the small, pure orchestration seam between a future allocator,
// a future owned native converter, and the existing immutable real-template job.

import { createHash } from 'node:crypto';

import { createRealTemplateJob } from './real_template.mjs';

const LOWER_HEX = /^[0-9a-f]+$/;
const ALLOWED_OPTION_KEYS = new Set([
  'extraNonceHex', 'convertFullBlock', 'nonceStart', 'nonceRange', 'ttlMs',
  'shareDifficulty', 'note', 'now', 'mintIssuanceId',
]);

export class TemplatePersonalizationError extends Error {
  constructor(code, message, cause) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'TemplatePersonalizationError';
    this.code = code;
  }
}

function fail(code, message, cause) {
  throw new TemplatePersonalizationError(code, message, cause);
}

function exactLowerHex(value, what) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0 || !LOWER_HEX.test(value)) {
    fail('bad_input', `${what} must be non-empty even-length lowercase hex`);
  }
  return value;
}

/**
 * Personalize one strict daemon template and return an immutable real-template job.
 *
 * `convertFullBlock` is an injected, server-owned canonical converter:
 *     async (personalizedFullBlockHex) => canonicalHashingBlobHex
 * It is called exactly once, after the reserved bytes are written.  Its output is still validated by
 * createRealTemplateJob; no converter assertion is accepted on faith.
 */
export async function personalizeRealTemplate(template, options) {
  if (template === null || typeof template !== 'object' || Array.isArray(template)) {
    fail('bad_input', 'template must be an object returned by the daemon adapter');
  }
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    fail('bad_input', 'personalization options must be an object');
  }
  for (const key of Object.keys(options)) {
    if (!ALLOWED_OPTION_KEYS.has(key)) fail('bad_input', `unexpected personalization option ${key.slice(0, 40)}`);
  }

  const { extraNonceHex, convertFullBlock } = options;
  if (typeof convertFullBlock !== 'function') fail('bad_input', 'convertFullBlock must be an injected function');
  if (!Number.isSafeInteger(template.reservedOffset) || template.reservedOffset < 0) {
    fail('bad_input', 'reservedOffset must be a non-negative safe integer');
  }
  if (!Number.isInteger(template.reservedSize) || template.reservedSize < 1 || template.reservedSize > 255) {
    fail('bad_input', 'reservedSize must be an integer from 1 to 255');
  }
  exactLowerHex(extraNonceHex, 'extraNonceHex');
  if (extraNonceHex.length !== template.reservedSize * 2) {
    fail('bad_input', 'extraNonceHex length must exactly equal the daemon-reserved size');
  }

  const originalFullHex = exactLowerHex(template.blocktemplateBlobHex, 'blocktemplateBlobHex');
  const full = Buffer.from(originalFullHex, 'hex');
  // Check with subtraction first so even a hostile very-large safe offset cannot make the
  // decision depend on a rounded addition.
  if (template.reservedOffset > full.length - template.reservedSize) {
    fail('bad_input', 'reserved region falls outside blocktemplateBlobHex');
  }
  const end = template.reservedOffset + template.reservedSize;
  Buffer.from(extraNonceHex, 'hex').copy(full, template.reservedOffset);
  const personalizedFullHex = full.toString('hex');

  let converted;
  try {
    converted = await convertFullBlock(personalizedFullHex);
  } catch (cause) {
    fail('conversion_failed', 'the canonical block-hashing conversion failed', cause);
  }
  const blockhashingBlobHex = exactLowerHex(converted, 'converted blockhashing blob');

  const jobInput = {
    height: template.height,
    seedHashHex: template.seedHashHex,
    wideDifficulty: template.wideDifficulty,
    blockhashingBlobHex,
    blocktemplateBlobHex: personalizedFullHex,
    ...(template.epochKeyHex === undefined ? {} : { epochKeyHex: template.epochKeyHex }),
    ...(template.seedHeight === null || template.seedHeight === undefined ? {} : { seedHeight: template.seedHeight }),
    ...(options.nonceStart === undefined ? {} : { nonceStart: options.nonceStart }),
    ...(options.nonceRange === undefined ? {} : { nonceRange: options.nonceRange }),
    ...(options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }),
    ...(options.shareDifficulty === undefined ? {} : { shareDifficulty: options.shareDifficulty }),
    ...(options.note === undefined ? {} : { note: options.note }),
  };
  const job = createRealTemplateJob(jobInput, {
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.mintIssuanceId === undefined ? {} : { mintIssuanceId: options.mintIssuanceId }),
  });
  const extraNonceDigest = createHash('sha256')
    .update('meepcoin-pool-extra-nonce/1\n', 'utf8')
    .update(Buffer.from(extraNonceHex, 'hex'))
    .digest('hex');

  return Object.freeze({
    job,
    reservedOffset: template.reservedOffset,
    reservedSize: template.reservedSize,
    extraNonceDigest,
  });
}
