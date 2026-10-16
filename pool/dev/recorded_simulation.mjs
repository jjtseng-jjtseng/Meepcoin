// Assemble the ONE recorded-template simulation from the committed devnet block vectors.
//
// EVERY VALUE COMES FROM THE COMMITTED FILE. Nothing is retyped: the row is looked up by height and
// cross-checked against the expectations below, so a swapped or edited vector file fails loudly
// instead of quietly changing what the simulation demonstrates.
//
// WHY HEIGHT 2113. It is the first committed row whose seed height is 2048 rather than 0, i.e. the
// first whose epoch key actually differs from the genesis one. Using a row that shares the genesis
// epoch key would not exercise the contextual setup at all.
//
// THE WINDOW IS ONE NONCE WIDE. The browser is asked for exactly the recorded nonce and nothing
// else. There is no search, no scan and no benchmark: one contextual hash, then stop.
//
// THE NATIVE CHECK IS THE LIVE LOCAL HELPER. The server-side verifier is createDualVerifier()
// initialised with THIS job's context: the server's own contextual Wasm build and the existing
// native C++ helper (meepow-v2-helper, in WSL on Windows), under the existing source-identity,
// process-identity, fault and two-phase shutdown machinery. Nothing is spawned here: this builds a
// FACTORY, and the factory runs only after a Start has reserved the one attempt.
//
// THE RECORDED ROW STILL BINDS THE MOCK DAEMON. createRecordedOracle().bindTo(job) is kept as a
// precondition check -- it proves the committed row describes this exact job before the mock daemon
// will answer -- but it is no longer on the verification path and computes nothing for it.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { createRealTemplateJob, hashingContextFor } from './real_template.mjs';
import { createFatalLatch, createTemplateAuthority } from './run_guard.mjs';
import { createMockDaemon, createRecordedOracle } from './recorded_oracle.mjs';
import { createDualVerifier } from './dual_verifier.mjs';
import { blobToHex } from './block_blob.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(__dirname, '../..');
export const VECTOR_PATH = resolve(REPO_ROOT, 'meepow/vectors/block_vectors_v16_devnet.json');

/** The row this simulation uses, and the values a reviewer can check by eye. */
export const RECORDED_HEIGHT = 2113;
export const EXPECTED = Object.freeze({
  height: 2113,
  seedHeight: 2048,
  majorVersion: 16,
  nonce: 1325931723,
  difficulty: 500,
  powHash: '0f25c4a8f186c14795b2978948b1fa6b44c6f58ecce4c1a991b4eb5638f31600',
  blockHash: 'c32e39e215733d4ef3b54989ec72a45bc3b7ee15713f63dcd8ed7faa44482375',
  /**
   * SHA-256 OVER THE WHOLE ROW, so the mock's expectations cannot be silently redefined.
   *
   * The named checks above cover the values a reviewer reads; they do NOT cover the two long byte
   * strings the mock daemon compares against -- full_block_blob and block_hashing_blob -- nor the
   * nonce offset, the byte order, the target or the coinbase fields. Editing a tail byte of the full
   * block would therefore have changed what "the mock accepted" meant while every named check still
   * passed. This digest covers every field of the row, in sorted key order, so any edit anywhere in
   * it fails loudly here instead.
   */
  rowDigest: 'f8ec5a1c43f2cebf24799fe44910730a56c87f30b521e74230bf88829785b094',
});

/** The canonical serialisation the pinned digest is taken over: every field, sorted by key. */
export function digestRecordedRow(row) {
  const canonical = Object.keys(row).sort()
    .map((k) => `${k}=${JSON.stringify(row[k])}`)
    .join('\n');
  return createHash('sha256')
    .update(`meepcoin-recorded-vector-row/1\n${canonical}`, 'utf8')
    .digest('hex');
}

export class RecordedVectorError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RecordedVectorError';
  }
}

/** Load and cross-check the committed row. Every mismatch is fatal. */
export function loadRecordedRow({ vectorPath = VECTOR_PATH, height = RECORDED_HEIGHT } = {}) {
  const doc = JSON.parse(readFileSync(vectorPath, 'utf8'));
  const row = doc.vectors.find((v) => v.height === height);
  if (!row) throw new RecordedVectorError(`no committed block vector at height ${height}`);

  // The cross-checks describe THE SIMULATION ROW. Loading any other row (a test comparing against
  // the genesis row, say) is a plain lookup and must not be measured against 2113's values.
  if (height !== RECORDED_HEIGHT) return row;

  const checks = [
    ['height', row.height, EXPECTED.height],
    ['seed_height', row.seed_height, EXPECTED.seedHeight],
    ['major_version', row.major_version, EXPECTED.majorVersion],
    ['nonce', row.nonce, EXPECTED.nonce],
    ['difficulty', row.difficulty, EXPECTED.difficulty],
    ['expected_meephash_w_v2', row.expected_meephash_w_v2, EXPECTED.powHash],
    ['daemon_pow_hash', row.daemon_pow_hash, EXPECTED.powHash],
    ['block_hash', row.block_hash, EXPECTED.blockHash],
    // The whole row, so the fields no named check reads cannot drift underneath the mock.
    ['row digest', digestRecordedRow(row), EXPECTED.rowDigest],
  ];
  for (const [what, actual, want] of checks) {
    if (actual !== want) {
      throw new RecordedVectorError(`committed vector ${what} is ${actual}, expected ${want}`);
    }
  }
  // The daemon feeds one seed hash as BOTH inputs; the row must agree, or the context is not what
  // this simulation claims to reproduce.
  if (row.epoch_key !== row.delayed_seed_input) {
    throw new RecordedVectorError('the committed row has a different epoch key and delayed seed input');
  }
  if (row.daemon_agrees_with_independent_meephash !== true) {
    throw new RecordedVectorError('the committed row does not record daemon agreement');
  }
  return row;
}

/**
 * Build everything the simulation session needs. One call per server process.
 *
 * The nonce window is exactly ONE nonce wide, positioned on the recorded nonce.
 */
export function buildRecordedSimulation({
  vectorPath = VECTOR_PATH,
  now = () => Date.now(),
  // The pool's own top-level helper configuration, passed through unchanged. `helperOptions` is
  // checked against the dual verifier's allowlist when the factory runs, before anything is spawned.
  helperPath,
  wslDistro = null,
  helperOptions,
  wasmPaths,
} = {}) {
  const row = loadRecordedRow({ vectorPath });

  const job = createRealTemplateJob({
    height: row.height,
    seedHashHex: row.delayed_seed_input,
    epochKeyHex: row.epoch_key,
    wideDifficulty: String(row.difficulty),
    blockhashingBlobHex: row.block_hashing_blob,
    blocktemplateBlobHex: row.full_block_blob,
    // EXACTLY ONE NONCE. No search, no scan.
    nonceStart: row.nonce,
    nonceRange: 1,
    seedHeight: row.seed_height,
    ttlMs: 10 * 60 * 1000,
    note: 'recorded-template simulation over a committed historical devnet block',
  }, { now });

  const latch = createFatalLatch();
  const authority = createTemplateAuthority({ now });
  authority.publish(job);

  // The committed row must describe THIS job before the mock daemon will answer anything.
  const oracle = createRecordedOracle(row);
  oracle.bindTo(job);
  const mockDaemon = createMockDaemon(row, { oracle });

  // THE AUTHORITATIVE CONTEXT, from the server-created job's private bytes and nowhere else. Both
  // the contextual Wasm build and the helper's INIT line are built from exactly this.
  const ctx = hashingContextFor(job);
  const recordedContext = Object.freeze({
    epochKeyHex: blobToHex(ctx.epochKey),
    seedHashHex: blobToHex(ctx.seedHash),
    height: ctx.height.toString(),
    templateHex: blobToHex(ctx.template),
  });

  return {
    job,
    latch,
    authority,
    oracle,
    mockDaemon,
    expectedHashHexLE: row.expected_meephash_w_v2,
    row,
    recordedContext,
    /**
     * THE LIVE SERVER-SIDE VERIFIER: the server's own contextual Wasm instance AND the native
     * helper, both initialised with `recordedContext`. Called only after a Start reserved the one
     * attempt. No synthetic self-test runs -- its vectors describe a different context -- so the
     * single recorded candidate is the known-answer check, and exactly one native HASH is sent.
     */
    makeServerVerifier: ({ signal, onFault }) => createDualVerifier({
      ...(wasmPaths ? { wasmPaths } : {}),
      ...(helperPath ? { helperPath } : {}),
      ...(wslDistro ? { wslDistro } : {}),
      ...(helperOptions ? { helperOptions } : {}),
      signal,
      onFault,
      context: recordedContext,
      selfTestNonces: [],
      checkSourceIdentity: true,
    }),
  };
}
