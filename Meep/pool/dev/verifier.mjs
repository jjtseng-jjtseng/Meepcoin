// Server-side share verification for the local development pool.
//
// TRUST BOUNDARY: the browser is untrusted. It submits jobId, nonce and workerId; the server
// recomputes the hash itself from its OWN job context and compares against its OWN target. A
// client-supplied `resultHash` is never read here -- it is not even a parameter of verify().
//
// CONSENT BOUNDARY: nothing in this module runs until a client declares start intent. The Wasm
// module is not imported, no instance exists and no dataset is allocated until
// createShareVerifier() is called, and pool/dev/server.mjs calls it only from the start-intent
// path. (The official page sends that intent only from its Start click handler, which is
// separately tested; the server itself can only observe the declaration.) The artifact bytes are
// read and identity-checked earlier, at pool startup, so that the server can serve exactly the
// bytes it verified -- reading ~58.1 KiB is not importing, compiling or instantiating anything.
//
// The hash-call counter is the point of this module for the tests: it makes "the expensive
// operation did not happen" an observable fact rather than an assertion about control flow.

import { pathToFileURL } from 'node:url';

import { createV2Hasher, createV2HasherForContext } from '../../web-miner/lib/shared/wasm_hasher.js';
import { meetsTargetLE, bytesToHex, hexToBytes } from '../../web-miner/lib/shared/target.js';
import { verifyWasmIdentity, WASM_MJS_PATH, WASM_BINARY_PATH, WasmIdentityError } from './identity.mjs';

export { WASM_MJS_PATH, WASM_BINARY_PATH, WasmIdentityError, verifyWasmIdentity };

/**
 * Build the server's own MeepHash-W v2 hasher. Verifies the pinned artifact identity first and
 * throws WasmIdentityError before importing anything if it does not match.
 *
 * This is a SECOND, INDEPENDENT INSTANCE of the same Wasm build the browser loads -- separate
 * memory, separate dataset, no shared state with any client. It is NOT a second implementation:
 * see the honesty note in web-miner/lib/shared/wasm_hasher.js and
 * docs/LOCAL_BROWSER_MINER_SLICE.md.
 */
export async function createShareVerifier({
  mjsPath = WASM_MJS_PATH,
  wasmPath = WASM_BINARY_PATH,
  signal,
  /**
   * OPTIONAL explicit hashing context, { epochKeyHex, seedHashHex, height, templateHex }. Omitted,
   * this is the fixed synthetic context exactly as before. The recorded-template simulation passes
   * the context of the server-created job; nothing here ever comes from a client.
   */
  context = null,
} = {}) {
  const identity = verifyWasmIdentity({ mjsPath, wasmPath });
  // Abortable startup. Shutdown must be able to stop waiting for an initialization that may never
  // finish, rather than blocking cancellation behind it.
  if (signal?.aborted) throw new VerifierCancelledError('verifier startup aborted');
  const createModule = (await import(pathToFileURL(mjsPath).href)).default;
  if (signal?.aborted) throw new VerifierCancelledError('verifier startup aborted');
  const hasher = context === null
    ? await createV2Hasher(createModule)
    : await createV2HasherForContext(createModule, {
      epochKey: hexToBytes(context.epochKeyHex),
      seedHash: hexToBytes(context.seedHashHex),
      height: context.height,
      template: hexToBytes(context.templateHex),
    });
  let closed = false;
  let closing = false;
  let closeReason = null;
  let closePromise = null;
  let released = false;

  return {
    /** Single-build verification: Wasm only, no native cross-check. */
    kind: 'wasm',
    identity,
    /** No native build is running, so no native algorithm memory is allocated. */
    nativeAlgorithmBytes: () => null,
    /** Real MeepHash-W v2 computations this verifier has performed. */
    get hashCalls() {
      return hasher.hashCalls;
    },
    wasmHeapBytes() {
      return hasher.wasmHeapBytes();
    },
    /**
     * Recompute one nonce and judge it against the server's target. No client input involved.
     * Async so the pipeline is written against a genuinely asynchronous verifier -- which is what
     * the native helper will be -- rather than one that only happens to be synchronous today.
     */
    async verify(nonce, targetBytes) {
      // FAIL CLOSED once cancellation has begun. This is what lets pool shutdown drain session
      // operations: a request issued (or still outstanding) after beginClose() must settle by
      // itself rather than wait for a teardown that is itself waiting for the drain.
      if (closing) throw new VerifierCancelledError(closeReason);
      const hash = hasher.hashOne(nonce);
      return { hash, hashHexLE: bytesToHex(hash), meets: meetsTargetLE(hash, targetBytes) };
    },
    /** Raw recomputation. Used only by tests that cross-check the committed vectors. */
    hashOne(nonce) {
      return hasher.hashOne(nonce);
    },
    /**
     * PHASE 1 of shutdown: synchronous, idempotent cancellation.
     *
     * Marks the verifier cancelled and settles everything outstanding fail-closed. It does NOT
     * wait for teardown. That split is the whole point: a verifier whose requests are answered by
     * a child process cannot have its requests drained by a teardown that is waiting for the
     * drain to finish. Calling this first breaks that cycle.
     */
    beginClose(reason = 'verifier shutting down') {
      if (closing) return;
      closing = true;
      closeReason = reason;
      // Nothing is outstanding for the synchronous Wasm hasher; a child-backed verifier rejects
      // its in-flight request map here.
    },
    /**
     * PHASE 2: asynchronous, idempotent terminal teardown. Awaiting a successful call means this
     * verifier has released everything it owns.
     *
     * On failure the resource is NOT abandoned: `closed` stays false, the handle remains usable,
     * and a later close() retries rather than returning a permanently rejected promise. Marking a
     * resource released when release failed is how an un-reaped child process gets lost.
     */
    async close(reason = 'verifier shutting down') {
      if (released) return;
      this.beginClose(reason);
      if (closePromise) return closePromise;
      closePromise = (async () => {
        hasher.free();
        released = true;
        closed = true;
      })();
      try {
        await closePromise;
      } catch (err) {
        closePromise = null; // allow a bounded retry; do not latch a rejected promise forever
        throw err;
      }
      return undefined;
    },
    /**
     * Bounded escalation for a graceful close that failed. For the Wasm verifier this is the same
     * release; it exists so callers have one contract, and so the native helper can escalate to
     * signalling its own exact child.
     */
    async forceClose(reason = 'verifier force close') {
      this.beginClose(reason);
      closePromise = null;
      return this.close(reason);
    },
    /** True only after release is CONFIRMED. */
    get closed() {
      return released;
    },
    /** True once cancellation has begun, whether or not teardown has finished. */
    get closing() {
      return closing;
    },
  };
}

/** Thrown by verify() once beginClose() has run, so callers fail closed instead of hanging. */
export class VerifierCancelledError extends Error {
  constructor(reason) {
    super(reason ?? 'verifier cancelled');
    this.name = 'VerifierCancelledError';
    this.cancelled = true;
  }
}

/**
 * Cross-check helper for tests ONLY: derive the fixture by actually hashing the window.
 *
 * The production path does NOT do this -- it reads the committed vectors through
 * pool/dev/identity.mjs so that no MeepHash-W call happens before Start. This exists so a test
 * can prove the two agree.
 */
export function deriveSyntheticTargetByHashing(verifier, { nonceStart = 0, nonceRange = 16 } = {}) {
  let best = null;
  let worst = null;
  for (let i = 0; i < nonceRange; i++) {
    const nonce = (nonceStart + i) >>> 0;
    const hash = verifier.hashOne(nonce);
    if (best === null || meetsTargetLE(hash, best.hash)) best = { nonce, hash };
    if (worst === null || meetsTargetLE(worst.hash, hash)) worst = { nonce, hash };
  }
  return {
    targetBytes: best.hash,
    targetHexLE: bytesToHex(best.hash),
    qualifyingNonce: best.nonce,
    qualifyingHashHexLE: bytesToHex(best.hash),
    nonQualifyingNonce: worst.nonce,
    nonQualifyingHashHexLE: bytesToHex(worst.hash),
    nonceStart,
    nonceRange,
  };
}
