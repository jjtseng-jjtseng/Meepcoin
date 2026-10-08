// The dual verifier: a share is accepted only when the server's own WebAssembly result and the
// native frozen-v2 result are byte-for-byte identical AND the agreed hash meets the server's
// target.
//
// WHAT THIS IS. An independent BUILD/RUNTIME cross-check of the SAME frozen C++ source. Both sides
// descend from meepow/src; one is compiled to WebAssembly by Emscripten, the other natively by the
// host compiler. It can catch glue, compiler, optimiser and runtime divergence between those two
// builds.
//
// WHAT THIS IS NOT. A second, independently authored implementation of MeepHash-W. If the frozen
// source itself is wrong, both sides are wrong together and agree. It does not make the algorithm
// secure, memory-hard, GPU-resistant, or fit for anything of value.
//
// FAIL CLOSED, GLOBALLY AND PERMANENTLY. A disagreement is not a rejected share and business as
// usual: it means one of the two builds is producing wrong answers, and this pool cannot tell
// which. So the verifier latches UNHEALTHY for the life of the process -- no later acceptance, no
// silent Wasm-only fallback, and every active mining session is stopped. Recovery requires a pool
// restart, deliberately.
//
// THE LATCH IS AN ACCEPTANCE FENCE, NOT A GATE AT THE DOOR. Checking health once on entry is not
// enough when two verifications are in flight: the first can expose a broken build while the
// second is mid-flight, and a second that only checked on the way in would still return success.
// Every asynchronous boundary in verify() is followed by a recheck, and the last thing before a
// successful return is another one. A result computed before the latch may never commit after it.

import { createShareVerifier } from './verifier.mjs';
import {
  startNativeHelper, HelperFaultError, HelperMissingError, HELPER_BUILD_PATH,
} from './native_helper.mjs';
import { checkReportedSourceId, SourceIdentityError } from './source_identity.mjs';
import { SYNTHETIC_CONTEXT } from './identity.mjs';
import { hexToBytes, meetsTargetLE } from '../../web-miner/lib/shared/target.js';

export { HelperFaultError, HelperMissingError, SourceIdentityError };

/**
 * A caller supplied a nested helper option it is not allowed to supply.
 *
 * SEPARATE FROM EVERY OTHER FAILURE ON PURPOSE. This is a configuration mistake, discovered before
 * anything is spawned, and it must not be mistaken for a build disagreement or a runtime fault.
 */
export class HelperOptionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'HelperOptionError';
  }
}

/**
 * THE PRODUCTION SAFETY WIRING. These belong to createDualVerifier and to nobody else.
 *
 *   onFault     the callback that makes an idle helper crash reach the pool. Replacing it with a
 *               no-op let a helper die after mining_ready while pool.verifierHealth stayed
 *               healthy and the active client was never sent mining_unavailable.
 *   signal      the startup AbortSignal shutdown uses to reach a verifier that is still in HELLO,
 *               INIT or the self-test.
 *   helperPath  the executable, which the pool passes as a documented TOP-LEVEL option.
 *   wslDistro / resolveWslDistro
 *               the PARENT-PINNED WSL distribution and its discovery. The whole point of pinning
 *               it is that nothing downstream of the parent chooses where the helper is launched
 *               or where it is later inspected and signalled -- a nested override would hand
 *               that authority straight back.
 *
 * A nested option with one of these names is REFUSED, loudly, rather than quietly ignored: a
 * caller that thinks it installed a fault handler and did not is worse off than one told it may
 * not. Spread order is fixed independently below, so neither mechanism is the only defence.
 */
export const RESERVED_HELPER_OPTIONS = Object.freeze([
  'onFault', 'signal', 'helperPath', 'wslDistro', 'resolveWslDistro',
]);

/**
 * The nested helper options a caller MAY supply: the deterministic-launch seams the lifecycle
 * tests need, none of which can disable the wiring above.
 *
 *   useWsl        run the helper directly instead of through wsl.exe
 *   spawnFn       substitute the helper child (a fake that can crash, stall or lie on cue)
 *   probeSpawnFn  substitute a probe child, so reaping can be exercised with a real handle shape
 *   wslRunner     substitute the whole probe channel, for the four observation states
 *   limits        tighten or loosen the bounded deadlines
 *
 * An unknown key is refused too. Silently dropping a misspelled option is how a test believes it
 * configured something it did not.
 */
export const ALLOWED_HELPER_OPTIONS = Object.freeze([
  'useWsl', 'spawnFn', 'probeSpawnFn', 'wslRunner', 'limits',
]);

/**
 * Validate nested helper options against the allowlist. Runs BEFORE anything is created, so a bad
 * configuration cannot leave a half-built verifier behind.
 */
export function checkHelperOptions(helperOptions) {
  if (helperOptions === undefined || helperOptions === null) return {};
  if (typeof helperOptions !== 'object' || Array.isArray(helperOptions)) {
    throw new HelperOptionError('helperOptions must be a plain object');
  }
  const safe = {};
  // Reflect.ownKeys, not Object.keys: a symbol-keyed property would still be copied by a spread.
  for (const key of Reflect.ownKeys(helperOptions)) {
    const name = typeof key === 'symbol' ? key.toString() : key;
    if (typeof key === 'symbol') {
      throw new HelperOptionError(`helperOptions may not carry symbol keys (${name})`);
    }
    if (RESERVED_HELPER_OPTIONS.includes(key)) {
      throw new HelperOptionError(
        `helperOptions.${key} is reserved: the dual verifier owns the helper path, the startup `
        + 'abort signal and the fault callback that stops the pool when the helper dies while '
        + 'idle. Overriding it would reopen exactly that hole. '
        + `Allowed nested options: ${ALLOWED_HELPER_OPTIONS.join(', ')}.`,
      );
    }
    if (!ALLOWED_HELPER_OPTIONS.includes(key)) {
      throw new HelperOptionError(
        `unknown helperOptions.${key}. Allowed nested options: ${ALLOWED_HELPER_OPTIONS.join(', ')}.`,
      );
    }
    safe[key] = helperOptions[key];
  }
  return safe;
}

/**
 * Validate an explicit hashing context BEFORE anything is created. Exactly the fields the helper's
 * INIT line and the contextual Wasm hasher both consume, in the helper's own grammar.
 */
const HEX64 = /^[0-9a-f]{64}$/;
const CANONICAL_U64 = /^(0|[1-9][0-9]{0,19})$/;
const LOWER_HEX_BYTES = /^(?:[0-9a-f]{2})+$/;
const MAX_CONTEXT_TEMPLATE_BYTES = 2048;   // the helper's MAX_TEMPLATE_BYTES

export class VerifierContextError extends Error {
  constructor(message) {
    super(message);
    this.name = 'VerifierContextError';
  }
}

function checkContext(context) {
  if (context === null || typeof context !== 'object') throw new VerifierContextError('context must be an object');
  const { epochKeyHex, seedHashHex, height, templateHex } = context;
  if (typeof epochKeyHex !== 'string' || !HEX64.test(epochKeyHex)) {
    throw new VerifierContextError('context.epochKeyHex must be 64 lowercase hex characters');
  }
  if (typeof seedHashHex !== 'string' || !HEX64.test(seedHashHex)) {
    throw new VerifierContextError('context.seedHashHex must be 64 lowercase hex characters');
  }
  if (typeof height !== 'string' || !CANONICAL_U64.test(height) || BigInt(height) > 0xffffffffffffffffn) {
    throw new VerifierContextError('context.height must be a canonical decimal uint64 string');
  }
  if (typeof templateHex !== 'string' || !LOWER_HEX_BYTES.test(templateHex)
    || templateHex.length / 2 > MAX_CONTEXT_TEMPLATE_BYTES) {
    throw new VerifierContextError(
      `context.templateHex must be 1..${MAX_CONTEXT_TEMPLATE_BYTES} bytes of lowercase hex`,
    );
  }
  return Object.freeze({ epochKeyHex, seedHashHex, height, templateHex });
}

export class VerifierMismatchError extends Error {
  constructor(nonce, wasmHex, nativeHex) {
    super(
      `MeepHash-W v2 build disagreement on nonce ${nonce}: `
      + `wasm=${wasmHex} native=${nativeHex}. `
      + 'The WebAssembly and native builds of the same frozen source produced different hashes. '
      + 'This pool cannot tell which is correct, so verification is disabled until it is restarted.',
    );
    this.name = 'VerifierMismatchError';
    this.nonce = nonce;
    this.wasmHex = wasmHex;
    this.nativeHex = nativeHex;
  }
}

/**
 * Startup failed, and cleanup of what had already been built could not be confirmed.
 *
 * This exists so the server can keep owning the pieces instead of assuming a rejected factory
 * produced nothing. `resources` are real handles with close()/forceClose()/closed.
 */
export class PartialVerifierError extends Error {
  constructor(cause, resources, cleanupErrors) {
    super(
      `dual verifier startup failed and cleanup could not be confirmed: ${cause?.message ?? cause}`
      + (cleanupErrors.length ? `; cleanup: ${cleanupErrors.join('; ')}` : ''),
    );
    this.name = 'PartialVerifierError';
    this.cause = cause;
    /** @type {{label:string, resource:object}[]} unreleased resources the caller must retain */
    this.resources = resources;
    this.cleanupErrors = cleanupErrors;
  }
}

/**
 * Build the dual verifier. Called ONLY from the pool's start-intent path, so nothing here exists
 * before a client declares start intent.
 *
 * The returned object satisfies the same contract the pool's shutdown barrier relies on:
 * `verify`, `beginClose`, `close`, `forceClose`, `closed`, `closing`.
 */
export async function createDualVerifier({
  wasmPaths,
  signal,
  helperPath = HELPER_BUILD_PATH,
  /** TOP-LEVEL and authoritative, like helperPath. Never accepted nested. */
  wslDistro = null,
  helperOptions = {},
  onFault = () => {},
  selfTestNonces = [SYNTHETIC_CONTEXT.selfTestNonce],
  checkSourceIdentity = true,
  /**
   * THE ONE NARROW PARAMETER this module gained. Omitted, both builds are initialised with the
   * fixed SYNTHETIC context and the startup self-test runs against its committed vectors, exactly
   * as before. Supplied, both builds are initialised with this explicit server-owned context --
   * the recorded-template simulation passes the server-created job's context -- and the synthetic
   * self-test is refused, because its committed vectors describe a different context. The caller
   * must pass `selfTestNonces: []` and owns its own known-answer check.
   */
  context = null,
} = {}) {
  // BEFORE ANYTHING IS CREATED. A refused configuration must not leave a child behind.
  const safeHelperOptions = checkHelperOptions(helperOptions);
  const explicitContext = context === null ? null : checkContext(context);
  if (explicitContext !== null && selfTestNonces.length > 0) {
    throw new VerifierContextError(
      'an explicit context cannot run the synthetic self-test; pass selfTestNonces: [] and check a known answer',
    );
  }
  const initContext = explicitContext ?? {
    epochKeyHex: SYNTHETIC_CONTEXT.epochKeyHex,
    seedHashHex: SYNTHETIC_CONTEXT.seedHashHex,
    height: SYNTHETIC_CONTEXT.height,
    templateHex: SYNTHETIC_CONTEXT.templateHex,
  };

  let wasm = null;
  let helper = null;
  let fault = null;
  let released = false;
  let closing = false;
  /** Abnormal-but-released shutdown facts. Reported, never retried. */
  const protocolAnomalies = [];
  const counters = {
    wasmSelfTestHashes: 0,
    nativeSelfTestHashes: 0,
    wasmShareHashes: 0,
    nativeShareHashes: 0,
  };

  /**
   * Latch unhealthy. Irreversible for the life of this verifier, by design.
   *
   * A CANCELLATION IS NOT A FAULT. Shutdown settles outstanding native requests through an error
   * that is explicitly flagged `cancelled`; latching that would relabel every ordinary pool close
   * as a verifier failure and send miners a fault notice for something we asked for.
   */
  function latch(err) {
    if (err?.cancelled) return err;
    if (!fault) {
      fault = err;
      // SYNCHRONOUSLY STOP THE SIBLINGS. Another verification may already be waiting on a native
      // reply; letting it run to completion would hand a caller a "successful" hash produced by a
      // verifier we have just decided cannot be trusted. Settling its request now is the
      // difference between a fence and a sign.
      try { helper?.fail(`verification disabled: ${err?.message ?? err}`); } catch { /* already latched */ }
      try {
        onFault(err);
      } catch {
        // A fault notifier that throws must not prevent the latch itself.
      }
    }
    return fault;
  }

  /**
   * The fence. Called after every asynchronous boundary, and immediately before any success.
   *
   * `helper.healthy` is part of it deliberately: the native side latches its own faults the moment
   * they happen, and this view may never report healthy while the helper it owns is faulted.
   */
  function assertUsable() {
    if (fault) throw fault;
    if (helper && !helper.healthy && !helper.fault?.cancelled) throw latch(helper.fault);
    if (closing) throw new HelperFaultError('verifier is shutting down', { cancelled: true });
  }

  // A native fault must reach the pool the instant it happens -- even with nothing awaiting a
  // hash. Subscribed BEFORE the helper can do anything, so an exit during INIT is caught too.
  const onHelperFault = (err) => { latch(err); };

  /**
   * Anything created before a failure must be released before the failure is surfaced. Cleanup
   * errors are NOT swallowed: if release cannot be confirmed, the handles are handed back so the
   * server can keep owning them.
   */
  async function abandonPartial(cause, extraResources = []) {
    const cleanupErrors = [];
    const retained = [];
    const drop = async (label, resource) => {
      if (!resource) return;
      try {
        await resource.forceClose('dual verifier startup failed');
      } catch (err) {
        cleanupErrors.push(`${label}: ${err?.message ?? err}`);
      }
      if (!resource.closed) retained.push({ label, resource });
    };
    for (const { label, resource } of extraResources) await drop(label, resource);
    await drop('native helper', helper);
    await drop('wasm verifier', wasm);
    helper = null;
    wasm = null;
    if (retained.length > 0) throw new PartialVerifierError(cause, retained, cleanupErrors);
    if (cleanupErrors.length > 0) {
      // Released, but not silently: the primary error carries what went wrong on the way out.
      cause.cleanupErrors = cleanupErrors;
    }
    throw cause;
  }

  let started = null;
  try {
    wasm = await createShareVerifier({ ...wasmPaths, signal, ...(explicitContext ? { context: explicitContext } : {}) });
    if (signal?.aborted) throw new HelperFaultError('dual verifier startup aborted', { cancelled: true });

    // THE AUTHORITATIVE VALUES GO LAST. checkHelperOptions() has already refused every reserved
    // key, so this ordering is a second, independent guarantee rather than the only one -- the
    // previous spread order (`...helperOptions` last) silently let a caller replace all three.
    started = await startNativeHelper({
      ...safeHelperOptions,
      helperPath,
      ...(wslDistro ? { wslDistro } : {}),
      signal,
      onFault: onHelperFault,
    });
    helper = started.helper;

    // Bind the running binary to the source tree in front of us. A stale helper -- built before
    // the algorithm or the helper itself was edited -- is the failure this catches, and it is the
    // one that would otherwise look like a perfectly healthy cross-check.
    if (checkSourceIdentity) checkReportedSourceId(started.hello.sourceId);

    // The SERVER owns the context: the fixed synthetic one the committed v2 vectors were generated
    // from, or the explicit server-created context above -- never anything a client supplied.
    const ready = await helper.init(initContext);
    assertUsable();

    // STARTUP SELF-TEST. Before a single share is verified, both builds must agree with each other
    // AND with the committed vectors.
    //
    // A disagreement here goes through latch(), exactly like one found later. It is a permanent
    // property of these two builds, not a transient startup hiccup: without the latch the pool
    // would report a generic retryable failure and spawn another helper on the next Start.
    for (const nonce of selfTestNonces) {
      const wasmResult = await wasm.verify(nonce, SYNTHETIC_CONTEXT.zeroTarget);
      counters.wasmSelfTestHashes++;
      assertUsable();
      const nativeHex = await helper.hash(nonce, { selfTest: true });
      counters.nativeSelfTestHashes++;
      assertUsable();
      const wasmHex = wasmResult.hashHexLE;
      if (wasmHex !== nativeHex) throw latch(new VerifierMismatchError(nonce, wasmHex, nativeHex));
      const expected = SYNTHETIC_CONTEXT.vectorFor(nonce);
      if (expected && wasmHex !== expected) {
        throw latch(new VerifierMismatchError(nonce, wasmHex, `committed vector ${expected}`));
      }
    }

    // Startup is over: the server owns the handle from here, and shutdown reaches it through
    // beginClose()/close() rather than through the startup abort listener.
    helper.detachAbort?.();

    return {
      kind: 'dual',
      identity: wasm.identity,
      helperLinuxPid: helper.linuxPid,
      helperToken: helper.token,
      helperCommand: helper.command,
      helperDistro: helper.linuxDistro,
      helperSourceId: helper.sourceId,
      datasetBytes: ready.datasetBytes,
      scratchBytes: ready.scratchBytes,
      /** The context both builds were initialised with. Frozen; evidence, not configuration. */
      context: Object.freeze({ ...initContext }),

      /** Total MeepHash-W computations on the Wasm side. Kept for the existing counter tests. */
      get hashCalls() { return wasm.hashCalls; },
      get counters() { return { ...counters }; },
      /** Never healthy while the owned native helper is faulted, whoever noticed first. */
      get healthy() {
        return fault === null && (helper === null || helper.healthy || helper.fault?.cancelled === true);
      },
      get fault() { return fault ?? (helper?.fault?.cancelled ? null : helper?.fault) ?? null; },
      wasmHeapBytes: () => wasm.wasmHeapBytes(),
      /** Algorithm memory owned natively: 32 MiB dataset + 8 MiB scratchpad. Not process RSS. */
      nativeAlgorithmBytes: () => ready.datasetBytes + ready.scratchBytes,

      /**
       * Recompute one nonce on BOTH builds and require byte equality before judging the target.
       * The client's own claimed hash is not a parameter here and never has been.
       */
      async verify(nonce, targetBytes) {
        assertUsable();

        const wasmResult = await wasm.verify(nonce, targetBytes);
        counters.wasmShareHashes++;
        // A sibling verification may have latched while this one was computing.
        assertUsable();

        let nativeHex;
        try {
          nativeHex = await helper.hash(nonce);
        } catch (err) {
          const e = err instanceof Error ? err : new HelperFaultError(String(err));
          if (e.cancelled) throw e; // deliberate shutdown, not a build problem
          throw latch(e);
        }
        counters.nativeShareHashes++;
        assertUsable();

        if (wasmResult.hashHexLE !== nativeHex) {
          throw latch(new VerifierMismatchError(nonce, wasmResult.hashHexLE, nativeHex));
        }

        // Only now is the AGREED hash compared to the server's own target.
        const agreed = hexToBytes(nativeHex);
        const meets = meetsTargetLE(agreed, targetBytes);
        // THE LAST THING BEFORE SUCCESS. Everything above may have taken time; if the pool latched
        // during any of it, this result is not allowed out.
        assertUsable();
        return { hash: agreed, hashHexLE: nativeHex, meets, crossChecked: true };
      },

      /** Raw single-build recomputation. Tests only; never on the share path. */
      hashOne(nonce) { return wasm.hashOne(nonce); },

      /**
       * THE TWO PATHS, SEPARATELY, for a caller that compares them itself (block_run.mjs). Each
       * computes ONCE and never calls the other, so a caller using both performs exactly one Wasm
       * hash and one native HASH -- there is no combined verify() underneath to double the work.
       * The same fences apply as in verify(): checked before and after every await, a native fault
       * latches, and a cancellation is not a fault.
       */
      async hashWasm(nonce) {
        assertUsable();
        if (wasm.closing) throw new HelperFaultError('wasm verifier is shutting down', { cancelled: true });
        const hash = wasm.hashOne(nonce);
        counters.wasmShareHashes++;
        assertUsable();
        return hash;
      },
      async hashNative(nonce) {
        assertUsable();
        let nativeHex;
        try {
          nativeHex = await helper.hash(nonce);
        } catch (err) {
          const e = err instanceof Error ? err : new HelperFaultError(String(err));
          if (e.cancelled) throw e;
          throw latch(e);
        }
        counters.nativeShareHashes++;
        assertUsable();
        return hexToBytes(nativeHex);
      },

      /**
       * Latch from outside. The pool's own fault seam routes through here so an injected fault
       * and a real build disagreement travel the SAME path and hit the SAME fence -- a seam that
       * behaved more safely than the thing it models would be worse than no seam.
       */
      latchExternalFault(err) { return latch(err); },

      beginClose(reason = 'verifier shutting down') {
        if (closing) return;
        closing = true;
        // Order matters: cancel the child first so requests waiting on it settle, then the Wasm
        // side. Both are synchronous and both must happen even if one throws.
        try { helper?.beginClose(reason); } catch { /* already cancelled */ }
        try { wasm?.beginClose(reason); } catch { /* already cancelled */ }
      },

      /**
       * TWO OUTCOMES, NOT ONE.
       *
       * `physicalReleaseConfirmed` and `gracefulProtocolShutdown` are independent. A helper that
       * died mid-goodbye is GONE -- there is nothing left to own, and re-signalling or retrying
       * its cleanup would only be an attempt to erase the anomaly -- and it is ABNORMAL, which the
       * pool and the operator must both be told. So a released-but-abnormal helper does NOT make
       * this throw (throwing would send the pool into escalation over a corpse); it is recorded in
       * `shutdownOutcome` and travels outward from there.
       *
       * A helper that is NOT positively released keeps the older, stronger behaviour: throw,
       * retain, and let the caller retry.
       */
      async close(reason = 'verifier shutting down') {
        if (released) return;
        this.beginClose(reason);
        const failures = [];
        try {
          await helper.close(reason);
        } catch (err) {
          const gone = err?.detail?.physicalReleaseConfirmed === true && helper.closed === true;
          if (gone) protocolAnomalies.push(`native helper: ${err?.message ?? err}`);
          else failures.push(`native helper: ${err?.message ?? err}`);
        }
        try { await wasm.close(reason); } catch (err) { failures.push(`wasm verifier: ${err?.message ?? err}`); }
        // Released only when BOTH sides say so. A close() that resolved without the resource
        // actually confirming release is a failure, not a success.
        if (failures.length > 0 || !helper.closed || !wasm.closed) {
          if (helper.closed === false) failures.push('native helper: release not confirmed');
          if (wasm.closed === false) failures.push('wasm verifier: release not confirmed');
          throw new HelperFaultError(failures.join('; '));
        }
        released = true;
      },

      /** { physicalReleaseConfirmed, gracefulProtocolShutdown, reason }. Read by the pool. */
      get shutdownOutcome() {
        return {
          physicalReleaseConfirmed: released,
          gracefulProtocolShutdown: released && protocolAnomalies.length === 0,
          reason: protocolAnomalies.length > 0 ? protocolAnomalies.join('; ').slice(0, 400) : null,
        };
      },

      async forceClose(reason = 'verifier force close') {
        this.beginClose(reason);
        const failures = [];
        // Idempotent: a retried escalation must not grow this list on every attempt.
        const forced = 'the verifier was force-closed rather than shut down gracefully';
        if (!protocolAnomalies.includes(forced)) protocolAnomalies.push(forced);
        try { await helper.forceClose(reason); } catch (err) { failures.push(`native helper: ${err?.message ?? err}`); }
        try { await wasm.forceClose(reason); } catch (err) { failures.push(`wasm verifier: ${err?.message ?? err}`); }
        if (failures.length > 0 || !helper.closed || !wasm.closed) {
          if (helper.closed === false) failures.push('native helper: release not confirmed');
          if (wasm.closed === false) failures.push('wasm verifier: release not confirmed');
          throw new HelperFaultError(failures.join('; '));
        }
        released = true;
      },

      get closed() { return released; },
      get closing() { return closing; },
      /** Bounded diagnostic text; never the raw unbounded stderr stream. */
      get helperStderrTail() { return helper?.stderrTail ?? ''; },
    };
  } catch (err) {
    // A helper whose handshake failed hands its handle back on the error. Adopt it so it is
    // reaped or retained here rather than lost.
    const extra = err?.helper && err.helper !== helper && !err.releaseConfirmed
      ? [{ label: 'native helper (handshake failed)', resource: err.helper }]
      : [];
    return await abandonPartial(err, extra);
  }
}
