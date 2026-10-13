// The one-shot real-block run: verification, then AT MOST ONE submission, with a terminal result
// that is published exactly once and never contradicted.
//
// Everything here is orchestration over injected interfaces. In the recorded-template simulation the
// "native" verifier is an in-memory recorded oracle and the "daemon" is an in-memory model; no
// process is spawned and no socket is opened. What is real is the ORDER, the fences, the shared
// ownership, and what each outcome is allowed to claim.
//
// FIVE CORRECTIONS WORTH NAMING, BECAUSE EACH WAS A REPRODUCED DEFECT
//
//   1. TERMINAL IS FIRST-WRITE-WINS, AND A BUSY RUN IS NOT A TERMINAL ONE. Previously a second
//      candidate arriving while the first was mid-verification saw state != RUNNING and called
//      finish(NOT_RUNNING), terminalising the run; the first then resumed and submitted anyway,
//      producing candidate_verified -> block_rejected -> block_submit_started -> block_accepted.
//      The run's state now stays RUNNING while candidates verify, a late candidate is a NONTERMINAL
//      busy refusal, and terminal publication is one guarded operation after which nothing may
//      hash, claim, submit or emit.
//
//   2. ONE CLOCK SAMPLE AT THE DEADLINE. gateOrTerminal(now()) followed by claim(..., now()) let a
//      clock return expiry at the gate and expiry+1 at the claim. The final section now samples the
//      clock ONCE and passes that value to both the expiry decision and the claim.
//
//   3. THE LATCH IS FENCED AFTER THE IRREVERSIBLE AWAIT TOO. Tripping the shared latch while the
//      submit promise was in flight still produced block_accepted. A trip after dispatch cannot
//      recall the request, so it can never become trusted success: it becomes an explicit
//      submitted-but-untrusted terminal.
//
//   4. "PREPARED" IS NOT "ENTERED" IS NOT "SENT". Three boundaries, not one. Preparation is local,
//      so its failures are definitely-not-sent. ENTERING the transport proves nothing either way:
//      the transport may write and then throw. Only the adapter's own one-use handoff receipt says
//      the bytes went out, and only then may a "sent" event be emitted. Everything in between is
//      AMBIGUOUS and is reported as ambiguous.
//
//   5. A DETERMINISTIC DISAGREEMENT IS A GLOBAL INTEGRITY FAULT. A calc_pow mismatch used to be a
//      per-candidate refusal, so a later issuance could carry on to submission. Identical context
//      bytes producing different hashes means one of the paths is wrong and we cannot tell which.
//
// WHAT "THREE PATHS" DOES AND DOES NOT MEAN. The server Wasm, the native/oracle path and the daemon
// path are distinct execution and build paths over the SAME MeepHash lineage. They are not three
// independently authored algorithms, and agreement is not independent-implementation evidence.
//
// WHY A READBACK NAMING OUR BLOCK IS DIFFERENT FROM A READBACK NAMING ANOTHER. If the header at
// the height we submitted to reports a DIFFERENT block, a reorg or a competing block explains it
// and the outcome is ambiguous. If it reports OUR block id but disagrees about the height we asked
// for, its orphan status, its nonce or its proof-of-work, no chain state explains that: the answer
// contradicts itself, and the fatal boundary is tripped rather than a verdict guessed.
//
// WHY THE POW READBACK CARRIES WEIGHT. We verify a hashing blob but submit a separately supplied
// full block; a shared header prefix does not prove they have the same proof-of-work input. The
// daemon's own pow_hash for the block AS STORED does. That is an immediate main-chain observation,
// never finality.

import { blobToHex, patchNonce } from './block_blob.mjs';
import { fullBlockBlobOf, hashingTemplateOf, shareTargetBytesOf, targetBytesOf } from './real_template.mjs';
import { CLAIM_REFUSED, FATAL_CODES } from './run_guard.mjs';
import { RPC_CODES, submissionProofs } from './daemon_rpc.mjs';
import { meetsTargetLE } from '../../web-miner/lib/shared/target.js';

export const RUN_STATES = Object.freeze({
  IDLE: 'idle',
  RUNNING: 'running',
  TERMINAL: 'terminal',
});

/** NONTERMINAL: this candidate is refused; the run stays open for other workers. */
export const NONTERMINAL = Object.freeze({
  BAD_CANDIDATE: 'bad_candidate',
  UNKNOWN_JOB: 'unknown_job',
  STALE_ISSUANCE: 'stale_issuance',
  STALE_GENERATION: 'stale_generation',
  UNKNOWN_WORKER: 'unknown_worker',
  NONCE_OUT_OF_WINDOW: 'nonce_outside_window',
  DUPLICATE: 'duplicate_nonce',
  ABOVE_TARGET: 'above_target',
  ALREADY_CLAIMED: 'submission_already_claimed',
  ISSUANCE_SUPERSEDED: 'issuance_superseded',
  NOT_STARTED: 'run_not_started',
  DAEMON_UNAVAILABLE: 'daemon_unavailable',
});

/** TERMINAL: the run is over, for everyone. Published exactly once. */
export const TERMINAL = Object.freeze({
  EXPIRED: 'expired_job',
  REVOKED: 'revoked_before_submit',
  CANCELLED: 'cancelled',
  NOT_RUNNING: 'run_not_active',
  FATAL_VERIFIER: 'fatal_verifier',
  SUBMIT_NOT_SENT: 'submit_definitely_not_sent',
  SUBMIT_REJECTED: 'submit_rejected',
  SUBMIT_AMBIGUOUS: 'submit_outcome_ambiguous',
  SUBMIT_UNTRUSTED: 'submitted_but_untrusted',
  READBACK_MISMATCH: 'readback_mismatch',
  VERIFIED_COMPLETE: 'verified_complete',
  INTERNAL: 'internal_error',
});

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Monotonic run intent, the thing Stop revokes.
 *
 * Generations only move forward. revoke() refuses any generation but the current one, so an old
 * tab's queued Stop cannot silence a run started afterwards. NOTHING re-arms itself: no reconnect,
 * visibility change or arriving job may set intent. Only start() can.
 */
export function createRunIntent({ now = () => Date.now() } = {}) {
  let generation = 0;
  let active = false;
  let revokedReason = null;
  let revokedAtMs = null;
  const listeners = new Set();

  function notify() {
    for (const fn of listeners) {
      try { fn({ generation, active, reason: revokedReason }); } catch { /* a bad listener changes nothing */ }
    }
  }

  return {
    get generation() { return generation; },
    get active() { return active; },
    get revokedReason() { return revokedReason; },
    get revokedAtMs() { return revokedAtMs; },
    start() {
      generation += 1;
      active = true;
      revokedReason = null;
      revokedAtMs = null;
      notify();
      return generation;
    },
    revoke(gen, reason = 'stop_request') {
      if (!Number.isInteger(gen) || gen !== generation) {
        return { ok: false, reason: NONTERMINAL.STALE_GENERATION, generation };
      }
      if (!active) return { ok: true, alreadyRevoked: true, generation };
      active = false;
      revokedReason = reason;
      revokedAtMs = now();
      notify();
      return { ok: true, generation, reason };
    },
    revokeCurrent(reason) {
      if (!active) return { ok: true, alreadyRevoked: true, generation };
      active = false;
      revokedReason = reason;
      revokedAtMs = now();
      notify();
      return { ok: true, generation, reason };
    },
    isLive(gen) { return active && gen === generation; },
    onChange(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
  };
}

/** A verifier result must be exactly 32 bytes. Anything else is an integrity fault, not a mismatch. */
function isHash32(v) {
  return v instanceof Uint8Array && v.length === 32;
}

function sameBytes(a, b) {
  if (!isHash32(a) || !isHash32(b)) return false;
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** An error a verifier explicitly flagged as a cancellation, not a fault. */
function isCancelled(err) {
  return err != null && (err.cancelled === true || err.code === 'cancelled');
}

/**
 * @param {object} o
 * @param {object} o.job         a job from real_template.mjs
 * @param {object} o.intent      createRunIntent()
 * @param {object} o.wasmVerifier    { hashOne(nonce) }
 * @param {object} o.nativeVerifier  { hashOne(nonce) } -- a recorded oracle in the simulation
 * @param {object} o.daemon      prepareSubmission / dispatchSubmission / calcPow / getBlockHeaderByHeight,
 *                               and `submissionAdapter`: the createDaemonRpc() instance whose private
 *                               proofs decide every "not sent", "handed off" and "refused" claim
 * @param {object} o.latch       the SHARED fatal latch
 * @param {object} o.authority   the SHARED template authority + submission claim
 * @param {string} o.workerId
 * @param {object} [o.vocabulary] outward event names, so a simulation can stay truthful
 * @param {object} [o.canonical]  REAL DAEMON ONLY, off by default: { prevHashHex }. Adds two readback
 *                               requirements -- the header's previous hash is the template's, and
 *                               the daemon's top block IS this block at this height -- and lets an
 *                               ambiguous submission be resolved, read-only and never by resubmitting,
 *                               when the canonical header at the template height carries exactly this
 *                               nonce, this proof-of-work hash and this previous hash.
 */
export function createBlockRun({
  job,
  intent,
  wasmVerifier,
  nativeVerifier,
  daemon,
  latch,
  authority,
  workerId,
  emit = () => {},
  now = () => Date.now(),
  hooks = {},
  vocabulary = {},
  canonical = null,
}) {
  if (!job || job.kind !== 'real') throw new TypeError('block_run requires a real-template job');
  if (canonical !== null) {
    if (typeof canonical !== 'object' || !HEX64.test(String(canonical.prevHashHex ?? ''))) {
      throw new TypeError('canonical readback requires the template prevHashHex');
    }
    if (typeof daemon?.getLastBlockHeader !== 'function') {
      throw new TypeError('canonical readback requires daemon.getLastBlockHeader');
    }
  }
  if (!latch || typeof latch.trip !== 'function') throw new TypeError('block_run requires the shared fatal latch');
  if (!authority || typeof authority.claimSubmission !== 'function') {
    throw new TypeError('block_run requires the shared template authority');
  }
  if (typeof workerId !== 'string' || workerId.length === 0) throw new TypeError('block_run requires a workerId');

  // Outward event names. The recorded simulation overrides these so nothing it emits can be read as
  // a real block reaching a real daemon.
  const EV = {
    verified: vocabulary.verified ?? 'candidate_verified',
    submitStarted: vocabulary.submitStarted ?? 'block_submit_started',
    success: vocabulary.success ?? 'block_accepted',
    failure: vocabulary.failure ?? 'block_rejected',
    candidateRejected: vocabulary.candidateRejected ?? 'candidate_rejected',
    shareAccepted: vocabulary.shareAccepted ?? 'share_accepted',
  };

  let state = RUN_STATES.IDLE;
  let generation = null;
  // THREE DIFFERENT FACTS, DELIBERATELY NOT ONE FLAG.
  let boundaryEntered = false;         // the transport function was called at all
  let dispatched = false;              // the transport returned this adapter's handoff receipt
  let terminal = null;                 // published exactly once
  let terminalDetail = null;
  let inFlight = 0;
  let sharesAccepted = 0;              // one counter, never a list
  const idleWaiters = new Set();
  const seenNonces = new Set();

  // The job's private bytes, copied ONCE into this run's closure. The accessors handed back fresh
  // copies, so later mutation of anything public cannot change what this run hashes or submits.
  const targetBytes = targetBytesOf(job);
  // THE SHARE TARGET, equal to the block target unless the job was issued with a share difficulty.
  // Numerically >= the block target, so `hash <= blockTarget` implies `hash <= shareTarget`.
  const shareTargetBytes = shareTargetBytesOf(job);
  const shareWork = job.shareWork === true;
  const hashingTemplate = hashingTemplateOf(job);

  // SUBSCRIBED, AND UNSUBSCRIBED AGAIN. A run that never released this left a closure on the
  // process-lifetime latch for as long as the process lived, so N starts meant N permanent
  // subscribers. The handle is kept and dropped the moment this run reaches a terminal state or is
  // disposed.
  let releaseLatch = latch.onTrip(() => {
    try { intent.revokeCurrent(FATAL_CODES.VERIFIER_FAULT); } catch { /* nothing to do */ }
  });

  function releaseSubscriptions() {
    if (!releaseLatch) return;
    const release = releaseLatch;
    releaseLatch = null;
    try { release(); } catch { /* already gone */ }
  }

  /** Emit without ever letting a listener change the machine. */
  function safeEmit(ev) {
    try { emit(ev); } catch { /* a throwing listener must not falsify state */ }
  }

  /** A per-candidate refusal. The run stays open; no terminal is published. */
  /**
   * `entered` says whether THIS candidate got past the cheap authorization checks and into
   * verification. A caller that can issue only one candidate needs the distinction: a forged or
   * mismatched candidate that never entered must not be allowed to spend the real one's attempt,
   * while a refusal of the real candidate after it was verified ends that attempt.
   */
  function refuse(reason, detail, extra = {}, entered = false) {
    safeEmit({
      type: EV.candidateRejected, jobId: job.jobId, reason, detail: detail || undefined, entered, ...extra,
    });
    return { ok: false, terminal: false, entered, reason, detail, dispatched, boundaryEntered };
  }
  function refuseEntered(reason, detail, extra = {}) {
    return refuse(reason, detail, extra, true);
  }

  /**
   * Publish THE terminal result. First write wins; every later call is a no-op that reports the
   * already-published outcome. Exactly one terminal event is emitted, ever.
   */
  function publishTerminal(reason, detail, extra = {}) {
    if (terminal !== null) return alreadyTerminal();
    terminal = reason;
    terminalDetail = detail ?? '';
    state = RUN_STATES.TERMINAL;
    // Nothing this run owns outlives its terminal state.
    releaseSubscriptions();
    const success = reason === TERMINAL.VERIFIED_COMPLETE;
    safeEmit(success
      ? { type: EV.success, jobId: job.jobId, ...extra }
      : {
        type: EV.failure,
        jobId: job.jobId,
        reason,
        detail: detail || undefined,
        dispatched,
        boundaryEntered,
        ...extra,
      });
    return { ok: success, terminal: true, reason, detail, dispatched, boundaryEntered, ...extra };
  }

  function alreadyTerminal() {
    return {
      ok: terminal === TERMINAL.VERIFIED_COMPLETE,
      terminal: true,
      reason: terminal,
      detail: terminalDetail,
      alreadyTerminal: true,
      dispatched,
      boundaryEntered,
    };
  }

  function intentLive(gen = generation) {
    return intent.isLive(gen);
  }

  /**
   * The run-wide fence. Returns a TERMINAL code when the whole run is over, or null.
   *
   * `atMs` is always supplied by the caller so the clock is sampled deliberately, never implicitly.
   * Inclusive deadline, matching the rest of the repository: active while atMs <= expiresAtMs.
   */
  function runGate(atMs) {
    if (terminal !== null) return terminal;
    if (latch.tripped) return TERMINAL.FATAL_VERIFIER;
    if (!intentLive()) return TERMINAL.REVOKED;
    if (atMs > job.expiresAtMs) return TERMINAL.EXPIRED;
    return null;
  }

  async function yieldAt(name) {
    const h = hooks[name];
    if (typeof h === 'function') await h();
  }

  return {
    get state() { return state; },
    get generation() { return generation; },
    /** True only once this adapter's own handoff receipt existed. */
    get dispatched() { return dispatched; },
    /** True once the transport function was CALLED, receipt or not. This is what cannot be undone. */
    get boundaryEntered() { return boundaryEntered; },
    /** Retained name. It has always meant "the transport was actually invoked". */
    get submitBegun() { return boundaryEntered; },
    get terminal() { return terminal; },
    get complete() { return terminal !== null; },
    get inFlight() { return inFlight; },
    /** How many verified non-block shares this run accepted. A number, not a history. */
    get sharesAccepted() { return sharesAccepted; },
    /** Whether this run's job was issued with a share target easier than its block target. */
    get shareWork() { return shareWork; },
    /** Resolve once every candidate already admitted to this run has settled. */
    whenIdle() {
      if (inFlight === 0) return Promise.resolve();
      return new Promise((resolve) => idleWaiters.add(resolve));
    },
    /** Test/diagnostic only: whether this run still holds its latch subscription. */
    get subscribed() { return releaseLatch !== null; },

    /**
     * Release everything this run holds on shared, process-lifetime objects.
     *
     * Idempotent, and called automatically when a terminal result is published. A session calls it
     * too, so a run abandoned without a terminal (a socket that simply went away) leaves nothing
     * attached to the shared latch.
     */
    dispose() { releaseSubscriptions(); },

    begin() {
      if (state !== RUN_STATES.IDLE) throw new Error('run already begun');
      generation = intent.generation;
      if (latch.tripped) return publishTerminal(TERMINAL.FATAL_VERIFIER, `verification is disabled: ${latch.code}`);
      if (!intent.isLive(generation)) return publishTerminal(TERMINAL.NOT_RUNNING, 'no active run intent');
      state = RUN_STATES.RUNNING;
      return { ok: true, generation };
    },

    /**
     * Process ONE candidate.
     *
     * `submission` must carry jobId, issuanceId, workerId, runGeneration and nonce. Nothing else is
     * read -- a forged target, height, blob or address in the same object is simply not looked at.
     */
    async submitCandidate(submission) {
      if (terminal !== null) return alreadyTerminal();
      if (state === RUN_STATES.IDLE) return refuse(NONTERMINAL.NOT_STARTED, 'the run has not begun');

      // ---- cheap, NONTERMINAL authorization. Zero hashing, zero daemon calls. ----------------
      if (submission === null || typeof submission !== 'object') {
        return refuse(NONTERMINAL.BAD_CANDIDATE, 'submission must be an object');
      }
      const { jobId, issuanceId, nonce } = submission;
      if (jobId !== job.jobId) return refuse(NONTERMINAL.UNKNOWN_JOB, 'submission is for a different job');
      if (issuanceId !== job.issuanceId) {
        return refuse(NONTERMINAL.STALE_ISSUANCE, 'submission is for a different issuance of this template');
      }
      if (submission.workerId !== workerId) {
        return refuse(NONTERMINAL.UNKNOWN_WORKER, 'workerId was not issued to this run');
      }
      if (submission.runGeneration !== generation) {
        return refuse(NONTERMINAL.STALE_GENERATION, 'submission belongs to an older run generation');
      }
      if (!Number.isInteger(nonce) || nonce < 0 || nonce > 0xffffffff) {
        return refuse(NONTERMINAL.BAD_CANDIDATE, 'nonce must be a uint32');
      }
      if (nonce < job.nonceStart || nonce >= job.nonceStart + job.nonceRange) {
        return refuse(NONTERMINAL.NONCE_OUT_OF_WINDOW, 'nonce is outside the issued window');
      }
      if (seenNonces.has(nonce)) return refuse(NONTERMINAL.DUPLICATE, 'nonce already submitted');

      // Run-wide conditions AFTER the per-candidate ones, so a stale worker's message is never what
      // reports the run as expired.
      const gate0 = runGate(now());
      if (gate0) return publishTerminal(gate0, 'run ended before verification');

      seenNonces.add(nonce);
      inFlight += 1;
      try {
        return await verifyAndMaybeSubmit(nonce);
      } finally {
        inFlight -= 1;
        if (inFlight === 0) {
          for (const resolve of idleWaiters) {
            try { resolve(); } catch { /* a waiter cannot change the run */ }
          }
          idleWaiters.clear();
        }
      }
    },

    /**
     * TRI-STATE, BECAUSE THERE ARE THREE DIFFERENT TRUTHS.
     *
     *   prevented   no untrusted submission step ran, or the adapter itself proved its failure
     *               happened before its transport: definitely not sent
     *   unknown     a submission step ran and no authenticated handoff receipt exists: it may or
     *               may not have been sent, and it cannot be recalled either way
     *   handed_off  the adapter minted a handoff receipt: sent, and no longer recallable
     *
     * The previous revision said "already sent" whenever the boundary had been entered. Entering a
     * function is not sending a block.
     */
    describeRevocation() {
      if (dispatched) {
        return {
          state: 'handed_off',
          submissionPrevented: false,
          alreadySent: true,
          notice: 'the transport reported handing the request over; it cannot be recalled',
        };
      }
      if (boundaryEntered) {
        return {
          state: 'unknown',
          submissionPrevented: false,
          alreadySent: null,
          mayHaveBeenSent: true,
          notice: 'a submission step ran without an authenticated handoff receipt; the request may '
            + 'or may not have been sent, and it cannot be recalled',
        };
      }
      return {
        state: 'prevented',
        submissionPrevented: true,
        alreadySent: false,
        notice: 'nothing had been dispatched, and nothing will be for this run',
      };
    },
  };

  // ------------------------------------------------------------------ the verification pipeline
  async function verifyAndMaybeSubmit(nonce) {
    // ---- the server's own Wasm --------------------------------------------------------------
    let wasmHash;
    try {
      await yieldAt('beforeWasm');
      const g = runGate(now());
      if (g) return publishTerminal(g, 'run ended before the wasm hash');
      wasmHash = await wasmVerifier.hashOne(nonce);
    } catch (err) {
      if (isCancelled(err)) return publishTerminal(TERMINAL.CANCELLED, 'the wasm verifier was cancelled');
      latch.trip(FATAL_CODES.VERIFIER_FAULT, err);
      return publishTerminal(TERMINAL.FATAL_VERIFIER, 'the wasm verifier faulted');
    }
    if (terminal !== null) return alreadyTerminal();
    if (!isHash32(wasmHash)) {
      latch.trip(FATAL_CODES.VERIFIER_MALFORMED_OUTPUT, 'wasm verifier did not return 32 bytes');
      return publishTerminal(TERMINAL.FATAL_VERIFIER, 'the wasm verifier returned a malformed result');
    }

    // ---- the native / recorded-oracle path, over the SAME context ---------------------------
    let nativeHash;
    try {
      await yieldAt('beforeNative');
      const g = runGate(now());
      if (g) return publishTerminal(g, 'run ended before the native hash');
      nativeHash = await nativeVerifier.hashOne(nonce);
    } catch (err) {
      if (isCancelled(err)) return publishTerminal(TERMINAL.CANCELLED, 'the native verifier was cancelled');
      latch.trip(FATAL_CODES.VERIFIER_FAULT, err);
      return publishTerminal(TERMINAL.FATAL_VERIFIER, 'the native verifier faulted');
    }
    if (terminal !== null) return alreadyTerminal();
    if (!isHash32(nativeHash)) {
      latch.trip(FATAL_CODES.VERIFIER_MALFORMED_OUTPUT, 'native verifier did not return 32 bytes');
      return publishTerminal(TERMINAL.FATAL_VERIFIER, 'the native verifier returned a malformed result');
    }

    // ---- byte equality is mandatory, and a mismatch is FATAL FOR THE PROCESS -----------------
    if (!sameBytes(wasmHash, nativeHash)) {
      latch.trip(FATAL_CODES.VERIFIER_BUILD_DISAGREEMENT,
        `nonce ${nonce}: two paths over identical context bytes disagreed`);
      return publishTerminal(TERMINAL.FATAL_VERIFIER,
        'two verification paths over identical context bytes disagreed; verification is disabled');
    }
    const hashHexLE = blobToHex(wasmHash);

    // Above target is a per-candidate refusal, not the end of the run. In a share-work job the
    // admitting target is the SHARE target; with no share difficulty configured the two are the
    // same bytes and this is exactly the check it has always been.
    if (!meetsTargetLE(wasmHash, shareTargetBytes)) {
      return refuseEntered(NONTERMINAL.ABOVE_TARGET,
        shareWork ? 'recomputed hash is above the share target' : 'recomputed hash is above the template target',
        { hashHexLE });
    }

    // ---- A VERIFIED SHARE THAT IS NOT A BLOCK ------------------------------------------------
    // Two independent server paths over identical context bytes agreed on it, and it meets the
    // share target. It does NOT meet the block target, so there is nothing to submit: no calc_pow,
    // no submission claim, no submit_block, no readback. The run stays open.
    if (shareWork && !meetsTargetLE(wasmHash, targetBytes)) {
      // THE SAME FENCE EVERY OTHER IRREVERSIBLE STEP USES, and for the same reason: both hashes were
      // awaited, and an expiry, a Stop/revocation or a tripped latch during those awaits must not be
      // answered with an accepted share. Announcing one after invalidation is a false statement about
      // what this run holds, even though it sends nothing.
      const gShare = runGate(now());
      if (gShare) return publishTerminal(gShare, 'run ended before the share could be accepted');
      sharesAccepted += 1;
      safeEmit({
        type: EV.shareAccepted,
        jobId: job.jobId,
        nonce,
        hashHexLE,
        shareIndex: sharesAccepted,
        agreedBy: ['server_wasm', 'native_path'],
        notice: 'a verified share below the share target and above the block target. '
          + 'Nothing was sent to the daemon.',
      });
      return {
        ok: true, terminal: false, entered: true, share: true, block: false,
        nonce, hashHexLE, shareIndex: sharesAccepted, dispatched, boundaryEntered,
      };
    }

    // ---- the daemon/model path must hash the SAME bytes --------------------------------------
    const { blob: noncedHashingBlob } = patchNonce(hashingTemplate, nonce);
    let daemonHash;
    try {
      await yieldAt('beforeCalcPow');
      const g = runGate(now());
      if (g) return publishTerminal(g, 'run ended before calc_pow');
      daemonHash = await daemon.calcPow({
        majorVersion: job.majorVersion,          // the PARSED version, never a default
        height: job.height.toString(),
        blockBlobHex: blobToHex(noncedHashingBlob),
        seedHashHex: job.seedHashHex,
      });
    } catch (err) {
      if (isCancelled(err)) return publishTerminal(TERMINAL.CANCELLED, 'calc_pow was cancelled');
      // Unreachable is not disagreement: the run stays open and only a CODE crosses the wire.
      return refuseEntered(NONTERMINAL.DAEMON_UNAVAILABLE, 'calc_pow could not be completed',
        { daemonCode: err?.code ?? null });
    }
    if (terminal !== null) return alreadyTerminal();
    // Re-validate the shape here as well as in the adapter: this is the boundary that decides.
    if (typeof daemonHash !== 'string' || !HEX64.test(daemonHash)) {
      latch.trip(FATAL_CODES.VERIFIER_MALFORMED_OUTPUT, 'calc_pow returned a malformed hash');
      return publishTerminal(TERMINAL.FATAL_VERIFIER, 'calc_pow returned a malformed proof-of-work hash');
    }
    if (daemonHash !== hashHexLE) {
      // IDENTICAL CONTEXT BYTES, DIFFERENT HASHES. One of these paths is wrong and we cannot tell
      // which, so nothing later may be trusted either.
      latch.trip(FATAL_CODES.ORACLE_DISAGREEMENT,
        `nonce ${nonce}: calc_pow disagreed with the server recomputation`);
      return publishTerminal(TERMINAL.FATAL_VERIFIER,
        'calc_pow disagreed with the server recomputation over identical context bytes',
        { serverHashHexLE: hashHexLE, daemonHashHexLE: daemonHash });
    }

    safeEmit({
      type: EV.verified,
      jobId: job.jobId,
      nonce,
      hashHexLE,
      agreedBy: ['server_wasm', 'native_path', 'daemon_calc_pow'],
      notice: 'three execution paths over the same MeepHash lineage agree. Nothing has been sent.',
    });

    // ---- PREPARE before the critical section. Nothing is sent by this. -----------------------
    await yieldAt('beforeSubmit');
    if (terminal !== null) return alreadyTerminal();

    const fullBlockHex = blobToHex(patchNonce(fullBlockBlobOf(job), nonce).blob);
    // THE PROOF LINEAGE FOR THIS ONE SUBMISSION. `proofs` are the private checks of the one adapter
    // the daemon names; `operation` is a token only this call holds. Every later claim -- not sent,
    // handed off, refused -- must be about THIS operation on THAT adapter. An authentic object from
    // another adapter, an earlier operation or a different dispatch proves nothing here.
    const proofs = submissionProofs(daemon?.submissionAdapter);
    const operation = Object.freeze({ kind: 'meepcoin-submission-operation' });
    let prepared;
    try {
      prepared = daemon.prepareSubmission(fullBlockHex, operation);
    } catch (err) {
      // ONLY THE ADAPTER CAN PROVE A LOCAL FAILURE, and only for this operation. Anything else came
      // from an injected object whose side effects nothing here can see: unknown, not "not sent".
      if (proofs !== null && proofs.notSentFor(operation, err)) {
        return publishTerminal(TERMINAL.SUBMIT_NOT_SENT,
          'the submission could not be prepared locally; nothing was sent',
          { nonce, hashHexLE, daemonCode: err?.code ?? null, definitelyNotSent: true });
      }
      boundaryEntered = true;
      return publishTerminal(TERMINAL.SUBMIT_AMBIGUOUS,
        'the submission step failed without adapter proof that nothing was sent; the outcome is unknown',
        { nonce, hashHexLE, daemonCode: RPC_CODES.UNAUTHENTICATED_DISPATCH, definitelyNotSent: false });
    }
    // The capability must be the adapter's own, for THIS operation, not yet dispatched, and its
    // private body must be EXACTLY the block built above for this nonce. A capability prepared for
    // other bytes -- even by the genuine adapter under this very operation -- is not this block. The
    // prepare step already ran untrusted code with unobservable side effects, so a mismatch is
    // unknown, never "not sent", and nothing is dispatched after it.
    if (proofs === null || !proofs.capabilityFor(operation, prepared, fullBlockHex)) {
      boundaryEntered = true;
      return publishTerminal(TERMINAL.SUBMIT_AMBIGUOUS,
        'the prepared submission is not this adapter\'s capability for this block; the outcome is unknown',
        { nonce, hashHexLE, daemonCode: RPC_CODES.UNAUTHENTICATED_DISPATCH, definitelyNotSent: false });
    }

    // ================= THE SYNCHRONOUS CRITICAL SECTION =======================================
    // ONE clock sample, used for BOTH the expiry decision and the claim. No await, no hook, no
    // serialization and no second now() between here and the dispatch.
    const finalAtMs = now();
    const gateFinal = runGate(finalAtMs);
    if (gateFinal) {
      return publishTerminal(gateFinal, 'run ended after verification and before dispatch; nothing was sent');
    }
    const claim = authority.claimSubmission({
      jobId: job.jobId,
      issuanceId: job.issuanceId,
      contentDigest: job.contentDigest,
      owner: workerId,
      runGeneration: generation,
      intentLive,
      atMs: finalAtMs,
    });
    if (!claim.ok) {
      if (claim.reason === CLAIM_REFUSED.EXPIRED) {
        return publishTerminal(TERMINAL.EXPIRED, 'the issuance expired at the claim');
      }
      if (claim.reason === CLAIM_REFUSED.INTENT_REVOKED) {
        return publishTerminal(TERMINAL.REVOKED, 'run intent was revoked at the claim');
      }
      if (claim.reason === CLAIM_REFUSED.NOT_CURRENT) {
        return refuseEntered(NONTERMINAL.ISSUANCE_SUPERSEDED, 'this issuance is no longer the current template');
      }
      // Someone else owns the one submission. Nonterminal: this run did nothing wrong.
      return refuseEntered(NONTERMINAL.ALREADY_CLAIMED, 'another candidate already claimed the single submission');
    }

    // The claim is held. Dispatch IMMEDIATELY -- the very next statement.
    let sent;
    try {
      sent = daemon.dispatchSubmission(prepared);
    } catch (err) {
      // Only a failure the adapter itself PROVES was pre-transport may be called not-sent. A
      // caller-set `definitelyNotSent` property, or any other throw, may have followed a write.
      if (proofs.notSentFor(operation, err)) {
        return publishTerminal(TERMINAL.SUBMIT_NOT_SENT, 'the submission was not dispatched',
          { nonce, hashHexLE, daemonCode: err?.code ?? null, definitelyNotSent: true });
      }
      boundaryEntered = true;
      return publishTerminal(TERMINAL.SUBMIT_AMBIGUOUS,
        'the dispatch failed without adapter proof that nothing was sent; the outcome is unknown',
        { nonce, hashHexLE, daemonCode: err?.code ?? null, definitelyNotSent: false });
    }
    // dispatchSubmission WAS INVOKED AND RETURNED. Whatever it returned, that is not evidence that
    // nothing happened -- so from here the floor is "unknown", never "not sent".
    boundaryEntered = true;
    // ================= END OF THE CRITICAL SECTION ============================================

    // PROVENANCE, NOT PROPERTIES. A missing, false, malformed or lookalike return carries no
    // authority; only the adapter's own private dispatch record does.
    const record = proofs.dispatchFor(operation, sent);
    if (record === null) {
      return publishTerminal(TERMINAL.SUBMIT_AMBIGUOUS,
        'the dispatch returned something the adapter did not produce; whether the block was sent is unknown',
        { nonce, hashHexLE, daemonCode: RPC_CODES.UNAUTHENTICATED_DISPATCH, definitelyNotSent: false });
    }

    // THE RECEIPT IS WHAT AUTHORIZES THE "SENT" EVENT. Read from the authenticated record; it
    // settles either way, with the adapter's own handoff receipt or with null.
    const receipt = await record.receipt;
    if (terminal !== null) return alreadyTerminal();
    if (!receipt || !proofs.receiptFor(record, receipt)) {
      // The transport was entered and never reported writing anything. We cannot say it was sent and
      // we cannot say it was not. Saying either would be a guess dressed as a fact.
      return publishTerminal(TERMINAL.SUBMIT_AMBIGUOUS,
        'the transport was entered but never reported handing the request over; '
        + 'whether the block was sent is unknown',
        { nonce, hashHexLE, daemonCode: RPC_CODES.NO_HANDOFF_RECEIPT, definitelyNotSent: false });
    }

    dispatched = true;
    safeEmit({
      type: EV.submitStarted,
      jobId: job.jobId,
      nonce,
      hashHexLE,
      requestBytes: record.requestBytes ?? null,
      notice: 'the transport reported handing the request over. From this point it CANNOT be '
        + 'recalled, including by pressing Stop.',
    });

    let submitted;
    try {
      submitted = await record.outcome;
    } catch (err) {
      // ONLY a positively identified daemon answer is a rejection. A timeout, reset, malformed
      // response or id mismatch means the block MAY have been accepted.
      if (proofs.refusalFor(record, err)) {
        return publishTerminal(TERMINAL.SUBMIT_REJECTED, 'the daemon answered and refused the block',
          { nonce, hashHexLE, daemonCode: err.code });
      }
      // NEVER RESUBMITTED. With canonical readback on, the ambiguity may only be resolved by reading.
      const resolved = await resolveByCanonicalReadback(nonce, hashHexLE, err?.code ?? null);
      if (resolved) return resolved;
      return publishTerminal(TERMINAL.SUBMIT_AMBIGUOUS,
        'the request was handed over but its outcome is unknown; the block may have been accepted',
        { nonce, hashHexLE, daemonCode: err?.code ?? null });
    }

    // A latch tripped WHILE the submission was in flight cannot recall it, and must never become
    // trusted success.
    if (latch.tripped) {
      return publishTerminal(TERMINAL.SUBMIT_UNTRUSTED,
        'verification was disabled while the request was in flight; the outcome cannot be trusted',
        { nonce, hashHexLE, fatalCode: latch.code });
    }
    if (terminal !== null) return alreadyTerminal();

    if (!submitted || typeof submitted.blockId !== 'string' || !HEX64.test(submitted.blockId)) {
      const resolved = await resolveByCanonicalReadback(nonce, hashHexLE, null);
      if (resolved) return resolved;
      return publishTerminal(TERMINAL.SUBMIT_AMBIGUOUS,
        'the submission returned no usable block id; the outcome is unknown', { nonce, hashHexLE });
    }

    // ---- success is necessary, not sufficient -----------------------------------------------
    let header;
    try {
      header = await daemon.getBlockHeaderByHeight(job.height.toString(), { fillPowHash: true });
    } catch (err) {
      return publishTerminal(TERMINAL.SUBMIT_AMBIGUOUS,
        'the block was dispatched but could not be read back; the outcome is unknown',
        { nonce, hashHexLE, submittedBlockId: submitted.blockId, daemonCode: err?.code ?? null });
    }
    if (latch.tripped) {
      return publishTerminal(TERMINAL.SUBMIT_UNTRUSTED,
        'verification was disabled before the readback could be trusted',
        { nonce, hashHexLE, fatalCode: latch.code });
    }
    if (terminal !== null) return alreadyTerminal();

    const sameBlock = typeof header?.hash === 'string' && HEX64.test(header.hash)
      && header.hash === submitted.blockId;
    const nonceOk = header?.nonce === nonce;
    const powOk = typeof header?.powHash === 'string' && HEX64.test(header.powHash)
      && header.powHash === hashHexLE;
    const heightOk = String(header?.height) === job.height.toString();
    const notOrphan = header?.orphanStatus === false;

    if (sameBlock && !(heightOk && notOrphan && nonceOk && powOk)) {
      // THE IMPOSSIBLE CASE. We asked for the header AT A GIVEN HEIGHT and the daemon answered with
      // OUR block id. Every field must then agree, because the answer is about the block we sent:
      //
      //   wrong height        -- we asked for height H and it returned our block as being elsewhere;
      //   orphan_status true  -- an orphan is not what is at height H on the main chain;
      //   different nonce     -- our block id is a commitment to our nonce;
      //   different pow_hash  -- likewise, for the same bytes.
      //
      // None of those is explained by a reorg or a competing block: a reorg produces a DIFFERENT
      // block id at that height, which is the ambiguous case below. This one is self-contradictory,
      // so verification is disabled rather than a verdict guessed.
      const inconsistent = [];
      if (!heightOk) inconsistent.push('height');
      if (!notOrphan) inconsistent.push('orphan_status');
      if (!nonceOk) inconsistent.push('nonce');
      if (!powOk) inconsistent.push('pow_hash');
      latch.trip(FATAL_CODES.IMPOSSIBLE_READBACK,
        `the readback named the submitted block but disagreed about: ${inconsistent.join(', ')}`);
      return publishTerminal(TERMINAL.SUBMIT_UNTRUSTED,
        'the readback identified the submitted block but disagreed about it; nothing here is trustworthy',
        {
          nonce,
          hashHexLE,
          submittedBlockId: submitted.blockId,
          inconsistentFields: inconsistent,
          readbackHeight: header?.height ?? null,
          readbackNonce: header?.nonce ?? null,
          readbackOrphanStatus: header?.orphanStatus ?? null,
          readbackPowHashMatched: powOk,
          fatalCode: FATAL_CODES.IMPOSSIBLE_READBACK,
        });
    }

    if (!sameBlock) {
      // A DIFFERENT block at the height we submitted to: absent, competing, or reorganised away.
      // AMBIGUOUS -- a reorg is plausible -- not a deterministic disagreement.
      const mismatched = ['block_id'];
      if (!heightOk) mismatched.push('height');
      if (!nonceOk) mismatched.push('nonce');
      if (!notOrphan) mismatched.push('orphan_status');
      if (!powOk) mismatched.push('pow_hash');
      return publishTerminal(TERMINAL.READBACK_MISMATCH,
        `the readback does not establish this block on the main chain: ${mismatched.join(', ')}`,
        {
          nonce,
          hashHexLE,
          mismatchedFields: mismatched,
          submittedBlockId: submitted.blockId,
          readbackBlockId: header?.hash ?? null,
          readbackHeight: header?.height ?? null,
          readbackNonce: header?.nonce ?? null,
          readbackOrphanStatus: header?.orphanStatus ?? null,
          readbackPowHashMatched: powOk,
        });
    }

    if (canonical !== null) {
      // THE TWO REAL-DAEMON REQUIREMENTS. Our block, at our height, on top of the template's parent,
      // and the daemon's top block is this very block. Anything else is not established.
      let top;
      try {
        top = await daemon.getLastBlockHeader({ fillPowHash: false });
      } catch (err) {
        return publishTerminal(TERMINAL.SUBMIT_AMBIGUOUS,
          'the block matched at its height but the top block could not be read back; not established',
          { nonce, hashHexLE, submittedBlockId: submitted.blockId, daemonCode: err?.code ?? null });
      }
      if (latch.tripped) {
        return publishTerminal(TERMINAL.SUBMIT_UNTRUSTED,
          'verification was disabled before the readback could be trusted',
          { nonce, hashHexLE, fatalCode: latch.code });
      }
      if (terminal !== null) return alreadyTerminal();
      const mismatched = [];
      if (header?.prevHash !== canonical.prevHashHex) mismatched.push('prev_hash');
      if (String(top?.height) !== job.height.toString()) mismatched.push('top_height');
      if (top?.hash !== submitted.blockId) mismatched.push('top_block_id');
      if (mismatched.length > 0) {
        return publishTerminal(TERMINAL.READBACK_MISMATCH,
          `the readback does not establish this block as the canonical top: ${mismatched.join(', ')}`,
          {
            nonce,
            hashHexLE,
            mismatchedFields: mismatched,
            submittedBlockId: submitted.blockId,
            readbackTopHeight: top?.height ?? null,
            readbackTopBlockId: top?.hash ?? null,
          });
      }
    }

    return publishTerminal(TERMINAL.VERIFIED_COMPLETE, '', {
      nonce,
      hashHexLE,
      blockId: submitted.blockId,
      height: job.height.toString(),
      // Named precisely. An immediate main-chain observation with a matching recomputed
      // proof-of-work. NOT finality: a reorg can still remove it.
      confirmedBy: canonical !== null
        ? 'immediate_canonical_readback_top_block_with_matching_pow_hash'
        : 'immediate_main_chain_readback_with_matching_pow_hash',
      isFinal: false,
    });
  }

  /**
   * RESOLVE AN AMBIGUOUS SUBMISSION BY READING, NEVER BY SUBMITTING AGAIN. Real-daemon mode only.
   *
   * The block is established only if the canonical header at the template height carries exactly
   * this nonce and this proof-of-work hash on top of the template's previous hash, is not an orphan,
   * and is the daemon's top block. The proof-of-work hash is taken over the hashing blob, which
   * commits to the header, the nonce and the merkle root of this template's transactions, so a
   * matching one identifies this exact block. Returns a published terminal, or null (still unknown).
   */
  async function resolveByCanonicalReadback(nonce, hashHexLE, daemonCode) {
    if (canonical === null) return null;
    let header;
    let top;
    try {
      header = await daemon.getBlockHeaderByHeight(job.height.toString(), { fillPowHash: true });
      top = await daemon.getLastBlockHeader({ fillPowHash: false });
    } catch {
      return null;
    }
    if (latch.tripped) {
      return publishTerminal(TERMINAL.SUBMIT_UNTRUSTED,
        'verification was disabled before the readback could be trusted',
        { nonce, hashHexLE, fatalCode: latch.code });
    }
    if (terminal !== null) return alreadyTerminal();
    const exact = typeof header?.hash === 'string' && HEX64.test(header.hash)
      && String(header.height) === job.height.toString()
      && header.nonce === nonce
      && header.powHash === hashHexLE
      && header.orphanStatus === false
      && header.prevHash === canonical.prevHashHex
      && String(top?.height) === job.height.toString()
      && top?.hash === header.hash;
    if (!exact) return null;
    return publishTerminal(TERMINAL.VERIFIED_COMPLETE, '', {
      nonce,
      hashHexLE,
      blockId: header.hash,
      height: job.height.toString(),
      submitResponse: 'ambiguous',
      daemonCode,
      confirmedBy: 'canonical_readback_resolved_an_ambiguous_submission',
      isFinal: false,
    });
  }
}
