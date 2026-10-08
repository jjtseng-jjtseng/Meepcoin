// Server-authoritative job state for the local development pool.
//
// The client cannot choose, mutate or even name a job context: it receives a jobId, a target and
// a nonce window, and the only thing it may say back is "nonce N of job J". Every field the
// server needs to recompute a share lives here, on the server.
//
// TERMINAL BY DESIGN. Each issued job is one bounded demonstration: it is CONSUMED by the first
// accepted share and is not replaced automatically. That is deliberate, because every job in this
// slice would carry the SAME fixed synthetic context, target and nonce window -- re-issuing it
// would look like fresh work while being a repeat of the same demonstration. A further
// demonstration requires another explicit start_request (the official page sends that only
// from its Start click handler).
//
// consumeIfActive() is the concurrency primitive the share pipeline depends on. It is a
// synchronous compare-and-consume against the captured job OBJECT, so between an `await` and the
// commit no second verification can also win the same generation. It also notifies onConsumed
// listeners, because the demonstration is GLOBAL: when it ends it ends for every session that was
// running it, not only for whichever one won.

import { ALGORITHM_LABEL } from '../../web-miner/lib/shared/protocol.js';

export const DEFAULT_JOB_TTL_MS = 10 * 60 * 1000;
export const DEFAULT_NONCE_START = 0;
export const DEFAULT_NONCE_RANGE = 16;
export const DEFAULT_BATCH_HINT = 4;

/**
 * @param {object} o
 * @param {{targetBytes:Uint8Array, targetHexLE:string, nonceStart:number, nonceRange:number}} o.fixture
 * @param {() => number} [o.now]
 */
export function createJobStore({
  fixture,
  now = () => Date.now(),
  jobTtlMs = DEFAULT_JOB_TTL_MS,
  batchHint = DEFAULT_BATCH_HINT,
}) {
  let generation = 0;
  let current = null;
  let lastConsumed = null;
  const listeners = new Set();
  const consumedListeners = new Set();

  function issue(atMs = now()) {
    generation += 1;
    // ONE timestamp for both fields: sampling the clock twice could make a job whose own
    // issuedAt/expiresAt pair disagrees by a millisecond about when it was created.
    current = {
      jobId: `devjob-${generation}`,
      generation,
      algorithm: ALGORITHM_LABEL,
      // The target lives here as BYTES. Nothing the client sends can change it.
      targetBytes: fixture.targetBytes,
      targetHexLE: fixture.targetHexLE,
      nonceStart: fixture.nonceStart,
      nonceRange: fixture.nonceRange,
      batchHint,
      issuedAtMs: atMs,
      expiresAtMs: atMs + jobTtlMs,
      consumed: false,
    };
    for (const fn of listeners) {
      try {
        fn(current);
      } catch {
        // one bad listener must not stop job issuance
      }
    }
    return current;
  }

  /** The client-facing job message. Deliberately excludes targetBytes and all internal state. */
  function toWireMessage(job) {
    return {
      type: 'job',
      jobId: job.jobId,
      generation: job.generation,
      algorithm: job.algorithm,
      // 64 lowercase hex characters = the 32 target bytes in LITTLE-ENDIAN STORAGE ORDER, i.e.
      // hex(target[0]) first. Same encoding as meepow/src/target.hpp and the committed vectors.
      targetHexLE: job.targetHexLE,
      nonceStart: job.nonceStart,
      nonceRange: job.nonceRange,
      batchHint: job.batchHint,
      expiresAtMs: job.expiresAtMs,
      notice: 'local synthetic development job - no coins or rewards',
    };
  }

  /**
   * Is `job` still THE active job, by object identity, and not expired or consumed?
   *
   * Object identity rather than a jobId string on purpose: the pipeline captures the job it
   * validated against and rechecks that exact object, so a resurrected id could never match.
   */
  function isActive(job, atMs = now()) {
    return job !== null && job === current && !job.consumed && atMs <= job.expiresAtMs;
  }

  /**
   * Why a captured job is no longer usable, or null when it still is. Distinguishes an EXPIRED
   * job from one that was completed or superseded, so a rejection after an await says which
   * actually happened instead of collapsing both into "stale".
   */
  function inactiveReasonFor(job, atMs = now()) {
    if (job !== null && job === current && !job.consumed && atMs > job.expiresAtMs) return 'expired_job';
    return isActive(job, atMs) ? null : 'stale_job';
  }

  return {
    issue,
    toWireMessage,
    isActive,
    inactiveReasonFor,
    get generation() {
      return generation;
    },
    /**
     * The current ACTIVE WORK, or null. Expired counts as not active: a job whose window has
     * closed is not something a browser should be sent away to hash. (staleReasonFor() still
     * reports expiry separately, so a submission against it gets the accurate reason.)
     */
    active(atMs = now()) {
      if (current === null || current.consumed) return null;
      return atMs <= current.expiresAtMs ? current : null;
    },
    /** True when there is usable current work. */
    hasActiveWork(atMs = now()) {
      return current !== null && !current.consumed && atMs <= current.expiresAtMs;
    },
    /** The job most recently completed by an accepted share, for reporting. */
    lastConsumedJob() {
      return lastConsumed;
    },
    /**
     * Atomically claim `job` as completed. Returns true for the FIRST caller only.
     *
     * This runs synchronously with no `await` inside, so two verifications that resolve in
     * different turns cannot both observe the job as active and both commit.
     */
    consumeIfActive(job, atMs = now(), winner = null) {
      if (!isActive(job, atMs)) return false;
      job.consumed = true;
      lastConsumed = job;
      generation += 1; // the completed generation can never be re-entered
      // The demonstration is GLOBAL, so completing it ends it for every session that was running
      // it -- not just the one that happened to win. `winner` lets that session send its own
      // terminal notice after share_accepted, instead of receiving one out of order from here.
      for (const fn of consumedListeners) {
        try {
          fn(job, winner);
        } catch {
          // one bad listener must not break the commit
        }
      }
      return true;
    },
    /**
     * ONE query, ONE time sample: either the job a submission may be verified against, or the
     * reason it may not. Returns `{ job }` or `{ reason }`, never both and never neither.
     *
     * This exists because splitting the decision was a real bug: `staleReasonFor(id, now())`
     * followed by `active()` sampled the clock twice, and a job whose expiry fell exactly between
     * the two reads passed the first check and then returned null from the second, dereferencing
     * null and closing the connection with an internal error. Callers must not re-fetch.
     */
    resolveForSubmission(jobId, atMs = now()) {
      if (current === null) return { reason: 'unknown_job' };
      if (jobId !== current.jobId) return { reason: 'stale_job' };
      if (current.consumed) return { reason: 'stale_job' };
      if (atMs > current.expiresAtMs) return { reason: 'expired_job' };
      return { job: current };
    },
    /**
     * Why a submission cannot be verified against the active job, or null when it can.
     * Retained for the post-await rechecks and for tests; new call sites should prefer
     * resolveForSubmission(), which cannot be split across two clock reads.
     */
    staleReasonFor(jobId, atMs = now()) {
      if (current === null) return 'unknown_job';
      if (jobId !== current.jobId) return 'stale_job';
      if (current.consumed) return 'stale_job';
      if (atMs > current.expiresAtMs) return 'expired_job';
      return null;
    },
    onIssue(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    /** Notified when a job is consumed: fn(job, winner). Returns an unsubscribe function. */
    onConsumed(fn) {
      consumedListeners.add(fn);
      return () => consumedListeners.delete(fn);
    },
  };
}
