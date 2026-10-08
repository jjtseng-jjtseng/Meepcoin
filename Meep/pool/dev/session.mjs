// Per-connection protocol state and the share-submission pipeline.
//
// This module is transport-free: it takes raw bytes in and calls `send(obj)` out, so the whole
// rejection ordering can be tested without a socket, and the real WebSocket server is a thin
// adapter over it.
//
// THE ORDERING IS THE POINT. Every cheap check runs BEFORE the expensive MeepHash-W
// recomputation, so a malformed, unauthorised, stale, duplicated, rate-limited or queued-out
// submission costs the server no hashing at all. `verifier.hashCalls` is the observable proof:
// the tests assert it is unchanged across each of those refusals.
//
//   1. message byte-size limit          (parseClientMessage, before JSON.parse)
//   2. strict schema + EXACT protocol version
//   3. connection + worker identity, and that this peer declared start intent
//   4. active job / expiry / nonce window        <-- captured job object, not a client string
//   5. duplicate (jobId, nonce)
//   6. per-connection token bucket
//   7. bounded per-connection verification-queue admission
//   -- everything above is free --
//   7b. RECHECK the captured job after queue admission; stale here still costs nothing
//   8. server-side hash recomputation   <-- the only hash call
//   9. RECHECK the captured job again, then compare against the SERVER's target
//  10. atomic consumeIfActive(): at most ONE completion may ever accept a given generation
//
// Steps 7b and 9 exist because verification is asynchronous. A job that goes stale while queued
// costs zero hashes; a job that goes stale after its hash already started may consume that call
// but can never be accepted. Both are reported honestly.

import { randomBytes } from 'node:crypto';

import { parseClientMessage, PROTOCOL_VERSION, REJECT_REASONS } from '../../web-miner/lib/shared/protocol.js';
import { nonceToHex } from '../../web-miner/lib/shared/target.js';
import { createTokenBucket } from './ratelimit.mjs';

export const DEFAULT_LIMITS = Object.freeze({
  maxDuplicateKeys: 4096,
  maxVerificationQueue: 2,
  // GLOBAL cap across all sessions. The native helper serialises hashing on a single Hasher, so a
  // per-connection cap alone cannot bound total queued work.
  maxGlobalVerificationQueue: 4,
  rateCapacity: 8,
  rateRefillPerSecond: 4,
});

const NOTICE = 'local synthetic development job - no coins or rewards';

let workerCounter = 0;

export function newWorkerId() {
  workerCounter += 1;
  return `w-${workerCounter}-${randomBytes(4).toString('hex')}`;
}

/**
 * @param {object} o
 * @param {ReturnType<import('./jobs.mjs').createJobStore>} o.jobs
 * @param {() => object|null} o.getVerifier      the ready verifier, or null before Start
 * @param {() => Promise<object>} o.ensureVerifier  single-flight lazy init, called ONLY on Start
 * @param {(obj:object) => void} o.send
 * @param {() => number} [o.now]
 * @param {object} [o.limits]                    ALL per-connection, not global
 * @param {() => Promise<void>} [o.scheduleVerification]  yield point before the hash call
 * @param {(entry:object) => void} [o.onAudit]
 */
export function createSession({
  jobs,
  getVerifier,
  ensureVerifier,
  send,
  now = () => Date.now(),
  limits = {},
  scheduleVerification = () => Promise.resolve(),
  onAudit = () => {},
  // { healthy, reason, detail }. A latched-unhealthy verifier refuses everything, permanently.
  verifierHealth = () => ({ healthy: true }),
  // Global admission across sessions; the default is an unbounded no-op for direct unit tests.
  globalQueue = { tryEnter: () => true, leave: () => {}, depth: 0 },
}) {
  const cfg = { ...DEFAULT_LIMITS, ...limits };
  const bucket = createTokenBucket({ capacity: cfg.rateCapacity, refillPerSecond: cfg.rateRefillPerSecond, now });

  let authorized = false;
  let started = false;
  let startInFlight = false;
  let disposed = false;
  let workerId = null;
  // Bounded replay memory: `${jobId}:${nonceHex}`. Cleared whenever a job is issued, so it cannot
  // grow with time; capped so it cannot grow with traffic either. PER CONNECTION.
  let seenShares = new Set();
  let inFlight = 0;
  let accepted = 0;
  let rejected = 0;
  let terminalSent = false;
  // Identity for the global consumption callback: the winning session recognises itself here.
  const selfTag = Symbol('session');

  const unsubscribeIssue = jobs.onIssue((job) => {
    // A newly issued job makes every old (jobId, nonce) key unreachable, so the memory for them
    // is released rather than accumulated.
    seenShares = new Set();
    if (authorized && !disposed) send(jobs.toWireMessage(job));
  });

  // The synthetic demonstration is GLOBAL. When it is consumed it is over for EVERY session that
  // was running it, so each of those has its start intent cleared and is told exactly once. The
  // winner is skipped here and sends its own notice after share_accepted, to keep that ordering.
  const unsubscribeConsumed = jobs.onConsumed((job, winner) => {
    if (winner === selfTag || disposed) return;
    if (!started) return; // a connected observer that never started did not "complete" anything
    started = false;
    sendTerminal(job, false);
  });

  /** The one terminal notice a started session gets when the shared demonstration ends. */
  function sendTerminal(job, won, extra = {}) {
    if (terminalSent) return;
    terminalSent = true;
    send({
      type: 'demo_complete',
      jobId: job.jobId,
      won,
      ...extra,
      notice: won
        ? 'synthetic demonstration complete - press Start again for another run. No coins or rewards.'
        : 'the shared synthetic demonstration was completed by another connection on this machine. '
          + 'Mining stopped; press Start again for another run. No coins or rewards.',
    });
  }

  /** hashCalls right now, or null before the verifier exists. Used only for audit records. */
  function hashCallsOrNull() {
    const v = getVerifier();
    return v ? v.hashCalls : null;
  }

  function reject(reason, detail, share) {
    rejected++;
    onAudit({ kind: 'reject', reason, detail, hashCalls: hashCallsOrNull() });
    if (share) {
      send({ type: 'share_rejected', jobId: share.jobId, nonce: share.nonceHex, reason, detail: detail || undefined });
    } else {
      send({ type: 'error', reason, detail: detail || undefined });
    }
    return { ok: false, reason, detail };
  }

  async function handleRaw(byteLength, text) {
    if (disposed) return { ok: false, reason: 'disposed' };
    // (1) size, (2) schema + exact protocol version
    const msg = parseClientMessage(byteLength, text);
    if (!msg.ok) return reject(msg.reason, msg.detail, null);

    switch (msg.type) {
      case 'client_hello':
        return handleClientHello();
      case 'start_request':
        return handleStartRequest();
      case 'ping':
        send({ type: 'pong' });
        return { ok: true, type: 'ping' };
      case 'pong':
        return { ok: true, type: 'pong' };
      case 'submit_share':
        return handleSubmitShare(msg);
      default:
        return reject(REJECT_REASONS.UNKNOWN_TYPE, msg.type, null);
    }
  }

  function handleClientHello() {
    if (authorized) return reject(REJECT_REASONS.BAD_SCHEMA, 'client_hello already sent', null);
    authorized = true;
    workerId = newWorkerId();
    // PASSIVE status only. A page that loads while the pool already has a verifier can show the
    // memory the pool is holding instead of an inaccurate dash. Reading it initializes nothing,
    // creates no Worker and is not run intent.
    const live = getVerifier();
    send({
      type: 'server_hello',
      protocolVersion: PROTOCOL_VERSION,
      workerId,
      verifierState: live ? 'ready' : 'uninitialized',
      verifierWasmHeapBytes: live ? live.wasmHeapBytes() : null,
      // Disclosed separately and never summed: the Wasm heap is measured, the native figure is the
      // algorithm's own dataset+scratchpad allocation, and neither is the pool process's RSS.
      verifierNativeAlgorithmBytes: live ? (live.nativeAlgorithmBytes?.() ?? null) : null,
      verifierMode: live ? (live.kind ?? 'wasm') : null,
      notice: NOTICE,
    });
    // Disclosing the job costs nothing: its target comes from the committed vectors, not from
    // hashing, and issuing one initializes no verifier. The client still may not mine until it
    // sends start_request and is told the verifier is ready.
    //
    // If the standing job has expired, issue a fresh one rather than disclosing dead work: a page
    // that connects late must still see a usable job, or its Start button never enables. onIssue
    // delivers it, so this must not also send it.
    //
    // ONE clock sample, ONE job capture. Asking "is there work?" and then re-fetching it with a
    // second now() let a job expiring between the two reads pass the first check and come back
    // null from the second, which threw and closed the connection.
    const at = now();
    const disclosed = jobs.active(at);
    if (disclosed) send(jobs.toWireMessage(disclosed));
    else jobs.issue(at);
    onAudit({ kind: 'client_hello', workerId, hashCalls: hashCallsOrNull() });
    return { ok: true, type: 'client_hello', workerId };
  }

  /**
   * THE CONSENT BOUNDARY. Only this path may bring the server's Wasm verifier into existence.
   * Repeated start_requests are idempotent: `ensureVerifier` is single-flight, and a second
   * request while one is in flight is answered by the same initialization.
   *
   * Precisely what this establishes: the peer DECLARED start intent. The official page sends this
   * only from its Start click handler, so a person using that page really did click. The server
   * cannot verify that; any local program able to open a loopback socket can send this message,
   * and Origin is not authentication.
   */
  async function handleStartRequest() {
    if (!authorized) return reject(REJECT_REASONS.NOT_AUTHORIZED, 'client_hello required first', null);
    const health = verifierHealth();
    if (!health.healthy) {
      // A pool whose two builds disagreed does not start new mining. Ever, until restarted.
      send({ type: 'mining_unavailable', reason: health.reason, detail: health.detail });
      return { ok: false, reason: health.reason };
    }
    if (startInFlight) return { ok: true, type: 'start_request', pending: true };
    startInFlight = true;
    try {
      const verifier = await ensureVerifier();
      if (disposed) return { ok: false, reason: 'disposed' };
      started = true;
      terminalSent = false;
      // Re-evaluate the job with the CURRENT clock, after the await. Absent, consumed, superseded
      // or EXPIRED all mean the same thing here: there is no usable work, so issue a fresh
      // generation. Without the expiry case, a page left open past the ten-minute job lifetime
      // would be told to mine an already-dead job, hash the whole window, be told expired_job,
      // and then wait forever because no replacement was ever sent.
      //
      // The new job goes out BEFORE mining_ready (the onIssue listener sends it synchronously),
      // so the Worker can only ever be handed current work. When a job is already active the
      // client was given it at client_hello and nothing is re-sent: a second copy of a job the
      // client already holds would look like new work and is not.
      const at = now();
      if (!jobs.hasActiveWork(at)) jobs.issue(at); // the onIssue listener delivers it first
      send({
        type: 'mining_ready',
        workerId,
        verifierWasmHeapBytes: verifier.wasmHeapBytes(),
        verifierNativeAlgorithmBytes: verifier.nativeAlgorithmBytes?.() ?? null,
        verifierMode: verifier.kind ?? 'wasm',
        notice: NOTICE,
      });
      onAudit({ kind: 'mining_ready', workerId, hashCalls: hashCallsOrNull() });
      return { ok: true, type: 'mining_ready' };
    } catch (err) {
      started = false;
      // A startup that FAILED BECAUSE THE TWO BUILDS DISAGREED is not a generic "could not start
      // the verifier". Re-read health here: the failing initialization latched the pool on its way
      // out, and reporting that as retryable would invite the client to ask again for something
      // that can never succeed until the pool is restarted.
      const after = verifierHealth();
      const reason = after.healthy ? REJECT_REASONS.VERIFIER_UNAVAILABLE : after.reason;
      const detail = after.healthy
        ? String(err?.message ?? err).split(String.fromCharCode(10))[0].slice(0, 240)
        : after.detail;
      onAudit({ kind: 'verifier_unavailable', reason, message: err?.message ?? String(err) });
      send({ type: 'mining_unavailable', reason, detail });
      return { ok: false, reason };
    } finally {
      startInFlight = false;
    }
  }

  async function handleSubmitShare(share) {
    // (3) identity, and that this peer declared start intent (not proof of a human click)
    if (!authorized) return reject(REJECT_REASONS.NOT_AUTHORIZED, 'client_hello required first', share);
    if (share.workerId !== workerId) return reject(REJECT_REASONS.UNKNOWN_WORKER, 'workerId not issued to this connection', share);
    const verifier = getVerifier();
    if (!started || !verifier) {
      // Nothing may be verified before Start; there is deliberately no verifier to do it with.
      return reject(REJECT_REASONS.NOT_STARTED, 'start_request required before submitting shares', share);
    }

    // (4) active job / expiry, as ONE decision against ONE clock sample. Capture the job OBJECT:
    // everything after this rechecks that exact object, so a client-supplied jobId can never
    // resurrect a completed generation. Splitting this into a reason check and a separate
    // active() fetch sampled the clock twice, and a job expiring between the two reads threw.
    const resolved = jobs.resolveForSubmission(share.jobId, now());
    if (resolved.reason) return reject(resolved.reason, 'job is not the active one', share);
    const job = resolved.job;
    if (!job) {
      // Defence in depth: a resolver that returned neither must fail closed as a protocol
      // rejection, never as a dereference that closes the connection with an internal error.
      return reject(REJECT_REASONS.STALE_JOB, 'no active job for this submission', share);
    }

    if (share.nonce < job.nonceStart || share.nonce >= job.nonceStart + job.nonceRange) {
      return reject(REJECT_REASONS.BAD_SCHEMA, 'nonce outside the issued window', share);
    }

    // (5) duplicate
    const key = `${share.jobId}:${share.nonceHex}`;
    if (seenShares.has(key)) return reject(REJECT_REASONS.DUPLICATE_SHARE, 'already submitted', share);
    if (seenShares.size >= cfg.maxDuplicateKeys) {
      // Fail closed: forgetting keys to make room would re-open replay.
      return reject(REJECT_REASONS.DUPLICATE_MEMORY_FULL, 'replay memory is full for this job', share);
    }

    // (6) rate
    if (!bucket.take()) return reject(REJECT_REASONS.RATE_LIMITED, 'too many submissions', share);

    // (7) bounded verification queue -- per connection, then GLOBAL. Both are cheap refusals and
    // both happen before either build hashes anything.
    if (inFlight >= cfg.maxVerificationQueue) return reject(REJECT_REASONS.QUEUE_FULL, 'verification queue is full', share);
    if (!globalQueue.tryEnter()) {
      return reject(REJECT_REASONS.QUEUE_FULL, 'the pool-wide verification queue is full', share);
    }

    // Recorded only once the submission is actually going to be verified, so a rejected message
    // never consumes a replay slot.
    seenShares.add(key);

    inFlight++;
    let result;
    try {
      await scheduleVerification();
      if (disposed) return { ok: false, reason: 'disposed' };

      // (7b) The job may have gone stale while this submission waited for the queue. Rechecking
      // HERE, before the hash, is what keeps a stale submission free.
      const queuedReason = jobs.inactiveReasonFor(job, now());
      if (queuedReason) return reject(queuedReason, 'job completed or expired while queued', share);

      // (8) recomputation. In dual mode this is ONE call that runs BOTH builds and requires them
      // to agree byte-for-byte before it returns; a disagreement throws rather than returning a
      // verdict. `share.untrustedResultHash` is deliberately not read anywhere in this function.
      result = await verifier.verify(share.nonce, job.targetBytes);
    } catch (err) {
      // A verification that failed because THE POOL IS SHUTTING DOWN is not news for the client:
      // its connection is being closed anyway, and a late `share_rejected` is exactly the noise
      // the shutdown contract forbids. Cancellation is flagged on the error by the verifier that
      // was asked to stop, so this cannot be confused with a child that died on its own -- and it
      // is checked as well as `disposed` because shutdown settles these operations BEFORE the
      // sessions are disposed. That ordering is the whole reason close() terminates at all.
      if (disposed || err?.cancelled === true) return { ok: false, reason: 'cancelled' };
      // A build disagreement or helper fault, though, is NEVER an accepted share. Reject this one
      // and let the pool's health latch stop every session.
      const health = verifierHealth();
      const reason = health.healthy ? REJECT_REASONS.VERIFIER_UNAVAILABLE : health.reason;
      return reject(reason, String(err?.message ?? err).split('\n')[0].slice(0, 240), share);
    } finally {
      inFlight--;
      globalQueue.leave();
    }
    if (disposed) return { ok: false, reason: 'disposed' };

    // (8b) THE ACCEPTANCE FENCE, in the session as well as in the verifier.
    //
    // This result was computed BEFORE anything below ran. While it was being computed, a sibling
    // verification on another connection may have caught the two builds disagreeing and latched
    // the pool. A verdict produced by a verifier that has since been declared untrustworthy may
    // not be committed, however correct it looked on its own.
    //
    // It is also the only place that catches a fault latched by something other than a share --
    // an idle helper crash, say. Defence in depth: the dual verifier fences its own returns, and
    // this fences the commit. From here to consumeIfActive() there is NO await, deliberately, so
    // nothing can latch in the gap between deciding and committing.
    const commitHealth = verifierHealth();
    if (!commitHealth.healthy) {
      return reject(commitHealth.reason,
        'the pool stopped being able to verify while this share was being checked', share);
    }

    // (9) The job may have been completed by another connection while this hash was running. The
    // call is already spent -- that is unavoidable and reported as such -- but it cannot be
    // accepted.
    // ONE commit-time sample for BOTH the final reason decision and the atomic consume. Sampling
    // twice here was safe but dishonest: a job crossing expiry between the two calls was rejected
    // as `stale_job` / "another share completed this job first" when nothing had completed it and
    // the truth was simply that it expired.
    const commitAt = now();
    const verifiedReason = jobs.inactiveReasonFor(job, commitAt);
    if (verifiedReason) return reject(verifiedReason, 'job completed or expired during verification', share);

    // (9b) The job is still live, so a run that has nonetheless ended here ended for some OTHER
    // reason -- this session was halted, stopped or already given its terminal notice. Checked
    // AFTER the job state on purpose: when another connection completed the work, `stale_job` is
    // the accurate answer and this blunter one would hide it.
    if (!started || terminalSent) {
      return reject(REJECT_REASONS.NOT_STARTED, 'this run had already ended', share);
    }

    if (!result.meets) return reject(REJECT_REASONS.ABOVE_TARGET, 'recomputed hash is above the target', share);

    // (10) Atomic compare-and-consume, against that SAME instant.
    if (!jobs.consumeIfActive(job, commitAt, selfTag)) {
      return reject(REJECT_REASONS.STALE_JOB, 'another share completed this job first', share);
    }

    accepted++;
    started = false; // the demonstration is over; another run needs another explicit Start
    onAudit({ kind: 'accept', nonce: share.nonce, hashCalls: hashCallsOrNull() });
    send({
      type: 'share_accepted',
      jobId: share.jobId,
      nonce: share.nonceHex,
      // The server's OWN recomputed hash, echoed so a human can check it. Not the client's.
      hashHexLE: result.hashHexLE,
      serverRecomputed: true,
    });
    // Terminal by design: this job is complete and is NOT replaced automatically. Every job here
    // carries the same fixed synthetic context, so re-issuing one would look like fresh work
    // while repeating the same demonstration. Another run requires another explicit Start.
    // Sent HERE, after share_accepted, which is why the winner is excluded from the global
    // onConsumed notification above.
    sendTerminal(job, true, { nonce: share.nonceHex, hashHexLE: result.hashHexLE });
    return { ok: true, type: 'share_accepted', nonce: share.nonce, hashHexLE: result.hashHexLE };
  }

  return {
    handleRaw,
    /**
     * The pool has latched unhealthy. Tell this connection NOW rather than waiting for its next
     * submission to be refused: a browser that has been told nothing keeps a Worker on a CPU core
     * hashing work this pool can no longer verify. Silent on a connection that is not mining, and
     * sent at most once.
     */
    notifyVerifierUnhealthy(health) {
      if (disposed || !started || terminalSent) return false;
      terminalSent = true;
      started = false;
      send({ type: 'mining_unavailable', reason: health.reason, detail: health.detail });
      onAudit({ kind: 'mining_halted', workerId, reason: health.reason });
      return true;
    },
    dispose() {
      disposed = true;
      unsubscribeIssue();
      unsubscribeConsumed();
      seenShares = new Set();
    },
    get workerId() {
      return workerId;
    },
    get authorized() {
      return authorized;
    },
    get started() {
      return started;
    },
    get disposed() {
      return disposed;
    },
    get accepted() {
      return accepted;
    },
    get rejected() {
      return rejected;
    },
    get seenShareCount() {
      return seenShares.size;
    },
    get inFlight() {
      return inFlight;
    },
    nonceToHex,
  };
}
