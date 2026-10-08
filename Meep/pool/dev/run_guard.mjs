// The server-owned ownership primitives a one-shot block submission needs:
//
//   createFatalLatch()         a process-lifetime fail-closed verifier latch
//   createTemplateAuthority()  which issuance is CURRENT, and the single submission claim
//
// EXACTLY ONE OF EACH PER SERVER PROCESS. These are safe only if every session shares the same
// instances. Two independently constructed registries can each let the same issuance submit, so the
// server constructs these once and injects them; nothing here creates its own.
//
// WHY A CLAIM ALONE IS NOT ENOUGH. A per-issuance claim stops the SAME issuance submitting twice.
// It does not stop two different issuances of the SAME template both submitting -- issue a
// template, issue it again, and two unexpired jobs with different issuanceIds each hold an
// unclaimed slot. The authority below therefore tracks which issuance is CURRENT and supersedes the
// previous one, so only the current issuance can ever claim.
//
// WHY THE LATCH IS SEPARATE FROM dual_verifier.mjs. The mature latch lives inside
// createDualVerifier(), entangled with a spawned native helper (helper.fail(), HelperFaultError, a
// closing flag). It cannot be constructed without starting a child process, and it is hard-coded to
// the synthetic context, so it is not usable for a recorded-context simulation. This is the same
// SEMANTICS in a form a block run can be handed: first-write-wins, irreversible for the life of the
// process, a fence rechecked after every await, and "a cancellation is not a fault".
//
// CONNECTION BOUNDARY. This latch is still a distinct object, but the real-daemon simulation wires
// dual-verifier faults into it through the verifier's onFault callback. Other callers must make that
// connection explicitly; constructing either object alone does not connect them.
//
// NOTHING MUTABLE LEAVES THE AUTHORITY. An earlier revision returned its live internal records:
// a caller could take the "current" publication and set expiresAtMs to Infinity, or take a granted
// claim and rewrite its issuanceId, and the authority's own decisions changed with it. Every record
// is now stored frozen and only frozen COPIES are handed out, so a caller holding one can mutate its
// own copy all it likes and the authority is unaffected.
//
// SUPERSESSION COMMITS BEFORE IT ANNOUNCES. The old order invoked the supersede listeners while
// `current` still pointed at the outgoing publication, so a listener that re-entered the authority
// observed a state that had already been decided but not yet written. State is updated first; the
// listeners then receive a frozen snapshot of the COMPLETED transition.
//
// CLAIMS ARE PER ISSUANCE, AND THEIR NUMBER IS BOUNDED BY CONSTRUCTION. `maxClaims` defaults to 1: the
// one-shot modes get exactly the old behaviour, where the first claim is the only one the process will
// ever grant. A development sequence constructs its authority with maxClaims equal to its configured
// block count (never more than REAL_SEQUENCE_DEV_MAX_BLOCKS), and even then each issuance can claim at
// most once, a superseded issuance can never claim, and nothing beyond the bound is granted. The
// latch's subscribers are released by each run when it terminates.
//
// THE AUTHORITY'S OWN MEMORY IS FIXED, NOT PROPORTIONAL TO THE RUN. An earlier revision kept a Map of
// every claim and a Set of every superseded issuance id. With at most two issuances that was two
// entries; with a configured sequence it would grow once per rotation, which is exactly the shape of
// state this project refuses to have in a rotation loop. What is kept now is:
//
//   - the CURRENT publication (one record) and whether it has been claimed (one boolean);
//   - a fixed TOMBSTONE TABLE sized to the build's absolute sequence ceiling, each entry carrying the
//     issuance id and whether it was claimed;
//   - counters: how many issuances were published, superseded and claimed.
//
// Nothing needs more than that, because CURRENCY -- not history -- is what authorises a claim: an
// issuance that is not the current one is refused. Keeping the whole possible sequence (at most 32)
// also means the diagnostic queries stay truthful and a previously retired id can never be published
// again during this authority's lifetime.

import { REAL_SEQUENCE_DEV_MAX_BLOCKS, isSupportedSequenceBlocks } from '../../web-miner/lib/shared/protocol.js';

const HEX64 = /^[0-9a-f]{64}$/;
const ISSUANCE_ID_RE = /^[0-9a-f]{32}$/;

/** Every retired issuance one finite run can create, still a hard build-time bound. */
export const SUPERSEDED_TOMBSTONES = REAL_SEQUENCE_DEV_MAX_BLOCKS;

/** Stable, structured codes. These cross the wire; raw exception text never does. */
export const FATAL_CODES = Object.freeze({
  VERIFIER_BUILD_DISAGREEMENT: 'verifier_build_disagreement',
  VERIFIER_MALFORMED_OUTPUT: 'verifier_malformed_output',
  VERIFIER_FAULT: 'verifier_fault',
  ORACLE_DISAGREEMENT: 'recorded_oracle_disagreement',
  IMPOSSIBLE_READBACK: 'impossible_readback_inconsistency',
});

/** Why a claim was refused. All nonterminal from the candidate's point of view. */
export const CLAIM_REFUSED = Object.freeze({
  ALREADY_CLAIMED: 'submission_already_claimed',
  NOT_CURRENT: 'issuance_superseded',
  UNKNOWN_ISSUANCE: 'unknown_issuance',
  IDENTITY_MISMATCH: 'issuance_identity_mismatch',
  INTENT_REVOKED: 'run_intent_revoked',
  EXPIRED: 'issuance_expired',
});

/** The authority was asked to redefine an issuance it already published. */
export class AuthorityEquivocationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuthorityEquivocationError';
  }
}

export class FatalVerifierError extends Error {
  constructor(code, detail) {
    super(`verification is disabled: ${code}`);
    this.name = 'FatalVerifierError';
    this.code = code;
    // Operator-facing only. Callers must send `code`, never this, to a browser.
    this.detail = detail ?? '';
    this.fatal = true;
  }
}

/**
 * A shared, irreversible fail-closed latch.
 *
 * One instance is injected into every run that may act on the same verifier set. Tripping it from
 * anywhere closes it for everything, immediately and for the life of the process.
 */
export function createFatalLatch({ onTrip = () => {} } = {}) {
  let tripped = null;
  const subscribers = new Set();

  function trip(code, detail) {
    // A CANCELLATION IS NOT A FAULT. Shutdown settles outstanding work through errors flagged
    // `cancelled`; latching those would relabel every ordinary close as a verifier failure and
    // permanently disable a server that did exactly what it was asked to do.
    if (detail && detail.cancelled === true) return null;
    if (tripped) return tripped;              // FIRST WRITE WINS, and it is final
    tripped = new FatalVerifierError(code, typeof detail === 'string' ? detail : (detail?.message ?? ''));
    // Synchronous: a sibling run between awaits must not be able to commit after this point. A
    // subscriber that throws must not prevent the latch itself.
    for (const fn of subscribers) {
      try { fn(tripped); } catch { /* a bad subscriber cannot un-latch anything */ }
    }
    try { onTrip(tripped); } catch { /* same */ }
    return tripped;
  }

  return {
    get tripped() { return tripped !== null; },
    get code() { return tripped?.code ?? null; },
    get error() { return tripped; },
    trip,
    /** The fence. Call after every asynchronous boundary and before any irreversible act. */
    assertUsable() { if (tripped) throw tripped; },
    /** Subscribe to the trip, e.g. to revoke every live run intent. Returns an unsubscribe fn. */
    onTrip(fn) {
      subscribers.add(fn);
      return () => subscribers.delete(fn);
    },
    /** Test/diagnostic only. */
    get subscriberCount() { return subscribers.size; },
  };
}

/**
 * The server's single authority over WHICH issuance is current, and the one submission claim.
 *
 * publish(job) makes `job` the current issuance and SUPERSEDES whatever was current before, so a
 * previous issuance can no longer claim even if it has not expired.
 *
 * claimSubmission() is the whole point: a synchronous compare-and-set that re-verifies every
 * binding at once. There is no await inside it, so two callers resolving in different turns cannot
 * both observe the issuance as claimable and both proceed.
 */
export function createTemplateAuthority({ now = () => Date.now(), maxClaims = 1 } = {}) {
  if (!isSupportedSequenceBlocks(maxClaims)) {
    throw new TypeError(`maxClaims must be an integer from 1 to ${REAL_SEQUENCE_DEV_MAX_BLOCKS}`);
  }
  // PRIVATE and FROZEN. Nothing outside this closure ever holds a reference to any record.
  let current = null;          // frozen { jobId, issuanceId, contentDigest, expiresAtMs }
  let claimed = null;          // the most recent frozen { issuanceId, owner, atMs }
  let currentClaim = null;     // the claim on `current`, or null: at most ONE, by construction
  let claimCount = 0;          // how many claims were ever granted; capped at maxClaims
  let publishedCount = 0;
  let supersededCount = 0;
  // THE FIXED TOMBSTONE TABLE. Never longer than the build's absolute sequence ceiling.
  const tombstones = [];       // [{ issuanceId, claimed }], oldest first
  const supersedeListeners = new Set();

  function tombstone(record, wasClaimed) {
    // Capacity is checked BEFORE mutating. The old push-then-check order threw correctly but left
    // the authority corrupted: the current issuance was simultaneously still current and present
    // in an over-limit tombstone table.
    if (tombstones.length >= SUPERSEDED_TOMBSTONES) {
      throw new AuthorityEquivocationError('the bounded issuance history overflowed');
    }
    tombstones.push(Object.freeze({ issuanceId: record.issuanceId, claimed: wasClaimed === true }));
    supersededCount += 1;
  }
  const inTombstones = (issuanceId) => tombstones.some((t) => t.issuanceId === issuanceId);

  /** What publish() will accept. A malformed or non-finite field is refused, not coerced. */
  function validatePublication(job) {
    if (job === null || typeof job !== 'object') {
      throw new TypeError('publish() needs a job object');
    }
    for (const field of ['jobId', 'issuanceId', 'contentDigest']) {
      const v = job[field];
      if (typeof v !== 'string' || v.length === 0 || v.length > 200) {
        throw new TypeError(`publish() needs a non-empty ${field} string`);
      }
    }
    if (!ISSUANCE_ID_RE.test(job.issuanceId)) {
      throw new TypeError('publish() needs an issuanceId of exactly 32 lowercase hex characters');
    }
    if (!HEX64.test(job.contentDigest)) {
      throw new TypeError('publish() needs a contentDigest of exactly 64 lowercase hex characters');
    }
    // A NON-FINITE EXPIRY IS THE WHOLE ATTACK. Infinity compares greater than every clock reading,
    // so an issuance carrying one would never expire. It is refused at the door.
    if (!Number.isFinite(job.expiresAtMs) || !Number.isInteger(job.expiresAtMs)) {
      throw new TypeError('publish() needs a finite integer expiresAtMs');
    }
    return Object.freeze({
      jobId: job.jobId,
      issuanceId: job.issuanceId,
      contentDigest: job.contentDigest,
      expiresAtMs: job.expiresAtMs,
    });
  }

  /** A frozen copy. Callers may mutate what they are given; it is not what the authority reads. */
  function snapshot(record) {
    return record === null ? null : Object.freeze({ ...record });
  }

  function publish(job) {
    const next = validatePublication(job);
    const previous = current;

    // THE SAME ISSUANCE ID MEANS THE SAME AUTHORITY RECORD, OR IT IS EQUIVOCATION. Re-publishing an
    // identical record is idempotent. Re-publishing that id with a different job, content digest or
    // expiry would silently rewrite what an already-issued capability authorises -- including
    // extending its lifetime -- so it is refused and the current record is left exactly as it was.
    if (previous !== null && previous.issuanceId === next.issuanceId) {
      const identical = previous.jobId === next.jobId
        && previous.contentDigest === next.contentDigest
        && previous.expiresAtMs === next.expiresAtMs;
      if (!identical) {
        throw new AuthorityEquivocationError(
          'publish() refused: this issuanceId is already current with a different job, content or expiry',
        );
      }
      return snapshot(current);
    }
    // A superseded issuance stays superseded for this authority's lifetime. Bringing one back would
    // reopen a capability that was deliberately closed.
    if (inTombstones(next.issuanceId)) {
      throw new AuthorityEquivocationError('publish() refused: this issuanceId was already superseded');
    }
    const replacing = previous !== null;

    // COMMIT FIRST. A listener that re-enters the authority must see the transition as finished.
    if (replacing) tombstone(previous, currentClaim !== null);
    current = next;
    currentClaim = null;
    publishedCount += 1;

    if (replacing) {
      const transition = Object.freeze({
        superseded: snapshot(previous),
        current: snapshot(next),
      });
      for (const fn of supersedeListeners) {
        // The first argument stays the outgoing publication, which is what the existing listeners
        // read; the completed transition is the second, for anything that needs both sides.
        try { fn(transition.superseded, transition); } catch { /* a bad listener cannot block it */ }
      }
    }
    return snapshot(current);
  }

  return {
    publish,
    /** A FROZEN COPY. Mutating it changes nothing the authority will ever read. */
    get current() { return snapshot(current); },
    get currentIssuanceId() { return current?.issuanceId ?? null; },
    isCurrent(issuanceId) { return current !== null && current.issuanceId === issuanceId; },
    isSuperseded(issuanceId) { return inTombstones(issuanceId); },
    isClaimed(issuanceId) {
      if (currentClaim !== null && currentClaim.issuanceId === issuanceId) return true;
      return tombstones.some((t) => t.issuanceId === issuanceId && t.claimed);
    },
    /** The most recently claimed issuance, or null. */
    get claimedIssuanceId() { return claimed?.issuanceId ?? null; },
    get anyClaimed() { return claimed !== null; },
    /** A FROZEN COPY of the most recent granted claim, or null. */
    get claim() { return snapshot(claimed); },
    get claimCount() { return claimCount; },
    get maxClaims() { return maxClaims; },
    /**
     * TEST-VISIBLE BOUNDED-STATE FACTS. Sizes and counters only -- no record and no control surface --
     * so a regression can assert that a long sequence does not grow this object.
     */
    get stateFacts() {
      return Object.freeze({
        tombstones: tombstones.length,
        tombstoneLimit: SUPERSEDED_TOMBSTONES,
        currentRecords: current === null ? 0 : 1,
        currentClaims: currentClaim === null ? 0 : 1,
        supersedeListeners: supersedeListeners.size,
        published: publishedCount,
        superseded: supersededCount,
        claims: claimCount,
      });
    },
    onSupersede(fn) {
      supersedeListeners.add(fn);
      return () => supersedeListeners.delete(fn);
    },

    /**
     * THE CRITICAL SECTION. Synchronous, no await, first caller wins.
     *
     * `atMs` is supplied by the caller and used for BOTH the expiry decision and the claim record,
     * so a clock that would advance between two reads cannot let an expired candidate through. The
     * caller must sample it once and pass that one value.
     *
     * `intentLive` is called synchronously here rather than checked beforehand, so a revocation that
     * lands between a caller's own gate and this call still refuses.
     */
    claimSubmission({ jobId, issuanceId, contentDigest, owner, runGeneration, intentLive, atMs }) {
      if (current === null) return { ok: false, reason: CLAIM_REFUSED.UNKNOWN_ISSUANCE };
      if (typeof issuanceId !== 'string' || issuanceId.length === 0) {
        return { ok: false, reason: CLAIM_REFUSED.UNKNOWN_ISSUANCE };
      }
      // CURRENCY DECIDES, NOT HISTORY. Anything that is not the current issuance is refused, whether or
      // not the fixed ring still remembers retiring it.
      if (issuanceId !== current.issuanceId) return { ok: false, reason: CLAIM_REFUSED.NOT_CURRENT };
      // Identity, not merely the token: a job id or template content that does not match the current
      // issuance means these are not the same work, whatever the issuance string says.
      if (jobId !== current.jobId) return { ok: false, reason: CLAIM_REFUSED.IDENTITY_MISMATCH };
      if (contentDigest !== current.contentDigest) {
        return { ok: false, reason: CLAIM_REFUSED.IDENTITY_MISMATCH };
      }
      if (typeof intentLive === 'function' && !intentLive(runGeneration)) {
        return { ok: false, reason: CLAIM_REFUSED.INTENT_REVOKED };
      }
      // The repository's inclusive deadline convention: active while atMs <= expiresAtMs.
      const at = Number.isFinite(atMs) ? atMs : now();
      if (at > current.expiresAtMs) return { ok: false, reason: CLAIM_REFUSED.EXPIRED };
      // One claim per issuance, and never more than the construction-time bound.
      if (currentClaim !== null || claimCount >= maxClaims) return { ok: false, reason: CLAIM_REFUSED.ALREADY_CLAIMED };

      claimed = Object.freeze({ issuanceId, owner: owner ?? null, atMs: at });
      currentClaim = claimed;
      claimCount += 1;
      return { ok: true, claim: snapshot(claimed) };
    },
  };
}
