// Bounded authority for a very small set of concurrently active, server-issued jobs.
//
// This is deliberately not a scheduler and not a pool protocol.  It provides the correctness
// boundary needed before two browser sessions may be given different personalized templates:
//
//   * at most two owners may hold live reservations;
//   * one owner/start token cannot be rebound to different work;
//   * every terminal reservation remains terminal for this authority's bounded lifetime; and
//   * all personalized jobs building on the same canonical {height,parent} share ONE synchronous
//     submission claim, so separate issuances cannot both be dispatched.
//
// The lifetime reservation ceiling makes the state strictly bounded without evicting tombstones.
// Once the ceiling is reached the authority refuses new work rather than forgetting a terminal
// token and making it reusable.

export const MULTI_JOB_MAX_ACTIVE = 2;
export const MULTI_JOB_MAX_RESERVATIONS = 32;

const START_ID = /^[0-9a-f]{32}$/;
const ISSUANCE_ID = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const CANONICAL_U64 = /^(?:0|[1-9][0-9]*)$/;
const U64_MAX = (1n << 64n) - 1n;

export const MULTI_JOB_REFUSED = Object.freeze({
  CAPACITY: 'pool_capacity',
  OWNER_BUSY: 'owner_already_reserved',
  TERMINAL: 'reservation_terminal',
  HISTORY_FULL: 'reservation_history_full',
  NOT_RESERVED: 'reservation_not_found',
  START_MISMATCH: 'reservation_start_mismatch',
  NOT_PUBLISHED: 'job_not_published',
  IDENTITY_MISMATCH: 'job_identity_mismatch',
  INTENT_REVOKED: 'run_intent_revoked',
  EXPIRED: 'issuance_expired',
  ALREADY_CLAIMED: 'submission_already_claimed',
  CANONICAL_CLAIMED: 'canonical_tip_already_claimed',
  TIP_INVALIDATED: 'canonical_tip_invalidated',
  CLAIM_MISMATCH: 'canonical_claim_mismatch',
});

export class MultiJobAuthorityError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.name = 'MultiJobAuthorityError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new MultiJobAuthorityError(code, message);
}

function validOwner(owner) {
  return (typeof owner === 'object' && owner !== null) || typeof owner === 'function';
}

function requireOwner(owner) {
  if (!validOwner(owner)) fail('bad_owner', 'owner must be a non-null object identity');
}

function requireStartId(clientStartId) {
  if (typeof clientStartId !== 'string' || !START_ID.test(clientStartId)) {
    fail('bad_client_start_id', 'clientStartId must be exactly 32 lowercase hex characters');
  }
}

function exactHeight(value, what) {
  // Numbers are deliberately refused.  Above Number.MAX_SAFE_INTEGER a caller could present one
  // decimal value while JavaScript had already rounded it to another before this boundary saw it.
  const text = typeof value === 'bigint' ? value.toString() : value;
  if (typeof text !== 'string' || !CANONICAL_U64.test(text)) {
    fail(what, 'height must be a canonical unsigned decimal string or bigint');
  }
  const height = BigInt(text);
  if (height > U64_MAX) fail(what, 'height exceeds uint64');
  return height.toString();
}

function exactTime(value, what) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(what, 'time must be a non-negative safe integer');
  }
  return value;
}

function canonicalRecord(canonical) {
  if (canonical === null || typeof canonical !== 'object' || Array.isArray(canonical)) {
    fail('bad_canonical_tip', 'canonical must be an object');
  }
  const height = exactHeight(canonical.height, 'bad_canonical_tip');
  if (typeof canonical.parent !== 'string' || !HEX64.test(canonical.parent)) {
    fail('bad_canonical_tip', 'canonical parent must be exactly 64 lowercase hex characters');
  }
  return Object.freeze({ height, parent: canonical.parent });
}

const canonicalKey = (canonical) => `${canonical.height}:${canonical.parent}`;

function publicationRecord(job, canonical) {
  if (job === null || typeof job !== 'object' || Array.isArray(job)) {
    fail('bad_job', 'publish() needs a job object');
  }
  if (typeof job.jobId !== 'string' || job.jobId.length === 0 || job.jobId.length > 200) {
    fail('bad_job', 'jobId must be a non-empty bounded string');
  }
  if (typeof job.issuanceId !== 'string' || !ISSUANCE_ID.test(job.issuanceId)) {
    fail('bad_job', 'issuanceId must be exactly 32 lowercase hex characters');
  }
  if (typeof job.contentDigest !== 'string' || !HEX64.test(job.contentDigest)) {
    fail('bad_job', 'contentDigest must be exactly 64 lowercase hex characters');
  }
  const expiresAtMs = exactTime(job.expiresAtMs, 'bad_job');
  const jobHeight = exactHeight(job.height, 'bad_job');
  if (jobHeight !== canonical.height) {
    fail('bad_job', 'job height must equal the canonical height');
  }
  return Object.freeze({
    jobId: job.jobId,
    issuanceId: job.issuanceId,
    contentDigest: job.contentDigest,
    expiresAtMs,
    canonical,
  });
}

const samePublication = (a, b) => a.jobId === b.jobId
  && a.issuanceId === b.issuanceId
  && a.contentDigest === b.contentDigest
  && a.expiresAtMs === b.expiresAtMs
  && a.canonical.height === b.canonical.height
  && a.canonical.parent === b.canonical.parent;

const snapshotPublication = (p) => p === null ? null : Object.freeze({
  jobId: p.jobId,
  issuanceId: p.issuanceId,
  contentDigest: p.contentDigest,
  expiresAtMs: p.expiresAtMs,
  canonical: Object.freeze({ ...p.canonical }),
});

function snapshotAssignment(record) {
  if (record === null) return null;
  return Object.freeze({
    clientStartId: record.clientStartId,
    state: record.state,
    publication: snapshotPublication(record.publication),
  });
}

/**
 * Create one process-wide authority.  The object must be shared by every session which can act on
 * the same daemon tip.  Constructing one per browser would defeat the canonical submission claim.
 */
export function createMultiJobAuthority({
  now = () => Date.now(),
  maxReservations = MULTI_JOB_MAX_RESERVATIONS,
} = {}) {
  if (typeof now !== 'function') fail('bad_config', 'now must be a function');
  if (!Number.isInteger(maxReservations) || maxReservations < MULTI_JOB_MAX_ACTIVE
    || maxReservations > MULTI_JOB_MAX_RESERVATIONS) {
    fail('bad_config', `maxReservations must be ${MULTI_JOB_MAX_ACTIVE}..${MULTI_JOB_MAX_RESERVATIONS}`);
  }

  // All collections have construction-time ceilings.  Owners are object identities and never cross
  // the wire.  A terminal entry is never evicted, because eviction would make its start token live
  // again.  The authority instead refuses once its lifetime reservation budget is consumed.
  const active = new Map();
  const terminal = [];
  const canonicalClaims = new Map();
  const invalidatedCanonicals = new Set();
  let reservationsIssued = 0;

  const terminalFor = (owner, clientStartId) => terminal.find(
    (t) => t.owner === owner && t.clientStartId === clientStartId,
  ) ?? null;

  function reserve({ owner, clientStartId }) {
    requireOwner(owner);
    requireStartId(clientStartId);
    const current = active.get(owner) ?? null;
    if (current !== null) {
      if (current.clientStartId === clientStartId) {
        return { ok: true, idempotent: true, assignment: snapshotAssignment(current) };
      }
      return { ok: false, reason: MULTI_JOB_REFUSED.OWNER_BUSY };
    }
    if (terminalFor(owner, clientStartId) !== null) {
      return { ok: false, reason: MULTI_JOB_REFUSED.TERMINAL };
    }
    if (active.size >= MULTI_JOB_MAX_ACTIVE) {
      return { ok: false, reason: MULTI_JOB_REFUSED.CAPACITY };
    }
    if (reservationsIssued >= maxReservations) {
      return { ok: false, reason: MULTI_JOB_REFUSED.HISTORY_FULL };
    }
    const record = {
      owner,
      clientStartId,
      state: 'reserved',
      publication: null,
      claim: null,
    };
    active.set(owner, record);
    reservationsIssued += 1;
    return { ok: true, idempotent: false, assignment: snapshotAssignment(record) };
  }

  function publish({ owner, clientStartId, job, canonical }) {
    requireOwner(owner);
    requireStartId(clientStartId);
    const record = active.get(owner) ?? null;
    if (record === null) {
      return { ok: false, reason: terminalFor(owner, clientStartId) === null
        ? MULTI_JOB_REFUSED.NOT_RESERVED : MULTI_JOB_REFUSED.TERMINAL };
    }
    if (record.clientStartId !== clientStartId) {
      return { ok: false, reason: MULTI_JOB_REFUSED.START_MISMATCH };
    }
    const next = publicationRecord(job, canonicalRecord(canonical));
    if (invalidatedCanonicals.has(canonicalKey(next.canonical))) {
      return { ok: false, reason: MULTI_JOB_REFUSED.TIP_INVALIDATED };
    }
    if (record.publication !== null) {
      if (!samePublication(record.publication, next)) {
        fail('publication_equivocation', 'one reservation cannot be rebound to different work');
      }
      return { ok: true, idempotent: true, assignment: snapshotAssignment(record) };
    }
    // An issuance id is globally unique inside this authority, not merely unique per owner.
    for (const other of active.values()) {
      if (other !== record && other.publication?.issuanceId === next.issuanceId) {
        fail('issuance_equivocation', 'one issuanceId cannot belong to two reservations');
      }
    }
    if (terminal.some((t) => t.publication?.issuanceId === next.issuanceId)) {
      fail('issuance_equivocation', 'a terminal issuanceId cannot be published again');
    }
    record.publication = next;
    record.state = 'published';
    return { ok: true, idempotent: false, assignment: snapshotAssignment(record) };
  }

  /** Synchronous compare-and-set across every active personalized issuance for one chain tip. */
  function claimSubmission({
    owner, clientStartId, jobId, issuanceId, contentDigest, runGeneration, intentLive, atMs,
  }) {
    requireOwner(owner);
    requireStartId(clientStartId);
    const record = active.get(owner) ?? null;
    if (record === null) {
      return { ok: false, reason: terminalFor(owner, clientStartId) === null
        ? MULTI_JOB_REFUSED.NOT_RESERVED : MULTI_JOB_REFUSED.TERMINAL };
    }
    if (record.clientStartId !== clientStartId) {
      return { ok: false, reason: MULTI_JOB_REFUSED.START_MISMATCH };
    }
    const p = record.publication;
    if (p === null) return { ok: false, reason: MULTI_JOB_REFUSED.NOT_PUBLISHED };
    if (jobId !== p.jobId || issuanceId !== p.issuanceId || contentDigest !== p.contentDigest) {
      return { ok: false, reason: MULTI_JOB_REFUSED.IDENTITY_MISMATCH };
    }
    let liveIntent = false;
    if (typeof intentLive === 'function') {
      try {
        liveIntent = intentLive(runGeneration) === true;
      } catch {
        liveIntent = false;
      }
    }
    if (!liveIntent) {
      return { ok: false, reason: MULTI_JOB_REFUSED.INTENT_REVOKED };
    }
    const at = exactTime(atMs === undefined ? now() : atMs, 'bad_time');
    if (at > p.expiresAtMs) return { ok: false, reason: MULTI_JOB_REFUSED.EXPIRED };
    if (record.claim !== null) return { ok: false, reason: MULTI_JOB_REFUSED.ALREADY_CLAIMED };
    const key = canonicalKey(p.canonical);
    if (canonicalClaims.has(key)) {
      return { ok: false, reason: MULTI_JOB_REFUSED.CANONICAL_CLAIMED };
    }
    const claim = Object.freeze({
      owner,
      clientStartId,
      issuanceId: p.issuanceId,
      canonical: Object.freeze({ ...p.canonical }),
      atMs: at,
    });
    // Commit both records synchronously; there is no await in this critical section.
    canonicalClaims.set(key, claim);
    record.claim = claim;
    record.state = 'claimed';
    return { ok: true, claim: Object.freeze({ ...claim, canonical: Object.freeze({ ...claim.canonical }) }) };
  }

  function makeTerminal(record, reason, atMs) {
    active.delete(record.owner);
    const entry = Object.freeze({
      owner: record.owner,
      clientStartId: record.clientStartId,
      state: 'terminal',
      reason,
      atMs,
      publication: snapshotPublication(record.publication),
      claimed: record.claim !== null,
    });
    terminal.push(entry);
    return entry;
  }

  function release({ owner, clientStartId, reason = 'released', atMs } = {}) {
    requireOwner(owner);
    requireStartId(clientStartId);
    const record = active.get(owner) ?? null;
    if (record === null) {
      const ended = terminalFor(owner, clientStartId);
      return ended === null
        ? { ok: false, reason: MULTI_JOB_REFUSED.NOT_RESERVED }
        : { ok: true, idempotent: true, terminal: Object.freeze({ ...ended }) };
    }
    if (record.clientStartId !== clientStartId) {
      return { ok: false, reason: MULTI_JOB_REFUSED.START_MISMATCH };
    }
    return {
      ok: true,
      idempotent: false,
      terminal: makeTerminal(record, reason, exactTime(atMs === undefined ? now() : atMs, 'bad_time')),
    };
  }

  /**
   * Close every active job on a canonical tip.  Supplying acceptedIssuanceId proves this is the tip
   * whose global claim won; omitting it is the fail-closed path for an externally observed tip move.
   */
  function invalidateCanonicalTip({
    height, parent, acceptedIssuanceId = null, reason = 'canonical_tip_invalidated', atMs,
  } = {}) {
    const canonical = canonicalRecord({ height, parent });
    const key = canonicalKey(canonical);
    const claim = canonicalClaims.get(key) ?? null;
    if (acceptedIssuanceId !== null
      && (claim === null || claim.issuanceId !== acceptedIssuanceId)) {
      return { ok: false, reason: MULTI_JOB_REFUSED.CLAIM_MISMATCH, invalidated: 0 };
    }
    const matches = [...active.values()].filter((r) => r.publication !== null
      && canonicalKey(r.publication.canonical) === key);
    const previouslyPublished = terminal.some((r) => r.publication !== null
      && canonicalKey(r.publication.canonical) === key);
    const invalidatedAt = exactTime(atMs === undefined ? now() : atMs, 'bad_time');
    // Remember only tips that this authority actually issued or claimed. Thus the set cannot grow
    // beyond the lifetime reservation bound, while an invalidated tip can never be re-published.
    if (matches.length > 0 || claim !== null || previouslyPublished) invalidatedCanonicals.add(key);
    for (const record of matches) makeTerminal(record, reason, invalidatedAt);
    return { ok: true, invalidated: matches.length };
  }

  return Object.freeze({
    reserve,
    publish,
    claimSubmission,
    invalidateCanonicalTip,
    release,
    get stateFacts() {
      return Object.freeze({
        active: active.size,
        activeLimit: MULTI_JOB_MAX_ACTIVE,
        terminal: terminal.length,
        reservationLimit: maxReservations,
        reservationsIssued,
        canonicalClaims: canonicalClaims.size,
        canonicalClaimLimit: maxReservations,
        invalidatedCanonicals: invalidatedCanonicals.size,
        invalidatedCanonicalLimit: maxReservations,
      });
    },
  });
}
