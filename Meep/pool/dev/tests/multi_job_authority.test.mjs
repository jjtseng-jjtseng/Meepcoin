// Focused, non-live tests for the bounded concurrent-job correctness boundary.
// No daemon, listener, browser, helper, wallet, network or hashing path is reachable here.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  MULTI_JOB_MAX_ACTIVE,
  MULTI_JOB_REFUSED,
  createMultiJobAuthority,
} from '../multi_job_authority.mjs';

const START_A = '01'.repeat(16);
const START_B = '02'.repeat(16);
const START_C = '03'.repeat(16);
const PARENT = 'aa'.repeat(32);
const OTHER_PARENT = 'bb'.repeat(32);

function job(n, { height = 7n, expiresAtMs = 2_000 } = {}) {
  return Object.freeze({
    jobId: `job-${n}`,
    issuanceId: Number(n).toString(16).padStart(32, '0'),
    contentDigest: Number(n).toString(16).padStart(64, '0'),
    expiresAtMs,
    height,
  });
}

const canonical = (parent = PARENT, height = 7n) => ({ height, parent });

function reserveAndPublish(authority, owner, clientStartId, value, tip = canonical()) {
  assert.equal(authority.reserve({ owner, clientStartId }).ok, true);
  const published = authority.publish({ owner, clientStartId, job: job(value, { height: BigInt(tip.height) }), canonical: tip });
  assert.equal(published.ok, true);
  return published;
}

function claim(authority, owner, clientStartId, value, over = {}) {
  const j = job(value, { height: over.height ?? 7n, expiresAtMs: over.expiresAtMs ?? 2_000 });
  return authority.claimSubmission({
    owner,
    clientStartId,
    jobId: j.jobId,
    issuanceId: j.issuanceId,
    contentDigest: j.contentDigest,
    runGeneration: 1,
    intentLive: () => true,
    atMs: 1_000,
    ...over,
  });
}

test('exactly two owners may reserve; same owner/start is idempotent and another start is refused', () => {
  const authority = createMultiJobAuthority();
  const a = {};
  const b = {};
  const c = {};

  const first = authority.reserve({ owner: a, clientStartId: START_A });
  assert.deepEqual([first.ok, first.idempotent, first.assignment.state], [true, false, 'reserved']);
  const again = authority.reserve({ owner: a, clientStartId: START_A });
  assert.deepEqual([again.ok, again.idempotent], [true, true]);
  assert.deepEqual(authority.reserve({ owner: a, clientStartId: START_B }), {
    ok: false, reason: MULTI_JOB_REFUSED.OWNER_BUSY,
  });
  assert.equal(authority.reserve({ owner: b, clientStartId: START_B }).ok, true);
  assert.deepEqual(authority.reserve({ owner: c, clientStartId: START_C }), {
    ok: false, reason: MULTI_JOB_REFUSED.CAPACITY,
  });
  assert.deepEqual(authority.stateFacts, {
    active: 2,
    activeLimit: MULTI_JOB_MAX_ACTIVE,
    terminal: 0,
    reservationLimit: 32,
    reservationsIssued: 2,
    canonicalClaims: 0,
    canonicalClaimLimit: 32,
    invalidatedCanonicals: 0,
    invalidatedCanonicalLimit: 32,
  });
});

test('publication is owner/start-bound, immutable and idempotent only for exactly the same work', () => {
  const authority = createMultiJobAuthority();
  const owner = {};
  authority.reserve({ owner, clientStartId: START_A });

  assert.deepEqual(authority.publish({ owner: {}, clientStartId: START_A, job: job(1), canonical: canonical() }), {
    ok: false, reason: MULTI_JOB_REFUSED.NOT_RESERVED,
  });
  assert.deepEqual(authority.publish({ owner, clientStartId: START_B, job: job(1), canonical: canonical() }), {
    ok: false, reason: MULTI_JOB_REFUSED.START_MISMATCH,
  });
  const first = authority.publish({ owner, clientStartId: START_A, job: job(1), canonical: canonical() });
  assert.deepEqual([first.ok, first.idempotent, first.assignment.state], [true, false, 'published']);
  const again = authority.publish({ owner, clientStartId: START_A, job: job(1), canonical: canonical() });
  assert.deepEqual([again.ok, again.idempotent], [true, true]);
  assert.throws(
    () => authority.publish({ owner, clientStartId: START_A, job: job(2), canonical: canonical() }),
    (err) => err?.code === 'publication_equivocation',
  );
});

test('one issuance id cannot be assigned to two active or terminal reservations', () => {
  const authority = createMultiJobAuthority();
  const a = {};
  const b = {};
  reserveAndPublish(authority, a, START_A, 1);
  authority.reserve({ owner: b, clientStartId: START_B });
  assert.throws(
    () => authority.publish({ owner: b, clientStartId: START_B, job: job(1), canonical: canonical() }),
    (err) => err?.code === 'issuance_equivocation',
  );
  authority.release({ owner: a, clientStartId: START_A });
  assert.throws(
    () => authority.publish({ owner: b, clientStartId: START_B, job: job(1), canonical: canonical() }),
    (err) => err?.code === 'issuance_equivocation',
  );
});

test('two personalized issuances on one canonical tip share one atomic process-wide claim', () => {
  const authority = createMultiJobAuthority({ now: () => 1_000 });
  const a = {};
  const b = {};
  reserveAndPublish(authority, a, START_A, 1);
  reserveAndPublish(authority, b, START_B, 2);

  const winner = claim(authority, a, START_A, 1);
  assert.equal(winner.ok, true);
  assert.equal(winner.claim.issuanceId, job(1).issuanceId);
  assert.deepEqual(claim(authority, b, START_B, 2), {
    ok: false, reason: MULTI_JOB_REFUSED.CANONICAL_CLAIMED,
  });
  assert.deepEqual(claim(authority, a, START_A, 1), {
    ok: false, reason: MULTI_JOB_REFUSED.ALREADY_CLAIMED,
  });
  assert.equal(authority.stateFacts.canonicalClaims, 1);
});

test('different canonical tips have independent claims while each tip remains single-claim', () => {
  const authority = createMultiJobAuthority();
  const a = {};
  const b = {};
  reserveAndPublish(authority, a, START_A, 1, canonical(PARENT, 7n));
  reserveAndPublish(authority, b, START_B, 2, canonical(OTHER_PARENT, 7n));
  assert.equal(claim(authority, a, START_A, 1).ok, true);
  assert.equal(claim(authority, b, START_B, 2).ok, true);
  assert.equal(authority.stateFacts.canonicalClaims, 2);
});

test('claim checks complete identity, live intent and inclusive expiry before mutating', () => {
  const authority = createMultiJobAuthority();
  const owner = {};
  reserveAndPublish(authority, owner, START_A, 1);

  for (const over of [
    { jobId: 'other' },
    { issuanceId: 'ff'.repeat(16) },
    { contentDigest: 'ff'.repeat(32) },
  ]) {
    assert.deepEqual(claim(authority, owner, START_A, 1, over), {
      ok: false, reason: MULTI_JOB_REFUSED.IDENTITY_MISMATCH,
    });
  }
  assert.deepEqual(claim(authority, owner, START_A, 1, { intentLive: () => false }), {
    ok: false, reason: MULTI_JOB_REFUSED.INTENT_REVOKED,
  });
  assert.deepEqual(claim(authority, owner, START_A, 1, { intentLive: undefined }), {
    ok: false, reason: MULTI_JOB_REFUSED.INTENT_REVOKED,
  });
  assert.deepEqual(claim(authority, owner, START_A, 1, { intentLive: () => 1 }), {
    ok: false, reason: MULTI_JOB_REFUSED.INTENT_REVOKED,
  });
  assert.deepEqual(claim(authority, owner, START_A, 1, {
    intentLive: () => { throw new Error('stale'); },
  }), {
    ok: false, reason: MULTI_JOB_REFUSED.INTENT_REVOKED,
  });
  assert.deepEqual(claim(authority, owner, START_A, 1, { atMs: 2_001 }), {
    ok: false, reason: MULTI_JOB_REFUSED.EXPIRED,
  });
  assert.equal(claim(authority, owner, START_A, 1, { atMs: 2_000 }).ok, true, 'deadline is inclusive');
});

test('release is terminal, idempotent and cannot release a later start by an old token', () => {
  const authority = createMultiJobAuthority();
  const owner = {};
  reserveAndPublish(authority, owner, START_A, 1);
  const ended = authority.release({ owner, clientStartId: START_A, reason: 'disconnect', atMs: 1_500 });
  assert.deepEqual([ended.ok, ended.idempotent, ended.terminal.reason], [true, false, 'disconnect']);
  assert.deepEqual(authority.reserve({ owner, clientStartId: START_A }), {
    ok: false, reason: MULTI_JOB_REFUSED.TERMINAL,
  });
  const again = authority.release({ owner, clientStartId: START_A });
  assert.deepEqual([again.ok, again.idempotent, again.terminal.reason], [true, true, 'disconnect']);

  assert.equal(authority.reserve({ owner, clientStartId: START_B }).ok, true);
  assert.deepEqual(authority.release({ owner, clientStartId: START_A }), {
    ok: false, reason: MULTI_JOB_REFUSED.START_MISMATCH,
  });
  assert.equal(authority.stateFacts.active, 1);
});

test('canonical invalidation closes every sibling job and requires a matching accepted issuance when supplied', () => {
  const authority = createMultiJobAuthority();
  const a = {};
  const b = {};
  reserveAndPublish(authority, a, START_A, 1);
  reserveAndPublish(authority, b, START_B, 2);
  assert.equal(claim(authority, a, START_A, 1).ok, true);

  assert.deepEqual(authority.invalidateCanonicalTip({
    ...canonical(), acceptedIssuanceId: job(2).issuanceId,
  }), { ok: false, reason: MULTI_JOB_REFUSED.CLAIM_MISMATCH, invalidated: 0 });
  assert.equal(authority.stateFacts.active, 2);

  const invalidated = authority.invalidateCanonicalTip({
    ...canonical(), acceptedIssuanceId: job(1).issuanceId, reason: 'block_accepted', atMs: 1_600,
  });
  assert.deepEqual(invalidated, { ok: true, invalidated: 2 });
  assert.deepEqual(claim(authority, b, START_B, 2), {
    ok: false, reason: MULTI_JOB_REFUSED.TERMINAL,
  });
  assert.deepEqual(authority.stateFacts, {
    active: 0,
    activeLimit: 2,
    terminal: 2,
    reservationLimit: 32,
    reservationsIssued: 2,
    canonicalClaims: 1,
    canonicalClaimLimit: 32,
    invalidatedCanonicals: 1,
    invalidatedCanonicalLimit: 32,
  });

  const c = {};
  assert.equal(authority.reserve({ owner: c, clientStartId: START_C }).ok, true);
  assert.deepEqual(authority.publish({
    owner: c, clientStartId: START_C, job: job(3), canonical: canonical(),
  }), { ok: false, reason: MULTI_JOB_REFUSED.TIP_INVALIDATED });
});

test('an externally observed tip move may invalidate unclaimed work fail-closed', () => {
  const authority = createMultiJobAuthority();
  const a = {};
  const b = {};
  reserveAndPublish(authority, a, START_A, 1);
  reserveAndPublish(authority, b, START_B, 2, canonical(OTHER_PARENT));
  assert.deepEqual(authority.invalidateCanonicalTip({ ...canonical(), reason: 'external_tip_move' }), {
    ok: true, invalidated: 1,
  });
  assert.equal(authority.stateFacts.active, 1);
  assert.equal(claim(authority, b, START_B, 2, { height: 7n }).ok, true);
});

test('a terminal publication still proves the canonical tip was issued and can be tombstoned', () => {
  const authority = createMultiJobAuthority();
  const a = {};
  const b = {};
  reserveAndPublish(authority, a, START_A, 1);
  authority.release({ owner: a, clientStartId: START_A, atMs: 1_100 });
  assert.deepEqual(authority.invalidateCanonicalTip({ ...canonical(), atMs: 1_200 }), {
    ok: true, invalidated: 0,
  });
  assert.equal(authority.reserve({ owner: b, clientStartId: START_B }).ok, true);
  assert.deepEqual(authority.publish({
    owner: b, clientStartId: START_B, job: job(2), canonical: canonical(),
  }), { ok: false, reason: MULTI_JOB_REFUSED.TIP_INVALIDATED });
});

test('bounded history refuses new reservations instead of evicting terminal tokens', () => {
  const authority = createMultiJobAuthority({ maxReservations: 2 });
  const a = {};
  const b = {};
  const c = {};
  assert.equal(authority.reserve({ owner: a, clientStartId: START_A }).ok, true);
  authority.release({ owner: a, clientStartId: START_A });
  assert.equal(authority.reserve({ owner: b, clientStartId: START_B }).ok, true);
  authority.release({ owner: b, clientStartId: START_B });
  assert.deepEqual(authority.reserve({ owner: c, clientStartId: START_C }), {
    ok: false, reason: MULTI_JOB_REFUSED.HISTORY_FULL,
  });
  assert.deepEqual(authority.reserve({ owner: a, clientStartId: START_A }), {
    ok: false, reason: MULTI_JOB_REFUSED.TERMINAL,
  });
  assert.deepEqual(authority.stateFacts, {
    active: 0, activeLimit: 2, terminal: 2, reservationLimit: 2,
    reservationsIssued: 2, canonicalClaims: 0, canonicalClaimLimit: 2,
    invalidatedCanonicals: 0, invalidatedCanonicalLimit: 2,
  });
});

test('malformed owners, starts, canonical identities, jobs and non-finite expiries fail closed', () => {
  const authority = createMultiJobAuthority();
  const owner = {};
  assert.throws(() => authority.reserve({ owner: 'browser', clientStartId: START_A }), (e) => e.code === 'bad_owner');
  assert.throws(() => authority.reserve({ owner, clientStartId: 'A'.repeat(32) }), (e) => e.code === 'bad_client_start_id');
  authority.reserve({ owner, clientStartId: START_A });
  assert.throws(
    () => authority.publish({ owner, clientStartId: START_A, job: job(1), canonical: { height: '07', parent: PARENT } }),
    (e) => e.code === 'bad_canonical_tip',
  );
  assert.throws(
    () => authority.publish({ owner, clientStartId: START_A, job: job(1), canonical: { height: 7, parent: PARENT } }),
    (e) => e.code === 'bad_canonical_tip',
  );
  assert.throws(
    () => authority.publish({ owner, clientStartId: START_A, job: { ...job(1), height: '07' }, canonical: canonical() }),
    (e) => e.code === 'bad_job',
  );
  assert.throws(
    () => authority.publish({ owner, clientStartId: START_A, job: { ...job(1), expiresAtMs: Infinity }, canonical: canonical() }),
    (e) => e.code === 'bad_job',
  );
  assert.throws(
    () => authority.publish({ owner, clientStartId: START_A, job: { ...job(1), expiresAtMs: -1 }, canonical: canonical() }),
    (e) => e.code === 'bad_job',
  );
  assert.throws(
    () => authority.publish({
      owner, clientStartId: START_A,
      job: { ...job(1), expiresAtMs: Number.MAX_SAFE_INTEGER + 1 }, canonical: canonical(),
    }),
    (e) => e.code === 'bad_job',
  );
  assert.throws(
    () => authority.publish({ owner, clientStartId: START_A, job: job(1), canonical: { height: 7n, parent: 'AA'.repeat(32) } }),
    (e) => e.code === 'bad_canonical_tip',
  );
});

test('invalid explicit or injected clock values are refused rather than silently replaced', () => {
  const owner = {};
  const authority = createMultiJobAuthority({ now: () => Infinity });
  reserveAndPublish(authority, owner, START_A, 1);
  assert.throws(
    () => claim(authority, owner, START_A, 1, { atMs: Infinity }),
    (e) => e.code === 'bad_time',
  );
  assert.throws(
    () => authority.release({ owner, clientStartId: START_A }),
    (e) => e.code === 'bad_time',
  );
  assert.equal(authority.stateFacts.active, 1, 'a bad release clock mutated the reservation');
  assert.throws(
    () => authority.invalidateCanonicalTip({ ...canonical() }),
    (e) => e.code === 'bad_time',
  );
  assert.equal(authority.stateFacts.active, 1, 'a bad invalidation clock mutated the reservation');
  assert.equal(authority.stateFacts.invalidatedCanonicals, 0, 'a bad clock tombstoned the canonical tip');
});
