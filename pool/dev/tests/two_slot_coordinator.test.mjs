// Non-live lifecycle tests. No listener, daemon, browser, helper, wallet, network or hash exists.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  TWO_SLOT_REFUSED,
  createTwoSlotCoordinator,
} from '../two_slot_coordinator.mjs';
import { createMultiJobAuthority } from '../multi_job_authority.mjs';

const A = '01'.repeat(16);
const B = '02'.repeat(16);
const C = '03'.repeat(16);
const PARENT = 'aa'.repeat(32);

function issued(n) {
  return Object.freeze({
    job: Object.freeze({
      jobId: `job-${n}`,
      issuanceId: Number(n).toString(16).padStart(32, '0'),
      contentDigest: Number(n).toString(16).padStart(64, '0'),
      expiresAtMs: 10_000,
      height: 7n,
    }),
    context: Object.freeze({ marker: n }),
    templateFacts: Object.freeze({ block: 1, marker: n }),
    canonical: Object.freeze({ prevHashHex: PARENT }),
  });
}

function controlledIssuer() {
  const calls = [];
  const waiters = [];
  let active = 0;
  let maxActive = 0;
  return {
    calls,
    get maxActive() { return maxActive; },
    issuer: {
      async issue({ stillWanted }) {
        const n = calls.length + 1;
        calls.push({ n, stillWanted });
        active += 1;
        maxActive = Math.max(maxActive, active);
        await new Promise((resolve) => waiters.push(resolve));
        active -= 1;
        if (!stillWanted()) {
          throw Object.assign(new Error('cancelled'), { code: 'personalized_issue_cancelled' });
        }
        return issued(n);
      },
    },
    releaseOne() { waiters.shift()?.(); },
  };
}

const claim = (assignment, over = {}) => assignment.authority.claimSubmission({
  jobId: assignment.issued.job.jobId,
  issuanceId: assignment.issued.job.issuanceId,
  contentDigest: assignment.issued.job.contentDigest,
  runGeneration: 1,
  intentLive: () => true,
  atMs: 1_000,
  ...over,
});

test('two reservations issue distinct same-tip jobs and a third is refused before issuance', async () => {
  const source = controlledIssuer();
  const coordinator = createTwoSlotCoordinator({ issuer: source.issuer, now: () => 1_000 });
  const oa = {};
  const ob = {};
  const oc = {};
  const pa = coordinator.begin({ owner: oa, clientStartId: A });
  const pb = coordinator.begin({ owner: ob, clientStartId: B });
  const third = await coordinator.begin({ owner: oc, clientStartId: C });
  assert.deepEqual(third, { ok: false, reason: 'pool_capacity' });
  assert.equal(source.calls.length, 2, 'capacity refusal reached no issuer work');
  source.releaseOne();
  source.releaseOne();
  const [a, b] = await Promise.all([pa, pb]);
  assert.equal(a.ok, true);
  assert.equal(b.ok, true);
  assert.notEqual(a.issued.job.jobId, b.issued.job.jobId);
  assert.notEqual(a.issued.job.issuanceId, b.issued.job.issuanceId);
  assert.deepEqual(a.assignment.canonical, b.assignment.canonical);
  assert.equal(coordinator.stateFacts.active, 2);
});

test('same owner/start joins one issuance; a different start is refused', async () => {
  const source = controlledIssuer();
  const coordinator = createTwoSlotCoordinator({ issuer: source.issuer });
  const owner = {};
  const first = coordinator.begin({ owner, clientStartId: A });
  const repeated = coordinator.begin({ owner, clientStartId: A });
  assert.deepEqual(await coordinator.begin({ owner, clientStartId: B }), {
    ok: false, reason: 'owner_already_reserved',
  });
  assert.equal(source.calls.length, 1);
  source.releaseOne();
  const [a, again] = await Promise.all([first, repeated]);
  assert.equal(a.ok, true);
  assert.equal(again.ok, true);
  assert.equal(again.idempotent, true);
  assert.strictEqual(a.issued, again.issued);
});

test('cancel during issuance publishes nothing and releases capacity without a runtime', async () => {
  const source = controlledIssuer();
  const coordinator = createTwoSlotCoordinator({ issuer: source.issuer });
  const owner = {};
  const pending = coordinator.begin({ owner, clientStartId: A });
  const cancelling = coordinator.cancel({ owner, clientStartId: A, reason: 'disconnect' });
  source.releaseOne();
  assert.deepEqual(await pending, { ok: false, reason: TWO_SLOT_REFUSED.ISSUE_CANCELLED });
  assert.equal((await cancelling).ok, true);
  assert.equal(coordinator.stateFacts.active, 0);
  assert.equal(coordinator.stateFacts.successfulIssues, 0);
});

test('the first canonical claim revokes its sibling synchronously, then closes it after return', async () => {
  let next = 0;
  const coordinator = createTwoSlotCoordinator({
    issuer: { async issue() { next += 1; return issued(next); } },
    now: () => 1_000,
  });
  const oa = {};
  const ob = {};
  const events = [];
  const a = await coordinator.begin({ owner: oa, clientStartId: A });
  const b = await coordinator.begin({ owner: ob, clientStartId: B });
  let aClosed = false;
  coordinator.attachLifecycle({
    owner: oa, clientStartId: A,
    revoke: (reason) => events.push(`a-revoke:${reason}`),
    close: async (reason) => { events.push(`a-close:${reason}`); aClosed = true; },
    isClosed: () => aClosed,
  });
  let bClosed = false;
  let finishSiblingClose;
  coordinator.attachLifecycle({
    owner: ob, clientStartId: B,
    revoke: (reason) => events.push(`b-revoke:${reason}`),
    close: (reason) => new Promise((resolve) => {
      events.push(`b-close-start:${reason}`);
      finishSiblingClose = () => { bClosed = true; resolve(); };
    }),
    isClosed: () => bClosed,
  });

  assert.equal(claim(a).ok, true);
  assert.deepEqual(events, ['b-revoke:canonical_submission_claimed'],
    'the sibling stops searching before the winning claim returns');
  assert.deepEqual(claim(b), { ok: false, reason: 'run_intent_revoked' },
    'the sibling is sealed synchronously before lifecycle notification');
  await new Promise((resolve) => queueMicrotask(resolve));
  assert.equal(events[1], 'b-close-start:canonical_submission_claimed');
  assert.equal(coordinator.stateFacts.closing, 1);
  assert.deepEqual(await coordinator.begin({ owner: {}, clientStartId: C }), {
    ok: false, reason: TWO_SLOT_REFUSED.ROUND_CLOSED,
  });
  finishSiblingClose();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(coordinator.stateFacts.active, 1, 'loser released only after its close confirmed');
  assert.equal((await coordinator.finish({ owner: oa, clientStartId: A })).ok, true);
  assert.equal(coordinator.stateFacts.active, 0);
});

test('a claimed sibling without an attached lifecycle retains capacity until lifecycle arrives', async () => {
  let next = 0;
  const coordinator = createTwoSlotCoordinator({
    issuer: { async issue() { next += 1; return issued(next); } },
    now: () => 1_000,
  });
  const oa = {};
  const ob = {};
  const a = await coordinator.begin({ owner: oa, clientStartId: A });
  await coordinator.begin({ owner: ob, clientStartId: B });
  let aClosed = false;
  coordinator.attachLifecycle({
    owner: oa, clientStartId: A, revoke() {},
    async close() { aClosed = true; }, isClosed: () => aClosed,
  });
  assert.equal(claim(a).ok, true);
  assert.equal(coordinator.stateFacts.active, 2);
  assert.equal(coordinator.stateFacts.closing, 1);
  const calls = [];
  let bClosed = false;
  const attached = coordinator.attachLifecycle({
    owner: ob, clientStartId: B,
    revoke: (reason) => calls.push(`revoke:${reason}`),
    close: async (reason) => { calls.push(`close:${reason}`); bClosed = true; },
    isClosed: () => bClosed,
  });
  assert.equal(attached.ok, true);
  assert.deepEqual(await attached.closePromise, { ok: true, reason: 'canonical_submission_claimed' });
  assert.deepEqual(calls, [
    'revoke:canonical_submission_claimed',
    'close:canonical_submission_claimed',
  ]);
  assert.equal(coordinator.stateFacts.active, 1);
});

test('a claim while the sibling is still issuing cancels it before publication', async () => {
  const source = controlledIssuer();
  const coordinator = createTwoSlotCoordinator({ issuer: source.issuer, now: () => 1_000 });
  const oa = {};
  const ob = {};
  const pa = coordinator.begin({ owner: oa, clientStartId: A });
  const pb = coordinator.begin({ owner: ob, clientStartId: B });
  source.releaseOne();
  const a = await pa;
  let aClosed = false;
  coordinator.attachLifecycle({
    owner: oa, clientStartId: A, revoke() {},
    async close() { aClosed = true; }, isClosed: () => aClosed,
  });
  assert.equal(claim(a).ok, true);
  source.releaseOne();
  assert.deepEqual(await pb, { ok: false, reason: 'canonical_submission_claimed' });
  assert.equal(coordinator.stateFacts.successfulIssues, 1);
  assert.equal(coordinator.stateFacts.active, 1);
});

test('ordinary finish retains a reusable slot until close confirms', async () => {
  let next = 0;
  const coordinator = createTwoSlotCoordinator({
    issuer: { async issue() { next += 1; return issued(next); } },
  });
  const oa = {};
  const ob = {};
  const oc = {};
  await coordinator.begin({ owner: oa, clientStartId: A });
  await coordinator.begin({ owner: ob, clientStartId: B });
  let firstClosed = false;
  let confirmClose;
  coordinator.attachLifecycle({
    owner: oa, clientStartId: A,
    revoke() {},
    close: () => new Promise((resolve) => {
      confirmClose = () => { firstClosed = true; resolve(); };
    }),
    isClosed: () => firstClosed,
  });
  const finishing = coordinator.finish({ owner: oa, clientStartId: A, reason: 'client_stop' });
  assert.deepEqual(await coordinator.begin({ owner: oc, clientStartId: C }), {
    ok: false, reason: 'pool_capacity',
  });
  confirmClose();
  assert.equal((await finishing).ok, true);
  assert.equal((await coordinator.begin({ owner: oc, clientStartId: C })).ok, true);
});

test('finish during issuance joins the issuer before making capacity reusable', async () => {
  const source = controlledIssuer();
  const coordinator = createTwoSlotCoordinator({ issuer: source.issuer });
  const oa = {};
  const ob = {};
  const oc = {};
  const pa = coordinator.begin({ owner: oa, clientStartId: A });
  const pb = coordinator.begin({ owner: ob, clientStartId: B });
  const finishing = coordinator.finish({ owner: oa, clientStartId: A, reason: 'client_stop' });
  let finishSettled = false;
  finishing.then(() => { finishSettled = true; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(finishSettled, false);
  assert.deepEqual(await coordinator.begin({ owner: oc, clientStartId: C }), {
    ok: false, reason: 'pool_capacity',
  });
  assert.equal(source.calls.length, 2, 'replacement reached no issuer work');

  source.releaseOne();
  assert.equal((await pa).ok, false);
  assert.deepEqual(await finishing, { ok: true, reason: 'client_stop' });
  const pc = coordinator.begin({ owner: oc, clientStartId: C });
  assert.equal(source.calls.length, 3, 'capacity becomes reusable only after issuance settles');
  source.releaseOne();
  source.releaseOne();
  assert.equal((await pb).ok, true);
  assert.equal((await pc).ok, true);
});

test('repeated begin refuses stale work while teardown is pending', async () => {
  const coordinator = createTwoSlotCoordinator({ issuer: { async issue() { return issued(1); } } });
  const owner = {};
  assert.equal((await coordinator.begin({ owner, clientStartId: A })).ok, true);
  let closed = false;
  let confirmClose;
  coordinator.attachLifecycle({
    owner, clientStartId: A,
    revoke() {},
    close: () => new Promise((resolve) => {
      confirmClose = () => { closed = true; resolve(); };
    }),
    isClosed: () => closed,
  });
  const finishing = coordinator.finish({ owner, clientStartId: A });
  assert.deepEqual(await coordinator.begin({ owner, clientStartId: A }), {
    ok: false, reason: 'run_intent_revoked',
  });
  confirmClose();
  assert.equal((await finishing).ok, true);
});

test('a repeated begin cannot cross the published-to-closing microtask boundary', async () => {
  const coordinator = createTwoSlotCoordinator({ issuer: { async issue() { return issued(1); } } });
  const owner = {};
  assert.equal((await coordinator.begin({ owner, clientStartId: A })).ok, true);
  let closed = false;
  let confirmClose;
  coordinator.attachLifecycle({
    owner, clientStartId: A,
    revoke() {},
    close: () => new Promise((resolve) => {
      confirmClose = () => { closed = true; resolve(); };
    }),
    isClosed: () => closed,
  });

  const repeated = coordinator.begin({ owner, clientStartId: A });
  const finishing = coordinator.finish({ owner, clientStartId: A });
  assert.deepEqual(await repeated, { ok: false, reason: 'run_intent_revoked' });
  confirmClose();
  assert.equal((await finishing).ok, true);
});

test('the coordinator independently refuses a second job on another canonical tip', async () => {
  let next = 0;
  const coordinator = createTwoSlotCoordinator({
    issuer: {
      async issue() {
        next += 1;
        if (next === 1) return issued(1);
        return Object.freeze({
          ...issued(2),
          canonical: Object.freeze({ prevHashHex: 'bb'.repeat(32) }),
        });
      },
    },
  });
  assert.equal((await coordinator.begin({ owner: {}, clientStartId: A })).ok, true);
  assert.deepEqual(await coordinator.begin({ owner: {}, clientStartId: B }), {
    ok: false, reason: TWO_SLOT_REFUSED.TIP_MISMATCH,
  });
  assert.equal(coordinator.stateFacts.successfulIssues, 1);
  assert.equal(coordinator.stateFacts.active, 1);
});

test('a real issuer tip-change code remains distinguishable from an ordinary issue failure', async () => {
  const coordinator = createTwoSlotCoordinator({
    issuer: {
      async issue() {
        throw Object.assign(new Error('tip moved'), { code: 'personalized_issue_tip_changed' });
      },
    },
  });
  assert.deepEqual(await coordinator.begin({ owner: {}, clientStartId: A }), {
    ok: false, reason: TWO_SLOT_REFUSED.TIP_MISMATCH,
  });
  assert.equal(coordinator.stateFacts.active, 0);
});

test('malformed issuer output fails closed and does not strand authority capacity', async () => {
  let calls = 0;
  const coordinator = createTwoSlotCoordinator({
    issuer: {
      async issue() {
        calls += 1;
        return calls === 1 ? { job: null, canonical: null } : issued(2);
      },
    },
  });
  assert.deepEqual(await coordinator.begin({ owner: {}, clientStartId: A }), {
    ok: false, reason: TWO_SLOT_REFUSED.ISSUE_FAILED,
  });
  assert.equal(coordinator.stateFacts.active, 0);
  assert.equal((await coordinator.begin({ owner: {}, clientStartId: B })).ok, true);
});

test('a resolved close without positive closed readback still retains the slot', async () => {
  const coordinator = createTwoSlotCoordinator({ issuer: { async issue() { return issued(1); } } });
  const owner = {};
  await coordinator.begin({ owner, clientStartId: A });
  coordinator.attachLifecycle({
    owner, clientStartId: A,
    revoke() {},
    async close() {},
    isClosed: () => false,
  });
  assert.deepEqual(await coordinator.finish({ owner, clientStartId: A }), {
    ok: false, reason: TWO_SLOT_REFUSED.TEARDOWN_FAILED,
  });
  assert.equal(coordinator.stateFacts.active, 1);
  assert.equal(coordinator.stateFacts.closeFailed, 1);
  assert.deepEqual(await coordinator.begin({ owner, clientStartId: A }), {
    ok: false, reason: 'run_intent_revoked',
  });
});

test('a teardown failure keeps the slot occupied and visible', async () => {
  const coordinator = createTwoSlotCoordinator({ issuer: { async issue() { return issued(1); } } });
  const owner = {};
  await coordinator.begin({ owner, clientStartId: A });
  coordinator.attachLifecycle({
    owner, clientStartId: A,
    revoke() {},
    async close() { throw new Error('still alive'); },
    isClosed: () => false,
  });
  assert.deepEqual(await coordinator.finish({ owner, clientStartId: A }), {
    ok: false, reason: TWO_SLOT_REFUSED.TEARDOWN_FAILED,
  });
  assert.equal(coordinator.stateFacts.active, 1);
  assert.equal(coordinator.stateFacts.closeFailed, 1);
  assert.equal(coordinator.stateFacts.teardownFailures, 1);
  assert.deepEqual(await coordinator.begin({ owner, clientStartId: A }), {
    ok: false, reason: 'run_intent_revoked',
  });
});

test('authority release failure retains the positively closed slot', async () => {
  const base = createMultiJobAuthority();
  const authority = Object.freeze({
    reserve: (args) => base.reserve(args),
    publish: (args) => base.publish(args),
    claimSubmission: (args) => base.claimSubmission(args),
    release: () => ({ ok: false, reason: 'injected_release_failure' }),
    get stateFacts() { return base.stateFacts; },
  });
  const coordinator = createTwoSlotCoordinator({
    issuer: { async issue() { return issued(1); } },
    authority,
  });
  const owner = {};
  await coordinator.begin({ owner, clientStartId: A });
  let closed = false;
  coordinator.attachLifecycle({
    owner, clientStartId: A,
    revoke() {},
    async close() { closed = true; },
    isClosed: () => closed,
  });
  assert.deepEqual(await coordinator.finish({ owner, clientStartId: A }), {
    ok: false, reason: TWO_SLOT_REFUSED.TEARDOWN_FAILED,
  });
  assert.equal(coordinator.stateFacts.active, 1);
  assert.equal(coordinator.stateFacts.authority.active, 1);
  assert.equal(coordinator.stateFacts.closeFailed, 1);
});

test('shutdown cancels queued issuance and closes every attached runtime', async () => {
  const source = controlledIssuer();
  const coordinator = createTwoSlotCoordinator({ issuer: source.issuer });
  const oa = {};
  const ob = {};
  const pa = coordinator.begin({ owner: oa, clientStartId: A });
  const pb = coordinator.begin({ owner: ob, clientStartId: B });
  const closing = coordinator.beginClose('shutdown');
  source.releaseOne();
  source.releaseOne();
  assert.equal((await pa).ok, false);
  assert.equal((await pb).ok, false);
  assert.deepEqual(await closing, [
    { ok: true, reason: TWO_SLOT_REFUSED.ISSUE_CANCELLED },
    { ok: true, reason: TWO_SLOT_REFUSED.ISSUE_CANCELLED },
  ]);
  assert.equal(coordinator.stateFacts.active, 0);
  assert.equal(coordinator.stateFacts.poolClosing, true);
});
