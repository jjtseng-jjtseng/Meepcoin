// Two consent-model defects at the job/session boundary:
//
//   * work that expired while the human was reading the page was still handed to the Worker, and
//     no replacement ever arrived, so the browser hashed a whole window and then waited forever;
//   * the demonstration is GLOBAL but `started` was per-session, so a second connection kept its
//     stale mining consent and could submit into the NEXT job without ever starting again.

import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';

import { createShareVerifier } from '../verifier.mjs';
import { loadSyntheticFixture } from '../identity.mjs';
import { createJobStore } from '../jobs.mjs';
import { createSession } from '../session.mjs';
import { REJECT_REASONS } from '../../../web-miner/lib/shared/protocol.js';
import { nonceToHex } from '../../../web-miner/lib/shared/target.js';

let verifier;
let fixture;
let losers;

before(async () => {
  verifier = await createShareVerifier();
  fixture = loadSyntheticFixture({ nonceStart: 0, nonceRange: 16 });
  losers = [...Array(fixture.nonceRange).keys()].filter((n) => n !== fixture.qualifyingNonce);
}, { timeout: 60_000 });

after(async () => { await verifier?.close(); });

const raw = (o) => { const t = JSON.stringify(o); return [Buffer.byteLength(t, 'utf8'), t]; };
const TTL = 600_000;

/** One shared job store with as many sessions as the test wants, as on the real server. */
function world({ startMs = 1_000_000, jobTtlMs = TTL } = {}) {
  const clock = { t: startMs };
  const now = () => clock.t;
  const jobs = createJobStore({ fixture, now, jobTtlMs });
  jobs.issue();
  // Model the real pool: the verifier is GLOBAL and does not exist until some session starts.
  let live = null;
  const connect = () => {
    const sent = [];
    const session = createSession({
      jobs,
      getVerifier: () => live,
      ensureVerifier: async () => { live = verifier; return live; },
      now,
      send: (o) => sent.push(o),
    });
    return { session, sent };
  };
  const submit = (c, jobId, nonce) => c.session.handleRaw(...raw({
    type: 'submit_share', jobId, workerId: c.session.workerId, nonce: nonceToHex(nonce),
  }));
  return { clock, jobs, connect, submit };
}

async function hello(c) { await c.session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 })); }
async function start(c) { await c.session.handleRaw(...raw({ type: 'start_request' })); }

// ---------------------------------------------------------------- expired work

test('work that expired before Start is replaced, and the new job precedes mining_ready', async () => {
  const w = world();
  const a = w.connect();
  await hello(a);
  const firstJob = a.sent.find((m) => m.type === 'job');
  assert.ok(firstJob);

  w.clock.t += TTL + 1; // the human reads the consent panel for over ten minutes
  a.sent.length = 0;
  const hashesBefore = verifier.hashCalls;
  await start(a);

  const order = a.sent.map((m) => m.type);
  assert.deepEqual(order, ['job', 'mining_ready'],
    'fresh work must arrive BEFORE mining_ready, so the Worker can only get current work');
  const newJob = a.sent.find((m) => m.type === 'job');
  assert.notEqual(newJob.jobId, firstJob.jobId, 'a new generation was issued');
  assert.equal(newJob.targetHexLE, fixture.targetHexLE, 'the same fixed synthetic context');
  assert.ok(newJob.expiresAtMs > w.clock.t, 'and it is actually usable');
  assert.equal(verifier.hashCalls, hashesBefore, 'issuing work costs no MeepHash-W');

  // The run then completes normally, and the expired job never reached the verifier.
  const r = await w.submit(a, newJob.jobId, fixture.qualifyingNonce);
  assert.equal(r.type, 'share_accepted');
  assert.equal(verifier.hashCalls, hashesBefore + 1, 'exactly one recomputation, on the new job');
});

test('a page that connects after the standing job expired still gets usable work', async () => {
  const w = world();
  w.clock.t += TTL + 1; // the pool has been up longer than a job lifetime
  const a = w.connect();
  await hello(a);

  const job = a.sent.find((m) => m.type === 'job');
  assert.ok(job, 'a late-connecting page must still be given a job, or its Start never enables');
  assert.ok(job.expiresAtMs > w.clock.t, 'and it must not be dead on arrival');
  assert.equal(a.sent.filter((m) => m.type === 'job').length, 1, 'exactly one job message');

  a.sent.length = 0;
  await start(a);
  assert.deepEqual(a.sent.map((m) => m.type), ['mining_ready'], 'work was already current: nothing re-sent');
  const r = await w.submit(a, job.jobId, fixture.qualifyingNonce);
  assert.equal(r.type, 'share_accepted');
});

test('an unexpired job is not replaced and is not re-sent on Start', async () => {
  const w = world();
  const a = w.connect();
  await hello(a);
  const job = a.sent.find((m) => m.type === 'job');
  a.sent.length = 0;
  await start(a);
  assert.deepEqual(a.sent.map((m) => m.type), ['mining_ready'],
    'a client already holding current work must not get a duplicate job message');
  assert.equal(w.jobs.active().jobId, job.jobId);
});

test('jobs.active() treats an expired job as no active work', () => {
  const clock = { t: 1_000_000 };
  const jobs = createJobStore({ fixture, now: () => clock.t, jobTtlMs: 5_000 });
  const job = jobs.issue();
  assert.equal(jobs.active(), job);
  assert.equal(jobs.hasActiveWork(), true);
  clock.t += 5_001;
  assert.equal(jobs.active(), null, 'expired work is not active work');
  assert.equal(jobs.hasActiveWork(), false);
  // The accurate reason is still available for a submission against it.
  assert.equal(jobs.staleReasonFor(job.jobId), 'expired_job');
});

// ---------------------------------------------------------------- global terminal state

test('a completed demonstration is terminal for EVERY started session', async () => {
  const w = world();
  const a = w.connect();
  const b = w.connect();
  for (const c of [a, b]) { await hello(c); await start(c); }
  const jobId = w.jobs.active().jobId;
  a.sent.length = 0;
  b.sent.length = 0;

  await w.submit(a, jobId, fixture.qualifyingNonce);

  // The winner: share_accepted first, then its own terminal notice.
  assert.deepEqual(a.sent.map((m) => m.type), ['share_accepted', 'demo_complete'],
    'the winner is told it won AFTER being told the share was accepted');
  assert.equal(a.sent.at(-1).won, true);

  // The loser: told exactly once, and told it did not win.
  const bDone = b.sent.filter((m) => m.type === 'demo_complete');
  assert.equal(bDone.length, 1, 'the other started session is told exactly once');
  assert.equal(bDone[0].won, false);
  assert.match(bDone[0].notice, /another connection on this machine/i);
  assert.equal(b.sent.find((m) => m.type === 'share_accepted'), undefined, 'and is not credited');

  assert.equal(a.session.started, false);
  assert.equal(b.session.started, false, 'both run intents are cleared');
});

test('a losing session cannot carry stale consent into the next demonstration', async () => {
  const w = world();
  const a = w.connect();
  const b = w.connect();
  for (const c of [a, b]) { await hello(c); await start(c); }
  await w.submit(a, w.jobs.active().jobId, fixture.qualifyingNonce);
  a.sent.length = 0;
  b.sent.length = 0;

  // A starts a NEW demonstration. The new job is disclosed to B as well -- that is fine.
  await start(a);
  const job2 = b.sent.find((m) => m.type === 'job');
  assert.ok(job2, 'B may be shown the new job');
  assert.notEqual(job2.jobId, w.jobs.lastConsumedJob().jobId);

  // But B may not mine it without starting again. This was the defect: B was accepted.
  const before = verifier.hashCalls;
  const rb = await w.submit(b, job2.jobId, fixture.qualifyingNonce);
  assert.equal(rb.reason, REJECT_REASONS.NOT_STARTED, 'stale consent must not reach new work');
  assert.equal(verifier.hashCalls, before, 'and costs no hashing');

  // After B starts again it may mine normally.
  await start(b);
  assert.equal(b.session.started, true);
  const rb2 = await w.submit(b, w.jobs.active().jobId, fixture.qualifyingNonce);
  assert.equal(rb2.type, 'share_accepted');
});

test('a connected observer that never started is not told it completed anything', async () => {
  const w = world();
  const a = w.connect();
  const observer = w.connect();
  await hello(a);
  await start(a);
  await hello(observer); // connected, disclosed a job, but never started
  observer.sent.length = 0;

  await w.submit(a, w.jobs.active().jobId, fixture.qualifyingNonce);
  assert.equal(observer.sent.filter((m) => m.type === 'demo_complete').length, 0,
    'a session that never ran must not be told its run ended');
  assert.equal(observer.session.started, false);
});

test('a disposed session receives no terminal notice and retains no listener', async () => {
  const w = world();
  const a = w.connect();
  const b = w.connect();
  for (const c of [a, b]) { await hello(c); await start(c); }
  b.session.dispose();
  b.sent.length = 0;

  await w.submit(a, w.jobs.active().jobId, fixture.qualifyingNonce);
  assert.equal(b.sent.length, 0, 'nothing is written to a disposed session');

  // Its job subscription is gone too: a later issue must not reach it.
  await start(a);
  assert.equal(b.sent.length, 0);
});

test('the terminal notice is sent at most once even under a concurrent race', async () => {
  const w = world();
  const a = w.connect();
  const b = w.connect();
  for (const c of [a, b]) { await hello(c); await start(c); }
  const jobId = w.jobs.active().jobId;
  a.sent.length = 0;
  b.sent.length = 0;

  // Both submit the winner in the same turn; exactly one consumes it.
  const [ra, rb] = await Promise.all([
    w.submit(a, jobId, fixture.qualifyingNonce),
    w.submit(b, jobId, fixture.qualifyingNonce),
  ]);
  assert.equal([ra, rb].filter((r) => r.type === 'share_accepted').length, 1);
  assert.equal(a.sent.filter((m) => m.type === 'demo_complete').length, 1);
  assert.equal(b.sent.filter((m) => m.type === 'demo_complete').length, 1);
  const all = [...a.sent, ...b.sent].filter((m) => m.type === 'demo_complete');
  assert.equal(all.filter((m) => m.won === true).length, 1, 'exactly one winner');
});

// ---------------------------------------------------------------- passive status

test('server_hello discloses the pool verifier state without initializing it', async () => {
  const w = world();
  const a = w.connect();
  await hello(a);
  const cold = a.sent.find((m) => m.type === 'server_hello');
  assert.equal(cold.verifierState, 'uninitialized');
  assert.equal(cold.verifierWasmHeapBytes, null, 'nothing is allocated, so nothing is claimed');

  await start(a); // now a verifier exists
  const b = w.connect();
  await hello(b);
  const warm = b.sent.find((m) => m.type === 'server_hello');
  assert.equal(warm.verifierState, 'ready');
  assert.ok(warm.verifierWasmHeapBytes > 40 * 1024 * 1024,
    'a page loading later sees the memory the pool is really holding, not a dash');
  assert.equal(b.session.started, false, 'and learning it is not start intent');
});


// ---------------------------------------------------------------- the exact TTL boundary

/**
 * A clock whose FIRST read after arming returns exactly expiresAtMs and every read after that
 * returns expiresAtMs + 1.
 *
 * This is the shape of the real bug: production sampled the clock twice inside one logical
 * decision, so a job expiring between the two reads passed the first check and came back null
 * from the second. Because it counts reads, this test also fails if production goes back to
 * sampling twice -- the second sample is what makes the job vanish mid-decision.
 */
function boundaryClock(base, ttl) {
  let armed = false;
  let reads = 0;
  return {
    arm() { armed = true; reads = 0; },
    now() {
      if (!armed) return base;
      reads += 1;
      return reads === 1 ? base + ttl : base + ttl + 1;
    },
    get reads() { return reads; },
  };
}

test('client_hello at the exact expiry millisecond does not throw and discloses usable work', async () => {
  const base = 1_000_000;
  const ck = boundaryClock(base, TTL);
  const jobs = createJobStore({ fixture, now: () => ck.now(), jobTtlMs: TTL });
  jobs.issue();
  const sent = [];
  const session = createSession({
    jobs, getVerifier: () => null, ensureVerifier: async () => null,
    now: () => ck.now(), send: (o) => sent.push(o),
  });

  ck.arm();
  await assert.doesNotReject(
    () => session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 })),
    'the boundary must not throw; it used to dereference a null job',
  );

  const job = sent.find((m) => m.type === 'job');
  assert.ok(job, 'the client must still be given work at the boundary');
  assert.ok(job.expiresAtMs >= base + TTL, 'and that work must be usable, not already dead');
  assert.equal(ck.reads, 1, 'ONE clock read for one decision; a second read is what caused the bug');
});

test('submit_share at the exact expiry millisecond fails closed, not with an exception', async () => {
  const base = 1_000_000;
  const ck = boundaryClock(base, TTL);
  const jobs = createJobStore({ fixture, now: () => ck.now(), jobTtlMs: TTL });
  jobs.issue();
  const sent = [];
  // A verifier that would throw loudly if the pipeline ever reached it.
  const guard = {
    hashCalls: 0,
    wasmHeapBytes: () => 48_562_176,
    async verify() { throw new Error('the expired path must never reach the verifier'); },
  };
  const session = createSession({
    jobs, getVerifier: () => guard, ensureVerifier: async () => guard,
    now: () => ck.now(), send: (o) => sent.push(o),
  });
  await session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 }));
  await session.handleRaw(...raw({ type: 'start_request' }));
  const jobId = jobs.active().jobId;
  sent.length = 0;

  ck.arm();
  let result;
  await assert.doesNotReject(async () => {
    result = await session.handleRaw(...raw({
      type: 'submit_share', jobId, workerId: session.workerId, nonce: nonceToHex(fixture.qualifyingNonce),
    }));
  }, 'the boundary must not throw; it used to dereference a null job and close the connection');

  assert.equal(result.ok, false);
  assert.ok(
    [REJECT_REASONS.EXPIRED_JOB, REJECT_REASONS.STALE_JOB].includes(result.reason),
    `expected an expiry/stale protocol rejection, got ${result.reason}`,
  );
  assert.equal(sent.at(-1).type, 'share_rejected', 'the client gets a protocol rejection');
  assert.equal(guard.hashCalls, 0, 'and it costs zero hashing');
  // NOTE on clock reads: this path legitimately reads the clock more than once, because the rate
  // bucket and the DELIBERATE post-queue recheck are later decisions that are supposed to take
  // fresh samples. What must not happen is a single decision splitting across two reads -- which
  // is exactly what the doesNotReject above proves, since the old code returned a job from read 1
  // and null from read 2 and then dereferenced it. jobs.resolveForSubmission() is unit-tested
  // separately to show the step-4 decision is one query against one sample.
  assert.ok(ck.reads >= 1);
});

test('a job issued at the boundary has a coherent timestamp pair', () => {
  const base = 1_000_000;
  const ck = boundaryClock(base, TTL);
  const jobs = createJobStore({ fixture, now: () => ck.now(), jobTtlMs: TTL });
  ck.arm();
  const job = jobs.issue();
  assert.equal(job.expiresAtMs - job.issuedAtMs, TTL,
    'issuedAt and expiresAt must come from ONE timestamp, not two clock reads');
  assert.equal(ck.reads, 1);
});

test('resolveForSubmission answers with a job or a reason, never both and never neither', () => {
  const clock = { t: 1_000_000 };
  const jobs = createJobStore({ fixture, now: () => clock.t, jobTtlMs: 5_000 });
  assert.deepEqual(jobs.resolveForSubmission('devjob-1'), { reason: 'unknown_job' });

  const job = jobs.issue();
  assert.deepEqual(jobs.resolveForSubmission(job.jobId), { job });
  assert.deepEqual(jobs.resolveForSubmission('devjob-999'), { reason: 'stale_job' });

  // Exactly AT expiry is still usable; one millisecond later it is not.
  assert.deepEqual(jobs.resolveForSubmission(job.jobId, job.expiresAtMs), { job });
  assert.deepEqual(jobs.resolveForSubmission(job.jobId, job.expiresAtMs + 1), { reason: 'expired_job' });

  jobs.consumeIfActive(job);
  assert.deepEqual(jobs.resolveForSubmission(job.jobId), { reason: 'stale_job' });
});

test('a job crossing expiry between hash and commit is reported as expired, not as a lost race', async () => {
  // The final classification and the atomic consume must share ONE commit-time sample. Sampling
  // twice was safe but dishonest: the share was rejected as `stale_job` / "another share completed
  // this job first" when nothing had completed it and the truth was that it expired.
  const base = 1_000_000;
  const TTL_SHORT = 5_000;
  // Ordinary time until the hash returns, then exactly the expiry instant, then one past it. If
  // production samples twice at commit, the second sample turns a clean expiry into a false
  // "another share won" claim.
  let phase = 'pre';
  const clock = { now() { return phase === 'pre' ? base : base + TTL_SHORT + 1; } };

  const jobs = createJobStore({ fixture, now: () => clock.now(), jobTtlMs: TTL_SHORT });
  jobs.issue();
  const sent = [];
  const verifierProxy = {
    get hashCalls() { return verifier.hashCalls; },
    wasmHeapBytes: () => verifier.wasmHeapBytes(),
    // The job expires exactly while the hash is being computed.
    async verify(nonce, target) { const r = await verifier.verify(nonce, target); phase = 'post'; return r; },
  };
  const session = createSession({
    jobs, getVerifier: () => verifierProxy, ensureVerifier: async () => verifierProxy,
    now: () => clock.now(), send: (o) => sent.push(o),
  });
  await session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 }));
  await session.handleRaw(...raw({ type: 'start_request' }));
  const jobId = jobs.active().jobId;
  sent.length = 0;

  const r = await session.handleRaw(...raw({
    type: 'submit_share', jobId, workerId: session.workerId, nonce: nonceToHex(fixture.qualifyingNonce),
  }));

  assert.equal(r.ok, false, 'an expired job cannot be accepted');
  assert.equal(r.reason, REJECT_REASONS.EXPIRED_JOB,
    'it must be reported as expired, NOT as stale_job / another share winning');
  assert.notEqual(r.detail, 'another share completed this job first');
  assert.equal(sent.at(-1).reason, REJECT_REASONS.EXPIRED_JOB);
  assert.equal(jobs.lastConsumedJob(), null, 'and nothing was consumed, so no winner is claimed');
});
