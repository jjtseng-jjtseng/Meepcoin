// Stale-job safety across ASYNCHRONOUS verification.
//
// Verification is already async and the native helper will make it genuinely so. The pipeline
// therefore captures the job OBJECT it validated against and rechecks that exact object after
// every await:
//
//   * stale while WAITING FOR THE QUEUE  -> zero verifier calls, rejected
//   * stale while the hash is ALREADY RUNNING -> that one call is spent (unavoidable and reported
//     honestly), but the share can never be accepted
//   * two completions for the same generation -> at most ONE acceptance and ONE consumption,
//     because the commit is a synchronous compare-and-consume
//
// Before this fix, two sessions verifying the same winning job both succeeded, both hashed, and
// the generation advanced twice.

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

/** A world where several connections share ONE job store, as they do on the real server. */
function world({ scheduleVerification, limits = {} } = {}) {
  const clock = { t: 1_000_000 };
  const now = () => clock.t;
  const jobs = createJobStore({ fixture, now, jobTtlMs: 600_000 });
  jobs.issue();
  const sessions = [];

  async function connect() {
    const sent = [];
    const session = createSession({
      jobs,
      getVerifier: () => verifier,
      ensureVerifier: async () => verifier,
      now,
      limits,
      ...(scheduleVerification ? { scheduleVerification } : {}),
      send: (o) => sent.push(o),
    });
    await session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 }));
    await session.handleRaw(...raw({ type: 'start_request' }));
    const ctx = { session, sent, workerId: session.workerId };
    sessions.push(ctx);
    return ctx;
  }

  const submit = (ctx, jobId, nonce) => ctx.session.handleRaw(...raw({
    type: 'submit_share', jobId, workerId: ctx.workerId, nonce: nonceToHex(nonce),
  }));

  return { clock, jobs, connect, submit, sessions };
}

/** A verification gate the test opens by hand, so completion order is under test control. */
function gate() {
  let release;
  const promise = new Promise((r) => { release = r; });
  return { wait: () => promise, release: () => release() };
}

// ---------------------------------------------------------------- same session

test('a submission that goes stale while STILL QUEUED costs ZERO verifier calls', async () => {
  // Independent gates, so the second submission is provably still waiting for admission when the
  // first one completes the demonstration. (With one shared gate both would already be past the
  // pre-hash recheck, which is the different -- and separately tested -- in-flight case.)
  const gates = [gate(), gate()];
  let issued = 0;
  const w = world({
    scheduleVerification: () => gates[issued++].wait(),
    limits: { maxVerificationQueue: 8 },
  });
  const a = await w.connect();
  const jobId = w.jobs.active().jobId;
  const before = verifier.hashCalls;

  const winner = w.submit(a, jobId, fixture.qualifyingNonce);
  const loser = w.submit(a, jobId, losers[0]);
  assert.equal(verifier.hashCalls, before, 'nothing has hashed yet');

  gates[0].release();
  const rw = await winner;
  assert.equal(rw.type, 'share_accepted');
  assert.equal(w.jobs.active(), null, 'the job is consumed');
  assert.equal(verifier.hashCalls, before + 1, 'only the winner has hashed so far');

  // Now let the second one out of the queue. Its pre-hash recheck must refuse it for free.
  gates[1].release();
  const rl = await loser;
  assert.equal(rl.reason, REJECT_REASONS.STALE_JOB);
  assert.equal(verifier.hashCalls, before + 1,
    'the queued-but-stale submission was refused BEFORE hashing: still exactly one hash');
});

test('a burst of submissions on one session yields at most one acceptance', async () => {
  const g = gate();
  const w = world({ scheduleVerification: () => g.wait(), limits: { maxVerificationQueue: 32, rateCapacity: 32 } });
  const a = await w.connect();
  const jobId = w.jobs.active().jobId;
  const gen0 = w.jobs.generation;

  const all = [];
  for (let n = 0; n < fixture.nonceRange; n++) all.push(w.submit(a, jobId, n));
  g.release();
  const results = await Promise.all(all);

  const accepted = results.filter((r) => r.type === 'share_accepted');
  assert.equal(accepted.length, 1, 'exactly one acceptance');
  assert.equal(w.jobs.generation, gen0 + 1, 'and exactly one generation advance');
  assert.equal(a.sent.filter((m) => m.type === 'demo_complete').length, 1);
});

// ---------------------------------------------------------------- two sessions

test('two sessions verifying the same winning job yield at most ONE acceptance', async () => {
  // This is the exact defect: previously both were accepted, both hashed, generation 1 -> 3.
  const g = gate();
  const w = world({ scheduleVerification: () => g.wait() });
  const a = await w.connect();
  const b = await w.connect();
  const jobId = w.jobs.active().jobId;
  const gen0 = w.jobs.generation;
  const before = verifier.hashCalls;

  const pa = w.submit(a, jobId, fixture.qualifyingNonce);
  const pb = w.submit(b, jobId, fixture.qualifyingNonce);
  g.release();
  const [ra, rb] = await Promise.all([pa, pb]);

  const accepted = [ra, rb].filter((r) => r.type === 'share_accepted');
  const rejected = [ra, rb].filter((r) => r.ok === false);
  assert.equal(accepted.length, 1, 'at most one completion may accept');
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason, REJECT_REASONS.STALE_JOB);
  assert.equal(w.jobs.generation, gen0 + 1, 'the generation advanced exactly once');

  // Both hashes were already in flight when the first one won, so both were spent. That is the
  // honest cost of a genuinely concurrent verifier, and it is reported rather than hidden.
  assert.equal(verifier.hashCalls, before + 2,
    'both already-started hashes are consumed; only one of them can be accepted');

  // The demonstration is GLOBAL, so both started sessions are told it ended -- but exactly one of
  // them won it, and each is told exactly once.
  const completes = [...a.sent, ...b.sent].filter((m) => m.type === 'demo_complete');
  assert.equal(completes.length, 2, 'every started session gets a terminal notice');
  assert.equal(completes.filter((m) => m.won === true).length, 1, 'exactly one winner');
  assert.equal(completes.filter((m) => m.won === false).length, 1, 'exactly one loser told it ended');
  assert.equal(a.sent.filter((m) => m.type === 'demo_complete').length, 1, 'A told exactly once');
  assert.equal(b.sent.filter((m) => m.type === 'demo_complete').length, 1, 'B told exactly once');
});

test('three sessions racing the same job still yield exactly one acceptance', async () => {
  const g = gate();
  const w = world({ scheduleVerification: () => g.wait() });
  const conns = [await w.connect(), await w.connect(), await w.connect()];
  const jobId = w.jobs.active().jobId;
  const gen0 = w.jobs.generation;

  const results = await (async () => {
    const ps = conns.map((c) => w.submit(c, jobId, fixture.qualifyingNonce));
    g.release();
    return Promise.all(ps);
  })();

  assert.equal(results.filter((r) => r.type === 'share_accepted').length, 1);
  assert.equal(w.jobs.generation, gen0 + 1);
});

test('a job that expires while queued is refused before hashing', async () => {
  const g = gate();
  const w = world({ scheduleVerification: () => g.wait() });
  const a = await w.connect();
  const jobId = w.jobs.active().jobId;
  const before = verifier.hashCalls;

  const p = w.submit(a, jobId, fixture.qualifyingNonce);
  w.clock.t += 600_001; // the job expires while the submission waits
  g.release();
  const r = await p;

  assert.equal(r.reason, REJECT_REASONS.EXPIRED_JOB);
  assert.equal(verifier.hashCalls, before, 'an expired job costs no hashing even from the queue');
});

test('a job consumed by another session mid-verification cannot be accepted', async () => {
  // A verifies fast; B is held at the gate until after A has completed the demonstration.
  const bGate = gate();
  const clockRef = { t: 1_000_000 };
  const jobs = createJobStore({ fixture, now: () => clockRef.t, jobTtlMs: 600_000 });
  jobs.issue();

  const mk = (schedule) => {
    const sent = [];
    const session = createSession({
      jobs,
      getVerifier: () => verifier,
      ensureVerifier: async () => verifier,
      now: () => clockRef.t,
      ...(schedule ? { scheduleVerification: schedule } : {}),
      send: (o) => sent.push(o),
    });
    return { session, sent };
  };
  const a = mk();
  const b = mk(() => bGate.wait());
  for (const c of [a, b]) {
    await c.session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 }));
    await c.session.handleRaw(...raw({ type: 'start_request' }));
  }
  const jobId = jobs.active().jobId;

  const pb = b.session.handleRaw(...raw({
    type: 'submit_share', jobId, workerId: b.session.workerId, nonce: nonceToHex(fixture.qualifyingNonce),
  }));
  const ra = await a.session.handleRaw(...raw({
    type: 'submit_share', jobId, workerId: a.session.workerId, nonce: nonceToHex(fixture.qualifyingNonce),
  }));
  assert.equal(ra.type, 'share_accepted', 'A wins');
  assert.equal(jobs.active(), null);

  bGate.release();
  const rb = await pb;
  assert.equal(rb.reason, REJECT_REASONS.STALE_JOB, 'B cannot also be accepted');
  assert.equal(b.sent.find((m) => m.type === 'share_accepted'), undefined);
  // B was started, so it IS told the shared demonstration ended -- as a loser, exactly once.
  const bDone = b.sent.filter((m) => m.type === 'demo_complete');
  assert.equal(bDone.length, 1);
  assert.equal(bDone[0].won, false);
  assert.equal(b.session.started, false, 'and B may not mine on without starting again');
});

// ---------------------------------------------------------------- the primitive itself

test('consumeIfActive claims a job exactly once', () => {
  const jobs = createJobStore({ fixture, now: () => 1_000_000, jobTtlMs: 600_000 });
  const job = jobs.issue();
  const gen0 = jobs.generation;

  assert.equal(jobs.isActive(job), true);
  assert.equal(jobs.consumeIfActive(job), true, 'the first caller wins');
  for (let i = 0; i < 5; i++) assert.equal(jobs.consumeIfActive(job), false, 'and only the first');
  assert.equal(jobs.generation, gen0 + 1, 'the generation advanced exactly once');
  assert.equal(jobs.isActive(job), false);
  assert.equal(jobs.active(), null);
  assert.equal(jobs.lastConsumedJob(), job);
});

test('consumeIfActive refuses an expired or superseded job', () => {
  const clock = { t: 1_000_000 };
  const jobs = createJobStore({ fixture, now: () => clock.t, jobTtlMs: 5_000 });
  const first = jobs.issue();
  clock.t += 5_001;
  assert.equal(jobs.consumeIfActive(first), false, 'expired');

  clock.t = 2_000_000;
  const second = jobs.issue();
  jobs.issue(); // superseded
  assert.equal(jobs.consumeIfActive(second), false, 'no longer the active object');
});

test('isActive compares the job OBJECT, so a forged look-alike cannot pass', () => {
  const jobs = createJobStore({ fixture, now: () => 1_000_000, jobTtlMs: 600_000 });
  const job = jobs.issue();
  const lookAlike = { ...job }; // same jobId, same generation, same everything
  assert.equal(jobs.isActive(job), true);
  assert.equal(jobs.isActive(lookAlike), false, 'a copy is not the active job');
  assert.equal(jobs.consumeIfActive(lookAlike), false);
  assert.equal(jobs.isActive(job), true, 'and the real job is untouched');
});
