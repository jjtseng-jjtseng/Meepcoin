// The share-submission pipeline, driven directly against the REAL MeepHash-W v2 Wasm verifier.
//
// The recurring assertion in this file is `verifier.hashCalls`. Every cheap refusal must leave it
// untouched, which is what "rejected before expensive hashing" actually means; and an accepted
// share must advance it by exactly one, which is what "the server recomputed it itself" actually
// means. A green test that only checked the reason string would prove neither.

import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';

import { createShareVerifier } from '../verifier.mjs';
import { loadSyntheticFixture } from '../identity.mjs';
import { createJobStore } from '../jobs.mjs';
import { createSession } from '../session.mjs';
import { REJECT_REASONS, MAX_MESSAGE_BYTES } from '../../../web-miner/lib/shared/protocol.js';
import { nonceToHex, bytesToHex } from '../../../web-miner/lib/shared/target.js';

let verifier;
let fixture;
// Nonces guaranteed NOT to qualify. Tests that must not complete the demonstration draw from
// here, so they do not depend on where the winner landed.
let losers;

before(async () => {
  verifier = await createShareVerifier();
  fixture = loadSyntheticFixture({ nonceStart: 0, nonceRange: 16 });
  losers = [...Array(fixture.nonceRange).keys()].filter((n) => n !== fixture.qualifyingNonce);
}, { timeout: 60_000 });

after(async () => { await verifier?.close(); });

/** A fresh connection against a fresh job, sharing the one expensive verifier. */
function makeSession({ limits = {}, jobTtlMs = 600_000, startMs = 1_000_000, scheduleVerification } = {}) {
  const clock = { t: startMs };
  const now = () => clock.t;
  const sent = [];
  const audit = [];
  const jobs = createJobStore({ fixture, now, jobTtlMs });
  jobs.issue();
  const session = createSession({
    jobs,
    getVerifier: () => verifier,
    ensureVerifier: async () => verifier,
    now,
    limits,
    ...(scheduleVerification ? { scheduleVerification } : {}),
    send: (o) => sent.push(o),
    onAudit: (e) => audit.push(e),
  });
  return { clock, sent, audit, jobs, session };
}

function raw(obj) {
  const text = JSON.stringify(obj);
  return [Buffer.byteLength(text, 'utf8'), text];
}

/** A ready connection: greeted, started (so a verifier exists), holding the active job. */
async function connected(opts) {
  const ctx = makeSession(opts);
  await ctx.session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 }));
  await ctx.session.handleRaw(...raw({ type: 'start_request' }));
  ctx.workerId = ctx.session.workerId;
  ctx.jobId = ctx.jobs.active().jobId;
  ctx.sent.length = 0;
  ctx.audit.length = 0;
  return ctx;
}

function share(ctx, nonce, extra = {}) {
  return raw({
    type: 'submit_share',
    jobId: ctx.jobId,
    workerId: ctx.workerId,
    nonce: typeof nonce === 'string' ? nonce : nonceToHex(nonce),
    ...extra,
  });
}

/** Run `fn` and report how many real MeepHash-W computations it cost. */
async function hashCost(fn) {
  const before_ = verifier.hashCalls;
  const value = await fn();
  return { value, cost: verifier.hashCalls - before_ };
}

const lastSent = (ctx) => ctx.sent.at(-1);
// An accepted share is followed by a demo_complete notice, so a verdict assertion must look for
// the verdict rather than for whatever was sent most recently.
const lastVerdict = (ctx) => ctx.sent.filter((m) => m.type === 'share_accepted' || m.type === 'share_rejected').at(-1);

// ---------------------------------------------------------------- the fixture itself

test('the synthetic fixture has one qualifying and one non-qualifying nonce', () => {
  assert.notEqual(fixture.qualifyingNonce, fixture.nonQualifyingNonce);
  assert.equal(fixture.targetHexLE.length, 64);
  assert.equal(fixture.targetHexLE, fixture.qualifyingHashHexLE,
    'the target IS the lowest hash in the window, so that nonce passes by equality');
  assert.equal(bytesToHex(verifier.hashOne(fixture.qualifyingNonce)), fixture.qualifyingHashHexLE,
    'recomputing the qualifying nonce reproduces the committed vector');
});

// ---------------------------------------------------------------- (1)(2) size and schema

test('an oversized message is refused before any hashing', async () => {
  const ctx = await connected();
  const padded = { type: 'submit_share', jobId: ctx.jobId, workerId: ctx.workerId, nonce: '00000000', clientVersion: 'x' };
  const text = JSON.stringify(padded);
  const { cost } = await hashCost(() => ctx.session.handleRaw(MAX_MESSAGE_BYTES + 1, text));
  assert.equal(cost, 0, 'the size cap must be applied before JSON is even parsed');
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.MESSAGE_TOO_LARGE);
  assert.equal(ctx.audit.at(-1).hashCalls, verifier.hashCalls);
});

test('a message exactly at the cap is not refused for size', async () => {
  const ctx = await connected();
  const [, text] = share(ctx, fixture.nonQualifyingNonce);
  const { cost } = await hashCost(() => ctx.session.handleRaw(MAX_MESSAGE_BYTES, text));
  assert.equal(cost, 1, 'a legal-size message reaches verification');
});

test('malformed messages are refused before any hashing', async () => {
  const cases = [
    ['not JSON at all', 'this is not json', REJECT_REASONS.BAD_JSON],
    ['a JSON array', '[1,2,3]', REJECT_REASONS.BAD_JSON],
    ['a JSON string', '"hello"', REJECT_REASONS.BAD_JSON],
    ['truncated JSON', '{"type":"submit_sh', REJECT_REASONS.BAD_JSON],
    ['no type field', '{"jobId":"devjob-1"}', REJECT_REASONS.BAD_SCHEMA],
    ['a numeric type', '{"type":42}', REJECT_REASONS.BAD_SCHEMA],
    ['an unknown type', '{"type":"mine_everything"}', REJECT_REASONS.UNKNOWN_TYPE],
    ['a server-only type', '{"type":"share_accepted"}', REJECT_REASONS.UNKNOWN_TYPE],
    ['a server-only readiness type', '{"type":"mining_ready"}', REJECT_REASONS.UNKNOWN_TYPE],
  ];
  for (const [label, text, expected] of cases) {
    const ctx = await connected();
    const { cost } = await hashCost(() => ctx.session.handleRaw(Buffer.byteLength(text), text));
    assert.equal(cost, 0, `${label} must cost no hashing`);
    assert.equal(lastSent(ctx).reason, expected, label);
  }
});

test('a schema-violating submit_share is refused before any hashing', async () => {
  const overrides = [
    ['missing jobId', { jobId: undefined }],
    ['numeric jobId', { jobId: 7 }],
    ['null jobId', { jobId: null }],
    ['empty jobId', { jobId: '' }],
    ['oversized jobId', { jobId: 'j'.repeat(65) }],
    ['missing workerId', { workerId: undefined }],
    ['oversized workerId', { workerId: 'w'.repeat(65) }],
    ['missing nonce', { nonce: undefined }],
    ['numeric nonce', { nonce: 15 }],
    ['short nonce', { nonce: 'f' }],
    ['long nonce', { nonce: '00000000f' }],
    ['uppercase nonce', { nonce: '0000000F' }],
    ['non-hex nonce', { nonce: 'zzzzzzzz' }],
    ['0x-prefixed nonce', { nonce: '0x00000f' }],
    ['an unexpected extra field', { difficulty: 1 }],
    ['a nested payload', { extra: { a: 1 } }],
    ['oversized clientVersion', { clientVersion: 'v'.repeat(33) }],
    ['numeric clientVersion', { clientVersion: 3 }],
  ];
  for (const [label, override] of overrides) {
    const ctx = await connected();
    const message = {
      type: 'submit_share',
      jobId: ctx.jobId,
      workerId: ctx.workerId,
      nonce: nonceToHex(fixture.qualifyingNonce),
      ...override,
    };
    const text = JSON.stringify(message);
    assert.notEqual(text, JSON.stringify({
      type: 'submit_share', jobId: ctx.jobId, workerId: ctx.workerId, nonce: nonceToHex(fixture.qualifyingNonce),
    }), `${label}: the override must actually change the message`);

    const { cost } = await hashCost(() => ctx.session.handleRaw(Buffer.byteLength(text), text));
    assert.equal(cost, 0, `${label} must cost no hashing`);
    assert.equal(lastSent(ctx).reason, REJECT_REASONS.BAD_SCHEMA, label);
  }
});

// ---------------------------------------------------------------- (2b) protocol version

test('an unsupported protocol version is refused, unauthorized, and costs no hashing', async () => {
  for (const version of [0, 2, 999, 1_000_000]) {
    const ctx = makeSession();
    const { cost } = await hashCost(() => ctx.session.handleRaw(...raw({ type: 'client_hello', protocolVersion: version })));
    assert.equal(cost, 0, `version ${version} must cost no hashing`);
    assert.equal(lastSent(ctx).reason, REJECT_REASONS.UNSUPPORTED_VERSION, `version ${version}`);
    assert.equal(ctx.session.authorized, false, `version ${version} must NOT be authorized`);
    assert.equal(ctx.session.workerId, null, `version ${version} must get no workerId`);
    assert.equal(ctx.sent.find((m) => m.type === 'server_hello'), undefined);
    assert.equal(ctx.sent.find((m) => m.type === 'job'), undefined, `version ${version} must get no job`);
  }
});

test('an unsupported version cannot then start mining or submit', async () => {
  const ctx = makeSession();
  await ctx.session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 999 }));
  const start = await hashCost(() => ctx.session.handleRaw(...raw({ type: 'start_request' })));
  assert.equal(start.cost, 0);
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.NOT_AUTHORIZED);

  const text = JSON.stringify({
    type: 'submit_share', jobId: ctx.jobs.active().jobId, workerId: 'w-forged', nonce: nonceToHex(fixture.qualifyingNonce),
  });
  const sub = await hashCost(() => ctx.session.handleRaw(Buffer.byteLength(text), text));
  assert.equal(sub.cost, 0);
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.NOT_AUTHORIZED);
});

test('the supported version is accepted and gets a job', async () => {
  const ctx = makeSession();
  await ctx.session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 }));
  assert.equal(ctx.session.authorized, true);
  assert.ok(ctx.sent.find((m) => m.type === 'job'));
});

// ---------------------------------------------------------------- (3) identity and consent

test('a share before client_hello is refused before any hashing', async () => {
  const ctx = makeSession();
  const text = JSON.stringify({
    type: 'submit_share', jobId: ctx.jobs.active().jobId, workerId: 'w-forged', nonce: nonceToHex(fixture.qualifyingNonce),
  });
  const { cost } = await hashCost(() => ctx.session.handleRaw(Buffer.byteLength(text), text));
  assert.equal(cost, 0);
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.NOT_AUTHORIZED);
});

test('a share before start_request is refused before any hashing', async () => {
  // The consent boundary, enforced server-side too: no Start, no verification.
  const ctx = makeSession();
  await ctx.session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 }));
  const workerId = ctx.session.workerId;
  const jobId = ctx.jobs.active().jobId;
  const text = JSON.stringify({ type: 'submit_share', jobId, workerId, nonce: nonceToHex(fixture.qualifyingNonce) });
  const { cost } = await hashCost(() => ctx.session.handleRaw(Buffer.byteLength(text), text));
  assert.equal(cost, 0, 'nothing may be verified before a client declares start intent');
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.NOT_STARTED);
});

test('start_request before client_hello is refused', async () => {
  const ctx = makeSession();
  await ctx.session.handleRaw(...raw({ type: 'start_request' }));
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.NOT_AUTHORIZED);
  assert.equal(ctx.session.started, false);
});

test('start_request answers mining_ready and reports the pool allocation', async () => {
  const ctx = makeSession();
  let inits = 0;
  const sent = [];
  const session = createSession({
    jobs: ctx.jobs,
    getVerifier: () => (inits > 0 ? verifier : null),
    ensureVerifier: async () => { inits++; return verifier; },
    now: () => ctx.clock.t,
    send: (o) => sent.push(o),
  });
  await session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 }));
  await Promise.all([
    session.handleRaw(...raw({ type: 'start_request' })),
    session.handleRaw(...raw({ type: 'start_request' })),
    session.handleRaw(...raw({ type: 'start_request' })),
  ]);
  await session.handleRaw(...raw({ type: 'start_request' }));
  const readies = sent.filter((m) => m.type === 'mining_ready');
  assert.ok(readies.length >= 1, 'the client is told when it may mine');
  assert.ok(readies[0].verifierWasmHeapBytes > 40 * 1024 * 1024, 'and how much the pool allocated');
  assert.equal(session.started, true);
});

test('a verifier that fails to initialize yields mining_unavailable and no start', async () => {
  const ctx = makeSession();
  const sent = [];
  const session = createSession({
    jobs: ctx.jobs,
    getVerifier: () => null,
    ensureVerifier: async () => { throw new Error('Wasm identity mismatch for meepow/wasm/meepow.wasm\nsecond line'); },
    now: () => ctx.clock.t,
    send: (o) => sent.push(o),
  });
  await session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 }));
  const r = await session.handleRaw(...raw({ type: 'start_request' }));
  assert.equal(r.reason, REJECT_REASONS.VERIFIER_UNAVAILABLE);
  const msg = sent.at(-1);
  assert.equal(msg.type, 'mining_unavailable');
  assert.match(msg.detail, /identity mismatch/);
  assert.doesNotMatch(msg.detail, /second line/, 'only the first line is disclosed');
  assert.equal(session.started, false);
});

test('a workerId this connection was not issued is refused before any hashing', async () => {
  const ctx = await connected();
  for (const forged of ['w-1-deadbeef', 'w-other', ctx.workerId + 'x', ctx.workerId.toUpperCase()]) {
    const [len, text] = raw({ type: 'submit_share', jobId: ctx.jobId, workerId: forged, nonce: nonceToHex(fixture.qualifyingNonce) });
    const { cost } = await hashCost(() => ctx.session.handleRaw(len, text));
    assert.equal(cost, 0, `${forged} must cost no hashing`);
    assert.equal(lastSent(ctx).reason, REJECT_REASONS.UNKNOWN_WORKER);
  }
});

test('a second client_hello on one connection is refused', async () => {
  const ctx = await connected();
  await ctx.session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 }));
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.BAD_SCHEMA);
});

// ---------------------------------------------------------------- (4) job / expiry

test('a stale jobId is refused before any hashing', async () => {
  const ctx = await connected();
  const staleJobId = ctx.jobId;
  ctx.jobs.issue();
  assert.notEqual(ctx.jobs.active().jobId, staleJobId);

  const [len, text] = raw({ type: 'submit_share', jobId: staleJobId, workerId: ctx.workerId, nonce: nonceToHex(fixture.qualifyingNonce) });
  const { cost } = await hashCost(() => ctx.session.handleRaw(len, text));
  assert.equal(cost, 0);
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.STALE_JOB);
});

test('an unknown jobId is refused before any hashing', async () => {
  const ctx = await connected();
  const [len, text] = raw({ type: 'submit_share', jobId: 'devjob-999', workerId: ctx.workerId, nonce: nonceToHex(fixture.qualifyingNonce) });
  const { cost } = await hashCost(() => ctx.session.handleRaw(len, text));
  assert.equal(cost, 0);
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.STALE_JOB);
});

test('an expired job is refused before any hashing', async () => {
  const ctx = await connected({ jobTtlMs: 5_000 });
  ctx.clock.t += 5_001; // deterministic: the clock is injected, nothing sleeps
  const { cost } = await hashCost(() => ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce)));
  assert.equal(cost, 0);
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.EXPIRED_JOB);
});

test('a job that has not expired yet still verifies', async () => {
  const ctx = await connected({ jobTtlMs: 5_000 });
  ctx.clock.t += 4_999;
  const { cost } = await hashCost(() => ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce)));
  assert.equal(cost, 1);
  assert.equal(lastVerdict(ctx).type, 'share_accepted');
});

test('a nonce outside the issued window is refused before any hashing', async () => {
  const ctx = await connected();
  for (const nonce of [fixture.nonceRange, fixture.nonceRange + 1, 0xffffffff, 1000]) {
    const { cost } = await hashCost(() => ctx.session.handleRaw(...share(ctx, nonce)));
    assert.equal(cost, 0, `nonce ${nonce} must cost no hashing`);
    assert.equal(lastSent(ctx).reason, REJECT_REASONS.BAD_SCHEMA);
  }
});

// ---------------------------------------------------------------- (5) duplicates

test('a duplicate submission is refused before a second hash call', async () => {
  const ctx = await connected();
  const first = await hashCost(() => ctx.session.handleRaw(...share(ctx, losers[0])));
  assert.equal(first.cost, 1, 'the first submission is verified');

  for (let i = 0; i < 3; i++) {
    const again = await hashCost(() => ctx.session.handleRaw(...share(ctx, losers[0])));
    assert.equal(again.cost, 0, 'a replay must never be hashed again');
    assert.equal(lastSent(ctx).reason, REJECT_REASONS.DUPLICATE_SHARE);
  }
});

test('a winning nonce cannot be replayed for a second acceptance', async () => {
  const ctx = await connected();
  const first = await hashCost(() => ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce)));
  assert.equal(first.cost, 1);
  assert.equal(lastVerdict(ctx).type, 'share_accepted');
  const replay = await hashCost(() => ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce)));
  assert.equal(replay.cost, 0);
  assert.equal(ctx.session.accepted, 1, 'a replayed winner is not credited twice');
});

test('a rejected submission does not consume a replay slot', async () => {
  const ctx = await connected();
  await ctx.session.handleRaw(...share(ctx, '0000000F')); // bad schema
  assert.equal(ctx.session.seenShareCount, 0);
  await ctx.session.handleRaw(...share(ctx, losers[0]));
  assert.equal(ctx.session.seenShareCount, 1);
});

test('replay memory is bounded and fails closed when full', async () => {
  const ctx = await connected({ limits: { maxDuplicateKeys: 3 } });
  for (let i = 0; i < 3; i++) await ctx.session.handleRaw(...share(ctx, losers[i]));
  assert.equal(ctx.session.seenShareCount, 3);
  const { cost } = await hashCost(() => ctx.session.handleRaw(...share(ctx, losers[3])));
  assert.equal(cost, 0, 'a full replay memory must refuse before hashing');
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.DUPLICATE_MEMORY_FULL);
  assert.equal(ctx.session.seenShareCount, 3, 'and must not grow past its bound');
});

test('issuing a new job clears the replay memory rather than accumulating it', async () => {
  const ctx = await connected();
  for (let i = 0; i < 5; i++) await ctx.session.handleRaw(...share(ctx, losers[i]));
  assert.equal(ctx.session.seenShareCount, 5);

  ctx.jobs.issue();
  assert.equal(ctx.session.seenShareCount, 0, 'old (jobId, nonce) keys are unreachable and must be released');

  const jobMsg = ctx.sent.filter((m) => m.type === 'job').at(-1);
  assert.ok(jobMsg, 'a newly issued job must be sent to the connection');
  ctx.jobId = jobMsg.jobId;
  const { cost } = await hashCost(() => ctx.session.handleRaw(...share(ctx, losers[0])));
  assert.equal(cost, 1);
  assert.equal(ctx.session.seenShareCount, 1);
});

// ---------------------------------------------------------------- (6) rate limit

test('rate-limited submissions are refused before any hashing, and refill deterministically', async () => {
  const ctx = await connected({ limits: { rateCapacity: 2, rateRefillPerSecond: 1 } });
  const a = await hashCost(() => ctx.session.handleRaw(...share(ctx, losers[0])));
  const b = await hashCost(() => ctx.session.handleRaw(...share(ctx, losers[1])));
  assert.equal(a.cost, 1);
  assert.equal(b.cost, 1);

  for (const nonce of [losers[2], losers[3]]) {
    const c = await hashCost(() => ctx.session.handleRaw(...share(ctx, nonce)));
    assert.equal(c.cost, 0, 'a rate-limited submission must cost no hashing');
    assert.equal(lastSent(ctx).reason, REJECT_REASONS.RATE_LIMITED);
  }

  ctx.clock.t += 1000; // one injected second refills exactly one token
  const d = await hashCost(() => ctx.session.handleRaw(...share(ctx, losers[4])));
  assert.equal(d.cost, 1, 'the bucket refilled');
  const e = await hashCost(() => ctx.session.handleRaw(...share(ctx, losers[5])));
  assert.equal(e.cost, 0, 'and only by one token');
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.RATE_LIMITED);
});

// ---------------------------------------------------------------- (7) verification queue

test('a submission arriving while the queue is full is refused before any hashing', async () => {
  const ctx = await connected({ limits: { maxVerificationQueue: 1 } });
  const before_ = verifier.hashCalls;

  const p1 = ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce));
  const p2 = ctx.session.handleRaw(...share(ctx, fixture.nonQualifyingNonce));
  const [r1, r2] = await Promise.all([p1, p2]);

  assert.equal(r1.type, 'share_accepted', 'the first submission is verified normally');
  assert.equal(r2.reason, REJECT_REASONS.QUEUE_FULL);

  const queueFull = ctx.audit.find((e) => e.reason === REJECT_REASONS.QUEUE_FULL);
  assert.ok(queueFull, 'the rejection was audited');
  assert.equal(queueFull.hashCalls, before_, 'no hash had been computed when it was refused');
  assert.equal(verifier.hashCalls, before_ + 1, 'exactly one hash for the two submissions');
});

// ---------------------------------------------------------------- (8)(9) recomputation

test('a qualifying nonce is accepted after exactly one server recomputation', async () => {
  const ctx = await connected();
  const { value, cost } = await hashCost(() => ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce)));
  assert.equal(cost, 1, 'exactly one MeepHash-W computation, on the server');
  assert.equal(value.type, 'share_accepted');

  const reply = lastVerdict(ctx);
  assert.equal(reply.serverRecomputed, true);
  assert.equal(reply.nonce, nonceToHex(fixture.qualifyingNonce));
  assert.equal(reply.hashHexLE, fixture.qualifyingHashHexLE, 'the reply carries the SERVER hash');
  assert.equal(reply.hashHexLE, fixture.targetHexLE, 'which equals the target: it passes by equality');
});

test('an accepted share ends the demonstration and does not re-issue work', async () => {
  const ctx = await connected();
  const jobId = ctx.jobId;
  await ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce));

  const done = ctx.sent.find((m) => m.type === 'demo_complete');
  assert.ok(done, 'the client is told the demonstration is over');
  assert.match(done.notice, /press Start again/i);
  assert.equal(ctx.sent.filter((m) => m.type === 'job').length, 0,
    'no fresh-looking job is pushed: every job here repeats the same synthetic context');
  assert.equal(ctx.jobs.active(), null, 'the job is consumed');
  assert.equal(ctx.jobs.lastConsumedJob().jobId, jobId);
  assert.equal(ctx.session.started, false, 'another run needs another explicit Start');

  // A further submission is refused for free. The reason is NOT_STARTED rather than STALE_JOB
  // because the completed demonstration also cleared the run: the identity/consent check is
  // cheaper and more fundamental than the job check, so it fires first.
  const { cost } = await hashCost(() => ctx.session.handleRaw(...share(ctx, losers[0])));
  assert.equal(cost, 0);
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.NOT_STARTED);
});

test('a completed job ends the demonstration for the OTHER started connection too', async () => {
  // Two connections share the job store. A completes the demonstration; because the job is
  // global, B's run ends too -- B is told once, its start intent is cleared, and it cannot
  // submit again until it starts again.
  const a = await connected();
  const b = makeSession();
  const bSession = createSession({
    jobs: a.jobs,
    getVerifier: () => verifier,
    ensureVerifier: async () => verifier,
    now: () => a.clock.t,
    send: (o) => b.sent.push(o),
  });
  await bSession.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 }));
  await bSession.handleRaw(...raw({ type: 'start_request' }));
  const bWorker = bSession.workerId;
  const jobId = a.jobId;

  await a.session.handleRaw(...share(a, fixture.qualifyingNonce));
  assert.equal(a.jobs.active(), null, 'the job is consumed');

  const bDone = b.sent.filter((m) => m.type === 'demo_complete');
  assert.equal(bDone.length, 1, 'B is told exactly once that the shared demonstration ended');
  assert.equal(bDone[0].won, false, 'and told it did not win it');
  assert.equal(bSession.started, false, 'B start intent is cleared');

  const [len, text] = raw({ type: 'submit_share', jobId, workerId: bWorker, nonce: nonceToHex(losers[0]) });
  const { cost } = await hashCost(() => bSession.handleRaw(len, text));
  assert.equal(cost, 0, 'a consumed job costs the second connection no hashing');
  assert.equal(b.sent.at(-1).reason, REJECT_REASONS.NOT_STARTED,
    'and B must start again before it may submit anything');
});

test('a second Start after a completed demonstration issues fresh work', async () => {
  const ctx = await connected();
  const firstJobId = ctx.jobId;
  await ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce));
  ctx.sent.length = 0;

  await ctx.session.handleRaw(...raw({ type: 'start_request' }));
  const job = ctx.sent.find((m) => m.type === 'job');
  assert.ok(job, 'a new Start issues a new job');
  assert.notEqual(job.jobId, firstJobId);
  assert.equal(job.targetHexLE, fixture.targetHexLE, 'the same synthetic context, honestly repeated');
  assert.ok(ctx.sent.find((m) => m.type === 'mining_ready'));

  ctx.jobId = job.jobId;
  const { cost, value } = await hashCost(() => ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce)));
  assert.equal(cost, 1);
  assert.equal(value.type, 'share_accepted');
  assert.equal(ctx.session.accepted, 2);
});

test('a non-qualifying nonce is rejected honestly, after being recomputed', async () => {
  const ctx = await connected();
  const { cost } = await hashCost(() => ctx.session.handleRaw(...share(ctx, fixture.nonQualifyingNonce)));
  assert.equal(cost, 1, 'the server did the work before saying no');
  const reply = lastVerdict(ctx);
  assert.equal(reply.type, 'share_rejected');
  assert.equal(reply.reason, REJECT_REASONS.ABOVE_TARGET);
  assert.notEqual(fixture.nonQualifyingHashHexLE, fixture.targetHexLE);
});

test('every non-qualifying nonce in the window is rejected, and only one is accepted', async () => {
  let accepted = 0;
  for (let nonce = 0; nonce < fixture.nonceRange; nonce++) {
    const ctx = await connected();
    const r = await ctx.session.handleRaw(...share(ctx, nonce));
    if (r.type === 'share_accepted') accepted++;
  }
  assert.equal(accepted, 1, 'the fixture target admits exactly one nonce in the window');
});

// ---------------------------------------------------------------- client resultHash is inert

test('a forged resultHash cannot make a losing nonce win', async () => {
  const forgeries = [
    ['the target itself', fixture.targetHexLE],
    ['all zeroes (the best possible hash)', '00'.repeat(32)],
    ['the genuine winning hash, on the wrong nonce', fixture.qualifyingHashHexLE],
  ];
  for (const [label, resultHash] of forgeries) {
    const ctx = await connected();
    const { cost } = await hashCost(() => ctx.session.handleRaw(...share(ctx, fixture.nonQualifyingNonce, { resultHash })));
    assert.equal(cost, 1, 'the server still recomputes');
    const reply = lastVerdict(ctx);
    assert.equal(reply.type, 'share_rejected', label);
    assert.equal(reply.reason, REJECT_REASONS.ABOVE_TARGET, label);
  }
});

test('a wrong resultHash cannot make a winning nonce lose', async () => {
  for (const resultHash of ['ff'.repeat(32), '00'.repeat(32), 'deadbeef']) {
    const ctx = await connected();
    const { cost } = await hashCost(() => ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce, { resultHash })));
    assert.equal(cost, 1);
    const reply = lastVerdict(ctx);
    assert.equal(reply.type, 'share_accepted', `resultHash ${resultHash} must not condemn a valid share`);
    assert.equal(reply.hashHexLE, fixture.qualifyingHashHexLE, 'the reply is the server hash, not the client one');
    assert.notEqual(reply.hashHexLE, resultHash);
  }
});

test('present, absent and correct resultHash all give the identical verdict', async () => {
  const variants = [{}, { resultHash: fixture.qualifyingHashHexLE }, { resultHash: '11'.repeat(32) }];
  const verdicts = [];
  for (const extra of variants) {
    const ctx = await connected();
    await ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce, extra));
    const reply = lastVerdict(ctx);
    verdicts.push(`${reply.type}:${reply.hashHexLE}`);
  }
  assert.equal(verdicts[0], verdicts[1]);
  assert.equal(verdicts[1], verdicts[2], 'the optional field is inert: it changes nothing');
});

test('a malformed resultHash is refused before any hashing', async () => {
  const bad = [
    ['uppercase', 'AB'.repeat(32)],
    ['too long', 'ab'.repeat(33)],
    ['not hex', 'zz'.repeat(32)],
    ['odd length', 'abc'],
  ];
  for (const [label, resultHash] of bad) {
    const ctx = await connected();
    const { cost } = await hashCost(() => ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce, { resultHash })));
    assert.equal(cost, 0, `${label} must cost no hashing`);
    assert.equal(lastSent(ctx).reason, REJECT_REASONS.BAD_SCHEMA, label);
  }
  const ctx = await connected();
  const [len, text] = raw({ type: 'submit_share', jobId: ctx.jobId, workerId: ctx.workerId, nonce: nonceToHex(0), resultHash: 12345 });
  const { cost } = await hashCost(() => ctx.session.handleRaw(len, text));
  assert.equal(cost, 0);
  assert.equal(lastSent(ctx).reason, REJECT_REASONS.BAD_SCHEMA);
});

test('the session source never reads the client-supplied hash when deciding', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../session.mjs', import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
  assert.doesNotMatch(src, /untrustedResultHash/, 'session.mjs must not read the client hash at all');
  assert.doesNotMatch(src, /resultHash/, 'and must not reference it in any decision');
});

// ---------------------------------------------------------------- protocol basics

test('ping is answered and costs no hashing', async () => {
  const ctx = await connected();
  const { cost } = await hashCost(() => ctx.session.handleRaw(...raw({ type: 'ping' })));
  assert.equal(cost, 0);
  assert.equal(lastSent(ctx).type, 'pong');
});

test('client_hello issues a workerId and the current job', async () => {
  const ctx = makeSession();
  await ctx.session.handleRaw(...raw({ type: 'client_hello', protocolVersion: 1 }));
  const hello_ = ctx.sent.find((m) => m.type === 'server_hello');
  const job = ctx.sent.find((m) => m.type === 'job');
  assert.match(hello_.workerId, /^w-\d+-[0-9a-f]{8}$/);
  assert.match(hello_.notice, /no coins or rewards/);
  assert.equal(job.algorithm, 'meephash-w-v2-frozen-synthetic');
  assert.equal(job.targetHexLE, fixture.targetHexLE);
  assert.equal(job.nonceRange, 16);
  assert.match(job.notice, /no coins or rewards/);
  assert.equal(job.targetBytes, undefined, 'internal state is not sent to the client');
});

test('a disposed session accepts nothing further', async () => {
  const ctx = await connected();
  ctx.session.dispose();
  const { cost } = await hashCost(() => ctx.session.handleRaw(...share(ctx, fixture.qualifyingNonce)));
  assert.equal(cost, 0);
  assert.equal(ctx.session.disposed, true);
});
