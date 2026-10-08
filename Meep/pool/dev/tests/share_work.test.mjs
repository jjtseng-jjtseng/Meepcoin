// ROUND 1a: SERVER-SIDE SHARE VERIFICATION AND BLOCK PROMOTION.
//
// A share is a result that meets a SHARE target the server chose. Share difficulty <= network
// difficulty, so the numeric share target is >= the block target: every block is a share, and a
// share is usually not a block. A share that is not a block must cost the daemon NOTHING -- no
// calc_pow, no submission claim, no submit_block, no readback -- and must not end the run. A result
// that is also a block takes the unchanged one-submission path.
//
// NOTHING LIVE IS IN THIS FILE. The verifiers, the daemon and the chain are in-memory objects; no
// process, socket, listener, container, browser or wallet exists. The browser is not involved at
// all: this round is the server half, and the page still reports one result per template.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { NONTERMINAL, createBlockRun, createRunIntent } from '../block_run.mjs';
import { createFatalLatch, createTemplateAuthority } from '../run_guard.mjs';
import { createRealTemplateJob, shareTargetBytesOf, targetBytesOf } from '../real_template.mjs';
import { blobToHex, hexToBlob } from '../block_blob.mjs';
import { MAX_256, bigIntToLeBytes32, leBytes32ToBigInt } from '../difficulty.mjs';
import {
  REAL_P2P_PROFILE, REAL_P2P_SHARE_PROFILE, SIM_ATTEMPT_STATES, createSimulationContext, createSimulationSession,
} from '../sim_session.mjs';
import { buildScriptedChain, CHAIN_A, powFor } from './in_memory_chain.mjs';
import { buildRealDaemonMode } from '../real_daemon_mode.mjs';
import { REAL_SHARE_LIMITS, REJECT_REASONS } from '../../../web-miner/lib/shared/protocol.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, '../../..');
const V = JSON.parse(
  readFileSync(resolve(REPO, 'meepow/vectors/block_vectors_v16_devnet.json'), 'utf8'),
).vectors[1];

const WORKER = 'w-share-1';
const ISSUANCE = 'abcdef0123456789abcdef0123456789';
const START_ID = '0123456789abcdef0123456789abcdef';
const BLOCK_DIFFICULTY = 1_000_000n;
const SHARE_DIFFICULTY = 1_000n;

/** A hash that meets difficulty `d` exactly at its boundary. */
const hashForDifficulty = (d) => bigIntToLeBytes32(MAX_256 / d);
const BLOCK_QUALITY = hashForDifficulty(BLOCK_DIFFICULTY);          // meets both targets
const SHARE_QUALITY = hashForDifficulty(10_000n);                   // meets share, not block
const TOO_WEAK = hashForDifficulty(10n);                            // meets neither

function makeJob({ shareDifficulty, issuanceId = ISSUANCE, now = () => 1000 } = {}) {
  return createRealTemplateJob({
    height: V.height,
    seedHashHex: V.epoch_key,
    wideDifficulty: `0x${BLOCK_DIFFICULTY.toString(16)}`,
    blockhashingBlobHex: V.block_hashing_blob,
    blocktemplateBlobHex: V.full_block_blob,
    nonceStart: 0,
    nonceRange: 1 << 16,
    ...(shareDifficulty === undefined ? {} : { shareDifficulty }),
  }, { mintIssuanceId: () => issuanceId, now });
}

/**
 * A run over in-memory collaborators that COUNT every costly step. `hashes` decides, per nonce,
 * what both server paths return -- they must agree, or block_run trips its fatal latch, which is
 * itself existing behaviour and not what this file is about.
 */
function runHarness({ shareDifficulty, hashes = () => BLOCK_QUALITY, nativeGate = null } = {}) {
  const clock = { ms: 1000 };
  const job = makeJob({ shareDifficulty, now: () => clock.ms });
  const latch = createFatalLatch();
  const authority = createTemplateAuthority();
  authority.publish(job);
  const intent = createRunIntent({ now: () => clock.ms });
  const calls = [];
  const events = [];
  const daemon = {
    async calcPow() { calls.push('calcPow'); return blobToHex(hashes(calls.lastNonce)); },
    submissionAdapter: null,
    prepareSubmission() { calls.push('prepareSubmission'); throw Object.assign(new Error('not reached in this file'), { code: 'not_reached' }); },
    dispatchSubmission() { calls.push('dispatchSubmission'); throw new Error('not reached in this file'); },
    async getBlockHeaderByHeight() { calls.push('getBlockHeaderByHeight'); return null; },
  };
  const run = createBlockRun({
    job,
    intent,
    wasmVerifier: { hashOne: async (n) => { calls.push('wasm'); calls.lastNonce = n; return hashes(n); } },
    nativeVerifier: {
      hashOne: async (n) => {
        calls.push('native');
        // The seam the deferred-native tests need: the run is mid-await here, exactly where an
        // expiry, a Stop or a fatal latch can land.
        if (nativeGate) await nativeGate();
        return hashes(n);
      },
    },
    daemon,
    latch,
    authority,
    workerId: WORKER,
    emit: (e) => events.push(e),
    now: () => clock.ms,
  });
  intent.start();
  run.begin();
  const submit = (nonce, over = {}) => run.submitCandidate({
    jobId: job.jobId, issuanceId: job.issuanceId, workerId: WORKER, runGeneration: 1, nonce, ...over,
  });
  const count = (name) => calls.filter((c) => c === name).length;
  return { job, run, intent, latch, authority, calls, events, submit, count, clock };
}

const daemonCalls = (h) => h.count('calcPow') + h.count('prepareSubmission') + h.count('dispatchSubmission')
  + h.count('getBlockHeaderByHeight');

// ==================================================================== the target inequality
test('SHARE TARGET: share difficulty <= network difficulty, so the share target >= the block target', () => {
  const legacy = makeJob();
  assert.equal(legacy.shareWork, false);
  assert.equal(legacy.shareTargetHexLE, legacy.targetHexLE, 'a job without share work moved its target');
  assert.equal(legacy.shareDifficulty, legacy.difficulty);
  assert.deepEqual(shareTargetBytesOf(legacy), targetBytesOf(legacy));

  const shared = makeJob({ shareDifficulty: Number(SHARE_DIFFICULTY) });
  assert.equal(shared.shareWork, true);
  assert.equal(shared.shareDifficulty, SHARE_DIFFICULTY);
  assert.ok(leBytes32ToBigInt(shareTargetBytesOf(shared)) > leBytes32ToBigInt(targetBytesOf(shared)),
    'an easier share difficulty did not produce a numerically larger target');
  assert.equal(leBytes32ToBigInt(shareTargetBytesOf(shared)), MAX_256 / SHARE_DIFFICULTY);

  // Equal difficulties are legal and collapse to the block target.
  const equal = makeJob({ shareDifficulty: Number(BLOCK_DIFFICULTY) });
  assert.equal(equal.shareTargetHexLE, equal.targetHexLE);
  assert.equal(equal.shareWork, true, 'an explicitly configured share target is still share work');

  // Anything harder than the network target, or malformed, is refused at construction.
  for (const bad of [Number(BLOCK_DIFFICULTY) + 1, 0, -1, 1.5, '1000', {}]) {
    assert.throws(() => makeJob({ shareDifficulty: bad }), /shareDifficulty|bad_field/,
      `shareDifficulty ${JSON.stringify(bad)} was accepted`);
  }
});

test('SHARE TARGET: a legacy job is byte-for-byte the job it always was', () => {
  const a = makeJob();
  const b = makeJob();
  assert.equal(a.jobId, b.jobId);
  assert.equal(a.authDigest, b.authDigest);
  const shared = makeJob({ shareDifficulty: Number(SHARE_DIFFICULTY) });
  // Same work, different capability: content identity is unchanged, authorization identity is not.
  assert.equal(shared.contentDigest, a.contentDigest, 'the share target changed what the work IS');
  assert.notEqual(shared.authDigest, a.authDigest, 'the share target is not bound to the issuance');
  assert.notEqual(shared.jobId, a.jobId);
});

// ==================================================================== shares, then a block
test('SHARE RUN: two verified non-block shares cost the daemon nothing and the run continues', async () => {
  const h = runHarness({
    shareDifficulty: Number(SHARE_DIFFICULTY),
    hashes: (n) => (n === 30 ? BLOCK_QUALITY : SHARE_QUALITY),
  });

  const first = await h.submit(10);
  const second = await h.submit(20);
  for (const [i, r] of [first, second].entries()) {
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.share, true);
    assert.equal(r.block, false);
    assert.equal(r.terminal, false);
    assert.equal(r.shareIndex, i + 1);
  }
  assert.equal(h.run.sharesAccepted, 2);
  assert.equal(daemonCalls(h), 0, `a non-block share reached the daemon: ${h.calls.join(',')}`);
  assert.equal(h.count('wasm'), 2);
  assert.equal(h.count('native'), 2, 'the native path did not independently verify each share');
  assert.deepEqual(h.events.map((e) => e.type), ['share_accepted', 'share_accepted']);
  assert.deepEqual(h.events.map((e) => e.nonce), [10, 20]);
  assert.deepEqual(h.events[0].agreedBy, ['server_wasm', 'native_path']);
  assert.equal(h.authority.anyClaimed, false, 'a non-block share spent the one submission claim');
  assert.equal(h.run.complete, false, 'a non-block share ended the run');

  // The block-quality nonce takes the unchanged path: calc_pow, then the claim, then submission.
  // This harness deliberately stops at the adapter boundary (prepareSubmission throws), so what it
  // proves is that a block-quality result LEAVES the share path: the daemon recomputes it and the
  // submission boundary is entered. The complete claim/submit/readback path is the session test
  // below, where a real submission and exactly one claim are asserted.
  const third = await h.submit(30);
  assert.equal(h.count('calcPow'), 1, 'the block path did not recompute on the daemon');
  assert.equal(h.count('prepareSubmission'), 1, 'the block path never reached the submission boundary');
  assert.equal(third.terminal, true, 'the block path did not reach a terminal outcome');
  assert.equal(h.run.sharesAccepted, 2, 'the block was miscounted as a share');
});

test('SHARE RUN: shares without a block submit nothing at all', async () => {
  const h = runHarness({ shareDifficulty: Number(SHARE_DIFFICULTY), hashes: () => SHARE_QUALITY });
  for (const nonce of [1, 2, 3, 4]) {
    const r = await h.submit(nonce);
    assert.equal(r.share, true, `nonce ${nonce}`);
  }
  assert.equal(h.run.sharesAccepted, 4);
  assert.equal(daemonCalls(h), 0);
  assert.equal(h.authority.anyClaimed, false);
  assert.equal(h.run.complete, false);
});

test('SHARE RUN: a result above the SHARE target is a refusal that costs the daemon nothing', async () => {
  const h = runHarness({ shareDifficulty: Number(SHARE_DIFFICULTY), hashes: () => TOO_WEAK });
  const r = await h.submit(7);
  assert.equal(r.ok, false);
  assert.equal(r.reason, NONTERMINAL.ABOVE_TARGET);
  assert.equal(r.entered, true);
  assert.equal(r.terminal, false, 'an above-target result ended the run at the run level');
  assert.equal(daemonCalls(h), 0);
  assert.equal(h.events[0].type, 'candidate_rejected');
  assert.match(h.events[0].detail, /above the share target/);
  assert.equal(h.run.sharesAccepted, 0);
});

test('SHARE RUN: forged, stale, out-of-window and duplicate results are refused BEFORE any hashing', async () => {
  const h = runHarness({ shareDifficulty: Number(SHARE_DIFFICULTY), hashes: () => SHARE_QUALITY });
  const cheap = [
    ['a different job', { jobId: 'realjob-0000000000000000' }, NONTERMINAL.UNKNOWN_JOB],
    ['a different issuance', { issuanceId: '0'.repeat(32) }, NONTERMINAL.STALE_ISSUANCE],
    ['another worker', { workerId: 'w-other' }, NONTERMINAL.UNKNOWN_WORKER],
    ['an older generation', { runGeneration: 0 }, NONTERMINAL.STALE_GENERATION],
    ['a nonce outside the window', { nonce: 1 << 20 }, NONTERMINAL.NONCE_OUT_OF_WINDOW],
  ];
  for (const [label, over, reason] of cheap) {
    const r = await h.submit(11, over);
    assert.equal(r.reason, reason, label);
    assert.equal(r.entered, false, `${label} entered verification`);
  }
  assert.equal(h.count('wasm'), 0, 'a refused result was hashed');
  assert.equal(h.count('native'), 0);
  assert.equal(daemonCalls(h), 0);

  // A duplicate of an ACCEPTED share is refused on the same cheap fence, without re-hashing.
  assert.equal((await h.submit(12)).share, true);
  const hashesAfterFirst = h.count('wasm');
  const dup = await h.submit(12);
  assert.equal(dup.reason, NONTERMINAL.DUPLICATE);
  assert.equal(dup.entered, false);
  assert.equal(h.count('wasm'), hashesAfterFirst, 'a duplicate nonce was hashed again');
});

test('SHARE RUN: with no share difficulty configured, behaviour is exactly what it was', async () => {
  // The same share-quality hash that is a share above is an ordinary above-target refusal here,
  // and no share event exists at all.
  const h = runHarness({ hashes: () => SHARE_QUALITY });
  const r = await h.submit(10);
  assert.equal(r.ok, false);
  assert.equal(r.reason, NONTERMINAL.ABOVE_TARGET);
  assert.equal(r.share, undefined, 'a legacy run produced a share result');
  assert.match(h.events[0].detail, /above the template target/);
  assert.equal(h.run.shareWork, false);
  assert.equal(h.run.sharesAccepted, 0);
  assert.equal(daemonCalls(h), 0);
});

// ==================================================================== the session, end to end
//
// The real session, the real profile, the real authority and the in-memory daemon pair. The
// verifier's two paths are scripted PER NONCE so the same run can produce shares and then a block.

async function shareSession({ sequenceBlocks = 1, shareDifficulty = 50, chainOptions = {} } = {}) {
  const ctx = await buildScriptedChain(chainOptions, { sequenceBlocks, shareDifficulty });
  const sim = createSimulationContext({
    ...ctx.built,
    profile: REAL_P2P_SHARE_PROFILE,
    now: () => ctx.clock.ms,
  });
  const sent = [];
  const timers = [];
  const session = createSimulationSession({
    sim,
    now: () => ctx.clock.ms,
    send: (o) => sent.push(o),
    setTimer: (fn, ms) => { const t = { fn, ms, cleared: false }; timers.push(t); return t; },
    clearTimer: (t) => { t.cleared = true; },
  });
  const say = (obj) => {
    const text = JSON.stringify(obj);
    return session.handleRaw(Buffer.byteLength(text), text);
  };
  await say({ type: 'client_hello', protocolVersion: 1 });
  await say({ type: 'start_request', clientStartId: START_ID });
  const ready = [...sent].reverse().find((m) => m.type === 'mining_ready');
  assert.ok(ready, `no readiness: ${JSON.stringify(sent.map((m) => [m.type, m.reason]))}`);
  const candidate = (nonce, over = {}) => ({
    type: 'submit_real_candidate',
    clientStartId: START_ID,
    jobId: ready.jobId,
    issuanceId: ready.issuanceId,
    workerId: ready.workerId,
    runGeneration: ready.runGeneration,
    nonce: nonce.toString(16).padStart(8, '0'),
    ...over,
  });
  return {
    ...ctx, sim, session, sent, timers, say, ready, candidate,
    all: (type) => sent.filter((m) => m.type === type),
    last: (type) => [...sent].reverse().find((m) => m.type === type),
  };
}

/** Script the live verifier's two paths per nonce: block-quality for `blockNonce`, share otherwise. */
function scriptVerifier(ctx, blockNonce) {
  const v = ctx.journal.created.at(-1);
  const answer = (n) => (n === blockNonce
    ? hexToBlob(powFor(1))                       // exactly what daemon A's calc_pow will say
    : hashForDifficulty(200n));                  // meets share difficulty 50, not block difficulty 500
  v.hashWasm = async (n) => answer(n);
  v.hashNative = async (n) => answer(n);
  return v;
}

test('SHARE SESSION: two accepted shares, the run keeps going, then one block and one submission', async () => {
  const c = await shareSession();
  scriptVerifier(c, 90);

  assert.equal(c.ready.notice.includes('at most one block submission'), true);
  await c.say(c.candidate(10));
  await c.say(c.candidate(20));
  const shares = c.all('share_accepted');
  assert.equal(shares.length, 2, JSON.stringify(c.sent.map((m) => [m.type, m.reason])));
  assert.deepEqual(shares.map((s) => s.sharesAccepted), [1, 2]);
  assert.equal(shares[0].terminal, false);
  assert.equal(shares[0].jobId, c.ready.jobId, 'a share was announced without its binding');
  assert.equal(c.net.log.calcPow.length, 0, 'a non-block share reached daemon A');
  assert.equal(c.net.log.submitBodies.length, 0);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING, 'a share ended the attempt');
  assert.equal(c.sim.authority.anyClaimed, false);

  await c.say(c.candidate(90));
  assert.equal(c.net.log.calcPow.length, 1, 'the block was not recomputed by daemon A');
  assert.equal(c.net.log.submitBodies.length, 1, 'exactly one submission');
  assert.equal(c.sim.authority.claimCount, 1);
  assert.equal(c.last('block_accepted')?.terminal, true);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(c.session.stateFacts.sharesAccepted, 2);
  // Three DISTINCT candidates were admitted, one at a time, and the slot is free again.
  assert.equal(c.session.stateFacts.candidatesAdmittedThisBlock, 3);
  assert.equal(c.session.stateFacts.candidatesInFlight, 0);
  assert.equal(c.session.stateFacts.verificationSlotFree, 1);
  assert.deepEqual(c.net.log.bWrites, [], 'daemon B was written to');
});

test('SHARE SESSION: shares alone never submit, and the absolute search bound still ends the run', async () => {
  const c = await shareSession();
  scriptVerifier(c, -1);                       // no nonce is ever block quality
  await c.say(c.candidate(10));
  await c.say(c.candidate(20));
  assert.equal(c.all('share_accepted').length, 2);
  assert.equal(c.net.log.submitBodies.length, 0);

  // THE BACKSTOP IS ABSOLUTE IN THIS PROFILE: an admitted candidate does not disarm it, so a
  // session that keeps sending shares cannot idle past the frozen bound.
  const timer = c.timers.find((t) => !t.cleared);
  assert.ok(timer, 'the search backstop was cleared by an admitted share');
  timer.fn();
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(c.net.log.submitBodies.length, 0);
});

test('SHARE SESSION: the candidate cap and the invalid-result cap are both finite', async () => {
  const cap = await shareSession();
  scriptVerifier(cap, -1);
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) await cap.say(cap.candidate(100 + i));
  assert.equal(cap.all('share_accepted').length, REAL_SHARE_LIMITS.maxSharesPerJob);
  assert.equal(cap.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED,
    'the eighth settled share left the attempt idle until its timer');
  assert.equal(cap.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(cap.all('run_stopped').length, 1);
  assert.equal(cap.session.stateFacts.searchTimers, 0, 'the spent template kept its backstop armed');
  const over = await cap.say(cap.candidate(200));
  assert.equal(over.ok, false);
  assert.equal(over.reason, REJECT_REASONS.NOT_STARTED);
  assert.equal(cap.net.log.calcPow.length, 0);
  assert.equal(cap.net.log.submitBodies.length, 0);

  // Results that ENTER verification and are refused are capped too, and only then is it terminal.
  const bad = await shareSession();
  const v = bad.journal.created.at(-1);
  v.hashWasm = async () => hashForDifficulty(2n);        // above even the share target
  v.hashNative = async () => hashForDifficulty(2n);
  for (let i = 0; i < REAL_SHARE_LIMITS.maxInvalidCandidates - 1; i += 1) {
    await bad.say(bad.candidate(300 + i));
    assert.equal(bad.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING, `refusal ${i + 1} ended the run`);
  }
  await bad.say(bad.candidate(400));
  assert.equal(bad.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
  assert.equal(bad.last('block_rejected')?.reason, 'invalid_share_limit_reached');
  assert.equal(bad.net.log.submitBodies.length, 0);
});

test('SHARE SESSION: Stop, expiry and an issuance id that was never issued end a share run cleanly', async () => {
  const stopped = await shareSession();
  scriptVerifier(stopped, -1);
  await stopped.say(stopped.candidate(10));
  await stopped.say({
    type: 'stop_request', clientStartId: START_ID, workerId: stopped.ready.workerId,
    runGeneration: stopped.ready.runGeneration, jobId: stopped.ready.jobId,
    issuanceId: stopped.ready.issuanceId, reason: 'user_stop',
  });
  assert.equal(stopped.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  const after = await stopped.say(stopped.candidate(11));
  assert.equal(after.ok, false, 'a share was admitted after Stop');
  assert.equal(stopped.all('share_accepted').length, 1);
  assert.equal(stopped.net.log.submitBodies.length, 0);

  const expired = await shareSession();
  scriptVerifier(expired, -1);
  expired.clock.ms = Number(expired.sim.job.expiresAtMs) + 1;
  const late = await expired.say(expired.candidate(12));
  assert.equal(late.ok, false, 'an expired job accepted a share');
  assert.equal(expired.all('share_accepted').length, 0);
  assert.equal(expired.net.log.calcPow.length, 0);

  // A FORGED issuance id, refused on the cheap fence. Real authority supersession is a different
  // thing and is tested separately below.
  const forged = await shareSession();
  scriptVerifier(forged, -1);
  const stale = await forged.say(forged.candidate(13, { issuanceId: '1'.repeat(32) }));
  assert.equal(stale.ok, false);
  assert.equal(forged.all('share_accepted').length, 0);
  assert.equal(forged.net.log.calcPow.length, 0);
});

test('SHARE CONFIG: share work is trusted and bounded, and a sequence may now use it', async () => {
  // A SEQUENCE WITH SHARE WORK IS BUILT, not refused: each of its templates carries the same share
  // difficulty. The composition itself is exercised in share_sequence.test.mjs.
  const paired = await buildScriptedChain({}, { sequenceBlocks: 2, shareDifficulty: 50 });
  assert.equal(paired.built.shareWork, true);
  assert.equal(paired.built.sequence.total, 2);
  assert.equal(paired.built.job.shareWork, true);
  // A sequence still needs the pair, and share work still needs a positive integer difficulty.
  for (const bad of [0, -1, 1.5]) {
    await assert.rejects(buildScriptedChain({}, { sequenceBlocks: 1, shareDifficulty: bad }),
      (e) => e.code === 'bad_config', `shareDifficulty ${bad}`);
  }
  // Too hard for the template is refused by the job itself, not silently clamped.
  await assert.rejects(buildScriptedChain({}, { sequenceBlocks: 1, shareDifficulty: 501 }),
    (e) => /shareDifficulty/.test(String(e?.message ?? e)));
  // And the profile that consumes it never advertises browser-side multi-share.
  assert.equal(/browser.*multi|multi.*share.*browser/i.test(REAL_P2P_SHARE_PROFILE.helloNotice), false);
  // The consent text must state what the browser ACTUALLY does now: one window, one at a time,
  // bounded, stopping early on a block.
  assert.match(REAL_P2P_SHARE_PROFILE.helloNotice, /one browser worker search its single issued window/);
  assert.match(REAL_P2P_SHARE_PROFILE.helloNotice, /one at a time, stopping early if it finds a block/);
  assert.match(REAL_P2P_SHARE_PROFILE.helloNotice, /never rescanned/);
});

// ==================================================================== the corrective round
//
// Each test below failed against the first revision of this feature (11dc4c6) and is here because
// an independent audit found the hole, not because it rounds out a table.

// ---------------------------------------------------------------- (1) the deferred native hash
test('SHARE GATE: an expiry, a Stop or a tripped latch DURING the native hash prevents the share', async () => {
  for (const how of ['expiry', 'revocation', 'latch']) {
    // THE HANDSHAKE IS THE POINT OF THIS TEST. Invalidating straight after submit() would land
    // before the wasm/native gates that already existed, so the test would pass even with the new
    // post-native gate removed. `entered` resolves INSIDE the native hash, so every assertion below
    // is about a run that is past every earlier gate and suspended in the deferred hash.
    let enter;
    const entered = new Promise((r) => { enter = r; });
    let release;
    const gate = new Promise((r) => { release = r; });
    const h = runHarness({
      shareDifficulty: Number(SHARE_DIFFICULTY),
      hashes: () => SHARE_QUALITY,
      nativeGate: () => { enter(); return gate; },
    });
    const pending = h.submit(10);
    await entered;
    assert.equal(h.count('wasm'), 1, `${how}: the wasm hash did not run first`);
    assert.equal(h.count('native'), 1, `${how}: the native hash was not entered before invalidation`);

    if (how === 'expiry') h.clock.ms = Number(h.job.expiresAtMs) + 1;
    if (how === 'revocation') h.intent.revokeCurrent('user_stop');
    if (how === 'latch') h.latch.trip('verifier_fault', 'scripted fault during the native hash');
    release();
    const r = await pending;

    assert.equal(r.share, undefined, `${how}: a share was accepted after the run was invalidated`);
    assert.equal(r.terminal, true, `${how}: the invalidated run did not publish a terminal result`);
    assert.equal(h.run.sharesAccepted, 0, how);
    assert.equal(h.events.some((e) => e.type === 'share_accepted'), false,
      `${how}: share_accepted was emitted after invalidation`);
    assert.equal(daemonCalls(h), 0, how);
    const expected = { expiry: 'expired_job', revocation: 'revoked_before_submit', latch: 'fatal_verifier' }[how];
    assert.equal(h.run.terminal, expected, how);
  }
});

test('SHARE GATE: the same deferred hash with nothing wrong still produces the share', async () => {
  let enter;
  const entered = new Promise((r) => { enter = r; });
  let release;
  const gate = new Promise((r) => { release = r; });
  const h = runHarness({
    shareDifficulty: Number(SHARE_DIFFICULTY),
    hashes: () => SHARE_QUALITY,
    nativeGate: () => { enter(); return gate; },
  });
  const pending = h.submit(10);
  await entered;
  assert.equal(h.count('native'), 1, 'the native hash was not entered');
  release();
  const r = await pending;
  assert.equal(r.share, true, 'the new gate refused a perfectly good share');
  assert.equal(h.run.sharesAccepted, 1);
  assert.equal(daemonCalls(h), 0);
});

// ---------------------------------------------------------------- (2) share work needs the pair
test('SHARE CONFIG: share work without the private daemon pair is refused, not mislabelled', async () => {
  let started = 0;
  await assert.rejects(buildRealDaemonMode({
    daemon: CHAIN_A,
    shareDifficulty: 50,
    ownResource: () => {},
    startDaemon: async () => { started += 1; throw new Error('must not start'); },
    makeTransport: () => async () => '',
    makeVerifier: async () => { throw new Error('must not build'); },
  }), (e) => e.code === 'bad_config' && /pair/.test(e.message));
  assert.equal(started, 0, 'a daemon was started for a refused configuration');
});

// ---------------------------------------------------------------- (3) block-path refusals stay terminal
test('SHARE SESSION: a second block-quality frame sent before the first settles never enters the run', async () => {
  const c = await shareSession();
  const v = c.journal.created.at(-1);
  v.hashWasm = async () => hexToBlob(powFor(1));      // every nonce is block quality
  v.hashNative = async () => hexToBlob(powFor(1));

  const first = c.say(c.candidate(90));
  const second = await c.say(c.candidate(91));
  assert.equal(second.ok, false, 'a concurrent frame entered the shared run');
  assert.equal(second.reason, 'queue_full');
  await first;

  assert.equal(c.net.log.submitBodies.length, 1, 'the race produced more than one submission');
  assert.equal(c.sim.authority.claimCount, 1);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE,
    `the accepted block was overwritten: ${JSON.stringify(c.sent.map((m) => [m.type, m.reason]))}`);
  const terminals = c.sent.filter((m) => m.terminal === true);
  assert.equal(terminals.length, 1, `exactly one terminal message: ${JSON.stringify(terminals.map((m) => m.type))}`);
  assert.equal(terminals[0].type, 'block_accepted');
  // The loser's refusal is visible and nonterminal ON THE WIRE, and it did not become a share.
  assert.equal(c.all('share_accepted').length, 0);
});

test('SHARE SESSION: a daemon that cannot recompute, and a superseded issuance, END the run', async () => {
  // calc_pow unavailable: a BLOCK-path refusal, never a benign share.
  const down = await shareSession({
    chainOptions: {
      gate: (method) => { if (method === 'calc_pow') throw new Error('scripted daemon A failure'); },
    },
  });
  const dv = down.journal.created.at(-1);
  dv.hashWasm = async () => hexToBlob(powFor(1));
  dv.hashNative = async () => hexToBlob(powFor(1));
  await down.say(down.candidate(90));
  assert.equal(down.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED,
    `daemon_unavailable was swallowed as an invalid share: ${JSON.stringify(down.sent.map((m) => [m.type, m.reason]))}`);
  assert.equal(down.last('block_rejected')?.reason, 'daemon_unavailable');
  assert.equal(down.net.log.submitBodies.length, 0);

  // A REAL supersession: the shared authority publishes a newer issuance of this template, so the
  // run's own issuance is no longer current when its block-quality result tries to claim.
  const old = await shareSession();
  const ov = old.journal.created.at(-1);
  ov.hashWasm = async () => hexToBlob(powFor(1));
  ov.hashNative = async () => hexToBlob(powFor(1));
  const superseding = {
    jobId: `${old.sim.job.jobId}-next`,
    issuanceId: 'b'.repeat(32),
    contentDigest: old.sim.job.contentDigest,
    expiresAtMs: old.sim.job.expiresAtMs,
  };
  old.sim.authority.publish(superseding);
  assert.equal(old.sim.authority.isSuperseded(old.sim.job.issuanceId), true, 'the test did not supersede anything');
  await old.say(old.candidate(90));
  assert.equal(old.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED,
    `issuance_superseded was swallowed: ${JSON.stringify(old.sent.map((m) => [m.type, m.reason]))}`);
  assert.equal(old.last('block_rejected')?.reason, 'issuance_superseded');
  assert.equal(old.net.log.submitBodies.length, 0);
  assert.equal(old.all('share_accepted').length, 0);
});

// ---------------------------------------------------------------- (4) duplicates spend no budget
test('SHARE SESSION: repeating one nonce costs no candidate budget and no hashing', async () => {
  const c = await shareSession();
  scriptVerifier(c, -1);
  const hashesFor = () => c.journal.events.filter((e) => e.startsWith('wasm')).length;

  assert.equal((await c.say(c.candidate(10))).share, true);
  const afterFirst = hashesFor();
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob + 3; i += 1) {
    const dup = await c.say(c.candidate(10));
    assert.equal(dup.ok, false, `repeat ${i} was admitted`);
    assert.equal(dup.reason, 'duplicate_nonce', `repeat ${i}`);
  }
  assert.equal(hashesFor(), afterFirst, 'a repeated nonce was hashed again');
  assert.equal(c.session.stateFacts.candidatesAdmittedThisBlock, 1,
    'repeats of one nonce spent the candidate budget');
  assert.equal(c.session.stateFacts.admittedNonces, 1);

  // The budget is still entirely available to DISTINCT nonces.
  for (let i = 1; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) {
    assert.equal((await c.say(c.candidate(10 + i))).share, true, `distinct nonce ${i}`);
  }
  assert.equal(c.all('share_accepted').length, REAL_SHARE_LIMITS.maxSharesPerJob);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal((await c.say(c.candidate(99))).reason, REJECT_REASONS.NOT_STARTED);
});

// ---------------------------------------------------------------- (5) a real pre-change witness
test('SHARE TARGET: a legacy job reproduces the PRE-CHANGE authorization formula exactly', () => {
  const job = makeJob();
  // The authorization digest as this module computed it BEFORE share work existed, recomputed here
  // from the job's own public fields. No share line, and therefore the same job id.
  const legacyAuthDigest = createHash('sha256').update([
    'meepcoin-real-template-auth/2',
    `content=${job.contentDigest}`,
    `issuance=${job.issuanceId}`,
    `issuedAtMs=${job.issuedAtMs}`,
    `expiresAtMs=${job.expiresAtMs}`,
    `seedHeight=${job.seedHeight === null ? 'null' : job.seedHeight.toString()}`,
    `nonceStart=${job.nonceStart}`,
    `nonceRange=${job.nonceRange}`,
  ].join('\n'), 'utf8').digest('hex');
  assert.equal(job.authDigest, legacyAuthDigest, 'a job without share work changed its authorization digest');
  assert.equal(job.jobId, `realjob-${legacyAuthDigest.slice(0, 32)}`);

  // And a share-work job is the same witness PLUS the two share lines: the difference is exactly
  // the share target, not an unrelated change of formula.
  const shared = makeJob({ shareDifficulty: Number(SHARE_DIFFICULTY) });
  const sharedAuthDigest = createHash('sha256').update([
    'meepcoin-real-template-auth/2',
    `content=${shared.contentDigest}`,
    `issuance=${shared.issuanceId}`,
    `issuedAtMs=${shared.issuedAtMs}`,
    `expiresAtMs=${shared.expiresAtMs}`,
    `seedHeight=${shared.seedHeight === null ? 'null' : shared.seedHeight.toString()}`,
    `nonceStart=${shared.nonceStart}`,
    `nonceRange=${shared.nonceRange}`,
    `shareDifficulty=${SHARE_DIFFICULTY.toString()}`,
    `shareTarget=${shared.shareTargetHexLE}`,
  ].join('\n'), 'utf8').digest('hex');
  assert.equal(shared.authDigest, sharedAuthDigest);
});

// ---------------------------------------------------------------- serial verification
//
// Share mode admits several candidates for ONE template, and they all share ONE createBlockRun.
// block_run's gates publish a TERMINAL for the whole run, so a second candidate that reaches
// runGate() after an expiry or a revocation ends the run that a first candidate's CLAIMED
// submission is still awaiting a daemon answer for -- and no event filtering in the session can
// undo that, because the run is already terminal. The session therefore verifies one candidate at
// a time: while one is in flight, a later bound frame is refused cheaply with `queue_full`, before
// the deadline check, the duplicate check, the budget, any hash and any daemon RPC.

test('SHARE SERIAL: a bound frame arriving while a claim is in flight is refused cheaply', async () => {
  for (const where of ['submit_block', 'get_block_header_by_height']) {
    let enter;
    const entered = new Promise((r) => { enter = r; });
    let release;
    const gate = new Promise((r) => { release = r; });
    let armed = true;
    const c = await shareSession({
      chainOptions: {
        gate: async (method, n, side) => {
          if (side !== 'A' || method !== where || !armed) return;
          armed = false;
          enter();
          await gate;
        },
      },
    });
    const v = c.journal.created.at(-1);
    v.hashWasm = async () => hexToBlob(powFor(1));
    v.hashNative = async () => hexToBlob(powFor(1));

    const winner = c.say(c.candidate(90));
    await entered;                                    // the claim is held; A has not answered yet
    const hashesDuring = c.journal.events.filter((e) => e.startsWith('wasm')).length;
    assert.equal(c.session.stateFacts.candidatesInFlight, 1, where);
    assert.equal(c.session.stateFacts.verificationSlotFree, 0, where);

    // FOUR more bound frames, all inside the eight-candidate budget. None of them may enter the
    // shared run at all.
    for (let i = 0; i < 4; i += 1) {
      const busy = await c.say(c.candidate(91 + i));
      assert.equal(busy.ok, false, `${where}: frame ${i} was admitted`);
      assert.equal(busy.reason, 'queue_full', `${where}: frame ${i}`);
    }
    assert.equal(c.journal.events.filter((e) => e.startsWith('wasm')).length, hashesDuring,
      `${where}: a queued-away frame was hashed`);
    assert.equal(c.session.stateFacts.candidatesAdmittedThisBlock, 1,
      `${where}: a refused frame spent the candidate budget`);
    assert.equal(c.session.stateFacts.admittedNonces, 1, where);
    assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING, where);

    release();
    await winner;
    await Promise.resolve();

    assert.equal(c.net.log.submitBodies.length, 1, `${where}: exactly one submission`);
    assert.equal(c.sim.authority.claimCount, 1, where);
    assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE,
      `${where}: ${JSON.stringify(c.sent.map((m) => [m.type, m.reason]))}`);
    const terminals = c.sent.filter((m) => m.terminal === true);
    assert.equal(terminals.length, 1, where);
    assert.equal(terminals[0].type, 'block_accepted', where);
    assert.equal(c.session.stateFacts.candidatesInFlight, 0, where);
    assert.equal(c.session.stateFacts.verificationSlotFree, 1, where);
  }
});

test('SHARE SERIAL: a refused frame keeps its nonce, and the slot reopens when the run settles', async () => {
  let enter;
  const entered = new Promise((r) => { enter = r; });
  let release;
  const gate = new Promise((r) => { release = r; });
  let armed = true;
  const c = await shareSession({
    chainOptions: {
      gate: async (method, n, side) => {
        if (side === 'A' && method === 'get_block_template' && !armed) return;
        return undefined;
      },
    },
  });
  const v = c.journal.created.at(-1);
  v.hashWasm = async (n) => {
    if (n === 10 && armed) { armed = false; enter(); await gate; }
    return hashForDifficulty(200n);                    // share quality, never a block
  };
  v.hashNative = async () => hashForDifficulty(200n);

  const first = c.say(c.candidate(10));
  await entered;
  const busy = await c.say(c.candidate(11));
  assert.equal(busy.reason, 'queue_full');
  release();
  await first;

  // The same nonce the busy frame carried is NOT spent: it is admitted once the slot is free.
  assert.equal(c.session.stateFacts.verificationSlotFree, 1);
  const retried = await c.say(c.candidate(11));
  assert.equal(retried.share, true, JSON.stringify(c.sent.map((m) => [m.type, m.reason])));
  assert.equal(c.all('share_accepted').length, 2);
  assert.equal(c.session.stateFacts.candidatesAdmittedThisBlock, 2,
    'the refused frame had spent a budget slot after all');
  assert.equal(c.net.log.submitBodies.length, 0);
});

test('SHARE DEADLINE: a clock past the TTL cannot reach block_run while a claimant is pending', async () => {
  let enter;
  const entered = new Promise((r) => { enter = r; });
  let release;
  const gate = new Promise((r) => { release = r; });
  let armed = true;
  const c = await shareSession({
    chainOptions: {
      gate: async (method, n, side) => {
        if (side !== 'A' || method !== 'submit_block' || !armed) return;
        armed = false;
        enter();
        await gate;
      },
    },
  });
  const v = c.journal.created.at(-1);
  v.hashWasm = async () => hexToBlob(powFor(1));
  v.hashNative = async () => hexToBlob(powFor(1));

  const winner = c.say(c.candidate(90));
  await entered;
  const hashesDuring = c.journal.events.filter((e) => e.startsWith('wasm')).length;

  // Past the job's own TTL, and BEFORE the backstop timer callback runs.
  c.clock.ms = Number(c.sim.job.expiresAtMs) + 1;
  const late = await c.say(c.candidate(91));
  assert.equal(late.ok, false, 'a post-TTL frame was admitted while a claimant was pending');
  assert.equal(late.reason, 'queue_full',
    'the post-TTL frame reached the deadline path instead of the serial fence');
  assert.equal(c.journal.events.filter((e) => e.startsWith('wasm')).length, hashesDuring,
    'the post-TTL frame entered block_run and hashed');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING,
    `a post-TTL frame ended the attempt: ${JSON.stringify(c.sent.map((m) => [m.type, m.reason]))}`);

  // The backstop firing now closes admission; it still must not overwrite the claimant.
  const timer = c.timers.find((t) => !t.cleared);
  if (timer) timer.fn();
  assert.equal(c.session.stateFacts.deadlineReached, true);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING);

  release();
  await winner;
  await Promise.resolve();

  assert.equal(c.net.log.submitBodies.length, 1);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE,
    JSON.stringify(c.sent.map((m) => [m.type, m.reason])));
  const terminals = c.sent.filter((m) => m.terminal === true);
  assert.equal(terminals.length, 1);
  assert.equal(terminals[0].type, 'block_accepted');
  assert.equal(c.sent.some((m) => m.reason === 'search_deadline_exceeded'), false);
  assert.equal(c.sent.some((m) => m.type === 'run_stopped'), false);
  assert.equal(c.session.stateFacts.deadlineSettling, 0);
});

test('SHARE DEADLINE: with nothing in flight the bound still ends the run at once', async () => {
  const c = await shareSession();
  scriptVerifier(c, -1);
  await c.say(c.candidate(10));                     // settled before the deadline
  assert.equal(c.all('share_accepted').length, 1);
  assert.equal(c.session.stateFacts.verificationSlotFree, 1);
  const timer = c.timers.find((t) => !t.cleared);
  timer.fn();
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED,
    'an idle share run was not ended by its absolute bound');
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(c.session.stateFacts.deadlineSettling, 0, 'nothing was in flight to wait for');
  assert.equal(c.net.log.submitBodies.length, 0);
});

test('SHARE SERIAL: with NO claim held, a block-path refusal still ends the run', async () => {
  const c = await shareSession({
    chainOptions: { gate: (method) => { if (method === 'calc_pow') throw new Error('scripted daemon A failure'); } },
  });
  const v = c.journal.created.at(-1);
  v.hashWasm = async () => hexToBlob(powFor(1));
  v.hashNative = async () => hexToBlob(powFor(1));
  await c.say(c.candidate(90));
  assert.equal(c.sim.authority.anyClaimed, false, 'the test accidentally claimed the submission');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
  assert.equal(c.last('block_rejected')?.reason, 'daemon_unavailable');
});

test('LEGACY PROFILE: one candidate, and the opt-in dedupe and deadline changes do not reach it', async () => {
  const ctx = await buildScriptedChain({}, { sequenceBlocks: 1 });
  const sim = createSimulationContext({ ...ctx.built, profile: REAL_P2P_PROFILE, now: () => ctx.clock.ms });
  const sent = [];
  const timers = [];
  const session = createSimulationSession({
    sim,
    now: () => ctx.clock.ms,
    send: (o) => sent.push(o),
    setTimer: (fn, ms) => { const t = { fn, ms, cleared: false }; timers.push(t); return t; },
    clearTimer: (t) => { t.cleared = true; },
  });
  const say = async (obj) => {
    const text = JSON.stringify(obj);
    return session.handleRaw(Buffer.byteLength(text), text);
  };
  await say({ type: 'client_hello', protocolVersion: 1 });
  await say({ type: 'start_request', clientStartId: START_ID });
  const ready = [...sent].reverse().find((m) => m.type === 'mining_ready');
  assert.ok(ready);
  const cand = (nonce) => ({
    type: 'submit_real_candidate', clientStartId: START_ID, jobId: ready.jobId,
    issuanceId: ready.issuanceId, workerId: ready.workerId, runGeneration: ready.runGeneration,
    nonce: nonce.toString(16).padStart(8, '0'),
  });
  // The one candidate is held mid-verification so a repeat of its nonce meets the LIMIT, which is
  // the reply this profile has always given -- not the share profile's duplicate_nonce.
  let release;
  const gate = new Promise((r) => { release = r; });
  const v = ctx.journal.created.at(-1);
  v.hashWasm = async () => { await gate; return hashForDifficulty(2n); };
  v.hashNative = async () => hashForDifficulty(2n);

  const held = say(cand(10));
  await Promise.resolve();
  const repeat = await say(cand(10));
  assert.equal(repeat.reason, 'candidate_limit_reached',
    'the opt-in dedupe changed a one-candidate profile reply');
  release();
  await held;
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED,
    'the legacy one-candidate profile no longer ends on its refused candidate');

  // And the legacy late-frame path still reports its own immediate deadline failure.
  const fresh = await buildScriptedChain({}, { sequenceBlocks: 1 });
  const sim2 = createSimulationContext({ ...fresh.built, profile: REAL_P2P_PROFILE, now: () => fresh.clock.ms });
  const sent2 = [];
  const session2 = createSimulationSession({
    sim: sim2,
    now: () => fresh.clock.ms,
    send: (o) => sent2.push(o),
    setTimer: (fn, ms) => ({ fn, ms }),
    clearTimer: () => {},
  });
  const say2 = async (obj) => {
    const text = JSON.stringify(obj);
    return session2.handleRaw(Buffer.byteLength(text), text);
  };
  await say2({ type: 'client_hello', protocolVersion: 1 });
  await say2({ type: 'start_request', clientStartId: START_ID });
  const ready2 = [...sent2].reverse().find((m) => m.type === 'mining_ready');
  fresh.clock.ms += 10 * 60_000;
  const lateLegacy = await say2({
    type: 'submit_real_candidate', clientStartId: START_ID, jobId: ready2.jobId,
    issuanceId: ready2.issuanceId, workerId: ready2.workerId, runGeneration: ready2.runGeneration,
    nonce: '0000000a',
  });
  assert.equal(lateLegacy.reason, 'search_deadline_exceeded', 'the legacy deadline reply changed');
  assert.equal(lateLegacy.terminal, true);
  assert.equal(sim2.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
});

// ---------------------------------------------------------------- the pacing cue (Round 1b seam)
//
// `share_accepted` is emitted from INSIDE block_run, while the candidate is still counted in
// run.inFlight and the serial fence still holds the slot. A client that released its next report on
// that event would be refused `queue_full` every time. `candidate_settled` is emitted only after
// submitCandidate returned AND nothing is in flight, which is the moment the slot is free.

test('SHARE CUE: candidate_settled is emitted after the slot is free, never before the acceptance', async () => {
  const c = await shareSession();
  scriptVerifier(c, -1);                              // every nonce is a share, never a block

  await c.say(c.candidate(10));
  const order = c.sent.map((m) => m.type);
  const acceptedAt = order.indexOf('share_accepted');
  const settledAt = order.indexOf('candidate_settled');
  assert.ok(acceptedAt >= 0, JSON.stringify(order));
  assert.ok(settledAt > acceptedAt, 'the cue was emitted before the acceptance it follows');

  const cue = c.sent[settledAt];
  assert.equal(cue.terminal, false);
  assert.equal(cue.nonce, 10, 'the cue does not name the nonce that settled');
  assert.equal(cue.jobId, c.ready.jobId, 'the cue is not bound to the run');
  assert.equal(cue.issuanceId, c.ready.issuanceId);
  assert.equal(cue.runGeneration, c.ready.runGeneration);
  assert.equal(cue.workerId, c.ready.workerId);
  assert.equal(cue.candidatesAdmitted, 1);
  assert.equal(cue.maxCandidates, REAL_SHARE_LIMITS.maxSharesPerJob);
  // And the slot really is free when the cue goes out: the next report is admitted, not queue_full.
  assert.equal(c.session.stateFacts.verificationSlotFree, 1);
  assert.equal((await c.say(c.candidate(11))).share, true);
  assert.equal(c.all('candidate_settled').length, 2);
});

test('SHARE CUE: it is NOT emitted while the slot is held -- the negative case the client depends on', async () => {
  let enter;
  const entered = new Promise((r) => { enter = r; });
  let release;
  const gate = new Promise((r) => { release = r; });
  let armed = true;
  const c = await shareSession({
    chainOptions: {
      gate: async (method, n, side) => {
        if (side !== 'A' || method !== 'submit_block' || !armed) return;
        armed = false;
        enter();
        await gate;
      },
    },
  });
  const v = c.journal.created.at(-1);
  v.hashWasm = async () => hexToBlob(powFor(1));
  v.hashNative = async () => hexToBlob(powFor(1));

  const winner = c.say(c.candidate(90));
  await entered;                                      // in flight: the slot is HELD
  assert.equal(c.all('candidate_settled').length, 0,
    'a cue was emitted while the verification slot was still held');
  // A client that (wrongly) sent its next report here is refused, which is exactly why the cue
  // must not arrive yet.
  assert.equal((await c.say(c.candidate(91))).reason, 'queue_full');

  release();
  await winner;
  await Promise.resolve();
  // The run ended with the block, so no cue follows: a terminal message supersedes the cue.
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(c.all('candidate_settled').length, 0,
    'a cue was emitted after the attempt was already terminal');
});

test('SHARE CUE: no cue after the deadline closes admission or once the budget is spent', async () => {
  const closed = await shareSession();
  scriptVerifier(closed, -1);
  await closed.say(closed.candidate(10));
  assert.equal(closed.all('candidate_settled').length, 1);
  const timer = closed.timers.find((t) => !t.cleared);
  timer.fn();                                          // the absolute bound closes admission
  assert.equal(closed.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(closed.all('candidate_settled').length, 1, 'a cue followed the closure');

  const spent = await shareSession();
  scriptVerifier(spent, -1);
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) await spent.say(spent.candidate(20 + i));
  assert.equal(spent.all('share_accepted').length, REAL_SHARE_LIMITS.maxSharesPerJob);
  // The last settlement spends the budget, so there is nothing left to invite: no cue for it.
  assert.equal(spent.all('candidate_settled').length, REAL_SHARE_LIMITS.maxSharesPerJob - 1,
    'the server invited a report it would have refused');
  assert.equal(spent.last('run_stopped')?.reason, 'search_bound_reached',
    'the last share did not end the bounded no-block search');
});

test('SHARE CUE: the legacy one-candidate profile emits no cue at all', async () => {
  const ctx = await buildScriptedChain({}, { sequenceBlocks: 1 });
  const sim = createSimulationContext({ ...ctx.built, profile: REAL_P2P_PROFILE, now: () => ctx.clock.ms });
  const sent = [];
  const session = createSimulationSession({
    sim,
    now: () => ctx.clock.ms,
    send: (o) => sent.push(o),
    setTimer: (fn, ms) => ({ fn, ms }),
    clearTimer: () => {},
  });
  const say = async (obj) => {
    const text = JSON.stringify(obj);
    return session.handleRaw(Buffer.byteLength(text), text);
  };
  await say({ type: 'client_hello', protocolVersion: 1 });
  await say({ type: 'start_request', clientStartId: START_ID });
  const ready = [...sent].reverse().find((m) => m.type === 'mining_ready');
  const v = ctx.journal.created.at(-1);
  v.hashWasm = async () => hexToBlob(powFor(1));
  v.hashNative = async () => hexToBlob(powFor(1));
  await say({
    type: 'submit_real_candidate', clientStartId: START_ID, jobId: ready.jobId,
    issuanceId: ready.issuanceId, workerId: ready.workerId, runGeneration: ready.runGeneration,
    nonce: '0000005a',
  });
  assert.equal(sent.some((m) => m.type === 'candidate_settled'), false,
    'the legacy profile gained a share-mode cue');
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
});

test('SHARE JOB: the client message projects the share target only for an opted-in job', async () => {
  const shared = await shareSession();
  const job = shared.sent.find((m) => m.type === 'real_job');
  assert.equal(job.shareWork, true);
  assert.equal(job.shareTargetHexLE, shared.sim.job.shareTargetHexLE);
  assert.equal(job.targetHexLE, shared.sim.job.targetHexLE, 'the block target must still be sent');
  assert.equal(leBytes32ToBigInt(hexToBlob(job.shareTargetHexLE))
    >= leBytes32ToBigInt(hexToBlob(job.targetHexLE)), true,
  'the projected share target is harder than the block target');

  const ctx = await buildScriptedChain({}, { sequenceBlocks: 1 });
  const sim = createSimulationContext({ ...ctx.built, profile: REAL_P2P_PROFILE, now: () => ctx.clock.ms });
  const sent = [];
  const session = createSimulationSession({
    sim, now: () => ctx.clock.ms, send: (o) => sent.push(o),
    setTimer: (fn, ms) => ({ fn, ms }), clearTimer: () => {},
  });
  const text = JSON.stringify({ type: 'client_hello', protocolVersion: 1 });
  await session.handleRaw(Buffer.byteLength(text), text);
  const legacyJob = sent.find((m) => m.type === 'real_job');
  assert.equal('shareWork' in legacyJob, false, 'a legacy job message gained a share field');
  assert.equal('shareTargetHexLE' in legacyJob, false);
});
