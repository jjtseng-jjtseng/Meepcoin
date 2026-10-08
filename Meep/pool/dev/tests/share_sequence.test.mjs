// THE FINITE SEQUENCE WITH OPT-IN SHARE WORK: two consecutive heights under ONE Start, each with
// its own share budget, its own replay set and its own single submission.
//
// NOTHING LIVE IS IN THIS FILE. Two in-memory daemons with a real little chain sit behind the real
// daemon_rpc adapters; the verifiers are scripted, context-bound objects. No WSL, Docker, daemon,
// helper, browser, listener, socket, wallet or network exists here. The session, block_run, the
// template authority, the fatal latch, the run intent and the profile are the real ones.
//
// WHAT THIS ROUND ADDS is only the composition: share work per template inside the sequence that
// already existed. Every rule of each feature is meant to survive unchanged, so most assertions
// below are about things NOT happening -- no daemon call for a share, no second submission per
// height, no rotation before the previous verifier is confirmed released, no work after Stop.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SIM_ATTEMPT_STATES, createSimulationContext, createSimulationSession, realSequenceProfile,
  realSequenceShareProfile,
} from '../sim_session.mjs';
import { MAX_256, bigIntToLeBytes32 } from '../difficulty.mjs';
import { hexToBlob } from '../block_blob.mjs';
import { buildScriptedChain, powFor } from './in_memory_chain.mjs';
import { REAL_SHARE_LIMITS } from '../../../web-miner/lib/shared/protocol.js';

const START_ID = '0123456789abcdef0123456789abcdef';
const SHARE_DIFFICULTY = 50;            // the chain's fixed block difficulty is 500
const WRITE_METHODS = ['submit_block', 'calc_pow', 'get_block_template'];

/** Meets the share target (difficulty 50) and NOT the block target (difficulty 500). */
const SHARE_ONLY = bigIntToLeBytes32(MAX_256 / 100n);

/**
 * One session over a share-enabled sequence, with every verifier scripted per height: the nonce
 * named for that height hashes to exactly what daemon A's calc_pow will answer (a block), and every
 * other nonce hashes to a share-quality value that meets the share target only.
 */
async function shareSequence({ blocks = 2, blockNonceFor = () => 90, chainOptions = {} } = {}) {
  const ctx = await buildScriptedChain(chainOptions, {
    sequenceBlocks: blocks, shareDifficulty: SHARE_DIFFICULTY,
  });
  const sim = createSimulationContext({
    ...ctx.built,
    profile: realSequenceShareProfile(blocks),
    now: () => ctx.clock.ms,
  });
  // Script each verifier as it is created, so height 2's verifier is scripted too.
  const scripted = new Set();
  const scriptAll = () => {
    for (const v of ctx.journal.created) {
      if (scripted.has(v)) continue;
      scripted.add(v);
      const height = Number(v.context.height);
      const answer = (n) => (n === blockNonceFor(height) ? hexToBlob(powFor(height)) : SHARE_ONLY);
      v.hashWasm = async (n) => { v.counters.wasmShareHashes += 1; return answer(n); };
      v.hashNative = async (n) => { v.counters.nativeShareHashes += 1; return answer(n); };
    }
  };
  const sent = [];
  const timers = [];
  const session = createSimulationSession({
    sim,
    now: () => ctx.clock.ms,
    send: (o) => { sent.push(o); scriptAll(); },
    setTimer: (fn, ms) => { const t = { fn, ms, cleared: false }; timers.push(t); return t; },
    clearTimer: (t) => { t.cleared = true; },
  });
  const say = async (obj) => {
    const text = JSON.stringify(obj);
    const r = await session.handleRaw(Buffer.byteLength(text), text);
    scriptAll();
    return r;
  };
  await say({ type: 'client_hello', protocolVersion: 1 });
  await say({ type: 'start_request', clientStartId: START_ID });
  scriptAll();
  const last = (type) => [...sent].reverse().find((m) => m.type === type);
  const all = (type) => sent.filter((m) => m.type === type);
  const candidate = (ready, nonce, over = {}) => ({
    type: 'submit_real_candidate',
    clientStartId: START_ID,
    jobId: ready.jobId,
    issuanceId: ready.issuanceId,
    workerId: ready.workerId,
    runGeneration: ready.runGeneration,
    nonce: nonce.toString(16).padStart(8, '0'),
    ...over,
  });
  return { ...ctx, sim, session, sent, timers, say, last, all, candidate, ready1: last('mining_ready') };
}

const hashCount = (journal) => journal.created.reduce(
  (n, v) => n + v.counters.wasmShareHashes + v.counters.nativeShareHashes, 0,
);

// ================================================================== the whole composed session
test('SHARE SEQUENCE: one Start, two heights, ordinary shares and one block each, one submission per height', async () => {
  const c = await shareSequence();
  const { sim, net, journal } = c;

  // ---- height 1: two ordinary shares, then the block ------------------------------------------
  assert.equal(sim.job.height, 1n);
  assert.equal(sim.job.shareWork, true, 'the sequence template carries no share target');
  assert.equal(c.ready1.sequenceIndex, 1);
  await c.say(c.candidate(c.ready1, 10));
  await c.say(c.candidate(c.ready1, 11));
  const shares1 = c.all('share_accepted');
  assert.equal(shares1.length, 2, JSON.stringify(c.sent.map((m) => [m.type, m.reason])));
  assert.deepEqual(shares1.map((s) => s.sharesAccepted), [1, 2], 'the per-template count is wrong');
  assert.deepEqual(shares1.map((s) => s.sharesAcceptedTotal), [1, 2]);
  assert.deepEqual(shares1.map((s) => s.sequenceIndex), [1, 1]);
  assert.equal(shares1[0].terminal, false, 'a share ended the run');
  // A SHARE COSTS THE DAEMONS NOTHING.
  assert.equal(net.log.calcPow.length, 0, 'an ordinary share reached daemon A');
  assert.equal(net.log.submitBodies.length, 0);
  assert.equal(sim.authority.anyClaimed, false);
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.RUNNING);

  await c.say(c.candidate(c.ready1, 90));
  const acc1 = c.all('sequence_block_accepted')[0];
  assert.ok(acc1, JSON.stringify(c.sent.map((m) => [m.type, m.reason])));
  assert.equal(acc1.terminal, false);
  assert.equal(acc1.height, '1');
  assert.equal(acc1.nonce, 90);
  assert.equal(acc1.blockId, net.blocksA[1].hash);
  assert.equal(net.log.calcPow.length, 1, 'exactly one calc_pow for the block');
  assert.equal(net.log.submitBodies.length, 1, 'exactly one submission for height 1');

  // ---- the rotation, on the sequence's own unchanged terms --------------------------------------
  const next = c.last('sequence_next');
  assert.ok(next, 'no rotation');
  assert.equal(next.sequenceIndex, 2);
  assert.equal(next.job.height, '2');
  assert.equal(sim.job.height, 2n);
  assert.equal(sim.job.shareWork, true, 'the second template lost its share target');
  assert.equal(sim.job.shareTargetHexLE, next.job.shareTargetHexLE);
  assert.notEqual(sim.job.jobId, c.ready1.jobId);
  assert.equal(sim.authority.isSuperseded(c.ready1.issuanceId), true);
  // The height-1 verifier was CONFIRMED released before the height-2 verifier was created.
  const closed1 = journal.events.indexOf('closed 1');
  const created2 = journal.events.findIndex((e) => e.startsWith('created 2'));
  assert.ok(closed1 >= 0 && created2 > closed1, journal.events.join(' | '));
  assert.equal(journal.created.length, 2, 'more than one verifier per height');
  const ready2 = c.last('mining_ready');
  assert.equal(ready2.sequenceIndex, 2);
  assert.ok(ready2.runGeneration > c.ready1.runGeneration);

  // ---- height 2: its own fresh share budget and its own block ----------------------------------
  const facts = c.session.stateFacts;
  assert.equal(facts.sharesAccepted, 0, 'the new template inherited the old one\'s share count');
  assert.equal(facts.sharesAcceptedTotal, 2, 'the cumulative count was reset by the rotation');
  assert.equal(facts.admittedNonces, 0, 'the replay set survived the rotation');
  assert.equal(facts.candidatesAdmittedThisBlock, 0);

  // The SAME nonces are usable again at the new height: they name a different template.
  await c.say(c.candidate(ready2, 10));
  await c.say(c.candidate(ready2, 11));
  const shares2 = c.all('share_accepted').slice(2);
  assert.equal(shares2.length, 2, 'height 2 refused nonces that belong to its own window');
  assert.deepEqual(shares2.map((s) => s.sharesAccepted), [1, 2], 'the per-template count did not restart');
  assert.deepEqual(shares2.map((s) => s.sharesAcceptedTotal), [3, 4], 'the cumulative count did not continue');
  assert.deepEqual(shares2.map((s) => s.sequenceIndex), [2, 2]);
  assert.equal(net.log.calcPow.length, 1, 'a height-2 share reached daemon A');

  await c.say(c.candidate(ready2, 90));
  const done = c.last('block_accepted');
  assert.ok(done, JSON.stringify(c.sent.map((m) => [m.type, m.reason])));
  assert.equal(done.terminal, true);
  assert.equal(done.height, '2');
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(net.log.calcPow.length, 2, 'one calc_pow per height, no more');
  assert.equal(net.log.submitBodies.length, 2, 'one submission per height, no more');
  assert.equal(sim.authority.claimCount, 2);

  // NOTHING WAS EVER SENT TO DAEMON B. It is read-only in this run, shares included.
  assert.deepEqual(Object.keys(net.rpcCountsB ?? {}).filter((m) => WRITE_METHODS.includes(m)), []);
  // One Start, one run per height, no extra worker context.
  assert.equal(c.all('run_started').length, 1, 'a second Start');
  assert.equal(c.all('mining_ready').length, 2);
  assert.equal(c.session.stateFacts.sharesAcceptedTotal, 4);
});

// ================================================================== bounds that must not leak
test('SHARE SEQUENCE: each height gets its own share budget, and the budget is not shared', async () => {
  const c = await shareSequence();
  // Spend the whole height-1 budget on ordinary shares. The last settled share closes this
  // no-block attempt immediately; it must not idle until the 150-second backstop or rotate.
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) {
    await c.say(c.candidate(c.ready1, 100 + i));
  }
  assert.equal(c.all('share_accepted').length, REAL_SHARE_LIMITS.maxSharesPerJob);
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  const refused = await c.say(c.candidate(c.ready1, 200));
  assert.notEqual(refused.reason, undefined);
  assert.equal(c.all('sequence_next').length, 0);
  // The block still fits nowhere: the budget is spent for this template, so nothing is submitted.
  assert.equal(c.net.log.submitBodies.length, 0);
  assert.equal(c.net.log.calcPow.length, 0);
});

test('SHARE SEQUENCE: both templates can use their full independent eight-result budgets', async () => {
  const c = await shareSequence();
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob - 1; i += 1) {
    await c.say(c.candidate(c.ready1, 100 + i));
  }
  await c.say(c.candidate(c.ready1, 90)); // eighth result is the first block
  const ready2 = c.last('mining_ready');
  assert.equal(ready2.sequenceIndex, 2);
  assert.equal(c.session.stateFacts.candidatesAdmittedThisBlock, 0);
  assert.equal(c.session.stateFacts.sharesAccepted, 0);
  assert.equal(c.session.stateFacts.sharesAcceptedTotal, REAL_SHARE_LIMITS.maxSharesPerJob - 1);
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob - 1; i += 1) {
    await c.say(c.candidate(ready2, 100 + i)); // same nonce set, new template
  }
  assert.equal(c.session.stateFacts.candidatesAdmittedThisBlock, REAL_SHARE_LIMITS.maxSharesPerJob - 1);
  assert.equal(c.session.stateFacts.sharesAccepted, REAL_SHARE_LIMITS.maxSharesPerJob - 1);
  await c.say(c.candidate(ready2, 90));
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(c.all('share_accepted').length, 2 * (REAL_SHARE_LIMITS.maxSharesPerJob - 1));
  assert.equal(c.net.log.submitBodies.length, 2);
  assert.equal(c.net.log.calcPow.length, 2);
});

test('SHARE SEQUENCE: a deadline during the eighth block candidate cannot erase its acceptance', async () => {
  let releaseCalc;
  const heldCalc = new Promise((resolve) => { releaseCalc = resolve; });
  const c = await shareSequence({ chainOptions: {
    gate: (method, _n, side) => (side === 'A' && method === 'calc_pow' ? heldCalc : undefined),
  } });
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob - 1; i += 1) {
    await c.say(c.candidate(c.ready1, 100 + i));
  }
  const candidate = c.say(c.candidate(c.ready1, 90)); // eighth admission, block quality
  let calcStarted = false;
  for (let i = 0; i < 40; i += 1) {
    calcStarted = c.net.log.A.includes('calc_pow');
    if (calcStarted) break;
    await new Promise((resolve) => setImmediate(resolve));
  }
  const timer = c.timers.find((t) => !t.cleared);
  try {
    assert.equal(calcStarted, true, 'the block candidate did not reach daemon A');
    assert.ok(timer, 'the share search backstop was not armed');
    timer.fn(); // admission closes while this block's daemon answer is still in flight
    assert.equal(c.session.stateFacts.deadlineReached, true);
  } finally {
    releaseCalc();
  }
  await candidate;
  assert.equal(c.all('sequence_block_accepted').length, 1);
  assert.equal(c.last('sequence_next')?.sequenceIndex, 2);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING);
  assert.equal(c.all('run_stopped').length, 0, 'the backstop overwrote the accepted block');
});

test('SHARE SEQUENCE: a duplicate nonce is refused per template, and the refusal costs no hash', async () => {
  const c = await shareSequence();
  await c.say(c.candidate(c.ready1, 10));
  const hashesAfterFirst = hashCount(c.journal);
  const dup = await c.say(c.candidate(c.ready1, 10));
  assert.equal(dup.reason, 'duplicate_nonce');
  assert.equal(hashCount(c.journal), hashesAfterFirst, 'a duplicate nonce was hashed again');
  assert.equal(c.all('share_accepted').length, 1);
});

test('SHARE SEQUENCE: a stale old-job or old-generation share is refused before any hash', async () => {
  const c = await shareSequence();
  await c.say(c.candidate(c.ready1, 90));            // height 1's block; rotation follows
  const ready2 = c.last('mining_ready');
  assert.equal(ready2.sequenceIndex, 2);
  const before = hashCount(c.journal);
  const beforeShares = c.all('share_accepted').length;

  // The OLD template's binding, replayed after the rotation.
  const stale = await c.say(c.candidate(c.ready1, 12));
  assert.notEqual(stale.reason, undefined, 'a stale-job share was accepted');
  // The new template's job, with the old run generation.
  const oldGen = await c.say(c.candidate(ready2, 13, { runGeneration: c.ready1.runGeneration }));
  assert.notEqual(oldGen.reason, undefined, 'an old-generation share was accepted');
  // A nonce outside the issued window.
  const outside = await c.say(c.candidate(ready2, c.sim.job.nonceStart + c.sim.job.nonceRange + 5));
  assert.notEqual(outside.reason, undefined, 'a share outside the window was accepted');

  assert.equal(hashCount(c.journal), before, 'a stale or malformed share was hashed');
  assert.equal(c.all('share_accepted').length, beforeShares, 'a stale share was announced as accepted');
  assert.equal(c.net.log.calcPow.length, 1, 'a refused share reached daemon A');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING);
});

test('SHARE SEQUENCE: Stop after the first block prevents the second height entirely', async () => {
  const c = await shareSequence();
  await c.say(c.candidate(c.ready1, 10));            // an ordinary share first
  await c.say(c.candidate(c.ready1, 90));            // the block, then the rotation
  const ready2 = c.last('mining_ready');
  const verifiersBefore = c.journal.created.length;

  await c.say({
    type: 'stop_request', clientStartId: START_ID, workerId: ready2.workerId,
    runGeneration: ready2.runGeneration, jobId: ready2.jobId, issuanceId: ready2.issuanceId,
    reason: 'user_stop',
  });
  assert.equal(c.sim.attemptFinished, true);

  const submitsBefore = c.net.log.submitBodies.length;
  const hashesBefore = hashCount(c.journal);
  const afterStop = await c.say(c.candidate(ready2, 90));
  assert.notEqual(afterStop.reason, undefined, 'a candidate was admitted after Stop');
  assert.equal(c.net.log.submitBodies.length, submitsBefore, 'a submission happened after Stop');
  assert.equal(hashCount(c.journal), hashesBefore, 'a hash happened after Stop');
  assert.equal(c.journal.created.length, verifiersBefore, 'a verifier was created after Stop');
  assert.equal(c.all('mining_ready').length, 2, 'the session offered more work after Stop');
});

test('SHARE SEQUENCE: a disconnect after the first block ends the session and starts no second height', async () => {
  const c = await shareSequence();
  await c.say(c.candidate(c.ready1, 90));
  const ready2 = c.last('mining_ready');
  const verifiers = c.journal.created.length;
  c.session.dispose();
  const submits = c.net.log.submitBodies.length;
  const hashes = hashCount(c.journal);
  await c.say(c.candidate(ready2, 90));
  assert.equal(c.net.log.submitBodies.length, submits, 'a disposed session submitted');
  assert.equal(hashCount(c.journal), hashes, 'a disposed session hashed');
  assert.equal(c.journal.created.length, verifiers);
});

test('SHARE SEQUENCE: hiding the page on height 2 ends consent and admits no later share', async () => {
  const c = await shareSequence();
  await c.say(c.candidate(c.ready1, 90));
  const ready2 = c.last('mining_ready');
  const before = { hashes: hashCount(c.journal), submits: c.net.log.submitBodies.length };
  const stopped = await c.say({
    type: 'stop_request', clientStartId: START_ID, workerId: ready2.workerId,
    runGeneration: ready2.runGeneration, jobId: ready2.jobId, issuanceId: ready2.issuanceId,
    reason: 'page_hidden',
  });
  assert.equal(stopped.accepted, true);
  await c.say(c.candidate(ready2, 10));
  assert.equal(hashCount(c.journal), before.hashes);
  assert.equal(c.net.log.submitBodies.length, before.submits);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
});

test('SHARE SEQUENCE: an external canonical tip supersedes old share work and starts a fresh height', async () => {
  const c = await shareSequence();
  await c.say(c.candidate(c.ready1, 10));
  const foreign = {
    hash: 'a'.repeat(64), height: 1, nonce: 4242,
    powHash: powFor(1), prevHash: c.net.blocksA[0].hash,
  };
  c.net.blocksA.push(foreign); // the injected daemon's canonical chain, not a network action
  const moved = await c.sim.notifyExternalTip({ height: '1', blockId: foreign.hash });
  assert.equal(moved.ok, true, JSON.stringify(moved));
  const ready2 = c.last('mining_ready');
  assert.equal(c.last('sequence_next').cause, 'external_tip');
  assert.equal(ready2.sequenceIndex, 2);
  assert.equal(c.session.stateFacts.sharesAccepted, 0);
  assert.equal(c.session.stateFacts.sharesAcceptedTotal, 1);
  const hashesBefore = hashCount(c.journal);
  await c.say(c.candidate(c.ready1, 11));
  assert.equal(hashCount(c.journal), hashesBefore, 'old share work was hashed after supersession');
  await c.say(c.candidate(ready2, 10)); // the old nonce is valid again for the new job
  assert.equal(c.last('share_accepted').sequenceIndex, 2);
  assert.equal(c.session.stateFacts.sharesAccepted, 1);
  assert.equal(c.net.log.calcPow.length, 0, 'an ordinary share reached daemon A');
  assert.equal(c.net.log.submitBodies.length, 0);
});

// ================================================================== the profile's own truth
test('SHARE SEQUENCE PROFILE: the text states both the sequence length and the per-template budget', () => {
  const two = realSequenceShareProfile(2);
  const plain = realSequenceProfile(2);
  assert.equal(two.shareWork, true);
  assert.equal(plain.shareWork, undefined, 'the plain sequence profile gained share work');
  assert.equal(two.maxCandidates, REAL_SHARE_LIMITS.maxSharesPerJob);
  assert.equal(two.maxInvalidCandidates, REAL_SHARE_LIMITS.maxInvalidCandidates);
  assert.equal(two.sequenceBlocks, 2);
  assert.match(two.helloNotice, /TWO \(2\) consecutive positions/);
  assert.match(two.helloNotice, new RegExp(`verify up to ${REAL_SHARE_LIMITS.maxSharesPerJob} results, one at a time`));
  assert.match(two.helloNotice, /nothing is sent to a daemon for it/);
  assert.match(two.readyNotice, /at most one block submission for this height/);
  assert.ok(two.labels.some((l) => l.includes(`UP TO ${REAL_SHARE_LIMITS.maxSharesPerJob} VERIFIED RESULTS PER TEMPLATE`)));
  assert.ok(two.labels.some((l) => l.includes('AT MOST ONE BLOCK SUBMISSION PER HEIGHT')));
  // A length of three says three, never two.
  const three = realSequenceShareProfile(3);
  assert.match(three.helloNotice, /THREE \(3\) consecutive positions/);
  assert.equal(/TWO \(2\)/.test(three.helloNotice), false);
  assert.throws(() => realSequenceShareProfile(1), TypeError);
});
