// THE OPT-IN SAME-HEIGHT REFRESH: one explicit Start, ONE height, several nonce windows.
//
// This is not the development sequence and it is not a pool. Nothing here advances a height,
// nothing here needs an accepted block, and nothing here may run once a submission was claimed: a
// window that is exhausted with nothing submitted, on daemon A's UNCHANGED canonical tip, may be
// replaced by ANOTHER window of the same template -- a fresh job and issuance over a nonce range
// that provably does not overlap one already searched -- up to a small fixed total and inside one
// fixed wall-clock budget.
//
// NOTHING LIVE IS IN THIS FILE. Two in-memory daemons with a real little chain sit behind the real
// daemon_rpc adapters; the verifiers are scripted, context-bound objects. No WSL, Docker, daemon,
// helper, browser, listener, socket, wallet or network exists here. The session, block_run, the
// template authority, the fatal latch, the run intent and the profile are the real ones.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  REAL_P2P_SHARE_PROFILE, SIM_ATTEMPT_STATES, createSimulationContext, createSimulationSession,
  realRefreshProfile,
} from '../sim_session.mjs';
import { MAX_256, bigIntToLeBytes32 } from '../difficulty.mjs';
import { hexToBlob } from '../block_blob.mjs';
import { buildScriptedChain, powFor } from './in_memory_chain.mjs';
import {
  REAL_MAX_CONTEXTS_PER_START, REAL_REFRESH_LIMITS, REAL_SEARCH_LIMITS,
  REAL_SHARE_LIMITS,
} from '../../../web-miner/lib/shared/protocol.js';

const START_ID = '0123456789abcdef0123456789abcdef';
const SHARE_DIFFICULTY = 50;             // the chain's fixed block difficulty is 500
const WRITE_METHODS = ['submit_block', 'calc_pow', 'get_block_template'];
/** Meets the share target (difficulty 50) and NOT the block target (difficulty 500). */
const SHARE_ONLY = bigIntToLeBytes32(MAX_256 / 100n);

/**
 * One session over a refresh-enabled run. Every verifier is scripted as it is created: the nonce
 * named `blockNonce` hashes to exactly what daemon A's calc_pow will answer (a block); every other
 * nonce hashes to a share-quality value, or -- without share work -- to the same block answer only
 * for that one nonce, so an ordinary search simply finds nothing.
 */
async function refreshRun({
  windows = 3, shareWork = true, shareDifficulty = SHARE_DIFFICULTY,
  blockNonce = -1, chainOptions = {}, buildOptions = {},
  startImmediately = true,
} = {}) {
  const ctx = await buildScriptedChain(chainOptions, {
    sequenceBlocks: 1,
    refreshWindows: windows,
    ...(shareWork ? { shareDifficulty } : {}),
    ...buildOptions,
  });
  const sim = createSimulationContext({
    ...ctx.built,
    profile: realRefreshProfile(windows, { shareWork }),
    now: () => ctx.clock.ms,
  });
  const scripted = new Set();
  const scriptAll = () => {
    for (const v of ctx.journal.created) {
      if (scripted.has(v)) continue;
      scripted.add(v);
      const height = Number(v.context.height);
      const answer = (n) => (n === blockNonce ? hexToBlob(powFor(height)) : SHARE_ONLY);
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
  const start = () => say({ type: 'start_request', clientStartId: START_ID });
  if (startImmediately) await start();
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
  /** Fire the one live search backstop, which is how an ordinary exhausted window is noticed. */
  const fired = new Set();
  const fireBackstop = async () => {
    const t = [...timers].reverse().find((x) => !x.cleared && !fired.has(x));
    assert.ok(t, 'no live search backstop');
    fired.add(t);
    t.fn();
    for (let i = 0; i < 40; i += 1) await new Promise((r) => setImmediate(r));
  };
  const settle = async () => { for (let i = 0; i < 40; i += 1) await new Promise((r) => setImmediate(r)); };
  return {
    ...ctx, sim, session, sent, timers, say, start, last, all, candidate, fireBackstop, settle,
    ready1: last('mining_ready'),
  };
}

const hashCount = (journal) => journal.created.reduce(
  (n, v) => n + v.counters.wasmShareHashes + v.counters.nativeShareHashes, 0,
);

test('REFRESH ALLOCATION CLOCK: records are stamped only at the one factory invocation', async () => {
  const ctx = await buildScriptedChain({}, {
    sequenceBlocks: 1,
    refreshWindows: 2,
    shareDifficulty: SHARE_DIFFICULTY,
  });
  const invokeFactory = ctx.built.makeServerVerifier;
  const factoryStartedAt = [];
  let sim;
  sim = createSimulationContext({
    ...ctx.built,
    profile: realRefreshProfile(2, { shareWork: true }),
    now: () => ctx.clock.ms,
    makeServerVerifier: (options) => {
      factoryStartedAt.push(ctx.clock.ms);
      assert.equal(sim.windowRecords.at(-1).verifierAllocationStartedAtMs, ctx.clock.ms,
        'the record was not stamped immediately before the factory invocation');
      return invokeFactory(options);
    },
  });

  // Construction and reservation are not allocation, so the first record starts honestly unknown.
  const initialJob = sim.job;
  const initialRecord = sim.windowRecords[0];
  assert.equal(initialRecord.verifierAllocationStartedAtMs, null);
  assert.equal(Object.isFrozen(initialRecord), true, 'a window-record readout is externally mutable');
  assert.deepEqual({
    height: initialRecord.height,
    shareDifficulty: initialRecord.shareDifficulty,
    blockDifficulty: initialRecord.blockDifficulty,
    shareTargetHexLE: initialRecord.shareTargetHexLE,
    blockTargetHexLE: initialRecord.blockTargetHexLE,
  }, {
    height: initialJob.height,
    shareDifficulty: initialJob.shareDifficulty,
    blockDifficulty: initialJob.difficulty,
    shareTargetHexLE: initialJob.shareTargetHexLE,
    blockTargetHexLE: initialJob.targetHexLE,
  });
  assert.throws(() => { initialRecord.height = 999n; }, TypeError,
    'a caller could rewrite a server-owned issuance fact');
  const owner = {};
  assert.equal(sim.reserveAttempt({ owner, clientStartId: START_ID }).ok, true);
  assert.equal(sim.windowRecords[0].verifierAllocationStartedAtMs, null);

  ctx.clock.ms = 1_000_111;
  const first = sim.ensureServerVerifier();
  const firstDuplicate = sim.ensureServerVerifier();
  assert.strictEqual(firstDuplicate, first, 'concurrent ensure calls did not join the single flight');
  await first;
  assert.deepEqual(factoryStartedAt, [1_000_111]);
  assert.equal(sim.windowRecords[0].verifierAllocationStartedAtMs, 1_000_111);
  ctx.clock.ms = 1_000_222;
  await sim.ensureServerVerifier();
  assert.deepEqual(factoryStartedAt, [1_000_111], 'a duplicate ensure invoked the factory again');
  assert.equal(sim.windowRecords[0].verifierAllocationStartedAtMs, 1_000_111,
    'a duplicate ensure overwrote the first window stamp');

  await sim.releaseVerifierForRotation(owner, 'allocation-clock test handover');
  ctx.clock.ms = 1_000_333;
  await sim.issueRefreshWindow(owner);
  assert.deepEqual(sim.windowRecords.map((w) => w.verifierAllocationStartedAtMs), [1_000_111, null],
    'successor adoption was misreported as allocation');
  const successorRecord = sim.windowRecords[1];
  assert.equal(Object.isFrozen(successorRecord), true);
  assert.deepEqual({
    height: successorRecord.height,
    shareDifficulty: successorRecord.shareDifficulty,
    blockDifficulty: successorRecord.blockDifficulty,
    shareTargetHexLE: successorRecord.shareTargetHexLE,
    blockTargetHexLE: successorRecord.blockTargetHexLE,
  }, {
    height: sim.job.height,
    shareDifficulty: sim.job.shareDifficulty,
    blockDifficulty: sim.job.difficulty,
    shareTargetHexLE: sim.job.shareTargetHexLE,
    blockTargetHexLE: sim.job.targetHexLE,
  });
  assert.deepEqual(factoryStartedAt, [1_000_111]);

  ctx.clock.ms = 1_000_444;
  const second = sim.ensureServerVerifier();
  const secondDuplicate = sim.ensureServerVerifier();
  assert.strictEqual(secondDuplicate, second, 'successor ensure calls did not join the single flight');
  await second;
  assert.deepEqual(factoryStartedAt, [1_000_111, 1_000_444]);
  assert.deepEqual(sim.windowRecords.map((w) => w.verifierAllocationStartedAtMs), [1_000_111, 1_000_444]);
  ctx.clock.ms = 1_000_555;
  await sim.ensureServerVerifier();
  assert.deepEqual(factoryStartedAt, [1_000_111, 1_000_444]);
  assert.equal(sim.windowRecords[1].verifierAllocationStartedAtMs, 1_000_444,
    'a duplicate successor ensure overwrote the actual factory-start stamp');
});

// ================================================================== the normal refresh
test('REFRESH: an exhausted share window is replaced by another window of the SAME height', async () => {
  const c = await refreshRun({ windows: 3 });
  const { sim, net, journal } = c;
  assert.equal(c.ready1.windowIndex, 1);
  assert.equal(c.ready1.windowTotal, 3);
  assert.equal(sim.job.height, 1n);
  const job1 = sim.job;

  // Spend the whole window's share budget: eight verified non-block results.
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) {
    await c.say(c.candidate(c.ready1, 100 + i));
  }
  await c.settle();
  assert.equal(c.all('share_accepted').length, REAL_SHARE_LIMITS.maxSharesPerJob);

  // THE EXHAUSTED WINDOW DID NOT END THE SESSION.
  assert.equal(c.all('run_stopped').length, 0, JSON.stringify(c.sent.map((m) => [m.type, m.reason])));
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.RUNNING);
  const refresh = c.last('job_refresh');
  assert.ok(refresh, 'no refresh was issued');
  assert.equal(refresh.terminal, false);
  assert.equal(refresh.cause, 'window_exhausted');
  assert.equal(refresh.windowIndex, 2);
  assert.equal(refresh.windowTotal, 3);
  assert.deepEqual(refresh.previous, {
    jobId: c.ready1.jobId, issuanceId: c.ready1.issuanceId, runGeneration: c.ready1.runGeneration,
  });
  assert.equal(refresh.clientStartId, START_ID);
  assert.equal(refresh.workerId, c.ready1.workerId);
  assert.ok(refresh.runGeneration > c.ready1.runGeneration);

  // SAME HEIGHT, NEW CAPABILITY, DISJOINT WINDOW.
  const job2 = sim.job;
  assert.equal(job2.height, job1.height, 'the refresh moved to another height');
  assert.notEqual(job2.jobId, job1.jobId);
  assert.notEqual(job2.issuanceId, job1.issuanceId);
  assert.equal(job2.nonceStart, job1.nonceStart + job1.nonceRange);
  assert.equal(refresh.job.nonceStart, job2.nonceStart);
  assert.equal(sim.authority.isSuperseded(job1.issuanceId), true, 'the old issuance is still live');
  assert.equal(sim.authority.isCurrent(job2.issuanceId), true);
  assert.equal(sim.authority.anyClaimed, false);
  assert.equal(sim.windowIndex, 2);

  // ONE VERIFIER AT A TIME, the previous one CONFIRMED released before the next was created.
  const closed1 = journal.events.indexOf('closed 1');
  const created2 = journal.events.findIndex((e) => e.startsWith('created 2'));
  assert.ok(closed1 >= 0 && created2 > closed1, journal.events.join(' | '));
  assert.equal(journal.created.length, 2, 'more than one verifier per window');
  assert.equal(journal.created[1].context.height, '1', 'the new context is not the same height');

  // PER-WINDOW COUNTERS RESET; CUMULATIVE EVIDENCE KEPT.
  const facts = c.session.stateFacts;
  assert.equal(facts.sharesAccepted, 0);
  assert.equal(facts.sharesAcceptedTotal, REAL_SHARE_LIMITS.maxSharesPerJob);
  assert.equal(facts.candidatesAdmittedThisBlock, 0);
  assert.equal(facts.admittedNonces, 0);
  assert.equal(facts.windowIndex, 2);
  assert.equal(facts.windowTotal, 3);
  assert.equal(facts.refreshesDone, 1);
  assert.deepEqual(sim.windowRecords.map((w) => w.window), [1, 2]);
  assert.deepEqual(sim.windowRecords.map((w) => w.nonceStart), [0, REAL_SEARCH_LIMITS.maxAttempts]);
  // THE PERSISTED PER-WINDOW FACTS: the retired window's own counters and its cause survive the
  // rotation, and each window record carries its literal verifier-factory-start reading. The release
  // reading of the predecessor is no later than the successor's actual allocation start.
  assert.deepEqual(facts.windowOutcomes, [{
    block: 1, window: 1, outcome: 'window_exhausted',
    sharesAccepted: REAL_SHARE_LIMITS.maxSharesPerJob,
    candidatesAdmitted: REAL_SHARE_LIMITS.maxSharesPerJob,
    invalidCandidates: 0,
  }]);
  assert.equal(sim.windowRecords.every((w) => Number.isSafeInteger(w.verifierAllocationStartedAtMs)), true,
    'a window record lacks its verifier-allocation-start reading');
  const [record1, record2] = sim.windowRecords;
  const release1 = sim.verifierHistory[0];
  assert.ok(release1 && Number.isSafeInteger(release1.releasedAtMs));
  assert.ok(release1.releasedAtMs <= record2.verifierAllocationStartedAtMs,
    'the predecessor was released after its successor was allocated');
  assert.ok(record1.verifierAllocationStartedAtMs <= release1.releasedAtMs,
    'window 1 was allocated after its own verifier was released');

  // NO DAEMON WORK FOR ANY OF IT, and daemon B stays read-only.
  assert.equal(net.log.calcPow.length, 0);
  assert.equal(net.log.submitBodies.length, 0);
  assert.deepEqual(Object.keys(net.rpcCountsB ?? {}).filter((m) => WRITE_METHODS.includes(m)), []);

  // The new window really is usable, with the same nonce values as before.
  const ready2 = c.last('mining_ready');
  assert.equal(ready2.windowIndex, 2);
  assert.equal(ready2.nonceStart, job2.nonceStart);
  assert.equal((await c.say(c.candidate(ready2, job2.nonceStart + 1))).share, true);
});

test('REFRESH HANDOFF PROBE SHAPE: difficulty 1 completes both eight-share windows and the bound', async () => {
  const c = await refreshRun({
    windows: 2, shareDifficulty: 1, buildOptions: { refreshHandoffProbe: true },
  });
  assert.equal(c.built.refreshHandoffProbe, true, 'the trusted probe marker was lost in the builder');
  assert.equal(c.sim.job.shareDifficulty, 1n);
  assert.equal(c.sim.job.difficulty, 500n);

  // Difficulty 1 makes each scripted result a qualifying share. The unchanged eight-result cap is
  // still the retirement trigger; neither the target nor the candidate cap is client supplied.
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) {
    assert.equal((await c.say(c.candidate(c.ready1, i))).share, true);
  }
  await c.settle();
  assert.equal(c.all('job_refresh').length, 1);
  assert.equal(c.sim.windowIndex, 2);
  assert.equal(c.sim.windowRecords.length, 2);
  const ready2 = c.last('mining_ready');
  assert.equal(ready2.windowIndex, 2);
  assert.equal(c.sim.job.shareDifficulty, 1n);
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) {
    assert.equal((await c.say(c.candidate(ready2, REAL_SEARCH_LIMITS.maxAttempts + i))).share, true,
      `window 2 share ${i + 1} did not perform a real bound verification`);
  }
  await c.settle();
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.sim.attemptReason, 'search_bound_reached');
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(c.session.stateFacts.sharesAcceptedTotal, 2 * REAL_SHARE_LIMITS.maxSharesPerJob);
  assert.equal(c.session.stateFacts.sharesAccepted, REAL_SHARE_LIMITS.maxSharesPerJob);
  assert.equal(c.all('job_refresh').length, 1, 'a third issuance was attempted');
  assert.equal(c.net.log.calcPow.length, 0);
  assert.equal(c.net.log.submitBodies.length, 0);
  assert.equal(c.journal.events.indexOf('closed 1') < c.journal.events.findIndex((e) => e.startsWith('created 2')), true,
    c.journal.events.join(' | '));
});

test('REFRESH HANDOFF PROBE SHAPE: a genuine difficulty-500 block in window 2 wins once', async () => {
  const secondStart = REAL_SEARCH_LIMITS.maxAttempts;
  const c = await refreshRun({
    windows: 2, shareDifficulty: 1, blockNonce: secondStart,
    buildOptions: { refreshHandoffProbe: true },
  });
  assert.equal(c.built.refreshHandoffProbe, true);
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) {
    assert.equal((await c.say(c.candidate(c.ready1, i))).share, true);
  }
  await c.settle();
  const ready2 = c.last('mining_ready');
  assert.equal(ready2.windowIndex, 2);
  await c.say(c.candidate(ready2, secondStart));
  await c.settle();
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(c.net.log.calcPow.length, 1);
  assert.equal(c.net.log.submitBodies.length, 1);
  assert.equal(c.all('job_refresh').length, 1, 'a block caused an extra refresh');
  assert.equal(c.sim.windowIndex, 2);
});

test('REFRESH HANDOFF PROBE SHAPE: a genuine difficulty-500 block in window 1 still wins', async () => {
  const c = await refreshRun({
    windows: 2, shareDifficulty: 1, blockNonce: 0,
    buildOptions: { refreshHandoffProbe: true },
  });
  assert.equal(c.built.refreshHandoffProbe, true);
  await c.say(c.candidate(c.ready1, 0));
  await c.settle();
  assert.equal(c.sim.job.shareDifficulty, 1n);
  assert.equal(c.sim.job.difficulty, 500n);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(c.net.log.calcPow.length, 1);
  assert.equal(c.net.log.submitBodies.length, 1);
  assert.equal(c.all('job_refresh').length, 0, 'the probe suppressed a real block to manufacture a handoff');
  assert.equal(c.sim.windowIndex, 1);
});

test('REFRESH: identical template bytes still produce a new capability and a disjoint window', async () => {
  const c = await refreshRun({ windows: 2 });
  const first = c.sim.templateFacts;
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) await c.say(c.candidate(c.ready1, 100 + i));
  await c.settle();
  const second = c.sim.templateFacts;
  // The chain answers the same template for the same tip: the CONTENT is identical on purpose.
  assert.equal(second.blockhashingBlobHex, first.blockhashingBlobHex);
  assert.equal(second.contentDigest, first.contentDigest, 'this test is meaningless if the bytes differ');
  assert.equal(second.height, first.height);
  assert.equal(second.prevHashHex, first.prevHashHex);
  // ... and the capability and the window are not.
  assert.notEqual(second.jobId, first.jobId);
  assert.notEqual(second.issuanceId, first.issuanceId);
  assert.equal(second.window, 2);
  assert.equal(first.nonceStart + first.nonceRange, second.nonceStart);
  assert.equal(second.nonceRange, REAL_SEARCH_LIMITS.maxAttempts);
});

test('REFRESH: a stale old-issuance or duplicate candidate is refused cheaply, with no hash', async () => {
  const c = await refreshRun({ windows: 2 });
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) await c.say(c.candidate(c.ready1, 100 + i));
  await c.settle();
  const ready2 = c.last('mining_ready');
  assert.equal(ready2.windowIndex, 2);
  const hashesBefore = hashCount(c.journal);
  const sharesBefore = c.all('share_accepted').length;

  // The replaced window's binding, replayed.
  const stale = await c.say(c.candidate(c.ready1, 101));
  assert.notEqual(stale.reason, undefined, 'a stale-issuance candidate was accepted');
  // The new job with the old run generation.
  const oldGen = await c.say(c.candidate(ready2, ready2.nonceStart + 2, { runGeneration: c.ready1.runGeneration }));
  assert.notEqual(oldGen.reason, undefined, 'an old-generation candidate was accepted');
  // A nonce from the PREVIOUS window is now outside the issued window.
  const outside = await c.say(c.candidate(ready2, 101));
  assert.notEqual(outside.reason, undefined, 'a nonce from the replaced window was accepted');

  assert.equal(hashCount(c.journal), hashesBefore, 'a refused candidate was hashed');
  assert.equal(c.all('share_accepted').length, sharesBefore);
  assert.equal(c.net.log.calcPow.length, 0);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING);

  // And a duplicate inside the NEW window is still the cheap per-window refusal.
  const n = ready2.nonceStart + 5;
  assert.equal((await c.say(c.candidate(ready2, n))).share, true);
  const afterOne = hashCount(c.journal);
  const dup = await c.say(c.candidate(ready2, n));
  assert.equal(dup.reason, 'duplicate_nonce');
  assert.equal(hashCount(c.journal), afterOne, 'a duplicate nonce was hashed again');
});

// ================================================================== the limits
test('REFRESH: the window total is finite, and the last exhausted window ends the session', async () => {
  const windows = 3;
  const c = await refreshRun({ windows });
  for (let w = 0; w < windows; w += 1) {
    const ready = c.last('mining_ready');
    for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) {
      await c.say(c.candidate(ready, ready.nonceStart + i));
    }
    await c.settle();
  }
  assert.equal(c.all('job_refresh').length, windows - 1, 'more refreshes than windows');
  assert.equal(c.sim.windowIndex, windows);
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.sim.attemptFinished, true);
  assert.equal(c.session.stateFacts.sharesAcceptedTotal, windows * REAL_SHARE_LIMITS.maxSharesPerJob);
  assert.equal(c.net.log.submitBodies.length, 0);
  assert.deepEqual(c.sim.verifierHistory.map((v) => [v.window, v.jobId, v.issuanceId]),
    c.sim.windowRecords.slice(0, -1).map((w) => [w.window, w.jobId, w.issuanceId]),
    'a later release was attributed to the original job instead of the verifier it actually retired');
  // Nothing is admitted afterwards, and the window budget cannot be re-opened.
  const after = await c.say(c.candidate(c.last('mining_ready'), 200));
  assert.equal(after.ok, false);
  assert.equal(c.all('job_refresh').length, windows - 1);
});

test('REFRESH: the session wall-clock budget ends the run even with windows left', async () => {
  const c = await refreshRun({ windows: 3 });
  const deadline = c.session.stateFacts.sessionDeadlineAtMs;
  assert.ok(Number.isSafeInteger(deadline), 'no session budget was frozen at readiness');
  assert.equal(deadline, c.clock.ms + REAL_REFRESH_LIMITS.maxSessionMs);
  // The clock passes the whole-session budget while the first window is still being searched.
  c.clock.ms = deadline + 1;
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) await c.say(c.candidate(c.ready1, 100 + i));
  await c.settle();
  assert.equal(c.all('job_refresh').length, 0, 'a refresh outlived the session budget');
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.sim.windowIndex, 1);
});

test('REFRESH: the budget is armed at the accepted Start and a refresh never extends it', async () => {
  const c = await refreshRun({ windows: 3 });
  const deadline = c.session.stateFacts.sessionDeadlineAtMs;
  c.clock.ms += 1000;
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) await c.say(c.candidate(c.ready1, 100 + i));
  await c.settle();
  assert.equal(c.all('job_refresh').length, 1);
  assert.equal(c.session.stateFacts.sessionDeadlineAtMs, deadline, 'the refresh restarted the session budget');
});

// ================================================================== the unsafe conditions
test('REFRESH: a claimed or started submission stops any further window', async () => {
  // The eighth admitted result is a block: the submission path runs and the session completes.
  const c = await refreshRun({ windows: 3, blockNonce: 90 });
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob - 1; i += 1) await c.say(c.candidate(c.ready1, 100 + i));
  await c.say(c.candidate(c.ready1, 90));
  await c.settle();
  assert.equal(c.sim.authority.anyClaimed, true, 'the block path did not claim the submission');
  assert.equal(c.net.log.submitBodies.length, 1, 'exactly one submission');
  assert.equal(c.all('job_refresh').length, 0, 'a refresh followed a submission');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(c.sim.windowIndex, 1);
  assert.equal(c.journal.created.length, 1, 'a second verifier was built after the block');
});

test('REFRESH: a candidate still in flight is never overtaken by a refresh', async () => {
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  let armed = true;
  const c = await refreshRun({
    windows: 3,
    chainOptions: {},
  });
  // Hold the LAST candidate inside its native hash, so the window's budget is spent while one
  // verification is still in flight.
  const v = c.journal.created.at(-1);
  const nativeAnswer = v.hashNative;
  v.hashNative = async (n) => {
    if (armed && n === 107) { armed = false; await held; }
    return nativeAnswer(n);
  };
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob - 1; i += 1) await c.say(c.candidate(c.ready1, 100 + i));
  const pending = c.say(c.candidate(c.ready1, 107));
  await c.settle();
  assert.equal(c.session.stateFacts.candidatesInFlight, 1, 'the last candidate is not in flight');
  assert.equal(c.all('job_refresh').length, 0, 'a refresh started while a candidate was in flight');
  // A second frame at that moment is the serial fence's refusal, not a new window.
  assert.equal((await c.say(c.candidate(c.ready1, 120))).reason, 'queue_full');
  release();
  await pending;
  await c.settle();
  // Only now, with the slot free, is the window replaced.
  assert.equal(c.all('job_refresh').length, 1, 'the settled window was not refreshed');
  assert.equal(c.session.stateFacts.candidatesInFlight, 0);
});

test('REFRESH: Stop, a hidden tab and a lost socket all prevent any further window', async () => {
  for (const [label, act] of [
    ['Stop', async (c) => {
      const r = c.last('mining_ready');
      await c.say({
        type: 'stop_request', clientStartId: START_ID, workerId: r.workerId,
        runGeneration: r.runGeneration, jobId: r.jobId, issuanceId: r.issuanceId, reason: 'user_stop',
      });
    }],
    ['a hidden tab', async (c) => {
      const r = c.last('mining_ready');
      await c.say({
        type: 'stop_request', clientStartId: START_ID, workerId: r.workerId,
        runGeneration: r.runGeneration, jobId: r.jobId, issuanceId: r.issuanceId, reason: 'page_hidden',
      });
    }],
    ['a lost socket', async (c) => { c.session.dispose(); }],
  ]) {
    const c = await refreshRun({ windows: 3 });
    for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob - 1; i += 1) await c.say(c.candidate(c.ready1, 100 + i));
    await act(c);
    const verifiers = c.journal.created.length;
    const refreshesBefore = c.all('job_refresh').length;
    // The last result of the window arrives after the session ended: nothing is refreshed.
    await c.say(c.candidate(c.ready1, 107));
    await c.settle();
    assert.equal(c.all('job_refresh').length, refreshesBefore, `${label}: a window was refreshed`);
    assert.equal(c.journal.created.length, verifiers, `${label}: a verifier was built`);
    assert.equal(c.net.log.submitBodies.length, 0, label);
  }
});

test('REFRESH: a moved canonical tip refuses the next window and ends the session honestly', async () => {
  const c = await refreshRun({ windows: 3 });
  // Another miner's block arrives at this height while the window is being searched. The refresh
  // path reads daemon A's top before asking for a template, sees it moved, and refuses.
  const tip = c.net.blocksA.at(-1);
  c.net.blocksA.push({
    hash: 'f'.repeat(64), height: tip.height + 1, nonce: 7,
    powHash: '1'.repeat(64), prevHash: tip.hash,
  });
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) await c.say(c.candidate(c.ready1, 100 + i));
  await c.settle();
  assert.equal(c.all('job_refresh').length, 0, 'a window was refreshed onto a moved tip');
  assert.equal(c.sim.attemptFinished, true);
  assert.equal(c.last('block_rejected')?.reason, 'next_template_refused');
  assert.equal(c.net.log.submitBodies.length, 0);
});

// ================================================================== the ordinary (non-share) profile
test('REFRESH: without share work, the server backstop is what replaces an exhausted window', async () => {
  const c = await refreshRun({ windows: 2, shareWork: false });
  assert.equal(c.ready1.windowIndex, 1);
  assert.equal(c.sim.job.shareWork, false);
  await c.fireBackstop();
  const refresh = c.last('job_refresh');
  assert.ok(refresh, JSON.stringify(c.sent.map((m) => [m.type, m.reason])));
  assert.equal(refresh.windowIndex, 2);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING);
  assert.equal(c.sim.job.nonceStart, REAL_SEARCH_LIMITS.maxAttempts);
  assert.equal(c.journal.created.length, 2);
  // The second window's backstop ends the session: the total is still two.
  await c.fireBackstop();
  assert.equal(c.all('job_refresh').length, 1);
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
});

// ================================================================== configuration and text
test('REFRESH CONFIG: opt-in, pair-only, composable, and bounded to 32 serial contexts', async () => {
  const composed = await buildScriptedChain({}, { sequenceBlocks: 2, refreshWindows: 2 });
  assert.equal(composed.built.sequence.total, 2);
  assert.equal(composed.built.refresh.maxWindows, 2);
  assert.equal(composed.built.authority.maxClaims, 2,
    'same-height windows changed the one-submission-per-height claim budget');
  await assert.rejects(
    buildScriptedChain({}, {
      sequenceBlocks: Math.floor(REAL_MAX_CONTEXTS_PER_START / 2) + 1,
      refreshWindows: 2,
    }),
    (e) => e.code === 'bad_config'
      && new RegExp(`must not exceed ${REAL_MAX_CONTEXTS_PER_START} serial contexts`).test(e.message),
    'a sequence/window product above the retained-state ceiling was accepted',
  );
  for (const bad of [0, 1.5, REAL_REFRESH_LIMITS.maxWindows + 1]) {
    await assert.rejects(buildScriptedChain({}, { sequenceBlocks: 1, refreshWindows: bad }),
      (e) => e.code === 'bad_config', `refreshWindows ${bad}`);
  }
  // Omitted entirely: the run has exactly one window and no refresh source at all.
  const plain = await buildScriptedChain({}, { sequenceBlocks: 1 });
  assert.equal(plain.built.refresh, null);
  assert.equal(plain.built.refreshWindows, 1);
  const refreshed = await buildScriptedChain({}, { sequenceBlocks: 1, refreshWindows: 2 });
  assert.equal(refreshed.built.refresh.maxWindows, 2);
  assert.equal(refreshed.built.sequence, null);
  assert.equal(refreshed.built.authority.maxClaims, 1, 'a refresh run may authorise more than one submission');
  await assert.rejects(
    buildScriptedChain({}, {
      sequenceBlocks: 1, refreshWindows: 2, shareDifficulty: 100, refreshHandoffProbe: true,
    }),
    /refreshHandoffProbe requires refreshWindows 2, sequenceBlocks 1 and shareDifficulty 1/,
    'the probe marker accepted ordinary D100 work',
  );
});

test('REFRESH PROFILE: the text states both caps and never calls a window a block', () => {
  const p = realRefreshProfile(2, { shareWork: true, probeShareDifficulty: 1 });
  assert.equal(p.refreshWindows, 2);
  assert.equal(p.refreshSessionMs, REAL_REFRESH_LIMITS.maxSessionMs);
  assert.equal(p.shareWork, true);
  assert.match(p.helloNotice, /two \(2\) windows in total/);
  assert.match(p.helloNotice, /within 10 minutes of this Start/);
  assert.match(p.helloNotice, /at most ONE block submission for this height/);
  assert.match(p.helloNotice, /does not overlap any window already searched/);
  assert.match(p.helloNotice, /trusted startup configuration fixes share difficulty 1/);
  assert.match(p.helloNotice, /block difficulty remains 500/);
  assert.match(p.helloNotice, /genuine block result still wins immediately/);
  assert.ok(p.labels.some((l) => l.includes('NONCE WINDOWS OF THE SAME BLOCK HEIGHT')));
  assert.equal(/SEQUENTIAL FRESH BLOCK TEMPLATES/.test(p.labels.join(' ')), false,
    'the refresh profile claims a block sequence');
  const two = realRefreshProfile(2, { shareWork: false });
  assert.match(two.helloNotice, /two \(2\) windows in total/);
  assert.equal(two.shareWork, undefined);
  assert.throws(() => realRefreshProfile(1), TypeError);
  assert.throws(() => realRefreshProfile(REAL_REFRESH_LIMITS.maxWindows + 1), TypeError);
  assert.throws(() => realRefreshProfile(2, { shareWork: false, probeShareDifficulty: 1 }), TypeError);
  assert.throws(() => realRefreshProfile(2, { shareWork: true, probeShareDifficulty: 0 }), TypeError);
});

// ================================================================== the audit's counterexamples
//
// Each test below fails on the first draft of this feature, for the reason named in its title.

test('REFRESH STOP: a Stop naming the PREVIOUS window is accepted after the handover', async () => {
  const c = await refreshRun({ windows: 3 });
  const oldBinding = c.ready1;
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) await c.say(c.candidate(c.ready1, 100 + i));
  await c.settle();
  const ready2 = c.last('mining_ready');
  assert.equal(ready2.windowIndex, 2, 'the handover did not happen');
  assert.notEqual(ready2.jobId, oldBinding.jobId);

  // The page pressed Stop while it still held window 1's binding: the message names the job and the
  // run generation the user was actually looking at. Judging it against the CURRENT issuance only
  // would answer `unknown_job` and leave the session mining.
  const r = await c.say({
    type: 'stop_request', clientStartId: START_ID, workerId: oldBinding.workerId,
    runGeneration: oldBinding.runGeneration, jobId: oldBinding.jobId, issuanceId: oldBinding.issuanceId,
    reason: 'page_hidden',
  });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.accepted, true, 'a Stop for a window this Start was issued was refused');
  assert.notEqual(c.last('error')?.reason, 'unknown_job');
  assert.equal(c.sim.attemptFinished, true, 'the whole Start was not revoked');
  assert.equal(c.last('run_stopped')?.reason, 'page_hidden');

  // And nothing may be admitted or refreshed afterwards.
  const after = await c.say(c.candidate(ready2, ready2.nonceStart + 1));
  assert.equal(after.ok, false);
  await c.settle();
  assert.equal(c.all('job_refresh').length, 1, 'a window was refreshed after Stop');
  assert.equal(c.net.log.submitBodies.length, 0);
});

test('REFRESH STOP: a Stop DURING the handover is accepted and nothing further is published', async () => {
  let releaseTemplate;
  const held = new Promise((resolve) => { releaseTemplate = resolve; });
  const c = await refreshRun({
    windows: 3,
    chainOptions: {
      // The SECOND template request -- the refresh's own -- is held open.
      gate: (method, n, side) => (side === 'A' && method === 'get_block_template' && n === 2 ? held : undefined),
    },
  });
  const oldBinding = c.ready1;
  const issuanceBefore = c.sim.job.issuanceId;
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) await c.say(c.candidate(c.ready1, 100 + i));
  await c.settle();
  assert.equal(c.session.stateFacts.refreshInFlight, 1, 'the refresh is not in flight');

  // Stop lands while the template request is still outstanding.
  const r = await c.say({
    type: 'stop_request', clientStartId: START_ID, workerId: oldBinding.workerId,
    runGeneration: oldBinding.runGeneration, jobId: oldBinding.jobId, issuanceId: oldBinding.issuanceId,
    reason: 'user_stop',
  });
  assert.equal(r.accepted, true, 'a Stop during the handover was refused');
  assert.equal(c.sim.attemptFinished, true);
  releaseTemplate();
  await c.settle();

  // THE FETCH RETURNED AFTER THE STOP, AND NOTHING WAS PUBLISHED FOR IT.
  assert.equal(c.all('job_refresh').length, 0, 'a fresh issuance was published for a stopped session');
  assert.equal(c.sim.authority.isSuperseded(issuanceBefore), false,
    'the old issuance was superseded by a window nobody consented to');
  assert.equal(c.sim.authority.isCurrent(issuanceBefore), true);
  assert.equal(c.sim.windowIndex, 1);
  assert.equal(c.all('mining_ready').length, 1, 'a window nobody consented to became ready');
  assert.equal(c.all('run_stopped').length, 1);
  assert.equal(c.net.log.submitBodies.length, 0);
});

test('REFRESH BUDGET: the advertised session budget ends the run mid-window, not only at a refresh', async () => {
  const c = await refreshRun({ windows: 3 });
  const deadline = c.session.stateFacts.sessionDeadlineAtMs;
  assert.equal(c.session.stateFacts.sessionTimers, 1, 'no independent whole-session backstop was armed');
  // One ordinary share, so the window is very much NOT exhausted.
  assert.equal((await c.say(c.candidate(c.ready1, 100))).share, true);
  const hashesBefore = hashCount(c.journal);
  const sharesBefore = c.all('share_accepted').length;

  // The advertised minutes pass while this window is still live.
  c.clock.ms = deadline + 1;
  const late = await c.say(c.candidate(c.ready1, 101));
  assert.equal(late.ok, false, 'a result was admitted after the advertised session budget');
  assert.equal(late.reason, 'search_bound_reached');
  await c.settle();
  assert.equal(hashCount(c.journal), hashesBefore, 'a late result was hashed');
  assert.equal(c.all('share_accepted').length, sharesBefore, 'a late share was published');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(c.all('job_refresh').length, 0);
  assert.equal(c.net.log.calcPow.length, 0);
  assert.equal(c.net.log.submitBodies.length, 0);
});

test('REFRESH BUDGET: the session backstop fires on its own timer with the window still live', async () => {
  const c = await refreshRun({ windows: 3 });
  const sessionTimer = c.timers.find((t) => t.ms === REAL_REFRESH_LIMITS.maxSessionMs);
  assert.ok(sessionTimer, 'the whole-session budget has no timer of its own');
  assert.notEqual(sessionTimer.ms, REAL_SEARCH_LIMITS.maxSearchMs,
    'the session budget is the per-window backstop again');
  assert.equal((await c.say(c.candidate(c.ready1, 100))).share, true);
  sessionTimer.fn();
  await c.settle();
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(c.session.stateFacts.sessionBudgetSpent, true);
  const after = await c.say(c.candidate(c.ready1, 101));
  assert.equal(after.ok, false, 'a result was admitted after the session backstop');
  assert.equal(c.all('job_refresh').length, 0);
});

test('REFRESH INIT: a Stop while the next window verifier is initialising lets nothing escape', async () => {
  let releaseInit;
  const held = new Promise((resolve) => { releaseInit = resolve; });
  const c = await refreshRun({
    windows: 3,
    // The SECOND verifier -- the next window's -- is held mid-initialisation.
    buildOptions: { makeVerifierGate: async (n) => { if (n === 2) await held; } },
  });
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) await c.say(c.candidate(c.ready1, 100 + i));
  await c.settle();
  // The window was handed over and the successor verifier is still being built.
  assert.equal(c.all('job_refresh').length, 1);
  assert.equal(c.all('mining_ready').length, 1, 'readiness was announced before the verifier existed');
  assert.ok(c.sim.pendingInit, 'no verifier initialisation is pending');

  const r = await c.say({
    type: 'stop_request', clientStartId: START_ID, workerId: c.ready1.workerId,
    runGeneration: c.ready1.runGeneration, jobId: c.ready1.jobId, issuanceId: c.ready1.issuanceId,
    reason: 'user_stop',
  });
  assert.equal(r.accepted, true);
  assert.equal(c.sim.attemptFinished, true);
  releaseInit();
  await c.settle();

  // NOTHING ESCAPED: no readiness for the abandoned window, no job, no hash, no submission.
  assert.equal(c.all('mining_ready').length, 1, 'an abandoned window announced readiness');
  assert.equal(c.all('job_refresh').length, 1);
  assert.equal(c.sim.serverVerifierReady, false, 'an abandoned verifier became usable');
  assert.equal(c.net.log.calcPow.length, 0);
  assert.equal(c.net.log.submitBodies.length, 0);
  const after = await c.say(c.candidate(c.last('job_refresh').job ? {
    jobId: c.last('job_refresh').jobId,
    issuanceId: c.last('job_refresh').issuanceId,
    workerId: c.last('job_refresh').workerId,
    runGeneration: c.last('job_refresh').runGeneration,
  } : c.ready1, c.sim.job.nonceStart + 1));
  assert.equal(after.ok, false, 'a result was admitted for the abandoned window');
});

// ============================================================ the second audit's counterexamples

test('REFRESH BUDGET: the session clock starts at the accepted Start, not at the first readiness', async () => {
  let releaseInit;
  const held = new Promise((resolve) => { releaseInit = resolve; });
  const c = await refreshRun({
    windows: 3,
    // The FIRST verifier is held mid-initialisation: the allocation itself eats the budget.
    buildOptions: { makeVerifierGate: async (n) => { if (n === 1) await held; } },
    startImmediately: false,
  });
  const startedAtMs = c.clock.ms;
  const starting = c.start();
  await c.settle();
  assert.equal(c.all('mining_ready').length, 0, 'readiness was announced before the verifier existed');
  assert.equal(c.session.stateFacts.sessionDeadlineAtMs, startedAtMs + REAL_REFRESH_LIMITS.maxSessionMs,
    'the session budget is not anchored at the accepted Start');
  assert.equal(c.session.stateFacts.sessionTimers, 1, 'the whole-session backstop is not armed yet');

  // The allocation outlives the whole advertised budget.
  c.clock.ms = startedAtMs + REAL_REFRESH_LIMITS.maxSessionMs + 1;
  const sessionTimer = c.timers.find((t) => t.ms === REAL_REFRESH_LIMITS.maxSessionMs);
  sessionTimer.fn();
  releaseInit();
  await starting;
  await c.settle();

  // NOTHING BECAME READY, and the run ended on its own bound.
  assert.equal(c.all('mining_ready').length, 0, 'a session past its budget announced readiness');
  assert.equal(c.all('job_refresh').length, 0);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(c.net.log.calcPow.length, 0);
  assert.equal(c.net.log.submitBodies.length, 0);
});

test('REFRESH BUDGET: expiry during a held refresh fetch is a bound, not a dispose', async () => {
  let releaseTemplate;
  const held = new Promise((resolve) => { releaseTemplate = resolve; });
  const c = await refreshRun({
    windows: 3,
    chainOptions: {
      gate: (method, n, side) => (side === 'A' && method === 'get_block_template' && n === 2 ? held : undefined),
    },
  });
  const issuanceBefore = c.sim.job.issuanceId;
  for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) await c.say(c.candidate(c.ready1, 100 + i));
  await c.settle();
  assert.equal(c.session.stateFacts.refreshInFlight, 1, 'the refresh is not in flight');

  // The advertised minutes pass while the template request is still outstanding.
  c.clock.ms = c.session.stateFacts.sessionDeadlineAtMs + 1;
  releaseTemplate();
  await c.settle();

  // The run reached a BOUND it was given, not an abandoned session: the page consented to those
  // minutes, and reporting `session_dispose` would describe a bounded observation as a walk-away.
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.sim.attemptReason, 'search_bound_reached');
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.notEqual(c.sim.attemptReason, 'session_dispose');
  // And the fetch that returned late published nothing.
  assert.equal(c.all('job_refresh').length, 0);
  assert.equal(c.sim.authority.isCurrent(issuanceBefore), true);
  assert.equal(c.sim.windowIndex, 1);
  assert.equal(c.net.log.submitBodies.length, 0);
});

test('REFRESH BUDGET: an already-admitted candidate still settles honestly at the bound', async () => {
  let releaseNative;
  const held = new Promise((resolve) => { releaseNative = resolve; });
  const c = await refreshRun({ windows: 3 });
  const v = c.journal.created.at(-1);
  const native = v.hashNative;
  let armed = true;
  v.hashNative = async (n) => {
    if (armed && n === 100) { armed = false; await held; }
    return native(n);
  };
  const pending = c.say(c.candidate(c.ready1, 100));
  await c.settle();
  assert.equal(c.session.stateFacts.candidatesInFlight, 1);

  // The budget passes while that candidate is being verified.
  const sessionTimer = c.timers.find((t) => t.ms === REAL_REFRESH_LIMITS.maxSessionMs);
  sessionTimer.fn();
  await c.settle();
  assert.equal(c.sim.attemptFinished, false, 'the in-flight candidate was talked over');
  // No NEW candidate is admitted in the meantime.
  assert.equal((await c.say(c.candidate(c.ready1, 101))).reason, 'search_bound_reached');

  releaseNative();
  await pending;
  await c.settle();
  assert.equal(c.all('share_accepted').length, 1, 'the admitted result never published its outcome');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(c.all('job_refresh').length, 0);
});

// ============================================================ truthful disclosure composition
test('REFRESH PROFILE: share checking survives, and the allocation text describes serial verifiers', () => {
  const shared = realRefreshProfile(3, { shareWork: true });
  const plain = realRefreshProfile(3);

  // THE SHARE-CHECKING LABEL IS NOT DELETED. Slicing the base labels by position removed it.
  const shareLabel = REAL_P2P_SHARE_PROFILE.labels.find((l) => l.startsWith('SERVER-SIDE SHARE CHECKING'));
  assert.ok(shareLabel, 'the share profile no longer states share checking at all');
  assert.ok(shared.labels.includes(shareLabel), 'a share-enabled refresh run hides its share checking');
  assert.equal(plain.labels.some((l) => l.startsWith('SERVER-SIDE SHARE CHECKING')), false,
    'a run without share work claims share checking');

  // Every other base label survives, the window label is present, and the submission label is last.
  for (const label of REAL_P2P_SHARE_PROFILE.labels.filter((l) => !l.startsWith('AT MOST ONE BLOCK SUBMISSION'))) {
    assert.ok(shared.labels.includes(label), `a base label was dropped: ${label}`);
  }
  assert.ok(shared.labels.some((l) => /NONCE WINDOWS OF THE SAME BLOCK HEIGHT, ONE AT A TIME/.test(l)));
  assert.match(shared.labels.at(-1), /^AT MOST ONE BLOCK SUBMISSION/);
  assert.equal(shared.labels.filter((l) => l.startsWith('AT MOST ONE BLOCK SUBMISSION')).length, 1,
    'the submission label is stated twice');
  assert.equal(/SEQUENTIAL FRESH BLOCK TEMPLATES/.test(shared.labels.join(' ')), false);

  // THE ALLOCATION TEXT SAYS WHAT MAY ACTUALLY BE BUILT, and that it is never simultaneous.
  for (const text of [
    'up to three (3) nonce windows',
    'ONE AT A TIME, never simultaneously',
    'release confirmed before the next pair is allocated',
    'never more than one server verifier at any moment',
  ]) assert.ok(shared.willAllocate.includes(text), `the allocation text is missing: ${text}`);
  assert.ok(shared.willAllocate.startsWith(REAL_P2P_SHARE_PROFILE.willAllocate),
    'the base allocation disclosure was replaced rather than extended');

  // The hello and ready text state the serial rule too, and claim nothing about a public network.
  assert.match(shared.helloNotice, /one at a time, never simultaneously/);
  assert.match(shared.helloNotice, /confirms that release -- before the next one is built/);
  assert.match(shared.helloNotice, /says nothing about any public network/);
  assert.match(shared.readyNotice, /each with its own verifier released before the next/);
  assert.equal(/secure|safe|production|mainnet/i.test(shared.helloNotice), false,
    'the disclosure was inflated into a security claim');
});
