// THE FINITE HEIGHT SEQUENCE COMPOSED WITH SAME-HEIGHT NONCE WINDOWS.
//
// This file tests only the composition: one Start may search two disjoint windows at height 1,
// advance only after its block is visible on the read-only peer, reset the window budget at height 2,
// and finish there. The standalone sequence and refresh suites own the exhaustive tests for each
// feature. Nothing live exists here: both daemons and every verifier are injected in memory.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SIM_ATTEMPT_STATES, createSimulationContext, createSimulationSession,
} from '../sim_session.mjs';
import { selectSimulationProfile } from '../server.mjs';
import { MAX_256, bigIntToLeBytes32 } from '../difficulty.mjs';
import { hexToBlob } from '../block_blob.mjs';
import { GENESIS, buildScriptedChain, powFor } from './in_memory_chain.mjs';
import {
  REAL_SEARCH_LIMITS, REAL_SHARE_LIMITS,
} from '../../../web-miner/lib/shared/protocol.js';

const START_ID = '0123456789abcdef0123456789abcdef';
const SHARE_DIFFICULTY = 50;
const SHARE_ONLY = bigIntToLeBytes32(MAX_256 / 100n);
const BLOCK_OFFSET = 90;

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

async function waitBounded(promise, label, ms = 2_000) {
  let timer = null;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`timed out waiting for ${label}`)), ms);
      }),
    ]);
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

const hashCount = (journal) => journal.created.reduce(
  (n, v) => n + v.counters.wasmShareHashes + v.counters.nativeShareHashes, 0,
);

const costs = (c) => ({
  hashes: hashCount(c.journal),
  verifiers: c.journal.created.length,
  templates: c.net.counts.A.get_block_template ?? 0,
  calcPow: c.net.log.calcPow.length,
  submits: c.net.log.submitBodies.length,
});

/**
 * A two-height, two-window session. Every window-1 nonce is a share only. In window 2, the nonce at
 * `nonceStart + BLOCK_OFFSET` is a real block and every other nonce is a share. This makes the exact
 * H1W1 -> H1W2 -> H2W1 -> H2W2 route deterministic without a browser, timer, process or network.
 */
async function sequenceRefreshRun({ chainOptions = {}, buildOptions = {}, profileOver = {} } = {}) {
  const ctx = await buildScriptedChain(chainOptions, {
    sequenceBlocks: 2,
    refreshWindows: 2,
    shareDifficulty: SHARE_DIFFICULTY,
    ...buildOptions,
  });
  const profile = Object.freeze({ ...selectSimulationProfile(ctx.built), ...profileOver });
  const sim = createSimulationContext({
    ...ctx.built,
    profile,
    now: () => ctx.clock.ms,
  });

  const scripted = new Set();
  const scriptAll = () => {
    for (const v of ctx.journal.created) {
      if (scripted.has(v)) continue;
      scripted.add(v);
      const height = Number(v.context.height);
      const answer = (nonce) => (nonce === REAL_SEARCH_LIMITS.maxAttempts + BLOCK_OFFSET
        ? hexToBlob(powFor(height))
        : SHARE_ONLY);
      v.hashWasm = async (nonce) => {
        v.counters.wasmShareHashes += 1;
        return answer(nonce);
      };
      v.hashNative = async (nonce) => {
        v.counters.nativeShareHashes += 1;
        return answer(nonce);
      };
    }
  };

  const sent = [];
  const timers = [];
  const session = createSimulationSession({
    sim,
    now: () => ctx.clock.ms,
    send: (message) => { sent.push(message); scriptAll(); },
    setTimer: (fn, ms) => { const timer = { fn, ms, cleared: false }; timers.push(timer); return timer; },
    clearTimer: (timer) => { timer.cleared = true; },
  });
  const settle = async () => {
    for (let i = 0; i < 50; i += 1) await new Promise((resolve) => setImmediate(resolve));
    scriptAll();
  };
  const say = async (object) => {
    const text = JSON.stringify(object);
    const result = await session.handleRaw(Buffer.byteLength(text), text);
    scriptAll();
    return result;
  };
  const last = (type) => [...sent].reverse().find((message) => message.type === type);
  const all = (type) => sent.filter((message) => message.type === type);
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
  const stop = (ready, reason = 'user_stop') => ({
    type: 'stop_request',
    clientStartId: START_ID,
    jobId: ready.jobId,
    issuanceId: ready.issuanceId,
    workerId: ready.workerId,
    runGeneration: ready.runGeneration,
    reason,
  });
  const exhaust = async (ready) => {
    for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob; i += 1) {
      const result = await say(candidate(ready, ready.nonceStart + i));
      assert.equal(result.share, true, `share ${i + 1} did not settle at H${ready.sequenceIndex}W${ready.windowIndex}`);
    }
    await settle();
  };

  await say({ type: 'client_hello', protocolVersion: 1 });
  await say({ type: 'start_request', clientStartId: START_ID });
  await settle();
  return {
    ...ctx, profile, sim, session, sent, timers, say, settle, last, all, candidate, stop, exhaust,
    ready11: last('mining_ready'),
  };
}

test('SEQUENCE REFRESH: H1W1 exhausts, H1W2 wins, peer converges, then H2W1 exhausts and H2W2 wins', async () => {
  const topsAtTemplate = [];
  const c = await sequenceRefreshRun({
    chainOptions: {
      beforeTemplate: ({ blocksA, blocksB }) => topsAtTemplate.push([blocksA.length, blocksB.length]),
    },
  });

  const hello = c.last('server_hello');
  assert.equal(hello.sequenceTotal, 2);
  assert.equal(hello.windowTotal, 2);
  assert.equal(c.profile.sequenceBlocks, 2);
  assert.equal(c.profile.refreshWindows, 2);
  assert.deepEqual(
    [c.ready11.sequenceIndex, c.ready11.windowIndex, c.ready11.nonceStart],
    [1, 1, 0],
  );

  await c.exhaust(c.ready11);
  const ready12 = c.last('mining_ready');
  assert.deepEqual([ready12.sequenceIndex, ready12.windowIndex, ready12.nonceStart], [
    1, 2, REAL_SEARCH_LIMITS.maxAttempts,
  ]);
  assert.deepEqual(
    [
      c.last('job_refresh').sequenceIndex, c.last('job_refresh').sequenceTotal,
      c.last('job_refresh').windowIndex, c.last('job_refresh').windowTotal,
    ],
    [1, 2, 2, 2],
  );

  await c.say(c.candidate(ready12, ready12.nonceStart + BLOCK_OFFSET));
  await c.settle();
  const ready21 = c.last('mining_ready');
  const next = c.last('sequence_next');
  assert.equal(next.cause, 'accepted');
  assert.deepEqual(
    [next.sequenceIndex, next.sequenceTotal, next.windowIndex, next.windowTotal],
    [2, 2, 1, 2],
  );
  assert.deepEqual([ready21.sequenceIndex, ready21.windowIndex, ready21.nonceStart], [2, 1, 0]);
  assert.equal(c.sim.blockRecords[0].propagation.converged, true, 'H2 was issued before B showed H1');

  await c.exhaust(ready21);
  const ready22 = c.last('mining_ready');
  assert.deepEqual([ready22.sequenceIndex, ready22.windowIndex, ready22.nonceStart], [
    2, 2, REAL_SEARCH_LIMITS.maxAttempts,
  ]);
  assert.deepEqual(
    [
      c.last('job_refresh').sequenceIndex, c.last('job_refresh').sequenceTotal,
      c.last('job_refresh').windowIndex, c.last('job_refresh').windowTotal,
    ],
    [2, 2, 2, 2],
  );

  await c.say(c.candidate(ready22, ready22.nonceStart + BLOCK_OFFSET));
  await c.settle();

  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(c.all('run_started').length, 1, 'a height or window minted another Start');
  assert.equal(c.all('job_refresh').length, 2);
  assert.equal(c.all('sequence_next').length, 1);
  assert.equal(c.all('sequence_block_accepted').length, 2);
  assert.deepEqual(c.all('mining_ready').map((ready) => [ready.sequenceIndex, ready.windowIndex]), [
    [1, 1], [1, 2], [2, 1], [2, 2],
  ]);
  assert.deepEqual(c.all('mining_ready').map((ready) => ready.nonceStart), [
    0, REAL_SEARCH_LIMITS.maxAttempts, 0, REAL_SEARCH_LIMITS.maxAttempts,
  ]);

  // The first two templates are on genesis. H2 is not requested until B has H1, and both H2 windows
  // are on that exact accepted parent.
  assert.deepEqual(topsAtTemplate, [[1, 1], [1, 1], [2, 2], [2, 2]]);
  const block1 = c.net.blocksA[1].hash;
  assert.deepEqual(c.net.log.templates.map((template) => [template.height, template.prev]), [
    [1, GENESIS], [1, GENESIS], [2, block1], [2, block1],
  ]);
  assert.deepEqual(c.built.rpcAudit.snapshots.map((snapshot) => [snapshot.block, snapshot.window]), [
    [1, 1], [1, 2], [2, 1], [2, 2],
  ]);
  assert.equal(c.net.log.calcPow.length, 2, 'a share reached calc_pow or a block was recomputed twice');
  assert.equal(c.net.log.submitBodies.length, 2, 'there was not exactly one submission per height');
  assert.equal(c.sim.authority.claimCount, 2, 'window refreshes consumed submission claims');
  assert.deepEqual(c.net.log.bWrites, [], 'a write reached daemon B');
  assert.deepEqual(c.net.blocksB.map((block) => block.hash), c.net.blocksA.map((block) => block.hash));
  assert.equal(c.session.stateFacts.sharesAcceptedTotal, 2 * REAL_SHARE_LIMITS.maxSharesPerJob);
  assert.deepEqual(c.session.stateFacts.windowOutcomes.map((outcome) => [outcome.block, outcome.window]), [
    [1, 1], [2, 1],
  ]);
  assert.deepEqual(c.sim.windowRecords.map((record) => [record.block, record.window]), [
    [1, 1], [1, 2], [2, 1], [2, 2],
  ]);

  assert.deepEqual(c.journal.created.map((verifier) => verifier.context.height), ['1', '1', '2', '2']);
  for (let index = 1; index < 4; index += 1) {
    const closed = c.journal.events.indexOf(`closed ${index}`);
    const created = c.journal.events.findIndex((event) => event.startsWith(`created ${index + 1}`));
    assert.ok(closed >= 0 && created > closed, c.journal.events.join(' | '));
  }
  assert.equal(c.journal.created.filter((verifier) => verifier.closed !== true).length, 1);
});

test('SEQUENCE REFRESH STOP: Stop while H1W2 waits on B prevents H2W1 and all late work', async () => {
  const peerGate = deferred();
  let entered;
  const atPeer = new Promise((resolve) => { entered = resolve; });
  let held = false;
  const c = await sequenceRefreshRun({
    chainOptions: {
      gate: async (method, _count, side, chain) => {
        if (!held && side === 'B' && method === 'get_last_block_header' && chain.blocksA.length === 2) {
          held = true;
          entered();
          await peerGate.promise;
        }
      },
    },
  });
  await c.exhaust(c.ready11);
  const ready12 = c.last('mining_ready');
  const submitting = c.say(c.candidate(ready12, ready12.nonceStart + BLOCK_OFFSET));
  await atPeer;

  const stopped = await c.say(c.stop(ready12));
  assert.equal(stopped.accepted, true);
  peerGate.resolve();
  await submitting;
  await c.settle();

  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.all('sequence_next').length, 0);
  assert.equal(c.all('mining_ready').length, 2, 'H2W1 became ready after Stop');
  assert.equal(c.net.counts.A.get_block_template, 2, 'H2W1 was fetched after Stop');
  assert.equal(c.journal.created.length, 2, 'an H2 verifier was allocated after Stop');
  const before = costs(c);
  assert.equal((await c.say(c.candidate(ready12, ready12.nonceStart + BLOCK_OFFSET + 1))).ok, false);
  assert.deepEqual(costs(c), before, 'a late frame did work after Stop');
});

test('SEQUENCE REFRESH BUDGET: expiry during peer convergence records H1 but creates no H2 resource', async () => {
  const peerGate = deferred();
  let entered;
  const atPeer = new Promise((resolve) => { entered = resolve; });
  let held = false;
  const c = await sequenceRefreshRun({
    // Keep this test inside the real job's independent TTL while making the whole-session boundary
    // controllable without waiting. Production still advertises and enforces the frozen ten minutes.
    profileOver: { refreshSessionMs: 10 },
    chainOptions: {
      gate: async (method, _count, side, chain) => {
        if (!held && side === 'B' && method === 'get_last_block_header' && chain.blocksA.length === 2) {
          held = true;
          entered();
          await peerGate.promise;
        }
      },
    },
  });
  await c.exhaust(c.ready11);
  const ready12 = c.last('mining_ready');
  // Enter propagation one millisecond before the whole-Start deadline. Advancing a full ten
  // minutes while B is held would correctly trip the independent 60-second propagation timeout
  // instead of exercising the boundary this regression owns.
  c.clock.ms = c.session.stateFacts.sessionDeadlineAtMs - 1;
  const submitting = c.say(c.candidate(ready12, ready12.nonceStart + BLOCK_OFFSET));
  await atPeer;

  const sessionTimer = c.timers.find((timer) => (
    timer.ms === c.profile.refreshSessionMs && timer.cleared === false
  ));
  assert.ok(sessionTimer, 'the whole-Start session timer was not armed');
  c.clock.ms += 1;
  sessionTimer.fn();
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING,
    'the deadline talked over an already-accepted block awaiting peer evidence');

  peerGate.resolve();
  await submitting;
  await c.settle();

  assert.equal(c.sim.blockRecords[0].propagation.converged, true,
    'the already-accepted H1 block lost its peer-convergence evidence');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.sim.attemptReason, 'search_bound_reached');
  assert.equal(c.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(c.all('sequence_next').length, 0, 'an H2 binding was published after the session deadline');
  assert.equal(c.all('mining_ready').length, 2, 'an H2 verifier became ready after the session deadline');
  assert.equal(c.net.counts.A.get_block_template, 2, 'an H2 template was fetched after the session deadline');
  assert.equal(c.journal.created.length, 2, 'an H2 verifier was allocated after the session deadline');
  assert.equal(c.journal.created[1].closed, true, 'the accepted block\'s outgoing verifier was not released');
  const before = costs(c);
  assert.equal((await c.say(c.candidate(ready12, ready12.nonceStart + BLOCK_OFFSET + 1))).ok, false);
  assert.deepEqual(costs(c), before, 'late work escaped after the whole-Start deadline');
});

test('SEQUENCE REFRESH BUDGET: a delayed session timer still records clock expiry before H2', async () => {
  const peerGate = deferred();
  let entered;
  const atPeer = new Promise((resolve) => { entered = resolve; });
  let held = false;
  const c = await sequenceRefreshRun({
    profileOver: { refreshSessionMs: 10 },
    chainOptions: {
      gate: async (method, _count, side, chain) => {
        if (!held && side === 'B' && method === 'get_last_block_header' && chain.blocksA.length === 2) {
          held = true;
          entered();
          await peerGate.promise;
        }
      },
    },
  });
  await c.exhaust(c.ready11);
  const ready12 = c.last('mining_ready');
  c.clock.ms = c.session.stateFacts.sessionDeadlineAtMs - 1;
  const submitting = c.say(c.candidate(ready12, ready12.nonceStart + BLOCK_OFFSET));
  await atPeer;

  const sessionTimer = c.timers.find((timer) => (
    timer.ms === c.profile.refreshSessionMs && timer.cleared === false
  ));
  assert.ok(sessionTimer, 'the delayed whole-Start timer was not still pending');
  c.clock.ms += 1;
  // Deliberately do not call sessionTimer.fn(): the authoritative clock has crossed its deadline
  // before the event loop delivered the timer callback.
  peerGate.resolve();
  await submitting;
  await c.settle();

  assert.equal(c.sim.blockRecords[0].propagation.converged, true);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.sim.attemptReason, 'search_bound_reached');
  assert.equal(c.session.stateFacts.sessionBudgetSpent, true,
    'the clock gate stopped H2 but the durable budget fact was left false');
  assert.equal(c.all('sequence_next').length, 0, 'an H2 binding was published after clock expiry');
  assert.equal(c.net.counts.A.get_block_template, 2, 'an H2 template was fetched after clock expiry');
  assert.equal(c.journal.created.length, 2, 'an H2 verifier was allocated after clock expiry');
  assert.equal(c.journal.created[1].closed, true, 'the accepted H1 verifier was not released');
});

test('SEQUENCE REFRESH BUDGET: expiry while releasing H1 creates no H2 template or resource', async () => {
  const releaseGate = deferred();
  let entered;
  const atRelease = new Promise((resolve) => { entered = resolve; });
  const c = await sequenceRefreshRun({
    profileOver: { refreshSessionMs: 10 },
    // Converge on the first B read so the test, not the peer poll sleep, owns the exact deadline.
    chainOptions: { propagateAfterBReads: 0 },
    buildOptions: {
      verifierOptions: (index) => (index === 2 ? {
        closeGate: async () => { entered(); await releaseGate.promise; },
      } : {}),
    },
  });
  await c.exhaust(c.ready11);
  const ready12 = c.last('mining_ready');
  c.clock.ms = c.session.stateFacts.sessionDeadlineAtMs - 1;
  const submitting = c.say(c.candidate(ready12, ready12.nonceStart + BLOCK_OFFSET));
  await atRelease;

  const sessionTimer = c.timers.find((timer) => (
    timer.ms === c.profile.refreshSessionMs && timer.cleared === false
  ));
  assert.ok(sessionTimer, 'the whole-Start session timer was not armed');
  c.clock.ms += 1;
  sessionTimer.fn();
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING,
    'the deadline talked over the accepted block while its resource was still owned');

  releaseGate.resolve();
  await submitting;
  await c.settle();

  assert.equal(c.sim.blockRecords[0].propagation.converged, true);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.sim.attemptReason, 'search_bound_reached');
  assert.equal(c.all('sequence_next').length, 0);
  assert.equal(c.all('mining_ready').length, 2);
  assert.equal(c.net.counts.A.get_block_template, 2,
    'the H2 template RPC began after the deadline landed during release');
  assert.equal(c.sim.authority.stateFacts.published, 2, 'an H2 issuance was published');
  assert.equal(c.sim.authority.currentIssuanceId, ready12.issuanceId, 'H1W2 was superseded');
  assert.equal(c.journal.created.length, 2, 'an H2 verifier was allocated');
  assert.equal(c.journal.created[1].closed, true, 'the outgoing verifier release was not confirmed');
});

test('SEQUENCE REFRESH BUDGET: expiry during the H2 template RPC publishes no H2 issuance', async () => {
  const templateGate = deferred();
  let entered;
  const atTemplate = new Promise((resolve) => { entered = resolve; });
  let held = false;
  const c = await sequenceRefreshRun({
    profileOver: { refreshSessionMs: 10 },
    chainOptions: {
      // Converge on the first B read so the RPC gate below is reached before the deadline.
      propagateAfterBReads: 0,
      gate: async (method, count, side) => {
        if (!held && side === 'A' && method === 'get_block_template' && count === 3) {
          held = true;
          entered();
          await templateGate.promise;
        }
      },
    },
  });
  await c.exhaust(c.ready11);
  const ready12 = c.last('mining_ready');
  c.clock.ms = c.session.stateFacts.sessionDeadlineAtMs - 1;
  const submitting = c.say(c.candidate(ready12, ready12.nonceStart + BLOCK_OFFSET));
  await waitBounded(atTemplate, 'the H2 template RPC gate').catch((err) => {
    throw new Error(`${err.message}; counts=${JSON.stringify(c.net.counts.A)}; state=${c.sim.attemptState}/${c.sim.attemptReason}`);
  });

  const sessionTimer = c.timers.find((timer) => (
    timer.ms === c.profile.refreshSessionMs && timer.cleared === false
  ));
  assert.ok(sessionTimer, 'the whole-Start session timer was not armed');
  c.clock.ms += 1;
  sessionTimer.fn();
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING,
    'the deadline talked over the accepted block while its template read was in flight');

  templateGate.resolve();
  await waitBounded(submitting, 'the H2 template cancellation to settle');
  await c.settle();

  assert.equal(c.sim.blockRecords[0].propagation.converged, true);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.sim.attemptReason, 'search_bound_reached');
  assert.equal(c.net.counts.A.get_block_template, 3,
    'this regression did not reach the held H2 template RPC');
  assert.equal(c.sim.authority.stateFacts.published, 2,
    'the template fetched after expiry was published into authority');
  assert.equal(c.sim.authority.currentIssuanceId, ready12.issuanceId, 'H1W2 was superseded');
  assert.equal(c.all('sequence_next').length, 0, 'an H2 binding was sent');
  assert.equal(c.all('mining_ready').length, 2, 'an H2 context became ready');
  assert.equal(c.journal.created.length, 2, 'an H2 verifier was allocated');
  assert.equal(c.journal.created[1].closed, true, 'the H1W2 verifier did not stay released');
});

test('SEQUENCE REFRESH TIP: an external H1 tip skips H1W2 and starts H2W1 with a reset window', async () => {
  const c = await sequenceRefreshRun();
  assert.equal((await c.say(c.candidate(c.ready11, 7))).share, true);
  const foreign = {
    hash: 'a'.repeat(64), height: 1, nonce: 4242,
    powHash: powFor(1), prevHash: c.net.blocksA[0].hash,
  };
  c.net.blocksA.push(foreign);
  const moved = await c.sim.notifyExternalTip({ height: '1', blockId: foreign.hash });
  await c.settle();

  assert.equal(moved.ok, true, JSON.stringify(moved));
  assert.equal(c.last('sequence_next').cause, 'external_tip');
  const ready21 = c.last('mining_ready');
  assert.deepEqual([ready21.sequenceIndex, ready21.windowIndex, ready21.nonceStart], [2, 1, 0]);
  assert.equal(c.all('job_refresh').length, 0, 'the spent H1 was refreshed');
  assert.equal(c.net.log.submitBodies.length, 0);
  assert.equal(c.net.log.calcPow.length, 0);
  assert.deepEqual(c.net.log.templates.map((template) => [template.height, template.prev]), [
    [1, GENESIS], [2, foreign.hash],
  ]);
  assert.equal(c.journal.created.length, 2);
  assert.ok(c.journal.events.indexOf('closed 1') < c.journal.events.indexOf('created 2 height 2'));
});

test('SEQUENCE REFRESH RELEASE: an unconfirmed H1W2 release prevents every H2 resource', async () => {
  const c = await sequenceRefreshRun({
    buildOptions: {
      verifierOptions: (index) => (index === 2 ? { closeConfirms: false } : {}),
    },
  });
  await c.exhaust(c.ready11);
  const ready12 = c.last('mining_ready');
  await c.say(c.candidate(ready12, ready12.nonceStart + BLOCK_OFFSET));
  await c.settle();

  assert.equal(c.last('block_rejected')?.reason, 'verifier_release_unconfirmed');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
  assert.equal(c.all('sequence_next').length, 0);
  assert.equal(c.net.counts.A.get_block_template, 2, 'H2W1 was fetched after a failed release');
  assert.equal(c.journal.created.length, 2, 'an H2 verifier was created after a failed release');
  assert.deepEqual(c.journal.events.filter((event) => /^(close|force) 2$/.test(event)), ['close 2', 'force 2']);
  assert.deepEqual(
    [c.sim.verifierHistory.at(-1).block, c.sim.verifierHistory.at(-1).window, c.sim.verifierHistory.at(-1).closed],
    [1, 2, false],
  );
});

test('SEQUENCE REFRESH LATE FRAME: retired-window and retired-height bindings are free refusals', async () => {
  const c = await sequenceRefreshRun();
  await c.exhaust(c.ready11);
  const ready12 = c.last('mining_ready');

  let before = costs(c);
  assert.equal((await c.say(c.candidate(c.ready11, 33))).ok, false, 'H1W1 remained usable in H1W2');
  assert.deepEqual(costs(c), before, 'a retired-window frame did work');

  await c.say(c.candidate(ready12, ready12.nonceStart + BLOCK_OFFSET));
  await c.settle();
  const ready21 = c.last('mining_ready');
  before = costs(c);
  assert.equal((await c.say(c.candidate(ready12, ready12.nonceStart + BLOCK_OFFSET + 1))).ok, false,
    'H1W2 remained usable in H2W1');
  assert.equal((await c.say(c.candidate(ready21, 9, { runGeneration: ready12.runGeneration }))).ok, false,
    'the H2 job accepted H1 run generation');
  assert.deepEqual(costs(c), before, 'a retired-height or mixed-binding frame did work');

  assert.equal((await c.say(c.candidate(ready21, 9))).share, true, 'a stale frame spent H2W1 admission');
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.RUNNING);
  assert.equal(c.net.log.submitBodies.length, 1);
});
