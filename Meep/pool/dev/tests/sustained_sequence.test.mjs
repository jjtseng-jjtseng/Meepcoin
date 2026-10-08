// SUSTAINED ROTATION: one Start, a CONFIGURED finite sequence of more than two blocks, driven entirely
// against in-memory collaborators -- two scripted daemons behind the real daemon_rpc adapters, and
// context-bound scripted verifiers. The session, block_run, template binding, template authority, fatal
// latch, reservation and profile are the real production ones.
//
// WHAT THIS FILE IS FOR. The two-block ceiling was the only thing that made the rotation path's
// bookkeeping obviously finite. With a configured sequence it has to be finite BY CONSTRUCTION instead,
// and stale work has to stay free however many rotations have gone by. Everything here is about those
// two properties, plus the boundaries where a rotation must refuse to continue.
//
// NO WSL, DOCKER, DAEMON, HELPER, BROWSER, WASM, NATIVE VERIFIER, LISTENER, SOCKET, CHILD PROCESS,
// WALLET, KEY OR NETWORK is created, contacted or needed by this file.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SIM_ATTEMPT_STATES, createSimulationContext, createSimulationSession, realSequenceProfile,
  RETAINED_BINDINGS, RETAINED_BLOCK_RECORDS, RETAINED_VERIFIERS, RETAINED_RESOURCES,
} from '../sim_session.mjs';
import { MAX_RAW_RECORDS } from '../real_daemon_mode.mjs';
import { AuthorityEquivocationError, SUPERSEDED_TOMBSTONES, createTemplateAuthority } from '../run_guard.mjs';
import { REAL_SEQUENCE_DEV_MAX_BLOCKS, SIM_FAILURE_CODES } from '../../../web-miner/lib/shared/protocol.js';
import { buildScriptedChain, powFor } from './in_memory_chain.mjs';

const START_ID = '0123456789abcdef0123456789abcdef';
/** Longer than the old ceiling and still a small fixed number. */
const BLOCKS = 12;

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

async function sequenceContext(chainOptions = {}, buildOptions = {}) {
  const blocks = buildOptions.sequenceBlocks ?? BLOCKS;
  const ctx = await buildScriptedChain(chainOptions, { ...buildOptions, sequenceBlocks: blocks });
  const sim = createSimulationContext({
    ...ctx.built,
    profile: realSequenceProfile(blocks),
    now: () => ctx.clock.ms,
  });
  return { ...ctx, sim, blocks };
}

function driver(sim, clock) {
  const sent = [];
  const timers = [];
  const session = createSimulationSession({
    sim,
    now: () => clock.ms,
    send: (o) => sent.push(o),
    setTimer: (fn, ms) => { const t = { fn, ms, cleared: false }; timers.push(t); return t; },
    clearTimer: (t) => { t.cleared = true; },
  });
  const say = (obj) => {
    const text = JSON.stringify(obj);
    return session.handleRaw(Buffer.byteLength(text), text);
  };
  const last = (type) => [...sent].reverse().find((m) => m.type === type);
  const all = (type) => sent.filter((m) => m.type === type);
  return { session, sent, timers, say, last, all };
}

const candidateFor = (ready, nonce, over = {}) => ({
  type: 'submit_real_candidate',
  clientStartId: START_ID,
  jobId: ready.jobId,
  issuanceId: ready.issuanceId,
  workerId: ready.workerId,
  runGeneration: ready.runGeneration,
  nonce: nonce.toString(16).padStart(8, '0'),
  ...over,
});

const stopFor = (binding, reason = 'user_stop') => ({
  type: 'stop_request', clientStartId: START_ID, workerId: binding.workerId, runGeneration: binding.runGeneration,
  jobId: binding.jobId, issuanceId: binding.issuanceId, reason,
});

async function started(chainOptions, buildOptions) {
  const c = await sequenceContext(chainOptions, buildOptions);
  const d = driver(c.sim, c.clock);
  await d.say({ type: 'client_hello', protocolVersion: 1 });
  await d.say({ type: 'start_request', clientStartId: START_ID });
  return { ...c, d, ready: d.last('mining_ready') };
}

/** Search-and-accept block N: one candidate, which carries the whole rotation with it. */
const solve = (d, nonce) => d.say(candidateFor(d.last('mining_ready'), nonce));

/** Everything that costs a hash, an RPC or a submission. Stale work must move none of these. */
const costs = (c) => ({
  verifierEvents: c.journal.events.filter((e) => /^(wasm|native) /.test(e)).length,
  verifiersCreated: c.journal.created.length,
  calcPow: c.net.log.calcPow.length,
  submits: c.net.log.submitBodies.length,
  templates: c.net.counts.A.get_block_template ?? 0,
});

function assertCompleteRawEvidence(built, blocks) {
  const raw = built.rpcAudit.raw;
  assert.equal(built.rpcAudit.rawDropped, 0, 'raw A-side evidence was silently truncated');
  assert.equal(built.rpcAudit.rawLimit, MAX_RAW_RECORDS);
  assert.ok(raw.length <= MAX_RAW_RECORDS);
  for (let block = 1; block <= blocks; block += 1) {
    const methods = raw.filter((record) => record.block === block).map((record) => record.method);
    for (const required of [
      'get_block_template', 'calc_pow', 'submit_block',
      'get_block_header_by_height', 'get_last_block_header',
    ]) {
      assert.ok(methods.includes(required), `block ${block} has no raw ${required} evidence`);
    }
  }
}

// ================================================================== the sustained run
test('SUSTAINED: one Start, twelve consecutive blocks, one binding chain, and every retained structure stays under the fixed ceiling', async () => {
  const c = await started();
  const { d, sim, net, journal } = c;

  assert.equal(d.last('server_hello').sequenceTotal, BLOCKS);
  assert.equal(c.ready.sequenceIndex, 1);
  assert.ok(d.last('server_hello').labels.some((l) => l.includes(`(${BLOCKS})`)), 'the labels still say two');

  const facts = [];
  for (let block = 1; block <= BLOCKS; block += 1) {
    const ready = d.last('mining_ready');
    assert.equal(ready.sequenceIndex, block, `block ${block} was not announced`);
    assert.equal(ready.sequenceTotal, BLOCKS);
    assert.equal(sim.blockIndex, block);
    await solve(d, block + 2);
    facts.push({ block, session: d.session.stateFacts, context: sim.stateFacts });
  }

  // ---- the run really did twelve blocks, once each ---------------------------------------------
  assert.equal(d.all('run_started').length, 1, 'a second run_started would be a second Start');
  assert.equal(d.all('mining_ready').length, BLOCKS);
  assert.equal(d.all('sequence_next').length, BLOCKS - 1);
  // Every block is announced nonterminally as it is accepted -- including the last, which is then
  // followed by the one terminal block_accepted for the whole session.
  assert.equal(d.all('sequence_block_accepted').length, BLOCKS);
  assert.equal(d.last('block_accepted')?.terminal, true);
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(net.counts.A.get_block_template, BLOCKS);
  assert.equal(net.log.submitBodies.length, BLOCKS);
  assert.equal(net.log.calcPow.length, BLOCKS);
  assert.equal(net.blocksA.length, BLOCKS + 1);
  assert.deepEqual(net.blocksB.map((b) => b.hash), net.blocksA.map((b) => b.hash));
  assert.deepEqual(net.log.bWrites, [], 'a write reached daemon B');
  assert.equal(sim.authority.claimCount, BLOCKS, 'one claim per height');
  assert.equal(journal.created.length, BLOCKS, 'one server verifier per block');
  assertCompleteRawEvidence(c.built, BLOCKS);

  // ---- every rotation released the previous verifier BEFORE the next existed --------------------
  const life = journal.events.filter((e) => /^(created|closed) /.test(e));
  for (let i = 1; i < BLOCKS; i += 1) {
    const closed = life.indexOf(`closed ${i}`);
    const createdNext = life.indexOf(`created ${i + 1} height ${i + 1}`);
    assert.ok(closed >= 0, `verifier ${i} was never confirmed released`);
    assert.ok(createdNext > closed, `verifier ${i + 1} existed before ${i} was released`);
  }
  assert.equal(journal.created.filter((v) => v.closed !== true).length, 1, 'only the last verifier is still held');

  // ---- BOUNDED STATE: all retained histories share the absolute 32-block build ceiling ---------
  // Twelve blocks deliberately do not fill that ceiling: the system retains the complete finite run
  // instead of discarding an early binding and later mis-reporting it as unknown.
  for (const f of facts) {
    assert.ok(f.session.retainedBindings <= RETAINED_BINDINGS);
    assert.ok(f.context.blockRecords <= RETAINED_BLOCK_RECORDS);
    assert.ok(f.context.verifierHistory <= RETAINED_VERIFIERS);
    assert.ok(f.context.retainedResources <= RETAINED_RESOURCES);
    assert.ok(f.context.authority.tombstones <= SUPERSEDED_TOMBSTONES);
    assert.equal(f.context.authority.currentRecords, 1);
    assert.ok(f.context.authority.currentClaims <= 1);
    assert.ok(f.context.liveVerifiers <= 1, 'more than one verifier was alive at once');
    assert.ok(f.session.rotationsInFlight <= 1);
    assert.ok(f.session.fatalLatchSubscribers <= 1, 'fatal-latch subscribers accumulated across rotations');
  }
  // ...while the counters show the work really happened.
  const end = sim.stateFacts;
  assert.equal(end.blocksRecorded, BLOCKS);
  assert.equal(end.verifiersReleased, BLOCKS - 1);
  assert.equal(end.authority.published, BLOCKS);
  assert.equal(end.authority.superseded, BLOCKS - 1);
  assert.equal(end.authority.claims, BLOCKS);
  assert.equal(d.session.stateFacts.bindingsIssued, BLOCKS);

  // ---- nothing is left armed -------------------------------------------------------------------
  assert.equal(d.timers.filter((t) => !t.cleared).length, 0, 'a search backstop timer is still armed');
  // The LAST block's verifier is still held -- as in every one-shot mode, the pool's shutdown closes it --
  // and its settled single-flight cache with it. What matters is that there is never more than one.
  assert.equal(sim.stateFacts.liveVerifiers, 1);
  assert.ok(sim.stateFacts.pendingInits <= 1);
  assert.equal(sim.stateFacts.externalTipListeners, 0, 'the tip listener outlived the attempt');
  assert.equal(sim.stateFacts.faultListeners, 0);

  // ---- and it is over: no thirteenth template, no further candidate ----------------------------
  const before = costs(c);
  await assert.rejects(c.built.sequence.issueNext({ acceptedBlockId: net.blocksA.at(-1).hash, acceptedHeight: String(BLOCKS) }),
    (e) => e.code === 'sequence_exhausted');
  const after = await d.say(candidateFor(d.last('mining_ready'), 99));
  assert.equal(after.ok, false);
  assert.deepEqual(costs(c), before, 'work happened after the sequence completed');
});

test('SUSTAINED: the 32-position ceiling retains complete per-height raw evidence with zero drops', async () => {
  const blocks = REAL_SEQUENCE_DEV_MAX_BLOCKS;
  const c = await started({}, { sequenceBlocks: blocks });
  for (let block = 1; block <= blocks; block += 1) await solve(c.d, block + 2);
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(c.built.rpcAudit.raw.length, (blocks * 9) - 1,
    'the successful-path raw RPC budget changed without updating its bound');
  assertCompleteRawEvidence(c.built, blocks);
});

// ================================================================== stale, replayed and expired work
test('SUSTAINED: after nine rotations every old binding is still refused for free', async () => {
  const c = await started();
  const { d } = c;
  const early = { ready1: c.ready };
  for (let block = 1; block <= 4; block += 1) {
    if (block === 3) early.ready3 = d.last('mining_ready');
    await solve(d, block + 2);
  }
  const mid = d.last('mining_ready');
  for (let block = 5; block <= 9; block += 1) await solve(d, block + 2);
  const current = d.last('mining_ready');
  assert.equal(current.sequenceIndex, 10);

  const before = costs(c);
  for (const [name, ready] of [['block 1', early.ready1], ['block 3', early.ready3], ['block 5', mid]]) {
    for (const over of [
      {},                                                       // the whole old binding
      { jobId: current.jobId },                                 // new job, old issuance and generation
      { issuanceId: current.issuanceId },
      { runGeneration: current.runGeneration },
      { jobId: current.jobId, issuanceId: current.issuanceId }, // old generation only
      { workerId: 'sim-1-deadbeef' },                           // wrong owner
    ]) {
      const r = await d.say(candidateFor(ready, 7, over));
      assert.equal(r.ok, false, `${name} ${JSON.stringify(over)} was admitted`);
    }
  }
  assert.deepEqual(costs(c), before, 'a stale candidate did costly work');
  assert.equal(c.sim.authority.stateFacts.tombstones, 9, 'one tombstone per completed rotation was not retained');
  assert.ok(c.sim.authority.stateFacts.tombstones <= SUPERSEDED_TOMBSTONES, 'the tombstone table exceeded its fixed ceiling');

  // The current block still works normally afterwards.
  await solve(d, 12);
  assert.equal(d.last('mining_ready').sequenceIndex, 11);
});

test('SUSTAINED: replaying the winning candidate of a completed height costs nothing', async () => {
  const c = await started();
  const { d } = c;
  const ready3 = (await solve(d, 3), await solve(d, 4), d.last('mining_ready'));
  assert.equal(ready3.sequenceIndex, 3);
  const winner = candidateFor(ready3, 5);
  await d.say(winner);                       // block 3 is accepted and the session rotates
  const before = costs(c);
  for (let i = 0; i < 3; i += 1) {
    const r = await d.say(winner);           // byte-identical replays
    assert.equal(r.ok, false);
  }
  assert.deepEqual(costs(c), before, 'a replayed candidate did costly work');
  assert.equal(c.sim.authority.isClaimed(ready3.issuanceId), true);
  assert.equal(c.net.log.submitBodies.length, 3, 'a replay submitted again');
});

test('SUSTAINED: an expired issuance in the middle of a sequence is refused before any work', async () => {
  const c = await started();
  const { d, clock } = c;
  for (let block = 1; block <= 5; block += 1) await solve(d, block + 2);
  const ready6 = d.last('mining_ready');
  const before = costs(c);
  clock.ms += 20 * 60 * 1000;                 // past REAL_JOB_TTL_MS for this issuance
  const r = await d.say(candidateFor(ready6, 9));
  assert.equal(r.ok, false);
  assert.equal(c.net.log.submitBodies.length, before.submits, 'an expired candidate was submitted');
  assert.equal(c.sim.attemptFinished, true, 'the attempt should not still be live after an expired job');
});

// ================================================================== supersession from outside
test('SUSTAINED: an EXTERNAL canonical tip supersedes the active job, releases its verifier and reissues', async () => {
  // Another miner takes the height this session is searching, between blocks 4 and 5.
  const c = await started();
  const { d, sim, net, journal } = c;
  for (let block = 1; block <= 4; block += 1) await solve(d, block + 2);

  const superseded = d.last('mining_ready');
  assert.equal(superseded.sequenceIndex, 5);
  const heightNow = sim.job.height.toString();
  assert.equal(heightNow, '5');
  const verifiersBefore = journal.created.length;

  // The external block really exists on daemon A, as it would if it had arrived over P2P.
  const foreign = { hash: 'a'.repeat(64), height: 5, nonce: 4242, powHash: powFor(5), prevHash: net.blocksA.at(-1).hash };
  net.blocksA.push(foreign);

  const r = await sim.notifyExternalTip({ height: heightNow, blockId: foreign.hash });
  assert.equal(r.ok, true, JSON.stringify(r));

  // A fresh job, for the block ON TOP of the foreign one, under the same Start.
  const next = d.last('sequence_next');
  assert.equal(next.cause, 'external_tip');
  assert.equal(next.sequenceIndex, 6);
  assert.deepEqual(next.previous, {
    jobId: superseded.jobId, issuanceId: superseded.issuanceId, runGeneration: superseded.runGeneration,
  });
  assert.equal(sim.templateFacts.prevHashHex, foreign.hash, 'the new template does not build on the foreign tip');
  assert.equal(sim.job.height.toString(), '6');
  assert.equal(d.last('mining_ready').sequenceIndex, 6);
  assert.equal(sim.attemptFinished, false);

  // The superseded block's verifier was physically released BEFORE the next one existed.
  const life = journal.events.filter((e) => /^(created|closed) /.test(e));
  assert.ok(life.indexOf(`closed ${verifiersBefore}`) >= 0, 'the superseded verifier was not released');
  assert.ok(life.indexOf(`created ${verifiersBefore + 1} height 6`) > life.indexOf(`closed ${verifiersBefore}`));
  assert.equal(journal.created.filter((v) => v.closed !== true).length, 1);

  // Nothing was mined, claimed, calc_pow'd or submitted for the foreign block.
  assert.equal(net.log.submitBodies.length, 4);
  assert.equal(net.log.calcPow.length, 4);
  assert.equal(sim.authority.claimCount, 4);
  assert.deepEqual(net.log.bWrites, []);

  // LATE WORK ON THE SUPERSEDED JOB IS FREE, and the run continues normally.
  const before = costs(c);
  for (const over of [{}, { runGeneration: d.last('mining_ready').runGeneration }]) {
    const late = await d.say(candidateFor(superseded, 6, over));
    assert.equal(late.ok, false);
  }
  assert.deepEqual(costs(c), before, 'late work on a superseded job cost something');
  await solve(d, 11);
  assert.equal(d.last('mining_ready').sequenceIndex, 7);
});

test('SUSTAINED: an external tip revokes an in-flight candidate immediately, drains it, then rotates without stale dispatch', async () => {
  const gate = deferred();
  let entered;
  const atHash = new Promise((resolve) => { entered = resolve; });
  const c = await started({}, {
    verifierOptions: (n) => (n === 1 ? { wasmGate: async () => { entered(); await gate.promise; } } : {}),
  });
  const { d, sim, net, journal } = c;
  const stale = d.last('mining_ready');
  const candidate = d.say(candidateFor(stale, 3));
  await atHash;
  assert.equal(d.session.run.inFlight, 1);

  const foreign = { hash: 'e'.repeat(64), height: 1, nonce: 99, powHash: powFor(1), prevHash: net.blocksA[0].hash };
  net.blocksA.push(foreign);
  const moving = sim.notifyExternalTip({ height: '1', blockId: foreign.hash });
  // Revocation is synchronous even though the returned operation is waiting for the old hash.
  assert.equal(d.session.intent.active, false);
  assert.equal(journal.created[0].closed, false, 'the verifier was closed while its hash was in flight');
  assert.equal(net.log.calcPow.length, 0);
  assert.equal(net.log.submitBodies.length, 0);

  gate.resolve();
  const [candidateResult, moved] = await Promise.all([candidate, moving]);
  assert.equal(candidateResult.ok, false);
  assert.equal(moved.ok, true, JSON.stringify(moved));
  assert.equal(net.log.calcPow.length, 0, 'the revoked candidate reached calc_pow');
  assert.equal(net.log.submitBodies.length, 0, 'the revoked candidate was dispatched');
  assert.equal(journal.created[0].closed, true);
  assert.equal(d.last('sequence_next').cause, 'external_tip');
  assert.equal(d.last('mining_ready').sequenceIndex, 2);
  assert.equal(sim.job.height.toString(), '2');
});

test('SUSTAINED: an external tip during the initial verifier build joins and releases it before rotating', async () => {
  const gate = deferred();
  let enteredBuild;
  const atBuild = new Promise((resolve) => { enteredBuild = resolve; });
  const c = await sequenceContext({}, {
    makeVerifierGate: async (n) => {
      if (n === 1) {
        enteredBuild();
        await gate.promise;
      }
    },
  });
  const d = driver(c.sim, c.clock);
  await d.say({ type: 'client_hello', protocolVersion: 1 });
  const starting = d.say({ type: 'start_request', clientStartId: START_ID });
  await atBuild;

  const foreign = {
    hash: 'd'.repeat(64), height: 1, nonce: 101, powHash: powFor(1), prevHash: c.net.blocksA[0].hash,
  };
  c.net.blocksA.push(foreign);
  const moving = c.sim.notifyExternalTip({ height: '1', blockId: foreign.hash });
  assert.equal(c.journal.created.length, 0, 'the gated verifier unexpectedly finished construction');
  assert.equal(c.net.counts.A.get_block_template, 1, 'a replacement template was fetched before release');

  gate.resolve();
  const [startResult, moved] = await Promise.all([starting, moving]);
  assert.deepEqual(startResult, { ok: false, reason: 'superseded_before_ready' });
  assert.equal(moved.ok, true, JSON.stringify(moved));
  assert.equal(c.journal.created.length, 2, 'the old verifier or its replacement was not constructed exactly once');
  assert.equal(c.journal.created[0].closed, true, 'the first verifier was not positively released');
  assert.equal(c.journal.events.indexOf('closed 1') < c.journal.events.indexOf('created 2 height 2'), true,
    'the replacement verifier existed before the initial verifier was released');
  assert.equal(d.all('mining_ready').length, 1, 'the superseded initial job was announced ready');
  assert.equal(d.last('mining_ready').sequenceIndex, 2);
  assert.equal(d.last('sequence_next').cause, 'external_tip');
  assert.equal(c.sim.stateFacts.liveVerifiers, 1);
  assert.equal(c.sim.job.height.toString(), '2');
});

test('SUSTAINED: a lower or malformed external tip is inert, and an exact tip ends the run when the sequence is spent', async () => {
  const c = await started({}, { sequenceBlocks: 3 });
  const { d, sim, net } = c;
  await solve(d, 3);
  const before = costs(c);
  // A lower height or malformed observation changes nothing at all.
  for (const bad of [
    { height: '1', blockId: 'b'.repeat(64) },
    { height: sim.job.height.toString(), blockId: 'not-a-hash' },
  ]) {
    const r = await sim.notifyExternalTip(bad);
    assert.equal(r.ok, false, JSON.stringify(bad));
  }
  assert.deepEqual(costs(c), before);
  assert.equal(sim.attemptFinished, false);

  // The last block of the sequence, taken by someone else: there is no further template to issue.
  await solve(d, 4);
  const last = d.last('mining_ready');
  assert.equal(last.sequenceIndex, 3);
  const foreign = { hash: 'c'.repeat(64), height: 3, nonce: 7, powHash: powFor(3), prevHash: net.blocksA.at(-1).hash };
  net.blocksA.push(foreign);
  const r = await sim.notifyExternalTip({ height: '3', blockId: foreign.hash });
  assert.equal(r.ok, true);
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(d.last('block_rejected')?.reason, 'external_tip_superseded');
  assert.ok(SIM_FAILURE_CODES.includes('external_tip_superseded'));
  assert.equal(net.counts.A.get_block_template, 3, 'a template was fetched with the sequence spent');
  // And it does not auto-resume.
  assert.equal((await sim.notifyExternalTip({ height: '4', blockId: 'd'.repeat(64) })).ok, false);
});

test('SUSTAINED: a canonical tip ahead of this job revokes stale work and stops instead of guessing a catch-up template', async () => {
  const c = await started();
  const { d, sim } = c;
  await solve(d, 3);
  const stale = d.last('mining_ready');
  const before = costs(c);
  const r = await sim.notifyExternalTip({ height: '9', blockId: 'b'.repeat(64) });
  assert.deepEqual(r, { ok: true, reason: 'tip_ahead_session_stopped' });
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(d.last('block_rejected')?.reason, 'external_tip_superseded');
  assert.deepEqual(costs(c), before, 'a higher tip fetched, hashed or submitted anything');
  assert.equal((await d.say(candidateFor(stale, 9))).ok, false, 'the stale job remained usable');
  assert.deepEqual(costs(c), before, 'stale work after the higher tip was costly');
});

// ================================================================== boundaries, late in the run
for (const how of ['user_stop', 'page_hidden', 'page_unload', 'socket_close', 'fatal_latch']) {
  test(`SUSTAINED: ${how} at the ninth rotation prevents block 10 and never resumes`, async () => {
    const gate = deferred();
    let paused;
    const atPause = new Promise((r) => { paused = r; });
    const c = await started({}, {
      // Pause the rotation out of block 9, inside the release of its verifier.
      verifierOptions: (n) => (n === 9 ? { closeGate: async () => { paused(); await gate.promise; } } : {}),
    });
    const { d, sim, net, journal } = c;
    for (let block = 1; block <= 8; block += 1) await solve(d, block + 2);
    const ready9 = d.last('mining_ready');
    assert.equal(ready9.sequenceIndex, 9);

    const rotating = d.say(candidateFor(ready9, 11));
    await atPause;
    if (how === 'socket_close') {
      d.session.dispose();
    } else if (how === 'fatal_latch') {
      sim.recordInitFailure(new Error('native helper died'));
    } else {
      const r = await d.say(stopFor(ready9, how));
      assert.equal(r.accepted, true, `${how}: the stop was not accepted`);
    }
    gate.resolve();
    await rotating;

    assert.equal(sim.attemptState,
      how === 'fatal_latch' ? SIM_ATTEMPT_STATES.TERMINAL_FAILED : SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
    assert.equal(d.all('mining_ready').length, 9, 'block 10 was announced ready');
    assert.equal(net.counts.A.get_block_template, 9, 'a tenth template was fetched');
    assert.equal(net.log.submitBodies.length, 9);
    assert.equal(journal.created.length, 9, 'a block-10 verifier was created');

    // Nothing revives it: neither a candidate nor an external tip nor a visible tab.
    const before = costs(c);
    await d.say(candidateFor(ready9, 12));
    const next = d.last('sequence_next');
    if (next) await d.say(candidateFor(next, 13));
    assert.equal((await sim.notifyExternalTip({ height: '10', blockId: 'e'.repeat(64) })).ok, false);
    assert.deepEqual(costs(c), before, 'something resumed after the boundary');
    assert.equal(d.timers.filter((t) => !t.cleared).length, 0, 'a timer is still armed');
    assert.deepEqual(net.log.bWrites, []);
  });
}

test('SUSTAINED: a verifier fault at the eleventh block ends everything and no later work is possible', async () => {
  const c = await started();
  const { d, sim, net, journal } = c;
  for (let block = 1; block <= 10; block += 1) await solve(d, block + 2);
  const ready11 = d.last('mining_ready');
  assert.equal(ready11.sequenceIndex, 11);

  journal.created[10].hashNative = async () => new Uint8Array(32).fill(0x11);   // the two paths disagree
  await d.say(candidateFor(ready11, 13));

  assert.equal(sim.latch.tripped, true);
  assert.equal(d.last('block_rejected')?.reason, 'fatal_verifier');
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
  assert.equal(net.log.submitBodies.length, 10, 'block 11 was submitted after a disagreement');
  assert.equal(net.counts.A.get_block_template, 11);

  const before = costs(c);
  await d.say(candidateFor(ready11, 14));
  assert.equal((await sim.notifyExternalTip({ height: '11', blockId: 'f'.repeat(64) })).ok, false);
  assert.deepEqual(costs(c), before, 'work happened after the latch tripped');
});

test('SUSTAINED: a release that cannot be confirmed at the seventh rotation stops the session there', async () => {
  const c = await started({}, { verifierOptions: (n) => (n === 7 ? { closeConfirms: false } : {}) });
  const { d, sim, net, journal } = c;
  for (let block = 1; block <= 7; block += 1) await solve(d, block + 2);

  assert.equal(d.last('block_rejected')?.reason, 'verifier_release_unconfirmed');
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
  assert.equal(journal.created.length, 7, 'a block-8 verifier was created after an unconfirmed release');
  assert.deepEqual(journal.events.filter((e) => /^(close|force) 7$/.test(e)), ['close 7', 'force 7']);
  assert.equal(net.counts.A.get_block_template, 7, 'a template was fetched after an unconfirmed release');
  assert.equal(sim.verifierHistory.at(-1).closed, false);
  assert.equal(d.timers.filter((t) => !t.cleared).length, 0);
});

// ================================================================== contention and configuration
test('SUSTAINED: a second session cannot join a long sequence, at any point in it', async () => {
  const c = await sequenceContext();
  const one = driver(c.sim, c.clock);
  const two = driver(c.sim, c.clock);
  await one.say({ type: 'client_hello', protocolVersion: 1 });
  await two.say({ type: 'client_hello', protocolVersion: 1 });
  await one.say({ type: 'start_request', clientStartId: START_ID });
  assert.equal((await two.say({ type: 'start_request', clientStartId: 'f'.repeat(32) })).ok, false);
  assert.equal(two.last('run_unavailable')?.reason, 'simulation_attempt_in_progress');

  for (let block = 1; block <= 6; block += 1) {
    const ready = one.last('mining_ready');
    const before = costs(c);
    // The other connection knows the binding -- it can read the same job -- and still cannot use it.
    assert.equal((await two.say(candidateFor(ready, block + 2))).ok, false);
    assert.equal((await two.say(stopFor(ready))).ok, false);
    assert.equal((await two.say({ type: 'start_request', clientStartId: 'f'.repeat(32) })).ok, false);
    assert.deepEqual(costs(c), before, 'the second session did costly work');
    await one.say(candidateFor(ready, block + 2));
  }
  assert.equal(one.last('mining_ready').sequenceIndex, 7);
  assert.equal(c.sim.authority.claimCount, 6);
  assert.equal(c.journal.created.length, 7);
  // Only the one session ever held a tip listener or a fault listener.
  assert.equal(c.sim.stateFacts.externalTipListeners, 1);
  assert.equal((await c.sim.notifyExternalTip({ height: '1', blockId: 'a'.repeat(64) })).ok, false);
});

test('SUSTAINED: the configured length is a hard, finite, trusted-only bound', async () => {
  assert.throws(() => realSequenceProfile(1), /blocks/);
  assert.throws(() => realSequenceProfile(REAL_SEQUENCE_DEV_MAX_BLOCKS + 1), /blocks/);
  assert.throws(() => realSequenceProfile(2.5), /blocks/);
  const p = realSequenceProfile(REAL_SEQUENCE_DEV_MAX_BLOCKS);
  assert.equal(p.sequenceBlocks, REAL_SEQUENCE_DEV_MAX_BLOCKS);
  assert.ok(p.labels.some((l) => l.includes(`(${REAL_SEQUENCE_DEV_MAX_BLOCKS})`)));
  assert.ok(p.helloNotice.includes(`(${REAL_SEQUENCE_DEV_MAX_BLOCKS})`));
  // A three-block run still says three, everywhere a human reads it.
  const three = realSequenceProfile(3);
  assert.ok(three.helloNotice.includes('THREE (3)'));
  assert.ok(three.actionLabel.includes('three'));
  assert.ok(!three.helloNotice.includes('TWO ('));
});

test('SUSTAINED: authority history overflow is atomic and cannot mark the current issuance superseded', () => {
  const authority = createTemplateAuthority({ now: () => 1, maxClaims: REAL_SEQUENCE_DEV_MAX_BLOCKS });
  const job = (n) => ({
    jobId: `job-${n}`,
    issuanceId: n.toString(16).padStart(32, '0'),
    contentDigest: n.toString(16).padStart(64, '0'),
    expiresAtMs: 10,
  });
  // One current record plus the complete 32-entry absolute tombstone ceiling.
  for (let n = 1; n <= SUPERSEDED_TOMBSTONES + 1; n += 1) authority.publish(job(n));
  const before = authority.stateFacts;
  const current = authority.current;
  assert.equal(before.tombstones, SUPERSEDED_TOMBSTONES);
  assert.equal(authority.isSuperseded(current.issuanceId), false);
  assert.throws(() => authority.publish(job(SUPERSEDED_TOMBSTONES + 2)), AuthorityEquivocationError);
  assert.deepEqual(authority.stateFacts, before, 'overflow changed counters or retained sizes');
  assert.deepEqual(authority.current, current, 'overflow replaced the current publication');
  assert.equal(authority.isSuperseded(current.issuanceId), false, 'overflow tombstoned the current issuance');
});
