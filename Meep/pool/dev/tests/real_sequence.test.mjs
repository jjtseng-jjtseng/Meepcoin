// THE TWO-BLOCK CONSENTED SESSION, server side, with every live dependency injected: two in-memory
// daemons with a real little chain (in_memory_chain.mjs) behind the real daemon_rpc adapters, and
// context-bound scripted verifiers. The session, block_run, template binding, authority, fatal latch,
// reservation and profile are the real ones.
//
// NO WSL, DOCKER, DAEMON, HELPER, BROWSER, LISTENER OR SOCKET is started by this file.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { buildRealDaemonMode } from '../real_daemon_mode.mjs';
import {
  REAL_P2P_PROFILE, REAL_P2P_SEQUENCE_PROFILE, SIM_ATTEMPT_STATES, createSimulationContext, createSimulationSession,
  REAL_P2P_NATURAL_PROFILE, realNaturalSequenceProfile,
} from '../sim_session.mjs';
import { createTemplateAuthority, CLAIM_REFUSED } from '../run_guard.mjs';
import { CHAIN_A, CHAIN_B, GENESIS, buildScriptedChain, powFor } from './in_memory_chain.mjs';
import {
  REAL_SEQUENCE_DEV_MAX_BLOCKS, REAL_SEQUENCE_MAX_BLOCKS, SIM_FAILURE_CODES,
} from '../../../web-miner/lib/shared/protocol.js';

const START_ID = '0123456789abcdef0123456789abcdef';
const WRITE_METHODS = ['submit_block', 'calc_pow', 'get_block_template'];

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

async function sequenceContext(chainOptions = {}, buildOptions = {}) {
  const ctx = await buildScriptedChain(chainOptions, buildOptions);
  const sim = createSimulationContext({
    ...ctx.built,
    profile: ctx.built.naturalDifficulty
      ? (ctx.built.sequence ? realNaturalSequenceProfile(ctx.built.sequence.total) : REAL_P2P_NATURAL_PROFILE)
      : (ctx.built.sequence ? REAL_P2P_SEQUENCE_PROFILE : REAL_P2P_PROFILE),
    now: () => ctx.clock.ms,
  });
  return { ...ctx, sim };
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
  return { ...c, d, ready1: d.last('mining_ready') };
}

const perVerifier = (journal) => journal.created.map((v) => ({ height: v.context.height, ...v.counters, closed: v.closed }));

test('NATURAL PAIR: a fresh second height takes its own daemon-issued difficulty, not 500 or the prior target', async () => {
  const c = await started({ difficultyForHeight: (height) => height === 1 ? 750 : 900 },
    { naturalDifficulty: true, sequenceBlocks: 2 });
  assert.equal(c.built.naturalDifficulty, true);
  assert.equal(c.sim.templateFacts.difficulty, '750');
  assert.equal(c.d.last('server_hello').labels.some((s) => s.includes('FIXED TEST DIFFICULTY')), false);
  await c.d.say(candidateFor(c.ready1, 11));
  const ready2 = c.d.last('mining_ready');
  assert.ok(ready2, JSON.stringify(c.d.sent.map((m) => [m.type, m.reason])));
  assert.equal(ready2.sequenceIndex, 2);
  assert.equal(c.sim.templateFacts.difficulty, '900');
  assert.equal(c.sim.job.height, 2n);
  await c.d.say(candidateFor(ready2, 22));
  assert.equal(c.d.last('block_accepted')?.height, '2');
  assert.deepEqual(c.net.log.templates.map((t) => t.height), [1, 2]);
  assert.equal(c.net.log.submitBodies.length, 2);
  assert.deepEqual(c.net.log.bWrites, []);
});

test('NATURAL PAIR: three fresh-chain heights reach the first changing daemon target under one Start', async () => {
  const c = await started({ difficultyForHeight: (height) => height < 3 ? 1 : 60 },
    { naturalDifficulty: true, sequenceBlocks: 3 });
  const { d, sim, net, journal, built } = c;
  assert.equal(d.last('server_hello').sequenceTotal, 3);
  assert.equal(sim.templateFacts.difficulty, '1');
  const firstTarget = sim.job.targetHexLE;
  await d.say(candidateFor(c.ready1, 11));
  const ready2 = d.last('mining_ready');
  assert.equal(ready2.sequenceIndex, 2);
  assert.equal(sim.templateFacts.difficulty, '1');
  assert.equal(sim.job.targetHexLE, firstTarget);
  await d.say(candidateFor(ready2, 22));
  const ready3 = d.last('mining_ready');
  assert.equal(ready3.sequenceIndex, 3);
  assert.equal(sim.templateFacts.difficulty, '60');
  assert.notEqual(sim.job.targetHexLE, firstTarget);
  assert.equal(sim.job.height, 3n);
  const beforeStale = { hashes: journal.events.length, pow: net.log.calcPow.length,
    submits: net.log.submitBodies.length };
  assert.equal((await d.say(candidateFor(ready2, 23))).ok, false);
  assert.equal(journal.events.length, beforeStale.hashes);
  assert.equal(net.log.calcPow.length, beforeStale.pow);
  assert.equal(net.log.submitBodies.length, beforeStale.submits);
  await d.say(candidateFor(ready3, 33));
  assert.equal(d.last('block_accepted')?.height, '3');
  assert.equal(d.all('run_started').length, 1);
  assert.deepEqual(net.log.templates.map((t) => t.height), [1, 2, 3]);
  assert.equal(net.log.submitBodies.length, 3);
  assert.deepEqual(net.log.bWrites, []);
  assert.deepEqual(net.blocksB.map((b) => b.hash), net.blocksA.map((b) => b.hash));
  await assert.rejects(built.sequence.issueNext({ acceptedBlockId: d.last('block_accepted').blockId,
    acceptedHeight: '3' }), (err) => err?.code === 'sequence_exhausted');
});

// ================================================================== the whole sequence
test('SEQUENCE: one Start, two fresh consecutive templates, one candidate / hash / calc_pow / submit per height, B shows both', async () => {
  const c = await started();
  const { d, sim, net, journal, built } = c;
  const hello = d.last('server_hello');
  assert.equal(hello.sequenceTotal, 2);
  assert.deepEqual(hello.labels, [...REAL_P2P_SEQUENCE_PROFILE.labels]);
  assert.equal(c.ready1.sequenceIndex, 1);
  assert.equal(d.all('run_started').length, 1, 'a second run_started would be a second Start');
  const job1 = sim.job;
  assert.equal(job1.height, 1n);
  assert.equal(built.templateFacts.prevHashHex, GENESIS);

  // ---- block 1 --------------------------------------------------------------------------------
  await d.say(candidateFor(c.ready1, 11));
  const acc1 = d.all('sequence_block_accepted')[0];
  assert.ok(acc1, JSON.stringify(d.sent.map((m) => [m.type, m.reason])));
  assert.equal(acc1.terminal, false);
  assert.equal(acc1.sequenceIndex, 1);
  assert.equal(acc1.height, '1');
  assert.equal(acc1.nonce, 11);
  assert.equal(acc1.hashHexLE, powFor(1));
  assert.equal(acc1.blockId, net.blocksA[1].hash);

  // ---- the rotation ---------------------------------------------------------------------------
  const next = d.last('sequence_next');
  assert.ok(next, 'no sequence_next');
  assert.deepEqual(next.previous, { jobId: c.ready1.jobId, issuanceId: c.ready1.issuanceId, runGeneration: c.ready1.runGeneration });
  assert.equal(next.sequenceIndex, 2);
  assert.equal(next.clientStartId, START_ID);
  assert.equal(next.workerId, c.ready1.workerId);
  const job2 = sim.job;
  assert.notEqual(job2, job1);
  assert.equal(job2.height, 2n);
  assert.equal(sim.templateFacts.prevHashHex, acc1.blockId, 'block 2 does not build on the accepted block 1');
  assert.equal(sim.templateFacts.topBeforeHash, acc1.blockId);
  assert.equal(sim.templateFacts.difficulty, '500');
  for (const field of ['jobId', 'issuanceId', 'contentDigest']) assert.notEqual(job2[field], job1[field], field);
  assert.ok(job2.expiresAtMs >= job1.expiresAtMs);
  assert.notEqual(job2.hashingTemplateHex, job1.hashingTemplateHex);
  assert.equal(next.job.height, '2');
  assert.equal(next.job.jobId, job2.jobId);
  assert.equal(next.jobId, job2.jobId);
  assert.ok(next.runGeneration > c.ready1.runGeneration);
  assert.equal(JSON.stringify(next).includes('blocktemplate'), false, 'the full block reached the page');
  // Superseded before it can be acted on, and one claim per issuance.
  assert.equal(sim.authority.isSuperseded(job1.issuanceId), true);
  assert.equal(sim.authority.isCurrent(job2.issuanceId), true);
  // The block-1 verifier was confirmed released BEFORE the block-2 verifier was created.
  const iClosed1 = journal.events.indexOf('closed 1');
  const iCreated2 = journal.events.findIndex((e) => e.startsWith('created 2'));
  assert.ok(iClosed1 >= 0 && iCreated2 > iClosed1, journal.events.join(' | '));
  assert.equal(journal.created[1].context.height, '2', 'the block-2 verifier is not bound to the block-2 context');
  assert.equal(journal.created[1].context.templateHex, sim.recordedContext.templateHex);
  const ready2 = d.last('mining_ready');
  assert.equal(ready2.jobId, job2.jobId);
  assert.equal(ready2.runGeneration, next.runGeneration);
  assert.equal(ready2.sequenceIndex, 2);

  // ---- block 2 --------------------------------------------------------------------------------
  await d.say(candidateFor(ready2, 22));
  const done = d.last('block_accepted');
  assert.ok(done, JSON.stringify(d.sent.map((m) => [m.type, m.reason])));
  assert.equal(done.terminal, true);
  assert.equal(done.height, '2');
  assert.equal(done.nonce, 22);
  assert.equal(done.hashHexLE, powFor(2));
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.deepEqual(done.sequence.accepted.map((b) => [b.height, b.nonce, b.propagated]), [['1', 11, true], ['2', 22, true]]);

  // ---- per-height bounds and the chain on both daemons -----------------------------------------
  assert.deepEqual(perVerifier(journal), [
    { height: '1', wasmShareHashes: 1, nativeShareHashes: 1, closed: true },
    { height: '2', wasmShareHashes: 1, nativeShareHashes: 1, closed: false },   // closed by pool shutdown
  ]);
  assert.deepEqual(net.log.calcPow.map((p) => p.height), [1, 2]);
  assert.equal(net.log.submitBodies.length, 2);
  assert.deepEqual(net.log.templates.map((t) => [t.height, t.prev]), [[1, GENESIS], [2, acc1.blockId]]);
  assert.equal(net.counts.A.get_block_template, 2);
  assert.deepEqual(net.log.bWrites, [], 'a write reached daemon B');
  assert.deepEqual(net.blocksB.map((b) => b.hash), net.blocksA.map((b) => b.hash));
  assert.equal(net.blocksA.length, 3);
  assert.equal(sim.authority.claimCount, 2);
  const records = sim.blockRecords;
  assert.deepEqual(records.map((r) => [r.block, r.accepted.height, r.propagation.converged]), [[1, '1', true], [2, '2', true]]);
  assert.equal(records[0].verifier.closed, true);
  assert.equal(records[0].verifier.forced, false);
  assert.equal(records[0].lastHashes.serverWasmHex, powFor(1));
  assert.equal(records[1].lastHashes.nativeHelperHex, powFor(2));
  // Raw evidence is tagged with the block it belongs to.
  assert.deepEqual(built.rpcAudit.raw.filter((r) => r.method === 'get_block_template').map((r) => r.block), [1, 2]);
  assert.deepEqual(built.rpcAudit.snapshots.map((s) => s.block), [1, 2]);
  // There is no third template.
  await assert.rejects(built.sequence.issueNext({ acceptedBlockId: done.blockId, acceptedHeight: '2' }), (e) => e.code === 'sequence_exhausted');
  assert.equal(net.counts.A.get_block_template, 2);
  const after = await d.say(candidateFor(ready2, 23));
  assert.equal(after.ok, false);
  assert.equal(net.log.submitBodies.length, 2);
});

test('SEQUENCE: a STALE block-1 candidate after block 2 is published costs nothing and cannot touch block 2', async () => {
  const c = await started();
  const { d, journal, net } = c;
  await d.say(candidateFor(c.ready1, 3));
  const ready2 = d.last('mining_ready');
  assert.equal(ready2.sequenceIndex, 2);
  const before = { events: journal.events.length, calcPow: net.log.calcPow.length, submits: net.log.submitBodies.length };
  for (const over of [
    {},                                                                   // the whole block-1 binding
    { jobId: ready2.jobId },                                              // job 2, issuance 1, generation 1
    { issuanceId: ready2.issuanceId },
    { runGeneration: ready2.runGeneration },
    { jobId: ready2.jobId, issuanceId: ready2.issuanceId },               // generation 1 only
  ]) {
    const r = await d.say(candidateFor(c.ready1, 4, over));
    assert.equal(r.ok, false, JSON.stringify(over));
  }
  assert.equal(journal.events.length, before.events, `stale candidates hashed: ${journal.events.slice(before.events)}`);
  assert.equal(net.log.calcPow.length, before.calcPow);
  assert.equal(net.log.submitBodies.length, before.submits);
  // ...and block 2's one candidate is still unspent.
  await d.say(candidateFor(ready2, 5));
  assert.ok(d.last('block_accepted'));
});

test('SEQUENCE: a candidate while the session is between templates is refused before any work', async () => {
  const gate = deferred();
  let paused;
  const atPause = new Promise((r) => { paused = r; });
  const c = await started({ gate: async (method, n, side) => { if (side === 'A' && method === 'get_block_template' && n === 2) { paused(); await gate.promise; } } });
  const { d, journal, net } = c;
  const submitting = d.say(candidateFor(c.ready1, 3));
  await atPause;
  const events = journal.events.length;
  const r = await d.say(candidateFor(c.ready1, 9));
  assert.equal(r.ok, false);
  assert.equal(d.last('error')?.detail, 'the session is between templates');
  assert.equal(journal.events.length, events);
  assert.equal(net.log.submitBodies.length, 1);
  gate.resolve();
  await submitting;
  assert.equal(d.last('mining_ready').sequenceIndex, 2);
});

// ================================================================== every rotation boundary
/**
 * Pause the rotation at `boundary`, revoke consent there by `how`, then let it continue. Nothing for
 * block 2 may become ready, and no block-2 candidate can be admitted.
 */
async function interruptRotation(boundary, how) {
  const gate = deferred();
  let paused;
  const atPause = new Promise((r) => { paused = r; });
  const chainOptions = {};
  const buildOptions = {};
  if (boundary === 'propagation') {
    // B's first read AFTER block 1 exists on A, i.e. the first propagation poll.
    let armed = true;
    chainOptions.gate = async (method, n, side, chain) => {
      if (armed && side === 'B' && method === 'get_last_block_header' && chain.blocksA.length === 2) { armed = false; paused(); await gate.promise; }
    };
  } else if (boundary === 'release') {
    buildOptions.verifierOptions = (n) => (n === 1 ? { closeGate: async () => { paused(); await gate.promise; } } : {});
  } else if (boundary === 'template') {
    chainOptions.gate = async (method, n, side) => { if (side === 'A' && method === 'get_block_template' && n === 2) { paused(); await gate.promise; } };
  } else if (boundary === 'next_verifier') {
    buildOptions.makeVerifierGate = async (n) => { if (n === 2) { paused(); await gate.promise; } };
  }
  const c = await started(chainOptions, buildOptions);
  const { d, sim } = c;
  const submitting = d.say(candidateFor(c.ready1, 3));
  await atPause;
  if (how === 'socket_close') {
    d.session.dispose();
  } else if (how === 'fatal_latch') {
    sim.recordInitFailure(new Error('native helper died'));   // the process latch, as a real fault trips it
  } else {
    // The page still holds block 1's binding (or, at the last boundary, block 2's): either is honoured.
    const binding = boundary === 'next_verifier' ? d.last('sequence_next') : c.ready1;
    const r = await d.say(stopFor(binding, how));
    assert.equal(r.accepted, true, `${boundary}/${how}: the stop was not accepted`);
  }
  gate.resolve();
  await submitting;
  return c;
}

for (const boundary of ['propagation', 'release', 'template', 'next_verifier']) {
  for (const how of ['user_stop', 'page_hidden', 'page_unload', 'socket_close', 'fatal_latch']) {
    test(`SEQUENCE: ${how} during the rotation at "${boundary}" ends the session with nothing ready for block 2`, async () => {
      const c = await interruptRotation(boundary, how);
      const { d, sim, net, journal } = c;
      const expected = how === 'fatal_latch' ? SIM_ATTEMPT_STATES.TERMINAL_FAILED : SIM_ATTEMPT_STATES.TERMINAL_CANCELLED;
      assert.equal(sim.attemptState, expected, JSON.stringify(d.sent.map((m) => [m.type, m.reason])));
      assert.equal(d.all('mining_ready').length, 1, 'block 2 was announced ready');
      assert.equal(net.log.submitBodies.length, 1);
      // Templates: the second is fetched only if consent survived to that step.
      const templates = { propagation: 1, release: 1, template: 2, next_verifier: 2 }[boundary];
      assert.equal(net.counts.A.get_block_template, templates, 'templates fetched');
      // A block-2 verifier exists only if its construction had already begun -- and then its startup
      // was aborted, not completed.
      if (boundary === 'next_verifier') {
        assert.equal(journal.signals[1]?.aborted, true, 'the next verifier startup was not aborted');
        assert.equal(journal.created.length, 1);
      } else {
        assert.ok(journal.created.length <= 1, 'a block-2 verifier was created');
      }
      // No later message can revive it: a block-2-shaped candidate is refused before work.
      const events = journal.events.length;
      const next = d.last('sequence_next');
      if (next) await d.say(candidateFor(next, 5));
      assert.equal(journal.events.length, events);
      assert.deepEqual(net.log.bWrites, []);
      if (how === 'fatal_latch') assert.equal(sim.latch.tripped, true);
    });
  }
}

// ================================================================== outcomes that must never advance
test('SEQUENCE: an AMBIGUOUS block-1 submission advances only when exact canonical readback resolves it', async () => {
  const resolved = await started({ submit: { 1: 'lost' } });
  await resolved.d.say(candidateFor(resolved.ready1, 3));
  const acc = resolved.d.last('sequence_block_accepted');
  assert.equal(acc?.confirmedBy, 'canonical_readback_resolved_an_ambiguous_submission');
  assert.equal(resolved.d.last('mining_ready').sequenceIndex, 2);

  const unresolved = await started({ submit: { 1: 'lost_unresolvable' } });
  await unresolved.d.say(candidateFor(unresolved.ready1, 3));
  assert.equal(unresolved.d.last('block_rejected')?.reason, 'submit_outcome_ambiguous');
  assert.equal(unresolved.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
  assert.equal(unresolved.d.all('sequence_next').length, 0);
  assert.equal(unresolved.net.counts.A.get_block_template, 1);
  assert.equal(unresolved.net.log.submitBodies.length, 1, 'the block was resubmitted');
});

test('SEQUENCE: an explicit daemon refusal of block 1 never advances', async () => {
  const c = await started({ submit: { 1: 'refuse' } });
  await c.d.say(candidateFor(c.ready1, 3));
  assert.equal(c.d.last('block_rejected')?.reason, 'submit_rejected');
  assert.equal(c.d.all('sequence_block_accepted').length, 0);
  assert.equal(c.net.counts.A.get_block_template, 1);
  assert.equal(c.journal.created[0].closed, false, 'the verifier was rotated after a refusal');
});

test('SEQUENCE: daemon B that never shows block 1 is p2p_propagation_failed -- no release, no next template', async () => {
  const c = await started({ neverPropagate: { 1: true } });
  await c.d.say(candidateFor(c.ready1, 3));
  const fail = c.d.last('block_rejected');
  assert.equal(fail?.reason, 'p2p_propagation_failed');
  assert.equal(fail.terminal, true);
  assert.ok(SIM_FAILURE_CODES.includes('p2p_propagation_failed'));
  assert.equal(c.net.counts.A.get_block_template, 1);
  assert.equal(c.journal.created.length, 1);
  assert.deepEqual(c.net.log.bWrites, []);
  assert.equal(c.sim.blockRecords[0].propagation.reason, 'P2P_PROPAGATION_FAILED');

  // The same for block 2: the session does not complete.
  const late = await started({ neverPropagate: { 2: true } });
  await late.d.say(candidateFor(late.ready1, 3));
  await late.d.say(candidateFor(late.d.last('mining_ready'), 4));
  assert.equal(late.d.last('block_rejected')?.reason, 'p2p_propagation_failed');
  assert.equal(late.d.last('block_accepted'), undefined);
  assert.equal(late.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
});

test('SEQUENCE: an unexpected tip on daemon A before the next template fails closed, fetching nothing', async () => {
  // Another block appears on A after block 1 was accepted and B showed it.
  let injected = false;
  const c = await started({
    gate: (method, n, side, chain) => {
      if (side === 'A' && method === 'get_last_block_header' && chain.blocksB.length === 2 && !injected) {
        injected = true;
        chain.blocksA.push({ hash: 'e'.repeat(64), height: 2, nonce: 0, powHash: powFor(2), prevHash: chain.blocksA[1].hash });
      }
    },
  });
  await c.d.say(candidateFor(c.ready1, 3));
  assert.equal(c.d.last('block_rejected')?.reason, 'next_template_refused', JSON.stringify(c.d.sent.map((m) => [m.type, m.reason])));
  assert.equal(c.sim.blockRecords[0].rotationFailure?.detailCode ?? c.sim.blockRecords[1]?.rotationFailure?.detailCode, 'template_tip_changed');
  assert.equal(c.net.counts.A.get_block_template, 1, 'a template was fetched on an unexpected tip');
  assert.equal(c.d.all('sequence_next').length, 0);
});

test('SEQUENCE: a block-1 verifier whose release cannot be confirmed stops the session before anything for block 2', async () => {
  const c = await started({}, { verifierOptions: (n) => (n === 1 ? { closeConfirms: false } : {}) });
  await c.d.say(candidateFor(c.ready1, 3));
  assert.equal(c.d.last('block_rejected')?.reason, 'verifier_release_unconfirmed');
  assert.equal(c.journal.created.length, 1);
  assert.equal(c.journal.created[0].closed, false, 'claimed closed');
  assert.deepEqual(c.journal.events.filter((e) => /^(close|force)/.test(e)), ['close 1', 'force 1'], 'force only after an unconfirmed close');
  assert.equal(c.net.counts.A.get_block_template, 1);
  assert.equal(c.sim.verifierHistory[0].closed, false);
});

test('SEQUENCE: a disagreement in the block-2 verifier trips the one process latch and nothing is submitted for block 2', async () => {
  const c = await started();
  await c.d.say(candidateFor(c.ready1, 3));
  const ready2 = c.d.last('mining_ready');
  // Block 2's server verifier returns another hash: two paths over identical bytes disagree.
  c.journal.created[1].hashNative = async () => new Uint8Array(32).fill(0x11);
  await c.d.say(candidateFor(ready2, 4));
  assert.equal(c.d.last('block_rejected')?.reason, 'fatal_verifier');
  assert.equal(c.sim.latch.tripped, true);
  assert.equal(c.net.log.submitBodies.length, 1);
  assert.equal(c.net.log.calcPow.length, 1);
});

// ================================================================== races and configuration
test('SEQUENCE: two sessions racing cannot both work, and no height is claimed twice', async () => {
  const c = await sequenceContext();
  const one = driver(c.sim, c.clock);
  const two = driver(c.sim, c.clock);
  await one.say({ type: 'client_hello', protocolVersion: 1 });
  await two.say({ type: 'client_hello', protocolVersion: 1 });
  await one.say({ type: 'start_request', clientStartId: START_ID });
  await two.say({ type: 'start_request', clientStartId: 'ffffffffffffffffffffffffffffffff' });
  assert.equal(two.last('run_unavailable')?.reason, 'simulation_attempt_in_progress');
  const ready1 = one.last('mining_ready');
  // The second session forges the first's binding: it holds no run, so nothing is hashed.
  const r = await two.say({ ...candidateFor(ready1, 3), clientStartId: 'ffffffffffffffffffffffffffffffff' });
  assert.equal(r.ok, false);
  assert.equal(c.journal.events.filter((e) => e.startsWith('wasm')).length, 0);
  // The two candidates of the real session race each other for block 1.
  const [a, b] = await Promise.all([one.say(candidateFor(ready1, 3)), one.say(candidateFor(ready1, 4))]);
  assert.equal([a, b].filter((x) => x.ok === true).length, 1);
  assert.equal(c.net.log.submitBodies.length, 1);

  // The authority itself: one claim per issuance, never beyond its bound, never for a superseded one.
  const auth = createTemplateAuthority({ now: () => 1, maxClaims: 2 });
  const job = (n) => ({ jobId: `j${n}`, issuanceId: String(n).repeat(32), contentDigest: String(n).repeat(64), expiresAtMs: 10 });
  auth.publish(job(1));
  const claim = (n, owner) => auth.claimSubmission({ jobId: `j${n}`, issuanceId: String(n).repeat(32), contentDigest: String(n).repeat(64), owner, atMs: 1 });
  assert.equal(claim(1, 'x').ok, true);
  assert.equal(claim(1, 'y').reason, CLAIM_REFUSED.ALREADY_CLAIMED);
  auth.publish(job(2));
  assert.equal(claim(1, 'x').reason, CLAIM_REFUSED.NOT_CURRENT);
  assert.equal(claim(2, 'x').ok, true);
  assert.equal(claim(2, 'y').reason, CLAIM_REFUSED.ALREADY_CLAIMED);
  auth.publish(job(3));
  assert.equal(claim(3, 'x').reason, CLAIM_REFUSED.ALREADY_CLAIMED, 'a third claim exceeded the bound');
  assert.equal(auth.claimCount, 2);
  const single = createTemplateAuthority({ now: () => 1 });
  single.publish(job(1));
  assert.equal(single.claimSubmission({ jobId: 'j1', issuanceId: '1'.repeat(32), contentDigest: '1'.repeat(64), atMs: 1 }).ok, true);
  single.publish(job(2));
  assert.equal(single.claimSubmission({ jobId: 'j2', issuanceId: '2'.repeat(32), contentDigest: '2'.repeat(64), atMs: 1 }).reason,
    CLAIM_REFUSED.ALREADY_CLAIMED, 'the default authority granted a second claim');
  // The ceiling moved from 2 to the configured-sequence bound, and it is still a HARD one.
  assert.throws(() => createTemplateAuthority({ maxClaims: 0 }), /maxClaims/);
  assert.throws(() => createTemplateAuthority({ maxClaims: REAL_SEQUENCE_DEV_MAX_BLOCKS + 1 }), /maxClaims/);
  assert.throws(() => createTemplateAuthority({ maxClaims: 2.5 }), /maxClaims/);
  assert.equal(createTemplateAuthority({ maxClaims: 3 }).maxClaims, 3);
});

test('SEQUENCE is opt-in: the pair without it stays one-shot, and it is refused without the pair or beyond the finite ceiling', async () => {
  const oneShot = await started({}, { sequenceBlocks: 1 });
  assert.equal(oneShot.built.sequence, null);
  assert.equal(oneShot.d.last('server_hello').sequenceTotal, undefined);
  await oneShot.d.say(candidateFor(oneShot.ready1, 3));
  assert.equal(oneShot.d.last('block_accepted')?.terminal, true);
  assert.equal(oneShot.d.all('sequence_block_accepted').length, 0);
  assert.equal(oneShot.d.all('sequence_next').length, 0);
  assert.equal(oneShot.net.counts.A.get_block_template, 1);
  assert.equal(oneShot.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(REAL_SEQUENCE_MAX_BLOCKS, 2);

  for (const [name, opts] of [
    ['no pair', { daemon: CHAIN_A, sequenceBlocks: 2 }],
    ['beyond the ceiling', { daemon: CHAIN_A, peer: { daemon: CHAIN_B }, sequenceBlocks: REAL_SEQUENCE_DEV_MAX_BLOCKS + 1 }],
    ['zero blocks', { daemon: CHAIN_A, peer: { daemon: CHAIN_B }, sequenceBlocks: 0 }],
    ['not an integer', { daemon: CHAIN_A, peer: { daemon: CHAIN_B }, sequenceBlocks: '2' }],
  ]) {
    let startedDaemons = 0;
    await assert.rejects(buildRealDaemonMode({
      ...opts,
      ownResource: () => {},
      startDaemon: async () => { startedDaemons += 1; throw new Error('must not start'); },
      makeTransport: () => async () => '',
      makeVerifier: async () => { throw new Error('must not build'); },
    }), (e) => e.code === 'bad_config', name);
    assert.equal(startedDaemons, 0, name);
  }
});

test('SEQUENCE: pool shutdown during the rotation drains it -- the rotation settles and starts nothing more', async () => {
  const gate = deferred();
  let paused;
  const atPause = new Promise((r) => { paused = r; });
  let armed = true;
  const c = await started({
    gate: async (method, n, side, chain) => {
      if (armed && side === 'B' && method === 'get_last_block_header' && chain.blocksA.length === 2) { armed = false; paused(); await gate.promise; }
    },
  });
  const submitting = c.d.say(candidateFor(c.ready1, 3));
  await atPause;
  // What runShutdown does first: cancel, then dispose the sessions.
  c.sim.beginClose('pool shutting down');
  c.d.session.dispose();
  gate.resolve();
  await submitting;
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(c.net.counts.A.get_block_template, 1);
  assert.equal(c.journal.created.length, 1);
  assert.deepEqual(c.net.log.bWrites, []);
});

test('GUARD: no test in this file can reach the real daemon, transport, verifier or a listener', () => {
  const code = readFileSync(fileURLToPath(import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((line) => line.replace(/\/\/.*$/, '').replace(/'[^']*'/g, "''"))
    .join('\n');
  const builds = code.match(/buildRealDaemonMode\(/g) ?? [];
  const injected = code.match(/buildRealDaemonMode\(\{[\s\S]*?startDaemon:[\s\S]*?makeTransport:[\s\S]*?makeVerifier:/g) ?? [];
  assert.equal(builds.length, injected.length);
  assert.equal(/startDevPool\(/.test(code), false);
  const support = readFileSync(new URL('./in_memory_chain.mjs', import.meta.url), 'utf8');
  assert.match(support, /startDaemon: async/);
  assert.match(support, /makeTransport: \(endpoint\)/);
  assert.match(support, /makeVerifier: async/);
});
