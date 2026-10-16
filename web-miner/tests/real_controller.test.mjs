// The page controller in REAL-LOCAL-DAEMON mode, with a fake Worker and a fake socket. No browser,
// no Wasm, no server, no daemon.

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import * as nodeFsAll from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import { createMiningController, STATES, STOP_REASONS } from '../lib/controller.js';
import {
  REAL_DAEMON_MODE, REAL_SEARCH_LIMITS, RECORDED_SIMULATION_MODE,
} from '../lib/shared/protocol.js';
// The server's closed attempt-state vocabulary, imported (not copied) so the operator-start checks
// below cannot drift from it. sim_session.mjs is a library: importing it starts nothing.
import { SIM_ATTEMPT_STATES } from '../../pool/dev/sim_session.mjs';
// The real lifecycle and the Node event machinery the owned-browser checks drive with fakes.
import { EventEmitter } from 'node:events';
import { EXIT_CODES, createRunLifecycle, persistJsonAtomically } from '../tools/live_run_lifecycle.mjs';

const ISSUANCE = 'abcdef0123456789abcdef0123456789';
const JOB_ID = 'realjob-2222222222222222';
const WORKER_ID = 'sim-1-bbbb';
// A target an all-zero hash meets and an all-ff hash does not (little-endian: last byte most significant).
const TARGET = `${'00'.repeat(31)}01`;
const WIN_HASH = '00'.repeat(32);
const LOSE_HASH = 'ff'.repeat(32);
const BLOCK_ID = 'c'.repeat(64);
const CONTENT_DIGEST = 'd'.repeat(64);

function makeFakeWorker(registry) {
  const w = {
    posted: [], terminated: 0, onmessage: null, onerror: null,
    postMessage(m) { this.posted.push(m); },
    terminate() { this.terminated++; },
    emit(data) { if (this.onmessage) this.onmessage({ data }); },
  };
  registry.push(w);
  return w;
}

function makeFakeSocket(registry) {
  const s = {
    sent: [], closed: 0,
    onopen: null, onmessage: null, onclose: null, onerror: null,
    send(text) { this.sent.push(JSON.parse(text)); },
    close() { this.closed++; },
    open() { if (this.onopen) this.onopen(); },
    deliver(obj) { if (this.onmessage) this.onmessage({ data: JSON.stringify(obj) }); },
  };
  registry.push(s);
  return s;
}

function connected(mode = REAL_DAEMON_MODE, helloOverrides = {}) {
  const workers = [];
  const sockets = [];
  let n = 0;
  const controller = createMiningController({
    createWorker: () => makeFakeWorker(workers),
    createSocket: () => makeFakeSocket(sockets),
    newStartId: () => { n += 1; return n.toString(16).padStart(32, '0'); },
  });
  controller.connect('ws://127.0.0.1:8171/ws');
  const socket = sockets[0];
  socket.open();
  socket.deliver({
    type: 'server_hello', protocolVersion: 1, mode, workerId: WORKER_ID,
    labels: ['REAL LOCAL DAEMON'], actionLabel: 'Search the fresh template once', alreadyCompleted: false,
    searchLimits: REAL_SEARCH_LIMITS,
    ...helloOverrides,
  });
  socket.deliver({
    type: 'real_job', jobId: JOB_ID, issuanceId: ISSUANCE, algorithm: 'meephash-w-v2-frozen-real-template',
    height: '1', majorVersion: 16, epochKeyHex: 'e'.repeat(64), seedHashHex: 'e'.repeat(64),
    hashingTemplateHex: `1010${'00'.repeat(74)}`, targetHexLE: TARGET, nonceStart: 0, nonceRange: 8192,
    expiresAtMs: Date.now() + 600000,
  });
  return { controller, socket, workers };
}

function delayedJob(over = {}) {
  return {
    type: 'real_job', jobId: JOB_ID, issuanceId: ISSUANCE, contentDigest: CONTENT_DIGEST,
    algorithm: 'meephash-w-v2-frozen-real-template', height: '1', majorVersion: 16,
    epochKeyHex: 'e'.repeat(64), seedHashHex: 'e'.repeat(64),
    hashingTemplateHex: `1010${'00'.repeat(74)}`, targetHexLE: TARGET,
    nonceStart: 0, nonceRange: 8192, expiresAtMs: Date.now() + 600000,
    ...over,
  };
}

/** Real mode with no pre-issued job: only the explicit true capability makes Start legal. */
function delayedConnected(capability) {
  const workers = [];
  const sockets = [];
  let n = 0;
  const controller = createMiningController({
    createWorker: () => makeFakeWorker(workers),
    createSocket: () => makeFakeSocket(sockets),
    newStartId: () => { n += 1; return n.toString(16).padStart(32, '0'); },
  });
  controller.connect('ws://127.0.0.1:8171/ws');
  const socket = sockets[0];
  socket.open();
  const hello = {
    type: 'server_hello', protocolVersion: 1, mode: REAL_DAEMON_MODE, workerId: WORKER_ID,
    labels: ['REAL LOCAL DAEMON'], actionLabel: 'Search the fresh template once', alreadyCompleted: false,
    searchLimits: REAL_SEARCH_LIMITS,
  };
  if (capability !== undefined) hello.jobIssuedOnStart = capability;
  socket.deliver(hello);
  return { controller, socket, workers };
}

const binding = (id, over = {}) => ({
  clientStartId: id, workerId: WORKER_ID, jobId: JOB_ID, issuanceId: ISSUANCE, runGeneration: 1, ...over,
});

/** Start, acknowledge, ready, Worker ready: the Worker has been told to search. */
function searching(helloOverrides = {}) {
  const c = connected(REAL_DAEMON_MODE, helloOverrides);
  c.controller.start();
  const id = c.controller.clientStartId;
  c.socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...binding(id) });
  c.socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, nonceStart: 0, nonceRange: 8192, searchLimits: REAL_SEARCH_LIMITS, ...binding(id) });
  const w = c.workers[0];
  w.emit({ ev: 'ready', gen: c.controller.localWorkerGeneration, wasmHeapBytes: 1, context: true, search: true });
  return { ...c, id, w, gen: () => c.controller.localWorkerGeneration };
}

test('DELAYED JOB: explicit real-mode capability permits one correlated Start without allocating a Worker', () => {
  const c = delayedConnected(true);
  assert.equal(c.controller.snapshot().realJobIssuedOnStart, true);
  assert.equal(c.controller.realJob, null);
  assert.equal(c.controller.start(), true);
  const starts = c.socket.sent.filter((m) => m.type === 'start_request');
  assert.equal(starts.length, 1);
  assert.match(starts[0].clientStartId, /^[0-9a-f]{32}$/);
  assert.equal(c.controller.snapshot().state, STATES.STARTING);
  assert.equal(c.workers.length, 0);
});

test('real Start latches browser pace until server readiness; invalid pace starts nothing', () => {
  const c = connected();
  for (const invalid of [{ pacingMs: 50 }, { pacingMs: '100' }, null]) {
    assert.equal(c.controller.start(invalid), false);
  }
  assert.equal(c.socket.sent.filter((m) => m.type === 'start_request').length, 0);
  assert.equal(c.workers.length, 0);
  assert.equal(c.controller.start({ pacingMs: 100 }), true);
  const id = c.controller.clientStartId;
  assert.equal(c.workers.length, 0);
  c.socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...binding(id) });
  c.socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, nonceStart: 0,
    nonceRange: 8192, searchLimits: REAL_SEARCH_LIMITS, ...binding(id) });
  assert.equal(c.workers.length, 1);
  assert.equal(c.workers[0].posted.find((m) => m.cmd === 'init_search').pacingMs, 100);
});

test('DELAYED JOB: a bound capacity refusal with null job identity is retryable and allocates nothing', () => {
  const c = delayedConnected(true);
  assert.equal(c.controller.start(), true);
  const firstId = c.controller.clientStartId;
  c.socket.deliver({
    type: 'run_unavailable', terminal: true, reason: 'pool_capacity',
    clientStartId: firstId, workerId: WORKER_ID, jobId: null, issuanceId: null,
    runGeneration: null, attemptState: 'idle',
  });
  assert.equal(c.workers.length, 0);
  assert.equal(c.controller.snapshot().simProcessSpent, false);
  assert.match(c.controller.snapshot().error, /both local browser slots are occupied/);
  assert.equal(c.controller.start(), true, 'a retry still requires and accepts a fresh explicit Start');
  assert.notEqual(c.controller.clientStartId, firstId);
  assert.equal(c.socket.sent.filter((m) => m.type === 'start_request').length, 2);
  assert.equal(c.workers.length, 0);
});

test('DELAYED JOB: capacity refusal is inert unless every null-identity field is exact', () => {
  for (const mutate of [
    (m) => { delete m.terminal; },
    (m) => { m.terminal = false; },
    (m) => { m.jobId = JOB_ID; },
    (m) => { m.issuanceId = ISSUANCE; },
    (m) => { m.runGeneration = 1; },
    (m) => { m.workerId = 'other'; },
    (m) => { m.reason = 'simulation_attempt_in_progress'; },
    ...Object.values(SIM_ATTEMPT_STATES)
      .filter((state) => state !== SIM_ATTEMPT_STATES.IDLE)
      .map((state) => (m) => { m.attemptState = state; }),
  ]) {
    const c = delayedConnected(true);
    assert.equal(c.controller.start(), true);
    const id = c.controller.clientStartId;
    const msg = {
      type: 'run_unavailable', terminal: true, reason: 'pool_capacity',
      clientStartId: id, workerId: WORKER_ID, jobId: null, issuanceId: null,
      runGeneration: null, attemptState: 'idle',
    };
    mutate(msg);
    c.socket.deliver(msg);
    assert.equal(c.controller.pendingStart, true);
    assert.equal(c.controller.snapshot().state, STATES.STARTING);
    assert.equal(c.workers.length, 0);
  }
});

test('DELAYED JOB: capacity vocabulary is inert on both pre-issued legacy paths', () => {
  for (const [mode, type] of [
    [REAL_DAEMON_MODE, 'run_unavailable'],
    [RECORDED_SIMULATION_MODE, 'simulation_unavailable'],
  ]) {
    for (const reason of ['pool_capacity', 'reservation_history_full']) {
      const c = connected(mode);
      assert.equal(c.controller.start(), true, `${mode} ${reason}`);
      const id = c.controller.clientStartId;
      c.socket.deliver({
        type, terminal: true, reason,
        clientStartId: id, workerId: WORKER_ID, jobId: JOB_ID, issuanceId: ISSUANCE,
        runGeneration: null, attemptState: 'idle',
      });
      assert.equal(c.controller.pendingStart, true, `${mode} ${reason}`);
      assert.equal(c.controller.snapshot().state, STATES.STARTING, `${mode} ${reason}`);
      assert.equal(c.controller.snapshot().simProcessSpent, false, `${mode} ${reason}`);
      assert.equal(c.workers.length, 0, `${mode} ${reason}`);
    }
  }
});

test('DELAYED JOB: exhausted reservation history is bound like capacity but spends the process', () => {
  const c = delayedConnected(true);
  assert.equal(c.controller.start(), true);
  const id = c.controller.clientStartId;
  c.socket.deliver({
    type: 'run_unavailable', terminal: true, reason: 'reservation_history_full',
    clientStartId: id, workerId: WORKER_ID, jobId: null, issuanceId: null,
    runGeneration: null, attemptState: 'idle',
  });
  assert.equal(c.workers.length, 0);
  assert.equal(c.controller.snapshot().simProcessSpent, true);
  assert.match(c.controller.snapshot().error, /bounded browser-slot history/);
  assert.equal(c.controller.start(), false);
});

test('DELAYED JOB: two-slot closed reasons spend this page without creating a Worker', () => {
  for (const reason of ['two_slot_round_closed', 'canonical_submission_claimed']) {
    const c = delayedConnected(true);
    assert.equal(c.controller.start(), true);
    c.socket.deliver({
      type: 'run_unavailable', terminal: true, reason,
      clientStartId: c.controller.clientStartId, workerId: WORKER_ID,
      jobId: null, issuanceId: null, runGeneration: null, attemptState: 'idle',
    });
    assert.equal(c.workers.length, 0, reason);
    assert.equal(c.controller.snapshot().simProcessSpent, true, reason);
    assert.equal(c.controller.start(), false, reason);
  }
});

test('DELAYED JOB: omission, false and malformed capability never permit a jobless Start', () => {
  for (const capability of [undefined, false, 'true', 1, null]) {
    const c = delayedConnected(capability);
    assert.equal(c.controller.snapshot().realJobIssuedOnStart, false, String(capability));
    assert.equal(c.controller.start(), false, String(capability));
    assert.equal(c.socket.sent.filter((m) => m.type === 'start_request').length, 0, String(capability));
    assert.equal(c.workers.length, 0, String(capability));
    if (capability !== undefined && capability !== false) {
      assert.equal(c.controller.snapshot().state, STATES.ERROR, String(capability));
      assert.match(c.controller.snapshot().error, /invalid delayed-job capability/, String(capability));
    }
  }
});

test('DELAYED JOB: valid sequence fields cannot resurrect a malformed delayed-job capability', () => {
  const workers = [];
  const sockets = [];
  const controller = createMiningController({
    createWorker: () => makeFakeWorker(workers),
    createSocket: () => makeFakeSocket(sockets),
    newStartId: () => '1'.repeat(32),
  });
  controller.connect('ws://127.0.0.1:8171/ws');
  const socket = sockets[0];
  socket.open();
  socket.deliver({
    type: 'server_hello', protocolVersion: 1, mode: REAL_DAEMON_MODE, workerId: WORKER_ID,
    labels: [], alreadyCompleted: false, searchLimits: REAL_SEARCH_LIMITS,
    jobIssuedOnStart: 'true', sequenceTotal: 2,
  });
  // Even a usable pre-issued job cannot forgive the malformed capability declaration.
  socket.deliver(delayedJob());
  assert.equal(controller.realJob?.jobId, JOB_ID);
  assert.equal(controller.start(), false);
  assert.equal(socket.sent.filter((m) => m.type === 'start_request').length, 0);
  assert.equal(workers.length, 0);
  assert.equal(controller.snapshot().state, STATES.ERROR);
});

test('DELAYED JOB: job then matching acknowledgement and readiness create exactly one Worker', () => {
  const c = delayedConnected(true);
  assert.equal(c.controller.start(), true);
  const id = c.controller.clientStartId;
  c.socket.deliver(delayedJob());
  assert.equal(c.workers.length, 0, 'the job alone allocated a Worker');
  c.socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...binding(id) });
  assert.equal(c.workers.length, 0, 'the acknowledgement allocated a Worker');
  c.socket.deliver({
    type: 'mining_ready', mode: REAL_DAEMON_MODE, nonceStart: 0, nonceRange: 8192,
    searchLimits: REAL_SEARCH_LIMITS, ...binding(id),
  });
  assert.equal(c.workers.length, 1);
  assert.equal(c.controller.workersCreated, 1);
  assert.equal(c.workers[0].posted.filter((m) => m.cmd === 'init_search').length, 1);
  assert.equal(c.workers[0].posted.find((m) => m.cmd === 'init_search').jobId, JOB_ID);
});

test('DELAYED JOB: out-of-order binding frames are inert and cannot bypass the job identity', () => {
  const c = delayedConnected(true);
  c.controller.start();
  const id = c.controller.clientStartId;
  const bind = binding(id);
  c.socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...bind });
  c.socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, ...bind });
  assert.equal(c.workers.length, 0);
  assert.equal(c.controller.serverRunBinding, null);

  c.socket.deliver(delayedJob());
  assert.equal(c.workers.length, 0);
  // The ignored early acknowledgement did not become authority: the server must bind again now.
  c.socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, ...bind });
  assert.equal(c.workers.length, 0);
  c.socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...bind });
  c.socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, ...bind });
  assert.equal(c.workers.length, 1);
});

test('DELAYED JOB: unsolicited, duplicate and malformed jobs fail closed before Worker creation', () => {
  const unsolicited = delayedConnected(true);
  unsolicited.socket.deliver(delayedJob());
  assert.equal(unsolicited.controller.snapshot().state, STATES.ERROR);
  assert.equal(unsolicited.controller.start(), false);
  assert.equal(unsolicited.workers.length, 0);

  const duplicate = delayedConnected(true);
  duplicate.controller.start();
  duplicate.socket.deliver(delayedJob());
  duplicate.socket.deliver(delayedJob());
  assert.equal(duplicate.controller.runIntent, false);
  assert.equal(duplicate.controller.snapshot().state, STATES.ERROR);
  assert.equal(duplicate.workers.length, 0);

  for (const malformed of [
    { contentDigest: 'x'.repeat(64) },
    { issuanceId: 'A'.repeat(32) },
    { nonceRange: 0 },
    { nonceStart: 0xffffffff, nonceRange: 2 },
    { hashingTemplateHex: 'abc' },
    { shareWork: true, shareTargetHexLE: '00' },
  ]) {
    const c = delayedConnected(true);
    c.controller.start();
    c.socket.deliver(delayedJob(malformed));
    assert.equal(c.controller.runIntent, false, JSON.stringify(malformed));
    assert.equal(c.controller.snapshot().state, STATES.ERROR, JSON.stringify(malformed));
    assert.equal(c.workers.length, 0, JSON.stringify(malformed));
  }
});

const candidates = (socket) => socket.sent.filter((m) => m.type === 'submit_real_candidate');
const stops = (socket) => socket.sent.filter((m) => m.type === 'stop_request');

test('the Worker gets the FRESH server context and the issued window at the frozen bounds -- and no nonce', () => {
  const { w } = searching();
  const init = w.posted.find((m) => m.cmd === 'init_search');
  assert.ok(init, 'no init_search');
  assert.equal(init.jobId, JOB_ID);
  assert.deepEqual(init.window, { nonceStart: 0, nonceRange: 8192, targetHexLE: TARGET, maxSearchMs: 120000 });
  assert.deepEqual(init.context, {
    epochKeyHex: 'e'.repeat(64), seedHashHex: 'e'.repeat(64), height: '1', hashingTemplateHex: `1010${'00'.repeat(74)}`,
  });
  assert.equal('nonce' in init, false, 'a nonce was supplied to the search');
  assert.equal(w.posted.some((m) => m.cmd === 'init_context' || m.cmd === 'hash_one' || m.cmd === 'work'), false);
  assert.deepEqual(w.posted.filter((m) => m.cmd === 'search').map((m) => m.jobId), [JOB_ID]);
});

test('refusing the initial real context fails closed with one bound stop and no exact total', () => {
  const c = connected();
  c.controller.start();
  const id = c.controller.clientStartId;
  c.socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...binding(id) });
  c.socket.deliver({
    type: 'mining_ready', mode: REAL_DAEMON_MODE, nonceStart: 0, nonceRange: 8192,
    searchLimits: REAL_SEARCH_LIMITS, ...binding(id),
  });
  const w = c.workers[0];
  assert.ok(w.posted.some((m) => m.cmd === 'init_search'));
  w.emit({ ev: 'command_refused', cmd: 'init_search', reason: 'bad_context' });
  const snapshot = c.controller.snapshot();
  assert.equal(c.controller.runIntent, false);
  assert.equal(w.terminated, 1);
  assert.equal(stops(c.socket).length, 1);
  assert.equal(snapshot.realTotalAttempts, null);
  assert.equal(snapshot.state, STATES.ERROR);
});

test('refusing the issued real search stops immediately and late Worker work is inert', () => {
  const c = searching();
  c.w.emit({ ev: 'progress', jobId: JOB_ID, hashes: 11, elapsedMs: 2 });
  c.w.emit({ ev: 'command_refused', cmd: 'search', reason: 'search_refused' });
  const terminal = c.controller.snapshot();
  assert.equal(c.controller.runIntent, false);
  assert.equal(c.w.terminated, 1);
  assert.equal(stops(c.socket).length, 1);
  assert.equal(terminal.realTotalAttempts, null);
  assert.equal(terminal.state, STATES.ERROR);
  c.w.emit({ ev: 'progress', jobId: JOB_ID, hashes: 12, elapsedMs: 3 });
  c.w.emit({ ev: 'found', jobId: JOB_ID, nonce: 5, nonceHex: '00000005', hashHexLE: WIN_HASH });
  assert.deepEqual(c.controller.snapshot(), terminal);
  assert.equal(candidates(c.socket).length, 0);
});

test('the first valid FOUND becomes the one candidate; the browser hash is never sent', () => {
  const { socket, w, gen, controller } = searching();
  w.emit({ ev: 'found', gen: gen(), jobId: JOB_ID, nonce: 77, nonceHex: '0000004d', hashHexLE: WIN_HASH, elapsedMs: 3 });
  assert.equal(candidates(socket).length, 1);
  assert.equal(candidates(socket)[0].nonce, '0000004d');
  assert.equal(JSON.stringify(candidates(socket)[0]).includes(WIN_HASH), false);
  assert.equal(controller.snapshot().realFoundNonce, 77);

  // A duplicate FOUND sends nothing and ends the run through the error stop.
  w.emit({ ev: 'found', gen: gen(), jobId: JOB_ID, nonce: 78, nonceHex: '0000004e', hashHexLE: WIN_HASH, elapsedMs: 4 });
  assert.equal(candidates(socket).length, 1, 'a second candidate was sent');
  assert.equal(controller.snapshot().stopReason, STOP_REASONS.ERROR);
  assert.equal(w.terminated, 1);
});

test('a FOUND for other work, outside the window, or not meeting the target is not a candidate', () => {
  for (const [name, over] of [
    ['wrong job', { jobId: 'realjob-other' }],
    ['outside window', { nonce: 8192, nonceHex: '00002000' }],
    ['hex disagrees', { nonceHex: '00000000' }],
    ['above target', { hashHexLE: LOSE_HASH }],
    ['malformed hash', { hashHexLE: 'abc' }],
    ['string nonce', { nonce: '77' }],
  ]) {
    const { socket, w, gen, controller } = searching();
    w.emit({ ev: 'found', gen: gen(), jobId: JOB_ID, nonce: 77, nonceHex: '0000004d', hashHexLE: WIN_HASH, ...over });
    assert.equal(candidates(socket).length, 0, name);
    assert.equal(controller.snapshot().simBrowserEvidence, 'invalid', name);
    assert.equal(w.terminated, 1, name);
  }
});

test('BOUNDED_NO_SOLUTION: a search that ends with no solution sends one bound stop and no candidate', () => {
  const { socket, w, gen, controller, id } = searching();
  w.emit({ ev: 'progress', gen: gen(), jobId: JOB_ID, hashes: 8000, elapsedMs: 1000 });
  w.emit({ ev: 'finished', gen: gen(), jobId: JOB_ID, hashes: 8192, found: 0, stopped: false, exhausted: true, timedOut: false });
  assert.equal(candidates(socket).length, 0);
  assert.equal(stops(socket).length, 1);
  assert.equal(stops(socket)[0].reason, 'search_bound_reached');
  assert.equal(stops(socket)[0].clientStartId, id);
  const s = controller.snapshot();
  assert.equal(s.realOutcome, 'bounded_no_solution');
  assert.equal(s.hashes, 8192);
  assert.deepEqual(s.realSearch, { hashes: 8192, found: 0, timedOut: false, exhausted: true });
  assert.equal(w.terminated, 1);
  // The server's answer marks the process spent.
  socket.deliver({ type: 'run_stopped', ...binding(id), terminal: true, accepted: true, reason: 'search_bound_reached' });
  assert.equal(controller.snapshot().simProcessSpent, true);
  assert.equal(controller.start(), false, 'a spent process accepted a second Start');
});

test('block_accepted is recorded, and browser agreement needs the found nonce and all hashes to match', () => {
  const { socket, w, gen, controller, id } = searching();
  w.emit({ ev: 'found', gen: gen(), jobId: JOB_ID, nonce: 77, nonceHex: '0000004d', hashHexLE: WIN_HASH });
  socket.deliver({ type: 'candidate_verified', ...binding(id), nonce: 77, hashHexLE: WIN_HASH });
  socket.deliver({ type: 'block_submit_started', ...binding(id), nonce: 77, hashHexLE: WIN_HASH });
  socket.deliver({
    type: 'block_accepted', ...binding(id), terminal: true, nonce: 77, hashHexLE: WIN_HASH, blockId: BLOCK_ID,
    height: '1', confirmedBy: 'immediate_canonical_readback_top_block_with_matching_pow_hash', counters: { daemonDispatchSubmission: 1 },
  });
  const s = controller.snapshot();
  assert.equal(s.realOutcome, 'block_accepted');
  assert.equal(s.realBlockId, BLOCK_ID);
  assert.equal(s.realBlockHeight, '1');
  assert.equal(s.simBrowserMatched, true);
  assert.equal(s.simProcessSpent, true);
  assert.equal(s.state, STATES.STOPPED);

  // The server accepting a DIFFERENT nonce than this browser found is not browser agreement.
  const b = searching();
  b.w.emit({ ev: 'found', gen: b.gen(), jobId: JOB_ID, nonce: 77, nonceHex: '0000004d', hashHexLE: WIN_HASH });
  b.socket.deliver({ type: 'candidate_verified', ...binding(b.id), nonce: 77, hashHexLE: WIN_HASH });
  b.socket.deliver({ type: 'block_accepted', ...binding(b.id), terminal: true, nonce: 78, hashHexLE: WIN_HASH, blockId: BLOCK_ID, height: '1' });
  assert.equal(b.controller.snapshot().simBrowserMatched, false);
});

test('a real-mode page ignores simulation-named events, and an unbound acceptance changes nothing', () => {
  const { socket, controller, id } = searching();
  socket.deliver({ type: 'simulation_complete', ...binding(id), terminal: true, counters: {} });
  socket.deliver({ type: 'simulation_failed', ...binding(id), terminal: true, reason: 'fatal_verifier' });
  assert.equal(controller.snapshot().simFinished, false);
  socket.deliver({ type: 'block_accepted', ...binding(id, { runGeneration: 2 }), terminal: true, nonce: 1, hashHexLE: WIN_HASH, blockId: BLOCK_ID, height: '1' });
  assert.equal(controller.snapshot().realOutcome, null);
  assert.equal(controller.snapshot().simComplete, false);
});

test('block_rejected is finished, not succeeded', () => {
  const { socket, controller, id } = searching();
  socket.deliver({ type: 'block_rejected', ...binding(id), terminal: true, reason: 'submit_outcome_ambiguous' });
  const s = controller.snapshot();
  assert.equal(s.realOutcome, 'failed');
  assert.equal(s.simComplete, false);
  assert.equal(s.simFailureCode, 'submit_outcome_ambiguous');
});

test('the losing two-browser slot ends cleanly without claiming its own block', () => {
  const { socket, w, controller, id } = searching({ twoSlotCompetition: true });
  socket.deliver({ type: 'block_rejected', ...binding(id), terminal: true,
    reason: 'submission_already_claimed' });
  const s = controller.snapshot();
  assert.equal(s.twoSlotCompetition, true);
  assert.equal(s.state, STATES.STOPPED);
  assert.equal(s.stopReason, STOP_REASONS.OTHER_BROWSER_WON);
  assert.equal(s.realOutcome, 'other_browser_won');
  assert.equal(s.simFailureCode, 'submission_already_claimed');
  assert.equal(s.simComplete, false);
  assert.equal(s.simBrowserMatched, false);
  assert.equal(s.realBlockId, null);
  assert.equal(s.error, null);
  assert.equal(s.simProcessSpent, true);
  assert.equal(w.terminated, 1);
  assert.equal(controller.start(), false);
  socket.deliver({ type: 'block_accepted', ...binding(id), terminal: true,
    nonce: 77, hashHexLE: WIN_HASH, blockId: BLOCK_ID, height: '1' });
  assert.equal(controller.snapshot().realOutcome, 'other_browser_won');
});

test('a single-client submission_already_claimed remains a failure; malformed capability fails closed', () => {
  const solo = searching();
  solo.socket.deliver({ type: 'block_rejected', ...binding(solo.id), terminal: true,
    reason: 'submission_already_claimed' });
  assert.equal(solo.controller.snapshot().state, STATES.ERROR);
  assert.equal(solo.controller.snapshot().realOutcome, 'failed');
  for (const malformed of [2, 'true', null, {}]) {
    const c = connected(REAL_DAEMON_MODE, { twoSlotCompetition: malformed });
    assert.equal(c.controller.snapshot().state, STATES.ERROR);
    assert.equal(c.controller.start(), false);
    assert.equal(c.workers.length, 0);
  }
});

test('hidden, pagehide and Stop each terminate the Worker and send one bound stop before any candidate', () => {
  for (const [act, wire] of [
    [(c) => c.setHidden(true), 'page_hidden'],
    [(c) => c.teardown(), 'page_unload'],
    [(c) => c.stop(), 'user_stop'],
  ]) {
    const { socket, w, gen, controller } = searching();
    act(controller);
    assert.equal(w.terminated, 1, wire);
    assert.equal(stops(socket).length, 1, wire);
    assert.equal(stops(socket)[0].reason, wire);
    // A queued FOUND from the terminated Worker is inert.
    w.emit({ ev: 'found', gen: gen(), jobId: JOB_ID, nonce: 77, nonceHex: '0000004d', hashHexLE: WIN_HASH });
    assert.equal(candidates(socket).length, 0, `${wire}: a queued found became a candidate`);
  }
});

/**
 * BOTH live runners go through the ONE shared lifecycle (live_run_lifecycle.mjs, tested behaviourally in
 * live_run_lifecycle.test.mjs). These static checks only pin that wiring in the entry scripts, which
 * cannot be started without live resources: no signal handler, cleanup or process.exit of their own.
 */
function assertUsesSharedLifecycle(src, name) {
  const has = (text) => assert.ok(src.includes(text), `${name}: missing ${text}`);
  const count = (text) => src.split(text).length - 1;
  has("import { EXIT_CODES, createRunLifecycle, persistJsonAtomically } from './live_run_lifecycle.mjs';");
  has('lifecycle.installSignalHandlers(process);');
  has('exit: (code) => process.exit(code),');
  has('await lifecycle.startPool({');
  has('lifecycle.run(async () => {');
  // The evidence is persisted by the shared atomic writer. The paired runner's share path may
  // publish to a run-id sibling instead of replacing a file that appeared after its pre-run check,
  // so the TARGET is allowed to be that chosen path -- the writer never changes.
  assert.ok(/persistJsonAtomically\((?:evidencePath|candidate), evidence, \{/.test(src),
    `${name}: the evidence is not persisted by the shared atomic writer`);
  has('lifecycle.throwIfCancelled();');
  has('verifierAbsent: sim.verifier === null');
  has('exit $LASTEXITCODE');
  assert.equal(count('await startDevPool('), 0, `${name}: startDevPool is awaited outside the lifecycle`);
  assert.equal(count('process.once(') + count('process.on('), 0, `${name}: a signal handler of its own`);
  // The only other exits are usage refusals, before anything exists.
  assert.equal(count('process.exit('), count('process.exit(EXIT_CODES.USAGE);') + 1, `${name}: an exit outside the lifecycle`);
  has('process.exit(EXIT_CODES.USAGE);');
  assert.equal(count('writeFileSync(evidencePath'), 0, `${name}: a non-atomic evidence write`);
  assert.equal(/[^A-Za-z]verifier: sim\.verifier === null/.test(src), false, `${name}: the misleading field name is back`);
}

test('the PAIRED live runner: the shared lifecycle, gates before start, retained data dirs, no RPC write to B', () => {
  const src = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '../tools/local_p2p_block.mjs'), 'utf8');
  assertUsesSharedLifecycle(src, 'local_p2p_block');
  for (const text of [
    'const power = classifyPowerLineStatus(powerQuery);',
    'if (!power.ok) throw new Error(power.error);',
    "if (power.warning !== null) note('BATTERY WARNING', power.warning);",
    'if (actualImage !== imageId) throw',
    'const runtimeArtifacts = classifyConverterRuntimeArtifacts({',
    'if (!runtimeArtifacts.ok) throw new Error(runtimeArtifacts.error);',
    "'/usr/bin/env', '-i', `LD_LIBRARY_PATH=${runtimeLibraryDir}`",
    'a daemon port is occupied or a daemon container is left over',
    'shell: false',
    // A failed transcript append is counted separately; it cannot falsify the JSON result.
    'catch { evidence.transcriptAppendFailures += 1; }',
  ]) assert.ok(src.includes(text), text);
  // The finite sequence is selected only through the trusted realDaemon option, with a shared 1..32 bound.
  assert.ok(src.includes('...(blocks > 1 ? { sequenceBlocks: blocks } : {})'));
  assert.ok(src.includes('if (!isSupportedSequenceBlocks(blocks)) {'));
  assert.ok(src.includes('personalizeTemplates: true'), 'the paired runner issued duplicate unpersonalized work');
  // The observer uses a separate read-only RPC channel; the live record must not call the main
  // channel a total or omit the causal tip/failure facts.
  for (const text of [
    'daemonACombinedTotal', 'daemonAApplicationEvidence', 'daemonATipObserverReadOnly',
    'tipObserver: sim.tipObserverFacts', 'externalTip: rec.externalTip',
    'tipObservationFailure: rec.tipObservationFailure',
  ]) assert.ok(src.includes(text), `missing observer evidence: ${text}`);
  // Only the throwaway profile is removed; the daemon run directories are recorded, never deleted.
  assert.equal(src.includes("'rm', '-rf'"), false, 'the paired runner removes a daemon directory');
  // Browser failures beyond exceptions are captured.
  for (const ev of ['Runtime.exceptionThrown', 'Runtime.consoleAPICalled', 'Network.loadingFailed', 'Network.responseReceived', 'Target.setAutoAttach']) {
    assert.ok(src.includes(ev), ev);
  }
  // Daemon B is only ever read.
  assert.equal(/peer\.(?:[a-zA-Z]+\.)*(?:submit|calcPow|prepareSubmission|dispatchSubmission)/.test(src), false);
});

test('the single-daemon live runner: the shared lifecycle; a supplied evidence file is required', () => {
  const src = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '../tools/local_daemon_block.mjs'), 'utf8');
  assertUsesSharedLifecycle(src, 'local_daemon_block');
  assert.ok(src.includes('persistEvidence: evidencePath === null ? null : '));
  assert.ok(src.includes('personalizeTemplates: true'), 'the single-daemon runner issued unpersonalized work');
});

// ==================================================================== operator start (--interactive)
//
// The paired runner cannot be imported: the module IS the run (it parses argv, writes a transcript and
// starts a pool). So its two operator-start primitives are PURE and are lifted out of the file here
// and EXECUTED against real inputs. That is the difference between checking behaviour and checking
// that somebody typed the word "interactive": these assertions fail if the default run stops being
// headless, if the visible run smuggles the headless flag back in, if the throwaway-profile/private
// debugging-port ownership is dropped from either mode, or if "Start" is ever believed from anything
// other than the server's own attempt state.

const pairedRunnerSource = () => readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), '../tools/local_p2p_block.mjs'), 'utf8');

/**
 * Lift `function NAME(...) { ... }` out of a source file and make it callable, with nothing in scope
 * except the pure helpers it is explicitly given. A missing dependency is a failure, not a stub: the
 * point is to run the production text, not something resembling it.
 */
function liftPureFunction(src, name, deps = [], consts = []) {
  const body = (fn) => {
    const at = src.indexOf(`function ${fn}(`);
    assert.notEqual(at, -1, `${fn} is not defined in the runner`);
    return sliceFunction(src, at, fn);
  };
  const constant = (c) => {
    const m = new RegExp(`^const ${c} = [^;]+;`, 'm').exec(src);
    assert.ok(m, `${c} is not a top-level constant in the runner`);
    return m[0];
  };
  const text = [...consts.map(constant), ...deps.map(body), body(name)].join('\n');
  return new Function(`${text}\nreturn ${name};`)();
}

function sliceFunction(src, start, name) {
  // The body brace, not a destructured parameter's brace and not a default value's arrow body: find
  // the parameter list's OWN closing parenthesis by depth first.
  let parens = 0;
  let paramsEnd = -1;
  for (let i = src.indexOf('(', start); i < src.length; i += 1) {
    if (src[i] === '(') parens += 1;
    else if (src[i] === ')') { parens -= 1; if (parens === 0) { paramsEnd = i; break; } }
  }
  assert.notEqual(paramsEnd, -1, `${name} has no complete parameter list`);
  const bodyAt = src.indexOf('{', paramsEnd);
  let depth = 0;
  let end = -1;
  for (let i = bodyAt; i < src.length; i += 1) {
    if (src[i] === '{') depth += 1;
    else if (src[i] === '}') { depth -= 1; if (depth === 0) { end = i + 1; break; } }
  }
  assert.notEqual(end, -1, `${name} is not a complete function`);
  return src.slice(start, end);
}

const operatorBranch = (src) => {
  const start = src.indexOf('if (interactive) {');
  return src.slice(start, src.indexOf('  } else {', start));
};

test('the PAIRED live runner: the default browser stays headless and the runner still owns the one Start', () => {
  const src = pairedRunnerSource();
  const launchArgs = liftPureFunction(src, 'browserLaunchArgs');

  const headlessArgs = launchArgs({ headed: false, profileDir: 'C:/tmp/meep-p2p-block-xyz' });
  assert.ok(headlessArgs.includes('--headless=new'), 'the default run stopped being headless');
  assert.equal(headlessArgs[0], '--headless=new');
  // Absent or garbage flag values must not accidentally select the visible browser.
  for (const notHeaded of [undefined, null, 0, '', 'false', 'yes']) {
    assert.ok(launchArgs({ headed: notHeaded, profileDir: 'd' }).includes('--headless=new'),
      `headed=${JSON.stringify(notHeaded)} silently produced a visible browser`);
  }

  // The default path performs exactly one programmatic Start, and it is the runner's own click.
  const clicks = src.split('document.getElementById("start-btn").click()').length - 1;
  assert.equal(clicks, 1, 'the runner has more than one programmatic Start');
  assert.ok(src.includes("note('Start clicked', now());"), 'the single runner-owned Start disappeared');
  assert.ok(src.includes("const interactive = process.argv.includes('--interactive');"),
    'the flag is not a bare boolean read from argv');
  assert.ok(/\[--interactive\]/.test(src), 'the usage text does not offer the flag');
});

test('the PAIRED live runner: --interactive drops only headless and keeps the owned throwaway browser', () => {
  const src = pairedRunnerSource();
  const launchArgs = liftPureFunction(src, 'browserLaunchArgs');
  const profile = 'C:/tmp/meep-p2p-block-abc';
  const headless = launchArgs({ headed: false, profileDir: profile });
  const visible = launchArgs({ headed: true, profileDir: profile });

  assert.equal(visible.includes('--headless=new'), false, 'the visible run still asks for headless');
  assert.deepEqual(visible, headless.filter((a) => a !== '--headless=new'),
    'the visible run differs from the headless run by more than the headless flag');
  for (const required of [
    `--user-data-dir=${profile}`, '--remote-debugging-port=0', 'about:blank',
    '--no-first-run', '--no-default-browser-check', '--disable-extensions',
    '--disable-background-networking', '--disable-component-update', '--disable-sync',
  ]) {
    assert.ok(visible.includes(required), `the visible run dropped ${required}`);
    assert.ok(headless.includes(required), `the headless run dropped ${required}`);
  }
  // No second browser and no real profile: the page is brought forward through the owned page session.
  assert.equal(src.split('spawn(browserPath').length - 1, 1, 'more than one browser is launched');
  assert.ok(src.includes("await cdp.send('Page.bringToFront');"), 'activation does not use the owned CDP page');
  assert.equal(/--user-data-dir=(?!\$\{dir\})/.test(src), false, 'a profile other than the throwaway one');
});

test('the PAIRED live runner reuses its only blank tab and checks visibility before operator Start', () => {
  const src = pairedRunnerSource();
  const select = liftPureFunction(src, 'initialBlankPageTarget');
  const blank = { type: 'page', url: 'about:blank', targetId: 'owned-page' };
  assert.equal(select([]), null, 'the initial page may not yet be listed');
  assert.deepEqual(select([{ type: 'service_worker', url: 'about:blank' }, blank]), blank);
  assert.throws(() => select([blank, { ...blank, targetId: 'foreign-page' }]), /more than one page/);
  assert.throws(() => select([{ ...blank, url: 'https://example.invalid/' }]), /not blank/);
  assert.throws(() => select([{ ...blank, targetId: '' }]), /not blank/);
  assert.throws(() => select(null), /inventory is missing/);
  assert.ok(src.includes("browserCdp.send('Target.getTargets')"), 'the owned initial page is not queried');
  assert.equal(src.includes("browserCdp.send('Target.createTarget'"), false,
    'the runner creates a second tab that can hide the mining page');
  assert.ok(src.includes("note('page visibility before operator Start', visibilityBeforeStart)"),
    'the page visibility before Start is not recorded');
  assert.ok(src.includes("visibilityBeforeStart.state !== 'visible' || visibilityBeforeStart.hidden !== false"),
    'the initial hidden state is not detected');
  assert.ok(src.includes("label: 'the mining page to become visible before Start'"),
    'a backgrounded Chrome window cannot be foregrounded before the runner asks for Start');
  assert.ok(src.includes("visibility.state === 'visible' && visibility.hidden === false ? visibility : null"),
    'the foreground wait accepts a still-hidden tab');
});

test('the PAIRED live runner: the operator branch cannot reach the programmatic click', () => {
  const src = pairedRunnerSource();
  const start = src.indexOf('if (interactive) {');
  assert.notEqual(start, -1, 'there is no operator-start branch');
  const elseAt = src.indexOf('  } else {', start);
  const clickAt = src.indexOf('document.getElementById("start-btn").click()', start);
  assert.ok(elseAt > start, 'the operator branch is not the one that precedes the click branch');
  assert.notEqual(elseAt, -1, 'the operator branch has no exclusive alternative');
  assert.ok(clickAt > elseAt, 'the one programmatic click is reachable from the operator branch');
  const branch = operatorBranch(src);
  assert.ok(/runnerClicksStart: false/.test(branch), 'the run record does not state that the runner will not click');
  assert.ok(/waiting for the operator or delegated agent to press Start/.test(branch),
    'the operator is never told it is their turn');
  assert.ok(/this runner never clicks/.test(branch), 'the branch no longer states that the runner will not click');
  assert.equal(branch.includes('click()'), false, 'the operator branch clicks something');
});

test('the PAIRED live runner: operator Start is proved by server state, on one fixed bounded budget', () => {
  const src = pairedRunnerSource();
  const observed = liftPureFunction(src, 'serverObservedStart');

  // IDLE is the only state that is not a Start. Every other real attempt state proves the pool itself
  // acted; nothing about the DOM is consulted.
  assert.equal(observed(SIM_ATTEMPT_STATES.IDLE, SIM_ATTEMPT_STATES.IDLE), false);
  for (const state of Object.values(SIM_ATTEMPT_STATES).filter((s) => s !== SIM_ATTEMPT_STATES.IDLE)) {
    assert.equal(observed(state, SIM_ATTEMPT_STATES.IDLE), true, `${state} was not accepted as a Start`);
  }
  for (const bad of [undefined, null, '', 0, false, {}, ['reserved']]) {
    assert.equal(observed(bad, SIM_ATTEMPT_STATES.IDLE), false, `${JSON.stringify(bad)} was read as a Start`);
  }

  // One fixed budget, defined in the source, not taken from a caller or the environment.
  const timeout = /const OPERATOR_START_TIMEOUT_MS = ([^;]+);/.exec(src);
  assert.ok(timeout, 'the operator-start budget is not a source constant');
  const ms = new Function(`return ${timeout[1]};`)();
  assert.ok(Number.isSafeInteger(ms) && ms > 0 && ms <= 30 * 60_000, `unbounded operator budget: ${ms}`);
  assert.equal(/OPERATOR_START_TIMEOUT_MS\s*=[^;]*(arg\(|process\.env)/.test(src), false,
    'the operator budget is caller-controlled');
  const branch = operatorBranch(src);
  assert.ok(branch.includes('timeoutMs: OPERATOR_START_TIMEOUT_MS'), 'the wait does not use the fixed budget');
  // The wait asks the classifier, which asks the server first; it reads both facts from ONE snapshot.
  assert.ok(branch.includes('attemptState: sim.attemptState'), 'the wait is not server-state based');
  assert.ok(branch.includes('idleState: SIM_ATTEMPT_STATES.IDLE'), 'the wait invents its own idle state');
  assert.ok(branch.includes('browserExited: chromeExited'), 'the wait ignores the browser');
  assert.ok(/classifyOperatorStart\(\{/.test(branch), 'the four joint cases are not decided in one place');
  // A browser the operator closed BEFORE the server saw Start fails the wait immediately; nothing
  // retries and nothing auto-starts.
  assert.ok(/verdict === 'exited_before_start'/.test(branch) && /throw new Error\('the visible browser exited before the server observed Start'\)/.test(branch),
    'a closed browser does not fail the pre-Start wait');
  assert.equal(/setInterval|retry|resume/i.test(branch), false, 'the operator wait retries or resumes');
  // The old ordering bug: the browser fact must not be tested before the server fact.
  const exitedAt = branch.indexOf('browserExited');
  const serverAt = branch.indexOf('attemptState: sim.attemptState');
  assert.ok(serverAt !== -1 && exitedAt > serverAt, 'the browser is consulted before the server');
});

test('the PAIRED live runner: the four joint operator/browser cases, with server evidence winning', () => {
  const src = pairedRunnerSource();
  const classify = liftPureFunction(src, 'classifyOperatorStart', ['serverObservedStart']);
  const IDLE = SIM_ATTEMPT_STATES.IDLE;
  const started = Object.values(SIM_ATTEMPT_STATES).filter((s) => s !== IDLE);
  assert.ok(started.length >= 3, 'the attempt vocabulary lost its non-idle states');

  // 1. still IDLE, window alive -> keep waiting.
  assert.equal(classify({ attemptState: IDLE, idleState: IDLE, browserExited: false }), 'waiting');
  // 2. still IDLE, window gone -> fail the pre-Start wait at once.
  assert.equal(classify({ attemptState: IDLE, idleState: IDLE, browserExited: true }), 'exited_before_start');
  for (const state of started) {
    // 3. Start observed, window alive.
    assert.equal(classify({ attemptState: state, idleState: IDLE, browserExited: false }), 'observed',
      `${state} with a live window was not a Start`);
    // 4. Start observed AND the window has already gone: the server still wins. This is the race the
    //    first revision lost -- it reported a pre-Start browser exit over a reserved, possibly spent
    //    attempt. Whatever becomes of that attempt is the terminal wait's and the lifecycle's job.
    assert.equal(classify({ attemptState: state, idleState: IDLE, browserExited: true }), 'observed',
      `${state} with a closed window was misread as a pre-Start exit`);
  }
  // A missing or malformed server state is never a Start, and with the window gone it is a failure.
  for (const bad of [undefined, null, '', 0, false, {}, ['running']]) {
    assert.equal(classify({ attemptState: bad, idleState: IDLE, browserExited: false }), 'waiting');
    assert.equal(classify({ attemptState: bad, idleState: IDLE, browserExited: true }), 'exited_before_start');
  }
  // Only an explicit exit is an exit: an unknown browser fact must not end the wait.
  for (const unknown of [undefined, null, 'true', 1]) {
    assert.equal(classify({ attemptState: IDLE, idleState: IDLE, browserExited: unknown }), 'waiting',
      `browserExited=${JSON.stringify(unknown)} ended the wait`);
  }
  // Exactly three verdicts exist; the classifier invents nothing else.
  const verdicts = new Set([IDLE, ...started].flatMap((state) => [true, false]
    .map((exited) => classify({ attemptState: state, idleState: IDLE, browserExited: exited }))));
  assert.deepEqual([...verdicts].sort(), ['exited_before_start', 'observed', 'waiting']);
});

test('the PAIRED live runner: operator start changes nothing about gates, lifecycle or the server Start fence', () => {
  const src = pairedRunnerSource();
  // The one cleanup/finalization path is still the shared lifecycle, in both modes.
  assertUsesSharedLifecycle(src, 'local_p2p_block interactive');
  // The operator branch creates no pool, browser, profile, evidence path or exit of its own.
  const branch = operatorBranch(src);
  for (const forbidden of ['startDevPool', 'spawn(', 'mkdtempSync', 'persistJsonAtomically', 'process.exit']) {
    assert.equal(branch.includes(forbidden), false, `the operator branch does its own ${forbidden}`);
  }
  // Nothing expensive exists before a Start in EITHER mode: that fence is the server's, exercised by
  // the non-live session tests. The runner only records it, and it still records it BEFORE the wait.
  assert.ok(src.includes('verifierAbsent: sim.verifier === null'), 'the pre-Start server fact is gone');
  assert.ok(src.indexOf("note('server before Start'") < src.indexOf('if (interactive) {'),
    'the pre-Start server record moved after the Start');
  // The flag is boolean-only: it never becomes a value that could widen a bound.
  assert.equal(/arg\('interactive'/.test(src), false, 'the flag takes a caller-supplied value');
});

// ==================================================================== the owned browser's startup
//
// A ChildProcess with no `error` listener THROWS the event. The paired runner spawns its browser
// AFTER the pool already owns daemon A, daemon B and the native helper, and it installs no
// uncaughtException handler, so an explicit --browser path that cannot be executed used to kill Node
// outside lifecycle.run(): no beforePoolClose, no pool shutdown, no release observation, no evidence
// file, two containers left running. These checks execute the production wiring against a fake child.

class FakeStream extends EventEmitter {}

/** A ChildProcess-shaped fake: the same events, none of the side effects. */
function fakeChild({ pid = 4242, onKill = null } = {}) {
  const child = new EventEmitter();
  child.stdout = new FakeStream();
  child.stderr = new FakeStream();
  child.pid = pid;                      // undefined/null models a spawn that produced no process
  child.killed = false;
  child.kills = [];
  child.kill = (signal) => {
    child.killed = true;
    child.kills.push(signal ?? 'default');
    if (onKill) onKill(child, signal ?? 'default');
    return true;
  };
  return child;
}

const DEVTOOLS_LINE = 'DevTools listening on ws://127.0.0.1:51234/devtools/browser/8b1f0c2e-1111-2222-3333-444455556666\n';

test('the PAIRED live runner: the owned browser child can never throw an unhandled error event', () => {
  const src = pairedRunnerSource();
  const observe = liftPureFunction(src, 'observeBrowserStartup', ['browserStartupError'],
    ['BROWSER_START_FAILED', 'BROWSER_EXITED_BEFORE_DEVTOOLS']);

  // 1. spawn failure (a --browser path that does not exist): no pid, classified, never thrown at Node.
  const spawnFailed = fakeChild({ pid: null });
  let exits = 0;
  const failedState = observe(spawnFailed, { onExit: () => { exits += 1; } });
  assert.equal(spawnFailed.listenerCount('error'), 1, 'no error listener was attached to the child');
  const enoent = Object.assign(new Error('spawn C:/nope.exe ENOENT'), { code: 'ENOENT' });
  assert.doesNotThrow(() => spawnFailed.emit('error', enoent), 'the child error escaped as a throw');
  assert.equal(failedState.failure?.code, 'browser_start_failed');
  assert.match(failedState.failure.message, /ENOENT/);
  assert.equal(failedState.devtoolsUrl, null);
  // A child that never started cannot be killed or waited for: the runner must treat it as gone.
  assert.equal(failedState.exited, true, 'a failed spawn left the runner believing a browser exists');
  assert.equal(exits, 1);

  // 2. an early exit before the DevTools endpoint is its own closed code, not a 30-second timeout.
  const died = fakeChild();
  const diedState = observe(died, {});
  died.emit('exit', 1, null);
  assert.equal(diedState.failure?.code, 'browser_exited_before_devtools');
  assert.match(diedState.failure.message, /code 1 signal null/);
  assert.equal(diedState.exited, true);
  assert.deepEqual(diedState.exit, { code: 1, signal: null });

  // 3. the ordinary case still works, and a later exit does not invent a startup failure.
  const ok = fakeChild();
  const okState = observe(ok, {});
  ok.stdout.emit('data', Buffer.from('noise\n'));
  ok.stderr.emit('data', Buffer.from(DEVTOOLS_LINE));
  assert.equal(okState.devtoolsUrl, 'ws://127.0.0.1:51234/devtools/browser/8b1f0c2e-1111-2222-3333-444455556666');
  assert.equal(okState.failure, null);
  ok.emit('exit', 0, null);
  assert.equal(okState.failure, null, 'a browser that exited after DevTools was called a startup failure');
  assert.equal(okState.exited, true);

  // 4. first failure wins; nothing overwrites or accumulates.
  const both = fakeChild({ pid: null });
  const bothState = observe(both, {});
  both.emit('error', Object.assign(new Error('boom'), { code: 'EACCES' }));
  both.emit('exit', 7, 'SIGKILL');
  assert.equal(bothState.failure.code, 'browser_start_failed');
  assert.match(bothState.failure.message, /EACCES/);
});

test('the PAIRED live runner: a browser startup failure is an ordinary body rejection, cleaned up once', async () => {
  const src = pairedRunnerSource();
  const observe = liftPureFunction(src, 'observeBrowserStartup', ['browserStartupError'],
    ['BROWSER_START_FAILED', 'BROWSER_EXITED_BEFORE_DEVTOOLS']);

  // The real lifecycle, the real wait semantics, a fake pool and a fake child. No process is started.
  const calls = { spawns: 0, poolClosed: 0, beforePoolClose: 0, afterPoolClose: 0, persisted: 0, exits: [] };
  const pool = {
    url: 'http://127.0.0.1:0/',
    port: 0,
    httpServer: { listening: false },
    close: async () => { calls.poolClosed += 1; return { ok: true, physicalReleaseConfirmed: true }; },
  };
  const lifecycle = createRunLifecycle({
    startPool: async () => pool,
    exit: (code) => calls.exits.push(code),
    persistEvidence: ({ exitCode }) => { calls.persisted += 1; return { ok: true, exitCode }; },
  });

  let child = null;
  const bodyError = [];
  await lifecycle.run(async () => {
    await lifecycle.startPool({});             // the pool (and, live, its daemons) now exist
    calls.spawns += 1;                         // the ONE browser launch
    child = fakeChild();
    const startup = observe(child, {});
    // Exactly the runner's wait: the failure is thrown from the poll, nothing else.
    setImmediate(() => child.emit('error', Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' })));
    for (;;) {
      if (startup.failure !== null) throw startup.failure;
      if (startup.devtoolsUrl) break;
      await new Promise((r) => setImmediate(r));
    }
    return EXIT_CODES.OK;
  }, {
    beforePoolClose: async () => { calls.beforePoolClose += 1; },
    afterPoolClose: async () => { calls.afterPoolClose += 1; return { released: true }; },
    onBodyError: (err) => bodyError.push(err),
  });

  assert.equal(bodyError.length, 1, 'the spawn failure did not reach the body error path exactly once');
  assert.equal(bodyError[0].code, 'browser_start_failed');
  assert.equal(calls.spawns, 1, 'a second browser was launched');
  assert.equal(calls.beforePoolClose, 1, 'the browser stop step did not run exactly once');
  assert.equal(calls.poolClosed, 1, 'the pool was not closed exactly once');
  assert.equal(calls.afterPoolClose, 1, 'the release observation did not run exactly once');
  assert.equal(calls.persisted, 1, 'the evidence was not persisted exactly once');
  assert.deepEqual(calls.exits, [EXIT_CODES.FAILED], 'the failure did not exit once as an ordinary failure');
});

test('the PAIRED live runner: the startup wiring is in the same tick, with one launch and no retry', () => {
  const src = pairedRunnerSource();
  // One spawn, one observer, and the observer is attached with no await between it and the spawn.
  assert.equal(src.split('spawn(browserPath').length - 1, 1, 'more than one browser launch');
  assert.equal(src.split('observeBrowserStartup(chrome').length - 1, 1);
  const between = src.slice(src.indexOf('chrome = spawn(browserPath'), src.indexOf('observeBrowserStartup(chrome'));
  assert.equal(/await|then\(|setTimeout|sleep\(/.test(between), false,
    'something asynchronous sits between the spawn and its error listener');
  // The wait throws the classified failure; the old unconditional 30-second poll is gone.
  const wait = src.slice(src.indexOf('const devtoolsUrl = await waitUntil'), src.indexOf("label: 'DevTools'"));
  assert.ok(wait.includes('throw browserStartup.failure'), 'the wait does not surface the startup failure');
  assert.ok(wait.includes('return browserStartup.devtoolsUrl'));
  assert.equal(/retry|relaunch|spawn\(/i.test(wait), false, 'the wait retries or relaunches');
  // An explicit --browser path that does not exist is refused before anything is owned.
  assert.ok(src.includes('|| !browserPath || !existsSync(browserPath)'),
    'an unusable explicit browser path is still accepted into the run');
  // No alternate exit or cleanup was added for these failures: still only the usage refusals plus
  // the lifecycle's single exit.
  const exits = src.split('process.exit(').length - 1;
  const usageExits = src.split('process.exit(EXIT_CODES.USAGE);').length - 1;
  assert.equal(exits, usageExits + 1, 'an exit outside the lifecycle');
});

// An `error` event is NOT an exit. ChildProcess emits it both for a spawn that never produced a
// process and for a later failure on a live one -- a kill that could not be delivered is the case
// that matters here, because stopBrowser() escalates to SIGKILL only while `chromeExited` is false.
// Equating the two would mark a running Chrome as gone, skip the escalation, and let the release
// observation confirm a release that never happened.

test('the PAIRED live runner: only an exit, or an error with no pid, may mark the browser gone', () => {
  const src = pairedRunnerSource();
  const observe = liftPureFunction(src, 'observeBrowserStartup', ['browserStartupError'],
    ['BROWSER_START_FAILED', 'BROWSER_EXITED_BEFORE_DEVTOOLS']);

  // a. a true spawn failure: no process was ever created, so gone is correct -- exactly once.
  for (const shape of ['null-pid', 'absent-pid']) {
    const child = fakeChild({ pid: null });
    if (shape === 'absent-pid') delete child.pid;      // exactly what a failed spawn leaves behind
    let exits = 0;
    const state = observe(child, { onExit: () => { exits += 1; } });
    child.emit('error', Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' }));
    assert.equal(state.failure?.code, 'browser_start_failed', shape);
    assert.equal(state.exited, true, `${shape}: a spawn that produced nothing was not treated as gone`);
    assert.equal(exits, 1, `${shape}: onExit did not fire exactly once`);
  }

  // b. a PRE-DevTools error on a child that HAS a pid: still an ordinary classified failure, but the
  //    browser is NOT gone and cleanup must still run against it.
  const live = fakeChild({ pid: 9001 });
  let liveExits = 0;
  const liveState = observe(live, { onExit: () => { liveExits += 1; } });
  live.emit('error', Object.assign(new Error('kill EPERM'), { code: 'EPERM' }));
  assert.equal(liveState.failure?.code, 'browser_start_failed', 'a pre-DevTools error was swallowed');
  assert.match(liveState.failure.message, /pid 9001/, 'the failure hides that a process exists');
  assert.equal(liveState.exited, false, 'a post-spawn error marked a live browser gone');
  assert.equal(liveExits, 0, 'a post-spawn error called onExit');
  assert.equal(liveState.exit, null);
  assert.equal(liveState.lastError.includes('EPERM'), true);

  // c. DevTools already observed, then a later error with a pid: no startup failure at all, not gone.
  const running = fakeChild({ pid: 9002 });
  let runningExits = 0;
  const runningState = observe(running, { onExit: () => { runningExits += 1; } });
  running.stderr.emit('data', Buffer.from(DEVTOOLS_LINE));
  running.emit('error', Object.assign(new Error('kill ESRCH'), { code: 'ESRCH' }));
  assert.equal(runningState.failure, null, 'a kill failure became a startup failure after DevTools');
  assert.equal(runningState.exited, false, 'a kill failure marked a running browser gone');
  assert.equal(runningExits, 0);
  assert.equal(runningState.devtoolsUrl !== null, true);
  assert.equal(runningState.lastError.includes('ESRCH'), true, 'the kill failure was not recorded at all');

  // d. the actual exit is still the one post-spawn event that marks gone, error or no error.
  const exiting = fakeChild({ pid: 9003 });
  let exitingExits = 0;
  const exitingState = observe(exiting, { onExit: () => { exitingExits += 1; } });
  exiting.emit('error', Object.assign(new Error('kill EPERM'), { code: 'EPERM' }));
  assert.equal(exitingState.exited, false);
  exiting.emit('exit', null, 'SIGKILL');
  assert.equal(exitingState.exited, true, 'a real exit did not mark the browser gone');
  assert.deepEqual(exitingState.exit, { code: null, signal: 'SIGKILL' });
  assert.equal(exitingExits, 1, 'the exit did not report gone exactly once');
});

test('the PAIRED live runner: a kill that fails without an exit cannot confirm release or skip SIGKILL', async () => {
  const src = pairedRunnerSource();
  const observe = liftPureFunction(src, 'observeBrowserStartup', ['browserStartupError'],
    ['BROWSER_START_FAILED', 'BROWSER_EXITED_BEFORE_DEVTOOLS']);

  // The PRODUCTION stopBrowser text, with its module state injected and its sleeps made instant.
  // Nothing is spawned: `chrome` is the fake, `cdp` is absent.
  const stopBrowserSource = sliceFunction(src, src.indexOf('async function stopBrowser('), 'stopBrowser');
  const build = new Function('child', `
    let chrome = child;
    let chromeExited = false;
    const cdp = null;
    const sleep = () => Promise.resolve();
    const markExited = () => { chromeExited = true; };
    ${stopBrowserSource}
    return { stopBrowser, markExited, exited: () => chromeExited };
  `);

  // A browser that is alive and whose kill cannot be delivered: 'error', never 'exit'.
  const stubborn = fakeChild({ pid: 9100, onKill: (c) => c.emit('error', Object.assign(new Error('kill EPERM'), { code: 'EPERM' })) });
  const harness = build(stubborn);
  const startup = observe(stubborn, { onExit: harness.markExited });
  stubborn.stderr.emit('data', Buffer.from(DEVTOOLS_LINE));   // a fully started browser

  await harness.stopBrowser();

  assert.equal(startup.exited, false, 'the failed kill was read as an exit');
  assert.equal(harness.exited(), false, 'chromeExited became true without any exit event');
  assert.deepEqual(stubborn.kills, ['default', 'SIGKILL'],
    'the SIGKILL escalation was skipped because a failed kill claimed the browser was gone');
  assert.equal(startup.failure, null, 'a cleanup-time kill failure was reported as a startup failure');

  // And the release predicate cannot confirm a release over that flag: observeRelease derives
  // browserExited from chromeExited and requires it to be anything but false.
  assert.ok(src.includes("c.browserExited = chrome ? chromeExited : 'not started';"));
  assert.ok(src.includes('const released = c.browserExited !== false'),
    'release confirmation no longer depends on the browser actually being gone');

  // A browser that really does exit is still reaped on the first kill, with no escalation.
  const clean = fakeChild({ pid: 9101, onKill: (c) => c.emit('exit', 0, null) });
  const cleanHarness = build(clean);
  const cleanStartup = observe(clean, { onExit: cleanHarness.markExited });
  clean.stderr.emit('data', Buffer.from(DEVTOOLS_LINE));
  await cleanHarness.stopBrowser();
  assert.deepEqual(clean.kills, ['default'], 'a browser that exited was killed twice');
  assert.equal(cleanStartup.exited, true);
  assert.equal(cleanHarness.exited(), true);
});

// ---------------------------------------------------------------- the opt-in share launcher path
//
// NON-LIVE. These run the runner's OWN pure text (lifted from the source) and, for the reservation,
// real files in a temporary directory. No daemon, container, browser, pool or network is involved.

test('the PAIRED live runner: --share-profile is narrow, and its absence leaves the legacy path alone', () => {
  const src = pairedRunnerSource();
  const classify = liftPureFunction(src, 'classifyShareProfileFlags');
  const known = ['--artifact-dir', '--image', '--blocks', '--interactive', '--share-profile', '--reservation'];
  const base = {
    argv: ['--share-profile', '--interactive', '--blocks', '1'],
    shareProfile: true, interactive: true, blocks: 1,
    shareDifficulty: 100, blockDifficulty: 500, knownFlags: known,
  };
  assert.deepEqual(classify(base), { ok: true, error: null });
  assert.deepEqual(classify({ ...base, blocks: 2, argv: ['--share-profile', '--interactive', '--blocks', '2'] }),
    { ok: true, error: null }, 'the explicitly bounded two-block share sequence is refused');

  // WITHOUT THE FLAG IT SAYS NOTHING: the legacy runner keeps every combination it ever accepted.
  for (const legacy of [
    { ...base, shareProfile: false, interactive: false, blocks: 32, argv: ['--blocks', '32'] },
    { ...base, shareProfile: false, shareDifficulty: 9999, blocks: 4 },
  ]) assert.deepEqual(classify(legacy), { ok: true, error: null }, JSON.stringify(legacy.argv));

  // WITH IT, each requirement is separately enforced.
  const refused = (over) => {
    const v = classify({ ...base, ...over });
    assert.equal(v.ok, false, JSON.stringify(over));
    assert.ok(typeof v.error === 'string' && v.error.length > 0);
    return v.error;
  };
  assert.match(refused({ interactive: false, argv: ['--share-profile', '--blocks', '1'] }), /--interactive/);
  assert.match(refused({ blocks: 3, argv: ['--share-profile', '--interactive', '--blocks', '3'] }), /--blocks 1 or 2/);
  assert.match(refused({ argv: ['--share-profile', '--interactive', '--blocks', '01'], blocks: 1 }), /canonical --blocks 1 or 2/);
  assert.match(refused({ argv: ['--share-profile', '--interactive', '--blocks', '02'], blocks: 2 }), /canonical --blocks 1 or 2/);
  assert.match(refused({ argv: ['--share-profile', '--interactive', '--headless'] }), /unknown flag/);
  assert.match(refused({ shareDifficulty: 0 }), /positive integer/);
  // The inequality that makes a share target >= a block target: share difficulty must not exceed it.
  assert.match(refused({ shareDifficulty: 501 }), /must not exceed/);
  assert.deepEqual(classify({ ...base, shareDifficulty: 500 }), { ok: true, error: null },
    'an equal difficulty is legal');
});

test('the PAIRED live runner: the tracked tree decides, and the user\'s own untracked paths are only named', () => {
  const src = pairedRunnerSource();
  const trackedDirty = liftPureFunction(src, 'trackedDirtyEntries');
  const allowed = ['.wakatime-project', 'retypes/'];

  assert.deepEqual(trackedDirty('?? .wakatime-project\n?? retypes/\n', allowed), []);
  assert.deepEqual(trackedDirty('', allowed), []);
  assert.deepEqual(trackedDirty(' M pool/dev/sim_session.mjs\n?? retypes/\n', allowed),
    [' M pool/dev/sim_session.mjs']);
  assert.deepEqual(trackedDirty('?? something-else.txt\n', allowed), ['?? something-else.txt']);
  // A staged deletion or rename is tracked dirt, whatever it looks like.
  assert.equal(trackedDirty('D  web-miner/app.js\n', allowed).length, 1);
  assert.equal(trackedDirty('R  a -> b\n', allowed).length, 1);
  // The names are matched, never opened: the helper takes only the status text.
  assert.equal(trackedDirty.length, 2, 'the helper grew a dependency beyond the status text');
  // The pin itself is SUPPLIED, never written here and never derived from HEAD at runtime.
  assert.equal(/const EXPECTED_HEAD\s*=/.test(src), false, 'a self-invalidating commit hash is back in the source');
  assert.ok(src.includes("const expectedHead = arg('expected-head');"), 'the pin is not supplied externally');
  assert.ok(src.includes('if (!pin.ok) throw new Error(pin.error);'), 'the pin gate is gone');
  assert.ok(src.includes("'--share-profile requires --expected-head <40 lowercase hex>"), 'the pin is not required');
});

test('the PAIRED live runner: the one-use reservation cannot be reconsumed by restarting', () => {
  const src = pairedRunnerSource();
  const reserve = liftPureFunction(src, 'reserveOneUse');
  const dir = mkdtempSync(join(tmpdir(), 'meep-reservation-test-'));
  try {
    const path = join(dir, 'reservation.json');
    const payload = { head: 'b'.repeat(40), runId: 'abc', shareDifficulty: 100 };
    const first = reserve({ path, payload, writeFile: writeFileSync, readFile: readFileSync });
    assert.equal(first.ok, true, first.reason ?? '');
    assert.deepEqual(first.payload, payload);

    // THE RESTART. The same runner, the same path, a new run id: refused, and the file on disk is
    // the ORIGINAL one -- nothing overwrote the record of what consumed the authorization.
    const second = reserve({
      path, payload: { ...payload, runId: 'second' }, writeFile: writeFileSync, readFile: readFileSync,
    });
    assert.equal(second.ok, false, 'a restart reconsumed the authorization');
    assert.match(second.reason, /already consumed/);
    assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), payload);

    // A write that cannot happen at all is a refusal, not a silent success.
    const broken = reserve({
      path: join(dir, 'nested', 'deep', 'reservation.json'), payload,
      writeFile: writeFileSync, readFile: readFileSync,
    });
    assert.equal(broken.ok, false);
    assert.match(broken.reason, /could not be created/);

    // A write that lands as something else is refused too.
    const lying = reserve({
      path: join(dir, 'other.json'), payload,
      writeFile: (p2) => writeFileSync(p2, '{"tampered":true}\n', { flag: 'wx' }),
      readFile: readFileSync,
    });
    assert.equal(lying.ok, false);
    assert.match(lying.reason, /not what was written/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  // It is written BEFORE the pool is started, and nothing removes it.
  assert.ok(src.indexOf('reserveOneUse({') < src.indexOf('await lifecycle.startPool('),
    'the reservation is taken after the first live side effect');
  assert.equal(/rmSync\([^)]*reservation/i.test(src), false, 'the runner deletes a reservation');
  assert.ok(src.includes("if (shareProfile) writeFileSync(transcriptPath, '', { flag: 'wx' });"),
    'the share path still truncates an existing transcript');
});

test('the PAIRED live runner: a share run claims a block only on real, non-lossy block evidence', () => {
  const src = pairedRunnerSource();
  const classify = liftPureFunction(src, 'classifyShareRunOutcome');
  const COMPLETE = 'terminal_complete';
  const BLOCK_ID = 'ab'.repeat(32);
  const base = {
    attemptState: COMPLETE, attemptReason: null, completeState: COMPLETE,
    shares: 3, shareSource: 'pool_sessions+websocket_frames',
    submitBlockCount: 1, calcPowCount: 1, rawDropped: 0,
    propagation: { converged: true, aHeader: { hash: BLOCK_ID } }, bWriteMethods: [],
    agreement: { agreed: true }, rpcRequestBodies: { proven: true, reason: null },
    blockIdFromFrame: BLOCK_ID, pageBlockId: BLOCK_ID,
  };
  assert.equal(classify(base), 'SHARE_RUN_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B_AFTER_3_ACCEPTED_SHARES');

  // EVERY REQUIRED FACT, INDIVIDUALLY. Each of these is a failure of proof, not a success.
  const cases = [
    [{ rawDropped: 1 }, 'FAILED:rpc_evidence_truncated'],
    [{ submitBlockCount: 0 }, 'FAILED:complete_without_one_submission'],
    [{ submitBlockCount: 2 }, 'FAILED:more_than_one_submission'],
    [{ calcPowCount: 0 }, 'FAILED:expected_one_calc_pow_saw_0'],
    [{ calcPowCount: 2 }, 'FAILED:expected_one_calc_pow_saw_2'],
    [{ rpcRequestBodies: null }, 'FAILED:rpc_request_body_mismatch:unknown'],
    [{ rpcRequestBodies: { proven: false, reason: 'calc_pow_request_body_mismatch' } },
      'FAILED:rpc_request_body_mismatch:calc_pow_request_body_mismatch'],
    [{ agreement: { agreed: false, reason: 'hash_disagreement' } }, 'FAILED:browser_agreement_not_established:hash_disagreement'],
    [{ agreement: { agreed: false } }, 'FAILED:browser_agreement_not_established:unknown'],
    [{ blockIdFromFrame: null }, 'FAILED:no_bound_block_accepted_frame'],
    [{ blockIdFromFrame: 'not-a-hash' }, 'FAILED:no_bound_block_accepted_frame'],
    // B converged on a DIFFERENT block: someone else's, or another height's.
    [{ propagation: { converged: true, aHeader: { hash: 'cd'.repeat(32) } } }, 'FAILED:accepted_block_id_mismatch'],
    [{ propagation: { converged: false, reason: 'peer_never_saw_it' } }, 'FAILED:peer_never_saw_it'],
    [{ pageBlockId: 'cd'.repeat(32) }, 'FAILED:page_block_id_mismatch'],
    [{ bWriteMethods: ['submit_block'] }, 'FAILED:rpc_write_to_daemon_b'],
  ];
  for (const [over, want] of cases) assert.equal(classify({ ...base, ...over }), want, JSON.stringify(over));

  // A block with an unproven share count is still a block -- and says so rather than inventing 0.
  assert.equal(classify({ ...base, shares: null }),
    'SHARE_RUN_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B_WITH_UNPROVEN_SHARE_COUNT');

  // BOUNDED OBSERVATIONS: truthful, never a block claim, and never a fabricated zero.
  const noBlock = {
    ...base, attemptState: 'terminal_cancelled', attemptReason: 'search_bound_reached',
    submitBlockCount: 0, calcPowCount: 0, propagation: null, blockIdFromFrame: null, pageBlockId: null,
  };
  assert.equal(classify({ ...noBlock, shares: 5 }), 'BOUNDED_OBSERVATION_NO_BLOCK_5_ACCEPTED_SHARES_0_CALC_POW');
  assert.equal(classify({ ...noBlock, shares: 0 }), 'BOUNDED_OBSERVATION_NO_BLOCK_0_ACCEPTED_SHARES_0_CALC_POW');
  assert.equal(classify({ ...noBlock, shares: null, shareSource: 'none' }),
    'BOUNDED_OBSERVATION_NO_BLOCK_SHARE_COUNT_UNPROVEN_none');
  assert.equal(classify({ ...noBlock, shares: null, shareSource: 'disagreement' }),
    'BOUNDED_OBSERVATION_NO_BLOCK_SHARE_COUNT_UNPROVEN_disagreement');
  assert.equal(classify({ ...noBlock, attemptReason: 'search_deadline_exceeded', shares: 2 }),
    'BOUNDED_OBSERVATION_NO_BLOCK_2_ACCEPTED_SHARES_0_CALC_POW');
  assert.equal(classify({ ...noBlock, rawDropped: 3, shares: 2 }), 'FAILED:rpc_evidence_truncated');
  assert.equal(classify({ ...noBlock, submitBlockCount: 1 }), 'FAILED:submission_without_an_accepted_block');
  assert.equal(classify({ ...noBlock, attemptReason: 'verifier_disagreement' }), 'FAILED:verifier_disagreement');

  // ORDINARY SHARE RUNS keep the historical rule: only an accepted, propagated block exits 0.
  // The separately named engineering probe has its own explicit success meaning, so test the pure
  // finalizer instead of pinning the old inline return statement that preceded that narrow mode.
  const finalize = liftPureFunction(src, 'finalizeShareRun');
  assert.equal(finalize({
    probe: false,
    shareOutcome: 'SHARE_RUN_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B_AFTER_3_ACCEPTED_SHARES',
    handoffProbeOutcome: null,
    okCode: 0,
    failedCode: 1,
  }).exitCode, 0);
  assert.equal(finalize({
    probe: false,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_5_ACCEPTED_SHARES_0_CALC_POW',
    handoffProbeOutcome: null,
    okCode: 0,
    failedCode: 1,
  }).exitCode, 1, 'an ordinary bounded no-block observation exited 0');
  assert.equal(finalize({
    probe: true,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
    handoffProbeOutcome: 'HANDOFF_PROBE_EXERCISED_BOUNDED_NO_BLOCK',
    okCode: 0,
    failedCode: 1,
  }).exitCode, 0, 'the explicitly named engineering probe could not report its own success');
  // The exact block is REQUIRED of daemon B, not merely a converged tip.
  assert.ok(src.includes('awaitPropagation({ expectedBlockId: blockFrame.blockId })'),
    'propagation no longer requires the exact accepted block id');
});

test('the PAIRED live runner: browser agreement is computed, never read off a label', () => {
  const src = pairedRunnerSource();
  const agree = liftPureFunction(src, 'classifyBrowserAgreement');
  const H = '11'.repeat(32);
  const ok = { pageNonce: 4242, submittedNonce: 4242, pageHash: H, serverWasmHash: H, nativeHash: H, daemonHash: H };
  assert.deepEqual(agree(ok), { agreed: true, reason: null, hashHexLE: H });
  // The page reports a string; the frame reports a number. Equal values still agree.
  assert.equal(agree({ ...ok, pageNonce: '4242' }).agreed, true);

  assert.deepEqual(agree({ ...ok, daemonHash: null }), { agreed: false, reason: 'missing_daemonHash' });
  assert.deepEqual(agree({ ...ok, nativeHash: undefined }), { agreed: false, reason: 'missing_nativeHash' });
  assert.deepEqual(agree({ ...ok, serverWasmHash: 'zz'.repeat(32) }), { agreed: false, reason: 'missing_serverWasmHash' });
  assert.deepEqual(agree({ ...ok, pageHash: '22'.repeat(32) }), { agreed: false, reason: 'hash_disagreement' });
  assert.deepEqual(agree({ ...ok, submittedNonce: null }), { agreed: false, reason: 'missing_nonce' });
  assert.deepEqual(agree({ ...ok, submittedNonce: 7 }), { agreed: false, reason: 'nonce_mismatch' });

  // Daemon A's hash comes out of the raw record, and a body that does not contain one is null.
  const powHash = liftPureFunction(src, 'daemonPowHashFromRaw');
  assert.equal(powHash({ responseText: JSON.stringify({ result: H }) }), H);
  assert.equal(powHash({ responseText: JSON.stringify({ result: 'short' }) }), null);
  assert.equal(powHash({ responseText: 'not json' }), null);
  assert.equal(powHash({ responseText: null }), null);
  assert.equal(powHash(undefined), null);
});

test('the PAIRED live runner: accepted blocks are bound to exact nonce-bearing daemon request bytes', () => {
  const src = pairedRunnerSource();
  const prove = liftPureFunction(src, 'classifyAcceptedRpcRequestBodies', [
    'noncePatchedTemplateHex', 'canonicalRpcRequestBodyMatches',
  ]);
  const nonce = 0x12345678;
  const facts = {
    height: '7', majorVersion: 16, seedHashHex: '66'.repeat(32),
    hashingNonceOffset: 4, fullNonceOffset: 8, fullBlockBytes: 24,
    blockhashingBlobHex: '10'.repeat(16), blocktemplateBlobHex: '30'.repeat(24),
  };
  const patched = (hex, offset) => {
    const bytes = Buffer.from(hex, 'hex');
    bytes.writeUInt32LE(nonce, offset);
    return bytes.toString('hex');
  };
  const calcParams = {
    major_version: 16, height: 7,
    block_blob: patched(facts.blockhashingBlobHex, facts.hashingNonceOffset),
    seed_hash: facts.seedHashHex,
  };
  const submitParams = [patched(facts.blocktemplateBlobHex, facts.fullNonceOffset)];
  const calcRecord = { requestBody: JSON.stringify({
    jsonrpc: '2.0', id: 'calc-7', method: 'calc_pow', params: calcParams,
  }) };
  const submitRecord = { requestBody: JSON.stringify({
    jsonrpc: '2.0', id: 'submit-7', method: 'submit_block', params: submitParams,
  }) };
  const base = { templateFacts: facts, nonce, calcRecord, submitRecord };
  assert.deepEqual(prove(base), { proven: true, reason: null });

  const failures = [
    { ...base, calcRecord: { requestBody: JSON.stringify({
      jsonrpc: '2.0', id: 'calc-7', method: 'calc_pow', params: { ...calcParams, block_blob: '00'.repeat(16) },
    }) } },
    { ...base, calcRecord: { requestBody: JSON.stringify({
      jsonrpc: '2.0', id: 'calc-7', method: 'calc_pow', params: calcParams, extra: true,
    }) } },
    { ...base, calcRecord: { requestBody: JSON.stringify({
      id: 'calc-7', jsonrpc: '2.0', method: 'calc_pow', params: calcParams,
    }) } },
    { ...base, submitRecord: { requestBody: JSON.stringify({
      jsonrpc: '2.0', id: 'submit-7', method: 'submit_block', params: ['00'.repeat(24)],
    }) } },
    { ...base, templateFacts: { ...facts, hashingNonceOffset: facts.hashingNonceOffset + 1 } },
    { ...base, templateFacts: { ...facts, fullBlockBytes: facts.fullBlockBytes + 1 } },
    { ...base, templateFacts: { ...facts, height: '07' } },
    { ...base, templateFacts: { ...facts, majorVersion: 256 } },
  ];
  for (const sample of failures) assert.equal(prove(sample).proven, false);
});

test('the PAIRED live runner: an empty session set is unknown shares, never zero', () => {
  const src = pairedRunnerSource();
  const reconcile = liftPureFunction(src, 'reconcileShareCount');

  // The socket closed and the session was disposed, and no frames were captured: UNKNOWN.
  const none = reconcile({ sessionsPresent: false, sessionShares: 0, frameShareNonces: [], framesCaptured: false });
  assert.equal(none.shares, null, 'a disposed session was reported as zero shares');
  assert.equal(none.source, 'none');

  // One source only: that source answers.
  assert.equal(reconcile({ sessionsPresent: true, sessionShares: 3, frameShareNonces: [], framesCaptured: false }).shares, 3);
  assert.equal(reconcile({ sessionsPresent: false, sessionShares: 0, frameShareNonces: [7, 9], framesCaptured: true }).shares, 2);
  // Frames are deduplicated by bound nonce: a replayed frame is not a second share.
  assert.equal(reconcile({ sessionsPresent: false, sessionShares: 0, frameShareNonces: [7, 7, 9], framesCaptured: true }).shares, 2);
  // A truncated capture is not a count at all -- the caller passes framesCaptured false for it.
  assert.equal(reconcile({ sessionsPresent: false, sessionShares: 0, frameShareNonces: [1, 2], framesCaptured: false }).shares, null);

  // Both sources, agreeing and disagreeing.
  const both = reconcile({ sessionsPresent: true, sessionShares: 2, frameShareNonces: [7, 9], framesCaptured: true });
  assert.equal(both.shares, 2);
  assert.equal(both.source, 'pool_sessions+websocket_frames');
  const clash = reconcile({ sessionsPresent: true, sessionShares: 3, frameShareNonces: [7, 9], framesCaptured: true });
  assert.equal(clash.shares, null, 'a disagreement was averaged into a number');
  assert.equal(clash.source, 'disagreement');
  // A genuine zero from a live session stays zero.
  assert.equal(reconcile({ sessionsPresent: true, sessionShares: 0, frameShareNonces: [], framesCaptured: true }).shares, 0);

  // The runner really does feed it both sources, and only bound frames. On a refresh run the
  // bound capture is the per-window one; on every other run it is exactly serverFrames.
  assert.ok(src.includes("method === 'Network.webSocketFrameReceived'"), 'no durable frame capture');
  assert.ok(src.includes('const boundFrames = refreshWindows !== null ? refreshFrames : serverFrames;'),
    'the bound frame source is not selected by run kind');
  assert.ok(src.includes('framesCaptured: boundFrames.captured && !boundFrames.truncated,'),
    'a truncated frame capture could be read as a complete count');
});

test('the PAIRED live runner: the evidence writer never replaces a file it did not create', () => {
  const src = pairedRunnerSource();
  const candidates = liftPureFunction(src, 'publishCandidates');
  const publish = liftPureFunction(src, 'publishNoReplace');
  const runId = 'deadbeefdeadbeef';

  assert.deepEqual(candidates({ path: 'C:/e/run.json', runId }), ['C:/e/run.json', `C:/e/run.json.${runId}.json`]);
  // The candidate list does not look at the filesystem at all: looking, then writing, IS the race.
  assert.equal(candidates.length, 1, 'the candidate list grew a filesystem dependency');

  const free = publish({ candidates: ['a', 'b'], write: () => ({ ok: true }) });
  assert.equal(free.path, 'a');
  assert.equal(free.fallback, false);

  const raced = publish({
    candidates: ['a', 'b'],
    write: (p2) => (p2 === 'a' ? { ok: false, stage: 'exists', code: 'EEXIST' } : { ok: true }),
  });
  assert.equal(raced.path, 'b');
  assert.equal(raced.fallback, true);
  assert.match(raced.reason, /deleted nothing/);

  const taken = publish({ candidates: ['a', 'b'], write: () => ({ ok: false, stage: 'exists', code: 'EEXIST' }) });
  assert.equal(taken.ok, false);
  assert.equal(taken.path, null);
  assert.match(taken.reason, /nothing was overwritten and nothing was deleted/);

  // A REAL failure is not a reason to try the next name: it is reported as itself.
  const broken = publish({ candidates: ['a', 'b'], write: () => ({ ok: false, stage: 'write', code: 'ENOSPC' }) });
  assert.equal(broken.ok, false);
  assert.equal(broken.attempts.length, 1, 'a write failure silently moved to another path');
  assert.match(broken.reason, /could not be written: write/);

  assert.equal(/rmSync\([^)]*evidence/i.test(src), false, 'the runner removes an evidence file');
  assert.ok(src.includes('write: (candidate) => persistJsonAtomically(candidate, evidence, { expect, noReplace: true }),'),
    'the share path does not publish with the no-replace writer');
  // THE SAVED DOCUMENT CAN ONLY CONTAIN WHAT WAS KNOWN BEFORE IT WAS SERIALISED. The intended paths
  // are recorded first and really appear in the file; the publication RESULT is stated as living in
  // the transcript, because writing it into the document would change the verified bytes.
  const intendedAt = src.indexOf('evidence.publish = {');
  const publishAt = src.indexOf('const published = publishNoReplace({');
  assert.notEqual(intendedAt, -1, 'the intended output paths are not recorded in the evidence');
  assert.ok(intendedAt < publishAt, 'the publish record is assigned after serialization again');
  assert.ok(src.includes("resultRecordedIn: 'the transcript and the process output, not this field',"),
    'the evidence implies it contains a publication outcome it cannot contain');
  assert.ok(src.includes("note('evidence publication', r0);"), 'the publication result reaches no durable record');
  assert.equal(src.includes('evidence.publish = published;'), false,
    'the publication result is assigned into an already-serialised document');
});

test('THE REAL WRITER: no-replace publication cannot overwrite or delete a racing file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'meep-publish-test-'));
  try {
    const target = join(dir, 'evidence.json');
    // A third party's file, written by somebody else, with content this run must never destroy.
    writeFileSync(target, 'SOMEONE ELSE\'S FILE\n');

    const blocked = persistJsonAtomically(target, { outcome: 'ours' }, { noReplace: true });
    assert.equal(blocked.ok, false, 'the no-replace writer overwrote an existing file');
    assert.equal(blocked.stage, 'exists');
    assert.equal(blocked.code, 'EEXIST');
    assert.equal(readFileSync(target, 'utf8'), 'SOMEONE ELSE\'S FILE\n', 'the third-party file was changed');

    // The fallback name is free, so the evidence lands there, intact and verified.
    const sibling = `${target}.abc123.json`;
    const ok = persistJsonAtomically(sibling, { outcome: 'ours' }, { noReplace: true, expect: { outcome: 'ours' } });
    assert.equal(ok.ok, true, ok.message ?? '');
    assert.equal(JSON.parse(readFileSync(sibling, 'utf8')).outcome, 'ours');
    assert.equal(readFileSync(target, 'utf8'), 'SOMEONE ELSE\'S FILE\n', 'publishing beside it disturbed it');

    // THE RACE ITSELF: the file appears between a would-be check and the write. Exclusive creation
    // is what makes that safe -- the writer loses the race instead of destroying the winner.
    const raced = join(dir, 'raced.json');
    assert.equal(existsSync(raced), false);
    writeFileSync(raced, 'appeared after the check\n');    // the racing creator wins
    const lost = persistJsonAtomically(raced, { outcome: 'ours' }, { noReplace: true });
    assert.equal(lost.ok, false);
    assert.equal(lost.stage, 'exists');
    assert.equal(readFileSync(raced, 'utf8'), 'appeared after the check\n');

    // A VERIFICATION FAILURE AFTER PUBLICATION removes only this call's own TEMPORARY file. The
    // final name is left alone on purpose: by then it is either our complete bytes or somebody
    // else's replacement of them, and unlinking it would destroy whichever it is.
    const bad = join(dir, 'verify.json');
    const failed = persistJsonAtomically(bad, { outcome: 'ours' }, { noReplace: true, expect: { outcome: 'other' } });
    assert.equal(failed.ok, false);
    assert.equal(failed.stage, 'verify');
    assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith('.tmp')), [], 'a temporary file was left behind');
    // What it did publish is COMPLETE, never half a document: the bytes were written, flushed and
    // closed in the temp sibling before the final name existed at all.
    assert.deepEqual(JSON.parse(readFileSync(bad, 'utf8')), { outcome: 'ours' });

    // A CRASH CANNOT LEAVE PARTIAL EVIDENCE UNDER THE FINAL NAME. A write that fails midway never
    // reaches the publish step, so the final name is never created and only the temp is removed.
    const partial = join(dir, 'partial.json');
    let wrote = 0;
    const crashingFs = {
      ...nodeFsAll,
      writeSync: (...args) => {
        wrote += 1;
        if (wrote > 0) throw Object.assign(new Error('device went away'), { code: 'EIO' });
        return nodeFsAll.writeSync(...args);
      },
    };
    const crashed = persistJsonAtomically(partial, { outcome: 'ours' }, { noReplace: true, fs: crashingFs });
    assert.equal(crashed.ok, false);
    assert.equal(crashed.stage, 'write');
    assert.equal(existsSync(partial), false, 'a failed write published a partial final file');
    assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith('.tmp')), [], 'a partial temporary file survived');

    // THE PUBLISH STEP IS A LINK, NOT A RENAME: it cannot replace, and losing the race leaves the
    // winner's file and our own temp behind is not an option either -- the temp is always removed.
    const linkRace = join(dir, 'link-race.json');
    writeFileSync(linkRace, 'the winner\n');
    const lostLink = persistJsonAtomically(linkRace, { outcome: 'ours' }, { noReplace: true });
    assert.equal(lostLink.stage, 'exists');
    assert.equal(lostLink.code, 'EEXIST');
    assert.equal(readFileSync(linkRace, 'utf8'), 'the winner\n');
    assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith('.tmp')), [],
      'a losing publish left its temporary file behind');

    // LEGACY SEMANTICS ARE UNCHANGED: the default writer still replaces a path this run owns.
    const legacy = join(dir, 'legacy.json');
    writeFileSync(legacy, 'old content\n');
    const replaced = persistJsonAtomically(legacy, { outcome: 'new' }, { expect: { outcome: 'new' } });
    assert.equal(replaced.ok, true, replaced.message ?? '');
    assert.equal(JSON.parse(readFileSync(legacy, 'utf8')).outcome, 'new');
    // And it leaves no temporary files behind.
    assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith('.tmp')), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the PAIRED live runner: the commit pin comes from outside and both git commands must succeed', () => {
  const src = pairedRunnerSource();
  const classify = liftPureFunction(src, 'classifyHeadPin');
  const trackedDirty = liftPureFunction(src, 'trackedDirtyEntries');
  const HEAD = 'a'.repeat(40);
  const allowed = ['.wakatime-project', 'retypes/'];
  const call = (over = {}) => classify({
    expectedHead: HEAD,
    headResult: { status: 0, stdout: `${HEAD}\n` },
    statusResult: { status: 0, stdout: '?? .wakatime-project\n?? retypes/\n' },
    allowedUntracked: allowed,
    trackedDirty,
    ...over,
  });
  assert.deepEqual(call(), { ok: true, error: null, head: HEAD, trackedDirty: [] });

  assert.match(call({ expectedHead: 'not-a-hash' }).error, /not 40 lowercase hex/);
  assert.match(call({ expectedHead: HEAD.toUpperCase() }).error, /not 40 lowercase hex/);
  assert.match(call({ expectedHead: 'b'.repeat(40) }).error, /is not the authorized commit/);
  assert.match(call({ headResult: { status: 128, stdout: '' } }).error, /git rev-parse HEAD failed/);
  assert.match(call({ headResult: { status: 0, stdout: 'ref: refs/heads/x\n' } }).error, /unusable HEAD/);
  // A FAILED status command proves nothing: its empty output must never be read as clean.
  const failedStatus = call({ statusResult: { status: 128, stdout: '' } });
  assert.equal(failedStatus.ok, false, 'a failed status check passed as clean');
  assert.match(failedStatus.error, /cleanliness is unproven/);
  assert.match(call({ statusResult: { status: 0, stdout: ' M pool/dev/sim_session.mjs\n' } }).error,
    /the tracked tree is not clean/);
});

test('the PAIRED live runner: share-path screenshots are unique, exclusive and taken before cleanup', () => {
  const src = pairedRunnerSource();
  const name = liftPureFunction(src, 'screenshotFileName');
  assert.equal(name({ runId: 'abc123', phase: 'pre-start' }), 'meepcoin-share-run-abc123-pre-start.png');
  assert.notEqual(name({ runId: 'abc123', phase: 'terminal' }), name({ runId: 'abc123', phase: 'pre-start' }));
  assert.notEqual(name({ runId: 'zzz', phase: 'terminal' }), name({ runId: 'abc123', phase: 'terminal' }));

  // The directory must be supplied, must BE a directory, and must be writable by this process.
  for (const text of [
    "if (!screenshotDir) return 'is required';",
    'if (!statSync(screenshotDir).isDirectory()) return',
    'accessSync(screenshotDir, fsConstants.W_OK);',
    "return 'is not writable by this process';",
  ]) assert.ok(src.includes(text), `the screenshot directory check is missing: ${text}`);
  // A PRE-START screenshot that cannot be written fails closed, BEFORE anyone is asked to press
  // Start, and goes through the one finalization path; the terminal one is only ever disclosed.
  const preAt = src.indexOf("const pre = await captureScreenshot('pre-start');");
  assert.notEqual(preAt, -1, 'no pre-Start screenshot');
  assert.ok(src.includes('if (!pre.ok) {'), 'a failed pre-Start screenshot no longer fails closed');
  assert.ok(src.includes('throw new Error(`the pre-Start screenshot could not be written'),
    'the pre-Start failure no longer ends the run');
  // AND IT SAYS WHAT THAT MEANS, TRUTHFULLY: by then the reservation is spent and both daemons are
  // up; what did NOT happen is the browser mining Start. The old wording claimed nothing had been
  // started at all.
  assert.equal(src.includes('nothing was started'), false, 'the false "nothing was started" claim is back');
  for (const text of [
    'the browser mining Start `',
    'was never requested, but the setup and the one-use reservation are already consumed',
    'reservationConsumed: true,',
    'browserMiningStarted: false,',
    'daemonsLaunched: true,',
    'a further attempt needs a new authorization and a new reservation path',
  ]) assert.ok(src.includes(text), `the pre-Start failure disclosure is missing: ${text}`);
  assert.ok(preAt < src.indexOf('waiting for the operator or delegated agent to press Start'),
    'the pre-Start screenshot is taken after the operator is asked to press Start');
  assert.equal(src.includes("if (!terminalShot.ok) throw"), false,
    'a failed terminal screenshot now throws over a run that may hold a block');
  assert.ok(src.includes("'--screenshot-dir is only meaningful with --share-profile'"));
  // Exclusive create, no overwrite, taken through the existing CDP page domain.
  assert.ok(src.includes("await cdp.send('Page.captureScreenshot', { format: 'png' });"));
  assert.ok(src.includes("writeFileSync(file, bytes, { flag: 'wx' });"), 'a screenshot could overwrite a file');
  // The terminal picture is taken inside the body, before beforePoolClose closes the browser, and a
  // failure is disclosed rather than retried.
  const terminalAt = src.indexOf("await captureScreenshot('terminal')");
  assert.notEqual(terminalAt, -1, 'no terminal screenshot');
  assert.ok(terminalAt < src.indexOf('beforePoolClose: stopBrowser'), 'the terminal screenshot races cleanup');
  assert.ok(src.includes('INCOMPLETE SCREENSHOT EVIDENCE'), 'a missing screenshot is not disclosed');
  assert.equal(src.split("captureScreenshot('terminal')").length - 1, 3,
    'the disjoint one-block, pure two-block, and Cartesian branches must each attempt one terminal screenshot');
  assert.equal(src.split("captureScreenshot('pre-start')").length - 1, 1);
});

test('the PAIRED live runner: share work is enabled only by trusted startup configuration', () => {
  const src = pairedRunnerSource();
  // The ONE wiring, and it is conditional on the flag: no --share-profile, no shareDifficulty key.
  assert.ok(src.includes('...(shareProfile ? { shareDifficulty: effectiveShareDifficulty } : {}),'),
    'share work is not wired through trusted startup configuration');
  assert.equal(src.split('shareDifficulty: effectiveShareDifficulty').length - 1, 3,
    'the selected source-fixed share difficulty appears somewhere unexpected');
  assert.match(src, /const SHARE_PROFILE_DIFFICULTY = 100;/);
  assert.match(src, /const HANDOFF_PROBE_SHARE_DIFFICULTY = 1;/);
  assert.ok(src.includes('function selectTrustedShareDifficulty({'));
  assert.equal(/--share-difficulty|arg\('share-difficulty'/.test(src), false,
    'the share difficulty became caller-selectable');
  // The evidence must separate shares from blocks, and say what a share cost the daemon TRUTHFULLY:
  // a block-quality result is also a share, and it does use calc_pow and a submission.
  for (const text of [
    'sharesAccepted: shareCount.shares', 'daemonCalcPow', 'daemonSubmitBlock', 'distinctNoncesAdmitted',
    'shareTargetHexLE', 'blockTargetHexLE', 'invalidCandidates', 'rawEvidenceDropped', 'browserAgreement',
    'an accepted share that is NOT a block costs the daemon nothing',
    'A block-quality result is also a share by construction, and it DOES use ',
  ]) assert.ok(src.includes(text), `missing share evidence: ${text}`);
  assert.equal(src.includes('each accepted share cost the daemon nothing'), false,
    'the false claim about every accepted share is back');
  // The consent text states the real bounds, including the one-at-a-time verification.
  assert.ok(src.includes('FROZEN BOUNDS (before Start, opt-in share path)'));
  for (const text of ['never rescanned', 'ONE AT A TIME', 'at most ONE submit_block to daemon A', 'no wallet']) {
    assert.ok(src.includes(text), `missing consent text: ${text}`);
  }
});

test('the PAIRED live runner: a captured server frame counts only if it names THIS run', () => {
  const src = pairedRunnerSource();
  const classify = liftPureFunction(src, 'classifyServerFrame');
  const H = '33'.repeat(32);
  const active = {
    clientStartId: 'a'.repeat(32), workerId: 'sim-1-bbbb', jobId: 'realjob-1111',
    issuanceId: '1'.repeat(32), runGeneration: 1,
  };
  const ctx = { active, jobId: active.jobId, issuanceId: active.issuanceId };
  const share = { type: 'share_accepted', ...active, nonce: 7, hashHexLE: H, shareIndex: 1 };
  const block = { type: 'block_accepted', ...active, nonce: 9, hashHexLE: H, blockId: 'ab'.repeat(32) };

  assert.deepEqual(classify({ frame: share, ...ctx }), { accepted: true, reason: null });
  assert.deepEqual(classify({ frame: block, ...ctx }), { accepted: true, reason: null });

  // ALL FIVE BINDING FIELDS ARE REQUIRED, and each must match the active record.
  for (const field of ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration']) {
    const { [field]: _drop, ...without } = share;
    assert.deepEqual(classify({ frame: { ...without }, ...ctx }), { accepted: false, reason: `missing_${field}` },
      `a frame without ${field} was counted`);
    assert.deepEqual(classify({ frame: { ...share, [field]: 'something-else' }, ...ctx }),
      { accepted: false, reason: `mismatched_${field}` }, `a frame with a foreign ${field} was counted`);
  }
  // clientStartId is the field the first revision never looked at at all.
  assert.equal(classify({ frame: { ...share, clientStartId: 'b'.repeat(32) }, ...ctx }).accepted, false);

  // A STALE BINDING: well formed, self-consistent, but not the template the pool is working on.
  const older = { ...active, jobId: 'realjob-0000', issuanceId: '0'.repeat(32), runGeneration: 0 };
  assert.equal(classify({ frame: { ...share, ...older }, active: older, jobId: active.jobId, issuanceId: active.issuanceId }).reason,
    'stale_job');
  assert.equal(classify({
    frame: { ...share, issuanceId: '2'.repeat(32) },
    active: { ...active, issuanceId: '2'.repeat(32) },
    jobId: active.jobId,
    issuanceId: active.issuanceId,
  }).reason, 'stale_issuance');

  // MALFORMED PAYLOADS are refused even when perfectly bound.
  assert.equal(classify({ frame: { ...share, nonce: -1 }, ...ctx }).reason, 'bad_nonce');
  assert.equal(classify({ frame: { ...share, nonce: 1.5 }, ...ctx }).reason, 'bad_nonce');
  assert.equal(classify({ frame: { ...share, hashHexLE: 'nope' }, ...ctx }).reason, 'bad_hash');
  assert.equal(classify({ frame: { ...block, hashHexLE: 'nope' }, ...ctx }).reason, 'bad_hash');
  assert.equal(classify({ frame: { ...block, hashHexLE: undefined }, ...ctx }).reason, 'bad_hash');
  assert.equal(classify({ frame: { ...block, blockId: 'nope' }, ...ctx }).reason, 'bad_block_id');
  assert.equal(classify({ frame: { ...share, type: 'mining_ready' }, ...ctx }).reason, 'not_an_evidence_frame');

  // Before run_started there is NO active binding, so nothing can be accepted.
  assert.deepEqual(classify({ frame: share, active: null, jobId: active.jobId, issuanceId: active.issuanceId }),
    { accepted: false, reason: 'no_active_binding' });

  // The runner learns the binding once, from run_started, and feeds the live template in.
  assert.ok(src.includes("if (frame?.type === 'run_started' && serverFrames.activeBinding === null) {"),
    'the active binding is not learned from the server itself');
  assert.ok(src.includes('active: serverFrames.activeBinding,'), 'frames are not checked against the binding');
  assert.ok(src.includes('jobId: sim?.job?.jobId ?? null,'), 'frames are not cross-checked against the live job');
  assert.ok(src.includes("issuanceId: sim?.authority?.currentIssuanceId ?? null,"),
    'frames are not cross-checked against the live issuance');
  assert.ok(src.includes('rejectFrame(frame.type, verdict.reason);'), 'refused frames are not recorded');
  // The block id is taken from an ALREADY VALIDATED frame, not re-sniffed by shape. On a refresh
  // run that list is the per-window bound capture; on every other run it is exactly serverFrames.
  assert.ok(src.includes('const blockFrame = boundFrames.blocks[0] ?? null;'),
    'the block frame is selected by shape rather than by binding');
});

test('the PAIRED live runner: a block claim requires the page to show that exact block id', () => {
  const src = pairedRunnerSource();
  const classify = liftPureFunction(src, 'classifyShareRunOutcome');
  const BLOCK_ID = 'ab'.repeat(32);
  const base = {
    attemptState: 'terminal_complete', attemptReason: null, completeState: 'terminal_complete',
    shares: 2, shareSource: 'pool_sessions+websocket_frames',
    submitBlockCount: 1, calcPowCount: 1, rawDropped: 0,
    propagation: { converged: true, aHeader: { hash: BLOCK_ID } }, bWriteMethods: [],
    agreement: { agreed: true }, rpcRequestBodies: { proven: true, reason: null },
    blockIdFromFrame: BLOCK_ID, pageBlockId: BLOCK_ID,
  };
  assert.equal(classify(base), 'SHARE_RUN_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B_AFTER_2_ACCEPTED_SHARES');

  // AN ABSENT PAGE BLOCK ID IS NOT A PASS. The browser never showed the accepted block, so its
  // agreement with A and B is unproven -- the previous revision let this through.
  for (const missing of [null, undefined, '', '\u2014', 'not-a-hash', BLOCK_ID.toUpperCase()]) {
    assert.equal(classify({ ...base, pageBlockId: missing }), 'FAILED:page_block_id_missing',
      `pageBlockId=${JSON.stringify(missing)} was accepted`);
  }
  assert.equal(classify({ ...base, pageBlockId: 'cd'.repeat(32) }), 'FAILED:page_block_id_mismatch');
});

test('the PAIRED live runner: two-block share frames chain five fields and quarantine old work', () => {
  const src = pairedRunnerSource();
  const capture = liftPureFunction(src, 'captureShareSequenceFrame',
    ['classifyServerFrame', 'classifyShareSequenceNext']);
  const b1 = { clientStartId: 'a'.repeat(32), workerId: 'worker-1', jobId: 'job-1',
    issuanceId: '1'.repeat(32), runGeneration: 1 };
  const b2 = { ...b1, jobId: 'job-2', issuanceId: '2'.repeat(32), runGeneration: 2 };
  const hash = '11'.repeat(32);
  const id1 = 'aa'.repeat(32);
  const state = { activeBinding: null, bindings: [], shares: [], blocks: [], terminalBlocks: [],
    truncated: false, captured: false, rejected: [], rejectedCount: 0 };
  const send = (frame) => capture({ state, frame, limit: 50 });
  assert.equal(send({ type: 'share_accepted', sequenceIndex: 1, nonce: 7, hashHexLE: hash, ...b1 }).accepted, false,
    'a share before run_started was counted');
  // A rejected pre-start frame is retained as incomplete evidence, so start a clean capture below.
  state.rejectedCount = 0;
  state.rejected.length = 0;
  assert.equal(send({ type: 'run_started', ...b1 }).accepted, true);
  assert.equal(send({ type: 'share_accepted', sequenceIndex: 1, nonce: 7, hashHexLE: hash,
    sharesAccepted: 1, sharesAcceptedTotal: 1, ...b1 }).accepted, true);
  assert.equal(send({ type: 'sequence_block_accepted', sequenceIndex: 1, sequenceTotal: 2,
    height: '1', nonce: 11, hashHexLE: hash, blockId: id1, ...b1 }).accepted, true);
  const next = { type: 'sequence_next', sequenceIndex: 2, sequenceTotal: 2, cause: 'accepted',
    previous: { jobId: b1.jobId, issuanceId: b1.issuanceId, runGeneration: 1 },
    job: { jobId: b2.jobId, issuanceId: b2.issuanceId, height: '2', shareWork: true,
      shareTargetHexLE: 'ff'.repeat(32) }, ...b2 };
  assert.equal(send({ ...next, previous: { ...next.previous, issuanceId: 'wrong' } }).accepted, false);
  assert.equal(state.activeBinding.jobId, b1.jobId, 'a bad next frame advanced the binding');
  state.rejectedCount = 0;
  state.rejected.length = 0;
  assert.equal(send(next).accepted, true);
  assert.equal(send({ type: 'share_accepted', sequenceIndex: 1, nonce: 9, hashHexLE: hash, ...b1 }).accepted, false,
    'a stale first-height share counted on height 2');
  assert.equal(send({ type: 'share_accepted', sequenceIndex: 2, nonce: 7, hashHexLE: hash,
    sharesAccepted: 1, sharesAcceptedTotal: 2, ...b2 }).accepted, true,
  'the same nonce on a new template must be distinct');
  assert.deepEqual(state.shares.map((s) => [s.sequenceIndex, s.nonce]), [[1, 7], [2, 7]]);
  assert.equal(state.rejectedCount, 1, 'the stale frame rejection disappeared');
  assert.ok(src.includes('captureShareSequenceFrame({ state: sequenceFrames, frame, limit: MAX_BROWSER_EVENTS })'));
});

test('the PAIRED live runner: two-block share success requires independent proof at both heights', () => {
  const src = pairedRunnerSource();
  const classify = liftPureFunction(src, 'classifyShareSequenceOutcome',
    [
      'daemonPowHashFromRaw', 'classifyBrowserAgreement', 'noncePatchedTemplateHex',
      'canonicalRpcRequestBodyMatches', 'classifyAcceptedRpcRequestBodies',
    ]);
  const H = '11'.repeat(32);
  const ids = ['aa'.repeat(32), 'bb'.repeat(32)];
  const nonceHex = (hex, nonce, offset) => {
    const bytes = Buffer.from(hex, 'hex');
    bytes.writeUInt32LE(nonce, offset);
    return bytes.toString('hex');
  };
  const hashingTemplates = ['10'.repeat(16), '20'.repeat(16)];
  const fullTemplates = ['30'.repeat(24), '40'.repeat(24)];
  const bindings = [1, 2].map((i) => ({ clientStartId: 'a'.repeat(32), workerId: 'worker-1',
    jobId: `job-${i}`, issuanceId: String(i).repeat(32), runGeneration: i, sequenceIndex: i }));
  const records = [1, 2].map((i) => ({ block: i, runGeneration: i,
    templateFacts: {
      height: String(i), majorVersion: 16, seedHashHex: '66'.repeat(32),
      hashingNonceOffset: 4, fullNonceOffset: 8, fullBlockBytes: 24,
      blockhashingBlobHex: hashingTemplates[i - 1], blocktemplateBlobHex: fullTemplates[i - 1],
    },
    accepted: { height: String(i), nonce: 10 + i, hashHexLE: H, blockId: ids[i - 1],
      jobId: bindings[i - 1].jobId, issuanceId: bindings[i - 1].issuanceId },
    lastHashes: { serverWasmHex: H, nativeHelperHex: H },
    propagation: { converged: true, aHeader: { hash: ids[i - 1] }, bHeader: { hash: ids[i - 1] } },
  }));
  const blocks = [1, 2].map((i) => ({ sequenceIndex: i, nonce: 10 + i,
    hashHexLE: H, blockId: ids[i - 1], boundTo: bindings[i - 1] }));
  const shares = [1, 2].map((i) => ({ sequenceIndex: i, nonce: 7, hashHexLE: H,
    sharesAccepted: 1, sharesAcceptedTotal: i, boundTo: bindings[i - 1] }));
  const pageBlocks = [1, 2].map((i) => ({ block: i, height: String(i), jobId: bindings[i - 1].jobId,
    nonce: 10 + i, hashHexLE: H, blockId: ids[i - 1], browserNonce: 10 + i,
    browserHashHexLE: H, browserMatched: true }));
  const raw = [1, 2].flatMap((i) => [
    { block: i, method: 'get_block_template' },
    { block: i, method: 'calc_pow', requestBody: JSON.stringify({
      jsonrpc: '2.0', id: `calc-${i}`, method: 'calc_pow', params: {
        major_version: 16, height: i,
        block_blob: nonceHex(hashingTemplates[i - 1], 10 + i, 4), seed_hash: '66'.repeat(32),
      },
    }), responseText: JSON.stringify({ result: H }) },
    { block: i, method: 'submit_block', requestBody: JSON.stringify({
      jsonrpc: '2.0', id: `submit-${i}`, method: 'submit_block',
      params: [nonceHex(fullTemplates[i - 1], 10 + i, 8)],
    }) },
  ]);
  const base = { attemptState: 'terminal_complete', attemptReason: 'complete',
    completeState: 'terminal_complete', currentHeight: '2', records, raw, rawDropped: 0,
    page: { blocks: pageBlocks, workerContexts: [
      { contextIndex: 1, jobId: bindings[0].jobId },
      { contextIndex: 2, jobId: bindings[1].jobId },
    ],
      workersCreated: '1', outcome: '2 blocks accepted by node A', error: '\u2014', startDisabled: true },
    frames: { bindings, blocks, shares, terminalBlocks: [blocks[1]],
      captured: true, truncated: false, rejectedCount: 0 },
    sessionFacts: [{ sharesAcceptedTotal: 2, sharesAccepted: 1 }],
    finalA: { get_block_template: 2, calc_pow: 2, submit_block: 2 }, finalB: {}, shareLimit: 8 };
  assert.equal(classify(base).outcome, 'SHARE_SEQUENCE_2_BLOCKS_ACCEPTED_BY_A_AND_RECEIVED_BY_B');
  const rejects = [
    { ...base, rawDropped: 1 },
    { ...base, finalB: { submit_block: 1 } },
    { ...base, frames: { ...base.frames, truncated: true } },
    { ...base, frames: { ...base.frames, rejectedCount: 1 } },
    { ...base, frames: { ...base.frames, blocks: [blocks[0]] } },
    { ...base, frames: { ...base.frames, terminalBlocks: [] } },
    { ...base, records: [records[0], { ...records[1], lastHashes: { ...records[1].lastHashes,
      nativeHelperHex: '22'.repeat(32) } }] },
    { ...base, records: [records[0], { ...records[1], propagation: { ...records[1].propagation,
      bHeader: { hash: 'cc'.repeat(32) } } }] },
    { ...base, page: { ...base.page, blocks: [pageBlocks[0], { ...pageBlocks[1],
      browserHashHexLE: '22'.repeat(32) }] } },
    { ...base, raw: raw.filter((r) => !(r.block === 2 && r.method === 'calc_pow')) },
    { ...base, raw: raw.map((record) => (
      record.block === 2 && record.method === 'calc_pow'
        ? { ...record, requestBody: record.requestBody.replace(/"block_blob":"[0-9a-f]+"/, `"block_blob":"${'00'.repeat(16)}"`) }
        : record
    )) },
    { ...base, raw: raw.map((record) => (
      record.block === 2 && record.method === 'submit_block'
        ? { ...record, requestBody: JSON.stringify({ jsonrpc: '2.0', id: 'submit-2', method: 'submit_block', params: ['00'.repeat(24)] }) }
        : record
    )) },
    { ...base, sessionFacts: [{ sharesAcceptedTotal: 1, sharesAccepted: 1 }] },
    { ...base, page: { ...base.page, startDisabled: false } },
  ];
  for (const sample of rejects) assert.match(classify(sample).outcome, /^FAILED:/);
  const bounded = classify({ ...base, attemptState: 'terminal_cancelled',
    attemptReason: 'search_bound_reached', currentHeight: '1', records: [], raw: [],
    frames: { ...base.frames, bindings: [bindings[0]], blocks: [], terminalBlocks: [], shares: [] },
    finalA: { get_block_template: 1 }, page: { ...base.page, blocks: [] } });
  assert.equal(bounded.outcome, 'BOUNDED_OBSERVATION_NO_BLOCK_AT_HEIGHT_1');
  assert.notEqual(bounded.outcome, 'SHARE_SEQUENCE_2_BLOCKS_ACCEPTED_BY_A_AND_RECEIVED_BY_B');
  assert.ok(src.includes("const terminalShot = await captureScreenshot('terminal');"));
  assert.ok(src.includes('blocks, shareProfile, sequenceFrames }'));
});

test('the PAIRED live runner: Cartesian proof binds issued prefixes, reset nonces, workers, RPCs, releases, and propagation', () => {
  const src = pairedRunnerSource();
  const classify = liftPureFunction(src, 'classifyShareSequenceRefreshOutcome', [
    'daemonPowHashFromRaw', 'classifyBrowserAgreement', 'noncePatchedTemplateHex',
    'canonicalRpcRequestBodyMatches', 'classifyAcceptedRpcRequestBodies',
    'sequenceRefreshSuccessOutcome',
  ]);
  const HASH = '11'.repeat(32);
  const MAX = 8192;
  const BUDGET = 600000;
  const bind = (binding) => ({
    clientStartId: binding.clientStartId,
    workerId: binding.workerId,
    jobId: binding.jobId,
    issuanceId: binding.issuanceId,
    runGeneration: binding.runGeneration,
    block: binding.block,
    window: binding.window,
  });
  const GENESIS_ID = '99'.repeat(32);
  const templateFactsFor = (binding) => {
    const parent = binding.block === 1 ? GENESIS_ID : 'aa'.repeat(32);
    return {
      block: binding.block,
      window: binding.window,
      height: binding.jobFacts.height,
      seedHashHex: binding.jobFacts.seedHashHex,
      majorVersion: 16,
      hashingNonceOffset: 4,
      fullNonceOffset: 8,
      fullBlockBytes: 24,
      blockhashingBlobHex: `${binding.block.toString(16).padStart(2, '0')}`.repeat(16),
      blocktemplateBlobHex: `${(binding.block + 2).toString(16).padStart(2, '0')}`.repeat(24),
      targetHexLE: binding.jobFacts.blockTargetHexLE,
      contentDigest: binding.jobFacts.contentDigest,
      jobId: binding.jobId,
      issuanceId: binding.issuanceId,
      nonceStart: binding.jobFacts.nonceStart,
      nonceRange: binding.jobFacts.nonceRange,
      prevHashHex: parent,
      topBeforeHash: parent,
      topBeforeHeight: binding.block - 1,
    };
  };
  // `sim_session` creates the current block record as soon as Start owns the run.  It is therefore
  // present even when no block was found, and its mutable per-height facts name the latest issued
  // window. The record's runGeneration is different: production writes it at W1 and deliberately
  // leaves it there when W2+ refreshes replace only templateFacts. Keep that split explicit so a
  // fixture cannot accidentally teach the auditor that a refreshed record must name the active
  // generation.
  const currentBlockRecord = (binding, firstWindowGeneration = binding.runGeneration, over = {}) => ({
    block: binding.block,
    runGeneration: firstWindowGeneration,
    templateFacts: templateFactsFor(binding),
    ...over,
  });
  const fixture = (winningWindows) => {
    const bindings = [];
    const readiness = [];
    const windowRecords = [];
    const workers = [];
    const shares = [];
    const windowOutcomes = [];
    const raw = [];
    const framesByBlock = [];
    const records = [];
    const pageBlocks = [];
    let shareTotal = 0;
    let contextIndex = 0;
    for (let block = 1; block <= 2; block += 1) {
      const winningWindow = winningWindows[block - 1];
      for (let window = 1; window <= winningWindow; window += 1) {
        contextIndex += 1;
        const jobId = `job-${block}-${window}`;
        const issuanceId = contextIndex.toString(16).padStart(32, '0');
        const nonceStart = (window - 1) * MAX;
        const jobFacts = {
          height: String(block), nonceStart, nonceRange: MAX,
          shareTargetHexLE: '22'.repeat(32), blockTargetHexLE: '33'.repeat(32),
          contentDigest: '44'.repeat(32), epochKeyHex: '55'.repeat(32),
          seedHashHex: '66'.repeat(32), hashingTemplateSha256: '77'.repeat(32),
        };
        const binding = {
          clientStartId: 'a'.repeat(32), workerId: 'worker-1', jobId, issuanceId,
          runGeneration: contextIndex, block, window, jobFacts,
        };
        bindings.push(binding);
        readiness.push({ block, window, sessionBudgetMs: BUDGET, boundTo: bind(binding) });
        windowRecords.push({
          block, window, jobId, issuanceId, height: String(block), nonceStart, nonceRange: MAX,
          shareTargetHexLE: jobFacts.shareTargetHexLE, blockTargetHexLE: jobFacts.blockTargetHexLE,
          contentDigest: jobFacts.contentDigest, epochKeyHex: jobFacts.epochKeyHex,
          seedHashHex: jobFacts.seedHashHex, hashingTemplateSha256: jobFacts.hashingTemplateSha256,
          verifierAllocationStartedAtMs: contextIndex * 100,
        });
        workers.push({
          jobId, contextIndex, moduleInstances: 1, rotated: contextIndex > 1,
          priorContextFreed: contextIndex > 1, priorContextActive: contextIndex > 1 ? false : null,
          wasmHeapBytes: 4096,
        });
        raw.push({ method: 'get_block_template', block, window, atMs: (contextIndex * 100) - 10, failure: null });
        if (window < winningWindow) {
          shareTotal += 1;
          shares.push({
            type: 'share_accepted', block, window, nonce: nonceStart, hashHexLE: HASH,
            sharesAccepted: 1, sharesAcceptedTotal: shareTotal, boundTo: bind(binding),
          });
          windowOutcomes.push({ block, window, outcome: 'window_exhausted', sharesAccepted: 1 });
        }
      }
      const binding = bindings.at(-1);
      const nonce = binding.jobFacts.nonceStart + 5;
      const templateFacts = templateFactsFor(binding);
      const nonceHex = (hex, offset) => {
        const bytes = Buffer.from(hex, 'hex');
        bytes.writeUInt32LE(nonce, offset);
        return bytes.toString('hex');
      };
      const blockId = block === 1 ? 'aa'.repeat(32) : 'bb'.repeat(32);
      const frame = {
        type: 'sequence_block_accepted', block, window: binding.window, nonce,
        hashHexLE: HASH, blockId, boundTo: bind(binding),
      };
      framesByBlock.push(frame);
      raw.push(
        { method: 'calc_pow', block, window: binding.window, failure: null,
          requestBody: JSON.stringify({
            jsonrpc: '2.0', id: `calc-${block}`, method: 'calc_pow', params: {
              major_version: templateFacts.majorVersion, height: Number(templateFacts.height),
              block_blob: nonceHex(templateFacts.blockhashingBlobHex, templateFacts.hashingNonceOffset),
              seed_hash: templateFacts.seedHashHex,
            },
          }),
          responseText: JSON.stringify({ result: HASH }) },
        { method: 'submit_block', block, window: binding.window, failure: null,
          requestBody: JSON.stringify({
            jsonrpc: '2.0', id: `submit-${block}`, method: 'submit_block',
            params: [nonceHex(templateFacts.blocktemplateBlobHex, templateFacts.fullNonceOffset)],
          }) },
      );
      const nextBlockFirst = block < 2 ? ((contextIndex + 1) * 100) - 10 : 9999;
      const firstHeightBinding = bindings.find((item) => item.block === block && item.window === 1);
      records.push({
        ...currentBlockRecord(binding, firstHeightBinding.runGeneration),
        block,
        accepted: {
          height: String(block), nonce, hashHexLE: HASH, blockId,
          jobId: binding.jobId, issuanceId: binding.issuanceId,
        },
        lastHashes: { serverWasmHex: HASH, nativeHelperHex: HASH },
        propagation: {
          converged: true, observedAtMs: nextBlockFirst - 1,
          aHeader: { hash: blockId, height: block }, aTop: { hash: blockId, height: block },
          bHeader: { hash: blockId, height: block }, bTop: { hash: blockId, height: block },
        },
      });
      pageBlocks.push({
        block, height: String(block), jobId: binding.jobId, nonce, hashHexLE: HASH, blockId,
        browserNonce: nonce, browserHashHexLE: HASH, browserMatched: true,
      });
    }
    const verifierHistory = windowRecords.slice(0, -1).map((record, index) => ({
      block: record.block, window: record.window, jobId: record.jobId, issuanceId: record.issuanceId,
      context: { height: record.height }, closed: true,
      releasedAtMs: record.verifierAllocationStartedAtMs + 1,
    }));
    const finalBinding = bindings.at(-1);
    return {
      attemptState: 'terminal_complete', attemptReason: 'complete', completeState: 'terminal_complete',
      currentHeight: '2', currentWindow: finalBinding.window,
      requestedBlocks: 2, requestedWindows: 2, maxAttempts: MAX, maxContexts: 32,
      sessionBudgetMs: BUDGET, records, windowRecords, verifierHistory,
      currentVerifier: {
        block: 2, window: finalBinding.window, jobId: finalBinding.jobId,
        issuanceId: finalBinding.issuanceId, closed: false, context: { height: '2' },
      },
      raw, rawDropped: 0,
      page: {
        blocks: pageBlocks, workersCreated: '1', workerContexts: workers, staleWorkerMessages: '0',
        outcome: '2 blocks accepted by node A', error: '\u2014', startDisabled: true,
      },
      frames: {
        activeBinding: finalBinding, bindings, readiness, shares, blocks: framesByBlock,
        terminalBlocks: [{ ...framesByBlock.at(-1), type: 'block_accepted' }],
        captured: true, truncated: false, rejectedCount: 0,
      },
      sessionFacts: [{
        sharesAcceptedTotal: shareTotal, sharesAccepted: 0, sessionDeadlineAtMs: 999999,
        sessionBudgetSpent: false, windowOutcomes,
      }],
      finalA: { get_block_template: bindings.length, calc_pow: 2, submit_block: 2 },
      finalB: {}, shareLimit: 8,
    };
  };

  const full = fixture([2, 2]);
  const success = 'SHARE_SEQUENCE_REFRESH_2_BLOCKS_UP_TO_2_WINDOWS_PER_HEIGHT_ACCEPTED_BY_A_AND_RECEIVED_BY_B';
  assert.equal(classify(full).outcome, success);
  assert.equal(classify(fixture([1, 1])).outcome, success, 'legal first-window wins required unused windows');
  assert.equal(classify(fixture([1, 2])).outcome, success, 'issued prefixes were mistaken for a full grid');
  assert.equal(classify({
    ...full, sessionFacts: [{ ...full.sessionFacts[0], sessionBudgetSpent: true }],
  }).outcome, success, 'a pre-deadline candidate that settled after the session timer was rejected');

  const rejects = [
    { ...full, windowRecords: full.windowRecords.map((record, index) => (
      index === 2 ? { ...record, nonceStart: MAX } : record
    )) },
    { ...full, raw: full.raw.map((record) => (
      record.block === 2 && record.method === 'calc_pow' ? { ...record, window: 1 } : record
    )) },
    { ...full, verifierHistory: full.verifierHistory.map((record, index) => (
      index === 1 ? { ...record, block: 2 } : record
    )) },
    { ...full, page: { ...full.page, workerContexts: full.page.workerContexts.map((worker, index) => (
      index === 2 ? { ...worker, jobId: 'wrong-job' } : worker
    )) } },
    { ...full, records: full.records.map((record, index) => (
      index === 0 ? { ...record, propagation: { ...record.propagation, observedAtMs: 999999 } } : record
    )) },
    { ...full, records: full.records.map((record, index) => (
      index === 0 ? { ...record, propagation: {
        ...record.propagation, bTop: { ...record.propagation.bTop, hash: 'cc'.repeat(32) },
      } } : record
    )) },
    { ...full, sessionFacts: [{ ...full.sessionFacts[0], windowOutcomes: full.sessionFacts[0].windowOutcomes
      .map((outcome, index) => (index === 0 ? { ...outcome, sharesAccepted: 0 } : outcome)) }] },
    { ...full, currentVerifier: { ...full.currentVerifier, jobId: 'wrong-job' } },
    { ...full, sessionBudgetMs: BUDGET - 1 },
    { ...full, frames: { ...full.frames, readiness: full.frames.readiness.map((ready, index) => (
      index === 0 ? { ...ready, sessionBudgetMs: BUDGET - 1 } : ready
    )) } },
    { ...full, frames: { ...full.frames, readiness: full.frames.readiness.map((ready, index) => {
      if (index !== 0) return ready;
      const withoutBudget = { ...ready };
      delete withoutBudget.sessionBudgetMs;
      return withoutBudget;
    }) } },
    { ...full, raw: [...full.raw, {
      method: 'get_block_template', block: 1, window: 99, atMs: 50, failure: null,
    }] },
    { ...full, raw: full.raw.map((record) => (
      record.block === 1 && record.method === 'calc_pow'
        ? { ...record, requestBody: record.requestBody.replace('"seed_hash":"66', '"seed_hash":"00') }
        : record
    )) },
    { ...full, raw: full.raw.map((record) => (
      record.block === 2 && record.method === 'submit_block'
        ? { ...record, requestBody: JSON.stringify({
          jsonrpc: '2.0', id: 'submit-2', method: 'submit_block', params: ['00'.repeat(24)],
        }) }
        : record
    )) },
  ];
  for (const [index, sample] of rejects.entries()) {
    assert.match(classify(sample).outcome, /^FAILED:/, `Cartesian invalid fixture ${index} passed`);
  }

  // A bounded result is evidence-bearing, not a label produced from the current coordinate alone.
  // This H1/W1 prefix proves its server issuance, browser readiness, Worker context, template RPC,
  // fixed whole-Start budget and live verifier. It may therefore retain that one validated context
  // while making no block claim.
  const firstBinding = full.frames.bindings[0];
  const firstRecord = full.windowRecords[0];
  const firstReady = full.frames.readiness[0];
  const firstWorker = full.page.workerContexts.find((worker) => worker.jobId === firstBinding.jobId);
  const boundedBase = {
    ...full,
    attemptState: 'terminal_cancelled',
    attemptReason: 'search_bound_reached',
    currentHeight: '1',
    currentWindow: 1,
    records: [currentBlockRecord(firstBinding)],
    windowRecords: [firstRecord],
    verifierHistory: [],
    currentVerifier: {
      block: 1, window: 1, jobId: firstBinding.jobId, issuanceId: firstBinding.issuanceId,
      closed: false, context: { height: '1' },
    },
    raw: [full.raw.find((record) => (
      record.block === 1 && record.window === 1 && record.method === 'get_block_template'
    ))],
    page: {
      ...full.page,
      blocks: [],
      workerContexts: [firstWorker],
      outcome: 'BOUNDED_NO_SOLUTION: no block-quality nonce before the preset search limit at height 1',
    },
    frames: {
      activeBinding: firstBinding,
      bindings: [firstBinding],
      readiness: [firstReady],
      shares: [],
      blocks: [], terminalBlocks: [], captured: true, truncated: false, rejectedCount: 0,
    },
    sessionFacts: [{
      sharesAcceptedTotal: 0, sharesAccepted: 0, sessionDeadlineAtMs: 999999,
      sessionBudgetSpent: true, windowOutcomes: [],
    }],
    finalA: { get_block_template: 1 },
  };
  const bounded = classify(boundedBase);
  assert.equal(bounded.outcome, 'BOUNDED_OBSERVATION_NO_BLOCK_AT_HEIGHT_1_WINDOW_1');
  assert.deepEqual(bounded.contexts.map((context) => [
    context.block, context.window, context.jobId,
  ]), [[1, 1, firstBinding.jobId]], 'the valid bounded context prefix was discarded');
  assert.deepEqual(bounded.heights, [], 'a bounded current height fabricated an accepted block');
  assert.match(classify({ ...boundedBase, attemptReason: 'search_deadline_exceeded' }).outcome, /^FAILED:/,
    'a terminal failure reason was mislabeled as a bounded no-block observation');

  const noEvidence = classify({
    ...boundedBase,
    windowRecords: [], currentVerifier: null, raw: [], finalA: {},
    page: { ...boundedBase.page, workerContexts: [] },
    frames: {
      ...boundedBase.frames, activeBinding: null, bindings: [], readiness: [], shares: [],
    },
    sessionFacts: [],
  });
  assert.match(noEvidence.outcome, /^FAILED:/,
    'an empty coordinate-only run was upgraded to a bounded observation');
  assert.deepEqual(noEvidence.contexts, []);
  assert.deepEqual(noEvidence.heights, []);

  for (const unexpectedRaw of [
    { method: 'calc_pow', block: 1, window: 1, failure: null },
    { method: 'get_block_template', block: 1, window: 2, atMs: 90, failure: null },
  ]) {
    const verdict = classify({ ...boundedBase, raw: [...boundedBase.raw, unexpectedRaw] });
    assert.match(verdict.outcome, /^FAILED:/,
      `bounded evidence accepted an unexpected ${unexpectedRaw.method} RPC`);
  }

  // A later bounded window proves a two-context prefix. This gives the geometry, generation and
  // Worker-lifecycle negative tests a valid baseline rather than making them fail for some unrelated
  // missing release or template fact.
  const secondBinding = full.frames.bindings[1];
  const boundedAtHeightOneWindowTwo = {
    ...boundedBase,
    currentWindow: 2,
    records: [currentBlockRecord(secondBinding, firstBinding.runGeneration)],
    windowRecords: full.windowRecords.slice(0, 2),
    verifierHistory: full.verifierHistory.slice(0, 1),
    currentVerifier: {
      block: 1, window: 2, jobId: secondBinding.jobId, issuanceId: secondBinding.issuanceId,
      closed: false, context: { height: '1' },
    },
    raw: full.raw.filter((record) => record.block === 1 && record.method === 'get_block_template'),
    page: {
      ...boundedBase.page,
      workerContexts: full.page.workerContexts.slice(0, 2),
    },
    frames: {
      ...boundedBase.frames,
      activeBinding: secondBinding,
      bindings: full.frames.bindings.slice(0, 2),
      readiness: full.frames.readiness.slice(0, 2),
      shares: full.frames.shares.filter((share) => share.block === 1 && share.window === 1),
    },
    sessionFacts: [{
      sharesAcceptedTotal: 1, sharesAccepted: 0, sessionDeadlineAtMs: 999999,
      sessionBudgetSpent: true,
      windowOutcomes: full.sessionFacts[0].windowOutcomes.filter((outcome) => outcome.block === 1),
    }],
    finalA: { get_block_template: 2 },
  };
  const boundedH1W2 = classify(boundedAtHeightOneWindowTwo);
  assert.equal(boundedH1W2.outcome, 'BOUNDED_OBSERVATION_NO_BLOCK_AT_HEIGHT_1_WINDOW_2');
  assert.deepEqual(boundedH1W2.contexts.map((context) => [context.block, context.window]), [[1, 1], [1, 2]]);
  assert.equal(boundedAtHeightOneWindowTwo.records[0].runGeneration, firstBinding.runGeneration,
    'the fixture did not preserve the production W1 block-record generation');
  assert.notEqual(boundedAtHeightOneWindowTwo.records[0].runGeneration, secondBinding.runGeneration,
    'the fixture accidentally copied the active refreshed generation into blockRecords');

  // At a nonfinal window, `search_bound_reached` can end the whole Start only when the one global
  // session budget was actually spent.  At the final configured window, exhausting the Cartesian
  // search is independently terminal, so either timer state is coherent.
  assert.match(classify({
    ...boundedBase,
    sessionFacts: [{ ...boundedBase.sessionFacts[0], sessionBudgetSpent: false }],
  }).outcome, /^FAILED:/,
  'an unspent whole-session budget ended the run before its next configured window');
  for (const sessionBudgetSpent of [false, true]) {
    assert.equal(classify({
      ...boundedAtHeightOneWindowTwo,
      sessionFacts: [{ ...boundedAtHeightOneWindowTwo.sessionFacts[0], sessionBudgetSpent }],
    }).outcome, 'BOUNDED_OBSERVATION_NO_BLOCK_AT_HEIGHT_1_WINDOW_2',
    `the final window rejected coherent sessionBudgetSpent=${sessionBudgetSpent}`);
  }

  for (const [label, current] of [
    ['accepted flag', {
      ...boundedBase.records[0],
      accepted: { ...full.records[0].accepted },
    }],
    ['block identity', { ...boundedBase.records[0], block: 2 }],
    ['template identity', {
      ...boundedBase.records[0],
      templateFacts: { ...boundedBase.records[0].templateFacts, jobId: 'foreign-job' },
    }],
  ]) {
    assert.match(classify({ ...boundedBase, records: [current] }).outcome, /^FAILED:/,
      `an H1 bounded observation accepted a current record with forged ${label}`);
  }

  const withGeometry = (base, contextIndex, over) => {
    const record = { ...base.windowRecords[contextIndex], ...over };
    const binding = {
      ...base.frames.bindings[contextIndex],
      jobFacts: { ...base.frames.bindings[contextIndex].jobFacts, ...over },
    };
    const bindings = base.frames.bindings.map((item, index) => (index === contextIndex ? binding : item));
    return {
      ...base,
      windowRecords: base.windowRecords.map((item, index) => (index === contextIndex ? record : item)),
      frames: {
        ...base.frames,
        activeBinding: contextIndex === base.frames.bindings.length - 1 ? binding : base.frames.activeBinding,
        bindings,
      },
    };
  };
  for (const [label, sample] of [
    ['window 1 nonzero nonce start', withGeometry(boundedBase, 0, { nonceStart: 1 })],
    ['short nonce range', withGeometry(boundedBase, 0, { nonceRange: MAX - 1 })],
    ['window 2 shifted nonce start', withGeometry(boundedAtHeightOneWindowTwo, 1, { nonceStart: MAX + 1 })],
  ]) {
    assert.match(classify(sample).outcome, /^FAILED:/,
      `${label} passed despite violating the exact maxAttempts geometry`);
  }

  const gapBinding = { ...secondBinding, runGeneration: secondBinding.runGeneration + 1 };
  const generationGap = {
    ...boundedAtHeightOneWindowTwo,
    frames: {
      ...boundedAtHeightOneWindowTwo.frames,
      activeBinding: gapBinding,
      bindings: [firstBinding, gapBinding],
      readiness: [full.frames.readiness[0], {
        ...full.frames.readiness[1],
        boundTo: { ...full.frames.readiness[1].boundTo, runGeneration: gapBinding.runGeneration },
      }],
    },
  };
  assert.match(classify(generationGap).outcome, /^FAILED:/,
    'a bounded context prefix accepted a run-generation gap');

  for (const [label, over] of [
    ['rotation flag', { rotated: false }],
    ['prior-context release', { priorContextFreed: false }],
    ['prior-context liveness', { priorContextActive: true }],
    ['positive Wasm heap', { wasmHeapBytes: 0 }],
  ]) {
    const badWorker = {
      ...boundedAtHeightOneWindowTwo,
      page: {
        ...boundedAtHeightOneWindowTwo.page,
        workerContexts: boundedAtHeightOneWindowTwo.page.workerContexts.map((worker, index) => (
          index === 1 ? { ...worker, ...over } : worker
        )),
      },
    };
    assert.match(classify(badWorker).outcome, /^FAILED:/,
      `a bounded prefix did not prove the successor Worker's ${label}`);
  }

  // Height 2 may be bounded only after height 1 has passed the same independent block proof used
  // by a completed run. The first accepted height is retained in `heights`; it is not thrown away
  // merely because the current height found no block before the global deadline.
  const thirdBinding = full.frames.bindings[2];
  const acceptedHeightOneRecord = { ...full.records[0] };
  const currentHeightTwoRecord = currentBlockRecord(thirdBinding);
  const boundedAtHeightTwo = {
    ...full,
    attemptState: 'terminal_cancelled',
    attemptReason: 'search_bound_reached',
    currentHeight: '2', currentWindow: 1,
    records: [acceptedHeightOneRecord, currentHeightTwoRecord],
    windowRecords: full.windowRecords.slice(0, 3),
    verifierHistory: full.verifierHistory.slice(0, 2),
    currentVerifier: {
      block: 2, window: 1, jobId: thirdBinding.jobId, issuanceId: thirdBinding.issuanceId,
      closed: false, context: { height: '2' },
    },
    raw: full.raw.filter((record) => (
      record.block === 1
      || (record.block === 2 && record.window === 1 && record.method === 'get_block_template')
    )),
    page: {
      ...full.page,
      blocks: full.page.blocks.slice(0, 1),
      workerContexts: full.page.workerContexts.slice(0, 3),
      outcome: 'BOUNDED_NO_SOLUTION: no block-quality nonce before the preset search limit at height 2',
    },
    frames: {
      ...full.frames,
      activeBinding: thirdBinding,
      bindings: full.frames.bindings.slice(0, 3),
      readiness: full.frames.readiness.slice(0, 3),
      shares: full.frames.shares.filter((share) => share.block === 1),
      blocks: full.frames.blocks.slice(0, 1),
      terminalBlocks: [],
    },
    sessionFacts: [{
      sharesAcceptedTotal: 1, sharesAccepted: 0, sessionDeadlineAtMs: 999999,
      sessionBudgetSpent: true,
      windowOutcomes: full.sessionFacts[0].windowOutcomes.filter((outcome) => outcome.block === 1),
    }],
    finalA: { get_block_template: 3, calc_pow: 1, submit_block: 1 },
  };
  const boundedH2 = classify(boundedAtHeightTwo);
  assert.equal(boundedH2.outcome, 'BOUNDED_OBSERVATION_NO_BLOCK_AT_HEIGHT_2_WINDOW_1');
  assert.deepEqual(boundedH2.contexts.map((context) => [context.block, context.window]), [
    [1, 1], [1, 2], [2, 1],
  ]);
  assert.equal(boundedH2.heights.length, 1, 'the validated first-height proof was discarded');
  assert.equal(boundedH2.heights[0].block, 1);
  assert.equal(String(boundedH2.heights[0].height), '1');
  assert.equal(boundedH2.heights[0].blockId, full.records[0].accepted.blockId);

  // The whole-Start clock can pass after an accepted non-final height has reached peer B but before
  // the server is allowed to issue the successor template. That is neither a two-height success nor
  // a no-block observation at the accepted height: retain the independently proven H1 block and say
  // explicitly that no H2 context ever existed.
  const boundedAfterAcceptedHeightOne = {
    ...full,
    attemptState: 'terminal_cancelled',
    attemptReason: 'search_bound_reached',
    currentHeight: '1', currentWindow: secondBinding.window,
    records: [acceptedHeightOneRecord],
    windowRecords: full.windowRecords.slice(0, 2),
    verifierHistory: full.verifierHistory.slice(0, 2),
    currentVerifier: null,
    raw: full.raw.filter((record) => record.block === 1),
    page: {
      ...full.page,
      blocks: full.page.blocks.slice(0, 1),
      workerContexts: full.page.workerContexts.slice(0, 2),
      outcome: 'BOUNDED_NO_SOLUTION: the whole-session limit passed before the next height was issued',
    },
    frames: {
      ...full.frames,
      activeBinding: secondBinding,
      bindings: full.frames.bindings.slice(0, 2),
      readiness: full.frames.readiness.slice(0, 2),
      shares: full.frames.shares.filter((share) => share.block === 1),
      blocks: full.frames.blocks.slice(0, 1),
      terminalBlocks: [],
    },
    sessionFacts: [{
      sharesAcceptedTotal: 1, sharesAccepted: 0, sessionDeadlineAtMs: 999999,
      sessionBudgetSpent: true,
      windowOutcomes: full.sessionFacts[0].windowOutcomes.filter((outcome) => outcome.block === 1),
    }],
    finalA: { get_block_template: 2, calc_pow: 1, submit_block: 1 },
  };
  const acceptedThenBounded = classify(boundedAfterAcceptedHeightOne);
  assert.equal(acceptedThenBounded.outcome, 'BOUNDED_AFTER_1_BLOCK_ACCEPTED_BEFORE_SUCCESSOR_ISSUED');
  assert.deepEqual(acceptedThenBounded.contexts.map((context) => [context.block, context.window]), [
    [1, 1], [1, 2],
  ]);
  assert.equal(acceptedThenBounded.heights.length, 1, 'the accepted H1 evidence was discarded at handoff');
  assert.equal(acceptedThenBounded.heights[0].blockId, full.records[0].accepted.blockId);
  assert.ok(src.includes('before the successor height was ever issued'),
    'the durable report does not explain that no successor context existed');

  for (const [label, sample] of [
    ['unspent session budget', {
      ...boundedAfterAcceptedHeightOne,
      sessionFacts: [{ ...boundedAfterAcceptedHeightOne.sessionFacts[0], sessionBudgetSpent: false }],
    }],
    ['unexpected live winning verifier', {
      ...boundedAfterAcceptedHeightOne,
      currentVerifier: { ...full.verifierHistory[1], closed: false },
    }],
    ['missing winning-verifier release', {
      ...boundedAfterAcceptedHeightOne,
      verifierHistory: boundedAfterAcceptedHeightOne.verifierHistory.slice(0, 1),
    }],
    ['invented successor template', {
      ...boundedAfterAcceptedHeightOne,
      raw: [...boundedAfterAcceptedHeightOne.raw, full.raw.find((record) => (
        record.block === 2 && record.window === 1 && record.method === 'get_block_template'
      ))],
    }],
    ['missing peer convergence', {
      ...boundedAfterAcceptedHeightOne,
      records: [{ ...acceptedHeightOneRecord, propagation: { ...acceptedHeightOneRecord.propagation, converged: false } }],
    }],
    ['fabricated terminal-success frame', {
      ...boundedAfterAcceptedHeightOne,
      frames: { ...boundedAfterAcceptedHeightOne.frames, terminalBlocks: [full.frames.blocks[0]] },
    }],
    ['wrong terminal height', {
      ...boundedAfterAcceptedHeightOne,
      currentHeight: String(BigInt(boundedAfterAcceptedHeightOne.currentHeight) + 1n),
    }],
    ['wrong active block coordinate', {
      ...boundedAfterAcceptedHeightOne,
      frames: {
        ...boundedAfterAcceptedHeightOne.frames,
        activeBinding: { ...boundedAfterAcceptedHeightOne.frames.activeBinding, block: 2 },
      },
    }],
    ['success-looking page terminal', {
      ...boundedAfterAcceptedHeightOne,
      page: { ...boundedAfterAcceptedHeightOne.page, outcome: '2 blocks accepted by node A' },
    }],
    ['unissued-coordinate readback', {
      ...boundedAfterAcceptedHeightOne,
      raw: [...boundedAfterAcceptedHeightOne.raw, {
        ...boundedAfterAcceptedHeightOne.raw[0], method: 'get_last_block_header', block: 2, window: 1,
      }],
    }],
    ['run-generation gap', {
      ...boundedAfterAcceptedHeightOne,
      frames: {
        ...boundedAfterAcceptedHeightOne.frames,
        bindings: boundedAfterAcceptedHeightOne.frames.bindings.map((binding, index) => (
          index === 1 ? { ...binding, runGeneration: binding.runGeneration + 1 } : binding
        )),
      },
    }],
    ['missing session deadline', {
      ...boundedAfterAcceptedHeightOne,
      sessionFacts: [{ ...boundedAfterAcceptedHeightOne.sessionFacts[0], sessionDeadlineAtMs: null }],
    }],
  ]) {
    assert.match(classify(sample).outcome, /^FAILED:/,
      `the accepted-before-successor boundary accepted ${label}`);
  }

  for (const [label, records] of [
    ['prior accepted template identity', boundedAtHeightTwo.records.map((record, index) => (
      index === 0 ? {
        ...record,
        templateFacts: { ...record.templateFacts, jobId: 'foreign-prior-job' },
      } : record
    ))],
    ['prior accepted template content', boundedAtHeightTwo.records.map((record, index) => (
      index === 0 ? {
        ...record,
        templateFacts: { ...record.templateFacts, contentDigest: '00'.repeat(32) },
      } : record
    ))],
    ['prior accepted parent identity', boundedAtHeightTwo.records.map((record, index) => (
      index === 0 ? {
        ...record,
        templateFacts: { ...record.templateFacts, prevHashHex: '88'.repeat(32) },
      } : record
    ))],
    ['current previous-block identity', boundedAtHeightTwo.records.map((record, index) => (
      index === 1 ? {
        ...record,
        templateFacts: { ...record.templateFacts, prevHashHex: '88'.repeat(32) },
      } : record
    ))],
    ['current top-before identity', boundedAtHeightTwo.records.map((record, index) => (
      index === 1 ? {
        ...record,
        templateFacts: { ...record.templateFacts, topBeforeHash: '88'.repeat(32) },
      } : record
    ))],
    ['current top-before height', boundedAtHeightTwo.records.map((record, index) => (
      index === 1 ? {
        ...record,
        templateFacts: { ...record.templateFacts, topBeforeHeight: 0 },
      } : record
    ))],
  ]) {
    assert.match(classify({ ...boundedAtHeightTwo, records }).outcome, /^FAILED:/,
      `an H2 bounded observation accepted a forged ${label}`);
  }

  for (const [label, current] of [
    ['accepted flag', {
      ...currentHeightTwoRecord,
      accepted: { ...full.records[1].accepted },
    }],
    ['block identity', { ...currentHeightTwoRecord, block: 3 }],
    ['template identity', {
      ...currentHeightTwoRecord,
      templateFacts: { ...currentHeightTwoRecord.templateFacts, contentDigest: '00'.repeat(32) },
    }],
  ]) {
    assert.match(classify({
      ...boundedAtHeightTwo,
      records: [acceptedHeightOneRecord, current],
    }).outcome, /^FAILED:/,
    `an H2 bounded observation accepted a current record with forged ${label}`);
  }

  const priorProofForgeries = [
    ['accepted record', {
      ...boundedAtHeightTwo,
      records: boundedAtHeightTwo.records.map((record, index) => (index === 0 ? {
        ...record, accepted: { ...record.accepted, blockId: 'cc'.repeat(32) },
      } : record)),
    }],
    ['bound block frame', {
      ...boundedAtHeightTwo,
      frames: { ...boundedAtHeightTwo.frames, blocks: [{
        ...boundedAtHeightTwo.frames.blocks[0], nonce: boundedAtHeightTwo.frames.blocks[0].nonce + 1,
      }] },
    }],
    ['page block', {
      ...boundedAtHeightTwo,
      page: { ...boundedAtHeightTwo.page, blocks: [{
        ...boundedAtHeightTwo.page.blocks[0], browserHashHexLE: '22'.repeat(32),
      }] },
    }],
    ['calc_pow result', {
      ...boundedAtHeightTwo,
      raw: boundedAtHeightTwo.raw.map((record) => (
        record.block === 1 && record.method === 'calc_pow'
          ? { ...record, responseText: JSON.stringify({ result: '22'.repeat(32) }) }
          : record
      )),
    }],
    ['submit_block result', {
      ...boundedAtHeightTwo,
      raw: boundedAtHeightTwo.raw.map((record) => (
        record.block === 1 && record.method === 'submit_block'
          ? { ...record, failure: 'rpc_failed' }
          : record
      )),
    }],
    ['peer propagation', {
      ...boundedAtHeightTwo,
      records: boundedAtHeightTwo.records.map((record, index) => (index === 0 ? {
        ...record,
        propagation: {
          ...record.propagation,
          bTop: { ...record.propagation.bTop, hash: 'cc'.repeat(32) },
        },
      } : record)),
    }],
  ];
  for (const [label, sample] of priorProofForgeries) {
    assert.match(classify(sample).outcome, /^FAILED:/,
      `a height-2 bounded prefix retained a forged height-1 ${label}`);
  }
  assert.ok(src.includes('return outcome === sequenceRefreshSuccessOutcome(blocks, refreshWindows)'),
    'the terminal exit check can drift from the classifier success label');
});
