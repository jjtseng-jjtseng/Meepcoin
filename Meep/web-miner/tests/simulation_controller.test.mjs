// The BROWSER side of the recorded-template simulation, tested without a browser.
//
// The Worker and the WebSocket are injected, so every Worker construction, every posted message and
// every sent frame is counted exactly. No browser, no listener, no Wasm, no server.
//
// The properties under test are the ones a page can get wrong silently: allocating before Start,
// confusing the browser-local Worker token with the server's run generation, creating a Worker for a
// run the user already abandoned, acting on a message that names no attempt at all, and stopping
// without telling the server.
//
// SEVERAL OF THESE REPRODUCE EXACT DEFECTS. A delayed acknowledgement for a cancelled attempt used
// to clear the pending cancellation, build a Worker and submit a candidate on the stale binding; a
// readiness message alone used to build a Worker with no acknowledgement at all; and an unsolicited
// simulation_complete, arriving while nothing was running, was accepted -- it set the completion
// flag and imported whatever counters it carried.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createMiningController, STATES, STOP_REASONS } from '../lib/controller.js';
import { RECORDED_SIMULATION_MODE } from '../lib/shared/protocol.js';

const SIM_LABELS = [
  'RECORDED-TEMPLATE SIMULATION', 'LIVE LOCAL NATIVE HELPER', 'MOCK DAEMON',
  'NO DAEMON OR BLOCKCHAIN CONTACTED', 'NO BLOCK MINED, SUBMITTED, OR ACCEPTED',
];
const ISSUANCE = 'abcdef0123456789abcdef0123456789';
const JOB_ID = 'realjob-1111111111111111';
const WORKER_ID = 'sim-1-aaaa';
const NONCE = 1325931723;
// The protocol hex of NONCE. An earlier revision of this file had '4f0e8b0b' here, which is not the
// hex of 1325931723 at all; the controller forwarded whatever the Worker said, so nothing noticed.
const NONCE_HEX = '4f081ccb';
const EXPECTED_HASH = '0f25c4a8f186c14795b2978948b1fa6b44c6f58ecce4c1a991b4eb5638f31600';

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
    sent: [], closed: 0, url: null,
    onopen: null, onmessage: null, onclose: null, onerror: null,
    send(text) { this.sent.push(JSON.parse(text)); },
    close() { this.closed++; },
    open() { if (this.onopen) this.onopen(); },
    deliver(obj) { if (this.onmessage) this.onmessage({ data: JSON.stringify(obj) }); },
  };
  registry.push(s);
  return s;
}

/** Deterministic 32-hex correlation tokens, one per Start, in the order they were minted. */
function startIdSource() {
  const minted = [];
  const next = () => {
    const id = (minted.length + 1).toString(16).padStart(32, '0');
    minted.push(id);
    return id;
  };
  next.minted = minted;
  return next;
}

/** A controller connected to a simulation-mode server, up to the point of Start. */
function connected({ alreadyCompleted = false } = {}) {
  const workers = [];
  const sockets = [];
  const newStartId = startIdSource();
  const controller = createMiningController({
    createWorker: () => makeFakeWorker(workers),
    createSocket: (url) => { const s = makeFakeSocket(sockets); s.url = url; return s; },
    newStartId,
  });
  controller.connect('ws://127.0.0.1:8171/ws');
  const socket = sockets[0];
  socket.open();
  socket.deliver({
    type: 'server_hello',
    protocolVersion: 1,
    mode: RECORDED_SIMULATION_MODE,
    workerId: WORKER_ID,
    labels: SIM_LABELS,
    actionLabel: 'Run one-hash simulation',
    alreadyCompleted,
    notice: 'recorded-template simulation',
    willAllocate: 'one browser dataset and one server dataset',
  });
  socket.deliver({
    type: 'real_job',
    jobId: JOB_ID,
    issuanceId: ISSUANCE,
    algorithm: 'meephash-w-v2-frozen-real-template',
    height: '2113',
    majorVersion: 16,
    epochKeyHex: 'f'.repeat(64),
    seedHashHex: 'f'.repeat(64),
    hashingTemplateHex: `1010c4e2aad306${'00'.repeat(60)}`,
    targetHexLE: '4f8d976e1283c0caa145b6f3fdd478e9263108ac1c5a643bdf4f8d976e128300',
    nonceStart: NONCE,
    nonceRange: 1,
    expiresAtMs: Date.now() + 600000,
  });
  return { controller, socket, workers, sockets, minted: newStartId.minted };
}

/** The complete binding, as the server repeats it on every run-scoped message. */
function binding(clientStartId, runGeneration = 1, over = {}) {
  return {
    clientStartId,
    workerId: WORKER_ID,
    jobId: JOB_ID,
    issuanceId: ISSUANCE,
    runGeneration,
    ...over,
  };
}

/** Deliver the server's Start acknowledgement. */
function ack(socket, clientStartId, runGeneration = 1, over = {}) {
  socket.deliver({
    type: 'run_started',
    mode: RECORDED_SIMULATION_MODE,
    ...binding(clientStartId, runGeneration, over),
  });
}

function ready(socket, clientStartId, runGeneration = 1, over = {}) {
  socket.deliver({
    type: 'mining_ready',
    mode: RECORDED_SIMULATION_MODE,
    nonceStart: NONCE,
    nonceRange: 1,
    ...binding(clientStartId, runGeneration, over),
  });
}

/** Start, then acknowledge and ready it, returning the correlation token that was minted. */
function startAckReady(controller, socket) {
  controller.start();
  const id = controller.clientStartId;
  ack(socket, id);
  ready(socket, id);
  return id;
}

const stops = (socket) => socket.sent.filter((m) => m.type === 'stop_request');
const candidates = (socket) => socket.sent.filter((m) => m.type === 'submit_real_candidate');

// ================================================================== before Start
test('the page learns simulation mode from the SERVER, and allocates nothing before Start', () => {
  const { controller, workers } = connected();
  const s = controller.snapshot();
  assert.equal(s.mode, RECORDED_SIMULATION_MODE);
  assert.deepEqual(s.simLabels, SIM_LABELS);
  assert.equal(s.simActionLabel, 'Run one-hash simulation');
  assert.equal(s.simHeight, '2113');
  assert.equal(s.simNonce, NONCE);
  // The decisive check: connecting and receiving a job creates NO Worker.
  assert.equal(workers.length, 0, 'a Worker existed before Start');
  assert.equal(controller.workersCreated, 0);
  assert.equal(s.hashes, 0);
});

test('Start sends its correlation token and STILL creates no Worker until acknowledged and ready', () => {
  const { controller, socket, workers, minted } = connected();
  controller.start();
  assert.equal(minted.length, 1, 'Start minted no correlation token');
  assert.deepEqual(socket.sent.at(-1), { type: 'start_request', clientStartId: minted[0] });
  assert.equal(controller.clientStartId, minted[0]);
  assert.equal(workers.length, 0, 'a Worker was created before the server acknowledged');
  assert.equal(controller.snapshot().state, STATES.STARTING);

  ack(socket, minted[0]);
  assert.equal(workers.length, 0, 'the acknowledgement alone created a Worker');
  assert.equal(controller.serverRunGeneration, 1);

  ready(socket, minted[0]);
  assert.equal(workers.length, 1, 'readiness did not create the one Worker');
  // The context init, not the synthetic one, and it names the job the permit will be armed against.
  assert.equal(workers[0].posted[0].cmd, 'init_context');
  assert.equal(workers[0].posted[0].jobId, JOB_ID);
  // The server's exact nonce, passed through unconverted, so the Worker can arm its permit on it.
  assert.equal(workers[0].posted[0].nonce, NONCE);
  assert.equal(workers[0].posted[0].context.height, '2113');
});

test('the local Worker token and the server run generation are distinct', () => {
  const { controller, socket } = connected();
  controller.start();
  const id = controller.clientStartId;
  ack(socket, id, 7);
  ready(socket, id, 7);
  assert.equal(controller.serverRunGeneration, 7, 'the server generation was not adopted');
  assert.notEqual(controller.localWorkerGeneration, 7,
    'the local Worker token and the server generation are the same value');
  // The local token counts abandoned Workers; it changes on stop, and the server one does not.
  const localBefore = controller.localWorkerGeneration;
  controller.stop();
  assert.ok(controller.localWorkerGeneration > localBefore);
  assert.equal(controller.serverRunGeneration, 7);
});

// ================================================================== the one hash
test('ONE browser hash produces exactly one bound submit_real_candidate', () => {
  const { controller, socket, workers } = connected();
  const id = startAckReady(controller, socket);
  const w = workers[0];
  w.emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1234, context: true });

  // Exactly one hash is asked for, and it is the recorded nonce.
  const work = w.posted.filter((m) => m.cmd === 'hash_one');
  assert.equal(work.length, 1, 'more than one hash was requested');
  assert.equal(work[0].nonce, NONCE);
  assert.equal(w.posted.some((m) => m.cmd === 'work'), false, 'a scanning work command was sent');

  w.emit({
    ev: 'hashed_one', gen: controller.localWorkerGeneration,
    jobId: JOB_ID, nonce: NONCE, nonceHex: NONCE_HEX, hashHexLE: EXPECTED_HASH, elapsedMs: 16,
  });

  assert.equal(candidates(socket).length, 1);
  assert.deepEqual(candidates(socket)[0], {
    type: 'submit_real_candidate',
    clientStartId: id,
    jobId: JOB_ID,
    issuanceId: ISSUANCE,
    workerId: WORKER_ID,
    runGeneration: 1,
    nonce: NONCE_HEX,
  });
  // The browser's own hash is NOT sent.
  assert.equal(JSON.stringify(candidates(socket)[0]).includes(EXPECTED_HASH), false,
    'the browser result was sent to the server');
  // It is shown locally, though, so a human can compare it.
  assert.equal(controller.snapshot().simBrowserHashHexLE, EXPECTED_HASH);
  assert.equal(socket.sent.some((m) => m.type === 'submit_share'), false,
    'the synthetic message was used in simulation mode');
});

// ================================================================== stale and unsolicited traffic
test('STALE START RACE: A, stop, B, then A arrives late -- zero stale Worker or submission', () => {
  // THE WITNESS. Start A; stop before A is acknowledged; Start B; then deliver A's delayed
  // run_started and mining_ready. The controller cleared its single pendingCancel flag on the
  // second Start, adopted A's binding as B's, created a Worker and submitted on generation 1.
  const { controller, socket, workers, minted } = connected();
  controller.start();
  const a = minted[0];
  controller.stop(STOP_REASONS.USER);
  assert.equal(controller.pendingCancel, true, 'the pending cancellation was not recorded');

  controller.start();
  const b = minted[1];
  assert.notEqual(a, b, 'the second Start reused the first correlation token');
  assert.equal(controller.pendingCancel, true,
    'clicking Start again cleared an unacknowledged cancellation');

  // A's delayed acknowledgement and readiness now arrive.
  ack(socket, a);
  ready(socket, a);

  assert.equal(workers.length, 0, 'a stale acknowledgement created a Worker');
  assert.equal(controller.workersCreated, 0);
  assert.equal(candidates(socket).length, 0);
  // A is answered on ITS OWN terms: exactly one fully bound stop, naming A.
  assert.equal(stops(socket).length, 1, 'the abandoned attempt did not get exactly one bound stop');
  assert.deepEqual(stops(socket)[0], {
    type: 'stop_request',
    clientStartId: a,
    workerId: WORKER_ID,
    runGeneration: 1,
    jobId: JOB_ID,
    issuanceId: ISSUANCE,
    reason: 'user_stop',
  });
  // B is untouched and still waiting for its own answer.
  assert.equal(controller.clientStartId, b);
  assert.equal(controller.serverRunBinding, null, 'A woke up B');
  assert.equal(controller.snapshot().state, STATES.STARTING);

  // A second late acknowledgement for A earns NO second stop.
  ack(socket, a);
  assert.equal(stops(socket).length, 1, 'a repeated late acknowledgement sent another stop');

  // And B's own acknowledgement still works, so the controller was not wedged.
  ack(socket, b, 2);
  ready(socket, b, 2);
  assert.equal(workers.length, 1);
  assert.equal(controller.serverRunGeneration, 2);
});

test('READINESS WITHOUT AN ACKNOWLEDGEMENT creates zero Workers', () => {
  const { controller, socket, workers, minted } = connected();
  controller.start();
  // mining_ready arrives first, perfectly well formed, for the attempt actually outstanding.
  ready(socket, minted[0]);
  assert.equal(workers.length, 0, 'readiness alone created a Worker');
  assert.equal(controller.workersCreated, 0);
  assert.equal(controller.serverRunBinding, null);
  // The acknowledgement then arrives and a REPEAT readiness is needed; one ordering, one Worker.
  ack(socket, minted[0]);
  assert.equal(workers.length, 0);
  ready(socket, minted[0]);
  assert.equal(workers.length, 1);
});

test('a WRONG BINDING at the acknowledgement or the readiness creates zero Workers', () => {
  // The acknowledgement MINTS the run generation, so that one field cannot be wrong at this point;
  // everything else it names was already stated by server_hello and real_job.
  const wrongAtAck = [
    ['wrong start correlation', { clientStartId: 'f'.repeat(32) }],
    ['wrong worker', { workerId: 'sim-someone-else' }],
    ['wrong job', { jobId: 'realjob-elsewhere' }],
    ['wrong issuance', { issuanceId: '0'.repeat(32) }],
    ['malformed correlation', { clientStartId: 'abcd' }],
    ['missing correlation', { clientStartId: undefined }],
    ['unsafe generation', { runGeneration: Number.MAX_SAFE_INTEGER + 1 }],
    ['negative generation', { runGeneration: -1 }],
  ];
  const wrongAtReady = [...wrongAtAck, ['wrong generation', { runGeneration: 9 }]];

  // (a) a wrong binding on the ACKNOWLEDGEMENT is not adopted at all.
  for (const [name, over] of wrongAtAck) {
    const { controller, socket, workers, minted } = connected();
    controller.start();
    ack(socket, minted[0], 1, over);
    assert.equal(controller.serverRunBinding, null, `${name}: a wrong acknowledgement was adopted`);
    ready(socket, minted[0]);
    assert.equal(workers.length, 0, `${name}: a Worker was created`);
  }

  // (b) a correct acknowledgement followed by a wrong READINESS also creates nothing.
  for (const [name, over] of wrongAtReady) {
    const { controller, socket, workers, minted } = connected();
    controller.start();
    ack(socket, minted[0]);
    assert.ok(controller.serverRunBinding, name);
    ready(socket, minted[0], 1, over);
    assert.equal(workers.length, 0, `${name}: a mismatched readiness created a Worker`);
    assert.equal(controller.workersCreated, 0, name);
  }
});

test('an UNSOLICITED terminal or status message changes nothing at all', () => {
  // THE WITNESS: an unsolicited simulation_complete naming an unrelated job, delivered while idle,
  // was accepted -- it set simComplete, imported the attacker's counters and changed the state.
  const { controller, socket, workers } = connected();
  const before = controller.snapshot();

  const forged = {
    counters: { serverWasmHashes: 999, nativeHelperHashes: 999, realTransportCalls: 42 },
    recordedVector: { height: '1', nonce: 1, expectedHashHexLE: 'a'.repeat(64) },
  };
  const unsolicited = [
    { type: 'simulation_complete', jobId: 'realjob-attacker', ...forged },
    { type: 'simulation_complete', ...binding('f'.repeat(32)), ...forged },
    { type: 'simulation_failed', ...binding('f'.repeat(32)), reason: 'forged' },
    { type: 'mock_verification_complete', ...binding('f'.repeat(32)), hashHexLE: 'b'.repeat(64) },
    { type: 'mock_submit_path_exercised', ...binding('f'.repeat(32)) },
    { type: 'candidate_rejected', ...binding('f'.repeat(32)), reason: 'forged' },
    { type: 'simulation_stopped', ...binding('f'.repeat(32)), accepted: true },
    { type: 'simulation_unavailable', ...binding('f'.repeat(32)), reason: 'forged' },
  ];
  for (const msg of unsolicited) socket.deliver(msg);

  const after = controller.snapshot();
  assert.equal(after.simComplete, before.simComplete, 'an unsolicited message set the completion flag');
  assert.equal(after.simCounters, before.simCounters, 'forged counters were imported');
  assert.equal(after.simExpectedHashHexLE, before.simExpectedHashHexLE);
  assert.equal(after.simVerifiedHashHexLE, before.simVerifiedHashHexLE);
  assert.equal(after.simMockSubmitExercised, before.simMockSubmitExercised);
  assert.equal(after.rejected, before.rejected);
  assert.equal(after.state, before.state, 'an unsolicited message changed the state');
  assert.equal(after.error, before.error);
  assert.equal(workers.length, 0);
  assert.equal(controller.simTerminal, false);

  // And the same messages arriving MID-RUN, bound to another attempt, are equally inert.
  const id = startAckReady(controller, socket);
  workers[0].emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1 });
  const midRun = controller.snapshot();
  for (const msg of unsolicited) socket.deliver(msg);
  assert.equal(controller.snapshot().simComplete, midRun.simComplete);
  assert.equal(controller.snapshot().state, STATES.MINING, 'a forged message stopped a live run');
  assert.equal(workers[0].terminated, 0);
  // The genuine one, for THIS attempt, does work.
  socket.deliver({
    type: 'simulation_complete',
    ...binding(id),
    counters: { serverWasmHashes: 1, realTransportCalls: 0 },
    recordedVector: { height: '2113', nonce: NONCE, expectedHashHexLE: EXPECTED_HASH },
  });
  assert.equal(controller.snapshot().simComplete, true);
  assert.equal(controller.snapshot().simCounters.serverWasmHashes, 1);
});

test('candidate_rejected is NOT terminal by itself: terminality comes only from an explicit message', () => {
  const { controller, socket, workers } = connected();
  const id = startAckReady(controller, socket);
  workers[0].emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1 });

  // A cheap refusal of a forged or mismatched candidate. The real attempt is still live on the
  // server, so the page must not end it either.
  socket.deliver({ type: 'candidate_rejected', ...binding(id), terminal: false, reason: 'unknown_worker' });
  let s = controller.snapshot();
  assert.equal(s.rejected, 1);
  assert.equal(s.state, STATES.MINING, 'a nonterminal rejection ended the run');
  assert.equal(workers[0].terminated, 0);
  assert.equal(controller.simTerminal, false);
  assert.equal(s.simFinished, false);
  assert.equal(s.simProcessSpent, false);

  // The explicit terminal ends it.
  socket.deliver({ type: 'simulation_failed', ...binding(id), terminal: true, reason: 'daemon_unavailable' });
  s = controller.snapshot();
  assert.equal(workers[0].terminated, 1);
  assert.equal(controller.simTerminal, true);
  assert.equal(s.simFinished, true);

  // COUNTERS FREEZE after the terminal.
  socket.deliver({ type: 'candidate_rejected', ...binding(id), terminal: false, reason: 'duplicate_nonce' });
  assert.equal(controller.snapshot().rejected, 1, 'counters kept moving after the terminal');
});

test('a GENUINE simulation_failed is finished, NOT succeeded, and never looks like success', () => {
  // THE WITNESS: a genuine bound simulation_failed left state=stopped, stopReason=error,
  // error=null and simComplete=true -- and the page rendered "Simulation complete".
  const { controller, socket, workers } = connected();
  const id = startAckReady(controller, socket);
  workers[0].emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1 });

  socket.deliver({ type: 'simulation_failed', ...binding(id), terminal: true, reason: 'fatal_verifier' });

  const s = controller.snapshot();
  assert.equal(s.simComplete, false, 'a failure set the success flag');
  assert.equal(s.simFinished, true);
  assert.equal(s.simProcessSpent, true);
  assert.equal(s.simFailureCode, 'fatal_verifier');
  assert.equal(s.state, STATES.ERROR);
  assert.equal(s.stopReason, STOP_REASONS.ERROR);
  assert.notEqual(s.error, null, 'a failure left the error empty');
  assert.match(s.error, /fatal_verifier/);
  assert.equal(workers[0].terminated, 1);
});

test('an UNRECOGNISED failure reason is recorded as a closed code, not copied', () => {
  const { controller, socket } = connected();
  const id = startAckReady(controller, socket);
  const hostile = '<img src=x onerror=alert(1)> /home/someone/secret';
  socket.deliver({ type: 'simulation_failed', ...binding(id), terminal: true, reason: hostile });
  const s = controller.snapshot();
  assert.equal(s.simFailureCode, 'unrecognised_failure');
  assert.equal(JSON.stringify(s).includes('secret'), false, 'server text reached page state');
  assert.equal(s.simComplete, false);
});

test('a STALE OR FORGED readiness changes no telemetry', () => {
  // THE WITNESS: mining_ready copied its heap, native and verifier figures BEFORE checking the
  // binding, so a stale or forged one overwrote them.
  const { controller, socket, minted } = connected();
  controller.start();
  ack(socket, minted[0]);
  const before = controller.snapshot();
  for (const over of [
    { clientStartId: 'f'.repeat(32) },
    { runGeneration: 9 },
    { workerId: 'sim-someone-else' },
  ]) {
    socket.deliver({
      type: 'mining_ready',
      mode: RECORDED_SIMULATION_MODE,
      ...binding(minted[0], 1, over),
      verifierWasmHeapBytes: 999_999_999,
      verifierNativeAlgorithmBytes: 888_888_888,
      verifierMode: 'forged',
    });
  }
  const after = controller.snapshot();
  assert.equal(after.serverVerifierHeapBytes, before.serverVerifierHeapBytes);
  assert.equal(after.serverNativeAlgorithmBytes, before.serverNativeAlgorithmBytes);
  assert.equal(after.serverVerifierMode, before.serverVerifierMode);
  assert.equal(after.state, before.state);
});

// ================================================================== stopping
test('STOP BEFORE THE ACKNOWLEDGEMENT sends one bound stop and creates no Worker', () => {
  const { controller, socket, workers, minted } = connected();
  controller.start();
  // The user stops while the server is still preparing. There is no binding to stop yet.
  controller.stop(STOP_REASONS.USER);
  assert.equal(controller.pendingCancel, true, 'the pending cancellation was not recorded');
  assert.equal(socket.sent.some((m) => m.type === 'stop_request'), false, 'an unbound stop was sent');

  // The acknowledgement arrives late.
  ack(socket, minted[0]);
  assert.equal(stops(socket).length, 1, 'the late acknowledgement did not produce exactly one bound stop');
  assert.deepEqual(stops(socket)[0], {
    type: 'stop_request',
    clientStartId: minted[0],
    workerId: WORKER_ID,
    runGeneration: 1,
    jobId: JOB_ID,
    issuanceId: ISSUANCE,
    reason: 'user_stop',
  });

  // And a late readiness must NOT create a Worker.
  ready(socket, minted[0]);
  assert.equal(workers.length, 0, 'a late readiness created a Worker for an abandoned run');
  assert.equal(controller.workersCreated, 0);
});

test('Stop after ready terminates the Worker AND tells the server', () => {
  const { controller, socket, workers } = connected();
  const id = startAckReady(controller, socket);
  workers[0].emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1 });

  controller.stop(STOP_REASONS.USER);
  assert.equal(workers[0].terminated, 1, 'the Worker was not terminated');
  assert.equal(stops(socket).length, 1);
  assert.equal(stops(socket)[0].issuanceId, ISSUANCE);
  assert.equal(stops(socket)[0].runGeneration, 1);
  assert.equal(stops(socket)[0].clientStartId, id);
});

test('a hidden tab and a pagehide each send a correctly mapped bound stop', () => {
  for (const [act, wire] of [['hidden', 'page_hidden'], ['pagehide', 'page_unload']]) {
    const { controller, socket, workers } = connected();
    startAckReady(controller, socket);
    workers[0].emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1 });

    if (act === 'hidden') controller.setHidden(true); else controller.teardown();

    assert.equal(stops(socket).length, 1, act);
    assert.equal(stops(socket)[0].reason, wire, `${act} mapped to the wrong wire reason`);
    assert.equal(workers[0].terminated, 1, act);
  }
});

test('becoming visible again does NOT resume', () => {
  const { controller, socket, workers } = connected();
  startAckReady(controller, socket);
  workers[0].emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1 });
  controller.setHidden(true);
  const workersAfterHide = workers.length;

  controller.setHidden(false);
  assert.equal(workers.length, workersAfterHide, 'becoming visible created a Worker');
  assert.equal(controller.snapshot().state, STATES.STOPPED_HIDDEN);
  // And no second start_request was sent by itself.
  assert.equal(socket.sent.filter((m) => m.type === 'start_request').length, 1);
});

test('a duplicate acknowledgement for a FINISHED run cannot drive a new one', () => {
  const { controller, socket, workers } = connected();
  const id = startAckReady(controller, socket);
  workers[0].emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1 });
  controller.stop();

  const before = workers.length;
  ack(socket, id);
  ready(socket, id);
  assert.equal(workers.length, before, 'a stale acknowledgement created a Worker');
});

test('no stop is sent once the attempt has already reached a terminal', () => {
  const { controller, socket, workers } = connected();
  const id = startAckReady(controller, socket);
  workers[0].emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1 });
  socket.deliver({
    type: 'simulation_complete',
    ...binding(id),
    counters: { serverWasmHashes: 1, realTransportCalls: 0 },
    recordedVector: { height: '2113', nonce: NONCE, expectedHashHexLE: EXPECTED_HASH },
  });
  assert.equal(controller.simTerminal, true);
  const after = stops(socket).length;
  // The user presses Stop, hides the tab and leaves the page, all after the run is over. The server
  // has already published its outcome; asking it to revoke something finished is noise.
  controller.stop(STOP_REASONS.USER);
  controller.setHidden(true);
  controller.teardown();
  assert.equal(stops(socket).length, after, 'a stop was sent after the terminal outcome');
});

test('the terminal simulation_complete is recorded and stops the run', () => {
  const { controller, socket, workers } = connected();
  const id = startAckReady(controller, socket);
  workers[0].emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1 });

  socket.deliver({ type: 'mock_verification_complete', ...binding(id), nonce: NONCE, hashHexLE: EXPECTED_HASH });
  socket.deliver({ type: 'mock_submit_path_exercised', ...binding(id), nonce: NONCE });
  socket.deliver({
    type: 'simulation_complete',
    ...binding(id),
    counters: {
      serverWasmHashes: 1, nativeHelperHashes: 1, mockCalcPow: 1,
      mockDispatchSubmission: 1, mockReadback: 1, realTransportCalls: 0,
    },
    recordedVector: { height: '2113', nonce: NONCE, expectedHashHexLE: EXPECTED_HASH },
  });

  const s = controller.snapshot();
  assert.equal(s.simComplete, true);
  assert.equal(s.simVerifiedHashHexLE, EXPECTED_HASH);
  assert.equal(s.simExpectedHashHexLE, EXPECTED_HASH);
  assert.equal(s.simMockSubmitExercised, true);
  assert.equal(s.simCounters.realTransportCalls, 0);
  assert.equal(workers[0].terminated, 1, 'the Worker kept running after the terminal event');
});

/** A pre-run refusal in its own closed schema. */
function preRunRefusal(clientStartId, over = {}) {
  return {
    type: 'simulation_unavailable',
    terminal: true,
    reason: 'simulation_attempt_in_progress',
    clientStartId,
    workerId: WORKER_ID,
    jobId: JOB_ID,
    issuanceId: ISSUANCE,
    runGeneration: null,
    attemptState: 'running',
    ...over,
  };
}

test('a PRE-RUN refusal has its own closed schema, and imports no server text', () => {
  const { controller, socket, minted, workers } = connected();
  controller.start();
  socket.deliver(preRunRefusal(minted[0], {
    detail: '<script>alert(1)</script> this text must never reach the page',
  }));
  const s = controller.snapshot();
  assert.equal(s.state, STATES.ERROR);
  assert.equal(controller.runIntent, false);
  assert.match(s.error, /another connection is running/);
  assert.equal(JSON.stringify(s).includes('script'), false, 'server detail was imported into page state');
  assert.equal(s.simAttemptState, 'running');
  // A late acknowledgement afterwards still creates nothing.
  ack(socket, minted[0]);
  ready(socket, minted[0]);
  assert.equal(workers.length, 0);
});

test('a pre-run refusal that does not fit its schema changes nothing', () => {
  const malformed = [
    ['live run generation', { runGeneration: 1 }],
    ['non-null generation 0', { runGeneration: 0 }],
    ['missing generation', { runGeneration: undefined }],
    ['wrong worker', { workerId: 'sim-someone-else' }],
    ['wrong job', { jobId: 'realjob-elsewhere' }],
    ['wrong issuance', { issuanceId: '0'.repeat(32) }],
    ['wrong correlation', { clientStartId: 'f'.repeat(32) }],
    ['unknown reason', { reason: 'please_reload_from_evil_example' }],
    ['unknown attempt state', { attemptState: 'hacked' }],
  ];
  for (const [name, over] of malformed) {
    const { controller, socket, minted } = connected();
    controller.start();
    const before = controller.snapshot();
    const msg = preRunRefusal(minted[0], over);
    for (const [k, v] of Object.entries(over)) if (v === undefined) delete msg[k];
    socket.deliver(msg);
    const after = controller.snapshot();
    assert.equal(after.state, before.state, `${name}: state changed`);
    assert.equal(after.error, before.error, `${name}: error changed`);
    assert.equal(after.simProcessSpent, false, `${name}: page disabled`);
    assert.equal(controller.runIntent, true, `${name}: the pending start was cancelled`);
  }
});

test('Start is permanently disabled only when the SERVER PROCESS is spent', () => {
  // Another session holds a still-live attempt: NOT spent; this page may try again later.
  const busy = connected();
  busy.controller.start();
  busy.socket.deliver(preRunRefusal(busy.minted[0]));
  assert.equal(busy.controller.snapshot().simProcessSpent, false,
    'a live attempt elsewhere permanently disabled this page');

  // The process has already used its one attempt: spent.
  const used = connected();
  used.controller.start();
  used.socket.deliver(preRunRefusal(used.minted[0], {
    reason: 'simulation_already_completed', attemptState: 'terminal_complete',
  }));
  assert.equal(used.controller.snapshot().simProcessSpent, true);

  // This page's own attempt completed, failed, or was accepted-stopped: spent in every case.
  for (const [name, terminal] of [
    ['completed', (id) => ({ type: 'simulation_complete', ...binding(id), terminal: true, counters: {}, recordedVector: {} })],
    ['failed', (id) => ({ type: 'simulation_failed', ...binding(id), terminal: true, reason: 'fatal_verifier' })],
    ['stopped', (id) => ({ type: 'simulation_stopped', ...binding(id), terminal: true, accepted: true, reason: 'user_stop' })],
  ]) {
    const { controller, socket } = connected();
    const id = startAckReady(controller, socket);
    socket.deliver(terminal(id));
    assert.equal(controller.snapshot().simProcessSpent, true, name);
    assert.equal(controller.snapshot().simFinished, true, name);
    assert.equal(controller.snapshot().simComplete, name === 'completed', name);
  }

  // An already-spent server says so in its hello.
  const hello = connected({ alreadyCompleted: true });
  assert.equal(hello.controller.snapshot().simProcessSpent, true);
});

test('the server answering an ABANDONED attempt\'s stop marks the process spent', () => {
  const { controller, socket, minted } = connected();
  controller.start();
  controller.stop(STOP_REASONS.USER);       // before the acknowledgement
  ack(socket, minted[0]);                   // the late ack earns one bound stop
  assert.equal(stops(socket).length, 1);
  socket.deliver({
    type: 'simulation_stopped', ...binding(minted[0]), terminal: true, accepted: true, reason: 'user_stop',
  });
  assert.equal(controller.snapshot().simProcessSpent, true,
    'the server cancelled the one attempt and the page did not learn it was spent');
});

test('an already-completed server is reported before Start', () => {
  const { controller, workers } = connected({ alreadyCompleted: true });
  assert.equal(controller.snapshot().simAlreadyCompleted, true);
  assert.equal(workers.length, 0);
});

test('a Worker that refuses a hash command is recorded, not retried', () => {
  const { controller, socket, workers } = connected();
  startAckReady(controller, socket);
  const w = workers[0];
  w.emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1 });
  const asked = w.posted.filter((m) => m.cmd === 'hash_one').length;

  w.emit({ ev: 'command_refused', gen: controller.localWorkerGeneration, cmd: 'hash_one', reason: 'already_hashed' });
  assert.equal(controller.snapshot().lastRejectReason, 'worker_already_hashed');
  assert.equal(w.posted.filter((m) => m.cmd === 'hash_one').length, asked,
    'the page retried a hash the Worker had refused');
  assert.equal(candidates(socket).length, 0);
});

// ================================================================== A3: one-shot in code, browser truth
/** Start, ack, ready, Worker ready: the one Worker is now waiting to report its hash. */
function readyToHash(controller, socket, workers) {
  const id = startAckReady(controller, socket);
  workers[0].emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1, context: true });
  return id;
}

function completeFor(socket, id, { verified = EXPECTED_HASH, expected = EXPECTED_HASH } = {}) {
  socket.deliver({ type: 'mock_verification_complete', ...binding(id), nonce: NONCE, hashHexLE: verified });
  socket.deliver({
    type: 'simulation_complete',
    ...binding(id),
    terminal: true,
    counters: { serverWasmHashes: 1, nativeHelperHashes: 1, realTransportCalls: 0 },
    recordedVector: { height: '2113', nonce: NONCE, expectedHashHexLE: expected },
  });
}

test('A PROGRAMMATIC second start() after the process is spent changes nothing at all', () => {
  const { controller, socket, workers, minted } = connected();
  const id = readyToHash(controller, socket, workers);
  completeFor(socket, id);
  assert.equal(controller.snapshot().simProcessSpent, true);

  const before = {
    generation: controller.localWorkerGeneration,
    state: controller.snapshot().state,
    sent: socket.sent.length,
    workers: workers.length,
    minted: minted.length,
    runIntent: controller.runIntent,
  };
  // The button is disabled -- this bypasses it and calls the controller directly.
  assert.equal(controller.start(), false, 'a spent process accepted a second start()');
  assert.equal(controller.localWorkerGeneration, before.generation, 'the generation moved');
  assert.equal(controller.snapshot().state, before.state, 'the state moved');
  assert.equal(socket.sent.length, before.sent, 'a message was sent');
  assert.equal(workers.length, before.workers, 'a Worker was created');
  assert.equal(minted.length, before.minted, 'a correlation token was minted');
  assert.equal(controller.runIntent, before.runIntent);

  // The same holds for a server that says in its hello that it is already spent.
  const spent = connected({ alreadyCompleted: true });
  assert.equal(spent.controller.start(), false);
  assert.equal(spent.socket.sent.filter((m) => m.type === 'start_request').length, 0);
  assert.equal(spent.minted.length, 0);
});

test('a Worker reporting the WRONG JOB, WRONG NONCE or a MALFORMED hash is not browser evidence', () => {
  const cases = [
    ['wrong job', { jobId: 'realjob-someone-else' }],
    ['wrong nonce', { nonce: NONCE + 1, nonceHex: (NONCE + 1).toString(16).padStart(8, '0') }],
    ['nonce/hex disagree', { nonceHex: '00000000' }],
    ['malformed hash: short', { hashHexLE: 'abcd' }],
    ['malformed hash: uppercase', { hashHexLE: EXPECTED_HASH.toUpperCase() }],
    ['malformed hash: missing', { hashHexLE: undefined }],
  ];
  for (const [name, over] of cases) {
    const { controller, socket, workers } = connected();
    const id = readyToHash(controller, socket, workers);
    workers[0].emit({
      ev: 'hashed_one', gen: controller.localWorkerGeneration,
      jobId: JOB_ID, nonce: NONCE, nonceHex: NONCE_HEX, hashHexLE: EXPECTED_HASH, elapsedMs: 5,
      ...over,
    });
    const s = controller.snapshot();
    assert.equal(candidates(socket).length, 0, `${name}: a candidate was sent on invalid evidence`);
    assert.equal(s.simBrowserHashHexLE, null, `${name}: the invalid hash was recorded`);
    assert.equal(s.simBrowserEvidence, 'invalid', name);
    assert.equal(s.hashes, 0, `${name}: the browser was credited with a hash`);
    assert.equal(workers[0].terminated, 1, `${name}: the Worker kept running`);
    // Even a later server completion cannot turn this into a browser match.
    completeFor(socket, id);
    assert.equal(controller.snapshot().simBrowserMatched, false, `${name}: claimed a browser match`);
  }
});

test('a WELL-FORMED but WRONG browser hash never yields the browser-matched claim', () => {
  const { controller, socket, workers } = connected();
  const id = readyToHash(controller, socket, workers);
  const wrong = 'b'.repeat(64);
  workers[0].emit({
    ev: 'hashed_one', gen: controller.localWorkerGeneration,
    jobId: JOB_ID, nonce: NONCE, nonceHex: NONCE_HEX, hashHexLE: wrong, elapsedMs: 5,
  });
  // The candidate still goes to the server -- the server is independent of the browser hash -- and it
  // names the AUTHORIZED nonce, never a Worker field.
  assert.equal(candidates(socket).length, 1);
  assert.equal(candidates(socket)[0].nonce, NONCE_HEX);
  assert.equal(JSON.stringify(candidates(socket)[0]).includes(wrong), false, 'the browser hash was sent');
  completeFor(socket, id);
  const s = controller.snapshot();
  assert.equal(s.simComplete, true, 'the server-side completion is still recorded');
  assert.equal(s.simBrowserMatched, false, 'a wrong browser hash was reported as a match');
  assert.equal(s.simBrowserHashHexLE, wrong);
});

test('the browser-matched claim holds ONLY when browser, server and recorded hashes all agree', () => {
  const { controller, socket, workers } = connected();
  const id = readyToHash(controller, socket, workers);
  workers[0].emit({
    ev: 'hashed_one', gen: controller.localWorkerGeneration,
    jobId: JOB_ID, nonce: NONCE, nonceHex: NONCE_HEX, hashHexLE: EXPECTED_HASH, elapsedMs: 5,
  });
  completeFor(socket, id);
  assert.equal(controller.snapshot().simBrowserMatched, true);

  // Browser right, but the server's recomputation disagreeing with the recorded value: no match.
  const b = connected();
  const id2 = readyToHash(b.controller, b.socket, b.workers);
  b.workers[0].emit({
    ev: 'hashed_one', gen: b.controller.localWorkerGeneration,
    jobId: JOB_ID, nonce: NONCE, nonceHex: NONCE_HEX, hashHexLE: EXPECTED_HASH, elapsedMs: 5,
  });
  completeFor(b.socket, id2, { verified: 'c'.repeat(64) });
  assert.equal(b.controller.snapshot().simBrowserMatched, false);
});

test('TWO VALID-SHAPED Worker reports send ONE candidate, and the duplicate ends the run', () => {
  // THE WITNESS (Regression testing): the same otherwise-valid hashed_one emitted twice before completion produced
  // two submit_real_candidate frames while the page's counter still said one hash.
  const { controller, socket, workers } = connected();
  const id = readyToHash(controller, socket, workers);
  const report = {
    ev: 'hashed_one', gen: controller.localWorkerGeneration,
    jobId: JOB_ID, nonce: NONCE, nonceHex: NONCE_HEX, hashHexLE: EXPECTED_HASH, elapsedMs: 5,
  };
  workers[0].emit(report);
  assert.equal(candidates(socket).length, 1);
  assert.equal(controller.snapshot().hashes, 1);
  assert.equal(controller.snapshot().simBrowserEvidence, 'reported');

  workers[0].emit({ ...report });
  const s = controller.snapshot();
  assert.equal(candidates(socket).length, 1, 'a duplicate report sent a second candidate');
  assert.equal(s.hashes, 1, 'the browser hash count moved past one');
  // The duplicate cannot continue the run normally: error stop, Worker gone, bound stop sent.
  assert.equal(s.simBrowserEvidence, 'invalid');
  assert.equal(s.stopReason, STOP_REASONS.ERROR);
  assert.equal(controller.runIntent, false);
  assert.equal(workers[0].terminated, 1);
  assert.equal(stops(socket).length, 1);
  assert.equal(stops(socket)[0].clientStartId, id);

  // A third report, and a later server completion, change nothing and never claim browser agreement.
  workers[0].emit({ ...report });
  assert.equal(candidates(socket).length, 1);
  assert.equal(controller.snapshot().hashes, 1);
  completeFor(socket, id);
  assert.equal(controller.snapshot().simBrowserMatched, false);
});

// ================================================================== the default path
test('the default synthetic mode sends no simulation fields and still drives the scan', () => {
  const workers = [];
  const sockets = [];
  const controller = createMiningController({
    createWorker: () => makeFakeWorker(workers),
    createSocket: () => makeFakeSocket(sockets),
    newStartId: startIdSource(),
  });
  controller.connect('ws://127.0.0.1:8171/ws');
  const socket = sockets[0];
  socket.open();
  // A synthetic server_hello carries no mode field at all.
  socket.deliver({ type: 'server_hello', protocolVersion: 1, workerId: 'w-1' });
  assert.equal(controller.mode, 'synthetic');
  socket.deliver({
    type: 'job', jobId: 'devjob-1', generation: 1, algorithm: 'meephash-w-v2-frozen-synthetic',
    targetHexLE: 'f'.repeat(64), nonceStart: 0, nonceRange: 16, batchHint: 4,
    expiresAtMs: Date.now() + 60000,
  });
  controller.start();
  // NO correlation token on the synthetic wire.
  assert.deepEqual(socket.sent.at(-1), { type: 'start_request' });
  assert.equal(controller.clientStartId, null);
  socket.deliver({ type: 'mining_ready', workerId: 'w-1' });
  assert.equal(workers.length, 1);
  // The SYNTHETIC init and the scanning work command, not the contextual ones.
  assert.equal(workers[0].posted[0].cmd, 'init');
  workers[0].emit({ ev: 'ready', gen: controller.localWorkerGeneration, wasmHeapBytes: 1 });
  assert.equal(workers[0].posted.some((m) => m.cmd === 'work'), true);
  assert.equal(workers[0].posted.some((m) => m.cmd === 'hash_one'), false);
  // And a synthetic stop sends no stop_request.
  controller.stop();
  assert.equal(socket.sent.some((m) => m.type === 'stop_request'), false,
    'the synthetic path started sending stop_request');
});
