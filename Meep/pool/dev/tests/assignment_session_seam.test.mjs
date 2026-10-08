// Non-live tests for the narrow delayed-assignment handoff into createSimulationSession.
// No listener, daemon process, browser, helper, Wasm module, filesystem write, network or hash.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  SIM_ATTEMPT_STATES,
  createSimulationContext,
  createSimulationSession,
} from '../sim_session.mjs';
import { createFatalLatch, createTemplateAuthority } from '../run_guard.mjs';
import { createRealTemplateJob } from '../real_template.mjs';

const START_ID = '01'.repeat(16);
const WORKER_ID = 'sim-700-1234abcd';

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTOR = JSON.parse(readFileSync(
  resolve(HERE, '../../../meepow/vectors/block_vectors_v16_devnet.json'),
  'utf8',
)).vectors[0];
const JOB = createRealTemplateJob({
  height: VECTOR.height,
  seedHashHex: VECTOR.epoch_key,
  wideDifficulty: String(VECTOR.difficulty),
  blockhashingBlobHex: VECTOR.block_hashing_blob,
  blocktemplateBlobHex: VECTOR.full_block_blob,
  nonceStart: 0,
  nonceRange: 1,
}, {
  now: () => 1_000,
  mintIssuanceId: () => 'a'.repeat(32),
});

function verifier() {
  return {
    closed: false,
    datasetBytes: 32,
    scratchBytes: 16,
    wasmHeapBytes: () => 64,
    nativeAlgorithmBytes: () => 48,
    beginClose() {},
    async close() { this.closed = true; },
    async forceClose() { this.closed = true; },
  };
}

function makeHarness({ session = {}, onTerminal } = {}) {
  const latch = createFatalLatch();
  const authority = createTemplateAuthority({ now: () => 1_000 });
  authority.publish(JOB);
  const mockDaemon = {
    counters: {
      calcPow: 0,
      prepareSubmission: 0,
      dispatchSubmission: 0,
      readback: 0,
      inMemoryTransportCalls: 0,
      transportCalls: 0,
    },
    async submitBlock() { throw new Error('not reached'); },
  };
  const sim = createSimulationContext({
    job: JOB,
    latch,
    authority,
    mockDaemon,
    makeServerVerifier: async () => verifier(),
    expectedHashHexLE: null,
    recordedContext: Object.freeze({ marker: 'assigned-context' }),
    assignmentScopedTeardown: true,
    now: () => 1_000,
  });
  const sent = [];
  const audits = [];
  const api = createSimulationSession({
    sim,
    send: (message) => sent.push(message),
    onAudit: (entry) => audits.push(entry),
    onTerminal,
    now: () => 1_000,
    setTimer: () => Object.freeze({}),
    clearTimer: () => {},
    ...session,
  });
  const say = (message) => {
    const text = JSON.stringify(message);
    return api.handleRaw(Buffer.byteLength(text), text);
  };
  return {
    sim,
    api,
    sent,
    audits,
    say,
    all: (type) => sent.filter((message) => message.type === type),
    last: (type) => [...sent].reverse().find((message) => message.type === type),
  };
}

async function closeHarness(harness) {
  harness.api.dispose();
  await harness.sim.closeAssignmentResources('test cleanup');
}

test('legacy session still requires hello and mints its own connection identity', async () => {
  const h = makeHarness();
  try {
    const beforeHello = await h.say({ type: 'start_request', clientStartId: START_ID });
    assert.deepEqual(beforeHello, { ok: false, reason: 'not_authorized' });
    assert.equal(h.api.authorized, false);
    assert.equal(h.api.workerId, null);

    const hello = await h.say({ type: 'client_hello', protocolVersion: 1 });
    assert.equal(hello.ok, true);
    assert.match(h.api.workerId, /^sim-[0-9]{1,9}-[0-9a-f]{8}$/);
    assert.equal(h.all('server_hello').length, 1);
    assert.equal(h.last('server_hello').workerId, h.api.workerId);
  } finally {
    await closeHarness(h);
  }
});

test('preauthorized handoff preserves exact owner and worker without a second hello', async () => {
  const owner = Object.freeze({ assignment: 'A' });
  const h = makeHarness({ session: { sessionOwner: owner, preauthorizedWorkerId: WORKER_ID } });
  try {
    assert.equal(h.api.authorized, true);
    assert.equal(h.api.ownerToken, owner);
    assert.equal(h.api.workerId, WORKER_ID);
    assert.equal(h.all('server_hello').length, 0);

    const started = await h.say({ type: 'start_request', clientStartId: START_ID });
    assert.equal(started.ok, true, JSON.stringify({ started, sent: h.sent, audits: h.audits }));
    assert.equal(h.all('server_hello').length, 0, 'the handed-off session minted a second hello');
    assert.equal(h.all('run_started').length, 1);
    assert.equal(h.all('mining_ready').length, 1);
    assert.equal(h.last('run_started').workerId, WORKER_ID);
    assert.equal(h.last('run_started').clientStartId, START_ID);
    assert.equal(h.last('mining_ready').workerId, WORKER_ID);
    assert.equal(h.api.ownerToken, owner);
  } finally {
    await closeHarness(h);
  }
});

test('assignment revocation is synchronous, terminal and exactly once', async () => {
  const notices = [];
  const h = makeHarness({
    session: { sessionOwner: Object.freeze({}), preauthorizedWorkerId: WORKER_ID },
    onTerminal: (notice) => { notices.push(notice); },
  });
  try {
    await h.say({ type: 'start_request', clientStartId: START_ID });
    assert.equal(h.api.revokeAssignment('submission_already_claimed'), true);
    assert.equal(h.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
    assert.equal(h.sim.attemptReason, 'submission_already_claimed');
    assert.equal(h.api.intent.active, false);
    assert.equal(h.all('simulation_failed').length, 1);
    assert.equal(h.last('simulation_failed').reason, 'submission_already_claimed');
    assert.equal(h.last('simulation_failed').terminal, true);
    assert.equal(h.api.revokeAssignment('submission_already_claimed'), false);
    assert.equal(h.all('simulation_failed').length, 1);
    assert.equal(notices.length, 1);
    assert.equal(notices[0].owner, h.api.ownerToken);
    assert.equal(notices[0].clientStartId, START_ID);
    assert.equal(notices[0].state, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  } finally {
    await closeHarness(h);
  }
});

test('terminal callback exceptions and promise rejections cannot change the terminal result', async () => {
  for (const onTerminal of [
    () => { throw new Error('synchronous diagnostic failure'); },
    () => Promise.reject(new Error('asynchronous diagnostic failure')),
  ]) {
    const h = makeHarness({
      session: { sessionOwner: Object.freeze({}), preauthorizedWorkerId: WORKER_ID },
      onTerminal,
    });
    try {
      await h.say({ type: 'start_request', clientStartId: START_ID });
      assert.equal(h.api.revokeAssignment(), true);
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(h.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
      assert.equal(h.all('simulation_failed').length, 1);
    } finally {
      await closeHarness(h);
    }
  }
});

test('invalid handoff identities fail before a session is created', () => {
  const h = makeHarness();
  h.api.dispose();
  assert.throws(() => createSimulationSession({
    sim: h.sim,
    send() {},
    sessionOwner: 'not-an-identity',
  }), /sessionOwner/);
  assert.throws(() => createSimulationSession({
    sim: h.sim,
    send() {},
    preauthorizedWorkerId: WORKER_ID,
  }), /requires its exact session owner/);
  assert.throws(() => createSimulationSession({
    sim: h.sim,
    send() {},
    sessionOwner: {},
    preauthorizedWorkerId: 'worker A',
  }), /preauthorizedWorkerId/);
  assert.throws(() => createSimulationSession({
    sim: h.sim,
    send() {},
    onTerminal: null,
  }), /onTerminal/);
});

test('revocation before a reserved attempt is a harmless no-op', async () => {
  const notices = [];
  const h = makeHarness({
    session: { sessionOwner: Object.freeze({}), preauthorizedWorkerId: WORKER_ID },
    onTerminal: (notice) => notices.push(notice),
  });
  try {
    assert.equal(h.api.revokeAssignment(), false);
    assert.equal(h.sim.attemptState, SIM_ATTEMPT_STATES.IDLE);
    assert.deepEqual(notices, []);
    assert.equal(h.sent.length, 0);
  } finally {
    await closeHarness(h);
  }
});

test('session disposal notifies assignment teardown once, with or without a reserved run', async () => {
  for (const startFirst of [false, true]) {
    const notices = [];
    const h = makeHarness({
      session: { sessionOwner: Object.freeze({}), preauthorizedWorkerId: WORKER_ID },
      onTerminal: (notice) => notices.push(notice),
    });
    if (startFirst) await h.say({ type: 'start_request', clientStartId: START_ID });
    h.api.dispose();
    h.api.dispose();
    assert.equal(notices.length, 1);
    assert.equal(notices[0].owner, h.api.ownerToken);
    assert.equal(notices[0].clientStartId, startFirst ? START_ID : null);
    assert.equal(notices[0].state, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
    assert.equal(notices[0].reason, 'session_dispose');
    await h.sim.closeAssignmentResources('test cleanup');
  }
});

test('disposing after an ordinary terminal outcome does not notify twice', async () => {
  const notices = [];
  const h = makeHarness({
    session: { sessionOwner: Object.freeze({}), preauthorizedWorkerId: WORKER_ID },
    onTerminal: (notice) => notices.push(notice),
  });
  await h.say({ type: 'start_request', clientStartId: START_ID });
  assert.equal(h.api.revokeAssignment(), true);
  h.api.dispose();
  assert.equal(notices.length, 1);
  assert.equal(notices[0].reason, 'submission_already_claimed');
  await h.sim.closeAssignmentResources('test cleanup');
});
