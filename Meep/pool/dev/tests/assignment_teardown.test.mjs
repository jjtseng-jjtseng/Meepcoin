// Assignment-scoped verifier teardown. Pure in-memory resources: no listener, daemon, browser,
// Wasm module, native helper process, WSL, Docker, filesystem write, network request or hash.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createSimulationContext } from '../sim_session.mjs';

const JOB = Object.freeze({
  jobId: 'assignment-job', issuanceId: 'a'.repeat(32), height: 1n,
  nonceStart: 0, nonceRange: 1, targetHexLE: 'f'.repeat(64),
});

function gate() {
  let open;
  return { promise: new Promise((resolve) => { open = resolve; }), open };
}

function resource({ closeConfirms = true, forceConfirms = true } = {}) {
  return {
    closed: false,
    beginCloseCalls: 0,
    closeCalls: 0,
    forceCloseCalls: 0,
    beginClose() { this.beginCloseCalls += 1; },
    async close() { this.closeCalls += 1; if (closeConfirms) this.closed = true; },
    async forceClose() { this.forceCloseCalls += 1; if (forceConfirms) this.closed = true; },
  };
}

function makeContext({
  makeServerVerifier,
  initialVerifierContext = null,
  assignmentScopedTeardown = true,
  sequence = null,
  refresh = null,
  releaseOwnedResource = null,
} = {}) {
  const owned = [];
  const released = [];
  const latch = {
    tripped: false,
    subscriberCount: 0,
    trip() { this.tripped = true; },
  };
  const sim = createSimulationContext({
    job: JOB,
    latch,
    authority: { stateFacts: Object.freeze({}) },
    makeServerVerifier,
    expectedHashHexLE: null,
    recordedContext: Object.freeze({ source: 'builder-default' }),
    initialVerifierContext,
    assignmentScopedTeardown,
    sequence,
    refresh,
    ownResource: (label, value) => owned.push({ label, value }),
    releaseOwnedResource: releaseOwnedResource
      ?? ((value, facts) => released.push({ value, facts })),
  });
  return { sim, owned, released };
}

test('assignment teardown is opt-in and structurally excludes rotation modes', async () => {
  const disabled = makeContext({
    assignmentScopedTeardown: false,
    makeServerVerifier: async () => resource(),
  }).sim;
  assert.equal(disabled.assignmentResourcesClosed, false);
  await assert.rejects(
    disabled.closeAssignmentResources(),
    (err) => err?.code === 'assignment_teardown_unavailable',
  );
  assert.equal(disabled.closing, false, 'the refused opt-in close mutated the legacy context');

  assert.throws(() => makeContext({
    sequence: { total: 2 },
    makeServerVerifier: async () => resource(),
  }), /requires one-shot work/);
  assert.throws(() => makeContext({
    refresh: { maxWindows: 2 },
    makeServerVerifier: async () => resource(),
  }), /requires one-shot work/);
});

test('closing before allocation creates nothing and positively closes an empty assignment', async () => {
  let factoryCalls = 0;
  const { sim } = makeContext({
    makeServerVerifier: async () => { factoryCalls += 1; return resource(); },
  });
  assert.equal(sim.assignmentResourcesClosed, false);
  await sim.closeAssignmentResources('never started');
  assert.equal(factoryCalls, 0);
  assert.equal(sim.assignmentResourcesClosed, true);
  await assert.rejects(sim.ensureServerVerifier(), (err) => err?.cancelled === true);
});

test('assignment context passes its explicit verifier context and closes exactly once', async () => {
  const assignmentContext = Object.freeze({ source: 'personalized-B' });
  const verifier = resource();
  const seen = [];
  const { sim, owned, released } = makeContext({
    initialVerifierContext: assignmentContext,
    makeServerVerifier: async (options) => { seen.push(options.context); return verifier; },
  });

  await sim.ensureServerVerifier();
  assert.deepEqual(seen, [assignmentContext]);
  assert.equal(sim.assignmentResourcesClosed, false);
  const first = sim.closeAssignmentResources('assignment finished');
  const repeated = sim.closeAssignmentResources('ignored repeat');
  assert.equal(repeated, first, 'assignment close was not single-flight');
  await first;

  assert.equal(sim.assignmentResourcesClosed, true);
  assert.equal(sim.verifier, null);
  assert.equal(sim.pendingInit, null);
  assert.equal(verifier.closeCalls, 1);
  assert.equal(verifier.forceCloseCalls, 0);
  assert.equal(owned.length, 1);
  assert.deepEqual(released.map((entry) => entry.value), [verifier]);
  assert.equal(released[0].facts.closed, true);
});

test('assignment close joins a late verifier factory and closes what arrives after cancellation', async () => {
  const entered = gate();
  const releaseFactory = gate();
  const verifier = resource();
  let sawAbort = false;
  const { sim, released } = makeContext({
    makeServerVerifier: async ({ signal }) => {
      signal.addEventListener('abort', () => { sawAbort = true; }, { once: true });
      entered.open();
      await releaseFactory.promise;
      return verifier;
    },
  });

  const initializing = sim.ensureServerVerifier();
  await entered.promise;
  const closing = sim.closeAssignmentResources('disconnect during init');
  assert.equal(sawAbort, true);
  assert.equal(sim.assignmentResourcesClosed, false);
  releaseFactory.open();
  await initializing;
  await closing;

  assert.equal(verifier.closed, true);
  assert.equal(sim.assignmentResourcesClosed, true);
  assert.deepEqual(released.map((entry) => entry.value), [verifier]);
});

test('partial startup resources are adopted, escalated and confirmed before release', async () => {
  const partialA = resource({ closeConfirms: false, forceConfirms: true });
  const partialB = resource();
  const { sim, owned, released } = makeContext({
    makeServerVerifier: async () => {
      const err = new Error('scripted partial startup');
      err.name = 'PartialVerifierError';
      err.resources = [
        { label: 'wasm-half', resource: partialA },
        { label: 'native-half', resource: partialB },
      ];
      throw err;
    },
  });

  await assert.rejects(sim.ensureServerVerifier(), /scripted partial startup/);
  await sim.closeAssignmentResources('failed startup');

  assert.equal(sim.assignmentResourcesClosed, true);
  assert.deepEqual(owned.map((entry) => entry.value), [partialA, partialB]);
  assert.equal(partialA.forceCloseCalls, 1);
  assert.equal(partialB.forceCloseCalls, 0);
  assert.equal(released.length, 2);
  assert.equal(released.some((entry) => entry.value === partialA), true);
  assert.equal(released.some((entry) => entry.value === partialB), true);
});

test('an unconfirmed physical release rejects and is never disowned', async () => {
  const stuck = resource({ closeConfirms: false, forceConfirms: false });
  const { sim, released } = makeContext({ makeServerVerifier: async () => stuck });
  await sim.ensureServerVerifier();

  await assert.rejects(
    sim.closeAssignmentResources('stuck assignment'),
    (err) => err?.code === 'verifier_release_unconfirmed',
  );
  assert.equal(sim.assignmentResourcesClosed, false);
  assert.equal(stuck.closeCalls, 1);
  assert.equal(stuck.forceCloseCalls, 1);
  assert.deepEqual(released, []);
});

test('one stuck partial resource cannot prevent every sibling close attempt', async () => {
  const stuck = resource({ closeConfirms: false, forceConfirms: false });
  const sibling = resource();
  const { sim, released } = makeContext({
    makeServerVerifier: async () => {
      const err = new Error('two partial handles');
      err.name = 'PartialVerifierError';
      err.resources = [
        { label: 'stuck-half', resource: stuck },
        { label: 'closable-half', resource: sibling },
      ];
      throw err;
    },
  });

  await assert.rejects(sim.ensureServerVerifier(), /two partial handles/);
  await assert.rejects(
    sim.closeAssignmentResources('partial failure'),
    (err) => err?.code === 'verifier_release_unconfirmed',
  );

  assert.equal(stuck.closeCalls, 1);
  assert.equal(stuck.forceCloseCalls, 1);
  assert.equal(stuck.closed, false);
  assert.equal(sibling.closeCalls, 1);
  assert.equal(sibling.closed, true);
  assert.equal(sim.assignmentResourcesClosed, false);
  assert.deepEqual(released.map((entry) => entry.value), [sibling]);
});

test('physical closure wins when graceful close throws after closing', async () => {
  const verifier = resource();
  verifier.close = async function closeThenThrow() {
    this.closeCalls += 1;
    this.closed = true;
    throw new Error('reporting failed after physical close');
  };
  const { sim, released } = makeContext({ makeServerVerifier: async () => verifier });
  await sim.ensureServerVerifier();

  await sim.closeAssignmentResources('close callback throws');

  assert.equal(sim.assignmentResourcesClosed, true);
  assert.equal(verifier.closeCalls, 1);
  assert.equal(verifier.forceCloseCalls, 0);
  assert.deepEqual(released.map((entry) => entry.value), [verifier]);
});

test('ownership callback failure cannot negate confirmed physical closure', async () => {
  const verifier = resource();
  let releaseCalls = 0;
  const { sim } = makeContext({
    makeServerVerifier: async () => verifier,
    releaseOwnedResource: () => {
      releaseCalls += 1;
      throw new Error('ownership graph kept the already-closed handle');
    },
  });
  await sim.ensureServerVerifier();

  await sim.closeAssignmentResources('ownership callback throws');

  assert.equal(releaseCalls, 1);
  assert.equal(verifier.closed, true);
  assert.equal(sim.assignmentResourcesClosed, true);
});

test('assignmentResourcesClosed stays false until physical close completes', async () => {
  const allowClose = gate();
  const verifier = resource();
  verifier.close = async function gatedClose() {
    this.closeCalls += 1;
    await allowClose.promise;
    this.closed = true;
  };
  const { sim } = makeContext({ makeServerVerifier: async () => verifier });
  await sim.ensureServerVerifier();

  const closing = sim.closeAssignmentResources('gated close');
  assert.equal(sim.assignmentResourcesClosed, false);
  assert.equal(verifier.closed, false);
  allowClose.open();
  await closing;

  assert.equal(sim.assignmentResourcesClosed, true);
});
