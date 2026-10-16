// Non-live transport adapter tests. All jobs, sessions and teardown handles are in memory.
import test from 'node:test';
import assert from 'node:assert/strict';

import { createTwoSlotCoordinator } from '../two_slot_coordinator.mjs';
import { createTwoSlotSession } from '../two_slot_session.mjs';

const A = '01'.repeat(16);
const B = '02'.repeat(16);
const C = '03'.repeat(16);
const PARENT = 'ab'.repeat(32);

function gate() {
  let open;
  return { promise: new Promise((resolve) => { open = resolve; }), open };
}

function issued(n) {
  const hex = n.toString(16);
  return {
    job: Object.freeze({
      jobId: `personalized-${n}`, issuanceId: hex.padStart(32, '0'),
      contentDigest: hex.padStart(64, '0'), height: 7n,
      algorithm: 'meephash-w-v2-frozen-real-template', majorVersion: 16,
      epochKeyHex: 'a'.repeat(64), seedHashHex: 'b'.repeat(64),
      hashingTemplateHex: '00'.repeat(80), targetHexLE: 'f'.repeat(64),
      nonceStart: 0, nonceRange: 8192, expiresAtMs: 10_000,
    }),
    context: Object.freeze({ n }),
    templateFacts: Object.freeze({ n }),
    canonical: Object.freeze({ prevHashHex: PARENT }),
  };
}

function harness({ issueGate = null, closeGate = null, failContext = false,
  failContextOnce = false, failChildOnce = false, throwRealJob = false } = {}) {
  let issueCalls = 0;
  const coordinator = createTwoSlotCoordinator({
    now: () => 1_000,
    issuer: {
      async issue({ stillWanted }) {
        issueCalls += 1;
        const n = issueCalls;
        if (issueGate !== null) await issueGate.promise;
        if (!stillWanted()) throw Object.assign(new Error('cancelled'), {
          code: 'personalized_issue_cancelled',
        });
        return issued(n);
      },
    },
  });
  const contexts = [];
  const children = [];
  const tracked = [];
  let hContextCalls = 0;
  let childCalls = 0;
  const makeSession = () => {
    const sent = [];
    let jobSendFailed = false;
    const adapter = createTwoSlotSession({
      coordinator,
      now: () => 1_000,
      send: (frame) => {
        if (throwRealJob && frame.type === 'real_job' && !jobSendFailed) {
          jobSendFailed = true;
          throw new Error('transport closed while publishing job');
        }
        sent.push(frame);
      },
      trackAsync: (operation) => tracked.push(operation),
      createContext: (assignment) => {
        if (failContext || (failContextOnce && hContextCalls++ === 0)) {
          throw new Error('private setup detail');
        }
        const context = {
          assignment,
          closed: false,
          closeCalls: 0,
          get assignmentResourcesClosed() { return this.closed; },
          async closeAssignmentResources() {
            this.closeCalls += 1;
            if (closeGate !== null) await closeGate.promise;
            this.closed = true;
          },
        };
        contexts.push(context);
        return context;
      },
      childFactory: ({ sessionOwner, preauthorizedWorkerId, onTerminal, send }) => {
        if (failChildOnce && childCalls++ === 0) throw new Error('private child setup detail');
        const child = {
          owner: sessionOwner,
          workerId: preauthorizedWorkerId,
          starts: 0,
          disposed: false,
          revoked: false,
          async handleRaw(_length, text) {
            const message = JSON.parse(text);
            if (message.type === 'start_request') {
              this.starts += 1;
              send({ type: 'run_started', clientStartId: message.clientStartId,
                workerId: this.workerId, jobId: contexts.at(-1).assignment.issued.job.jobId });
            }
            return { ok: true, type: message.type };
          },
          revokeAssignment(reason) {
            if (this.revoked || this.disposed) return false;
            this.revoked = true;
            onTerminal({ owner: sessionOwner, clientStartId: adapter.clientStartId, reason });
            return true;
          },
          dispose() {
            if (this.disposed) return;
            this.disposed = true;
            onTerminal({ owner: sessionOwner, clientStartId: adapter.clientStartId,
              reason: 'session_dispose' });
          },
          notifyVerifierUnhealthy() { return true; },
        };
        children.push(child);
        return child;
      },
    });
    const say = (message) => {
      const text = JSON.stringify(message);
      return adapter.handleRaw(Buffer.byteLength(text), text);
    };
    return { adapter, sent, say, last: (type) => sent.filter((f) => f.type === type).at(-1) };
  };
  return { coordinator, contexts, children, tracked, makeSession, get issueCalls() { return issueCalls; } };
}

async function hello(session) {
  return session.say({ type: 'client_hello', protocolVersion: 1 });
}

test('hello is jobless and two accepted Starts get distinct jobs with matching connection identity', async () => {
  const h = harness();
  const a = h.makeSession();
  const b = h.makeSession();
  await hello(a);
  await hello(b);
  assert.equal(h.issueCalls, 0);
  assert.equal(h.contexts.length, 0);
  assert.equal(a.last('server_hello').jobIssuedOnStart, true);
  assert.equal(a.last('real_job'), undefined);
  assert.notEqual(a.adapter.workerId, b.adapter.workerId);

  assert.equal((await a.say({ type: 'start_request', clientStartId: A })).ok, true);
  assert.equal((await b.say({ type: 'start_request', clientStartId: B })).ok, true);
  assert.equal(h.issueCalls, 2);
  assert.equal(h.contexts.length, 2);
  assert.notEqual(a.last('real_job').jobId, b.last('real_job').jobId);
  assert.equal(a.adapter.child.owner, a.adapter.ownerToken);
  assert.equal(a.adapter.child.workerId, a.last('server_hello').workerId);
  assert.deepEqual(a.sent.map((f) => f.type), ['server_hello', 'real_job', 'run_started']);
  assert.equal(h.coordinator.stateFacts.active, 2);
  await Promise.all([a.adapter.disposeAsync(), b.adapter.disposeAsync()]);
  assert.equal(h.coordinator.stateFacts.active, 0);
});

test('third Start is refused before issuance, context construction or verifier work', async () => {
  const h = harness();
  const a = h.makeSession();
  const b = h.makeSession();
  const c = h.makeSession();
  await Promise.all([hello(a), hello(b), hello(c)]);
  await Promise.all([
    a.say({ type: 'start_request', clientStartId: A }),
    b.say({ type: 'start_request', clientStartId: B }),
  ]);
  const result = await c.say({ type: 'start_request', clientStartId: C });
  assert.deepEqual(result, { ok: false, reason: 'pool_capacity' });
  assert.equal(c.last('run_unavailable').jobId, null);
  assert.equal(c.last('run_unavailable').runGeneration, null);
  assert.equal(c.last('real_job'), undefined);
  assert.equal(h.issueCalls, 2);
  assert.equal(h.contexts.length, 2);
  await Promise.all([a.adapter.disposeAsync(), b.adapter.disposeAsync()]);
});

test('a refused connection may retry only through a fresh Start after positive teardown', async () => {
  const h = harness();
  const a = h.makeSession();
  const b = h.makeSession();
  const c = h.makeSession();
  await Promise.all([hello(a), hello(b), hello(c)]);
  await Promise.all([
    a.say({ type: 'start_request', clientStartId: A }),
    b.say({ type: 'start_request', clientStartId: B }),
  ]);
  assert.equal((await c.say({ type: 'start_request', clientStartId: C })).reason, 'pool_capacity');
  await a.adapter.disposeAsync();
  assert.equal((await c.say({ type: 'start_request', clientStartId: C })).ok, true);
  assert.equal(h.issueCalls, 3);
  await Promise.all([b.adapter.disposeAsync(), c.adapter.disposeAsync()]);
});

test('disconnect during serialized issuance cancels demand and creates no context', async () => {
  const issuing = gate();
  const h = harness({ issueGate: issuing });
  const a = h.makeSession();
  await hello(a);
  const start = a.say({ type: 'start_request', clientStartId: A });
  assert.equal(h.issueCalls, 1);
  a.adapter.dispose();
  issuing.open();
  await start;
  await a.adapter.disposeAsync();
  assert.equal(h.contexts.length, 0);
  assert.equal(h.children.length, 0);
  assert.equal(h.coordinator.stateFacts.active, 0);
});

test('a slot stays occupied until physical assignment teardown confirms closure', async () => {
  const closing = gate();
  const h = harness({ closeGate: closing });
  const a = h.makeSession();
  const b = h.makeSession();
  const c = h.makeSession();
  await Promise.all([hello(a), hello(b), hello(c)]);
  await Promise.all([
    a.say({ type: 'start_request', clientStartId: A }),
    b.say({ type: 'start_request', clientStartId: B }),
  ]);
  const disposal = a.adapter.disposeAsync();
  assert.equal(h.coordinator.stateFacts.active, 2);
  assert.equal((await c.say({ type: 'start_request', clientStartId: C })).reason, 'pool_capacity');
  closing.open();
  await disposal;
  assert.equal((await c.say({ type: 'start_request', clientStartId: C })).ok, true);
  await Promise.all([b.adapter.disposeAsync(), c.adapter.disposeAsync()]);
});

test('one canonical claim revokes sibling before it can keep its assignment', async () => {
  const h = harness();
  const a = h.makeSession();
  const b = h.makeSession();
  await Promise.all([hello(a), hello(b)]);
  await Promise.all([
    a.say({ type: 'start_request', clientStartId: A }),
    b.say({ type: 'start_request', clientStartId: B }),
  ]);
  const winner = h.contexts[0].assignment;
  const claimed = winner.authority.claimSubmission({
    jobId: winner.issued.job.jobId, issuanceId: winner.issued.job.issuanceId,
    contentDigest: winner.issued.job.contentDigest, runGeneration: 1,
    intentLive: () => true, atMs: 1_000,
  });
  assert.equal(claimed.ok, true);
  assert.equal(b.adapter.child.revoked, true);
  await b.adapter.pendingDisposal;
  assert.equal(h.contexts[1].closed, true);
  assert.equal(h.coordinator.stateFacts.admissionClosed, true);
  await a.adapter.disposeAsync();
});

test('context setup errors expose only a closed public reason and release the reservation', async () => {
  const h = harness({ failContext: true });
  const a = h.makeSession();
  await hello(a);
  const result = await a.say({ type: 'start_request', clientStartId: A });
  assert.deepEqual(result, { ok: false, reason: 'assignment_setup_failed' });
  assert.equal(a.last('run_unavailable').reason, 'assignment_setup_failed');
  assert.equal(JSON.stringify(a.sent).includes('private setup detail'), false);
  await a.adapter.pendingDisposal;
  assert.equal(h.coordinator.stateFacts.active, 0);
  assert.equal(h.children.length, 0);
});

test('a fresh Start after setup failure owns its own later cleanup promise', async () => {
  const h = harness({ failContextOnce: true });
  const a = h.makeSession();
  await hello(a);
  assert.equal((await a.say({ type: 'start_request', clientStartId: A })).reason,
    'assignment_setup_failed');
  await a.adapter.pendingDisposal;
  assert.equal((await a.say({ type: 'start_request', clientStartId: B })).ok, true);
  assert.equal(h.coordinator.stateFacts.active, 1);
  await a.adapter.disposeAsync();
  assert.equal(h.contexts[0].closeCalls, 1);
  assert.equal(h.coordinator.stateFacts.active, 0);
});

test('a child-factory failure does not carry revocation into the next Start', async () => {
  const h = harness({ failChildOnce: true });
  const a = h.makeSession();
  await hello(a);
  assert.equal((await a.say({ type: 'start_request', clientStartId: A })).reason,
    'assignment_setup_failed');
  await a.adapter.pendingDisposal;
  assert.equal((await a.say({ type: 'start_request', clientStartId: B })).ok, true);
  assert.equal(a.last('real_job').jobId, h.contexts[1].assignment.issued.job.jobId);
  assert.equal(a.last('run_started').clientStartId, B);
  await a.adapter.disposeAsync();
  assert.equal(h.coordinator.stateFacts.active, 0);
});

test('a failed job publication disposes the child and closes its assignment', async () => {
  const h = harness({ throwRealJob: true });
  const a = h.makeSession();
  await hello(a);
  assert.equal((await a.say({ type: 'start_request', clientStartId: A })).reason,
    'assignment_setup_failed');
  await a.adapter.pendingDisposal;
  assert.equal(h.children[0].disposed, true);
  assert.equal(h.contexts[0].closed, true);
  assert.equal(h.coordinator.stateFacts.active, 0);
});
