// The opt-in pool route, over actual loopback WebSockets. Its daemon and personalized issuer are
// in-memory collaborators; no browser, native helper, container or external network is started.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { startDevPool } from '../server.mjs';
import { createDaemonRpc } from '../daemon_rpc.mjs';
import { createRealTemplateJob, hashingContextFor } from '../real_template.mjs';
import { createFatalLatch } from '../run_guard.mjs';
import { REAL_DAEMON_MODE } from '../../../web-miner/lib/shared/protocol.js';

const STARTS = ['01', '02', '03'].map((byte) => byte.repeat(16));
const VECTOR = JSON.parse(readFileSync(new URL('../../../meepow/vectors/block_vectors_v16_devnet.json', import.meta.url), 'utf8')).vectors[1];

function waitFor(messages, type) {
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error(`no ${type} frame arrived`)), 3_000);
    const tick = () => {
      const frame = messages.find((item) => item.type === type);
      if (frame) { clearTimeout(deadline); resolve(frame); }
      else setTimeout(tick, 5);
    };
    tick();
  });
}

function waitUntil(predicate, label) {
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error(`timed out waiting for ${label}`)), 3_000);
    const tick = () => {
      if (predicate()) { clearTimeout(deadline); resolve(); }
      else setTimeout(tick, 5);
    };
    tick();
  });
}

function fakeBuild() {
  let issued = 0;
  const verifiers = [];
  const makeJob = (id) => createRealTemplateJob({
    height: VECTOR.height, seedHashHex: VECTOR.epoch_key,
    wideDifficulty: String(VECTOR.difficulty),
    blockhashingBlobHex: VECTOR.block_hashing_blob,
    blocktemplateBlobHex: VECTOR.full_block_blob,
    nonceStart: 0, nonceRange: 8192,
  }, { mintIssuanceId: () => id.toString(16).padStart(32, '0') });
  const job = makeJob(1);
  const daemon = {
    counters: { getBlockTemplate: 1, calcPow: 0, prepareSubmission: 0,
      dispatchSubmission: 0, headerReadback: 0, topReadback: 0 },
    async getLastBlockHeader() { throw new Error('no candidate is submitted by this test'); },
  };
  const latch = createFatalLatch();
  return {
    job, daemon, latch, personalizedTemplates: true, peer: null, sequence: null, refresh: null,
    shareWork: false,
    makeServerVerifier: async ({ context }) => {
      const verifier = {
        context, closed: false, datasetBytes: 33_554_432, scratchBytes: 8_388_608,
        wasmHeapBytes: () => 48_562_176, nativeAlgorithmBytes: () => 41_943_040,
        async hashWasm() { throw new Error('no hash is requested by this test'); },
        async hashNative() { throw new Error('no hash is requested by this test'); },
        beginClose() {},
        async close() { this.closed = true; },
        async forceClose() { this.closed = true; },
      };
      verifiers.push(verifier);
      return verifier;
    },
    serializedPersonalizedTemplateIssuer: {
      async issue() {
        issued += 1;
        const next = issued === 1 ? job : makeJob(issued);
        return { job: next, context: hashingContextFor(next), templateFacts: {},
          canonical: { prevHashHex: VECTOR.prev_hash } };
      },
    },
    get issueCalls() { return issued; },
    get verifiers() { return [...verifiers]; },
  };
}

// Script the *real* submission adapter behind the two-slot WebSocket route. This is still an
// offline test: the adapter's transport is memory-only, but its operation-bound submission
// proofs, dispatch receipt and canonical readback are the same ones the live daemon path uses.
function winningBuild() {
  const built = fakeBuild();
  built.expectedHashHexLE = null;
  const hashes = { wasm: 0, native: 0 };
  const pow = '00'.repeat(32);
  const blockId = 'c'.repeat(64);
  let submitted = 0;
  const rpc = createDaemonRpc({
    transport: async (request) => {
      const body = JSON.parse(request.body);
      request.handoff();
      let result;
      switch (body.method) {
        case 'calc_pow': result = pow; break;
        case 'submit_block':
          submitted += 1;
          result = { status: 'OK', block_id: blockId };
          break;
        case 'get_block_header_by_height':
        case 'get_last_block_header':
          result = { status: 'OK', block_header: {
            hash: blockId, height: VECTOR.height, nonce: 0, orphan_status: false,
            prev_hash: VECTOR.prev_hash, pow_hash: pow,
          } };
          break;
        default: throw new Error(`unexpected scripted RPC ${body.method}`);
      }
      return JSON.stringify({ jsonrpc: '2.0', id: body.id, result });
    },
  });
  const counters = built.daemon.counters;
  built.daemon = {
    submissionAdapter: rpc, counters,
    async calcPow(request) { counters.calcPow += 1; return rpc.calcPow(request); },
    prepareSubmission(hex, operation) { counters.prepareSubmission += 1; return rpc.prepareSubmission(hex, operation); },
    dispatchSubmission(capability) { counters.dispatchSubmission += 1; return rpc.dispatchSubmission(capability); },
    async getBlockHeaderByHeight(height, options) {
      counters.headerReadback += 1;
      return rpc.getBlockHeaderByHeight(height, options);
    },
    async getLastBlockHeader(options) {
      counters.topReadback += 1;
      return rpc.getLastBlockHeader(options);
    },
  };
  const makeVerifier = built.makeServerVerifier;
  built.makeServerVerifier = async (options) => {
    const verifier = await makeVerifier(options);
    verifier.hashWasm = async () => { hashes.wasm += 1; return new Uint8Array(32); };
    verifier.hashNative = async () => { hashes.native += 1; return new Uint8Array(32); };
    return verifier;
  };
  return { built, hashes, get submitted() { return submitted; } };
}

test('two-slot startup configuration refuses incompatible modes before the factory runs', async () => {
  let built = 0;
  const factory = async () => { built += 1; throw new Error('must not build'); };
  for (const options of [
    { mode: 'synthetic', realDaemon: null },
    { mode: REAL_DAEMON_MODE, realDaemon: { personalizeTemplates: false } },
    { mode: REAL_DAEMON_MODE, realDaemon: { personalizeTemplates: true, sequenceBlocks: 2 } },
    { mode: REAL_DAEMON_MODE, realDaemon: { personalizeTemplates: true, refreshWindows: 2 } },
    { mode: REAL_DAEMON_MODE, realDaemon: { personalizeTemplates: true, shareDifficulty: 1 } },
  ]) {
    await assert.rejects(startDevPool({ ...options, twoSlotAssignments: true,
      realDaemonFactory: factory }), /twoSlotAssignments requires/);
  }
  assert.equal(built, 0);
});

test('a shared fatal latch terminalizes both browser-facing sockets and closes both assignments', async (t) => {
  const built = fakeBuild();
  const pool = await startDevPool({
    mode: REAL_DAEMON_MODE, realDaemon: { personalizeTemplates: true },
    twoSlotAssignments: true, realDaemonFactory: async () => built,
  });
  t.after(() => pool.close());
  const sockets = [];
  const seen = [];
  t.after(() => { for (const socket of sockets) socket.close(); });
  for (let i = 0; i < 2; i += 1) {
    const frames = [];
    const socket = new WebSocket(pool.wsUrl);
    sockets.push(socket);
    seen.push(frames);
    socket.onmessage = (event) => frames.push(JSON.parse(event.data));
    await new Promise((resolve, reject) => {
      socket.onopen = resolve;
      socket.onerror = reject;
    });
    socket.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
    await waitFor(frames, 'server_hello');
    socket.send(JSON.stringify({ type: 'start_request', clientStartId: STARTS[i] }));
    await waitFor(frames, 'mining_ready');
  }
  assert.equal(built.verifiers.length, 2);
  assert.equal(pool.twoSlotState.active, 2);
  const ready = seen.map((frames) => frames.find((frame) => frame.type === 'mining_ready'));
  assert.equal(built.latch.trip('verifier_fault', new Error('synthetic fault')).code, 'verifier_fault');
  const terminal = await Promise.all(seen.map((frames) => waitFor(frames, 'block_rejected')));
  for (let i = 0; i < 2; i += 1) {
    assert.equal(terminal[i].reason, 'fatal_verifier');
    assert.equal(terminal[i].terminal, true);
    assert.equal(terminal[i].clientStartId, STARTS[i]);
    assert.equal(terminal[i].jobId, ready[i].jobId);
    assert.equal(terminal[i].issuanceId, ready[i].issuanceId);
    assert.equal(terminal[i].runGeneration, ready[i].runGeneration);
  }
  await waitUntil(() => pool.twoSlotState.active === 0, 'both assignment releases');
  assert.equal(built.verifiers.every((verifier) => verifier.closed), true);
  assert.equal(pool.ownedResourceCount, 0);
  for (let i = 0; i < 2; i += 1) {
    sockets[i].send(JSON.stringify({
      type: 'submit_real_candidate', clientStartId: STARTS[i],
      jobId: ready[i].jobId, issuanceId: ready[i].issuanceId,
      workerId: ready[i].workerId, runGeneration: ready[i].runGeneration,
      nonce: '00000000',
    }));
  }
  const refused = await Promise.all(seen.map((frames) => waitFor(frames, 'error')));
  assert.deepEqual(refused.map((frame) => frame.reason), ['mining_not_started', 'mining_not_started']);
  const late = new WebSocket(pool.wsUrl);
  sockets.push(late);
  const lateFrames = [];
  late.onmessage = (event) => lateFrames.push(JSON.parse(event.data));
  await new Promise((resolve, reject) => {
    late.onopen = resolve;
    late.onerror = reject;
  });
  late.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
  await waitFor(lateFrames, 'server_hello');
  late.send(JSON.stringify({ type: 'start_request', clientStartId: STARTS[2] }));
  assert.equal((await waitFor(lateFrames, 'run_unavailable')).reason, 'two_slot_round_closed');
  assert.equal(built.issueCalls, 2);
  await pool.close();
  assert.equal(built.daemon.counters.dispatchSubmission, 0);
  assert.equal(pool.twoSlotEvidence.daemonCounters.dispatchSubmission, 0);
  assert.deepEqual(seen.map((frames) => frames.filter((frame) => frame.type === 'block_rejected').length), [1, 1]);
});

test('two connections get distinct real jobs after Start and a third is refused before issuance', async (t) => {
  const built = fakeBuild();
  const pool = await startDevPool({
    mode: REAL_DAEMON_MODE, realDaemon: { personalizeTemplates: true },
    twoSlotAssignments: true, realDaemonFactory: async () => built,
  });
  t.after(() => pool.close());
  assert.equal(pool.simulation, null);
  assert.equal(pool.twoSlotState.active, 0);
  const sockets = [];
  const seen = [];
  t.after(() => { for (const socket of sockets) socket.close(); });
  for (let i = 0; i < 3; i += 1) {
    const frames = [];
    const socket = new WebSocket(pool.wsUrl);
    sockets.push(socket);
    seen.push(frames);
    socket.onmessage = (event) => frames.push(JSON.parse(event.data));
    await new Promise((resolve, reject) => {
      socket.onopen = resolve;
      socket.onerror = reject;
    });
    socket.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
    const hello = await waitFor(frames, 'server_hello');
    assert.equal(hello.jobIssuedOnStart, true);
    assert.equal(hello.twoSlotCompetition, true);
    assert.equal(hello.mode, REAL_DAEMON_MODE);
    assert.match(hello.notice, /at most two browser sessions/);
    assert.equal(frames.some((frame) => frame.type === 'real_job'), false);
  }
  assert.notEqual(seen[0][0].workerId, seen[1][0].workerId);
  assert.equal(built.issueCalls, 0);
  assert.equal(pool.twoSlotState.successfulIssues, 0);
  assert.equal(pool.ownedResourceCount, 0);
  for (let i = 0; i < 2; i += 1) {
    sockets[i].send(JSON.stringify({ type: 'start_request', clientStartId: STARTS[i] }));
    await waitFor(seen[i], 'real_job');
    await waitFor(seen[i], 'mining_ready');
  }
  assert.notEqual(seen[0].find((f) => f.type === 'real_job').issuanceId,
    seen[1].find((f) => f.type === 'real_job').issuanceId);
  assert.equal(pool.twoSlotState.active, 2);
  assert.equal(built.issueCalls, 2);
  sockets[2].send(JSON.stringify({ type: 'start_request', clientStartId: STARTS[2] }));
  const unavailable = await waitFor(seen[2], 'run_unavailable');
  assert.equal(unavailable.reason, 'pool_capacity');
  assert.equal(unavailable.jobId, null);
  assert.equal(built.issueCalls, 2);
});

test('one canonical WebSocket submission terminalizes the sibling before any second daemon dispatch', async (t) => {
  const scripted = winningBuild();
  const pool = await startDevPool({
    mode: REAL_DAEMON_MODE, realDaemon: { personalizeTemplates: true },
    twoSlotAssignments: true, realDaemonFactory: async () => scripted.built,
  });
  const sockets = [];
  const seen = [];
  t.after(async () => {
    for (const socket of sockets) socket.close();
    await pool.close();
  });
  for (let i = 0; i < 2; i += 1) {
    const frames = [];
    const socket = new WebSocket(pool.wsUrl);
    sockets.push(socket);
    seen.push(frames);
    socket.onmessage = (event) => frames.push(JSON.parse(event.data));
    await new Promise((resolve, reject) => {
      socket.onopen = resolve;
      socket.onerror = reject;
    });
    socket.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
    await waitFor(frames, 'server_hello');
    socket.send(JSON.stringify({ type: 'start_request', clientStartId: STARTS[i] }));
    await waitFor(frames, 'mining_ready');
  }
  const ready = seen.map((frames) => frames.find((frame) => frame.type === 'mining_ready'));
  assert.notEqual(ready[0].issuanceId, ready[1].issuanceId);
  assert.equal(pool.twoSlotState.active, 2);
  sockets[0].send(JSON.stringify({
    type: 'submit_real_candidate', clientStartId: STARTS[0],
    jobId: ready[0].jobId, issuanceId: ready[0].issuanceId,
    workerId: ready[0].workerId, runGeneration: ready[0].runGeneration,
    nonce: '00000000',
  }));
  let winner;
  let loser;
  try {
    [winner, loser] = await Promise.all([
      waitFor(seen[0], 'block_accepted'), waitFor(seen[1], 'block_rejected'),
    ]);
  } catch (error) {
    throw new Error(`${error.message}; frames=${JSON.stringify(seen.map((frames) => frames.map((f) => [f.type, f.reason])))}`);
  }
  assert.equal(winner.terminal, true);
  assert.equal(winner.confirmedBy, 'immediate_canonical_readback_top_block_with_matching_pow_hash');
  assert.equal(loser.terminal, true);
  assert.equal(loser.reason, 'submission_already_claimed');
  assert.equal(loser.clientStartId, STARTS[1]);
  assert.equal(loser.issuanceId, ready[1].issuanceId);
  assert.equal(scripted.submitted, 1);
  assert.equal(scripted.built.daemon.counters.dispatchSubmission, 1);
  assert.equal(pool.twoSlotEvidence.daemonCounters.dispatchSubmission, 1);
  assert.deepEqual(scripted.hashes, { wasm: 1, native: 1 });
  await waitUntil(() => pool.twoSlotState.active === 0, 'both assignment releases');
  assert.equal(pool.twoSlotState.admissionClosed, true);
  assert.equal(scripted.built.verifiers.every((verifier) => verifier.closed), true);
  assert.equal(pool.ownedResourceCount, 0);
  sockets[1].send(JSON.stringify({
    type: 'submit_real_candidate', clientStartId: STARTS[1],
    jobId: ready[1].jobId, issuanceId: ready[1].issuanceId,
    workerId: ready[1].workerId, runGeneration: ready[1].runGeneration,
    nonce: '00000000',
  }));
  await waitFor(seen[1], 'error');
  assert.equal(scripted.submitted, 1, 'a late sibling frame reached submit_block');
  await pool.close();
  assert.equal(pool.ownedResourceCount, 0);
});
