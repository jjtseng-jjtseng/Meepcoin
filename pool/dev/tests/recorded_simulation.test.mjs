// The recorded-template simulation, driven directly through the session with NO socket, NO
// listener, NO browser and NO operating-system child process.
//
// This exercises the real server half: the real committed vector, the real contextual Wasm instance,
// the real createDualVerifier and native_helper.mjs protocol client, the real block_run state machine,
// the shared latch and authority. The native helper CHILD is an in-process scripted stand-in behind
// the existing `spawnFn` seam: it speaks the real HELLO / INIT / HASH / QUIT protocol and records
// every line the pool writes, so "exactly one HASH" and "the INIT carried this context" are counts
// of real protocol lines. The real helper executable is exercised separately, by the live run.
//
// It DOES load the Wasm module and allocate one dataset, once, because that is the thing being
// demonstrated. Everything before Start is asserted to allocate nothing.
//
// A LARGE PART OF THIS FILE IS THE ONE-ATTEMPT RESERVATION, because the previous revision only
// claimed to be one-shot: two sessions could both be acknowledged and both hash, and six sequential
// start_requests produced six run generations, six readiness messages and six permanent latch
// subscribers. Those exact witnesses are reproduced here.

import test, { afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  FORBIDDEN_SIM_PHRASES, RESERVE_REFUSED, SIM_ACTION_LABEL, SIM_ATTEMPT_STATES, SIM_LABELS, SIM_MODE,
  createSimulationContext, createSimulationSession,
} from '../sim_session.mjs';
import {
  EXPECTED, RecordedVectorError, buildRecordedSimulation as buildRecordedSimulationWithRealHelper,
  digestRecordedRow, loadRecordedRow,
} from '../recorded_simulation.mjs';
import { createMockDaemon, createRecordedOracle } from '../recorded_oracle.mjs';
import { startDevPool } from '../server.mjs';
import { NONTERMINAL, TERMINAL } from '../block_run.mjs';
import { submissionProofs } from '../daemon_rpc.mjs';
import { FATAL_CODES } from '../run_guard.mjs';
import { computeSourceId } from '../source_identity.mjs';
import { createDualVerifier } from '../dual_verifier.mjs';
import { hashingTemplateOf } from '../real_template.mjs';
import { blobToHex } from '../block_blob.mjs';
import { nonceToHex } from '../../../web-miner/lib/shared/target.js';
import {
  SIM_ATTEMPT_STATE_VALUES, SIM_FAILURE_CODES, SIM_PRE_RUN_REFUSALS,
} from '../../../web-miner/lib/shared/protocol.js';

const SOURCE_ID = computeSourceId().sourceId;

function pipeStub() {
  const p = new EventEmitter();
  p.destroyed = false;
  p.destroy = () => { p.destroyed = true; };
  return p;
}

/**
 * An in-process scripted native helper child. No operating-system process: the pool's real
 * native_helper.mjs client talks to this object through the `spawnFn` seam, in the real protocol.
 *
 *   hashHex       what RESULT carries (the committed recorded hash by default)
 *   sourceId      what HELLO reports (this working tree's real source identity by default)
 *   readyBytes    what READY reports for dataset/scratchpad
 *   stallInit     never answer INIT
 */
function scriptedHelper({
  hashHex = EXPECTED.powHash,
  sourceId = SOURCE_ID,
  readyBytes = [33_554_432, 8_388_608],
  stallInit = false,
} = {}) {
  const log = { spawned: 0, lines: [], inits: [], hashes: [], children: [] };
  const spawnFn = (cmd) => {
    log.spawned += 1;
    const c = new EventEmitter();
    c.pid = 7000 + log.spawned;
    c.stdout = pipeStub();
    c.stderr = pipeStub();
    c.exited = false;
    const say = (line) => setImmediate(() => { if (!c.exited) c.stdout.emit('data', Buffer.from(`${line}\n`, 'latin1')); });
    c.exitNow = (code = 0, signal = null) => {
      if (c.exited) return;
      c.exited = true;
      setImmediate(() => { c.emit('exit', code, signal); setImmediate(() => c.emit('close', code)); });
    };
    c.kill = () => { c.exitNow(null, 'SIGKILL'); return true; };
    c.stdin = {
      writable: true,
      destroyed: false,
      write(text) {
        for (const line of String(text).split('\n')) {
          if (line.length === 0) continue;
          log.lines.push(line);
          const t = line.split(' ');
          if (t[0] === 'INIT') {
            log.inits.push(t);
            if (!stallInit) say(`READY ${t[1]} ${readyBytes[0]} ${readyBytes[1]}`);
          } else if (t[0] === 'HASH') {
            log.hashes.push(Number(t[2]));
            say(`RESULT ${t[1]} ${hashHex}`);
          } else if (t[0] === 'QUIT') {
            say('BYE');
            setImmediate(() => setImmediate(() => c.exitNow(0, null)));
          }
        }
        return true;
      },
      end() { c.stdin.writable = false; },
      destroy() { c.stdin.destroyed = true; c.stdin.writable = false; },
    };
    log.children.push(c);
    say(`HELLO 2 ${c.pid} ${cmd.args.at(-1)} 2 60 - - ${sourceId}`);
    return c;
  };
  return {
    log,
    helperOptions: {
      useWsl: false,
      spawnFn,
      limits: { startupTimeoutMs: 5000, initTimeoutMs: 5000, quitTimeoutMs: 500, stdioDrainMs: 500, signalTimeoutMs: 500 },
    },
  };
}

async function waitFor(predicate, label, timeoutMs = 5000) {
  const t0 = Date.now();
  while (!predicate()) {
    if (Date.now() - t0 > timeoutMs) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

/** Every context built here is shut down after its test, so no scripted child outlives it. */
const liveContexts = [];
afterEach(async () => {
  while (liveContexts.length > 0) {
    const sim = liveContexts.pop();
    sim.beginClose('test cleanup');
    try { await sim.pendingInit; } catch { /* reported by the test that cared */ }
    for (const r of sim.createdResources) {
      if (r.closed) continue;
      try { await r.close('test cleanup'); } catch { try { await r.forceClose('test cleanup'); } catch { /* reported */ } }
    }
  }
});

/**
 * THE ONLY WAY THIS FILE BUILDS A SIMULATION, and it can never reach the real helper.
 *
 * An earlier draft of these tests called the real builder bare in several places. On Windows its
 * default factory resolves the WSL distribution and launches the REAL meepow-v2-helper -- which it
 * did, during what was meant to be a pure run. Every build now goes through here: a scripted
 * in-process child, `useWsl: false`, and a guard test below that fails if the real builder is
 * called anywhere else in this file.
 */
function buildScripted(helper = scriptedHelper()) {
  const base = buildRecordedSimulationWithRealHelper({
    helperPath: process.execPath,
    helperOptions: helper.helperOptions,
  });
  return { base, helper };
}

/** Every context is tracked, so its verifier is closed after the test whatever happened. */
function track(sim) {
  liveContexts.push(sim);
  return sim;
}

/** One shared simulation context over a scripted native helper. */
function makeSim(overrides = {}, helper = scriptedHelper()) {
  const { base } = buildScripted(helper);
  const sim = track(createSimulationContext({ ...base, ...overrides }));
  return { base, sim, helper };
}

const SIM_TERMINAL_STATES = ['terminal_complete', 'terminal_cancelled', 'terminal_failed'];

let startIdCounter = 0;
/** A distinct 32-hex correlation token per Start attempt, exactly as the page mints one. */
function newStartId() {
  startIdCounter += 1;
  return startIdCounter.toString(16).padStart(32, '0');
}

function driver(sim, { now } = {}) {
  const sent = [];
  const audits = [];
  const session = createSimulationSession({
    sim, now, send: (o) => sent.push(o), onAudit: (e) => audits.push(e),
  });
  const say = (obj) => {
    const text = JSON.stringify(obj);
    return session.handleRaw(Buffer.byteLength(text), text);
  };
  const last = (type) => [...sent].reverse().find((m) => m.type === type);
  const all = (type) => sent.filter((m) => m.type === type);
  return { sent, audits, session, say, last, all, types: () => sent.map((m) => m.type) };
}

const HELLO = { type: 'client_hello', protocolVersion: 1 };

/** Start, with a fresh correlation token. Returns the token so a later message can repeat it. */
async function start(d, clientStartId = newStartId()) {
  await d.say({ type: 'start_request', clientStartId });
  return clientStartId;
}

/** The one candidate this simulation expects, bound to the live session. */
function candidateFrom(d, sim, over = {}) {
  const started = d.last('run_started');
  return {
    type: 'submit_real_candidate',
    jobId: started.jobId,
    issuanceId: started.issuanceId,
    workerId: started.workerId,
    runGeneration: started.runGeneration,
    clientStartId: started.clientStartId,
    nonce: nonceToHex(sim.job.nonceStart),
    ...over,
  };
}

function stopFrom(d, over = {}) {
  const started = d.last('run_started');
  return {
    type: 'stop_request',
    workerId: started.workerId,
    runGeneration: started.runGeneration,
    jobId: started.jobId,
    issuanceId: started.issuanceId,
    clientStartId: started.clientStartId,
    reason: 'user_stop',
    ...over,
  };
}

function work(sim) {
  return {
    hashes: sim.counters.serverWasmHashes,
    native: sim.counters.nativeHashRequests,
    ...sim.mockDaemon.counters,
  };
}

// ================================================================== the committed vector
test('the committed row is exactly the one this simulation claims', () => {
  const row = loadRecordedRow();
  assert.equal(row.height, EXPECTED.height);
  assert.equal(row.seed_height, EXPECTED.seedHeight);
  assert.equal(row.major_version, EXPECTED.majorVersion);
  assert.equal(row.nonce, EXPECTED.nonce);
  assert.equal(row.expected_meephash_w_v2, EXPECTED.powHash);
  assert.equal(row.daemon_pow_hash, EXPECTED.powHash);
  assert.equal(row.block_hash, EXPECTED.blockHash);
  // The discriminating property: this row does NOT share the genesis epoch key.
  const genesis = loadRecordedRow({ height: 0 });
  assert.notEqual(row.epoch_key, genesis.epoch_key, 'the chosen row shares the genesis epoch key');
  assert.equal(genesis.seed_height, 0);
});

test('the WHOLE row is pinned, so a tail byte cannot redefine what the mock expects', () => {
  const row = loadRecordedRow();
  assert.equal(digestRecordedRow(row), EXPECTED.rowDigest);

  // The named checks above read eight fields. These are the ones they do NOT read, and they are
  // exactly the bytes the mock daemon compares against -- editing one used to change what a green
  // run meant while every named check still passed.
  const unnamed = ['full_block_blob', 'block_hashing_blob', 'blob_nonce_zeroed',
    'nonce_offset_bytes', 'nonce_byte_order', 'target_le_hex', 'prev_hash', 'timestamp'];
  for (const field of unnamed) {
    assert.ok(field in row, `the committed row lost ${field}`);
    const tampered = { ...row };
    // A tail-byte edit: the smallest change that still produces a well-formed value.
    tampered[field] = typeof row[field] === 'string'
      ? `${row[field].slice(0, -1)}${row[field].endsWith('0') ? '1' : '0'}`
      : row[field] + 1;
    assert.notEqual(digestRecordedRow(tampered), EXPECTED.rowDigest,
      `a one-byte edit to ${field} did not change the pinned digest`);
  }
});

test('a one-nonce window is issued, and it is the recorded nonce', () => {
  const { sim } = makeSim();
  assert.equal(sim.job.nonceStart, EXPECTED.nonce);
  assert.equal(sim.job.nonceRange, 1, 'the window must contain exactly one nonce');
  assert.equal(sim.job.height, BigInt(EXPECTED.height));
  assert.equal(sim.job.majorVersion, 16);
});

// ================================================================== nothing before Start
test('NOTHING is allocated or hashed before Start', async () => {
  const { sim, helper } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);

  assert.equal(sim.serverVerifierReady, false, 'a verifier existed before Start');
  assert.equal(sim.verifier, null);
  assert.equal(sim.counters.serverWasmHashes, 0);
  assert.equal(sim.counters.nativeHashRequests, 0);
  assert.deepEqual(sim.mockDaemon.counters,
    {
      calcPow: 0, prepareSubmission: 0, dispatchSubmission: 0, readback: 0, inMemoryTransportCalls: 0, transportCalls: 0,
    });
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.IDLE);
  assert.equal(sim.latch.subscriberCount, 0, 'something subscribed to the latch before Start');

  // And the hello carries the labels a page must show BEFORE Start.
  const hello = d.last('server_hello');
  assert.equal(hello.mode, SIM_MODE);
  assert.deepEqual(hello.labels, SIM_LABELS);
  assert.equal(hello.actionLabel, SIM_ACTION_LABEL);
  assert.equal(hello.alreadyCompleted, false);
  assert.equal(hello.attemptState, SIM_ATTEMPT_STATES.IDLE);
  assert.match(hello.willAllocate, /one native helper dataset/);

  // THE CONSENT BOUNDARY, for the native side: construction, hello and job publication spawned no
  // helper, sent no INIT and no HASH, and allocated no native dataset.
  assert.equal(helper.log.spawned, 0, 'a native helper was spawned before Start');
  assert.equal(helper.log.lines.length, 0, 'the helper was spoken to before Start');

  // The public job is disclosed; the full block is not.
  const job = d.last('real_job');
  assert.equal(job.height, String(EXPECTED.height));
  assert.equal(JSON.stringify(job).includes(loadRecordedRow().full_block_blob), false,
    'the full block blob reached the client');
});

test('a Start with no correlation token is refused before any reservation', async () => {
  const { sim } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  const r = await d.say({ type: 'start_request' });
  assert.equal(r.ok, false);
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.IDLE, 'a bare Start reserved the attempt');
  assert.equal(sim.serverVerifierReady, false);
  assert.deepEqual(work(sim),
    {
      hashes: 0, native: 0, calcPow: 0, prepareSubmission: 0, dispatchSubmission: 0, readback: 0,
      inMemoryTransportCalls: 0, transportCalls: 0,
    });
});

// ================================================================== bindings on every message
test('run_started precedes readiness and both carry the same full binding', async () => {
  const { sim } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  const startId = await start(d);

  const order = d.types();
  const iStarted = order.indexOf('run_started');
  const iReady = order.indexOf('mining_ready');
  assert.ok(iStarted >= 0, 'no run_started acknowledgement');
  assert.ok(iReady > iStarted, 'mining_ready did not follow run_started');

  const a = d.last('run_started');
  const b = d.last('mining_ready');
  for (const f of ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration']) {
    assert.ok(a[f] !== undefined && a[f] !== null, `run_started is missing ${f}`);
    assert.equal(b[f], a[f], `mining_ready disagrees about ${f}`);
  }
  assert.equal(a.clientStartId, startId, 'the acknowledgement does not echo the Start correlation');
  assert.match(a.issuanceId, /^[0-9a-f]{32}$/);
  assert.equal(a.mode, SIM_MODE);
});

test('EVERY run-scoped message repeats the complete binding', async () => {
  const { sim } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  const startId = await start(d);
  await d.say(candidateFrom(d, sim));

  const runScoped = new Set([
    'run_started', 'mining_ready', 'mock_verification_complete', 'mock_submit_path_exercised',
    'candidate_rejected', 'simulation_complete', 'simulation_failed', 'simulation_stopped',
    'simulation_unavailable',
  ]);
  const seen = [];
  for (const msg of d.sent) {
    if (!runScoped.has(msg.type)) continue;
    seen.push(msg.type);
    for (const f of ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration']) {
      assert.ok(msg[f] !== undefined && msg[f] !== null, `${msg.type} is missing ${f}`);
    }
    assert.equal(msg.clientStartId, startId, `${msg.type} names another attempt`);
    assert.equal(msg.jobId, sim.job.jobId, `${msg.type} names another job`);
    assert.equal(msg.issuanceId, sim.job.issuanceId, `${msg.type} names another issuance`);
  }
  // The happy path really did emit the ones this asserts over.
  assert.deepEqual(seen,
    ['run_started', 'mining_ready', 'mock_verification_complete', 'mock_submit_path_exercised', 'simulation_complete']);
});

// ================================================================== the one full run
test('ONE browser result causes exactly one of each server-side step', async () => {
  const { sim, helper } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);
  assert.equal(sim.serverVerifierReady, true, 'Start did not prepare the server verifier');
  assert.equal(sim.counters.serverWasmHashes, 0, 'readiness alone hashed something');
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.RUNNING);

  const r = await d.say(candidateFrom(d, sim));
  assert.equal(r.ok, true, `the candidate was refused: ${r.reason}`);

  assert.equal(sim.counters.serverWasmHashes, 1, 'server Wasm hash count');
  assert.equal(sim.counters.nativeHashRequests, 1, 'native HASH requests');
  assert.equal(sim.counters.nativeHelperHashes, 1, 'native helper hashes');
  // Counted on the PROTOCOL: exactly one HASH line reached the helper, for the recorded nonce, and
  // no synthetic self-test ran before it.
  assert.deepEqual(helper.log.hashes, [EXPECTED.nonce]);
  assert.equal(helper.log.lines.filter((l) => l.startsWith('HASH ')).length, 1);
  assert.equal(sim.verifier.counters.nativeSelfTestHashes, 0);
  assert.equal(sim.verifier.counters.wasmSelfTestHashes, 0);
  assert.equal(sim.verifier.counters.wasmShareHashes, 1);
  assert.equal(sim.verifier.counters.nativeShareHashes, 1);
  // The recorded lookup table is no longer on the verification path.
  assert.equal(sim.oracle.calls, 0, 'the lookup table was consulted as a native check');
  assert.equal(sim.mockDaemon.counters.calcPow, 1);
  assert.equal(sim.mockDaemon.counters.prepareSubmission, 1);
  assert.equal(sim.mockDaemon.counters.dispatchSubmission, 1);
  assert.equal(sim.mockDaemon.counters.readback, 1);
  assert.equal(sim.mockDaemon.counters.transportCalls, 0, 'a transport was invoked');

  const done = d.last('simulation_complete');
  assert.ok(done, 'no terminal simulation_complete');
  assert.equal(done.counters.serverWasmHashes, 1);
  assert.equal(done.counters.nativeHelperHashes, 1);
  assert.equal(done.counters.nativeHelperHashRequests, 1);
  assert.equal(done.counters.mockInMemoryTransportCalls, 1);
  assert.equal(done.counters.realTransportCalls, 0);
  assert.equal(done.recordedVector.expectedHashHexLE, EXPECTED.powHash);
  // The server recomputed the recorded hash itself.
  assert.equal(d.last('mock_verification_complete').hashHexLE, EXPECTED.powHash);

  // The attempt is over, and nothing it held is still attached to the process-lifetime latch.
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(sim.latch.subscriberCount, 0, 'the finished run kept its latch subscription');
  // And `completed` is not left false while the one submission claim is permanently held.
  assert.equal(sim.authority.anyClaimed, true);
  assert.equal(sim.state.completed, true);
});

test('no simulation message uses real-world acceptance or submission wording', async () => {
  const { sim } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);
  await d.say(candidateFrom(d, sim));

  const json = JSON.stringify(d.sent).toLowerCase();
  for (const phrase of FORBIDDEN_SIM_PHRASES) {
    assert.equal(json.includes(phrase.toLowerCase()), false,
      `a simulation message contained forbidden wording: ${phrase}`);
  }
  // And the labels ARE present, so the page cannot be mistaken for real mining.
  const hello = d.last('server_hello');
  assert.ok(hello.labels.includes('NO BLOCK MINED, SUBMITTED, OR ACCEPTED'));
  assert.ok(hello.labels.includes('MOCK DAEMON'));
});

// ================================================================== the one-attempt reservation
test('TWO SESSIONS racing Start: ONE reservation, one verifier, one hash', async () => {
  // THE WITNESS: both sessions used to receive run_started and mining_ready, and both drove a run.
  // serverWasmHashes reached 2, mockNative 2, mockCalcPow 2 and mockPrepare 2; only the DISPATCH
  // was held to one, by the authority's claim, long after both had done the work. The loser was
  // left displayed as mining with an idle Worker.
  const { sim } = makeSim();
  const a = driver(sim);
  const b = driver(sim);
  await a.say(HELLO);
  await b.say(HELLO);

  const [ra, rb] = await Promise.all([
    a.say({ type: 'start_request', clientStartId: newStartId() }),
    b.say({ type: 'start_request', clientStartId: newStartId() }),
  ]);

  const winners = [[a, ra], [b, rb]].filter(([d]) => d.last('run_started') !== undefined);
  const losers = [[a, ra], [b, rb]].filter(([d]) => d.last('run_started') === undefined);
  assert.equal(winners.length, 1, 'both sessions were acknowledged');
  assert.equal(losers.length, 1);

  const [loser, loserResult] = losers[0];
  assert.equal(loserResult.ok, false);
  assert.equal(loserResult.reason, RESERVE_REFUSED.IN_PROGRESS);
  assert.equal(loser.last('mining_ready'), undefined, 'the losing session was told it was ready');
  const refusal = loser.last('simulation_unavailable');
  assert.ok(refusal, 'the losing session was told nothing');
  assert.equal(refusal.reason, RESERVE_REFUSED.IN_PROGRESS);

  // AND NO WORK WAS DONE TWICE. The refusal happened before verifier construction.
  const [winner] = winners[0];
  await winner.say(candidateFrom(winner, sim));
  assert.equal(sim.counters.serverWasmHashes, 1, 'the server hashed more than once');
  assert.equal(sim.counters.nativeHelperHashes, 1);
  assert.equal(sim.mockDaemon.counters.calcPow, 1);
  assert.equal(sim.mockDaemon.counters.prepareSubmission, 1);
  assert.equal(sim.mockDaemon.counters.dispatchSubmission, 1);
});

test('SIX sequential raw Starts produce one run, one generation and no subscriber growth', async () => {
  // THE WITNESS: six start_requests on one connection produced six run_started messages, six
  // mining_ready messages, intent generation 6, and six permanent fatal-latch subscribers.
  const { sim } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);

  const results = [];
  for (let i = 0; i < 6; i++) {
    results.push(await d.say({ type: 'start_request', clientStartId: newStartId() }));
  }

  assert.equal(d.all('run_started').length, 1, 'more than one acknowledgement');
  assert.equal(d.all('mining_ready').length, 1, 'more than one readiness');
  assert.equal(d.session.intent.generation, 1, 'a second run generation was minted');
  assert.equal(sim.latch.subscriberCount, 1, 'each Start left a permanent latch subscriber');
  assert.equal(results[0].ok, true);
  for (const r of results.slice(1)) {
    assert.equal(r.ok, false, 'a repeat Start was accepted');
    assert.equal(r.reason, RESERVE_REFUSED.IN_PROGRESS);
  }
  assert.equal(sim.counters.serverWasmHashes, 0, 'readiness alone hashed');

  // One run happened, and only one.
  await d.say(candidateFrom(d, sim));
  assert.equal(sim.counters.serverWasmHashes, 1);
  assert.equal(sim.mockDaemon.counters.dispatchSubmission, 1);
  assert.equal(sim.latch.subscriberCount, 0, 'the terminal run kept its subscription');
});

test('a byte-identical repeat Start is idempotent and mints nothing', async () => {
  const { sim } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  const startId = await start(d);
  const before = {
    generation: d.session.intent.generation,
    subscribers: sim.latch.subscriberCount,
    ...work(sim),
  };

  // The same attempt, sent again at three different points of its life.
  for (let i = 0; i < 3; i++) {
    const again = await d.say({ type: 'start_request', clientStartId: startId });
    assert.equal(again.ok, true, 'an identical repeat was refused');
    assert.equal(again.idempotent, true);
  }

  assert.equal(d.session.intent.generation, before.generation, 'a repeat rotated the generation');
  assert.equal(sim.latch.subscriberCount, before.subscribers, 'a repeat added a subscriber');
  assert.deepEqual(work(sim), { hashes: before.hashes, native: before.native,
    calcPow: before.calcPow, prepareSubmission: before.prepareSubmission,
    dispatchSubmission: before.dispatchSubmission, readback: before.readback,
    inMemoryTransportCalls: before.inMemoryTransportCalls, transportCalls: before.transportCalls });

  // It received the SAME acknowledgement again, not a new one.
  const acks = d.all('run_started');
  assert.equal(acks.length, 4, 'the repeat was not answered with the stored acknowledgement');
  for (const ack of acks) assert.deepEqual(ack, acks[0]);
  assert.equal(d.all('mining_ready').length, 4);
});

test('a repeat Start DURING initialization does not create a second anything', async () => {
  // The window between the synchronous acknowledgement and the verifier being ready.
  let releaseInit;
  const gate = new Promise((r) => { releaseInit = r; });
  const { base, helper } = buildScripted();
  const slow = {
    ...base,
    makeServerVerifier: async (opts) => { await gate; return base.makeServerVerifier(opts); },
  };
  const sim = track(createSimulationContext(slow));
  const d = driver(sim);
  await d.say(HELLO);

  const startId = newStartId();
  const first = d.say({ type: 'start_request', clientStartId: startId });
  // Same attempt, and a different one, both while initialization is still in flight.
  const repeat = await d.say({ type: 'start_request', clientStartId: startId });
  const other = await d.say({ type: 'start_request', clientStartId: newStartId() });
  assert.equal(repeat.ok, true);
  assert.equal(repeat.idempotent, true);
  assert.equal(other.ok, false);
  assert.equal(other.reason, RESERVE_REFUSED.IN_PROGRESS);
  assert.equal(sim.serverVerifierReady, false, 'a verifier appeared while initialization was gated');

  assert.equal(helper.log.spawned, 0, 'a helper was spawned while initialization was gated');

  releaseInit();
  await first;
  assert.equal(d.all('mining_ready').length, 1);
  assert.equal(d.session.intent.generation, 1);
  assert.equal(sim.latch.subscriberCount, 1);
  assert.equal(helper.log.spawned, 1, 'the repeat Start started a second helper');
  assert.equal(helper.log.inits.length, 1);
});

test('a Start after any terminal state is refused, whatever ended it', async () => {
  for (const [name, end] of [
    ['completed', async (d, sim) => { await d.say(candidateFrom(d, sim)); }],
    ['stopped', async (d) => { await d.say(stopFrom(d)); }],
    ['disposed', async (d) => { d.session.dispose(); }],
  ]) {
    const { sim } = makeSim();
    const d = driver(sim);
    await d.say(HELLO);
    await start(d);
    await end(d, sim);
    assert.equal(sim.attemptFinished, true, name);
    assert.equal(sim.state.completed, true, `${name}: completed stayed false after a terminal`);

    // Same session (where it still exists), and a completely fresh one.
    const fresh = driver(sim);
    await fresh.say(HELLO);
    assert.equal(fresh.last('server_hello').alreadyCompleted, true, name);
    const again = await fresh.say({ type: 'start_request', clientStartId: newStartId() });
    assert.equal(again.ok, false, name);
    assert.equal(again.reason, RESERVE_REFUSED.ALREADY_FINISHED, name);
    // A PRE-RUN REFUSAL, in its own closed schema: no run generation, no free text.
    const refusal = fresh.last('simulation_unavailable');
    assert.equal(refusal.runGeneration, null, name);
    assert.equal(refusal.reason, RESERVE_REFUSED.ALREADY_FINISHED, name);
    assert.equal('detail' in refusal, false, `${name}: a pre-run refusal carried free text`);
    assert.ok(SIM_TERMINAL_STATES.includes(refusal.attemptState), name);
  }
});

test('a PRE-RUN refusal has exactly its own closed schema', async () => {
  const { sim } = makeSim();
  const owner = driver(sim);
  await owner.say(HELLO);
  await start(owner);
  const other = driver(sim);
  await other.say(HELLO);
  const refusedId = newStartId();
  await other.say({ type: 'start_request', clientStartId: refusedId });

  const refusal = other.last('simulation_unavailable');
  assert.deepEqual(Object.keys(refusal).sort(), [
    'attemptState', 'clientStartId', 'issuanceId', 'jobId', 'reason', 'runGeneration', 'terminal', 'type', 'workerId',
  ]);
  assert.equal(refusal.clientStartId, refusedId, 'the refusal names a different Start');
  assert.equal(refusal.workerId, other.last('server_hello').workerId);
  assert.equal(refusal.jobId, sim.job.jobId);
  assert.equal(refusal.issuanceId, sim.job.issuanceId);
  assert.equal(refusal.runGeneration, null, 'a pre-run refusal named a run generation');
  assert.ok(SIM_PRE_RUN_REFUSALS.includes(refusal.reason));
  assert.ok(SIM_ATTEMPT_STATE_VALUES.includes(refusal.attemptState));
  assert.equal(refusal.attemptState, 'running');

  // Even the OWNER, sending a DIFFERENT Start while its own run is live, gets a null generation and
  // its new correlation token -- never its live run's binding.
  const ownerSecond = newStartId();
  await owner.say({ type: 'start_request', clientStartId: ownerSecond });
  const ownerRefusal = owner.last('simulation_unavailable');
  assert.equal(ownerRefusal.runGeneration, null);
  assert.equal(ownerRefusal.clientStartId, ownerSecond);
});

test('an initialization failure terminalizes the attempt and permits no later work', async () => {
  const { base } = buildScripted();
  const broken = track(createSimulationContext({
    ...base,
    makeServerVerifier: async () => { throw new Error('/home/someone/secret-path/libmeep.so is missing'); },
  }));
  const d = driver(broken);
  await d.say(HELLO);
  const r = await start(d);
  assert.ok(r);

  assert.equal(broken.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
  assert.equal(broken.serverVerifierReady, false);
  // A verifier that cannot start closes the process-wide latch: nothing may try again.
  assert.equal(broken.latch.tripped, true, 'an initialization failure did not latch');
  assert.equal(broken.latch.code, FATAL_CODES.VERIFIER_FAULT);
  assert.equal(d.last('simulation_unavailable').reason, 'verifier_unavailable');
  assert.equal(d.all('simulation_unavailable').length, 1);
  assert.equal(d.last('mining_ready'), undefined);
  assert.equal(broken.latch.subscriberCount, 0, 'the failed attempt kept its latch subscription');

  // NO RAW EXCEPTION MESSAGE REACHES THE AUDIT LOG. It used to be interpolated straight in.
  const auditJson = JSON.stringify(d.audits);
  assert.equal(auditJson.includes('secret-path'), false, 'a raw error message reached the audit log');
  assert.equal(auditJson.includes('libmeep.so'), false);
  assert.ok(d.audits.some((e) => e.kind === 'sim_verifier_unavailable' && e.category === 'verifier_init_failed'));
  // And the client learns a code, not a path.
  assert.equal(JSON.stringify(d.sent).includes('secret-path'), false);

  const again = await d.say({ type: 'start_request', clientStartId: newStartId() });
  assert.equal(again.ok, false);
  assert.equal(again.reason, RESERVE_REFUSED.ALREADY_FINISHED);
});

test('a dispatch failure or an unresolvable readback terminalizes the one attempt', async () => {
  // The other two ways an attempt can end. In each case the run publishes a terminal, the session
  // must carry it out to the client exactly once, and the process must not offer another attempt.
  const cases = [
    ['dispatch refused before any transport', (d) => ({
      ...d,
      prepareSubmission(hex) { return d.prepareSubmission(hex); },
      dispatchSubmission() {
        const e = new Error('injected: nothing was sent');
        e.definitelyNotSent = true;
        throw e;
      },
    })],
    ['a readback that names another block', (d) => ({
      ...d,
      async getBlockHeaderByHeight(height, opts) {
        const header = await d.getBlockHeaderByHeight(height, opts);
        return { ...header, hash: 'a'.repeat(64) };
      },
    })],
    ['a readback that cannot be obtained at all', (d) => ({
      ...d,
      async getBlockHeaderByHeight() { throw new Error('injected: readback unavailable'); },
    })],
  ];

  for (const [name, wrap] of cases) {
    const { base } = buildScripted();
    const sim = track(createSimulationContext({ ...base, mockDaemon: wrap(base.mockDaemon) }));
    const d = driver(sim);
    await d.say(HELLO);
    await start(d);
    const r = await d.say(candidateFrom(d, sim));

    assert.equal(r.ok, false, name);
    assert.equal(d.last('simulation_complete'), undefined, `${name}: reported success`);
    assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED, name);
    assert.equal(sim.state.completed, true, name);
    assert.equal(sim.latch.subscriberCount, 0, `${name}: kept its latch subscription`);
    assert.equal(d.all('simulation_failed').length, 1, `${name}: not exactly one terminal message`);
    assert.equal(d.session.intent.active, false, `${name}: intent survived`);

    // NO LATER WORK IS POSSIBLE, from this session or a fresh one.
    const again = await d.say({ type: 'start_request', clientStartId: newStartId() });
    assert.equal(again.reason, RESERVE_REFUSED.ALREADY_FINISHED, name);
    const fresh = driver(sim);
    await fresh.say(HELLO);
    assert.equal(
      (await fresh.say({ type: 'start_request', clientStartId: newStartId() })).reason,
      RESERVE_REFUSED.ALREADY_FINISHED,
      name,
    );
  }
});

// ================================================================== candidates and stops
test('a stale, cross-worker or wrong-issuance candidate costs zero work', async () => {
  const overrides = [
    ['wrong worker', { workerId: 'sim-someone-else' }],
    ['wrong issuance', { issuanceId: 'f'.repeat(32) }],
    ['wrong generation', { runGeneration: 99 }],
    ['wrong job', { jobId: 'realjob-elsewhere' }],
    ['wrong start correlation', { clientStartId: 'f'.repeat(32) }],
  ];
  for (const [name, over] of overrides) {
    const { sim } = makeSim();
    const d = driver(sim);
    await d.say(HELLO);
    await start(d);
    const before = work(sim);

    const r = await d.say(candidateFrom(d, sim, over));
    assert.equal(r.ok, false, name);
    assert.equal(sim.counters.serverWasmHashes, before.hashes, `${name}: hashed`);
    assert.equal(sim.counters.nativeHashRequests, before.native, `${name}: asked the native helper`);
    assert.equal(sim.mockDaemon.counters.dispatchSubmission, 0, `${name}: dispatched`);
  }
});

test('a candidate that NEVER ENTERED verification cannot spend the real attempt', async () => {
  // THE WITNESS: every candidate_rejected used to finish the attempt, so a forged, stale or
  // mismatched candidate -- refused cheaply, before any hashing -- spent the one attempt the real
  // candidate still needed.
  const cheap = [
    ['nonce outside the window', { nonce: nonceToHex(EXPECTED.nonce + 1) }, NONTERMINAL.NONCE_OUT_OF_WINDOW],
    ['wrong worker', { workerId: 'sim-someone-else' }, NONTERMINAL.UNKNOWN_WORKER],
    ['wrong issuance', { issuanceId: 'f'.repeat(32) }, NONTERMINAL.STALE_ISSUANCE],
    ['wrong generation', { runGeneration: 99 }, NONTERMINAL.STALE_GENERATION],
    ['wrong job', { jobId: 'realjob-elsewhere' }, NONTERMINAL.UNKNOWN_JOB],
  ];
  const { sim } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);

  for (const [name, over, reason] of cheap) {
    const r = await d.say(candidateFrom(d, sim, over));
    assert.equal(r.ok, false, name);
    assert.equal(r.entered, false, `${name}: reported as having entered verification`);
    assert.equal(r.reason, reason, name);
    const rejected = d.last('candidate_rejected');
    assert.equal(rejected.terminal, false, `${name}: a rejection claimed to be terminal`);
    // DIRECT STATE: the attempt is exactly as it was.
    assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.RUNNING, `${name}: the attempt changed state`);
    assert.equal(sim.attemptFinished, false, name);
    assert.equal(sim.state.completed, false, name);
    assert.equal(d.session.intent.active, true, `${name}: intent was revoked`);
    assert.equal(sim.latch.subscriberCount, 1, name);
    assert.equal(sim.authority.anyClaimed, false, name);
    assert.equal(d.last('simulation_failed'), undefined, `${name}: the attempt was ended`);
    assert.deepEqual(work(sim), {
      hashes: 0, native: 0, calcPow: 0, prepareSubmission: 0, dispatchSubmission: 0, readback: 0,
      inMemoryTransportCalls: 0, transportCalls: 0,
    }, `${name}: cost work`);
  }

  // And the REAL candidate still completes the attempt afterwards.
  const good = await d.say(candidateFrom(d, sim));
  assert.equal(good.ok, true, 'the forged candidates spent the real attempt');
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
});

test('the ONE issued candidate refused AFTER entering verification does end the attempt', async () => {
  // calc_pow unavailable is a refusal of the real candidate after both Wasm and the native path
  // agreed. Nothing else can succeed in a one-nonce attempt, so it is terminal.
  const { base } = buildScripted();
  const flaky = { ...base.mockDaemon, async calcPow() { throw new Error('injected: calc_pow unavailable'); } };
  const sim = track(createSimulationContext({ ...base, mockDaemon: flaky }));
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);

  const r = await d.say(candidateFrom(d, sim));
  assert.equal(r.ok, false);
  assert.equal(r.entered, true);
  assert.equal(r.reason, NONTERMINAL.DAEMON_UNAVAILABLE);
  assert.equal(d.last('candidate_rejected').terminal, false, 'the rejection itself claimed terminality');
  const failed = d.last('simulation_failed');
  assert.ok(failed, 'the attempt stayed live after its only real candidate was refused');
  assert.equal(failed.terminal, true);
  assert.equal(failed.reason, NONTERMINAL.DAEMON_UNAVAILABLE);
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
  assert.equal(d.session.intent.active, false);
  assert.equal(sim.latch.subscriberCount, 0);
  assert.equal(d.all('simulation_failed').length, 1);
});

test('every failure code the server can emit is in the page\'s closed vocabulary', () => {
  const emittable = [
    ...Object.values(TERMINAL).filter((c) => c !== TERMINAL.VERIFIED_COMPLETE),
    NONTERMINAL.ABOVE_TARGET, NONTERMINAL.DAEMON_UNAVAILABLE,
    NONTERMINAL.ALREADY_CLAIMED, NONTERMINAL.ISSUANCE_SUPERSEDED,
    'verifier_unavailable',
    'candidate_limit_reached', 'search_deadline_exceeded',
    'p2p_propagation_failed', 'verifier_release_unconfirmed', 'next_template_refused',
    'external_tip_superseded', 'tip_observation_failed', 'canonical_parent_changed',
  ];
  for (const code of emittable) {
    assert.ok(SIM_FAILURE_CODES.includes(code), `${code} would be shown as unrecognised`);
  }
  for (const reason of Object.values(RESERVE_REFUSED)) {
    assert.ok(SIM_PRE_RUN_REFUSALS.includes(reason), `${reason} is not in the pre-run schema`);
  }
  for (const state of Object.values(SIM_ATTEMPT_STATES)) {
    assert.ok(SIM_ATTEMPT_STATE_VALUES.includes(state), `${state} is not in the closed state set`);
  }
});

test('audit entries are BUILT from an allowlist; no dependency-controlled string reaches them', async () => {
  // A thrown object controls its own message, name, stack and constructor. None of them may appear.
  const hostile = new Error('/home/someone/.wallet/seed words here');
  hostile.name = 'https://attacker.example/?token=abc';
  const { base } = buildScripted();
  const sim = track(createSimulationContext({ ...base, makeServerVerifier: async () => { throw hostile; } }));
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);
  const json = JSON.stringify(d.audits);
  for (const leak of ['wallet', 'seed words', 'attacker.example', 'token=abc', 'stack', 'Error']) {
    assert.equal(json.includes(leak), false, `${leak} reached the audit log`);
  }
  const ALLOWED = new Set(['kind', 'workerId', 'reason', 'state', 'category', 'accepted', 'terminal', 'entered']);
  for (const entry of d.audits) {
    for (const key of Object.keys(entry)) assert.ok(ALLOWED.has(key), `unexpected audit field ${key}`);
    assert.match(entry.workerId ?? 'sim-1-00000000', /^sim-[0-9]{1,9}-[0-9a-f]{8}$/);
  }
});

test('a duplicate or post-terminal candidate causes no additional work', async () => {
  const { sim } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);
  await d.say(candidateFrom(d, sim));

  const after = work(sim);
  const runScopedBefore = d.sent.filter((m) => m.type !== 'error').length;

  const again = await d.say(candidateFrom(d, sim));
  assert.equal(again.ok, false);
  assert.equal(sim.counters.serverWasmHashes, after.hashes, 'a post-terminal candidate hashed');
  assert.equal(sim.mockDaemon.counters.dispatchSubmission, after.dispatchSubmission);
  // It is answered -- being told the attempt is over beats silence -- but it changes NOTHING:
  // no run-scoped event, no second terminal, no counter movement.
  assert.equal(d.sent.filter((m) => m.type !== 'error').length, runScopedBefore,
    'a post-terminal candidate emitted a run-scoped message');
  assert.equal(d.all('simulation_complete').length, 1);
  assert.equal(d.sent.at(-1).type, 'error');
});

test('Stop revokes server-side intent and prevents any later dispatch', async () => {
  const { sim } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);

  const stopped = await d.say(stopFrom(d));
  assert.equal(stopped.accepted, true);
  assert.equal(d.session.intent.active, false, 'Stop did not revoke server-side intent');
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(sim.latch.subscriberCount, 0);
  assert.equal(d.last('simulation_stopped').clientStartId, d.last('run_started').clientStartId);

  const late = await d.say(candidateFrom(d, sim));
  assert.equal(late.ok, false);
  assert.equal(sim.mockDaemon.counters.dispatchSubmission, 0, 'a late candidate dispatched after Stop');
  assert.equal(d.last('simulation_complete'), undefined);
});

test('a stop naming another issuance, worker or attempt is refused', async () => {
  const { sim } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);
  for (const over of [
    { workerId: 'sim-other' },
    { issuanceId: 'a'.repeat(32) },
    { jobId: 'realjob-x' },
    { clientStartId: 'b'.repeat(32) },
  ]) {
    const r = await d.say(stopFrom(d, over));
    assert.equal(r.ok, false, JSON.stringify(over));
    assert.equal(d.session.intent.active, true, `${JSON.stringify(over)} revoked the run`);
    assert.equal(sim.attemptFinished, false, JSON.stringify(over));
  }
  // A stale generation is refused as a revocation, and the run stays live.
  const started = d.last('run_started');
  const stale = await d.say(stopFrom(d, { runGeneration: started.runGeneration + 5 }));
  assert.equal(stale.accepted, false);
  assert.equal(d.session.intent.active, true);
});

test('session disposal revokes run intent and releases the attempt', async () => {
  const { sim } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);
  assert.equal(d.session.intent.active, true);
  assert.equal(sim.latch.subscriberCount, 1);

  d.session.dispose();
  assert.equal(d.session.intent.active, false, 'a closed session left run intent armed');
  assert.equal(d.session.intent.revokedReason, 'session_dispose');
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
  assert.equal(sim.latch.subscriberCount, 0, 'a disposed session left a latch subscriber behind');
});

test('TWO SESSIONS cannot both reach a dispatch', async () => {
  const { sim } = makeSim();
  const a = driver(sim);
  const b = driver(sim);
  await a.say(HELLO);
  await b.say(HELLO);
  await a.say({ type: 'start_request', clientStartId: newStartId() });
  await b.say({ type: 'start_request', clientStartId: newStartId() });

  // Only one of them can even build a candidate; the other never got an acknowledgement.
  const acknowledged = [a, b].filter((d) => d.last('run_started') !== undefined);
  assert.equal(acknowledged.length, 1);
  await acknowledged[0].say(candidateFrom(acknowledged[0], sim));
  assert.equal(sim.mockDaemon.counters.dispatchSubmission, 1);
  assert.equal(sim.authority.anyClaimed, true);
});

test('the synthetic submit_share message is refused in simulation mode', async () => {
  const { sim } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);
  const r = await d.say({ type: 'submit_share', jobId: 'j', workerId: 'w', nonce: '00000001' });
  assert.equal(r.ok, false);
  assert.equal(sim.mockDaemon.counters.dispatchSubmission, 0);
});

// ================================================================== the two pretend components
test('the strict oracles refuse anything but the recorded values', async () => {
  const { base } = makeSim();
  // A nonce the recorded row does not cover.
  await assert.rejects(() => base.oracle.hashOne(EXPECTED.nonce + 1), /nonce/);
  // A calc_pow request with the wrong seed, height or blob.
  const good = {
    majorVersion: 16, height: String(EXPECTED.height),
    blockBlobHex: base.row.block_hashing_blob, seedHashHex: base.row.delayed_seed_input,
  };
  assert.equal(await base.mockDaemon.calcPow(good), EXPECTED.powHash);
  for (const over of [
    { majorVersion: 15 }, { height: '2112' },
    { seedHashHex: 'a'.repeat(64) }, { blockBlobHex: 'deadbeef' },
  ]) {
    await assert.rejects(() => base.mockDaemon.calcPow({ ...good, ...over }), /recorded vector/,
      JSON.stringify(over));
  }
  // A full block that is not the recorded one.
  assert.throws(() => base.mockDaemon.prepareSubmission('deadbeef'), /recorded vector/);
  // And a readback that was not asked for a pow hash.
  await assert.rejects(() => base.mockDaemon.getBlockHeaderByHeight(String(EXPECTED.height), { fillPowHash: false }),
    /fill_pow_hash/);
});

test('the oracle answers NOTHING until it is bound to the exact job', async () => {
  const row = loadRecordedRow();
  const unbound = createRecordedOracle(row);
  assert.equal(unbound.bound, false);
  await assert.rejects(() => unbound.hashOne(EXPECTED.nonce), /before the oracle was bound/);
  assert.equal(unbound.calls, 0, 'an unbound oracle counted a call');

  // And a mock daemon whose oracle is unbound refuses every kind of work.
  const daemon = createMockDaemon(row, { oracle: unbound });
  await assert.rejects(() => daemon.calcPow({
    majorVersion: 16, height: String(EXPECTED.height),
    blockBlobHex: row.block_hashing_blob, seedHashHex: row.delayed_seed_input,
  }), /before the oracle was bound/);
  assert.throws(() => daemon.prepareSubmission(row.full_block_blob), /before the oracle was bound/);
  await assert.rejects(() => daemon.getBlockHeaderByHeight(String(EXPECTED.height)),
    /before the oracle was bound/);
  assert.deepEqual(daemon.counters,
    {
      calcPow: 0, prepareSubmission: 0, dispatchSubmission: 0, readback: 0, inMemoryTransportCalls: 0, transportCalls: 0,
    });
});

test('binding checks the height, seed, epoch key, template, nonce and expected hash', async () => {
  const row = loadRecordedRow();
  const { base } = makeSim();
  assert.equal(base.oracle.bound, true);
  assert.equal(base.oracle.context.height, EXPECTED.height);
  assert.equal(base.oracle.context.epochKeyHex, row.epoch_key);
  assert.equal(base.oracle.context.seedHashHex, row.delayed_seed_input);
  assert.equal(base.oracle.context.templateHex, row.blob_nonce_zeroed);
  assert.equal(base.oracle.context.nonce, EXPECTED.nonce);
  assert.equal(base.oracle.context.expectedHashHexLE, EXPECTED.powHash);

  // A job describing a DIFFERENT block cannot bind this row's oracle, so the recorded answer can
  // never be handed to a run that is not about this block.
  const otherRow = loadRecordedRow({ height: 0 });
  const { base: otherSim } = buildScripted();
  const wrong = createRecordedOracle(otherRow);
  assert.throws(() => wrong.bindTo(otherSim.job), /recorded vector/);
  // Nor can a non-job.
  assert.throws(() => createRecordedOracle(row).bindTo({ kind: 'synthetic' }), /job kind/);
});

test('the mock daemon\'s submit path IS the real adapter, over an in-memory transport', async () => {
  const { base } = makeSim();
  const row = loadRecordedRow();
  const proofs = submissionProofs(base.mockDaemon.submissionAdapter);
  assert.ok(proofs, 'the mock daemon does not name a genuine adapter');
  const operation = Object.freeze({});
  const capability = base.mockDaemon.prepareSubmission(row.full_block_blob, operation);
  assert.deepEqual(Object.keys(capability), ['kind']);
  assert.equal(JSON.stringify(capability).includes(row.full_block_blob), false);
  assert.equal(proofs.capabilityFor(operation, capability, row.full_block_blob), true);

  const sent = base.mockDaemon.dispatchSubmission(capability);
  // AUTHENTICATED by the adapter's own private state, for THIS operation.
  const record = proofs.dispatchFor(operation, sent);
  assert.ok(record, 'the mock daemon produced an unauthenticated dispatch handle');
  const receipt = await record.receipt;
  assert.equal(proofs.receiptFor(record, receipt), true);
  assert.equal((await record.outcome).blockId, EXPECTED.blockHash);
  assert.equal(base.mockDaemon.counters.inMemoryTransportCalls, 1);
  assert.equal(base.mockDaemon.counters.transportCalls, 0, 'a REAL transport was used');

  // One use only, and not transferable -- refused by the adapter before any transport.
  for (const bad of [capability, { kind: 'meepcoin-prepared-submission' }]) {
    let thrown = null;
    try { base.mockDaemon.dispatchSubmission(bad); } catch (e) { thrown = e; }
    assert.ok(thrown);
    // Neither refusal is proof that THIS operation was never sent: it was.
    assert.equal(proofs.notSentFor(operation, thrown), false);
  }
  assert.equal(base.mockDaemon.counters.inMemoryTransportCalls, 1);
});

// ================================================================== the live native helper path
test('GUARD: no test in this file can build a simulation that launches the real helper', () => {
  // CODE only: line comments and single-quoted strings are removed before looking for call sites,
  // so this guard's own prose and messages cannot trip it.
  const code = readFileSync(fileURLToPath(import.meta.url), 'utf8')
    .split('\n')
    .map((line) => line.replace(/\/\/.*$/, '').replace(/'[^']*'/g, "''"))
    .join('\n');
  const calls = code.match(/buildRecordedSimulationWithRealHelper\(/g) ?? [];
  assert.equal(calls.length, 1, 'the real builder is called outside buildScripted()');
  const bare = code.replace(/buildRecordedSimulationWithRealHelper/g, '').match(/\bbuildRecordedSimulation\(/g) ?? [];
  assert.equal(bare.length, 0, 'a bare builder call would reach the real WSL helper');
  const { helperOptions } = scriptedHelper();
  assert.equal(helperOptions.useWsl, false);
  assert.equal(typeof helperOptions.spawnFn, 'function');
});

test('the helper INIT carries EXACTLY the server-created job context, and nothing from a client', async () => {
  const { sim, helper } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);

  assert.equal(helper.log.spawned, 1);
  assert.equal(helper.log.inits.length, 1);
  const [, , epochKeyHex, seedHashHex, height, templateHex] = helper.log.inits[0];
  const row = loadRecordedRow();
  assert.equal(epochKeyHex, row.epoch_key);
  assert.equal(seedHashHex, row.delayed_seed_input);
  assert.equal(height, '2113');
  assert.equal(templateHex, row.blob_nonce_zeroed);
  // And it is derived from the job's PRIVATE bytes, not from anything the page was sent.
  assert.equal(templateHex, blobToHex(hashingTemplateOf(sim.job)));
  assert.deepEqual({ ...sim.verifier.context }, { ...sim.recordedContext });
  // The contextual Wasm build was initialised with the same context object.
  assert.equal(sim.recordedContext.height, '2113');
  // No HASH before a candidate exists.
  assert.equal(helper.log.hashes.length, 0);
  // Readiness reports the helper's own validated allocation, separately from Wasm memory.
  const ready = d.last('mining_ready');
  assert.equal(ready.nativeDatasetBytes, 33_554_432);
  assert.equal(ready.nativeScratchBytes, 8_388_608);
  assert.equal(ready.verifierNativeAlgorithmBytes, 33_554_432 + 8_388_608);
  assert.ok(ready.verifierWasmHeapBytes > 0);
});

test('a NATIVE DISAGREEMENT latches the process, ends the attempt once, and never reaches the daemon', async () => {
  const wrong = 'a'.repeat(64);
  const { sim, helper } = makeSim({}, scriptedHelper({ hashHex: wrong }));
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);
  const r = await d.say(candidateFrom(d, sim));

  assert.equal(r.ok, false);
  assert.equal(helper.log.hashes.length, 1, 'exactly one HASH was still sent');
  assert.equal(sim.latch.tripped, true, 'a native disagreement did not latch');
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
  assert.equal(d.all('simulation_failed').length, 1, 'not exactly one terminal failure');
  assert.equal(d.last('simulation_complete'), undefined);
  assert.equal(sim.mockDaemon.counters.calcPow, 0, 'the mock-daemon stage ran after a disagreement');
  assert.equal(sim.mockDaemon.counters.dispatchSubmission, 0);
  assert.equal(sim.verifier.healthy, false, 'the verifier itself was not failed');
  // No further attempt on this process.
  const fresh = driver(sim);
  await fresh.say(HELLO);
  const refused = await fresh.say({ type: 'start_request', clientStartId: newStartId() });
  assert.equal(refused.ok, false);
});

test('a helper that DIES WHILE IDLE after readiness ends the attempt with one truthful failure', async () => {
  const { sim, helper } = makeSim();
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);
  assert.ok(d.last('mining_ready'));

  // The child exits on its own, with nothing outstanding.
  helper.log.children[0].exitNow(9, null);
  await waitFor(() => sim.latch.tripped, 'the idle crash to reach the latch');

  assert.equal(sim.latch.code, FATAL_CODES.VERIFIER_FAULT);
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
  const failed = d.last('simulation_failed');
  assert.ok(failed, 'an idle helper death told the page nothing');
  assert.equal(failed.reason, 'fatal_verifier');
  assert.equal(failed.terminal, true);
  assert.equal(d.all('simulation_failed').length, 1);
  assert.equal(d.session.intent.active, false);

  // A late candidate does no work, and the mock daemon never runs.
  await d.say(candidateFrom(d, sim));
  assert.equal(helper.log.hashes.length, 0);
  assert.equal(sim.counters.serverWasmHashes, 0);
  assert.equal(sim.mockDaemon.counters.calcPow, 0);
});

test('a STALE HELPER (different source identity) is refused before INIT and latches', async () => {
  const { sim, helper } = makeSim({}, scriptedHelper({ sourceId: 'f'.repeat(64) }));
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);

  assert.equal(helper.log.spawned, 1);
  assert.equal(helper.log.inits.length, 0, 'a stale helper was sent INIT');
  assert.equal(helper.log.hashes.length, 0);
  assert.equal(sim.verifier, null);
  assert.equal(sim.latch.tripped, true);
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
  assert.equal(d.last('simulation_unavailable').reason, 'verifier_unavailable');
  assert.equal(d.last('mining_ready'), undefined);
  // The child it did start is not lost: the startup handed it back and it was released.
  await waitFor(() => helper.log.children[0].exited, 'the refused helper to be reaped');
});

test('a helper whose INIT reports the wrong allocation is refused and latches', async () => {
  const { sim, helper } = makeSim({}, scriptedHelper({ readyBytes: [1024, 1024] }));
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);
  assert.equal(helper.log.inits.length, 1);
  assert.equal(helper.log.hashes.length, 0);
  assert.equal(sim.latch.tripped, true);
  assert.equal(sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_FAILED);
  assert.equal(d.last('mining_ready'), undefined);
});

test('the context parameter is validated before anything is spawned, and refuses the synthetic self-test', async () => {
  const helper = scriptedHelper();
  const good = buildScripted(helper).base.recordedContext;
  const common = { helperPath: process.execPath, helperOptions: helper.helperOptions };
  for (const [name, context] of [
    ['short epoch key', { ...good, epochKeyHex: 'ab' }],
    ['uppercase seed', { ...good, seedHashHex: good.seedHashHex.toUpperCase() }],
    ['numeric height', { ...good, height: 2113 }],
    ['non-canonical height', { ...good, height: '02113' }],
    ['odd template', { ...good, templateHex: 'abc' }],
    ['oversized template', { ...good, templateHex: 'ab'.repeat(2049) }],
  ]) {
    await assert.rejects(() => createDualVerifier({ ...common, context, selfTestNonces: [] }),
      /context\./, name);
  }
  await assert.rejects(() => createDualVerifier({ ...common, context: good }), /self-test/);
  assert.equal(helper.log.spawned, 0, 'a refused context still spawned a helper');
});

test('shutdown DURING helper initialization settles fail-closed and leaves nothing unreleased', async () => {
  const { sim, helper } = makeSim({}, scriptedHelper({ stallInit: true }));
  const d = driver(sim);
  await d.say(HELLO);
  const starting = d.say({ type: 'start_request', clientStartId: newStartId() });
  await waitFor(() => helper.log.inits.length === 1, 'INIT to be sent');

  // Phase 1: cancellation BEFORE any drain. The stalled INIT must settle, not hold shutdown open.
  sim.beginClose('pool shutting down');
  const result = await starting;
  assert.equal(result.ok, false);
  // A cancellation is not a fault.
  assert.equal(sim.latch.tripped, false, 'an ordinary shutdown latched the verifier as faulty');
  // Every resource the failed startup produced was adopted, and every one is released.
  for (const r of sim.createdResources) {
    if (!r.closed) await r.close('pool shutting down').catch(() => r.forceClose('escalation'));
    assert.equal(r.closed, true, 'a resource from the cancelled startup is unreleased');
  }
  await waitFor(() => helper.log.children.every((c) => c.exited), 'the helper child to exit');
});

test('the simulation hands every resource it creates to the owner graph the moment it exists', async () => {
  const owned = [];
  const { base, helper } = buildScripted();
  const sim = track(createSimulationContext({ ...base, ownResource: (label, r) => owned.push({ label, r }) }));
  const d = driver(sim);
  await d.say(HELLO);
  await start(d);
  assert.equal(owned.length, 1);
  assert.equal(owned[0].label, 'simulation verifier');
  assert.equal(owned[0].r, sim.verifier);
  assert.equal(helper.log.spawned, 1);

  // And release is confirmed by the resource itself, through the existing QUIT/BYE/exit path.
  sim.beginClose('pool shutting down');
  await sim.verifier.close('pool shutting down');
  assert.equal(sim.verifier.closed, true);
  assert.equal(helper.log.lines.at(-1), 'QUIT');
  assert.equal(helper.log.children[0].exited, true);
});

// ================================================================== server startup order
test('an unknown pool mode is refused, and never falls through to synthetic', async () => {
  // THE WITNESS: `mode` was only ever compared against the simulation constant, so a typo silently
  // ran the synthetic pool while the caller believed it had asked for a simulation.
  for (const mode of ['simluation', 'recorded-template-simulaton', 'SYNTHETIC', '', null, 0, {}]) {
    await assert.rejects(
      () => startDevPool({ host: '127.0.0.1', port: 0, mode }),
      /unknown pool mode/,
      JSON.stringify(mode),
    );
  }
});

test('a simulation that cannot be built leaves NO listener behind', async () => {
  // THE WITNESS: the simulation was constructed after listen(), so a bad vector file left a live
  // listener with nothing reachable behind it.
  const servers = () => process.getActiveResourcesInfo().filter((r) => r === 'TCPSERVERWRAP').length;
  const before = servers();
  await assert.rejects(
    () => startDevPool({
      host: '127.0.0.1',
      port: 0,
      mode: SIM_MODE,
      simulationFactory: () => { throw new RecordedVectorError('injected vector failure'); },
    }),
    /injected vector failure/,
  );
  assert.equal(servers(), before, 'a failed startup left a listening socket open');
});
