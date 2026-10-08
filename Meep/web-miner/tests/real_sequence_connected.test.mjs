// THE TWO-BLOCK SESSION, CONNECTED: the real page controller, the real server session and block runs,
// and the real Worker dispatcher, wired together in-process. The daemons are in_memory_chain.mjs's
// in-memory pair; the verifiers and the Worker's hasher are context-bound stand-ins that return each
// height's proof-of-work at that height's winning nonce.
//
// What this adds beyond each side's own tests: the two sides agree on every message of the rotation, and
// the browser-side rules (one Worker, re-contextualised only after its search settled and the next run is
// ready, stale messages inert, Stop / hidden / pagehide / socket loss end everything) hold against the
// real server rather than against hand-written frames.
//
// No browser, socket, listener, WSL, Docker, daemon or helper.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createMiningController, STATES } from '../lib/controller.js';
import { createWorkerCore } from '../lib/worker_core.js';
import { searchNonces } from '../lib/shared/search.js';
import { bytesToHex, hexToBytes, nonceToHex } from '../lib/shared/target.js';
import { REAL_P2P_SEQUENCE_PROFILE, SIM_ATTEMPT_STATES, createSimulationContext, createSimulationSession, realSequenceShareProfile } from '../../pool/dev/sim_session.mjs';
import { MAX_256, bigIntToLeBytes32 } from '../../pool/dev/difficulty.mjs';
import { buildScriptedChain, powFor } from '../../pool/dev/tests/in_memory_chain.mjs';

const WINNER = { 1: 11, 2: 22 };
const SHARE_WINNER = { 1: 3, 2: 5 };
const SHARE_ONLY = bigIntToLeBytes32(MAX_256 / 100n); // difficulty 50 share, not difficulty 500 block

/** Let every queued microtask and immediate run until the system is quiet. */
async function settle(rounds = 60) {
  for (let i = 0; i < rounds; i++) await new Promise((r) => setImmediate(r));
}

async function connectedSession({ chainOptions = {}, buildOptions = {}, holdSecondSearch = false, shareWork = false } = {}) {
  const chain = await buildScriptedChain(chainOptions, {
    ...buildOptions, ...(shareWork ? { shareDifficulty: 50 } : {}),
  });
  const sim = createSimulationContext({ ...chain.built, profile: shareWork ? realSequenceShareProfile(2) : REAL_P2P_SEQUENCE_PROFILE, now: () => chain.clock.ms });
  const answerFor = (height, nonce) => nonce === SHARE_WINNER[height]
    ? hexToBytes(powFor(height))
    : (nonce === 1 || nonce === 2 ? SHARE_ONLY.slice() : new Uint8Array(32).fill(0xff));
  const scripted = new Set();
  const scriptVerifiers = () => {
    if (!shareWork) return;
    for (const v of chain.journal.created) {
      if (scripted.has(v)) continue;
      scripted.add(v);
      const height = Number(v.context.height);
      v.hashWasm = async (nonce) => { v.counters.wasmShareHashes += 1; return answerFor(height, nonce); };
      v.hashNative = async (nonce) => { v.counters.nativeShareHashes += 1; return answerFor(height, nonce); };
    }
  };
  const serverSent = [];
  const worker = { core: null, page: null, posted: [], held: [], terminated: 0, hashers: [], modules: 0 };
  let socket = null;
  let session = null;

  const controller = createMiningController({
    createSocket: () => {
      socket = {
        onopen: null, onmessage: null, onclose: null, onerror: null, closed: 0, sent: [],
        send(text) {
          this.sent.push(JSON.parse(text));
          session.handleRaw(Buffer.byteLength(text), text);
        },
        close() { this.closed += 1; },
      };
      session = createSimulationSession({
        sim,
        now: () => chain.clock.ms,
        send: (obj) => {
          scriptVerifiers();
          serverSent.push(obj);
          queueMicrotask(() => socket.onmessage?.({ data: JSON.stringify(obj) }));
        },
        setTimer: () => ({}),
        clearTimer: () => {},
      });
      queueMicrotask(() => socket.onopen?.());
      return socket;
    },
    createWorker: () => {
      const w = {
        onmessage: null, onerror: null,
        postMessage(m) {
          worker.posted.push(m);
          if (holdSecondSearch && m.cmd === 'search' && worker.posted.filter((x) => x.cmd === 'search').length === 2) {
            worker.held.push(m);
            return;
          }
          queueMicrotask(() => { if (!w.dead) worker.core.handle(m); });
        },
        terminate() { worker.terminated += 1; w.dead = true; },
      };
      worker.page = w;
      worker.release = () => { for (const m of worker.held.splice(0)) queueMicrotask(() => { if (!w.dead) worker.core.handle(m); }); };
      const module = { active: null };
      worker.core = createWorkerCore({
        createModule: () => { worker.modules += 1; return module; },
        createV2Hasher: async () => { throw new Error('no synthetic hasher'); },
        createV2HasherForContext: async (factory, ctx) => {
          const M = await factory();
          const id = worker.hashers.length + 1;
          M.active = id;
          const height = String(ctx.height);
          let freed = false;
          const h = {
            calls: 0,
            hashOne(nonce) {
              if (freed || M.active !== id) throw new Error('inactive context hashed');
              this.calls += 1;
              return shareWork ? answerFor(Number(height), nonce)
                : (nonce === WINNER[height] ? hexToBytes(powFor(height)) : new Uint8Array(32).fill(0xff));
            },
            get hashCalls() { return this.calls; },
            wasmHeapBytes: () => 48_562_176,
            isActive: () => !freed && M.active === id,
            free() { freed = true; if (M.active === id) M.active = null; },
          };
          worker.hashers.push(h);
          return h;
        },
        searchNonces: (o) => searchNonces({ ...o, yieldFn: () => Promise.resolve() }),
        hexToBytes,
        bytesToHex,
        nonceToHex,
        postMessage: (m) => queueMicrotask(() => { if (!w.dead) w.onmessage?.({ data: m }); }),
      });
      return w;
    },
  });
  controller.connect('ws://127.0.0.1:1/ws');
  await settle();
  return { chain, sim, controller, worker, serverSent, get socket() { return socket; }, get session() { return session; } };
}

const types = (sent) => sent.map((m) => m.type);

test('CONNECTED: one Start, one Worker, two consecutive blocks accepted by A and shown by B, browser agreement for both', async () => {
  const c = await connectedSession();
  assert.equal(c.controller.snapshot().realSequenceTotal, 2);
  assert.equal(c.controller.workersCreated, 0, 'a Worker existed before Start');
  assert.equal(c.controller.start(), true);
  await settle(400);

  const s = c.controller.snapshot();
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE, JSON.stringify(types(c.serverSent)));
  assert.equal(s.simComplete, true);
  assert.equal(s.realSequenceComplete, true);
  assert.equal(s.simBrowserMatched, true, JSON.stringify(s.realBlocks));
  assert.deepEqual(s.realBlocks.map((b) => [b.block, b.height, b.nonce, b.browserMatched, b.attempts]), [[1, '1', 11, true, 12], [2, '2', 22, true, 23]]);
  assert.deepEqual(s.realBlocks.map((b) => [b.browserNonce, b.browserHashHexLE]),
    [[11, powFor(1)], [22, powFor(2)]], 'rotation lost the first height browser evidence');
  assert.equal(s.realTotalAttempts, 35);
  assert.equal(s.realStaleWorkerMessages, 0);
  // ONE Worker, TWO contexts on ONE module, the first freed before the second.
  assert.equal(c.controller.workersCreated, 1);
  assert.equal(c.worker.core.contextsBuilt, 2);
  assert.equal(c.worker.modules, 1);
  assert.equal(c.worker.hashers[0].isActive(), false);
  assert.deepEqual(s.realWorkerContexts.map((x) => [x.contextIndex, x.moduleInstances, x.rotated, x.priorContextActive]),
    [[1, 1, false, null], [2, 1, true, false]]);
  assert.deepEqual(c.worker.posted.map((m) => m.cmd), ['init_search', 'search', 'init_search_next', 'search', 'stop']);
  // Exactly one candidate and one submission per height; B was only read.
  assert.deepEqual(c.socket.sent.filter((m) => m.type === 'submit_real_candidate').map((m) => parseInt(m.nonce, 16)), [11, 22]);
  assert.equal(c.chain.net.log.submitBodies.length, 2);
  assert.equal(c.chain.net.counts.A.get_block_template, 2);
  assert.deepEqual(c.chain.net.log.bWrites, []);
  assert.deepEqual(c.chain.net.blocksB.map((b) => b.hash), c.chain.net.blocksA.map((b) => b.hash));
  // One Start, and the page is done: no second Start for this server process.
  assert.equal(types(c.socket.sent).filter((t) => t === 'start_request').length, 1);
  assert.equal(c.controller.start(), false);
});

test('CONNECTED SHARE SEQUENCE: one Start checks ordinary shares at both heights and submits only two blocks', async () => {
  const c = await connectedSession({ shareWork: true });
  assert.equal(c.controller.workersCreated, 0);
  assert.equal(c.controller.start(), true);
  await settle(600);

  const s = c.controller.snapshot();
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE, JSON.stringify(types(c.serverSent)));
  assert.equal(s.realSequenceComplete, true);
  assert.equal(s.realSharesAccepted, 4);
  assert.deepEqual(s.realBlocks.map((b) => [b.browserNonce, b.browserHashHexLE]),
    [[3, powFor(1)], [5, powFor(2)]], 'share-mode rotation lost per-height browser evidence');
  assert.deepEqual(c.serverSent.filter((m) => m.type === 'share_accepted').map((m) => [m.sequenceIndex, m.sharesAccepted, m.sharesAcceptedTotal]),
    [[1, 1, 1], [1, 2, 2], [2, 1, 3], [2, 2, 4]]);
  const [first, second] = c.serverSent.filter((m) => m.type === 'mining_ready').map((m) => m.jobId);
  assert.deepEqual(c.socket.sent.filter((m) => m.type === 'submit_real_candidate').map((m) => [m.jobId, parseInt(m.nonce, 16)]),
    [[first, 1], [first, 2], [first, 3], [second, 1], [second, 2], [second, 5]]);
  assert.equal(c.chain.net.log.calcPow.length, 2, 'an ordinary share reached daemon A');
  assert.equal(c.chain.net.log.submitBodies.length, 2, 'a block was submitted more than once');
  assert.deepEqual(c.chain.net.log.bWrites, []);
  assert.equal(c.controller.workersCreated, 1);
  assert.equal(c.worker.core.contextsBuilt, 2);
  assert.equal(c.worker.modules, 1);
  assert.equal(types(c.socket.sent).filter((t) => t === 'start_request').length, 1);
});

/** Run until the rotation is paused at `pause`, apply `act`, release, and settle. */
async function interrupted({ pause, act }) {
  let release;
  const gate = new Promise((r) => { release = r; });
  let paused;
  const atPause = new Promise((r) => { paused = r; });
  const chainOptions = {};
  const buildOptions = {};
  if (pause === 'propagation') {
    let armed = true;
    chainOptions.gate = async (method, n, side, chain) => {
      if (armed && side === 'B' && method === 'get_last_block_header' && chain.blocksA.length === 2) { armed = false; paused(); await gate; }
    };
  } else if (pause === 'next_verifier') {
    buildOptions.makeVerifierGate = async (n) => { if (n === 2) { paused(); await gate; } };
  }
  const c = await connectedSession({ chainOptions, buildOptions });
  c.controller.start();
  await Promise.race([atPause, settle(400)]);
  await settle();
  act(c);
  await settle();
  release();
  await settle(400);
  return c;
}

for (const [name, act, expectState] of [
  ['Stop', (c) => c.controller.stop(), STATES.STOPPED],
  ['a hidden tab', (c) => c.controller.setHidden(true), STATES.STOPPED_HIDDEN],
  ['pagehide', (c) => c.controller.teardown(), STATES.STOPPED],
  ['socket loss', (c) => { c.session.dispose(); c.socket.onclose?.(); }, STATES.ERROR],
]) {
  for (const pause of ['propagation', 'next_verifier']) {
    test(`CONNECTED: ${name} while the server is rotating (${pause}) ends the session -- no next context, hash or candidate`, async () => {
      const c = await interrupted({ pause, act });
      const s = c.controller.snapshot();
      assert.equal(s.state, expectState);
      assert.equal(c.controller.runIntent, false);
      assert.equal(c.worker.terminated, 1);
      assert.equal(c.controller.workersCreated, 1);
      assert.equal(c.worker.posted.some((m) => m.cmd === 'init_search_next'), false, 'the Worker was re-contextualised after consent was revoked');
      assert.equal(c.worker.hashers.length, 1);
      assert.ok([SIM_ATTEMPT_STATES.TERMINAL_CANCELLED].includes(c.sim.attemptState), c.sim.attemptState);
      assert.equal(c.chain.net.log.submitBodies.length, 1);
      assert.equal(c.chain.net.counts.A.get_block_template, pause === 'propagation' ? 1 : 2);
      assert.equal(c.serverSent.filter((m) => m.type === 'mining_ready').length, 1, 'block 2 was announced ready');
      assert.equal(c.socket.sent.filter((m) => m.type === 'submit_real_candidate').length, 1);
      assert.deepEqual(c.chain.net.log.bWrites, []);
    });
  }
}

test('CONNECTED: a LATE block-1 Worker message after the rotation is stale -- no candidate, no count, no evidence', async () => {
  // Block 2's context is ready in the Worker but its search is held, so stale frames arrive in between.
  const c = await connectedSession({ holdSecondSearch: true });
  c.controller.start();
  await settle(400);
  assert.equal(c.controller.blockIndex, 2);
  assert.equal(c.worker.held.length, 1, 'the block-2 search was not reached');
  const s0 = c.controller.snapshot();
  const job1 = s0.realBlocks[0].jobId;
  const job2 = c.controller.realJob.jobId;
  const candidates = () => c.socket.sent.filter((m) => m.type === 'submit_real_candidate').map((m) => parseInt(m.nonce, 16));
  assert.deepEqual(candidates(), [11]);
  const inject = (data) => c.worker.page.onmessage({ data: { gen: 0, ...data } });
  inject({ ev: 'found', jobId: job1, nonce: 11, nonceHex: nonceToHex(11), hashHexLE: powFor(1), elapsedMs: 1 });
  inject({ ev: 'found', jobId: job1, nonce: 22, nonceHex: nonceToHex(22), hashHexLE: powFor(2), elapsedMs: 1 });
  inject({ ev: 'progress', jobId: job1, hashes: 999, elapsedMs: 1 });
  inject({ ev: 'finished', jobId: job1, hashes: 999, found: 1, exhausted: false, timedOut: false, elapsedMs: 1 });
  inject({ ev: 'ready', jobId: job1, wasmHeapBytes: 1, context: true, search: true });
  await settle();
  const s1 = c.controller.snapshot();
  assert.equal(s1.realStaleWorkerMessages, 5);
  assert.deepEqual(candidates(), [11], 'a stale frame became a candidate');
  assert.equal(s1.realFoundNonce, null, 'a stale frame became block-2 evidence');
  assert.equal(s1.hashes, 0, 'a stale frame changed the block-2 count');
  assert.equal(s1.realBlocks[0].attempts, 12, 'a stale frame rewrote block 1');
  assert.equal(c.controller.runIntent, true, 'a stale frame ended the session');
  assert.equal(c.serverSent.filter((m) => m.type === 'candidate_rejected').length, 0);

  c.worker.release();
  await settle(400);
  const s2 = c.controller.snapshot();
  assert.equal(c.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.deepEqual(candidates(), [11, 22]);
  assert.equal(s2.realBlocks[1].jobId, job2);
  assert.equal(s2.simBrowserMatched, true);
  assert.equal(c.chain.net.log.submitBodies.length, 2);
});
