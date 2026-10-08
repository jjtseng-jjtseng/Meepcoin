// The one-shot run: exactly one submission, a terminal result published once and never
// contradicted, fences at every irreversible boundary, and a shared fatal latch.
//
// NO DAEMON, NO NATIVE HELPER, NO SOCKET, NO CHILD PROCESS. The verifiers and the daemon are plain
// mock objects. Every test in this file is pure in-memory.
//
// Most of these exist because a previous revision genuinely failed them: two concurrent candidates
// both submitted; a run that expired mid-verification still submitted and reported success; an
// overlapping candidate terminalised the run and the first one then submitted anyway, producing
// verified -> rejected -> submit_started -> accepted; a latch tripped during the submit await still
// produced acceptance; and a calc_pow mismatch left the process free to try again.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { NONTERMINAL, RUN_STATES, TERMINAL, createBlockRun, createRunIntent } from '../block_run.mjs';
import {
  AuthorityEquivocationError, CLAIM_REFUSED, createFatalLatch, createTemplateAuthority, FATAL_CODES,
} from '../run_guard.mjs';
import { createRealTemplateJob, fullBlockBlobOf, hashingTemplateOf } from '../real_template.mjs';
import { RPC_CODES, createDaemonRpc, submissionProofs } from '../daemon_rpc.mjs';
import { blobToHex, hexToBlob, patchNonce, readNonce } from '../block_blob.mjs';
import { MAX_256, bigIntToLeBytes32 } from '../difficulty.mjs';
import { parseClientMessage } from '../../../web-miner/lib/shared/protocol.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, '../../..');
const VECTORS = JSON.parse(
  readFileSync(resolve(REPO, 'meepow/vectors/block_vectors_v16_devnet.json'), 'utf8'),
).vectors;
const V = VECTORS[1];

const WORKER = 'w-test-1';
const ISSUANCE = 'abcdef0123456789abcdef0123456789';   // 32 hex, the production shape
const START_ID = '0123456789abcdef0123456789abcdef';    // the client's own correlation token
const NONCE_A = 1234;
const NONCE_B = 5678;
const GOOD_HASH = bigIntToLeBytes32(MAX_256 / 1000000n);
const GOOD_HEX = blobToHex(GOOD_HASH);
const BLOCK_ID = 'e'.repeat(64);

/**
 * `issuanceId` is NOT a template input any more -- a security-relevant identity does not belong in
 * the same bag as daemon-derived template values. A deterministic one comes from the named
 * `mintIssuanceId` dependency seam instead, which is what production leaves at its random default.
 */
function makeJob(over = {}, opts = {}) {
  const { issuanceId = ISSUANCE, ...templateInput } = over;
  return createRealTemplateJob({
    height: V.height,
    seedHashHex: V.epoch_key,
    wideDifficulty: String(V.difficulty),
    blockhashingBlobHex: V.block_hashing_blob,
    blocktemplateBlobHex: V.full_block_blob,
    nonceStart: 0,
    nonceRange: 1 << 16,
    ...templateInput,
  }, { mintIssuanceId: () => issuanceId, ...opts });
}

/** An RPC-shaped error whose PROPERTIES claim things. It is not the adapter's, so it proves nothing. */
function rpcErr(code, extra = {}) {
  return Object.assign(new Error(code), { code, ...extra });
}

/** JSON-RPC reply bodies for the scripted in-memory transport. */
const reply = {
  ok: (id, blockId = BLOCK_ID) => ({ jsonrpc: '2.0', id, result: { status: 'OK', block_id: blockId } }),
  error: (id, error = { code: -7, message: 'Block not accepted' }) => ({ jsonrpc: '2.0', id, error }),
  status: (id, status) => ({ jsonrpc: '2.0', id, result: { status } }),
};

function harness({
  job: providedJob,
  wasmHash = GOOD_HASH,
  nativeHash = GOOD_HASH,
  daemonPow = GOOD_HEX,
  // async ({ id, body }) => reply object | raw text; may throw. Runs AFTER the handoff (see below).
  submit,
  // false: the transport never reports writing the request.
  handoff = true,
  // (hex, adapter) => capability. Replaces the adapter's own prepareSubmission.
  prepare,
  // (capability, adapter) => handle. Replaces the adapter's own dispatchSubmission.
  dispatch,
  header,
  hooks = {},
  latch = createFatalLatch(),
  authority = createTemplateAuthority(),
  clock = { ms: 1000 },
  workerId = WORKER,
  publish = true,
  limits = {},
} = {}) {
  // The job must be minted on the SAME injected clock, or expiresAtMs lands on real wall time and
  // an injected-clock expiry test can never reach it.
  const job = providedJob ?? makeJob({}, { now: () => clock.ms });
  // The server publishes the issuance to the shared authority. Without this no claim can succeed --
  // which is the point: a claim must name the CURRENT template, not merely an unclaimed one.
  if (publish) authority.publish(job);

  const calls = [];
  const events = [];
  const intent = createRunIntent({ now: () => clock.ms });
  // The default readback ECHOES THE DISPATCHED NONCE, as a real daemon would: it reports the block
  // it actually stored. Hard-coding one nonce here made the mock disagree with any candidate but the
  // first, which is an artefact of the mock rather than a property of the code under test.
  let lastDispatchedNonce = null;
  const defaultReadback = () => ({
    hash: BLOCK_ID,
    height: Number(job.height),
    nonce: lastDispatchedNonce,
    powHash: GOOD_HEX,
    orphanStatus: false,
    prevHash: null,
  });
  const readback = header;

  // THE SUBMIT PATH IS THE REAL ADAPTER. block_run believes a "not sent" or a "handed off" only
  // when daemon_rpc.mjs's own private records say so, so the harness cannot hand-build either: it
  // runs createDaemonRpc over a scripted in-memory transport. `prepare` and `dispatch` replace the
  // adapter's methods to inject lookalikes and forgeries, which is exactly what they are for.
  const transportCalls = [];
  const adapter = createDaemonRpc({
    endpoint: 'http://127.0.0.1:18081/json_rpc',
    limits,
    transport: async (req) => {
      const body = JSON.parse(req.body);
      transportCalls.push(body);
      lastDispatchedNonce = readNonce(hexToBlob(body.params[0]));
      if (handoff) req.handoff();
      const out = typeof submit === 'function'
        ? await submit({ id: body.id, body })
        : reply.ok(body.id);
      return typeof out === 'string' ? out : JSON.stringify(out);
    },
  });

  const daemon = {
    async calcPow(req) {
      calls.push({ call: 'calcPow', req });
      if (daemonPow instanceof Error) throw daemonPow;
      return daemonPow;
    },
    // The adapter whose PRIVATE proofs block_run consults. A prepare or dispatch that does not go
    // through it, for this operation, cannot produce a proof block_run will believe.
    submissionAdapter: adapter,
    prepareSubmission(hex, operation) {
      calls.push({ call: 'prepareSubmission', hex });
      if (typeof prepare === 'function') return prepare(hex, adapter, operation);
      return adapter.prepareSubmission(hex, operation);
    },
    dispatchSubmission(capability) {
      calls.push({ call: 'dispatchSubmission' });
      if (typeof dispatch === 'function') return dispatch(capability, adapter);
      return adapter.dispatchSubmission(capability);
    },
    async getBlockHeaderByHeight(h, o) {
      calls.push({ call: 'getBlockHeaderByHeight', h, o });
      if (readback instanceof Error) throw readback;
      return readback === undefined ? defaultReadback() : readback;
    },
  };

  const mkRun = (over = {}) => createBlockRun({
    job,
    intent,
    wasmVerifier: { hashOne: async (n) => { calls.push({ call: 'wasm', n }); return wasmHash; } },
    nativeVerifier: { hashOne: async (n) => { calls.push({ call: 'native', n }); return nativeHash; } },
    daemon,
    latch,
    authority,
    workerId,
    emit: (e) => events.push(e),
    now: () => clock.ms,
    hooks,
    ...over,
  });

  return {
    mkRun, run: mkRun(), intent, calls, events, job, latch, authority, clock, daemon, adapter, transportCalls,
  };
}

const names = (calls) => calls.map((c) => c.call);
const types = (events) => events.map((e) => e.type);
// A SUBMISSION means the transport was actually invoked, i.e. dispatchSubmission. Counting
// prepareSubmission would count requests that were built and then refused locally.
const submitCount = (calls) => calls.filter((c) => c.call === 'dispatchSubmission').length;

function candidate(job, nonce, over = {}) {
  return {
    jobId: job.jobId, issuanceId: job.issuanceId, workerId: WORKER, runGeneration: 1, nonce, ...over,
  };
}

/** Terminal events must appear at most once, and nothing may follow one. */
function assertCoherentTerminalSuffix(evs) {
  const terminals = evs.filter((e) => e.type === 'block_accepted' || e.type === 'block_rejected');
  assert.ok(terminals.length <= 1, `expected at most one terminal event, got ${terminals.length}: ${types(evs)}`);
  if (terminals.length === 1) {
    assert.equal(evs.at(-1).type, terminals[0].type,
      `a terminal event was not last: ${JSON.stringify(types(evs))}`);
  }
}

// ---------------------------------------------------------------- the happy path
test('the full order runs and success requires a matching pow_hash readback', async () => {
  const h = harness();
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));

  assert.equal(r.ok, true);
  assert.deepEqual(names(h.calls), [
    'wasm', 'native', 'calcPow', 'prepareSubmission', 'dispatchSubmission', 'getBlockHeaderByHeight',
  ]);
  assert.deepEqual(types(h.events), ['candidate_verified', 'block_submit_started', 'block_accepted']);
  assert.equal(h.run.state, RUN_STATES.TERMINAL);

  const acc = h.events.at(-1);
  assert.equal(acc.blockId, BLOCK_ID);
  assert.equal(acc.isFinal, false, 'an immediate readback must not be described as final');
  assert.equal(acc.confirmedBy, 'immediate_main_chain_readback_with_matching_pow_hash');

  const rb = h.calls.find((c) => c.call === 'getBlockHeaderByHeight');
  assert.deepEqual(rb.o, { fillPowHash: true });

  const calc = h.calls.find((c) => c.call === 'calcPow');
  assert.equal(calc.req.blockBlobHex, blobToHex(patchNonce(hashingTemplateOf(h.job), NONCE_A).blob));
  assert.equal(calc.req.majorVersion, h.job.majorVersion);

  // The bytes that actually crossed the adapter's transport boundary.
  assert.equal(h.transportCalls.length, 1);
  assert.equal(h.transportCalls[0].method, 'submit_block');
  assert.equal(h.transportCalls[0].params[0], blobToHex(patchNonce(fullBlockBlobOf(h.job), NONCE_A).blob));
});

// ---------------------------------------------------------------- A2 terminal monotonicity
test('A2: an overlapping candidate cannot terminalise a run that is still verifying', async () => {
  // THE EXACT REPRODUCED WITNESS. Hold A at an awaited hook, run B to completion, release A.
  // The old code produced: candidate_verified -> block_rejected -> block_submit_started ->
  // block_accepted.
  let release;
  const gate = new Promise((r) => { release = r; });
  let held = 0;
  const h = harness({
    hooks: { beforeSubmit: async () => { held += 1; if (held === 1) await gate; } },
  });
  h.intent.start();
  h.run.begin();

  const a = h.run.submitCandidate(candidate(h.job, NONCE_A));
  while (held < 1) await new Promise((r) => setImmediate(r));
  const b = await h.run.submitCandidate(candidate(h.job, NONCE_B));
  release();
  const ra = await a;

  assertCoherentTerminalSuffix(h.events);
  assert.equal(submitCount(h.calls), 1, 'more than one dispatch');

  // Exactly one candidate CAUSED the outcome. The other either lost the claim (nonterminal) or
  // resumed to find the run already terminal -- and reports it as an observation, not as its own
  // success. What must never happen is the old behaviour: one of them publishing a terminal
  // rejection that the other then contradicts by submitting anyway.
  const results = [ra, b];
  const causers = results.filter((x) => x.ok === true && !x.alreadyTerminal);
  const observers = results.filter((x) => x.alreadyTerminal === true);
  const losers = results.filter((x) => x.ok !== true);
  assert.equal(causers.length, 1, 'more than one candidate claimed to have caused the outcome');
  assert.equal(observers.length + losers.length, 1);
  for (const l of losers) {
    assert.equal(l.terminal, false, `the loser terminalised the run: ${l.reason}`);
    assert.equal(l.reason, NONTERMINAL.ALREADY_CLAIMED);
  }
  assert.equal(types(h.events).at(-1), 'block_accepted');
});

test('A2: after a terminal result a later candidate does no work and emits nothing', async () => {
  const h = harness();
  h.intent.start();
  h.run.begin();
  const first = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(first.ok, true);
  const eventsAfter = h.events.length;
  const callsAfter = h.calls.length;

  const later = await h.run.submitCandidate(candidate(h.job, NONCE_B));
  assert.equal(later.alreadyTerminal, true);
  assert.equal(later.reason, TERMINAL.VERIFIED_COMPLETE);
  assert.equal(h.events.length, eventsAfter, 'a post-terminal candidate emitted an event');
  assert.equal(h.calls.length, callsAfter, 'a post-terminal candidate performed work');
});

test('A2: a reentrant listener that submits another candidate cannot corrupt the terminal', async () => {
  const h = harness();
  let reentered = null;
  const run = h.mkRun({
    emit: (e) => {
      h.events.push(e);
      // Adversarial: re-enter the run from inside its own event callback.
      if (e.type === 'candidate_verified' && !reentered) {
        reentered = run.submitCandidate(candidate(h.job, NONCE_B));
      }
    },
  });
  h.intent.start();
  run.begin();
  const r = await run.submitCandidate(candidate(h.job, NONCE_A));
  if (reentered) await reentered;

  assertCoherentTerminalSuffix(h.events);
  assert.equal(submitCount(h.calls), 1);
  assert.equal(r.ok, true);
});

// ---------------------------------------------------------------- A1/A7 one submission
test('TWO SIMULTANEOUS qualifying candidates produce exactly ONE dispatch', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  let waiting = 0;
  const h = harness({ hooks: { beforeSubmit: async () => { waiting += 1; await gate; } } });
  h.intent.start();
  h.run.begin();

  const p = Promise.all([
    h.run.submitCandidate(candidate(h.job, NONCE_A)),
    h.run.submitCandidate(candidate(h.job, NONCE_B)),
  ]);
  while (waiting < 2) await new Promise((r) => setImmediate(r));
  release();
  const [a, b] = await p;

  assert.equal(submitCount(h.calls), 1, `expected exactly 1 dispatch, got ${submitCount(h.calls)}`);
  assert.equal([a, b].filter((x) => x.ok === true).length, 1);
  assert.equal([a, b].find((x) => x.ok !== true).reason, NONTERMINAL.ALREADY_CLAIMED);
  assertCoherentTerminalSuffix(h.events);
});

test('TWO SESSIONS racing one issuance produce exactly ONE dispatch', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  let waiting = 0;
  const h = harness({ hooks: { beforeSubmit: async () => { waiting += 1; await gate; } } });
  h.intent.start();
  const runA = h.run;
  const runB = h.mkRun();
  runA.begin();
  runB.begin();

  const p = Promise.all([
    runA.submitCandidate(candidate(h.job, NONCE_A)),
    runB.submitCandidate(candidate(h.job, NONCE_B)),
  ]);
  while (waiting < 2) await new Promise((r) => setImmediate(r));
  release();
  const results = await p;

  assert.equal(submitCount(h.calls), 1, 'two sessions over one issuance dispatched more than once');
  assert.equal(results.filter((x) => x.ok === true).length, 1);
});

test('A7: two issuances of IDENTICAL template content cannot both dispatch', async () => {
  // A per-issuance claim alone would allow this: two unexpired jobs, same bytes, different tokens.
  const latch = createFatalLatch();
  const authority = createTemplateAuthority();
  const clock = { ms: 1000 };

  const jobOld = makeJob({ issuanceId: '1'.repeat(32) }, { now: () => clock.ms });
  const jobNew = makeJob({ issuanceId: '2'.repeat(32) }, { now: () => clock.ms });
  assert.equal(jobOld.contentDigest, jobNew.contentDigest, 'the two issuances must share content');
  assert.notEqual(jobOld.jobId, jobNew.jobId);

  const older = harness({ latch, authority, clock, job: jobOld });
  // The server issues a new template: the older issuance is superseded.
  const newer = harness({ latch, authority, clock, job: jobNew });

  older.intent.start();
  older.run.begin();
  const ro = await older.run.submitCandidate(
    candidate(jobOld, NONCE_A, { runGeneration: older.run.generation }));
  assert.equal(ro.ok, false, 'a superseded issuance dispatched');
  assert.equal(ro.reason, NONTERMINAL.ISSUANCE_SUPERSEDED);
  assert.equal(submitCount(older.calls), 0, 'a superseded issuance reached the transport');

  newer.intent.start();
  newer.run.begin();
  const rn = await newer.run.submitCandidate(
    candidate(jobNew, NONCE_A, { runGeneration: newer.run.generation }));
  assert.equal(rn.ok, true, 'the current issuance could not dispatch');
  assert.equal(submitCount(newer.calls), 1);
});

test('A7: the authority refuses a claim whose identity does not match the current issuance', () => {
  const a = createTemplateAuthority();
  const job = makeJob({}, { now: () => 1000 });
  a.publish(job);
  const base = {
    jobId: job.jobId,
    issuanceId: job.issuanceId,
    contentDigest: job.contentDigest,
    owner: WORKER,
    runGeneration: 1,
    intentLive: () => true,
    atMs: 1000,
  };
  assert.equal(a.claimSubmission({ ...base, jobId: 'realjob-other' }).reason, CLAIM_REFUSED.IDENTITY_MISMATCH);
  assert.equal(a.claimSubmission({ ...base, contentDigest: 'x'.repeat(64) }).reason, CLAIM_REFUSED.IDENTITY_MISMATCH);
  assert.equal(a.claimSubmission({ ...base, issuanceId: '9'.repeat(32) }).reason, CLAIM_REFUSED.NOT_CURRENT);
  assert.equal(a.claimSubmission({ ...base, intentLive: () => false }).reason, CLAIM_REFUSED.INTENT_REVOKED);
  assert.equal(a.claimSubmission({ ...base, atMs: job.expiresAtMs + 1 }).reason, CLAIM_REFUSED.EXPIRED);
  // The inclusive deadline: exactly at expiry is still claimable.
  assert.equal(a.claimSubmission({ ...base, atMs: job.expiresAtMs }).ok, true);
  // And only once.
  assert.equal(a.claimSubmission(base).reason, CLAIM_REFUSED.ALREADY_CLAIMED);
});

// ---------------------------------------------------------------- A3 one clock sample
test('A3: expiry at every async stage produces zero dispatches', async () => {
  for (const stage of ['beforeWasm', 'beforeNative', 'beforeCalcPow', 'beforeSubmit']) {
    const clock = { ms: 1000 };
    const h = harness({ clock, hooks: { [stage]: async () => { clock.ms = 10_000_000; } } });
    h.intent.start();
    h.run.begin();
    const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(submitCount(h.calls), 0, `${stage}: dispatched after expiry`);
    assert.equal(h.run.dispatched, false, stage);
    assert.equal(r.reason, TERMINAL.EXPIRED, stage);
  }
});

test('A3: the inclusive deadline holds at expiry-1, expiry and expiry+1', async () => {
  for (const [delta, shouldDispatch] of [[-1, true], [0, true], [1, false]]) {
    const clock = { ms: 1000 };
    const job = makeJob({}, { now: () => clock.ms });
    const h = harness({ clock, job });
    h.intent.start();
    h.run.begin();
    h.clock.ms = job.expiresAtMs + delta;
    const r = await h.run.submitCandidate(candidate(job, NONCE_A));
    assert.equal(submitCount(h.calls), shouldDispatch ? 1 : 0,
      `expiresAtMs${delta >= 0 ? '+' : ''}${delta}: wrong dispatch count`);
    if (!shouldDispatch) assert.equal(r.reason, TERMINAL.EXPIRED);
  }
});

test('A3: a clock that advances on every read cannot produce an expired dispatch', async () => {
  // If the final section sampled the clock twice, the second read would be past the deadline while
  // the first was not. Whatever this decides, it must never BOTH dispatch and report expiry.
  const job = makeJob({}, { now: () => 1000 });
  let armed = false;
  let reads = 0;
  const clock = {
    get ms() {
      reads += 1;
      return armed ? job.expiresAtMs + reads : 1000;
    },
    set ms(_v) { /* driven by the getter */ },
  };
  const h = harness({ clock, job });
  h.intent.start();
  h.run.begin();
  armed = true;
  const r = await h.run.submitCandidate(candidate(job, NONCE_A));
  if (r.reason === TERMINAL.EXPIRED) {
    assert.equal(submitCount(h.calls), 0, 'reported expiry but still dispatched');
  } else {
    assert.equal(submitCount(h.calls), 1);
  }
  assertCoherentTerminalSuffix(h.events);
});

test('revocation at every async stage produces zero dispatches', async () => {
  for (const stage of ['beforeWasm', 'beforeNative', 'beforeCalcPow', 'beforeSubmit']) {
    let ref = null;
    const h = harness({ hooks: { [stage]: async () => { ref.revokeCurrent('user_stop'); } } });
    ref = h.intent;
    h.intent.start();
    h.run.begin();
    const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(submitCount(h.calls), 0, `${stage}: dispatched after Stop`);
    assert.equal(r.reason, TERMINAL.REVOKED, stage);
    assert.equal(h.run.describeRevocation().submissionPrevented, true);
  }
});

// ---------------------------------------------------------------- A4 latch after dispatch
test('A4: a latch tripped while the submit promise is in flight never yields success', async () => {
  // THE EXACT REPRODUCED WITNESS: hold the submit promise, trip the latch, then resolve it plus a
  // matching readback. The old code still emitted block_accepted.
  const latch = createFatalLatch();
  let resolveSubmit;
  const held = new Promise((r) => { resolveSubmit = r; });
  const h = harness({ latch, submit: async ({ id }) => { await held; return reply.ok(id); } });
  h.intent.start();
  h.run.begin();
  const p = h.run.submitCandidate(candidate(h.job, NONCE_A));
  while (submitCount(h.calls) === 0) await new Promise((r) => setImmediate(r));
  // Wait for the adapter's own receipt, so the trip lands after an authenticated handoff.
  while (!h.events.some((e) => e.type === 'block_submit_started')) await new Promise((r) => setImmediate(r));
  latch.trip(FATAL_CODES.VERIFIER_BUILD_DISAGREEMENT, 'tripped mid-flight');
  resolveSubmit();
  const r = await p;

  assert.equal(r.ok, false, 'a latch tripped mid-flight still produced success');
  assert.equal(r.reason, TERMINAL.SUBMIT_UNTRUSTED);
  assert.equal(r.fatalCode, FATAL_CODES.VERIFIER_BUILD_DISAGREEMENT);
  assert.equal(types(h.events).includes('block_accepted'), false);
  assert.equal(h.run.dispatched, true);
  assert.equal(h.run.describeRevocation().state, 'handed_off');
  assert.equal(h.run.describeRevocation().alreadySent, true);
});

test('A4: a latch tripped before dispatch prevents the dispatch entirely', async () => {
  const latch = createFatalLatch();
  const h = harness({
    latch,
    hooks: { beforeSubmit: async () => { latch.trip(FATAL_CODES.VERIFIER_FAULT, 'before dispatch'); } },
  });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(submitCount(h.calls), 0);
  assert.equal(r.reason, TERMINAL.FATAL_VERIFIER);
});

// ---------------------------------------------------------------- A5 prepared vs dispatched
test('A5: a local prepare failure is DEFINITELY NOT SENT and emits no submit-started', async () => {
  // A GENUINE adapter-local failure: the real size cap, refusing a block too large to send.
  const h = harness({
    limits: { maxRequestBytes: 1024 },
    prepare: (_hex, adapter, operation) => adapter.prepareSubmission('ab'.repeat(1400), operation),
  });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));

  assert.equal(r.reason, TERMINAL.SUBMIT_NOT_SENT);
  assert.equal(r.definitelyNotSent, true);
  assert.equal(r.daemonCode, RPC_CODES.REQUEST_TOO_LARGE);
  assert.equal(submitCount(h.calls), 0, 'dispatch was invoked');
  assert.equal(h.transportCalls.length, 0, 'the transport was invoked');
  assert.equal(h.run.describeRevocation().state, 'prevented');
  assert.equal(h.run.dispatched, false);
  assert.equal(types(h.events).includes('block_submit_started'), false,
    'an event claimed the request was sent when nothing was dispatched');
  // calc_pow may run; prepare happens after it.
  assert.equal(names(h.calls).includes('calcPow'), true);
});

test('A5: a FORGED "not sent" from prepare is AMBIGUOUS, not definitely-not-sent', async () => {
  // A property is a claim. An injected prepare step that throws an error carrying
  // `definitelyNotSent: true` is not the adapter, and nothing can see what it did first.
  const h = harness({
    prepare: () => { throw rpcErr(RPC_CODES.REQUEST_TOO_LARGE, { definitelyNotSent: true }); },
  });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(r.reason, TERMINAL.SUBMIT_AMBIGUOUS);
  assert.equal(r.definitelyNotSent, false);
  assert.equal(h.run.describeRevocation().state, 'unknown');
  assert.equal(h.run.describeRevocation().alreadySent, null);
  assert.equal(types(h.events).includes('block_submit_started'), false);
});

test('A5: a dispatch followed by a timeout is AMBIGUOUS, not a rejection', async () => {
  const replies = {
    [RPC_CODES.TRANSPORT_FAILED]: async () => { throw new Error('ETIMEDOUT'); },
    [RPC_CODES.BAD_RESPONSE]: async () => 'not json',
    [RPC_CODES.ID_MISMATCH]: async () => reply.ok('some-other-id'),
  };
  for (const code of [RPC_CODES.TRANSPORT_FAILED, RPC_CODES.BAD_RESPONSE, RPC_CODES.ID_MISMATCH]) {
    const h = harness({ submit: replies[code] });
    h.intent.start();
    h.run.begin();
    const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(r.reason, TERMINAL.SUBMIT_AMBIGUOUS, code);
    assert.equal(r.daemonCode, code);
    assert.equal(h.run.dispatched, true, code);
    assert.equal(types(h.events).includes('block_accepted'), false, code);
  }
});

test('A5: only a positively identified daemon answer is an explicit rejection', async () => {
  const replies = {
    [RPC_CODES.DAEMON_ERROR]: async ({ id }) => reply.error(id),
    [RPC_CODES.DAEMON_STATUS]: async ({ id }) => reply.status(id, 'BUSY'),
  };
  for (const code of [RPC_CODES.DAEMON_ERROR, RPC_CODES.DAEMON_STATUS]) {
    const h = harness({ submit: replies[code] });
    h.intent.start();
    h.run.begin();
    const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(r.reason, TERMINAL.SUBMIT_REJECTED, code);
    assert.equal(types(h.events).includes('block_accepted'), false, code);
  }
});

test('A5: a MALFORMED error or status envelope after dispatch is ambiguous, never a rejection', async () => {
  const malformed = [
    ['error: null', async ({ id }) => ({ jsonrpc: '2.0', id, error: null })],
    ['error: string', async ({ id }) => ({ jsonrpc: '2.0', id, error: 'Block not accepted' })],
    ['error: empty object', async ({ id }) => ({ jsonrpc: '2.0', id, error: {} })],
    ['status: missing', async ({ id }) => ({ jsonrpc: '2.0', id, result: { block_id: BLOCK_ID } })],
    ['status: null', async ({ id }) => reply.status(id, null)],
    ['status: number', async ({ id }) => reply.status(id, 7)],
  ];
  for (const [name, submit] of malformed) {
    const h = harness({ submit });
    h.intent.start();
    h.run.begin();
    const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(r.reason, TERMINAL.SUBMIT_AMBIGUOUS, `${name} was read as a daemon refusal`);
    assert.equal(r.daemonCode, RPC_CODES.BAD_RESPONSE, name);
    assert.equal(h.run.describeRevocation().state, 'handed_off', name);
  }
});

test('A5: a caller-set not-sent property, or a bare synchronous throw, is never not-sent', async () => {
  // FORGED: a `definitelyNotSent: true` property from something that is not the adapter.
  const forged = harness({
    dispatch: () => { throw rpcErr(RPC_CODES.PREPARED_CONSUMED, { definitelyNotSent: true }); },
  });
  forged.intent.start();
  forged.run.begin();
  const f = await forged.run.submitCandidate(candidate(forged.job, NONCE_A));
  assert.equal(f.reason, TERMINAL.SUBMIT_AMBIGUOUS, 'a forged not-sent property was believed');
  assert.equal(forged.run.describeRevocation().state, 'unknown');

  // A THROW THAT DOES NOT CARRY ADAPTER PROOF IS NOT PROOF OF ANYTHING. The transport may have written
  // and then thrown.
  const ambiguous = harness({
    dispatch: () => { throw rpcErr(RPC_CODES.TRANSPORT_FAILED); },
  });
  ambiguous.intent.start();
  ambiguous.run.begin();
  const b = await ambiguous.run.submitCandidate(candidate(ambiguous.job, NONCE_A));
  assert.equal(b.reason, TERMINAL.SUBMIT_AMBIGUOUS, 'a bare synchronous throw was called not-sent');
  assert.equal(ambiguous.run.dispatched, false, 'no receipt existed, so nothing was "sent"');
  assert.equal(ambiguous.run.boundaryEntered, true, 'the boundary WAS entered');
  assert.equal(types(ambiguous.events).includes('block_submit_started'), false);
});

// ---------------------------------------------------------------- A1: proofs bound to THIS attempt
/** Every lineage mismatch must end the same way: ambiguous, no success, no false not-sent. */
function assertLineageMismatch(h, r, name) {
  assert.equal(r.ok, false, `${name}: reported ok`);
  assert.equal(r.reason, TERMINAL.SUBMIT_AMBIGUOUS, `${name}: ${r.reason}`);
  assert.notEqual(r.reason, TERMINAL.VERIFIED_COMPLETE, name);
  assert.notEqual(r.reason, TERMINAL.SUBMIT_NOT_SENT, `${name}: a false definitely-not-sent`);
  assert.notEqual(r.reason, TERMINAL.SUBMIT_REJECTED, `${name}: a false explicit rejection`);
  assert.equal(r.definitelyNotSent === true, false, name);
  assert.equal(types(h.events).includes('block_accepted'), false, `${name}: block_accepted was emitted`);
  assert.equal(h.run.describeRevocation().submissionPrevented, false, `${name}: claimed prevented`);
  assert.equal(h.run.describeRevocation().state === 'prevented', false, name);
}

/** An adapter A that genuinely submitted some OTHER block earlier, and what that left behind. */
async function earlierAdapterArtifacts() {
  const replies = { mode: 'ok' };
  const a = createDaemonRpc({
    endpoint: 'http://127.0.0.1:18082/json_rpc',
    transport: async (req) => {
      req.handoff();
      const id = JSON.parse(req.body).id;
      return JSON.stringify(replies.mode === 'ok' ? reply.ok(id, 'd'.repeat(64)) : reply.error(id));
    },
  });
  // An authentic dispatch handle for block "aabb", fully settled as accepted.
  const oldOp = Object.freeze({});
  const oldHandle = a.dispatchSubmission(a.prepareSubmission('aabb', oldOp));
  await oldHandle.outcome;
  // An authentic local not-sent error, proven for adapter A's own earlier operation.
  let oldNotSent = null;
  try { a.prepareSubmission('zz', Object.freeze({})); } catch (e) { oldNotSent = e; }
  // An authentic daemon refusal of an earlier dispatch on A.
  replies.mode = 'error';
  let oldRefusal = null;
  try { await a.dispatchSubmission(a.prepareSubmission('ccdd', Object.freeze({}))).outcome; } catch (e) { oldRefusal = e; }
  return { a, oldHandle, oldNotSent, oldRefusal };
}

test('A1: an authentic OLD dispatch handle from ANOTHER adapter cannot make this block accepted', async () => {
  // THE WITNESS: adapter A's settled handle for "aabb", returned by the current dispatch, was
  // authenticated; block_run emitted block_accepted and verified_complete for bytes never sent.
  const { oldHandle } = await earlierAdapterArtifacts();
  const h = harness({ dispatch: () => oldHandle });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assertLineageMismatch(h, r, 'cross-adapter old handle');
  assert.equal(r.daemonCode, RPC_CODES.UNAUTHENTICATED_DISPATCH);
  assert.equal(h.transportCalls.length, 0, 'the current block bytes were never transported');
  assert.equal(h.run.dispatched, false);
});

test('A1: the SAME adapter\'s handle for a DIFFERENT prepared block is not this dispatch', async () => {
  const h = harness({
    // The same adapter, but a different capability and different bytes.
    dispatch: (_cap, adapter) => adapter.dispatchSubmission(adapter.prepareSubmission('aabb', Object.freeze({}))),
  });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assertLineageMismatch(h, r, 'same-adapter other-capability handle');
  assert.equal(r.daemonCode, RPC_CODES.UNAUTHENTICATED_DISPATCH);
  // Something WAS transported -- other bytes -- which is exactly why this cannot be "not sent".
  assert.equal(h.transportCalls.length, 1);
  assert.notEqual(h.transportCalls[0].params[0], blobToHex(patchNonce(fullBlockBlobOf(h.job), NONCE_A).blob));
});

test('A1: an authentic NOT-SENT error from ANOTHER adapter, thrown after a side effect, is not proof', async () => {
  // THE WITNESS: an unrelated adapter's authentic not-sent error, thrown after the current block was
  // transported, produced submit_definitely_not_sent / boundaryEntered=false / submissionPrevented.
  const { oldNotSent } = await earlierAdapterArtifacts();
  assert.ok(oldNotSent);
  const h = harness({
    dispatch: (cap, adapter) => {
      adapter.dispatchSubmission(cap);     // the side effect: the current block IS handed over
      throw oldNotSent;
    },
  });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assertLineageMismatch(h, r, 'cross-adapter old not-sent error');
  assert.equal(h.run.boundaryEntered, true);
  assert.equal(h.transportCalls.length, 1, 'the side effect really happened');
});

test('A1: the SAME adapter\'s not-sent error from an EARLIER operation, thrown after a side effect, is not proof', async () => {
  let earlier = null;
  const h = harness({
    dispatch: (cap, adapter) => {
      try { adapter.prepareSubmission('zz', Object.freeze({})); } catch (e) { earlier = e; }
      adapter.dispatchSubmission(cap);
      throw earlier;
    },
  });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assert.ok(earlier, 'the earlier operation did not produce an authentic local error');
  assertLineageMismatch(h, r, 'same-adapter earlier-operation error');
  assert.equal(h.transportCalls.length, 1);
});

test('A1: an authentic RECEIPT from a different dispatch does not authenticate this one', async () => {
  // At the proof level: a receipt answers only for the record that minted it.
  const { a } = await earlierAdapterArtifacts();
  const proofs = submissionProofs(a);
  const op1 = Object.freeze({});
  const op2 = Object.freeze({});
  const h1 = a.dispatchSubmission(a.prepareSubmission('aa11', op1));
  const h2 = a.dispatchSubmission(a.prepareSubmission('bb22', op2));
  const r1 = proofs.dispatchFor(op1, h1);
  const r2 = proofs.dispatchFor(op2, h2);
  const receipt1 = await r1.receipt;
  assert.equal(proofs.receiptFor(r1, receipt1), true);
  assert.equal(proofs.receiptFor(r2, receipt1), false, 'a receipt authenticated another dispatch');
  assert.equal(proofs.dispatchFor(op2, h1), null, 'a handle authenticated for another operation');
  await Promise.allSettled([r1.outcome, r2.outcome]);

  // At the run level: a current dispatch whose transport never hands off, dressed up with another
  // dispatch's authentic receipt, is still unproven.
  const other = createDaemonRpc({ transport: async (req) => { req.handoff(); return JSON.stringify(reply.ok(JSON.parse(req.body).id)); } });
  const otherHandle = other.dispatchSubmission(other.prepareSubmission('ee33', Object.freeze({})));
  const foreignReceipt = await otherHandle.receipt;
  const h = harness({
    handoff: false,
    dispatch: (cap, adapter) => {
      const real = adapter.dispatchSubmission(cap);
      return { ...real, receipt: Promise.resolve(foreignReceipt) };
    },
  });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assertLineageMismatch(h, r, 'foreign receipt');
  assert.equal(types(h.events).includes('block_submit_started'), false);
});

test('A1: an authentic OLD daemon refusal injected into the current outcome is not a rejection', async () => {
  const { a, oldRefusal } = await earlierAdapterArtifacts();
  assert.ok(oldRefusal);
  assert.equal(oldRefusal.code, RPC_CODES.DAEMON_ERROR);
  // The transport hands over the current block, then rejects with the OLD authentic refusal object.
  const h = harness({ submit: async () => { throw oldRefusal; } });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assertLineageMismatch(h, r, 'old refusal injected');
  // It was handed off, so the honest state is "handed off, outcome unknown".
  assert.equal(h.run.dispatched, true);
  assert.equal(h.run.describeRevocation().state, 'handed_off');
  // And at the proof level it is bound to A's earlier dispatch, never to anything current.
  const proofs = submissionProofs(h.adapter);
  assert.equal(proofs.refusalFor(null, oldRefusal), false);
  void a;
});

test('A1: the VALID lineage -- this adapter, this operation, this capability -- still succeeds', async () => {
  const h = harness();
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(r.ok, true);
  assert.equal(r.reason, TERMINAL.VERIFIED_COMPLETE);
  assert.equal(h.transportCalls.length, 1);
  assert.equal(h.transportCalls[0].params[0], blobToHex(patchNonce(fullBlockBlobOf(h.job), NONCE_A).blob));
  // A genuine, current explicit refusal is still an explicit refusal.
  const refused = harness({ submit: async ({ id }) => reply.error(id) });
  refused.intent.start();
  refused.run.begin();
  assert.equal((await refused.run.submitCandidate(candidate(refused.job, NONCE_A))).reason, TERMINAL.SUBMIT_REJECTED);
  // And a genuine, current local failure is still definitely not sent.
  const tooBig = harness({
    limits: { maxRequestBytes: 1024 },
    prepare: (_hex, adapter, operation) => adapter.prepareSubmission('ab'.repeat(1400), operation),
  });
  tooBig.intent.start();
  tooBig.run.begin();
  assert.equal((await tooBig.run.submitCandidate(candidate(tooBig.job, NONCE_A))).reason, TERMINAL.SUBMIT_NOT_SENT);
});

test('A1: a facade preparing a DIFFERENT block under the SAME genuine adapter and CURRENT operation is never accepted', async () => {
  // THE WITNESS (Regression testing): the facade named the genuine adapter, received block_run's current operation
  // token, changed the final byte of fullBlockHex and had that adapter prepare the altered block under
  // the same operation. Every lineage check passed, the altered bytes were transported, and the
  // scripted outcome/readback let block_run return verified_complete for a block never sent.
  let intendedHex = null;
  let alteredHex = null;
  const h = harness({
    prepare: (hex, adapter, operation) => {
      intendedHex = hex;
      const last = parseInt(hex.slice(-2), 16);
      alteredHex = hex.slice(0, -2) + ((last + 1) & 0xff).toString(16).padStart(2, '0');
      return adapter.prepareSubmission(alteredHex, operation);
    },
  });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));

  assert.ok(intendedHex && alteredHex && intendedHex !== alteredHex && intendedHex.length === alteredHex.length);
  assert.equal(intendedHex, blobToHex(patchNonce(fullBlockBlobOf(h.job), NONCE_A).blob));
  assertLineageMismatch(h, r, 'same adapter, current operation, different body');
  assert.equal(r.definitelyNotSent, false);
  assert.equal(r.daemonCode, RPC_CODES.UNAUTHENTICATED_DISPATCH);
  assert.equal(types(h.events).includes('block_accepted'), false);
  assert.equal(h.events.some((e) => e.reason === TERMINAL.VERIFIED_COMPLETE), false);
  // block_run stopped at the proof: no later dispatch, no transport, no readback.
  assert.equal(submitCount(h.calls), 0, 'block_run dispatched after the body mismatch');
  assert.equal(h.transportCalls.length, 0, 'bytes were transported after the body mismatch');
  assert.equal(h.transportCalls.some((b) => b.params?.[0] === intendedHex), false, 'the intended block was transported');
  assert.equal(names(h.calls).includes('getBlockHeaderByHeight'), false);
  assert.equal(h.run.dispatched, false);
  // And the claim was never taken, so no other candidate or session is blocked by a phantom claim.
  const other = harness();
  other.intent.start();
  other.run.begin();
  const ok = await other.run.submitCandidate(candidate(other.job, NONCE_A));
  assert.equal(ok.reason, TERMINAL.VERIFIED_COMPLETE, 'the ordinary exact-body path is no longer green');
  assert.equal(other.transportCalls[0].params[0], blobToHex(patchNonce(fullBlockBlobOf(other.job), NONCE_A).blob));
});

test('A1: a daemon object with no genuine submissionAdapter can never claim sent, refused or not-sent', async () => {
  const h = harness();
  const run = h.mkRun({ daemon: { ...h.daemon, submissionAdapter: { lookalike: true } } });
  h.intent.start();
  run.begin();
  const r = await run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(r.reason, TERMINAL.SUBMIT_AMBIGUOUS);
  assert.equal(h.transportCalls.length, 0);
});

test('A5: submit-started is emitted only AFTER the adapter\'s handoff receipt exists', async () => {
  const order = [];
  const h = harness();
  // A real adapter whose transport records the moment it reports the handoff.
  const adapter = createDaemonRpc({
    endpoint: 'http://127.0.0.1:18081/json_rpc',
    transport: async (req) => {
      order.push('transport');
      req.handoff();
      order.push('receipt');
      const body = JSON.parse(req.body);
      return JSON.stringify(reply.ok(body.id));
    },
  });
  const run = h.mkRun({
    daemon: {
      ...h.daemon,
      submissionAdapter: adapter,
      prepareSubmission: (hex, operation) => adapter.prepareSubmission(hex, operation),
      dispatchSubmission: (cap) => { order.push('dispatch'); return adapter.dispatchSubmission(cap); },
    },
    emit: (e) => { if (e.type === 'block_submit_started') order.push('event'); h.events.push(e); },
  });
  h.intent.start();
  run.begin();
  await run.submitCandidate(candidate(h.job, NONCE_A));
  assert.deepEqual(order, ['dispatch', 'transport', 'receipt', 'event'],
    'the "sent" event preceded the adapter\'s receipt');
});

test('A5: a LOOKALIKE dispatch handle is ambiguous and emits no "sent", even if it says it was handed off', async () => {
  const h = harness({
    dispatch: () => ({
      kind: 'meepcoin-dispatch',
      boundaryEntered: true,
      handedOff: true,
      receiptIfAny: { method: 'submit_block' },
      receipt: Promise.resolve({ method: 'submit_block', requestBytes: 1 }),
      requestBytes: 1,
      outcome: Promise.resolve({ blockId: BLOCK_ID }),
    }),
  });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(r.reason, TERMINAL.SUBMIT_AMBIGUOUS);
  assert.equal(r.daemonCode, RPC_CODES.UNAUTHENTICATED_DISPATCH);
  assert.equal(h.run.dispatched, false, 'a lookalike receipt was believed');
  assert.equal(types(h.events).includes('block_submit_started'), false);
  assert.equal(types(h.events).includes('block_accepted'), false);
  assert.equal(h.run.describeRevocation().state, 'unknown');
});

test('A5: a transport entered with NO handoff receipt is ambiguous and emits no "sent"', async () => {
  // The exact defect: an async transport can return a Promise before it performs any I/O. Entering
  // it is not a handoff, so nothing may claim the block was sent -- and nothing may claim it was
  // not, either. This is the REAL adapter, over a transport that answers without a handoff.
  const h = harness({ handoff: false });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(r.reason, TERMINAL.SUBMIT_AMBIGUOUS);
  assert.equal(r.daemonCode, RPC_CODES.NO_HANDOFF_RECEIPT);
  assert.equal(h.run.dispatched, false, 'dispatched was claimed without a receipt');
  assert.equal(h.run.boundaryEntered, true);
  assert.equal(types(h.events).includes('block_submit_started'), false);
  assert.equal(types(h.events).includes('block_accepted'), false);
  // TRI-STATE. Not "already sent": it may or may not have been, and it cannot be recalled.
  const rev = h.run.describeRevocation();
  assert.equal(rev.state, 'unknown');
  assert.equal(rev.alreadySent, null);
  assert.equal(rev.mayHaveBeenSent, true);
  assert.equal(rev.submissionPrevented, false);
});

test('a dispatch that returns false, nothing, or `boundaryEntered: false` is AMBIGUOUS, not "not sent"', async () => {
  // THE WITNESS: `{ boundaryEntered: false }` from an invoked dispatchSubmission was reported as
  // definitely-not-sent. The function ran; nothing about its return proves it did not write.
  for (const [name, value] of [
    ['boundaryEntered false', { boundaryEntered: false }],
    ['undefined', undefined],
    ['false', false],
    ['null', null],
    ['a string', 'sent'],
  ]) {
    const h = harness({ dispatch: () => value });
    h.intent.start();
    h.run.begin();
    const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(r.reason, TERMINAL.SUBMIT_AMBIGUOUS, name);
    assert.equal(h.run.boundaryEntered, true, name);
    assert.equal(h.run.describeRevocation().state, 'unknown', name);
    assert.equal(types(h.events).includes('block_submit_started'), false, name);
  }
});

// ---------------------------------------------------------------- A6 fatal health
test('A6: a calc_pow disagreement trips the shared latch and blocks all later work', async () => {
  const latch = createFatalLatch();
  const a = harness({ latch, daemonPow: 'f'.repeat(64) });
  a.intent.start();
  a.run.begin();
  const ra = await a.run.submitCandidate(candidate(a.job, NONCE_A));
  assert.equal(ra.reason, TERMINAL.FATAL_VERIFIER, 'a calc_pow disagreement was not fatal');
  assert.equal(latch.tripped, true);
  assert.equal(latch.code, FATAL_CODES.ORACLE_DISAGREEMENT);
  assert.equal(submitCount(a.calls), 0);

  // A separately constructed run: own job, own intent, own authority. Only the latch is shared.
  const clock = { ms: 1000 };
  const b = harness({
    latch,
    authority: createTemplateAuthority(),
    clock,
    job: makeJob({ issuanceId: '3'.repeat(32) }, { now: () => clock.ms }),
  });
  b.intent.start();
  const begun = b.run.begin();
  assert.equal(begun.ok, false, 'run B began after a fatal latch');
  assert.equal(begun.reason, TERMINAL.FATAL_VERIFIER);
  const rb = await b.run.submitCandidate(candidate(b.job, NONCE_A));
  assert.equal(rb.reason, TERMINAL.FATAL_VERIFIER);
  assert.equal(b.calls.length, 0, 'run B performed work after the latch tripped');
});

test('A6: a Wasm/native disagreement trips the latch before calc_pow', async () => {
  const latch = createFatalLatch();
  const h = harness({ latch, nativeHash: bigIntToLeBytes32(999n) });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(r.reason, TERMINAL.FATAL_VERIFIER);
  assert.equal(latch.code, FATAL_CODES.VERIFIER_BUILD_DISAGREEMENT);
  assert.equal(names(h.calls).includes('calcPow'), false, 'calc_pow ran after a disagreement');
});

test('A6: a CANCELLED verifier does NOT trip the latch', async () => {
  const errs = [
    Object.assign(new Error('closing'), { cancelled: true }),
    Object.assign(new Error('x'), { code: 'cancelled' }),
  ];
  for (const err of errs) {
    const latch = createFatalLatch();
    const h = harness({ latch });
    const run = h.mkRun({ nativeVerifier: { hashOne: async () => { throw err; } } });
    h.intent.start();
    run.begin();
    const r = await run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(r.reason, TERMINAL.CANCELLED, 'a cancellation was treated as a fault');
    assert.equal(latch.tripped, false, 'a cancellation tripped the fatal latch');
    assert.equal(submitCount(h.calls), 0);
  }
});

test('A6: malformed verifier output trips the latch instead of reading as a mismatch', async () => {
  const cases = [['short', new Uint8Array(16)], ['long', new Uint8Array(33)], ['string', 'deadbeef'], ['null', null]];
  for (const [name, bad] of cases) {
    const latch = createFatalLatch();
    const h = harness({ latch, nativeHash: bad });
    h.intent.start();
    h.run.begin();
    const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(r.reason, TERMINAL.FATAL_VERIFIER, name);
    assert.equal(latch.code, FATAL_CODES.VERIFIER_MALFORMED_OUTPUT, name);
  }
});

test('A6: a malformed calc_pow hash is a fatal integrity fault', async () => {
  for (const bad of ['NOTHEX', 'abcd', GOOD_HEX.toUpperCase(), 12345, null]) {
    const latch = createFatalLatch();
    const h = harness({ latch, daemonPow: bad });
    h.intent.start();
    h.run.begin();
    const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(r.reason, TERMINAL.FATAL_VERIFIER, String(bad));
    assert.equal(latch.code, FATAL_CODES.VERIFIER_MALFORMED_OUTPUT, String(bad));
    assert.equal(submitCount(h.calls), 0, String(bad));
  }
});

test('A6: a malformed submitted blockId is ambiguous, never success', async () => {
  for (const bad of ['NOTHEX', 'abcd', BLOCK_ID.toUpperCase(), undefined]) {
    const h = harness({
      submit: async ({ id }) => ({ jsonrpc: '2.0', id, result: { status: 'OK', block_id: bad } }),
    });
    h.intent.start();
    h.run.begin();
    const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(r.reason, TERMINAL.SUBMIT_AMBIGUOUS, String(bad));
    assert.equal(types(h.events).includes('block_accepted'), false, String(bad));
  }
});

test('A6: an IMPOSSIBLE readback (OUR block id, but self-contradictory) is fatal', async () => {
  // We asked for the header AT A GIVEN HEIGHT and got OUR block id back. Every other field must
  // then agree: no chain state explains our block being at another height, being an orphan at the
  // height we asked for, or carrying a different nonce or proof-of-work than the id commits to.
  const cases = [
    ['same block, different nonce',
      { hash: BLOCK_ID, height: Number(V.height), nonce: NONCE_A + 1, powHash: GOOD_HEX, orphanStatus: false }],
    ['same block, different pow',
      { hash: BLOCK_ID, height: Number(V.height), nonce: NONCE_A, powHash: 'b'.repeat(64), orphanStatus: false }],
    ['same block, WRONG HEIGHT',
      { hash: BLOCK_ID, height: Number(V.height) + 5, nonce: NONCE_A, powHash: GOOD_HEX, orphanStatus: false }],
    ['same block, ORPHANED at the height we asked for',
      { hash: BLOCK_ID, height: Number(V.height), nonce: NONCE_A, powHash: GOOD_HEX, orphanStatus: true }],
  ];
  for (const [name, header] of cases) {
    const latch = createFatalLatch();
    const h = harness({ latch, header });
    h.intent.start();
    h.run.begin();
    const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(r.reason, TERMINAL.SUBMIT_UNTRUSTED, name);
    assert.equal(latch.tripped, true, `${name}: the impossible case did not latch`);
    assert.equal(latch.code, FATAL_CODES.IMPOSSIBLE_READBACK, name);
    assert.equal(types(h.events).includes('block_accepted'), false, name);
  }
});

test('A6: a readback naming ANOTHER block is ambiguous and does NOT latch', async () => {
  // A different block id at that height is exactly what a reorg or a competing block produces. It
  // is not a contradiction, so it must not disable verification for the whole process.
  const cases = [
    ['a different block at that height (reorg-like)',
      { hash: 'a'.repeat(64), height: Number(V.height), nonce: NONCE_A, powHash: GOOD_HEX, orphanStatus: false }],
    ['another block, orphaned',
      { hash: 'a'.repeat(64), height: Number(V.height), nonce: NONCE_A, powHash: GOOD_HEX, orphanStatus: true }],
    ['another block, wrong height',
      { hash: 'a'.repeat(64), height: Number(V.height) + 5, nonce: NONCE_A, powHash: GOOD_HEX, orphanStatus: false }],
  ];
  for (const [name, header] of cases) {
    const latch = createFatalLatch();
    const h = harness({ latch, header });
    h.intent.start();
    h.run.begin();
    const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(r.ok, false, name);
    assert.ok([TERMINAL.READBACK_MISMATCH, TERMINAL.SUBMIT_AMBIGUOUS, TERMINAL.SUBMIT_UNTRUSTED].includes(r.reason),
      `${name}: unexpected ${r.reason}`);
    assert.equal(latch.tripped, false, `${name}: an ordinary readback failure latched the process`);
    assert.equal(types(h.events).includes('block_accepted'), false, name);
  }
});

test('a failed readback call is ambiguous', async () => {
  const h = harness({ header: new Error('daemon busy') });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(r.reason, TERMINAL.SUBMIT_AMBIGUOUS);
  assert.equal(r.dispatched, true);
});

// ---------------------------------------------------------------- binding
test('forged worker, generation or issuance costs zero work and is NONTERMINAL', async () => {
  const cases = [
    ['forged workerId', { workerId: 'w-someone-else' }, NONTERMINAL.UNKNOWN_WORKER],
    ['stale generation', { runGeneration: 0 }, NONTERMINAL.STALE_GENERATION],
    ['future generation', { runGeneration: 99 }, NONTERMINAL.STALE_GENERATION],
    ['stale issuance', { issuanceId: 'f'.repeat(32) }, NONTERMINAL.STALE_ISSUANCE],
    ['wrong job', { jobId: 'realjob-elsewhere' }, NONTERMINAL.UNKNOWN_JOB],
    ['missing workerId', { workerId: undefined }, NONTERMINAL.UNKNOWN_WORKER],
    ['missing issuanceId', { issuanceId: undefined }, NONTERMINAL.STALE_ISSUANCE],
    ['missing runGeneration', { runGeneration: undefined }, NONTERMINAL.STALE_GENERATION],
  ];
  for (const [name, over, reason] of cases) {
    const h = harness();
    h.intent.start();
    h.run.begin();
    const r = await h.run.submitCandidate(candidate(h.job, NONCE_A, over));
    assert.equal(r.reason, reason, name);
    assert.equal(r.terminal, false, `${name} must be nonterminal`);
    assert.equal(h.calls.length, 0, `${name}: work was performed`);
    // And the run is still usable by the legitimate worker.
    const good = await h.run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(good.ok, true, `${name}: a forged candidate locked out the real worker`);
  }
});

test('above-target and duplicate are nonterminal and cost no dispatch', async () => {
  const h = harness({
    wasmHash: bigIntToLeBytes32((MAX_256 / 500n) + 1n),
    nativeHash: bigIntToLeBytes32((MAX_256 / 500n) + 1n),
  });
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(r.reason, NONTERMINAL.ABOVE_TARGET);
  assert.equal(h.run.complete, false);
  const dup = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(dup.reason, NONTERMINAL.DUPLICATE);
  assert.equal(submitCount(h.calls), 0);
});

test('client-supplied consensus fields cannot influence the outcome', async () => {
  const h = harness();
  h.intent.start();
  h.run.begin();
  const r = await h.run.submitCandidate({
    ...candidate(h.job, NONCE_A),
    targetHexLE: 'f'.repeat(64), difficulty: 1, wideDifficulty: '0x1', height: 999999,
    seedHashHex: 'a'.repeat(64), epochKeyHex: 'a'.repeat(64), hashingTemplateHex: '00',
    blocktemplateBlobHex: 'dead', fullBlockBlob: 'dead', nonceOffset: 0,
    miningAddress: 'FAKE', resultHash: 'b'.repeat(64), majorVersion: 99,
  });
  assert.equal(r.ok, true);
  const calc = h.calls.find((c) => c.call === 'calcPow');
  assert.equal(calc.req.height, String(V.height));
  assert.equal(calc.req.seedHashHex, V.epoch_key);
  assert.equal(calc.req.majorVersion, h.job.majorVersion);
});

test('mutating returned byte copies cannot change what the run hashes or submits', async () => {
  const job = makeJob({}, { now: () => 1000 });
  hashingTemplateOf(job).fill(0xff);
  fullBlockBlobOf(job).fill(0xff);
  const h = harness({ job });
  h.intent.start();
  h.run.begin();
  await h.run.submitCandidate(candidate(job, NONCE_A));
  const calc = h.calls.find((c) => c.call === 'calcPow');
  assert.equal(calc.req.blockBlobHex, blobToHex(patchNonce(hexToBlob(V.blob_nonce_zeroed), NONCE_A).blob));
  assert.equal(h.transportCalls[0].params[0], blobToHex(patchNonce(hexToBlob(V.full_block_blob), NONCE_A).blob));
});

test('no emitted event carries the full block blob', async () => {
  const h = harness();
  h.intent.start();
  h.run.begin();
  await h.run.submitCandidate(candidate(h.job, NONCE_A));
  const json = JSON.stringify(h.events);
  assert.equal(json.includes(blobToHex(patchNonce(fullBlockBlobOf(h.job), NONCE_A).blob)), false);
  assert.equal(json.includes(V.full_block_blob), false);
  assert.equal(json.includes(h.job.hashingTemplateHex), false);
});

// ---------------------------------------------------------------- intent semantics
test('a stale generation cannot revoke a newer run, and nothing auto-resumes', () => {
  const intent = createRunIntent();
  const g1 = intent.start();
  intent.revoke(g1, 'user_stop');
  const g2 = intent.start();
  const stale = intent.revoke(g1, 'user_stop');
  assert.equal(stale.ok, false);
  assert.equal(stale.reason, NONTERMINAL.STALE_GENERATION);
  assert.equal(intent.isLive(g2), true);
  intent.revoke(g2, 'socket_close');
  assert.equal(intent.active, false);
  assert.equal(intent.revoke(intent.generation, 'page_hidden').alreadyRevoked, true);
  assert.equal(intent.active, false);
});

test('a run begun without live intent refuses immediately', async () => {
  const h = harness();
  const begun = h.run.begin();
  assert.equal(begun.reason, TERMINAL.NOT_RUNNING);
  const r = await h.run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(r.alreadyTerminal, true);
  assert.equal(h.calls.length, 0);
});

// ---------------------------------------------------------------- the central authority
test('a returned publication cannot be mutated into a longer-lived issuance', () => {
  // THE WITNESS: take what publish() returns, set expiresAtMs to Infinity, and a claim at t=9999
  // succeeded against a job whose real expiry was 10.
  const a = createTemplateAuthority();
  const job = { jobId: 'j1', issuanceId: ISSUANCE, contentDigest: 'b'.repeat(64), expiresAtMs: 10 };
  const returned = a.publish(job);
  assert.equal(Object.isFrozen(returned), true);
  try { returned.expiresAtMs = Infinity; } catch { /* frozen in strict mode */ }
  const current = a.current;
  try { current.expiresAtMs = Infinity; } catch { /* same */ }
  // And mutating the caller's own input object afterwards changes nothing either.
  job.expiresAtMs = Infinity;

  const base = {
    jobId: 'j1', issuanceId: ISSUANCE, contentDigest: 'b'.repeat(64), owner: 'w', runGeneration: 1,
  };
  assert.equal(a.claimSubmission({ ...base, atMs: 9999 }).reason, CLAIM_REFUSED.EXPIRED);
  assert.equal(a.claimSubmission({ ...base, atMs: 10 }).ok, true, 'the real deadline stopped working');
});

test('a granted claim cannot be mutated into a different one', () => {
  // THE WITNESS: rewrite the returned claim's issuanceId and isClaimed() followed it.
  const a = createTemplateAuthority();
  a.publish({ jobId: 'j1', issuanceId: ISSUANCE, contentDigest: 'b'.repeat(64), expiresAtMs: 1000 });
  const granted = a.claimSubmission({
    jobId: 'j1', issuanceId: ISSUANCE, contentDigest: 'b'.repeat(64), owner: 'w', runGeneration: 1, atMs: 1,
  });
  assert.equal(granted.ok, true);
  assert.equal(Object.isFrozen(granted.claim), true);
  try { granted.claim.issuanceId = 'f'.repeat(32); granted.claim.owner = 'someone-else'; } catch { /* frozen */ }
  assert.equal(a.isClaimed(ISSUANCE), true, 'mutating a returned claim changed the authority');
  assert.equal(a.isClaimed('f'.repeat(32)), false);
  assert.equal(a.claimedIssuanceId, ISSUANCE);
  assert.equal(a.claim.owner, 'w');
});

test('re-publishing an issuance is idempotent ONLY when byte-for-byte identical', () => {
  const a = createTemplateAuthority();
  const job = { jobId: 'j1', issuanceId: ISSUANCE, contentDigest: 'b'.repeat(64), expiresAtMs: 10 };
  a.publish(job);
  assert.deepEqual(a.publish({ ...job }), { ...job }, 'an identical re-publication was not idempotent');

  // SAME ID, DIFFERENT AUTHORITY: equivocation. Refused, and the current record is unchanged -- in
  // particular its lifetime is not extended.
  for (const [name, patch] of [
    ['a longer expiry', { expiresAtMs: 10_000_000 }],
    ['a shorter expiry', { expiresAtMs: 5 }],
    ['a different job', { jobId: 'j2' }],
    ['different content', { contentDigest: 'c'.repeat(64) }],
  ]) {
    assert.throws(() => a.publish({ ...job, ...patch }), AuthorityEquivocationError, name);
    assert.deepEqual(a.current, job, `${name}: the current record changed`);
  }
  const base = {
    jobId: 'j1', issuanceId: ISSUANCE, contentDigest: 'b'.repeat(64), owner: 'w', runGeneration: 1,
  };
  assert.equal(a.claimSubmission({ ...base, atMs: 11 }).reason, CLAIM_REFUSED.EXPIRED,
    'equivocation extended the issuance lifetime');
});

test('a superseded issuance cannot be published back into currency', () => {
  const a = createTemplateAuthority();
  const first = { jobId: 'j1', issuanceId: '1'.repeat(32), contentDigest: 'b'.repeat(64), expiresAtMs: 1000 };
  const second = { jobId: 'j2', issuanceId: '2'.repeat(32), contentDigest: 'c'.repeat(64), expiresAtMs: 1000 };
  a.publish(first);
  a.publish(second);
  assert.throws(() => a.publish(first), AuthorityEquivocationError);
  assert.equal(a.currentIssuanceId, '2'.repeat(32));
});

test('publish() refuses a malformed or non-finite publication', () => {
  const a = createTemplateAuthority();
  const good = { jobId: 'j1', issuanceId: ISSUANCE, contentDigest: 'b'.repeat(64), expiresAtMs: 10 };
  for (const [what, patch] of [
    ['infinite expiry', { expiresAtMs: Infinity }],
    ['NaN expiry', { expiresAtMs: NaN }],
    ['fractional expiry', { expiresAtMs: 10.5 }],
    ['string expiry', { expiresAtMs: '10' }],
    ['short issuance', { issuanceId: 'abcd' }],
    ['uppercase issuance', { issuanceId: ISSUANCE.toUpperCase() }],
    ['missing digest', { contentDigest: undefined }],
    ['short digest', { contentDigest: 'ab' }],
    ['empty jobId', { jobId: '' }],
  ]) {
    assert.throws(() => a.publish({ ...good, ...patch }), TypeError, what);
  }
  assert.equal(a.current, null, 'a refused publication still became current');
});

test('a supersede listener observes the COMPLETED transition and cannot reopen it', () => {
  // THE WITNESS: the listener ran while `current` still pointed at the outgoing publication, so a
  // re-entrant caller saw a transition that had been decided but not written.
  const a = createTemplateAuthority();
  const first = { jobId: 'j1', issuanceId: '1'.repeat(32), contentDigest: 'b'.repeat(64), expiresAtMs: 1000 };
  const second = { jobId: 'j2', issuanceId: '2'.repeat(32), contentDigest: 'c'.repeat(64), expiresAtMs: 1000 };
  a.publish(first);

  const observed = [];
  a.onSupersede((old, transition) => {
    observed.push({
      oldIssuance: old.issuanceId,
      currentDuringCallback: a.currentIssuanceId,
      supersededFlag: a.isSuperseded(old.issuanceId),
      transitionCurrent: transition.current.issuanceId,
      frozen: Object.isFrozen(old) && Object.isFrozen(transition),
    });
    // Re-entrant attempts from inside the callback.
    try { old.expiresAtMs = Infinity; } catch { /* frozen */ }
    a.claimSubmission({
      jobId: 'j1', issuanceId: '1'.repeat(32), contentDigest: 'b'.repeat(64), owner: 'reentrant',
      runGeneration: 1, atMs: 1,
    });
  });
  a.publish(second);

  assert.deepEqual(observed, [{
    oldIssuance: '1'.repeat(32),
    currentDuringCallback: '2'.repeat(32),
    supersededFlag: true,
    transitionCurrent: '2'.repeat(32),
    frozen: true,
  }]);
  // The re-entrant claim named the superseded issuance, so it changed nothing.
  assert.equal(a.anyClaimed, false, 'a reentrant callback claimed the single submission');
  assert.equal(a.currentIssuanceId, '2'.repeat(32));
});

// ---------------------------------------------------------------- the wire messages
test('submit_real_candidate requires all five binding fields', () => {
  const good = {
    type: 'submit_real_candidate', jobId: 'realjob-x', issuanceId: ISSUANCE,
    workerId: 'w1', runGeneration: 2, nonce: '4f0e8b0b', clientStartId: START_ID,
  };
  const text = JSON.stringify(good);
  const p = parseClientMessage(Buffer.byteLength(text), text);
  assert.equal(p.ok, true);
  assert.equal(p.issuanceId, ISSUANCE);
  assert.equal(p.runGeneration, 2);
  assert.equal(p.nonce, 0x4f0e8b0b);
  assert.equal(p.clientStartId, START_ID);

  for (const drop of ['jobId', 'issuanceId', 'workerId', 'runGeneration', 'nonce', 'clientStartId']) {
    const bad = { ...good };
    delete bad[drop];
    const t = JSON.stringify(bad);
    assert.equal(parseClientMessage(Buffer.byteLength(t), t).ok, false, `missing ${drop}`);
  }
  for (const bad of [
    { ...good, issuanceId: 'abcd' },
    { ...good, issuanceId: ISSUANCE.toUpperCase() },
    { ...good, runGeneration: -1 },
    { ...good, runGeneration: '2' },
    { ...good, nonce: 'ZZZZZZZZ' },
    { ...good, nonce: '4f0e8b0' },
    { ...good, resultHash: 'b'.repeat(64) },   // extra fields fail closed
    { ...good, extra: 1 },
  ]) {
    const t = JSON.stringify(bad);
    assert.equal(parseClientMessage(Buffer.byteLength(t), t).ok, false, t.slice(0, 90));
  }
});

test('legacy submit_share cannot smuggle the real binding fields', () => {
  const base = { type: 'submit_share', jobId: 'j', workerId: 'w', nonce: '00000001' };
  const ok = JSON.stringify(base);
  assert.equal(parseClientMessage(Buffer.byteLength(ok), ok).ok, true, 'the synthetic path must still work');
  for (const field of ['issuanceId', 'runGeneration']) {
    const t = JSON.stringify({ ...base, [field]: field === 'runGeneration' ? 1 : ISSUANCE });
    assert.equal(parseClientMessage(Buffer.byteLength(t), t).ok, false, field);
  }
});

test('stop_request stays fully bound, with a 32-hex issuance', () => {
  const good = JSON.stringify({
    type: 'stop_request', workerId: 'w1', runGeneration: 3, jobId: 'realjob-x', issuanceId: ISSUANCE,
  });
  assert.equal(parseClientMessage(Buffer.byteLength(good), good).ok, true);
  for (const bad of [
    { type: 'stop_request', runGeneration: 1, jobId: 'j', issuanceId: ISSUANCE },
    { type: 'stop_request', workerId: 'w1', jobId: 'j', issuanceId: ISSUANCE },
    { type: 'stop_request', workerId: 'w1', runGeneration: 1, issuanceId: ISSUANCE },
    { type: 'stop_request', workerId: 'w1', runGeneration: 1, jobId: 'j' },
    { type: 'stop_request', workerId: 'w1', runGeneration: 1, jobId: 'j', issuanceId: 'abcd' },
    { type: 'stop_request', workerId: 'w1', runGeneration: 1, jobId: 'j', issuanceId: ISSUANCE, extra: 1 },
  ]) {
    const t = JSON.stringify(bad);
    assert.equal(parseClientMessage(Buffer.byteLength(t), t).ok, false, t.slice(0, 90));
  }
});

// ================================================================== canonical readback (real daemon)
import { findNonceOffset, PREV_ID_BYTES } from '../block_blob.mjs';

const TEMPLATE_PREV = (() => {
  const full = hexToBlob(V.full_block_blob);
  const { offset } = findNonceOffset(full);
  return blobToHex(full.subarray(offset - PREV_ID_BYTES, offset));
})();

/**
 * A run with canonical readback on. `header` is what get_block_header_by_height reports (defaults to
 * this exact block), `top` what get_last_block_header reports (defaults to this block as the top).
 */
function canonicalRun({ header = {}, top = {}, submit, topThrows = false, headerThrows = false } = {}) {
  const h = harness({ submit });
  const calls = { header: 0, top: 0 };
  const exactHeader = () => ({
    hash: BLOCK_ID, height: Number(h.job.height), nonce: NONCE_A, powHash: GOOD_HEX,
    orphanStatus: false, prevHash: TEMPLATE_PREV, ...header,
  });
  const daemon = {
    ...h.daemon,
    async getBlockHeaderByHeight(height, o) {
      calls.header += 1;
      h.calls.push({ call: 'getBlockHeaderByHeight', h: height, o });
      if (headerThrows) throw rpcErr(RPC_CODES.TRANSPORT_FAILED);
      return exactHeader();
    },
    async getLastBlockHeader() {
      calls.top += 1;
      if (topThrows) throw rpcErr(RPC_CODES.TRANSPORT_FAILED);
      return { hash: BLOCK_ID, height: Number(h.job.height), nonce: NONCE_A, powHash: null, orphanStatus: false, prevHash: TEMPLATE_PREV, ...top };
    },
  };
  const run = h.mkRun({ daemon, canonical: { prevHashHex: TEMPLATE_PREV } });
  h.intent.start();
  run.begin();
  return { h, run, calls };
}

test('CANONICAL: success needs this block at its height, the template parent, and this block as the top', async () => {
  const { h, run, calls } = canonicalRun();
  const r = await run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(r.reason, TERMINAL.VERIFIED_COMPLETE);
  assert.equal(r.blockId, BLOCK_ID);
  assert.equal(r.confirmedBy, 'immediate_canonical_readback_top_block_with_matching_pow_hash');
  assert.equal(calls.header, 1);
  assert.equal(calls.top, 1);
  assert.equal(h.transportCalls.length, 1, 'exactly one submit_block');
});

test('CANONICAL: every mismatched field is failure or ambiguity, never success', async () => {
  const cases = [
    ['prev_hash', { header: { prevHash: 'a'.repeat(64) } }, TERMINAL.READBACK_MISMATCH],
    ['top_height', { top: { height: 999999 } }, TERMINAL.READBACK_MISMATCH],
    ['top_block_id', { top: { hash: 'c'.repeat(64) } }, TERMINAL.READBACK_MISMATCH],
    ['block_id at height', { header: { hash: 'd'.repeat(64) } }, TERMINAL.READBACK_MISMATCH],
    ['nonce', { header: { nonce: NONCE_A + 1 } }, TERMINAL.SUBMIT_UNTRUSTED],
    ['pow_hash', { header: { powHash: 'b'.repeat(64) } }, TERMINAL.SUBMIT_UNTRUSTED],
    ['orphan_status', { header: { orphanStatus: true } }, TERMINAL.SUBMIT_UNTRUSTED],
    ['top unreadable', { topThrows: true }, TERMINAL.SUBMIT_AMBIGUOUS],
    ['header unreadable', { headerThrows: true }, TERMINAL.SUBMIT_AMBIGUOUS],
  ];
  for (const [name, over, want] of cases) {
    const { h, run } = canonicalRun(over);
    const r = await run.submitCandidate(candidate(h.job, NONCE_A));
    assert.equal(r.ok, false, `${name}: reported success`);
    assert.equal(r.reason, want, `${name}: ${r.reason}`);
    assert.equal(types(h.events).includes('block_accepted'), false, name);
    assert.equal(h.transportCalls.length, 1, `${name}: submit_block was not exactly once`);
  }
});

test('CANONICAL: an ambiguous submit is resolved ONLY by an exact read-only readback, never resubmitted', async () => {
  // The transport hands the request over and then the answer is lost.
  const lost = async () => { throw new Error('socket reset after handoff'); };
  const { h, run, calls } = canonicalRun({ submit: lost });
  const r = await run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(r.reason, TERMINAL.VERIFIED_COMPLETE);
  assert.equal(r.confirmedBy, 'canonical_readback_resolved_an_ambiguous_submission');
  assert.equal(r.submitResponse, 'ambiguous');
  assert.equal(r.blockId, BLOCK_ID);
  assert.equal(h.transportCalls.length, 1, 'the block was submitted again');
  assert.equal(submitCount(h.calls), 1);
  assert.equal(calls.header, 1);
  assert.equal(calls.top, 1);

  // Any field short of exact leaves it ambiguous -- still with exactly one submission.
  for (const [name, over] of [
    ['nonce', { header: { nonce: NONCE_A + 1 } }],
    ['pow_hash', { header: { powHash: 'b'.repeat(64) } }],
    ['prev_hash', { header: { prevHash: 'a'.repeat(64) } }],
    ['orphan', { header: { orphanStatus: true } }],
    ['height', { header: { height: 999999 } }],
    ['top height', { top: { height: 999999 } }],
    ['top id', { top: { hash: 'c'.repeat(64) } }],
    ['unreadable', { headerThrows: true }],
  ]) {
    const c = canonicalRun({ submit: lost, ...over });
    const rr = await c.run.submitCandidate(candidate(c.h.job, NONCE_A));
    assert.equal(rr.reason, TERMINAL.SUBMIT_AMBIGUOUS, `${name}: ${rr.reason}`);
    assert.equal(c.h.transportCalls.length, 1, `${name}: resubmitted`);
    assert.equal(submitCount(c.h.calls), 1, `${name}: dispatched twice`);
  }
});

test('CANONICAL: an explicit daemon refusal is never "resolved" into success by a readback', async () => {
  const { h, run, calls } = canonicalRun({ submit: async ({ id }) => reply.error(id) });
  const r = await run.submitCandidate(candidate(h.job, NONCE_A));
  assert.equal(r.reason, TERMINAL.SUBMIT_REJECTED);
  assert.equal(calls.header, 0);
  assert.equal(calls.top, 0);
});

test('CANONICAL is off by default and refuses a half configuration', () => {
  const h = harness();
  assert.throws(() => h.mkRun({ canonical: { prevHashHex: 'zz' } }), /prevHashHex/);
  assert.throws(() => h.mkRun({ canonical: { prevHashHex: TEMPLATE_PREV } }), /getLastBlockHeader/);
});
