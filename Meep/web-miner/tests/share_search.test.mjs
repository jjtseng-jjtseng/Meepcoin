// ROUND 1b: THE BROWSER SIDE OF THE OPT-IN SHARE SEARCH.
//
// Two seams, both pure and in memory:
//
//   * the WORKER CORE with an injected hasher, so a bounded multi-hit search can be driven exactly:
//     every "hash" is chosen by the test, so shares, a block and exhaustion are all deterministic;
//   * the CONTROLLER with a fake Worker and a fake socket, so every ordering the real system rarely
//     produces -- the pacing cue arriving early, a duplicate report, a ninth hit, Stop mid-queue --
//     can be forced.
//
// WHAT IS MOCKED, HONESTLY. There is no browser, no Web Worker, no Wasm module, no pool listener, no
// daemon and no network here. These tests prove the CONTRACT between the page, its Worker and the
// server frames; they cannot prove that a real Chrome Worker over the real Wasm build produces the
// same hashes. That is what the (separately authorised, not re-run) live path is for.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createWorkerCore, WORKER_REFUSED } from '../lib/worker_core.js';
import { createMiningController, STOP_REASONS } from '../lib/controller.js';
import { searchNonces } from '../lib/shared/search.js';
import { bytesToHex, hexToBytes, nonceToHex } from '../lib/shared/target.js';
import { REAL_DAEMON_MODE, REAL_SEARCH_LIMITS, REAL_SHARE_LIMITS } from '../lib/shared/protocol.js';

// EVERY constant here is 32-byte LITTLE-ENDIAN: the LAST hex pair is the most significant byte.
//
//   block target = 1                  only a hash of 0 meets it
//   share target = 256^31             enormously easier; share >= block, as the server guarantees
//   SHARE_HASH(i) = i (2..255)        meets the share target, never the block target
//   MISS_HASH     = 2 * 256^31        meets neither
const BLOCK_TARGET = `01${'00'.repeat(31)}`;
const SHARE_TARGET = `${'00'.repeat(31)}01`;
const BLOCK_HASH = '00'.repeat(32);
const SHARE_HASH = (i) => `${((i % 250) + 2).toString(16).padStart(2, '0')}${'00'.repeat(31)}`;
const MISS_HASH = `${'00'.repeat(31)}02`;

// ==================================================================== the Worker core
function workerHarness({ hashFor, shareTargetHexLE = SHARE_TARGET, maxShares = REAL_SHARE_LIMITS.maxSharesPerJob }) {
  const posted = [];
  const hasher = {
    hashCalls: 0,
    hashOne(n) { hasher.hashCalls += 1; return hexToBytes(hashFor(n)); },
    wasmHeapBytes: () => 1,
    free() {},
    isActive: () => false,
  };
  const core = createWorkerCore({
    createModule: () => ({}),
    createV2Hasher: () => hasher,
    createV2HasherForContext: async () => hasher,
    searchNonces,
    hexToBytes,
    bytesToHex,
    nonceToHex,
    postMessage: (m) => posted.push(m),
    now: () => 0,
  });
  const init = (over = {}) => core.handle({
    cmd: 'init_search',
    gen: 1,
    jobId: 'realjob-1111',
    sequenceTotal: 1,
    window: {
      nonceStart: 0,
      nonceRange: 32,
      targetHexLE: BLOCK_TARGET,
      maxSearchMs: REAL_SEARCH_LIMITS.maxSearchMs,
      ...(shareTargetHexLE === null ? {} : { shareTargetHexLE, maxShares }),
      ...over,
    },
    context: {
      epochKeyHex: 'e'.repeat(64), seedHashHex: 'e'.repeat(64), height: '1',
      hashingTemplateHex: `1010${'00'.repeat(74)}`,
    },
  });
  const search = () => core.handle({ cmd: 'search', gen: 1, jobId: 'realjob-1111' });
  const of = (ev) => posted.filter((m) => m.ev === ev);
  return { core, posted, init, search, of, hasher };
}

test('WORKER SHARE: two share hits do not stop the search; a block hit does', async () => {
  // Nonces 3 and 7 are shares; nonce 11 is a block; everything else misses.
  const h = workerHarness({
    hashFor: (n) => (n === 3 ? SHARE_HASH(1) : n === 7 ? SHARE_HASH(2) : n === 11 ? BLOCK_HASH : MISS_HASH),
  });
  await h.init();
  await h.search();

  const shares = h.of('share');
  assert.deepEqual(shares.map((s) => s.nonce), [3, 7, 11], 'the search stopped at the first share');
  assert.deepEqual(shares.map((s) => s.block), [false, false, true]);
  assert.deepEqual(shares.map((s) => s.shareIndex), [1, 2, 3]);
  assert.deepEqual(shares.map((s) => s.nonceHex), ['00000003', '00000007', '0000000b']);
  assert.equal(shares[0].hashHexLE, SHARE_HASH(1));
  assert.equal(h.of('found').length, 0, 'share mode must not emit the legacy single-candidate event');

  const fin = h.of('finished')[0];
  assert.equal(fin.shares, 3);
  assert.equal(fin.blockFound, true);
  assert.equal(fin.stopCause, 'block_found');
  assert.equal(fin.found, 1);
  assert.equal(fin.hashes, 12, 'the search continued past the shares and stopped at the block');
  assert.equal(h.hasher.hashCalls, 12, 'no nonce was rescanned');
});

test('WORKER SHARE: the share cap ends the search, with no block', async () => {
  const h = workerHarness({ hashFor: (n) => SHARE_HASH(n % 250) });   // every nonce is a share
  await h.init();
  await h.search();
  const shares = h.of('share');
  assert.equal(shares.length, REAL_SHARE_LIMITS.maxSharesPerJob, 'the cap did not hold');
  assert.deepEqual(shares.map((s) => s.nonce), [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.equal(shares.some((s) => s.block), false);
  const fin = h.of('finished')[0];
  assert.equal(fin.shares, REAL_SHARE_LIMITS.maxSharesPerJob);
  assert.equal(fin.blockFound, false);
  assert.equal(fin.found, 0, 'the cap must not be reported as a block');
  assert.equal(fin.stopCause, 'share_cap');
  assert.equal(h.hasher.hashCalls, REAL_SHARE_LIMITS.maxSharesPerJob);
});

test('WORKER SHARE: a window with no qualifying hit is exhausted honestly', async () => {
  const h = workerHarness({ hashFor: () => MISS_HASH });
  await h.init();
  await h.search();
  assert.equal(h.of('share').length, 0);
  const fin = h.of('finished')[0];
  assert.equal(fin.shares, 0);
  assert.equal(fin.blockFound, false);
  assert.equal(fin.exhausted, true);
  assert.equal(fin.stopCause, 'window_exhausted');
  assert.equal(fin.hashes, 32);
});

test('WORKER SHARE: a share window is refused unless the share target is usable', async () => {
  for (const bad of [
    { shareTargetHexLE: 'nothex', maxShares: 4 },
    { shareTargetHexLE: SHARE_TARGET, maxShares: 0 },
    { shareTargetHexLE: SHARE_TARGET, maxShares: REAL_SHARE_LIMITS.maxSharesPerJob + 1 },
    // HARDER than the block target: refused, because a "share" rarer than a block is nonsense.
    { shareTargetHexLE: '00'.repeat(32), maxShares: 4 },   // target 0 < block target 1
  ]) {
    const h = workerHarness({ hashFor: () => MISS_HASH });
    const r = await h.init(bad);
    assert.equal(r.ok, false, JSON.stringify(bad));
    assert.equal(r.reason, WORKER_REFUSED.BAD_WINDOW, JSON.stringify(bad));
    assert.equal(h.hasher.hashCalls, 0, 'a refused window allocated and hashed');
  }
  // A share target EQUAL to the block target is legal (share difficulty may equal the network's).
  const equal = workerHarness({ hashFor: () => MISS_HASH });
  assert.equal((await equal.init({ shareTargetHexLE: BLOCK_TARGET, maxShares: 2 })).ok, true);
});

test('WORKER LEGACY: without a share target the search is exactly the one-solution search', async () => {
  const h = workerHarness({
    hashFor: (n) => (n === 3 || n === 7 ? BLOCK_HASH : MISS_HASH),
    shareTargetHexLE: null,
  });
  await h.init();
  await h.search();
  assert.equal(h.of('share').length, 0, 'a legacy window produced share events');
  assert.deepEqual(h.of('found').map((f) => f.nonce), [3], 'the legacy search did not stop at its one solution');
  const fin = h.of('finished')[0];
  assert.equal(fin.found, 1);
  assert.equal(fin.shares, undefined, 'legacy finished gained share fields');
  assert.equal(fin.stopCause, undefined);
  assert.equal(h.hasher.hashCalls, 4);
});

// ==================================================================== the controller
const WORKER_ID = 'sim-1-bbbb';
const START = 'a'.repeat(32);
const JOB = {
  type: 'real_job',
  jobId: 'realjob-1111',
  issuanceId: '1'.repeat(32),
  contentDigest: '1'.repeat(64),
  algorithm: 'meephash-w-v2-frozen-real-template',
  height: '1',
  majorVersion: 16,
  epochKeyHex: 'e'.repeat(64),
  seedHashHex: 'e'.repeat(64),
  hashingTemplateHex: `1010${'00'.repeat(74)}`,
  targetHexLE: BLOCK_TARGET,
  shareWork: true,
  shareTargetHexLE: SHARE_TARGET,
  nonceStart: 0,
  nonceRange: 8192,
  expiresAtMs: 1,
};

function controllerHarness({ job = JOB } = {}) {
  const workers = [];
  const sockets = [];
  const controller = createMiningController({
    createWorker: () => {
      const w = {
        posted: [], terminated: 0, onmessage: null, onerror: null,
        postMessage(m) { this.posted.push(m); },
        terminate() { this.terminated++; },
        emit(data) { this.onmessage?.({ data }); },
      };
      workers.push(w);
      return w;
    },
    createSocket: () => {
      const s = {
        sent: [], onopen: null, onmessage: null, onclose: null, onerror: null,
        send(t) { this.sent.push(JSON.parse(t)); },
        close() {},
        deliver(o) { this.onmessage?.({ data: JSON.stringify(o) }); },
      };
      sockets.push(s);
      return s;
    },
    newStartId: () => START,
  });
  controller.connect('ws://127.0.0.1:1/ws');
  const socket = sockets[0];
  socket.onopen();
  socket.deliver({
    type: 'server_hello', protocolVersion: 1, mode: REAL_DAEMON_MODE, workerId: WORKER_ID,
    labels: [], alreadyCompleted: false, searchLimits: REAL_SEARCH_LIMITS,
  });
  socket.deliver(job);
  const bind = {
    clientStartId: START, workerId: WORKER_ID, jobId: job.jobId, issuanceId: job.issuanceId,
    runGeneration: 1,
  };
  controller.start();
  socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...bind });
  socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, ...bind });
  const w = workers[0];
  w?.emit({ ev: 'ready', jobId: job.jobId, contextIndex: 1, moduleInstances: 1 });
  const share = (nonce, hashHexLE, block = false) => w.emit({
    ev: 'share', jobId: job.jobId, nonce, nonceHex: nonceToHex(nonce), hashHexLE, block, shareIndex: 1,
  });
  const settled = (nonce, over = {}) => socket.deliver({
    type: 'candidate_settled', terminal: false, nonce, ...bind, ...over,
  });
  const accepted = (nonce, hashHexLE, over = {}) => socket.deliver({
    type: 'share_accepted', terminal: false, nonce, hashHexLE, ...bind, ...over,
  });
  const submits = () => socket.sent.filter((m) => m.type === 'submit_real_candidate');
  return { controller, socket, workers, w, bind, share, settled, accepted, submits };
}

test('CONTROLLER SHARE: the issued window carries the server share target and the shared cap', () => {
  const h = controllerHarness();
  const init = h.w.posted.find((m) => m.cmd === 'init_search');
  assert.ok(init, 'no search was initialised');
  assert.equal(init.window.shareTargetHexLE, SHARE_TARGET);
  assert.equal(init.window.maxShares, REAL_SHARE_LIMITS.maxSharesPerJob);
  assert.equal(init.window.targetHexLE, BLOCK_TARGET, 'the block target must still be issued');
  assert.equal(h.controller.snapshot().realShareMode, true);
});

test('CONTROLLER SHARE: a job whose share target is harder than its block target is refused', () => {
  const h = controllerHarness({ job: { ...JOB, shareTargetHexLE: '00'.repeat(32) } });   // target 0
  assert.equal(h.workers.length, 0, 'a Worker was allocated for an unusable share target');
  assert.match(h.controller.snapshot().error ?? '', /unusable share target/);
  assert.equal(h.controller.start(), false, 'Start was still possible');
});

test('CONTROLLER SHARE: one submission at a time, released only by the settled cue', () => {
  const h = controllerHarness();
  h.share(3, SHARE_HASH(1));
  h.share(7, SHARE_HASH(2));
  h.share(11, BLOCK_HASH, true);

  assert.equal(h.submits().length, 1, 'more than one candidate was outstanding');
  assert.equal(h.submits()[0].nonce, '00000003');
  assert.equal(h.controller.snapshot().realSharesReported, 3);
  assert.equal(h.controller.snapshot().realShareQueueDepth, 2);

  // The ACCEPTANCE alone must not release the next one: the server's slot is still held there.
  h.accepted(3, SHARE_HASH(1));
  assert.equal(h.submits().length, 1, 'share_accepted released the next report');
  assert.equal(h.controller.snapshot().realSharesAccepted, 1);

  // The cue does, and only for the outstanding nonce.
  h.settled(999);
  assert.equal(h.submits().length, 1, 'a cue for another nonce released a report');
  h.settled(3);
  assert.equal(h.submits().length, 2);
  assert.equal(h.submits()[1].nonce, '00000007');

  h.accepted(7, SHARE_HASH(2));
  h.settled(7);
  assert.equal(h.submits().length, 3);
  assert.equal(h.submits()[2].nonce, '0000000b', 'the block-quality report was not sent last');
  assert.equal(h.controller.snapshot().realSharesAccepted, 2, 'a block was counted as a share');

  // Only the server's own block message may say a block happened.
  assert.equal(h.controller.snapshot().realOutcome, null);
  h.socket.deliver({
    type: 'block_accepted', terminal: true, height: '1', nonce: 11, hashHexLE: BLOCK_HASH,
    blockId: 'c'.repeat(64), confirmedBy: 'canonical_readback', ...h.bind,
  });
  assert.equal(h.controller.snapshot().realOutcome, 'block_accepted');
});

test('CONTROLLER SHARE: a duplicate, a ninth, a forged or a stale report fails closed', () => {
  for (const [label, emit] of [
    ['a duplicate nonce', (h) => { h.share(3, SHARE_HASH(1)); h.share(3, SHARE_HASH(1)); }],
    ['a nonce outside the window', (h) => h.share(999999, SHARE_HASH(1))],
    ['a hash that does not meet the share target', (h) => h.share(3, MISS_HASH)],
    ['a malformed hash', (h) => h.share(3, 'nope')],
    ['a mismatched nonceHex', (h) => h.w.emit({
      ev: 'share', jobId: JOB.jobId, nonce: 3, nonceHex: '00000004', hashHexLE: SHARE_HASH(1), block: false,
    })],
    ['a report for another job', (h) => h.w.emit({
      ev: 'share', jobId: 'realjob-9999', nonce: 3, nonceHex: '00000003', hashHexLE: SHARE_HASH(1), block: false,
    })],
    ['a ninth hit', (h) => {
      for (let i = 0; i < REAL_SHARE_LIMITS.maxSharesPerJob + 1; i += 1) h.share(i, SHARE_HASH(i + 1));
    }],
  ]) {
    const h = controllerHarness();
    emit(h);
    const snap = h.controller.snapshot();
    assert.equal(h.controller.runIntent, false, `${label}: the run continued`);
    assert.equal(h.w.terminated, 1, `${label}: the Worker was left running`);
    assert.ok(snap.error, label);
    assert.ok(h.submits().length <= REAL_SHARE_LIMITS.maxSharesPerJob, label);
  }
});

test('CONTROLLER SHARE: an unexpected queue_full fails closed instead of retrying', () => {
  const h = controllerHarness();
  h.share(3, SHARE_HASH(1));
  assert.equal(h.submits().length, 1);
  h.socket.deliver({ type: 'error', reason: 'queue_full' });
  assert.equal(h.controller.runIntent, false, 'the page kept mining after an impossible refusal');
  assert.equal(h.submits().length, 1, 'the page retried a refused candidate');
  assert.match(h.controller.snapshot().error ?? '', /already verifying/);
});

test('CONTROLLER SHARE: a finished search with shares outstanding waits for the server', () => {
  const h = controllerHarness();
  h.share(3, SHARE_HASH(1));
  h.share(11, BLOCK_HASH, true);
  h.w.emit({
    ev: 'finished', jobId: JOB.jobId, hashes: 12, found: 1, shares: 2, blockFound: true,
    stopCause: 'block_found', exhausted: false,
  });
  const snap = h.controller.snapshot();
  assert.equal(h.controller.runIntent, true, 'the page stopped over an in-flight submission');
  assert.equal(snap.realSearchSettled, true);
  assert.equal(snap.realShareStopCause, 'block_found');
  assert.equal(h.socket.sent.some((m) => m.type === 'stop_request'), false,
    'the page sent Stop while the server still held a candidate');
  assert.equal(h.submits().length, 1, 'the queue drained without a cue');

  // The server's own terminal ends it.
  h.socket.deliver({ type: 'block_rejected', terminal: true, reason: 'above_target', ...h.bind });
  assert.equal(h.controller.runIntent, false);
});

test('CONTROLLER SHARE: Stop, a hidden tab and a lost socket all end the run and send nothing more', () => {
  for (const [label, act] of [
    ['Stop', (h) => h.controller.stop(STOP_REASONS.USER)],
    ['a hidden tab', (h) => h.controller.setHidden(true)],
    ['a lost socket', (h) => h.socket.onclose?.({ code: 1006 })],
  ]) {
    const h = controllerHarness();
    h.share(3, SHARE_HASH(1));
    h.share(7, SHARE_HASH(2));
    const before = h.submits().length;
    act(h);
    assert.equal(h.controller.runIntent, false, `${label}: run intent survived`);
    // The queued report must not be released afterwards, by a cue or anything else.
    h.settled(3);
    assert.equal(h.submits().length, before, `${label}: a queued report was sent after the run ended`);
    // And nothing auto-resumes: becoming visible again, or the socket returning, changes nothing.
    h.controller.setHidden(false);
    assert.equal(h.controller.runIntent, false, `${label}: the run resumed by itself`);
  }
});

test('CONTROLLER LEGACY: a job without share work keeps the one-candidate path exactly', () => {
  const { shareWork, shareTargetHexLE, ...legacyJob } = JOB;
  const h = controllerHarness({ job: legacyJob });
  const init = h.w.posted.find((m) => m.cmd === 'init_search');
  assert.equal(init.window.shareTargetHexLE, undefined, 'a legacy window carried a share target');
  assert.equal(init.window.maxShares, undefined);
  assert.equal(h.controller.snapshot().realShareMode, false);

  h.w.emit({ ev: 'found', jobId: JOB.jobId, nonce: 5, nonceHex: '00000005', hashHexLE: BLOCK_HASH });
  assert.equal(h.submits().length, 1);
  assert.equal(h.submits()[0].nonce, '00000005');
  // A share event on a legacy job is a fault, not silently accepted work.
  h.share(7, SHARE_HASH(1));
  assert.equal(h.controller.runIntent, false);
  assert.match(h.controller.snapshot().error ?? '', /share for a job that has none/);
});

// ==================================================================== the Round 1b audit findings
//
// Three defects an independent audit found in the first revision of this loop. Each test below
// fails against that revision.

test('CONTROLLER SHARE: an accepted browser block is recorded as this page\'s own evidence', () => {
  const h = controllerHarness();
  h.share(3, SHARE_HASH(1));
  h.settled(3);
  // The Worker's `block` hint is deliberately WRONG here (false for a block-quality hash): the page
  // must derive block quality itself, from the validated hash against the server's block target.
  h.share(11, BLOCK_HASH, false);
  h.settled(3);                                        // ignored: not the outstanding nonce
  h.settled(11);
  assert.equal(h.controller.snapshot().realFoundNonce, 11, 'the block hit was not recorded');
  // The server's three-way recomputation, as the real block path sends it before submitting.
  h.socket.deliver({ type: 'candidate_verified', hashHexLE: BLOCK_HASH, ...h.bind });
  assert.equal(h.controller.snapshot().simBrowserEvidence, 'reported');
  assert.equal(h.controller.snapshot().simBrowserHashHexLE, BLOCK_HASH);

  h.socket.deliver({
    type: 'block_accepted', terminal: true, height: '1', nonce: 11, hashHexLE: BLOCK_HASH,
    blockId: 'c'.repeat(64), confirmedBy: 'canonical_readback', ...h.bind,
  });
  const snap = h.controller.snapshot();
  assert.equal(snap.realOutcome, 'block_accepted');
  assert.equal(snap.simBrowserMatched, true,
    'a block this browser really found was reported as unmatched');
});

test('CONTROLLER SHARE: browser agreement is NOT claimed for a block this page did not produce', () => {
  for (const [label, terminalOver] of [
    ['a different nonce', { nonce: 12 }],
    ['a different hash', { hashHexLE: `${'0a'.repeat(31)}00` }],
  ]) {
    const h = controllerHarness();
    h.share(11, BLOCK_HASH, true);
    h.socket.deliver({ type: 'candidate_verified', hashHexLE: BLOCK_HASH, ...h.bind });
    h.socket.deliver({
      type: 'block_accepted', terminal: true, height: '1', nonce: 11, hashHexLE: BLOCK_HASH,
      blockId: 'c'.repeat(64), confirmedBy: 'canonical_readback', ...h.bind, ...terminalOver,
    });
    assert.equal(h.controller.snapshot().simBrowserMatched, false,
      `${label}: browser agreement was claimed for a result this page did not produce`);
  }
  // A share-only run claims no browser agreement either: there is no block of ours to match.
  const shareOnly = controllerHarness();
  shareOnly.share(3, SHARE_HASH(1));
  assert.equal(shareOnly.controller.snapshot().simBrowserEvidence, null,
    'a non-block share was recorded as block evidence');
  assert.equal(shareOnly.controller.snapshot().realFoundNonce, null);
});

test('CONTROLLER SHARE: a replayed acceptance counts once; a different share still counts', () => {
  const h = controllerHarness();
  h.share(3, SHARE_HASH(1));
  h.share(7, SHARE_HASH(2));

  h.accepted(3, SHARE_HASH(1));
  h.accepted(3, SHARE_HASH(1));                        // an exact replay, before the cue
  h.accepted(3, SHARE_HASH(1));
  assert.equal(h.controller.snapshot().realSharesAccepted, 1, 'a replayed acceptance was counted twice');

  h.settled(3);
  h.accepted(7, SHARE_HASH(2));
  assert.equal(h.controller.snapshot().realSharesAccepted, 2,
    'the latch suppressed a genuinely different share');
  h.accepted(7, SHARE_HASH(2));
  assert.equal(h.controller.snapshot().realSharesAccepted, 2);
  // An acceptance that does not match the outstanding report is ignored either way.
  h.accepted(99, SHARE_HASH(3));
  assert.equal(h.controller.snapshot().realSharesAccepted, 2);
});

test('CONTROLLER SHARE: a legacy `found` event from a share-mode Worker fails closed', () => {
  const h = controllerHarness();
  h.w.emit({ ev: 'found', jobId: JOB.jobId, nonce: 5, nonceHex: '00000005', hashHexLE: BLOCK_HASH });
  assert.equal(h.submits().length, 0, 'a legacy event bypassed the opt-in queue and submitted');
  assert.equal(h.controller.runIntent, false, 'the run continued after an impossible Worker event');
  assert.equal(h.w.terminated, 1);
  assert.match(h.controller.snapshot().error ?? '', /single result for a share job/);
});

test('CONTROLLER SHARE: Stop, hidden and socket loss still end a run that recorded block evidence', () => {
  for (const [label, act] of [
    ['Stop', (h) => h.controller.stop(STOP_REASONS.USER)],
    ['a hidden tab', (h) => h.controller.setHidden(true)],
    ['a lost socket', (h) => h.socket.onclose?.({ code: 1006 })],
  ]) {
    const h = controllerHarness();
    h.share(11, BLOCK_HASH, true);
    assert.equal(h.controller.snapshot().simBrowserEvidence, 'reported', label);
    const before = h.submits().length;
    act(h);
    assert.equal(h.controller.runIntent, false, `${label}: run intent survived`);
    h.settled(11);
    assert.equal(h.submits().length, before, `${label}: a report was released after the run ended`);
    h.controller.setHidden(false);
    assert.equal(h.controller.runIntent, false, `${label}: the run resumed by itself`);
  }
});
