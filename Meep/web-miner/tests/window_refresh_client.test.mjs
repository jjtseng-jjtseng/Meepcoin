// THE PAGE SIDE OF THE OPT-IN SAME-HEIGHT REFRESH: one Start, ONE Worker, several nonce windows.
//
// No browser, no Wasm, no server, no daemon: a fake Worker and a fake socket drive the real
// controller, so every ordering the live system rarely produces can be forced -- a refresh that
// arrives before the Worker settled, a refresh naming the wrong binding, a refresh after Stop.
//
// WHAT MUST HOLD: the same Worker is re-contextualised (never a second Worker, never a second live
// context), only after its previous search settled; the new window must be the SAME height with a
// different capability and a nonce range that does not overlap the one it replaces -- even though
// the template bytes, and therefore the content digest, may be identical; and an exhausted window
// is NOT a reason for the page to Stop a session the server may still refresh.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createMiningController, STOP_REASONS } from '../lib/controller.js';
import {
  REAL_DAEMON_MODE, REAL_REFRESH_LIMITS, REAL_SEARCH_LIMITS,
} from '../lib/shared/protocol.js';

const WORKER_ID = 'sim-1-bbbb';
const START = 'a'.repeat(32);
const BLOCK_TARGET = `01${'00'.repeat(31)}`;
const SHARE_TARGET = `${'00'.repeat(31)}01`;
const BLOCK_HASH = '00'.repeat(32);
const SHARE_HASH = (i) => `${((i % 250) + 2).toString(16).padStart(2, '0')}${'00'.repeat(31)}`;

const JOB1 = {
  type: 'real_job',
  jobId: 'realjob-w1',
  issuanceId: '1'.repeat(32),
  contentDigest: 'c'.repeat(64),
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
  nonceRange: REAL_SEARCH_LIMITS.maxAttempts,
  expiresAtMs: 1,
};
/** The SAME height and the SAME content digest: only the capability and the window differ. */
const JOB2 = {
  ...JOB1,
  jobId: 'realjob-w2',
  issuanceId: '2'.repeat(32),
  nonceStart: REAL_SEARCH_LIMITS.maxAttempts,
};
const JOB_BLOCK2 = {
  ...JOB1,
  jobId: 'realjob-b2w1',
  issuanceId: '3'.repeat(32),
  contentDigest: 'd'.repeat(64),
  height: '2',
  hashingTemplateHex: `1110${'00'.repeat(74)}`,
  nonceStart: 0,
};

function harness({ windowTotal = 3, sequenceTotal = 1, job = JOB1, helloOver = null, readyOver = null } = {}) {
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
    ...(sequenceTotal > 1 ? { sequenceTotal } : {}),
    ...(windowTotal !== 1 ? { windowTotal, sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs } : {}),
    ...(helloOver ?? {}),
  });
  socket.deliver(job);
  const bind1 = {
    clientStartId: START, workerId: WORKER_ID, jobId: job.jobId, issuanceId: job.issuanceId,
    runGeneration: 1,
  };
  controller.start();
  socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...bind1 });
  // Window facts are sent only by a server that offered windows: an unsolicited one is a fault.
  socket.deliver({
    type: 'mining_ready', mode: REAL_DAEMON_MODE, ...bind1,
    ...(sequenceTotal > 1 ? { sequenceTotal, sequenceIndex: 1 } : {}),
    ...(windowTotal > 1 ? { windowIndex: 1, windowTotal, sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs } : {}),
    ...(readyOver ?? {}),
  });
  const w = workers[0];
  w?.emit({ ev: 'ready', jobId: job.jobId, contextIndex: 1, moduleInstances: 1 });
  const bind2 = {
    clientStartId: START, workerId: WORKER_ID, jobId: JOB2.jobId, issuanceId: JOB2.issuanceId,
    runGeneration: 2,
  };
  /** The server's own readiness for the new window: what actually permits the re-context. */
  const readyForNextWindow = (over = {}) => socket.deliver({
    type: 'mining_ready', mode: REAL_DAEMON_MODE, ...bind2, windowIndex: 2, windowTotal,
    sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs,
    ...(sequenceTotal > 1 ? { sequenceTotal, sequenceIndex: 1 } : {}), ...over,
  });
  const refresh = (over = {}) => socket.deliver({
    type: 'job_refresh',
    terminal: false,
    cause: 'window_exhausted',
    windowIndex: 2,
    windowTotal,
    ...(sequenceTotal > 1 ? { sequenceTotal, sequenceIndex: 1 } : {}),
    previous: { jobId: job.jobId, issuanceId: job.issuanceId, runGeneration: 1 },
    job: JOB2,
    ...bind2,
    ...over,
  });
  const finished = (jobId = job.jobId, over = {}) => w.emit({
    ev: 'finished', jobId, hashes: 8192, found: 0, shares: 8, blockFound: false,
    stopCause: 'share_cap', exhausted: false, ...over,
  });
  const posted = (cmd) => w.posted.filter((m) => m.cmd === cmd);
  return {
    controller, socket, workers, w, bind1, bind2, refresh, readyForNextWindow, finished, posted,
    windowTotal, sequenceTotal,
  };
}

test('CLIENT REFRESH: the declared window total latches the Worker context budget', () => {
  const h = harness({ windowTotal: 3 });
  const init = h.posted('init_search')[0];
  assert.ok(init, 'no search was initialised');
  assert.equal(init.contextLimit, 3, 'the Worker was not given the window budget');
  assert.equal(init.window.nonceStart, 0);
  assert.equal(h.controller.snapshot().realWindowTotal, 3);
  assert.equal(h.controller.snapshot().realWindowIndex, 1);
  assert.equal(h.controller.snapshot().realSequenceTotal, 1, 'a window was counted as a block');

  // No declaration at all is the legacy path: no context budget beyond the sequence's own.
  const plain = harness({ windowTotal: 1 });
  assert.equal(plain.posted('init_search')[0].contextLimit, undefined);
  assert.equal(plain.controller.snapshot().realWindowTotal, 1);
});

test('CLIENT REFRESH: an over-limit window total is a protocol error', () => {
  for (const total of [REAL_REFRESH_LIMITS.maxWindows + 1, 0, 1.5]) {
    const h = harness({ windowTotal: total });
    assert.match(h.controller.snapshot().error ?? '', /invalid window total/, String(total));
    assert.equal(h.controller.start(), false, `${total}: Start was still possible`);
  }
});

test('CLIENT COMPOSED BUDGET: block and window totals compose only within the 32-context ceiling', () => {
  const valid = harness({ sequenceTotal: 16, windowTotal: 2 });
  const init = valid.posted('init_search')[0];
  assert.ok(init, 'a valid composed run did not initialise');
  assert.deepEqual(
    { sequenceTotal: init.sequenceTotal, contextLimit: init.contextLimit, sequenceIndex: init.sequenceIndex, windowIndex: init.windowIndex },
    { sequenceTotal: 16, contextLimit: 2, sequenceIndex: 1, windowIndex: 1 },
  );

  const over = harness({ sequenceTotal: 17, windowTotal: 2 });
  assert.match(over.controller.snapshot().error ?? '', /invalid window total/);
  assert.equal(over.workers.length, 0, 'an over-budget composition allocated a Worker');
  assert.equal(over.controller.start(), false, 'an over-budget composition remained startable');
});

test('CLIENT REFRESH: the SAME Worker is re-contextualised, and only after its search settled', () => {
  const h = harness();
  h.refresh();
  h.readyForNextWindow();
  // The Worker is still searching the replaced window: nothing may be posted to it yet.
  assert.equal(h.posted('init_search_next').length, 0, 'the Worker was rotated mid-search');
  assert.equal(h.controller.snapshot().realWindowIndex, 2);

  h.finished();                                   // the old window's one search settles
  const next = h.posted('init_search_next')[0];
  assert.ok(next, 'the settled Worker was never re-contextualised');
  assert.equal(next.prevJobId, JOB1.jobId);
  assert.equal(next.jobId, JOB2.jobId);
  assert.equal(next.contextLimit, h.windowTotal);
  assert.equal(next.window.nonceStart, REAL_SEARCH_LIMITS.maxAttempts, 'the new window is not disjoint');
  assert.equal(next.window.nonceRange, REAL_SEARCH_LIMITS.maxAttempts);
  assert.equal(next.window.shareTargetHexLE, SHARE_TARGET);
  // ONE Worker for the whole session, and no second one at any point.
  assert.equal(h.workers.length, 1, 'a second Worker was created');
  assert.equal(h.w.terminated, 0);
  assert.equal(h.controller.snapshot().realWorkersCreated, 1);
  assert.equal(h.controller.snapshot().realWindowRefreshes, 1);
});

test('CLIENT COMPOSED HANDOFF: windows advance within a block, then reset to window one for the next block', () => {
  const h = harness({ sequenceTotal: 2, windowTotal: 2 });
  h.finished(JOB1.jobId, { hashes: 100 });
  h.refresh();
  h.readyForNextWindow();
  h.w.emit({
    ev: 'ready', jobId: JOB2.jobId, contextIndex: 2, moduleInstances: 1, rotated: true,
    priorContextFreed: true, priorContextActive: false,
  });
  h.finished(JOB2.jobId, { hashes: 200, found: 1 });

  h.socket.deliver({
    type: 'sequence_block_accepted', terminal: false, sequenceTotal: 2, sequenceIndex: 1,
    height: JOB2.height, nonce: 0, blockId: 'b'.repeat(64), hashHexLE: BLOCK_HASH,
    confirmedBy: 'node_a', ...h.bind2,
  });
  const bind3 = {
    clientStartId: START, workerId: WORKER_ID, jobId: JOB_BLOCK2.jobId,
    issuanceId: JOB_BLOCK2.issuanceId, runGeneration: 3,
  };
  h.socket.deliver({
    type: 'sequence_next', terminal: false, cause: 'accepted', sequenceTotal: 2, sequenceIndex: 2,
    windowTotal: 2, windowIndex: 1, sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs,
    previous: { jobId: JOB2.jobId, issuanceId: JOB2.issuanceId, runGeneration: 2 },
    job: JOB_BLOCK2, ...bind3,
  });
  let snap = h.controller.snapshot();
  assert.deepEqual(
    { issuedBlock: snap.realBlockIndex, issuedWindow: snap.realWindowIndex, activeBlock: snap.realActiveBlockIndex, activeWindow: snap.realActiveWindowIndex },
    { issuedBlock: 2, issuedWindow: 1, activeBlock: 1, activeWindow: 2 },
    'the page blurred the issued next-block context with the still-active old one',
  );
  assert.equal(snap.realWindowHandoff, true);
  assert.equal(snap.realBlocks[0].attempts, 300, 'per-block attempts did not sum both windows');

  h.socket.deliver({
    type: 'mining_ready', mode: REAL_DAEMON_MODE, sequenceTotal: 2, sequenceIndex: 2,
    windowTotal: 2, windowIndex: 1, sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs, ...bind3,
  });
  const rotations = h.posted('init_search_next');
  assert.equal(rotations.length, 2);
  assert.deepEqual(
    { sequenceTotal: rotations[1].sequenceTotal, contextLimit: rotations[1].contextLimit, sequenceIndex: rotations[1].sequenceIndex, windowIndex: rotations[1].windowIndex },
    { sequenceTotal: 2, contextLimit: 2, sequenceIndex: 2, windowIndex: 1 },
  );
  h.w.emit({
    ev: 'ready', jobId: JOB_BLOCK2.jobId, contextIndex: 3, moduleInstances: 1, rotated: true,
    priorContextFreed: true, priorContextActive: false,
  });
  snap = h.controller.snapshot();
  assert.deepEqual(
    { activeBlock: snap.realActiveBlockIndex, activeWindow: snap.realActiveWindowIndex, handoff: snap.realWindowHandoff },
    { activeBlock: 2, activeWindow: 1, handoff: false },
  );
  assert.equal(h.workers.length, 1, 'the composed handoff created a second Worker');
});

test('CLIENT COMPOSED HANDOFF: a next-block window-one claim cannot carry a later-window nonce range', () => {
  const h = harness({ sequenceTotal: 2, windowTotal: 2 });
  h.finished(JOB1.jobId, { hashes: 100, found: 1 });
  h.socket.deliver({
    type: 'sequence_block_accepted', terminal: false, sequenceTotal: 2, sequenceIndex: 1,
    height: JOB1.height, nonce: 0, blockId: 'b'.repeat(64), hashHexLE: BLOCK_HASH,
    confirmedBy: 'node_a', ...h.bind1,
  });
  const badJob = { ...JOB_BLOCK2, nonceStart: REAL_SEARCH_LIMITS.maxAttempts };
  const badBind = {
    clientStartId: START, workerId: WORKER_ID, jobId: badJob.jobId,
    issuanceId: badJob.issuanceId, runGeneration: 2,
  };
  h.socket.deliver({
    type: 'sequence_next', terminal: false, cause: 'accepted', sequenceTotal: 2, sequenceIndex: 2,
    windowTotal: 2, windowIndex: 1, sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs,
    previous: { jobId: JOB1.jobId, issuanceId: JOB1.issuanceId, runGeneration: 1 },
    job: badJob, ...badBind,
  });
  assert.equal(h.controller.blockIndex, 1, 'the carried-over nonce range advanced the block coordinate');
  assert.equal(h.controller.serverRunGeneration, 1, 'the carried-over nonce range replaced the live binding');
  assert.equal(h.posted('init_search_next').length, 0, 'the Worker was rotated to the invalid range');
});

test('CLIENT REFRESH: an exhausted window is not a reason to Stop a refreshable session', () => {
  const h = harness();
  h.finished();
  assert.equal(h.controller.runIntent, true, 'the page stopped a session the server may refresh');
  assert.equal(h.socket.sent.some((m) => m.type === 'stop_request'), false, 'a Stop was sent');
  assert.equal(h.controller.snapshot().realOutcome, null, 'the page declared a bounded no-solution');
  // The refresh then arrives, and the already-settled Worker is rotated as soon as the server is
  // ready for the new window.
  h.refresh();
  h.readyForNextWindow();
  assert.equal(h.posted('init_search_next').length, 1);

  // The LAST window is different: there is nothing further to wait for.
  const last = harness({ windowTotal: 2 });
  last.refresh();
  last.finished();
  last.readyForNextWindow();
  assert.equal(last.controller.snapshot().realWindowIndex, 2);
  last.finished(JOB2.jobId, { shares: 0, stopCause: 'window_exhausted', exhausted: true });
  assert.equal(last.controller.runIntent, true,
    'share mode still waits for the server after the last window');
});

test('CLIENT REFRESH: a refresh that does not extend this exact binding is ignored', () => {
  const cases = [
    ['a foreign previous binding', { previous: { jobId: 'other', issuanceId: '9'.repeat(32), runGeneration: 1 } }],
    ['a stale run generation', { runGeneration: 1 }],
    ['a reused job id', { job: { ...JOB2, jobId: JOB1.jobId }, jobId: JOB1.jobId }],
    ['a reused issuance', { job: { ...JOB2, issuanceId: JOB1.issuanceId }, issuanceId: JOB1.issuanceId }],
    ['another height', { job: { ...JOB2, height: '2' } }],
    ['an overlapping nonce window', { job: { ...JOB2, nonceStart: REAL_SEARCH_LIMITS.maxAttempts - 1 } }],
    ['a window index that skips one', { windowIndex: 3 }],
    ['a window index beyond the total', { windowIndex: 4, windowTotal: 3 }],
    ['another cause', { cause: 'accepted' }],
    ['a different declared total', { windowTotal: 2 }],
    ['a share target harder than the block target', { job: { ...JOB2, shareTargetHexLE: '00'.repeat(32) } }],
    ['a dropped share mode', { job: { ...JOB2, shareWork: false, shareTargetHexLE: undefined } }],
    ['a foreign worker', { workerId: 'sim-9-zzzz' }],
  ];
  for (const [label, over] of cases) {
    const h = harness();
    h.refresh(over);
    h.finished();
    h.readyForNextWindow();
    assert.equal(h.posted('init_search_next').length, 0, `${label}: the Worker was rotated`);
    assert.equal(h.controller.snapshot().realWindowIndex, 1, `${label}: the page moved on`);
    assert.equal(h.workers.length, 1, label);
  }
});

test('CLIENT REFRESH: Stop, a hidden tab and a lost socket prevent any re-contextualisation', () => {
  for (const [label, act] of [
    ['Stop', (h) => h.controller.stop(STOP_REASONS.USER)],
    ['a hidden tab', (h) => h.controller.setHidden(true)],
    ['a lost socket', (h) => h.socket.onclose?.({ code: 1006 })],
  ]) {
    const h = harness();
    h.finished();
    act(h);
    assert.equal(h.controller.runIntent, false, `${label}: run intent survived`);
    h.refresh();
    h.readyForNextWindow();
    assert.equal(h.posted('init_search_next').length, 0, `${label}: the Worker was rotated after the end`);
    assert.equal(h.workers.length, 1, label);
    // And nothing auto-resumes.
    h.controller.setHidden(false);
    assert.equal(h.controller.runIntent, false, `${label}: the session resumed by itself`);
  }
});

test('CLIENT REFRESH: a terminal message supersedes a refresh, and shares stay per window', () => {
  const h = harness();
  // One accepted share in window 1, then the refresh: the new window starts with a clean queue.
  h.w.emit({ ev: 'share', jobId: JOB1.jobId, nonce: 3, nonceHex: '00000003', hashHexLE: SHARE_HASH(1) });
  h.socket.deliver({ type: 'share_accepted', terminal: false, nonce: 3, hashHexLE: SHARE_HASH(1), ...h.bind1 });
  assert.equal(h.controller.snapshot().realSharesAccepted, 1);
  h.finished();
  h.refresh();
  h.readyForNextWindow();
  assert.equal(h.posted('init_search_next').length, 1);
  assert.equal(h.controller.snapshot().realSharesReported, 0, 'the old window kept its reports');
  assert.equal(h.controller.snapshot().realShareQueueDepth, 0);
  assert.equal(h.controller.snapshot().realSharesAccepted, 1, 'the session total lost an accepted share');
  // An acceptance for the RETIRED window is not counted again.
  h.socket.deliver({ type: 'share_accepted', terminal: false, nonce: 3, hashHexLE: SHARE_HASH(1), ...h.bind1 });
  assert.equal(h.controller.snapshot().realSharesAccepted, 1);

  // The server's own terminal ends the session, whatever windows remain.
  h.socket.deliver({
    type: 'run_stopped', terminal: true, accepted: true, reason: 'search_bound_reached', ...h.bind2,
  });
  assert.equal(h.controller.runIntent, false);
  assert.equal(h.controller.snapshot().realOutcome, 'bounded_no_solution');
  const posts = h.posted('init_search_next').length;
  h.refresh({ windowIndex: 3, runGeneration: 3, previous: { jobId: JOB2.jobId, issuanceId: JOB2.issuanceId, runGeneration: 2 } });
  assert.equal(h.posted('init_search_next').length, posts, 'a refresh was honoured after the terminal');
});

// ================================================================== the audit's counterexamples
//
// Each test below fails on the first draft of the refresh client, for the reason in its title: the
// stale-event fence and the rotated-ready bookkeeping were conditioned on a BLOCK sequence, while a
// refresh run has sequenceTotal === 1 and windowTotal > 1.

test('CLIENT STALE: an old window\'s share after the handover is fenced, not judged as new work', () => {
  const h = harness();
  h.finished();
  h.refresh();
  h.readyForNextWindow();
  assert.equal(h.posted('init_search_next').length, 1, 'the Worker was not re-contextualised');
  const staleBefore = h.controller.snapshot().realStaleWorkerMessages;

  // The old context reports a hit it found before it was retired. Read against the NEW window it is
  // out of range, and the draft stopped the whole session for it.
  h.w.emit({ ev: 'share', jobId: JOB1.jobId, nonce: 7, nonceHex: '00000007', hashHexLE: SHARE_HASH(2) });
  assert.equal(h.controller.runIntent, true, 'a stale share ended a valid session');
  assert.equal(h.controller.snapshot().error, null);
  assert.equal(h.socket.sent.filter((m) => m.type === 'submit_real_candidate').length, 0,
    'a stale share was submitted against the new issuance');
  assert.equal(h.controller.snapshot().realStaleWorkerMessages, staleBefore + 1);
  assert.equal(h.controller.snapshot().realSharesReported, 0);
});

test('CLIENT STALE: an old window\'s progress does not become the new window\'s attempt count', () => {
  const h = harness();
  h.w.emit({ ev: 'progress', jobId: JOB1.jobId, hashes: 4096, elapsedMs: 10 });
  assert.equal(h.controller.snapshot().hashes, 4096);
  h.finished(JOB1.jobId, { hashes: 8192 });
  h.refresh();
  h.readyForNextWindow();
  const staleBefore = h.controller.snapshot().realStaleWorkerMessages;
  const hashesAtHandover = h.controller.snapshot().hashes;

  h.w.emit({ ev: 'progress', jobId: JOB1.jobId, hashes: 8192, elapsedMs: 20 });
  assert.equal(h.controller.snapshot().hashes, hashesAtHandover,
    'a retired context\'s progress was shown as the new window\'s');
  assert.equal(h.controller.snapshot().realStaleWorkerMessages, staleBefore + 1);
  // The cumulative total across windows is still reported.
  assert.equal(Number.isSafeInteger(h.controller.snapshot().realTotalAttempts), true);
});

test('CLIENT STALE: exactly ONE finished settles the old window, and a repeat settles nothing', () => {
  const h = harness();
  h.refresh();                                    // the server hands over while the search runs
  h.readyForNextWindow();
  assert.equal(h.posted('init_search_next').length, 0, 'the Worker was rotated mid-search');

  // The one legitimate settling event for the retired window.
  h.finished(JOB1.jobId);
  assert.equal(h.posted('init_search_next').length, 1, 'the old context could not settle');
  assert.equal(h.controller.runIntent, true);
  const staleBefore = h.controller.snapshot().realStaleWorkerMessages;
  const attemptsAfterSettle = h.controller.snapshot().realTotalAttempts;

  // A DUPLICATE finished for the same retired job settles nothing and must not settle the NEW
  // window: the draft counted it and could end the session as a bounded no-solution.
  h.finished(JOB1.jobId);
  assert.equal(h.controller.snapshot().realStaleWorkerMessages, staleBefore + 1,
    'a duplicate finished was acted on');
  assert.equal(h.controller.snapshot().realTotalAttempts, attemptsAfterSettle,
    'a duplicate finished was counted again');
  assert.equal(h.posted('init_search_next').length, 1, 'a duplicate finished rotated the Worker again');
  assert.equal(h.controller.runIntent, true, 'a duplicate finished ended the session');
  assert.equal(h.controller.snapshot().realOutcome, null);
  assert.equal(h.socket.sent.some((m) => m.type === 'stop_request'), false);
});

test('CLIENT STALE: a job-less worker event is fenced in a refresh run', () => {
  const h = harness();
  const staleBefore = h.controller.snapshot().realStaleWorkerMessages;
  h.w.emit({ ev: 'progress', hashes: 99, elapsedMs: 5 });
  assert.equal(h.controller.snapshot().realStaleWorkerMessages, staleBefore + 1);
  assert.equal(h.controller.snapshot().hashes, 0, 'an unbound progress event was shown');
});

test('CLIENT STALE: the rotated readiness is recorded as a window context, once', () => {
  const h = harness();
  h.finished();
  h.refresh();
  h.readyForNextWindow();
  h.w.emit({
    ev: 'ready', jobId: JOB2.jobId, contextIndex: 2, moduleInstances: 1, rotated: true,
    priorContextFreed: true, priorContextActive: false, wasmHeapBytes: 48562176,
  });
  const contexts = h.controller.snapshot().realWorkerContexts;
  // The first window's context and the rotated one, in order: one live context at a time.
  assert.equal(contexts.length, 2, 'the rotated context was not recorded');
  assert.equal(contexts[0].jobId, JOB1.jobId);
  assert.equal(contexts[0].rotated, false);
  assert.equal(contexts[1].jobId, JOB2.jobId);
  assert.equal(contexts[1].rotated, true);
  assert.equal(contexts[1].priorContextFreed, true);
  assert.equal(contexts[1].priorContextActive, false);
  assert.equal(h.workers.length, 1, 'a second Worker exists');
  assert.equal(h.controller.pendingRotation, null, 'the rotation was never closed out');
});

// ============================================================ the second audit's counterexamples
//
// EXACT ORDERING MATTERS. The earlier tests settled the old search BEFORE the refresh arrived, so
// they never exercised the gap the audit found: between `job_refresh` (which moves serverRun and
// realJob to the new window) and the old context's own settling `finished`, the Worker is still on
// the OLD job. Every test below refreshes FIRST and then emits the old context's events.

test('CLIENT GAP: a stale share received AFTER job_refresh and BEFORE the old finished is fenced', () => {
  const h = harness();
  h.refresh();                                    // the server issues window 2; the Worker is still on 1
  h.readyForNextWindow();
  assert.equal(h.posted('init_search_next').length, 0, 'the Worker rotated before it settled');
  const staleBefore = h.controller.snapshot().realStaleWorkerMessages;

  // The old context reports a hit for the OLD window. It is not the new window's work and must not
  // be validated against the new issuance -- doing that failed the range check and stopped the run.
  h.w.emit({ ev: 'share', jobId: JOB1.jobId, nonce: 5, nonceHex: '00000005', hashHexLE: SHARE_HASH(3) });
  assert.equal(h.controller.runIntent, true, 'a stale share ended a valid session');
  assert.equal(h.controller.snapshot().error, null);
  assert.equal(h.socket.sent.filter((m) => m.type === 'submit_real_candidate').length, 0,
    'a stale share was submitted against the new issuance');
  assert.equal(h.controller.snapshot().realSharesReported, 0);
  assert.equal(h.controller.snapshot().realStaleWorkerMessages, staleBefore + 1);
});

test('CLIENT GAP: a stale progress received AFTER job_refresh and BEFORE the old finished is fenced', () => {
  const h = harness();
  h.w.emit({ ev: 'progress', jobId: JOB1.jobId, hashes: 2048, elapsedMs: 10 });
  assert.equal(h.controller.snapshot().hashes, 2048);
  h.refresh();
  h.readyForNextWindow();
  const staleBefore = h.controller.snapshot().realStaleWorkerMessages;

  h.w.emit({ ev: 'progress', jobId: JOB1.jobId, hashes: 4096, elapsedMs: 20 });
  assert.equal(h.controller.snapshot().hashes, 2048,
    'the old context\'s progress was shown as the new window\'s');
  assert.equal(h.controller.snapshot().realStaleWorkerMessages, staleBefore + 1);
  // A `found` and a `ready` for the retired job are fenced in the same gap.
  h.w.emit({ ev: 'found', jobId: JOB1.jobId, nonce: 5, nonceHex: '00000005', hashHexLE: BLOCK_HASH });
  h.w.emit({ ev: 'ready', jobId: JOB1.jobId, contextIndex: 1, moduleInstances: 1 });
  assert.equal(h.controller.runIntent, true, 'a stale found or ready ended the session');
  assert.equal(h.controller.snapshot().realStaleWorkerMessages, staleBefore + 3);
});

test('CLIENT GAP: the first old finished settles the old context; a duplicate settles nothing', () => {
  const h = harness();
  h.refresh();
  h.readyForNextWindow();

  h.finished(JOB1.jobId);                         // the ONE legitimate settling event
  assert.equal(h.posted('init_search_next').length, 1, 'the retired context could not settle');
  const staleAfterSettle = h.controller.snapshot().realStaleWorkerMessages;
  const attempts = h.controller.snapshot().realTotalAttempts;

  h.finished(JOB1.jobId);                         // a duplicate: it settles nothing at all
  assert.equal(h.controller.snapshot().realStaleWorkerMessages, staleAfterSettle + 1);
  assert.equal(h.controller.snapshot().realTotalAttempts, attempts, 'a duplicate was counted again');
  assert.equal(h.posted('init_search_next').length, 1, 'a duplicate rotated the Worker again');
  assert.equal(h.controller.runIntent, true, 'a duplicate finished ended the session');
  assert.equal(h.socket.sent.some((m) => m.type === 'stop_request'), false);
});

// ============================================================ the transitional state
test('CLIENT HANDOVER: the page is "preparing", not "searching", until the rotated readiness', () => {
  const h = harness();
  h.w.emit({ ev: 'progress', jobId: JOB1.jobId, hashes: 4096, elapsedMs: 10 });
  let snap = h.controller.snapshot();
  assert.equal(snap.realWindowIndex, 1);
  assert.equal(snap.realActiveWindowIndex, 1);
  assert.equal(snap.realWindowHandoff, false);

  // The server issues window 2 while the Worker is still on window 1.
  h.refresh();
  snap = h.controller.snapshot();
  assert.equal(snap.realWindowIndex, 2, 'the issued window is not recorded');
  assert.equal(snap.realActiveWindowIndex, 1, 'the page claims to be searching a context it lacks');
  assert.equal(snap.realWindowHandoff, true);
  assert.equal(h.controller.activeRealJob.jobId, JOB1.jobId,
    'the page shows the new window\'s range before anything searches it');

  // The old context settles and the Worker is re-contextualised: STILL preparing.
  h.finished(JOB1.jobId);
  h.readyForNextWindow();
  snap = h.controller.snapshot();
  assert.equal(h.posted('init_search_next').length, 1);
  assert.equal(snap.realActiveWindowIndex, 1, 'the page started searching before the Worker was ready');
  assert.equal(snap.realWindowHandoff, true);
  assert.equal(snap.hashes, 0, 'the old window\'s hashes were attributed to the new job');

  // Only the rotated readiness makes window 2 the active one.
  h.w.emit({
    ev: 'ready', jobId: JOB2.jobId, contextIndex: 2, moduleInstances: 1, rotated: true,
    priorContextFreed: true, priorContextActive: false,
  });
  snap = h.controller.snapshot();
  assert.equal(snap.realActiveWindowIndex, 2);
  assert.equal(snap.realWindowHandoff, false);
  assert.equal(h.controller.activeRealJob.jobId, JOB2.jobId);
  assert.equal(h.workers.length, 1, 'a second Worker was created');
});

test('CLIENT HANDOVER: Stop, a hidden tab and a lost socket in the gap fail closed', () => {
  for (const [label, act] of [
    ['Stop', (c) => c.controller.stop(STOP_REASONS.USER)],
    ['a hidden tab', (c) => c.controller.setHidden(true)],
    ['a lost socket', (c) => c.socket.onclose?.({ code: 1006 })],
  ]) {
    const h = harness();
    h.refresh();                                  // inside the handover gap
    act(h);
    assert.equal(h.controller.runIntent, false, `${label}: run intent survived the gap`);
    h.finished(JOB1.jobId);
    h.readyForNextWindow();
    assert.equal(h.posted('init_search_next').length, 0, `${label}: the Worker rotated after the end`);
    assert.equal(h.workers.length, 1, label);
    h.controller.setHidden(false);
    assert.equal(h.controller.runIntent, false, `${label}: the session auto-resumed`);
  }
});

// ============================================================ the retiring phase, said truthfully
test('CLIENT PHASES: the retiring flag is true only until the old context settles', () => {
  const h = harness();
  h.w.emit({ ev: 'progress', jobId: JOB1.jobId, hashes: 4096, elapsedMs: 10 });
  assert.equal(h.controller.snapshot().realWindowRetiring, false,
    'a session with no handover claimed a retiring window');

  // The server issues window 2 while the Worker is STILL SEARCHING window 1: the old window is
  // retiring, and the page must not claim that nothing at all is hashing.
  h.refresh();
  let snap = h.controller.snapshot();
  assert.equal(snap.realWindowHandoff, true);
  assert.equal(snap.realWindowRetiring, true,
    'the gap before the old finished was not called retiring');

  // The old context settles: the handover continues, but nothing is hashing any more.
  h.finished(JOB1.jobId);
  snap = h.controller.snapshot();
  assert.equal(snap.realWindowHandoff, true, 'the handover ended with the old search');
  assert.equal(snap.realWindowRetiring, false,
    'a settled old window was still called retiring');

  // Only the rotated readiness ends the handover.
  h.readyForNextWindow();
  h.w.emit({
    ev: 'ready', jobId: JOB2.jobId, contextIndex: 2, moduleInstances: 1, rotated: true,
    priorContextFreed: true, priorContextActive: false,
  });
  snap = h.controller.snapshot();
  assert.equal(snap.realWindowHandoff, false);
  assert.equal(snap.realWindowRetiring, false);
  assert.equal(snap.realActiveWindowIndex, 2);

  // A refresh that arrives AFTER the old search already settled never enters the retiring phase.
  const settled = harness();
  settled.finished();
  settled.refresh();
  assert.equal(settled.controller.snapshot().realWindowRetiring, false,
    'an already-settled window was called retiring');
  assert.equal(settled.controller.snapshot().realWindowHandoff, true);
});

// ============================================================ fail-closed refresh protocol facts
test('CLIENT PROTOCOL: malformed or unsolicited window facts create no Worker', () => {
  // (a) an over-limit, non-integer or budget-mismatched declaration before Start.
  for (const [label, hello] of [
    ['an over-limit total', { windowTotal: REAL_REFRESH_LIMITS.maxWindows + 1, sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs }],
    ['a fractional total', { windowTotal: 2.5, sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs }],
    ['a one-window opt-in', { windowTotal: 1, sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs }],
    ['a longer session budget', { windowTotal: 3, sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs + 1 }],
    ['a missing session budget', { windowTotal: 3 }],
  ]) {
    const h = harness({ windowTotal: 1, helloOver: hello });
    assert.match(h.controller.snapshot().error ?? '', /invalid window total/, label);
    assert.equal(h.workers.length, 0, `${label}: a Worker was created`);
    assert.equal(h.controller.start(), false, `${label}: Start was still possible`);
  }
});

test('CLIENT PROTOCOL: a readiness whose window facts were never offered allocates nothing and ENDS the run', () => {
  // Unsolicited: the server never declared windows, but its readiness carries them.
  const unsolicited = harness({ windowTotal: 1, readyOver: { windowIndex: 1, windowTotal: 2 } });
  assert.equal(unsolicited.workers.length, 0, 'a Worker was created for unsolicited window facts');
  assert.match(unsolicited.controller.snapshot().error ?? '', /window facts this page was not offered/);

  // Declared, but the readiness disagrees with the declaration or names another window. THE CLOSED
  // ERROR IS NOT ENOUGH: the shared bound error-stop path must also have run, or the page would sit
  // in an error state over a server session it can no longer stop. Exactly one bound stop_request,
  // run intent cleared, no Worker, and no auto-resume afterwards.
  for (const [label, over] of [
    ['a different total', { windowTotal: 2 }],
    ['a window the server did not issue', { windowIndex: 2 }],
    ['no window facts at all', { windowIndex: undefined, windowTotal: undefined, sessionBudgetMs: undefined }],
    ['a foreign session budget', { sessionBudgetMs: 1 }],
    ['an omitted session budget', { sessionBudgetMs: undefined }],
  ]) {
    const h = harness({ windowTotal: 3, readyOver: over });
    assert.equal(h.workers.length, 0, `${label}: a Worker was created`);
    assert.match(h.controller.snapshot().error ?? '', /window facts this page was not offered/, label);
    // THE CLEANUP: one bound stop, and nothing live on either side.
    const stops = h.socket.sent.filter((m) => m.type === 'stop_request');
    assert.equal(stops.length, 1, `${label}: not exactly one bound stop_request`);
    assert.deepEqual(
      stops[0] && { clientStartId: stops[0].clientStartId, workerId: stops[0].workerId, jobId: stops[0].jobId, issuanceId: stops[0].issuanceId, runGeneration: stops[0].runGeneration },
      h.bind1,
      `${label}: the stop was not bound to the acknowledged attempt`,
    );
    assert.equal(h.controller.runIntent, false, `${label}: run intent survived the protocol fault`);
    assert.equal(h.controller.start(), false, `${label}: Start was still possible after the fault`);
    // No auto-resume, and a late readiness can no longer construct a Worker.
    h.socket.deliver({
      type: 'mining_ready', mode: REAL_DAEMON_MODE, ...h.bind1, windowIndex: 1, windowTotal: 3,
      sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs,
    });
    assert.equal(h.workers.length, 0, `${label}: a late readiness built a Worker after the fault`);
    assert.equal(h.socket.sent.filter((m) => m.type === 'stop_request').length, 1,
      `${label}: a second stop was sent`);
  }
});
