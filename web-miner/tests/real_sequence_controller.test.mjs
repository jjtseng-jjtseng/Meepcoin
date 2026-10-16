// The page controller's side of a finite development sequence, with hand-written server frames and a fake
// Worker, so every ordering the real system rarely produces can be forced: the next run arriving before
// the Worker settled, a malformed or unsolicited sequence_next, Stop between frames, a Worker refusal.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createMiningController, STATES, STOP_REASONS } from '../lib/controller.js';
import { REAL_DAEMON_MODE, REAL_SEARCH_LIMITS } from '../lib/shared/protocol.js';

const WORKER_ID = 'sim-1-bbbb';
const TARGET = `${'00'.repeat(31)}01`;       // an all-zero hash meets it
const WIN = '00'.repeat(32);
const BLOCK1 = 'c'.repeat(64);
const BLOCK2 = 'd'.repeat(64);
const JOB1 = { type: 'real_job', jobId: 'realjob-1111', issuanceId: '1'.repeat(32), contentDigest: '1'.repeat(64), algorithm: 'meephash-w-v2-frozen-real-template', height: '1', majorVersion: 16, epochKeyHex: 'e'.repeat(64), seedHashHex: 'e'.repeat(64), hashingTemplateHex: `1010${'00'.repeat(74)}`, targetHexLE: TARGET, nonceStart: 0, nonceRange: 8192, expiresAtMs: 1 };
const JOB2 = { ...JOB1, jobId: 'realjob-2222', issuanceId: '2'.repeat(32), contentDigest: '2'.repeat(64), height: '2', hashingTemplateHex: `2020${'00'.repeat(74)}` };

function harness({ sequenceTotal = 2 } = {}) {
  const workers = [];
  const sockets = [];
  const controller = createMiningController({
    createWorker: () => {
      const w = { posted: [], terminated: 0, onmessage: null, onerror: null, postMessage(m) { this.posted.push(m); }, terminate() { this.terminated++; }, emit(data) { this.onmessage?.({ data }); } };
      workers.push(w);
      return w;
    },
    createSocket: () => {
      const s = { sent: [], onopen: null, onmessage: null, onclose: null, onerror: null, send(t) { this.sent.push(JSON.parse(t)); }, close() {}, deliver(o) { this.onmessage?.({ data: JSON.stringify(o) }); } };
      sockets.push(s);
      return s;
    },
    newStartId: () => 'a'.repeat(32),
  });
  controller.connect('ws://127.0.0.1:1/ws');
  const socket = sockets[0];
  socket.onopen();
  socket.deliver({
    type: 'server_hello', protocolVersion: 1, mode: REAL_DAEMON_MODE, workerId: WORKER_ID, labels: [], alreadyCompleted: false,
    searchLimits: REAL_SEARCH_LIMITS, ...(sequenceTotal ? { sequenceTotal } : {}),
  });
  socket.deliver(JOB1);
  const b1 = { clientStartId: 'a'.repeat(32), workerId: WORKER_ID, jobId: JOB1.jobId, issuanceId: JOB1.issuanceId, runGeneration: 1 };
  const b2 = { ...b1, jobId: JOB2.jobId, issuanceId: JOB2.issuanceId, runGeneration: 2 };
  controller.start();
  socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...b1 });
  socket.deliver({
    type: 'mining_ready', mode: REAL_DAEMON_MODE, ...b1,
    ...(sequenceTotal ? { sequenceIndex: 1, sequenceTotal } : {}),
  });
  const w = workers[0];
  w.emit({ ev: 'ready', jobId: JOB1.jobId, contextIndex: 1, moduleInstances: 1 });
  const found1 = () => w.emit({ ev: 'found', jobId: JOB1.jobId, nonce: 5, nonceHex: '00000005', hashHexLE: WIN });
  const finished1 = () => w.emit({ ev: 'finished', jobId: JOB1.jobId, hashes: 6, found: 1 });
  const accepted1 = () => socket.deliver({ type: 'sequence_block_accepted', terminal: false, sequenceIndex: 1, sequenceTotal: sequenceTotal ?? 2, height: '1', nonce: 5, hashHexLE: WIN, blockId: BLOCK1, ...b1 });
  const next = (over = {}) => socket.deliver({ type: 'sequence_next', sequenceIndex: 2, sequenceTotal: sequenceTotal ?? 2, cause: 'accepted', previous: { jobId: b1.jobId, issuanceId: b1.issuanceId, runGeneration: 1 }, job: JOB2, ...b2, ...over });
  const ready2 = () => socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, sequenceIndex: 2, sequenceTotal: sequenceTotal ?? 2, ...b2 });
  const posted = (cmd) => w.posted.filter((m) => m.cmd === cmd);
  return { controller, socket, workers, w, b1, b2, found1, finished1, accepted1, next, ready2, posted };
}

test('the Worker is re-contextualised only when the next run is ready AND its first search has settled -- in either order', async () => {
  // Server first: sequence_next and mining_ready before the Worker's `finished`.
  let h = harness();
  h.found1();
  h.accepted1();
  h.next();
  h.ready2();
  assert.equal(h.posted('init_search_next').length, 0, 'rotated before the first search settled');
  h.finished1();
  assert.equal(h.posted('init_search_next').length, 1);
  const rot = h.posted('init_search_next')[0];
  assert.equal(rot.prevJobId, JOB1.jobId);
  assert.equal(rot.jobId, JOB2.jobId);
  assert.equal(rot.gen, h.controller.localWorkerGeneration);
  assert.deepEqual(rot.window, { nonceStart: 0, nonceRange: 8192, targetHexLE: TARGET, maxSearchMs: 120000 });
  assert.equal(rot.context.height, '2');
  assert.equal(h.workers.length, 1);
  // The Worker's rotated ready starts exactly one search of job 2.
  h.w.emit({ ev: 'ready', jobId: JOB2.jobId, rotated: true, contextIndex: 2, moduleInstances: 1, priorContextFreed: true, priorContextActive: false });
  assert.deepEqual(h.posted('search').map((m) => m.jobId), [JOB1.jobId, JOB2.jobId]);
  h.w.emit({ ev: 'found', jobId: JOB2.jobId, nonce: 9, nonceHex: '00000009', hashHexLE: WIN });
  const cands = h.socket.sent.filter((m) => m.type === 'submit_real_candidate');
  assert.equal(cands.length, 2);
  assert.deepEqual({ jobId: cands[1].jobId, issuanceId: cands[1].issuanceId, runGeneration: cands[1].runGeneration }, { jobId: JOB2.jobId, issuanceId: JOB2.issuanceId, runGeneration: 2 });

  // Worker first: `finished` before the server's next run.
  h = harness();
  h.found1();
  h.finished1();
  h.accepted1();
  h.next();
  assert.equal(h.posted('init_search_next').length, 0, 'rotated before the next run was ready');
  h.ready2();
  assert.equal(h.posted('init_search_next').length, 1);
});

test('a sequence_next that does not extend exactly this binding, or comes before block 1 is accepted, changes nothing', () => {
  for (const [name, prep, over] of [
    ['before acceptance', (h) => h.found1(), {}],
    ['wrong previous generation', (h) => { h.found1(); h.accepted1(); }, { previous: { jobId: JOB1.jobId, issuanceId: JOB1.issuanceId, runGeneration: 7 } }],
    ['wrong previous job', (h) => { h.found1(); h.accepted1(); }, { previous: { jobId: 'realjob-x', issuanceId: JOB1.issuanceId, runGeneration: 1 } }],
    ['another start', (h) => { h.found1(); h.accepted1(); }, { clientStartId: 'b'.repeat(32) }],
    ['another worker id', (h) => { h.found1(); h.accepted1(); }, { workerId: 'sim-9-ffff' }],
    ['a third block', (h) => { h.found1(); h.accepted1(); }, { sequenceIndex: 3 }],
    ['the same job again', (h) => { h.found1(); h.accepted1(); }, { jobId: JOB1.jobId, job: { ...JOB2, jobId: JOB1.jobId } }],
    ['generation not advancing', (h) => { h.found1(); h.accepted1(); }, { runGeneration: 1 }],
    ['height not the next one', (h) => { h.found1(); h.accepted1(); }, { job: { ...JOB2, height: '5' } }],
    ['same content', (h) => { h.found1(); h.accepted1(); }, { job: { ...JOB2, contentDigest: JOB1.contentDigest } }],
    ['job and binding disagree', (h) => { h.found1(); h.accepted1(); }, { job: { ...JOB2, issuanceId: '3'.repeat(32) } }],
  ]) {
    const h = harness();
    prep(h);
    h.next(over);
    h.finished1();
    h.ready2();
    assert.equal(h.controller.blockIndex, 1, `${name}: the binding advanced`);
    assert.equal(h.controller.realJob.jobId, JOB1.jobId, name);
    assert.equal(h.posted('init_search_next').length, 0, `${name}: the Worker was re-contextualised`);
  }
  // Not a sequence server at all.
  const one = harness({ sequenceTotal: null });
  one.found1();
  one.accepted1();
  one.next();
  one.finished1();
  one.ready2();
  assert.equal(one.controller.sequenceTotal, 1);
  assert.equal(one.posted('init_search_next').length, 0);
  assert.equal(one.controller.snapshot().realBlocks.length, 0);
});

test('Stop between sequence_next and readiness: the stop names the NEW run, and a late readiness builds nothing', () => {
  const h = harness();
  h.found1();
  h.finished1();
  h.accepted1();
  h.next();
  h.controller.stop();
  const stop = h.socket.sent.filter((m) => m.type === 'stop_request').at(-1);
  assert.deepEqual({ jobId: stop.jobId, runGeneration: stop.runGeneration }, { jobId: JOB2.jobId, runGeneration: 2 });
  assert.equal(h.w.terminated, 1);
  h.ready2();
  assert.equal(h.posted('init_search_next').length, 0);
  assert.equal(h.workers.length, 1);
  // ...and the server's terminal for the new run is recognised.
  h.socket.deliver({ type: 'run_stopped', accepted: true, reason: 'user_stop', terminal: true, ...h.b2 });
  assert.equal(h.controller.snapshot().simFinished, true);
});

test('Stop BEFORE sequence_next arrives: the stop names block 1, and the late sequence_next only records the binding', () => {
  const h = harness();
  h.found1();
  h.finished1();
  h.accepted1();
  h.controller.setHidden(true);
  const stop = h.socket.sent.filter((m) => m.type === 'stop_request').at(-1);
  assert.equal(stop.jobId, JOB1.jobId);
  assert.equal(stop.reason, 'page_hidden');
  h.next();
  h.ready2();
  assert.equal(h.controller.snapshot().state, STATES.STOPPED_HIDDEN);
  assert.equal(h.posted('init_search_next').length, 0);
  assert.equal(h.controller.pendingRotation, null);
  h.socket.deliver({ type: 'run_stopped', accepted: true, reason: 'page_hidden', terminal: true, ...h.b2 });
  assert.equal(h.controller.snapshot().simFinished, true);
});

test('a Worker that refuses the rotation ends the session; a forged rotated ready starts nothing', () => {
  const h = harness();
  h.found1();
  h.finished1();
  h.accepted1();
  h.next();
  // A rotated ready the page never asked for.
  h.w.emit({ ev: 'ready', jobId: JOB2.jobId, rotated: true });
  assert.deepEqual(h.posted('search').map((m) => m.jobId), [JOB1.jobId]);
  h.ready2();
  assert.equal(h.posted('init_search_next').length, 1);
  h.w.emit({ ev: 'command_refused', cmd: 'init_search_next', reason: 'previous_search_not_settled' });
  const s = h.controller.snapshot();
  assert.equal(s.stopReason, STOP_REASONS.ERROR);
  assert.equal(h.w.terminated, 1);
  assert.equal(h.posted('search').length, 1);
});

// ================================================================== sustained browser-side sequence
const seqHex = (n, width) => n.toString(16).padStart(width, '0');
const seqJob = (n) => ({
  ...JOB1,
  jobId: `realjob-${String(n).padStart(16, '0')}`,
  issuanceId: seqHex(n, 32),
  contentDigest: seqHex(1000 + n, 64),
  height: String(n),
  hashingTemplateHex: `${(n & 0xff).toString(16).padStart(2, '0')}10${'00'.repeat(74)}`,
});
const seqBinding = (n) => ({
  clientStartId: 'a'.repeat(32), workerId: WORKER_ID,
  jobId: seqJob(n).jobId, issuanceId: seqJob(n).issuanceId, runGeneration: n,
});

function sustainedHarness(total) {
  const workers = [];
  const sockets = [];
  const controller = createMiningController({
    createWorker: () => {
      const w = { posted: [], terminated: 0, onmessage: null, onerror: null, postMessage(m) { this.posted.push(m); }, terminate() { this.terminated++; }, emit(data) { this.onmessage?.({ data }); } };
      workers.push(w);
      return w;
    },
    createSocket: () => {
      const s = { sent: [], onopen: null, onmessage: null, onclose: null, onerror: null, send(t) { this.sent.push(JSON.parse(t)); }, close() {}, deliver(o) { this.onmessage?.({ data: JSON.stringify(o) }); } };
      sockets.push(s);
      return s;
    },
    newStartId: () => 'a'.repeat(32),
  });
  controller.connect('ws://127.0.0.1:1/ws');
  const socket = sockets[0];
  socket.onopen();
  socket.deliver({
    type: 'server_hello', protocolVersion: 1, mode: REAL_DAEMON_MODE, workerId: WORKER_ID,
    labels: [], alreadyCompleted: false, searchLimits: REAL_SEARCH_LIMITS, sequenceTotal: total,
  });
  socket.deliver(seqJob(1));
  controller.start();
  socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...seqBinding(1) });
  socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, sequenceIndex: 1, sequenceTotal: total, ...seqBinding(1) });
  return { controller, socket, workers, w: workers[0] };
}

test('twelve positions use one Worker, twelve exact contexts/searches/candidates, and no thirteenth context', () => {
  const total = 12;
  const h = sustainedHarness(total);
  const attempts = [];
  h.w.emit({ ev: 'ready', jobId: seqJob(1).jobId, contextIndex: 1, moduleInstances: 1 });

  for (let n = 1; n <= total; n += 1) {
    const job = seqJob(n);
    const binding = seqBinding(n);
    const hashes = n + 4;
    h.w.emit({ ev: 'found', jobId: job.jobId, nonce: n, nonceHex: n.toString(16).padStart(8, '0'), hashHexLE: WIN });
    assert.equal(h.socket.sent.filter((m) => m.type === 'submit_real_candidate').length, n);

    // Alternate the two legal orders: Worker settlement first, or server rotation/readiness first.
    if (n % 2 === 0 || n === total) {
      h.w.emit({ ev: 'finished', jobId: job.jobId, hashes, found: 1, exhausted: false, timedOut: false });
    }
    attempts.push(hashes);
    h.socket.deliver({
      type: 'sequence_block_accepted', terminal: false, sequenceIndex: n, sequenceTotal: total,
      height: String(n), nonce: n, hashHexLE: WIN, blockId: seqHex(2000 + n, 64), ...binding,
    });

    if (n < total) {
      const next = n + 1;
      h.socket.deliver({
        type: 'sequence_next', sequenceIndex: next, sequenceTotal: total, cause: 'accepted',
        previous: { jobId: binding.jobId, issuanceId: binding.issuanceId, runGeneration: binding.runGeneration },
        job: seqJob(next), ...seqBinding(next),
      });
      h.socket.deliver({
        type: 'mining_ready', mode: REAL_DAEMON_MODE, sequenceIndex: next, sequenceTotal: total, ...seqBinding(next),
      });
      if (n % 2 === 1) {
        assert.equal(h.w.posted.filter((m) => m.cmd === 'init_search_next').length, n - 1,
          `position ${n + 1} was built before the old search settled`);
        h.w.emit({ ev: 'finished', jobId: job.jobId, hashes, found: 1, exhausted: false, timedOut: false });
      }
      const init = h.w.posted.filter((m) => m.cmd === 'init_search_next').at(-1);
      assert.deepEqual({ prevJobId: init.prevJobId, jobId: init.jobId, sequenceTotal: init.sequenceTotal },
        { prevJobId: job.jobId, jobId: seqJob(next).jobId, sequenceTotal: total });
      h.w.emit({
        ev: 'ready', jobId: seqJob(next).jobId, rotated: true, contextIndex: next,
        moduleInstances: 1, priorContextFreed: true, priorContextActive: false,
      });
    }
  }

  const last = seqBinding(total);
  const initCount = h.w.posted.filter((m) => m.cmd === 'init_search_next').length;
  // Even a valid-looking binding cannot extend beyond the server-declared total.
  h.socket.deliver({
    type: 'sequence_next', sequenceIndex: total + 1, sequenceTotal: total, cause: 'accepted',
    previous: { jobId: last.jobId, issuanceId: last.issuanceId, runGeneration: last.runGeneration },
    job: seqJob(total + 1), ...seqBinding(total + 1),
  });
  assert.equal(h.w.posted.filter((m) => m.cmd === 'init_search_next').length, initCount);
  h.socket.deliver({
    type: 'block_accepted', terminal: true, height: String(total), nonce: total, hashHexLE: WIN,
    blockId: seqHex(2000 + total, 64), confirmedBy: 'immediate_canonical_readback_top_block_with_matching_pow_hash',
    ...last,
  });

  const snapshot = h.controller.snapshot();
  assert.equal(h.workers.length, 1);
  assert.equal(snapshot.realWorkersCreated, 1);
  assert.equal(snapshot.realWorkerContexts.length, total);
  assert.equal(h.w.posted.filter((m) => m.cmd === 'search').length, total);
  assert.equal(h.w.posted.filter((m) => m.cmd === 'init_search_next').length, total - 1);
  assert.equal(h.socket.sent.filter((m) => m.type === 'submit_real_candidate').length, total);
  assert.deepEqual(snapshot.realBlocks.map((b) => b.attempts), attempts);
  assert.equal(snapshot.realTotalAttempts, attempts.reduce((a, b) => a + b, 0));
  assert.equal(snapshot.realSequenceComplete, true);
});

test('an external tip retires the Worker\'s actual context, records no browser block, and reuses that Worker', () => {
  const h = sustainedHarness(3);
  h.w.emit({ ev: 'ready', jobId: seqJob(1).jobId, contextIndex: 1, moduleInstances: 1 });
  h.socket.deliver({
    type: 'sequence_next', sequenceIndex: 2, sequenceTotal: 3, cause: 'external_tip',
    previous: { jobId: seqJob(1).jobId, issuanceId: seqJob(1).issuanceId, runGeneration: 1 },
    job: seqJob(2), ...seqBinding(2),
  });
  assert.deepEqual(h.w.posted.filter((m) => m.cmd === 'supersede_search'), [
    { cmd: 'supersede_search', gen: h.controller.localWorkerGeneration, jobId: seqJob(1).jobId },
  ]);
  h.socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, sequenceIndex: 2, sequenceTotal: 3, ...seqBinding(2) });
  assert.equal(h.w.posted.filter((m) => m.cmd === 'init_search_next').length, 0);
  // Late work from the retired context is evidence of nothing and submits nothing.
  h.w.emit({ ev: 'progress', jobId: seqJob(1).jobId, hashes: 7, elapsedMs: 1 });
  h.w.emit({ ev: 'found', jobId: seqJob(1).jobId, nonce: 1, nonceHex: '00000001', hashHexLE: WIN });
  assert.equal(h.socket.sent.filter((m) => m.type === 'submit_real_candidate').length, 0);
  h.w.emit({ ev: 'finished', jobId: seqJob(1).jobId, hashes: 7, found: 0, superseded: true });
  assert.equal(h.w.posted.filter((m) => m.cmd === 'init_search_next').length, 1);
  h.w.emit({
    ev: 'ready', jobId: seqJob(2).jobId, rotated: true, contextIndex: 2,
    moduleInstances: 1, priorContextFreed: true, priorContextActive: false,
  });
  const snapshot = h.controller.snapshot();
  assert.equal(h.workers.length, 1);
  assert.equal(snapshot.realExternalSupersessions, 1);
  assert.deepEqual(snapshot.realBlocks, []);
  assert.equal(h.w.posted.filter((m) => m.cmd === 'search').at(-1).jobId, seqJob(2).jobId);
});

test('an externally superseded context still counts in the exact terminal nonce total', () => {
  const h = sustainedHarness(2);
  h.w.emit({ ev: 'ready', jobId: seqJob(1).jobId, contextIndex: 1, moduleInstances: 1 });
  h.socket.deliver({
    type: 'sequence_next', sequenceIndex: 2, sequenceTotal: 2, cause: 'external_tip',
    previous: { jobId: seqJob(1).jobId, issuanceId: seqJob(1).issuanceId, runGeneration: 1 },
    job: seqJob(2), ...seqBinding(2),
  });
  h.socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, sequenceIndex: 2, sequenceTotal: 2, ...seqBinding(2) });
  h.w.emit({ ev: 'finished', jobId: seqJob(1).jobId, hashes: 7, found: 0, superseded: true });
  h.w.emit({
    ev: 'ready', jobId: seqJob(2).jobId, rotated: true, contextIndex: 2,
    moduleInstances: 1, priorContextFreed: true, priorContextActive: false,
  });
  h.w.emit({ ev: 'found', jobId: seqJob(2).jobId, nonce: 2, nonceHex: '00000002', hashHexLE: WIN });
  h.w.emit({ ev: 'finished', jobId: seqJob(2).jobId, hashes: 5, found: 1, exhausted: false, timedOut: false });
  const binding = seqBinding(2);
  h.socket.deliver({
    type: 'sequence_block_accepted', terminal: false, sequenceIndex: 2, sequenceTotal: 2,
    height: '2', nonce: 2, hashHexLE: WIN, blockId: seqHex(2202, 64), ...binding,
  });
  h.socket.deliver({
    type: 'block_accepted', terminal: true, height: '2', nonce: 2, hashHexLE: WIN,
    blockId: seqHex(2202, 64), confirmedBy: 'immediate_canonical_readback_top_block_with_matching_pow_hash',
    ...binding,
  });

  const snapshot = h.controller.snapshot();
  assert.equal(snapshot.realTotalAttempts, 12, 'the superseded context\'s seven hashes were omitted');
  assert.equal(snapshot.realBlocks.length, 1, 'an external block was misreported as this browser\'s block');
  assert.equal(snapshot.realSequenceComplete, false, 'a sequence containing an external block was called browser-complete');
});

test('terminal server evidence that beats the final Worker finish leaves nonce counts explicitly unknown', () => {
  const h = harness();
  h.found1();
  h.finished1();
  h.accepted1();
  h.next();
  h.ready2();
  h.w.emit({
    ev: 'ready', jobId: JOB2.jobId, rotated: true, contextIndex: 2,
    moduleInstances: 1, priorContextFreed: true, priorContextActive: false,
  });
  h.w.emit({ ev: 'found', jobId: JOB2.jobId, nonce: 9, nonceHex: '00000009', hashHexLE: WIN });
  // The server can finish its canonical readback before the Worker's queued `finished` reaches the
  // page. A progress count is only a lower bound, so neither the block nor aggregate may claim it.
  h.socket.deliver({
    type: 'sequence_block_accepted', terminal: false, sequenceIndex: 2, sequenceTotal: 2,
    height: '2', nonce: 9, hashHexLE: WIN, blockId: BLOCK2, ...h.b2,
  });
  h.socket.deliver({
    type: 'block_accepted', terminal: true, height: '2', nonce: 9, hashHexLE: WIN,
    blockId: BLOCK2, confirmedBy: 'immediate_canonical_readback_top_block_with_matching_pow_hash',
    ...h.b2,
  });
  const terminal = h.controller.snapshot();
  assert.equal(terminal.realBlocks.at(-1).attempts, null);
  assert.equal(terminal.realTotalAttempts, null);

  // The terminal stop owns the truth boundary. A late Worker message cannot retroactively turn an
  // unavailable exact count into a number after the run has ended.
  h.w.emit({ ev: 'finished', jobId: JOB2.jobId, hashes: 10, found: 1 });
  assert.equal(h.controller.snapshot().realTotalAttempts, null);
});

test('a local Stop mid-search discards the progress lower bound instead of calling it a final total', () => {
  const h = sustainedHarness(3);
  h.w.emit({ ev: 'ready', jobId: seqJob(1).jobId, contextIndex: 1, moduleInstances: 1 });
  h.w.emit({ ev: 'progress', jobId: seqJob(1).jobId, hashes: 23, elapsedMs: 2 });
  assert.equal(h.controller.snapshot().realTotalAttempts, 23, 'live progress was not displayed');
  h.controller.stop();
  const snapshot = h.controller.snapshot();
  assert.equal(snapshot.realTotalAttempts, null, 'a progress lower bound survived as a final total');
  assert.equal(h.w.terminated, 1);
});

test('a terminal server failure before Worker finish leaves the attempt total unknown', () => {
  const h = sustainedHarness(3);
  h.w.emit({ ev: 'ready', jobId: seqJob(1).jobId, contextIndex: 1, moduleInstances: 1 });
  h.w.emit({ ev: 'progress', jobId: seqJob(1).jobId, hashes: 17, elapsedMs: 2 });
  h.socket.deliver({
    type: 'block_rejected', terminal: true, reason: 'external_tip_superseded', ...seqBinding(1),
  });
  const snapshot = h.controller.snapshot();
  assert.equal(snapshot.realOutcome, 'failed');
  assert.equal(snapshot.realTotalAttempts, null);
  assert.equal(h.w.terminated, 1);
});

test('tip_observation_failed remains a recognized terminal reason and kills the Worker', () => {
  const h = sustainedHarness(3);
  h.w.emit({ ev: 'ready', jobId: seqJob(1).jobId, contextIndex: 1, moduleInstances: 1 });
  h.socket.deliver({
    type: 'block_rejected', terminal: true, reason: 'tip_observation_failed', ...seqBinding(1),
  });
  const snapshot = h.controller.snapshot();
  assert.equal(snapshot.realOutcome, 'failed');
  assert.equal(snapshot.simFailureCode, 'tip_observation_failed');
  assert.equal(snapshot.lastRejectReason, 'tip_observation_failed');
  assert.equal(h.controller.runIntent, false);
  assert.equal(h.w.terminated, 1);
});

test('a server run_stopped backstop terminates an active Worker and freezes an unknown total', () => {
  const h = sustainedHarness(3);
  h.w.emit({ ev: 'ready', jobId: seqJob(1).jobId, contextIndex: 1, moduleInstances: 1 });
  h.w.emit({ ev: 'progress', jobId: seqJob(1).jobId, hashes: 19, elapsedMs: 2 });
  h.socket.deliver({
    type: 'run_stopped', accepted: true, terminal: true, reason: 'search_bound_reached', ...seqBinding(1),
  });
  const terminal = h.controller.snapshot();
  assert.equal(h.controller.runIntent, false);
  assert.equal(h.w.terminated, 1);
  assert.equal(terminal.realOutcome, 'bounded_no_solution');
  assert.equal(terminal.realTotalAttempts, null);
  assert.equal(terminal.simFinished, true);

  // terminate() detaches the handler. Queued lower-bound or finished messages cannot revise truth.
  h.w.emit({ ev: 'progress', jobId: seqJob(1).jobId, hashes: 21, elapsedMs: 3 });
  h.w.emit({ ev: 'finished', jobId: seqJob(1).jobId, hashes: 22, found: 0, exhausted: true });
  assert.deepEqual(h.controller.snapshot(), terminal);
});

test('two fast external tips coalesce from the Worker\'s real job directly to the latest server job', () => {
  const h = sustainedHarness(4);
  h.w.emit({ ev: 'ready', jobId: seqJob(1).jobId, contextIndex: 1, moduleInstances: 1 });
  const external = (from, to) => h.socket.deliver({
    type: 'sequence_next', sequenceIndex: to, sequenceTotal: 4, cause: 'external_tip',
    previous: { jobId: seqJob(from).jobId, issuanceId: seqJob(from).issuanceId, runGeneration: from },
    job: seqJob(to), ...seqBinding(to),
  });
  external(1, 2);
  external(2, 3);
  assert.equal(h.w.posted.filter((m) => m.cmd === 'supersede_search').length, 1,
    'the Worker was asked to retire a context it never built');
  h.socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, sequenceIndex: 3, sequenceTotal: 4, ...seqBinding(3) });
  h.w.emit({ ev: 'finished', jobId: seqJob(1).jobId, hashes: 3, found: 0, superseded: true });
  const [init] = h.w.posted.filter((m) => m.cmd === 'init_search_next');
  assert.deepEqual({ prevJobId: init.prevJobId, jobId: init.jobId },
    { prevJobId: seqJob(1).jobId, jobId: seqJob(3).jobId });
  assert.equal(h.controller.snapshot().realExternalSupersessions, 2);
  assert.equal(h.controller.snapshot().state === STATES.ERROR, false);
});

test('server sequence totals are exact: 3/12/32 are accepted; explicit 0/1/33/string/fraction are fail-closed', () => {
  for (const total of [3, 12, 32]) {
    const h = sustainedHarness(total);
    assert.equal(h.controller.sequenceTotal, total);
    assert.equal(h.controller.snapshot().state, STATES.STARTING);
  }
  for (const total of [0, 1, 33, '3', 2.5, null]) {
    const h = sustainedHarness(total);
    assert.equal(h.controller.snapshot().state, STATES.ERROR, String(total));
    assert.equal(h.workers.length, 0, String(total));
  }
});

test('a sequence Worker ready without its exact job id is stale and cannot start a search', () => {
  const h = sustainedHarness(3);
  h.w.emit({ ev: 'ready', contextIndex: 1, moduleInstances: 1 });
  assert.equal(h.w.posted.filter((m) => m.cmd === 'search').length, 0);
  assert.equal(h.controller.snapshot().realStaleWorkerMessages, 1);
});
