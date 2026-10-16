// Fake socket and Worker only: the page's share queue across two server-issued templates.
import test from 'node:test';
import assert from 'node:assert/strict';

import { createMiningController } from '../lib/controller.js';
import { REAL_DAEMON_MODE, REAL_SEARCH_LIMITS, REAL_SHARE_LIMITS } from '../lib/shared/protocol.js';

const START = 'a'.repeat(32);
const WORKER = 'sim-1-bbbb';
const BLOCK_TARGET = `01${'00'.repeat(31)}`;
const SHARE_TARGET_1 = `${'00'.repeat(31)}01`;
const SHARE_TARGET_2 = `ff${'00'.repeat(31)}`;
const BLOCK_HASH = '00'.repeat(32);
const SHARE_HASH = `10${'00'.repeat(31)}`;
const job1 = {
  type: 'real_job', jobId: 'realjob-1111', issuanceId: '1'.repeat(32), contentDigest: '1'.repeat(64),
  algorithm: 'meephash-w-v2-frozen-real-template', height: '1', majorVersion: 16,
  epochKeyHex: 'e'.repeat(64), seedHashHex: 'e'.repeat(64),
  hashingTemplateHex: `1010${'00'.repeat(74)}`, targetHexLE: BLOCK_TARGET,
  shareWork: true, shareTargetHexLE: SHARE_TARGET_1, nonceStart: 0, nonceRange: 8192, expiresAtMs: 1,
};
const job2 = {
  ...job1, jobId: 'realjob-2222', issuanceId: '2'.repeat(32), contentDigest: '2'.repeat(64),
  height: '2', hashingTemplateHex: `2020${'00'.repeat(74)}`, shareTargetHexLE: SHARE_TARGET_2,
};
const bind1 = { clientStartId: START, workerId: WORKER, jobId: job1.jobId, issuanceId: job1.issuanceId, runGeneration: 1 };
const bind2 = { ...bind1, jobId: job2.jobId, issuanceId: job2.issuanceId, runGeneration: 2 };

function harness() {
  const worker = {
    posted: [], onmessage: null, onerror: null,
    postMessage(msg) { this.posted.push(msg); }, terminate() {},
    emit(msg) { this.onmessage?.({ data: msg }); },
  };
  const socket = {
    sent: [], onopen: null, onmessage: null, onclose: null, onerror: null,
    send(raw) { this.sent.push(JSON.parse(raw)); }, close() {},
    deliver(msg) { this.onmessage?.({ data: JSON.stringify(msg) }); },
  };
  const controller = createMiningController({
    createWorker: () => worker, createSocket: () => socket, newStartId: () => START,
  });
  controller.connect('ws://127.0.0.1:1/ws');
  socket.onopen();
  socket.deliver({
    type: 'server_hello', protocolVersion: 1, mode: REAL_DAEMON_MODE, workerId: WORKER,
    labels: [], alreadyCompleted: false, searchLimits: REAL_SEARCH_LIMITS, sequenceTotal: 2,
  });
  socket.deliver(job1);
  controller.start();
  socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...bind1 });
  socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, sequenceIndex: 1, sequenceTotal: 2, ...bind1 });
  worker.emit({ ev: 'ready', jobId: job1.jobId, contextIndex: 1, moduleInstances: 1 });
  const share = (jobId, nonce, hashHexLE) => worker.emit({
    ev: 'share', jobId, nonce, nonceHex: nonce.toString(16).padStart(8, '0'), hashHexLE,
  });
  const submits = () => socket.sent.filter((msg) => msg.type === 'submit_real_candidate');
  const next = (cause = 'accepted', nextJob = job2) => socket.deliver({
    type: 'sequence_next', sequenceIndex: 2, sequenceTotal: 2, cause,
    previous: { jobId: bind1.jobId, issuanceId: bind1.issuanceId, runGeneration: 1 },
    job: nextJob, ...bind2,
  });
  return { controller, socket, worker, share, submits, next };
}

test('SHARE SEQUENCE CONTROLLER: a block rotates to a fresh target and queue under one Start', () => {
  const h = harness();
  h.share(job1.jobId, 3, SHARE_HASH);
  h.share(job1.jobId, 5, BLOCK_HASH);
  h.share(job1.jobId, 7, SHARE_HASH); // queued behind the block, never sent to height 2
  assert.equal(h.submits().length, 1);
  h.socket.deliver({ type: 'share_accepted', terminal: false, nonce: 3, hashHexLE: SHARE_HASH, ...bind1 });
  h.socket.deliver({ type: 'candidate_settled', terminal: false, nonce: 3, ...bind1 });
  assert.equal(h.submits().length, 2);
  assert.equal(h.submits()[1].nonce, '00000005');
  h.socket.deliver({
    type: 'sequence_block_accepted', terminal: false, sequenceIndex: 1, sequenceTotal: 2,
    height: '1', nonce: 5, hashHexLE: BLOCK_HASH, blockId: 'c'.repeat(64), ...bind1,
  });
  h.next();
  assert.equal(h.controller.snapshot().realSharesReported, 0);
  assert.equal(h.controller.snapshot().realShareQueueDepth, 0);
  assert.equal(h.controller.snapshot().realShareMode, true);
  assert.equal(h.controller.snapshot().realSharesAccepted, 1, 'session total was lost');
  // No block candidate_settled is sent. The old outstanding result must not hold the new queue.
  h.socket.deliver({ type: 'candidate_settled', terminal: false, nonce: 5, ...bind1 });
  h.worker.emit({ ev: 'finished', jobId: job1.jobId, hashes: 8, found: 1, shares: 3 });
  h.socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, sequenceIndex: 2, sequenceTotal: 2, ...bind2 });
  const init2 = h.worker.posted.find((m) => m.cmd === 'init_search_next');
  assert.ok(init2);
  assert.equal(init2.window.shareTargetHexLE, SHARE_TARGET_2);
  assert.equal(init2.window.maxShares, REAL_SHARE_LIMITS.maxSharesPerJob);
  h.worker.emit({ ev: 'ready', jobId: job2.jobId, rotated: true, contextIndex: 2, moduleInstances: 1, priorContextFreed: true });
  h.share(job2.jobId, 3, SHARE_HASH); // same nonce is valid at a new height
  assert.equal(h.submits().length, 3, 'the old block held the second template queue');
  assert.deepEqual({ jobId: h.submits()[2].jobId, issuanceId: h.submits()[2].issuanceId, runGeneration: h.submits()[2].runGeneration },
    { jobId: job2.jobId, issuanceId: job2.issuanceId, runGeneration: 2 });
  h.socket.deliver({ type: 'share_accepted', terminal: false, nonce: 3, hashHexLE: SHARE_HASH, ...bind2 });
  assert.equal(h.controller.snapshot().realSharesAccepted, 2);
  assert.equal(h.controller.snapshot().realSharesReported, 1);
});

test('SHARE SEQUENCE CONTROLLER: late old-height share frames are ignored, not fatal to the new height', () => {
  const h = harness();
  h.share(job1.jobId, 5, BLOCK_HASH);
  h.socket.deliver({
    type: 'sequence_block_accepted', terminal: false, sequenceIndex: 1, sequenceTotal: 2,
    height: '1', nonce: 5, hashHexLE: BLOCK_HASH, blockId: 'c'.repeat(64), ...bind1,
  });
  h.next();
  const before = h.submits().length;
  h.share(job1.jobId, 9, SHARE_HASH);
  h.worker.emit({ ev: 'share', nonce: 10, nonceHex: '0000000a', hashHexLE: SHARE_HASH });
  assert.equal(h.controller.runIntent, true);
  assert.equal(h.submits().length, before);
  assert.equal(h.controller.snapshot().realSharesReported, 0);
  assert.equal(h.controller.snapshot().realStaleWorkerMessages, 2);
});

test('SHARE SEQUENCE CONTROLLER: an unusable second share target is not installed', () => {
  const h = harness();
  h.share(job1.jobId, 5, BLOCK_HASH);
  h.socket.deliver({
    type: 'sequence_block_accepted', terminal: false, sequenceIndex: 1, sequenceTotal: 2,
    height: '1', nonce: 5, hashHexLE: BLOCK_HASH, blockId: 'c'.repeat(64), ...bind1,
  });
  h.next('accepted', { ...job2, shareTargetHexLE: '00'.repeat(32) });
  assert.equal(h.controller.snapshot().serverRunGeneration, 1);
  assert.equal(h.worker.posted.filter((m) => m.cmd === 'init_search_next').length, 0);
});
