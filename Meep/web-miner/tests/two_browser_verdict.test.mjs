import test from 'node:test';
import assert from 'node:assert/strict';

import { adjudicateTwoBrowser } from '../tools/two_browser_verdict.mjs';

const jobs = [0, 1].map((n) => ({
  type: 'real_job', jobId: `${n + 1}`, issuanceId: `${n + 1}`,
  contentDigest: `${n + 1}`, height: '1', seedHashHex: 'a', epochKeyHex: 'a',
}));
const bindings = [0, 1].map((n) => ({
  clientStartId: `${n + 1}`, workerId: `${n + 1}`, jobId: jobs[n].jobId,
  issuanceId: jobs[n].issuanceId, runGeneration: 1,
}));
function fixture() {
  return {
    browsers: [0, 1].map((n) => ({ frames: [{ ...jobs[n] }, { type: 'mining_ready', ...bindings[n] },
      n === 0
        ? { type: 'block_accepted', ...bindings[n], terminal: true,
          confirmedBy: 'immediate_canonical_readback_top_block_with_matching_pow_hash' }
        : { type: 'block_rejected', ...bindings[n], terminal: true, reason: 'submission_already_claimed' }],
    })),
    poolState: { active: 0, closeFailed: 0, teardownFailures: 0, successfulIssues: 2, admissionClosed: true },
    poolEvidence: { daemonCounters: { dispatchSubmission: 1 }, rpcCounts: { submit_block: 1 }, rpcRawDropped: 0 },
    cleanup: { released: true },
  };
}

test('canonical two-browser handoff needs two distinct ready jobs and one server-confirmed dispatch', () => {
  assert.deepEqual(adjudicateTwoBrowser(fixture()), {
    ok: true, code: 'TWO_BROWSER_CANONICAL_HANDOFF', winningBrowser: 'A',
  });
  for (const [mutate, code] of [
    [(x) => { x.browsers[1].frames[0].jobId = x.browsers[0].frames[0].jobId; }, 'JOB_IDENTITY_MISMATCH'],
    [(x) => { x.browsers[1].frames[1].issuanceId = 'wrong'; }, 'READY_BINDING_MISMATCH'],
    [(x) => { x.browsers[1].frames[2].reason = 'search_bound_reached'; }, 'CANONICAL_HANDOFF_NOT_PROVED'],
    [(x) => { x.poolEvidence.daemonCounters.dispatchSubmission = 2; }, 'DISPATCH_COUNT_UNTRUSTED'],
    [(x) => { x.poolEvidence.rpcCounts.submit_block = 0; }, 'DISPATCH_COUNT_UNTRUSTED'],
    [(x) => { x.poolEvidence.rpcRawDropped = 1; }, 'RPC_CAPTURE_TRUNCATED'],
    [(x) => { x.poolState.active = 1; }, 'ASSIGNMENT_NOT_RELEASED'],
    [(x) => { x.cleanup.released = false; }, 'RELEASE_UNCONFIRMED'],
    [(x) => { x.browsers[0].errors = ['page exception']; }, 'BROWSER_ERRORS'],
    [(x) => { delete x.browsers[0].frames[0].height; }, 'INCOMPLETE_JOB_BINDING'],
  ]) {
    const x = fixture(); mutate(x);
    assert.equal(adjudicateTwoBrowser(x).code, code);
  }
});

test('an early block and a bounded no-block run are distinct from a proved handoff', () => {
  const early = fixture();
  early.browsers[1].frames.splice(0, 2);
  assert.equal(adjudicateTwoBrowser(early).code, 'BLOCK_BEFORE_TWO_READY');
  const noBlock = fixture();
  noBlock.poolEvidence.daemonCounters.dispatchSubmission = 0;
  noBlock.poolEvidence.rpcCounts.submit_block = 0;
  // A method not yet called is absent from the RPC audit rather than represented by a zero key.
  delete noBlock.poolEvidence.rpcCounts.submit_block;
  noBlock.browsers[0].frames[2] = { type: 'run_stopped', ...bindings[0], terminal: true,
    reason: 'search_bound_reached' };
  noBlock.browsers[1].frames[2] = { type: 'run_stopped', ...bindings[1], terminal: true,
    reason: 'search_bound_reached' };
  assert.equal(adjudicateTwoBrowser(noBlock).code, 'BOUNDED_NO_BLOCK');
  noBlock.browsers[1].frames[2].reason = 'session_dispose';
  assert.equal(adjudicateTwoBrowser(noBlock).code, 'NO_BLOCK_OTHER_TERMINAL');
});
