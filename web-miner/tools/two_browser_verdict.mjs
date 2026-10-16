// Deliberately narrow post-run adjudication for the private two-browser acceptance probe.
// Browser frames alone cannot prove daemon dispatch; the pool's own counters and confirmed physical
// cleanup are separate required inputs. This module has no I/O and cannot start a miner.

const terminalTypes = new Set(['block_accepted', 'block_rejected', 'run_stopped', 'run_unavailable']);
const one = (frames, type) => frames.filter((frame) => frame?.type === type);

function bound(frame, ready) {
  return frame?.jobId === ready?.jobId && frame?.issuanceId === ready?.issuanceId
    && frame?.workerId === ready?.workerId && frame?.clientStartId === ready?.clientStartId
    && frame?.runGeneration === ready?.runGeneration;
}

export function adjudicateTwoBrowser({ browsers, poolState, poolEvidence, cleanup } = {}) {
  const fail = (code, detail) => ({ ok: false, code, detail });
  if (!Array.isArray(browsers) || browsers.length !== 2
    || browsers.some((b) => !Array.isArray(b?.frames) || b.truncated === true)) {
    return fail('INCOMPLETE_BROWSER_CAPTURE', 'two complete, distinct browser frame captures are required');
  }
  if (browsers.some((b) => Array.isArray(b.errors) && b.errors.length > 0)) {
    return fail('BROWSER_ERRORS', 'a browser emitted an unparseable server frame or page exception');
  }
  if (cleanup?.released !== true) return fail('RELEASE_UNCONFIRMED', 'owned processes were not all confirmed released');
  if (poolState?.teardownFailures !== 0 || poolState?.active !== 0
    || poolState?.closeFailed !== 0) {
    return fail('ASSIGNMENT_NOT_RELEASED', 'an assignment was retained or teardown failed');
  }
  const dispatches = poolEvidence?.daemonCounters?.dispatchSubmission;
  // The RPC audit creates a key on first use; absence is the documented zero-call state.
  const rpcDispatches = poolEvidence?.rpcCounts && Object.hasOwn(poolEvidence.rpcCounts, 'submit_block')
    ? poolEvidence.rpcCounts.submit_block : poolEvidence?.rpcCounts ? 0 : null;
  if (!Number.isSafeInteger(dispatches) || dispatches < 0 || dispatches > 1
    || !Number.isSafeInteger(rpcDispatches) || rpcDispatches !== dispatches) {
    return fail('DISPATCH_COUNT_UNTRUSTED', 'both daemon dispatch counters must agree and be at most one');
  }
  if (poolEvidence?.rpcRawDropped !== 0) {
    return fail('RPC_CAPTURE_TRUNCATED', 'the daemon RPC audit dropped records');
  }
  const jobs = browsers.map((b) => one(b.frames, 'real_job'));
  const ready = browsers.map((b) => one(b.frames, 'mining_ready'));
  const accepted = browsers.map((b) => one(b.frames, 'block_accepted'));
  const rejected = browsers.map((b) => one(b.frames, 'block_rejected'));
  if (accepted.some((a) => a.length > 1) || rejected.some((r) => r.length > 1)) {
    return fail('DUPLICATE_TERMINAL', 'a browser received duplicate success or failure terminals');
  }
  const winners = accepted.flat();
  if (jobs.some((j) => j.length !== 1) || ready.some((r) => r.length !== 1)) {
    return dispatches === 1 && winners.length === 1
      ? fail('BLOCK_BEFORE_TWO_READY', 'a block was accepted, but both browser assignments were not ready')
      : fail('TWO_ASSIGNMENTS_NOT_PROVED', 'both browsers must receive one job and one ready binding');
  }
  const [a, b] = jobs.map((j) => j[0]);
  const nonempty = (value) => typeof value === 'string' && value.length > 0;
  if ([a, b].some((job) => !nonempty(job.jobId) || !nonempty(job.issuanceId)
    || !nonempty(job.contentDigest) || !/^[1-9][0-9]*$/.test(job.height ?? '')
    || !nonempty(job.seedHashHex) || !nonempty(job.epochKeyHex))
    || ready.some((r) => !nonempty(r[0].clientStartId) || !nonempty(r[0].workerId)
      || !Number.isSafeInteger(r[0].runGeneration) || r[0].runGeneration < 1)) {
    return fail('INCOMPLETE_JOB_BINDING', 'a job or its ready binding lacks a required identity field');
  }
  if (a.jobId === b.jobId || a.issuanceId === b.issuanceId || a.contentDigest === b.contentDigest
    || a.height !== b.height || a.seedHashHex !== b.seedHashHex || a.epochKeyHex !== b.epochKeyHex) {
    return fail('JOB_IDENTITY_MISMATCH', 'the jobs must be distinct work on one height and hashing epoch');
  }
  for (let i = 0; i < 2; i++) {
    if (ready[i][0].jobId !== jobs[i][0].jobId
      || ready[i][0].issuanceId !== jobs[i][0].issuanceId) {
      return fail('READY_BINDING_MISMATCH', `browser ${i + 1} readiness was not for its issued job`);
    }
    const terminal = browsers[i].frames.filter((f) => terminalTypes.has(f?.type));
    if (terminal.length !== 1) return fail('TERMINAL_COUNT_MISMATCH', `browser ${i + 1} needs one terminal`);
    if (!bound(terminal[0], ready[i][0])) {
      return fail('TERMINAL_BINDING_MISMATCH', `browser ${i + 1} terminal names other work`);
    }
  }
  if (poolState.successfulIssues !== 2) {
    return fail('ISSUANCE_COUNT_MISMATCH', 'the coordinator did not record exactly two successful issuances');
  }
  if (dispatches === 0 && winners.length === 0) {
    const bounded = browsers.every((browser) => browser.frames.some((frame) =>
      frame.type === 'run_stopped' && frame.terminal === true
        && frame.reason === 'search_bound_reached'));
    return bounded
      ? { ok: false, code: 'BOUNDED_NO_BLOCK', detail: 'two distinct browser searches reached their bounds without a daemon submission' }
      : fail('NO_BLOCK_OTHER_TERMINAL', 'no block was dispatched, but a browser did not end at its search bound');
  }
  if (dispatches !== 1 || winners.length !== 1) {
    return fail('BLOCK_DISPATCH_MISMATCH', 'one dispatch requires exactly one browser success');
  }
  const winningIndex = accepted[0].length === 1 ? 0 : 1;
  const losingIndex = 1 - winningIndex;
  if (!bound(accepted[winningIndex][0], ready[winningIndex][0])
    || accepted[winningIndex][0].terminal !== true
    || accepted[winningIndex][0].confirmedBy !== 'immediate_canonical_readback_top_block_with_matching_pow_hash'
    || rejected[losingIndex].length !== 1
    || rejected[losingIndex][0].terminal !== true
    || rejected[losingIndex][0].reason !== 'submission_already_claimed'
    || poolState.admissionClosed !== true) {
    return fail('CANONICAL_HANDOFF_NOT_PROVED', 'the winner readback or sibling-stop terminal is missing');
  }
  return { ok: true, code: 'TWO_BROWSER_CANONICAL_HANDOFF', winningBrowser: winningIndex === 0 ? 'A' : 'B' };
}
