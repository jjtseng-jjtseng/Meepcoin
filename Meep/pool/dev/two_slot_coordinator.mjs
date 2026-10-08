// Process-wide lifecycle coordinator for the opt-in two-browser real-template slice.
//
// This is deliberately narrower than a pool scheduler. It joins the already-fenced serialized
// personalized issuer to the bounded multi-job authority, and adds the lifecycle rule neither
// primitive can enforce alone: an assignment continues to occupy capacity until its verifier/helper
// teardown has positively completed. No listener, daemon, helper, browser or hash is started here.

import {
  MULTI_JOB_REFUSED,
  createMultiJobAuthority,
} from './multi_job_authority.mjs';

export const TWO_SLOT_REFUSED = Object.freeze({
  ...MULTI_JOB_REFUSED,
  ROUND_CLOSED: 'two_slot_round_closed',
  ISSUE_FAILED: 'personalized_issue_failed',
  ISSUE_CANCELLED: 'personalized_issue_cancelled',
  PUBLICATION_REFUSED: 'personalized_publication_refused',
  TIP_MISMATCH: 'personalized_issue_tip_changed',
  TEARDOWN_FAILED: 'assignment_teardown_failed',
});

function validOwner(owner) {
  return (typeof owner === 'object' && owner !== null) || typeof owner === 'function';
}

function requireRequest(owner, clientStartId) {
  if (!validOwner(owner)) throw new TypeError('owner must be a non-null object identity');
  if (typeof clientStartId !== 'string' || !/^[0-9a-f]{32}$/.test(clientStartId)) {
    throw new TypeError('clientStartId must be exactly 32 lowercase hex characters');
  }
}

function wanted(fn) {
  try { return fn() === true; } catch { return false; }
}

function canonicalFrom(issued) {
  const height = issued?.job?.height;
  const parent = issued?.canonical?.prevHashHex;
  return { height, parent };
}

const sameCanonical = (a, b) => a !== null && b !== null
  && a.height === b.height && a.parent === b.parent;

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

/**
 * Create the single coordinator shared by every session in one opt-in two-browser round.
 *
 * `issuer.issue({stillWanted})` must be the process-owned serializedPersonalizedTemplateIssuer.
 * A caller must attach its lifecycle before allocating a verifier. The lifecycle's `revoke` is a
 * synchronous, no-throw stop signal; `close` is the asynchronous positive teardown confirmation.
 */
export function createTwoSlotCoordinator({
  issuer,
  now = () => Date.now(),
  authority = createMultiJobAuthority({ now }),
} = {}) {
  if (issuer === null || typeof issuer !== 'object' || typeof issuer.issue !== 'function') {
    throw new TypeError('issuer.issue is required');
  }
  if (typeof now !== 'function') throw new TypeError('now must be a function');
  if (authority === null || typeof authority !== 'object'
    || typeof authority.reserve !== 'function'
    || typeof authority.publish !== 'function'
    || typeof authority.claimSubmission !== 'function'
    || typeof authority.release !== 'function') {
    throw new TypeError('a multi-job authority is required');
  }

  // Only live/closing assignments are retained here. The authority owns the bounded terminal
  // tombstones. Consequently this map never exceeds the authority's two-active limit.
  const assignments = new Map();
  let closing = false;
  let admissionClosed = false;
  let successfulIssues = 0;
  let teardownFailures = 0;
  let pinnedCanonical = null;

  function find(owner, clientStartId) {
    const record = assignments.get(owner) ?? null;
    if (record === null || record.clientStartId !== clientStartId) return null;
    return record;
  }

  function snapshot(record) {
    return Object.freeze({
      clientStartId: record.clientStartId,
      state: record.state,
      canonical: record.canonical === null ? null : Object.freeze({ ...record.canonical }),
      jobId: record.issued?.job?.jobId ?? null,
      issuanceId: record.issued?.job?.issuanceId ?? null,
      claimed: record.claimed,
      lifecycleAttached: record.lifecycle !== null,
      terminalReason: record.terminalReason,
    });
  }

  function signalRevoke(record, reason) {
    if (record.lifecycle === null || record.revoked) return;
    record.revoked = true;
    try { record.lifecycle.revoke(reason); } catch { /* close still runs and proves physical release */ }
  }

  function releaseAfterClose(record, reason) {
    if (record.closeStarted) return record.closeGate.promise;
    if (record.lifecycle === null && record.runtimeExpected) return record.closeGate.promise;
    record.closeStarted = true;
    let closeResult;
    try {
      signalRevoke(record, reason);
      closeResult = record.lifecycle === null ? undefined : record.lifecycle.close(reason);
    } catch (err) {
      closeResult = Promise.reject(err);
    }
    Promise.resolve(closeResult).then(() => {
      if (record.lifecycle !== null) {
        let confirmed = false;
        try { confirmed = record.lifecycle.isClosed() === true; } catch { confirmed = false; }
        if (!confirmed) {
          teardownFailures += 1;
          record.state = 'close_failed';
          record.closeGate.resolve({ ok: false, reason: TWO_SLOT_REFUSED.TEARDOWN_FAILED });
          return;
        }
      }
      let released;
      try {
        released = authority.release({
          owner: record.owner,
          clientStartId: record.clientStartId,
          reason,
          atMs: now(),
        });
      } catch {
        released = { ok: false };
      }
      if (!released.ok) {
        teardownFailures += 1;
        record.state = 'close_failed';
        record.closeGate.resolve({ ok: false, reason: TWO_SLOT_REFUSED.TEARDOWN_FAILED });
        return;
      }
      record.state = 'terminal';
      assignments.delete(record.owner);
      record.closeGate.resolve({ ok: true, reason });
    }, () => {
      // Fail closed: the authority reservation stays active, so this slot cannot be reused while a
      // verifier/helper may still exist. Shutdown/audit can see the retained close_failed record.
      teardownFailures += 1;
      record.state = 'close_failed';
      record.closeGate.resolve({ ok: false, reason: TWO_SLOT_REFUSED.TEARDOWN_FAILED });
    });
    return record.closeGate.promise;
  }

  function startClosing(record, reason, { noRuntime = false, deferLifecycle = false } = {}) {
    record.wanted = false;
    if (record.terminalReason === null) record.terminalReason = reason;
    if (record.state !== 'close_failed') record.state = 'closing';
    if (noRuntime) record.runtimeExpected = false;
    if (deferLifecycle) {
      // A canonical claim is immediately followed by daemon dispatch. The sibling's stop signal
      // must run in this same stack, before claimSubmission returns; only physical teardown waits.
      signalRevoke(record, record.terminalReason);
      queueMicrotask(() => releaseAfterClose(record, record.terminalReason));
      return record.closeGate.promise;
    }
    return releaseAfterClose(record, record.terminalReason);
  }

  function authorityAdapter(record) {
    return Object.freeze({
      claimSubmission(args = {}) {
        if (record.state !== 'published' || !record.wanted) {
          return { ok: false, reason: MULTI_JOB_REFUSED.INTENT_REVOKED };
        }
        const claim = authority.claimSubmission({
          ...args,
          owner: record.owner,
          clientStartId: record.clientStartId,
        });
        if (!claim.ok) return claim;
        record.claimed = true;
        admissionClosed = true;

        // Synchronous revocation precedes block_run's immediate dispatch. Teardown is asynchronous,
        // but the losing assignment remains inside the authority until that teardown confirms.
        for (const sibling of assignments.values()) {
          if (sibling === record) continue;
          if (sibling.state === 'issuing') {
            // The serialized issuer may still be preparing browser B while browser A finds a block.
            // Revoke demand now, but let begin() join the issuer and release its reservation only
            // after that in-flight operation observes cancellation and settles.
            sibling.wanted = false;
            sibling.terminalReason ??= 'canonical_submission_claimed';
          } else if (sibling.state === 'published'
            && sameCanonical(sibling.canonical, record.canonical)) {
            startClosing(sibling, 'canonical_submission_claimed', { deferLifecycle: true });
          }
        }
        return claim;
      },
      isClaimed(issuanceId) {
        return record.claimed === true && record.issued?.job?.issuanceId === issuanceId;
      },
    });
  }

  async function begin({ owner, clientStartId, stillWanted = () => true } = {}) {
    requireRequest(owner, clientStartId);
    if (typeof stillWanted !== 'function') throw new TypeError('stillWanted must be a function');
    const existing = assignments.get(owner) ?? null;
    if (existing !== null) {
      if (existing.clientStartId !== clientStartId) {
        return { ok: false, reason: MULTI_JOB_REFUSED.OWNER_BUSY };
      }
      if (existing.state === 'issuing') {
        const repeated = await existing.issuePromise;
        if (!repeated.ok) return repeated;
        if (existing.state !== 'published' || !existing.wanted) {
          return { ok: false, reason: MULTI_JOB_REFUSED.INTENT_REVOKED };
        }
        return { ...repeated, idempotent: true, assignment: snapshot(existing) };
      }
      if (existing.state === 'published' && existing.wanted) {
        const repeated = await existing.issuePromise;
        if (existing.state !== 'published' || !existing.wanted) {
          return { ok: false, reason: MULTI_JOB_REFUSED.INTENT_REVOKED };
        }
        return { ...repeated, idempotent: true, assignment: snapshot(existing) };
      }
      return { ok: false, reason: MULTI_JOB_REFUSED.INTENT_REVOKED };
    }
    if (closing || admissionClosed) return { ok: false, reason: TWO_SLOT_REFUSED.ROUND_CLOSED };

    const reservation = authority.reserve({ owner, clientStartId });
    if (!reservation.ok) return reservation;
    const record = {
      owner,
      clientStartId,
      state: 'issuing',
      wanted: true,
      issued: null,
      canonical: null,
      claimed: false,
      runtimeExpected: false,
      lifecycle: null,
      terminalReason: null,
      closeStarted: false,
      revoked: false,
      closeGate: deferred(),
      issuePromise: null,
    };
    assignments.set(owner, record);

    record.issuePromise = (async () => {
      let issued;
      try {
        issued = await issuer.issue({ stillWanted: () => record.wanted && wanted(stillWanted) });
      } catch (err) {
        const mapped = err?.code === TWO_SLOT_REFUSED.ISSUE_CANCELLED
          ? TWO_SLOT_REFUSED.ISSUE_CANCELLED
          : err?.code === 'personalized_issue_tip_changed'
            ? TWO_SLOT_REFUSED.TIP_MISMATCH
            : TWO_SLOT_REFUSED.ISSUE_FAILED;
        const reason = record.terminalReason ?? mapped;
        await startClosing(record, reason, { noRuntime: true });
        return { ok: false, reason };
      }
      if (!record.wanted || !wanted(stillWanted) || admissionClosed) {
        const reason = record.terminalReason ?? TWO_SLOT_REFUSED.ISSUE_CANCELLED;
        await startClosing(record, reason, { noRuntime: true });
        return { ok: false, reason };
      }

      let normalizedCanonical;
      let published;
      try {
        const canonical = canonicalFrom(issued);
        normalizedCanonical = Object.freeze({
          height: issued.job.height.toString(),
          parent: issued.canonical.prevHashHex,
        });
        if (pinnedCanonical !== null && !sameCanonical(pinnedCanonical, normalizedCanonical)) {
          await startClosing(record, TWO_SLOT_REFUSED.TIP_MISMATCH, { noRuntime: true });
          return { ok: false, reason: TWO_SLOT_REFUSED.TIP_MISMATCH };
        }
        published = authority.publish({ owner, clientStartId, job: issued.job, canonical });
      } catch {
        await startClosing(record, TWO_SLOT_REFUSED.ISSUE_FAILED, { noRuntime: true });
        return { ok: false, reason: TWO_SLOT_REFUSED.ISSUE_FAILED };
      }
      if (!published.ok) {
        await startClosing(record, published.reason ?? TWO_SLOT_REFUSED.PUBLICATION_REFUSED,
          { noRuntime: true });
        return { ok: false, reason: published.reason ?? TWO_SLOT_REFUSED.PUBLICATION_REFUSED };
      }
      record.issued = issued;
      record.canonical = normalizedCanonical;
      pinnedCanonical ??= normalizedCanonical;
      record.runtimeExpected = true;
      record.state = 'published';
      successfulIssues += 1;
      return Object.freeze({
        ok: true,
        idempotent: false,
        assignment: snapshot(record),
        issued,
        authority: authorityAdapter(record),
      });
    })();
    return record.issuePromise;
  }

  function attachLifecycle({ owner, clientStartId, revoke, close, isClosed } = {}) {
    requireRequest(owner, clientStartId);
    if (typeof revoke !== 'function' || typeof close !== 'function' || typeof isClosed !== 'function') {
      throw new TypeError('lifecycle revoke, close and isClosed functions are required');
    }
    const record = find(owner, clientStartId);
    if (record === null) return { ok: false, reason: MULTI_JOB_REFUSED.NOT_RESERVED };
    if (record.lifecycle !== null) throw new Error('assignment lifecycle is already attached');
    record.lifecycle = Object.freeze({ revoke, close, isClosed });
    if (record.state === 'closing') releaseAfterClose(record, record.terminalReason);
    return { ok: true, assignment: snapshot(record), closePromise: record.closeGate.promise };
  }

  async function finish({ owner, clientStartId, reason = 'assignment_finished', noRuntime = false } = {}) {
    requireRequest(owner, clientStartId);
    const record = find(owner, clientStartId);
    if (record === null) return { ok: false, reason: MULTI_JOB_REFUSED.NOT_RESERVED };
    if (record.state === 'issuing') {
      record.wanted = false;
      record.terminalReason ??= reason;
      await record.issuePromise;
      return record.closeGate.promise;
    }
    return startClosing(record, reason, { noRuntime });
  }

  async function cancel({ owner, clientStartId, reason = 'assignment_cancelled' } = {}) {
    requireRequest(owner, clientStartId);
    const record = find(owner, clientStartId);
    if (record === null) return { ok: false, reason: MULTI_JOB_REFUSED.NOT_RESERVED };
    record.wanted = false;
    if (record.state === 'issuing') {
      await record.issuePromise;
      return record.closeGate.promise;
    }
    return startClosing(record, reason, { noRuntime: record.lifecycle === null });
  }

  async function beginClose(reason = 'pool shutting down') {
    closing = true;
    const closingAssignments = [];
    for (const record of [...assignments.values()]) {
      record.wanted = false;
      if (record.state === 'issuing') {
        closingAssignments.push(record.issuePromise.then(() => record.closeGate.promise));
      } else {
        closingAssignments.push(startClosing(record, reason, { noRuntime: record.lifecycle === null }));
      }
    }
    return Promise.all(closingAssignments);
  }

  return Object.freeze({
    begin,
    attachLifecycle,
    finish,
    cancel,
    beginClose,
    get stateFacts() {
      let issuing = 0;
      let published = 0;
      let closingCount = 0;
      let closeFailed = 0;
      for (const record of assignments.values()) {
        if (record.state === 'issuing') issuing += 1;
        if (record.state === 'published') published += 1;
        if (record.state === 'closing') closingCount += 1;
        if (record.state === 'close_failed') closeFailed += 1;
      }
      return Object.freeze({
        active: assignments.size,
        activeLimit: 2,
        issuing,
        published,
        closing: closingCount,
        closeFailed,
        successfulIssues,
        teardownFailures,
        admissionClosed,
        poolClosing: closing,
        authority: authority.stateFacts,
      });
    },
  });
}
