// Per-connection adapter for the opt-in two-browser personalized-template slice.
//
// It owns no daemon, verifier or listener. Before Start it sends only the delayed-job hello. Start
// reserves one of the process' two slots, waits for one personalized issuance, builds exactly one
// assignment-scoped simulation context, attaches its teardown to the shared coordinator, then
// hands the original Start to createSimulationSession with the SAME owner and worker identity.

import { randomBytes } from 'node:crypto';

import {
  PROTOCOL_VERSION,
  REJECT_REASONS,
  parseClientMessage,
} from '../../web-miner/lib/shared/protocol.js';
import {
  REAL_TWO_SLOT_PROFILE,
  createSimulationSession,
} from './sim_session.mjs';
import { toClientJobMessage } from './real_template.mjs';
import { MULTI_JOB_REFUSED } from './multi_job_authority.mjs';

let workerCounter = 0;
const PUBLIC_PRE_RUN_REASONS = new Set([
  'pool_capacity', 'reservation_history_full', 'owner_already_reserved',
  'reservation_terminal', 'reservation_start_mismatch', 'run_intent_revoked',
  'two_slot_round_closed', 'personalized_issue_failed', 'personalized_issue_cancelled',
  'personalized_publication_refused', 'personalized_issue_tip_changed',
  'canonical_submission_claimed', 'assignment_setup_failed',
]);

function mintWorkerId() {
  workerCounter += 1;
  return `sim-${workerCounter}-${randomBytes(4).toString('hex')}`;
}

function validCoordinator(value) {
  return value !== null && typeof value === 'object'
    && typeof value.begin === 'function'
    && typeof value.attachLifecycle === 'function'
    && typeof value.finish === 'function'
    && typeof value.cancel === 'function';
}

/**
 * Build one transport-facing session around the process-owned two-slot coordinator.
 *
 * `createContext(result)` receives the successful coordinator begin result. It must return an
 * assignment-scoped createSimulationContext result with `closeAssignmentResources()` and the
 * `assignmentResourcesClosed` readback. No context is created for a refused or abandoned Start.
 */
export function createTwoSlotSession({
  coordinator,
  createContext,
  send,
  now = () => Date.now(),
  onAudit = () => {},
  trackAsync = () => {},
  profile = REAL_TWO_SLOT_PROFILE,
  childFactory = createSimulationSession,
} = {}) {
  if (!validCoordinator(coordinator)) throw new TypeError('a two-slot coordinator is required');
  if (typeof createContext !== 'function') throw new TypeError('createContext is required');
  if (typeof send !== 'function') throw new TypeError('send is required');
  if (typeof now !== 'function' || typeof onAudit !== 'function'
    || typeof trackAsync !== 'function' || typeof childFactory !== 'function') {
    throw new TypeError('invalid two-slot session callback');
  }
  if (profile?.mode !== 'real-local-daemon' || profile?.vocabulary?.unavailable === undefined) {
    throw new TypeError('a real-daemon session profile is required');
  }

  const owner = Object.freeze({});
  const workerId = mintWorkerId();
  let authorized = false;
  let disposed = false;
  let wanted = true;
  let pendingStartId = null;
  let assignmentPromise = null;
  let closePromise = null;
  let child = null;
  let context = null;
  let stage = 'idle';
  let revoked = false;

  function audit(kind, reason) {
    const entry = { kind, workerId };
    if (reason !== undefined) entry.reason = reason;
    try { onAudit(Object.freeze(entry)); } catch { /* diagnostics cannot change control flow */ }
  }

  function track(promise) {
    const observed = Promise.resolve(promise);
    try { trackAsync(observed); } catch { /* server shutdown still has closePromise below */ }
    return observed;
  }

  function rememberClose(promise) {
    const closing = track(promise);
    closePromise = closing;
    closing.then((result) => {
      // A fresh Start on this transport is legal only after the previous assignment's authority
      // and physical resources have both been released. Never let an old close promise stand in
      // for the next assignment's teardown.
      if (closePromise === closing && child === null && !disposed && result?.ok === true
        && (context === null || context.assignmentResourcesClosed === true)) {
        context = null;
        closePromise = null;
        stage = 'idle';
        revoked = false;
      }
    }, () => { /* retain the failed close as a terminal occupancy fact */ });
    return closing;
  }

  function reject(reason, detail) {
    send({ type: 'error', reason, detail: detail || undefined });
    return { ok: false, reason };
  }

  function refusePreRun(reason, clientStartId) {
    const publicReason = PUBLIC_PRE_RUN_REASONS.has(reason) ? reason : 'assignment_setup_failed';
    send({
      type: profile.vocabulary.unavailable,
      terminal: true,
      reason: publicReason,
      clientStartId,
      workerId,
      jobId: null,
      issuanceId: null,
      runGeneration: null,
      attemptState: 'idle',
    });
    audit('two_slot_start_refused', publicReason);
    return { ok: false, reason: publicReason };
  }

  function handleHello() {
    if (authorized) return reject(REJECT_REASONS.BAD_SCHEMA, 'client_hello already sent');
    authorized = true;
    send({
      type: 'server_hello',
      protocolVersion: PROTOCOL_VERSION,
      mode: profile.mode,
      workerId,
      labels: profile.labels,
      actionLabel: profile.actionLabel,
      alreadyCompleted: coordinator.stateFacts?.admissionClosed === true,
      attemptState: 'idle',
      notice: profile.helloNotice,
      willAllocate: profile.willAllocate,
      searchLimits: profile.searchLimits,
      jobIssuedOnStart: true,
      // A losing sibling receives submission_already_claimed as a normal competition result.
      // Declare that contract explicitly; a single-client failure with the same code is not a win.
      twoSlotCompetition: true,
    });
    audit('two_slot_hello');
    return { ok: true, type: 'client_hello', workerId };
  }

  function beginClose(notice) {
    if (closePromise !== null) return closePromise;
    const clientStartId = notice?.clientStartId ?? pendingStartId;
    if (clientStartId === null) return Promise.resolve({ ok: true, reason: 'no_assignment' });
    const method = notice?.reason === 'session_dispose' ? 'cancel' : 'finish';
    return rememberClose(coordinator[method]({
      owner,
      clientStartId,
      reason: notice?.reason ?? 'assignment_finished',
    }));
  }

  async function activate(msg, byteLength, text) {
    stage = 'issuing';
    const begun = await coordinator.begin({
      owner,
      clientStartId: msg.clientStartId,
      stillWanted: () => wanted && !disposed && pendingStartId === msg.clientStartId,
    });
    if (!begun.ok) return refusePreRun(begun.reason, msg.clientStartId);
    if (!wanted || disposed) {
      beginClose({ clientStartId: msg.clientStartId, reason: 'session_dispose' });
      return { ok: false, reason: 'disposed' };
    }

    stage = 'setup';
    try {
      context = createContext(begun);
      if (context === null || typeof context !== 'object'
        || typeof context.closeAssignmentResources !== 'function'
        || typeof context.assignmentResourcesClosed !== 'boolean') {
        throw new TypeError('createContext must return an assignment-scoped context synchronously');
      }
    } catch {
      rememberClose(coordinator.finish({
        owner,
        clientStartId: msg.clientStartId,
        reason: 'assignment_context_failed',
        noRuntime: true,
      }));
      return refusePreRun('assignment_setup_failed', msg.clientStartId);
    }

    const attached = coordinator.attachLifecycle({
      owner,
      clientStartId: msg.clientStartId,
      revoke: (reason) => {
        revoked = true;
        return child?.revokeAssignment(reason) ?? false;
      },
      close: (reason) => context.closeAssignmentResources(reason),
      isClosed: () => context.assignmentResourcesClosed === true,
    });
    if (!attached.ok) {
      try { await context.closeAssignmentResources('assignment lifecycle refused'); } catch { /* fail closed in coordinator */ }
      rememberClose(coordinator.finish({
        owner,
        clientStartId: msg.clientStartId,
        reason: attached.reason ?? MULTI_JOB_REFUSED.NOT_RESERVED,
      }));
      return refusePreRun('assignment_setup_failed', msg.clientStartId);
    }

    if (!wanted || disposed || revoked) {
      beginClose({ clientStartId: msg.clientStartId, reason: 'session_dispose' });
      return { ok: false, reason: 'disposed' };
    }

    try {
      child = childFactory({
        sim: context,
        send,
        now,
        onAudit,
        sessionOwner: owner,
        preauthorizedWorkerId: workerId,
        onTerminal: (notice) => beginClose(notice),
      });
    } catch {
      rememberClose(coordinator.finish({
        owner,
        clientStartId: msg.clientStartId,
        reason: 'assignment_session_failed',
      }));
      return refusePreRun('assignment_setup_failed', msg.clientStartId);
    }

    if (!wanted || disposed || revoked) {
      child.dispose();
      beginClose({ clientStartId: msg.clientStartId, reason: 'session_dispose' });
      return { ok: false, reason: 'disposed' };
    }

    // Publication to this transport happens only after the coordinator owns the assignment and its
    // physical teardown lifecycle. The child emits no duplicate hello or job.
    send(toClientJobMessage(begun.issued.job));
    audit('two_slot_assignment_published');
    if (!wanted || disposed || revoked) {
      child.dispose();
      beginClose({ clientStartId: msg.clientStartId, reason: 'session_dispose' });
      return { ok: false, reason: 'disposed' };
    }
    stage = 'active';
    return child.handleRaw(byteLength, text);
  }

  async function handleRaw(byteLength, text) {
    if (disposed) return { ok: false, reason: 'disposed' };
    if (child !== null) return child.handleRaw(byteLength, text);
    const msg = parseClientMessage(byteLength, text);
    if (!msg.ok) return reject(msg.reason, msg.detail);
    if (msg.type === 'client_hello') return handleHello();
    if (msg.type === 'ping') { send({ type: 'pong' }); return { ok: true, type: 'ping' }; }
    if (msg.type === 'pong') return { ok: true, type: 'pong' };
    if (msg.type !== 'start_request') {
      return reject(REJECT_REASONS.NOT_AUTHORIZED, 'Start is required before assignment work');
    }
    if (!authorized) return reject(REJECT_REASONS.NOT_AUTHORIZED, 'client_hello required first');
    if (typeof msg.clientStartId !== 'string') {
      return reject(REJECT_REASONS.BAD_SCHEMA, 'two-slot Start requires clientStartId');
    }
    if (assignmentPromise !== null) {
      if (msg.clientStartId !== pendingStartId) {
        return refusePreRun(MULTI_JOB_REFUSED.OWNER_BUSY, msg.clientStartId);
      }
      return assignmentPromise;
    }
    if (closePromise !== null) return refusePreRun(MULTI_JOB_REFUSED.OWNER_BUSY, msg.clientStartId);
    pendingStartId = msg.clientStartId;
    const current = activate(msg, byteLength, text).catch(() => {
      if (child !== null) {
        try { child.dispose(); } finally { child = null; }
      }
      if (closePromise === null) beginClose({ clientStartId: msg.clientStartId, reason: 'assignment_setup_failed' });
      if (disposed) return { ok: false, reason: 'disposed' };
      return refusePreRun('assignment_setup_failed', msg.clientStartId);
    }).then((result) => {
      if (child === null && !disposed && pendingStartId === msg.clientStartId) {
        pendingStartId = null;
        assignmentPromise = null;
      }
      return result;
    });
    assignmentPromise = current;
    return assignmentPromise;
  }

  function dispose() {
    if (disposed) return;
    disposed = true;
    wanted = false;
    if (child !== null) {
      child.dispose();
    } else if (pendingStartId !== null && stage !== 'setup') {
      beginClose({ clientStartId: pendingStartId, reason: 'session_dispose' });
    }
  }

  async function disposeAsync() {
    dispose();
    try { await assignmentPromise; } catch { /* activation is already terminalized */ }
    if (closePromise !== null) return closePromise;
    return { ok: true, reason: 'no_assignment' };
  }

  return Object.freeze({
    handleRaw,
    dispose,
    disposeAsync,
    notifyVerifierUnhealthy(health) {
      if (child !== null) return child.notifyVerifierUnhealthy(health);
      if (pendingStartId === null) return false;
      revoked = true;
      dispose();
      return true;
    },
    get workerId() { return workerId; },
    get ownerToken() { return owner; },
    get authorized() { return authorized; },
    get disposed() { return disposed; },
    get clientStartId() { return pendingStartId; },
    get child() { return child; },
    get context() { return context; },
    get pendingDisposal() { return closePromise; },
  });
}
