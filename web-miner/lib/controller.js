// Mining lifecycle for the MeepCoin local browser miner. Deliberately DOM-free and fully
// dependency-injected so the voluntary-mining guarantees can be tested without a browser:
//
//   * Constructing this controller creates NO Worker, allocates NO dataset and computes NO hash.
//     Mining begins only inside start(), which only an explicit Start click calls.
//   * start() does NOT create the Worker. It sends `start_request` and waits: the LOCAL SERVER
//     must bring its own verifier up first and answer `mining_ready`. Only that answer, and only
//     while run intent is still held for the same run generation, constructs the one Worker. So
//     before Start this browser has not requested the Wasm at all, and the server has not
//     imported, compiled or instantiated it, allocated a dataset, or computed a hash. (The server
//     has read and hashed ~58.1 KiB of the build files, so it can serve exactly what it verified.)
//   * Every socket failure -- close, error, or a throwing send -- funnels into the same
//     fail-closed stop as an explicit Stop.
//   * There is exactly ONE stop path, stop(). Explicit Stop, tab-hidden, pagehide and unload all
//     funnel through it, and it clears run intent and TERMINATES the worker -- it never merely
//     relabels the UI.
//   * Becoming visible again does nothing. Nothing about run intent is written to localStorage,
//     sessionStorage, cookies, IndexedDB, the URL, or a service worker, so no reload, restore,
//     history navigation or reconnect can resume mining.
//   * THE FINITE DEVELOPMENT SEQUENCE (real mode, only when the server's hello says so). One Start is
//     consent for the exact bounded number of consecutive templates declared before Start. After the
//     server reports a block accepted or says an external canonical tip superseded it and names the next
//     run (sequence_next, which must extend the exact binding this page holds), the SAME Worker is
//     re-contextualised -- only once its first search has posted `finished`, only while run intent is
//     still held, and only after the server's mining_ready for the new run. A Worker message about a job
//     this page already moved past is stale: it is counted and ignored, and can never become block 2's
//     candidate, count or evidence. Stop, hide, pagehide and socket loss end the whole session.

import {
  PROTOCOL_VERSION, ALGORITHM_LABEL, CLIENT_START_ID_RE, MAX_RUN_GENERATION,
  RECORDED_SIMULATION_MODE as SIM_MODE, REAL_DAEMON_MODE as REAL_MODE, REAL_SEARCH_LIMITS,
  REAL_REFRESH_LIMITS, REAL_SEQUENCE_DEV_MAX_BLOCKS, REAL_SHARE_LIMITS,
  isSupportedRefreshWindows, isSupportedSequenceBlocks,
  SIM_ATTEMPT_STATE_VALUES, SIM_PRE_RUN_REFUSALS, SIM_TERMINAL_ATTEMPT_STATES, simFailureCode,
} from './shared/protocol.js';
import { hexToBytes, meetsTargetLE, targetAtLeastLE } from './shared/target.js';
import { isExactUint32 } from './shared/one_shot.js';

/**
 * REAL-LOCAL-DAEMON EVENT NAMES. That mode reuses the one-attempt machinery below, so each real
 * event is handled by the same bound, gated case as its simulation counterpart -- but only in real
 * mode, and a real-mode page never accepts a simulation-named event (nor the reverse).
 */
const REAL_EVENT_ALIASES = Object.freeze({
  candidate_verified: 'mock_verification_complete',
  block_submit_started: 'mock_submit_path_exercised',
  block_accepted: 'simulation_complete',
  block_rejected: 'simulation_failed',
  run_stopped: 'simulation_stopped',
  run_unavailable: 'simulation_unavailable',
});
const SIMULATION_ONLY_EVENTS = Object.freeze(Object.values(REAL_EVENT_ALIASES));

export const STATES = Object.freeze({
  IDLE: 'idle',
  // Start pressed; waiting for the local server to report its verifier ready. No Worker yet.
  STARTING: 'starting',
  MINING: 'mining',
  STOPPED: 'stopped',
  STOPPED_HIDDEN: 'stopped_hidden',
  ERROR: 'error',
});

export const STOP_REASONS = Object.freeze({
  USER: 'user',
  HIDDEN: 'hidden',
  PAGEHIDE: 'pagehide',
  ERROR: 'error',
  DISCONNECTED: 'disconnected',
  SOCKET_ERROR: 'socket_error',
  SEND_FAILED: 'send_failed',
  COMPLETE: 'demo_complete',
  // real-local-daemon: the frozen attempt/time bound ended with no nonce meeting the target
  BOUNDED_NO_SOLUTION: 'bounded_no_solution',
  OTHER_BROWSER_WON: 'other_browser_won',
});

const CLIENT_VERSION = 'meep-web-miner-slice/0';

/** Page text for a pre-run refusal, keyed by its closed reason. No server-supplied text is shown. */
const PRE_RUN_REFUSAL_TEXT = Object.freeze({
  simulation_already_completed:
    'this local server has already used its one recorded-template simulation; restart the local server to run another',
  simulation_attempt_in_progress:
    'another connection is running this server\u2019s one recorded-template simulation right now',
  pool_capacity:
    'both local browser slots are occupied; press Start again after one has fully stopped',
  reservation_history_full:
    'this local server has used its bounded browser-slot history; restart the local server',
  owner_already_reserved:
    'this browser connection already has a different Start in progress',
  reservation_terminal:
    'this Start identity has already ended; press Start again to create a fresh request',
  reservation_start_mismatch:
    'the local server refused a mismatched Start identity',
  run_intent_revoked:
    'this Start was cancelled before personalized work could be handed over',
  two_slot_round_closed:
    'this local two-browser round has already closed; restart the local server for a new round',
  personalized_issue_failed:
    'the local daemon could not issue this browser a personalized template; no mining started',
  personalized_issue_cancelled:
    'personalized template issuance was cancelled before mining started',
  personalized_publication_refused:
    'the local server could not publish this personalized template; no mining started',
  personalized_issue_tip_changed:
    'the private daemon tip changed while personalized work was being issued; no mining started',
  canonical_submission_claimed:
    'the other browser claimed this round\u2019s one block submission before your job was issued',
  assignment_setup_failed:
    'the local server could not prepare this browser\u2019s mining session; no mining started',
  verification_disabled:
    'verification is disabled on this local server; restart the local server',
  missing_client_start_id: 'the Start request was malformed',
});

const HASH64_RE = /^[0-9a-f]{64}$/;
const ISSUANCE_ID_RE = /^[0-9a-f]{32}$/;
const REAL_ALGORITHM_LABEL = 'meephash-w-v2-frozen-real-template';
const REAL_JOB_ID_RE = /^[!-~]{1,200}$/;
const CANONICAL_U64_RE = /^(?:0|[1-9][0-9]{0,19})$/;
const MAX_U64 = (1n << 64n) - 1n;
const EVEN_HEX_RE = /^(?:[0-9a-f]{2}){1,1048576}$/;

/**
 * The minimum closed shape required before a post-Start real job can become browser work.
 *
 * Legacy/pre-issued jobs retain their existing compatibility path. This stricter check applies
 * only when the server explicitly promised `jobIssuedOnStart`: in that path there is no earlier
 * job for the acknowledgement to cross-check, so malformed work must be rejected before it can
 * establish that identity or contribute to Worker construction.
 */
function isWellFormedDelayedRealJob(job) {
  if (!job || job.type !== 'real_job'
    || typeof job.jobId !== 'string' || !REAL_JOB_ID_RE.test(job.jobId)
    || typeof job.issuanceId !== 'string' || !ISSUANCE_ID_RE.test(job.issuanceId)
    || typeof job.contentDigest !== 'string' || !HASH64_RE.test(job.contentDigest)
    || job.algorithm !== REAL_ALGORITHM_LABEL
    || typeof job.height !== 'string' || !CANONICAL_U64_RE.test(job.height)
    || !Number.isInteger(job.majorVersion) || job.majorVersion < 0 || job.majorVersion > 255
    || typeof job.epochKeyHex !== 'string' || !HASH64_RE.test(job.epochKeyHex)
    || typeof job.seedHashHex !== 'string' || !HASH64_RE.test(job.seedHashHex)
    || typeof job.hashingTemplateHex !== 'string' || !EVEN_HEX_RE.test(job.hashingTemplateHex)
    || typeof job.targetHexLE !== 'string' || !HASH64_RE.test(job.targetHexLE)
    || !isExactUint32(job.nonceStart)
    || !Number.isSafeInteger(job.nonceRange) || job.nonceRange < 1
    || job.nonceStart + job.nonceRange > 0x100000000
    || !Number.isSafeInteger(job.expiresAtMs) || job.expiresAtMs < 0) return false;
  try {
    return BigInt(job.height) <= MAX_U64;
  } catch {
    return false;
  }
}

/** A uint32 as the protocol's 8 lowercase hex characters. */
function nonceHexOf(nonce) {
  return (nonce >>> 0).toString(16).padStart(8, '0');
}

/** 16 random bytes as 32 lowercase hex characters. */
function defaultStartId() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Is this message's run binding even well formed?
 *
 * Checked before it is compared to anything, so a message carrying `undefined` in four fields
 * cannot match an attempt whose fields are also unset.
 */
function isWellFormedBinding(msg) {
  return typeof msg.clientStartId === 'string' && CLIENT_START_ID_RE.test(msg.clientStartId)
    && typeof msg.workerId === 'string' && msg.workerId.length > 0
    && typeof msg.jobId === 'string' && msg.jobId.length > 0
    && typeof msg.issuanceId === 'string' && msg.issuanceId.length > 0
    && Number.isSafeInteger(msg.runGeneration)
    && msg.runGeneration >= 0 && msg.runGeneration <= MAX_RUN_GENERATION;
}

/**
 * @param {object} deps
 * @param {() => {postMessage(m:any):void, terminate():void, onmessage:Function|null, onerror:Function|null}} deps.createWorker
 * @param {(url:string) => {send(s:string):void, close():void, onopen:Function|null, onmessage:Function|null, onclose:Function|null, onerror:Function|null}} deps.createSocket
 * @param {() => number} [deps.now]
 * @param {() => string} [deps.newStartId]  16 random bytes as 32 lowercase hex. A CORRELATION token
 *        for one Start attempt, never authority. Injectable so tests can be deterministic.
 * @param {(snapshot:object) => void} [deps.onChange]
 */
export function createMiningController({
  createWorker,
  createSocket,
  now = () => Date.now(),
  newStartId = defaultStartId,
  onChange = () => {},
}) {
  const stats = {
    state: STATES.IDLE,
    connection: 'disconnected',
    stopReason: null,
    workerId: null,
    jobId: null,
    algorithm: null,
    hashes: 0,
    hashesPerSecond: 0,
    accepted: 0,
    rejected: 0,
    lastRejectReason: null,
    lastAcceptedNonceHex: null,
    wasmHeapBytes: null,
    serverVerifierHeapBytes: null,
    // Reported separately from the Wasm heap and never added to it: this is the native build's own
    // dataset + scratchpad allocation, not a measurement of the pool process's resident memory.
    serverNativeAlgorithmBytes: null,
    serverVerifierMode: null,
    demoComplete: false,
    demoWon: false,
    error: null,
    // RECORDED-TEMPLATE SIMULATION OUTCOME. Three separate facts, deliberately not one flag:
    //   simComplete      the attempt SUCCEEDED -- set only by a bound simulation_complete
    //   simFinished      the attempt reached ANY terminal state
    //   simProcessSpent  this server process can make no further attempt; restart required
    // A failure used to set simComplete, and the page then rendered the success summary for it.
    simComplete: false,
    // Whether THIS browser's own validated hash equals the independently proven server result.
    simBrowserMatched: false,
    // null until the Worker reports; then 'reported' (validated) or 'invalid' (not this work).
    simBrowserEvidence: null,
    simBrowserHashHexLE: null,
    // REAL-LOCAL-DAEMON outcome facts, all null outside that mode.
    realFoundNonce: null,
    realBlockId: null,
    realBlockHeight: null,
    realConfirmedBy: null,
    realOutcome: null,          // 'block_accepted' | 'bounded_no_solution' | 'other_browser_won' | 'failed' | 'stopped'
    realSearch: null,           // { hashes, found, timedOut, exhausted } from the Worker's one search
    // THE FINITE DEVELOPMENT SEQUENCE, when the server declared one. Per-block facts are never merged.
    // The opt-in same-height window budget and position. 1 / 1 everywhere else.
    realWindowTotal: 1,
    realWindowIndex: 1,
    // The window whose context the Worker actually holds, and whether the page is between the two.
    realActiveWindowIndex: 1,
    realWindowHandoff: false,
    // True only in the FIRST part of a handover: the server has issued the next window but the
    // Worker's OLD context has not settled yet, so its search may still be finishing. The page must
    // not claim that nothing at all is hashing while this is true.
    realWindowRetiring: false,
    realWindowRefreshes: 0,
    realSequenceTotal: 1,
    realBlockIndex: 1,
    // The block whose context the Worker actually holds. During a composed handoff this can lag
    // `realBlockIndex`, just as the active window can lag the server-issued window.
    realActiveBlockIndex: 1,
    realBlocks: [],             // [{ block, height, nonce, blockId, hashHexLE, browserNonce, browserHashHexLE, confirmedBy, browserMatched, attempts, jobId }]
    realTotalAttempts: 0,
    realWorkersCreated: 0,
    realWorkerContexts: [],     // what the Worker reported for each context it built
    realStaleWorkerMessages: 0,
    realExternalSupersessions: 0,
    // OPT-IN SHARE SEARCH. `realSharesAccepted` counts only fully bound server acceptances; it is
    // never incremented from anything this browser computed, and it is never a block count.
    realShareMode: false,
    realSharesReported: 0,
    realSharesAccepted: 0,
    realShareQueueDepth: 0,
    realSearchSettled: false,
    // Opt-in capability: in real mode only, the server may promise that this click causes the
    // first personalized job to be issued. False everywhere else and when omitted.
    realJobIssuedOnStart: false,
    twoSlotCompetition: false,
    simFinished: false,
    simProcessSpent: false,
    simFailureCode: null,
  };

  let socket = null;
  let worker = null;
  let runIntent = false;
  // Chosen by the explicit Start click; never persisted or changed mid-run.
  let searchPacingMs = 0;
  // THE BROWSER-LOCAL Worker/message invalidation token. It is NOT the server's run generation and
  // must never be sent as one: it counts Workers this tab has abandoned. The server's generation is
  // `serverRun.runGeneration` below, minted by the server and echoed back verbatim.
  let generation = 0;

  // ---- recorded-template simulation state (null in the default synthetic mode) --------------
  let mode = 'synthetic';
  let serverProtocolValid = true;
  let realJob = null;              // the public projection of the recorded template
  let realJobIssuedOnStart = false;
  let twoSlotCompetition = false;
  // The ONE attempt this controller is currently waiting on, minted by start(). It is correlation,
  // not authority: the server grants nothing because we sent it.
  let pendingStartId = null;
  // What the SERVER already told us, before any Start: the worker id from server_hello and the job
  // from real_job. An acknowledgement is checked against these -- it is the message that mints the
  // run generation, but it does not get to invent the worker, the job or the issuance.
  let helloWorkerId = null;
  // { clientStartId, workerId, jobId, issuanceId, runGeneration } -- set ONLY by a run_started that
  // matches pendingStartId while this attempt is still live.
  let serverRun = null;
  /**
   * ATTEMPTS THE USER ABANDONED BEFORE THE SERVER ANSWERED.
   *
   * Keyed by correlation token, so a later Start CANNOT clear them -- that was the defect: start()
   * cleared a single `pendingCancel` flag, so attempt A's delayed run_started then looked like an
   * acknowledgement for attempt B, and a Worker was built and a candidate submitted on A's stale
   * binding. Each entry earns AT MOST ONE fully bound stop when its acknowledgement finally
   * arrives, and can never wake anything.
   */
  const abandonedStarts = new Map();
  // True once this attempt has reached a terminal server state. Counters and results freeze here:
  // nothing after it may change a count, a hash, a completion flag or the state.
  let simTerminal = false;
  // ONE BROWSER REPORT PER RUN: 'unreported' -> 'reported' | 'invalid', and never back. The honest
  // Worker reports once, but the page must not depend on that: two valid-shaped hashed_one events
  // used to send two submit_real_candidate frames while the counter still said one.
  let browserReport = 'unreported';
  let currentJob = null;
  let runStartedAt = 0;
  // Hashes are cumulative for the whole run: a job's nonce window is bounded, so one run walks
  // through several of them and the readout must not restart at zero each time.
  let hashesBefore = 0;
  let hashesThisRun = 0;
  // Set when the worker has exhausted a job's window. The client then waits for the pool to issue
  // new work rather than rescanning the same nonces and resubmitting shares it has already sent.
  let awaitingWork = false;
  let dispatchedJobId = null;
  // True between the Start click and the server's mining_ready. A stop during this window must
  // make the eventual reply inert.
  let pendingStart = false;
  // Counts every Worker this controller has ever constructed. Tests assert it is 0 before Start
  // and never advances past 1 while one run is live.
  let workersCreated = 0;
  // ---- the finite sequence (real mode with a server-declared total, hard-capped by this build) ----
  let sequenceTotal = 1;
  // THE OPT-IN SAME-HEIGHT WINDOW BUDGET the server declared, and which window of it this page is
  // on. 1 / 1 in every other mode. These are NOT blocks and are never displayed as blocks.
  let windowTotal = 1;
  let windowIndex = 1;                  // the window the SERVER has issued
  let activeWindowIndex = 1;            // the window the Worker's LIVE context actually searches
  let activeBlockIndex = 1;             // the block the Worker's LIVE context actually searches
  let activeRealJob = null;             // the job that live context was built for
  let windowHandoff = false;            // issued != active: nothing is being hashed
  let blockIndex = 1;
  let acceptedCurrentBlock = false;
  let searchJobId = null;               // the job the Worker's CURRENT context searches
  let searchBlockIndex = 1;              // the block coordinate of that exact Worker context
  let settledSearchJobId = null;        // the job whose one search has posted `finished`
  let retiringSearchJobId = null;       // the one old search allowed to emit only its settling `finished`
  let completedSearchAttempts = 0;      // cumulative over settled contexts; one number, never a history
  let completedSearchAttemptsExact = true;
  let blockSearchAttempts = Array(REAL_SEQUENCE_DEV_MAX_BLOCKS).fill(0);
  let blockSearchAttemptsExact = Array(REAL_SEQUENCE_DEV_MAX_BLOCKS).fill(true);
  let pendingRotation = null;           // { targetJobId, ready, posted } for the latest server job not yet in the Worker
  // ---- the opt-in share search (real mode, only when the SERVER's job says shareWork) -----------
  //
  // The browser reports every qualifying hit, but it submits ONE at a time: the server verifies one
  // candidate per template at a time and refuses a second with `queue_full`. The queue below is the
  // client's side of that contract. It is bounded by the same small number the Worker caps its hits
  // at, it is never retried on a timer, and the next report leaves only on the server's own
  // `candidate_settled` cue for the exact nonce that is outstanding.
  let shareMode = false;
  let shareTargetBytes = null;
  const shareQueue = [];                // [{ nonce, nonceHex, hashHexLE, block }], at most maxSharesPerJob
  const reportedNonces = [];            // bounded: the nonces this run has already reported
  let outstandingShare = null;          // the one report the server is verifying, or null
  let outstandingAccepted = false;      // its acceptance was already counted; a replay adds nothing
  let searchSettledAwaitingServer = false;

  function emit() {
    onChange({ ...stats });
  }

  function setState(state, extra = {}) {
    stats.state = state;
    Object.assign(stats, extra);
    emit();
  }

  // ---------------------------------------------------------------- connection

  function connect(url) {
    if (socket) return;
    stats.connection = 'connecting';
    emit();
    socket = createSocket(url);
    socket.onopen = () => {
      stats.connection = 'connected';
      send({ type: 'client_hello', protocolVersion: PROTOCOL_VERSION, clientVersion: CLIENT_VERSION });
      emit();
    };
    socket.onmessage = (event) => onServerMessage(event.data);
    // All three socket failure paths are the SAME fail-closed stop. A browser is not required to
    // deliver `close` after `error`, so the controller must not depend on it.
    socket.onclose = () => failClosed(STOP_REASONS.DISCONNECTED, 'the connection to the local pool closed');
    socket.onerror = () => failClosed(STOP_REASONS.SOCKET_ERROR, 'the connection to the local pool failed');
  }

  /**
   * The single fail-closed disconnect path. Idempotent, and safe to call from any state --
   * including STARTING, where there is no Worker yet but there IS run intent that must be
   * cleared so a late mining_ready cannot construct one.
   */
  function failClosed(reason, message) {
    stats.connection = 'disconnected';
    stats.workerId = null;
    const wasLive = runIntent || pendingStart;
    if (wasLive) {
      stats.error = message;
      stop(reason);
    } else {
      emit();
    }
  }

  /**
   * Send, treating a throw as a dead socket rather than letting it escape into a Worker message
   * handler. A share that cannot be sent must stop mining, not be silently dropped while the
   * worker keeps burning CPU.
   */
  function send(obj) {
    if (!socket || stats.connection !== 'connected') return false;
    try {
      socket.send(JSON.stringify(obj));
      return true;
    } catch (err) {
      failClosed(STOP_REASONS.SEND_FAILED, `could not reach the local pool: ${err?.message ?? 'send failed'}`);
      return false;
    }
  }

  /** Both one-attempt modes share the reservation, binding and terminal machinery. */
  function oneAttempt() {
    return mode === SIM_MODE || mode === REAL_MODE;
  }

  function onServerMessage(data) {
    let msg;
    try {
      msg = JSON.parse(typeof data === 'string' ? data : String(data));
    } catch {
      return;
    }
    if (!msg || typeof msg.type !== 'string') return;

    let type = msg.type;
    if (mode === REAL_MODE) {
      if (SIMULATION_ONLY_EVENTS.includes(type)) return;
      type = REAL_EVENT_ALIASES[type] ?? type;
    }

    switch (type) {
      case 'server_hello':
        // THE SERVER decides the mode. A client cannot select it and nothing here asks for it.
        mode = typeof msg.mode === 'string' ? msg.mode : 'synthetic';
        stats.mode = mode;
        // This capability is recognized only in REAL-LOCAL-DAEMON mode and only as the literal
        // boolean true. A malformed real-mode declaration is a protocol fault; a declaration in
        // any other mode grants nothing and preserves that mode's existing behavior.
        realJobIssuedOnStart = mode === REAL_MODE && msg.jobIssuedOnStart === true;
        stats.realJobIssuedOnStart = realJobIssuedOnStart;
        twoSlotCompetition = mode === REAL_MODE && msg.twoSlotCompetition === true;
        stats.twoSlotCompetition = twoSlotCompetition;
        if (mode === REAL_MODE && msg.twoSlotCompetition !== undefined
          && typeof msg.twoSlotCompetition !== 'boolean') {
          serverProtocolValid = false;
          stats.state = STATES.ERROR;
          stats.error = 'the local pool declared an invalid two-browser competition capability';
        }
        if (mode === REAL_MODE && msg.jobIssuedOnStart !== undefined
          && typeof msg.jobIssuedOnStart !== 'boolean') {
          serverProtocolValid = false;
          stats.state = STATES.ERROR;
          stats.error = 'the local pool declared an invalid delayed-job capability';
        }
        stats.simLabels = Array.isArray(msg.labels) ? msg.labels.slice() : null;
        stats.simActionLabel = typeof msg.actionLabel === 'string' ? msg.actionLabel : null;
        stats.simAlreadyCompleted = msg.alreadyCompleted === true;
        stats.simAttemptState = SIM_ATTEMPT_STATE_VALUES.includes(msg.attemptState) ? msg.attemptState : null;
        if (stats.simAlreadyCompleted || SIM_TERMINAL_ATTEMPT_STATES.includes(stats.simAttemptState)) {
          stats.simProcessSpent = true;
        }
        // THE SERVER decides whether one Start covers a finite sequence; only real mode honours it.
        // An explicitly malformed or over-limit value is a protocol error, never a silent downgrade
        // to one block that would make the page disclose less work than the server intends.
        if (mode === REAL_MODE && msg.sequenceTotal !== undefined) {
          const sequenceOk = isSupportedSequenceBlocks(msg.sequenceTotal) && msg.sequenceTotal >= 2;
          // Protocol validity is a one-way latch. A valid field later in this hello (or a later
          // hello) cannot forgive an earlier malformed capability or budget declaration.
          serverProtocolValid = serverProtocolValid && sequenceOk;
          sequenceTotal = sequenceOk ? msg.sequenceTotal : 1;
          if (!sequenceOk) {
            stats.state = STATES.ERROR;
            stats.error = `the local pool declared an invalid sequence length (maximum ${REAL_SEQUENCE_DEV_MAX_BLOCKS})`;
          }
        } else {
          sequenceTotal = 1;
        }
        stats.realSequenceTotal = sequenceTotal;
        // THE SERVER also decides whether one Start may search several nonce windows of the SAME
        // height. A malformed or over-limit total is a protocol error, exactly like the sequence
        // length: a page that quietly downgraded it would understate the work it consented to.
        if (mode === REAL_MODE && msg.windowTotal !== undefined) {
          // The advertised session budget must be EXACTLY this build's own: a longer one is a
          // promise this page cannot keep, a shorter one is a bound it would not display.
          const contextTotal = sequenceTotal * msg.windowTotal;
          const windowsOk = isSupportedRefreshWindows(msg.windowTotal) && msg.windowTotal >= 2
            && Number.isSafeInteger(contextTotal) && contextTotal <= REAL_SEQUENCE_DEV_MAX_BLOCKS
            && msg.sessionBudgetMs === REAL_REFRESH_LIMITS.maxSessionMs;
          serverProtocolValid = serverProtocolValid && windowsOk;
          windowTotal = windowsOk ? msg.windowTotal : 1;
          if (!windowsOk) {
            stats.state = STATES.ERROR;
            stats.error = `the local pool declared an invalid window total (maximum ${REAL_REFRESH_LIMITS.maxWindows})`;
          }
        } else {
          windowTotal = 1;
          // A session budget without a window declaration is an unsolicited capability claim.
          if (mode === REAL_MODE && msg.sessionBudgetMs !== undefined) {
            serverProtocolValid = false;
            stats.state = STATES.ERROR;
            stats.error = 'the local pool declared a session budget without a window total';
          }
        }
        windowIndex = 1;
        activeWindowIndex = 1;
        activeBlockIndex = 1;
        activeRealJob = null;
        windowHandoff = false;
        stats.realWindowTotal = windowTotal;
        stats.realWindowIndex = 1;
        stats.realActiveWindowIndex = 1;
        stats.realActiveBlockIndex = 1;
        stats.realWindowHandoff = false;
        stats.realWindowRetiring = false;
        stats.simNotice = typeof msg.notice === 'string' ? msg.notice : null;
        stats.simAllocateNotice = typeof msg.willAllocate === 'string' ? msg.willAllocate : null;
        stats.workerId = typeof msg.workerId === 'string' ? msg.workerId : null;
        helloWorkerId = stats.workerId;
        // PASSIVE status. If the pool already holds a verifier from an earlier run, show its real
        // memory instead of a dash. Reading it starts nothing and is not run intent.
        stats.serverVerifierHeapBytes = msg.verifierWasmHeapBytes ?? null;
        stats.serverNativeAlgorithmBytes = msg.verifierNativeAlgorithmBytes ?? null;
        stats.serverVerifierMode = typeof msg.verifierMode === 'string' ? msg.verifierMode : null;
        emit();
        break;
      case 'job':
        if (msg.algorithm !== ALGORITHM_LABEL) {
          // The server has offered work this build cannot verify it is doing correctly. Drop the
          // previous job too: silently falling back to stale work would mean mining something the
          // server has already moved on from.
          currentJob = null;
          stats.jobId = null;
          stats.algorithm = null;
          setState(STATES.ERROR, { error: 'unsupported algorithm ' + String(msg.algorithm).slice(0, 48) });
          if (runIntent) stop(STOP_REASONS.ERROR);
          return;
        }
        currentJob = {
          jobId: msg.jobId,
          generation: msg.generation,
          algorithm: msg.algorithm,
          targetHexLE: msg.targetHexLE,
          nonceStart: msg.nonceStart,
          nonceRange: msg.nonceRange,
          batch: msg.batchHint ?? 4,
        };
        stats.jobId = currentJob.jobId;
        stats.algorithm = currentJob.algorithm;
        emit();
        // New work for a run that had exhausted the previous window.
        if (runIntent && awaitingWork && currentJob.jobId !== dispatchedJobId) {
          awaitingWork = false;
          dispatchWork(generation);
        }
        break;
      case 'mining_ready': {
        // READINESS ALONE CREATES NOTHING IN SIMULATION MODE, AND CHANGES NOTHING EITHER. It must
        // name an attempt this controller is waiting on AND one the server has already acknowledged
        // with a matching run_started -- all five fields -- BEFORE any of its telemetry is copied.
        // A stale or forged readiness used to overwrite the memory and verifier figures first.
        if (oneAttempt()) {
          if (simTerminal || !isWellFormedBinding(msg) || !matchesActiveRun(msg)) return;
          if (mode === REAL_MODE && sequenceTotal > 1
            && (msg.sequenceTotal !== sequenceTotal || msg.sequenceIndex !== blockIndex)) return;
          // THE REFRESH FACTS ARE FAIL-CLOSED, AND THEY ARE CHECKED BEFORE ANY ALLOCATION. A
          // readiness that carries window facts this page was never offered -- or that disagrees
          // with the total the server declared before Start, or names a window other than the one
          // it just issued -- is a protocol fault: no Worker is created for it and nothing is
          // allocated. Silently ignoring the fields would mine a window nobody agreed on.
          // THE REFRESH FACTS ARE FAIL-CLOSED, AND THEY ARE CHECKED BEFORE ANY ALLOCATION. A
          // readiness that carries window facts this page was never offered -- or that disagrees
          // with the total the server declared before Start, or names a window other than the one
          // it just issued, or omits the exact session budget it advertised -- is a protocol fault:
          // no Worker is created for it and nothing is allocated. Silently ignoring the fields
          // would mine a window nobody agreed on, and leaving the run live would strand a server
          // session the page can no longer stop, so this ends it through the shared bound
          // error-stop path: run intent cleared, exactly one bound stop_request, no Worker, and no
          // auto-resume afterwards.
          if (mode === REAL_MODE && !readyWindowFactsOk(msg)) {
            serverProtocolValid = false;
            setState(STATES.ERROR, { error: 'the local pool declared window facts this page was not offered' });
            if (runIntent) stop(STOP_REASONS.ERROR);
            return;
          }
        }
        // The pool's memory figure is true regardless of whether we still want to mine, so record
        // it first: after a cancelled Start the pool really is holding that memory until it is
        // stopped, and showing a dash there would be inaccurate.
        stats.serverVerifierHeapBytes = msg.verifierWasmHeapBytes ?? null;
        stats.serverNativeAlgorithmBytes = msg.verifierNativeAlgorithmBytes ?? null;
        stats.serverVerifierMode = typeof msg.verifierMode === 'string' ? msg.verifierMode : null;
        if (oneAttempt()) {
          // Reported by the helper itself, validated there as the exact frozen-v2 allocation.
          stats.simNativeDatasetBytes = Number.isSafeInteger(msg.nativeDatasetBytes) ? msg.nativeDatasetBytes : null;
          stats.simNativeScratchBytes = Number.isSafeInteger(msg.nativeScratchBytes) ? msg.nativeScratchBytes : null;
        }
        // THE NEXT BLOCK'S READINESS re-contextualises the existing Worker; it never builds another.
        if (mode === REAL_MODE && pendingRotation !== null
          && pendingRotation.targetJobId === msg.jobId && !pendingRotation.ready) {
          if (runIntent && worker) {
            pendingRotation.ready = true;
            maybeRecontext();
          }
          emit();
          return;
        }
        // The Worker, though, is constructed ONLY if run intent from THIS run is still held. A
        // readiness that arrives after Stop/hide/pagehide is inert.
        if (!pendingStart || !runIntent) {
          emit();
          return;
        }
        pendingStart = false;
        spawnWorker();
        break;
      }
      // ---- recorded-template simulation -----------------------------------------------------
      case 'real_job':
        if (mode === REAL_MODE && realJobIssuedOnStart) {
          // In this opt-in path the first job must be the direct answer to the currently pending
          // Start. Before Start, after cancellation, after acknowledgement, or as a duplicate it is
          // out of order. None of those messages is allowed to establish work or create a Worker.
          const expectedNow = pendingStart && runIntent && serverRun === null && realJob === null;
          const structurallyValid = isWellFormedDelayedRealJob(msg)
            && (msg.shareWork !== true || shareTargetUsable(msg));
          if (!expectedNow || !structurallyValid) {
            serverProtocolValid = false;
            stats.error = expectedNow
              ? 'the local pool offered a malformed delayed real job'
              : 'the local pool sent delayed real work out of order';
            if (runIntent || pendingStart) stop(STOP_REASONS.ERROR);
            else setState(STATES.ERROR);
            return;
          }
        }
        realJob = msg;
        stats.jobId = msg.jobId;
        stats.algorithm = msg.algorithm;
        stats.simHeight = msg.height;
        stats.simNonce = msg.nonceStart;
        // THE SERVER DECIDES WHETHER THIS JOB IS A SHARE JOB, and the page only checks that what it
        // was given is usable. A job that CLAIMS share work with a malformed share target, or one
        // harder than its own block target, is refused outright: nothing is allocated for it.
        if (mode === REAL_MODE && msg.shareWork === true) {
          if (shareTargetUsable(msg)) {
            shareMode = true;
            shareTargetBytes = hexToBytes(msg.shareTargetHexLE);
          } else {
            shareMode = false;
            serverProtocolValid = false;
            stats.state = STATES.ERROR;
            stats.error = 'the local pool offered an unusable share target';
          }
        }
        stats.realShareMode = shareMode;
        emit();
        break;
      case 'run_started': {
        if (!oneAttempt() || !isWellFormedBinding(msg)) break;
        // A LATE ACKNOWLEDGEMENT FOR AN ATTEMPT THE USER ALREADY ABANDONED. It gets exactly one
        // fully bound best-effort stop -- for ITS OWN attempt -- and wakes nothing.
        const abandoned = abandonedStarts.get(msg.clientStartId);
        if (abandoned) {
          if (!abandoned.stopSent && msg.workerId === helloWorkerId && realJob
            && msg.jobId === realJob.jobId && msg.issuanceId === realJob.issuanceId) {
            abandoned.stopSent = true;
            abandoned.stopBinding = {
              clientStartId: msg.clientStartId,
              workerId: msg.workerId,
              jobId: msg.jobId,
              issuanceId: msg.issuanceId,
              runGeneration: msg.runGeneration,
            };
            sendStopFor(msg, abandoned.reason);
          }
          break;
        }
        // Unsolicited, or for an attempt other than the one outstanding right now.
        if (msg.clientStartId !== pendingStartId || !pendingStart || !runIntent) break;
        if (serverRun !== null) break;           // one acknowledgement per attempt, not two
        // AND IT MUST NAME WHAT THE SERVER ALREADY TOLD US. The acknowledgement mints the run
        // generation, and nothing else: the worker id came with server_hello and the job and
        // issuance came with real_job, so an acknowledgement naming different ones is not ours.
        if (msg.workerId !== helloWorkerId) break;
        if (!realJob || msg.jobId !== realJob.jobId || msg.issuanceId !== realJob.issuanceId) break;
        serverRun = {
          clientStartId: msg.clientStartId,
          workerId: msg.workerId,
          jobId: msg.jobId,
          issuanceId: msg.issuanceId,
          runGeneration: msg.runGeneration,
        };
        stats.workerId = msg.workerId;
        stats.serverRunGeneration = msg.runGeneration;
        emit();
        break;
      }
      case 'simulation_stopped': {
        if (!oneAttempt() || !isWellFormedBinding(msg) || msg.accepted !== true) break;
        // The server cancelled the one process attempt: for the run we are running, or for an
        // abandoned one whose single bound stop we sent. Either way this process is now spent.
        const forAbandoned = [...abandonedStarts.values()].some((rec) => rec.stopBinding
          && sameBinding(rec.stopBinding, msg));
        if (!matchesActiveRun(msg) && !forAbandoned) break;
        if (matchesActiveRun(msg)) {
          if (simTerminal) break;
          simTerminal = true;
          stats.simFinished = true;
          if (mode === REAL_MODE) {
            stats.realOutcome = msg.reason === 'search_bound_reached' ? 'bounded_no_solution' : 'stopped';
            finalizeRealAttemptCount();
          }
          stats.simProcessSpent = true;
          // A server backstop can end the run before the Worker's final message.  Terminal state is
          // not enough: route a still-live Worker through the one stop path so it cannot keep hashing
          // or later overwrite the frozen result.  simTerminal is already true, so this sends no
          // redundant stop back to the server.  If the browser stopped first, preserve that existing
          // local reason/state instead of stopping it a second time.
          if (runIntent || pendingStart) {
            const terminalReason = {
              search_bound_reached: STOP_REASONS.BOUNDED_NO_SOLUTION,
              page_hidden: STOP_REASONS.HIDDEN,
              page_unload: STOP_REASONS.PAGEHIDE,
              socket_close: STOP_REASONS.DISCONNECTED,
              user_stop: STOP_REASONS.USER,
            }[msg.reason] ?? STOP_REASONS.USER;
            stop(terminalReason);
            break;
          }
        }
        stats.simProcessSpent = true;
        emit();
        break;
      }
      case 'simulation_unavailable': {
        if (!oneAttempt()) break;
        if (isPreRunRefusal(msg)) {
          // A REFUSAL BEFORE ANY RUN EXISTED. Its own closed schema: no run generation, a closed
          // reason and attempt state, and no server text imported into the page.
          simTerminal = true;
          stats.simAttemptState = msg.attemptState;
          stats.error = PRE_RUN_REFUSAL_TEXT[msg.reason];
          // FOLLOW THE SERVER'S STATE. A process whose one attempt is finished is spent for good;
          // another session holding a still-live attempt is not a reason to disable this page.
          if (SIM_TERMINAL_ATTEMPT_STATES.includes(msg.attemptState)
            || msg.reason === 'simulation_already_completed'
            || msg.reason === 'reservation_history_full'
            || msg.reason === 'two_slot_round_closed'
            || msg.reason === 'canonical_submission_claimed') {
            stats.simProcessSpent = true;
          }
          stop(STOP_REASONS.ERROR);
          break;
        }
        // A failure of the ACKNOWLEDGED run: the full five-field binding.
        if (simTerminal || !isWellFormedBinding(msg) || !matchesActiveRun(msg)) break;
        simTerminal = true;
        stats.simFinished = true;
        stats.simProcessSpent = true;
        stats.simFailureCode = simFailureCode(msg.reason);
        stats.error = mode === REAL_MODE
          ? `the block run could not start: ${stats.simFailureCode}`
          : `the simulation could not run: ${stats.simFailureCode}`;
        stop(STOP_REASONS.ERROR);
        break;
      }
      case 'sequence_block_accepted': {
        // A BLOCK OF THE SEQUENCE, NONTERMINAL. It must name the active run and be the block we are on.
        if (mode !== REAL_MODE || sequenceTotal < 2 || simTerminal || !isWellFormedBinding(msg) || !matchesActiveRun(msg)) break;
        if (msg.sequenceTotal !== sequenceTotal || msg.sequenceIndex !== blockIndex || acceptedCurrentBlock) break;
        if (!HASH64_RE.test(msg.blockId ?? '') || !HASH64_RE.test(msg.hashHexLE ?? '')
          || typeof msg.height !== 'string' || msg.height !== realJob?.height || !isExactUint32(msg.nonce)) break;
        // Preserve the browser's own observed pair before sequence_next clears the current-job
        // fields. A later runner can compare each height independently, including a mismatch;
        // never fill these from the server's acceptance frame.
        const browserNonce = browserReport === 'reported' ? stats.realFoundNonce : null;
        const browserHashHexLE = browserReport === 'reported' ? stats.simBrowserHashHexLE : null;
        const browserMatched = browserNonce === msg.nonce && browserHashHexLE === msg.hashHexLE;
        stats.realBlocks = [...stats.realBlocks, Object.freeze({
          block: blockIndex,
          height: msg.height,
          nonce: msg.nonce,
          blockId: msg.blockId,
          hashHexLE: msg.hashHexLE,
          browserNonce,
          browserHashHexLE,
          confirmedBy: typeof msg.confirmedBy === 'string' && /^[a-z_]{1,80}$/.test(msg.confirmedBy) ? msg.confirmedBy : null,
          browserMatched,
          // Exact only after the current context's finished event. In a composed run this is the
          // sum of every settled window searched for the block, never merely the last window.
          attempts: settledSearchJobId === serverRun.jobId ? attemptsForBlock(blockIndex) : null,
          jobId: serverRun.jobId,
        })];
        acceptedCurrentBlock = true;
        retiringSearchJobId = serverRun.jobId;
        stats.realBlockId = msg.blockId;
        stats.realBlockHeight = msg.height;
        stats.simVerifiedHashHexLE = msg.hashHexLE;
        stats.realTotalAttempts = totalAttempts();
        emit();
        break;
      }
      case 'sequence_next': {
        // THE NEXT RUN OF THE SAME SESSION. It must extend EXACTLY the binding this page holds, follow an
        // accepted block, and describe the block on top of it. It builds nothing: even after a Stop it only
        // records the binding, so a terminal message for the new run is still recognised.
        if (mode !== REAL_MODE || sequenceTotal < 2 || simTerminal || !serverRun || !isWellFormedBinding(msg)) break;
        const prev = msg.previous;
        if (!prev || prev.jobId !== serverRun.jobId || prev.issuanceId !== serverRun.issuanceId
          || prev.runGeneration !== serverRun.runGeneration) break;
        if (msg.clientStartId !== serverRun.clientStartId || msg.workerId !== serverRun.workerId) break;
        if (msg.sequenceTotal !== sequenceTotal || msg.sequenceIndex !== blockIndex + 1 || msg.sequenceIndex > sequenceTotal) break;
        if (windowTotal > 1 && (msg.windowTotal !== windowTotal || msg.windowIndex !== 1
          || msg.sessionBudgetMs !== REAL_REFRESH_LIMITS.maxSessionMs)) break;
        if (msg.cause !== 'accepted' && msg.cause !== 'external_tip') break;
        if ((msg.cause === 'accepted') !== acceptedCurrentBlock) break;
        if (!(msg.runGeneration > serverRun.runGeneration) || msg.jobId === serverRun.jobId
          || msg.issuanceId === serverRun.issuanceId) break;
        if (!isNextRealJob(msg.job, msg)) break;
        // A new template is a new share window. In particular a block-quality report never gets a
        // candidate_settled cue, so its outstanding latch must not hold the next height's queue.
        // Discard queued old-height reports; they cannot be rebound to the new issuance.
        shareQueue.length = 0;
        reportedNonces.length = 0;
        outstandingShare = null;
        outstandingAccepted = false;
        searchSettledAwaitingServer = false;
        shareMode = msg.job.shareWork === true;
        shareTargetBytes = shareMode ? hexToBytes(msg.job.shareTargetHexLE) : null;
        stats.realShareMode = shareMode;
        stats.realSharesReported = 0;
        stats.realShareQueueDepth = 0;
        stats.realSearchSettled = false;
        stats.realShareStopCause = null;
        stats.realSharesFound = null;
        serverRun = {
          clientStartId: msg.clientStartId,
          workerId: msg.workerId,
          jobId: msg.jobId,
          issuanceId: msg.issuanceId,
          runGeneration: msg.runGeneration,
        };
        realJob = msg.job;
        blockIndex = msg.sequenceIndex;
        // Every new block starts at window one. The whole-Start session clock does not reset; only
        // this two-dimensional coordinate does.
        windowIndex = 1;
        acceptedCurrentBlock = false;
        if (msg.cause === 'external_tip') {
          stats.realExternalSupersessions += 1;
          // The server may advance more quickly than an asynchronous Worker context build. Retire
          // the job the Worker ACTUALLY owns, not merely the server's immediately previous job; a
          // second tip can then coalesce the pending target without asking the Worker to retire a
          // context it never built.
          const workerJobId = searchJobId;
          const alreadyRequested = workerJobId !== null && retiringSearchJobId === workerJobId;
          if (workerJobId !== null && settledSearchJobId !== workerJobId) {
            retiringSearchJobId = workerJobId;
          }
          // Per-context supersession is not a final Stop: the same Worker settles this obsolete
          // search, frees it, and can accept the latest context once readiness arrives.
          if (runIntent && worker && workerJobId !== null
            && settledSearchJobId !== workerJobId && !alreadyRequested) {
            worker.postMessage({ cmd: 'supersede_search', gen: generation, jobId: workerJobId });
          }
        }
        browserReport = 'unreported';
        stats.realBlockIndex = blockIndex;
        stats.realWindowIndex = windowIndex;
        if (windowTotal > 1) {
          windowHandoff = true;
          stats.realWindowHandoff = true;
          stats.realWindowRetiring = searchJobId !== null && settledSearchJobId !== searchJobId;
        }
        stats.serverRunGeneration = msg.runGeneration;
        stats.jobId = msg.job.jobId;
        stats.simHeight = msg.job.height;
        stats.simNonce = msg.job.nonceStart;
        stats.realFoundNonce = null;
        stats.simBrowserEvidence = null;
        stats.simBrowserHashHexLE = null;
        stats.simVerifiedHashHexLE = null;
        stats.realSearch = null;
        pendingRotation = runIntent && worker
          ? { targetJobId: realJob.jobId, ready: false, posted: false }
          : null;
        emit();
        break;
      }
      case 'job_refresh': {
        // ANOTHER NONCE WINDOW OF THE SAME HEIGHT, under the same Start. It is not a block, it is not
        // a sequence position, and it is accepted only when it extends EXACTLY the binding this page
        // holds: same start id and worker, a strictly newer run generation, a different job and
        // issuance, the SAME height, and a nonce window that does not overlap the one being replaced.
        // The template bytes -- and therefore the content digest -- may legitimately be identical.
        if (mode !== REAL_MODE || windowTotal < 2 || simTerminal || !serverRun
          || !isWellFormedBinding(msg)) break;
        const prev = msg.previous;
        if (!prev || prev.jobId !== serverRun.jobId || prev.issuanceId !== serverRun.issuanceId
          || prev.runGeneration !== serverRun.runGeneration) break;
        if (msg.clientStartId !== serverRun.clientStartId || msg.workerId !== serverRun.workerId) break;
        if (msg.cause !== 'window_exhausted') break;
        if (sequenceTotal > 1
          && (msg.sequenceTotal !== sequenceTotal || msg.sequenceIndex !== blockIndex)) break;
        if (msg.windowTotal !== windowTotal || msg.windowIndex !== windowIndex + 1
          || msg.windowIndex > windowTotal) break;
        if (!(msg.runGeneration > serverRun.runGeneration) || msg.jobId === serverRun.jobId
          || msg.issuanceId === serverRun.issuanceId) break;
        if (!isRefreshRealJob(msg.job, msg)) break;
        // A new issuance is a new share window: nothing queued for the old one can be rebound.
        shareQueue.length = 0;
        reportedNonces.length = 0;
        outstandingShare = null;
        outstandingAccepted = false;
        searchSettledAwaitingServer = false;
        shareMode = msg.job.shareWork === true;
        shareTargetBytes = shareMode ? hexToBytes(msg.job.shareTargetHexLE) : null;
        stats.realShareMode = shareMode;
        stats.realSharesReported = 0;
        stats.realShareQueueDepth = 0;
        stats.realSearchSettled = false;
        stats.realShareStopCause = null;
        stats.realSharesFound = null;
        serverRun = {
          clientStartId: msg.clientStartId,
          workerId: msg.workerId,
          jobId: msg.jobId,
          issuanceId: msg.issuanceId,
          runGeneration: msg.runGeneration,
        };
        realJob = msg.job;
        windowIndex = msg.windowIndex;
        browserReport = 'unreported';
        // THE OLD CONTEXT IS RETIRING FROM THIS INSTANT, not from the moment it settles.
        //
        // serverRun and realJob now name the NEW window, but the Worker still holds the OLD one: its
        // job id is still `searchJobId`. Without this the fence read "the job the Worker searches" as
        // CURRENT, so an old window's `share` or `progress` arriving in that gap was applied against
        // the new server job -- validated against the new issuance and the new nonce range, and
        // failing there it stopped a perfectly good session. Marking it retiring lets through
        // exactly one thing: its own first `finished`, which settles the OLD context and nothing else.
        if (searchJobId !== null && settledSearchJobId !== searchJobId) retiringSearchJobId = searchJobId;
        // THE PAGE IS NOT SEARCHING THE NEW WINDOW YET. The server has issued it; the Worker still
        // has to settle the old context and be re-contextualised, and nothing is hashed until its
        // rotated readiness arrives. `realWindowIndex` is what the SERVER issued; the ACTIVE window
        // stays what it was until that readiness.
        windowHandoff = true;
        stats.realWindowHandoff = true;
        // True while the retired window's own search has not settled yet: its hashing may still be
        // finishing, so the page must say the previous window is retiring and that no NEW-window
        // hashing has begun -- never that nothing at all is hashing.
        stats.realWindowRetiring = searchJobId !== null && settledSearchJobId !== searchJobId;
        stats.realWindowIndex = windowIndex;
        stats.realWindowRefreshes += 1;
        stats.serverRunGeneration = msg.runGeneration;
        stats.jobId = msg.job.jobId;
        stats.simNonce = msg.job.nonceStart;
        stats.realFoundNonce = null;
        stats.simBrowserEvidence = null;
        stats.simBrowserHashHexLE = null;
        stats.simVerifiedHashHexLE = null;
        stats.realSearch = null;
        // THE SAME WORKER, re-contextualised -- and only once its previous search and every report
        // for the old window have settled. maybeRecontext() is what enforces that; nothing here
        // creates a second Worker or a second context.
        pendingRotation = runIntent && worker
          ? { targetJobId: realJob.jobId, ready: false, posted: false }
          : null;
        emit();
        break;
      }
      case 'candidate_settled': {
        // THE PACING CUE, AND THE ONLY THING THAT RELEASES THE NEXT REPORT. The server emits it
        // after the candidate has fully settled and its verification slot is free again;
        // `share_accepted` is emitted earlier, while the slot is still held, so releasing on that
        // would earn `queue_full` every time. A cue for anything but our one outstanding nonce is
        // ignored, and a terminal message always supersedes it.
        if (!shareMode || simTerminal || !isWellFormedBinding(msg) || !matchesActiveRun(msg)) break;
        if (outstandingShare === null || msg.nonce !== outstandingShare.nonce) break;
        outstandingShare = null;
        outstandingAccepted = false;
        releaseNextShare();
        emit();
        break;
      }
      case 'mock_verification_complete':
        if (simTerminal || !isWellFormedBinding(msg) || !matchesActiveRun(msg)) break;
        stats.simVerifiedHashHexLE = msg.hashHexLE ?? null;
        emit();
        break;
      case 'mock_submit_path_exercised':
        if (simTerminal || !isWellFormedBinding(msg) || !matchesActiveRun(msg)) break;
        stats.simMockSubmitExercised = true;
        emit();
        break;
      case 'candidate_rejected': {
        if (!oneAttempt()) break;
        if (simTerminal || !isWellFormedBinding(msg) || !matchesActiveRun(msg)) break;
        // NOT TERMINAL BY ITSELF. A cheap refusal of a forged or mismatched candidate leaves the
        // real attempt untouched on the server, and the page must not end it either. Whether the
        // attempt is over is decided ONLY by an explicit terminal message: simulation_failed,
        // simulation_complete, an accepted simulation_stopped, or simulation_unavailable.
        stats.rejected++;
        stats.lastRejectReason = simFailureCode(msg.reason);
        emit();
        break;
      }
      case 'simulation_complete':
        // AN UNSOLICITED COMPLETION CHANGES NOTHING. It used to be accepted while idle, setting the
        // completion flag and importing whatever counters it carried.
        if (simTerminal || !isWellFormedBinding(msg) || !matchesActiveRun(msg)) break;
        simTerminal = true;
        stats.simComplete = true;
        stats.simFinished = true;
        stats.simProcessSpent = true;
        stats.simCounters = msg.counters ?? null;
        if (mode === REAL_MODE) {
          // THE ACCEPTED BLOCK, as the server's canonical readback established it. The browser matched
          // only if its own validated found nonce and hash are the accepted ones and the server's
          // three-way recomputation agrees.
          stats.realOutcome = 'block_accepted';
          stats.realBlockId = HASH64_RE.test(msg.blockId ?? '') ? msg.blockId : null;
          stats.realBlockHeight = typeof msg.height === 'string' && /^[0-9]{1,20}$/.test(msg.height) ? msg.height : null;
          stats.realConfirmedBy = typeof msg.confirmedBy === 'string' && /^[a-z_]{1,80}$/.test(msg.confirmedBy)
            ? msg.confirmedBy : null;
          stats.simExpectedHashHexLE = HASH64_RE.test(msg.hashHexLE ?? '') ? msg.hashHexLE : null;
          stats.simBrowserMatched = stats.simBrowserEvidence === 'reported'
            && stats.realFoundNonce !== null && msg.nonce === stats.realFoundNonce
            && stats.simExpectedHashHexLE !== null
            && stats.simBrowserHashHexLE === stats.simExpectedHashHexLE
            && stats.simVerifiedHashHexLE === stats.simExpectedHashHexLE;
          if (sequenceTotal > 1) {
            // THE WHOLE SEQUENCE: every block accepted, the last one this terminal message, and this
            // browser's own validated result matching for each.
            const lastBlock = stats.realBlocks.at(-1);
            stats.realSequenceComplete = stats.realBlocks.length === sequenceTotal
              && lastBlock?.blockId === stats.realBlockId && lastBlock?.nonce === msg.nonce;
            stats.simBrowserMatched = stats.realSequenceComplete && stats.realBlocks.every((b) => b.browserMatched);
            // Include every context this browser actually searched, including a context retired by
            // an external canonical tip. The accepted-block list intentionally omits such a block,
            // so summing that list would under-report the browser's work.
            stats.realTotalAttempts = completedSearchAttemptsExact && settledSearchJobId === searchJobId
              ? completedSearchAttempts
              : null;
          }
        } else {
          stats.simExpectedHashHexLE = msg.recordedVector?.expectedHashHexLE ?? null;
          // BROWSER AGREEMENT IS ESTABLISHED LOCALLY OR NOT AT ALL. The server's completion proves the
          // server-side paths; it says nothing about what this browser computed. The page may say the
          // browser matched only if its own validated hash, its single count, the server's recomputed
          // hash and the recorded expected hash are all the same value.
          stats.simBrowserMatched = stats.simBrowserEvidence === 'reported'
            && stats.hashes === 1
            && HASH64_RE.test(stats.simExpectedHashHexLE ?? '')
            && stats.simBrowserHashHexLE === stats.simExpectedHashHexLE
            && stats.simVerifiedHashHexLE === stats.simExpectedHashHexLE;
        }
        stop(STOP_REASONS.USER);
        break;
      case 'simulation_failed':
        if (simTerminal || !isWellFormedBinding(msg) || !matchesActiveRun(msg)) break;
        // FINISHED, NOT SUCCEEDED. This used to set simComplete, so a failure rendered the success
        // summary while state said stopped and error said nothing at all.
        simTerminal = true;
        stats.simFinished = true;
        stats.simProcessSpent = true;
        stats.simFailureCode = simFailureCode(msg.reason);
        stats.lastRejectReason = stats.simFailureCode;
        if (mode === REAL_MODE && twoSlotCompetition
          && stats.simFailureCode === 'submission_already_claimed') {
          // The other browser claimed the only permitted submission. This browser mined no block,
          // but the contest ended normally; do not report its expected loss as a verifier failure.
          stats.realOutcome = 'other_browser_won';
          finalizeRealAttemptCount();
          stop(STOP_REASONS.OTHER_BROWSER_WON);
          break;
        }
        if (mode === REAL_MODE) stats.realOutcome = 'failed';
        stats.error = mode === REAL_MODE
          ? `the block run did not succeed: ${stats.simFailureCode}`
          : `the simulation failed: ${stats.simFailureCode}`;
        stop(STOP_REASONS.ERROR);
        break;
      case 'mining_unavailable': {
        // Two distinct situations share this message, and telling a person the wrong one is worse
        // than saying nothing: either the pool could not bring a verifier up at all (no Worker was
        // ever created), or it was verifying fine and then its two builds stopped agreeing while
        // this page was mining. The second case is why this stops a LIVE worker rather than only
        // clearing a pending start: continuing to hash for a pool that can no longer prove a
        // result would burn a CPU core for nothing.
        const wasMining = !pendingStart && runIntent;
        pendingStart = false;
        const detail = String(msg.detail ?? msg.reason ?? 'unknown').slice(0, 240);
        stats.error = wasMining
          ? `the local pool stopped verifying and this run was halted: ${detail}`
          : `the local pool could not start its verifier: ${detail}`;
        stop(STOP_REASONS.ERROR);
        break;
      }
      case 'share_accepted':
        if (shareMode) {
          // THE OPT-IN REAL-MODE ACCEPTANCE OF ONE VERIFIED SHARE. It counts only when it names
          // this active run AND the exact nonce and hash this browser computed for it. It is NOT a
          // block: a block is announced by the existing block_accepted path, on server evidence.
          if (simTerminal || !isWellFormedBinding(msg) || !matchesActiveRun(msg)) break;
          const mine = outstandingShare;
          if (mine === null || msg.nonce !== mine.nonce || msg.hashHexLE !== mine.hashHexLE) break;
          // A REPLAY OF THE SAME FRAME IS NOT A SECOND SHARE. The latch is per OUTSTANDING report,
          // so a genuinely different share -- a different nonce, released by its own cue -- still
          // counts; only a repeat of the one already counted is ignored.
          if (outstandingAccepted) break;
          outstandingAccepted = true;
          stats.realSharesAccepted += 1;
          stats.simVerifiedHashHexLE = msg.hashHexLE;
          emit();
          break;
        }
        stats.accepted++;
        stats.lastAcceptedNonceHex = msg.nonce ?? null;
        emit();
        break;
      case 'demo_complete':
        // Terminal by design: the shared synthetic demonstration is over. `won` distinguishes
        // "this page found the share" from "another connection on this machine finished the run
        // we were both working on"; either way this page stops and needs another explicit Start.
        stats.demoComplete = true;
        stats.demoWon = msg.won !== false;
        stats.lastAcceptedNonceHex = msg.nonce ?? stats.lastAcceptedNonceHex;
        stop(STOP_REASONS.COMPLETE);
        break;
      case 'share_rejected':
        stats.rejected++;
        stats.lastRejectReason = msg.reason ?? 'unknown';
        emit();
        break;
      case 'error':
        stats.lastRejectReason = msg.reason ?? 'error';
        // A ONE-AT-A-TIME CLIENT MUST NEVER SEE `queue_full`. If it does, this page and the server
        // disagree about what is outstanding, and the honest response is to fail closed -- not to
        // retry on a timer, which is exactly the behaviour the server's serial fence exists to
        // prevent.
        if (shareMode && msg.reason === 'queue_full' && runIntent && !simTerminal) {
          stats.error = 'the local pool was already verifying another result for this template';
          stop(STOP_REASONS.ERROR);
          break;
        }
        emit();
        break;
      default:
        break;
    }
  }

  // ---------------------------------------------------------------- mining

  /** Called ONLY from an explicit Start click. */
  function start(options = {}) {
    const pacingMs = options && typeof options === 'object' && !Array.isArray(options)
      ? (options.pacingMs ?? 0) : null;
    if (pacingMs !== 0 && pacingMs !== 100) return false;
    if (runIntent) return false; // repeated clicks must not create a second worker
    if (!serverProtocolValid) return false;
    // FAIL CLOSED IN CODE, NOT ONLY IN THE BUTTON. A spent server process has made its one attempt;
    // a programmatic second start() must change nothing -- no generation, no state, no message and
    // no Worker -- whatever the page's disabled button says.
    if (oneAttempt() && stats.simProcessSpent) return false;
    // The legacy real-mode contract requires the job before Start. Only an explicit, valid
    // server_hello capability may defer that job until after the correlated Start request.
    if (mode === REAL_MODE && realJob === null && !realJobIssuedOnStart) {
      setState(STATES.ERROR, { error: 'no real job from the local pool yet' });
      return false;
    }
    if (!oneAttempt() && !currentJob) {
      setState(STATES.ERROR, { error: 'no job from the local pool yet' });
      return false;
    }
    if (stats.connection !== 'connected') {
      setState(STATES.ERROR, { error: 'not connected to the local pool' });
      return false;
    }
    runIntent = true;
    searchPacingMs = pacingMs;
    pendingStart = true;
    simTerminal = false;
    browserReport = 'unreported';
    generation++;
    hashesBefore = 0;
    hashesThisRun = 0;
    awaitingWork = false;
    dispatchedJobId = null;
    runStartedAt = now();
    stats.hashes = 0;
    stats.hashesPerSecond = 0;
    stats.error = null;
    stats.stopReason = null;
    stats.demoComplete = false;
    stats.demoWon = false;
    setState(STATES.STARTING);

    serverRun = null;
    blockIndex = 1;
    acceptedCurrentBlock = false;
    searchJobId = null;
    searchBlockIndex = 1;
    settledSearchJobId = null;
    retiringSearchJobId = null;
    completedSearchAttempts = 0;
    completedSearchAttemptsExact = true;
    blockSearchAttempts = Array(REAL_SEQUENCE_DEV_MAX_BLOCKS).fill(0);
    blockSearchAttemptsExact = Array(REAL_SEQUENCE_DEV_MAX_BLOCKS).fill(true);
    pendingRotation = null;
    stats.realBlockIndex = 1;
    stats.realBlocks = [];
    stats.realTotalAttempts = 0;
    stats.realWorkerContexts = [];
    stats.realStaleWorkerMessages = 0;
    stats.realExternalSupersessions = 0;
    // RE-DERIVED FROM THE SERVER'S CURRENT JOB, never simply cleared: the job arrived before this
    // Start, and clearing the mode here would issue a legacy window for a share job.
    shareMode = mode === REAL_MODE && realJob?.shareWork === true && shareTargetUsable(realJob);
    shareTargetBytes = shareMode ? hexToBytes(realJob.shareTargetHexLE) : null;
    shareQueue.length = 0;
    reportedNonces.length = 0;
    outstandingShare = null;
    outstandingAccepted = false;
    searchSettledAwaitingServer = false;
    activeWindowIndex = windowIndex;
    activeBlockIndex = blockIndex;
    activeRealJob = null;
    windowHandoff = false;
    stats.realActiveWindowIndex = activeWindowIndex;
    stats.realActiveBlockIndex = activeBlockIndex;
    stats.realWindowHandoff = false;
    stats.realWindowRetiring = false;
    stats.realShareMode = shareMode;
    stats.realSharesReported = 0;
    stats.realSharesAccepted = 0;
    stats.realShareQueueDepth = 0;
    stats.realSearchSettled = false;
    // A NEW CORRELATION TOKEN, AND NOTHING IS FORGIVEN. Attempts the user abandoned keep their own
    // entries in `abandonedStarts`; clicking Start again cannot clear them, so a delayed
    // acknowledgement for one of them can never be mistaken for an acknowledgement of this one.
    pendingStartId = oneAttempt() ? newStartId() : null;
    stats.clientStartId = pendingStartId;
    // NO Worker yet. Ask the local server to bring its verifier up first, so neither side has
    // loaded MeepHash-W until a human asked for it.
    const request = pendingStartId === null
      ? { type: 'start_request' }
      : { type: 'start_request', clientStartId: pendingStartId };
    if (!send(request)) return false;
    return true;
  }

  function sameBinding(a, b) {
    return a.clientStartId === b.clientStartId && a.workerId === b.workerId && a.jobId === b.jobId
      && a.issuanceId === b.issuanceId && a.runGeneration === b.runGeneration;
  }

  /**
   * A pre-run refusal, checked against its OWN closed schema: the correlation token of the attempt
   * we are waiting on, a run generation that is exactly null, and a closed reason and attempt state.
   * Legacy/pre-issued work must repeat the server's job and issuance. Delayed work has no job yet,
   * so only a closed delayed-assignment refusal may carry an exactly-null job identity. Nothing else
   * about the message is trusted.
   */
  function isPreRunRefusal(msg) {
    const delayedAssignmentReason = msg.reason === 'pool_capacity'
      || msg.reason === 'reservation_history_full'
      || msg.reason === 'owner_already_reserved'
      || msg.reason === 'reservation_terminal'
      || msg.reason === 'reservation_start_mismatch'
      || msg.reason === 'run_intent_revoked'
      || msg.reason === 'two_slot_round_closed'
      || msg.reason === 'personalized_issue_failed'
      || msg.reason === 'personalized_issue_cancelled'
      || msg.reason === 'personalized_publication_refused'
      || msg.reason === 'personalized_issue_tip_changed'
      || msg.reason === 'canonical_submission_claimed'
      || msg.reason === 'assignment_setup_failed';
    const delayedWithoutJob = mode === REAL_MODE && realJobIssuedOnStart && realJob === null;
    if (msg.terminal !== true) return false;
    if (delayedAssignmentReason && !delayedWithoutJob) return false;
    const identityMatches = delayedWithoutJob
      ? msg.jobId === null && msg.issuanceId === null
        && delayedAssignmentReason && msg.attemptState === 'idle'
      : realJob !== null
        && msg.jobId === realJob.jobId && msg.issuanceId === realJob.issuanceId;
    return pendingStart
      && serverRun === null
      && typeof pendingStartId === 'string'
      && msg.clientStartId === pendingStartId
      && msg.runGeneration === null
      && msg.workerId === helloWorkerId
      && identityMatches
      && SIM_PRE_RUN_REFUSALS.includes(msg.reason)
      && SIM_ATTEMPT_STATE_VALUES.includes(msg.attemptState);
  }

  /** Does this message name the acknowledged attempt, in every one of its five fields? */
  function matchesActiveRun(msg) {
    return serverRun !== null
      && msg.clientStartId === serverRun.clientStartId
      && msg.workerId === serverRun.workerId
      && msg.jobId === serverRun.jobId
      && msg.issuanceId === serverRun.issuanceId
      && msg.runGeneration === serverRun.runGeneration;
  }

  /** The block after the current one, as the public projection a sequence_next must carry. */
  function isNextRealJob(job, msg) {
    if (!job || job.type !== 'real_job' || !realJob) return false;
    let nextHeight;
    try { nextHeight = (BigInt(realJob.height) + 1n).toString(); } catch { return false; }
    return job.jobId === msg.jobId && job.issuanceId === msg.issuanceId
      && job.algorithm === realJob.algorithm && job.height === nextHeight
      && (job.shareWork === true) === (realJob.shareWork === true)
      && (job.shareWork !== true || shareTargetUsable(job))
      && HASH64_RE.test(job.epochKeyHex ?? '') && HASH64_RE.test(job.seedHashHex ?? '')
      && HASH64_RE.test(job.targetHexLE ?? '')
      && typeof job.hashingTemplateHex === 'string' && /^(?:[0-9a-f]{2}){1,1048576}$/.test(job.hashingTemplateHex)
      && isExactUint32(job.nonceStart) && Number.isSafeInteger(job.nonceRange) && job.nonceRange >= 1
      && job.nonceStart + job.nonceRange <= 0x100000000
      // A composed next block explicitly resets to window 1, whose builder starts at nonce zero.
      // Do not accept the coordinate reset with a carried-over later-window range.
      && (windowTotal <= 1 || (job.nonceStart === 0 && job.nonceRange <= REAL_SEARCH_LIMITS.maxAttempts))
      && typeof job.contentDigest === 'string' && job.contentDigest !== realJob.contentDigest;
  }

  /**
   * A SAME-HEIGHT REFRESH JOB. Everything the next-height check wants EXCEPT the two things that
   * make a refresh a refresh: the height does NOT advance, and the content digest may be identical,
   * because the template bytes can legitimately be the same. What must differ is the capability --
   * job id, issuance -- and the nonce window, which must start at or after the end of the window it
   * replaces, so no nonce this page already searched is ever issued to it again.
   */
  function isRefreshRealJob(job, msg) {
    if (!job || job.type !== 'real_job' || !realJob) return false;
    const previousEnd = realJob.nonceStart + realJob.nonceRange;
    return job.jobId === msg.jobId && job.issuanceId === msg.issuanceId
      && job.algorithm === realJob.algorithm && job.height === realJob.height
      && job.jobId !== realJob.jobId && job.issuanceId !== realJob.issuanceId
      && (job.shareWork === true) === (realJob.shareWork === true)
      && (job.shareWork !== true || shareTargetUsable(job))
      && HASH64_RE.test(job.epochKeyHex ?? '') && HASH64_RE.test(job.seedHashHex ?? '')
      && HASH64_RE.test(job.targetHexLE ?? '')
      && typeof job.hashingTemplateHex === 'string' && /^(?:[0-9a-f]{2}){1,1048576}$/.test(job.hashingTemplateHex)
      && isExactUint32(job.nonceStart) && Number.isSafeInteger(job.nonceRange) && job.nonceRange >= 1
      && isExactUint32(previousEnd) && job.nonceStart >= previousEnd
      && job.nonceStart + job.nonceRange <= 0x100000000;
  }

  function totalAttempts() {
    if (!completedSearchAttemptsExact) return null;
    return completedSearchAttempts + (settledSearchJobId === searchJobId ? 0 : stats.hashes);
  }

  function recordBlockAttempts(index, hashes) {
    const offset = index - 1;
    if (!Number.isSafeInteger(offset) || offset < 0 || offset >= blockSearchAttempts.length) return;
    if (hashes === null) blockSearchAttemptsExact[offset] = false;
    else blockSearchAttempts[offset] += hashes;
  }

  function attemptsForBlock(index) {
    const offset = index - 1;
    if (!Number.isSafeInteger(offset) || offset < 0 || offset >= blockSearchAttempts.length
      || !blockSearchAttemptsExact[offset]) return null;
    return blockSearchAttempts[offset];
  }

  /**
   * Freeze only an EXACT terminal attempt count. Progress is a lower bound: termination can race
   * with more Worker hashes, and terminate() deliberately prevents a later `finished` message from
   * repairing the number. Settled contexts remain exact, including a context retired by an external
   * tip; an actually-started current context without its one `finished` event makes the aggregate
   * explicitly unknown.
   */
  function finalizeRealAttemptCount() {
    if (mode !== REAL_MODE) return;
    stats.realTotalAttempts = completedSearchAttemptsExact
      && (searchJobId === null || settledSearchJobId === searchJobId)
      ? completedSearchAttempts
      : null;
  }

  /**
   * ARE THIS READINESS'S WINDOW FACTS THE ONES THIS PAGE WAS OFFERED?
   *
   * Three closed answers, and everything else is a fault:
   *   * an opt-in refresh run (windowTotal > 1 declared before Start) must carry the SAME total,
   *     exactly the window the server has just issued, and the EXACT session budget that was
   *     advertised -- an omitted budget is not a match, because the page would be unable to say
   *     which budget the run is actually bounded by;
   *   * a run that was never offered windows must carry no window fields at all -- unsolicited ones
   *     mean the server and the page disagree about what this Start is;
   *   * a sequence never carries window fields either, because a window is not a block.
   */
  function readyWindowFactsOk(msg) {
    const carries = msg.windowTotal !== undefined || msg.windowIndex !== undefined
      || msg.sessionBudgetMs !== undefined;
    if (windowTotal <= 1) return !carries;
    if (!carries) return false;
    return msg.windowTotal === windowTotal
      && msg.windowIndex === windowIndex
      && msg.sessionBudgetMs === REAL_REFRESH_LIMITS.maxSessionMs;
  }

  /** The Worker's latched per-block window total, in addition to the independently sent block total. */
  function contextLimitField() {
    return windowTotal > 1 ? { contextLimit: windowTotal } : {};
  }

  /** The exact two-dimensional context coordinate the Worker must enforce for composed runs. */
  function contextCoordinateFields() {
    return { sequenceIndex: blockIndex, windowIndex };
  }

  /** The Worker window and server context for the CURRENT realJob. */
  function searchWindowFor(job) {
    return {
      window: {
        nonceStart: job.nonceStart,
        nonceRange: Math.min(job.nonceRange, REAL_SEARCH_LIMITS.maxAttempts),
        targetHexLE: job.targetHexLE,
        maxSearchMs: REAL_SEARCH_LIMITS.maxSearchMs,
        // OPT-IN ONLY, and only after shareTargetUsable() proved the server's share target is not
        // harder than its block target. Absent otherwise, which is the legacy window exactly.
        ...(shareMode ? {
          shareTargetHexLE: job.shareTargetHexLE,
          maxShares: REAL_SHARE_LIMITS.maxSharesPerJob,
        } : {}),
      },
      context: {
        epochKeyHex: job.epochKeyHex,
        seedHashHex: job.seedHashHex,
        height: job.height,
        hashingTemplateHex: job.hashingTemplateHex,
      },
    };
  }

  /**
   * RE-CONTEXTUALISE THE SAME WORKER, once every condition holds at the same moment: the server's next
   * run is ready, the Worker's previous search has settled, run intent is live and nothing is terminal.
   */
  function maybeRecontext() {
    if (pendingRotation === null || pendingRotation.posted || !pendingRotation.ready) return;
    if (!runIntent || !worker || simTerminal || settledSearchJobId !== searchJobId || !realJob) return;
    if (pendingRotation.targetJobId !== realJob.jobId) return;
    const prevJobId = searchJobId;
    searchJobId = realJob.jobId;
    searchBlockIndex = blockIndex;
    retiringSearchJobId = null;
    pendingRotation.posted = true;
    stats.hashes = 0;
    worker.postMessage({
      cmd: 'init_search_next', gen: generation, prevJobId, jobId: realJob.jobId,
      sequenceTotal, ...contextLimitField(), ...contextCoordinateFields(), ...searchWindowFor(realJob),
    });
  }

  /**
   * Send ONE fully bound stop, if the server has told us what to bind it to.
   *
   * Returns false when there is no binding yet -- the caller then records a pending cancellation
   * and sends this when the acknowledgement arrives.
   */
  // The controller's own stop vocabulary is richer than the protocol's closed set, so it is mapped
  // rather than sent raw -- an unmapped reason would be refused as a schema error and the server
  // would learn nothing, which is the exact failure this path exists to prevent.
  const WIRE_STOP_REASON = {
    [STOP_REASONS.USER]: 'user_stop',
    [STOP_REASONS.COMPLETE]: 'user_stop',
    [STOP_REASONS.ERROR]: 'user_stop',
    [STOP_REASONS.HIDDEN]: 'page_hidden',
    [STOP_REASONS.PAGEHIDE]: 'page_unload',
    [STOP_REASONS.DISCONNECTED]: 'socket_close',
    [STOP_REASONS.SOCKET_ERROR]: 'socket_close',
    [STOP_REASONS.SEND_FAILED]: 'socket_close',
    [STOP_REASONS.BOUNDED_NO_SOLUTION]: 'search_bound_reached',
    [STOP_REASONS.OTHER_BROWSER_WON]: 'user_stop',
  };

  function sendBoundStop(reason) {
    if (!oneAttempt() || !serverRun) return false;
    return sendStopFor(serverRun, reason);
  }

  /**
   * Send ONE stop for an EXPLICIT binding, which may belong to an attempt this controller is no
   * longer running. That is the whole point: a late acknowledgement for an abandoned attempt is
   * answered on its own terms, and never on the current attempt's.
   */
  function sendStopFor(bindingSource, reason) {
    return send({
      type: 'stop_request',
      clientStartId: bindingSource.clientStartId,
      workerId: bindingSource.workerId,
      runGeneration: bindingSource.runGeneration,
      jobId: bindingSource.jobId,
      issuanceId: bindingSource.issuanceId,
      reason: WIRE_STOP_REASON[reason] ?? 'user_stop',
    });
  }

  /** Construct the one Worker. Reached only from a mining_ready that matches live run intent. */
  function spawnWorker() {
    if (!runIntent || worker) return;
    workersCreated++;
    worker = createWorker();
    const myGen = generation;
    worker.onmessage = (event) => onWorkerMessage(myGen, event.data);
    worker.onerror = (err) => {
      if (myGen !== generation || !runIntent) return;
      stats.error = err && err.message ? err.message : 'worker error';
      stop(STOP_REASONS.ERROR);
    };
    if (mode === REAL_MODE && realJob) {
      // THE FRESH SERVER-OWNED CONTEXT AND THE ISSUED WINDOW. No nonce is supplied: the Worker
      // searches, and caps the window and time at the frozen bounds whatever this says.
      stats.realWorkersCreated = workersCreated;
      searchJobId = realJob.jobId;
      searchBlockIndex = blockIndex;
      worker.postMessage({
        cmd: 'init_search',
        gen: myGen,
        pacingMs: searchPacingMs,
        jobId: realJob.jobId,
        sequenceTotal,
        // ONE LATCHED CONTEXT BUDGET. In a same-height refresh run the Worker may build one context
        // per WINDOW; the sequence still declares blocks. Sent explicitly so the Worker never has to
        // infer which feature is running.
        ...contextLimitField(),
        ...contextCoordinateFields(),
        ...searchWindowFor(realJob),
      });
    } else if (mode === SIM_MODE && realJob) {
      worker.postMessage({
        cmd: 'init_context',
        gen: myGen,
        // The Worker arms its own one-hash permit against this job id AND this exact nonce, so a
        // command naming a different job or nonce performs zero hashes even if the page asks. The
        // nonce is the server's, from real_job, passed through unconverted.
        jobId: realJob.jobId,
        nonce: realJob.nonceStart,
        context: {
          epochKeyHex: realJob.epochKeyHex,
          seedHashHex: realJob.seedHashHex,
          height: realJob.height,
          hashingTemplateHex: realJob.hashingTemplateHex,
        },
      });
    } else {
      worker.postMessage({ cmd: 'init', gen: myGen });
    }
  }

  function onWorkerMessage(msgGen, msg) {
    // Messages already queued when the worker was abandoned are dropped, not acted on.
    if (msgGen !== generation || !runIntent || !msg) return;

    // THE HANDOVER STALE-MESSAGE FENCE. A message about any job other than the one the Worker's
    // current context searches changes nothing -- except the `finished` that settles that very
    // search, which is allowed through exactly once so the old context can settle.
    //
    // IT APPLIES TO EVERY SESSION THAT HANDS WORK OVER, not only to a block sequence. A same-height
    // refresh replaces the job and the run generation with sequenceTotal still 1, so fencing on the
    // sequence alone let an old window's `share`, `progress` or repeated `finished` be read against
    // the NEW window: a stale share would be validated against the new issuance and, failing, would
    // stop a perfectly good session.
    const handsOverWork = sequenceTotal > 1 || windowTotal > 1;
    const jobBoundWorkerEvent = msg.ev === 'ready' || msg.ev === 'progress'
      || msg.ev === 'found' || msg.ev === 'share' || msg.ev === 'finished';
    if (mode === REAL_MODE && handsOverWork && jobBoundWorkerEvent
      && typeof msg.jobId !== 'string') {
      stats.realStaleWorkerMessages += 1;
      emit();
      return;
    }
    if (mode === REAL_MODE && handsOverWork && typeof msg.jobId === 'string') {
      const current = msg.jobId === searchJobId;
      const settles = current && msg.ev === 'finished' && settledSearchJobId !== msg.jobId;
      if (!current || (retiringSearchJobId === msg.jobId && !settles)
        || (msg.ev === 'finished' && !settles)) {
        stats.realStaleWorkerMessages += 1;
        emit();
        return;
      }
    }

    switch (msg.ev) {
      case 'ready':
        if (mode === REAL_MODE && (sequenceTotal > 1 || windowTotal > 1)) {
          if (msg.rotated === true && (pendingRotation === null || !pendingRotation.posted)) break;
          if (msg.rotated === true) pendingRotation = null;
          stats.realWorkerContexts = [...stats.realWorkerContexts, Object.freeze({
            jobId: typeof msg.jobId === 'string' ? msg.jobId : null,
            contextIndex: Number.isSafeInteger(msg.contextIndex) ? msg.contextIndex : null,
            moduleInstances: Number.isSafeInteger(msg.moduleInstances) ? msg.moduleInstances : null,
            rotated: msg.rotated === true,
            priorContextFreed: msg.priorContextFreed === true,
            priorContextActive: typeof msg.priorContextActive === 'boolean' ? msg.priorContextActive : null,
            wasmHeapBytes: Number.isSafeInteger(msg.wasmHeapBytes) ? msg.wasmHeapBytes : null,
          })];
        }
        // THE WORKER IS NOW LIVE ON THIS JOB. Only here does the page move either active coordinate
        // to the server-issued pair: before this readiness the new context did not exist.
        if (mode === REAL_MODE && realJob && msg.jobId === realJob.jobId) {
          activeBlockIndex = blockIndex;
          activeWindowIndex = windowIndex;
          activeRealJob = realJob;
          windowHandoff = false;
          stats.realActiveBlockIndex = activeBlockIndex;
          stats.realActiveWindowIndex = activeWindowIndex;
          stats.realWindowHandoff = false;
          stats.realWindowRetiring = false;
        }
        stats.wasmHeapBytes = msg.wasmHeapBytes ?? null;
        setState(STATES.MINING);
        if (mode === REAL_MODE) dispatchSearch(msgGen);
        else if (mode === SIM_MODE) dispatchOneHash(msgGen);
        else dispatchWork(msgGen);
        break;
      case 'hashed_one': {
        // The browser's own result is NOT sent. The server recomputes it from its own context, so
        // shipping it would add nothing but a forgery surface.
        if (mode !== SIM_MODE) break;
        if (simTerminal || !serverRun || !realJob) break;
        // A SECOND REPORT IS NOT EVIDENCE, IT IS A FAULT. Nothing more is recorded or sent; the run
        // ends through the ordinary error stop, and the browser-agreement claim is withdrawn.
        if (browserReport !== 'unreported') {
          browserReport = 'invalid';
          stats.simBrowserEvidence = 'invalid';
          stats.error = 'the browser worker reported more than one result';
          stop(STOP_REASONS.ERROR);
          break;
        }
        // THE LOCAL EVIDENCE MUST DESCRIBE THE AUTHORIZED WORK before it is recorded, shown, or used
        // to ask the server anything: the active job, the exact authorized nonce, and a well-formed
        // 32-byte hash. A Worker reporting anything else is not evidence the browser did this work.
        const authorizedNonce = realJob.nonceStart;
        const evidenceOk = msg.jobId === serverRun.jobId
          && msg.nonce === authorizedNonce
          && msg.nonceHex === nonceHexOf(authorizedNonce)
          && typeof msg.hashHexLE === 'string' && HASH64_RE.test(msg.hashHexLE);
        if (!evidenceOk) {
          browserReport = 'invalid';
          stats.simBrowserEvidence = 'invalid';
          stats.error = 'the browser worker reported a result for work it was not given';
          stop(STOP_REASONS.ERROR);
          break;
        }
        browserReport = 'reported';
        stats.hashes = 1;
        stats.simBrowserEvidence = 'reported';
        stats.simBrowserHashHexLE = msg.hashHexLE;
        stats.simBrowserHashMs = Number.isFinite(msg.elapsedMs) ? msg.elapsedMs : null;
        send({
          type: 'submit_real_candidate',
          clientStartId: serverRun.clientStartId,
          jobId: serverRun.jobId,
          issuanceId: serverRun.issuanceId,
          workerId: serverRun.workerId,
          runGeneration: serverRun.runGeneration,
          // The AUTHORIZED nonce, never the Worker's own field.
          nonce: nonceHexOf(authorizedNonce),
        });
        emit();
        break;
      }
      case 'command_refused':
        // The Worker's own dispatcher refused a command. It performed no hash; nothing to record
        // beyond a bounded reason, and nothing here may retry.
        stats.lastRejectReason = `worker_${String(msg.reason ?? 'refused').replace(/[^a-z_]/g, '').slice(0, 32)}`;
        if (mode === REAL_MODE
          && ['init_search', 'search', 'init_search_next', 'supersede_search'].includes(msg.cmd)) {
          // Every one of these commands is a capability step the real-mode controller itself issued.
          // Refusal means the page and server can no longer complete the bound run. End immediately;
          // never leave a Worker/verifier live until the server backstop, and never retry behind the
          // user's back.
          stats.error = 'the browser worker could not start or continue the issued search';
          stop(STOP_REASONS.ERROR);
          break;
        }
        emit();
        break;
      case 'progress': {
        hashesThisRun = hashesBefore + msg.hashes;
        stats.hashes = hashesThisRun;
        if (mode === REAL_MODE) stats.realTotalAttempts = totalAttempts();
        const elapsed = Math.max(1, now() - runStartedAt);
        stats.hashesPerSecond = (hashesThisRun * 1000) / elapsed;
        emit();
        break;
      }
      case 'share':
        // OPT-IN ONLY. A `share` event from a Worker that was never given a share window is a fault.
        if (mode === REAL_MODE && shareMode) {
          onRealShare(msg);
        } else {
          stats.error = 'the browser worker reported a share for a job that has none';
          stop(STOP_REASONS.ERROR);
        }
        break;
      case 'found':
        if (mode === REAL_MODE) {
          if (shareMode) {
            // A SHARE-MODE WORKER REPORTS `share`, NEVER `found`. Letting a legacy event through
            // here would bypass the opt-in queue entirely: it would submit immediately, outside the
            // one-at-a-time discipline the server's serial fence requires.
            stats.error = 'the browser worker reported a single result for a share job';
            stop(STOP_REASONS.ERROR);
            break;
          }
          onRealFound(msg);
          break;
        }
        // Normal operation submits jobId, nonce and workerId ONLY. The hash the worker computed
        // is not sent: the pool recomputes it, so shipping it would add nothing but a forgery
        // surface.
        if (stats.workerId) {
          send({ type: 'submit_share', jobId: msg.jobId, nonce: msg.nonceHex, workerId: stats.workerId });
        }
        break;
      case 'finished':
        if (mode === REAL_MODE) {
          onRealSearchFinished(msg);
          break;
        }
        hashesBefore += msg.hashes;
        hashesThisRun = hashesBefore;
        stats.hashes = hashesBefore;
        if (runIntent) {
          if (currentJob && currentJob.jobId !== dispatchedJobId) {
            dispatchWork(msgGen); // the server issued newer work while this window was running
          } else {
            // Window exhausted and no newer job yet. Wait for the pool instead of rescanning the
            // same nonces, which would only produce shares the server already has.
            awaitingWork = true;
          }
        }
        emit();
        break;
      case 'error':
        stats.error = msg.message ?? 'worker error';
        stop(STOP_REASONS.ERROR);
        break;
      default:
        break;
    }
  }

  /** The real-daemon workload: ONE bounded search of the issued window. */
  function dispatchSearch(myGen) {
    if (!runIntent || !worker || myGen !== generation || !realJob) return;
    dispatchedJobId = realJob.jobId;
    awaitingWork = false;
    worker.postMessage({ cmd: 'search', gen: myGen, jobId: realJob.jobId });
  }

  /** A share target is usable only if it is well formed and NOT harder than the block target. */
  function shareTargetUsable(job) {
    try {
      return typeof job.shareTargetHexLE === 'string' && HASH64_RE.test(job.shareTargetHexLE)
        && typeof job.targetHexLE === 'string' && HASH64_RE.test(job.targetHexLE)
        && targetAtLeastLE(hexToBytes(job.shareTargetHexLE), hexToBytes(job.targetHexLE));
    } catch {
      return false;
    }
  }

  /**
   * ONE REPORTED HIT FROM THE WORKER, in the opt-in share search.
   *
   * It is bound to this run before anything else happens: the active job, the issued window, a
   * well-formed hash that really does meet the SERVER's share target, a nonce this run has not
   * reported before, and no more than the shared cap. Anything else is a fault in our own Worker,
   * not a thing to tolerate, and it ends the run the same way a bad single report always has.
   *
   * Nothing here decides what a hit IS. `block` is the Worker's hint and is not sent; the server
   * recomputes the hash and both comparisons, and only the server's own messages move any counter.
   */
  function onRealShare(msg) {
    if (simTerminal || !serverRun || !realJob || !shareMode) return;
    const lo = realJob.nonceStart;
    const hi = lo + Math.min(realJob.nonceRange, REAL_SEARCH_LIMITS.maxAttempts);
    const n = msg.nonce;
    let meetsShare = false;
    try {
      meetsShare = typeof msg.hashHexLE === 'string' && HASH64_RE.test(msg.hashHexLE)
        && shareTargetBytes !== null
        && meetsTargetLE(hexToBytes(msg.hashHexLE), shareTargetBytes);
    } catch {
      meetsShare = false;
    }
    const ok = msg.jobId === serverRun.jobId
      && isExactUint32(n) && n >= lo && n < hi
      && msg.nonceHex === nonceHexOf(n)
      && meetsShare
      && !reportedNonces.includes(n)
      && reportedNonces.length < REAL_SHARE_LIMITS.maxSharesPerJob;
    if (!ok) {
      stats.error = 'the browser worker reported a result for work it was not given';
      stats.simBrowserEvidence = 'invalid';
      stop(STOP_REASONS.ERROR);
      return;
    }
    // BLOCK QUALITY IS DERIVED HERE, from the validated hash against the SERVER's block target.
    // The Worker's own `block` flag is a pacing hint and is never trusted for evidence: a Worker
    // that lied about it in either direction would otherwise decide what this page claims.
    let isBlock = false;
    try {
      isBlock = meetsTargetLE(hexToBytes(msg.hashHexLE), hexToBytes(realJob.targetHexLE));
    } catch {
      isBlock = false;
    }
    reportedNonces.push(n);
    shareQueue.push(Object.freeze({
      nonce: n, nonceHex: msg.nonceHex, hashHexLE: msg.hashHexLE, block: isBlock,
    }));
    if (isBlock && browserReport === 'unreported') {
      // THE BROWSER-AGREEMENT EVIDENCE FOR A BLOCK, recorded exactly once. Without this a block
      // this page really found was reported with simBrowserMatched false, because the terminal
      // comparison had nothing of ours to compare against. A second block-quality hit cannot
      // overwrite it: the Worker stops at the first one, and a later one would be a fault.
      browserReport = 'reported';
      stats.simBrowserEvidence = 'reported';
      stats.simBrowserHashHexLE = msg.hashHexLE;
      stats.realFoundNonce = n;
    }
    stats.realSharesReported = reportedNonces.length;
    stats.realShareQueueDepth = shareQueue.length;
    releaseNextShare();
    emit();
  }

  /** Send the next queued report, and only ever one at a time. */
  function releaseNextShare() {
    if (!shareMode || outstandingShare !== null || simTerminal || !runIntent || !serverRun) return;
    const next = shareQueue.shift();
    if (next === undefined) return;
    outstandingShare = next;
    outstandingAccepted = false;                 // one acceptance per outstanding report, at most
    stats.realShareQueueDepth = shareQueue.length;
    // The browser hash is NOT sent: the server recomputes it. Only the binding and the nonce go.
    send({
      type: 'submit_real_candidate',
      clientStartId: serverRun.clientStartId,
      jobId: serverRun.jobId,
      issuanceId: serverRun.issuanceId,
      workerId: serverRun.workerId,
      runGeneration: serverRun.runGeneration,
      nonce: next.nonceHex,
    });
  }

  /**
   * The Worker found a nonce. It becomes the ONE candidate only if it names the active job, lies
   * inside the issued window, and its reported hash is well formed and meets the issued target --
   * and only the first such report ever does. The browser hash is never sent: the server recomputes
   * it three ways.
   */
  function onRealFound(msg) {
    if (simTerminal || !serverRun || !realJob) return;
    if (browserReport !== 'unreported') {
      browserReport = 'invalid';
      stats.simBrowserEvidence = 'invalid';
      stats.error = 'the browser worker reported more than one result';
      stop(STOP_REASONS.ERROR);
      return;
    }
    const lo = realJob.nonceStart;
    const hi = lo + Math.min(realJob.nonceRange, REAL_SEARCH_LIMITS.maxAttempts);
    const n = msg.nonce;
    let meets = false;
    try {
      meets = typeof msg.hashHexLE === 'string' && HASH64_RE.test(msg.hashHexLE)
        && typeof realJob.targetHexLE === 'string' && HASH64_RE.test(realJob.targetHexLE)
        && meetsTargetLE(hexToBytes(msg.hashHexLE), hexToBytes(realJob.targetHexLE));
    } catch {
      meets = false;
    }
    const evidenceOk = msg.jobId === serverRun.jobId
      && isExactUint32(n) && n >= lo && n < hi
      && msg.nonceHex === nonceHexOf(n)
      && meets;
    if (!evidenceOk) {
      browserReport = 'invalid';
      stats.simBrowserEvidence = 'invalid';
      stats.error = 'the browser worker reported a result for work it was not given';
      stop(STOP_REASONS.ERROR);
      return;
    }
    browserReport = 'reported';
    stats.simBrowserEvidence = 'reported';
    stats.simBrowserHashHexLE = msg.hashHexLE;
    stats.realFoundNonce = n;
    send({
      type: 'submit_real_candidate',
      clientStartId: serverRun.clientStartId,
      jobId: serverRun.jobId,
      issuanceId: serverRun.issuanceId,
      workerId: serverRun.workerId,
      runGeneration: serverRun.runGeneration,
      nonce: nonceHexOf(n),
    });
    emit();
  }

  /** The one search ended. With no solution inside the frozen bound, the run ends honestly. */
  function onRealSearchFinished(msg) {
    const hashes = Number.isSafeInteger(msg.hashes) && msg.hashes >= 0 ? msg.hashes : null;
    const settledBlockIndex = searchBlockIndex;
    if (msg.jobId === searchJobId && settledSearchJobId !== msg.jobId) {
      if (hashes === null) completedSearchAttemptsExact = false;
      else completedSearchAttempts += hashes;
      recordBlockAttempts(settledBlockIndex, hashes);
    }
    settledSearchJobId = typeof msg.jobId === 'string' ? msg.jobId : settledSearchJobId;
    const forCurrentJob = !realJob || msg.jobId === undefined || msg.jobId === realJob.jobId;
    if ((sequenceTotal > 1 || windowTotal > 1) && !forCurrentJob) {
      // The work this search belonged to was already handed over and the page moved on: its exact
      // count goes to that record, and the rotation may now proceed. It must NOT be read as the new
      // window's own result -- that is how a settled old context used to settle the new one.
      if (sequenceTotal > 1) {
        const attempts = attemptsForBlock(settledBlockIndex);
        stats.realBlocks = stats.realBlocks.map((b) => (b.block === settledBlockIndex
          ? Object.freeze({ ...b, attempts }) : b));
      }
      // The retired window's search has settled: from here the handover gap really does hash
      // nothing, and the page may say so.
      stats.realWindowRetiring = false;
      stats.realTotalAttempts = totalAttempts();
      maybeRecontext();
      emit();
      return;
    }
    stats.realSearch = {
      hashes,
      found: msg.found === 1 ? 1 : 0,
      timedOut: msg.timedOut === true,
      exhausted: msg.exhausted === true,
    };
    if (hashes !== null) stats.hashes = hashes;
    if (sequenceTotal > 1) {
      const attempts = attemptsForBlock(settledBlockIndex);
      stats.realBlocks = stats.realBlocks.map((b) => (b.block === settledBlockIndex
        ? Object.freeze({ ...b, attempts }) : b));
      stats.realTotalAttempts = totalAttempts();
      maybeRecontext();
    }
    if (windowTotal > 1) stats.realTotalAttempts = totalAttempts();
    if (windowTotal > 1 && windowIndex < windowTotal) {
      // THE WINDOW IS SEARCHED; THE SESSION IS NOT OVER. The server declared that one Start may
      // search several nonce windows of this height, so an exhausted window is not a bounded
      // no-solution result for the session: sending Stop here would end a session the server may
      // still refresh, and could revoke a report it is verifying. The page says what is true and
      // waits for the server's own `job_refresh` or its bounded terminal message.
      searchSettledAwaitingServer = true;
      stats.realSearchSettled = true;
      if (shareMode) {
        stats.realShareStopCause = typeof msg.stopCause === 'string' ? msg.stopCause : null;
        if (Number.isSafeInteger(msg.shares)) stats.realSharesFound = msg.shares;
        releaseNextShare();
      }
      maybeRecontext();
      emit();
      return;
    }
    if (shareMode) {
      // THE SEARCH IS OVER; THE RUN IS NOT. Reports may still be queued or outstanding, and one of
      // them may be a block the server is submitting right now. Sending Stop here could revoke that
      // in-flight submission, so the page says what is true -- the window is searched, the server
      // has the results -- and waits for the server's own bounded terminal message.
      searchSettledAwaitingServer = true;
      stats.realSearchSettled = true;
      stats.realShareStopCause = typeof msg.stopCause === 'string' ? msg.stopCause : null;
      if (Number.isSafeInteger(msg.shares)) stats.realSharesFound = msg.shares;
      releaseNextShare();
      emit();
      return;
    }
    if (msg.found === 1 || browserReport !== 'unreported') {
      emit();
      return;                                    // the candidate is with the server; wait for it
    }
    if (runIntent && !simTerminal) {
      stats.realOutcome = 'bounded_no_solution';
      stop(STOP_REASONS.BOUNDED_NO_SOLUTION);
    } else {
      emit();
    }
  }

  /** The simulation's whole workload: one nonce, once. */
  function dispatchOneHash(myGen) {
    if (!runIntent || !worker || myGen !== generation || !realJob) return;
    dispatchedJobId = realJob.jobId;
    awaitingWork = false;
    worker.postMessage({ cmd: 'hash_one', gen: myGen, jobId: realJob.jobId, nonce: realJob.nonceStart });
  }

  function dispatchWork(myGen) {
    if (!runIntent || !worker || myGen !== generation || !currentJob) return;
    dispatchedJobId = currentJob.jobId;
    awaitingWork = false;
    worker.postMessage({ cmd: 'work', gen: myGen, job: currentJob });
  }

  /**
   * The single shared stop path: explicit Stop, hidden tab, pagehide/unload, socket loss and
   * worker errors all end here. Terminates the worker and clears run intent.
   */
  function stop(reason = STOP_REASONS.USER) {
    const wasRunning = runIntent || pendingStart;
    finalizeRealAttemptCount();
    // THE SERVER MUST LEARN ABOUT THIS. Terminating the Worker is not enough once a verified
    // candidate could become a submission. If the acknowledgement has not arrived yet there is
    // nothing to bind to, so the intent is recorded and sent the moment it does.
    // Not after the run already finished: the server has published its terminal result and a
    // late stop would only ask it to revoke something that is already over.
    // Not after a terminal: the server has published its outcome and revoked its own intent, so a
    // late stop would only ask it to revoke something that is already over.
    if (oneAttempt() && wasRunning && !simTerminal && stats.connection === 'connected') {
      if (!sendBoundStop(reason) && pendingStartId !== null) {
        // NOTHING TO BIND TO YET. Remember THIS attempt -- by its own correlation token, so a later
        // Start cannot erase it -- and send exactly one bound stop when its acknowledgement lands.
        if (!abandonedStarts.has(pendingStartId)) {
          abandonedStarts.set(pendingStartId, { reason, stopSent: false });
        }
      }
    }
    runIntent = false;
    pendingRotation = null;
    // Clearing this is what makes a late mining_ready inert: it can no longer construct a Worker.
    pendingStart = false;
    awaitingWork = false;
    dispatchedJobId = null;
    generation++; // anything still in flight from the old worker is now stale
    if (worker) {
      try {
        worker.postMessage({ cmd: 'stop', gen: generation });
      } catch {
        // terminate() below is the guarantee; a failed courtesy message changes nothing.
      }
      worker.onmessage = null;
      worker.onerror = null;
      worker.terminate();
      worker = null;
    }
    if (wasRunning || stats.state !== STATES.IDLE) stats.stopReason = reason;
    stats.hashesPerSecond = 0;
    if (reason === STOP_REASONS.HIDDEN) setState(STATES.STOPPED_HIDDEN);
    else if (stats.error) setState(STATES.ERROR);
    else setState(STATES.STOPPED);
    return wasRunning;
  }

  /** visibilitychange. Hidden stops; visible deliberately does NOTHING. */
  function setHidden(hidden) {
    if (hidden) {
      // Covers a pending start too: hiding the tab while waiting for the server must make the
      // eventual mining_ready inert rather than spawning a Worker into a hidden tab.
      if (runIntent || pendingStart) stop(STOP_REASONS.HIDDEN);
      return;
    }
    // No auto-resume. Mining restarts only from another explicit Start click.
  }

  /** pagehide / unload. Stops mining and closes the socket without recording any resume intent. */
  function teardown() {
    stop(STOP_REASONS.PAGEHIDE);
    if (socket) {
      socket.onclose = null;
      socket.onmessage = null;
      socket.onopen = null;
      socket.onerror = null;
      try {
        socket.close();
      } catch {
        // the page is going away regardless
      }
      socket = null;
      stats.connection = 'disconnected';
    }
    emit();
  }

  return {
    connect,
    start,
    stop,
    setHidden,
    teardown,
    snapshot: () => ({ ...stats }),
    // Test/diagnostic accessors only; nothing in the UI depends on them.
    get workersCreated() {
      return workersCreated;
    },
    get runIntent() {
      return runIntent;
    },
    /** The SERVER-minted run generation, or null. Distinct from the local Worker token below. */
    get serverRunGeneration() {
      return serverRun ? serverRun.runGeneration : null;
    },
    get serverRunBinding() {
      return serverRun ? { ...serverRun } : null;
    },
    get mode() {
      return mode;
    },
    get realJob() {
      return realJob;
    },
    /** True while an abandoned attempt is still waiting to send its one bound stop. */
    get pendingCancel() {
      for (const rec of abandonedStarts.values()) if (!rec.stopSent) return true;
      return false;
    },
    /** The correlation token of the attempt now outstanding, or null. */
    get clientStartId() {
      return pendingStartId;
    },
    get simTerminal() {
      return simTerminal;
    },
    /** Test/diagnostic only: how many abandoned attempts are still tracked. */
    get abandonedStartCount() {
      return abandonedStarts.size;
    },
    /** The BROWSER-LOCAL Worker invalidation token. Never sent to the server. */
    get localWorkerGeneration() {
      return generation;
    },
    get generation() {
      return generation;
    },
    get currentJob() {
      return currentJob ? { ...currentJob } : null;
    },
    get awaitingWork() {
      return awaitingWork;
    },
    get pendingStart() {
      return pendingStart;
    },
    /** The finite sequence: which block, and whether a Worker re-contextualisation is pending. */
    get sequenceTotal() {
      return sequenceTotal;
    },
    get blockIndex() {
      return blockIndex;
    },
    /**
     * THE JOB THE WORKER'S LIVE CONTEXT WAS BUILT FOR, or null before the first readiness. During a
     * window handover this is still the PREVIOUS window: the page must not show the new window's
     * nonce range as though something were searching it.
     */
    get activeRealJob() {
      return activeRealJob;
    },
    get pendingRotation() {
      return pendingRotation ? { ...pendingRotation } : null;
    },
    _receiveServerMessage: onServerMessage,
  };
}
