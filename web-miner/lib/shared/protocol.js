// Strict JSON protocol shared by the browser miner and the local development pool server.
//
// RELATIONSHIP TO pool/protocol/pool_message.hpp: this is a deliberately STRICTER LOCAL SUBSET
// inspired by that older C++ skeleton, not an exact mirror of it. It borrows the message names,
// the size and length limits, the "nonce is exactly 8 lowercase hex characters" rule and the
// treatment of `resultHash` as optional and never trusted. It then diverges on purpose:
//
//   * the schema is CLOSED -- an unknown top-level field is an error, not something to ignore;
//   * `protocolVersion` must be EXACTLY the supported version, where the C++ skeleton accepts any
//     non-negative integer;
//   * `authorize_address` is refused outright, because this slice has no wallet, address or
//     payout of any kind;
//   * `start_request` exists only here: it is the consent boundary, and nothing in the server
//     loads the Wasm module or allocates a dataset until it arrives.
//
// The C++ header is unchanged by this slice. Where the two disagree, this file is the authority
// for the JavaScript development pool and only for it.

export const PROTOCOL_VERSION = 1;

// Exactly one version is supported. There is no negotiation and no forward compatibility: an
// unrecognised version is refused rather than optimistically served.
export const SUPPORTED_PROTOCOL_VERSIONS = Object.freeze([PROTOCOL_VERSION]);

// Hard limits on untrusted input (pool/protocol/pool_message.hpp).
export const MAX_MESSAGE_BYTES = 4096;
export const MAX_ID_LEN = 64;
export const MAX_VERSION_LEN = 32;
export const MAX_HASH_HEX = 64;

// The SYNTHETIC algorithm label. It names the fixed development context meep_v2_setup() builds in
// meepow/wasm/meepow_wasm.cpp -- not a daemon block template. A real template carries
// REAL_ALGORITHM_LABEL from pool/dev/real_template.mjs instead, and the two are deliberately
// different strings so a synthetic acceptance can never be read as a real one.
export const ALGORITHM_LABEL = 'meephash-w-v2-frozen-synthetic';

/**
 * Why a run stopped. A closed set: an unrecognised reason is a schema error, so a client cannot
 * invent a reason string that ends up in a server log or a UI.
 *
 * Every one of these must revoke server-side run intent, not merely stop the local Worker.
 */
/**
 * An issuanceId is EXACTLY 32 lowercase hex characters: 16 cryptographically random bytes minted by
 * the server for one template issuance.
 *
 * WHAT IT IS. A one-use replay/capability identifier. Holding it shows the bearer was handed THIS
 * issuance of THIS template, so a candidate or a stop cannot be replayed into a different issuance.
 *
 * WHAT IT IS NOT. It is not user authentication and not a secret key. Any local program that can
 * open a loopback socket and receive a job also receives this value; it distinguishes issuances,
 * not people.
 *
 * A deterministic value may be injected ONLY through the explicitly named test seam in
 * createRealTemplateJob(); it is never accepted as ordinary untrusted production input.
 */
export const ISSUANCE_ID_RE = /^[0-9a-f]{32}$/;

/**
 * A START CORRELATION TOKEN, minted by the CLIENT for one Start attempt: 16 random bytes.
 *
 * WHAT IT IS. Correlation, and nothing else. It lets an acknowledgement, a readiness message and
 * every later run-scoped event be matched to the exact attempt that asked for them, so a delayed
 * reply for an attempt the user already cancelled cannot be mistaken for a reply to a newer one.
 *
 * WHAT IT IS NOT. It is NOT authority, authentication or a capability. The server never grants
 * anything because a client presented one: authority comes from the server's own reservation,
 * worker id, issuance and run generation. A client that invents a value gains nothing -- it can
 * only fail to match, which refuses it.
 *
 * OPTIONAL AT PARSE TIME, REQUIRED BY THE SIMULATION. The synthetic session has no attempt
 * lifecycle and sends a bare start_request; the recorded-template simulation refuses a Start or a
 * stop that does not carry one.
 */
export const CLIENT_START_ID_RE = /^[0-9a-f]{32}$/;

/**
 * Upper bound for every protocol integer that counts something.
 *
 * Number.isInteger alone accepts 2^53 and beyond, where +1 is a no-op, so two different generations
 * can compare equal. Every integer field below is checked with Number.isSafeInteger AND a range.
 */
export const MAX_RUN_GENERATION = 0xffffffff;

function isCountInteger(v, max = MAX_RUN_GENERATION) {
  return Number.isSafeInteger(v) && v >= 0 && v <= max;
}

/**
 * The two server modes. The SERVER chooses; no client message can change it.
 *
 * 'synthetic' is the default and is the whole runnable browser miner. The simulation mode is
 * opt-in through a local server option only.
 */
export const SYNTHETIC_MODE = 'synthetic';
export const RECORDED_SIMULATION_MODE = 'recorded-template-simulation';
/**
 * ONE private, offline, locally built daemon and ONE fresh template from it. Off by default, chosen
 * only by a local server option, never by a page or a client message.
 */
export const REAL_DAEMON_MODE = 'real-local-daemon';

/**
 * THE FROZEN BOUNDS of a real-local-daemon run, shared by the server, the page and the Worker so none
 * of them can widen them alone. Stop at the first bound reached; no retry within a template. A
 * separately declared finite sequence applies the same bound independently to each fresh template.
 */
export const REAL_SEARCH_LIMITS = Object.freeze({
  maxAttempts: 8192,
  maxSearchMs: 120_000,
});

/**
 * THE DEFAULT DEVELOPMENT SEQUENCE. One explicit Start covers at most this many sequential fresh
 * templates unless trusted server configuration asks for more -- each with its own run generation,
 * one candidate and one submission, and each bounded by REAL_SEARCH_LIMITS on its own. Chosen only
 * by trusted server configuration; the server, the page and the Worker each cap it independently.
 */
export const REAL_SEQUENCE_MAX_BLOCKS = 2;

/**
 * THE HARD CEILING of a configured development sequence, and it is FINITE ON PURPOSE.
 *
 * A longer run than the original two blocks is a development sequence, not a service: it is chosen
 * once, at trusted server startup, it is a small integer, and every component -- the server, the
 * template authority, the page and the Worker -- caps it independently at this same constant. The
 * bound matters because it is what makes the per-run bookkeeping provably finite: nothing in the
 * rotation path may grow with "how long has this been running", only with a number that cannot
 * exceed this one. There is no configuration, message or page that can raise it.
 */
export const REAL_SEQUENCE_DEV_MAX_BLOCKS = 32;

/**
 * Is `n` a sequence length this build will accept anywhere? 1 is every one-shot mode; 2 is the
 * original development sequence; up to the ceiling above is a configured development sequence.
 */
export function isSupportedSequenceBlocks(n) {
  return Number.isSafeInteger(n) && n >= 1 && n <= REAL_SEQUENCE_DEV_MAX_BLOCKS;
}

/**
 * THE SERVER-SIDE SHARE BOUNDS, for the OPT-IN share-work profile only.
 *
 * A share is a verified result that meets a SHARE target the server chose, which is never harder
 * than the block target: share difficulty <= network difficulty, so numerically shareTarget >=
 * blockTarget and every block is also a share. A share that is not a block costs the daemon nothing
 * -- no calc_pow, no claim, no submit -- and does not end the run.
 *
 * Both numbers are small, fixed at build time, and not reachable from any client message: they are
 * what keeps a run that accepts several results still finite in work and in memory.
 *
 * BOTH SIDES USE THESE NUMBERS. The server admits at most `maxSharesPerJob` distinct in-window
 * nonces for one template and verifies them ONE AT A TIME; the Worker caps its qualifying hits at
 * the same number and stops early on a block, and the page queues at most that many reports and
 * keeps one submission outstanding. This is still one explicit Start, one issued window and at most
 * one block submission -- not unbounded mining.
 */
export const REAL_SHARE_LIMITS = Object.freeze({
  maxSharesPerJob: 8,
  maxInvalidCandidates: 4,
});

/**
 * THE OPT-IN SAME-HEIGHT REFRESH BOUNDS. Trusted server configuration only.
 *
 * A refresh is a different transition from the development sequence, but the two may be composed.
 * The sequence moves to the NEXT height only after the current block was accepted and shown by the
 * peer. A refresh stays at the SAME height, on daemon A's UNCHANGED canonical tip, and happens only
 * when the current window is exhausted WITHOUT any block submission having been claimed or started
 * for that height. It exists so one explicit Start can search more than one 8,192-nonce window of a
 * template instead of ending at the first exhaustion.
 *
 * Two independent caps, both small, both fixed here, neither reachable from a page, a message or a
 * query string, and both disclosed before Start:
 *
 *   maxWindows     total nonce windows PER HEIGHT, INCLUDING the first. Each window is a fresh
 *                  server-owned job/issuance over a PROVABLY DISJOINT uint32 nonce range, so no
 *                  nonce is ever searched twice even when the template bytes are identical.
 *   maxSessionMs   the whole session's wall-clock budget, measured from the accepted Start (the
 *                  moment the page consented to), never from readiness. It is
 *                  a second, independent bound: whichever is reached first ends the session.
 *
 * NOTHING A CLIENT SAYS TRIGGERS A REFRESH. This build has no client exhaustion hint at all: the
 * server replaces a window on its OWN bounds -- its share cap, its per-window search backstop, its
 * whole-session backstop -- and only after re-reading daemon A's canonical tip itself.
 */
export const REAL_REFRESH_LIMITS = Object.freeze({
  maxWindows: 4,
  maxSessionMs: 10 * 60_000,
});

/** Is `n` a window total this build will accept? 1 is "no refresh", which is every existing mode. */
export function isSupportedRefreshWindows(n) {
  return Number.isSafeInteger(n) && n >= 1 && n <= REAL_REFRESH_LIMITS.maxWindows;
}

/**
 * THE HARD CAP ON SERIAL CONTEXTS ONE EXPLICIT START MAY EVER ISSUE.
 *
 * A composed sequence/refresh plan can issue `sequenceBlocks * refreshWindows` distinct jobs,
 * verifier pairs and browser contexts over its lifetime. They are strictly serial -- never active
 * together -- but their bindings and release evidence must remain bounded for an exact late Stop.
 * Keeping this equal to the existing sequence ceiling preserves the fixed 32-entry ownership rings.
 */
export const REAL_MAX_CONTEXTS_PER_START = REAL_SEQUENCE_DEV_MAX_BLOCKS;

/** Is this exact block/window plan finite and small enough for every retained-state bound? */
export function isSupportedRealContextPlan(sequenceBlocks, refreshWindows) {
  return isSupportedSequenceBlocks(sequenceBlocks)
    && isSupportedRefreshWindows(refreshWindows)
    && sequenceBlocks <= Math.floor(REAL_MAX_CONTEXTS_PER_START / refreshWindows);
}

/**
 * THE CLOSED FAILURE VOCABULARY of a recorded-template simulation.
 *
 * A genuine, bound `simulation_failed` is recorded by CODE. Anything outside this list is recorded
 * as UNRECOGNISED_SIM_FAILURE rather than copied, so a server-side string can never become UI state.
 * pool/dev/tests/recorded_simulation.test.mjs asserts every code the server can emit is listed.
 */
export const SIM_FAILURE_CODES = Object.freeze([
  // terminal run outcomes (pool/dev/block_run.mjs TERMINAL, success excluded)
  'expired_job', 'revoked_before_submit', 'cancelled', 'run_not_active', 'fatal_verifier',
  'submit_definitely_not_sent', 'submit_rejected', 'submit_outcome_ambiguous',
  'submitted_but_untrusted', 'readback_mismatch', 'internal_error',
  // refusals of the ONE issued candidate AFTER it entered verification, which end the attempt
  'above_target', 'daemon_unavailable', 'submission_already_claimed', 'issuance_superseded',
  // initialization
  'verifier_unavailable',
  // real-local-daemon: the one-candidate limit and the frozen search deadline
  'candidate_limit_reached', 'search_deadline_exceeded',
  // a finite paired-daemon sequence: B never showed the accepted block, the previous verifier could not
  // be confirmed released, or the next template was not exactly the block after the accepted one
  'p2p_propagation_failed', 'verifier_release_unconfirmed', 'next_template_refused',
  // a development sequence: the canonical tip moved to a block this session did not mine, at the height
  // it was searching, and the configured sequence had no further template left to issue
  'external_tip_superseded',
  // the server-side observer could not read daemon A's canonical tip, or it answered malformed
  // bytes: the browser can no longer be told the chain moved, so the run ends rather than hashing on
  'tip_observation_failed',
  // daemon A remained readable but the exact parent named by the issued template was replaced or
  // rolled back; this slice stops instead of guessing how to refresh the same height
  'canonical_parent_changed',
  // the OPT-IN share-work profile: too many results that entered verification and were refused
  // (above the share target, stale, or unusable), so the run ends rather than verifying forever
  'invalid_share_limit_reached',
]);
export const UNRECOGNISED_SIM_FAILURE = 'unrecognised_failure';

export function simFailureCode(value) {
  return SIM_FAILURE_CODES.includes(value) ? value : UNRECOGNISED_SIM_FAILURE;
}

/** The server's one-attempt states, as a closed set. */
export const SIM_ATTEMPT_STATE_VALUES = Object.freeze([
  'idle', 'reserved', 'running', 'terminal_complete', 'terminal_cancelled', 'terminal_failed',
]);
export const SIM_TERMINAL_ATTEMPT_STATES = Object.freeze([
  'terminal_complete', 'terminal_cancelled', 'terminal_failed',
]);

/**
 * Why a Start was refused BEFORE any run existed. A closed set.
 *
 * Such a refusal has no run generation, because no run was created. It is therefore a DIFFERENT
 * schema from a run-scoped message and must never be described as carrying the same binding.
 */
export const SIM_PRE_RUN_REFUSALS = Object.freeze([
  'simulation_already_completed',
  'simulation_attempt_in_progress',
  // Opt-in delayed real work: both physical verifier/helper slots are occupied. No job or run was
  // issued to this Start, and the page may retry only after a fresh explicit click.
  'pool_capacity',
  // The process-wide bounded reservation history is full. Restart is required; forgetting an old
  // terminal token in order to make room would make that token reusable.
  'reservation_history_full',
  // Opt-in two-slot personalized work. These are distinct fail-closed outcomes from the shared
  // coordinator, all before a job, verifier, run generation or browser Worker exists.
  'owner_already_reserved',
  'reservation_terminal',
  'reservation_start_mismatch',
  'run_intent_revoked',
  'two_slot_round_closed',
  'personalized_issue_failed',
  'personalized_issue_cancelled',
  'personalized_publication_refused',
  'personalized_issue_tip_changed',
  'canonical_submission_claimed',
  'assignment_setup_failed',
  'verification_disabled',
  'missing_client_start_id',
]);

/**
 * Which mode-specific block of the page may be shown.
 *
 * Before `server_hello` the mode is genuinely unknown, and showing the synthetic consent copy in
 * that window would state things ("a local synthetic development job", "two independently built
 * copies", "one accepted share") that are false if the server turns out to be in simulation mode.
 * So neither block is shown until the server has said which it is.
 */
export function selectModeView(mode) {
  if (mode === SYNTHETIC_MODE) {
    return Object.freeze({ showConnecting: false, showSynthetic: true, showSimulation: false });
  }
  if (mode === RECORDED_SIMULATION_MODE) {
    return Object.freeze({ showConnecting: false, showSynthetic: false, showSimulation: true });
  }
  if (mode === REAL_DAEMON_MODE) {
    return Object.freeze({
      showConnecting: false, showSynthetic: false, showSimulation: false, showRealDaemon: true,
    });
  }
  return Object.freeze({ showConnecting: true, showSynthetic: false, showSimulation: false });
}

export const STOP_REASONS = Object.freeze([
  'user_stop',      // the Stop button
  'page_hidden',    // visibilitychange -> hidden
  'page_unload',    // pagehide / beforeunload
  'socket_close',   // the connection went away
  'session_dispose',
  'search_bound_reached',  // real-local-daemon: the frozen attempt/time bound ended with no solution
]);

export const REJECT_REASONS = Object.freeze({
  MESSAGE_TOO_LARGE: 'message_too_large',
  BAD_JSON: 'bad_json',
  BAD_SCHEMA: 'bad_schema',
  UNKNOWN_TYPE: 'unknown_type',
  NOT_AUTHORIZED: 'not_authorized',
  UNKNOWN_WORKER: 'unknown_worker',
  UNKNOWN_JOB: 'unknown_job',
  STALE_JOB: 'stale_job',
  EXPIRED_JOB: 'expired_job',
  DUPLICATE_SHARE: 'duplicate_share',
  DUPLICATE_MEMORY_FULL: 'duplicate_memory_full',
  RATE_LIMITED: 'rate_limited',
  QUEUE_FULL: 'queue_full',
  ABOVE_TARGET: 'above_target',
  UNSUPPORTED_VERSION: 'unsupported_protocol_version',
  NOT_STARTED: 'mining_not_started',
  VERIFIER_UNAVAILABLE: 'verifier_unavailable',
  // Latched, process-wide, and never per-share: the pool's two builds of frozen v2 disagreed, or
  // the native helper died. Either way this pool can no longer prove a result and stops mining.
  VERIFIER_FAULT: 'verifier_fault',
  VERIFIER_BUILD_DISAGREEMENT: 'verifier_build_disagreement',
});

/** Reasons that mean the pool is permanently done verifying, not that one share was bad. */
export const TERMINAL_VERIFIER_REASONS = Object.freeze([
  'verifier_fault',
  'verifier_build_disagreement',
]);

const LOWER_HEX = /^[0-9a-f]+$/;

/**
 * The exact rule pool/protocol/pool_message.hpp's `is_lower_hex` applies: non-empty, EVEN length
 * (it is a byte string), lowercase only. The even-length requirement matters -- without it the
 * JavaScript validator would accept inputs the C++ one refuses.
 */
function isLowerHexBytes(s) {
  return typeof s === 'string' && s.length > 0 && s.length % 2 === 0 && LOWER_HEX.test(s);
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function fail(reason, detail) {
  return { ok: false, reason, detail: detail ?? '' };
}

/**
 * Parse and strictly validate ONE untrusted client->server message.
 *
 * `raw` is the exact byte length that arrived on the wire, checked BEFORE parsing, and `text` is
 * the decoded body. Never throws. Unknown top-level keys are rejected for every message type:
 * this slice has a closed schema, so a typo or an injected field is an error rather than a
 * silently ignored one.
 */
export function parseClientMessage(byteLength, text) {
  if (byteLength > MAX_MESSAGE_BYTES) return fail(REJECT_REASONS.MESSAGE_TOO_LARGE, `${byteLength} bytes`);

  let root;
  try {
    root = JSON.parse(text);
  } catch {
    return fail(REJECT_REASONS.BAD_JSON, 'not valid JSON');
  }
  if (!isPlainObject(root)) return fail(REJECT_REASONS.BAD_JSON, 'root is not an object');
  if (typeof root.type !== 'string') return fail(REJECT_REASONS.BAD_SCHEMA, 'missing type');

  switch (root.type) {
    case 'client_hello':
      return parseClientHello(root);
    case 'start_request':
      return parseStartRequest(root);
    case 'stop_request':
      return parseStopRequest(root);
    case 'submit_share':
      // The SYNTHETIC path, unchanged. It deliberately does NOT accept the real-template binding
      // fields: widening it would let a synthetic submission carry real-path authority.
      return parseSubmitShare(root);
    case 'submit_real_candidate':
      return parseSubmitRealCandidate(root);
    case 'ping':
      return closedSchema(root, ['type'], { ok: true, type: 'ping' });
    case 'pong':
      return closedSchema(root, ['type'], { ok: true, type: 'pong' });
    default:
      return fail(REJECT_REASONS.UNKNOWN_TYPE, root.type.slice(0, 32));
  }
}

function closedSchema(root, allowed, value) {
  for (const key of Object.keys(root)) {
    if (!allowed.includes(key)) return fail(REJECT_REASONS.BAD_SCHEMA, `unexpected field ${key.slice(0, 32)}`);
  }
  return value;
}

function parseClientHello(root) {
  if (!isCountInteger(root.protocolVersion)) {
    return fail(REJECT_REASONS.BAD_SCHEMA, 'bad protocolVersion');
  }
  // Exact-version enforcement, at parse time, so an unsupported client is refused before it can
  // be authorized or handed a job.
  if (!SUPPORTED_PROTOCOL_VERSIONS.includes(root.protocolVersion)) {
    return fail(REJECT_REASONS.UNSUPPORTED_VERSION,
      `this pool speaks protocol version ${PROTOCOL_VERSION}, not ${root.protocolVersion}`);
  }
  if (root.clientVersion !== undefined) {
    if (typeof root.clientVersion !== 'string' || root.clientVersion.length > MAX_VERSION_LEN) {
      return fail(REJECT_REASONS.BAD_SCHEMA, 'bad clientVersion');
    }
  }
  return closedSchema(root, ['type', 'protocolVersion', 'clientVersion'], {
    ok: true,
    type: 'client_hello',
    protocolVersion: root.protocolVersion,
    clientVersion: root.clientVersion ?? '',
  });
}

/**
 * THE CONSENT BOUNDARY. It declares start intent; it grants nothing.
 *
 * `clientStartId` is OPTIONAL here and REQUIRED by the recorded-template simulation. Making it
 * optional at parse time keeps the synthetic path, which has no attempt lifecycle, exactly as it
 * was; the simulation session refuses a Start without one. Either way it is a CORRELATION token --
 * see CLIENT_START_ID_RE. The server can observe only the declaration: any local program able to
 * open a loopback socket can send this message.
 */
function parseStartRequest(root) {
  if (root.clientStartId !== undefined) {
    if (typeof root.clientStartId !== 'string' || !CLIENT_START_ID_RE.test(root.clientStartId)) {
      return fail(REJECT_REASONS.BAD_SCHEMA, 'clientStartId must be exactly 32 lowercase hex characters');
    }
  }
  return closedSchema(root, ['type', 'clientStartId'], {
    ok: true,
    type: 'start_request',
    clientStartId: root.clientStartId ?? null,
  });
}

/**
 * THE REVOCATION BOUNDARY, and the counterpart to start_request.
 *
 * Stop used to be purely client-side: the page terminated its Worker, and the server learned
 * nothing. That is fine while the only outcome is a synthetic share, and NOT fine once a verified
 * candidate can become a real block submission -- the server needs a durable reason to refuse a
 * late one.
 *
 * BOUND TO A GENERATION, ON PURPOSE. `runGeneration` is the monotonic token the server minted when
 * this run started. Requiring it means an old tab's queued Stop, a replayed message, or a stale
 * reconnect cannot revoke a run the user started AFTERWARDS -- createRunIntent().revoke() refuses
 * any generation that is not the current one.
 *
 * `workerId` is required for the same reason a share carries it: the server checks it against the
 * id it issued to THIS connection, so one connection cannot stop another's run.
 */
function parseStopRequest(root) {
  if (typeof root.workerId !== 'string' || root.workerId.length === 0 || root.workerId.length > MAX_ID_LEN) {
    return fail(REJECT_REASONS.BAD_SCHEMA, 'bad workerId');
  }
  if (!isCountInteger(root.runGeneration)) {
    return fail(REJECT_REASONS.BAD_SCHEMA,
      'runGeneration must be a safe integer in [0, ' + MAX_RUN_GENERATION + ']');
  }
  // jobId and issuanceId are REQUIRED, not optional. An unbound stop is a stop that could apply to
  // whatever happens to be running, which is exactly what a stale or replayed message would want.
  if (typeof root.jobId !== 'string' || root.jobId.length === 0 || root.jobId.length > MAX_ID_LEN) {
    return fail(REJECT_REASONS.BAD_SCHEMA, 'bad jobId');
  }
  if (typeof root.issuanceId !== 'string' || !ISSUANCE_ID_RE.test(root.issuanceId)) {
    return fail(REJECT_REASONS.BAD_SCHEMA, 'issuanceId must be exactly 32 lowercase hex characters');
  }
  if (root.reason !== undefined) {
    if (typeof root.reason !== 'string' || !STOP_REASONS.includes(root.reason)) {
      return fail(REJECT_REASONS.BAD_SCHEMA, 'unknown stop reason');
    }
  }
  if (root.clientStartId !== undefined) {
    if (typeof root.clientStartId !== 'string' || !CLIENT_START_ID_RE.test(root.clientStartId)) {
      return fail(REJECT_REASONS.BAD_SCHEMA, 'clientStartId must be exactly 32 lowercase hex characters');
    }
  }
  return closedSchema(root,
    ['type', 'workerId', 'runGeneration', 'jobId', 'issuanceId', 'reason', 'clientStartId'], {
      ok: true,
      type: 'stop_request',
      workerId: root.workerId,
      runGeneration: root.runGeneration,
      jobId: root.jobId,
      issuanceId: root.issuanceId,
      reason: root.reason ?? 'user_stop',
      clientStartId: root.clientStartId ?? null,
    });
}

/**
 * THE REAL-TEMPLATE CANDIDATE. A distinct closed-schema message, not a widened submit_share.
 *
 * Every one of the five binding fields is REQUIRED, because block_run.mjs refuses a candidate that
 * cannot name its job, its issuance, its worker and its run generation. Adding those to
 * submit_share instead would have meant either loosening the synthetic schema or leaving the two
 * permanently contradictory -- the synthetic parser accepted three fields while the real path
 * demanded five, so a correctly-formed real candidate could not be expressed on the wire at all.
 *
 * NO RESULT HASH. The old optional `resultHash` diagnostic is deliberately absent: the server
 * recomputes the hash itself, and a field that is never read is a field that invites someone to
 * believe it matters.
 */
function parseSubmitRealCandidate(root) {
  if (typeof root.jobId !== 'string' || root.jobId.length === 0 || root.jobId.length > MAX_ID_LEN) {
    return fail(REJECT_REASONS.BAD_SCHEMA, 'bad jobId');
  }
  if (typeof root.issuanceId !== 'string' || !ISSUANCE_ID_RE.test(root.issuanceId)) {
    return fail(REJECT_REASONS.BAD_SCHEMA, 'issuanceId must be exactly 32 lowercase hex characters');
  }
  if (typeof root.workerId !== 'string' || root.workerId.length === 0 || root.workerId.length > MAX_ID_LEN) {
    return fail(REJECT_REASONS.BAD_SCHEMA, 'bad workerId');
  }
  if (!isCountInteger(root.runGeneration)) {
    return fail(REJECT_REASONS.BAD_SCHEMA,
      'runGeneration must be a safe integer in [0, ' + MAX_RUN_GENERATION + ']');
  }
  if (typeof root.nonce !== 'string' || root.nonce.length !== 8 || !LOWER_HEX.test(root.nonce)) {
    return fail(REJECT_REASONS.BAD_SCHEMA, 'nonce must be 8 lowercase hex chars');
  }
  // REQUIRED on this message: a real candidate always belongs to one acknowledged Start attempt,
  // and the server refuses one that cannot name it.
  if (typeof root.clientStartId !== 'string' || !CLIENT_START_ID_RE.test(root.clientStartId)) {
    return fail(REJECT_REASONS.BAD_SCHEMA, 'clientStartId must be exactly 32 lowercase hex characters');
  }
  return closedSchema(root,
    ['type', 'jobId', 'issuanceId', 'workerId', 'runGeneration', 'nonce', 'clientStartId'], {
      ok: true,
      type: 'submit_real_candidate',
      jobId: root.jobId,
      issuanceId: root.issuanceId,
      workerId: root.workerId,
      runGeneration: root.runGeneration,
      nonce: parseInt(root.nonce, 16) >>> 0,
      nonceHex: root.nonce,
      clientStartId: root.clientStartId,
    });
}

function parseSubmitShare(root) {
  if (typeof root.jobId !== 'string' || root.jobId.length === 0 || root.jobId.length > MAX_ID_LEN) {
    return fail(REJECT_REASONS.BAD_SCHEMA, 'bad jobId');
  }
  if (typeof root.workerId !== 'string' || root.workerId.length === 0 || root.workerId.length > MAX_ID_LEN) {
    return fail(REJECT_REASONS.BAD_SCHEMA, 'bad workerId');
  }
  if (typeof root.nonce !== 'string' || root.nonce.length !== 8 || !LOWER_HEX.test(root.nonce)) {
    return fail(REJECT_REASONS.BAD_SCHEMA, 'nonce must be 8 lowercase hex chars');
  }
  if (root.clientVersion !== undefined) {
    if (typeof root.clientVersion !== 'string' || root.clientVersion.length > MAX_VERSION_LEN) {
      return fail(REJECT_REASONS.BAD_SCHEMA, 'bad clientVersion');
    }
  }
  // OPTIONAL and NEVER TRUSTED. Accepted only so the wire shape matches pool_message.hpp and so
  // the adversarial tests can prove a forged value cannot influence the verdict. The server
  // recomputes the hash itself and ignores this field when deciding.
  if (root.resultHash !== undefined) {
    if (!isLowerHexBytes(root.resultHash) || root.resultHash.length > MAX_HASH_HEX) {
      return fail(REJECT_REASONS.BAD_SCHEMA, 'bad resultHash');
    }
  }
  return closedSchema(root, ['type', 'jobId', 'workerId', 'nonce', 'clientVersion', 'resultHash'], {
    ok: true,
    type: 'submit_share',
    jobId: root.jobId,
    workerId: root.workerId,
    nonce: parseInt(root.nonce, 16) >>> 0,
    nonceHex: root.nonce,
    clientVersion: root.clientVersion ?? '',
    untrustedResultHash: root.resultHash ?? '',
  });
}
