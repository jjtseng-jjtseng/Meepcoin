// The RECORDED-TEMPLATE SIMULATION session.
//
// WHAT THIS IS. A rehearsal of the future daemon bridge, over ONE committed historical block
// vector. The browser computes one real MeepHash-W v2 hash; the server recomputes it once with its
// own contextual Wasm instance AND once with the LIVE LOCAL NATIVE HELPER (the existing
// meepow-v2-helper child), both over this job's server-owned context; an in-memory mock daemon then
// exercises the submission path.
//
// WHAT IT IS NOT, AND THE WORDING REFLECTS THIS EVERYWHERE:
//   * no real daemon, RPC socket, chain, wallet or network is involved;
//   * the Wasm and native builds compile the SAME C++ source: their agreement is a build, toolchain
//     and runtime cross-check for this context, not a second independently authored algorithm;
//   * the "daemon" is an in-memory model with counters;
//   * nothing is mined, submitted or accepted, and no coin or block is created.
//
// WHY A SEPARATE SESSION MODULE RATHER THAN A BRANCH INSIDE session.mjs. The synthetic session is
// 470 lines of synthetic-specific ordering that is already audited and working. Threading a second
// mode through all of it would put the two paths' invariants in one place and risk the default. This
// module reuses the same transport, protocol parser, ws layer, static server and shutdown; only the
// per-connection behaviour differs. session.mjs is not modified by this mode; the synthetic
// controller and lifecycle regressions are what check the default path still behaves.
//
// ONE ATTEMPT PER SERVER PROCESS, AND IT IS RESERVED BEFORE ANY WORK HAPPENS.
//
// The previous revision only CLAIMED to be one-shot. Nothing was reserved when Start arrived, so:
//
//   * two connections could both be acknowledged and both drive a run -- the authority's single
//     submission claim stopped the second DISPATCH, but only after both had already built a
//     verifier, allocated a dataset and hashed, and the loser was left displayed as mining with an
//     idle Worker;
//   * six sequential start_requests on one connection produced six run_started messages, six
//     mining_ready messages, six run generations and six permanent fatal-latch subscribers.
//
// A reservation is now taken BEFORE verifier construction, dataset allocation or hashing:
//
//   IDLE -> RESERVED(owner session, start correlation, run binding) -> RUNNING
//        -> TERMINAL_COMPLETE | TERMINAL_CANCELLED | TERMINAL_FAILED
//
// A different session, or a different Start identity, is refused before any work. A byte-identical
// repeat of the same Start is answered idempotently with the acknowledgement it already got, and
// mints no second generation, verifier, run, subscription, Worker or hash. Every terminal outcome --
// stop, disconnect, initialization failure, dispatch failure, readback trouble, fatal latch, a
// rejected candidate -- ends the one attempt for this process; the page then needs a server restart.
// Recorded simulation and one-shot daemon modes remain single-template. The explicit finite
// paired-daemon development sequence below rotates the same reservation across a trusted 2..32
// template count; it is not an unbounded queue, schedule, retry service or production miner.
//
// EVERY RUN-SCOPED MESSAGE REPEATS THE WHOLE BINDING. A client cannot tell which attempt a bare
// event belongs to, so every one of them carries clientStartId, workerId, jobId, issuanceId and the
// server run generation, and the client checks all five before it changes anything.

import { createHash, randomBytes } from 'node:crypto';

import {
  parseClientMessage, PROTOCOL_VERSION, REAL_DAEMON_MODE, REAL_MAX_CONTEXTS_PER_START,
  REAL_REFRESH_LIMITS, REAL_SEARCH_LIMITS,
  REAL_SHARE_LIMITS, RECORDED_SIMULATION_MODE,
  REAL_SEQUENCE_DEV_MAX_BLOCKS, REJECT_REASONS, STOP_REASONS,
  isSupportedRealContextPlan, isSupportedRefreshWindows, isSupportedSequenceBlocks, simFailureCode,
} from '../../web-miner/lib/shared/protocol.js';
import { NONTERMINAL, createBlockRun, createRunIntent } from './block_run.mjs';
import { FATAL_CODES } from './run_guard.mjs';
import { TIP_OBSERVATION_FAILED, TIP_PARENT_CHANGED } from './tip_observer.mjs';
import { blobToHex } from './block_blob.mjs';
import { toClientJobMessage } from './real_template.mjs';

/** Re-exported from the shared protocol so the client and server cannot drift apart. */
export const SIM_MODE = RECORDED_SIMULATION_MODE;

/** The labels the page must show. Exported so a test can assert the page and the server agree. */
export const SIM_LABELS = Object.freeze([
  'RECORDED-TEMPLATE SIMULATION',
  'LIVE LOCAL NATIVE HELPER',
  'MOCK DAEMON',
  'NO DAEMON OR BLOCKCHAIN CONTACTED',
  'NO BLOCK MINED, SUBMITTED, OR ACCEPTED',
]);

export const SIM_ACTION_LABEL = 'Run one-hash simulation';

/** The one attempt a server process may make. */
export const SIM_ATTEMPT_STATES = Object.freeze({
  IDLE: 'idle',
  RESERVED: 'reserved',
  RUNNING: 'running',
  TERMINAL_COMPLETE: 'terminal_complete',
  TERMINAL_CANCELLED: 'terminal_cancelled',
  TERMINAL_FAILED: 'terminal_failed',
});

const TERMINAL_ATTEMPT_STATES = Object.freeze([
  SIM_ATTEMPT_STATES.TERMINAL_COMPLETE,
  SIM_ATTEMPT_STATES.TERMINAL_CANCELLED,
  SIM_ATTEMPT_STATES.TERMINAL_FAILED,
]);

/** Why a reservation was refused. A closed set; nothing else ever reaches a client. */
export const RESERVE_REFUSED = Object.freeze({
  ALREADY_FINISHED: 'simulation_already_completed',
  IN_PROGRESS: 'simulation_attempt_in_progress',
  VERIFIER_DISABLED: 'verification_disabled',
  MISSING_START_ID: 'missing_client_start_id',
});

/**
 * Wording that must never appear in a simulation-bound message.
 *
 * Checked by a test against every emitted event, because the honest thing here is not to trust that
 * a future edit will remember. `block_submit_started` is renamed too: in a simulation nothing is
 * submitted anywhere.
 */
export const FORBIDDEN_SIM_PHRASES = Object.freeze([
  'block_accepted', 'share_accepted', 'block_submit_started',
  'daemon accepted', 'block submitted', 'block was accepted', 'submitted to the daemon',
  'mined a block', 'block accepted',
]);
// NOTE: the word "blockchain" is deliberately NOT forbidden -- one of the required labels is
// "NO DAEMON OR BLOCKCHAIN CONTACTED", which uses it in a negation. What is forbidden is an
// AFFIRMATIVE claim that a block was mined, submitted or accepted.

/** Outward names for this mode. block_run's internals are unchanged; only the labels differ. */
const SIM_VOCABULARY = Object.freeze({
  verified: 'mock_verification_complete',
  submitStarted: 'mock_submit_path_exercised',
  success: 'simulation_complete',
  failure: 'simulation_failed',
  candidateRejected: 'candidate_rejected',
  stopped: 'simulation_stopped',
  unavailable: 'simulation_unavailable',
});

// ==================================================================================== profiles
// ONE SESSION MACHINE, TWO TRUTHFUL PROFILES. The one-attempt reservation, the bindings, the Stop
// handling and the terminal bookkeeping above are identical for both modes; what differs is only
// what the server CALLS things, what it tells the page before Start, the search bounds, and the
// counters it reports. The recorded profile reproduces this module's previous constants exactly.

/** The real-daemon labels. Nothing here says "simulation", and nothing overstates a private block. */
export const REAL_DAEMON_LABELS = Object.freeze([
  'REAL LOCAL DAEMON',
  'PRIVATE OFFLINE TESTNET NODE ON THIS COMPUTER',
  'ONE FRESH BLOCK TEMPLATE',
  'TEST COINS WITH NO MONETARY VALUE',
  'AT MOST ONE BLOCK SUBMISSION, NEVER RETRIED',
]);

export const REAL_DAEMON_ACTION_LABEL = 'Search the fresh template once';

/**
 * The server's own backstop on the page's frozen 120-second search. The Worker stops itself at
 * REAL_SEARCH_LIMITS.maxSearchMs; this grace covers the browser building its dataset after
 * mining_ready. After it, an attempt with no candidate is ended as search_bound_reached.
 */
export const SERVER_SEARCH_GRACE_MS = 30_000;

const REAL_VOCABULARY = Object.freeze({
  verified: 'candidate_verified',
  submitStarted: 'block_submit_started',
  success: 'block_accepted',
  failure: 'block_rejected',
  candidateRejected: 'candidate_rejected',
  // OPT-IN share-work profile only: a verified result that met the share target and not the block
  // target. Nonterminal, and nothing was sent to a daemon for it.
  shareAccepted: 'share_accepted',
  stopped: 'run_stopped',
  unavailable: 'run_unavailable',
});

function recordedSummary(sim) {
  return {
    mode: SIM_MODE,
    labels: SIM_LABELS,
    counters: {
      serverWasmHashes: sim.counters.serverWasmHashes,
      nativeHelperHashRequests: sim.counters.nativeHashRequests,
      nativeHelperHashes: sim.counters.nativeHelperHashes,
      mockCalcPow: sim.mockDaemon.counters.calcPow,
      mockPrepareSubmission: sim.mockDaemon.counters.prepareSubmission,
      mockDispatchSubmission: sim.mockDaemon.counters.dispatchSubmission,
      mockReadback: sim.mockDaemon.counters.readback,
      mockInMemoryTransportCalls: sim.mockDaemon.counters.inMemoryTransportCalls,
      realTransportCalls: sim.mockDaemon.counters.transportCalls,
    },
    recordedVector: {
      height: sim.job.height.toString(),
      nonce: sim.job.nonceStart,
      expectedHashHexLE: sim.expectedHashHexLE,
    },
    notice: 'Server Wasm and the live local native helper both reproduced the recorded hash, and '
      + 'the MOCK submit path was exercised. No daemon or chain was contacted; nothing was mined '
      + 'and nothing was created.',
  };
}

function realSummary(sim) {
  const d = sim.submissionDaemon.counters;
  return {
    mode: REAL_DAEMON_MODE,
    labels: sim.profile?.labels ?? REAL_DAEMON_LABELS,
    counters: {
      serverWasmHashes: sim.counters.serverWasmHashes,
      nativeHelperHashRequests: sim.counters.nativeHashRequests,
      nativeHelperHashes: sim.counters.nativeHelperHashes,
      daemonGetBlockTemplate: d.getBlockTemplate,
      daemonCalcPow: d.calcPow,
      daemonPrepareSubmission: d.prepareSubmission,
      daemonDispatchSubmission: d.dispatchSubmission,
      daemonHeaderReadback: d.headerReadback,
      daemonTopReadback: d.topReadback,
    },
    template: {
      height: sim.job.height.toString(),
      nonceStart: sim.job.nonceStart,
      nonceRange: sim.job.nonceRange,
      targetHexLE: sim.job.targetHexLE,
    },
    limits: REAL_SEARCH_LIMITS,
    // The sequence: which block this is, and the public facts of each block accepted so far.
    ...(sim.sequenceTotal > 1 ? {
      sequence: {
        block: sim.blockIndex,
        total: sim.sequenceTotal,
        accepted: sim.blockRecords.filter((b) => b.accepted).map((b) => ({
          block: b.block, height: b.accepted.height, nonce: b.accepted.nonce, blockId: b.accepted.blockId,
          hashHexLE: b.accepted.hashHexLE, propagated: b.propagation?.converged === true,
        })),
      },
    } : {}),
  };
}

export const RECORDED_PROFILE = Object.freeze({
  mode: SIM_MODE,
  labels: SIM_LABELS,
  actionLabel: SIM_ACTION_LABEL,
  vocabulary: SIM_VOCABULARY,
  helloNotice: 'This is a recorded-template simulation over one committed historical block vector. '
    + 'The native check is the live local native C++ helper over the same recorded context; '
    + 'the daemon is an in-memory model. No daemon or chain is contacted. Nothing is mined '
    + 'and nothing is created.',
  willAllocate: 'Start allocates one browser dataset, one server Wasm dataset and one native '
    + 'helper dataset (about 40 MiB each), starts the local native helper, and computes exactly '
    + 'one hash in each.',
  readyNotice: 'one recorded nonce to hash; nothing is submitted anywhere',
  maxCandidates: null,
  searchLimits: null,
  summary: recordedSummary,
});

/** The paired P2P test: the same machine and bounds, with labels that say what is really running. */
export const REAL_P2P_LABELS = Object.freeze([
  'REAL LOCAL DAEMONS',
  'TWO PRIVATE TESTNET NODES ON THIS COMPUTER, PAIRED ONLY WITH EACH OTHER',
  'ONE FRESH BLOCK TEMPLATE FROM NODE A',
  'FIXED TEST DIFFICULTY 500 (A DEVELOPMENT CONTROL)',
  'TEST COINS WITH NO MONETARY VALUE',
  'AT MOST ONE BLOCK SUBMISSION TO NODE A, NEVER RETRIED',
]);

export const REAL_DAEMON_PROFILE = Object.freeze({
  mode: REAL_DAEMON_MODE,
  labels: REAL_DAEMON_LABELS,
  actionLabel: REAL_DAEMON_ACTION_LABEL,
  vocabulary: REAL_VOCABULARY,
  helloNotice: 'One private, offline MeepCoin testnet daemon is already running on this computer, with '
    + 'no peers, and it produced one fresh block template. Start runs ONE bounded browser search of '
    + `at most ${REAL_SEARCH_LIMITS.maxAttempts} nonces or ${REAL_SEARCH_LIMITS.maxSearchMs / 1000} `
    + 'seconds. A nonce that meets the daemon target is recomputed by the server WebAssembly build, '
    + 'the native helper and the daemon, then submitted to that private daemon at most once, never '
    + 'retried. Test coins only; no public network.',
  willAllocate: 'Start allocates one browser dataset, one server Wasm dataset and one native helper '
    + 'dataset (about 40 MiB each) and starts the local native helper. The daemon is already running.',
  readyNotice: 'search the issued window once; at most one candidate and at most one submission',
  maxCandidates: 1,
  searchLimits: REAL_SEARCH_LIMITS,
  summary: realSummary,
});

/**
 * The opt-in TWO-BROWSER local-pool profile. Each accepted Start receives its own personalized
 * template and verifier/helper pair, but both assignments share one canonical submission fence.
 * This is intentionally still the one-height, offline-daemon development slice: it does not imply
 * accounting, payouts, public networking, a job queue, refresh, or a block sequence.
 */
export const REAL_TWO_SLOT_PROFILE = Object.freeze({
  ...REAL_DAEMON_PROFILE,
  labels: Object.freeze([
    'REAL LOCAL DAEMON',
    'UP TO TWO VOLUNTARY BROWSER SESSIONS ON THIS COMPUTER',
    'ONE DISTINCT PERSONALIZED TEMPLATE PER ACCEPTED START',
    'ONE CANONICAL BLOCK SUBMISSION ACROSS BOTH SESSIONS, NEVER RETRIED',
    'LOSING WORK STOPS WHEN THE WINNER CLAIMS THE CANONICAL SUBMISSION',
    'TEST COINS WITH NO MONETARY VALUE; NO PUBLIC NETWORK',
  ]),
  actionLabel: 'Search one personalized private template',
  helloNotice: 'One private, offline MeepCoin testnet daemon is already running on this computer. '
    + 'This local development pool admits at most two browser sessions. Each accepted Start receives '
    + 'a distinct personalized template for the same canonical tip and runs one bounded search. The '
    + 'first qualifying result to claim the canonical submission stops its sibling; across both '
    + 'sessions the private daemon receives at most one block submission, never retried. Test coins '
    + 'only; no wallet, payout or public network.',
  willAllocate: 'An accepted Start allocates one browser dataset, one server Wasm dataset and one '
    + 'native helper dataset (about 40 MiB each). A refused Start allocates none of them.',
  readyNotice: 'search this session\'s personalized window once; one canonical submission across both sessions',
});

export const REAL_P2P_PROFILE = Object.freeze({
  ...REAL_DAEMON_PROFILE,
  labels: REAL_P2P_LABELS,
  helloNotice: 'Two private MeepCoin testnet daemons are running on this computer, each allowed to talk only '
    + 'to the other over loopback, at a FIXED TEST DIFFICULTY of 500 (a development control, not a real '
    + `network difficulty). Start runs ONE bounded browser search of at most ${REAL_SEARCH_LIMITS.maxAttempts} `
    + `nonces or ${REAL_SEARCH_LIMITS.maxSearchMs / 1000} seconds over a fresh template from node A. A nonce `
    + 'that meets the target is recomputed by the server WebAssembly build, the native helper and node A, '
    + 'then submitted to node A at most once, never retried. Test coins only; no public network.',
  readyNotice: 'search node A\'s template once; at most one candidate and at most one submission',
});

/** An explicitly selected private pair using each daemon-issued, non-fixed block difficulty. */
export const REAL_P2P_NATURAL_PROFILE = Object.freeze({
  ...REAL_P2P_PROFILE,
  labels: Object.freeze(REAL_P2P_LABELS.map((label) => label.startsWith('FIXED TEST DIFFICULTY')
    ? 'DAEMON-SELECTED BLOCK DIFFICULTY; NO FIXED TEST TARGET' : label)),
  helloNotice: 'Two private MeepCoin testnet daemons are running on this computer, paired only over '
    + 'loopback. No fixed-difficulty option is set: node A chooses the block difficulty from its '
    + 'chain history. Start searches one fresh template at most once, for at most '
    + `${REAL_SEARCH_LIMITS.maxAttempts} nonces or ${REAL_SEARCH_LIMITS.maxSearchMs / 1000} seconds. `
    + 'A block may not be found. A qualifying result is checked independently by server Wasm, the '
    + 'native helper and node A, then submitted to A at most once; B can learn it only by P2P. '
    + 'Test coins only, no wallet, payout or public network.',
});

/**
 * THE OPT-IN SHARE-WORK PROFILE. Selected only when trusted startup configuration supplied a share
 * difficulty (`realDaemon.shareDifficulty`); every other profile is untouched by its existence.
 *
 * WHAT IT CHANGES, AND ONLY THIS:
 *   - the server admits up to REAL_SHARE_LIMITS.maxSharesPerJob distinct in-window nonces for the
 *     one job, instead of exactly one -- and SEQUENTIALLY. One candidate is verified at a time; a
 *     bound frame that arrives while another is in flight is refused cheaply with `queue_full`,
 *     spends no budget and does not spend its nonce. Several candidates inside ONE block_run can
 *     publish a terminal underneath each other, so this is a correctness fence, not pacing;
 *   - a verified result that meets the SHARE target but not the BLOCK target is announced as a
 *     nonterminal `share_accepted` and the run continues. No calc_pow, no submission claim, no
 *     submit_block and no readback happens for it;
 *   - a result that entered verification and was refused no longer ends the run by itself; the run
 *     ends when REAL_SHARE_LIMITS.maxInvalidCandidates of them have been refused;
 *   - the server's search backstop becomes ABSOLUTE for the run: it is armed once at readiness and
 *     is never cleared by an admitted candidate, so a session that keeps sending shares still ends
 *     at the frozen bound instead of idling forever.
 *
 * WHAT IT DOES NOT CHANGE: at most ONE block submission for the height (the shared template
 * authority's single claim), the frozen search bounds, the daemon pair, the verifier pair, the
 * cleanup path -- and the BROWSER, which in this build still searches to its first solution and
 * reports once. This profile describes what the SERVER accepts, and its text says so.
 */
export const REAL_P2P_SHARE_PROFILE = Object.freeze({
  ...REAL_P2P_PROFILE,
  labels: Object.freeze([
    ...REAL_P2P_LABELS.slice(0, 5),
    `SERVER-SIDE SHARE CHECKING: UP TO ${REAL_SHARE_LIMITS.maxSharesPerJob} VERIFIED RESULTS FOR THIS TEMPLATE`,
    'AT MOST ONE BLOCK SUBMISSION TO NODE A, NEVER RETRIED',
  ]),
  helloNotice: 'Two private MeepCoin testnet daemons are running on this computer, each allowed to talk only '
    + 'to the other over loopback. This server is configured with a SHARE difficulty no harder than the '
    + `network difficulty, so it will verify up to ${REAL_SHARE_LIMITS.maxSharesPerJob} results for this one `
    + 'template. A result that meets the share target but not the block target is checked by the server '
    + 'WebAssembly build and the native helper and then recorded: nothing is sent to a daemon for it. Only a '
    + 'result that also meets the block target is recomputed by node A and submitted, at most once, never '
    + `retried. One Start lets the one browser worker search its single issued window -- at most ${REAL_SEARCH_LIMITS.maxAttempts} `
    + `nonces or ${REAL_SEARCH_LIMITS.maxSearchMs / 1000} seconds, never rescanned -- and report up to `
    + `${REAL_SHARE_LIMITS.maxSharesPerJob} results from it, one at a time, stopping early if it finds a block. `
    + 'Test coins only; no public network.',
  readyNotice: `the server will verify up to ${REAL_SHARE_LIMITS.maxSharesPerJob} results for this template; `
    + 'at most one block submission',
  maxCandidates: REAL_SHARE_LIMITS.maxSharesPerJob,
  maxInvalidCandidates: REAL_SHARE_LIMITS.maxInvalidCandidates,
  shareWork: true,
});

/**
 * THE DEVELOPMENT SEQUENCE over the same private pair. One Start is consent for at most N sequential
 * fresh templates, each searched once under the same frozen bounds, with one candidate and one
 * submission per height. N is chosen ONCE by trusted server configuration (`realDaemon.sequenceBlocks`),
 * is a small integer, and can never exceed REAL_SEQUENCE_DEV_MAX_BLOCKS.
 *
 * THE TEXT IS GENERATED FROM N, NOT WRITTEN FOR TWO. An earlier revision hard-coded "TWO" in six places;
 * a configured sequence of twelve would have shown a page that said two and meant twelve. Everything a
 * human reads about how many blocks this run may take is now derived from the one number.
 */
const NUMBER_WORDS = Object.freeze([
  'zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve',
]);
/** A word up to twelve, then the digits. Never "many": the count is always exact. */
const countWord = (n) => NUMBER_WORDS[n] ?? String(n);

/** @param {number} blocks the configured, finite number of blocks one Start consents to. */
export function realSequenceLabels(blocks) {
  return Object.freeze([
    'REAL LOCAL DAEMONS',
    'TWO PRIVATE TESTNET NODES ON THIS COMPUTER, PAIRED ONLY WITH EACH OTHER',
    `ONE START: AT MOST ${countWord(blocks).toUpperCase()} (${blocks}) SEQUENTIAL FRESH BLOCK TEMPLATES FROM NODE A`,
    'FIXED TEST DIFFICULTY 500 (A DEVELOPMENT CONTROL)',
    'TEST COINS WITH NO MONETARY VALUE',
    'AT MOST ONE BLOCK SUBMISSION PER HEIGHT TO NODE A, NEVER RETRIED',
  ]);
}

/**
 * The profile for a sequence of exactly `blocks` blocks. Truthful for the configured number and for no
 * other: a run of one length never displays another length's text.
 */
export function realSequenceProfile(blocks) {
  if (!isSupportedSequenceBlocks(blocks) || blocks < 2) {
    throw new TypeError(`a sequence profile needs 2..${REAL_SEQUENCE_DEV_MAX_BLOCKS} blocks`);
  }
  const word = countWord(blocks);
  return Object.freeze({
    ...REAL_P2P_PROFILE,
    labels: realSequenceLabels(blocks),
    actionLabel: `Search ${word} consecutive fresh templates`,
    sequenceBlocks: blocks,
    helloNotice: 'Two private MeepCoin testnet daemons are running on this computer, each allowed to talk only '
      + 'to the other over loopback, at a FIXED TEST DIFFICULTY of 500 (a development control, not a real '
      + `network difficulty). Start is consent for at most ${word.toUpperCase()} (${blocks}) consecutive positions. `
      + `The same browser worker searches each template it actually starts at most once (at most ${REAL_SEARCH_LIMITS.maxAttempts} nonces or `
      + `${REAL_SEARCH_LIMITS.maxSearchMs / 1000} seconds). After this browser's submitted block is canonical on node A `
      + 'and node B shows it, the server may fetch the template on top of it. Each submitted block is recomputed by '
      + 'the server WebAssembly build, the native helper and node A, and submitted to node A at most once, never retried. '
      + 'If trusted local server code reports that another miner took a height first, the server confirms that exact tip '
      + 'on node A before replacing the job; it makes no node-B claim for that external block, and queued superseded '
      + 'templates may be skipped before the browser searches them. The old job can no longer do any work. Stop, hiding the tab or losing the connection '
      + 'ends the whole session. Test coins only; no public network.',
    willAllocate: 'Start allocates one browser dataset, one server Wasm dataset and one native helper dataset '
      + '(about 40 MiB each) and starts the local native helper. Before each further template the server closes '
      + 'that verifier and helper and starts a new pair for the new template, one pair at a time; the browser '
      + 'worker reuses its memory. The daemons are already running.',
    readyNotice: 'search this template at most once; at most one candidate and at most one submission for this height',
  });
}

/** At most three daemon-selected heights; the third can exercise a fresh-chain target change. */
export function realNaturalSequenceProfile(blocks) {
  if (blocks !== 2 && blocks !== 3) throw new TypeError('the natural-difficulty sequence allows two or three heights');
  return Object.freeze({
    ...realSequenceProfile(blocks),
    labels: Object.freeze(realSequenceLabels(blocks).map((label) => label.startsWith('FIXED TEST DIFFICULTY')
      ? 'DAEMON-SELECTED BLOCK DIFFICULTY AT EACH HEIGHT; NO FIXED TEST TARGET' : label)),
    helloNotice: 'Two private MeepCoin testnet daemons are running on this computer, paired only '
      + 'over loopback. No fixed-difficulty option is set: node A selects difficulty independently '
      + `for each fresh block template. One Start permits at most ${countWord(blocks)} (${blocks}) consecutive heights, one `
      + `window of ${REAL_SEARCH_LIMITS.maxAttempts} nonces or ${REAL_SEARCH_LIMITS.maxSearchMs / 1000} seconds per height. `
      + 'A block may not be found, and a harder later height will not be skipped or weakened. '
      + 'Only after A accepts a block and B reads the same canonical block may a fresh '
      + 'next-height template be issued. Every qualifying result is checked by server Wasm, '
      + 'the native helper and node A, then submitted at most once per height, never retried. '
      + 'Stop, hiding the tab or losing the connection ends the whole session. Test coins only; '
      + 'no wallet, payout or public network.',
  });
}

/**
 * THE FINITE SEQUENCE WITH OPT-IN SHARE WORK: the two features composed, not merged.
 *
 * Everything the sequence profile says about consent, rotation and one submission per height stays
 * exactly as it is. What share work adds is per-template: the server verifies up to
 * REAL_SHARE_LIMITS.maxSharesPerJob results for THAT height, one at a time, and a result that meets
 * the share target but not the block target reaches no daemon at all. Both numbers come from the
 * same shared constants the single-height share profile uses, so a page can never be shown a budget
 * the server does not hold.
 *
 * The text is generated from the configured length, like every other sequence text: a run of one
 * length never displays another length's promise.
 */
export function realSequenceShareProfile(blocks) {
  const base = realSequenceProfile(blocks);
  const word = countWord(blocks);
  return Object.freeze({
    ...base,
    labels: Object.freeze([
      ...realSequenceLabels(blocks).slice(0, 5),
      `SERVER-SIDE SHARE CHECKING: UP TO ${REAL_SHARE_LIMITS.maxSharesPerJob} VERIFIED RESULTS PER TEMPLATE`,
      'AT MOST ONE BLOCK SUBMISSION PER HEIGHT TO NODE A, NEVER RETRIED',
    ]),
    helloNotice: `${base.helloNotice} This server is also configured with a SHARE difficulty no harder than `
      + `the network difficulty, so for EACH of the at most ${word} (${blocks}) templates it will verify up to `
      + `${REAL_SHARE_LIMITS.maxSharesPerJob} results, one at a time. A result that meets the share target but not `
      + 'the block target is checked by the server WebAssembly build and the native helper and then recorded: '
      + 'nothing is sent to a daemon for it, and it does not end the search for that template.',
    readyNotice: `the server will verify up to ${REAL_SHARE_LIMITS.maxSharesPerJob} results for this template, one `
      + 'at a time; at most one block submission for this height',
    maxCandidates: REAL_SHARE_LIMITS.maxSharesPerJob,
    maxInvalidCandidates: REAL_SHARE_LIMITS.maxInvalidCandidates,
    shareWork: true,
  });
}

/**
 * THE OPT-IN SAME-HEIGHT REFRESH PROFILE: one Start, one height, several nonce windows.
 *
 * This is NOT the development sequence and must never be described as one. Nothing here moves to a
 * new height, and nothing here needs an accepted block: when the current window is exhausted
 * WITHOUT any submission having been claimed, and daemon A's canonical tip has not moved, the
 * server issues ANOTHER window of the SAME template -- a fresh jobId and issuance over a nonce range
 * that provably does not overlap any window already searched.
 *
 * Two independent caps, both from REAL_REFRESH_LIMITS, both stated before Start: the total number of
 * windows (the first included) and the whole session's wall-clock budget. Whichever is reached first
 * ends the session, and nothing restarts by itself.
 */
export function realRefreshProfile(windows, { shareWork = false, probeShareDifficulty = null } = {}) {
  if (!isSupportedRefreshWindows(windows) || windows < 2) {
    throw new TypeError(`a refresh profile needs 2..${REAL_REFRESH_LIMITS.maxWindows} windows`);
  }
  const base = shareWork ? REAL_P2P_SHARE_PROFILE : REAL_P2P_PROFILE;
  if (probeShareDifficulty !== null
    && (!shareWork || !Number.isSafeInteger(probeShareDifficulty) || probeShareDifficulty < 1)) {
    throw new TypeError('a refresh probe difficulty needs enabled share work and a positive safe integer');
  }
  const minutes = REAL_REFRESH_LIMITS.maxSessionMs / 60_000;
  const word = countWord(windows);
  const shareDifficultyNotice = probeShareDifficulty === null
    ? ''
    : ` This run's trusted startup configuration fixes share difficulty ${probeShareDifficulty}; the private `
      + 'block difficulty remains 500. A genuine block result still wins immediately and prevents a '
      + 'same-height refresh.';
  // EVERY LABEL THE BASE PROFILE STATES IS KEPT. Slicing the list by position quietly deleted the
  // share-checking disclosure from a share-enabled refresh run: the page then never said that the
  // server verifies several results per template. Only the submission label is repositioned, because
  // it must be the last thing read and it is re-stated for the height rather than for one template.
  const SUBMISSION_LABEL = 'AT MOST ONE BLOCK SUBMISSION TO NODE A, NEVER RETRIED';
  const kept = base.labels.filter((l) => !l.startsWith('AT MOST ONE BLOCK SUBMISSION'));
  return Object.freeze({
    ...base,
    labels: Object.freeze([
      ...kept,
      `ONE START: AT MOST ${word.toUpperCase()} (${windows}) NONCE WINDOWS OF THE SAME BLOCK HEIGHT, ONE AT A TIME`,
      SUBMISSION_LABEL,
    ]),
    actionLabel: `Search up to ${word} nonce windows of one template`,
    // THE ALLOCATION TEXT MUST DESCRIBE WHAT THIS RUN MAY ACTUALLY BUILD. The one-template wording it
    // inherited was true of a run that builds one verifier; this one may build up to `windows` of
    // them -- SERIALLY, never at the same time, each after the previous one's release was confirmed.
    willAllocate: `${base.willAllocate} This run may search up to ${word} (${windows}) nonce windows of the `
      + 'SAME height. Each further window is a fresh server-issued job and template and its own server '
      + 'WebAssembly verifier and native helper: they are built ONE AT A TIME, never simultaneously, and '
      + 'the previous verifier and helper are closed and their release confirmed before the next pair is '
      + 'allocated. The browser worker is re-used and re-contextualised; there is never more than one '
      + 'browser context and never more than one server verifier at any moment.',
    helloNotice: `${base.helloNotice}${shareDifficultyNotice} When a window is exhausted with nothing submitted, and node A's `
      + `canonical top has not moved, this server may issue another window of the SAME height: at most `
      + `${word} (${windows}) windows in total, within ${minutes} minutes of this Start, whichever comes `
      + 'first. Each further window is a fresh server-issued job over a nonce range that does not '
      + 'overlap any window already searched, the same one browser worker is re-used, and the server '
      + 'releases its verifier and native helper -- and confirms that release -- before the next one is '
      + `built. At most ${word} (${windows}) server-issued jobs, templates and verifier pairs for this one `
      + 'height, one at a time, never simultaneously. There is still at most ONE block submission for '
      + 'this height, and nothing restarts by itself. This is a private local development run and '
      + 'says nothing about any public network.',
    readyNotice: `${base.readyNotice}; at most ${windows} nonce windows for this height, searched one at a `
      + 'time, each with its own verifier released before the next',
    refreshWindows: windows,
    refreshSessionMs: REAL_REFRESH_LIMITS.maxSessionMs,
  });
}

/**
 * THE FINITE SEQUENCE COMPOSED WITH SAME-HEIGHT REFRESH.
 *
 * Windows are a per-height budget; the session clock is global from the one accepted Start. Every
 * successor context is serial: the previous verifier/helper is confirmed released before a refresh
 * or next-height template can be adopted, and the shared product cap keeps every retained binding
 * inside the existing fixed rings.
 */
export function realSequenceRefreshProfile(blocks, windows, { shareWork = false } = {}) {
  if (!isSupportedSequenceBlocks(blocks) || blocks < 2) {
    throw new TypeError(`a sequence refresh profile needs 2..${REAL_SEQUENCE_DEV_MAX_BLOCKS} blocks`);
  }
  if (!isSupportedRefreshWindows(windows) || windows < 2) {
    throw new TypeError(`a sequence refresh profile needs 2..${REAL_REFRESH_LIMITS.maxWindows} windows per height`);
  }
  if (!isSupportedRealContextPlan(blocks, windows)) {
    throw new TypeError(`a sequence refresh profile may issue at most ${REAL_MAX_CONTEXTS_PER_START} serial contexts`);
  }
  const base = shareWork ? realSequenceShareProfile(blocks) : realSequenceProfile(blocks);
  const blockWord = countWord(blocks);
  const windowWord = countWord(windows);
  const contexts = blocks * windows;
  const minutes = REAL_REFRESH_LIMITS.maxSessionMs / 60_000;
  const submissionLabels = base.labels.filter((label) => label.startsWith('AT MOST ONE BLOCK SUBMISSION'));
  const keptLabels = base.labels.filter((label) => !label.startsWith('AT MOST ONE BLOCK SUBMISSION'));
  return Object.freeze({
    ...base,
    labels: Object.freeze([
      ...keptLabels,
      `EACH HEIGHT: AT MOST ${windowWord.toUpperCase()} (${windows}) DISJOINT NONCE WINDOWS, ONE AT A TIME`,
      ...submissionLabels,
    ]),
    actionLabel: `Search ${blockWord} sequential heights, up to ${windowWord} nonce windows each`,
    willAllocate: `${base.willAllocate} Each of the at most ${blockWord} (${blocks}) heights may issue up to `
      + `${windowWord} (${windows}) disjoint nonce windows, but every browser context, server verifier and `
      + `native helper is replaced serially. At most ${contexts} contexts can be issued by this Start, and `
      + 'there is exactly one active context, verifier and helper at any moment.',
    helloNotice: `${base.helloNotice} At each height, when a window is exhausted with no block submission `
      + `claimed and node A's canonical tip is unchanged, the server may issue another disjoint nonce `
      + `window for that SAME height: at most ${windowWord} (${windows}) windows per height and at most `
      + `${contexts} serial contexts across this Start. The previous verifier and helper are confirmed `
      + `released before either a same-height refresh or a next-height context is built. The whole session `
      + `also ends after ${minutes} minutes from the accepted Start, whichever bound is reached first.`,
    readyNotice: `${base.readyNotice}; window 1..${windows} of this height, with each predecessor verifier `
      + 'released before its successor',
    refreshWindows: windows,
    refreshSessionMs: REAL_REFRESH_LIMITS.maxSessionMs,
  });
}

export const REAL_P2P_SEQUENCE_LABELS = realSequenceLabels(2);
export const REAL_P2P_SEQUENCE_PROFILE = realSequenceProfile(2);

/**
 * The audit vocabulary. A CLOSED SET, and every entry is BUILT, never spread.
 *
 * Two earlier revisions leaked: one put `err.message` into an audit entry, the next replaced it with
 * `err.name` -- which is just as dependency-controlled, since any thrown object may carry any name.
 * An audit entry is now constructed field by field from an explicit allowlist: a kind from this
 * list, the server-minted worker id, and values from closed vocabularies. Anything that does not
 * validate becomes `unrecognised`; nothing is copied through.
 */
export const SIM_AUDIT_KINDS = Object.freeze([
  'sim_hello', 'sim_reserved', 'sim_reserve_refused', 'sim_ready', 'sim_stop',
  'sim_candidate', 'sim_verifier_unavailable', 'simulation_complete', 'simulation_finished',
]);

/** The only failure categories an audit entry may carry. */
export const SIM_AUDIT_CATEGORIES = Object.freeze([
  'verifier_init_failed',
]);

/**
 * THE FIXED SIZES OF EVERY "a little history is needed" STRUCTURE. The shared context-plan validator
 * never authorizes more than REAL_MAX_CONTEXTS_PER_START serial issuances, so retaining every binding,
 * verifier and owned-resource fact is both truthful and absolutely bounded. Block records remain
 * bounded by the independently capped number of sequence heights. No history grows with process life.
 */
export const RETAINED_BINDINGS = REAL_MAX_CONTEXTS_PER_START;
export const RETAINED_BLOCK_RECORDS = REAL_SEQUENCE_DEV_MAX_BLOCKS;
export const RETAINED_VERIFIERS = REAL_MAX_CONTEXTS_PER_START;
export const RETAINED_RESOURCES = REAL_MAX_CONTEXTS_PER_START;

const WORKER_ID_RE = /^sim-[0-9]{1,9}-[0-9a-f]{8}$/;
const AUDIT_REASON_RE = /^[a-z][a-z0-9_]{0,63}$/;

let simWorkerCounter = 0;

/**
 * @param {object} o
 * @param {object} o.sim   the SERVER-OWNED simulation context (one per process):
 *                         { job, latch, authority, oracle, mockDaemon, ensureServerVerifier,
 *                           counters, state, reserveAttempt, ... }
 * @param {(obj:object) => void} o.send
 */
export function createSimulationSession({
  sim,
  send,
  now = () => Date.now(),
  onAudit = () => {},
  // The opt-in delayed-assignment adapter already sent server_hello before it had a job. It hands
  // the exact same connection identity into this session after assignment so the later job,
  // run_started and readiness cannot silently switch owners or worker ids. Null preserves the
  // long-standing path in which this function creates both values itself.
  sessionOwner = null,
  preauthorizedWorkerId = null,
  // A coordinator needs one notification when this assignment becomes terminal so it can close
  // the assignment-owned verifier and release capacity. Diagnostic callback failures are contained.
  onTerminal = () => {},
  // Test seams for the real-daemon search backstop. Unused by the recorded profile.
  setTimer = (fn, ms) => { const t = setTimeout(fn, ms); t.unref?.(); return t; },
  clearTimer = (t) => clearTimeout(t),
}) {
  if (sessionOwner !== null
    && ((typeof sessionOwner !== 'object' || sessionOwner === null) && typeof sessionOwner !== 'function')) {
    throw new TypeError('sessionOwner must be a non-null object identity');
  }
  if (preauthorizedWorkerId !== null && !WORKER_ID_RE.test(preauthorizedWorkerId)) {
    throw new TypeError('preauthorizedWorkerId must be a canonical simulation worker id');
  }
  if (preauthorizedWorkerId !== null && sessionOwner === null) {
    throw new TypeError('a preauthorized worker id requires its exact session owner');
  }
  if (typeof onTerminal !== 'function') throw new TypeError('onTerminal must be a function');
  // What this server CALLS things and what it bounds. The recorded profile is the previous behaviour.
  const profile = sim.profile ?? RECORDED_PROFILE;
  const VOCAB = profile.vocabulary;
  const intent = createRunIntent({ now });
  // Reference identity for this connection. Two sessions are different owners even if a client
  // reconnects and presents the same correlation token.
  const owner = sessionOwner ?? Object.freeze({});
  let authorized = preauthorizedWorkerId !== null;
  let workerId = preauthorizedWorkerId;
  let disposed = false;
  let terminalNotified = false;
  let run = null;
  let attempt = null;            // the frozen reservation this session holds, or null
  // REAL DAEMON ONLY. How many candidates were admitted into verification (at most maxCandidates),
  // and the server's backstop on the frozen search bound.
  let candidatesAdmitted = 0;
  // OPT-IN SHARE WORK ONLY. Two counters, never lists: verified results that met the share target
  // but not the block target, and results that entered verification and were refused.
  let sharesAccepted = 0;
  let invalidCandidates = 0;
  // ACROSS THE WHOLE SESSION, never reset by a rotation. In a sequence the per-template counters
  // above are rebuilt for each height -- that is what makes each height's budget its own -- so a
  // cumulative total has to be kept separately or the work of earlier heights simply disappears
  // from the record. The two are reported side by side and are never summed into one number.
  let sharesAcceptedTotal = 0;
  let invalidCandidatesTotal = 0;
  // The nonces this run has already admitted. At most profile.maxCandidates entries, cleared with
  // every other per-template counter at a rotation.
  const admittedNonces = new Set();
  // SHARE WORK ONLY. The absolute deadline has passed: no further candidate is admitted, and an
  // already-admitted one is being allowed to settle.
  let deadlineReached = false;
  let deadlineSettling = null;
  // How many OTHER candidates were refused while this issuance's irreversible claim was held. A
  // counter, for the run record; it decides nothing.
  let refusalsWhileClaimPending = 0;

  /**
   * THE ONE WAY A SHARE RUN REACHES ITS FROZEN BOUND.
   *
   * Both the backstop timer and a late frame that arrives after the deadline on the clock end up
   * here, so there is one rule instead of two that disagreed: the first of them ended the attempt
   * immediately with `search_deadline_exceeded`, which revoked intent underneath a candidate that
   * had already claimed the single submission and was awaiting its receipt, outcome or readback --
   * masking a block daemon A had accepted.
   *
   * The deadline closes NEW ADMISSION at once and nothing else. With no work in flight the run
   * finalizes immediately as a bounded no-solution; otherwise the in-flight candidate is allowed to
   * settle and publish its own real outcome first. finish() is first-write-wins, so the finalization
   * below can never overwrite an acceptance, a rejection or an explicit ambiguity.
   */
  /**
   * MAY THIS EXHAUSTED WINDOW BE REPLACED BY ANOTHER ONE, AT THE SAME HEIGHT?
   *
   * Every condition is the server's own; a client hint is never one of them. The answer is no if the
   * feature is off, if anything is still in flight, if a submission was ever claimed or started, if
   * consent is gone (Stop, hidden tab, pagehide, socket loss), if the attempt is already terminal,
   * if a rotation/refresh is already running, if the window budget is spent, or if the session's
   * wall-clock budget has passed. Daemon A's tip is checked by the issuing path itself, immediately
   * before the template request, and a moved tip is refused there.
   */
  function canRefreshWindow() {
    if (!refreshMode || disposed || sim.attemptFinished || sim.closing || sim.latch.tripped) return false;
    if (refreshing !== null || rotation !== null || acceptedPending !== null) return false;
    if (!intent.active) return false;
    if (run === null || (run.inFlight ?? 0) > 0) return false;
    // A CLAIMED OR STARTED SUBMISSION ENDS THE QUESTION. Whatever its outcome, this height already
    // had its one irreversible attempt; another window could only add work that may not submit.
    if (sim.authority.isClaimed(sim.job.issuanceId)) return false;
    if (sim.windowIndex >= refreshTotal) return false;
    if (sessionBudgetPassed()) return false;
    return true;
  }

  /**
   * ONE SAME-HEIGHT REFRESH, in the same order the block rotation uses, and for the same reasons:
   *
   *   1. the current run is retired and its search backstop cleared -- no capability survives it;
   *   2. this window's server verifier (Wasm context AND native helper) is CONFIRMED released before
   *      any successor exists;
   *   3. EXACTLY ONE further template for the SAME height is fetched on an unchanged canonical tip
   *      and published through the authority, which supersedes the old issuance irreversibly;
   *   4. a new run generation, a new run, per-window counters reset (cumulative evidence kept), and
   *      a `job_refresh` naming the previous binding;
   *   5. the next verifier, then mining_ready.
   *
   * Any failure ends the session with a named reason. Nothing is retried.
   */
  function startRefreshWindow() {
    const previous = bindingKey();
    // The window being retired, captured BEFORE the issuance advances the index: the outcome facts
    // below are pushed after the new window has been adopted, and must name the OLD one.
    const retiringWindow = sim.windowIndex;
    const outgoingRun = run;
    clearSearchTimer();
    if (outgoingRun !== null) {
      // Retire the outgoing run BEFORE the first await: its capability must be gone, and the
      // attempt must not still hold it, or the successor could not be attached.
      try { outgoingRun.dispose(); } catch { /* already released */ }
      if (!sim.detachRun(owner, outgoingRun)) {
        finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, 'internal_error', {
          type: VOCAB.failure, reason: 'internal_error', ...simulationSummary(),
        });
        return null;
      }
    }
    run = null;
    let stage = 'release';
    const work = (async () => {
      try {
        await sim.releaseVerifierForRotation(owner, 'rotating to the next nonce window');
        if (endedOrCancelledForRefresh()) return;
        stage = 'template';
        // THE GATE TRAVELS WITH THE REQUEST. A Stop, a hidden tab or a lost socket can land while the
        // template fetch is outstanding; checking only AFTER the await would already have published a
        // fresh issuance -- a live capability for a session that no longer consents. The issuing path
        // asks this immediately before it publishes, and refuses instead.
        await sim.issueRefreshWindow(owner, { stillWanted: () => refreshStillWanted() });
        if (endedOrCancelledForRefresh()) return;
        stage = 'run';
        searchDeadlineAtMs = null;
        // THE OUTGOING WINDOW'S OWN FACTS, PERSISTED BEFORE ITS COUNTERS ARE RESET. A rotation
        // rebuilds the per-window counters, and without this the only surviving record of what an
        // earlier window verified would be the session-wide cumulative total.
        windowOutcomes.push(Object.freeze({
          block: sim.blockIndex,
          window: retiringWindow,
          outcome: 'window_exhausted',
          sharesAccepted,
          candidatesAdmitted,
          invalidCandidates,
        }));
        // PER-WINDOW BOUNDS ARE REBUILT; the cumulative totals are deliberately kept.
        candidatesAdmitted = 0;
        sharesAccepted = 0;
        invalidCandidates = 0;
        admittedNonces.clear();
        refusalsWhileClaimPending = 0;
        deadlineReached = false;
        deadlineSettling = null;
        refreshesDone += 1;
        const runGeneration = intent.start();
        attempt = sim.bindAttempt(owner, { runGeneration });
        run = createCurrentRun();
        sim.attachRun(owner, run);
        rememberBinding(bindingKey());
        sendBound({
          type: 'job_refresh',
          terminal: false,
          cause: 'window_exhausted',
          ...(inSequence ? { sequenceIndex: sim.blockIndex, sequenceTotal } : {}),
          windowIndex: sim.windowIndex,
          windowTotal: refreshTotal,
          previous: { jobId: previous.jobId, issuanceId: previous.issuanceId, runGeneration: previous.runGeneration },
          job: toClientJobMessage(sim.job),
        });
        stage = 'verifier';
        const verifier = await sim.ensureServerVerifier();
        stage = 'ready';
        announceReady(verifier);
      } catch (err) {
        // A refusal BECAUSE consent went away is not a server failure: it is the cancellation the
        // page asked for, and it is reported as the stop it is.
        if (err?.code === 'refresh_cancelled') {
          // WHY it was cancelled decides what this run IS. The advertised session budget passing is
          // a bound this run reached -- `search_bound_reached`, the same terminal a spent window
          // gets -- not a page that went away; reporting it as a dispose would misdescribe a
          // completed bounded observation as an abandoned one.
          if (!sim.attemptFinished) {
            if (sessionBudgetPassed()) {
              closeSessionAtBudget();
              if (!sim.attemptFinished) {
                finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'search_bound_reached', {
                  type: VOCAB.stopped, accepted: true, reason: 'search_bound_reached',
                });
              }
            } else if (!endedOrCancelledForRefresh()) {
              finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'session_dispose', {
                type: VOCAB.stopped, accepted: true, reason: 'session_dispose',
              });
            }
          }
          return;
        }
        const code = {
          release: 'verifier_release_unconfirmed',
          template: 'next_template_refused',
          verifier: REJECT_REASONS.VERIFIER_UNAVAILABLE,
        }[stage] ?? 'internal_error';
        try { intent.revokeCurrent(code); } catch { /* nothing to revoke */ }
        finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, code, { type: VOCAB.failure, reason: code, ...simulationSummary() });
        if (stage === 'verifier') {
          audit({ kind: 'sim_verifier_unavailable', category: 'verifier_init_failed' });
          sim.recordInitFailure(err);
        }
      }
    })();
    refreshing = work;
    work.finally(() => {
      if (refreshing === work) refreshing = null;
    }).catch(() => { /* the refresh publishes its own outcome */ });
    return work;
  }

  /** Is this refresh still wanted RIGHT NOW? Asked again immediately before anything is published. */
  function refreshStillWanted() {
    return !(disposed || sim.attemptFinished || sim.closing || sim.latch.tripped
      || !consentLive || !intent.active || sessionBudgetPassed());
  }

  /** Consent and fault checks between the refresh's awaits. Identical in spirit to the rotation's. */
  function endedOrCancelledForRefresh() {
    if (sim.attemptFinished) return true;
    if (sim.latch.tripped) {
      finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, 'fatal_verifier', { type: VOCAB.failure, reason: 'fatal_verifier', ...simulationSummary() });
      return true;
    }
    if (disposed || sim.closing || !intent.active) {
      const reason = intent.revokedReason && STOP_REASONS.includes(intent.revokedReason) ? intent.revokedReason : 'session_dispose';
      finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, reason, { type: VOCAB.stopped, accepted: true, reason });
      return true;
    }
    return false;
  }

  function finalizeAtBound() {
    // A sequence block may already have been accepted while its candidate was in flight. Its
    // confirmation on B (or an explicit failure of that confirmation) owns the outcome; the
    // backstop must not turn that accepted block into a no-solution result between the candidate
    // settling and the rotation starting.
    if (disposed || sim.attemptFinished || acceptedPending !== null || rotation !== null) return;
    // THE EXHAUSTED WINDOW MAY BE REPLACED INSTEAD OF ENDING THE SESSION -- but only on the server's
    // own bounds, and only while nothing was ever submitted for this height.
    if (canRefreshWindow()) { startRefreshWindow(); return; }
    finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'search_bound_reached', {
      type: VOCAB.stopped, accepted: true, reason: 'search_bound_reached',
    });
  }
  function closeAdmissionAndSettle() {
    if (deadlineReached) return;                       // idempotent: one closure per template
    deadlineReached = true;
    if (disposed || sim.attemptFinished) return;
    const inFlightRun = run;
    if ((inFlightRun?.inFlight ?? 0) === 0) { finalizeAtBound(); return; }
    const settling = (async () => {
      try { await inFlightRun.whenIdle(); } catch { /* the run publishes its own outcome */ }
      if (run !== inFlightRun) return;
      finalizeAtBound();
    })();
    deadlineSettling = settling;
    settling.finally(() => {
      if (deadlineSettling === settling) deadlineSettling = null;
    }).catch(() => { /* the settlement cannot fail the session */ });
  }
  const shareWork = profile.shareWork === true;
  const maxInvalidCandidates = Number.isSafeInteger(profile.maxInvalidCandidates)
    ? profile.maxInvalidCandidates
    : REAL_SHARE_LIMITS.maxInvalidCandidates;
  let searchDeadlineAtMs = null;
  let searchTimer = null;
  // THE FINITE SEQUENCE (sim.sequenceTotal 2..32; 1 everywhere else, where none of this is used).
  //
  // CONSENT IS THE SESSION'S; A RUN IS THE TEMPLATE'S. `consentLive` is set by the one accepted Start and
  // cleared -- for good -- by Stop, a hidden tab, pagehide, socket loss, a fault or any terminal outcome.
  // Each template still gets its own run generation, run, candidate limit and one submission. Moving
  // from an accepted block 1 to block 2 needs consent to be live at every step of the rotation.
  const sequenceTotal = sim.sequenceTotal ?? 1;
  const inSequence = sequenceTotal > 1;
  // THE OPT-IN SAME-HEIGHT REFRESH. Both the profile (what the page was told) and the context (what
  // the server can actually issue) must agree, or there is no refresh: a profile that promised
  // windows a context cannot produce would be a false statement before Start.
  const refreshTotal = Number.isSafeInteger(profile.refreshWindows) ? profile.refreshWindows : 1;
  const refreshMode = refreshTotal > 1 && sim.refreshTotal === refreshTotal
    && isSupportedRealContextPlan(sequenceTotal, refreshTotal);
  const refreshSessionMs = Number.isSafeInteger(profile.refreshSessionMs)
    ? Math.min(profile.refreshSessionMs, REAL_REFRESH_LIMITS.maxSessionMs)
    : REAL_REFRESH_LIMITS.maxSessionMs;
  let refreshing = null;              // the in-flight same-height refresh, or null
  let refreshesDone = 0;              // windows issued AFTER the first one
  // PER-WINDOW OUTCOME FACTS, recorded as each window is retired. What the runtime actually has at
  // that moment: the window's own settled counters and the cause it ended on. Bounded by the build's
  // total context ceiling. Hashing attempts are a PAGE-side count the server never sees, so they are not
  // (and are not claimed to be) in these records.
  const windowOutcomes = [];
  let sessionDeadlineAtMs = null;     // armed at the accepted Start; never extended
  let sessionTimer = null;            // the INDEPENDENT whole-session backstop
  let sessionBudgetSpent = false;     // the advertised session budget has passed
  let consentLive = false;
  let acceptedPending = null;    // { run, ev, index, binding, handled } between acceptance and rotation
  let rotation = null;           // the in-flight rotation, or null
  // EVERY RUN THIS ATTEMPT HAD, up to the hard build-time ceiling. A delayed Stop may name any binding
  // this Start was issued, and retaining all possible bindings keeps that decision exact.
  // EVERY BLOCK THIS SESSION PRODUCED, by id, up to the same hard ceiling. The tip observer asks
  // whether daemon A's canonical tip is one of them: if it is, the acceptance and readback path owns
  // that transition and the observer must not manufacture an external-tip event for our own block.
  const ownBlockIds = [];
  function rememberOwnBlock(blockId) {
    if (typeof blockId !== 'string' || ownBlockIds.includes(blockId)) return;
    ownBlockIds.push(blockId);
    while (ownBlockIds.length > RETAINED_BINDINGS) ownBlockIds.shift();
  }

  const issuedBindings = [];
  let bindingsIssued = 0;
  function rememberBinding(b) {
    issuedBindings.push(b);
    while (issuedBindings.length > RETAINED_BINDINGS) issuedBindings.shift();
    bindingsIssued += 1;
  }

  /** Start the one whole-session clock. Idempotent: a second call changes nothing. */
  function armSessionBudget() {
    if (!refreshMode || sessionDeadlineAtMs !== null) return;
    sessionDeadlineAtMs = now() + refreshSessionMs;
    // ITS OWN TIMER, not the per-window backstop: an exhausted window may be replaced, but the
    // session's advertised minutes may not be.
    sessionTimer = setTimer(() => {
      sessionTimer = null;
      closeSessionAtBudget();
    }, refreshSessionMs);
  }

  function clearSessionTimer() {
    if (sessionTimer === null) return;
    try { clearTimer(sessionTimer); } catch { /* already gone */ }
    sessionTimer = null;
  }

  /** Has the advertised whole-session budget passed? A clock reading, not a timer's opinion. */
  function sessionBudgetPassed() {
    return sessionBudgetSpent
      || (sessionDeadlineAtMs !== null && now() >= sessionDeadlineAtMs);
  }

  /**
   * THE WHOLE SESSION'S ADVERTISED BUDGET, ENFORCED INDEPENDENTLY OF THE PER-WINDOW BOUND.
   *
   * The window budget alone is not the promise the page was given: a session that reached its last
   * permitted window could otherwise keep verifying results in it long after the advertised minutes
   * had passed, because the deadline was only consulted when ANOTHER window was being considered.
   * This closes admission the moment the budget passes -- whether or not the current window is
   * exhausted -- and ends the attempt as soon as whatever is in flight has settled, so an in-flight
   * candidate still publishes its own real outcome instead of being talked over.
   */
  function closeSessionAtBudget() {
    if (sessionBudgetSpent) return;
    sessionBudgetSpent = true;
    deadlineReached = true;                  // nothing new is admitted from here
    clearSessionTimer();
    if (disposed || sim.attemptFinished) return;
    const inFlightRun = run;
    const end = () => {
      if (disposed || sim.attemptFinished || acceptedPending !== null || rotation !== null) return;
      finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'search_bound_reached', {
        type: VOCAB.stopped, accepted: true, reason: 'search_bound_reached',
      });
    };
    if (inFlightRun === null || (inFlightRun.inFlight ?? 0) === 0) { end(); return; }
    const settling = (async () => {
      try { await inFlightRun.whenIdle(); } catch { /* the run publishes its own outcome */ }
      end();
    })();
    deadlineSettling = settling;
    settling.finally(() => {
      if (deadlineSettling === settling) deadlineSettling = null;
    }).catch(() => { /* the settlement cannot fail the session */ });
  }

  function clearSearchTimer() {
    if (searchTimer === null) return;
    try { clearTimer(searchTimer); } catch { /* already gone */ }
    searchTimer = null;
  }

  /** Construct one audit entry from an explicit allowlist. Nothing is spread or passed through. */
  function audit({ kind, reason, state, accepted, terminal, entered, category } = {}) {
    const entry = {
      kind: SIM_AUDIT_KINDS.includes(kind) ? kind : 'unrecognised',
      workerId: typeof workerId === 'string' && WORKER_ID_RE.test(workerId) ? workerId : null,
    };
    // A reason is a closed code: a stop reason, a failure code, a reservation refusal, or 'ok'.
    if (reason !== undefined) {
      const known = STOP_REASONS.includes(reason)
        || simFailureCode(reason) === reason
        || Object.values(RESERVE_REFUSED).includes(reason)
        || Object.values(NONTERMINAL).includes(reason)
        || reason === 'ok' || reason === 'complete' || reason === 'session_dispose';
      entry.reason = known && AUDIT_REASON_RE.test(reason) ? reason : 'unrecognised';
    }
    if (state !== undefined) {
      entry.state = Object.values(SIM_ATTEMPT_STATES).includes(state) ? state : 'unrecognised';
    }
    if (category !== undefined) {
      entry.category = SIM_AUDIT_CATEGORIES.includes(category) ? category : 'unrecognised';
    }
    if (accepted !== undefined) entry.accepted = accepted === true;
    if (terminal !== undefined) entry.terminal = terminal === true;
    if (entered !== undefined) entry.entered = entered === true;
    try { onAudit(entry); } catch { /* a throwing logger must not break the session */ }
  }

  function reject(reason, detail) {
    send({ type: 'error', reason, detail: detail || undefined });
    return { ok: false, reason };
  }

  /** The binding every run-scoped message repeats, so a client can prove which attempt it names. */
  function binding() {
    return {
      clientStartId: attempt?.clientStartId ?? null,
      workerId,
      jobId: sim.job.jobId,
      issuanceId: sim.job.issuanceId,
      runGeneration: attempt?.runGeneration ?? null,
    };
  }

  /** Send a run-scoped message. It is never emitted without the complete binding. */
  function sendBound(ev) {
    send({ ...ev, ...binding() });
  }

  async function handleRaw(byteLength, text) {
    if (disposed) return { ok: false, reason: 'disposed' };
    const msg = parseClientMessage(byteLength, text);
    if (!msg.ok) return reject(msg.reason, msg.detail);

    switch (msg.type) {
      case 'client_hello': return handleHello();
      case 'start_request': return handleStart(msg);
      case 'stop_request': return handleStop(msg);
      case 'submit_real_candidate': return handleCandidate(msg);
      case 'submit_share':
        // The synthetic message has no meaning here, and silently accepting it would blur the two
        // modes together.
        return reject(REJECT_REASONS.UNKNOWN_TYPE, `this server is in ${profile.mode} mode`);
      case 'ping': send({ type: 'pong' }); return { ok: true, type: 'ping' };
      case 'pong': return { ok: true, type: 'pong' };
      default: return reject(REJECT_REASONS.UNKNOWN_TYPE, msg.type);
    }
  }

  function handleHello() {
    if (authorized) return reject(REJECT_REASONS.BAD_SCHEMA, 'client_hello already sent');
    authorized = true;
    simWorkerCounter += 1;
    workerId = `sim-${simWorkerCounter}-${randomBytes(4).toString('hex')}`;

    send({
      type: 'server_hello',
      protocolVersion: PROTOCOL_VERSION,
      mode: profile.mode,
      workerId,
      labels: profile.labels,
      actionLabel: profile.actionLabel,
      // True once the one attempt has reached ANY terminal state: the process cannot make another,
      // whether it finished, was stopped, or failed. Leaving this false while the submission claim
      // was permanently held is how a page ended up offering a Start that could never succeed.
      alreadyCompleted: sim.attemptFinished,
      attemptState: sim.attemptState,
      // Said before Start, so the page can be honest before anything is allocated.
      notice: profile.helloNotice,
      willAllocate: profile.willAllocate,
      ...(profile.searchLimits ? { searchLimits: profile.searchLimits } : {}),
      ...(inSequence ? { sequenceTotal } : {}),
      // THE SAME-HEIGHT WINDOW BUDGET, SAID BEFORE START. Both caps are disclosed together, because
      // either one may be the one that ends the session.
      ...(refreshMode ? { windowTotal: refreshTotal, sessionBudgetMs: refreshSessionMs } : {}),
    });
    // Disclosing the public job costs nothing: no verifier is created and no dataset allocated.
    send(toClientJobMessage(sim.job));
    audit({ kind: 'sim_hello' });
    return { ok: true, type: 'client_hello', workerId };
  }

  /**
   * A REFUSAL BEFORE ANY RUN EXISTS. Its own closed schema, and it does not pretend otherwise:
   *
   *   clientStartId  the correlation token of the Start being refused
   *   workerId, jobId, issuanceId  values the client was already told by server_hello and real_job
   *   runGeneration  exactly null -- no run was created, so there is no generation to name
   *   reason         a closed RESERVE_REFUSED code
   *   attemptState   the server's closed attempt state
   *
   * No free-text detail: the page renders its own text from the reason code.
   */
  function refusePreRun(reason, clientStartId) {
    send({
      type: VOCAB.unavailable,
      terminal: true,
      reason,
      clientStartId,
      workerId,
      jobId: sim.job.jobId,
      issuanceId: sim.job.issuanceId,
      runGeneration: null,
      attemptState: sim.attemptState,
    });
    return { ok: false, reason };
  }

  async function handleStart(msg) {
    if (!authorized) return reject(REJECT_REASONS.NOT_AUTHORIZED, 'client_hello required first');
    // REQUIRED HERE even though the shared parser treats it as optional: the synthetic path has no
    // attempt lifecycle, this one cannot work without a correlation token.
    if (typeof msg.clientStartId !== 'string') {
      return reject(REJECT_REASONS.BAD_SCHEMA,
        'recorded-template simulation requires a clientStartId on start_request');
    }

    // ---- THE RESERVATION. Before any verifier, dataset, subscription or hash. ----------------
    const reservation = sim.reserveAttempt({ owner, clientStartId: msg.clientStartId });
    if (!reservation.ok) {
      audit({ kind: 'sim_reserve_refused', reason: reservation.reason });
      return refusePreRun(reservation.reason, msg.clientStartId);
    }

    if (reservation.idempotent) {
      // A byte-identical repeat of the Start this session already made. Re-send what it was already
      // told, and mint NOTHING: no generation, verifier, run, subscription or hash.
      if (attempt?.startedMessage) send(attempt.startedMessage);
      if (attempt?.readyMessage) send(attempt.readyMessage);
      return { ok: true, type: 'start_request', idempotent: true };
    }

    attempt = reservation.attempt;
    // A native fault that happens while this attempt holds the process -- during initialization,
    // while idle after readiness, or mid-candidate -- ends THIS attempt with one terminal failure.
    sim.setFaultListener(owner, () => {
      finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, 'fatal_verifier', {
        type: VOCAB.failure,
        reason: 'fatal_verifier',
        ...simulationSummary(),
      });
    });
    // THE ONE SESSION THAT HOLDS THE ATTEMPT is also the one an external canonical tip reaches. At most
    // one listener exists, and it is dropped when the attempt ends. The same registration carries what
    // the server-side tip observer must know about this run, and how it reports its own failure: the
    // observer never reads session state directly and cannot be reached from a client message.
    if (inSequence) {
      sim.setExternalTipListener(owner, handleExternalTip, {
        state: tipWatchState,
        onObservationFailure: handleTipObservationFailure,
      });
    }

    try {
      // (1) MINT INTENT AND ACKNOWLEDGE SYNCHRONOUSLY, before any async initialization. A client
      // that stops between Start and readiness needs a generation to bind its stop to; without this
      // acknowledgement it could only send an unbound stop, or none.
      const runGeneration = intent.start();
      attempt = sim.bindAttempt(owner, { runGeneration, intent });
      consentLive = true;
      // THE WHOLE SESSION'S WALL CLOCK STARTS AT THE ACCEPTED START, which is the moment the page
      // consented to. Anchoring it at the first readiness would silently exclude the verifier and
      // helper allocation -- minutes of it, in the worst case -- from the budget the page was shown,
      // and an allocation slower than the whole budget could still announce readiness afterwards.
      // It is armed once and never extended by a refresh.
      armSessionBudget();
      run = createCurrentRun();
      sim.attachRun(owner, run);
      rememberBinding(bindingKey());
      if (inSequence) sim.recordBlock(owner, sim.blockIndex, { runGeneration, templateFacts: sim.templateFacts });
      if (refreshMode) sim.recordBlock(owner, sim.blockIndex, { runGeneration, templateFacts: sim.templateFacts });

      const started = { type: 'run_started', mode: profile.mode, ...binding() };
      attempt = sim.rememberMessage(owner, 'startedMessage', started);
      send(started);
      audit({ kind: 'sim_reserved' });
      // The listener was registered before the run existed, but observation starts only now: after
      // explicit Start has minted a binding and a cancellable run. A scheduler/startup failure is a
      // terminal observation failure, never a silently unobserved live miner.
      if (inSequence && sim.startTipObserver(owner) !== true) {
        return { ok: false, terminal: true, reason: TIP_OBSERVATION_FAILED };
      }

      // (2) Only now the expensive part: the contextual Wasm instance AND the native helper, both
      // initialised with this job's server-owned context.
      const verifier = await sim.ensureServerVerifier();
      return announceReady(verifier);
    } catch (err) {
      intent.revokeCurrent('verifier_unavailable');
      // NOTHING FROM THE ERROR. Not its message, not its name, not its stack: every one of those is
      // whatever the thrower chose. The audit records a closed category and nothing else.
      audit({ kind: 'sim_verifier_unavailable', category: 'verifier_init_failed' });
      finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, REJECT_REASONS.VERIFIER_UNAVAILABLE, {
        type: VOCAB.unavailable,
        reason: REJECT_REASONS.VERIFIER_UNAVAILABLE,
      });
      // A source-identity refusal, a failed contextual INIT, a helper that died or lied during
      // startup: the verifier set cannot be trusted, so the process-wide latch closes. A deliberate
      // cancellation (shutdown) is not a fault and does not.
      sim.recordInitFailure(err);
      return { ok: false, reason: REJECT_REASONS.VERIFIER_UNAVAILABLE };
    }
  }

  /** The { jobId, issuanceId, runGeneration } of the run currently bound. */
  function bindingKey() {
    return Object.freeze({ jobId: sim.job.jobId, issuanceId: sim.job.issuanceId, runGeneration: attempt?.runGeneration ?? null });
  }

  /** ONE per-template run over the CURRENT job, with its own one-submission capability. */
  function createCurrentRun() {
    let created = null;
    created = createBlockRun({
      job: sim.job,
      intent,
      // THE TWO LIVE SERVER PATHS, each called exactly once per candidate by block_run, which
      // compares them itself. Each also checks the committed known answer.
      wasmVerifier: { hashOne: (n) => sim.hashOnServerWasm(n) },
      nativeVerifier: { hashOne: (n) => sim.hashOnNative(n) },
      daemon: sim.submissionDaemon,
      latch: sim.latch,
      authority: sim.authority,
      workerId,
      // A retired run may finish an already-awaited hash after an external tip. Tag every event
      // with the run that produced it so it cannot terminate or mutate the replacement run.
      emit: (ev) => onRunEvent(created, ev),
      now,
      vocabulary: VOCAB,
      canonical: sim.canonical ?? null,
    });
    return created;
  }

  /**
   * The current run's verifier is ready: begin the run, arm the search backstop and say mining_ready --
   * unless consent or intent went away while the verifier was starting, in which case nothing is begun.
   */
  function announceReady(verifier) {
    if (disposed) return { ok: false, reason: 'disposed' };
    // A trusted exact-height tip may retire the initial run while its verifier is still being
    // constructed.  That is a rotation under the same live Start consent, not a user stop.  The
    // rotation owns joining and releasing this verifier before it can issue the replacement job;
    // the superseded run must simply never be announced ready.
    if (inSequence && consentLive && rotation !== null && intent.revokedReason === 'external_tip'
        && !sim.attemptFinished) {
      return { ok: false, reason: 'superseded_before_ready' };
    }
    // A stop that arrived while we were initializing has already revoked intent. Do not create
    // work for a run the user abandoned.
    // THE BUDGET MAY HAVE PASSED WHILE THE VERIFIER WAS BEING BUILT. Announcing readiness now would
    // hand out work for a session whose advertised minutes are already spent, so the attempt ends
    // here instead and nothing is announced.
    if (refreshMode && sessionBudgetPassed()) {
      closeSessionAtBudget();
      if (!sim.attemptFinished) {
        finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'search_bound_reached', {
          type: VOCAB.stopped, accepted: true, reason: 'search_bound_reached',
        });
      }
      return { ok: false, reason: 'search_bound_reached' };
    }
    if (!intent.active || sim.attemptFinished || ((inSequence || refreshMode) && !consentLive)) {
      finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, intent.revokedReason ?? 'stopped', {
        type: VOCAB.stopped,
        reason: intent.revokedReason ?? 'stopped',
      });
      return { ok: false, reason: 'stopped_before_ready' };
    }
    run.begin();
    // begin() publishes a terminal itself if the shared latch tripped or intent is gone. If it
    // did, the attempt is already over and there is nothing to be ready for.
    if (sim.attemptFinished) return { ok: false, reason: sim.attemptReason ?? 'attempt_finished' };
    sim.markRunning(owner);
    const ready = {
      type: 'mining_ready',
      mode: profile.mode,
      ...binding(),
      nonceStart: sim.job.nonceStart,
      nonceRange: sim.job.nonceRange,
      // What the server actually holds, reported separately and never summed.
      verifierWasmHeapBytes: verifier.wasmHeapBytes(),
      verifierNativeAlgorithmBytes: verifier.nativeAlgorithmBytes(),
      nativeDatasetBytes: verifier.datasetBytes,
      nativeScratchBytes: verifier.scratchBytes,
      notice: profile.readyNotice,
      ...(profile.searchLimits ? { searchLimits: profile.searchLimits } : {}),
      ...(inSequence ? { sequenceIndex: sim.blockIndex, sequenceTotal } : {}),
      // THE SAME-HEIGHT WINDOW FACTS. `windowIndex` counts windows of THIS height, never blocks.
      ...(refreshMode ? {
        windowIndex: sim.windowIndex,
        windowTotal: refreshTotal,
        sessionBudgetMs: refreshSessionMs,
      } : {}),
    };
    attempt = sim.rememberMessage(owner, 'readyMessage', ready);
    if (profile.searchLimits) {
      // THE SERVER'S BACKSTOP on the frozen search bound, per template. The Worker stops itself at
      // maxSearchMs; if no candidate has been admitted by then plus the grace, the attempt ends here.
      const armedFor = run;
      searchDeadlineAtMs = now() + profile.searchLimits.maxSearchMs + SERVER_SEARCH_GRACE_MS;
      searchTimer = setTimer(() => {
        searchTimer = null;
        // IN SHARE WORK THIS BOUND IS ABSOLUTE FOR NEW WORK. It is armed once and never cleared by
        // an admitted candidate, so a session that keeps sending shares cannot idle past the frozen
        // bound. In every other profile the first admitted candidate disarms it, exactly as before.
        if (disposed || sim.attemptFinished || run !== armedFor) return;
        if (!shareWork) {
          if (candidatesAdmitted > 0) return;
          if (canRefreshWindow()) { startRefreshWindow(); return; }
          finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'search_bound_reached', {
            type: VOCAB.stopped, accepted: true, reason: 'search_bound_reached',
          });
          return;
        }
        // THE DEADLINE CLOSES ADMISSION IMMEDIATELY, AND ONLY ADMISSION. A candidate that is
        // already being verified -- and in particular one that has claimed the single submission
        // and is awaiting a receipt, an outcome or a canonical readback -- must be allowed to
        // SETTLE. Ending the attempt here would revoke intent and drop that candidate's own
        // terminal event, so a block daemon A had already accepted would be reported as
        // `search_bound_reached`. The wait is bounded by the same thing every other wait here is:
        // the adapter's own RPC timeouts, and nothing retries.
        closeAdmissionAndSettle();
      }, profile.searchLimits.maxSearchMs + SERVER_SEARCH_GRACE_MS);
    }
    send(ready);
    audit({ kind: 'sim_ready' });
    return { ok: true, type: 'mining_ready' };
  }

  /**
   * THE ROTATION, after block N was accepted with exact canonical readback on daemon A. Each step runs
   * only while the session's consent is still live, and each await is followed by that check:
   *
   *   1. daemon B shows exactly block N (read-only), else p2p_propagation_failed;
   *      -- if N is the last block, the session completes here --
   *   2. block N's server verifier is closed and its release CONFIRMED, else verifier_release_unconfirmed;
   *   3. EXACTLY ONE next template, for the block on top of N, published (N superseded), else
   *      next_template_refused;
   *   4. a new run generation and run, announced with sequence_next;
   *   5. the next verifier, over the new server-owned context, then mining_ready.
   *
   * Stop, a hidden tab, pagehide or a closed socket between two steps prevents every later step. A step
   * ALREADY AWAITING when it arrives is not interrupted: an in-flight read-only poll of B, the release of
   * the previous verifier, or the one read-only get_block_template request can still complete -- and that
   * template is then published through the authority -- before the post-await check ends the session; a
   * next-block verifier still starting is asked to abort, and whatever it started is owned and closed with
   * the pool. None of that can create a Worker context, a hash, a candidate or a submission for the next
   * block. Nothing here resubmits, re-searches or asks the page for anything.
   */
  async function afterAcceptedBlock(pending) {
    const index = pending.index;
    const acc = pending.ev;
    const outgoingRun = pending.run ?? run;
    // Retire the old run before the first await. Its verifier is released separately below, but its
    // intent/listener capability must already be gone so no re-entrant message can use it while a
    // propagation read or release is pending.
    if (outgoingRun && run === outgoingRun) {
      try { outgoingRun.dispose(); } catch { /* already released */ }
      if (!sim.detachRun(owner, outgoingRun)) {
        finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, 'internal_error', {
          type: VOCAB.failure, reason: 'internal_error', ...simulationSummary(),
        });
        return;
      }
      run = null;
    }
    const live = () => consentLive && !disposed && !sim.attemptFinished && !sim.closing && !sim.latch.tripped;
    const endedOrCancelled = () => {
      if (sim.attemptFinished) return true;
      if (sim.latch.tripped) {
        finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, 'fatal_verifier', { type: VOCAB.failure, reason: 'fatal_verifier', ...simulationSummary() });
        return true;
      }
      if (!live()) {
        const reason = intent.revokedReason && STOP_REASONS.includes(intent.revokedReason) ? intent.revokedReason : 'session_dispose';
        finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, reason, { type: VOCAB.stopped, accepted: true, reason });
        return true;
      }
      return false;
    };
    // AN EXTERNAL TIP IS NOT THIS SESSION'S BLOCK. Nothing about it is verified here, nothing is claimed
    // for it and daemon B's view of it is irrelevant: the only question is whether this run may be
    // replaced by one for the block ON TOP of it.
    const external = pending.external === true;
    let stage = external ? 'release' : 'propagation';
    try {
      if (!external) {
        const p = await sim.awaitBlockOnPeer(owner, { index, height: acc.height, blockId: acc.blockId, shouldContinue: live });
        if (endedOrCancelled()) return;
        if (p.converged !== true) {
          finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, 'p2p_propagation_failed', {
            type: VOCAB.failure, reason: 'p2p_propagation_failed', ...simulationSummary(),
          });
          return;
        }
      }
      if (index >= sequenceTotal) {
        if (external) {
          // The configured sequence is spent and the height we were on belongs to someone else. There is
          // no further template this Start consented to, so the session ends -- it does not idle.
          finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'external_tip_superseded', {
            type: VOCAB.failure, reason: 'external_tip_superseded', ...simulationSummary(),
          });
          return;
        }
        finish(SIM_ATTEMPT_STATES.TERMINAL_COMPLETE, 'complete', { ...acc, type: VOCAB.success, ...simulationSummary() });
        audit({ kind: 'simulation_complete' });
        return;
      }

      // THE WHOLE-START CLOCK MAY EXPIRE WHILE AN ACCEPTED NON-FINAL BLOCK IS BEING OBSERVED ON
      // PEER B.  Let that already-admitted block finish its canonical and propagation evidence, but
      // do not turn an expired Start into authority to fetch a successor template or allocate its
      // verifier.  The outgoing verifier is still our resource, so confirm its release before
      // publishing the bounded terminal.  A release failure continues to outrank the ordinary
      // bound in the catch path below.
      if (sessionBudgetPassed()) {
        // The clock is authoritative even if its timer callback is delayed (for example by a
        // suspend/resume or a busy event loop).  Adopt that same observation into the durable
        // session fact before ending this accepted-prefix run.  `rotation` is still live here, so
        // closeSessionAtBudget closes admission but deliberately cannot talk over this block's
        // propagation/release evidence; this branch remains the one that publishes the terminal.
        closeSessionAtBudget();
        stage = 'release';
        clearSearchTimer();
        if (endedOrCancelled()) return;
        await sim.releaseVerifierForRotation(owner, 'whole-session budget reached after accepted block');
        if (endedOrCancelled()) return;
        finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'search_bound_reached', {
          type: VOCAB.stopped, accepted: true, reason: 'search_bound_reached', ...simulationSummary(),
        });
        return;
      }

      stage = 'release';
      clearSearchTimer();
      if (endedOrCancelled()) return;
      await sim.releaseVerifierForRotation(owner);
      if (endedOrCancelled()) return;
      // Release is itself asynchronous. The whole-Start clock can expire after the pre-release
      // check, so consult it again before even asking daemon A for another template.
      if (sessionBudgetPassed()) {
        // As above, make a delayed timer indistinguishable in the evidence from an on-time timer:
        // the same clock gate stopped successor issuance, so sessionBudgetSpent must record it.
        closeSessionAtBudget();
        finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'search_bound_reached', {
          type: VOCAB.stopped, accepted: true, reason: 'search_bound_reached', ...simulationSummary(),
        });
        return;
      }

      stage = 'template';
      // The final gate travels through the awaited RPC to the point immediately before authority
      // publication. This prevents expiry (or lost consent) during get_block_template from creating
      // an unusable successor issuance.
      await sim.issueNextBlock(owner, {
        acceptedBlockId: acc.blockId,
        acceptedHeight: acc.height,
        // An external-tip rotation deliberately revokes the retired per-template intent before
        // reaching this point; the still-live whole-session consent, not that retired run flag,
        // authorises its successor. Stop/hidden/pagehide/socket loss all clear consentLive.
        stillWanted: () => live() && !sessionBudgetPassed(),
      });
      if (endedOrCancelled()) return;
      // A deterministic or advancing clock may cross the boundary immediately after publication.
      // The publication cannot be revoked, but no successor binding, run, Worker context or verifier
      // may be created once the advertised Start budget is spent.
      if (sessionBudgetPassed()) {
        finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'search_bound_reached', {
          type: VOCAB.stopped, accepted: true, reason: 'search_bound_reached', ...simulationSummary(),
        });
        return;
      }

      // A NEW PER-TEMPLATE RUN under the same, still-live consent. Synchronous from the check above.
      stage = 'run';
      const previous = pending.binding;
      searchDeadlineAtMs = null;
      // EVERY PER-TEMPLATE BOUND IS REBUILT FOR THE NEW HEIGHT, and only the per-template ones:
      // the share budget, the replay set that makes a repeated nonce cheap to refuse, the invalid
      // allowance and the absolute deadline all belong to the template that is being replaced. The
      // cumulative totals above are deliberately NOT cleared.
      candidatesAdmitted = 0;
      sharesAccepted = 0;
      invalidCandidates = 0;
      admittedNonces.clear();
      refusalsWhileClaimPending = 0;
      deadlineReached = false;
      deadlineSettling = null;
      const runGeneration = intent.start();
      attempt = sim.bindAttempt(owner, { runGeneration });
      run = createCurrentRun();
      sim.attachRun(owner, run);
      rememberBinding(bindingKey());
      sim.recordBlock(owner, sim.blockIndex, { runGeneration });
      sendBound({
        type: 'sequence_next',
        sequenceIndex: sim.blockIndex,
        sequenceTotal,
        ...(refreshMode ? {
          windowIndex: sim.windowIndex,
          windowTotal: refreshTotal,
          sessionBudgetMs: refreshSessionMs,
        } : {}),
        // WHY this rotation happened. 'accepted' is this session's own block; 'external_tip' is another
        // miner's block at the height this run was searching.
        cause: external ? 'external_tip' : 'accepted',
        previous: { jobId: previous.jobId, issuanceId: previous.issuanceId, runGeneration: previous.runGeneration },
        job: toClientJobMessage(sim.job),
      });

      stage = 'verifier';
      const verifier = await sim.ensureServerVerifier();
      stage = 'ready';
      announceReady(verifier);
    } catch (err) {
      // A next-height request cancelled at its pre-publication gate is an ordinary session-bound or
      // consent outcome, never a template/server failure. In particular, deadline expiry must retain
      // the truthful bounded-run result and must not be mislabeled next_template_refused.
      if (err?.code === 'sequence_cancelled') {
        if (!sim.attemptFinished) {
          if (sessionBudgetPassed()) {
            finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'search_bound_reached', {
              type: VOCAB.stopped, accepted: true, reason: 'search_bound_reached', ...simulationSummary(),
            });
          } else {
            endedOrCancelled();
          }
        }
        return;
      }
      const code = {
        propagation: 'p2p_propagation_failed',
        release: 'verifier_release_unconfirmed',
        template: 'next_template_refused',
        verifier: REJECT_REASONS.VERIFIER_UNAVAILABLE,
      }[stage] ?? 'internal_error';
      try { intent.revokeCurrent(code); } catch { /* nothing to revoke */ }
      if (!sim.attemptFinished) {
        sim.recordBlock(owner, sim.blockIndex, { rotationFailure: { stage, code, detailCode: typeof err?.code === 'string' ? err.code.slice(0, 64) : null } });
      }
      finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, code, { type: VOCAB.failure, reason: code, ...simulationSummary() });
      if (stage === 'verifier') {
        audit({ kind: 'sim_verifier_unavailable', category: 'verifier_init_failed' });
        sim.recordInitFailure(err);
      }
    }
  }

  /**
   * Every event the run publishes, bound and gated.
   *
   * Nothing is emitted once the attempt is terminal, and a rejected candidate ENDS the attempt:
   * this mode issues exactly one nonce, so a refused candidate leaves nothing that could still
   * succeed, and leaving the page displaying a live run with an idle Worker would be a lie.
   */
  function onRunEvent(sourceRun, ev) {
    // Events from a synchronously retired external-tip run are quarantined. Revocation still lets
    // its own promise settle, but no late failure/found/accepted frame can affect the new binding.
    if (sourceRun !== run) return;
    if (sim.attemptFinished) return;
    if (ev.type === VOCAB.success && inSequence) {
      // A BLOCK OF THE SEQUENCE, NOT THE END OF THE SESSION. Recorded and announced as nonterminal;
      // handleCandidate then runs the rotation (or completes the session after the last block) once
      // daemon B has shown this exact block. Nothing may rotate on anything but this run's success.
      acceptedPending = { run, ev, index: sim.blockIndex, binding: bindingKey(), handled: false };
      rememberOwnBlock(ev.blockId);
      sim.recordBlock(owner, sim.blockIndex, {
        accepted: {
          height: ev.height, nonce: ev.nonce, hashHexLE: ev.hashHexLE, blockId: ev.blockId,
          confirmedBy: ev.confirmedBy, jobId: sim.job.jobId, issuanceId: sim.job.issuanceId, atMs: now(),
        },
        lastHashes: { ...sim.lastHashes },
      });
      sendBound({ ...ev, type: 'sequence_block_accepted', terminal: false, sequenceIndex: sim.blockIndex, sequenceTotal });
      return;
    }
    if (ev.type === VOCAB.success) {
      finish(SIM_ATTEMPT_STATES.TERMINAL_COMPLETE, 'complete', { ...ev, ...simulationSummary() });
      audit({ kind: 'simulation_complete' });
      return;
    }
    if (ev.type === VOCAB.failure) {
      finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, ev.reason ?? 'failed', { ...ev, ...simulationSummary() });
      return;
    }
    if (shareWork && ev.type === VOCAB.shareAccepted) {
      // A VERIFIED SHARE THAT IS NOT A BLOCK. Nonterminal by construction: no daemon call happened
      // for it, the one submission claim is untouched, and the run stays open until the absolute
      // search bound, the candidate cap, a block, or any ordinary terminal event.
      sharesAccepted += 1;
      sharesAcceptedTotal += 1;
      sendBound({
        ...ev,
        terminal: false,
        // THIS TEMPLATE's count, and the session's, distinctly. A client that only ever sees one
        // template reads the same number twice; a sequence client can tell the two apart.
        sharesAccepted,
        sharesAcceptedTotal,
        ...(inSequence ? { sequenceIndex: sim.blockIndex, sequenceTotal } : {}),
      });
      return;
    }
    if (ev.type === VOCAB.candidateRejected) {
      // ALWAYS NONTERMINAL ON THE WIRE. Whether the attempt ends is said by a separate, explicit
      // terminal message -- never inferred from a rejection.
      sendBound({ ...ev, terminal: false });
      if (ev.entered !== true) {
        // A forged, stale or mismatched candidate that never entered verification. It cost zero
        // hashes and zero transport calls, and it must not spend the real attempt.
        return;
      }
      if (shareWork && sim.authority.isClaimed(sim.job.issuanceId) && run !== null && run.complete !== true) {
        // THE CLAIM HOLDER DECIDES, AND NOTHING ELSE DOES. Once the one irreversible submission
        // claim for this issuance is held and its run has not yet published a terminal, that
        // candidate is awaiting a receipt, an outcome or a canonical readback. Every OTHER
        // candidate's refusal -- above the share target, a daemon that could not recompute, an
        // issuance that moved on, or losing the claim race itself -- is still reported on the wire,
        // but none of them may end the attempt: doing so publishes a failure over an acceptance
        // that has not been announced yet. The claimant's own result, or its explicit ambiguity
        // code, is the outcome.
        //
        // NOT SWALLOWED: a verifier disagreement or a process-wide fatal latch is a TERMINAL run
        // event, not a candidate refusal, and takes the failure path below untouched.
        refusalsWhileClaimPending += 1;
        return;
      }
      if (shareWork && ev.reason === NONTERMINAL.ALREADY_CLAIMED
          && sim.authority.isClaimed(sim.job.issuanceId)) {
        // QUARANTINED, AND NOT COUNTED AGAINST ANY CAP. Every loser of the claim race is already
        // bounded by the admission cap itself -- there can never be more losers than admitted
        // candidates -- and counting them would let four losers end the attempt while the WINNER is
        // still awaiting its receipt, outcome or readback, which is precisely the acceptance this
        // quarantine exists to protect. The claim holder decides the final outcome.
        return;
      }
      if (shareWork && ev.reason === NONTERMINAL.ABOVE_TARGET) {
        // THE ONLY BENIGN ENTERED REFUSAL. A result that was verified and simply did not meet the
        // share target costs the daemon nothing and says nothing about any submission, so one of
        // them is not the end of a share run -- but an unbounded stream of them would be endless
        // verification work, so they are capped.
        //
        // EVERY OTHER entered refusal keeps its terminal handling. `submission_already_claimed`,
        // `issuance_superseded` and `daemon_unavailable` are all about the BLOCK path: the first
        // two mean another candidate holds or held the one submission, and swallowing them would
        // let a later result talk over an acceptance or a readback that is already in flight.
        invalidCandidates += 1;
        invalidCandidatesTotal += 1;
        if (invalidCandidates < maxInvalidCandidates) return;
        finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, 'invalid_share_limit_reached', {
          type: VOCAB.failure,
          reason: 'invalid_share_limit_reached',
          ...simulationSummary(),
        });
        return;
      }
      // The ONE issued candidate entered verification and was refused. Nothing else can succeed.
      finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, ev.reason ?? NONTERMINAL.BAD_CANDIDATE, {
        type: VOCAB.failure,
        reason: ev.reason ?? NONTERMINAL.BAD_CANDIDATE,
        ...simulationSummary(),
      });
      return;
    }
    sendBound(ev);
  }

  /**
   * End the one attempt, send its final message, and release everything it held. Idempotent: the
   * first caller decides, and exactly one terminal message goes out.
   */
  function notifyTerminal(state, reason) {
    if (terminalNotified) return false;
    terminalNotified = true;
    try {
      const terminalNotice = onTerminal(Object.freeze({
        owner,
        clientStartId: attempt?.clientStartId ?? null,
        state,
        reason,
      }));
      if (terminalNotice && typeof terminalNotice.then === 'function') {
        Promise.resolve(terminalNotice).then(() => {}, () => {});
      }
    } catch { /* coordinator notification cannot change the already-terminal run */ }
    return true;
  }

  function finish(state, reason, message) {
    const first = sim.finishAttempt(owner, state, reason);
    consentLive = false;
    if (!first) return false;
    clearSearchTimer();
    clearSessionTimer();
    // A successor verifier still starting -- the next block's, or the next window's -- is abandoned,
    // not completed. Without this a refresh whose verifier was mid-initialisation when the user
    // stopped would finish building it and announce readiness for work nobody consented to.
    if (inSequence || refreshMode) { try { sim.abortPendingInit(owner); } catch { /* nothing starting */ } }
    if (run) { try { run.dispose(); } catch { /* already released */ } }
    try { intent.revokeCurrent(reason); } catch { /* nothing to revoke */ }
    if (message) sendBound({ ...message, terminal: true });
    audit({ kind: 'simulation_finished', state, reason });
    notifyTerminal(state, reason);
    return true;
  }

  function handleStop(msg) {
    if (!authorized) return reject(REJECT_REASONS.NOT_AUTHORIZED, 'client_hello required first');
    if (msg.workerId !== workerId) return reject(REJECT_REASONS.UNKNOWN_WORKER, 'not this connection');
    // ANY SESSION THAT HANDS WORK OVER NEEDS SESSION-WIDE STOP SCOPE. A refresh run replaces the job
    // and the run generation exactly as a sequence does, so a Stop the page sent for the window it
    // was actually searching may arrive after the handover. Judging it against only the CURRENT
    // issuance would answer `unknown_job` and leave the session mining after the user said stop.
    if (inSequence || refreshMode) return handleSessionStop(msg);
    if (msg.jobId !== sim.job.jobId || msg.issuanceId !== sim.job.issuanceId) {
      return reject(REJECT_REASONS.UNKNOWN_JOB, 'stop names a different issuance');
    }
    // A stop must name the attempt it means. Without this, a stop queued by an abandoned attempt
    // would revoke whatever happened to be running.
    if (attempt === null || msg.clientStartId !== attempt.clientStartId) {
      return reject(REJECT_REASONS.BAD_SCHEMA, 'stop names a different start attempt');
    }
    const r = intent.revoke(msg.runGeneration, msg.reason);
    const accepted = r.ok === true;
    if (accepted) {
      finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, msg.reason, {
        type: VOCAB.stopped,
        accepted: true,
        reason: msg.reason,
      });
    } else {
      sendBound({ type: VOCAB.stopped, accepted: false, reason: msg.reason });
    }
    audit({ kind: 'sim_stop', accepted, reason: msg.reason });
    return { ok: true, type: 'stop_request', accepted };
  }

  /**
   * STOP IN A HANDOVER SESSION ENDS THE WHOLE SESSION. A stop may name ANY run binding this Start was
   * issued -- the page may still hold block 1's (or window 1's) binding while the server has already
   * moved on -- and it revokes the session's consent and whichever run is current. Stop only ever
   * removes capability; a binding from another Start, worker or issuance is still refused.
   */
  function handleSessionStop(msg) {
    const named = issuedBindings.some((b) => b.jobId === msg.jobId && b.issuanceId === msg.issuanceId
      && b.runGeneration === msg.runGeneration);
    if (attempt === null || msg.clientStartId !== attempt.clientStartId) {
      return reject(REJECT_REASONS.BAD_SCHEMA, 'stop names a different start attempt');
    }
    if (!named) return reject(REJECT_REASONS.UNKNOWN_JOB, 'stop names a run this start was not issued');
    consentLive = false;
    try { intent.revokeCurrent(msg.reason); } catch { /* nothing to revoke */ }
    const accepted = finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, msg.reason, {
      type: VOCAB.stopped,
      accepted: true,
      reason: msg.reason,
    });
    if (!accepted) sendBound({ type: VOCAB.stopped, accepted: false, reason: msg.reason });
    audit({ kind: 'sim_stop', accepted, reason: msg.reason });
    return { ok: true, type: 'stop_request', accepted };
  }

  /**
   * AN EXTERNAL CANONICAL TIP TOOK THE HEIGHT THIS RUN IS SEARCHING.
   *
   * Not every block this session mines: a block from anywhere -- another miner, the paired daemon, an
   * operator -- that makes the current template's height already spent. The server's tip source calls
   * this; a page cannot, because nothing reaches it from a client message.
   *
   * The active job is superseded (the next template is published through the same authority, so a late
   * candidate for the old one is refused before any hash, RPC or claim), its verifier is physically
   * released FIRST, and a fresh job is issued only while this session's consent is still live. If the
   * configured sequence is spent, or consent is gone, the session ends instead: nothing idles waiting.
   *
   * @returns {Promise<{ok:boolean, reason?:string}>}
   */
  /**
   * WHAT THE SERVER-SIDE TIP OBSERVER IS ALLOWED TO KNOW: whether there is a live consented run,
   * whether this session is in the middle of its own work, which job it is on, and whether a given
   * block id is one this session produced. Values only -- no run, no intent, no message and no way
   * to change anything through it.
   *
   * `busy` is the OWN-BLOCK FENCE. While a candidate is in flight, a block has been accepted but not
   * yet rotated past, or a rotation is running, the observer skips the cycle entirely, so this
   * session's own submission settling on daemon A can never be read as somebody else's tip.
   */
  function tipWatchState() {
    return {
      active: inSequence && consentLive && !disposed && !sim.attemptFinished && !sim.closing,
      busy: refreshing !== null || rotation !== null || acceptedPending !== null
        || run === null || (run.inFlight ?? 0) > 0,
      jobId: sim.job.jobId,
      jobHeight: sim.job.height.toString(),
      parentBlockId: sim.canonical?.prevHashHex ?? null,
      isOwnBlock: (blockId) => ownBlockIds.includes(blockId),
    };
  }

  /**
   * THE OBSERVER COULD NOT OBSERVE. A daemon read that failed or answered malformed bytes means this
   * session can no longer be told that the chain moved under it, so the browser must not keep
   * hashing. The attempt ends, closed, with the one closed code for it; nothing retries.
   */
  function handleTipObservationFailure(code, detail) {
    if (!inSequence || disposed || sim.attemptFinished) return { ok: false, reason: 'no_live_run' };
    const reason = code === TIP_PARENT_CHANGED ? TIP_PARENT_CHANGED : TIP_OBSERVATION_FAILED;
    try { intent.revokeCurrent(reason); } catch { /* nothing to revoke */ }
    clearSearchTimer();
    sim.recordBlock(owner, sim.blockIndex, {
      tipObservationFailure: { code: reason, detail: String(detail ?? '').slice(0, 240), atMs: now() },
    });
    finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, reason, {
      type: VOCAB.failure, reason, ...simulationSummary(),
    });
    return { ok: true, reason };
  }

  async function handleExternalTip({ height, blockId } = {}) {
    if (!inSequence) return { ok: false, reason: 'not_a_sequence' };
    if (disposed || sim.attemptFinished || !consentLive || run === null || attempt === null) {
      return { ok: false, reason: 'no_live_run' };
    }
    if (refreshing !== null || rotation !== null || acceptedPending !== null) {
      return { ok: false, reason: 'between_templates' };
    }
    if (typeof blockId !== 'string' || !/^[0-9a-f]{64}$/.test(blockId)) return { ok: false, reason: 'bad_tip' };
    if (typeof height !== 'string' || !/^(?:0|[1-9][0-9]{0,19})$/.test(height)) {
      return { ok: false, reason: 'bad_tip' };
    }
    const tipHeight = BigInt(height);
    const jobHeight = BigInt(sim.job.height);
    if (tipHeight < jobHeight) return { ok: false, reason: 'tip_behind' };
    if (tipHeight > jobHeight) {
      // We cannot safely guess or silently catch up across skipped templates. But work on this old
      // parent is definitely stale, so revoke it synchronously and end the finite session.
      intent.revokeCurrent('external_tip');
      clearSearchTimer();
      sim.recordBlock(owner, sim.blockIndex, {
        externalTip: { height: String(height), blockId, atMs: now(), ahead: true },
      });
      finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'external_tip_superseded', {
        type: VOCAB.failure, reason: 'external_tip_superseded', ...simulationSummary(),
      });
      return { ok: true, reason: 'tip_ahead_session_stopped' };
    }
    const outgoingRun = run;
    const pending = {
      external: true,
      run: outgoingRun,
      ev: { height: String(height), blockId },
      index: sim.blockIndex,
      binding: bindingKey(),
      handled: true,
    };
    // SYNCHRONOUS SUPERSESSION FENCE, before release, RPC, template fetch or any other await.
    // A candidate arriving after this point sees the session between templates; the old run's own
    // intent is already false as a second independent fence.
    intent.revokeCurrent('external_tip');
    clearSearchTimer();
    sim.recordBlock(owner, sim.blockIndex, { externalTip: { height: String(height), blockId, atMs: now() } });
    // Quarantine every later event from the outgoing run immediately, but do not release its
    // verifier while an admitted hash/RPC/submission is still executing. Once that exact operation
    // settles, issueNext() re-reads daemon A and proves the supplied foreign block is really current.
    try { outgoingRun.dispose(); } catch { /* already released */ }
    if (!sim.detachRun(owner, outgoingRun)) {
      finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, 'internal_error', {
        type: VOCAB.failure, reason: 'internal_error', ...simulationSummary(),
      });
      return { ok: false, reason: 'internal_error' };
    }
    run = null;
    rotation = (async () => {
      await outgoingRun.whenIdle();
      await afterAcceptedBlock(pending);
    })();
    try {
      await rotation;
    } finally {
      rotation = null;
    }
    const reason = sim.attemptFinished ? (sim.attemptReason ?? 'ended') : 'rotated';
    // The trusted observation itself was well-formed, but a failed rotation is not a successful
    // operation. Keep terminal cancellations (spent sequence, shutdown) distinct from a release,
    // template or verifier failure that prevented the requested rotation.
    return { ok: sim.attemptState !== SIM_ATTEMPT_STATES.TERMINAL_FAILED, reason };
  }

  async function handleCandidate(msg) {
    if (!authorized) return reject(REJECT_REASONS.NOT_AUTHORIZED, 'client_hello required first');
    if (attempt === null) return reject(REJECT_REASONS.NOT_STARTED, 'start_request required first');
    if (msg.clientStartId !== attempt.clientStartId) {
      return reject(REJECT_REASONS.BAD_SCHEMA, 'candidate names a different start attempt');
    }
    if (sim.attemptFinished) {
      return reject(REJECT_REASONS.NOT_STARTED, 'this attempt is over');
    }
    // BETWEEN TEMPLATES NOTHING IS ADMITTED: not a late block-1 candidate, not a guess at block 2.
    if ((inSequence || refreshMode) && (rotation !== null || acceptedPending !== null || refreshing !== null)) {
      return reject(REJECT_REASONS.NOT_STARTED, 'the session is between templates');
    }
    // THE ADVERTISED SESSION BUDGET IS A BOUND ON THE WHOLE START, not only on how many windows may
    // be issued. A result that arrives after it is refused before any hash, RPC or claim, and the
    // session is closed on the same reading of the clock.
    if (refreshMode && sessionBudgetPassed()) {
      closeSessionAtBudget();
      return reject('search_bound_reached', 'the session time budget has passed');
    }
    // A missing run outside the explicit rotation state is never usable. Keep this after the
    // between-templates check so a synchronously detached outgoing run still receives the exact,
    // stable refusal that describes the state it is in.
    if (!run) return reject(REJECT_REASONS.NOT_STARTED, 'start_request required first');
    if (profile.maxCandidates !== null) {
      // AT MOST ONE CANDIDATE ENTERS VERIFICATION. Only a candidate that names this very run and a
      // nonce inside its issued window counts against the limit, so a forged or stale one cannot
      // spend it; every later one is refused before block_run sees it.
      const binds = msg.jobId === sim.job.jobId && msg.issuanceId === sim.job.issuanceId
        && msg.workerId === workerId && msg.runGeneration === attempt.runGeneration
        && Number.isInteger(msg.nonce) && msg.nonce >= sim.job.nonceStart
        && msg.nonce < sim.job.nonceStart + sim.job.nonceRange;
      if (binds && shareWork && (run.inFlight ?? 0) > 0) {
        // SERIAL VERIFICATION, AND IT IS A CORRECTNESS FENCE, NOT A POLICY.
        //
        // Share mode admits several candidates for one template, but they all share ONE
        // createBlockRun, and block_run's gates publish a TERMINAL for the whole run: a second
        // candidate that reaches runGate() after an expiry or a revocation calls
        // publishTerminal(EXPIRED/REVOKED) and, with it, ends the run that a first candidate's
        // claimed submission is still awaiting a daemon answer for. No filtering of events in this
        // session can undo that -- the run itself is already terminal. The only sound fix at this
        // layer is not to have two candidates inside one run at the same time.
        //
        // So while any candidate is in flight, a later bound frame is refused CHEAPLY here: before
        // the deadline check, before the duplicate check, before the budget, before any hash and
        // before any daemon RPC. It costs nothing, it is nonterminal, and the nonce is not spent --
        // the client may send it again once the slot is free. There is no queue of any kind; the
        // browser side (Round 1b) paces its at-most-eight reports and submits them sequentially.
        return reject(REJECT_REASONS.QUEUE_FULL,
          'another result for this template is being verified; retry when it has settled');
      }
      if (binds && shareWork && deadlineReached) {
        // AFTER THE DEADLINE NOTHING NEW IS ADMITTED. This is what keeps the bound absolute while
        // an in-flight candidate settles: a late result cannot start verification, cannot claim the
        // submission, and therefore cannot talk over the outcome of the candidate that did.
        return reject('search_bound_reached', 'the frozen search bound has passed for this template');
      }
      if (binds) {
        // A REPEAT OF AN ALREADY ADMITTED NONCE IS NOT A NEW CANDIDATE. block_run refuses it on its
        // own cheap fence, but only AFTER this counter had already spent a slot, so seven repeats of
        // one nonce could exhaust an eight-candidate budget without a single hash. The set is
        // written synchronously, in the same turn as the counter, so two concurrent frames cannot
        // both see the nonce as new; it is bounded by maxCandidates entries, which is the same bound
        // the budget itself has.
        // SHARE MODE ONLY. In a one-candidate profile the second frame for the same nonce has
        // always been answered `candidate_limit_reached`, and this opt-in feature must not change
        // that reply.
        if (shareWork && admittedNonces.has(msg.nonce)) {
          return reject(NONTERMINAL.DUPLICATE, 'this nonce was already admitted for this run');
        }
        if (candidatesAdmitted >= profile.maxCandidates) {
          return reject('candidate_limit_reached', 'the one candidate for this run was already admitted');
        }
        if (searchDeadlineAtMs !== null && now() > searchDeadlineAtMs) {
          if (shareWork) {
            // The same closure the timer performs, whichever notices the deadline first. This frame
            // is refused; it never terminalizes over an in-flight claim.
            closeAdmissionAndSettle();
            return reject('search_bound_reached', 'the frozen search bound has passed for this template');
          }
          finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, 'search_deadline_exceeded', {
            type: VOCAB.failure,
            reason: 'search_deadline_exceeded',
            ...simulationSummary(),
          });
          return { ok: false, terminal: true, reason: 'search_deadline_exceeded' };
        }
        candidatesAdmitted += 1;
        admittedNonces.add(msg.nonce);
        if (!shareWork) clearSearchTimer();
      }
    }
    const thisRun = run;
    const result = await thisRun.submitCandidate({
      jobId: msg.jobId,
      issuanceId: msg.issuanceId,
      workerId: msg.workerId,
      runGeneration: msg.runGeneration,
      nonce: msg.nonce,
    });
    audit({
      kind: 'sim_candidate', reason: result.reason ?? 'ok', terminal: result.terminal, entered: result.entered,
    });
    // The eighth admitted result can be an ordinary share. At that point the browser's Worker has
    // stopped at its frozen share cap and there is no ninth result that could find a block. Close
    // the attempt now, AFTER the last verification slot is free. Never let this bounded no-solution
    // outcome overtake a block accepted by this candidate: that block owns peer confirmation and
    // rotation (or the final terminal result).
    if (shareWork && candidatesAdmitted >= profile.maxCandidates && !disposed && !sim.attemptFinished
      && run === thisRun && (thisRun.inFlight ?? 0) === 0 && acceptedPending === null
      && rotation === null) {
      finalizeAtBound();
    }
    // ---- THE PACING CUE, AND WHY IT IS NOT `share_accepted` -------------------------------------
    //
    // `share_accepted` is emitted from INSIDE block_run, while this candidate is still counted in
    // run.inFlight. A client that released its next queued result on that event would have it
    // refused `queue_full` by the serial fence -- every time. The cue below is emitted only AFTER
    // submitCandidate has returned AND the run reports nothing in flight, which is exactly the
    // moment the verification slot is free again.
    //
    // It is a NONTERMINAL hint about capacity and nothing else: it carries the nonce that settled,
    // it is fully bound like every other run-scoped message, and it is never sent once the attempt
    // is terminal, the deadline has closed admission, a rotation is running, or the budget is
    // spent -- in those cases a client has nothing useful to send and the server's own terminal
    // message supersedes anything this cue would have implied.
    if (shareWork && !disposed && !sim.attemptFinished && run === thisRun
      && (thisRun.inFlight ?? 0) === 0 && !deadlineReached && rotation === null
      && acceptedPending === null && candidatesAdmitted < profile.maxCandidates) {
      sendBound({
        type: 'candidate_settled',
        terminal: false,
        nonce: msg.nonce,
        candidatesAdmitted,
        maxCandidates: profile.maxCandidates,
      });
    }
    // THIS run's success, exactly once: B's check, then the rotation or the session's completion. This
    // operation stays admitted until that finishes, so pool shutdown drains it.
    if (inSequence && acceptedPending !== null && acceptedPending.run === thisRun && !acceptedPending.handled) {
      const pending = acceptedPending;
      pending.handled = true;
      rotation = afterAcceptedBlock(pending);
      try {
        await rotation;
      } finally {
        rotation = null;
        if (acceptedPending === pending) acceptedPending = null;
      }
    }
    return result;
  }

  /** Measured counters, attached to the terminal event so a human can check them. */
  function simulationSummary() {
    return profile.summary(sim);
  }

  return {
    handleRaw,
    /** The server's tip source only. See handleExternalTip. */
    externalTipAdvanced: handleExternalTip,
    /** A shared verifier fault must stop this browser even when the fault arose in its sibling. */
    notifyVerifierUnhealthy() {
      if (disposed || sim.attemptFinished || attempt === null) return false;
      try { intent.revokeCurrent('fatal_verifier'); } catch { /* finish remains authoritative */ }
      return finish(SIM_ATTEMPT_STATES.TERMINAL_FAILED, 'fatal_verifier', {
        type: VOCAB.failure,
        reason: 'fatal_verifier',
        ...simulationSummary(),
      });
    },
    /**
     * The process-wide assignment coordinator only. A sibling has irreversibly claimed the one
     * canonical submission, so this run loses consent immediately and receives one bound terminal
     * notice. The closed public reason is deliberately narrower than the coordinator's internal
     * bookkeeping phrase.
     */
    revokeAssignment(reason = 'submission_already_claimed') {
      if (disposed || sim.attemptFinished || attempt === null) return false;
      const publicReason = simFailureCode(reason) === reason ? reason : 'submission_already_claimed';
      try { intent.revokeCurrent(publicReason); } catch { /* finish is authoritative below */ }
      return finish(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, publicReason, {
        type: VOCAB.failure,
        reason: publicReason,
        ...simulationSummary(),
      });
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      consentLive = false;
      clearSearchTimer();
      // A closed socket revokes server-side run intent. Nothing re-arms it but another Start, and
      // in this mode there is no another Start: the one attempt this process had is spent.
      intent.revokeCurrent('session_dispose');
      if (run) { try { run.dispose(); } catch { /* already released */ } }
      sim.finishAttempt(owner, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'session_dispose');
      // A socket can disappear after assignment but before Start reserves the per-assignment
      // context. That is still terminal for the process-wide coordinator and must release capacity.
      // The one-shot fence prevents a later dispose from notifying twice after a normal finish.
      notifyTerminal(SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, 'session_dispose');
      clearSessionTimer();
      if (inSequence || refreshMode) { try { sim.abortPendingInit(owner); } catch { /* nothing starting */ } }
    },
    get workerId() { return workerId; },
    get authorized() { return authorized; },
    get intent() { return intent; },
    get run() { return run; },
    get disposed() { return disposed; },
    get clientStartId() { return attempt?.clientStartId ?? null; },
    /**
     * TEST-VISIBLE BOUNDED-STATE FACTS. Sizes and counters only: no binding, no message and no control
     * surface. A regression asserts these do not grow with the number of rotations.
     */
    get stateFacts() {
      return Object.freeze({
        retainedBindings: issuedBindings.length,
        retainedBindingLimit: RETAINED_BINDINGS,
        bindingsIssued,
        searchTimers: searchTimer === null ? 0 : 1,
        rotationsInFlight: rotation === null ? 0 : 1,
        acceptedPending: acceptedPending === null ? 0 : 1,
        candidatesAdmittedThisBlock: candidatesAdmitted,
        admittedNonces: admittedNonces.size,
        refusalsWhileClaimPending,
        candidatesInFlight: run?.inFlight ?? 0,
        verificationSlotFree: shareWork ? ((run?.inFlight ?? 0) === 0 ? 1 : 0) : 1,
        deadlineReached,
        deadlineSettling: deadlineSettling === null ? 0 : 1,
        refreshMode,
        windowIndex: sim.windowIndex ?? 1,
        windowTotal: refreshTotal,
        refreshesDone,
        windowOutcomes: windowOutcomes.map((o) => ({ ...o })),
        refreshInFlight: refreshing === null ? 0 : 1,
        sessionDeadlineAtMs,
        sessionBudgetSpent,
        sessionTimers: sessionTimer === null ? 0 : 1,
        sharesAccepted,
        sharesAcceptedTotal,
        invalidCandidates,
        invalidCandidatesTotal,
        shareWork,
        fatalLatchSubscribers: sim.latch.subscriberCount,
      });
    },
    /** Test/diagnostic only. */
    get ownerToken() { return owner; },
  };
}

/**
 * Build the ONE server-owned simulation context.
 *
 * Exactly one fatal latch, one template authority, one job and ONE ATTEMPT exist per server process,
 * and every session is handed these same objects. The attempt state machine lives here rather than
 * in a session, because a per-session flag is exactly what let two connections both do the work.
 */
export function createSimulationContext({
  job, latch, authority, oracle = null, mockDaemon = null, makeServerVerifier, expectedHashHexLE, recordedContext,
  // An assignment may replace the builder's first job with another server-personalized job. Its
  // verifier must receive that assignment's matching context, never the builder's default context.
  initialVerifierContext = null,
  // Opt-in only for an independently assigned one-shot context. Its complete resource set is kept
  // separately from the bounded diagnostic ring so teardown never depends on evidence retention.
  assignmentScopedTeardown = false,
  /**
   * REAL DAEMON ONLY. `daemon` is the counted wrapper over the real adapter that block_run submits
   * through (the recorded mode passes `mockDaemon` instead); `profile` is REAL_DAEMON_PROFILE;
   * `canonical` turns on block_run's canonical readback; the rest are read-only evidence.
   */
  daemon = null,
  profile = RECORDED_PROFILE,
  canonical = null,
  templateFacts = null,
  daemonResource = null,
  rpcEndpoint = null,
  // Paired P2P test only: the read-only peer API, and daemon A's total RPC counts and raw records.
  peer = null,
  rpcAudit = null,
  // Separate read-only daemon-A client used only by the automatic canonical-tip observer. Its
  // counters remain separate so polling cannot contaminate application-path/raw-evidence counts.
  tipSource = null,
  // The finite paired-daemon sequence only: real_daemon_mode.mjs's { total, issueNext }. Null elsewhere.
  sequence = null,
  // The opt-in SAME-HEIGHT refresh source: real_daemon_mode.mjs's { maxWindows, issueRefresh }.
  // Null in every mode that searches exactly one nonce window.
  refresh = null,
  now = () => Date.now(),
  /**
   * The server's ownership graph. Every verifier-shaped resource this context creates -- including
   * the handles a startup that could not confirm its own cleanup hands back -- is entered here the
   * moment it exists, so pool shutdown closes and escalates it exactly as it does the synthetic
   * verifier. A context built without one (a unit test) owns its resources itself.
   */
  ownResource = () => {},
  // A positively closed rotated verifier no longer needs to stay in the pool's teardown graph.
  // Unit tests omit this; the real server supplies its identity-based disown operation.
  releaseOwnedResource = () => {},
  /**
   * The server-side canonical-tip observer, or null. Started by the one accepted Start, stopped by
   * any terminal outcome and by shutdown. The pool owns and releases the handle itself.
   */
  tipObserver = null,
}) {
  const configuredSequenceTotal = sequence?.total ?? 1;
  const configuredRefreshTotal = refresh?.maxWindows ?? 1;
  if (typeof assignmentScopedTeardown !== 'boolean') {
    throw new TypeError('assignmentScopedTeardown must be boolean');
  }
  if (assignmentScopedTeardown && (sequence !== null || refresh !== null)) {
    throw new TypeError('assignment-scoped teardown requires one-shot work without sequence or refresh');
  }
  if (!isSupportedRealContextPlan(configuredSequenceTotal, configuredRefreshTotal)) {
    throw new TypeError(`one Start may issue at most ${REAL_MAX_CONTEXTS_PER_START} serial contexts`);
  }
  const counters = { serverWasmHashes: 0, nativeHashRequests: 0, nativeHelperHashes: 0 };
  let lastHashes = { serverWasmHex: null, nativeHelperHex: null };
  // THE CURRENT BLOCK. Fixed for one-shot modes; the finite sequence replaces it only after the
  // previous block's verifier is confirmed released, never beyond the configured total.
  let current = Object.freeze({
    job, templateFacts, canonical, recordedContext, verifierContext: initialVerifierContext,
  });
  let blockIndex = 1;
  // WHICH NONCE WINDOW OF THIS HEIGHT is current. 1 everywhere except an opt-in refresh run.
  let windowIndex = 1;
  // Bounded cumulative evidence: one small record per context this session issued, never more than
  // the build's total context ceiling. `verifierAllocationStartedAtMs` is literal: every record begins
  // unknown and is stamped exactly when the single-flight path actually invokes this window's
  // verifier factory. It is a bare millisecond reading: no blob, template or key is retained here.
  // A record's issuance facts are SERVER-OWNED SNAPSHOTS. The only field allowed to change after
  // construction is the allocation timestamp, which begins honestly unknown and is written by the
  // one verifier-factory path below. This prevents a later/current job from being substituted as
  // evidence for an earlier window's actual height, targets or difficulties.
  const hashingTemplateSha256 = (hex) => (typeof hex === 'string' && /^(?:[0-9a-f]{2})+$/.test(hex)
    ? createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex')
    : null);
  const makeWindowRecord = (block, window, windowJob) => {
    const record = { verifierAllocationStartedAtMs: null };
    Object.defineProperties(record, {
      block: { value: block, enumerable: true },
      window: { value: window, enumerable: true },
      jobId: { value: windowJob?.jobId ?? null, enumerable: true },
      issuanceId: { value: windowJob?.issuanceId ?? null, enumerable: true },
      nonceStart: { value: windowJob?.nonceStart ?? null, enumerable: true },
      nonceRange: { value: windowJob?.nonceRange ?? null, enumerable: true },
      height: { value: windowJob?.height ?? null, enumerable: true },
      shareDifficulty: { value: windowJob?.shareDifficulty ?? null, enumerable: true },
      blockDifficulty: { value: windowJob?.difficulty ?? null, enumerable: true },
      shareTargetHexLE: { value: windowJob?.shareTargetHexLE ?? null, enumerable: true },
      blockTargetHexLE: { value: windowJob?.targetHexLE ?? null, enumerable: true },
      contentDigest: { value: windowJob?.contentDigest ?? null, enumerable: true },
      epochKeyHex: { value: windowJob?.epochKeyHex ?? null, enumerable: true },
      seedHashHex: { value: windowJob?.seedHashHex ?? null, enumerable: true },
      hashingTemplateSha256: {
        value: hashingTemplateSha256(windowJob?.hashingTemplateHex), enumerable: true,
      },
    });
    return Object.seal(record);
  };
  const windowRecords = [makeWindowRecord(1, 1, job)];
  let awaitingNextBlock = false;     // the previous verifier is released and the next job not yet adopted
  // PER-BLOCK EVIDENCE AND RELEASED VERIFIERS, IN FIXED RINGS. Both used to grow once per block; the
  // most recent RETAINED_* entries are kept and the counters below say how many there were in total.
  // Nothing in the rotation path READS an old record: they are evidence, and the current block's record
  // is always present.
  const blockRecords = [];
  const verifierHistory = [];
  let blocksRecorded = 0;
  let verifiersReleased = 0;
  let resourcesCreated = 0;
  let verifier = null;
  // A verifier removed from the usable slot but still inside its asynchronous rotation close.
  // Pool shutdown must be able to force this exact resource BEFORE draining the rotation promise.
  let releasingVerifier = null; // { resource, record, wakeShutdown, forcePromise }
  let initPromise = null;
  let initAbort = null;
  let closing = false;
  let assignmentClosePromise = null;
  let assignmentCloseStarted = false;
  let assignmentCloseSettled = false;
  let faultListener = null;      // { owner, fn }
  let externalTipListener = null; // { owner, fn }: the same session, for a tip it did not produce
  const createdResources = [];   // every resource this context produced, for evidence and tests
  const assignmentResources = assignmentScopedTeardown ? new Set() : null;

  /**
   * OWNERSHIP FIRST, EVIDENCE SECOND. Every resource is handed to the server's ownership graph -- which
   * is what actually closes it -- and only the most recent RETAINED_RESOURCES are ALSO referenced here
   * for evidence. Dropping an old reference from this list releases nothing and hides nothing: the graph
   * still owns it and pool shutdown still closes it.
   */
  function adopt(label, resource) {
    if (!resource) return;
    assignmentResources?.add(resource);
    if (!createdResources.includes(resource)) {
      createdResources.push(resource);
      resourcesCreated += 1;
      while (createdResources.length > RETAINED_RESOURCES) createdResources.shift();
    }
    try { ownResource(label, resource); } catch { /* the graph refused; the reference is still kept */ }
  }

  const boundedReleaseError = (err) => String(err?.message ?? err ?? 'unknown release error').slice(0, 240);

  /**
   * Escalate the verifier currently stuck in a rotation close. Single-flight: shutdown and the
   * rotation itself can meet here without issuing two force-close operations. The wake is resolved
   * only after escalation returns, letting the admitted rotation leave the pool's pre-drain barrier
   * even if the original graceful close promise never settles.
   */
  function forceReleasingVerifier(reason, { abandonedGraceful = false } = {}) {
    const state = releasingVerifier;
    if (state === null) return Promise.resolve();
    if (abandonedGraceful && state.gracefulPending === true) {
      state.record.gracefulCloseAbandoned = true;
    }
    if (state.forcePromise !== null) return state.forcePromise;
    state.record.forced = true;
    state.forcePromise = (async () => {
      try { state.resource.beginClose?.(reason); } catch (err) {
        state.record.beginCloseError ??= boundedReleaseError(err);
      }
      if (state.resource.closed !== true) {
        try { await state.resource.forceClose(reason); } catch (err) {
          state.record.forceCloseError ??= boundedReleaseError(err);
        }
      }
      state.wakeShutdown();
    })();
    // No caller is required to await beginClose(); own this rejection boundary here. The body
    // records dependency-controlled errors as bounded facts and normally cannot reject.
    state.forcePromise.catch(() => {});
    return state.forcePromise;
  }

  function isCancellation(err) {
    return err?.cancelled === true || err?.cause?.cancelled === true;
  }

  /** A fault from the verifier set: latch the process, then end the attempt that holds it. */
  function handleVerifierFault(code, err) {
    if (isCancellation(err)) return;
    latch.trip(code, err);
    try { verifier?.latchExternalFault?.(latch.error); } catch { /* already latched */ }
    const listener = faultListener;
    if (listener) {
      try { listener.fn(latch.code); } catch { /* a bad listener cannot un-latch anything */ }
    }
  }

  /** A known-answer mismatch on either live path: an integrity fault, and it is fatal. */
  function checkKnownAnswer(path, bytes) {
    // A FRESH TEMPLATE HAS NO KNOWN ANSWER. block_run compares the Wasm, native and daemon results
    // with each other; there is nothing committed to compare them against.
    if (expectedHashHexLE === null) return bytes;
    const hex = blobToHex(bytes);
    if (hex !== expectedHashHexLE) {
      const err = new Error(`${path} did not reproduce the committed recorded hash`);
      handleVerifierFault(FATAL_CODES.VERIFIER_BUILD_DISAGREEMENT, err);
      throw err;
    }
    return bytes;
  }

  // THE ONE ATTEMPT. `owner` is a session's reference identity; `clientStartId` is that session's
  // correlation token for the Start click that won.
  let attemptState = SIM_ATTEMPT_STATES.IDLE;
  let attemptOwner = null;
  let attemptReason = null;
  let record = null;     // frozen { clientStartId, runGeneration, startedMessage, readyMessage }
  let attemptRun = null;

  function isFinished() {
    return TERMINAL_ATTEMPT_STATES.includes(attemptState);
  }

  function snapshot() {
    return record;
  }

  function update(fields) {
    record = Object.freeze({ ...record, ...fields });
    return record;
  }

  function requireOwner(owner) {
    return attemptOwner !== null && attemptOwner === owner;
  }

  function recordFor(index) {
    const existing = blockRecords.find((r) => r.block === index);
    if (existing) return existing;
    const rec = { block: index };
    blockRecords.push(rec);
    blocksRecorded += 1;
    while (blockRecords.length > RETAINED_BLOCK_RECORDS) blockRecords.shift();
    return rec;
  }

  const context = {
    /** The CURRENT block's job. Constant in a one-shot mode. */
    get job() { return current.job; },
    latch,
    authority,
    oracle,
    mockDaemon,
    /** The daemon block_run submits through: the real counted adapter, or the recorded mock. */
    submissionDaemon: daemon ?? mockDaemon,
    profile,
    get canonical() { return current.canonical; },
    get templateFacts() { return current.templateFacts; },
    daemonResource,
    rpcEndpoint,
    peer,
    rpcAudit,
    /** Observer RPC counts are a separate, copied channel; no client can mutate the source. */
    get tipObservationRpcCounts() { return { ...(tipSource?.counts ?? {}) }; },
    /** Final bounded observer lifecycle/counter facts for a live run record. */
    get tipObserverFacts() {
      const facts = tipObserver?.stateFacts;
      return facts === null || facts === undefined
        ? null
        : { ...facts, counts: { ...(facts.counts ?? {}) } };
    },
    counters,
    /** The last server-side hashes of the current block, as hex, for evidence. Null until computed. */
    get lastHashes() { return { ...lastHashes }; },
    expectedHashHexLE,
    get recordedContext() { return current.recordedContext; },

    // ---------------------------------------------------------------- the finite paired-daemon sequence
    /** 1 in every one-shot mode; otherwise the exact trusted 2..32 configuration. */
    get sequenceTotal() { return sequence?.total ?? 1; },
    /** The opt-in same-height refresh facts. 1 / false in every other mode. */
    get refreshTotal() { return refresh?.maxWindows ?? 1; },
    get refreshEnabled() { return refresh !== null; },
    get windowIndex() { return windowIndex; },
    get windowRecords() { return windowRecords.map((w) => Object.freeze({ ...w })); },
    /** Which block of the sequence the current job is (1 in a one-shot mode). */
    get blockIndex() { return blockIndex; },
    get closing() { return closing; },
    /** Per-block evidence, copied. The most recent RETAINED_BLOCK_RECORDS blocks. */
    get blockRecords() { return blockRecords.map((r) => ({ ...r })); },
    /** The most recent RETAINED_VERIFIERS verifiers released for rotation, and what each established. */
    get verifierHistory() { return verifierHistory.map((v) => ({ ...v })); },
    /**
     * TEST-VISIBLE BOUNDED-STATE FACTS of the server-owned context. Sizes and counters only, and no way
     * to mutate anything through them.
     */
    get stateFacts() {
      return Object.freeze({
        blockRecords: blockRecords.length,
        blockRecordLimit: RETAINED_BLOCK_RECORDS,
        blocksRecorded,
        verifierHistory: verifierHistory.length,
        verifierHistoryLimit: RETAINED_VERIFIERS,
        verifiersReleased,
        retainedResources: createdResources.length,
        retainedResourceLimit: RETAINED_RESOURCES,
        resourcesCreated,
        liveVerifiers: verifier === null && releasingVerifier === null ? 0 : 1,
        releasingVerifiers: releasingVerifier === null ? 0 : 1,
        pendingInits: initPromise === null ? 0 : 1,
        faultListeners: faultListener === null ? 0 : 1,
        externalTipListeners: externalTipListener === null ? 0 : 1,
        tipObservers: tipObserver === null ? 0 : 1,
        tipObserverRunning: tipObserver?.running === true ? 1 : 0,
        authority: authority.stateFacts,
      });
    },

    /** Merge evidence fields into block `index`'s record. Owner only. */
    recordBlock(owner, index, fields) {
      if (!requireOwner(owner) || !Number.isSafeInteger(index) || index < 1 || index > context.sequenceTotal) return false;
      Object.assign(recordFor(index), fields);
      return true;
    },

    /**
     * READ-ONLY: daemon B shows exactly the block this run established at `height` (see
     * real_daemon_mode.mjs awaitPropagation). The pair's reads only; nothing is sent to B.
     */
    async awaitBlockOnPeer(owner, { index, height, blockId, shouldContinue }) {
      if (!requireOwner(owner) || peer === null) throw new Error('awaitBlockOnPeer needs the owner and the pair');
      const p = await peer.awaitPropagation({ height, expectedBlockId: blockId, shouldContinue });
      Object.assign(recordFor(index), {
        propagation: {
          converged: p.converged === true, reason: p.reason ?? null, elapsedMs: p.elapsedMs ?? null,
          aHeader: p.aHeader ?? null, aTop: p.aTop ?? null, bHeader: p.bHeader ?? null, bTop: p.bTop ?? null,
          observations: p.observations ?? [], observedAtMs: now(),
        },
      });
      return p;
    },

    /**
     * ROTATION, STEP 1: release the current block's server verifier and CONFIRM it -- both its Wasm
     * context and its native helper process -- before anything for the next block may exist.
     *
     * The verifier becomes unusable at once (the hash paths refuse), is closed, is force-closed only if
     * the ordinary close did not confirm release, and stays in the server's ownership graph either way.
     * An unconfirmed release throws: nothing further is constructed.
     */
    async releaseVerifierForRotation(owner, reason = 'rotating to the next template') {
      if (!requireOwner(owner)) throw new Error('releaseVerifierForRotation from a session that holds no reservation');
      // A verifier may be rotated for the next BLOCK of a sequence or for the next same-height
      // WINDOW of a refresh run. Both are bounded by their own configured total; neither may run
      // while the previous release has not been adopted.
      const mayRotate = (sequence !== null && blockIndex < sequence.total)
        || (refresh !== null && windowIndex < refresh.maxWindows);
      if (!mayRotate || awaitingNextBlock) {
        throw Object.assign(new Error('there is no current verifier to rotate'), { code: 'verifier_release_unconfirmed' });
      }
      // A trusted external-tip notification can arrive after Start reserved the run but while the
      // first contextual verifier is still being constructed.  That context is already an owned
      // resource commitment: never skip past it and create the next block's context.  Join its
      // single-flight construction, then positively release it through the same path as a ready
      // verifier.  Shutdown may abort the construction; in that case this throws and no next
      // template can be issued.
      const pending = initPromise;
      let v = verifier;
      if (v === null && pending !== null) {
        try {
          v = await pending;
        } catch (cause) {
          throw Object.assign(new Error('the current verifier did not become releasable'), {
            code: 'verifier_release_unconfirmed', cause,
          });
        }
      }
      if (v === null || verifier !== v || (pending !== null && initPromise !== pending)) {
        throw Object.assign(new Error('there is no current verifier to rotate'), { code: 'verifier_release_unconfirmed' });
      }
      const rec = {
        block: blockIndex,
        // The verifier being retired is named by the exact server-issued capability it served.
        // Refresh evidence can therefore prove that the release belongs to the predecessor window,
        // rather than relying on position in an otherwise anonymous history array.
        window: refresh !== null ? windowIndex : null,
        jobId: current.job?.jobId ?? null,
        issuanceId: current.job?.issuanceId ?? null,
        helperLinuxPid: v.helperLinuxPid ?? null,
        helperSourceId: v.helperSourceId ?? null,
        helperDistro: v.helperDistro ?? null,
        context: v.context ?? null,
        counters: v.counters ?? null,
        releaseStartedAtMs: now(),
        forced: false,
      };
      let wakeShutdown;
      let shutdownWoken = false;
      const shutdownWake = new Promise((resolve) => {
        wakeShutdown = () => {
          if (shutdownWoken) return;
          shutdownWoken = true;
          resolve({ kind: 'shutdown_escalation' });
        };
      });
      const releaseState = {
        resource: v,
        record: rec,
        wakeShutdown,
        forcePromise: null,
        gracefulPending: true,
      };
      releasingVerifier = releaseState;
      verifier = null;                       // NOT USABLE from this instant
      initPromise = null;
      initAbort = null;
      awaitingNextBlock = true;
      try {
        try { v.beginClose?.(reason); } catch (err) { rec.beginCloseError = boundedReleaseError(err); }
        // Both branches handle rejection, so a graceful close abandoned by shutdown can never
        // become an unhandled rejection after the rotation has moved on.
        const gracefulClose = Promise.resolve()
          .then(() => v.close(reason))
          .then(
            () => ({ kind: 'graceful_close' }),
            (err) => ({ kind: 'graceful_close', error: boundedReleaseError(err) }),
          )
          .then((result) => {
            releaseState.gracefulPending = false;
            return result;
          });
        const closeResult = await Promise.race([gracefulClose, shutdownWake]);
        if (closeResult.kind === 'graceful_close' && closeResult.error) rec.closeError = closeResult.error;
        // Ordinary rotation escalates a returned/throwing close that did not confirm release.
        // Shutdown uses the same single-flight force path and wakes the race only after it returns.
        if (v.closed !== true) {
          await forceReleasingVerifier(reason, { abandonedGraceful: closeResult.kind === 'shutdown_escalation' });
        }
        rec.closed = v.closed === true;
        try {
          const outcome = v.shutdownOutcome;
          rec.shutdownOutcome = outcome ? { ...outcome } : null;
        } catch (err) {
          rec.shutdownOutcome = null;
          rec.shutdownOutcomeReadError = boundedReleaseError(err);
        }
        rec.releasedAtMs = now();
        verifierHistory.push(rec);
        verifiersReleased += 1;
        while (verifierHistory.length > RETAINED_VERIFIERS) verifierHistory.shift();
        Object.assign(recordFor(rec.block), { lastHashes: { ...lastHashes }, verifier: rec });
        // Hand the release facts back even when physical release failed. The server keeps an
        // unclosed resource owned, but it must remember that its graceful close was abandoned and
        // preserve every failure before this operation throws. On retry it can then go directly to
        // bounded escalation instead of re-awaiting the same stuck close.
        try { releaseOwnedResource(v, rec); } catch { /* the ownership graph still holds the handle */ }
        if (!rec.closed) {
          throw Object.assign(new Error('the previous block verifier could not be confirmed released'), { code: 'verifier_release_unconfirmed' });
        }
        return { ...rec };
      } finally {
        if (releasingVerifier === releaseState) releasingVerifier = null;
      }
    },

    /**
     * ROTATION, STEP 2: exactly one next template from daemon A, for the block on top of `acceptedBlockId`,
     * published through the authority (the previous issuance is superseded), then adopted as the current
     * block. Only after step 1 confirmed release.
     */
    async issueNextBlock(owner, { acceptedBlockId, acceptedHeight, stillWanted = () => true }) {
      if (!requireOwner(owner)) throw new Error('issueNextBlock from a session that holds no reservation');
      if (sequence === null || !awaitingNextBlock || verifier !== null || initPromise !== null) {
        throw Object.assign(new Error('the previous verifier has not been released'), { code: 'next_template_refused' });
      }
      const next = await sequence.issueNext({ acceptedBlockId, acceptedHeight, stillWanted });
      current = Object.freeze({
        job: next.job, templateFacts: next.templateFacts, canonical: next.canonical,
        recordedContext: next.context, verifierContext: next.context,
      });
      blockIndex += 1;
      // Window numbering is per height. The daemon source has already published this validated
      // next-height job and reset its own nonce-window cursor; adopt the same state atomically here.
      windowIndex = 1;
      lastHashes = { serverWasmHex: null, nativeHelperHex: null };
      awaitingNextBlock = false;
      if (windowRecords.length < REAL_MAX_CONTEXTS_PER_START) {
        windowRecords.push(makeWindowRecord(blockIndex, windowIndex, next.job));
      }
      Object.assign(recordFor(blockIndex), { templateFacts: next.templateFacts, issuedAtMs: now() });
      return next;
    },

    /**
     * REFRESH STEP 2: exactly one further template for the SAME height, on an unchanged canonical
     * tip, published through the authority (the previous issuance is superseded) and adopted as the
     * current work. Only after step 1 confirmed the previous verifier's release. The block index
     * does NOT move: this is another window of the same height, and it is counted as one.
     */
    async issueRefreshWindow(owner, { stillWanted = () => true } = {}) {
      if (!requireOwner(owner)) throw new Error('issueRefreshWindow from a session that holds no reservation');
      if (refresh === null || !awaitingNextBlock || verifier !== null || initPromise !== null) {
        throw Object.assign(new Error('the previous verifier has not been released'), { code: 'next_template_refused' });
      }
      const next = await refresh.issueRefresh({ stillWanted });
      current = Object.freeze({
        job: next.job, templateFacts: next.templateFacts, canonical: next.canonical,
        recordedContext: next.context, verifierContext: next.context,
      });
      windowIndex += 1;
      lastHashes = { serverWasmHex: null, nativeHelperHex: null };
      awaitingNextBlock = false;
      if (windowRecords.length < REAL_MAX_CONTEXTS_PER_START) {
        // ADOPTION IS NOT ALLOCATION. The record is born with immutable issuance facts and a null
        // allocation timestamp; the single-flight factory path stamps that one mutable field.
        windowRecords.push(makeWindowRecord(blockIndex, windowIndex, next.job));
      }
      Object.assign(recordFor(blockIndex), { templateFacts: next.templateFacts, windowIssuedAtMs: now() });
      return next;
    },

    /** A stop during a rotation aborts a next-block verifier still starting. Owner only. */
    abortPendingInit(owner) {
      if (!requireOwner(owner) || verifier !== null) return false;
      try { initAbort?.abort(); } catch { /* already aborted */ }
      return true;
    },
    get serverVerifierReady() { return verifier !== null; },
    /** The live verifier, or null. Evidence for tests and the live runs; never a control surface. */
    get verifier() { return verifier; },
    get pendingInit() { return initPromise; },
    get createdResources() { return [...createdResources]; },

    /**
     * True only after the assignment close path was requested and every verifier/helper resource
     * this context created is physically confirmed closed. A fulfilled close call is not proof:
     * the resources' own `closed` readback is the authority.
     */
    get assignmentResourcesClosed() {
      return assignmentScopedTeardown
        && assignmentCloseStarted
        && assignmentCloseSettled
        && initPromise === null
        && initAbort === null
        && releasingVerifier === null
        && verifier === null
        && [...assignmentResources].every((resource) => resource?.closed === true);
    },

    /**
     * Terminal, single-flight teardown for one independently assigned context. It joins a pending
     * factory so a late verifier or PartialVerifierError handle cannot escape, attempts ordinary
     * close, escalates when physical closure was not confirmed, and disowns only confirmed-closed
     * resources. This is deliberately separate from rotation and from the pool-wide pre-drain
     * beginClose() phase.
     */
    closeAssignmentResources(reason = 'assignment closing') {
      if (!assignmentScopedTeardown) {
        return Promise.reject(Object.assign(
          new Error('assignment-scoped teardown is not enabled for this context'),
          { code: 'assignment_teardown_unavailable' },
        ));
      }
      if (assignmentClosePromise !== null) return assignmentClosePromise;
      assignmentCloseStarted = true;
      closing = true;
      try { tipObserver?.stop(reason); } catch { /* already stopped */ }
      faultListener = null;
      externalTipListener = null;
      try { initAbort?.abort(); } catch { /* already aborted */ }
      if (attemptRun) {
        try { attemptRun.dispose(); } catch { /* already released */ }
        attemptRun = null;
      }

      const pending = initPromise;
      const closeSignalled = new Set();
      const signalClose = (resource) => {
        if (!resource || closeSignalled.has(resource)) return;
        closeSignalled.add(resource);
        try { resource.beginClose?.(reason); } catch { /* physical readback decides below */ }
      };
      for (const resource of assignmentResources) signalClose(resource);

      assignmentClosePromise = (async () => {
        try {
          if (pending !== null) {
            try { await pending; } catch { /* partial handles were adopted by the rejection path */ }
          }
          initPromise = null;
          initAbort = null;
          if (verifier !== null) assignmentResources.add(verifier);
          verifier = null; // unusable before any asynchronous close wait

          const rotationOverlap = releasingVerifier !== null;
          const resources = [...assignmentResources];
          for (const resource of resources) signalClose(resource);
          const outcomes = await Promise.all(resources.map(async (resource) => {
            if (resource?.closed !== true) {
              try { await resource?.close?.(reason); } catch { /* physical readback decides */ }
            }
            if (resource?.closed !== true) {
              try { await resource?.forceClose?.(reason); } catch { /* physical readback decides */ }
            }
            if (resource?.closed === true) {
              try {
                releaseOwnedResource(resource, Object.freeze({
                  kind: 'assignment_close', reason, closed: true, releasedAtMs: now(),
                }));
              } catch { /* a closed handle may conservatively remain in the global graph */ }
              return true;
            }
            return false;
          }));
          if (rotationOverlap || outcomes.some((closed) => !closed)) {
            throw Object.assign(
              new Error('assignment verifier resources could not be confirmed released'),
              { code: 'verifier_release_unconfirmed' },
            );
          }
        } finally {
          assignmentCloseSettled = true;
        }
      })();
      assignmentClosePromise.catch(() => {});
      return assignmentClosePromise;
    },

    // ---------------------------------------------------------------- the one attempt
    get attemptState() { return attemptState; },
    get attemptFinished() { return isFinished(); },
    get attemptReason() { return attemptReason; },
    get attempt() { return record; },
    /**
     * Retained shape. `completed` is true for EVERY terminal state, not only success: the one
     * attempt is spent either way, and the submission claim it may hold is never released.
     */
    state: Object.freeze({ get completed() { return isFinished(); } }),

    /**
     * RESERVE THE ONE ATTEMPT. Called before any verifier, dataset, subscription or hash.
     *
     * A repeat from the same session with the same correlation token is idempotent. Anything else --
     * a second session, a second Start identity, a finished attempt, a disabled verifier -- is
     * refused here, where refusing is free.
     */
    reserveAttempt({ owner, clientStartId }) {
      if (typeof clientStartId !== 'string' || clientStartId.length === 0) {
        return { ok: false, reason: RESERVE_REFUSED.MISSING_START_ID, detail: 'a clientStartId is required' };
      }
      if (isFinished()) {
        return {
          ok: false,
          reason: RESERVE_REFUSED.ALREADY_FINISHED,
          detail: 'this server process has already used its one recorded-template simulation; '
            + 'restart the local server to run another',
        };
      }
      if (latch.tripped) {
        return { ok: false, reason: RESERVE_REFUSED.VERIFIER_DISABLED, detail: 'verification is disabled' };
      }
      if (attemptState !== SIM_ATTEMPT_STATES.IDLE) {
        if (requireOwner(owner) && record?.clientStartId === clientStartId) {
          // The same Start, again. Answer with what it already got; mint nothing.
          return { ok: true, idempotent: true, attempt: record };
        }
        return {
          ok: false,
          reason: RESERVE_REFUSED.IN_PROGRESS,
          detail: 'another recorded-template simulation attempt already holds this server process',
        };
      }

      attemptState = SIM_ATTEMPT_STATES.RESERVED;
      attemptOwner = owner;
      record = Object.freeze({
        clientStartId,
        runGeneration: null,
        startedMessage: null,
        readyMessage: null,
      });
      return { ok: true, idempotent: false, attempt: record };
    },

    /** Record the server-minted run generation on the reservation. Owner only. */
    bindAttempt(owner, { runGeneration }) {
      if (!requireOwner(owner)) throw new Error('bindAttempt from a session that holds no reservation');
      return update({ runGeneration });
    },

    rememberMessage(owner, field, message) {
      if (!requireOwner(owner)) throw new Error('rememberMessage from a session that holds no reservation');
      return update({ [field]: Object.freeze({ ...message }) });
    },

    attachRun(owner, r) {
      if (!requireOwner(owner)) throw new Error('attachRun from a session that holds no reservation');
      if (attemptRun !== null && attemptRun !== r) {
        throw new Error('attachRun refused to overwrite an attached run');
      }
      attemptRun = r;
      return record;
    },

    /** Detach exactly the outgoing run at a rotation boundary. Owner only and idempotent. */
    detachRun(owner, expected) {
      if (!requireOwner(owner)) return false;
      if (attemptRun === null) return true;
      if (attemptRun !== expected) return false;
      try { attemptRun.dispose(); } catch { /* already released */ }
      attemptRun = null;
      return true;
    },

    /** The session holding the attempt registers how it is told about a native fault. */
    setFaultListener(owner, fn) {
      if (!requireOwner(owner)) return false;
      faultListener = { owner, fn };
      return true;
    },

    /**
     * The session holding the attempt registers how it is told the canonical tip moved elsewhere,
     * and (for the server-side observer) what it may know about the live run and how to report its
     * own failure. Registration itself does not poll; startTipObserver() is called only after an
     * explicit Start has minted its run binding.
     */
    setExternalTipListener(owner, fn, hooks = {}) {
      if (!requireOwner(owner)) return false;
      externalTipListener = { owner, fn, hooks };
      return true;
    },

    /** Arm the owned observer for this exact owner, fail-closed if it cannot be armed. */
    startTipObserver(owner) {
      if (!requireOwner(owner) || externalTipListener?.owner !== owner) return false;
      // Direct unit contexts intentionally omit the automatic component and exercise the trusted
      // seam manually. The production server requires one for every real sequence.
      if (tipObserver === null) return true;
      const listener = externalTipListener;
      try {
        if (tipObserver.start() === true) return true;
        // createTipObserver reports a scheduler failure itself. Only synthesize a failure when it
        // returned false without already terminalizing the attempt (for example, a closing handle).
        if (!isFinished()) listener.hooks?.onObservationFailure?.(
          TIP_OBSERVATION_FAILED, 'daemon A tip observer did not start');
      } catch (err) {
        if (!isFinished()) listener.hooks?.onObservationFailure?.(
          TIP_OBSERVATION_FAILED, `daemon A tip observer start failed: ${err?.message ?? err}`);
      }
      return false;
    },

    /** What the server-side observer may know about the live run. Values only. */
    tipWatchState() {
      const listener = externalTipListener;
      if (listener === null || typeof listener.hooks?.state !== 'function') return { active: false };
      return listener.hooks.state();
    },

    /** The observer could not observe: the one session ends the attempt, fail-closed. */
    notifyTipObservationFailure(code, detail) {
      const listener = externalTipListener;
      if (listener === null || typeof listener.hooks?.onObservationFailure !== 'function') {
        return { ok: false, reason: 'no_live_run' };
      }
      return listener.hooks.onObservationFailure(code, detail);
    },

    /**
     * THE SERVER'S TIP SOURCE. A canonical tip observed on daemon A that this session did not produce.
     * Forwarded to the one session holding the attempt, or refused if there is none. Nothing a client
     * sends can reach this: it is called by trusted server-side code only.
     */
    async notifyExternalTip({ height, blockId } = {}) {
      const listener = externalTipListener;
      if (listener === null) return { ok: false, reason: 'no_live_run' };
      return listener.fn({ height, blockId });
    },

    /** A failed verifier startup. Latches unless it was a deliberate cancellation. */
    recordInitFailure(err) {
      handleVerifierFault(FATAL_CODES.VERIFIER_FAULT, err);
    },

    markRunning(owner) {
      if (!requireOwner(owner)) return false;
      if (attemptState !== SIM_ATTEMPT_STATES.RESERVED) return false;
      attemptState = SIM_ATTEMPT_STATES.RUNNING;
      return true;
    },

    /**
     * End the one attempt. FIRST WRITE WINS and returns true; every later call returns false, so a
     * caller can use it to decide whether to send the single terminal message.
     */
    finishAttempt(owner, state, reason) {
      if (!requireOwner(owner)) return false;
      if (isFinished()) return false;
      if (!TERMINAL_ATTEMPT_STATES.includes(state)) return false;
      attemptState = state;
      attemptReason = reason ?? null;
      if (faultListener?.owner === owner) faultListener = null;
      if (externalTipListener?.owner === owner) externalTipListener = null;
      // TERMINAL MEANS NO MORE OBSERVATION. The poller stops here, not on the next cycle: whatever
      // ended this attempt, nothing reads daemon A for it again.
      try { tipObserver?.stop(`attempt ${state}`); } catch { /* already stopped */ }
      if (attemptRun) {
        try { attemptRun.dispose(); } catch { /* already released */ }
        attemptRun = null;
      }
      // A run that ended on a tripped latch (a disagreement block_run detected) also fails the
      // verifier itself, so its helper answers nothing further.
      if (latch.tripped) {
        try { verifier?.latchExternalFault?.(latch.error); } catch { /* already latched */ }
      }
      return true;
    },

    /**
     * Single-flight. The ONLY thing that creates the contextual Wasm instance and starts the helper.
     *
     * OWNERSHIP FROM THE START. The abort signal is handed to the factory before anything is
     * spawned, so a shutdown that arrives during HELLO, INIT or source checking reaches the child
     * through the existing lifetime abort listener. The resolved verifier -- or every handle a
     * failed startup hands back on PartialVerifierError -- enters the server's ownership graph the
     * moment it exists, before anything else can go wrong.
     */
    ensureServerVerifier() {
      if (closing) return Promise.reject(Object.assign(new Error('the pool is shutting down'), { cancelled: true }));
      if (latch.tripped) return Promise.reject(new Error('verification is disabled on this server process'));
      // Between blocks of the sequence there is no current context to verify against.
      if (awaitingNextBlock) return Promise.reject(new Error('the next block has not been issued'));
      if (verifier) return Promise.resolve(verifier);
      if (!initPromise) {
        initAbort = new AbortController();
        const signal = initAbort.signal;
        const block = blockIndex;
        const window = windowIndex;
        const verifierContext = current.verifierContext;
        initPromise = Promise.resolve()
          .then(() => {
            // THE LITERAL ALLOCATION START. This callback is inside the one single-flight creation
            // path and runs immediately before its sole factory invocation. Every window record is
            // born null, and the guard makes duplicate ensure calls incapable of rewriting it.
            const windowRecord = windowRecords.find((record) => (
              record.block === block && record.window === window
            ));
            if (windowRecord && windowRecord.verifierAllocationStartedAtMs === null) {
              windowRecord.verifierAllocationStartedAtMs = now();
            }
            return makeServerVerifier({
              signal,
              // A native fault at ANY time -- including one while idle -- reaches the process latch.
              onFault: (err) => handleVerifierFault(FATAL_CODES.VERIFIER_FAULT, err),
              // A rotated block's own server-owned context. The first block uses the builder's default.
              ...(verifierContext !== null ? { context: verifierContext } : {}),
            });
          })
          .then((v) => {
            adopt(closing ? 'late simulation verifier' : (block > 1 ? `simulation verifier (block ${block})` : 'simulation verifier'), v);
            if (block > 1) {
              Object.assign(recordFor(block), {
                verifier: { block, helperLinuxPid: v.helperLinuxPid ?? null, helperSourceId: v.helperSourceId ?? null, context: v.context ?? null, readyAtMs: now() },
              });
            }
            verifier = v;
            return v;
          }, (err) => {
            if (err?.name === 'PartialVerifierError' && Array.isArray(err.resources)) {
              for (const { label, resource } of err.resources) adopt(`partial simulation ${label}`, resource);
            }
            throw err;
          });
        // The caller owns the rejection; this only keeps an unawaited failure from crashing Node.
        initPromise.catch(() => {});
      }
      return initPromise;
    },

    /** The server's contextual Wasm hash, exactly once per call, checked against the known answer. */
    async hashOnServerWasm(nonce) {
      if (!verifier) throw new Error('the server verifier is not ready');
      const bytes = await verifier.hashWasm(nonce);
      counters.serverWasmHashes += 1;
      lastHashes.serverWasmHex = blobToHex(bytes);
      return checkKnownAnswer('server Wasm', bytes);
    },

    /** The live native helper's hash: exactly one HASH request per call, checked the same way. */
    async hashOnNative(nonce) {
      if (!verifier) throw new Error('the native helper is not ready');
      counters.nativeHashRequests += 1;
      const bytes = await verifier.hashNative(nonce);
      counters.nativeHelperHashes += 1;
      lastHashes.nativeHelperHex = blobToHex(bytes);
      return checkKnownAnswer('native helper', bytes);
    },

    /**
     * PHASE 1 of shutdown: synchronously stop admission and start cancellation, then return the
     * bounded escalation promise for a verifier already inside rotation release. The server awaits
     * that promise BEFORE draining admitted operations, which breaks the otherwise circular wait
     * between a stuck rotation close and the ownership sweep that follows the drain.
     */
    beginClose(reason = 'pool shutting down') {
      closing = true;
      try { tipObserver?.stop(reason); } catch { /* already stopped */ }
      try { initAbort?.abort(); } catch { /* already aborted */ }
      try { verifier?.beginClose?.(reason); } catch { /* already cancelling */ }
      const releasing = forceReleasingVerifier(reason, { abandonedGraceful: true });
      if (attemptRun) {
        try { attemptRun.dispose(); } catch { /* already released */ }
        attemptRun = null;
      }
      return releasing;
    },

    /** Test/diagnostic only. */
    get attemptSnapshot() { return snapshot(); },
  };

  return context;
}
