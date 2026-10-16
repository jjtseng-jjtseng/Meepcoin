// The REAL-LOCAL-DAEMON mode: one private daemon (or, in the paired test, two that name only each
// other as peers), ONE fresh block template, and the existing one-attempt session, block_run, dual
// verifier and ownership graph around them.
//
// Off by default. Selected only by the server option `mode: 'real-local-daemon'` (and, for the pair,
// `realDaemon.peer`), which a page or a client message cannot set. Nothing new is invented here: this
// file only ASSEMBLES
//
//   local_daemon.mjs       the owned meepcoind(s) (launch, identity, readiness, listener proof, close)
//   loopback_transport.mjs the numeric-loopback HTTP transport
//   daemon_rpc.mjs         the closed adapter, whose private proofs block_run trusts
//   real_template.mjs      exact template parsing and binding
//   run_guard.mjs          the one fatal latch and the one template authority
//   dual_verifier.mjs      server Wasm + the native helper, over the fresh context
//
// and hands the result to sim_session.mjs's createSimulationContext.
//
// WHAT HAPPENS BEFORE ANY PAGE CAN CONNECT, and why it is not "heavy work before Start": the daemon
// process is the explicit thing this mode exists to use, and a template can only come from it. It is
// started, proved healthy on a read-only RPC, proved to listen only on the intended numeric loopback
// ports, and asked for EXACTLY ONE block template. No verifier, dataset, Worker or hash exists until
// a Start reserves the one attempt.
//
// THE PAIRED P2P TEST (opt-in, `peer`). Daemon A and daemon B run the same pinned image and the same
// read-only artifact, each naming only the other as its exclusive numeric-loopback peer, with the
// frozen development difficulty 500. Before the template: both containers' image ids match the pin,
// both report the same genesis at height 0, both listen only on their loopback ports, and an A<->B
// P2P connection is observed with every observed connection numeric loopback. The template comes from
// A only and must be height 1 on that genesis at difficulty exactly 500. Daemon B gets a READ-ONLY
// client that refuses every other method before any byte leaves this process, so this code cannot
// deliver a block, or a calc_pow, to B; B can only receive the block through MeepCoin P2P, which
// awaitPeerPropagation() then checks by reading.
//
// THE DEVELOPMENT SEQUENCE (opt-in, `sequenceBlocks: 2..REAL_SEQUENCE_DEV_MAX_BLOCKS`, the pair only).
// The first template is fetched as above. `sequence.issueNext()` then fetches EXACTLY ONE more, only for
// the block after the one named as the new canonical tip -- whether this browser session produced it or
// an external miner did -- with the same frozen checks, and publishes it through the same authority so
// the previous issuance is superseded before the next can be used. Same-height refresh may be configured
// independently for each height, but the combined number of serial contexts is fixed and bounded before
// the listener exists.
//
// THE TEMPLATE IS FRESH AND NOTHING ELSE. It comes from the running daemon's get_block_template --
// never a committed vector, fixture or earlier run -- and no nonce is supplied: the browser searches
// [0, 8192) against the daemon's own target.

import { READ_ONLY_RPC_METHODS, createDaemonRpc } from './daemon_rpc.mjs';
import { createLoopbackTransport } from './loopback_transport.mjs';
import {
  DAEMON_PROFILES, PEER_TEST_FIXED_DIFFICULTY, checkPairConnections, parseConnections, startLocalDaemon,
} from './local_daemon.mjs';
import { launchBlockConverterOwner } from './block_converter_owner.mjs';
import { createExtraNonceAllocator } from './extra_nonce_allocator.mjs';
import { createRealTemplateJob, fullBlockBlobOf, hashingContextFor } from './real_template.mjs';
import { createFatalLatch, createTemplateAuthority } from './run_guard.mjs';
import { personalizeRealTemplate } from './template_personalizer.mjs';
import { createDualVerifier } from './dual_verifier.mjs';
import { PREV_ID_BYTES, blobToHex, findNonceOffset } from './block_blob.mjs';
import {
  REAL_MAX_CONTEXTS_PER_START, REAL_REFRESH_LIMITS, REAL_SEARCH_LIMITS, REAL_SEQUENCE_DEV_MAX_BLOCKS,
  isSupportedRealContextPlan, isSupportedRefreshWindows, isSupportedSequenceBlocks,
} from '../../web-miner/lib/shared/protocol.js';

/**
 * THE DEFAULT coinbase output, used whenever no trusted startup override is supplied. A PUBLIC
 * dev/test address already committed in this repository (node/scripts/verify-consensus.ps1, the
 * testnet get_block_template call). Not a secret; no wallet, key or seed is read, written or needed.
 */
export const REAL_COINBASE_ADDRESS =
  'D1Awzzi59qYFi65StYBcnwNqK8hmkJrhy7MT2hQLGeGYMFf32KtxbM3f3EtrB355w2Loa9xiMgyiLhFku57TdZmAEkgr3ZS';

/**
 * A DIFFERENT coinbase destination, for a trusted local run that wants the reward somewhere else
 * (the browser -> wallet ownership milestone pays a development wallet instead of the neutral
 * address above).
 *
 * TRUSTED LOCAL SERVER STARTUP CONFIGURATION ONLY. It arrives as `realDaemon.walletAddress` in the
 * options startDevPool is CONSTRUCTED with, which is the same closed channel as `mode` and `daemon`:
 * no page, WebSocket message, query string, HTTP request, browser storage, submitted share or job
 * field can reach it, and it is read once, here, before the listener exists. Omit it and the
 * committed neutral address above is still the destination.
 *
 * THE CHECK BELOW IS CHEAP AND LOCAL, NOT AUTHORITATIVE: type, length and Base58 shape only, so a
 * typo costs nothing. The daemon's own get_block_template -- which runs before listen(), before any
 * verifier, dataset, Worker or hash exists -- is what actually decides whether the address parses on
 * THIS network, and a refusal there is a startup failure that closes the daemon it started.
 */
const BASE58_ALPHABET = /^[1-9A-HJ-NP-Za-km-z]+$/;
/** Standard/subaddress and integrated lengths. */
const COINBASE_ADDRESS_LENGTHS = Object.freeze([95, 106]);

/** @returns {string|null} why the address cannot be a coinbase destination, or null if its shape is plausible. */
export function coinbaseAddressShapeProblem(address) {
  if (typeof address !== 'string') return `the coinbase destination must be a string, not ${typeof address}`;
  if (!COINBASE_ADDRESS_LENGTHS.includes(address.length)) {
    return `the coinbase destination must be ${COINBASE_ADDRESS_LENGTHS.join(' or ')} characters, not ${address.length}`;
  }
  if (!BASE58_ALPHABET.test(address)) return 'the coinbase destination is not Base58';
  return null;
}

/** How long the ONE issuance stays claimable. The search bound itself is REAL_SEARCH_LIMITS. */
export const REAL_JOB_TTL_MS = 10 * 60 * 1000;

/** RPC ceilings: the daemon builds its own MeepHash dataset on the first calc_pow / submit. */
export const REAL_RPC_LIMITS = Object.freeze({ timeoutMs: 60_000, submitTimeoutMs: 120_000 });

/** Paired test bounds: the A<->B link before the template, and B's convergence after acceptance. */
export const PEER_LINK_TIMEOUT_MS = 60_000;
export const PEER_PROPAGATION_TIMEOUT_MS = 60_000;

/** RPC methods whose raw request and response are kept (bounded) for replayable evidence. */
const RAW_CAPTURE_METHODS = Object.freeze([
  'get_block_template', 'calc_pow', 'submit_block', 'get_block_header_by_height', 'get_last_block_header',
]);
// Successful paired operation needs at most nine A-side records per issued context: the template,
// its post-conversion canonical-tip recheck, calc_pow, submit, canonical header/top, propagation
// header/top, and (except after the last block) the next-template top check. A composed
// sequence/refresh plan may still issue at most the shared
// context ceiling, so the same absolute evidence bound covers it. `rawDropped` is still explicit and
// makes every live success fail closed if this accounting ever becomes stale.
export const RAW_RECORDS_PER_SEQUENCE_BLOCK = 9;
export const MAX_RAW_RECORDS = REAL_MAX_CONTEXTS_PER_START * RAW_RECORDS_PER_SEQUENCE_BLOCK;
const MAX_OBSERVATIONS = 64;

export class RealDaemonModeError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.name = 'RealDaemonModeError';
    this.code = code;
  }
}

const PERSONALIZED_ISSUE_OPTION_KEYS = new Set([
  'nonceStart', 'nonceRange', 'shareDifficulty', 'ttlMs', 'note',
]);

/**
 * Own the allocation/conversion half of personalized work issuance.
 *
 * The caller still obtains and chain-validates the strict daemon template before passing it here.
 * This object owns the allocator and converter capabilities, allocates exactly once per call, and
 * never returns the raw extra nonce.  It is the narrow seam a future bounded multi-client
 * coordinator can share without giving a browser either capability.
 */
export function createServerOwnedPersonalizedWorkIssuer({
  extraNonceAllocator,
  convertFullBlock,
  personalizeTemplate = personalizeRealTemplate,
  now = () => Date.now(),
} = {}) {
  if (extraNonceAllocator === null || typeof extraNonceAllocator !== 'object'
    || !Number.isInteger(extraNonceAllocator.reserveSize) || extraNonceAllocator.reserveSize < 1
    || extraNonceAllocator.reserveSize > 255 || typeof extraNonceAllocator.issue !== 'function') {
    throw new RealDaemonModeError('bad_config', 'the extra-nonce allocator contract is invalid');
  }
  if (typeof convertFullBlock !== 'function' || typeof personalizeTemplate !== 'function'
    || typeof now !== 'function') {
    throw new RealDaemonModeError('bad_config', 'the personalized work issuer contract is invalid');
  }

  return Object.freeze({
    reserveSize: extraNonceAllocator.reserveSize,
    async issue(template, options = {}) {
      if (options === null || typeof options !== 'object' || Array.isArray(options)) {
        throw new RealDaemonModeError('bad_config', 'personalized work options must be an object');
      }
      for (const key of Reflect.ownKeys(options)) {
        if (typeof key !== 'string' || !PERSONALIZED_ISSUE_OPTION_KEYS.has(key)) {
          throw new RealDaemonModeError('bad_config', `unexpected personalized work option ${String(key).slice(0, 40)}`);
        }
      }
      // Allocation occurs only after buildRealDaemonMode has validated the template's height,
      // parent and seed.  A failed conversion burns this value; it can never be issued again.
      const extraNonceHex = extraNonceAllocator.issue();
      const personalized = await personalizeTemplate(template, {
        extraNonceHex,
        convertFullBlock,
        ...options,
        now,
      });
      const ctx = hashingContextFor(personalized.job);
      return Object.freeze({
        job: personalized.job,
        context: Object.freeze({
          epochKeyHex: blobToHex(ctx.epochKey),
          seedHashHex: blobToHex(ctx.seedHash),
          height: ctx.height.toString(),
          templateHex: blobToHex(ctx.template),
        }),
        reservedOffset: personalized.reservedOffset,
        reservedSize: personalized.reservedSize,
        extraNonceDigest: personalized.extraNonceDigest,
      });
    },
  });
}

/**
 * Wrap a transport to COUNT every RPC by method (total traffic, setup and audit included) and, while
 * capture is on, keep the raw request/response of the evidence methods. With `allowed`, any other
 * method is refused synchronously, before the inner transport is entered.
 */
export function auditedTransport(inner, { allowed = null } = {}) {
  const counts = {};
  const raw = [];
  let rawDropped = 0;
  const capture = { enabled: false, block: null, window: null };
  const transport = (req) => {
    if (allowed !== null && !allowed.includes(req.method)) {
      throw new RealDaemonModeError('method_not_allowed', 'this daemon client is read-only');
    }
    counts[req.method] = (counts[req.method] ?? 0) + 1;
    const captureThis = capture.enabled && RAW_CAPTURE_METHODS.includes(req.method);
    const rec = captureThis && raw.length < MAX_RAW_RECORDS
      ? {
        method: req.method, block: capture.block, window: capture.window, atMs: Date.now(),
        requestBody: req.body, responseText: null, failure: null,
      }
      : null;
    if (captureThis && rec === null) rawDropped += 1;
    if (rec) raw.push(rec);
    let out;
    try {
      out = Promise.resolve(inner(req));
    } catch (err) {
      if (rec) rec.failure = typeof err?.code === 'string' ? err.code : 'threw';
      throw err;
    }
    return out.then((text) => {
      if (rec) rec.responseText = typeof text === 'string' ? text : null;
      return text;
    }, (err) => {
      if (rec) rec.failure = typeof err?.code === 'string' ? err.code : 'failed';
      throw err;
    });
  };
  return {
    transport,
    counts,
    raw,
    capture,
    rawLimit: MAX_RAW_RECORDS,
    get rawDropped() { return rawDropped; },
  };
}

/** Validate the pair as a whole: cross-referenced exclusive peers, one image, four distinct ports. */
function checkPairConfig(a, b) {
  const fixed = a?.profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_TEST;
  const natural = a?.profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_NATURAL;
  const ok = (fixed || natural) && b?.profile === a.profile
    && (fixed
      ? a.fixedDifficulty === PEER_TEST_FIXED_DIFFICULTY && b.fixedDifficulty === PEER_TEST_FIXED_DIFFICULTY
      : a.fixedDifficulty === undefined && b.fixedDifficulty === undefined)
    && a.exclusivePeerP2pPort === b.p2pPort && b.exclusivePeerP2pPort === a.p2pPort
    && a.image === b.image && a.expectedImageId === b.expectedImageId && typeof a.expectedImageId === 'string'
    && a.artifactDir === b.artifactDir && a.runDir !== b.runDir
    && new Set([a.rpcPort, a.p2pPort, b.rpcPort, b.p2pPort]).size === 4;
  if (!ok) {
    throw new RealDaemonModeError('bad_pair_config',
      'the pair must be two peer-test daemons of one image naming only each other, on four distinct ports');
  }
}

/**
 * Start one daemon and enter it into the ownership graph the moment it exists.
 *
 * READINESS IS "THE RPC ANSWERS", NOT "THE NODE IS SYNCHRONISED". get_last_block_header (like
 * get_block_template) answers BUSY until the node's P2P layer considers itself synchronised. An
 * --offline node is synchronised at once; a node with an exclusive peer is not until it has synced
 * with that peer. Probing a paired daemon with get_last_block_header therefore deadlocked the first
 * live attempt: A could never be "ready" because B was only started after A was. get_info is not
 * gated and reports `synchronized` itself, so the pair uses it; the offline single daemon keeps its
 * original probe.
 */
async function startOwned({ startDaemon, config, rpc, signal, ownResource, label, paired }) {
  let resource;
  try {
    resource = await startDaemon({
      config,
      signal,
      isRpcReady: paired
        ? async () => { await rpc.getInfo(); return true; }
        : async () => { await rpc.getLastBlockHeader({ fillPowHash: false }); return true; },
    });
  } catch (err) {
    if (err?.resource) ownResource(`${label} (startup failed)`, err.resource);
    throw err;
  }
  ownResource(label, resource);
  return resource;
}

const sameCanonicalHeader = (x, y) => !!x && !!y
  && x.hash === y.hash && x.height === y.height && x.nonce === y.nonce && x.powHash === y.powHash
  && x.prevHash === y.prevHash && x.orphanStatus === false && y.orphanStatus === false;

/**
 * @param {object} o
 * @param {object} o.daemon          local_daemon.mjs config of daemon A (the only one in single mode)
 * @param {object} [o.peer]          { daemon: config of daemon B } -- the paired P2P test
 * @param {string} [o.walletAddress] TRUSTED STARTUP coinbase destination; defaults to the neutral address
 * @param {Function} o.ownResource   the server's own() -- every daemon enters the ownership graph here
 */
export async function buildRealDaemonMode({
  daemon: daemonConfig,
  peer = null,
  expectedGenesisTimestamp = null,
  expectedGenesisHash = null,
  maxGenesisAgeSeconds = null,
  walletAddress = REAL_COINBASE_ADDRESS,
  ownResource,
  helperPath,
  wslDistro,
  helperOptions,
  wasmPaths,
  now = () => Date.now(),
  signal = null,
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  peerLinkTimeoutMs = PEER_LINK_TIMEOUT_MS,
  /**
   * 1 (every existing mode), or 2..REAL_SEQUENCE_DEV_MAX_BLOCKS: a finite development sequence,
   * trusted startup configuration only. No page, message or query string can reach this.
   */
  sequenceBlocks = 1,
  /**
   * OPT-IN, trusted startup configuration only: the SHARE difficulty for every template of this
   * run. Must be a positive integer no greater than the template's own difficulty (so the share
   * target is numerically >= the block target). Omit it and every job is exactly what it was
   * before share work existed. No page, message or query string can reach it.
   */
  shareDifficulty = null,
  /**
   * OPT-IN SAME-HEIGHT REFRESH, trusted startup configuration only. 1 (every existing mode) or
   * 2..REAL_REFRESH_LIMITS.maxWindows: the TOTAL number of nonce windows PER HEIGHT one Start may
   * search, the first one included. Each further window is a fresh job and issuance over a provably
   * disjoint uint32 nonce range on daemon A's UNCHANGED canonical tip. No page, message or query
   * string can reach it.
   */
  refreshWindows = 1,
  /**
   * A NARROW TRUSTED MARKER for the one source-fixed handoff probe. It affects disclosure only;
   * the actual share difficulty and window total still travel through, and are validated by, their
   * ordinary independent configuration fields. No client message can set this.
   */
  refreshHandoffProbe = false,
  /**
   * OPT-IN SERVER-OWNED TEMPLATE PERSONALIZATION. The real command-line launcher enables this;
   * direct programmatic callers must ask explicitly. The converter binary is not caller-selected:
   * it is the `meepcoin-blockhashing` artifact in the same pinned build directory as the daemon.
   */
  personalizeTemplates = false,
  // Seams. The non-live tests inject all three; the defaults are the real ones.
  startDaemon = startLocalDaemon,
  makeTransport = (endpoint) => createLoopbackTransport({ endpoint }).transport,
  makeVerifier = createDualVerifier,
  makeTemplateAuthority = createTemplateAuthority,
  launchConverter = launchBlockConverterOwner,
  makeExtraNonceAllocator = createExtraNonceAllocator,
  personalizeTemplate = personalizeRealTemplate,
} = {}) {
  if (typeof ownResource !== 'function') throw new RealDaemonModeError('bad_config', 'ownResource is required');
  // BEFORE the daemon, the transport, the verifier, the dataset, the listener and any hash.
  const addressProblem = coinbaseAddressShapeProblem(walletAddress);
  if (addressProblem !== null) throw new RealDaemonModeError('bad_coinbase_address', addressProblem);
  const rpcPort = daemonConfig?.rpcPort;
  if (!Number.isInteger(rpcPort)) throw new RealDaemonModeError('bad_config', 'daemon.rpcPort is required');
  if (peer !== null) checkPairConfig(daemonConfig, peer?.daemon);
  const naturalPair = peer !== null && daemonConfig.profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_NATURAL;
  if (naturalPair && (!Number.isSafeInteger(expectedGenesisTimestamp) || expectedGenesisTimestamp < 1)) {
    throw new RealDaemonModeError('bad_config', 'natural-difficulty mode requires a positive expectedGenesisTimestamp');
  }
  if (naturalPair && (typeof expectedGenesisHash !== 'string' || !/^[0-9a-f]{64}$/.test(expectedGenesisHash))) {
    throw new RealDaemonModeError('bad_config', 'natural-difficulty mode requires a 64-character lowercase expectedGenesisHash');
  }
  if (!naturalPair && expectedGenesisTimestamp !== null) {
    throw new RealDaemonModeError('bad_config', 'expectedGenesisTimestamp is only valid for a natural-difficulty pair');
  }
  if (!naturalPair && expectedGenesisHash !== null) {
    throw new RealDaemonModeError('bad_config', 'expectedGenesisHash is only valid for a natural-difficulty pair');
  }
  if (maxGenesisAgeSeconds !== null && (!naturalPair || !Number.isSafeInteger(maxGenesisAgeSeconds)
    || maxGenesisAgeSeconds < 1)) {
    throw new RealDaemonModeError('bad_config', 'maxGenesisAgeSeconds must be a positive integer for a natural-difficulty pair');
  }
  if (!isSupportedSequenceBlocks(sequenceBlocks)) {
    throw new RealDaemonModeError('bad_config',
      `sequenceBlocks must be an integer from 1 to ${REAL_SEQUENCE_DEV_MAX_BLOCKS}`);
  }
  if (sequenceBlocks > 1 && peer === null) {
    throw new RealDaemonModeError('bad_config', 'a multi-block sequence needs the private daemon pair');
  }
  if (!isSupportedRefreshWindows(refreshWindows)) {
    throw new RealDaemonModeError('bad_config',
      `refreshWindows must be an integer from 1 to ${REAL_REFRESH_LIMITS.maxWindows}`);
  }
  if (naturalPair && (sequenceBlocks > 3 || refreshWindows !== 1 || shareDifficulty !== null
    || refreshHandoffProbe !== false)) {
    throw new RealDaemonModeError('bad_config',
      'the natural-difficulty pair allows at most three heights, one window each, and no share or refresh probe');
  }
  if (typeof refreshHandoffProbe !== 'boolean') {
    throw new RealDaemonModeError('bad_config', 'refreshHandoffProbe must be boolean');
  }
  if (typeof personalizeTemplates !== 'boolean') {
    throw new RealDaemonModeError('bad_config', 'personalizeTemplates must be boolean');
  }
  for (const [name, seam] of [
    ['launchConverter', launchConverter],
    ['makeExtraNonceAllocator', makeExtraNonceAllocator],
    ['personalizeTemplate', personalizeTemplate],
    ['makeTemplateAuthority', makeTemplateAuthority],
  ]) {
    if (typeof seam !== 'function') throw new RealDaemonModeError('bad_config', `${name} must be a function`);
  }
  if (refreshHandoffProbe
    && (refreshWindows !== 2 || sequenceBlocks !== 1 || shareDifficulty !== 1)) {
    throw new RealDaemonModeError('bad_config',
      'refreshHandoffProbe requires refreshWindows 2, sequenceBlocks 1 and shareDifficulty 1');
  }
  if (!isSupportedRealContextPlan(sequenceBlocks, refreshWindows)) {
    throw new RealDaemonModeError('bad_config',
      `sequenceBlocks * refreshWindows must not exceed ${REAL_MAX_CONTEXTS_PER_START} serial contexts`);
  }
  if (refreshWindows > 1) {
    // Defined for the private fixed-difficulty PAIR only: that is the profile whose text, tip checks
    // and read-only peer observations this build has.
    if (peer === null) {
      throw new RealDaemonModeError('bad_config', 'same-height refresh needs the private daemon pair in this build');
    }
  }
  if (shareDifficulty !== null) {
    if (!Number.isSafeInteger(shareDifficulty) || shareDifficulty < 1) {
      throw new RealDaemonModeError('bad_config', 'shareDifficulty must be a positive safe integer');
    }
    // SHARE WORK AND THE FINITE SEQUENCE NOW COMBINE, and they combine by staying separate: each
    // template of the sequence is issued with this same share difficulty, and every per-template
    // bound -- the share budget, the admitted-nonce set, the invalid-candidate allowance, the
    // absolute search backstop and the single submission claim -- belongs to ONE height and is
    // rebuilt for the next. The sequence's own rules are unchanged: the next template is fetched
    // only after this height's block is canonical on A, shown by B, and the height's verifier is
    // confirmed released.
    // THE PROFILE THAT CONSUMES SHARE WORK DESCRIBES TWO PRIVATE DAEMONS. There is no single-daemon
    // share profile in this build, and a page must never be shown text about a pair that does not
    // exist, so a single-daemon share configuration is refused rather than silently mislabelled.
    if (peer === null) {
      throw new RealDaemonModeError('bad_config', 'share work needs the private daemon pair in this build');
    }
  }

  // CANCELLATION REACHES EVERY STEP. startLocalDaemon checks the signal while it waits for a container;
  // the link wait, the genesis reads and the template request are checked here, so an aborted startup
  // stops at the next boundary and startDevPool's transactional cleanup closes whatever is owned.
  const throwIfAborted = () => {
    if (signal?.aborted) throw new RealDaemonModeError('startup_cancelled', 'real-daemon startup was cancelled');
  };
  throwIfAborted();

  // THE CONVERTER IS OWNED BEFORE ITS FIRST AWAIT and ready before a daemon can start. A malformed
  // build artifact therefore cannot leave a daemon behind, and a startup cancellation is handled by
  // the server's one transactional ownership graph. The allocator is process-local and never accepts
  // a browser value; one monotonic allocation domain serves every refresh and sequence issuance.
  const latch = createFatalLatch();
  let converterOwner = null;
  let extraNonceAllocator = null;
  let personalizedWorkIssuer = null;
  if (personalizeTemplates) {
    extraNonceAllocator = makeExtraNonceAllocator();
    if (extraNonceAllocator === null || typeof extraNonceAllocator !== 'object'
      || !Number.isInteger(extraNonceAllocator.reserveSize) || extraNonceAllocator.reserveSize < 1
      || extraNonceAllocator.reserveSize > 255 || typeof extraNonceAllocator.issue !== 'function') {
      throw new RealDaemonModeError('bad_config', 'the extra-nonce allocator contract is invalid');
    }
    converterOwner = launchConverter({
      distro: daemonConfig.wslDistro,
      binaryPath: `${daemonConfig.artifactDir}/meepcoin-blockhashing`,
      runtimeLibraryDir: `${daemonConfig.artifactDir}/runtime-libs`,
    });
    ownResource('block converter', converterOwner);
    await converterOwner.ready;
    throwIfAborted();
    personalizedWorkIssuer = createServerOwnedPersonalizedWorkIssuer({
      extraNonceAllocator,
      convertFullBlock: (fullHex) => converterOwner.convert(fullHex),
      personalizeTemplate,
      now,
    });
  }

  const endpoint = `http://127.0.0.1:${rpcPort}/json_rpc`;
  const auditA = auditedTransport(makeTransport(endpoint));
  const rpc = createDaemonRpc({ transport: auditA.transport, endpoint, limits: REAL_RPC_LIMITS });

  // ---- daemon A, owned the moment it exists --------------------------------------------------
  const daemonResource = await startOwned({
    startDaemon, config: daemonConfig, rpc, signal, ownResource, label: peer ? 'meepcoind A' : 'meepcoind',
    paired: peer !== null,
  });

  // ---- daemon B and the proved link (paired test only) ---------------------------------------
  let peerContext = null;
  throwIfAborted();
  if (peer !== null) {
    const cfgB = peer.daemon;
    const endpointB = `http://127.0.0.1:${cfgB.rpcPort}/json_rpc`;
    const auditB = auditedTransport(makeTransport(endpointB), { allowed: READ_ONLY_RPC_METHODS });
    const rpcB = createDaemonRpc({ transport: auditB.transport, endpoint: endpointB, limits: REAL_RPC_LIMITS });
    const resourceB = await startOwned({
      startDaemon, config: cfgB, rpc: rpcB, signal, ownResource, label: 'meepcoind B', paired: true,
    });
    throwIfAborted();
    if (daemonResource.imageId !== daemonConfig.expectedImageId || resourceB.imageId !== daemonConfig.expectedImageId) {
      throw new RealDaemonModeError('image_mismatch', 'the two daemons are not both the pinned image');
    }
    // Same genesis, read from the UNGATED status first (the nodes are not synchronised yet).
    const [statusA, statusB] = [await rpc.getInfo(), await rpcB.getInfo()];
    if (statusA.topHeight !== 0 || statusB.topHeight !== 0 || statusA.topBlockHash !== statusB.topBlockHash) {
      throw new RealDaemonModeError('genesis_mismatch', 'the two daemons do not start from the same genesis at height 0');
    }

    const linkObservations = [];
    // BOTH daemons from ONE snapshot: two separate probes could see a connection on one side that the
    // other side's earlier probe had not yet seen, and report a good link as a foreign peer.
    const observe = async () => {
      const table = await daemonResource.observeSocketTable();
      const aConns = table === null ? null : parseConnections(table, daemonResource.linuxPid);
      const bConns = table === null ? null : parseConnections(table, resourceB.linuxPid);
      const verdict = checkPairConnections({ aConns, bConns, a: daemonConfig, b: cfgB });
      return { aConns, bConns, verdict };
    };
    const linkStart = now();
    for (;;) {
      throwIfAborted();
      const o = await observe();
      const [infoA, infoB] = [await rpc.getInfo(), await rpcB.getInfo()];
      if (linkObservations.length < MAX_OBSERVATIONS) {
        linkObservations.push({
          atMs: now() - linkStart, aConns: o.aConns, bConns: o.bConns, linked: o.verdict.linked, bad: o.verdict.bad,
          a: { topHeight: infoA.topHeight, synchronized: infoA.synchronized, out: infoA.outgoingConnections, in: infoA.incomingConnections },
          b: { topHeight: infoB.topHeight, synchronized: infoB.synchronized, out: infoB.outgoingConnections, in: infoB.incomingConnections },
        });
      }
      if (!o.verdict.ok) {
        throw new RealDaemonModeError('unexpected_connection', 'a daemon connection was not numeric loopback to its paired daemon');
      }
      if (o.verdict.linked && infoA.synchronized && infoB.synchronized && infoA.topHeight === 0 && infoB.topHeight === 0) break;
      if (now() - linkStart > peerLinkTimeoutMs) {
        throw new RealDaemonModeError('peer_link_timeout', 'no synchronised A<->B P2P link within the bound');
      }
      await sleep(500);
    }
    throwIfAborted();
    // Now synchronised: the full genesis headers, which must agree with the status read above.
    const [genesisA, genesisB] = [
      await rpc.getLastBlockHeader({ fillPowHash: false }),
      await rpcB.getLastBlockHeader({ fillPowHash: false }),
    ];
    if (genesisA.height !== 0 || genesisB.height !== 0 || genesisA.hash !== genesisB.hash
      || genesisA.hash !== statusA.topBlockHash) {
      throw new RealDaemonModeError('genesis_mismatch', 'the two daemons do not share the genesis at height 0');
    }
    if (naturalPair && (genesisA.timestamp === null || genesisB.timestamp === null
      || genesisA.timestamp !== genesisB.timestamp)) {
      throw new RealDaemonModeError('genesis_timestamp_unverified',
        'natural-difficulty mining requires matching daemon-read genesis timestamps');
    }
    if (naturalPair && genesisA.timestamp !== expectedGenesisTimestamp) {
      throw new RealDaemonModeError('genesis_timestamp_mismatch',
        `daemon-read genesis timestamp ${genesisA.timestamp} differs from pinned ${expectedGenesisTimestamp}`);
    }
    if (naturalPair && genesisA.hash !== expectedGenesisHash) {
      throw new RealDaemonModeError('genesis_hash_mismatch',
        `daemon-read genesis hash ${genesisA.hash} differs from pinned ${expectedGenesisHash}`);
    }
    if (naturalPair && maxGenesisAgeSeconds !== null) {
      const nowMs = now();
      if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
        throw new RealDaemonModeError('genesis_age_unverified', 'the launch clock did not return a valid Unix millisecond timestamp');
      }
      const ageSeconds = Math.floor(nowMs / 1000) - genesisA.timestamp;
      if (ageSeconds < 0 || ageSeconds > maxGenesisAgeSeconds) {
        throw new RealDaemonModeError('genesis_age_out_of_bounds',
          `daemon-read genesis age ${ageSeconds} s is outside [0, ${maxGenesisAgeSeconds}] s`);
      }
    }
    peerContext = {
      daemonResource: resourceB, rpc: rpcB, rpcEndpoint: endpointB, audit: auditB,
      genesis: genesisA, linkObservations, observe,
    };
  }

  // ---- the fresh template(s) -------------------------------------------------------------------
  // One claim per issuance, and at most one per block of the sequence: 1 in every one-shot mode.
  const authority = makeTemplateAuthority({ now, maxClaims: sequenceBlocks });
  if (authority === null || typeof authority !== 'object' || typeof authority.publish !== 'function') {
    throw new RealDaemonModeError('bad_config', 'the template authority contract is invalid');
  }
  // The APPLICATION PATH, cumulative over the run (one template in a one-shot mode, two in the sequence).
  // Per-height figures are the differences between the snapshots taken at each issuance.
  const counters = {
    getBlockTemplate: 0,
    calcPow: 0,
    prepareSubmission: 0,
    dispatchSubmission: 0,
    headerReadback: 0,
    topReadback: 0,
  };
  const rpcSnapshots = [];         // { block, window, atMs, application, totalA, totalB } per issuance
  let templatesIssued = 0;         // every same-height refresh is a fresh template issuance
  let blocksIssued = 0;            // sequence positions only; refresh never advances this

  /**
   * Fetch and bind EXACTLY ONE fresh template from daemon A.
   *
   * Block 1 builds on the current top (in the pair: the shared genesis). Block N > 1 must build on the
   * block the previous run established -- `expectParent` at `expectHeight - 1` -- and daemon A's top is
   * read immediately before the request: if it is anything else, the experiment has changed and this
   * refuses rather than quietly mining on another tip.
   */
  async function issueTemplate({
    block, window = 1, nonceStart = 0, expectHeight = null, expectParent = null, expectSameTop = null,
  }) {
    // Capture may already be enabled by the first template. Advance its immutable attribution before
    // the same-tip/top read so every later record names the context whose issuance it is proving.
    auditA.capture.block = block;
    auditA.capture.window = window;
    rpcSnapshots.push({
      block, window, atMs: now(), application: { ...counters },
      totalA: { ...auditA.counts }, totalB: peerContext === null ? null : { ...peerContext.audit.counts },
    });
    const topBefore = await rpc.getLastBlockHeader({ fillPowHash: false });
    // A SAME-HEIGHT REFRESH IS ONLY EVER ISSUED ON AN UNCHANGED TIP. If daemon A's top moved at all
    // -- our own block, another miner's, a reorg -- this is no longer the same work, and it is
    // refused here, BEFORE the template request, rather than quietly mining a different height.
    if (expectSameTop !== null
      && (String(topBefore.height) !== String(expectSameTop.height) || topBefore.hash !== expectSameTop.hash)) {
      throw new RealDaemonModeError('template_tip_changed', 'daemon A top moved, so this is not the same work');
    }
    if (block > 1 && (String(topBefore.height) !== (expectHeight - 1n).toString() || topBefore.hash !== expectParent)) {
      throw new RealDaemonModeError('template_tip_changed', 'daemon A\'s top is not exactly the block the previous run established');
    }
    auditA.capture.enabled = true;                // from here on, the evidence methods are kept raw
    const tpl = await rpc.getBlockTemplate({
      walletAddress,
      reserveSize: personalizeTemplates ? extraNonceAllocator.reserveSize : 0,
    });
    templatesIssued += 1;
    counters.getBlockTemplate += 1;

    if (tpl.height !== topBefore.height + 1) {
      throw new RealDaemonModeError('template_height', 'the template is not for the block after the current top');
    }
    if (tpl.prevHashHex === null || tpl.prevHashHex !== topBefore.hash) {
      throw new RealDaemonModeError('template_parent', 'the template does not build on the current top block');
    }
    if (tpl.seedHeight === null) throw new RealDaemonModeError('template_seed', 'the template has no seed height');

    // Parsed and bound EXACTLY. Any lossy or malformed field is a refusal, not a rounding. Every call
    // mints a new issuance, job id, content digest and expiry. The personalized path allocates only
    // after the daemon template's chain binding has passed, then performs exactly one canonical
    // full-block conversion; a failure mints no job and the allocated value is never reused.
    const jobInput = {
      height: tpl.height,
      seedHashHex: tpl.seedHashHex,
      wideDifficulty: tpl.wideDifficulty,
      blockhashingBlobHex: tpl.blockhashingBlobHex,
      blocktemplateBlobHex: tpl.blocktemplateBlobHex,
      nonceStart,
      nonceRange: REAL_SEARCH_LIMITS.maxAttempts,
      // Omitted unless trusted startup configuration asked for share work: then the job carries a
      // share target no harder than its block target, and createRealTemplateJob refuses anything else.
      ...(shareDifficulty === null ? {} : { shareDifficulty }),
      seedHeight: tpl.seedHeight,
      ttlMs: REAL_JOB_TTL_MS,
      note: peer
        ? `fresh template ${block} from daemon A of a private exclusive pair`
        : 'fresh template from one private offline local daemon',
    };
    let personalization = null;
    let job;
    if (personalizeTemplates) {
      personalization = await personalizedWorkIssuer.issue(tpl, {
        nonceStart: jobInput.nonceStart,
        nonceRange: jobInput.nonceRange,
        ...(jobInput.shareDifficulty === undefined ? {} : { shareDifficulty: jobInput.shareDifficulty }),
        ttlMs: jobInput.ttlMs,
        note: jobInput.note,
      });
      job = personalization.job;
    } else {
      job = createRealTemplateJob(jobInput, { now });
    }

    if (peerContext !== null) {
      // THE FROZEN TEST CONDITIONS, checked before the job can be used.
      const wantHeight = block === 1 ? 1n : expectHeight;
      const wantParent = block === 1 ? peerContext.genesis.hash : expectParent;
      if (job.height !== wantHeight || tpl.prevHashHex !== wantParent) {
        throw new RealDaemonModeError('template_height',
          `the paired test needs the height-${wantHeight} template on ${block === 1 ? 'the shared genesis' : 'the accepted block'}`);
      }
      if (!naturalPair && job.difficulty !== BigInt(PEER_TEST_FIXED_DIFFICULTY)) {
        throw new RealDaemonModeError('template_difficulty', `the template difficulty is not exactly ${PEER_TEST_FIXED_DIFFICULTY}`);
      }
    }

    // The previous block id inside the FULL block header must be the one the daemon named.
    const full = fullBlockBlobOf(job);
    const { offset } = findNonceOffset(full);
    const blobPrevHex = blobToHex(full.subarray(offset - PREV_ID_BYTES, offset));
    if (blobPrevHex !== tpl.prevHashHex) {
      throw new RealDaemonModeError('template_parent', 'the block blob does not carry the template previous hash');
    }

    // THE PUBLICATION FENCE. get_block_template and, when enabled, the native personalization
    // conversion are awaited operations. The daemon may advance or reorganize while either is in
    // flight. A job must therefore not leave this function until one fresh read-only observation
    // proves that its exact parent is still canonical and its height is still the next height.
    // Cancellation is checked on both sides of the await, so an abort during this read cannot turn
    // a completed but no-longer-authorized observation into published work.
    throwIfAborted();
    const topAfter = await rpc.getLastBlockHeader({ fillPowHash: false });
    throwIfAborted();
    if (topAfter.orphanStatus !== false) {
      throw new RealDaemonModeError('template_tip_not_canonical',
        'daemon A marked the post-conversion canonical-tip recheck as orphaned');
    }
    if (topAfter.height !== topBefore.height || topAfter.hash !== topBefore.hash
      || job.height !== BigInt(topAfter.height) + 1n || tpl.prevHashHex !== topAfter.hash) {
      throw new RealDaemonModeError('template_tip_changed',
        'daemon A tip changed while the template was being issued');
    }

    const ctx = personalization === null ? hashingContextFor(job) : null;
    const context = personalization === null ? Object.freeze({
      epochKeyHex: blobToHex(ctx.epochKey),
      seedHashHex: blobToHex(ctx.seedHash),
      height: ctx.height.toString(),
      templateHex: blobToHex(ctx.template),
    }) : personalization.context;

    const templateFacts = Object.freeze({
      block,
      /** Which nonce window of this block this template is. 1 in every mode without refresh. */
      window,
      height: job.height.toString(),
      majorVersion: job.majorVersion,
      prevHashHex: tpl.prevHashHex,
      seedHashHex: job.seedHashHex,
      seedHeight: job.seedHeight === null ? null : job.seedHeight.toString(),
      wideDifficulty: tpl.wideDifficulty,
      difficulty: job.difficulty.toString(),
      targetHexLE: job.targetHexLE,
      hashingNonceOffset: job.hashingNonceOffset,
      fullNonceOffset: job.fullNonceOffset,
      fullBlockBytes: full.length,
      blockhashingBlobHex: personalization === null ? tpl.blockhashingBlobHex : job.hashingTemplateHex,
      blocktemplateBlobHex: personalization === null ? tpl.blocktemplateBlobHex : blobToHex(full),
      personalized: personalization !== null,
      ...(personalization === null ? {} : {
        reservedOffset: personalization.reservedOffset,
        reservedSize: personalization.reservedSize,
        extraNonceDigest: personalization.extraNonceDigest,
      }),
      contentDigest: job.contentDigest,
      jobId: job.jobId,
      issuanceId: job.issuanceId,
      expiresAtMs: job.expiresAtMs,
      nonceStart: job.nonceStart,
      nonceRange: job.nonceRange,
      topBeforeHeight: topBefore.height,
      topBeforeHash: topBefore.hash,
      topAfterHeight: topAfter.height,
      topAfterHash: topAfter.hash,
      /** The destination this template's coinbase was requested for. A public address; never a secret. */
      coinbaseAddress: walletAddress,
      coinbaseIsNeutralDefault: walletAddress === REAL_COINBASE_ADDRESS,
    });
    return Object.freeze({ job, context, templateFacts, canonical: Object.freeze({ prevHashHex: tpl.prevHashHex }) });
  }

  throwIfAborted();
  const first = await issueTemplate({ block: 1 });
  authority.publish(first.job);
  blocksIssued = 1;
  let latest = first;

  // A FUTURE MULTI-CLIENT COORDINATOR needs more than the allocator/converter half exposed by
  // `personalizedWorkIssuer`: it needs complete, chain-fenced jobs, and it must not be able to
  // start another daemon, converter, allocator or template authority.  This process-owned
  // capability lends out the already-issued first job, then serializes every later request through
  // the SAME issueTemplate closure above.  Thus each later result includes the post-conversion
  // canonical-tip fence and consumes the same owned allocator/converter domain.
  //
  // The first result that is actually returned pins the canonical work identity.  Every later
  // result must remain at that exact height and parent.  `stillWanted` is checked before joining
  // the queue, again after reaching its head, and as the final instruction before return: a queued
  // disconnect/Stop therefore cannot receive either the initial job or a newly minted job.
  let serializedPersonalizedTail = Promise.resolve();
  let serializedPersonalizedFirstAvailable = true;
  let serializedPersonalizedCanonical = null;
  let serializedPersonalizedAdmissions = 0;
  let serializedPersonalizedOutstanding = 0;
  // One active issue plus one FIFO waiter is the entire demand a two-slot coordinator can create.
  // Keeping this independent of the lifetime cap makes a burst cheap even early in the process.
  const maxSerializedPersonalizedOutstanding = 2;
  const serializedPersonalizedTemplateIssuer = personalizeTemplates
    && sequenceBlocks === 1 && refreshWindows === 1 ? Object.freeze({
    async issue(options = {}) {
      if (options === null || typeof options !== 'object' || Array.isArray(options)) {
        throw new RealDaemonModeError('bad_config', 'serialized personalized issuance options must be an object');
      }
      for (const key of Reflect.ownKeys(options)) {
        if (key !== 'stillWanted') {
          throw new RealDaemonModeError('bad_config',
            `unexpected serialized personalized issuance option ${String(key).slice(0, 40)}`);
        }
      }
      const stillWanted = options.stillWanted ?? (() => true);
      if (typeof stillWanted !== 'function') {
        throw new RealDaemonModeError('bad_config', 'stillWanted must be a function');
      }
      if (stillWanted() !== true) {
        throw new RealDaemonModeError('personalized_issue_cancelled',
          'the caller no longer wants personalized work');
      }

      // Admission happens synchronously before the first await and is deliberately irreversible.
      // A caller that withdraws while queued has still spent its bounded admission: cancellation
      // cannot be used as an unbounded retry mechanism.  The initial lend is one of these contexts,
      // so no more than REAL_MAX_CONTEXTS_PER_START results can ever be selected or minted here.
      if (serializedPersonalizedAdmissions >= REAL_MAX_CONTEXTS_PER_START) {
        throw new RealDaemonModeError('personalized_issue_exhausted',
          `personalized work is limited to ${REAL_MAX_CONTEXTS_PER_START} lifetime admissions`);
      }
      if (serializedPersonalizedOutstanding >= maxSerializedPersonalizedOutstanding) {
        throw new RealDaemonModeError('personalized_issue_queue_full',
          'the serialized personalized issuance queue is full');
      }
      serializedPersonalizedAdmissions += 1;
      serializedPersonalizedOutstanding += 1;

      // Take a FIFO turn without allowing a rejection to poison the tail.  The tail promises only
      // release; all result/error state stays inside this caller's turn.
      const previous = serializedPersonalizedTail;
      let release;
      serializedPersonalizedTail = new Promise((resolve) => { release = resolve; });
      await previous;
      try {
        if (stillWanted() !== true) {
          throw new RealDaemonModeError('personalized_issue_cancelled',
            'the caller no longer wants personalized work');
        }
        const result = serializedPersonalizedFirstAvailable
          ? first
          : await issueTemplate({
            block: first.templateFacts.block,
            expectHeight: first.job.height,
            expectParent: first.canonical.prevHashHex,
            expectSameTop: {
              height: first.templateFacts.topAfterHeight,
              hash: first.templateFacts.topAfterHash,
            },
          });
        const identity = Object.freeze({
          height: result.job.height.toString(),
          parent: result.canonical.prevHashHex,
        });
        if (serializedPersonalizedCanonical !== null
          && (identity.height !== serializedPersonalizedCanonical.height
            || identity.parent !== serializedPersonalizedCanonical.parent)) {
          throw new RealDaemonModeError('personalized_issue_tip_changed',
            'personalized work no longer has the first returned canonical height and parent');
        }
        if (stillWanted() !== true) {
          throw new RealDaemonModeError('personalized_issue_cancelled',
            'the caller no longer wants personalized work');
        }
        if (serializedPersonalizedCanonical === null) serializedPersonalizedCanonical = identity;
        serializedPersonalizedFirstAvailable = false;
        return result;
      } finally {
        serializedPersonalizedOutstanding -= 1;
        release();
      }
    },
    }) : null;

  // The daemon block_run talks to (A). Every call is the adapter's own; the wrapper only counts the
  // APPLICATION PATH. Total RPC traffic, setup and audit reads included, is in the audited transport.
  const runDaemon = Object.freeze({
    submissionAdapter: rpc,
    counters,
    async calcPow(req) { counters.calcPow += 1; return rpc.calcPow(req); },
    prepareSubmission(hex, operation) { counters.prepareSubmission += 1; return rpc.prepareSubmission(hex, operation); },
    dispatchSubmission(capability) { counters.dispatchSubmission += 1; return rpc.dispatchSubmission(capability); },
    async getBlockHeaderByHeight(h, o) { counters.headerReadback += 1; return rpc.getBlockHeaderByHeight(h, o); },
    async getLastBlockHeader(o) { counters.topReadback += 1; return rpc.getLastBlockHeader(o); },
  });

  const peerApi = peerContext === null ? null : Object.freeze({
    daemonResource: peerContext.daemonResource,
    rpcEndpoint: peerContext.rpcEndpoint,
    genesis: peerContext.genesis,
    linkObservations: peerContext.linkObservations,
    /** Every RPC this process sent daemon B, by method. Only read-only methods can appear. */
    get rpcCounts() { return { ...peerContext.audit.counts }; },
    /**
     * READ-ONLY: wait (bounded) for daemon B's canonical top and header at `height` to be exactly
     * daemon A's. Nothing is ever sent to B but reads; a failure is P2P_PROPAGATION_FAILED.
     *
     * `height` defaults to the first template's; `expectedBlockId` additionally requires A's canonical
     * block there to be that exact block; `shouldContinue` ends the wait early (`cancelled`).
     */
    async awaitPropagation({
      timeoutMs = PEER_PROPAGATION_TIMEOUT_MS, pollMs = 500, height = null, expectedBlockId = null,
      shouldContinue = () => true,
    } = {}) {
      const h = height === null ? first.job.height.toString() : String(height);
      const aHeader = await rpc.getBlockHeaderByHeight(h, { fillPowHash: true });
      const aTop = await rpc.getLastBlockHeader({ fillPowHash: true });
      if (!sameCanonicalHeader(aHeader, aTop) || (expectedBlockId !== null && aHeader.hash !== expectedBlockId)) {
        return { converged: false, reason: 'a_not_canonical', aHeader, aTop, observations: [] };
      }
      const observations = [];
      const t0 = now();
      for (;;) {
        if (!shouldContinue()) {
          return { converged: false, reason: 'cancelled', aHeader, aTop, observations };
        }
        let bTop = null;
        let bHeader = null;
        let readFailure = null;
        const readAtMs = now() - t0;
        try {
          bTop = await peerContext.rpc.getLastBlockHeader({ fillPowHash: true });
          if (bTop.height >= aHeader.height) bHeader = await peerContext.rpc.getBlockHeaderByHeight(h, { fillPowHash: true });
        } catch (err) {
          readFailure = typeof err?.code === 'string' ? err.code : 'read_failed';
        }
        const o = await peerContext.observe();
        if (observations.length < MAX_OBSERVATIONS) {
          observations.push({
            atMs: now() - t0, readAtMs, bTopHeight: bTop?.height ?? null, readFailure,
            aConns: o.aConns, bConns: o.bConns, linked: o.verdict.linked, bad: o.verdict.bad,
          });
        }
        if (!o.verdict.ok) {
          return { converged: false, reason: 'unexpected_connection', aHeader, aTop, bHeader, bTop, observations };
        }
        if (sameCanonicalHeader(aHeader, bHeader) && sameCanonicalHeader(aTop, bTop)) {
          return { converged: true, elapsedMs: now() - t0, aHeader, aTop, bHeader, bTop, observations };
        }
        if (now() - t0 >= timeoutMs) {
          return { converged: false, reason: 'P2P_PROPAGATION_FAILED', aHeader, aTop, bHeader, bTop, observations };
        }
        await sleep(pollMs);
      }
    },
  });

  /**
   * THE DEVELOPMENT SEQUENCE (trusted configuration only). `issueNext` fetches EXACTLY ONE more template,
   * for the block after `acceptedBlockId`, publishes it through the authority -- so the previous issuance
   * is irreversibly superseded before the new one can be acted upon -- and refuses to go past the
   * configured total. `acceptedBlockId` is simply the block that now sits at the current template's
   * height: this browser session's own accepted block, or an externally mined one that superseded it.
   */
  /**
   * THE CANONICAL-TIP READBACK FOR THE OBSERVER, and only for it.
   *
   * Same daemon, same strict adapter, same validation as every other read: get_last_block_header on
   * A, through createDaemonRpc, which refuses a malformed height or hash rather than coercing it.
   * It is a SEPARATE audited client for two reasons, neither of them a second trust source:
   *
   *   - the evidence transport captures raw request/response bytes for get_last_block_header, and a
   *     poller would fill that bounded buffer with observations and start dropping the per-height
   *     records a live run depends on;
   *   - its method allowlist is READ-ONLY, so this path cannot submit, calc_pow or fetch a template
   *     even if something later asked it to.
   *
   * Only a sequence has anything to observe; one-shot modes get null.
   */
  const tipAudit = sequenceBlocks === 1
    ? null
    : auditedTransport(makeTransport(endpoint), { allowed: READ_ONLY_RPC_METHODS });
  const tipRpc = tipAudit === null
    ? null
    : createDaemonRpc({ transport: tipAudit.transport, endpoint, limits: REAL_RPC_LIMITS });
  const tipSource = tipRpc === null ? null : Object.freeze({
    async readTip() {
      const header = await tipRpc.getLastBlockHeader({ fillPowHash: false });
      if (header.orphanStatus !== false) {
        throw new RealDaemonModeError('tip_not_canonical',
          'daemon A marked its reported last block header as orphaned');
      }
      return { height: String(header.height), blockId: header.hash };
    },
    /** Everything this observer has asked daemon A, by method. Read-only methods only. */
    get counts() { return { ...tipAudit.counts }; },
  });

  let issuing = false;
  let windowsIssued = 1;          // the first template is window 1

  /**
   * THE OPT-IN SAME-HEIGHT REFRESH (trusted configuration only).
   *
   * `issueRefresh` fetches EXACTLY ONE more template for the SAME height, only while daemon A's
   * canonical top is still exactly the one the current template was built on, publishes it through
   * the authority -- so the previous issuance is irreversibly superseded before the new one can be
   * acted upon -- and gives it a nonce window that starts where the previous window ended. The
   * disjointness is checked against the window actually issued, not assumed: an overlapping window
   * is a refusal, because a repeated nonce would be repeated work claiming to be fresh.
   *
   * The template BYTES may be byte-for-byte identical (same height, same tip, same coinbase), and
   * that is fine: the jobId, the issuanceId and the nonce window are what make this a new, bounded
   * unit of work. Nothing here can authorise a second block submission for one height: every window
   * of that height shares the authority's current issuance, while its cumulative claim cap remains
   * exactly the configured number of sequence heights.
   */
  const refreshApi = refreshWindows === 1 ? null : Object.freeze({
    maxWindows: refreshWindows,
    get windowsIssued() { return windowsIssued; },
    async issueRefresh({ stillWanted = () => true } = {}) {
      if (issuing || windowsIssued >= refreshWindows) {
        throw new RealDaemonModeError('refresh_exhausted', 'no further nonce window may be issued for this height');
      }
      // Claims are cumulative over the whole sequence. A claim from an EARLIER height must not
      // suppress refresh at the new height; only this exact current issuance closes this height.
      if (authority.isClaimed(latest.job.issuanceId)) {
        throw new RealDaemonModeError('refresh_refused', 'a submission was already claimed for this height');
      }
      const nonceStart = latest.job.nonceStart + latest.job.nonceRange;
      if (!Number.isSafeInteger(nonceStart) || nonceStart + REAL_SEARCH_LIMITS.maxAttempts > 0x100000000) {
        throw new RealDaemonModeError('refresh_window_exhausted', 'the uint32 nonce space has no further whole window');
      }
      issuing = true;
      try {
        const next = await issueTemplate({
          // The BLOCK stays fixed and only this height's WINDOW advances.
          block: latest.templateFacts.block,
          window: windowsIssued + 1,
          nonceStart,
          expectHeight: latest.job.height,
          expectParent: latest.canonical.prevHashHex,
          expectSameTop: { height: latest.templateFacts.topBeforeHeight, hash: latest.templateFacts.topBeforeHash },
        });
        if (next.job.height !== latest.job.height) {
          throw new RealDaemonModeError('template_height', 'a refresh must be for the same height');
        }
        // PROVABLY DISJOINT, CHECKED. Not "the same start plus a constant": the window this job
        // actually carries must begin at or after the end of the window that came before it.
        if (next.job.nonceStart < latest.job.nonceStart + latest.job.nonceRange) {
          throw new RealDaemonModeError('refresh_window_overlap', 'the refreshed nonce window overlaps the previous one');
        }
        // THE LAST GATE BEFORE AN IRREVERSIBLE PUBLICATION. The template request is an await, and a
        // Stop, a hidden tab or a lost socket can land while it is outstanding. Publishing here
        // would supersede the old issuance and mint a live capability for a session that no longer
        // consents, and no later check could take that back. The caller is asked once more, and a
        // refusal leaves the authority exactly as it was.
        if (stillWanted() !== true) {
          throw new RealDaemonModeError('refresh_cancelled', 'the session no longer consents to another window');
        }
        authority.publish(next.job);
        windowsIssued += 1;
        latest = next;
        return next;
      } finally {
        issuing = false;
      }
    },
  });

  const sequenceApi = sequenceBlocks === 1 ? null : Object.freeze({
    total: sequenceBlocks,
    /** Every daemon template request, including same-height refreshes. */
    get templatesIssued() { return templatesIssued; },
    /** Sequence positions issued; the guard that decides whether another height exists. */
    get blocksIssued() { return blocksIssued; },
    async issueNext({ acceptedBlockId, acceptedHeight, stillWanted = () => true }) {
      if (issuing || blocksIssued >= sequenceBlocks) {
        throw new RealDaemonModeError('sequence_exhausted', 'no further template may be issued in this sequence');
      }
      if (typeof acceptedBlockId !== 'string' || !/^[0-9a-f]{64}$/.test(acceptedBlockId)
        || String(acceptedHeight) !== latest.job.height.toString()) {
        throw new RealDaemonModeError('bad_sequence', 'the next template must follow the block the current template produced');
      }
      issuing = true;
      try {
        const next = await issueTemplate({ block: blocksIssued + 1, expectHeight: latest.job.height + 1n, expectParent: acceptedBlockId });
        // The template RPC is an await. A Stop or the whole-Start deadline may land while it is
        // outstanding; publishing afterward would supersede the current issuance and mint work for
        // a session that no longer has authority. This is the same final publication gate used by
        // same-height refreshes. No event-loop turn exists between this check and publish().
        if (stillWanted() !== true) {
          throw new RealDaemonModeError('sequence_cancelled', 'the session no longer consents to another block');
        }
        authority.publish(next.job);
        latest = next;
        blocksIssued += 1;
        // Window numbering and disjoint nonce ranges are per height. Reset only after the next
        // height's validated template was irreversibly published and adopted.
        windowsIssued = 1;
        return next;
      } finally {
        issuing = false;
      }
    },
  });

  return {
    /** Public, read-only echo of the trusted startup destination, for the run record. */
    coinbaseAddress: walletAddress,
    job: first.job,
    latch,
    authority,
    daemon: runDaemon,
    daemonResource,
    rpcEndpoint: endpoint,
    templateFacts: first.templateFacts,
    peer: peerApi,
    sequence: sequenceApi,
    /** The opt-in same-height refresh source, or null when this run may search one window only. */
    refresh: refreshApi,
    refreshWindows,
    tipSource,
    /** True only when trusted configuration asked for share work; the server selects its profile on this. */
    shareWork: shareDifficulty !== null,
    shareDifficulty,
    naturalDifficulty: naturalPair,
    /** True only for the source-fixed two-window engineering probe requested at trusted startup. */
    refreshHandoffProbe,
    /** True only when every issued daemon template is server-personalized through the owned native converter. */
    personalizedTemplates: personalizeTemplates,
    /** Server-only allocator/converter capability. Null in the legacy unpersonalized modes. */
    personalizedWorkIssuer,
    /** Complete same-tip personalized jobs, serialized through this process's one fenced issuer. */
    serializedPersonalizedTemplateIssuer,
    /** Daemon A's total RPC counts, the raw evidence records (template onwards), and per-issuance snapshots. */
    rpcAudit: Object.freeze({
      get counts() { return { ...auditA.counts }; },
      get raw() { return auditA.raw.slice(); },
      get rawDropped() { return auditA.rawDropped; },
      get rawLimit() { return auditA.rawLimit; },
      get snapshots() { return rpcSnapshots.map((s) => ({ ...s })); },
    }),
    expectedHashHexLE: null,          // there is no known answer for a fresh template
    recordedContext: first.context,
    canonical: first.canonical,
    /** `context` is the current block's server-owned hashing context; the first template's by default. */
    makeServerVerifier: ({ signal: sig, onFault, context = first.context }) => makeVerifier({
      ...(wasmPaths ? { wasmPaths } : {}),
      ...(helperPath ? { helperPath } : {}),
      ...(wslDistro ? { wslDistro } : {}),
      ...(helperOptions ? { helperOptions } : {}),
      signal: sig,
      onFault,
      context,
      selfTestNonces: [],
      checkSourceIdentity: true,
    }),
  };
}
