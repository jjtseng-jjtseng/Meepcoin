// The local MeepCoin development pool: one loopback listener serving the miner page over HTTP and
// the job/share protocol over WebSocket.
//
// This is a DEVELOPMENT POOL. In its default synthetic mode and in the recorded-template simulation
// it includes, connects to and runs no MeepCoin or Monero daemon; the synthetic mode issues one fixed
// synthetic job and throws every accepted share away. Only the explicit, off-by-default
// real-local-daemon mode starts, owns and stops its private local daemon, or its private pair (see
// real_daemon_mode.mjs).
// There is no accounting, no balance, no wallet, no payout and nothing durable. It refuses to bind
// anywhere but loopback.
//
// CONSENT BOUNDARY. Starting the pool performs NO MeepHash-W work: it checks the pinned Wasm
// identity (a SHA-256 of two small files), reads the synthetic target out of the committed
// vectors, and listens. The Wasm module is not imported and no dataset exists until a connected
// client sends `start_request`.
//
// What that does and does not establish. The OFFICIAL page this server serves sends
// `start_request` only from its Start click handler and creates its Worker only after
// `mining_ready`; that is proven structurally and behaviourally by the tests, and it is what a
// person using this page actually gets. The SERVER, however, can only observe that an
// OS-local protocol peer declared start intent. It cannot prove that any given message came from
// a human clicking anything, and Origin is not authentication. Any local program able to open a
// loopback socket can send `start_request`.

import { createServer } from 'node:http';

import { attachWebSocketServer, CLOSE } from './ws.mjs';
import { createStaticHandler } from './static.mjs';
import { createJobStore, DEFAULT_NONCE_START, DEFAULT_NONCE_RANGE } from './jobs.mjs';
import { createSession, DEFAULT_LIMITS } from './session.mjs';
import {
  REAL_DAEMON_PROFILE, REAL_P2P_PROFILE, REAL_P2P_NATURAL_PROFILE, REAL_P2P_SHARE_PROFILE, REAL_TWO_SLOT_PROFILE,
  SIM_MODE, createSimulationContext,
  realRefreshProfile, realSequenceProfile, realNaturalSequenceProfile, realSequenceRefreshProfile, realSequenceShareProfile,
  createSimulationSession,
} from './sim_session.mjs';
import {
  REAL_DAEMON_MODE, REAL_SEQUENCE_DEV_MAX_BLOCKS, SYNTHETIC_MODE,
} from '../../web-miner/lib/shared/protocol.js';
import { buildRecordedSimulation } from './recorded_simulation.mjs';
import { buildRealDaemonMode } from './real_daemon_mode.mjs';
import { createTwoSlotCoordinator } from './two_slot_coordinator.mjs';
import { createTwoSlotSession } from './two_slot_session.mjs';
import { createTipObserver } from './tip_observer.mjs';
import { createShareVerifier } from './verifier.mjs';
import { createDualVerifier } from './dual_verifier.mjs';
import { verifyWasmIdentity, loadSyntheticFixture } from './identity.mjs';
import { MAX_MESSAGE_BYTES, REJECT_REASONS } from '../../web-miner/lib/shared/protocol.js';

// A socket that never completes an HTTP request must not occupy one of the bounded connection
// slots forever. This is pool-owned rather than a claim about node:http's implementation-specific
// timeout scan. A complete first HTTP request or successful WebSocket upgrade clears it.
const PRE_REQUEST_TIMEOUT_MS = 5_000;

export class NonLoopbackBindError extends Error {
  constructor(host, detail = '') {
    super(
      `refusing to bind to ${JSON.stringify(host)}: the MeepCoin development pool listens on `
      + 'loopback only. It has no authentication or TLS; its bounded local abuse controls are '
      + `not an Internet security boundary, and it must never be reachable from another machine.${detail ? ` (${detail})` : ''}`,
    );
    this.name = 'NonLoopbackBindError';
    this.host = host;
  }
}

/**
 * Strictly loopback: 127.0.0.0/8, ::1, or the name "localhost". Everything else -- including
 * 0.0.0.0, ::, a LAN address or a hostname -- is refused.
 *
 * Accepts the bracketed IPv6 form too, because people paste URL authorities in, but see
 * normalizeBindHost(): brackets are URL syntax and are stripped before the socket ever sees it.
 */
export function isLoopbackHost(host) {
  if (typeof host !== 'string' || host.length === 0) return false;
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost') return true;
  if (h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(h);
  const candidate = mapped ? mapped[1] : h;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(candidate);
  if (!v4) return false;
  const octets = v4.slice(1).map(Number);
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  return octets[0] === 127;
}

export function isIpv6Literal(host) {
  const h = String(host).trim().replace(/^\[|\]$/g, '');
  return h.includes(':');
}

/**
 * The string to hand to socket.listen(). Brackets are URL-authority syntax, never part of an
 * address, so they are stripped here. Separating this from formatAuthority() is the whole fix
 * for the IPv6 URLs: "::1" is a bind host, "[::1]" is a URL authority, and they are not
 * interchangeable.
 */
export function normalizeBindHost(host) {
  return String(host).trim().replace(/^\[|\]$/g, '');
}

/** The `host:port` authority for a URL. IPv6 literals MUST be bracketed here (RFC 3986 3.2.2). */
export function formatAuthority(host, port) {
  const h = normalizeBindHost(host);
  return isIpv6Literal(h) ? `[${h}]:${port}` : `${h}:${port}`;
}

export function assertLoopbackHost(host) {
  if (!isLoopbackHost(host)) throw new NonLoopbackBindError(host);
  return normalizeBindHost(host);
}

/**
 * @param {object} [o]
 * @param {string} [o.host]        must be loopback
 * @param {number} [o.port]        0 = ephemeral (used by every test)
 * @param {number} [o.nonceRange]  size of the synthetic search window
 */
/**
 * THE ONE PLACE A REAL-DAEMON RUN'S PROFILE IS CHOSEN, from what the BUILDER actually produced.
 *
 * Every mode here is opt-in trusted startup configuration and none of them is reachable from a page,
 * a query string or a client message. A sequence advances heights after an accepted block; refresh
 * searches several nonce windows at one height, and the two may compose under the shared total-context
 * cap. Share work composes with either. The profile is built FOR the configured numbers, so the text
 * the page shows before Start states the exact bounds the server holds.
 *
 * Exported so a non-live test can check the choice without starting a listener or a daemon.
 */
export function selectSimulationProfile(built) {
  if (built?.naturalDifficulty === true) {
    if (!built?.peer || built?.shareWork === true || built?.refresh) {
      throw new TypeError('natural-difficulty mode requires one unrefreshed private pair without share work');
    }
    return built.sequence ? realNaturalSequenceProfile(built.sequence.total) : REAL_P2P_NATURAL_PROFILE;
  }
  if (built?.sequence && built?.refresh) {
    return realSequenceRefreshProfile(built.sequence.total, built.refresh.maxWindows, {
      shareWork: built.shareWork === true,
    });
  }
  if (built?.sequence) {
    return built.shareWork === true
      ? realSequenceShareProfile(built.sequence.total)
      : realSequenceProfile(built.sequence.total);
  }
  if (built?.refresh) {
    return realRefreshProfile(built.refresh.maxWindows, {
      shareWork: built.shareWork === true,
      probeShareDifficulty: built.refreshHandoffProbe === true ? built.shareDifficulty : null,
    });
  }
  if (built?.shareWork === true) return REAL_P2P_SHARE_PROFILE;
  return built?.peer ? REAL_P2P_PROFILE : REAL_DAEMON_PROFILE;
}

export async function startDevPool({
  host = '127.0.0.1',
  port = 0,
  nonceStart = DEFAULT_NONCE_START,
  nonceRange = DEFAULT_NONCE_RANGE,
  jobTtlMs,
  limits = {},
  now = () => Date.now(),
  log = () => {},
  wasmPaths,
  /**
   * 'dual' (default, the product path): every share is recomputed by BOTH the server's own
   * WebAssembly build and the long-lived native frozen-v2 helper, and is accepted only if the two
   * agree byte-for-byte. 'wasm' is the older single-build path, kept so the lifecycle tests can
   * exercise pool mechanics without spawning a child per case.
   */
  verifierMode = 'dual',
  /**
   * 'synthetic' (DEFAULT, unchanged) or 'recorded-template-simulation'.
   *
   * The simulation mode is opt-in through a deliberate local option only. Loading the page cannot
   * select it and NO CLIENT MESSAGE CAN CHANGE IT: it is read once here and never again.
   */
  mode = 'synthetic',
  /**
   * Test seam: builds the ONE recorded-template simulation. Injected so a startup-failure case can
   * be exercised without editing the committed vector file.
   */
  simulationFactory = buildRecordedSimulation,
  /**
   * REAL-LOCAL-DAEMON options, read only when `mode` is 'real-local-daemon': { daemon, walletAddress }.
   * `daemon` is local_daemon.mjs's closed config. Nothing a client sends can reach these.
   */
  realDaemon = null,
  /** Trusted opt-in: two independent browser assignments on one private canonical tip. */
  twoSlotAssignments = false,
  /** Test seam: builds the ONE real-daemon context. The non-live tests inject a scripted one. */
  realDaemonFactory = buildRealDaemonMode,
  /**
   * TRUSTED STARTUP CONFIGURATION for the canonical-tip observer of a sustained sequence:
   * { intervalMs, setTimer, clearTimer }. The non-live tests drive its clock through here.
   * No client message, query string or page can reach it.
   */
  tipObserverOptions = {},
  helperPath,
  /** The PARENT-PINNED WSL distribution. Top-level and authoritative; never accepted nested. */
  wslDistro,
  helperOptions,
  // How the pool obtains its verifier. The ownership tests inject deterministic child-shaped fakes
  // through this seam.
  verifierFactory = null,
  // Test seam: awaited by the static handler before it reads a file, so a test can hold an async
  // HTTP handler open and prove shutdown drains it.
  beforeStaticRead,
} = {}) {
  // ---- CLOSED ENUM, CHECKED FIRST ---------------------------------------------------------
  // Before the bind check, before the identity read, before any construction and long before the
  // listener. `mode` used to be compared only against the simulation constant, so `mode: 'simluation'`
  // -- a typo -- silently ran the synthetic pool while the caller believed otherwise. An unknown
  // mode is now a refusal, not a default.
  if (mode !== SYNTHETIC_MODE && mode !== SIM_MODE && mode !== REAL_DAEMON_MODE) {
    throw new TypeError(
      `unknown pool mode ${JSON.stringify(String(mode).slice(0, 40))}; `
      + `expected ${JSON.stringify(SYNTHETIC_MODE)}, ${JSON.stringify(SIM_MODE)} or ${JSON.stringify(REAL_DAEMON_MODE)}`);
  }
  if (mode === REAL_DAEMON_MODE && (realDaemon === null || typeof realDaemon !== 'object')) {
    throw new TypeError('real-local-daemon mode requires the explicit realDaemon option');
  }
  if (typeof twoSlotAssignments !== 'boolean'
    || (twoSlotAssignments && (mode !== REAL_DAEMON_MODE
      || realDaemon.personalizeTemplates !== true
      || (realDaemon.sequenceBlocks ?? 1) !== 1
      || (realDaemon.refreshWindows ?? 1) !== 1
      || (realDaemon.peer ?? null) !== null
      || (realDaemon.shareDifficulty ?? null) !== null))) {
    throw new TypeError('twoSlotAssignments requires one personalized, one-height, one-window private daemon without peer or share work');
  }

  // Refuse a non-loopback bind BEFORE anything is opened or allocated.
  const bindHost = assertLoopbackHost(host);

  // This is a RAW TCP admission limit, not a WebSocket/session limit. It therefore also bounds
  // peers that connect and then never finish an HTTP request line (the slow-loris shape). Keep the
  // trusted option deliberately small and closed: a typo must fail before file reads, daemon
  // construction or listen(), not silently mean "unlimited".
  const maxConnections = limits.maxConnections ?? 32;
  if (!Number.isSafeInteger(maxConnections) || maxConnections < 1 || maxConnections > 1024) {
    throw new TypeError('limits.maxConnections must be a safe integer from 1 through 1024');
  }

  // Cheap file integrity, before any import and before listening. NOT MeepHash-W, NOT mining:
  // this reads and SHA-256s ~58.1 KiB of build output and keeps those exact Buffers, which are
  // then the only bytes the static server will ever send for the algorithm routes. Nothing is
  // imported, compiled or instantiated, no dataset is allocated and no hash is computed.
  //
  // ONE read: `identity.bytes` are the very Buffers that were hashed, so the snapshots cannot be
  // a second, unverified read of the same paths.
  const identity = verifyWasmIdentity(wasmPaths);
  const verifiedArtifacts = new Map([
    ['/wasm/meepow.mjs', identity.bytes.get('meepow/wasm/meepow.mjs')],
    ['/wasm/meepow.wasm', identity.bytes.get('meepow/wasm/meepow.wasm')],
  ]);

  // The synthetic target comes from the COMMITTED vectors, so starting the pool costs zero
  // MeepHash-W computations. pool/dev/tests/identity.test.mjs proves it equals what the Wasm
  // produces.
  const fixture = loadSyntheticFixture({ nonceStart, nonceRange });

  const jobs = createJobStore({ fixture, now, ...(jobTtlMs === undefined ? {} : { jobTtlMs }) });
  jobs.issue();

  // ---------------------------------------------------------------- lazy verifier

  let verifier = null;
  let verifierState = 'uninitialized';
  let verifierPromise = null;
  let verifierInitCount = 0;
  let closing = false;
  let closePromise = null;
  // Aborts a verifier startup that may never finish, so cancellation is never queued behind it.
  let initAbort = null;
  // Set when a graceful close could not be confirmed. The RESOURCE HANDLE IS NOT DISCARDED: a
  // caller can inspect it and call close()/forceClose() again. Marking a resource released when
  // release failed is how an un-reaped child gets lost.
  let closeFailure = null;
  // ABNORMAL-BUT-RELEASED SHUTDOWNS. A resource that is positively gone is not retained and not
  // retried -- but an abnormal QUIT/BYE/exit transcript is a fact the operator must see. It used
  // to exist only as a safeLog() event, and the default logger is a no-op that the CLI never
  // replaces, so the whole thing reached the user as exit code 0 and silence.
  //
  // APPEND-ONLY FOR THE LIFETIME OF THIS POOL. It used to be cleared at the start of every
  // shutdown attempt, and that erased history: a first attempt could release resource A
  // abnormally, record it, DELETE A from the ownership graph, and still fail because resource B
  // was retained -- and the retry, finding A already gone, could never rediscover the anomaly and
  // returned a perfectly clean result. The CLI retries automatically, so a real abnormal shutdown
  // became exit 0. A retry may ADD facts; it may never remove one that already happened.
  const shutdownAnomalies = [];
  // One outward row per resource. Later attempts may add facts to that row, but never create a
  // second row for the same handle or erase what an earlier failed attempt established.
  const shutdownAnomalyByResource = new WeakMap();
  // A legal maximum-length run can release one verifier per block and then two daemons. Reserve
  // another verifier-sized half for partial-startup components and late resources, while keeping
  // the ledger absolutely bounded by the same build-time sequence ceiling.
  const MAX_SHUTDOWN_ANOMALIES = REAL_SEQUENCE_DEV_MAX_BLOCKS * 2;
  function recordShutdownAnomaly(label, reason, resource = null) {
    const boundedReason = String(reason).slice(0, 400);
    if (resource !== null && (typeof resource === 'object' || typeof resource === 'function')) {
      const existing = shutdownAnomalyByResource.get(resource);
      if (existing) {
        if (!existing.reason.includes(boundedReason)) {
          existing.reason = `${existing.reason}; ${boundedReason}`.slice(0, 400);
        }
        return;
      }
    }
    const entry = { label: String(label), reason: boundedReason };
    // Resource-backed rows deduplicate by identity above. Label/reason dedup is only for the rare
    // non-resource diagnostic: two distinct rotated verifiers may legitimately share both strings.
    if (resource === null
      && shutdownAnomalies.some((a) => a.label === entry.label && a.reason === entry.reason)) return;
    // ...and capped, so a pathological sequence of DISTINCT reasons cannot either.
    if (shutdownAnomalies.length >= MAX_SHUTDOWN_ANOMALIES) return;
    shutdownAnomalies.push(entry);
    if (resource !== null && (typeof resource === 'object' || typeof resource === 'function')) {
      shutdownAnomalyByResource.set(resource, entry);
    }
  }

  /**
   * Append a fact to a resource's EXISTING anomaly row, or do nothing.
   *
   * WHY THIS IS NOT recordShutdownAnomaly(). `protocolAnomalies` means "a resource let go, or is
   * letting go, abnormally" -- it is the ledger a later successful retry may not erase. A close
   * attempt that FAILED is a different fact: it is already in `failures`, it already fails this
   * shutdown, and the CLI already exits nonzero for it, and retrying it until it succeeds is the
   * documented, tested behaviour of this pool (pool/dev/tests/ownership_graph.test.mjs). Opening a
   * fresh anomaly row for such a resource turned an ordinary retried teardown into a permanent
   * protocol anomaly for a second, unrelated handle.
   *
   * A resource that ALREADY has a row is different: something abnormal was established about that
   * exact handle, and every later fact about it belongs on that one row rather than being lost.
   */
  function appendShutdownAnomalyFact(reason, resource) {
    if (resource === null || (typeof resource !== 'object' && typeof resource !== 'function')) return false;
    const existing = shutdownAnomalyByResource.get(resource);
    if (!existing) return false;
    const boundedReason = String(reason).slice(0, 400);
    if (!existing.reason.includes(boundedReason)) {
      existing.reason = `${existing.reason}; ${boundedReason}`.slice(0, 400);
    }
    return true;
  }

  function readShutdownOutcome(label, resource) {
    try {
      return resource?.shutdownOutcome ?? null;
    } catch (err) {
      recordShutdownAnomaly(
        label,
        `shutdownOutcome read threw: ${String(err?.message ?? err).slice(0, 240)}`,
        resource,
      );
      return null;
    }
  }

  /**
   * ONE OWNERSHIP GRAPH for every verifier-shaped resource this pool has ever created: the ready
   * one, one still initializing, one that finished after shutdown began, and one whose teardown
   * failed. Shutdown succeeds only when every member confirms `closed`, and retry operates on all
   * of them.
   *
   * Membership is removed ONLY on a positive `closed === true`. A resource whose close() resolved
   * without that is still owned -- "the call returned" is not "the child is gone".
   */
  const ownedResources = new Set(); // { label, resource }

  function own(label, resource) {
    if (!resource) return resource;
    for (const entry of ownedResources) if (entry.resource === resource) return resource;
    ownedResources.add({ label, resource, gracefulCloseAbandoned: false });
    return resource;
  }
  function disown(resource) {
    for (const entry of ownedResources) {
      if (entry.resource === resource && entry.resource.closed === true) ownedResources.delete(entry);
    }
  }
  /** Preserve an abnormal protocol-close fact before a positively released rotated resource leaves. */
  function recordReleasedResourceAndDisown(resource, releaseFacts = null) {
    const entry = [...ownedResources].find((candidate) => candidate.resource === resource);
    const releaseProblems = [];
    if (releaseFacts?.gracefulCloseAbandoned === true) {
      // This fact belongs to the ownership entry as well as the evidence record. If force-close did
      // not release the resource, the post-drain sweep and every retry must go straight back to the
      // bounded escalation path; awaiting the already-abandoned graceful close again can deadlock.
      if (entry) entry.gracefulCloseAbandoned = true;
      releaseProblems.push('graceful rotation close did not settle before shutdown escalation');
    }
    for (const [label, key] of [
      ['beginClose threw', 'beginCloseError'],
      ['close threw', 'closeError'],
      ['forceClose threw', 'forceCloseError'],
      ['shutdownOutcome read threw', 'shutdownOutcomeReadError'],
    ]) {
      if (typeof releaseFacts?.[key] === 'string') releaseProblems.push(`${label}: ${releaseFacts[key]}`);
    }
    if (releaseFacts?.closed === false) {
      releaseProblems.push('rotation release remained unconfirmed after escalation');
    }
    // The rotation captured this getter once, at the same boundary as `closed`. Prefer that snapshot:
    // re-reading a stateful or throwing diagnostic could lose an abnormal verdict already observed.
    const hasCapturedOutcome = releaseFacts !== null
      && Object.prototype.hasOwnProperty.call(releaseFacts, 'shutdownOutcome');
    const outcome = hasCapturedOutcome
      ? releaseFacts.shutdownOutcome
      : readShutdownOutcome(entry?.label ?? 'rotated verifier', resource);
    if (resource?.closed === true && outcome?.gracefulProtocolShutdown === false) {
      const reason = outcome.reason ?? 'resource was released but its protocol shutdown was not graceful';
      releaseProblems.push(String(reason));
    }
    if (releaseProblems.length > 0) {
      // One bounded ledger entry per released resource, even if both its close call and protocol
      // transcript were abnormal. This keeps the maximum-length sequence fully representable.
      recordShutdownAnomaly(entry?.label ?? 'rotated verifier', releaseProblems.join('; '), resource);
    }
    disown(resource);
  }
  /** Everything still unreleased, in creation order. Never hides a resource. */
  function unreleasedResources() {
    return [...ownedResources].filter((e) => e.resource.closed !== true);
  }
  // Latched when the dual verifier reports a build disagreement or a fatal helper fault. Once set,
  // no share is ever accepted again and every mining session is stopped.
  let verifierHealth = { healthy: true, reason: null };
  const healthListeners = new Set();

  const defaultVerifierFactory = (opts) => (verifierMode === 'dual'
    ? createDualVerifier({
        ...opts,
        ...(helperPath ? { helperPath } : {}),
        ...(wslDistro ? { wslDistro } : {}),
        ...(helperOptions ? { helperOptions } : {}),
        onFault: (err) => markVerifierUnhealthy(err),
      })
    : createShareVerifier(opts));
  const makeVerifier = verifierFactory ?? defaultVerifierFactory;

  /**
   * A build disagreement or fatal helper fault is not "this share failed". It means one of the two
   * builds is producing wrong answers and this pool cannot tell which, so verification is disabled
   * for the life of the process and every active mining session is stopped through the normal
   * fail-closed path. Recovery requires a restart, deliberately.
   */
  function markVerifierUnhealthy(err) {
    if (!verifierHealth.healthy) return;
    const reason = err?.name === 'VerifierMismatchError'
      ? REJECT_REASONS.VERIFIER_BUILD_DISAGREEMENT
      : REJECT_REASONS.VERIFIER_FAULT;
    // Bounded, explicit, and never the raw unbounded helper stderr.
    verifierHealth = { healthy: false, reason, detail: String(err?.message ?? err).split('\n')[0].slice(0, 240) };
    // Stop the miners, do not merely refuse their next share. A browser told nothing keeps one CPU
    // core hashing for a pool that will never accept another result.
    let halted = 0;
    for (const session of sessions) {
      try {
        if (session.notifyVerifierUnhealthy(verifierHealth)) halted++;
      } catch {
        // a session whose socket is already gone must not stop the others being told
      }
    }
    for (const fn of healthListeners) {
      try {
        fn(verifierHealth);
      } catch {
        // one bad listener must not stop the others from being told
      }
    }
    safeLog({
      kind: 'verifier_unhealthy', reason: verifierHealth.reason, detail: verifierHealth.detail, halted,
    });
  }

  /**
   * Single-flight lazy initialization. Concurrent Start clicks, repeated start_request messages
   * and multiple connections all share ONE initialization and ONE verifier instance.
   *
   * Once shutdown has begun this refuses rather than starting new work, so close() has a bounded
   * set of things to join. Building the Wasm dataset takes about a second, and the next phase
   * will own a native child process here -- close() must therefore be a real join point, not a
   * request to stop soon.
   */
  function ensureVerifier() {
    if (closing) return Promise.reject(new Error('pool is shutting down'));
    // A LATCHED POOL DOES NOT TRY AGAIN. A build disagreement -- whether it surfaced during the
    // startup self-test or on a later share -- is a permanent property of these two builds. Making
    // it a retryable initialization failure would spawn a fresh helper on every Start and report a
    // generic `verifier_unavailable` for something that is neither generic nor transient.
    if (!verifierHealth.healthy) {
      const err = new Error(verifierHealth.detail ?? 'verification is disabled on this pool');
      err.latchedReason = verifierHealth.reason;
      return Promise.reject(err);
    }
    // An unreleased resource from a failed startup means a child whose fate is unknown. Starting
    // another one on top of it is how an invisible process is created.
    const stranded = unreleasedResources();
    if (stranded.length > 0 && !verifier) {
      return Promise.reject(new Error(
        `refusing to start a verifier while ${stranded.length} unreleased resource(s) remain `
        + `(${stranded.map((e) => e.label).join(', ')}). Retry shutdown first.`,
      ));
    }
    if (verifier) return Promise.resolve(verifier);
    if (verifierPromise) return verifierPromise;
    verifierState = 'initializing';
    verifierInitCount++;
    initAbort = new AbortController();
    const signal = initAbort.signal;
    verifierPromise = (async () => {
      const v = await makeVerifier({ ...wasmPaths, signal });
      // Owned the moment it exists, before anything else can go wrong.
      own(closing ? 'late verifier' : 'verifier', v);
      if (closing) {
        // close() is waiting on this promise and will free whatever it resolves with; handing the
        // instance back keeps ownership in exactly one place.
        return v;
      }
      verifier = v;
      verifierState = 'ready';
      return v;
    })();
    // Failures are recorded without unhandling the rejection for the caller.
    verifierPromise.catch((err) => {
      // A startup that could not confirm cleanup hands its live handles back. Adopt them: the
      // alternative is a rejected promise and a child nobody is holding.
      if (err?.name === 'PartialVerifierError' && Array.isArray(err.resources)) {
        for (const { label, resource } of err.resources) own(`partial ${label}`, resource);
      }
      if (!closing) {
        verifierState = unreleasedResources().length > 0 ? 'close_failed' : 'failed';
        verifierPromise = null; // a later Start may retry, unless something above blocks it
      }
    });
    return verifierPromise;
  }

  // ---------------------------------------------------------------- http + ws

  const requests = [];
  const sessions = new Set();
  const stats = {
    requests,
    servedPaths: new Set(),
    accepted: 0,
    rejected: 0,
    connections: 0,
    connectionRefusals: 0,
    incompleteRequestTimeouts: 0,
    startRequests: 0,
  };

  const httpServer = createServer();
  let handler = null;

  // EVERYTHING THIS POOL OWNS, tracked so shutdown can drain it rather than hope.
  //
  // Raw TCP sockets are tracked from the HTTP server's 'connection' event -- before a socket can
  // become an HTTP request or a WebSocket upgrade -- because an uncooperative peer that never
  // finishes its request line otherwise holds httpServer.close() open. The pool-owned deadline
  // below bounds that peer; explicit tracking also lets shutdown destroy it immediately rather
  // than await the deadline.
  const openSockets = new Set();
  const preRequestDeadlines = new Map();

  function clearPreRequestDeadline(socket) {
    const timer = preRequestDeadlines.get(socket);
    if (timer !== undefined) clearTimeout(timer);
    preRequestDeadlines.delete(socket);
  }

  httpServer.on('connection', (socket) => {
    // Node delivers these callbacks serially. `openSockets` contains only sockets this pool has
    // admitted, so check + add is one synchronous admission decision. Refused sockets never reach
    // an HTTP handler, WebSocket upgrade, session or verifier.
    if (openSockets.size >= maxConnections) {
      stats.connectionRefusals++;
      socket.destroy();
      return;
    }
    openSockets.add(socket);
    const timer = setTimeout(() => {
      if (!openSockets.has(socket)) return;
      preRequestDeadlines.delete(socket);
      stats.incompleteRequestTimeouts++;
      socket.destroy();
    }, PRE_REQUEST_TIMEOUT_MS);
    timer.unref?.();
    preRequestDeadlines.set(socket, timer);
    socket.once('close', () => {
      clearPreRequestDeadline(socket);
      openSockets.delete(socket);
    });
  });
  // Every admitted session.handleRaw() promise. session.dispose() stops a late acceptance, but it
  // cannot cancel or join an operation already awaiting verifier.verify(); without this set,
  // close() returned while a verification was still running.
  const pendingOperations = new Set();

  // GLOBAL verification admission, across all sessions. The native helper serialises hashing on
  // one Hasher, so an unbounded number of connections must not be able to queue unbounded work.
  // Per-connection limits alone cannot bound that. Refusal happens BEFORE either build hashes.
  let globalVerifications = 0;
  const maxGlobalVerifications = limits.maxGlobalVerificationQueue ?? DEFAULT_LIMITS.maxGlobalVerificationQueue;

  // Every admitted async HTTP handler promise. The static handler is async (it reads a file), so
  // without this the pool could report `closed` while a GET was still being served.
  const pendingHttpHandlers = new Set();

  /** Track a promise in `set`, own its rejection, and remove it when it settles. */
  function trackPromise(set, promise) {
    set.add(promise);
    promise.then(() => set.delete(promise), () => set.delete(promise));
    return promise;
  }

  /**
   * THE ONE TRUSTED CANONICAL-TIP PATH. Both the operator/test seam `pool.notifyCanonicalTip` and
   * the server-side observer go through exactly this function, so there is one set of refusals and
   * one drain. A rotation can release a verifier and fetch a template, so it is admitted to the
   * same shutdown drain as a WebSocket operation; after `closing` nothing new is admitted.
   */
  function routeCanonicalTip(tip) {
    if (closing) return Promise.resolve({ ok: false, reason: 'pool_closing' });
    if (mode !== REAL_DAEMON_MODE || !simulation?.sequenceTotal || simulation.sequenceTotal < 2) {
      return Promise.resolve({ ok: false, reason: 'not_a_sequence' });
    }
    return trackPromise(pendingOperations, Promise.resolve().then(() => simulation.notifyExternalTip(tip)));
  }

  /**
   * Diagnostics must never defeat cleanup: a throwing logger is swallowed, never propagated.
   *
   * An ASYNC logger throws differently. `async () => { throw x }` does not throw synchronously --
   * it returns a rejected promise, which sails past a bare try/catch and becomes an unhandled
   * rejection that can take the process down during shutdown. Any returned thenable is therefore
   * consumed here too. The pool does not wait for it: logging is diagnostic and must never be on
   * the critical path of a teardown.
   */
  function safeLog(entry) {
    try {
      const returned = log(entry);
      if (returned && typeof returned.then === 'function') {
        Promise.resolve(returned).then(() => {}, () => {});
      }
    } catch {
      // A logger is diagnostic. If it throws, the connection still gets closed and the operation
      // still settles -- that is the whole point of containing it here.
    }
  }
  httpServer.on('request', (req, res) => {
    clearPreRequestDeadline(req.socket);
    if (closing) {
      // No new HTTP work is admitted once shutdown has begun, so the drain terminates.
      try {
        res.writeHead(503);
        res.end();
      } catch {
        // response already gone
      }
      return;
    }
    const served = Promise.resolve(handler?.(req, res)).catch(() => {
      try {
        res.writeHead(500);
        res.end();
      } catch {
        // response already gone
      }
    });
    trackPromise(pendingHttpHandlers, served);
  });

  // ---- BUILT BEFORE THE LISTENER EXISTS ---------------------------------------------------
  // ONE latch, ONE template authority, ONE job, ONE oracle, ONE mock daemon, ONE attempt -- per
  // PROCESS, built here and handed to every simulation session. Two independently constructed
  // registries could each let the same issuance submit, which is exactly what this single
  // construction prevents.
  //
  // IT HAPPENS BEFORE listen() ON PURPOSE. Reading and cross-checking the committed vector can fail,
  // and it used to run after the socket was already accepting connections, so a failure left a live
  // listener behind with no way to reach it. Nothing can be bound until this has succeeded.
  //
  // Building it spawns NOTHING. It captures the pool's own helper configuration into a factory that
  // runs only after a Start has reserved the one attempt. Every resource that factory produces is
  // entered into THIS pool's ownership graph, so shutdown closes, escalates and retains it exactly as
  // it does the synthetic verifier.
  let simulation = mode === SIM_MODE
    ? createSimulationContext({
      ...simulationFactory({
        ...(helperPath ? { helperPath } : {}),
        ...(wslDistro ? { wslDistro } : {}),
        ...(helperOptions ? { helperOptions } : {}),
        ...(wasmPaths ? { wasmPaths } : {}),
      }),
      ownResource: (label, resource) => own(label, resource),
      releaseOwnedResource: recordReleasedResourceAndDisown,
    })
    : null;
  let twoSlotCoordinator = null;
  let twoSlotCreateContext = null;
  let twoSlotBuilt = null;
  let unsubscribeTwoSlotFault = null;

  // TRANSACTIONAL STARTUP. From the first owned resource until startDevPool returns, ANY failure --
  // the real-daemon factory, the context, the bind (EADDRINUSE included), the resolved-address check,
  // the handler or the WebSocket attachment -- stops admission, closes the listener and every
  // accepted socket, closes every owned resource and awaits it, force-closes ONLY a resource whose
  // ordinary close did not confirm release, and then rethrows the ORIGINAL error. Anything that still
  // cannot be confirmed is attached as err.retainedResources. Nothing is found by name, port or PID:
  // only this pool's own ownership graph is touched.
  //
  // It used to cover the factory only. A bind that failed after the daemon was owned rejected with
  // EADDRINUSE and left the daemon running with nobody holding it.
  let ws = null;
  async function failStartup(err) {
    closing = true;
    try { ws?.closeAll(CLOSE.GOING_AWAY, 'development pool startup failed'); } catch { /* already gone */ }
    for (const socket of [...openSockets]) {
      clearPreRequestDeadline(socket);
      try { socket.destroy(); } catch { /* already gone */ }
      openSockets.delete(socket);
    }
    if (httpServer.listening) {
      await new Promise((resolveClosed) => {
        try { httpServer.close(() => resolveClosed()); } catch { resolveClosed(); }
        httpServer.closeAllConnections?.();
      });
    }
    try { await simulation?.beginClose('pool startup failed'); } catch { /* nothing to cancel */ }
    try { await twoSlotCoordinator?.beginClose('pool startup failed'); } catch { /* retained resources reported below */ }
    unsubscribeTwoSlotFault?.();
    unsubscribeTwoSlotFault = null;
    const unreleased = [];
    for (const entry of [...ownedResources]) {
      const { label, resource } = entry;
      if (resource.closed !== true) {
        try { await resource.close('pool startup failed'); } catch { /* escalated below */ }
      }
      if (resource.closed !== true) {
        try { await resource.forceClose('pool startup failed'); } catch { /* reported below */ }
      }
      if (resource.closed === true) ownedResources.delete(entry); else unreleased.push({ label, resource });
    }
    if (unreleased.length > 0 && err !== null && typeof err === 'object') {
      err.retainedResources = unreleased;
    }
    throw err;
  }

  let address;
  let boundPort;
  let httpOrigin;
  let wsOrigin;
  const allowedOrigins = new Set();
  try {
    // THE REAL-LOCAL-DAEMON CONTEXT, also BEFORE listen(). Its factory starts the one owned daemon,
    // proves its listeners, and fetches the one fresh template; the daemon enters THIS pool's ownership
    // graph the moment it exists.
    if (mode === REAL_DAEMON_MODE) {
      const built = await realDaemonFactory({
        ...realDaemon,
        ...(helperPath ? { helperPath } : {}),
        ...(wslDistro ? { wslDistro } : {}),
        ...(helperOptions ? { helperOptions } : {}),
        ...(wasmPaths ? { wasmPaths } : {}),
        now,
        ownResource: (label, resource) => own(label, resource),
      });
      // THE CANONICAL-TIP OBSERVER, for a sustained sequence only. It reads daemon A through the
      // builder's own read-only strict client and reports what it sees to the SAME trusted seam a
      // test or an operator uses -- `simulation` is assigned on the next statement and is what the
      // callbacks below close over, so nothing observes anything before the context exists.
      // DEFENCE IN DEPTH. real_daemon_mode already refuses share work without the pair; the factory
      // is an injectable seam, and the share profile's text describes two private daemons, so a
      // built context that claims share work without a peer is refused here too rather than shown.
      if (built.shareWork === true && (built.peer === null || built.peer === undefined)) {
        throw new TypeError('share work requires the private daemon pair its profile describes');
      }
      if (twoSlotAssignments) {
        if (built.personalizedTemplates !== true || built.peer != null || built.sequence != null
          || built.refresh != null || built.shareWork === true
          || typeof built.serializedPersonalizedTemplateIssuer?.issue !== 'function'
          || typeof built.latch?.onTrip !== 'function') {
          throw new TypeError('two-slot build did not produce the required private personalized issuer');
        }
        twoSlotBuilt = built;
        twoSlotCoordinator = createTwoSlotCoordinator({
          issuer: built.serializedPersonalizedTemplateIssuer,
          now,
        });
        // Every assignment shares this latch. A block_run subscriber fences server-side work,
        // but only a transport broadcast can stop the sibling browser's already-running Worker.
        // Signal both sessions synchronously, then close the entire assignment round.
        unsubscribeTwoSlotFault = built.latch.onTrip(() => {
          let halted = 0;
          for (const session of sessions) {
            try { if (session.notifyVerifierUnhealthy({ reason: 'fatal_verifier' })) halted += 1; }
            catch { /* one broken transport cannot prevent the other stop signal */ }
          }
          trackPromise(pendingOperations, twoSlotCoordinator.beginClose('fatal_verifier'));
          safeLog({ kind: 'two_slot_verifier_unhealthy', halted });
        });
      }
      const wantObserver = built.sequence !== null && built.sequence !== undefined;
      if (wantObserver && (built.tipSource === null || built.tipSource === undefined
        || typeof built.tipSource.readTip !== 'function')) {
        throw new TypeError('a real-daemon sequence requires its trusted daemon-A tip source');
      }
      const tipObserver = wantObserver
        ? createTipObserver({
          readTip: () => built.tipSource.readTip(),
          state: () => simulation?.tipWatchState() ?? { active: false },
          notify: (tip) => routeCanonicalTip(tip),
          onFailure: (code, detail) => simulation?.notifyTipObservationFailure(code, detail),
          ...(Number.isSafeInteger(tipObserverOptions.intervalMs)
            ? { intervalMs: tipObserverOptions.intervalMs } : {}),
          ...(typeof tipObserverOptions.setTimer === 'function'
            ? { setTimer: tipObserverOptions.setTimer } : {}),
          ...(typeof tipObserverOptions.clearTimer === 'function'
            ? { clearTimer: tipObserverOptions.clearTimer } : {}),
        })
        : null;
      if (!twoSlotAssignments) simulation = createSimulationContext({
        ...built,
        tipObserver,
        // A sequence only when the TRUSTED realDaemon option asked for one and the builder produced it;
        // no client message can reach either. The profile is built FOR THE CONFIGURED LENGTH, so the
        // text the page shows before Start states the number of blocks this run may actually take.
        // Share work is opt-in trusted configuration too, and the two now compose: a sequence with
        // share work gets the sequence's own text plus the per-template share budget, so the page
        // never promises one feature's bounds while the server holds the other's.
        profile: selectSimulationProfile(built),
        ownResource: (label, resource) => own(label, resource),
        releaseOwnedResource: recordReleasedResourceAndDisown,
      });
      if (twoSlotAssignments) {
        twoSlotCreateContext = (assignment) => createSimulationContext({
          ...built,
          job: assignment.issued.job,
          templateFacts: assignment.issued.templateFacts,
          canonical: assignment.issued.canonical,
          recordedContext: assignment.issued.context,
          initialVerifierContext: assignment.issued.context,
          authority: assignment.authority,
          profile: REAL_TWO_SLOT_PROFILE,
          assignmentScopedTeardown: true,
          ownResource: (label, resource) => own(label, resource),
          releaseOwnedResource: recordReleasedResourceAndDisown,
        });
      }
      // Owned only after the context exists, so a context that threw cannot leave a poller behind.
      if (tipObserver !== null) own('daemon A tip observer', tipObserver);
    }

    await new Promise((resolveListen, rejectListen) => {
      httpServer.once('error', rejectListen);
      httpServer.listen(port, bindHost, () => {
        httpServer.removeListener('error', rejectListen);
        resolveListen();
      });
    });

    address = httpServer.address();
    // A hostname such as "localhost" is resolved by the OS, so the only honest check is what we
    // actually got. Fail closed if it is not loopback after all.
    if (!isLoopbackHost(address.address)) {
      throw new NonLoopbackBindError(host, `resolved to ${address.address}, which is not loopback`);
    }

    boundPort = address.port;
    const authority = formatAuthority(address.address, boundPort);
    httpOrigin = `http://${authority}`;
    wsOrigin = `ws://${authority}`;

    handler = createStaticHandler({
      wsOrigin,
      artifacts: verifiedArtifacts,
      beforeRead: beforeStaticRead,
      onRequest: (entry) => {
        requests.push(entry);
        if (entry.status === 200) stats.servedPaths.add(new URL(entry.url, 'http://localhost').pathname);
      },
    });

    // Built from canonical parsed URLs rather than hand-spliced strings, so an IPv6 authority is
    // bracketed exactly once and exactly the way a browser will send it.
    for (const h of new Set([address.address, ...(isIpv6Literal(address.address) ? ['::1'] : ['127.0.0.1']), 'localhost'])) {
      if (!isLoopbackHost(h)) continue;
      allowedOrigins.add(new URL(`http://${formatAuthority(h, boundPort)}`).origin);
    }

    ws = attachWebSocketServer(httpServer, {
      path: '/ws',
      maxMessageBytes: MAX_MESSAGE_BYTES,
      // Origin is a MINOR ABUSE CONTROL, never authentication: any non-browser client can send any
      // Origin, and browsers omit it for non-browser-initiated requests. An absent Origin is
      // allowed so command-line clients and the browser smoke can connect; it proves nothing.
      isOriginAllowed: (origin) => origin === undefined || allowedOrigins.has(origin),
      onConnection: (conn, req) => {
        // Clear only inside the installed adapter's successful upgrade path. A generic early
        // 'upgrade' listener would create a startup race: it could clear the timer before this
        // adapter existed, leaving an already-emitted upgrade with nobody to own or close it.
        clearPreRequestDeadline(req.socket);
        stats.connections++;
        // THE MODE SEAM. Chosen from the server option captured above, never from anything a client
        // sends. The synthetic branch below is untouched.
        const session = twoSlotCoordinator ? createTwoSlotSession({
          coordinator: twoSlotCoordinator,
          createContext: twoSlotCreateContext,
          now,
          send: (obj) => conn.sendJson(obj),
          onAudit: (entry) => safeLog(entry),
          trackAsync: (operation) => trackPromise(pendingOperations, operation),
        }) : simulation ? createSimulationSession({
          sim: simulation,
          now,
          send: (obj) => conn.sendJson(obj),
          onAudit: (entry) => safeLog(entry),
        }) : createSession({
          jobs,
          verifierHealth: () => verifierHealth,
          globalQueue: {
            tryEnter: () => {
              if (globalVerifications >= maxGlobalVerifications) return false;
              globalVerifications++;
              return true;
            },
            leave: () => { globalVerifications = Math.max(0, globalVerifications - 1); },
            get depth() { return globalVerifications; },
          },
          getVerifier: () => verifier,
          ensureVerifier: () => {
            stats.startRequests++;
            return ensureVerifier();
          },
          now,
          limits: { ...DEFAULT_LIMITS, ...limits },
          send: (obj) => conn.sendJson(obj),
          onAudit: (entry) => {
            if (entry.kind === 'accept') stats.accepted++;
            if (entry.kind === 'reject') stats.rejected++;
            safeLog(entry);
          },
        });
        sessions.add(session);
        conn.onMessage((payload) => {
          // No new work is admitted once shutdown has begun, so the drain below terminates.
          if (closing) return;
          // The byte length that actually arrived on the wire is what the size limit is applied to.
          const operation = session.handleRaw(payload.length, payload.toString('utf8')).catch((err) => {
            // A THROWING LOGGER MUST NOT DEFEAT CLEANUP. safeLog() swallows its error, and the
            // connection is closed in `finally` so it happens whatever the logger did.
            try {
              safeLog({ kind: 'internal_error', message: err?.message ?? String(err) });
            } finally {
              try {
                conn.close(CLOSE.INTERNAL_ERROR, 'internal error');
              } catch {
                // the connection is already gone
              }
            }
          });
          // Tracked synchronously, and trackPromise owns the rejection of the derived promise, so a
          // failure here can never surface as an unhandled rejection.
          trackPromise(pendingOperations, operation);
        });
        conn.onClosed(() => {
          session.dispose();
          sessions.delete(session);
        });
      },
    });
  } catch (err) {
    await failStartup(err);
  }

  /**
   * Shut down, and do not return until everything this pool owns is actually finished.
   *
   * Single-flight: every caller joins the SAME shutdown promise. When it resolves there is no
   * listener, no tracked socket, no session, no admitted operation, no running initialization and
   * no verifier -- and the terminal state does not change afterwards.
   *
   * THE ORDER MATTERS, and each step exists because skipping it left something alive:
   *
   *   1. mark closing SYNCHRONOUSLY, before any await, so no new operation is admitted
   *   2. initiate the listener close (do not await it yet)
   *   3. close WebSocket connections and dispose sessions
   *   4. destroy the exact remaining pool-owned sockets -- an uncooperative peer must not be able
   *      to hold shutdown open until Node's header timeout
   *   5. NOW await the listener close callback
   *   6. drain every already-admitted operation with an all-settled barrier
   *   7. join any verifier initialization still running
   *   8. await the verifier's asynchronous teardown
   *
   * Cleanup attempts every owned resource even if a step throws. If anything could not be
   * confirmed, the pool does NOT claim `closed`: it enters `close_failed` and the promise rejects,
   * because reporting success over an un-reaped resource is exactly the lie the next phase's
   * native child process must never be able to tell.
   */
  function close() {
    if (closePromise) return closePromise;
    closePromise = runShutdown();
    // The caller owns the rejection; this only stops an unhandled-rejection crash when nobody
    // awaits close(). The stored promise still rejects for anyone who does.
    closePromise.catch(() => {});
    return closePromise;
  }

  /**
   * Retry shutdown after a failed close, escalating on every retained resource.
   *
   * SERIALIZED WITH close(). A retry that started while a shutdown was still running would race
   * two teardown sequences against the same child -- two QUITs, two TERM/KILL escalations, two
   * sets of WSL probes, and two writers of the same resource state. So a retry issued mid-flight
   * JOINS the attempt already running; only once that has settled into close_failed may a genuine
   * second attempt begin.
   */
  function retryClose() {
    if (verifierState === 'closed' && unreleasedResources().length === 0) return Promise.resolve();
    if (closePromise) {
      // Join, then re-enter at most once the previous attempt is finished.
      const joined = closePromise.then(
        () => (unreleasedResources().length > 0 ? retryClose() : undefined),
        () => (closePromise === null ? retryClose() : undefined),
      );
      joined.catch(() => {});
      return joined;
    }
    closePromise = runShutdown({ force: true });
    closePromise.catch(() => {});
    return closePromise;
  }

  /**
   * Shut down, and do not return until everything this pool owns is actually finished.
   *
   * TWO-PHASE VERIFIER LIFECYCLE. The ordering below exists because a verifier whose requests are
   * answered by a child process creates a cycle otherwise:
   *
   *     close waits for the session operation
   *       -> the session operation waits for the verifier request
   *         -> the verifier request only settles when verifier shutdown begins
   *           -> verifier shutdown was queued behind the drain
   *
   * So cancellation is INITIATED before the drain (phase 1, synchronous, settles everything
   * outstanding fail-closed) and final teardown is AWAITED after it (phase 2).
   *
   *   1. stop HTTP / WebSocket / verifier admission, synchronously, before any await
   *   2. abort a startup that may never finish, and beginClose() the verifier
   *   3. initiate the listener close (not awaited yet)
   *   4. close WebSocket connections and dispose sessions
   *   5. destroy exactly the pool-owned sockets
   *   6. await the listener close callback
   *   7. drain admitted session operations AND admitted HTTP handlers
   *   8. join a verifier initialization that is still running
   *   9. await final verifier teardown, escalating once if the graceful attempt fails
   *  10. only then report closed
   *
   * OWNERSHIP ON FAILURE. If teardown cannot be confirmed the verifier reference is NOT cleared
   * and `closed` is not claimed: the pool reports `close_failed`, keeps the handle reachable via
   * `retainedVerifier`, and a later close()/forceClose() retries instead of returning a
   * permanently rejected promise. Reporting success over an un-reaped resource is exactly the lie
   * a native child must never be able to tell.
   */
  async function runShutdown({ force = false } = {}) {
    closing = true; // (1) synchronous, before the first await
    closeFailure = null;
    const failures = [];
    const attempt = async (label, fn) => {
      try {
        await fn();
      } catch (err) {
        failures.push(`${label}: ${err?.message ?? String(err)}`);
      }
    };

    // (2) CANCELLATION FIRST. Abort a startup that may never complete, and tell the verifier to
    // settle everything outstanding, so the drain in step 7 can actually terminate.
    await attempt('verifier cancellation', async () => {
      initAbort?.abort();
      verifier?.beginClose('pool shutting down');
      // The simulation's verifier -- contextual Wasm and the native helper -- is cancelled here too,
      // BEFORE the drain, so a candidate waiting on a native HASH settles instead of holding the
      // drain open behind a teardown that is itself waiting for the drain.
      await simulation?.beginClose('pool shutting down');
      await twoSlotCoordinator?.beginClose('pool shutting down');
    });

    // (3) start the listener close; its callback fires once the last connection is gone.
    let listenerClosed;
    const listenerClosePromise = new Promise((resolve) => { listenerClosed = resolve; });
    httpServer.close(() => listenerClosed());

    // (4) end the protocol layer
    await attempt('websocket close', async () => {
      ws.closeAll(CLOSE.GOING_AWAY, 'development pool shutting down');
    });
    await attempt('session dispose', async () => {
      for (const session of sessions) session.dispose();
      sessions.clear();
    });

    // (5) destroy exactly the sockets this pool accepted -- no broad sweep, no waiting on a peer
    await attempt('socket teardown', async () => {
      for (const socket of [...openSockets]) {
        clearPreRequestDeadline(socket);
        socket.destroy();
        openSockets.delete(socket);
      }
      httpServer.closeAllConnections?.();
    });

    // (6) only now is awaiting the listener bounded
    await attempt('listener close', () => listenerClosePromise);

    // (7) drain everything admitted. Nothing new can be admitted (1) and outstanding verifier
    // requests were cancelled (2), so this terminates.
    await attempt('operation drain', async () => {
      while (pendingOperations.size > 0 || pendingHttpHandlers.size > 0) {
        await Promise.allSettled([...pendingOperations, ...pendingHttpHandlers]);
      }
    });

    // (8) join a verifier initialization that is still running. Whatever it produced was already
    // entered into the ownership graph by ensureVerifier(), including the handles a startup that
    // could not confirm its own cleanup handed back on its error.
    // The simulation's initialization, if one is still running. Whatever it produced -- a verifier,
    // or the handles a failed startup handed back -- was entered into the ownership graph by the
    // simulation context itself the moment it existed; joining here only makes this step a real
    // join point, so the sweep below sees it.
    if (simulation?.pendingInit) {
      try { await simulation.pendingInit; } catch { /* adopted by the context; the sweep reports it */ }
    }

    const pendingInit = verifierPromise;
    verifierPromise = null;
    if (pendingInit) {
      try {
        own('late verifier', await pendingInit);
      } catch (err) {
        // An initialization WE aborted in step 2, or one that failed on its own, has usually
        // produced no resource to release -- that is a completed shutdown, not a cleanup failure.
        // If it DID leave something unreleased, ensureVerifier's catch already adopted it and the
        // ownership sweep below is what reports it.
        if (err?.name === 'PartialVerifierError' && Array.isArray(err.resources)) {
          for (const { label, resource } of err.resources) own(`partial ${label}`, resource);
        }
      }
    }

    // (9) FINAL TEARDOWN OVER THE WHOLE OWNERSHIP GRAPH -- ready, late, provisional and retained
    // alike. Escalate ONCE per resource if the graceful attempt fails; the handle is kept either
    // way so a caller can retry.
    //
    // `closed` is the only thing that releases a resource here. A close() that resolved without
    // it is a FAILURE: the whole point of this barrier is that "the call returned" is not
    // evidence that a child process is gone.
    for (const entry of [...ownedResources]) {
      const { label, resource } = entry;
      if (resource.closed === true) {
        // Already released -- by an earlier attempt, or by its own owner. Read its verdict before
        // dropping it, so a resource that let go abnormally between attempts is not lost either.
        const priorOutcome = readShutdownOutcome(label, resource);
        if (priorOutcome && priorOutcome.gracefulProtocolShutdown === false && priorOutcome.reason) {
          recordShutdownAnomaly(label, priorOutcome.reason, resource);
        }
        ownedResources.delete(entry);
        continue;
      }
      let graceful = null;
      if (entry.gracefulCloseAbandoned !== true) {
        try {
          await resource.close('pool shutting down');
        } catch (err) {
          graceful = err;
        }
      }
      if (resource.closed !== true) {
        try {
          await resource.forceClose('pool shutdown escalation');
        } catch (escalationErr) {
          const detail = `${graceful ? `${graceful.message ?? graceful}; ` : ''}escalation: ${escalationErr?.message ?? String(escalationErr)}`;
          failures.push(`${label}: ${detail}`);
          // The failed attempt is reported through `failures` -- this shutdown does not succeed and
          // the CLI exits nonzero. It does NOT open a new anomaly row: a resource that is merely
          // stubborn and is released by a later retry is not a protocol anomaly. If this handle
          // already has a row, the failure is appended to it so nothing about it is lost.
          appendShutdownAnomalyFact(detail, resource);
          continue;
        }
      }
      if (resource.closed !== true) {
        failures.push(`${label}: teardown returned but release was never confirmed`);
        continue;
      }
      if (graceful) {
        // Escalation succeeded; the graceful failure is still worth saying out loud.
        safeLog({ kind: 'verifier_escalated', label, detail: String(graceful.message ?? graceful).slice(0, 240) });
        recordShutdownAnomaly(label, graceful.message ?? graceful, resource);
      }
      // Always read the resource's actual final verdict, even after escalation. A synthetic
      // "skipped graceful close" marker must never hide a real force-close protocol anomaly.
      const outcome = readShutdownOutcome(label, resource);
      if (outcome && outcome.gracefulProtocolShutdown === false && outcome.reason) {
        safeLog({ kind: 'verifier_shutdown_anomaly', label, detail: String(outcome.reason).slice(0, 240) });
        recordShutdownAnomaly(label, outcome.reason, resource);
      }
      // Recorded BEFORE the resource leaves the graph. Once it is gone, nothing can re-read its
      // outcome, which is precisely why the ledger has to survive this deletion.
      ownedResources.delete(entry);
    }

    // Only release the reference once the resource confirms it is released.
    if (verifier?.closed === true) { disown(verifier); verifier = null; }
    // THE SIMULATION'S RESOURCES WERE IN THE GRAPH ABOVE. Nothing about them is closed here and
    // nothing is swallowed: an unconfirmed native release is a stranded resource below, and a
    // stranded resource fails this shutdown.

    const stranded = unreleasedResources();
    if (failures.length > 0 || stranded.length > 0) {
      for (const { label } of stranded) failures.push(`${label}: resource not confirmed released`);
      verifierState = 'close_failed';
      closeFailure = new Error(`pool shutdown could not be confirmed: ${failures.join('; ')}`);
      // A failed close must NOT latch a permanently rejected promise: allow a bounded retry.
      closePromise = null;
      throw closeFailure;
    }
    verifierState = 'closed'; // one stable terminal state; nothing may move it afterwards
    unsubscribeTwoSlotFault?.();
    unsubscribeTwoSlotFault = null;
    void force;
    // THE STRUCTURED RESULT. Everything is released, so shutdown SUCCEEDED -- and if the protocol
    // shutdown was abnormal the caller is handed that too, rather than having to have installed a
    // logger in advance to find out.
    return {
      ok: true,
      physicalReleaseConfirmed: true,
      gracefulProtocolShutdown: shutdownAnomalies.length === 0,
      protocolAnomalies: shutdownAnomalies.map((a) => ({ ...a })),
    };
  }

  return {
    host: address.address,
    port: boundPort,
    url: httpOrigin,
    wsUrl: `${wsOrigin}/ws`,
    httpServer,
    jobs,
    fixture,
    identity,
    stats,
    sessions,
    close,
    mode,
    /** The one server-owned simulation context, or null in the default synthetic mode. */
    simulation,
    /** Read-only lifecycle facts for the opt-in two-browser assignment mode. */
    get twoSlotState() { return twoSlotCoordinator?.stateFacts ?? null; },
    /** Read-only evidence, not a daemon or converter capability. No raw template or wallet data. */
    get twoSlotEvidence() {
      if (twoSlotBuilt === null) return null;
      const resource = twoSlotBuilt.daemonResource;
      return {
        daemon: resource ? {
          containerName: resource.containerName ?? null,
          linuxPid: resource.linuxPid ?? null,
          imageId: resource.imageId ?? null,
          runDir: resource.runDir ?? null,
          closed: resource.closed === true,
        } : null,
        daemonCounters: twoSlotBuilt.daemon?.counters ? { ...twoSlotBuilt.daemon.counters } : null,
        rpcCounts: twoSlotBuilt.rpcAudit?.counts ? { ...twoSlotBuilt.rpcAudit.counts } : null,
        rpcRawDropped: twoSlotBuilt.rpcAudit?.rawDropped ?? null,
      };
    },
    /**
     * EVIDENCE about the simulation's live verifier, or null before Start. Read-only facts the
     * helper and the verifier already report: the exact child identity, the source identity the
     * pool checked, the context both builds were initialised with, and the separate counters.
     */
    get simulationEvidence() {
      const v = simulation?.verifier;
      if (!v) return null;
      return {
        helperLinuxPid: v.helperLinuxPid,
        helperDistro: v.helperDistro,
        helperSourceId: v.helperSourceId,
        helperCommand: v.helperCommand,
        datasetBytes: v.datasetBytes,
        scratchBytes: v.scratchBytes,
        context: v.context,
        verifierCounters: v.counters,
        simulationCounters: { ...simulation.counters },
        closed: v.closed,
        healthy: v.healthy,
      };
    },
    ensureVerifier,
    /** null until some client declares start intent. The tests assert this directly. */
    get verifier() {
      return verifier;
    },
    get verifierState() {
      return verifierState;
    },
    /** How many times the verifier was actually constructed. Single-flight keeps this at 0 or 1. */
    get verifierInitCount() {
      return verifierInitCount;
    },
    /** True once close() has begun. ensureVerifier() refuses from this point on. */
    get closing() {
      return closing;
    },
    /** Raw TCP sockets this pool has accepted and not yet seen closed. */
    get openSocketCount() {
      return openSockets.size;
    },
    /** Trusted raw-TCP admission limit applied before any HTTP request or WebSocket setup. */
    get maxConnections() {
      return maxConnections;
    },
    /** Admitted session operations still running. */
    get pendingOperationCount() {
      return pendingOperations.size;
    },
    /** Admitted async HTTP handlers still running. */
    get pendingHttpHandlerCount() {
      return pendingHttpHandlers.size;
    },
    /**
     * The verifier handle after a FAILED close. Non-null means the pool still owns an unreleased
     * resource and a caller may retry; it is never silently discarded.
     *
     * Answered from the ownership graph rather than from a state string: any unreleased resource
     * -- ready, late, provisional or retained -- makes this non-null, because a diagnostic that
     * says "nothing retained" while a child's fate is unknown is the exact lie this round exists
     * to remove.
     */
    get retainedVerifier() {
      return unreleasedResources()[0]?.resource ?? null;
    },
    /** Every unreleased resource, labelled. Empty when the pool truly owns nothing. */
    get retainedResources() {
      return unreleasedResources().map(({ label, resource }) => ({ label, resource }));
    },
    /** Test-visible size of the complete ownership graph, including positively closed entries. */
    get ownedResourceCount() {
      return ownedResources.size;
    },
    /**
     * Trusted server-side external-tip seam. It is not reachable from HTTP or WebSocket messages;
     * a bounded daemon observer or a non-live test may report one exact canonical tip here.
     */
    notifyCanonicalTip: (tip) => routeCanonicalTip(tip),
    /** The error from the last failed close, for diagnosis. */
    get closeFailure() {
      return closeFailure;
    },
    /**
     * The last shutdown's two independent facts. `protocolAnomalies` is non-empty when a resource
     * was positively released but its QUIT/BYE/exit transcript was not canonical.
     */
    get shutdownOutcome() {
      return {
        physicalReleaseConfirmed: verifierState === 'closed' && unreleasedResources().length === 0,
        gracefulProtocolShutdown: shutdownAnomalies.length === 0,
        protocolAnomalies: shutdownAnomalies.map((a) => ({ ...a })),
      };
    },
    retryClose,
    /** Which verification path this pool uses: 'dual' (Wasm + native) or 'wasm'. */
    get verifierMode() {
      return verifierMode;
    },
    /** { healthy, reason, detail }. Latched false by a build disagreement or a helper fault. */
    get verifierHealth() {
      return { ...verifierHealth };
    },
    /** Separate self-test and share counters for each build. */
    get verifierCounters() {
      return verifier?.counters ?? {
        wasmSelfTestHashes: 0, nativeSelfTestHashes: 0, wasmShareHashes: 0, nativeShareHashes: 0,
      };
    },
    /** The native helper's Linux PID, for exact-process shutdown evidence. */
    get helperLinuxPid() {
      return verifier?.helperLinuxPid ?? null;
    },
    /** Which WSL distribution the helper reported, so shutdown targets the same one. */
    get helperDistro() {
      return verifier?.helperDistro ?? null;
    },
    /** The build-source identity the helper reported and the pool verified against the tree. */
    get helperSourceId() {
      return verifier?.helperSourceId ?? null;
    },
    get globalVerificationDepth() {
      return globalVerifications;
    },
    onVerifierHealthChange(fn) {
      healthListeners.add(fn);
      return () => healthListeners.delete(fn);
    },
    /**
     * TEST/SMOKE SEAM. Drives the SAME latch a real fault drives, from outside.
     *
     * What using it proves: that once the pool is unhealthy, live mining really is halted -- the
     * browser is told, its Worker is terminated, and nothing further is accepted.
     *
     * What it does NOT prove, and must never be reported as proving: that a genuine disagreement
     * between the two builds is DETECTED. Detection is a property of the comparison in
     * dual_verifier.mjs, and it is proven separately by running a real Wasm build against a native
     * side that returns a different hash (pool/dev/tests/dual_verifier.test.mjs).
     */
    injectVerifierFault(err) {
      const e = err instanceof Error ? err : new Error(String(err));
      // Drive the verifier's OWN latch as well as the pool's, so an injected fault and a real
      // build disagreement travel the same path and meet the same fence. A seam that behaved more
      // safely than the thing it models would make every test that used it worthless.
      try { verifier?.latchExternalFault?.(e); } catch { /* already latched */ }
      markVerifierUnhealthy(e);
      return { ...verifierHealth };
    },
    /** MeepHash-W calls performed by the server, 0 while no verifier exists. */
    get serverHashCalls() {
      return verifier ? verifier.hashCalls : 0;
    },
  };
}
