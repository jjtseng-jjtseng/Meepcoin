// A narrow, strict JSON-RPC adapter for exactly six MeepCoin daemon methods (five block methods and
// the read-only get_info the paired-daemon test uses to see synchronisation and peer counts).
//
// NOTHING IN THIS FILE OPENS A SOCKET. The transport is injected: either a test transport (in-memory,
// no fetch, DNS, listener or daemon), or -- only in the explicitly selected real-local-daemon mode --
// loopback_transport.mjs's numeric-loopback HTTP transport to a private local daemon. The constraints
// below bound whichever one is supplied.
//
// ERRORS ARE STRUCTURED CODES, NOT MESSAGES. Every failure carries a stable `code`. Raw transport
// or daemon text never becomes a browser-visible string: it is kept on `.detail`, redacted, for an
// operator log only. A dependency's exception message is exactly the kind of thing that quietly
// carries a URL, an Authorization header or a block blob into a UI.
//
// GROUNDED IN THE COMMITTED DAEMON SOURCE (src/rpc/core_rpc_server_commands_defs.h,
// src/rpc/core_rpc_server.cpp):
//   * get_block_template returns difficulty, wide_difficulty, height, seed_height, seed_hash,
//     next_seed_hash, prev_hash, blocktemplate_blob, blockhashing_blob, expected_reward.
//   * calc_pow takes { major_version, height, block_blob, seed_hash } where block_blob is the
//     NONCE-BEARING hashing blob, and its `result` is a PLAIN STRING. Registered
//     MAP_JON_RPC_WE_IF(..., !m_restricted), so it exists only on an unrestricted RPC.
//   * submit_block takes an ARRAY of exactly one hex string and returns { block_id, status }.
//   * get_block_header_by_height takes { height, fill_pow_hash } -- KV_SERIALIZE_OPT(fill_pow_hash,
//     false) -- and fill_block_header_response() sets
//       pow_hash = fill_pow_hash ? pod_to_hex(get_block_longhash(<chain>, blk, height, 0)) : ""
//     i.e. the PoW of the block AS STORED. That is why an empty pow_hash must be refused: it means
//     nobody computed one, not that it matched.

export const RPC_METHODS = Object.freeze([
  'get_block_template', 'calc_pow', 'submit_block',
  'get_block_header_by_height', 'get_last_block_header',
  'get_info',
]);

/** The methods that change nothing on the daemon. A read-only client may call only these. */
export const READ_ONLY_RPC_METHODS = Object.freeze([
  'get_block_header_by_height', 'get_last_block_header', 'get_info',
]);

/** Stable codes. These may cross a wire; `.detail` may not. */
export const RPC_CODES = Object.freeze({
  BAD_ENDPOINT: 'rpc_bad_endpoint',
  BAD_LIMIT: 'rpc_bad_limit',
  NO_TRANSPORT: 'rpc_no_transport',
  BAD_REQUEST: 'rpc_bad_request',
  REQUEST_TOO_LARGE: 'rpc_request_too_large',
  TRANSPORT_FAILED: 'rpc_transport_failed',
  RESPONSE_TOO_LARGE: 'rpc_response_too_large',
  BAD_RESPONSE: 'rpc_bad_response',
  ID_MISMATCH: 'rpc_id_mismatch',
  DAEMON_ERROR: 'rpc_daemon_error',
  DAEMON_STATUS: 'rpc_daemon_status',
  METHOD_NOT_ALLOWED: 'rpc_method_not_allowed',
  UNREPRESENTABLE: 'rpc_unrepresentable',
  // The prepared-submission capability. All three are local refusals: no transport is entered.
  PREPARED_UNKNOWN: 'rpc_prepared_unknown',
  PREPARED_FOREIGN: 'rpc_prepared_foreign_adapter',
  PREPARED_CONSUMED: 'rpc_prepared_already_consumed',
  // The transport was entered and never reported a handoff. Ambiguous, not definitely-not-sent.
  NO_HANDOFF_RECEIPT: 'rpc_no_handoff_receipt',
  // dispatchSubmission was invoked and returned something this module did not produce.
  UNAUTHENTICATED_DISPATCH: 'rpc_unauthenticated_dispatch',
});

/**
 * WHAT A SUBMISSION ATTEMPT IS ALLOWED TO CLAIM. Five states, and the boundaries between them are
 * the entire point of this file.
 *
 *   DEFINITELY_NOT_SENT   local schema, size, preparation or capability failure. The transport
 *                         function was NEVER CALLED, so nothing can have happened.
 *   AMBIGUOUS             the transport boundary was entered and no authenticated handoff receipt
 *                         came back, OR a receipt came back and the answer never did (timeout,
 *                         reset, malformed reply, id mismatch). The block MAY be on the chain.
 *   DISPATCHED            the transport reported, through this adapter's own one-use handoff, that
 *                         the request bytes were written. The later outcome is a separate fact.
 *   EXPLICIT_REJECTION    a valid matching response carrying a JSON-RPC error or a non-OK status.
 *                         The daemon answered and said no.
 *   OBSERVED_CANONICAL    decided by the caller, not here: an immediate readback that matches on
 *                         block id, height, nonce, orphan status and proof-of-work.
 *
 * CALLING A FUNCTION IS NOT A HANDOFF RECEIPT, and throwing synchronously is not proof that no side
 * effect occurred. A transport may write and then throw; it may also return a Promise long before it
 * touches a socket. Both used to be reported as certainties, in opposite directions.
 */
export const SUBMIT_DISPOSITION = Object.freeze({
  DEFINITELY_NOT_SENT: 'definitely_not_sent',
  AMBIGUOUS: 'ambiguous',
  DISPATCHED: 'dispatched',
  EXPLICIT_REJECTION: 'explicit_rejection',
  OBSERVED_CANONICAL: 'observed_canonical',
});

/**
 * PROVENANCE IS PER ADAPTER, PER OPERATION, PER DISPATCH.
 *
 * WHY NOT MODULE-GLOBAL TABLES. The previous revision kept four module-wide WeakSets/WeakMaps. They
 * proved only that an object had come from SOME invocation inside this file -- not that it belonged
 * to the adapter, the prepared block or the dispatch actually being handled. Two reproduced
 * counterexamples: an authentic handle from adapter A's earlier submit_block("aabb") returned by
 * adapter B's current dispatch was trusted, and block_run reported the current block accepted
 * although its bytes were never transported; and an authentic old "not sent" error from an
 * unrelated adapter, thrown after a side effect, made block_run report "definitely not sent".
 *
 * NOW every proof lives in the private state of ONE createDaemonRpc() instance, and every proof is
 * bound to a lineage the caller holds:
 *
 *     adapter -> operation (caller-created token) -> prepared capability (exact request body)
 *             -> dispatch record -> its receipt -> its outcome / daemon refusal
 *
 * A caller obtains the checks with submissionProofs(adapter) and asks questions ABOUT ITS OWN
 * operation: "was THIS operation proven not sent", "is THIS handle the dispatch of THIS
 * operation", "is THIS receipt that dispatch's receipt", "is THIS error that dispatch's daemon
 * refusal". An authentic object from another adapter, another operation or an earlier dispatch
 * answers no.
 */
const ADAPTER_STATE = new WeakMap();      // adapter object -> its private provenance state
const ALL_CAPABILITIES = new WeakSet();   // every capability any adapter minted (foreign detection only)
const DEFINITE_ORIGIN = new WeakSet();    // refusal errors raised by rpcFail from a validated envelope
const BOUND_REFUSALS = new WeakSet();     // a refusal error is bound to at most one dispatch, ever

/**
 * The instance-bound proof checks for one adapter, or null when `adapter` is not a createDaemonRpc()
 * instance. There is deliberately no one-argument module-level membership test.
 */
export function submissionProofs(adapter) {
  const state = (typeof adapter === 'object' && adapter !== null) ? ADAPTER_STATE.get(adapter) : undefined;
  if (!state) return null;
  return Object.freeze({
    /**
     * Is `capability` this adapter's prepared request for `operation`, not yet dispatched, AND does
     * its private body carry exactly `expectedFullBlockHex`?
     *
     * THE EXPECTED BYTES ARE REQUIRED. Identity alone was not enough: a facade holding the genuine
     * adapter and the caller's current operation could prepare a DIFFERENT block under that
     * operation, and the lineage checks all passed while the caller's block was never transported.
     * The caller names the block it built; the adapter compares it with the exact string it
     * serialized. Nothing about the body is exposed by the answer except equality.
     */
    capabilityFor(operation, capability, expectedFullBlockHex) {
      const op = state.operations.get(operation);
      const rec = (typeof capability === 'object' && capability !== null) ? state.prepared.get(capability) : undefined;
      return op !== undefined && rec !== undefined && op.capability === capability
        && rec.operation === operation && op.dispatched === false && rec.consumed === false
        && typeof expectedFullBlockHex === 'string' && rec.fullBlockHex === expectedFullBlockHex;
    },
    /** The private record of `handle`, only if it is THIS adapter's dispatch of `operation`. */
    dispatchFor(operation, handle) {
      const rec = (typeof handle === 'object' && handle !== null) ? state.dispatches.get(handle) : undefined;
      if (rec === undefined || rec.operation !== operation) return null;
      return state.operations.has(operation) ? rec : null;
    },
    /** Is `receipt` the handoff receipt of exactly this dispatch record? */
    receiptFor(record, receipt) {
      return typeof receipt === 'object' && receipt !== null && state.receipts.get(receipt) === record;
    },
    /** Did THIS adapter prove, before any transport, that `operation` was never sent? */
    notSentFor(operation, err) {
      if (typeof err !== 'object' || err === null || !state.notSent.has(err)) return false;
      const op = state.operations.get(operation);
      return op !== undefined && state.notSent.get(err) === operation && op.dispatched === false;
    },
    /** Is `err` the daemon's own well-formed refusal of exactly this dispatch record? */
    refusalFor(record, err) {
      return typeof err === 'object' && err !== null && state.refusals.get(err) === record;
    },
  });
}

/**
 * Which failures mean "the daemon positively said no" and which mean "we do not know".
 *
 * THIS DISTINCTION IS LOAD-BEARING. A rejected Promise is not evidence a request was refused: a
 * timeout, a reset, a malformed reply or a mismatched response id all reject too, and in every one
 * of those the daemon may have accepted the block. Calling them all "the daemon rejected it" would
 * report a block that might be on the chain as one that certainly is not.
 */
export const DEFINITE_REJECTION_CODES = Object.freeze([
  RPC_CODES.DAEMON_ERROR,     // a JSON-RPC error object: the daemon answered, and said no
  RPC_CODES.DAEMON_STATUS,    // a result whose status is not OK: likewise an answer
]);

/** True only when the daemon itself answered and refused. Everything else is ambiguous. */
export function isDefiniteRejection(code) {
  return DEFINITE_REJECTION_CODES.includes(code);
}

/** Hard ceilings a caller may tighten but never exceed. */
export const LIMIT_BOUNDS = Object.freeze({
  maxRequestBytes: { min: 1024, max: 1 << 20, dflt: 64 * 1024 },
  maxResponseBytes: { min: 1024, max: 8 << 20, dflt: 1 << 20 },
  timeoutMs: { min: 100, max: 120_000, dflt: 10_000 },
  submitTimeoutMs: { min: 100, max: 300_000, dflt: 30_000 },
});

const HEX64 = /^[0-9a-f]{64}$/;
const LOWER_HEX = /^[0-9a-f]+$/;
const REQUIRED_RPC_PATH = '/json_rpc';
const MAX_DAEMON_MESSAGE_CHARS = 512;
const MAX_STATUS_CHARS = 64;
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;

export class DaemonRpcError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = 'DaemonRpcError';
    this.code = code;
    // OPERATOR-ONLY and already redacted. Never send this to a browser; send `code`.
    this.detail = detail ?? '';
  }
}

function rpcFail(code, message, detail) {
  const e = new DaemonRpcError(code, message, redact(detail));
  // Marks ORIGIN only. Whether it is a refusal OF A GIVEN DISPATCH is decided per adapter, below.
  if (DEFINITE_REJECTION_CODES.includes(code)) DEFINITE_ORIGIN.add(e);
  throw e;
}

/**
 * A failure raised BEFORE the transport was entered. `definitelyNotSent` is informational only; the
 * evidence is the adapter's private binding of this error to one operation.
 */
function localError(code, message, detail) {
  const e = new DaemonRpcError(code, message, redact(detail));
  e.definitelyNotSent = true;
  return e;
}

/**
 * Classify one submission failure FOR ONE OPERATION of one adapter.
 *
 * DEFINITELY_NOT_SENT only when that adapter bound the error to that operation before any transport.
 * EXPLICIT_REJECTION only for that dispatch's own daemon refusal. Everything else is AMBIGUOUS.
 */
export function classifySubmitFailure(proofs, { operation, record = null } = {}, err) {
  if (!proofs) return SUBMIT_DISPOSITION.AMBIGUOUS;
  if (proofs.notSentFor(operation, err)) return SUBMIT_DISPOSITION.DEFINITELY_NOT_SENT;
  if (record !== null && proofs.refusalFor(record, err)) return SUBMIT_DISPOSITION.EXPLICIT_REJECTION;
  return SUBMIT_DISPOSITION.AMBIGUOUS;
}

/**
 * Refuse anything that is not a literal loopback JSON-RPC endpoint, and KEEP THE WHOLE URL.
 *
 * An earlier revision returned only `url.origin`, silently dropping `/json_rpc` -- so a transport
 * handed the "validated" endpoint would have posted to `/`. The full normalized href is returned.
 *
 * A HOSTNAME IS REFUSED, NOT RESOLVED. "localhost" is a name; what it resolves to is decided by
 * /etc/hosts, a DNS server, or whoever can influence either. A loopback-only rule is only a rule if
 * no name resolution happens at all.
 */
export function assertLoopbackEndpoint(endpoint) {
  if (typeof endpoint !== 'string' || endpoint.length === 0 || endpoint.length > 200) {
    rpcFail(RPC_CODES.BAD_ENDPOINT, 'endpoint must be a short string');
  }
  let url;
  try {
    url = new URL(endpoint);
  } catch {
    rpcFail(RPC_CODES.BAD_ENDPOINT, 'endpoint must be an absolute URL');
  }
  if (url.protocol !== 'http:') {
    rpcFail(RPC_CODES.BAD_ENDPOINT, 'only plain http to loopback is permitted; this slice supports no TLS');
  }
  if (url.username || url.password) {
    rpcFail(RPC_CODES.BAD_ENDPOINT, 'credentials must not be embedded in the endpoint');
  }
  if (url.search || url.hash) {
    rpcFail(RPC_CODES.BAD_ENDPOINT, 'endpoint must not carry a query or fragment');
  }
  if (url.pathname !== REQUIRED_RPC_PATH) {
    rpcFail(RPC_CODES.BAD_ENDPOINT,
      `endpoint path must be exactly ${REQUIRED_RPC_PATH}, got ${url.pathname.slice(0, 40)}`);
  }

  const host = url.hostname;
  const isIpv4Loopback = /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
    && host.split('.').every((o) => Number(o) >= 0 && Number(o) <= 255);
  const isIpv6Loopback = host === '[::1]' || host === '::1';
  if (!isIpv4Loopback && !isIpv6Loopback) {
    rpcFail(RPC_CODES.BAD_ENDPOINT,
      `endpoint host must be a literal loopback address, got ${host.slice(0, 40)}. `
      + 'A hostname is refused rather than resolved: this adapter performs no DNS.');
  }
  // href, not origin: the path is part of the endpoint.
  return { url: url.href, origin: url.origin, pathname: url.pathname, host, port: url.port };
}

/** Validate one configurable limit as a finite integer inside its hard bounds. */
export function validateLimit(name, value) {
  const b = LIMIT_BOUNDS[name];
  if (!b) rpcFail(RPC_CODES.BAD_LIMIT, `unknown limit ${String(name).slice(0, 32)}`);
  if (value === undefined) return b.dflt;
  if (typeof value !== 'number' || !Number.isFinite(value) || !Number.isInteger(value)) {
    rpcFail(RPC_CODES.BAD_LIMIT, `${name} must be a finite integer`);
  }
  if (value < b.min || value > b.max) {
    rpcFail(RPC_CODES.BAD_LIMIT, `${name} must be within [${b.min}, ${b.max}], got ${value}`);
  }
  return value;
}

/**
 * A BEST-EFFORT TIDIER for a human-read operator string. NOT a general secret scrubber.
 *
 * Say what it does: it removes hex runs of 32+ characters, Bearer/Basic/Digest material, a few named
 * credential JSON fields, Monero-style 4/5-prefixed base58 runs, and URL userinfo.
 *
 * Say what it does NOT do, because the previous wording overclaimed: it does not match this
 * repository's C-prefixed MeepCoin example addresses, it does not remove arbitrary secret-looking
 * plaintext, and no regular expression can. THAT IS WHY NOTHING ARBITRARY IS LOGGED. The audit path
 * is auditRecord() below, which is an allowlist of a fixed code, a known method name, integer sizes
 * and this adapter's own validated endpoint -- never an exception body, URL, header or payload.
 * `.detail` exists for a human reading a thrown error in a terminal; it is not an approved sink.
 */
export function redact(value, { maxLen = 160 } = {}) {
  if (value === null || value === undefined) return '';
  let s;
  try {
    s = typeof value === 'string' ? value : JSON.stringify(value);
  } catch {
    return '<unserialisable>';
  }
  if (typeof s !== 'string') return '';
  // Any hex run of 32+ characters: hashes, ids, keys, blobs.
  s = s.replace(/[0-9a-fA-F]{32,}/g, '<redacted-hex>');
  // Authorization material in any of its usual shapes.
  s = s.replace(/\b(Bearer|Basic|Digest)\s+[A-Za-z0-9+/=._~-]+/gi, '$1 <redacted>');
  s = s.replace(/("(?:password|passwd|token|login|rpc_login|authorization|secret|api[_-]?key)"\s*:\s*)"[^"]*"/gi,
    '$1"<redacted>"');
  // Wallet-address-shaped base58 runs.
  s = s.replace(/\b[45][0-9A-HJ-NP-Za-km-z]{90,}\b/g, '<redacted-address>');
  // Anything that looks like a URL with userinfo.
  s = s.replace(/\/\/[^/@\s]+:[^/@\s]+@/g, '//<redacted>@');
  return s.length > maxLen ? `${s.slice(0, maxLen)}...` : s;
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/**
 * The ONLY shape that may be logged or audited.
 *
 * ALLOWLISTED, NOT SCRUBBED. `redact()` above is a best-effort tidier for a human-read `.detail`;
 * it is NOT a general secret scrubber and must not be described as one. It cannot know every secret
 * shape -- it does not, for instance, match this repository's C-prefixed MeepCoin example addresses,
 * and arbitrary secret-looking plaintext is not removable by pattern. So nothing arbitrary is ever
 * logged: an audit record carries a fixed code, a method name from a closed list, integer sizes, and
 * the endpoint origin and path that this adapter itself validated. No exception body, URL, header,
 * address, request body or response body reaches it.
 */
const AUDIT_CODES = new Set(Object.values(RPC_CODES));
// The only origin shape this adapter can legitimately have talked to, re-checked here rather than
// trusted: a literal loopback host and a port, nothing else.
const LOOPBACK_ORIGIN_RE = /^http:\/\/(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\]):\d{1,5}$/;

export function auditRecord({ code, method, requestBytes, responseBytes, endpoint }) {
  return Object.freeze({
    // A CLOSED SET, not "any string". An arbitrary code was the last way a caller-supplied value
    // could ride into an audit record: a secret pasted into a code field would have been logged
    // verbatim. An unrecognised code is reported as unrecognised, and its value is discarded.
    code: typeof code === 'string' && AUDIT_CODES.has(code) ? code : 'rpc_unknown',
    method: RPC_METHODS.includes(method) ? method : 'unknown',
    requestBytes: Number.isSafeInteger(requestBytes) && requestBytes >= 0 ? requestBytes : null,
    responseBytes: Number.isSafeInteger(responseBytes) && responseBytes >= 0 ? responseBytes : null,
    // RE-VALIDATED SHAPES, not pass-through strings. `endpoint` is normally this adapter's own
    // validated target, but auditRecord is exported and a caller could hand it anything.
    endpointOrigin: typeof endpoint?.origin === 'string' && LOOPBACK_ORIGIN_RE.test(endpoint.origin)
      ? endpoint.origin
      : null,
    endpointPath: endpoint?.pathname === REQUIRED_RPC_PATH ? REQUIRED_RPC_PATH : null,
  });
}

/**
 * @param {object} o
 * @param {(req:object) => Promise<string>} o.transport
 *        Receives { url, method, body, timeoutMs, maxResponseBytes, followRedirects, useProxyEnv }
 *        and returns the raw response text. A test transport, or the numeric-loopback daemon
 *        transport the real-local-daemon mode selects; this adapter opens nothing itself.
 * @param {string} [o.endpoint]  validated at construction; not contacted here.
 */
export function createDaemonRpc({
  transport,
  endpoint = 'http://127.0.0.1:19081/json_rpc',
  limits = {},
  idFactory,
} = {}) {
  if (typeof transport !== 'function') {
    throw new DaemonRpcError(RPC_CODES.NO_TRANSPORT, 'a transport function must be injected');
  }
  const target = assertLoopbackEndpoint(endpoint);
  if (!isPlainObject(limits)) rpcFail(RPC_CODES.BAD_LIMIT, 'limits must be an object');
  for (const key of Object.keys(limits)) {
    if (!Object.prototype.hasOwnProperty.call(LIMIT_BOUNDS, key)) {
      rpcFail(RPC_CODES.BAD_LIMIT, `unknown limit ${key.slice(0, 32)}`);
    }
  }
  const cfg = {
    maxRequestBytes: validateLimit('maxRequestBytes', limits.maxRequestBytes),
    maxResponseBytes: validateLimit('maxResponseBytes', limits.maxResponseBytes),
    timeoutMs: validateLimit('timeoutMs', limits.timeoutMs),
    submitTimeoutMs: validateLimit('submitTimeoutMs', limits.submitTimeoutMs),
  };

  // THIS ADAPTER'S PRIVATE PROVENANCE. Nothing outside this closure can read or write it; the only
  // way to ask about it is submissionProofs(adapter), and every question names an operation.
  const state = {
    operations: new WeakMap(),   // operation token -> { capability, dispatched }
    prepared: new WeakMap(),     // capability -> { operation, method, id, body, requestBytes, timeoutMs, consumed }
    dispatches: new WeakMap(),   // dispatch handle -> frozen dispatch record
    receipts: new WeakMap(),     // handoff receipt -> the dispatch record that minted it
    notSent: new WeakMap(),      // local error -> the operation it proves was not sent
    refusals: new WeakMap(),     // daemon refusal error -> the dispatch record it answered
  };

  let counter = 0;
  const nextId = idFactory ?? (() => {
    counter += 1;
    return `meepcoin-${counter}`;
  });

  /**
   * PHASE 1. Everything local: validate, assign an id, serialise, check the size cap.
   *
   * Nothing here touches the transport, so every failure from this function is DEFINITELY NOT SENT.
   * That is the point of separating it: an oversized or malformed request used to reject from
   * inside the same call that a caller had already announced as "sent".
   */
  function buildRequest(method, params, { timeoutMs = cfg.timeoutMs } = {}) {
    if (!RPC_METHODS.includes(method)) {
      // Unreachable through the public API. Defence in depth: this adapter must never become a
      // caller-controlled proxy, even by a future mistake inside this file.
      rpcFail(RPC_CODES.METHOD_NOT_ALLOWED, `method ${String(method).slice(0, 40)} is not exposed`);
    }
    const id = nextId();
    if (typeof id !== 'string' || id.length === 0 || id.length > 64) {
      rpcFail(RPC_CODES.BAD_REQUEST, 'request id must be a short non-empty string');
    }
    const body = JSON.stringify({ jsonrpc: '2.0', id, method, params });
    const requestBytes = Buffer.byteLength(body, 'utf8');
    if (requestBytes > cfg.maxRequestBytes) {
      rpcFail(RPC_CODES.REQUEST_TOO_LARGE,
        `request body is ${requestBytes} bytes, over the ${cfg.maxRequestBytes} cap`);
    }
    return Object.freeze({ method, id, body, requestBytes, timeoutMs });
  }

  /**
   * PHASE 2. ENTER THE TRANSPORT BOUNDARY.
   *
   * `handoff` is this adapter's own one-use function, passed into the transport. The transport must
   * call it at the moment the request bytes have actually been written. That call IS the receipt:
   * an injected object cannot bless itself as sent, because the only thing that can mint a receipt
   * is a function this closure created and handed over for this one request.
   *
   * `receipt` settles with the receipt object if the handoff happened, and with null once the
   * outcome settles without one. It always settles, so a caller may await it unconditionally.
   */
  function enterTransport(req) {
    let handedOff = null;
    let resolveReceipt;
    const receipt = new Promise((r) => { resolveReceipt = r; });
    let receiptSettled = false;
    function settleReceipt() {
      if (receiptSettled) return;
      receiptSettled = true;
      resolveReceipt(handedOff);
    }

    const handoff = () => {
      if (handedOff) return handedOff;           // one use; a second call mints nothing
      handedOff = Object.freeze({
        id: req.id,
        method: req.method,
        requestBytes: req.requestBytes,
        handedOffAtMs: Date.now(),
      });
      settleReceipt();
      return handedOff;
    };

    let promise;
    try {
      promise = transport({
        // THE FULL URL, path included.
        url: target.url,
        method: req.method,
        body: req.body,
        timeoutMs: req.timeoutMs,
        maxResponseBytes: cfg.maxResponseBytes,
        followRedirects: false,
        useProxyEnv: false,
        // The receipt. Call it when the bytes are written, not when the function is entered.
        handoff,
      });
    } catch (err) {
      // THE BOUNDARY WAS ENTERED. A synchronous throw does NOT prove nothing happened -- a transport
      // can write and then throw -- so this is ambiguous, whether or not a handoff arrived first.
      settleReceipt();
      const e = new DaemonRpcError(RPC_CODES.TRANSPORT_FAILED,
        `transport failed for ${req.method}`, redact(err?.message ?? String(err)));
      e.definitelyNotSent = false;
      e.ambiguous = true;
      const outcome = Promise.reject(e);
      outcome.catch(() => { /* the caller decides; this only keeps Node quiet if it does not */ });
      return { boundaryEntered: true, receipt, outcome, get handedOff() { return handedOff; } };
    }

    const outcome = settle(req, promise);
    // Whatever the answer is, the receipt question is decided by the time it arrives.
    outcome.then(settleReceipt, settleReceipt);
    return { boundaryEntered: true, receipt, outcome, get handedOff() { return handedOff; } };
  }

  /** Parse and validate one response for an already-dispatched request. */
  async function settle(req, promise) {
    const method = req.method;
    const id = req.id;
    let text;
    try {
      text = await promise;
    } catch (err) {
      rpcFail(RPC_CODES.TRANSPORT_FAILED, `transport failed for ${method}`, err?.message ?? String(err));
    }
    return parseResponse(method, id, text);
  }

  function parseResponse(method, id, text) {
    if (typeof text !== 'string') rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: transport did not return text`);
    if (Buffer.byteLength(text, 'utf8') > cfg.maxResponseBytes) {
      rpcFail(RPC_CODES.RESPONSE_TOO_LARGE, `${method}: response exceeds ${cfg.maxResponseBytes} bytes`);
    }

    let root;
    try {
      root = JSON.parse(text);
    } catch {
      rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: response is not valid JSON`);
    }
    if (!isPlainObject(root)) rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: response root is not an object`);

    for (const key of Object.keys(root)) {
      if (!['jsonrpc', 'id', 'result', 'error'].includes(key)) {
        rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: unexpected top-level field ${String(key).slice(0, 32)}`);
      }
    }
    if (root.jsonrpc !== '2.0') rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: jsonrpc must be "2.0"`);
    if (root.id !== id) {
      rpcFail(RPC_CODES.ID_MISMATCH, `${method}: response id does not match the request`);
    }
    const hasResult = Object.prototype.hasOwnProperty.call(root, 'result');
    const hasError = Object.prototype.hasOwnProperty.call(root, 'error');
    if (hasResult && hasError) rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: response carries both result and error`);
    if (!hasResult && !hasError) rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: response carries neither result nor error`);
    if (hasError) {
      // AN EXPLICIT REFUSAL ONLY WHEN IT IS SHAPED LIKE ONE. A JSON-RPC error object carries an
      // integer code and a string message. `error: null`, a bare string, an empty object, a
      // non-integer code or an unbounded message is a MALFORMED ENVELOPE -- after dispatch that
      // means "we do not know", and calling it "the daemon said no" would report a block that may
      // be on the chain as one that certainly is not.
      const e = root.error;
      const wellFormed = isPlainObject(e)
        && Number.isSafeInteger(e.code)
        && typeof e.message === 'string'
        && e.message.length <= MAX_DAEMON_MESSAGE_CHARS;
      if (!wellFormed) rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: malformed JSON-RPC error object`);
      rpcFail(RPC_CODES.DAEMON_ERROR, `${method}: daemon returned an error`,
        { code: e.code, message: e.message });
    }
    return root.result;
  }

  /** The ordinary one-shot path: build, dispatch, settle. Used by everything except submit_block. */
  async function call(method, params, opts = {}) {
    const req = buildRequest(method, params, opts);
    // Reads are idempotent, so they do not gate on the handoff receipt; they still cross the same
    // boundary and are classified the same way when they fail.
    return enterTransport(req).outcome;
  }

  function requireStatusOk(result, method) {
    if (!isPlainObject(result)) rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: result is not an object`);
    // A STATUS IS A BOUNDED STRING. Missing, null, a number, an object or an array is not a daemon
    // refusal -- it is a malformed result, and after dispatch it is ambiguous.
    const status = result.status;
    if (typeof status !== 'string' || status.length === 0 || status.length > MAX_STATUS_CHARS
      || !PRINTABLE_ASCII.test(status)) {
      rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: status is missing or malformed`);
    }
    if (status !== 'OK') {
      rpcFail(RPC_CODES.DAEMON_STATUS, `${method}: daemon status is not OK`, status);
    }
    return result;
  }

  const adapter = {
    /** The full normalized endpoint, path included. */
    endpoint: target.url,
    origin: target.origin,
    limits: Object.freeze({ ...cfg }),
    get requestCount() {
      return counter;
    },
    /** The adapter whose private proofs cover prepareSubmission/dispatchSubmission. Itself. */
    get submissionAdapter() {
      return adapter;
    },

    async getBlockTemplate({ walletAddress, reserveSize = 0 }) {
      if (typeof walletAddress !== 'string' || walletAddress.length === 0 || walletAddress.length > 200) {
        rpcFail(RPC_CODES.BAD_REQUEST, 'walletAddress must be a short non-empty string');
      }
      if (!Number.isInteger(reserveSize) || reserveSize < 0 || reserveSize > 255) {
        rpcFail(RPC_CODES.BAD_REQUEST, 'reserveSize must be 0..255 (the daemon caps it at 255)');
      }
      const r = requireStatusOk(
        await call('get_block_template', { wallet_address: walletAddress, reserve_size: reserveSize }),
        'get_block_template',
      );

      // wide_difficulty is REQUIRED. The uint64 `difficulty` field is deliberately not read: through
      // JSON it becomes a Number and rounds above 2^53.
      if (typeof r.wide_difficulty !== 'string' || r.wide_difficulty.length === 0
        || r.wide_difficulty.length > 40) {
        rpcFail(RPC_CODES.BAD_RESPONSE, 'get_block_template: wide_difficulty missing or malformed');
      }
      // SAFE integer, not merely an integer: past 2^53 a height stops being distinguishable from
      // its neighbour, and a daemon's uint64 reaches a JSON number as exactly that kind of value.
      if (!Number.isSafeInteger(r.height) || r.height < 0) {
        rpcFail(RPC_CODES.BAD_RESPONSE, 'get_block_template: height missing or malformed');
      }
      if (!HEX64.test(String(r.seed_hash ?? ''))) {
        rpcFail(RPC_CODES.BAD_RESPONSE, 'get_block_template: seed_hash must be 64 lowercase hex characters');
      }
      for (const f of ['blocktemplate_blob', 'blockhashing_blob']) {
        const v = r[f];
        if (typeof v !== 'string' || v.length === 0 || v.length % 2 !== 0 || !LOWER_HEX.test(v)) {
          rpcFail(RPC_CODES.BAD_RESPONSE, `get_block_template: ${f} must be non-empty lowercase hex`);
        }
      }
      // `reserved_offset` is the daemon-authored byte offset of the exact `reserve_size` bytes the
      // caller requested in the miner transaction extra.  A future pool extra-nonce must be written
      // only inside this region; guessing or re-parsing the transaction layout in JavaScript would
      // create a second, consensus-sensitive interpretation of the full block blob.  Bind the
      // response to the request now, even while today's one-owner path asks for zero bytes.
      if (!Number.isSafeInteger(r.reserved_offset) || r.reserved_offset < 0) {
        rpcFail(RPC_CODES.BAD_RESPONSE, 'get_block_template: reserved_offset must be a non-negative safe integer');
      }
      const fullBlobBytes = r.blocktemplate_blob.length / 2;
      // Subtraction avoids making the boundary check depend on a potentially rounded addition.
      if (r.reserved_offset > fullBlobBytes - reserveSize) {
        rpcFail(RPC_CODES.BAD_RESPONSE, 'get_block_template: reserved region falls outside blocktemplate_blob');
      }
      return {
        height: r.height,
        wideDifficulty: r.wide_difficulty,
        seedHashHex: r.seed_hash,
        seedHeight: Number.isSafeInteger(r.seed_height) && r.seed_height >= 0 ? r.seed_height : null,
        nextSeedHashHex: HEX64.test(String(r.next_seed_hash ?? '')) ? r.next_seed_hash : null,
        prevHashHex: HEX64.test(String(r.prev_hash ?? '')) ? r.prev_hash : null,
        blockhashingBlobHex: r.blockhashing_blob,
        blocktemplateBlobHex: r.blocktemplate_blob,
        reservedOffset: r.reserved_offset,
        // The daemon does not echo this field.  This is the exact validated value sent in the same
        // request, retained beside its returned offset so downstream code cannot lose the binding.
        reservedSize: reserveSize,
        expectedReward: Number.isSafeInteger(r.expected_reward) && r.expected_reward >= 0
          ? r.expected_reward
          : null,
      };
    },

    /** Ask the daemon to hash the SAME nonce-bearing hashing blob we hashed. */
    async calcPow({ majorVersion, height, blockBlobHex, seedHashHex }) {
      if (!Number.isInteger(majorVersion) || majorVersion < 0 || majorVersion > 255) {
        rpcFail(RPC_CODES.BAD_REQUEST, 'majorVersion must be 0..255');
      }
      if (typeof height !== 'string' || !/^(0|[1-9][0-9]*)$/.test(height)) {
        rpcFail(RPC_CODES.BAD_REQUEST, 'height must be a canonical decimal string (uint64, exact)');
      }
      if (typeof blockBlobHex !== 'string' || blockBlobHex.length === 0
        || blockBlobHex.length % 2 !== 0 || !LOWER_HEX.test(blockBlobHex)) {
        rpcFail(RPC_CODES.BAD_REQUEST, 'blockBlobHex must be non-empty lowercase hex');
      }
      if (!HEX64.test(seedHashHex)) {
        rpcFail(RPC_CODES.BAD_REQUEST, 'seedHashHex must be 64 lowercase hex characters');
      }

      const result = await call('calc_pow', {
        major_version: majorVersion,
        height: exactU64Number(height, 'calc_pow height'),
        block_blob: blockBlobHex,
        seed_hash: seedHashHex,
      });
      if (typeof result !== 'string' || !HEX64.test(result)) {
        rpcFail(RPC_CODES.BAD_RESPONSE, 'calc_pow: result must be a 64-character lowercase hex hash');
      }
      return result;
    },

    /**
     * PHASE 1 of submission: validate and serialise locally. NOTHING IS SENT.
     *
     * Every failure from here is definitely-not-sent, and the caller may say so. Separating this
     * out is what fixes the old shape, where an oversized request rejected from inside the same
     * call the caller had already announced as irreversible.
     */
    prepareSubmission(fullBlockHex, operation = undefined) {
      // THE OPERATION TOKEN is created by the caller and names this one submission attempt. It is
      // registered once; every later proof about this attempt is asked in its name. A missing or
      // reused token is still refused locally, but such a refusal proves nothing about any operation.
      const fresh = typeof operation === 'object' && operation !== null && !state.operations.has(operation);
      if (fresh) state.operations.set(operation, { capability: null, dispatched: false });
      const fail = (err) => {
        if (fresh) state.notSent.set(err, operation);
        return err;
      };
      if (operation !== undefined && !fresh) {
        throw fail(localError(RPC_CODES.BAD_REQUEST, 'the submission operation token is missing or already used'));
      }
      if (typeof fullBlockHex !== 'string' || fullBlockHex.length === 0
        || fullBlockHex.length % 2 !== 0 || !LOWER_HEX.test(fullBlockHex)) {
        throw fail(localError(RPC_CODES.BAD_REQUEST, 'full block must be non-empty lowercase hex'));
      }
      let req;
      try {
        req = buildRequest('submit_block', [fullBlockHex], { timeoutMs: cfg.submitTimeoutMs });
      } catch (err) {
        // Local validation or the size cap. buildRequest runs entirely in this file.
        err.definitelyNotSent = true;
        throw fail(err);
      }
      // AN OPAQUE, ONE-USE CAPABILITY, bound to this adapter, this operation and this exact body.
      const capability = Object.freeze({ kind: 'meepcoin-prepared-submission' });
      ALL_CAPABILITIES.add(capability);
      state.prepared.set(capability, {
        operation: fresh ? operation : null,
        // The exact block this request body serializes. Private: compared, never returned.
        fullBlockHex,
        method: req.method,
        id: req.id,
        body: req.body,
        requestBytes: req.requestBytes,
        timeoutMs: req.timeoutMs,
        consumed: false,
      });
      if (fresh) state.operations.get(operation).capability = capability;
      return capability;
    },

    /**
     * PHASE 2 of submission: hand the prepared request to the transport.
     *
     * Returns a RECEIPT synchronously once the transport has actually been invoked, plus an
     * `outcome` promise for the answer. A caller may only say "sent" after it holds this receipt.
     */
    dispatchSubmission(capability) {
      // EVERY REFUSAL BELOW HAPPENS BEFORE THE TRANSPORT IS TOUCHED, so every one of them is
      // definitely-not-sent and costs zero transport calls.
      const rec = typeof capability === 'object' && capability !== null
        ? state.prepared.get(capability)
        : undefined;
      // A refusal is bound to the capability's own operation ONLY while that operation has never
      // been dispatched. A consumed capability's refusal proves this CALL did not transport; it does
      // not prove the operation was never sent, because it was.
      const fail = (err) => {
        if (rec?.operation && state.operations.get(rec.operation)?.dispatched === false) {
          state.notSent.set(err, rec.operation);
        }
        return err;
      };
      if (rec === undefined) {
        const foreign = typeof capability === 'object' && capability !== null && ALL_CAPABILITIES.has(capability);
        throw localError(foreign ? RPC_CODES.PREPARED_FOREIGN : RPC_CODES.PREPARED_UNKNOWN,
          foreign ? 'this capability was prepared by a different adapter'
            : 'dispatchSubmission needs a capability returned by prepareSubmission');
      }
      if (rec.consumed) {
        throw fail(localError(RPC_CODES.PREPARED_CONSUMED, 'this prepared submission has already been dispatched'));
      }
      if (rec.method !== 'submit_block') {
        throw fail(localError(RPC_CODES.BAD_REQUEST, 'this capability is not a prepared submit_block'));
      }
      // THE CAP IS RE-CHECKED AT DISPATCH, not only at preparation. The size that matters is the
      // size of the bytes about to be written, and it is read from the private record.
      if (rec.requestBytes > cfg.maxRequestBytes) {
        throw fail(localError(RPC_CODES.REQUEST_TOO_LARGE,
          `request body is ${rec.requestBytes} bytes, over the ${cfg.maxRequestBytes} cap`));
      }

      // CONSUMED BEFORE THE TRANSPORT IS ENTERED, so even a re-entrant caller cannot dispatch it
      // twice. JavaScript runs this to completion; there is no window between the check and the set.
      rec.consumed = true;
      if (rec.operation) state.operations.get(rec.operation).dispatched = true;

      const sent = enterTransport(rec);
      // The record exists before any receipt or answer can be bound to it.
      const record = { operation: rec.operation, capability, requestBytes: rec.requestBytes };
      const outcome = sent.outcome.then((result) => {
        const r = requireStatusOk(result, 'submit_block');
        if (!HEX64.test(String(r.block_id ?? ''))) {
          rpcFail(RPC_CODES.BAD_RESPONSE, 'submit_block: block_id must be 64 lowercase hex characters');
        }
        return { blockId: r.block_id };
      }).catch((err) => {
        // A well-formed daemon refusal raised while settling THIS request is bound to THIS record,
        // once. Every error on this chain is created fresh inside this adapter (a transport rejection
        // is wrapped as TRANSPORT_FAILED), and an error already bound elsewhere is never rebound.
        if (DEFINITE_ORIGIN.has(err) && !BOUND_REFUSALS.has(err)) {
          BOUND_REFUSALS.add(err);
          state.refusals.set(err, record);
        }
        throw err;
      });
      // A caller may legitimately act on the receipt alone and never read the outcome.
      outcome.catch(() => {});
      // The receipt this adapter minted is bound to THIS dispatch record the moment it exists.
      const receipt = sent.receipt.then((r) => {
        if (r !== null) state.receipts.set(r, record);
        return r;
      });
      record.receipt = receipt;
      record.outcome = outcome;
      Object.freeze(record);

      // THE HANDLE CARRIES NO EVIDENCE. The authoritative record is reached only through
      // submissionProofs(adapter).dispatchFor(operation, handle).
      const handle = Object.freeze({
        kind: 'meepcoin-dispatch',
        get handedOff() { return sent.handedOff !== null; },
        receipt,
        outcome,
      });
      state.dispatches.set(handle, record);
      return handle;
    },

    /** Convenience for callers that do not need the two phases. Still prepares before dispatching. */
    /**
     * NON-AUTHORITATIVE CONVENIENCE. It resolves with the daemon's answer and DISCARDS the handoff
     * receipt, so its result can support neither "definitely not sent" nor "handed off". Nothing on
     * the block-run path calls it; block_run uses prepareSubmission + dispatchSubmission and
     * authenticates the dispatch record itself.
     */
    async submitBlock(fullBlockHex) {
      const capability = this.prepareSubmission(fullBlockHex);
      return this.dispatchSubmission(capability).outcome;
    },

    /**
     * Header readback, with the daemon's own recomputed proof-of-work.
     *
     * `fillPowHash` defaults TRUE here, because the only reason this adapter reads a header back is
     * to check a submission, and without pow_hash that check cannot be made. When the daemon is not
     * asked, it returns "" -- which this refuses rather than treats as a match.
     */
    async getBlockHeaderByHeight(height, { fillPowHash = true } = {}) {
      if (typeof height !== 'string' || !/^(0|[1-9][0-9]*)$/.test(height)) {
        rpcFail(RPC_CODES.BAD_REQUEST, 'height must be a canonical decimal string');
      }
      if (typeof fillPowHash !== 'boolean') rpcFail(RPC_CODES.BAD_REQUEST, 'fillPowHash must be a boolean');
      const r = requireStatusOk(
        await call('get_block_header_by_height', {
          height: exactU64Number(height, 'header height'),
          fill_pow_hash: fillPowHash,
        }),
        'get_block_header_by_height',
      );
      return validateHeader(r.block_header, 'get_block_header_by_height', fillPowHash);
    },

    async getLastBlockHeader({ fillPowHash = true } = {}) {
      const r = requireStatusOk(
        await call('get_last_block_header', { fill_pow_hash: fillPowHash }),
        'get_last_block_header',
      );
      return validateHeader(r.block_header, 'get_last_block_header', fillPowHash);
    },

    /**
     * READ-ONLY node status: chain length, top block, whether the node considers itself synchronised,
     * and its peer connection counts. Only fields that validate are returned; nothing else is copied.
     *
     * get_info's `height` is the BLOCKCHAIN LENGTH (core_rpc_server::on_get_info: "turn top block
     * height into blockchain height", i.e. top height + 1), unlike a block header's height. A genesis-only
     * chain reports 1. It is returned as `chainLength`, with the top height derived explicitly, so the
     * two cannot be confused again (an early paired attempt refused a correct genesis this way).
     */
    async getInfo() {
      const r = requireStatusOk(await call('get_info', {}), 'get_info');
      if (!Number.isSafeInteger(r.height) || r.height < 1) rpcFail(RPC_CODES.BAD_RESPONSE, 'get_info: height (chain length) malformed');
      if (!HEX64.test(String(r.top_block_hash ?? ''))) rpcFail(RPC_CODES.BAD_RESPONSE, 'get_info: top_block_hash malformed');
      if (typeof r.synchronized !== 'boolean') rpcFail(RPC_CODES.BAD_RESPONSE, 'get_info: synchronized must be a boolean');
      for (const f of ['outgoing_connections_count', 'incoming_connections_count']) {
        if (!Number.isSafeInteger(r[f]) || r[f] < 0) rpcFail(RPC_CODES.BAD_RESPONSE, `get_info: ${f} malformed`);
      }
      const nettype = typeof r.nettype === 'string' && /^[a-z]{1,16}$/.test(r.nettype) ? r.nettype : null;
      return {
        chainLength: r.height,
        topHeight: r.height - 1,
        topBlockHash: r.top_block_hash,
        synchronized: r.synchronized,
        outgoingConnections: r.outgoing_connections_count,
        incomingConnections: r.incoming_connections_count,
        nettype,
        offline: r.offline === true,
        wideDifficulty: typeof r.wide_difficulty === 'string' && r.wide_difficulty.length <= 40 ? r.wide_difficulty : null,
      };
    },
  };
  ADAPTER_STATE.set(adapter, state);
  return adapter;
}

/** A canonical decimal uint64 string as a JSON number, refusing anything not exactly representable. */
function exactU64Number(decimal, what) {
  const v = BigInt(decimal);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
    rpcFail(RPC_CODES.UNREPRESENTABLE, `${what} exceeds what a JSON number can carry exactly`);
  }
  return Number(v);
}

function validateHeader(h, method, requirePowHash) {
  if (!isPlainObject(h)) rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: block_header is not an object`);
  if (!HEX64.test(String(h.hash ?? ''))) rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: header hash malformed`);
  if (!Number.isSafeInteger(h.height) || h.height < 0) {
    rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: header height malformed`);
  }
  if (!Number.isSafeInteger(h.nonce) || h.nonce < 0 || h.nonce > 0xffffffff) {
    rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: header nonce malformed`);
  }
  // Preserve the daemon's own block time for launch-state provenance. Older scripted fixtures
  // omitted it, so the general readback keeps absence explicit; natural-difficulty startup
  // requires the genesis value before any work is issued.
  if (h.timestamp !== undefined && (!Number.isSafeInteger(h.timestamp) || h.timestamp < 0)) {
    rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: header timestamp malformed`);
  }
  // orphan_status must be an explicit boolean. A missing field is not "false".
  if (typeof h.orphan_status !== 'boolean') {
    rpcFail(RPC_CODES.BAD_RESPONSE, `${method}: orphan_status must be an explicit boolean`);
  }
  let powHash = null;
  if (requirePowHash) {
    if (typeof h.pow_hash !== 'string' || !HEX64.test(h.pow_hash)) {
      rpcFail(RPC_CODES.BAD_RESPONSE,
        `${method}: pow_hash must be 64 lowercase hex characters when fill_pow_hash was requested`);
    }
    powHash = h.pow_hash;
  }
  return {
    hash: h.hash,
    height: h.height,
    nonce: h.nonce,
    timestamp: h.timestamp ?? null,
    powHash,
    orphanStatus: h.orphan_status,
    prevHash: HEX64.test(String(h.prev_hash ?? '')) ? h.prev_hash : null,
  };
}
