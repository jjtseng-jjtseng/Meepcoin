// The one real transport daemon_rpc.mjs is given: plain HTTP POST to ONE configured numeric
// loopback /json_rpc endpoint. Dependency-free, and deliberately unable to do anything else.
//
// WHAT IT REFUSES, BEFORE ANY SOCKET EXISTS
//   * any endpoint that is not http://127.x.y.z:<port>/json_rpc or http://[::1]:<port>/json_rpc --
//     hostnames (no DNS), wildcard, LAN or public addresses, credentials, queries, fragments, other
//     paths, https (this slice has no TLS, and an "https downgrade" is not a thing it can do);
//   * any request whose url is not EXACTLY the configured endpoint -- the adapter cannot redirect it;
//   * any RPC method outside daemon_rpc's closed list.
//
// WHAT IT NEVER DOES
//   * follow a redirect (Node's http.request never does; a non-200 answer is a failure);
//   * use a proxy: every request gets its own fresh, non-keep-alive http.Agent, never the global
//     agent a proxy-from-environment setting would apply to, and the connection target is the
//     numeric address itself;
//   * retry anything. One call, one request, one answer or one failure.
//
// THE HANDOFF RECEIPT. daemon_rpc passes a one-use `handoff` function. It is called at the exact
// boundary where the prepared request bytes are handed to Node's HTTP request (`end(body)`), and not
// before. Everything after that point -- a connection refusal, a reset, a timeout, a malformed or
// oversized answer -- is a rejection AFTER handoff, which the adapter and block_run classify as
// ambiguous: the bytes may have reached the daemon.
//
// DIAGNOSTICS ARE CLOSED CODES. A rejection's message is one of TRANSPORT_CODES; no socket error
// text, header or body fragment is carried.

import http from 'node:http';

import { RPC_METHODS, assertLoopbackEndpoint } from './daemon_rpc.mjs';

export const TRANSPORT_CODES = Object.freeze({
  BAD_REQUEST: 'transport_bad_request',
  ENDPOINT_MISMATCH: 'transport_endpoint_mismatch',
  CONNECT_FAILED: 'transport_connect_failed',
  TIMEOUT: 'transport_timeout',
  HTTP_STATUS: 'transport_http_status',
  RESPONSE_TOO_LARGE: 'transport_response_too_large',
  ABORTED: 'transport_aborted',
});

export class LoopbackTransportError extends Error {
  constructor(code) {
    super(code);
    this.name = 'LoopbackTransportError';
    this.code = code;
  }
}

const IPV4_LOOPBACK = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * Validate and pin the ONE endpoint. Returns the connection target Node will be given.
 * Throws before any socket for everything that is not numeric loopback /json_rpc over http.
 */
export function pinLoopbackEndpoint(endpoint) {
  const t = assertLoopbackEndpoint(endpoint);   // http only, no userinfo/query/fragment, exact path
  let host = t.host;
  if (host === '[::1]' || host === '::1') {
    host = '::1';
  } else {
    const m = IPV4_LOOPBACK.exec(host);
    if (!m || m.slice(1).some((o) => Number(o) > 255)) {
      throw new LoopbackTransportError(TRANSPORT_CODES.BAD_REQUEST);
    }
  }
  const port = Number(t.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || t.port === '') {
    throw new LoopbackTransportError(TRANSPORT_CODES.BAD_REQUEST);
  }
  return Object.freeze({ url: t.url, host, port, path: t.pathname });
}

/**
 * @param {object} o
 * @param {string} o.endpoint                 the one numeric-loopback /json_rpc URL
 * @param {Function} [o.request]              test seam: replaces http.request
 * @param {Function} [o.makeAgent]            test seam: replaces `new http.Agent({ keepAlive: false })`
 */
export function createLoopbackTransport({
  endpoint,
  request = http.request,
  makeAgent = () => new http.Agent({ keepAlive: false, maxSockets: 1 }),
} = {}) {
  const target = pinLoopbackEndpoint(endpoint);
  let requests = 0;

  function transport(req) {
    // Everything below up to `end(body)` is local validation: a throw here rejects the promise
    // before the handoff, and the adapter already classifies a transport throw as ambiguous anyway.
    if (req === null || typeof req !== 'object') throw new LoopbackTransportError(TRANSPORT_CODES.BAD_REQUEST);
    if (req.url !== target.url) throw new LoopbackTransportError(TRANSPORT_CODES.ENDPOINT_MISMATCH);
    if (!RPC_METHODS.includes(req.method)) throw new LoopbackTransportError(TRANSPORT_CODES.BAD_REQUEST);
    if (typeof req.body !== 'string' || typeof req.handoff !== 'function') {
      throw new LoopbackTransportError(TRANSPORT_CODES.BAD_REQUEST);
    }
    if (req.followRedirects !== false || req.useProxyEnv !== false) {
      throw new LoopbackTransportError(TRANSPORT_CODES.BAD_REQUEST);
    }
    const timeoutMs = req.timeoutMs;
    const maxResponseBytes = req.maxResponseBytes;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || !Number.isSafeInteger(maxResponseBytes)
      || maxResponseBytes <= 0) {
      throw new LoopbackTransportError(TRANSPORT_CODES.BAD_REQUEST);
    }
    const body = Buffer.from(req.body, 'utf8');
    requests += 1;

    return new Promise((resolve, reject) => {
      let settled = false;
      let timer = null;
      const agent = makeAgent();
      const finish = (err, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { agent.destroy?.(); } catch { /* already gone */ }
        if (err) reject(err); else resolve(value);
      };
      const cr = request({
        host: target.host,
        family: target.host === '::1' ? 6 : 4,
        port: target.port,
        path: target.path,
        method: 'POST',
        agent,
        // A numeric host is never looked up; this makes any attempt to look one up a failure.
        lookup: (_h, _o, cb) => cb(new LoopbackTransportError(TRANSPORT_CODES.BAD_REQUEST)),
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(body.length),
          Connection: 'close',
        },
      }, (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          finish(new LoopbackTransportError(TRANSPORT_CODES.HTTP_STATUS));
          return;
        }
        const chunks = [];
        let size = 0;
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > maxResponseBytes) {
            finish(new LoopbackTransportError(TRANSPORT_CODES.RESPONSE_TOO_LARGE));
            cr.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => finish(null, Buffer.concat(chunks).toString('utf8')));
        res.on('aborted', () => finish(new LoopbackTransportError(TRANSPORT_CODES.ABORTED)));
        res.on('error', () => finish(new LoopbackTransportError(TRANSPORT_CODES.ABORTED)));
      });
      timer = setTimeout(() => {
        finish(new LoopbackTransportError(TRANSPORT_CODES.TIMEOUT));
        cr.destroy();
      }, timeoutMs);
      cr.on('error', () => finish(new LoopbackTransportError(TRANSPORT_CODES.CONNECT_FAILED)));
      // THE HANDOFF BOUNDARY: the prepared bytes are handed to Node's HTTP request here.
      req.handoff();
      cr.end(body);
    });
  }

  return Object.freeze({
    transport,
    endpoint: target.url,
    get requests() { return requests; },
  });
}
