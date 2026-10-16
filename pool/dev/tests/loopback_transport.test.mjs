// The one real transport, driven with an injected stand-in for http.request. NO SOCKET IS OPENED:
// every test replaces `request`, and a guard below fails if any test in this file could reach the
// real one.

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  LoopbackTransportError, TRANSPORT_CODES, createLoopbackTransport, pinLoopbackEndpoint,
} from '../loopback_transport.mjs';
import { RPC_CODES, createDaemonRpc, submissionProofs } from '../daemon_rpc.mjs';

const ENDPOINT = 'http://127.0.0.1:28081/json_rpc';

/**
 * A scripted http.request. `script(cr, res)` runs after the body is ended; it may answer, fail or do
 * nothing. Records the options it was given and the order of events.
 */
function fakeRequest(script = (cr, res) => { res.statusCode = 200; cr.respond(res, '{"ok":1}'); }) {
  const log = { calls: [], order: [] };
  const request = (options, onResponse) => {
    log.calls.push(options);
    log.order.push('request');
    const cr = new EventEmitter();
    cr.destroyed = false;
    cr.destroy = () => { cr.destroyed = true; log.order.push('destroy'); };
    cr.respond = (res, body) => {
      onResponse(res);
      setImmediate(() => {
        if (body !== undefined) res.emit('data', Buffer.from(body));
        res.emit('end');
      });
    };
    cr.end = (body) => {
      log.order.push('end');
      log.body = Buffer.isBuffer(body) ? body.toString('utf8') : String(body);
      const res = new EventEmitter();
      res.resume = () => {};
      setImmediate(() => script(cr, res));
    };
    return cr;
  };
  return { request, log };
}

function transportFor(script, extra = {}) {
  const f = fakeRequest(script);
  const agents = [];
  const t = createLoopbackTransport({
    endpoint: ENDPOINT,
    request: f.request,
    makeAgent: () => { const a = { destroy() {} }; agents.push(a); return a; },
    ...extra,
  });
  return { t, f, agents };
}

function req(over = {}) {
  const order = over.order ?? [];
  return {
    url: ENDPOINT,
    method: 'get_last_block_header',
    body: '{"jsonrpc":"2.0","id":"x","method":"get_last_block_header","params":{}}',
    timeoutMs: 1000,
    maxResponseBytes: 1024,
    followRedirects: false,
    useProxyEnv: false,
    handoff: () => { order.push('handoff'); },
    ...over,
  };
}

test('only a numeric loopback /json_rpc endpoint over http is accepted, and it is refused BEFORE any socket', () => {
  for (const good of ['http://127.0.0.1:28081/json_rpc', 'http://127.9.8.7:1/json_rpc', 'http://[::1]:28081/json_rpc']) {
    assert.ok(pinLoopbackEndpoint(good), good);
  }
  for (const bad of [
    'http://localhost:28081/json_rpc',          // a hostname: no DNS, ever
    'http://0.0.0.0:28081/json_rpc',            // wildcard
    'http://192.168.1.5:28081/json_rpc',        // LAN
    'http://8.8.8.8:28081/json_rpc',            // public
    'http://user:pw@127.0.0.1:28081/json_rpc',  // credentials
    'https://127.0.0.1:28081/json_rpc',         // TLS is not a mode of this transport
    'http://127.0.0.1:28081/',                  // path changed
    'http://127.0.0.1:28081/json_rpc/extra',
    'http://127.0.0.1:28081/json_rpc?x=1',
    'http://127.0.0.1/json_rpc',                // no explicit port
    'http://127.0.0.256:1/json_rpc',
  ]) {
    const f = fakeRequest();
    assert.throws(() => createLoopbackTransport({ endpoint: bad, request: f.request }), bad);
    assert.equal(f.log.calls.length, 0, `${bad}: a request was made`);
  }
});

test('the request goes to exactly the configured address and path, POST, with its own agent and no DNS', async () => {
  const { t, f, agents } = transportFor();
  const text = await t.transport(req());
  assert.equal(text, '{"ok":1}');
  assert.equal(f.log.calls.length, 1);
  const o = f.log.calls[0];
  assert.equal(o.host, '127.0.0.1');
  assert.equal(o.port, 28081);
  assert.equal(o.path, '/json_rpc');
  assert.equal(o.method, 'POST');
  assert.equal(o.family, 4);
  // Never the global agent a proxy-from-environment setting would apply to.
  assert.equal(agents.length, 1);
  assert.equal(o.agent, agents[0]);
  assert.notEqual(o.agent, http.globalAgent);
  // A lookup, if Node ever attempted one, fails.
  let looked = null;
  o.lookup('127.0.0.1', {}, (err) => { looked = err; });
  assert.ok(looked instanceof LoopbackTransportError);
  assert.equal(o.headers['Content-Type'], 'application/json');
});

test('a request naming any other URL, method or retry/proxy policy is refused before a socket', async () => {
  for (const [name, over] of [
    ['other url', { url: 'http://127.0.0.1:28082/json_rpc' }],
    ['other path', { url: 'http://127.0.0.1:28081/get_info' }],
    ['unknown method', { method: 'stop_daemon' }],
    ['follow redirects', { followRedirects: true }],
    ['proxy env', { useProxyEnv: true }],
    ['no handoff', { handoff: undefined }],
  ]) {
    const { t, f } = transportFor();
    assert.throws(() => t.transport(req(over)), LoopbackTransportError, name);
    assert.equal(f.log.calls.length, 0, `${name}: a request was made`);
  }
});

test('THE HANDOFF is called at the boundary where the bytes are handed to Node HTTP -- not before', async () => {
  const order = [];
  const { t, f } = transportFor((cr, res) => { res.statusCode = 200; cr.respond(res, '{}'); });
  const text = await t.transport(req({ order: f.log.order }));
  assert.equal(text, '{}');
  assert.deepEqual(f.log.order.slice(0, 3), ['request', 'handoff', 'end']);
  void order;
});

test('after the handoff, every failure is a closed code and the adapter classifies it as ambiguous', async () => {
  const cases = [
    ['connection refused', (cr) => cr.emit('error', new Error('connect ECONNREFUSED 127.0.0.1:28081 secret-looking-text')), TRANSPORT_CODES.CONNECT_FAILED],
    ['http status', (cr, res) => { res.statusCode = 302; res.headers = { location: 'http://evil/' }; cr.respond(res); }, TRANSPORT_CODES.HTTP_STATUS],
    ['oversized', (cr, res) => { res.statusCode = 200; cr.respond(res, 'x'.repeat(4096)); }, TRANSPORT_CODES.RESPONSE_TOO_LARGE],
    ['timeout', () => { /* never answers */ }, TRANSPORT_CODES.TIMEOUT],
  ];
  for (const [name, script, code] of cases) {
    const { t, f } = transportFor(script);
    let thrown = null;
    try { await t.transport(req({ timeoutMs: 50 })); } catch (e) { thrown = e; }
    assert.ok(thrown, `${name}: resolved`);
    assert.equal(thrown.code, code, name);
    assert.equal(thrown.message, code, `${name}: dependency text leaked into the message`);
    assert.equal(f.log.calls.length, 1, `${name}: retried`);

    // Through the real adapter: a submit that was handed off and then failed is AMBIGUOUS.
    const g = fakeRequest(script);
    const rpc = createDaemonRpc({
      endpoint: ENDPOINT,
      transport: createLoopbackTransport({ endpoint: ENDPOINT, request: g.request, makeAgent: () => ({ destroy() {} }) }).transport,
      limits: { submitTimeoutMs: 100, maxResponseBytes: 1024 },
    });
    const proofs = submissionProofs(rpc);
    const operation = Object.freeze({});
    const handle = rpc.dispatchSubmission(rpc.prepareSubmission('aabb', operation));
    const record = proofs.dispatchFor(operation, handle);
    const receipt = await record.receipt;
    assert.ok(receipt && proofs.receiptFor(record, receipt), `${name}: no handoff receipt`);
    let outcomeErr = null;
    try { await record.outcome; } catch (e) { outcomeErr = e; }
    assert.ok(outcomeErr, `${name}: outcome resolved`);
    assert.equal(outcomeErr.code, RPC_CODES.TRANSPORT_FAILED, name);
    assert.equal(proofs.refusalFor(record, outcomeErr), false, `${name}: treated as a daemon refusal`);
    assert.equal(proofs.notSentFor(operation, outcomeErr), false, `${name}: treated as not sent`);
    assert.equal(g.log.calls.length, 1, `${name}: submit_block was retried`);
  }
});

test('GUARD: no test in this file can reach the real http.request', () => {
  const code = readFileSync(fileURLToPath(import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((line) => line.replace(/\/\/.*$/, '').replace(/'[^']*'/g, "''"))
    .join('\n');
  const constructions = code.match(/createLoopbackTransport\(/g) ?? [];
  const injected = code.match(/createLoopbackTransport\(\{[^}]*request: [a-z]\.request/g) ?? [];
  assert.ok(constructions.length > 0);
  assert.equal(constructions.length, injected.length, 'a transport is constructed without an injected request');
  assert.equal(/\bhttp\.request\b/.test(code.replace(/http\.globalAgent/g, '')), false,
    'this file references the real http.request');
});
