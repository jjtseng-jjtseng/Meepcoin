// Static serving: a closed route table, restrictive headers, and no filesystem reachable from a
// URL. Run against the real server so the headers under test are the ones a browser would get.

import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';

import { startDevPool } from '../server.mjs';
import { ROUTES, lookupRoute, contentSecurityPolicy } from '../static.mjs';

let pool;

before(async () => {
  pool = await startDevPool({ port: 0 });
});

after(async () => {
  await pool?.close();
});

test('every advertised route resolves to a real file and is served', async () => {
  for (const path of Object.keys(ROUTES)) {
    const res = await fetch(pool.url + path);
    assert.equal(res.status, 200, `${path} must be served`);
    assert.equal(res.headers.get('content-type'), ROUTES[path].type, `${path} content type`);
    const body = await res.arrayBuffer();
    assert.ok(body.byteLength > 0, `${path} must not be empty`);
  }
});

test('the Wasm route serves the real identity-pinned build, not a stub', async () => {
  const res = await fetch(pool.url + '/wasm/meepow.wasm');
  const bytes = new Uint8Array(await res.arrayBuffer());
  assert.deepEqual([...bytes.slice(0, 4)], [0x00, 0x61, 0x73, 0x6d], 'WebAssembly magic number');
  assert.ok(bytes.length > 10_000, `unexpectedly small module: ${bytes.length} bytes`);
});

test('path traversal cannot escape the route table', async () => {
  const attempts = [
    '/../README.md',
    '/../../README.md',
    '/..%2f..%2fREADME.md',
    '/%2e%2e/%2e%2e/README.md',
    '/lib/../../../etc/passwd',
    '/wasm/../../README.md',
    '/wasm/..%5c..%5cREADME.md',
    '/./../.gitignore',
    '/....//....//README.md',
  ];
  for (const path of attempts) {
    const res = await fetch(pool.url + path, { redirect: 'manual' });
    assert.ok(res.status === 404 || res.status === 400, `${path} -> ${res.status}, expected 404/400`);
    const body = await res.text();
    assert.doesNotMatch(body, /MeepCoin \(MEEP\)/, `${path} must not leak README.md`);
    assert.doesNotMatch(body, /node_modules/, `${path} must not leak .gitignore`);
  }
});

test('repository files outside the table are not reachable by their real names', async () => {
  const paths = [
    '/README.md', '/.gitignore', '/LICENSE',
    '/pool/dev/server.mjs', '/pool/protocol/pool_message.hpp',
    '/meepow/wasm/meepow.wasm', '/meepow/src/meepow.cpp',
    '/web-miner/app.js', '/web-miner/tests/target.test.mjs',
    '/node/qual_runner_v2.py', '/results/', '/docs/ARCHITECTURE.md',
  ];
  for (const path of paths) {
    const res = await fetch(pool.url + path);
    assert.equal(res.status, 404, `${path} must be 404`);
  }
});

test('there are no directory listings', async () => {
  for (const path of ['/lib/', '/lib', '/wasm/', '/wasm', '/tests/']) {
    const res = await fetch(pool.url + path);
    assert.equal(res.status, 404, `${path} must be 404, never a listing`);
  }
});

test('only GET and HEAD are allowed', async () => {
  for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
    const res = await fetch(pool.url + '/', { method });
    assert.equal(res.status, 405, `${method} must be 405`);
    assert.equal(res.headers.get('allow'), 'GET, HEAD');
  }
});

test('a request body over the limit is refused', async () => {
  const res = await fetch(pool.url + '/', { method: 'POST', body: 'x'.repeat(4096) });
  // Refused either as a disallowed method or as an oversized body; both are refusals.
  assert.ok(res.status === 405 || res.status === 413, `got ${res.status}`);
});

test('the CSP permits the worker and Wasm and nothing external', async () => {
  const res = await fetch(pool.url + '/');
  const csp = res.headers.get('content-security-policy');
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /script-src 'self' 'wasm-unsafe-eval'/, 'Wasm compilation needs wasm-unsafe-eval');
  assert.match(csp, /worker-src 'self'/);
  assert.match(csp, new RegExp(`connect-src 'self' ws://127\\.0\\.0\\.1:${pool.port}`), 'the exact ws origin');
  assert.match(csp, /frame-ancestors 'none'/, 'the page must not be embeddable');
  assert.match(csp, /object-src 'none'/);
  // No wildcard anywhere, and no external scheme.
  assert.doesNotMatch(csp, /\*/);
  assert.doesNotMatch(csp, /https?:\/\/(?!127\.0\.0\.1)/);
  assert.equal(csp, contentSecurityPolicy(`ws://127.0.0.1:${pool.port}`));
});

test('other security headers are present and no CORS wildcard is offered', async () => {
  const res = await fetch(pool.url + '/');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(res.headers.get('cross-origin-resource-policy'), 'same-origin');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('access-control-allow-origin'), null, 'no CORS is granted at all');
});

test('the served page states the no-coins, localhost-only, one-worker facts before Start', async () => {
  const html = await (await fetch(pool.url + '/')).text();
  assert.match(html, /no coins or rewards/i);
  assert.match(html, /No wallet, no address, no payout/i);
  assert.match(html, /Exactly 1 Web Worker/i);
  assert.match(html, /46\.3 MiB/, 'the measured worker memory figure');
  assert.match(html, /Memory &mdash; in the local pool|Memory — in the local pool/,
    'the local pool verifier is disclosed separately from the browser worker');
  assert.match(html, /does not free the pool/i, 'and the Stop asymmetry is stated honestly');
  // Pre-Start disclosure must be exact: the browser has requested nothing, and the pool has not
  // imported/compiled/allocated/hashed -- while still admitting it read the build files.
  assert.match(html, /this browser has not requested[\s\S]{0,10}the algorithm/i,
    'the browser side is stated exactly');
  assert.match(html, /<em>not<\/em> loaded, compiled or started either/i,
    'the pool side is stated exactly, not as "has not loaded the algorithm"');
  // Both verification builds, and the native CHILD PROCESS, are disclosed before Start -- a page
  // that mentions only "the algorithm" would hide that pressing Start launches a second process.
  assert.match(html, /<em>not<\/em> launched the[\s\S]{0,20}native child process/i,
    'the native child process is disclosed as something Start will launch');
  assert.match(html, /two independently built copies/i, 'the cross-check is disclosed');
  assert.match(html, /byte-for-byte identical/i, 'and what agreement means is stated');
  assert.match(html, /cannot catch a[\s\S]{0,20}mistake that is in the algorithm itself/i,
    'and the limit of a same-source cross-check is admitted on the page, not only in the docs');
  // The two pool memory figures are DIFFERENT MEASUREMENTS and must never be presented as a total.
  assert.match(html, /40 MiB/, 'the native algorithm allocation is disclosed');
  assert.match(html, /not<\/em> the child process's[\s\S]{0,20}resident memory/i,
    'and it is explicitly NOT claimed to be process RSS');
  assert.doesNotMatch(html, /86\.3 MiB|92\.6 MiB/,
    'the two pool figures are never added together into one invented total');
  // REJECT the ambiguous formulations outright. The server DOES read and retain ~58.1 KiB of the
  // build files before Start; saying "neither side has loaded the algorithm" or "no Wasm loaded"
  // reads as though it holds none of it, which is not true.
  assert.doesNotMatch(html, /neither side has loaded the algorithm/i,
    'the over-broad claim must not come back');
  assert.doesNotMatch(html, /no Wasm loaded/i, 'nor the ambiguous "no Wasm loaded" phrasing');
  assert.match(html, /read about 58&nbsp;KiB of the algorithm build/i,
    'and the ~58 KiB it DOES read is disclosed rather than glossed over');
  assert.match(html, /runs no[\s\S]{0,20}MeepCoin or Monero daemon/i,
    'the daemon claim is scoped to THIS SLICE, not the whole repository');
  assert.match(html, /heat|warm|battery/i);
  assert.match(html, /MeepHash-W v2/);
  // Whitespace-tolerant: the assertion is about what the page says, not where it wraps.
  assert.match(html, /Hiding\s+this tab stops mining/i);
  assert.match(html, /Start/);
  assert.match(html, /Stop/);
});

test('lookupRoute is a table lookup, not a filesystem resolution', () => {
  assert.ok(lookupRoute('/'), 'the root is a route');
  assert.ok(lookupRoute('/app.js?cachebust=1'), 'query strings are ignored');
  assert.equal(lookupRoute('/APP.JS'), null, 'matching is exact and case-sensitive');
  assert.equal(lookupRoute('/app.js/'), null);
  assert.equal(lookupRoute('/%ff%fe'), null, 'undecodable paths are refused, not guessed');
  assert.equal(lookupRoute('/constructor'), null, 'prototype keys are not routes');
  assert.equal(lookupRoute('/__proto__'), null);
  assert.equal(lookupRoute('/toString'), null);
});

test('the WebSocket path is not served as a file', async () => {
  const res = await fetch(pool.url + '/ws');
  assert.equal(res.status, 404);
});
