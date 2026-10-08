// IPv6 loopback: bind host vs URL authority.
//
// "::1" is what a socket binds to; "[::1]" is what a URL authority must contain (RFC 3986 3.2.2).
// The two are not interchangeable, and conflating them produced "http://::1:PORT", which is not a
// parseable URL and which no browser or fetch() could use. These tests run against a REAL ::1
// listener when the host has one, and skip honestly when it does not.

import test, { before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { startDevPool, isLoopbackHost, normalizeBindHost, formatAuthority, isIpv6Literal } from '../server.mjs';

let ipv6Available = false;
let ipv6Note = '';

before(async () => {
  const probe = createServer();
  try {
    await new Promise((resolve, reject) => {
      probe.once('error', reject);
      probe.listen(0, '::1', resolve);
    });
    ipv6Available = true;
    await new Promise((r) => probe.close(r));
  } catch (err) {
    ipv6Note = err.code ?? err.message;
  }
});

// ---------------------------------------------------------------- pure formatting

test('bind host and URL authority are separate concerns', () => {
  assert.equal(normalizeBindHost('::1'), '::1', 'a socket binds the bare address');
  assert.equal(normalizeBindHost('[::1]'), '::1', 'brackets are URL syntax and are stripped');
  assert.equal(normalizeBindHost('127.0.0.1'), '127.0.0.1');

  assert.equal(formatAuthority('::1', 8171), '[::1]:8171', 'a URL authority MUST bracket IPv6');
  assert.equal(formatAuthority('[::1]', 8171), '[::1]:8171', 'and must not double-bracket it');
  assert.equal(formatAuthority('127.0.0.1', 8171), '127.0.0.1:8171');
  assert.equal(isIpv6Literal('::1'), true);
  assert.equal(isIpv6Literal('127.0.0.1'), false);
});

test('the formatted authorities are parseable URLs', () => {
  for (const host of ['::1', '[::1]', '127.0.0.1', 'localhost']) {
    const http = `http://${formatAuthority(host, 9999)}`;
    const ws = `ws://${formatAuthority(host, 9999)}`;
    assert.doesNotThrow(() => new URL(http), `${http} must parse`);
    assert.doesNotThrow(() => new URL(ws), `${ws} must parse`);
    assert.equal(new URL(http).port, '9999');
  }
});

test('the old broken form is exactly what is now avoided', () => {
  // Documents the defect: this is what the URL used to look like.
  assert.throws(() => new URL('http://::1:8171'), TypeError);
  assert.doesNotThrow(() => new URL(`http://${formatAuthority('::1', 8171)}`));
});

test('IPv6 loopback is accepted and everything else still refused', () => {
  for (const h of ['::1', '[::1]', '0:0:0:0:0:0:0:1', '::ffff:127.0.0.1', '127.0.0.1', 'localhost']) {
    assert.equal(isLoopbackHost(h), true, `${h} is loopback`);
  }
  for (const h of ['::', '[::]', '::ffff:0.0.0.0', '::ffff:8.8.8.8', 'fe80::1', '2001:db8::1', '0.0.0.0', '192.168.1.10']) {
    assert.equal(isLoopbackHost(h), false, `${h} must be refused`);
  }
});

// ---------------------------------------------------------------- real ::1 listener

test('a real ::1 pool serves HTTP and WebSocket with valid bracketed URLs', async (t) => {
  if (!ipv6Available) {
    t.skip(`IPv6 loopback unavailable on this host (${ipv6Note}); not faking a pass`);
    return;
  }
  const pool = await startDevPool({ host: '::1', port: 0 });
  t.after(() => pool.close());

  assert.equal(pool.httpServer.address().address, '::1', 'bound to the bare address');
  assert.equal(pool.url, `http://[::1]:${pool.port}`);
  assert.equal(pool.wsUrl, `ws://[::1]:${pool.port}/ws`);
  assert.doesNotThrow(() => new URL(pool.url));
  assert.doesNotThrow(() => new URL(pool.wsUrl));

  // Real HTTP over IPv6.
  const res = await fetch(pool.url + '/');
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /no coins or rewards/i);

  // The CSP must name the bracketed ws origin, or the browser would refuse the connection.
  const csp = res.headers.get('content-security-policy');
  assert.match(csp, new RegExp(`connect-src 'self' ws://\\[::1\\]:${pool.port}`));

  // Real WebSocket over IPv6, all the way to a job.
  const got = [];
  const socket = new WebSocket(pool.wsUrl);
  await new Promise((resolve, reject) => {
    socket.onopen = resolve;
    socket.onerror = () => reject(new Error('IPv6 WebSocket failed to open'));
  });
  socket.onmessage = (e) => got.push(JSON.parse(e.data));
  socket.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
  await new Promise((r) => setTimeout(r, 300));
  assert.ok(got.find((m) => m.type === 'server_hello'), 'greeted over IPv6');
  assert.ok(got.find((m) => m.type === 'job'), 'and given a job over IPv6');
  assert.equal(pool.verifier, null, 'and still no verifier: nobody pressed Start');
  const closed = new Promise((r) => { socket.onclose = r; });
  socket.close();
  await closed;
}, { timeout: 60_000 });

test('the bracketed form binds to the same place as the bare form', async (t) => {
  if (!ipv6Available) {
    t.skip(`IPv6 loopback unavailable on this host (${ipv6Note})`);
    return;
  }
  const pool = await startDevPool({ host: '[::1]', port: 0 });
  try {
    assert.equal(pool.httpServer.address().address, '::1');
    assert.equal(pool.url, `http://[::1]:${pool.port}`);
    assert.doesNotThrow(() => new URL(pool.url));
  } finally {
    await pool.close();
  }
});

test('an IPv6 pool accepts its own bracketed Origin and refuses a foreign one', async (t) => {
  if (!ipv6Available) {
    t.skip(`IPv6 loopback unavailable on this host (${ipv6Note})`);
    return;
  }
  const { createConnection } = await import('node:net');
  const pool = await startDevPool({ host: '::1', port: 0 });
  t.after(() => pool.close());

  const attempt = (origin) => new Promise((resolve) => {
    const socket = createConnection({ host: '::1', port: pool.port }, () => {
      socket.write(
        'GET /ws HTTP/1.1\r\n'
        + `Host: [::1]:${pool.port}\r\n`
        + 'Upgrade: websocket\r\nConnection: Upgrade\r\n'
        + 'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
        + `Origin: ${origin}\r\n\r\n`,
      );
    });
    let data = '';
    socket.on('data', (c) => {
      data += c.toString('utf8');
      if (data.includes('\r\n')) { socket.destroy(); resolve(data.split('\r\n')[0]); }
    });
    socket.on('error', () => resolve('error'));
  });

  assert.match(await attempt(`http://[::1]:${pool.port}`), /101/, 'its own bracketed origin is allowed');
  assert.match(await attempt('https://evil.example'), /403/, 'a foreign origin is refused');
  assert.match(await attempt(`http://[::1]:${pool.port + 1}`), /403/, 'a different port is refused');
}, { timeout: 60_000 });

// ---------------------------------------------------------------- IPv4 unaffected

test('IPv4 loopback still works and produces unbracketed URLs', async () => {
  const pool = await startDevPool({ host: '127.0.0.1', port: 0 });
  try {
    assert.equal(pool.url, `http://127.0.0.1:${pool.port}`);
    assert.equal(pool.wsUrl, `ws://127.0.0.1:${pool.port}/ws`);
    assert.doesNotThrow(() => new URL(pool.url));
    assert.equal((await fetch(pool.url + '/')).status, 200);
  } finally {
    await pool.close();
  }
});

test('a hostname bind is verified against the address it actually resolved to', async () => {
  // "localhost" is resolved by the OS, so the only honest check is what was really bound.
  const pool = await startDevPool({ host: 'localhost', port: 0 });
  try {
    const bound = pool.httpServer.address().address;
    assert.equal(isLoopbackHost(bound), true, `localhost resolved to ${bound}, which must be loopback`);
    assert.equal(pool.host, bound, 'the pool reports the address it really bound');
    assert.doesNotThrow(() => new URL(pool.url), `${pool.url} must be a valid URL`);
    assert.equal((await fetch(pool.url + '/')).status, 200);
  } finally {
    await pool.close();
  }
});
