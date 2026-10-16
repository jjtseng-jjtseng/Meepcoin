// The development pool must be unreachable from any other machine. It refuses a non-loopback
// bind before it opens a listener, loads the Wasm module or allocates a dataset.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { startDevPool, isLoopbackHost, assertLoopbackHost, NonLoopbackBindError } from '../server.mjs';
import { availablePort } from './available_port.mjs';

test('loopback addresses are recognised', () => {
  for (const host of ['127.0.0.1', '127.0.0.53', '127.1.2.3', 'localhost', 'LOCALHOST', '::1', '[::1]', '0:0:0:0:0:0:0:1', '::ffff:127.0.0.1']) {
    assert.equal(isLoopbackHost(host), true, `${host} is loopback`);
  }
});

test('everything else is refused, including the wildcard binds', () => {
  const nonLoopback = [
    '0.0.0.0', '::', '[::]', '::ffff:0.0.0.0',
    '192.168.1.10', '10.0.0.5', '172.16.4.1', '169.254.1.1',
    '8.8.8.8', '128.0.0.1', '126.255.255.255',
    'example.com', 'meepcoin.test', '', '   ', 'not-an-address',
    '127.0.0.1.evil.com', '999.0.0.1', '::ffff:8.8.8.8',
  ];
  for (const host of nonLoopback) {
    assert.equal(isLoopbackHost(host), false, `${host} must not be treated as loopback`);
  }
  assert.equal(isLoopbackHost(undefined), false);
  assert.equal(isLoopbackHost(null), false);
  assert.equal(isLoopbackHost(1270001), false);
});

test('assertLoopbackHost throws a named error explaining why', () => {
  assert.throws(() => assertLoopbackHost('0.0.0.0'), NonLoopbackBindError);
  try {
    assertLoopbackHost('0.0.0.0');
  } catch (err) {
    assert.match(err.message, /loopback only/);
    assert.match(err.message, /never be reachable from another machine/);
    assert.equal(err.host, '0.0.0.0');
  }
});

test('startDevPool refuses a non-loopback bind and leaves nothing listening', async () => {
  // One exact OS-selected port for the refusals and the post-refusal probe.
  const port = await availablePort();
  for (const host of ['0.0.0.0', '::', '192.168.1.10']) {
    await assert.rejects(() => startDevPool({ host, port }), NonLoopbackBindError, `${host} must be refused`);
  }

  // If the pool had bound anything, this would fail with EADDRINUSE.
  const probe = createServer();
  await new Promise((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(port, '127.0.0.1', resolve);
  });
  await new Promise((r) => probe.close(r));
});

test('the refusal happens before the Wasm dataset is built', async () => {
  // Building the verifier's 32 MiB dataset and deriving the fixture takes on the order of a
  // second; a refusal that returns in a few milliseconds cannot have done it.
  const t0 = process.hrtime.bigint();
  await assert.rejects(() => startDevPool({ host: '0.0.0.0', port: 0 }), NonLoopbackBindError);
  const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(elapsedMs < 250, `refusal took ${elapsedMs.toFixed(1)} ms; it must short-circuit before setup`);
});

test('a loopback bind is accepted and reports the port it actually got', async () => {
  const pool = await startDevPool({ host: '127.0.0.1', port: 0 });
  try {
    assert.ok(pool.port > 0);
    assert.equal(pool.url, `http://127.0.0.1:${pool.port}`);
    assert.equal(pool.wsUrl, `ws://127.0.0.1:${pool.port}/ws`);
    assert.equal(pool.httpServer.address().address, '127.0.0.1');
  } finally {
    await pool.close();
  }
});
