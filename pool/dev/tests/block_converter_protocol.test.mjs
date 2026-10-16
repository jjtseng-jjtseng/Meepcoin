// Protocol-only tests: no process, WSL distribution, daemon, browser, listener or hash is started.
// The fake child is already owned by the test. Physical Linux-process ownership is deliberately a
// separate future layer; these checks prove only the strict stdin/stdout protocol boundary.

import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  BlockConverterProtocolError, createBlockConverterProtocol,
} from '../block_converter_protocol.mjs';

const TOKEN = '0123456789abcdef0123456789abcdef';
const BLOCK = '10'.repeat(96);
const HASHING = '20'.repeat(80);

class FakeStream extends EventEmitter {
  constructor() {
    super();
    this.writable = true;
    this.writes = [];
    this.onWrite = null;
  }

  write(text, callback = () => {}) {
    if (!this.writable) {
      queueMicrotask(() => callback(new Error('closed')));
      return false;
    }
    this.writes.push(String(text));
    queueMicrotask(() => {
      try {
        this.onWrite?.(String(text));
        callback();
      } catch (error) {
        callback(error);
      }
    });
    return true;
  }

  end() { this.writable = false; }
}

function fakeChild() {
  const child = new EventEmitter();
  child.stdin = new FakeStream();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.line = (line) => child.stdout.emit('data', Buffer.from(`${line}\n`, 'ascii'));
  child.bytes = (bytes) => child.stdout.emit('data', Buffer.from(bytes));
  child.endProcess = (code = 0, signal = null) => child.emit('close', code, signal);
  return child;
}

async function readyClient({ child = fakeChild(), onFault = () => {}, limits = {} } = {}) {
  const client = createBlockConverterProtocol({ child, token: TOKEN, onFault, limits });
  child.line(`HELLO 1 ${TOKEN} 4321`);
  await client.ready;
  return { child, client };
}

function canonicalResponder(child, { result = HASHING, exitCode = 0, duplicateBye = false } = {}) {
  child.stdin.onWrite = (line) => {
    if (line.startsWith('CONVERT ')) {
      const id = line.split(' ', 3)[1];
      child.line(`RESULT ${id} ${result}`);
    } else if (line === 'QUIT\n') {
      child.line('BYE');
      if (duplicateBye) child.line('BYE');
      child.endProcess(exitCode, null);
    }
  };
}

test('one canonical request uses stdin, returns only its exact RESULT, and closes canonically', async () => {
  const { child, client } = await readyClient();
  canonicalResponder(child);
  assert.equal(client.linuxPid, 4321);
  assert.equal(client.healthy, true);
  assert.equal(await client.convert(BLOCK), HASHING);
  assert.deepEqual(child.stdin.writes, [`CONVERT 1 ${BLOCK}\n`]);
  assert.deepEqual(await client.close(), {
    wrapperExited: true, gracefulProtocolShutdown: true,
  });
  assert.deepEqual(child.stdin.writes, [`CONVERT 1 ${BLOCK}\n`, 'QUIT\n']);
  assert.equal(client.pendingCount, 0);
  assert.deepEqual(client.exitInfo, { code: 0, signal: null });
});

test('bad blocks and closed configuration fail before any secret-bearing write', async () => {
  const { child, client } = await readyClient();
  for (const value of ['', '0', 'AA', '0g', 42, null, '00'.repeat((1 << 20) + 1)]) {
    await assert.rejects(
      () => client.convert(value),
      (error) => error instanceof BlockConverterProtocolError && error.code === 'bad_block',
    );
  }
  assert.deepEqual(child.stdin.writes, []);

  for (const bad of [
    { token: 'A'.repeat(32) },
    { token: TOKEN, limits: { maxBlockBytes: 0 } },
    { token: TOKEN, limits: { surprise: 1 } },
  ]) {
    assert.throws(
      () => createBlockConverterProtocol({ child: fakeChild(), ...bad }),
      (error) => error.code === 'bad_config',
    );
  }
});

test('exactly one conversion may be outstanding, and request ids increase canonically', async () => {
  const { child, client } = await readyClient();
  const first = client.convert(BLOCK);
  await Promise.resolve();
  await assert.rejects(() => client.convert('11'.repeat(96)), (error) => error.code === 'busy');
  assert.deepEqual(child.stdin.writes, [`CONVERT 1 ${BLOCK}\n`]);
  child.line(`RESULT 1 ${HASHING}`);
  assert.equal(await first, HASHING);

  const second = client.convert('11'.repeat(96));
  await Promise.resolve();
  assert.equal(child.stdin.writes[1].startsWith('CONVERT 2 '), true);
  child.line(`RESULT 2 ${'22'.repeat(80)}`);
  assert.equal(await second, '22'.repeat(80));
});

test('HELLO is exact: token, version, arity and canonical positive pid', async () => {
  for (const line of [
    `HELLO 1 ${'f'.repeat(32)} 1`,
    `HELLO 2 ${TOKEN} 1`,
    `HELLO 1 ${TOKEN} 01`,
    `HELLO 1 ${TOKEN} 0`,
    `HELLO 1  ${TOKEN} 1`,
    `HELLO 1 ${TOKEN} 1 extra`,
  ]) {
    const child = fakeChild();
    let faults = 0;
    const client = createBlockConverterProtocol({ child, token: TOKEN, onFault: () => { faults += 1; } });
    child.line(line);
    await assert.rejects(client.ready, (error) => error.code === 'bad_hello', line);
    assert.equal(faults, 1, line);
    assert.equal(client.healthy, false, line);
  }
});

test('a wrong, malformed, duplicate or unsolicited result latches once and settles the request', async () => {
  const cases = [
    [`RESULT 2 ${HASHING}`, 'wrong_result'],
    [`RESULT 01 ${HASHING}`, 'wrong_result'],
    [`RESULT 1 ${'ab'.repeat(80).toUpperCase()}`, 'bad_result'],
    [`RESULT 1 ${HASHING.slice(1)}`, 'bad_result'],
    ['RESULT 1', 'bad_output'],
    ['SURPRISE', 'bad_output'],
  ];
  for (const [line, code] of cases) {
    const faults = [];
    const { child, client } = await readyClient({ onFault: (error) => faults.push(error.code) });
    const pending = client.convert(BLOCK);
    await Promise.resolve();
    child.line(line);
    await assert.rejects(pending, (error) => error.code === code, line);
    assert.deepEqual(faults, [code], line);
    assert.equal(client.pendingCount, 0, line);
  }

  const faults = [];
  const { child, client } = await readyClient({ onFault: (error) => faults.push(error.code) });
  child.line(`RESULT 1 ${HASHING}`);
  assert.equal(client.fault.code, 'wrong_result');
  assert.deepEqual(faults, ['wrong_result']);
});

test('a child FAULT is closed and never copies the full block into diagnostics', async () => {
  const faults = [];
  const { child, client } = await readyClient({ onFault: (error) => faults.push(error) });
  const pending = client.convert(BLOCK);
  await Promise.resolve();
  child.line('FAULT invalid_block');
  await assert.rejects(pending, (error) => {
    assert.equal(error.code, 'converter_fault');
    assert.equal(error.message.includes(BLOCK), false);
    assert.equal(error.message, 'converter refused the request (invalid_block)');
    return true;
  });
  assert.equal(faults.length, 1);
  assert.equal(faults[0].message.includes(BLOCK), false);
});

test('request timeout and explicit beginClose settle work once without leaking the block', async () => {
  {
    const faults = [];
    const { client } = await readyClient({
      limits: { requestTimeoutMs: 10 }, onFault: (error) => faults.push(error),
    });
    await assert.rejects(() => client.convert(BLOCK), (error) => {
      assert.equal(error.code, 'request_timeout');
      assert.equal(error.message.includes(BLOCK), false);
      return true;
    });
    assert.equal(faults.length, 1);
  }
  {
    const { client } = await readyClient();
    const pending = client.convert(BLOCK);
    client.beginClose('test cancellation');
    await assert.rejects(pending, (error) => error.cancelled === true && error.code === 'cancelled');
    await assert.rejects(() => client.convert(BLOCK), (error) => error.cancelled === true);
  }
});

test('only one exact BYE plus exit 0 is a graceful protocol close', async () => {
  {
    const { child, client } = await readyClient();
    canonicalResponder(child, { duplicateBye: true });
    await assert.rejects(() => client.close(), (error) => error.code === 'unexpected_bye');
  }
  {
    const { child, client } = await readyClient();
    canonicalResponder(child, { exitCode: 7 });
    await assert.rejects(() => client.close(), (error) => error.code === 'abnormal_close');
  }
  {
    const { child, client } = await readyClient({ limits: { quitTimeoutMs: 1000 } });
    child.stdin.onWrite = (line) => {
      if (line === 'QUIT\n') child.endProcess(7, null);
    };
    await assert.rejects(() => client.close(), (error) => error.code === 'unexpected_exit');
  }
  {
    const { child, client } = await readyClient();
    child.line('BYE');
    assert.equal(client.fault.code, 'unexpected_bye');
  }
  {
    const { child, client } = await readyClient();
    child.stdin.onWrite = (line) => {
      if (line === 'QUIT\n') {
        child.line('BYE extra');
        child.endProcess(0, null);
      }
    };
    await assert.rejects(() => client.close(), (error) => error.code === 'bad_output');
  }
  {
    const { child, client } = await readyClient();
    canonicalResponder(child);
    const first = client.close();
    await assert.rejects(() => client.close(), (error) => error.code === 'already_closing');
    assert.deepEqual(await first, { wrapperExited: true, gracefulProtocolShutdown: true });
    assert.deepEqual(child.stdin.writes, ['QUIT\n']);
  }
});

test('output bounds count bytes and stderr retention is bounded without surfacing its content', async () => {
  const faults = [];
  const { child, client } = await readyClient({
    limits: { maxBlockBytes: 16, maxStderrBytes: 256 },
    onFault: (error) => faults.push(error),
  });
  child.stderr.emit('data', Buffer.from(BLOCK.repeat(10), 'ascii'));
  assert.equal(client.stderrBytesRetained, 256);
  child.bytes(Buffer.alloc(16 * 2 + 65, 0x41));
  assert.equal(client.fault.code, 'oversized_output');
  assert.equal(faults.length, 1);
  assert.equal(faults[0].message.includes(BLOCK), false);
});

test('a child error or unexpected exit faults immediately, but the protocol never claims physical release', async () => {
  {
    const faults = [];
    const { child, client } = await readyClient({ onFault: (error) => faults.push(error.code) });
    child.emit('error', new Error(BLOCK));
    assert.equal(client.fault.code, 'child_error');
    assert.deepEqual(faults, ['child_error']);
    assert.equal(client.fault.message.includes(BLOCK), false);
  }
  {
    const { child, client } = await readyClient();
    child.endProcess(0, null);
    assert.equal(client.fault.code, 'unexpected_exit');
    assert.deepEqual(client.exitInfo, { code: 0, signal: null });
    assert.equal('closed' in client, false);
    assert.equal('forceClose' in client, false);
  }
});
