// Composition tests only. No WSL distribution, converter, daemon, browser, socket, wallet, hash or
// network is started. Child, protocol and custody are bounded fakes.

import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import { BlockConverterOwnerError, launchBlockConverterOwner } from '../block_converter_owner.mjs';
import { createBlockConverterProtocol } from '../block_converter_protocol.mjs';
import { OBSERVATION } from '../native_helper.mjs';
import { createWslProcessCustody } from '../wsl_process_custody.mjs';

const DISTRO = 'Ubuntu';
const BINARY = '/opt/meepcoin/meepcoin-blockhashing';
const RUNTIME_LIBS = '/opt/meepcoin/runtime-libs';
const TOKEN_BYTES = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
const TOKEN = TOKEN_BYTES.toString('hex');
const RELEASE = Object.freeze({ physicalReleaseConfirmed: true,
  linuxObservation: OBSERVATION.ABSENT, wrapperExited: true, probesReaped: true });

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  promise.catch(() => {});
  return { promise, resolve, reject };
}

function fakeChild() {
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  child.kills = [];
  child.stdin = { writable: true, ended: false, end() { this.ended = true; } };
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = (signal) => {
    child.kills.push(signal);
    queueMicrotask(() => child.endProcess(null, signal));
    return true;
  };
  child.endProcess = (code = 0, signal = null) => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.exitCode = code;
    child.signalCode = signal;
    child.emit('close', code, signal);
  };
  return child;
}

function harness({ protocolReady = Promise.resolve(), anchor = async () => {}, runtimeLibraryDir = RUNTIME_LIBS,
  protocolClose = async (_reason, child) => child.endProcess(0, null),
  release = async () => RELEASE, protocolFactoryThrows = null } = {}) {
  const child = fakeChild();
  const events = [];
  const spawns = [];
  let protocolCloseCalls = 0;
  let releaseCalls = 0;
  let convertCalls = 0;
  const dependencies = {
    randomBytesFn: (size) => { assert.equal(size, 16); return TOKEN_BYTES; },
    spawnFn: (file, args, options) => {
      spawns.push({ file, args, options });
      events.push('spawn');
      return child;
    },
    protocolFactory: ({ child: actual, token, onFault }) => {
      if (protocolFactoryThrows) throw protocolFactoryThrows;
      assert.strictEqual(actual, child);
      assert.equal(token, TOKEN);
      assert.equal(typeof onFault, 'function');
      events.push('protocol');
      return {
        ready: protocolReady,
        linuxPid: 4321,
        beginClose: () => events.push('begin-close'),
        convert: async (block) => { convertCalls += 1; return `hashing:${block}`; },
        close: async (reason) => {
          protocolCloseCalls += 1;
          events.push('protocol-close');
          return await protocolClose(reason, child);
        },
      };
    },
    custodyFactory: (config) => {
      events.push('custody');
      assert.strictEqual(config.wrapperChild, child);
      assert.equal(config.distro, DISTRO);
      assert.equal(config.linuxPid, 4321);
      assert.deepEqual(config.expectedLinuxArgv, [BINARY, '--server', TOKEN]);
      return {
        anchor: async () => { events.push('anchor'); return await anchor(); },
        release: async () => {
          releaseCalls += 1;
          events.push('release');
          return await release(releaseCalls, child);
        },
      };
    },
  };
  const owner = launchBlockConverterOwner({ distro: DISTRO, binaryPath: BINARY, runtimeLibraryDir, dependencies });
  return { owner, child, events, spawns,
    counts: () => ({ protocolCloseCalls, releaseCalls, convertCalls }) };
}

test('exact argv-native launch becomes ready only after HELLO and parent-owned anchor', async () => {
  const h = harness();
  assert.equal(h.owner.state, 'STARTING');
  assert.strictEqual(await h.owner.ready, h.owner);
  assert.equal(h.owner.state, 'READY');
  assert.deepEqual(h.spawns, [{
    file: 'wsl.exe',
    args: ['-d', DISTRO, '--exec', '/usr/bin/env', '-i',
      `LD_LIBRARY_PATH=${RUNTIME_LIBS}`, BINARY, '--server', TOKEN],
    options: { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false },
  }]);
  assert.deepEqual(h.events.slice(0, 4), ['spawn', 'protocol', 'custody', 'anchor']);
});

test('omitting the optional runtime directory preserves the direct argv-native launch', async () => {
  const h = harness({ runtimeLibraryDir: null });
  await h.owner.ready;
  assert.deepEqual(h.spawns[0].args, ['-d', DISTRO, '--exec', BINARY, '--server', TOKEN]);
});

test('convert waits for composed readiness and never bypasses the protocol owner', async () => {
  const gate = deferred();
  const h = harness({ protocolReady: gate.promise });
  const conversion = h.owner.convert('abcd');
  assert.equal(h.counts().convertCalls, 0);
  gate.resolve();
  assert.equal(await conversion, 'hashing:abcd');
  assert.equal(h.counts().convertCalls, 1);
});

test('canonical close is protocol first, physical release second, cached and idempotent', async () => {
  const h = harness();
  await h.owner.ready;
  const result = await h.owner.close();
  assert.deepEqual(result, {
    gracefulProtocolShutdown: true,
    physicalReleaseConfirmed: true,
    linuxObservation: OBSERVATION.ABSENT,
    wrapperExited: true,
    probesReaped: true,
  });
  assert.strictEqual(await h.owner.close(), result);
  assert.equal(h.owner.closed, true);
  assert.deepEqual(h.owner.shutdownOutcome, {
    physicalReleaseConfirmed: true,
    gracefulProtocolShutdown: true,
    reason: null,
  });
  assert.deepEqual(h.events.slice(-3), ['begin-close', 'protocol-close', 'release']);
  assert.deepEqual(h.counts(), { protocolCloseCalls: 1, releaseCalls: 1, convertCalls: 0 });
});

test('concurrent close joins one protocol and one release operation', async () => {
  const gate = deferred();
  const h = harness({ protocolClose: async (_reason, child) => {
    await gate.promise;
    child.endProcess(0, null);
  } });
  await h.owner.ready;
  const first = h.owner.close();
  const second = h.owner.close();
  gate.resolve();
  assert.deepEqual(await first, await second);
  assert.deepEqual(h.counts(), { protocolCloseCalls: 1, releaseCalls: 1, convertCalls: 0 });
});

test('a protocol anomaly is reported only after physical release succeeds', async () => {
  const h = harness({ protocolClose: async () => { throw Object.assign(new Error('no bye'),
    { code: 'quit_timeout' }); } });
  await h.owner.ready;
  await assert.rejects(() => h.owner.close(), (error) => {
    assert(error instanceof BlockConverterOwnerError);
    assert.equal(error.code, 'protocol_anomaly_after_release');
    assert.equal(error.detail.physicalReleaseConfirmed, true);
    assert.equal(error.detail.protocolCode, 'quit_timeout');
    return true;
  });
  assert.equal(h.owner.closed, true);
  assert.deepEqual(h.owner.shutdownOutcome, {
    physicalReleaseConfirmed: true,
    gracefulProtocolShutdown: false,
    reason: 'protocol quit_timeout',
  });
  await assert.rejects(() => h.owner.close(), (error) => {
    assert.equal(error.code, 'protocol_anomaly_after_release');
    assert.equal(error.detail.physicalReleaseConfirmed, true);
    return true;
  });
  assert.equal(h.counts().releaseCalls, 1);
  assert.equal(h.counts().protocolCloseCalls, 1);
});

test('close during startup waits for the anchor, refuses new work and shuts down cleanly', async () => {
  const gate = deferred();
  const h = harness({ protocolReady: gate.promise });
  const closing = h.owner.close();
  assert.equal(h.owner.closing, true);
  assert.equal(h.owner.state, 'CLOSING');
  const conversion = h.owner.convert('abcd');
  gate.resolve();
  await assert.rejects(() => conversion, (error) => error.code === 'closing');
  assert.equal((await closing).physicalReleaseConfirmed, true);
  assert.deepEqual(h.counts(), { protocolCloseCalls: 1, releaseCalls: 1, convertCalls: 0 });
});

test('a failed physical release retains retry while never repeating protocol close', async () => {
  const h = harness({ release: async (attempt) => {
    if (attempt === 1) throw Object.assign(new Error('inspection failed'), { code: 'release_unconfirmed' });
    return RELEASE;
  } });
  await h.owner.ready;
  await assert.rejects(() => h.owner.close(), (error) => {
    assert.equal(error.code, 'physical_release_unconfirmed');
    assert.equal(error.detail.physicalReleaseConfirmed, false);
    return true;
  });
  assert.equal(h.owner.closed, false);
  assert.equal(h.owner.shutdownOutcome.physicalReleaseConfirmed, false);
  const result = await h.owner.close();
  assert.equal(result.physicalReleaseConfirmed, true);
  assert.deepEqual(h.counts(), { protocolCloseCalls: 1, releaseCalls: 2, convertCalls: 0 });
});

test('beginClose is synchronous and forceClose joins the same bounded teardown', async () => {
  const gate = deferred();
  const h = harness({ protocolClose: async (_reason, child) => {
    await gate.promise;
    child.endProcess(0, null);
  } });
  await h.owner.ready;
  assert.equal(h.owner.beginClose('server drain'), undefined);
  assert.equal(h.owner.closing, true);
  const forced = h.owner.forceClose('server escalation');
  gate.resolve();
  assert.equal((await forced).physicalReleaseConfirmed, true);
  assert.equal(h.owner.closed, true);
  assert.deepEqual(h.counts(), { protocolCloseCalls: 1, releaseCalls: 1, convertCalls: 0 });
});

test('HELLO failure returns an owned object, reaps only its exact wrapper and claims no Linux release', async () => {
  const hello = Promise.reject(Object.assign(new Error('bad hello'), { code: 'bad_hello' }));
  hello.catch(() => {});
  const h = harness({ protocolReady: hello,
    protocolClose: async () => { throw Object.assign(new Error('bad hello'), { code: 'bad_hello' }); } });
  await assert.rejects(() => h.owner.ready, (error) => error.code === 'bad_hello');
  await assert.rejects(() => h.owner.close(), (error) => {
    assert.equal(error.code, 'physical_release_unconfirmed');
    assert.equal(error.detail.physicalReleaseConfirmed, false);
    assert.equal(error.detail.wrapperExited, true);
    return true;
  });
  assert.equal(h.child.stdin.ended, true);
  assert.deepEqual(h.child.kills, ['SIGTERM']);
});

test('synchronous protocol attachment failure also preserves an exact cleanup handle', async () => {
  const h = harness({ protocolFactoryThrows: Object.assign(new Error('shape'), { code: 'bad_config' }) });
  await assert.rejects(() => h.owner.ready, (error) => error.code === 'protocol_attach_failed');
  await assert.rejects(() => h.owner.close(), (error) => {
    assert.equal(error.code, 'physical_release_unconfirmed');
    assert.equal(error.detail.protocolCode, 'bad_config');
    return true;
  });
  assert.equal(h.owner.wrapperExited, true);
});

test('anchor failure cannot be laundered into readiness or a release claim', async () => {
  const h = harness({
    anchor: async () => { throw Object.assign(new Error('wrong argv'), { code: 'anchor_failed' }); },
    release: async () => { throw Object.assign(new Error('unanchored'), { code: 'unanchored' }); },
  });
  await assert.rejects(() => h.owner.ready, (error) => error.code === 'anchor_failed');
  await assert.rejects(() => h.owner.convert('abcd'), (error) => error.code === 'anchor_failed');
  await assert.rejects(() => h.owner.close(), (error) => {
    assert.equal(error.code, 'physical_release_unconfirmed');
    assert.equal(error.detail.readinessCode, 'anchor_failed');
    assert.equal(error.detail.releaseCode, 'unanchored');
    return true;
  });
});

test('closed validation and token generation fail before spawn', () => {
  let spawns = 0;
  const dependencies = { spawnFn: () => { spawns += 1; return fakeChild(); } };
  for (const options of [
    { distro: 'Ubuntu 24.04', binaryPath: BINARY },
    { distro: DISTRO, binaryPath: 'relative/tool' },
    { distro: DISTRO, binaryPath: '/bad\npath' },
    { distro: DISTRO, binaryPath: BINARY, runtimeLibraryDir: 'relative/libs' },
    { distro: DISTRO, binaryPath: BINARY, runtimeLibraryDir: '/bad:other' },
    { distro: DISTRO, binaryPath: BINARY, runtimeLibraryDir: '/bad/../other' },
    { distro: DISTRO, binaryPath: BINARY, runtimeLibraryDir: '/bad//other' },
    { distro: DISTRO, binaryPath: BINARY, runtimeLibraryDir: '/bad\nother' },
    { distro: DISTRO, binaryPath: BINARY, onFault: 1 },
    { distro: DISTRO, binaryPath: BINARY, dependencies: { surprise: () => {} } },
  ]) {
    assert.throws(() => launchBlockConverterOwner({ ...options, dependencies: {
      ...dependencies, ...(options.dependencies ?? {}),
    } }), (error) => error instanceof BlockConverterOwnerError && error.code === 'bad_config');
  }
  assert.equal(spawns, 0);

  assert.throws(() => launchBlockConverterOwner({
    distro: DISTRO, binaryPath: BINARY,
    dependencies: { ...dependencies, randomBytesFn: () => Buffer.alloc(15) },
  }), (error) => error.code === 'token_failed');
  assert.equal(spawns, 0);
});

test('a synchronous wsl.exe spawn throw is explicit and has no phantom owner', () => {
  assert.throws(() => launchBlockConverterOwner({
    distro: DISTRO,
    binaryPath: BINARY,
    dependencies: {
      randomBytesFn: () => TOKEN_BYTES,
      spawnFn: () => { throw new Error('missing executable'); },
    },
  }), (error) => error instanceof BlockConverterOwnerError && error.code === 'spawn_failed');
  assert.throws(() => launchBlockConverterOwner({
    distro: DISTRO,
    binaryPath: BINARY,
    dependencies: {
      randomBytesFn: () => TOKEN_BYTES,
      spawnFn: () => ({}),
    },
  }), (error) => error instanceof BlockConverterOwnerError && error.code === 'spawn_failed');
});

test('the real protocol and custody implementations compose for one bounded fake transcript', async () => {
  const child = fakeChild();
  let closed = false;
  child.stdin.write = (text, callback) => {
    const line = String(text).replace(/\n$/, '');
    if (line.startsWith('CONVERT ')) {
      const [, id] = line.split(' ');
      queueMicrotask(() => child.stdout.emit('data', Buffer.from(`RESULT ${id} beef\n`, 'ascii')));
    } else if (line === 'QUIT') {
      queueMicrotask(() => child.stdout.emit('data', Buffer.from('BYE\n', 'ascii')));
    }
    callback?.(null);
    return true;
  };
  child.stdin.end = () => {
    child.stdin.writable = false;
    queueMicrotask(() => { closed = true; child.endProcess(0, null); });
  };
  const probeRunner = async (args) => {
    if (args.includes('cat')) {
      return closed
        ? { ok: true, code: 1, stdout: Buffer.from(`${'11111111-2222-3333-4444-555555555555'}\n`),
          reason: null, probeReaped: true }
        : { ok: true, code: 0, stdout: Buffer.from(
          `${'11111111-2222-3333-4444-555555555555'}\n${BINARY}\0--server\0${TOKEN}\0`, 'latin1'),
        reason: null, probeReaped: true };
    }
    return { ok: true, code: 1, stdout: Buffer.from('/proc/self\n'),
      reason: null, probeReaped: true };
  };
  const owner = launchBlockConverterOwner({
    distro: DISTRO,
    binaryPath: BINARY,
    dependencies: {
      randomBytesFn: () => TOKEN_BYTES,
      spawnFn: () => {
        queueMicrotask(() => child.stdout.emit('data',
          Buffer.from(`HELLO 1 ${TOKEN} 4321\n`, 'ascii')));
        return child;
      },
      protocolFactory: createBlockConverterProtocol,
      custodyFactory: (config) => createWslProcessCustody({ ...config, probeRunner }),
    },
  });
  await owner.ready;
  assert.equal(await owner.convert('abcd'), 'beef');
  const result = await owner.close();
  assert.equal(result.gracefulProtocolShutdown, true);
  assert.equal(result.physicalReleaseConfirmed, true);
  assert.equal(result.linuxObservation, OBSERVATION.ABSENT);
  assert.equal(owner.state, 'CLOSED');
});
