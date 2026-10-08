// No daemon, WSL distribution, Docker engine, browser, wallet or network is started here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';

import { OBSERVATION } from '../native_helper.mjs';
import { createWslProcessCustody } from '../wsl_process_custody.mjs';
import { launchWslDaemonOwner, wslDaemonLaunchArgs } from '../wsl_daemon_owner.mjs';

const CONFIG = Object.freeze({
  wslDistro: 'Ubuntu',
  image: 'meepcoin-build:source-pinned',
  artifactDir: '/home/tseng/meepcoin-fresh-build',
  runDir: '/home/tseng/meepcoin-private-run-12345678',
  rpcPort: 28581,
  p2pPort: 28580,
  uid: 1000,
  gid: 1000,
});

function fakeChild(pidLine = 'MEEPCOIN_PID 4321\n') {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.writes = [];
  child.stdin = new Writable({
    write(chunk, _encoding, callback) {
      const text = chunk.toString();
      child.writes.push(text);
      if (text === 'STOP\n') queueMicrotask(() => child.emit('close', 0, null));
      callback();
    },
  });
  child.exitCode = null;
  child.signalCode = null;
  child.kill = (signal) => {
    child.signalCode = signal;
    child.emit('close', null, signal);
    return true;
  };
  queueMicrotask(() => child.stdout.write(pidLine));
  return child;
}

test('the direct launch is a closed, non-root WSL argv with one gated shell and no Docker', () => {
  const plan = wslDaemonLaunchArgs(CONFIG);
  assert.deepEqual(plan.wslArgs.slice(0, 7),
    ['-d', 'Ubuntu', '-u', 'tseng', '--exec', '/bin/sh', '-c']);
  assert.equal(plan.shellArgv[0], '/bin/sh');
  assert.equal(plan.shellArgv.includes('/usr/bin/env'), true);
  assert.equal(plan.shellArgv.includes('LD_LIBRARY_PATH=/home/tseng/meepcoin-fresh-build/runtime-libs'), true);
  assert.equal(plan.daemonArgv[0], '/home/tseng/meepcoin-fresh-build/meepcoind');
  assert.equal(plan.daemonArgv.includes('--offline'), true);
  assert.equal(plan.wslArgs.includes('docker'), false);
  assert.equal(plan.wslArgs.some((arg) => arg.includes('MEEPCOIN_PID')), true);
  assert.equal(plan.shellArgv[2].includes('"$(/usr/bin/id -u)" = "1000"'), true);
  assert.equal(plan.shellArgv[2].includes('"$(/usr/bin/id -g)" = "1000"'), true);
  assert.equal(plan.shellArgv.length > 16, true);
  const custody = createWslProcessCustody({ wrapperChild: fakeChild(''), distro: 'Ubuntu',
    linuxPid: 4321, expectedLinuxArgv: plan.shellArgv,
    additionalExpectedLinuxArgv: plan.daemonArgv, probeRunner: async () => { throw new Error('no probe'); } });
  assert.equal(custody.anchored, false); // construction accepts the real launch shape without probing
  assert.throws(() => wslDaemonLaunchArgs({ ...CONFIG, artifactDir: '/tmp/foreign' }),
    (error) => error.code === 'bad_config');
});

test('GO is sent only after the exact initial WSL process was anchored', async () => {
  const child = fakeChild();
  let anchored = false;
  let released = false;
  const owner = launchWslDaemonOwner({
    config: CONFIG,
    spawnFn(_program, args, options) {
      assert.equal(options.shell, false);
      assert.deepEqual(args, wslDaemonLaunchArgs(CONFIG).wslArgs);
      return child;
    },
    custodyFactory(input) {
      assert.equal(input.linuxPid, 4321);
      assert.deepEqual(input.expectedLinuxArgv, wslDaemonLaunchArgs(CONFIG).shellArgv);
      assert.deepEqual(input.additionalExpectedLinuxArgv, wslDaemonLaunchArgs(CONFIG).daemonArgv);
      return {
        execObserved: true,
        async anchor() { assert.deepEqual(child.writes, []); anchored = true; },
        async observe() {
          assert.equal(anchored, true);
          assert.deepEqual(child.writes, ['GO\n']);
          return { state: OBSERVATION.PRESENT_MATCH, matchedArgv: 'after_exec' };
        },
        async release() {
          released = true;
          return { physicalReleaseConfirmed: true, linuxObservation: OBSERVATION.ABSENT,
            wrapperExited: true, probesReaped: true };
        },
      };
    },
  });
  assert.equal(owner.closed, false);
  await owner.ready;
  assert.equal(owner.state, 'READY');
  assert.equal(owner.linuxPid, 4321);
  assert.equal(child.stdin.writableEnded, true);
  const result = await owner.close();
  assert.equal(released, true);
  assert.equal(result.daemonExecObserved, true);
  assert.equal(owner.closed, true);
  assert.strictEqual(await owner.close(), result);
});

test('cancellation before the anchor settles sends STOP, never GO, then releases custody', async () => {
  const child = fakeChild();
  let allowAnchor;
  const anchorGate = new Promise((resolve) => { allowAnchor = resolve; });
  let releases = 0;
  const owner = launchWslDaemonOwner({
    config: CONFIG,
    spawnFn: () => child,
    custodyFactory: () => ({
      execObserved: false,
      async anchor() { await anchorGate; },
      async observe() { throw new Error('GO must not be sent'); },
      async release() {
        releases++;
        return { physicalReleaseConfirmed: true, linuxObservation: OBSERVATION.ABSENT,
          wrapperExited: true, probesReaped: true };
      },
    }),
  });
  owner.beginClose();
  const close = owner.close();
  allowAnchor();
  await assert.rejects(owner.ready, (error) => error.code === 'closing');
  assert.equal((await close).physicalReleaseConfirmed, true);
  assert.deepEqual(child.writes, ['STOP\n']);
  assert.equal(releases, 1);
});

test('a failed gate write or missing exec identity retains an owned release path', async () => {
  {
    const child = fakeChild();
    child.stdin = new Writable({ write(_chunk, _encoding, callback) {
      callback(new Error('pipe closed'));
    } });
    let releases = 0;
    const owner = launchWslDaemonOwner({ config: CONFIG, spawnFn: () => child,
      custodyFactory: () => ({
        execObserved: false,
        async anchor() {},
        async observe() { throw new Error('no GO should have been delivered'); },
        async release() {
          releases++;
          return { physicalReleaseConfirmed: true, linuxObservation: OBSERVATION.ABSENT,
            wrapperExited: true, probesReaped: true };
        },
      }) });
    await assert.rejects(owner.ready, (error) => error.code === 'gate_write_failed');
    assert.equal((await owner.close()).physicalReleaseConfirmed, true);
    assert.equal(releases, 1);
  }
  {
    const child = fakeChild();
    let releases = 0;
    const owner = launchWslDaemonOwner({ config: CONFIG, spawnFn: () => child,
      execTimeoutMs: 1,
      custodyFactory: () => ({
        execObserved: false,
        async anchor() {},
        async observe() { return { state: OBSERVATION.PRESENT_MATCH, matchedArgv: 'initial' }; },
        async release() {
          releases++;
          return { physicalReleaseConfirmed: true, linuxObservation: OBSERVATION.ABSENT,
            wrapperExited: true, probesReaped: true };
        },
      }) });
    await assert.rejects(owner.ready, (error) => error.code === 'exec_timeout');
    assert.deepEqual(child.writes, ['GO\n']);
    assert.equal((await owner.close()).physicalReleaseConfirmed, true);
    assert.equal(releases, 1);
  }
});

test('malformed or timed-out PID handshake never sends GO and cannot claim physical release', async () => {
  for (const line of ['MEEPCOIN_PID 0001\n', 'MEEPCOIN_PID 4\nextra', 'x'.repeat(65)]) {
    const child = fakeChild(line);
    const owner = launchWslDaemonOwner({ config: CONFIG, spawnFn: () => child,
      custodyFactory: () => { throw new Error('custody must not be constructed'); } });
    await assert.rejects(owner.ready, (error) => error.code === 'bad_pid_line');
    await assert.rejects(() => owner.close(), (error) => error.code === 'custody_unavailable');
    assert.equal(child.writes.includes('GO\n'), false);
    assert.equal(owner.closed, false);
  }
  const child = fakeChild('');
  const owner = launchWslDaemonOwner({ config: CONFIG, spawnFn: () => child,
    pidHandshakeTimeoutMs: 1 });
  await assert.rejects(owner.ready, (error) => error.code === 'pid_handshake_timeout');
  await assert.rejects(() => owner.close(), (error) => error.code === 'custody_unavailable');
  assert.equal(child.writes.includes('GO\n'), false);
});

test('the launch dependency surface and timing bounds are validated before spawn', () => {
  let spawns = 0;
  const spawnFn = () => { spawns++; return fakeChild(); };
  for (const overrides of [
    { pidHandshakeTimeoutMs: 0 }, { execTimeoutMs: 60001 },
    { custodyFactory: null }, { onFault: null },
  ]) {
    assert.throws(() => launchWslDaemonOwner({ config: CONFIG, spawnFn, ...overrides }),
      (error) => error.code === 'bad_config');
  }
  assert.equal(spawns, 0);
});
