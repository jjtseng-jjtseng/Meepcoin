// Physical-process custody tests only. No WSL distribution, converter, daemon, browser, socket,
// wallet, hash or network is started. Every observation and process handle is a bounded fake.

import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import { OBSERVATION } from '../native_helper.mjs';
import { createWslProcessCustody, WslCustodyError } from '../wsl_process_custody.mjs';

const DISTRO = 'Ubuntu';
const PID = 4321;
const BOOT = '11111111-2222-3333-4444-555555555555';
const OTHER_BOOT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const ARGV = ['/opt/meepcoin/meepcoin-blockhashing', '--server',
  '0123456789abcdef0123456789abcdef'];
const EXEC_ARGV = ['/home/tseng/meepcoin-build/meepcoind', '--testnet', '--offline'];

function fakeWrapper({ closeOnKill = true } = {}) {
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  child.kills = [];
  child.kill = (signal) => {
    child.kills.push(signal);
    if (closeOnKill) queueMicrotask(() => child.endProcess(null, signal));
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

function probeOutput(boot = BOOT, argv = ARGV) {
  return Buffer.from(`${boot}\n${argv.map((field) => `${field}\0`).join('')}`, 'latin1');
}

function existsOutput(exists) {
  return Buffer.from(`/proc/self\n${exists ? `/proc/${PID}\n` : ''}`, 'latin1');
}

function answer(stdout, code = 0) {
  return { ok: true, code, stdout: Buffer.from(stdout), reason: null, probeReaped: true };
}

function scriptedRunner(answers) {
  const calls = [];
  const run = async (args) => {
    calls.push([...args]);
    assert(answers.length > 0, `unexpected probe: ${args.join(' ')}`);
    const next = answers.shift();
    return typeof next === 'function' ? await next(args) : next;
  };
  return { calls, run, remaining: answers };
}

function custody({ wrapper = fakeWrapper(), runner, limits = {}, additionalExpectedLinuxArgv = null } = {}) {
  return createWslProcessCustody({
    wrapperChild: wrapper,
    distro: DISTRO,
    linuxPid: PID,
    expectedLinuxArgv: ARGV,
    additionalExpectedLinuxArgv,
    probeRunner: runner,
    limits: { pollMs: 1, absenceTimeoutMs: 5, wrapperTimeoutMs: 5, ...limits },
  });
}

test('a controlled exec preserves custody of the same boot and pid, then locks out the old argv', async () => {
  const script = scriptedRunner([
    answer(probeOutput(BOOT, EXEC_ARGV)), // cannot anchor on the alternate alone
  ]);
  await assert.rejects(() => custody({ runner: script.run,
    additionalExpectedLinuxArgv: EXEC_ARGV }).anchor(), (error) => error.code === 'anchor_failed');

  const after = scriptedRunner([
    answer(probeOutput()),
    answer(probeOutput(BOOT, EXEC_ARGV)),
    answer(probeOutput()),
  ]);
  const owner = custody({ runner: after.run, additionalExpectedLinuxArgv: EXEC_ARGV });
  await owner.anchor();
  assert.deepEqual(owner.additionalExpectedLinuxArgv, EXEC_ARGV);
  assert.equal(owner.execObserved, false);
  const daemon = await owner.observe();
  assert.equal(daemon.state, OBSERVATION.PRESENT_MATCH);
  assert.equal(daemon.matchedArgv, 'after_exec');
  assert.equal(owner.execObserved, true);
  assert.equal((await owner.observe()).state, OBSERVATION.PRESENT_MISMATCH);
});

test('release after controlled exec signals only the freshly observed exact daemon pid', async () => {
  const wrapper = fakeWrapper();
  let terminated = false;
  const calls = [];
  const runner = async (args) => {
    calls.push([...args]);
    if (args.includes('-TERM')) {
      terminated = true;
      wrapper.endProcess(null, 'SIGTERM');
      return answer(Buffer.alloc(0));
    }
    if (args.includes('ls')) return answer(existsOutput(false), 1);
    if (terminated) return answer(Buffer.from(`${BOOT}\n`, 'latin1'), 1);
    return answer(probeOutput(BOOT, calls.length === 1 ? ARGV : EXEC_ARGV));
  };
  const owner = custody({ wrapper, runner, additionalExpectedLinuxArgv: EXEC_ARGV });
  await owner.anchor();
  const result = await owner.release();
  assert.equal(result.physicalReleaseConfirmed, true);
  assert.equal(owner.execObserved, true);
  assert.equal(calls.filter((args) => args.includes('-TERM')).length, 1);
  assert.equal(calls.some((args) => args.includes('-KILL')), false);
});

test('controlled-exec custody never treats an argv mismatch as proved process absence', async () => {
  const wrapper = fakeWrapper();
  wrapper.endProcess(0, null);
  const script = scriptedRunner([
    answer(probeOutput()),
    answer(probeOutput(BOOT, EXEC_ARGV)),
    answer(probeOutput(BOOT, ['/other/process'])),
  ]);
  const owner = custody({ wrapper, runner: script.run,
    additionalExpectedLinuxArgv: EXEC_ARGV });
  await owner.anchor();
  assert.equal((await owner.observe()).matchedArgv, 'after_exec');
  await assert.rejects(() => owner.release(), (error) => error.code === 'release_unconfirmed');
  assert.equal(owner.released, false);
  assert.equal(script.calls.some((args) => args.includes('kill')), false);
});

test('a malformed or identical controlled-exec argv is rejected before any probe', () => {
  for (const additionalExpectedLinuxArgv of [[], [...ARGV], ['/bad\npath'], Array(65).fill('x')]) {
    assert.throws(() => custody({ runner: scriptedRunner([]).run,
      additionalExpectedLinuxArgv }), (error) => error.code === 'bad_config');
  }
  const owner = custody({ runner: scriptedRunner([]).run,
    additionalExpectedLinuxArgv: Array(32).fill('x') });
  assert.equal(owner.additionalExpectedLinuxArgv.length, 32);
});

test('anchor binds one parent-pinned distro, boot id, pid and exact positional argv', async () => {
  const wrapper = fakeWrapper();
  const script = scriptedRunner([answer(probeOutput())]);
  const owner = custody({ wrapper, runner: script.run });
  assert.deepEqual(await owner.anchor(), { bootId: BOOT, linuxPid: PID, distro: DISTRO });
  assert.equal(owner.anchored, true);
  assert.equal(owner.anchoredBootId, BOOT);
  assert.deepEqual(owner.expectedLinuxArgv, ARGV);
  assert.deepEqual(script.calls, [[
    '-d', DISTRO, '--exec', 'cat', '/proc/sys/kernel/random/boot_id', `/proc/${PID}/cmdline`,
  ]]);
});

test('a malformed control, different argv, unreadable pid or failed probe cannot anchor', async () => {
  const emptyArg = Buffer.from(
    `${BOOT}\n${ARGV[0]}\0\0${ARGV.slice(1).map((field) => `${field}\0`).join('')}`,
    'latin1',
  );
  const unterminated = Buffer.from(`${BOOT}\n${ARGV.join('\0')}`, 'latin1');
  const cases = [
    answer(Buffer.from(`not-a-boot-id\n${ARGV.join('\0')}\0`, 'latin1')),
    answer(probeOutput(BOOT, ['/other/process'])),
    answer(emptyArg),
    answer(unterminated),
    { ok: false, code: null, stdout: Buffer.alloc(0), reason: 'spawn failed', probeReaped: true },
  ];
  for (const result of cases) {
    const owner = custody({ runner: scriptedRunner([result]).run });
    await assert.rejects(() => owner.anchor(),
      (error) => error instanceof WslCustodyError && error.code === 'anchor_failed');
    assert.equal(owner.anchored, false);
    assert.equal(owner.released, false);
  }
  {
    const script = scriptedRunner([
      answer(Buffer.from(`${BOOT}\n`, 'latin1'), 1),
      answer(existsOutput(true), 0),
    ]);
    const owner = custody({ runner: script.run });
    await assert.rejects(() => owner.anchor(), (error) => error.code === 'anchor_failed');
    assert.equal(owner.anchored, false);
  }
});

test('release needs a prior anchor; wrapper exit alone is never Linux absence', async () => {
  const wrapper = fakeWrapper();
  wrapper.endProcess(0, null);
  const owner = custody({ wrapper, runner: scriptedRunner([]).run });
  assert.equal(owner.wrapperExited, true);
  await assert.rejects(() => owner.release(), (error) => error.code === 'unanchored');
  assert.equal(owner.released, false);
});

test('canonical shutdown: independently confirmed absence plus wrapper close releases everything', async () => {
  const wrapper = fakeWrapper();
  const script = scriptedRunner([
    answer(probeOutput()),
    answer(Buffer.from(`${BOOT}\n`, 'latin1'), 1),
    answer(existsOutput(false), 1),
  ]);
  const owner = custody({ wrapper, runner: script.run });
  await owner.anchor();
  wrapper.endProcess(0, null);
  assert.deepEqual(await owner.release(), {
    physicalReleaseConfirmed: true,
    linuxObservation: OBSERVATION.ABSENT,
    wrapperExited: true,
    probesReaped: true,
  });
  assert.equal(owner.released, true);
  assert.deepEqual(wrapper.kills, []);
  assert.equal(owner.probeCount, 0);
});

test('a boot-id change is absence only after the launch identity was anchored', async () => {
  const wrapper = fakeWrapper();
  const script = scriptedRunner([answer(probeOutput()), answer(probeOutput(OTHER_BOOT, []))]);
  const owner = custody({ wrapper, runner: script.run });
  await owner.anchor();
  wrapper.endProcess(0, null);
  const result = await owner.release();
  assert.equal(result.linuxObservation, OBSERVATION.ABSENT);
  assert.deepEqual(wrapper.kills, []);
});

test('present mismatch after a valid anchor proves our old process is absent and is never signalled', async () => {
  const wrapper = fakeWrapper();
  const script = scriptedRunner([answer(probeOutput()), answer(probeOutput(BOOT, ['/new/process']))]);
  const owner = custody({ wrapper, runner: script.run });
  await owner.anchor();
  wrapper.endProcess(0, null);
  const result = await owner.release();
  assert.equal(result.linuxObservation, OBSERVATION.PRESENT_MISMATCH);
  assert.equal(script.calls.some((args) => args.includes('kill')), false);
  const callCount = script.calls.length;
  assert.strictEqual(await owner.release(), result);
  assert.equal(script.calls.length, callCount);
});

test('a still-live exact process gets TERM only behind a fresh exact identity', async () => {
  const wrapper = fakeWrapper();
  let termSeen = false;
  const calls = [];
  const runner = async (args) => {
    calls.push([...args]);
    if (args.includes('kill')) {
      assert.deepEqual(args.slice(-3), ['kill', '-TERM', String(PID)]);
      termSeen = true;
      wrapper.endProcess(null, 'SIGTERM');
      return answer(Buffer.alloc(0));
    }
    if (!termSeen) return answer(probeOutput());
    if (args.includes('ls')) return answer(existsOutput(false), 1);
    return answer(Buffer.from(`${BOOT}\n`, 'latin1'), 1);
  };
  const owner = custody({ wrapper, runner });
  await owner.anchor();
  const result = await owner.release();
  assert.equal(result.physicalReleaseConfirmed, true);
  assert.equal(calls.filter((args) => args.includes('kill')).length, 1);
  // Anchor, initial release observation, and the signal function's own fresh observation.
  assert.equal(calls.filter((args) => args.some((field) => field.endsWith('/cmdline'))).length >= 3, true);
});

test('KILL is fenced by its own fresh identity and is refused if the pid changed after TERM', async () => {
  const wrapper = fakeWrapper({ closeOnKill: false });
  let termSeen = false;
  let postTermObservations = 0;
  const calls = [];
  const runner = async (args) => {
    calls.push([...args]);
    if (args.includes('-TERM')) { termSeen = true; return answer(Buffer.alloc(0)); }
    if (args.includes('-KILL')) throw new Error('KILL must be fenced off');
    if (!termSeen) return answer(probeOutput());
    postTermObservations += 1;
    // waitForAbsence first sees our process through its short deadline. signalExact('KILL') then
    // takes a NEW observation and sees another process at that pid, so no KILL probe is launched.
    if (postTermObservations === 1) {
      await new Promise((resolve) => setTimeout(resolve, 2));
      return answer(probeOutput());
    }
    return answer(probeOutput(BOOT, ['/pid/reused']));
  };
  const owner = custody({ wrapper, runner,
    limits: { absenceTimeoutMs: 1, pollMs: 1, wrapperTimeoutMs: 1 } });
  await owner.anchor();
  await assert.rejects(() => owner.release(), (error) => error.code === 'kill_refused');
  assert.equal(calls.some((args) => args.includes('-KILL')), false);
  assert.equal(owner.released, false);
});

test('inspection failure retains ownership and sends no signal; a later retry may release', async () => {
  const wrapper = fakeWrapper();
  let failed = true;
  const calls = [];
  const runner = async (args) => {
    calls.push([...args]);
    if (calls.length === 1) return answer(probeOutput());
    if (failed) return { ok: false, code: null, stdout: Buffer.alloc(0),
      reason: 'inspection unavailable', probeReaped: true };
    if (args.includes('ls')) return answer(existsOutput(false), 1);
    return answer(Buffer.from(`${BOOT}\n`, 'latin1'), 1);
  };
  const owner = custody({ wrapper, runner });
  await owner.anchor();
  await assert.rejects(() => owner.release(), (error) => error.code === 'release_unconfirmed');
  assert.equal(calls.some((args) => args.includes('kill')), false);
  assert.equal(owner.released, false);
  failed = false;
  wrapper.endProcess(0, null);
  assert.equal((await owner.release()).physicalReleaseConfirmed, true);
});

test('after Linux absence, a stuck wrapper is signalled only through its exact ChildProcess handle', async () => {
  const wrapper = fakeWrapper();
  const script = scriptedRunner([
    answer(probeOutput()),
    answer(Buffer.from(`${BOOT}\n`, 'latin1'), 1),
    answer(existsOutput(false), 1),
  ]);
  const owner = custody({ wrapper, runner: script.run,
    limits: { wrapperTimeoutMs: 1 } });
  await owner.anchor();
  const result = await owner.release();
  assert.equal(result.wrapperExited, true);
  assert.deepEqual(wrapper.kills, ['SIGTERM']);
});

test('concurrent release calls join one custody operation and never duplicate a signal', async () => {
  const wrapper = fakeWrapper();
  let termSeen = false;
  let releaseTerm;
  const heldTerm = new Promise((resolve) => { releaseTerm = resolve; });
  const calls = [];
  const runner = async (args) => {
    calls.push([...args]);
    if (args.includes('-TERM')) {
      termSeen = true;
      await heldTerm;
      wrapper.endProcess(null, 'SIGTERM');
      return answer(Buffer.alloc(0));
    }
    if (!termSeen) return answer(probeOutput());
    if (args.includes('ls')) return answer(existsOutput(false), 1);
    return answer(Buffer.from(`${BOOT}\n`, 'latin1'), 1);
  };
  const owner = custody({ wrapper, runner });
  await owner.anchor();
  const first = owner.release();
  const second = owner.release();
  releaseTerm();
  const [a, b] = await Promise.all([first, second]);
  assert.deepEqual(a, b);
  assert.equal(calls.filter((args) => args.includes('-TERM')).length, 1);
});

class FakeProbe extends EventEmitter {
  constructor({ reapOnKill }) {
    super();
    this.pid = 9001;
    this.stdout = new EventEmitter();
    this.reapOnKill = reapOnKill;
    this.kills = [];
  }

  kill(signal) {
    this.kills.push(signal);
    if (this.reapOnKill) queueMicrotask(() => this.emit('close', null, signal));
    return true;
  }
}

test('a timed-out probe is joined and reaped before the failed observation returns', async () => {
  const probe = new FakeProbe({ reapOnKill: true });
  const owner = createWslProcessCustody({
    wrapperChild: fakeWrapper(), distro: DISTRO, linuxPid: PID, expectedLinuxArgv: ARGV,
    probeSpawnFn: () => probe,
    limits: { probeTimeoutMs: 2, probeReapMs: 2 },
  });
  await assert.rejects(() => owner.anchor(), (error) => error.code === 'anchor_failed');
  assert.deepEqual(probe.kills, ['SIGTERM']);
  assert.equal(owner.probeCount, 0);
});

test('a probe that cannot be confirmed gone remains visibly owned', async () => {
  const probe = new FakeProbe({ reapOnKill: false });
  const owner = createWslProcessCustody({
    wrapperChild: fakeWrapper(), distro: DISTRO, linuxPid: PID, expectedLinuxArgv: ARGV,
    probeSpawnFn: () => probe,
    limits: { probeTimeoutMs: 1, probeReapMs: 1 },
  });
  await assert.rejects(() => owner.anchor(), (error) => error.code === 'anchor_failed');
  assert.deepEqual(probe.kills, ['SIGTERM', 'SIGKILL']);
  assert.equal(owner.probeCount, 1);
  assert.equal(owner.released, false);
});

test('configuration is closed before any probe or signal can start', () => {
  const wrapper = fakeWrapper();
  const base = { wrapperChild: wrapper, distro: DISTRO, linuxPid: PID, expectedLinuxArgv: ARGV };
  for (const change of [
    { distro: 'Ubuntu 24.04' },
    { linuxPid: 0 },
    { expectedLinuxArgv: [] },
    { expectedLinuxArgv: ['ok', 'bad\nfield'] },
    { limits: { surprise: 1 } },
    { probeRunner: 42 },
  ]) {
    assert.throws(() => createWslProcessCustody({ ...base, ...change }),
      (error) => error instanceof WslCustodyError && error.code === 'bad_config');
  }
});
