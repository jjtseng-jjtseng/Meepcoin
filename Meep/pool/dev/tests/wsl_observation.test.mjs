// WSL process observation: four states, and the rule that only one of them authorises "released".
//
// THE ORIGINAL DEFECT. readLinuxCmdline() mapped ALL of confirmed absence, probe spawn failure,
// probe nonzero exit, empty output, timeout, permission trouble and wrong-distribution to the same
// value -- null -- and the callers read null as "gone". A Windows host that simply could not look
// into WSL would mark the helper released and the pool would report a clean shutdown over a
// process that was still running.
//
// THE DEFECT AFTER THAT. The repair still read ONE ambiguous wire shape as absence. `cat
// /proc/sys/kernel/random/boot_id /proc/<pid>/cmdline` returns, byte for byte and exit code for
// exit code, the SAME thing when the entry is MISSING and when its cmdline cannot be READ:
//
//   missing:  stdout = "<boot-id>\n" (37 bytes), exit 1, stderr "No such file or directory"
//   denied:   stdout = "<boot-id>\n" (37 bytes), exit 1, stderr "Permission denied"
//
// runWsl discards stderr, and localised stderr text is not a discriminator anyway. So absence is
// now claimed only when a SEPARATE probe positively establishes that /proc/<pid> is not there --
// `ls -1 -d -- /proc/self /proc/<pid>`, which needs only to stat its operands (it therefore still
// names an entry whose contents are unreadable) and carries the probe's own /proc entry as a
// control operand in the same invocation.
//
// AND THE BASELINE ITSELF. The launch boot id arrives in HELLO, from the very process whose fate
// it will later be used to decide. A malformed value used to be accepted, and would then differ
// from the next VALID observed boot id -- which was read as "the VM restarted", which authorised
// absence. A WSL launch now REQUIRES a canonical distribution and a canonical UUID boot id, and
// corroborates that boot id once through a parent-owned observation, before it may support any
// absence claim.
//
// These tests drive the REAL observation logic through the wslRunner seam, which returns exactly
// what the real probe returns. The real WSL path is exercised against the real helper in
// pool/dev/tests/dual_verifier.test.mjs, and probe OWNERSHIP (which this seam bypasses entirely)
// is exercised with child-shaped handles in pool/dev/tests/native_helper.test.mjs.

import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { startNativeHelper, OBSERVATION, HELPER_PROTOCOL_VERSION } from '../native_helper.mjs';

/**
 * The PARENT-PINNED distribution these tests launch in. Every probe must route here, whatever
 * HELLO says. Deliberately a literal: the regressions below must not depend on which
 * distributions happen to be installed on the machine running them.
 */
const PINNED = 'Ubuntu';

let scratch;
before(() => { scratch = mkdtempSync(join(tmpdir(), 'meep-wslobs-')); });
after(async () => {
  if (!scratch) return;
  for (let i = 0; i < 10 && existsSync(scratch); i++) {
    try { rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  if (existsSync(scratch)) console.error(`# LEFTOVER TEMP DIRECTORY NOT REMOVED: ${scratch}`);
});

const BOOT = '6dc31bb7-d4a7-40d0-9e96-6a7a3f625deb';
const OTHER_BOOT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const LINUX_PID = 4242;
const HELPER_WSL_PATH = '/mnt/c/Users/tseng/meepcoin/meepow/build/native-helper/meepow-v2-helper';

/**
 * A fake that greets as a WSL child: a fixed Linux pid, a distro, and the boot id above. Its own
 * Windows-side process is a Node script, but every /proc question goes through the seam.
 */
function greetAsWslChild(extra = '', { distro = PINNED, bootId = BOOT } = {}) {
  const file = join(scratch, `wsl-fake-${Math.random().toString(36).slice(2)}.mjs`);
  writeFileSync(file,
    `process.stdout.write('HELLO ${HELPER_PROTOCOL_VERSION} ${LINUX_PID} ' + process.argv[2] `
    + `+ ' 2 60 ${distro} ${bootId} fakesource\\n');\n${extra}\n`, 'utf8');
  return file;
}

/** Build the cmdline probe's stdout: the boot-id control line, then the target's NUL-separated argv. */
function probeOutput(bootId, argv) {
  return Buffer.from(`${bootId}\n${argv.map((a) => `${a}\0`).join('')}`, 'latin1');
}

/** Build the existence probe's stdout: the control operand, and the target only if it is there. */
function existenceOutput({ control = true, target = false } = {}) {
  const lines = [];
  if (target) lines.push(`/proc/${LINUX_PID}`);
  if (control) lines.push('/proc/self');
  return Buffer.from(lines.length ? `${lines.join('\n')}\n` : '', 'latin1');
}

// ---------------------------------------------------------------- probe classification
//
// The module now asks up to three DIFFERENT questions. A test runner that cannot tell them apart
// would answer the wrong one, so they are classified here exactly as the module spells them.

/** `cat /proc/sys/kernel/random/boot_id` alone: the startup boot-identity anchor. */
const isAnchor = (args) => args.includes('cat') && !args.some((a) => a.endsWith('/cmdline'));
/** `cat boot_id /proc/<pid>/cmdline`: the identity observation. */
const isCmdline = (args) => args.some((a) => a.endsWith('/cmdline'));
/** `ls -1 -d -- /proc/self /proc/<pid>`: the positive existence question. */
const isExistence = (args) => args.includes('ls');
const isKill = (args) => args.includes('kill');

async function helperWith(t, wslRunner, { extra = '', greet = {}, ...opts } = {}) {
  const file = greetAsWslChild(extra, greet);
  const { helper } = await startNativeHelper({
    helperPath: 'C:/Users/tseng/meepcoin/meepow/build/native-helper/meepow-v2-helper',
    useWsl: true,
    wslDistro: PINNED,
    wslRunner,
    spawnFn: (cmd) => spawn(process.execPath, [file, cmd.args.at(-1)], {
      stdio: ['pipe', 'pipe', 'pipe'], shell: false,
    }),
    ...opts,
  });
  t.after(async () => { try { await helper.forceClose('test cleanup'); } catch { /* fine */ } });
  return helper;
}

/**
 * A runner that can see the helper it belongs to, so it can echo the real per-launch token.
 * `make(helper, args, timeoutMs)` returns exactly what the real probe returns.
 *
 * The startup anchor is answered here, once, with the matching boot id: every test below is about
 * what happens AFTER a correctly anchored launch. The anchor's own failure modes are the last
 * section of this file.
 */
async function startObservation(t, make, opts = {}) {
  const box = {};
  const helper = await helperWith(t, (args, ms) => {
    if (isAnchor(args)) return { ok: true, code: 0, stdout: Buffer.from(`${BOOT}\n`, 'latin1'), reason: null };
    return make(box.helper, args, ms);
  }, opts);
  box.helper = helper;
  return { helper };
}

// ---------------------------------------------------------------- the four states

test('an exact argv match is CONFIRMED_PRESENT_MATCH', { timeout: 30_000 }, async (t) => {
  // Short signal bounds: this helper always observes as present, so cleanup deliberately walks the
  // full TERM -> KILL escalation and would otherwise sit on the 5 s defaults twice.
  const { helper } = await startObservation(t, (h) => ({
    ok: true, code: 0, stdout: probeOutput(BOOT, [HELPER_WSL_PATH, h.token]), reason: null,
  }), { limits: { signalTimeoutMs: 300, probeTimeoutMs: 300 } });
  const obs = await helper.observeLinuxProcess();
  assert.equal(obs.state, OBSERVATION.PRESENT_MATCH);
  assert.deepEqual(obs.argv, [HELPER_WSL_PATH, helper.token]);
});

test('a different process at that pid is CONFIRMED_PRESENT_MISMATCH, and is never signalled',
  { timeout: 30_000 }, async (t) => {
    const signalled = [];
    const { helper } = await startObservation(t, (h, args) => {
      if (isKill(args)) { signalled.push(args); return { ok: true, code: 0, stdout: Buffer.alloc(0) }; }
      return { ok: true, code: 0, stdout: probeOutput(BOOT, ['/usr/bin/some-other-program', 'x']), reason: null };
    });
    const obs = await helper.observeLinuxProcess();
    assert.equal(obs.state, OBSERVATION.PRESENT_MISMATCH);

    await assert.rejects(() => helper.forceClose('mismatch'),
      /refusing to signal Linux pid/,
      'a pid that is no longer ours must fail the close, not be killed');
    assert.deepEqual(signalled, [], 'and NOTHING was signalled');
    assert.equal(helper.closed, false, 'the resource stays owned');
  });

test('an argv that merely ENDS WITH the helper name is a mismatch, not a match',
  { timeout: 30_000 }, async (t) => {
    // The old check was `args.some(a => a.endsWith('meepow-v2-helper')) && args.includes(token)`.
    // A process at a different path, with the token anywhere in its argv, satisfied both.
    const { helper } = await startObservation(t, (h) => ({
      ok: true,
      code: 0,
      stdout: probeOutput(BOOT, ['/tmp/evil/meepow-v2-helper', 'unrelated', h.token]),
      reason: null,
    }));
    assert.equal((await helper.observeLinuxProcess()).state, OBSERVATION.PRESENT_MISMATCH);
  });

test('an INDEPENDENTLY CONFIRMED missing /proc entry is CONFIRMED_ABSENT',
  { timeout: 30_000 }, async (t) => {
    const asked = [];
    const { helper } = await startObservation(t, (h, args) => {
      asked.push(args);
      // cat printed the boot id and then failed on the cmdline: exit 1, control present.
      if (isCmdline(args)) return { ok: true, code: 1, stdout: Buffer.from(`${BOOT}\n`, 'latin1'), reason: null };
      // The separate existence question: the control operand came back, our pid did not.
      if (isExistence(args)) {
        return { ok: true, code: 2, stdout: existenceOutput({ control: true, target: false }), reason: null };
      }
      return { ok: true, code: 0, stdout: Buffer.alloc(0), reason: null };
    });
    const obs = await helper.observeLinuxProcess();
    assert.equal(obs.state, OBSERVATION.ABSENT);
    assert.match(obs.detail, /independently confirmed/);
    assert.ok(asked.some(isExistence),
      'absence must rest on the separate existence probe, not on cat exiting nonzero');
  });

test('a restarted WSL VM is CONFIRMED_ABSENT, because the pid namespace went with it',
  { timeout: 30_000 }, async (t) => {
    const { helper } = await startObservation(t, () => ({
      ok: true, code: 0, stdout: probeOutput(OTHER_BOOT, ['/anything', 'at-all']), reason: null,
    }));
    const obs = await helper.observeLinuxProcess();
    assert.equal(obs.state, OBSERVATION.ABSENT);
    assert.match(obs.detail, /WSL VM restarted/);
  });

// ---------------------------------------------------------------- THE AMBIGUOUS SHAPE
//
// This is the regression the second round exists for. The wire shape is IDENTICAL to the confirmed
// absence above -- same 37 stdout bytes, same nonzero exit -- and the only difference is what the
// separate existence probe says. It must never be read as absence.

test('a valid boot control with an UNREADABLE cmdline, where the process still EXISTS, '
  + 'is INSPECTION_FAILED', { timeout: 30_000 }, async (t) => {
  const shapes = [];
  const { helper } = await startObservation(t, (h, args) => {
    if (isCmdline(args)) {
      // Byte-for-byte what a genuinely missing entry produces. Only the existence probe can tell.
      const stdout = Buffer.from(`${BOOT}\n`, 'latin1');
      shapes.push({ code: 1, bytes: stdout.length });
      return { ok: true, code: 1, stdout, reason: null };
    }
    if (isExistence(args)) {
      // The entry IS there -- `ls -d` only stats it -- we simply were not allowed to read inside.
      return { ok: true, code: 0, stdout: existenceOutput({ control: true, target: true }), reason: null };
    }
    return { ok: true, code: 0, stdout: Buffer.alloc(0), reason: null };
  });

  const obs = await helper.observeLinuxProcess();
  assert.deepEqual(shapes, [{ code: 1, bytes: 37 }],
    'the cmdline probe returned exactly the shape a MISSING entry returns');
  assert.equal(obs.state, OBSERVATION.UNKNOWN,
    'a cmdline we could not read is not a process that is gone');
  assert.match(obs.detail, /exists but its cmdline could not be read/);

  // And the whole point: this must never authorise released.
  await assert.rejects(() => helper.close('cannot read cmdline'),
    (err) => /cannot confirm|could not be confirmed|cannot inspect/.test(err.message));
  assert.equal(helper.closed, false, 'ownership is retained');
});

for (const [label, existence] of [
  ['the existence probe could not be spawned',
    { ok: false, code: null, stdout: Buffer.alloc(0), reason: 'spawn failed: ENOENT' }],
  ['the existence probe timed out',
    { ok: false, code: null, stdout: Buffer.alloc(0), reason: 'probe timed out after 5000 ms' }],
  ['the existence probe lost its own control operand',
    { ok: true, code: 2, stdout: existenceOutput({ control: false, target: false }), reason: null }],
  ['the existence probe returned nothing at all',
    { ok: true, code: 0, stdout: Buffer.alloc(0), reason: null }],
]) {
  test(`INSPECTION_FAILED when the cmdline is empty and ${label}`, { timeout: 30_000 }, async (t) => {
    const { helper } = await startObservation(t, (h, args) => {
      if (isCmdline(args)) return { ok: true, code: 1, stdout: Buffer.from(`${BOOT}\n`, 'latin1'), reason: null };
      if (isExistence(args)) return existence;
      return { ok: true, code: 0, stdout: Buffer.alloc(0), reason: null };
    });
    const obs = await helper.observeLinuxProcess();
    assert.equal(obs.state, OBSERVATION.UNKNOWN, `${label} must not be read as absence`);
    assert.match(obs.detail, /existence probe/);
    await assert.rejects(() => helper.close('cannot inspect'),
      (err) => /cannot confirm|could not be confirmed|cannot inspect/.test(err.message));
    assert.equal(helper.closed, false);
  });
}

// ---------------------------------------------------------------- failure is NOT absence

for (const [label, answer] of [
  ['the probe could not be spawned', { ok: false, code: null, stdout: Buffer.alloc(0), reason: 'spawn failed: ENOENT' }],
  ['the probe timed out', { ok: false, code: null, stdout: Buffer.alloc(0), reason: 'probe timed out after 5000 ms' }],
  ['the probe exited nonzero with no control line', { ok: true, code: 1, stdout: Buffer.alloc(0), reason: null }],
  ['the probe returned unrecognisable output', { ok: true, code: 0, stdout: Buffer.from('who knows\n'), reason: null }],
  ['the control line is not a boot id', { ok: true, code: 0, stdout: Buffer.from(`${'z'.repeat(36)}\nx\0`), reason: null }],
]) {
  test(`INSPECTION_FAILED when ${label} -- and that never authorises released`,
    { timeout: 30_000 }, async (t) => {
      const { helper } = await startObservation(t, (h, args) => (isKill(args)
        ? { ok: true, code: 0, stdout: Buffer.alloc(0) }
        : answer));
      const obs = await helper.observeLinuxProcess();
      assert.equal(obs.state, OBSERVATION.UNKNOWN, `${label} must not be read as absence`);

      // The whole point: a close that could not confirm absence must FAIL and keep the resource.
      await assert.rejects(() => helper.close('cannot inspect'),
        (err) => /cannot confirm|could not be confirmed|cannot inspect/.test(err.message));
      assert.equal(helper.closed, false, 'not released: we never established the process is gone');
    });
}

// ---------------------------------------------------------------- signalling honestly

test('a TERM that fails is reported, not counted as a successful signal',
  { timeout: 30_000 }, async (t) => {
    const { helper } = await startObservation(t, (h, args) => {
      if (isKill(args)) return { ok: true, code: 1, stdout: Buffer.alloc(0), reason: null };
      return { ok: true, code: 0, stdout: probeOutput(BOOT, [HELPER_WSL_PATH, h.token]), reason: null };
    }, { limits: { signalTimeoutMs: 300, probeTimeoutMs: 300 } });

    await assert.rejects(() => helper.forceClose('failing signals'),
      (err) => /TERM failed/.test(err.message) && /KILL failed/.test(err.message),
      'both failed signals are named');
    assert.equal(helper.closed, false);
  });

test('a KILL that works, after a TERM that does not, still confirms absence',
  { timeout: 30_000 }, async (t) => {
    let killed = false;
    const { helper } = await startObservation(t, (h, args) => {
      if (isKill(args)) {
        if (args.includes('-KILL')) { killed = true; return { ok: true, code: 0, stdout: Buffer.alloc(0) }; }
        return { ok: true, code: 1, stdout: Buffer.alloc(0) }; // TERM fails
      }
      if (isExistence(args)) {
        return { ok: true, code: 2, stdout: existenceOutput({ control: true, target: false }), reason: null };
      }
      return killed
        ? { ok: true, code: 1, stdout: Buffer.from(`${BOOT}\n`, 'latin1'), reason: null }
        : { ok: true, code: 0, stdout: probeOutput(BOOT, [HELPER_WSL_PATH, h.token]), reason: null };
    }, { limits: { signalTimeoutMs: 1500, probeTimeoutMs: 300 } });

    await assert.rejects(() => helper.forceClose('term fails, kill works'), /TERM failed/,
      'the failed TERM is still reported honestly');
    assert.equal(killed, true, 'and escalation did reach KILL');
  });

test('every probe targets the PARENT-PINNED distribution, not the default and not the child-reported one',
  { timeout: 30_000 }, async (t) => {
    const seen = [];
    const { helper } = await startObservation(t, (h, args) => {
      seen.push(args);
      if (isExistence(args)) {
        return { ok: true, code: 2, stdout: existenceOutput({ control: true, target: false }), reason: null };
      }
      return { ok: true, code: 1, stdout: Buffer.from(`${BOOT}\n`, 'latin1'), reason: null };
    });
    await helper.observeLinuxProcess();
    assert.ok(seen.length >= 2, 'both the cmdline probe and the existence probe ran');
    for (const args of seen) {
      assert.deepEqual(args.slice(0, 2), ['-d', PINNED],
        'assuming the default distribution cannot change between launch and shutdown is a guess');
    }
    assert.ok(seen.some((a) => a.includes(`/proc/${LINUX_PID}/cmdline`)), 'it asks about exactly our pid');
    assert.ok(seen.some((a) => a.includes(`/proc/${LINUX_PID}`) && a.includes('/proc/self')),
      'and the existence question carries its own control operand');
  });

test('nothing is ever handed to a shell, on either side of the boundary',
  { timeout: 30_000 }, async (t) => {
    const seen = [];
    const { helper } = await startObservation(t, (h, args) => {
      seen.push(args);
      if (isExistence(args)) {
        return { ok: true, code: 2, stdout: existenceOutput({ control: true, target: false }), reason: null };
      }
      return { ok: true, code: 1, stdout: Buffer.from(`${BOOT}\n`, 'latin1'), reason: null };
    });
    await helper.observeLinuxProcess();
    for (const args of seen) {
      for (const a of args) {
        assert.doesNotMatch(a, /[;&|`$()<>*?]/, `argument must not look like shell: ${a}`);
      }
      assert.ok(!args.includes('sh') && !args.includes('bash') && !args.includes('-c'),
        `no shell may appear in the probe argv: ${args.join(' ')}`);
    }
  });

// ---------------------------------------------------------------- the boot-identity baseline
//
// A value the child reports about ITSELF is not evidence about its own fate. These prove the
// launch refuses every boot identity it cannot independently stand behind, and that ownership is
// still handled honestly when it does.

test('a WSL launch whose HELLO carries a MALFORMED boot id fails closed',
  { timeout: 30_000 }, async (t) => {
    void t;
    await assert.rejects(
      () => helperWith({ after: () => {} }, () => ({ ok: true, code: 0, stdout: Buffer.from(`${BOOT}\n`, 'latin1') }),
        { greet: { bootId: 'not-a-uuid' }, extra: 'setTimeout(() => {}, 10000);' }),
      (err) => /not a canonical/i.test(err.message) && /Refusing to start/.test(err.message),
      'a boot id that cannot be compared cannot support the pinned-boot claim',
    );
  });

test('a WSL launch whose HELLO declines to give a boot id fails closed',
  { timeout: 30_000 }, async (t) => {
    void t;
    await assert.rejects(
      () => helperWith({ after: () => {} }, () => ({ ok: true, code: 0, stdout: Buffer.from(`${BOOT}\n`, 'latin1') }),
        { greet: { bootId: '-' }, extra: 'setTimeout(() => {}, 10000);' }),
      (err) => /not a canonical/i.test(err.message),
      '"-" is an explicit "not available", which is not enough for the safety claim',
    );
  });

test('a WSL launch whose HELLO declines to name a distribution fails closed',
  { timeout: 30_000 }, async (t) => {
    void t;
    await assert.rejects(
      () => helperWith({ after: () => {} }, () => ({ ok: true, code: 0, stdout: Buffer.from(`${BOOT}\n`, 'latin1') }),
        { greet: { distro: '-' }, extra: 'setTimeout(() => {}, 10000);' }),
      (err) => /did not name a WSL distribution/.test(err.message),
      'without a pinned distribution, shutdown would assume the default never changes',
    );
  });

test('a WELL-FORMED but WRONG boot id fails closed, and does not become a clean-release claim',
  { timeout: 30_000 }, async (t) => {
    void t;
    // The parent looks for itself, in the distribution the child named, and sees a different VM.
    // Under the old code this same disagreement, discovered later, was read as "the VM restarted"
    // and AUTHORISED absence. It is now a refusal to start.
    let err = null;
    try {
      await helperWith({ after: () => {} },
        () => ({ ok: true, code: 0, stdout: Buffer.from(`${OTHER_BOOT}\n`, 'latin1') }),
        { greet: { bootId: BOOT }, extra: 'setTimeout(() => {}, 10000);' });
    } catch (e) { err = e; }
    assert.ok(err, 'a boot id the parent cannot corroborate must not start');
    assert.match(err.message, new RegExp(`reported boot id ${BOOT} but ${PINNED} reports ${OTHER_BOOT}`));
    assert.doesNotMatch(err.message, /released|absent/i, 'and it is a refusal, not a release');
    // OWNERSHIP SURVIVES, AND IS REPORTED HONESTLY. This runner answers every probe with the same
    // disagreeing boot id, so cleanup could not confirm the Linux process is gone either -- and
    // that is exactly what it says. The handle comes back on the error rather than being dropped,
    // which is what lets the pool keep owning it and retry.
    assert.ok(err.helper, 'the handle is handed to the caller');
    assert.equal(err.releaseConfirmed, false,
      'a cleanup that could not confirm absence must not claim release');
    assert.equal(err.helper.closed, false);
    assert.match(String(err.cleanupError?.message), /cannot inspect Linux pid/);
    await err.helper.forceClose('test cleanup').catch(() => {});
  });

test('an anchor probe that FAILS is not an anchor: the launch is refused, not assumed',
  { timeout: 30_000 }, async (t) => {
    void t;
    await assert.rejects(
      () => helperWith({ after: () => {} },
        () => ({ ok: false, code: null, stdout: Buffer.alloc(0), reason: 'probe timed out after 5000 ms' }),
        { extra: 'setTimeout(() => {}, 10000);', limits: { signalTimeoutMs: 300, probeTimeoutMs: 300 } }),
      (err) => /cannot anchor the WSL boot id/.test(err.message),
    );
  });

test('an INDEPENDENTLY CONFIRMED boot id starts, and is what lets a VM restart mean absence',
  { timeout: 30_000 }, async (t) => {
    const anchorCalls = [];
    const { helper } = await helperWith(t, (args) => {
      if (isAnchor(args)) {
        anchorCalls.push(args);
        return { ok: true, code: 0, stdout: Buffer.from(`${BOOT}\n`, 'latin1'), reason: null };
      }
      return { ok: true, code: 0, stdout: probeOutput(OTHER_BOOT, ['/anything', 'at-all']), reason: null };
    }, { extra: 'setTimeout(() => {}, 10000);' }).then((h) => ({ helper: h }));

    assert.equal(anchorCalls.length, 1, 'the parent corroborated the boot id exactly once, at launch');
    assert.deepEqual(anchorCalls[0].slice(0, 2), ['-d', PINNED],
      'in the PARENT-PINNED distribution, chosen before the child existed');
    assert.equal(helper.linuxBootId, BOOT);

    // Only now may a boot-id change mean the pid namespace is gone.
    const obs = await helper.observeLinuxProcess();
    assert.equal(obs.state, OBSERVATION.ABSENT);
    assert.match(obs.detail, /WSL VM restarted/);
  });

test('there is no way to reach an observation with an unanchored boot id', { timeout: 30_000 }, async (t) => {
  void t;
  // The observation code refuses to read a boot-id change as absence unless the launch value was
  // anchored. That guard is defence in depth: the ONLY way to obtain a WSL helper handle is
  // through a launch that already anchored, and every way of failing to anchor is a refusal.
  for (const [label, greet, anchor] of [
    ['malformed boot id', { bootId: 'zzzz' }, { ok: true, code: 0, stdout: Buffer.from(`${BOOT}\n`, 'latin1') }],
    ['absent boot id', { bootId: '-' }, { ok: true, code: 0, stdout: Buffer.from(`${BOOT}\n`, 'latin1') }],
    ['absent distro', { distro: '-' }, { ok: true, code: 0, stdout: Buffer.from(`${BOOT}\n`, 'latin1') }],
    ['unusable anchor', {}, { ok: true, code: 0, stdout: Buffer.from('not-a-boot-id\n', 'latin1') }],
    ['disagreeing anchor', {}, { ok: true, code: 0, stdout: Buffer.from(`${OTHER_BOOT}\n`, 'latin1') }],
  ]) {
    await assert.rejects(
      () => helperWith({ after: () => {} }, () => anchor,
        { greet, extra: 'setTimeout(() => {}, 10000);', limits: { signalTimeoutMs: 300, probeTimeoutMs: 300 } }),
      (err) => err instanceof Error && !/released/i.test(err.message),
      `${label} must refuse the launch outright`,
    );
  }
});

// ---------------------------------------------------------------- distribution authority
//
// THE DEFECT. The launch used default routing (`wsl.exe --exec ...`), the helper then supplied
// WSL_DISTRO_NAME in HELLO, and the parent redirected every later boot-id, /proc, existence and
// signal probe into whatever the CHILD had named. The process under examination chose the pid
// namespace its examiner looked in.
//
// That is not theoretical. On the development host, `Ubuntu` and `docker-desktop` report the SAME
// boot UUID and have DIFFERENT pid namespaces (pid:[4026532221] vs pid:[4026532244]): PID 2 exists
// in one and not the other, while `cat /proc/sys/kernel/random/boot_id` returns identical bytes in
// both. So a wrong child-reported name sails straight past the boot-id anchor and then finds no
// /proc entry for a perfectly live helper -- CONFIRMED_ABSENT, which is a false clean release.
//
// The values below are synthetic on purpose: this must keep failing correctly on a machine with
// different distributions installed, or none.

const OTHER_DISTRO = 'docker-desktop';

test('the launch itself names the parent-pinned distribution, before the child exists',
  { timeout: 30_000 }, async (t) => {
    const { helper } = await startObservation(t, (h) => ({
      ok: true, code: 0, stdout: probeOutput(BOOT, [HELPER_WSL_PATH, h.token]), reason: null,
    }), { limits: { signalTimeoutMs: 300, probeTimeoutMs: 300 } });

    assert.equal(helper.command.file, 'wsl.exe');
    assert.deepEqual(helper.command.args.slice(0, 3), ['-d', PINNED, '--exec'],
      'the exact launch argv begins -d <parent-pinned distro> --exec');
    assert.equal(helper.command.args.at(-1), helper.token, 'and ends with the per-launch token');
    assert.equal(helper.linuxDistro, PINNED, 'the distro the helper reports as ITS OWN is the pin');
  });

test('a HELLO naming a DIFFERENT distribution fails closed, even with identical boot ids',
  { timeout: 30_000 }, async (t) => {
    void t;
    // Same boot UUID in both -- exactly the real host condition -- so the boot-id anchor cannot
    // save us. Only refusing the mismatch can.
    let err = null;
    try {
      await helperWith({ after: () => {} },
        () => ({ ok: true, code: 0, stdout: Buffer.from(`${BOOT}\n`, 'latin1'), reason: null }),
        { greet: { distro: OTHER_DISTRO, bootId: BOOT }, extra: 'setTimeout(() => {}, 10000);',
          limits: { signalTimeoutMs: 300, probeTimeoutMs: 300 } });
    } catch (e) { err = e; }

    assert.ok(err, 'a child that claims a different distribution must not be accepted');
    assert.match(err.message, new RegExp(`reports distribution "${OTHER_DISTRO}"`));
    assert.match(err.message, new RegExp(`launched it in "${PINNED}"`));
    assert.match(err.message, /share a boot id and NOT share a pid namespace/,
      'the message must say why identical boot ids are not reassurance');
    // It is a REFUSAL TO START, not an absence verdict: nothing here claims the child is gone.
    // (The message names "confirmed absent" only to explain the hazard it is refusing to create.)
    assert.ok(err.helper, 'the handle comes back on the error rather than being dropped');
    assert.equal(err.helper.closed, false, 'no release is claimed for a child we just refused');
    assert.equal(err.helper.shutdownOutcome.gracefulProtocolShutdown, false);
    await err.helper.forceClose('test cleanup').catch(() => {});
  });

test('the helper-reported distribution never routes a probe', { timeout: 30_000 }, async (t) => {
  // The helper greets with the pinned name (anything else is refused above), and we prove every
  // single probe argv carries the PIN -- there is no code path left that consults HELLO's value.
  const seen = [];
  const { helper } = await startObservation(t, (h, args) => {
    seen.push(args);
    if (isExistence(args)) {
      return { ok: true, code: 2, stdout: existenceOutput({ control: true, target: false }), reason: null };
    }
    if (isKill(args)) return { ok: true, code: 0, stdout: Buffer.alloc(0), reason: null };
    return { ok: true, code: 1, stdout: Buffer.from(`${BOOT}\n`, 'latin1'), reason: null };
  });
  await helper.observeLinuxProcess();
  await helper.close('routing check').catch(() => {});
  assert.ok(seen.length >= 3, 'the anchor, the cmdline probe and the existence probe all ran');
  for (const args of seen) {
    assert.deepEqual(args.slice(0, 2), ['-d', PINNED],
      `every probe routes to the pin; saw ${args.join(' ')}`);
    assert.ok(!args.includes(OTHER_DISTRO), 'and no probe ever mentions a child-suggested name');
  }
});

// ---------------------------------------------------------------- the signal fence
//
// forceClose() observed PRESENT_MATCH, sent TERM, and then sent KILL when the NEXT state was
// PRESENT_MATCH *or* INSPECTION_FAILED -- and signalLinux() itself checked nothing. So a pid that
// had exited (and possibly been recycled by an unrelated process) could be killed on the strength
// of an observation that had already stopped working. The fence now lives inside signalLinux().

/** Record every kill argv the module attempts, and answer identity questions on cue. */
function fenceRunner({ identityAfterTerm }) {
  const signals = [];
  let termDelivered = false;
  const runner = (h, args) => {
    if (isKill(args)) {
      const sig = args[args.indexOf('kill') + 1];
      signals.push(sig);
      if (sig === '-TERM') termDelivered = true;
      return { ok: true, code: 0, stdout: Buffer.alloc(0), reason: null };
    }
    if (!termDelivered) {
      return { ok: true, code: 0, stdout: probeOutput(BOOT, [HELPER_WSL_PATH, h.token]), reason: null };
    }
    return identityAfterTerm(h, args);
  };
  return { runner, signals };
}

test('PRESENT_MATCH -> TERM -> INSPECTION_FAILED never sends KILL, and stays owned',
  { timeout: 30_000 }, async (t) => {
    const fence = fenceRunner({
      identityAfterTerm: () => ({ ok: false, code: null, stdout: Buffer.alloc(0), reason: 'probe timed out after 300 ms' }),
    });
    const { helper } = await startObservation(t, fence.runner,
      { limits: { signalTimeoutMs: 300, probeTimeoutMs: 300 } });

    await assert.rejects(() => helper.forceClose('identity lost after TERM'),
      (err) => /cannot confirm Linux pid/.test(err.message)
        && /Not escalating to KILL without a fresh identity/.test(err.message));

    // THE EXACT CALL LIST. An identity we can no longer establish is not a licence to kill: the
    // pid may have exited and been recycled by something that is not ours.
    assert.deepEqual(fence.signals, ['-TERM'], 'exactly one signal, and no KILL after UNKNOWN');
    assert.equal(helper.closed, false, 'the resource stays owned, unresolved, and retryable');
    assert.equal(helper.shutdownOutcome.physicalReleaseConfirmed, false);
  });

test('a FRESH PRESENT_MATCH immediately before KILL permits that one exact KILL',
  { timeout: 30_000 }, async (t) => {
    // The control for the test above: when identity IS still established after the TERM,
    // escalation proceeds -- once.
    let killed = false;
    const signals = [];
    let termDelivered = false;
    const { helper } = await startObservation(t, (h, args) => {
      if (isKill(args)) {
        const sig = args[args.indexOf('kill') + 1];
        signals.push(sig);
        if (sig === '-TERM') termDelivered = true;
        if (sig === '-KILL') killed = true;
        return { ok: true, code: 0, stdout: Buffer.alloc(0), reason: null };
      }
      if (isExistence(args)) {
        return killed
          ? { ok: true, code: 2, stdout: existenceOutput({ control: true, target: false }), reason: null }
          : { ok: true, code: 0, stdout: existenceOutput({ control: true, target: true }), reason: null };
      }
      if (killed) return { ok: true, code: 1, stdout: Buffer.from(`${BOOT}\n`, 'latin1'), reason: null };
      void termDelivered;
      return { ok: true, code: 0, stdout: probeOutput(BOOT, [HELPER_WSL_PATH, h.token]), reason: null };
    }, { limits: { signalTimeoutMs: 1200, probeTimeoutMs: 300 } });

    await helper.forceClose('still present after TERM');
    assert.deepEqual(signals, ['-TERM', '-KILL'], 'TERM, then exactly one KILL behind a fresh match');
    assert.equal(helper.closed, true, 'and absence was then positively established');
  });

test('PRESENT_MISMATCH is never signalled, in the exact call list', { timeout: 30_000 }, async (t) => {
  const signals = [];
  const { helper } = await startObservation(t, (h, args) => {
    if (isKill(args)) { signals.push(args[args.indexOf('kill') + 1]); return { ok: true, code: 0, stdout: Buffer.alloc(0) }; }
    return { ok: true, code: 0, stdout: probeOutput(BOOT, ['/usr/bin/someone-else', 'x']), reason: null };
  }, { limits: { signalTimeoutMs: 300, probeTimeoutMs: 300 } });

  await assert.rejects(() => helper.forceClose('someone else owns that pid'), /refusing to signal Linux pid/);
  assert.deepEqual(signals, [], 'a pid that is not ours receives NOTHING');
  assert.equal(helper.closed, false);
});

test('the fence is inside the signal path, so no caller can route around it',
  { timeout: 30_000 }, async (t) => {
    // Identity is UNKNOWN from the very first observation, so escalation never even reaches TERM.
    // The point is that the refusal comes from the signal helper itself, not from one call site.
    const signals = [];
    const { helper } = await startObservation(t, (h, args) => {
      if (isKill(args)) { signals.push(args[args.indexOf('kill') + 1]); return { ok: true, code: 0, stdout: Buffer.alloc(0) }; }
      return { ok: false, code: null, stdout: Buffer.alloc(0), reason: 'probe timed out after 300 ms' };
    }, { limits: { signalTimeoutMs: 300, probeTimeoutMs: 300 } });

    await assert.rejects(() => helper.forceClose('never established'), /cannot inspect Linux pid/);
    assert.deepEqual(signals, [], 'nothing was signalled on the strength of an inspection that failed');
    assert.equal(helper.closed, false);
  });
