import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  startNativeHelper, helperLaunchCommand, toWslPath,
  HelperFaultError, HelperMissingError, HELPER_PROTOCOL_VERSION,
  HELPER_DATASET_BYTES, HELPER_SCRATCH_BYTES, OBSERVATION,
  WslDistroError, WSL_DISTRO_RE, resolveDefaultWslDistro,
} from '../native_helper.mjs';
import { SYNTHETIC_CONTEXT } from '../identity.mjs';

let scratch;

before(() => { scratch = mkdtempSync(join(tmpdir(), 'meep-helper-')); });
// Windows keeps a brief handle on a script file after the process that was running it exits, so a
// removal issued the instant the last helper is reaped can lose the race and leave the directory
// behind. Await it, retry, and REPORT rather than swallow: a cleanup that silently half-worked is
// how a "no leftovers" claim becomes untrue.
after(async () => {
  if (!scratch) return;
  for (let attempt = 0; attempt < 10 && existsSync(scratch); attempt++) {
    try {
      rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  if (existsSync(scratch)) console.error(`# LEFTOVER TEMP DIRECTORY NOT REMOVED: ${scratch}`);
});

/** Poll for a condition inside a bound. Returns, or throws with a useful label. */
async function waitUntil(fn, label, timeoutMs = 8000) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    if (await fn()) return true;
    if (Date.now() > end) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

/** A fake helper written in Node, launched directly (no WSL), so the real client code runs. */
function fakeHelper(body) {
  const file = join(scratch, `fake-${Math.random().toString(36).slice(2)}.mjs`);
  writeFileSync(file, body, 'utf8');
  return file;
}

const HELLO_OK = `const token = process.argv[2];
process.stdout.write(\`HELLO ${HELPER_PROTOCOL_VERSION} \${process.pid} \${token} 2 60 - - fakesource\\n\`);
`;

/** Spawn a fake directly. Used by the startup-failure tests, which own their own cleanup. */
function fakeSpawn(file) {
  return (cmd) => spawn(process.execPath, [file, cmd.args.at(-1)], {
    stdio: ['pipe', 'pipe', 'pipe'], shell: false,
  });
}

/**
 * Start a fake helper OWNED BY THIS TEST. Registering cleanup on `t` (not on a file-level hook)
 * is deliberate: a failing assertion must still reap the child, or one leaked fake keeps the whole
 * test runner alive. That is exactly the ownership discipline these tests are about.
 */
async function startFake(t, file, opts = {}) {
  const { helper } = await startNativeHelper({
    helperPath: process.execPath,
    useWsl: false,
    spawnFn: fakeSpawn(file),
    ...opts,
  });
  t.after(async () => { try { await helper.forceClose('test cleanup'); } catch { /* already gone */ } });
  return helper;
}

// ---------------------------------------------------------------- launch shape

test('the launch command is argument-native, and names the PARENT-PINNED distribution', () => {
  const cmd = helperLaunchCommand({
    helperPath: 'C:\\repo\\meepow\\build\\native-helper\\meepow-v2-helper',
    token: 'abc123',
    useWsl: true,
    wslDistro: 'Ubuntu',
  });
  assert.equal(cmd.file, 'wsl.exe');
  // EXPLICIT `-d`. Default routing plus a child-reported distribution is circular: the process
  // under examination would be choosing the pid namespace its examiner looks in.
  assert.deepEqual(cmd.args,
    ['-d', 'Ubuntu', '--exec', '/mnt/c/repo/meepow/build/native-helper/meepow-v2-helper', 'abc123']);
  // Nothing is ever concatenated into one string that a shell could re-parse.
  for (const a of cmd.args) assert.doesNotMatch(a, /[;&|`$()<>]/, `argument must not look like shell: ${a}`);
  assert.equal(toWslPath('D:\\a b\\c'), '/mnt/d/a b/c', 'a spaced path stays one argument');

  // A distribution name is ONE bounded argv value, or the launch is refused outright.
  //
  // SPACES ARE REFUSED BEFORE THE SPAWN. The argv could carry "Ubuntu 22.04" perfectly well, but
  // the name has to survive a round trip the argv does not control: the helper echoes
  // $WSL_DISTRO_NAME in HELLO, whose grammar is space-separated with exact arity, and the C++
  // hello_field() turns any value containing a space into "-". Such a distribution would launch
  // and then fail corroboration every single time, so it is rejected up front with a reason
  // instead. This development helper supports space-free names only.
  for (const bad of [null, '', '  ', 'a;b', 'a|b', 'a`b', '$(x)', 'x'.repeat(65), '-leading-dash',
    'Ubuntu 22.04', 'has space']) {
    assert.throws(() => helperLaunchCommand({ helperPath: 'C:\\r\\h', token: 't', useWsl: true, wslDistro: bad }),
      (err) => err instanceof WslDistroError, `${JSON.stringify(bad)} must be refused`);
  }
  assert.ok(WSL_DISTRO_RE.test('Ubuntu-22.04'), 'ordinary names still work');
  assert.ok(WSL_DISTRO_RE.test('Ubuntu'), 'including the one this host uses');
  assert.ok(!WSL_DISTRO_RE.test('Ubuntu 22.04'), 'a spaced name could never corroborate through HELLO');
});

test('a spaced distribution name is refused BEFORE anything is spawned', { timeout: 30_000 }, async () => {
  let spawned = 0;
  await assert.rejects(
    () => startNativeHelper({
      helperPath: process.execPath,
      useWsl: true,
      wslDistro: 'Ubuntu 22.04',
      spawnFn: () => { spawned++; throw new Error('must not be reached'); },
    }),
    (err) => err instanceof WslDistroError && /not a usable argv value|space/i.test(err.message),
  );
  assert.equal(spawned, 0, 'a name that cannot corroborate must never launch a child');
});

test('the default distribution is discovered from machine-shaped values, and fails closed', async () => {
  // HKCU\...\Lxss: DefaultDistribution is a GUID, and that GUID's subkey carries
  // DistributionName. Registry values, not console prose -- `wsl --status` and the `wsl -l -v`
  // table have localized headers, and a parser for them would be a parser for English.
  const GUID = '{8790f505-1fbd-44d8-bde1-ac15c8b071da}';
  const ok = (args) => (args[3] === 'DefaultDistribution'
    ? { ok: true, stdout: `\n${args[1]}\n    DefaultDistribution    REG_SZ    ${GUID}\n\n`, reason: null }
    : { ok: true, stdout: `\n${args[1]}\n    DistributionName    REG_SZ    Ubuntu\n\n`, reason: null });
  assert.equal(await resolveDefaultWslDistro({ runReg: ok }), 'Ubuntu');

  // The argv is exactly what it should be: `reg query <key> /v <value>`, no shell.
  const seen = [];
  await resolveDefaultWslDistro({ runReg: (a) => { seen.push(a); return ok(a); } });
  assert.equal(seen.length, 2);
  for (const a of seen) {
    assert.equal(a[0], 'query');
    assert.equal(a[2], '/v');
    assert.doesNotMatch(a[1], /[;&|`$()<>]/);
  }

  for (const [label, runReg] of [
    ['the registry key cannot be read',
      () => ({ ok: false, stdout: '', reason: 'reg.exe exited 1' })],
    ['the default value is missing',
      (a) => (a[3] === 'DefaultDistribution' ? { ok: true, stdout: '\nkey\n\n', reason: null } : ok(a))],
    ['the default value is ambiguous (two matches)',
      (a) => (a[3] === 'DefaultDistribution'
        ? { ok: true, stdout: `\n    DefaultDistribution    REG_SZ    ${GUID}\n    DefaultDistribution    REG_SZ    ${GUID}\n`, reason: null }
        : ok(a))],
    ['the default value is not a GUID',
      (a) => (a[3] === 'DefaultDistribution'
        ? { ok: true, stdout: '\n    DefaultDistribution    REG_SZ    Ubuntu\n', reason: null } : ok(a))],
    // 36 hex-or-hyphen characters in braces is NOT a GUID. The old shape accepted misplaced and
    // repeated hyphens, so a value that is not a GUID at all could be pasted into the next key path.
    ['the default value has misplaced and doubled hyphens',
      (a) => (a[3] === 'DefaultDistribution'
        ? { ok: true, stdout: '\n    DefaultDistribution    REG_SZ    {8790f505-1fbd44d8--bde1-ac15c8b071da}\n', reason: null }
        : ok(a))],
    ['the default value is 36 hyphens in braces',
      (a) => (a[3] === 'DefaultDistribution'
        ? { ok: true, stdout: `\n    DefaultDistribution    REG_SZ    {${'-'.repeat(36)}}\n`, reason: null }
        : ok(a))],
    ['the name subkey cannot be read',
      (a) => (a[3] === 'DefaultDistribution' ? ok(a) : { ok: false, stdout: '', reason: 'reg.exe exited 1' })],
    ['the name is not a usable argv value',
      (a) => (a[3] === 'DefaultDistribution' ? ok(a)
        : { ok: true, stdout: '\n    DistributionName    REG_SZ    bad;name\n', reason: null })],
  ]) {
    await assert.rejects(() => resolveDefaultWslDistro({ runReg }),
      (err) => err instanceof WslDistroError, `${label} must fail closed, not guess`);
  }
});

test('a WSL launch with no pinnable distribution is refused before anything is spawned',
  { timeout: 30_000 }, async () => {
    let spawned = 0;
    await assert.rejects(
      () => startNativeHelper({
        helperPath: process.execPath,
        useWsl: true,
        spawnFn: () => { spawned++; throw new Error('must not be reached'); },
        resolveWslDistro: async () => { throw new WslDistroError('no default distribution'); },
      }),
      (err) => err instanceof WslDistroError,
    );
    assert.equal(spawned, 0, 'the pin is chosen BEFORE the child exists');
  });

test('a missing helper build fails closed with an actionable message', { timeout: 30_000 }, async () => {
  await assert.rejects(
    () => startNativeHelper({ helperPath: join(scratch, 'not-built'), useWsl: false }),
    (err) => err instanceof HelperMissingError && /npm run build:native-helper/.test(err.message)
      && /will not fall back to Wasm-only/.test(err.message),
  );
});

// ---------------------------------------------------------------- happy path

test('a well-behaved helper completes HELLO, INIT and HASH', { timeout: 30_000 }, async (t) => {
  const file = fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') process.stdout.write(\`RESULT \${t[1]} \${'a'.repeat(64)}\\n\`);
    else if (t[0] === 'QUIT') { process.stdout.write('BYE\\n'); process.exit(0); }
  }
});
`);
  const helper = await startFake(t, file);
  assert.ok(helper.linuxPid > 0);
  assert.equal(helper.healthy, true);
  const ready = await helper.init(SYNTHETIC_CONTEXT);
  assert.equal(ready.datasetBytes, 33_554_432);
  assert.equal(ready.scratchBytes, 8_388_608);
  assert.equal(await helper.hash(7), 'a'.repeat(64));
  assert.equal(helper.counters.shareHashes, 1);
  assert.equal(await helper.hash(8, { selfTest: true }), 'a'.repeat(64));
  assert.equal(helper.counters.selfTestHashes, 1, 'self-test and share hashes are counted apart');
  await helper.close();
  assert.equal(helper.closed, true);
});

// ---------------------------------------------------------------- strict failures

const FAILURES = [
  ['a malformed hash', `RESULT \${t[1]} nothex\\n`],
  ['an uppercase hash', `RESULT \${t[1]} \${'A'.repeat(64)}\\n`],
  ['a short hash', `RESULT \${t[1]} \${'a'.repeat(63)}\\n`],
  ['a wrong request id', `RESULT 99999 \${'a'.repeat(64)}\\n`],
  ['an unknown message', `WAT \${t[1]}\\n`],
  ['wrong arity', `RESULT \${t[1]}\\n`],
];

for (const [label, reply] of FAILURES) {
  test(`${label} is a fatal verifier fault`, { timeout: 30_000 }, async (t) => {
    const file = fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') process.stdout.write(\`${reply}\`);
  }
});
`);
    const helper = await startFake(t, file);
    await helper.init(SYNTHETIC_CONTEXT);
    await assert.rejects(() => helper.hash(1), HelperFaultError, label);
    assert.equal(helper.healthy, false, 'the helper is latched unhealthy');
    await assert.rejects(() => helper.hash(2), HelperFaultError, 'and never answers again');
    await helper.forceClose();
    assert.equal(helper.closed, true, 'and leaves no process');
  });
}

test('a correct reply followed by a duplicate in the same chunk is never delivered',
  { timeout: 30_000 }, async (t) => {
    // THE ACCEPTANCE BARRIER. The helper answers correctly and then immediately violates the
    // protocol, both inside one write. The old client resolved the caller's promise on the first
    // line and only then noticed the duplicate -- so a share was accepted by a helper that was, in
    // the same breath, proving it could not be trusted. Nothing parsed out of a chunk may be
    // delivered until the whole chunk is known to be well-formed.
    const file = fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') {
      process.stdout.write(\`RESULT \${t[1]} \${'a'.repeat(64)}\\n\` + \`RESULT \${t[1]} \${'b'.repeat(64)}\\n\`);
    }
  }
});
`);
    const helper = await startFake(t, file);
    await helper.init(SYNTHETIC_CONTEXT);

    await assert.rejects(
      () => helper.hash(1),
      (err) => err instanceof HelperFaultError && !err.cancelled
        && /unknown\/duplicate request id/.test(err.message),
      'the otherwise-correct first reply must NOT be handed back',
    );
    assert.equal(helper.healthy, false, 'and the helper is latched, not merely noted');
    await helper.forceClose();
  });

test('a fault reaches the owner immediately, with nothing awaiting a hash',
  { timeout: 30_000 }, async (t) => {
    // The idle case. A helper that dies (or misbehaves) while nobody is mid-request used to be
    // noticed only when the NEXT hash happened to reject -- so a live miner kept hashing for a
    // pool that could no longer verify anything.
    const faults = [];
    const file = fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') {
      process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
      // Nothing is outstanding after this. Exit anyway.
      setTimeout(() => process.exit(9), 120);
    }
  }
});
`);
    const helper = await startFake(t, file, { onFault: (err) => faults.push(err) });
    await helper.init(SYNTHETIC_CONTEXT);
    assert.equal(faults.length, 0, 'nothing has gone wrong yet');

    await waitUntil(() => faults.length > 0, 'the idle exit to be reported');
    assert.equal(faults.length, 1, 'reported exactly once');
    assert.equal(faults[0].cancelled, false, 'and reported as a FAULT, not a cancellation');
    assert.match(faults[0].message, /exited unexpectedly/);
    assert.equal(helper.healthy, false);
  });

test('an unsolicited BYE while idle is fatal', { timeout: 30_000 }, async (t) => {
  const faults = [];
  const file = fakeHelper(`${HELLO_OK}
setTimeout(() => process.stdout.write('BYE\\n'), 100);
setTimeout(() => {}, 5000);
`);
  const helper = await startFake(t, file, { onFault: (err) => faults.push(err) });
  await waitUntil(() => faults.length > 0, 'the unsolicited BYE to be reported');
  assert.match(faults[0].message, /unsolicited BYE/);
  assert.equal(helper.healthy, false);
});


test('an unsolicited line with no request outstanding is fatal', { timeout: 30_000 }, async (t) => {
  const file = fakeHelper(`${HELLO_OK}
setTimeout(() => process.stdout.write(\`RESULT 1 \${'a'.repeat(64)}\\n\`), 60);
process.stdin.resume();
`);
  const helper = await startFake(t, file);
  await new Promise((r) => setTimeout(r, 400));
  assert.equal(helper.healthy, false);
  assert.match(helper.fault.message, /unknown\/duplicate request id/);
  await helper.forceClose();
});

test('an oversized line is refused rather than buffered', { timeout: 30_000 }, async (t) => {
  const file = fakeHelper(`${HELLO_OK}
setTimeout(() => process.stdout.write('RESULT 1 ' + 'a'.repeat(20000) + '\\n'), 60);
process.stdin.resume();
`);
  const helper = await startFake(t, file);
  await new Promise((r) => setTimeout(r, 500));
  assert.equal(helper.healthy, false);
  assert.match(helper.fault.message, /oversized line/);
  await helper.forceClose();
});

test('a stderr flood is bounded and does not become the fault message', { timeout: 30_000 }, async (t) => {
  const file = fakeHelper(`${HELLO_OK}
process.stderr.write('x'.repeat(2_000_000));
setTimeout(() => process.exit(7), 120);
`);
  const helper = await startFake(t, file);
  await new Promise((r) => setTimeout(r, 700));
  assert.equal(helper.healthy, false, 'the unexpected exit is a fault');
  assert.ok(helper.stderrTail.length <= 1024, `stderr tail must be bounded, got ${helper.stderrTail.length}`);
  assert.ok(String(helper.fault.message).length < 500, 'the fault message stays bounded');
  await helper.forceClose();
});

test('a startup that never says HELLO times out and leaves no process', { timeout: 30_000 }, async () => {
  const file = fakeHelper(`process.stdin.resume(); setInterval(() => {}, 1000);`);
  await assert.rejects(
    () => startNativeHelper({
      helperPath: process.execPath,
      useWsl: false,
      limits: { startupTimeoutMs: 400 },
      spawnFn: fakeSpawn(file),
    }),
    (err) => err instanceof HelperFaultError && /startup timed out/.test(err.message),
  );
});

test('a HELLO that does not echo the token is refused', { timeout: 30_000 }, async () => {
  const file = fakeHelper(`process.stdout.write('HELLO ${HELPER_PROTOCOL_VERSION} ' + process.pid + ' wrongtoken 2 60 - - fakesource\\n');
process.stdin.resume();`);
  await assert.rejects(
    () => startNativeHelper({
      helperPath: process.execPath, useWsl: false, limits: { startupTimeoutMs: 1500 },
      spawnFn: fakeSpawn(file),
    }),
    /did not echo the startup token/,
  );
});

test('a wrong protocol or algorithm version is refused', { timeout: 40_000 }, async () => {
  for (const [label, hello] of [
    ['protocol', `HELLO 99 ' + process.pid + ' ' + process.argv[2] + ' 2 60 - - fakesource`],
    ['algo', `HELLO ${HELPER_PROTOCOL_VERSION} ' + process.pid + ' ' + process.argv[2] + ' 3 60 - - fakesource`],
    ['paramset', `HELLO ${HELPER_PROTOCOL_VERSION} ' + process.pid + ' ' + process.argv[2] + ' 2 61 - - fakesource`],
  ]) {
    const file = fakeHelper(`process.stdout.write('${hello}\\n'); process.stdin.resume();`);
    await assert.rejects(
      () => startNativeHelper({
        helperPath: process.execPath, useWsl: false, limits: { startupTimeoutMs: 1500 },
        spawnFn: fakeSpawn(file),
      }),
      /not supported|is wrong/,
      label,
    );
  }
});

test('a request timeout is fatal and settles the promise', { timeout: 30_000 }, async (t) => {
  const file = fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    // HASH is deliberately never answered.
  }
});
`);
  const helper = await startFake(t, file, { limits: { requestTimeoutMs: 400 } });
  await helper.init(SYNTHETIC_CONTEXT);
  await assert.rejects(() => helper.hash(1), /timed out/);
  assert.equal(helper.healthy, false);
  await helper.forceClose();
});

test('an early exit rejects everything outstanding', { timeout: 30_000 }, async (t) => {
  const file = fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  if (buf.includes('HASH')) process.exit(9);
  const i = buf.indexOf('\\n');
  if (i >= 0 && buf.startsWith('INIT')) {
    const t = buf.slice(0, i).split(' '); buf = buf.slice(i + 1);
    process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
  }
});
`);
  const helper = await startFake(t, file);
  await helper.init(SYNTHETIC_CONTEXT);
  await assert.rejects(() => helper.hash(1), HelperFaultError);
  assert.equal(helper.healthy, false);
  assert.equal(helper.pendingCount, 0, 'no promise is left dangling');
  await helper.forceClose();
});

test('beginClose settles outstanding requests so a caller can drain', { timeout: 30_000 }, async (t) => {
  const file = fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    // HASH never answered: only beginClose can settle it.
  }
});
`);
  const helper = await startFake(t, file, { limits: { requestTimeoutMs: 30_000 } });
  await helper.init(SYNTHETIC_CONTEXT);
  const inflight = helper.hash(1);
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(helper.pendingCount, 1);
  helper.beginClose('test cancellation');
  await assert.rejects(() => inflight, /test cancellation|cancelled|shutting down/);
  assert.equal(helper.pendingCount, 0);
  await helper.forceClose();
});

test('a helper that ignores QUIT is escalated, reaped, AND reported', { timeout: 30_000 }, async (t) => {
  const file = fakeHelper(`${HELLO_OK}
process.stdin.resume();
setInterval(() => {}, 1000);   // never exits on its own
`);
  const helper = await startFake(t, file, { limits: { quitTimeoutMs: 300, signalTimeoutMs: 2000 } });
  // Escalation releases the resource, and the close still SAYS the graceful exchange failed. A
  // silent resolve here is what let "the helper never said goodbye" read as a clean shutdown.
  await assert.rejects(() => helper.close(),
    (err) => /never sent BYE/.test(err.message) && /escalated to termination/.test(err.message));
  assert.equal(helper.closed, true, 'escalation completed: physical release is still recorded');
  assert.equal(helper.exited, true, 'the exact launcher child exited');
});

// ---------------------------------------------------------------- canonical grammar

// Regression testing accepted every one of the first three of these. `Number()` is a permissive parser: it
// happily reads "1e0" as 1, "01" as 1, "NaN" as NaN and "-1" as -1, so a helper could greet with a
// version it does not have and report a NaN dataset size while looking perfectly healthy.
for (const [label, hello] of [
  ['exponent notation in the protocol version', "HELLO 1e0 ' + process.pid + ' ' + process.argv[2] + ' 2 60 - - fakesource"],
  ['leading zeros in the algo version', "HELLO 2 ' + process.pid + ' ' + process.argv[2] + ' 02 60 - - fakesource"],
  ['leading zeros in the param set', "HELLO 2 ' + process.pid + ' ' + process.argv[2] + ' 2 060 - - fakesource"],
  ['a negative pid', "HELLO 2 -1 ' + process.argv[2] + ' 2 60 - - fakesource"],
  ['a hexadecimal pid', "HELLO 2 0x10 ' + process.argv[2] + ' 2 60 - - fakesource"],
  ['double spaces between fields', "HELLO 2  ' + process.pid + ' ' + process.argv[2] + ' 2 60 - - fakesource"],
  ['an empty identity field', "HELLO 2 ' + process.pid + ' ' + process.argv[2] + ' 2 60 - -  "],
  ['too few fields (the v1 greeting)', "HELLO 2 ' + process.pid + ' ' + process.argv[2] + ' 2 60"],
]) {
  test(`HELLO with ${label} is refused`, { timeout: 30_000 }, async () => {
    const file = fakeHelper(`process.stdout.write('${hello}\\n');
setTimeout(() => {}, 5000);
`);
    await assert.rejects(
      () => startNativeHelper({
        helperPath: process.execPath, useWsl: false, spawnFn: fakeSpawn(file),
        limits: { startupTimeoutMs: 2000 },
      }),
      (err) => err instanceof HelperFaultError && !err.cancelled,
      `a helper greeting with ${label} must not be accepted`,
    );
  });
}

// READY is the helper telling us how much memory the algorithm allocated. It is checked against
// the frozen-v2 values, not merely parsed: a helper reporting a different dataset or scratchpad is
// not running the algorithm we cross-check against, whatever version it claims.
for (const [label, ready] of [
  ['NaN and a negative size', "READY ' + t[1] + ' NaN -1"],
  ['a leading-zero id', "READY 0' + t[1] + ' 33554432 8388608"],
  ['a plausible but wrong dataset size', "READY ' + t[1] + ' 33554431 8388608"],
  ['a plausible but wrong scratchpad size', "READY ' + t[1] + ' 33554432 8388609"],
  ['a zero dataset', "READY ' + t[1] + ' 0 8388608"],
]) {
  test(`READY with ${label} is refused`, { timeout: 30_000 }, async (t) => {
    const file = fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write('${ready}\\n');
  }
});
`);
    const helper = await startFake(t, file);
    await assert.rejects(() => helper.init(SYNTHETIC_CONTEXT),
      (err) => err instanceof HelperFaultError && !err.cancelled);
    assert.equal(helper.healthy, false);
    assert.equal(helper.datasetBytes, undefined, 'no allocation figure is adopted from a bad READY');
  });
}

test('READY reporting the exact frozen-v2 allocation is accepted', { timeout: 30_000 }, async (t) => {
  const helper = await startFake(t, fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
  }
});
`));
  const ready = await helper.init(SYNTHETIC_CONTEXT);
  assert.deepEqual(ready, { datasetBytes: HELPER_DATASET_BYTES, scratchBytes: HELPER_SCRATCH_BYTES });
});

// ---------------------------------------------------------------- QUIT / BYE

test('the QUIT/BYE exchange is actually validated, and a decorated BYE is fatal',
  { timeout: 30_000 }, async (t) => {
    // Previously close() latched a fault BEFORE registering the BYE waiter, so the waiter rejected
    // instantly and the real BYE was ignored. The exchange was never checked at all.
    const faults = [];
    const helper = await startFake(t, fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (line === 'QUIT') { process.stdout.write('BYE unexpected-extra\\n'); }
  }
});
setTimeout(() => {}, 5000);
`), { onFault: (err) => faults.push(err), limits: { quitTimeoutMs: 800, signalTimeoutMs: 800 } });

    await helper.close('validated exchange').catch(() => {});
    assert.ok(faults.some((f) => /BYE takes no arguments/.test(f.message)),
      `a BYE with arguments must be fatal; saw ${JSON.stringify(faults.map((f) => f.message))}`);
  });

test('a well-formed BYE completes a normal close without ever latching a fault',
  { timeout: 30_000 }, async (t) => {
    const faults = [];
    const helper = await startFake(t, fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (line === 'QUIT') { process.stdout.write('BYE\\n'); process.exit(0); }
  }
});
`), { onFault: (err) => faults.push(err) });

    await helper.close('normal');
    assert.equal(helper.closed, true, 'released');
    assert.equal(helper.healthy, true, 'a normal close is NOT a fault');
    assert.deepEqual(faults, [], 'and nobody was told the verifier failed');
  });

test('the line bound is enforced in BYTES, not UTF-16 units', { timeout: 30_000 }, async (t) => {
  // 3000 three-byte characters is 9000 bytes but only 3000 JavaScript string units. Counting
  // string length would let a helper exceed the advertised memory bound by a factor of three.
  const helper = await startFake(t, fakeHelper(`${HELLO_OK}
setTimeout(() => process.stdout.write('RESULT 1 ' + '\\u4e2d'.repeat(3000) + '\\n'), 60);
setTimeout(() => {}, 5000);
`), { limits: { maxLineBytes: 8192 } });
  await waitUntil(() => helper.healthy === false, 'the oversized line to be refused');
  assert.match(helper.fault.message, /oversized line|non-ASCII/);
});

// ---------------------------------------------------------------- QUIT / BYE / exit, strictly
//
// Regression testing ran fake helpers that exited immediately on QUIT without ever sending BYE. Exit code 0 and
// exit code 7 BOTH produced `close() resolved, closed=true, healthy=true, no fault reported`,
// because close() raced the BYE waiter against process exit and only checked the exit status when
// a BYE had already arrived. A graceful close is QUIT -> exactly one canonical BYE -> exit 0, with
// no signal; every other outcome is named.

/** A fake that answers QUIT the way `answer` says, so one table drives every shutdown outcome. */
function quitFake(answer) {
  return fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (line === 'QUIT') { ${answer} }
  }
});
setTimeout(() => {}, 10000);
`);
}

for (const [label, answer, expected] of [
  [
    'exits 0 without ever sending BYE',
    'process.exit(0);',
    [/exited without sending BYE/],
  ],
  [
    'exits nonzero without ever sending BYE',
    'process.exit(7);',
    [/exited without sending BYE/, /exited 7 without acknowledging QUIT/],
  ],
  [
    'sends BYE and then exits nonzero',
    "process.stdout.write('BYE\\n'); setTimeout(() => process.exit(7), 30);",
    [/exited 7 after acknowledging QUIT/],
  ],
  [
    'sends a second, duplicate BYE',
    "process.stdout.write('BYE\\nBYE\\n'); setTimeout(() => process.exit(0), 40);",
    [/protocol fault during shutdown/, /unsolicited BYE/],
  ],
  [
    'sends a decorated BYE',
    "process.stdout.write('BYE now\\n'); setTimeout(() => process.exit(0), 40);",
    [/protocol fault during shutdown/, /BYE takes no arguments/],
  ],
]) {
  test(`a helper that ${label} does not get a clean graceful close`, { timeout: 30_000 }, async (t) => {
    const faults = [];
    const helper = await startFake(t, quitFake(answer), {
      onFault: (err) => faults.push(err),
      limits: { quitTimeoutMs: 1500, signalTimeoutMs: 1500 },
    });
    let closeErr = null;
    try { await helper.close('strict exchange'); } catch (err) { closeErr = err; }
    assert.ok(closeErr, `close() must not resolve cleanly when the helper ${label}`);
    for (const re of expected) {
      assert.match(closeErr.message, re,
        `the anomaly must be named; saw ${JSON.stringify(closeErr.message)}`);
    }
    // PHYSICAL RELEASE IS A SEPARATE FACT. The process is positively gone, so the handle is
    // released -- there is nothing left to own -- but nobody may read that as a healthy goodbye.
    assert.equal(helper.closed, true, 'a process that is positively gone is released');
    assert.equal(helper.exited, true);
  });
}

test('the canonical exchange -- one BYE, exit 0 -- is the ONLY clean graceful close',
  { timeout: 30_000 }, async (t) => {
    const faults = [];
    const helper = await startFake(t, quitFake("process.stdout.write('BYE\\n'); process.exit(0);"),
      { onFault: (err) => faults.push(err) });
    await helper.close('canonical');   // must not throw
    assert.equal(helper.closed, true, 'released');
    assert.equal(helper.healthy, true, 'a normal close is NOT a fault');
    assert.deepEqual(helper.exitInfo, { code: 0, signal: null });
    assert.deepEqual(faults, [], 'and nobody was told the verifier failed');
  });

test('a helper terminated by a signal during shutdown is reported as a signal, not a clean exit',
  { timeout: 30_000 }, async (t) => {
    // The fake acknowledges the QUIT on stderr and then stalls. Something OUTSIDE this module then
    // terminates it -- the case an OOM kill or an operator kill produces. The module did not cause
    // the signal, so it must not describe the result as a graceful goodbye.
    let child = null;
    const file = fakeHelper(`${HELLO_OK}
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (line === 'QUIT') process.stderr.write('GOT-QUIT\\n');
  }
});
setTimeout(() => {}, 10000);
`);
    const { helper } = await startNativeHelper({
      helperPath: process.execPath,
      useWsl: false,
      limits: { quitTimeoutMs: 5000, signalTimeoutMs: 1500 },
      spawnFn: (cmd) => {
        child = spawn(process.execPath, [file, cmd.args.at(-1)], {
          stdio: ['pipe', 'pipe', 'pipe'], shell: false,
        });
        return child;
      },
    });
    t.after(async () => { try { await helper.forceClose('test cleanup'); } catch { /* fine */ } });

    const closing = helper.close('signalled shutdown').then(() => null, (err) => err);
    await waitUntil(() => helper.stderrTail.includes('GOT-QUIT'), 'the QUIT to reach the fake');
    child.kill('SIGTERM');

    const closeErr = await closing;
    assert.ok(closeErr, 'a signalled shutdown is not a clean close');
    assert.match(closeErr.message, /terminated by signal SIGTERM/,
      `the signal must be named; saw ${JSON.stringify(closeErr?.message)}`);
    assert.match(closeErr.message, /exited without sending BYE/, 'and the missing goodbye too');
    assert.equal(helper.closed, true, 'the process is positively gone, so it is released');
  });

// ---------------------------------------------------------------- probe ownership and reaping
//
// runWsl() used to call probe.kill() on timeout and IMMEDIATELY delete the probe from the owned
// set, so a timed-out or uncooperative wsl.exe could outlive the operation after its only tracked
// handle had been discarded. The existing WSL tests inject `wslRunner`, which replaces the whole
// probe channel and therefore cannot exercise ownership at all. These use a CHILD-SHAPED handle
// through the real runWsl body.

const PROBE_BOOT = '1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9';
const PINNED_DISTRO = 'Ubuntu';

/**
 * A ChildProcess-shaped fake. `onKill` decides what happens when the module asks it to stop --
 * including "nothing", which is the case that must never be read as a reaping.
 */
function fakeProbe({ stdout = '', onKill = () => {} } = {}) {
  const p = new EventEmitter();
  p.stdout = new EventEmitter();
  p.stderr = new EventEmitter();
  p.pid = 90000 + Math.floor(Math.random() * 1000);
  p.killCalls = [];
  p.kill = (sig = 'SIGTERM') => { p.killCalls.push(sig); onKill(p, sig); return true; };
  p.finish = (code = 0) => p.emit('close', code);
  if (stdout) setImmediate(() => p.stdout.emit('data', Buffer.from(stdout, 'latin1')));
  return p;
}

/**
 * Start a WSL-shaped helper whose PROBES are fakes. The boot-identity anchor runs for real through
 * the same seam, so `answerAnchor` must satisfy it before any observation is possible.
 */
async function startWithFakeProbes(t, probeFor, opts = {}) {
  const file = fakeHelper(
    `process.stdout.write('HELLO ${HELPER_PROTOCOL_VERSION} 4242 ' + process.argv[2]`
    + ` + ' 2 60 ${PINNED_DISTRO} ${PROBE_BOOT} fakesource\\n');\nsetTimeout(() => {}, 20000);\n`,
  );
  const { helper } = await startNativeHelper({
    helperPath: 'C:/repo/meepow/build/native-helper/meepow-v2-helper',
    useWsl: true,
    wslDistro: PINNED_DISTRO,
    probeSpawnFn: probeFor,
    spawnFn: (cmd) => spawn(process.execPath, [file, cmd.args.at(-1)], {
      stdio: ['pipe', 'pipe', 'pipe'], shell: false,
    }),
    limits: { probeTimeoutMs: 200, probeReapMs: 200, signalTimeoutMs: 300, quitTimeoutMs: 300 },
    ...opts,
  });
  t.after(async () => { try { await helper.forceClose('test cleanup'); } catch { /* fine */ } });
  return helper;
}

/** The anchor probe: `cat /proc/sys/kernel/random/boot_id`, and nothing else. */
const isAnchor = (args) => args.includes('cat') && !args.some((a) => a.includes('/cmdline'));

test('a probe whose kill() is acknowledged but which never exits is NOT released',
  { timeout: 30_000 }, async (t) => {
    const stubborn = [];
    let obstructed = true;
    const helper = await startWithFakeProbes(t, (args) => {
      if (isAnchor(args)) {
        const p = fakeProbe({ stdout: `${PROBE_BOOT}\n` });
        setImmediate(() => p.finish(0));
        return p;
      }
      if (!obstructed) {
        // The obstruction lifted: the cmdline read comes back empty and the separate existence
        // probe positively reports the entry gone, so escalation can finally confirm release.
        const body = args.includes('ls') ? '/proc/self\n' : `${PROBE_BOOT}\n`;
        const ok = fakeProbe({ stdout: body });
        setImmediate(() => ok.finish(0));
        return ok;
      }
      // Acknowledges every signal and exits for none of them: the exact shape whose only tracked
      // handle used to be thrown away the instant kill() returned true.
      const p = fakeProbe();
      stubborn.push(p);
      return p;
    });

    const obs = await helper.observeLinuxProcess();
    assert.equal(obs.state, OBSERVATION.UNKNOWN, 'a timed-out probe establishes nothing');
    assert.match(obs.detail, /could not be confirmed reaped/,
      `the reaping failure must be distinguished from the deadline; saw ${obs.detail}`);

    assert.equal(stubborn.length, 1);
    assert.deepEqual(stubborn[0].killCalls, ['SIGTERM', 'SIGKILL'],
      'termination was requested of THAT EXACT child, and escalated once');
    assert.equal(helper.probeCount, 1,
      'kill() returning true is not evidence of death: the handle stays owned');

    // Shutdown must fail rather than claim a clean release over a process still represented here.
    // (Escalation re-observes before signalling, so it makes a probe of its own -- which is also
    // stubborn, is also owned, and must also be reported.)
    await assert.rejects(() => helper.forceClose('unreaped probe'),
      (err) => /probe not confirmed reaped/.test(err.message));
    assert.equal(helper.closed, false, 'not released while a probe is unaccounted for');
    assert.equal(helper.probeCount, stubborn.length,
      'every stubborn probe is still reachable by a later retry, and none was silently dropped');
    assert.ok(helper.probeCount >= 1);

    // Once they can be reached, a retry releases them -- each exactly once.
    obstructed = false;
    for (const p of stubborn) p.finish(0);
    await helper.forceClose('retry after the probes exit');
    assert.equal(helper.probeCount, 0, 'released');
    assert.equal(helper.closed, true);
  });

test('a probe that exits only AFTER the kill is released exactly once, and not before',
  { timeout: 30_000 }, async (t) => {
    // The delayed-close case: kill() is honoured, but 'close' arrives later. The module must join
    // the exit rather than assume it, and must not double-release when both events fire.
    let releases = 0;
    const helper = await startWithFakeProbes(t, (args) => {
      if (isAnchor(args)) {
        const p = fakeProbe({ stdout: `${PROBE_BOOT}\n` });
        setImmediate(() => p.finish(0));
        return p;
      }
      const p = fakeProbe({
        onKill: (self, sig) => {
          if (sig !== 'SIGTERM') return;
          setTimeout(() => { releases++; self.emit('exit', null, 'SIGTERM'); self.emit('close', null); }, 60);
        },
      });
      return p;
    }, { limits: { probeTimeoutMs: 120, probeReapMs: 1500, signalTimeoutMs: 400, quitTimeoutMs: 300 } });

    const obs = await helper.observeLinuxProcess();
    assert.equal(obs.state, OBSERVATION.UNKNOWN);
    assert.doesNotMatch(obs.detail, /could not be confirmed reaped/,
      'this probe WAS confirmed reaped, so only the deadline is reported');
    assert.equal(helper.probeCount, 0, 'joined and released');
    assert.equal(releases, 1, 'exit and close together release it exactly once');
  });

// ---------------------------------------------------------------- the stdio drain barrier
//
// Node's ChildProcess emits 'exit' when the process is gone and 'close' when its stdio has ended,
// and bytes the child already wrote can still be delivered in between. Judging the transcript at
// 'exit' therefore did BOTH kinds of damage: a real, canonical BYE still in flight was recorded as
// "exited without sending BYE" (a well-behaved helper slandered), and a DECORATED BYE arriving in
// the same window was never parsed at all (a real protocol violation hidden behind the generic
// message). And a child whose stdio never closed was declared CLEAN.
//
// `stdioClosed` below is the ChildProcess 'close' EVENT. It is not this module's close() METHOD.

/**
 * A ChildProcess-shaped fake whose exit / stdout / stdio-close ordering the test drives exactly.
 *
 * Its three pipes report `destroyed` honestly, because "the process exited" and "the parent let go
 * of its pipes" are different facts and the shutdown code is required to establish both. A fake
 * whose streams cannot be witnessed is correctly refused release -- which is why they are modelled
 * here rather than left as bare EventEmitters.
 */
function pipeStub() {
  const s = new EventEmitter();
  s.destroyed = false;
  s.destroy = () => { s.destroyed = true; };
  return s;
}

function scriptedChild() {
  const c = new EventEmitter();
  c.pid = 4321;
  c.stdout = pipeStub();
  c.stderr = pipeStub();
  c.killCalls = [];
  c.stdin = {
    writable: true,
    destroyed: false,
    written: [],
    write(text) { c.stdin.written.push(text); return true; },
    end() { c.stdin.writable = false; },
    destroy() { c.stdin.destroyed = true; c.stdin.writable = false; },
  };
  c.kill = (sig = 'SIGTERM') => { c.killCalls.push(sig); return true; };
  c.say = (line) => c.stdout.emit('data', Buffer.from(`${line}\n`, 'latin1'));
  c.exitNow = (code = 0, signal = null) => c.emit('exit', code, signal);
  /** The ChildProcess 'close' EVENT -- the stdio drain witness. Not helper.close(). */
  c.stdioCloseNow = (code = 0) => c.emit('close', code);
  return c;
}

async function startScripted(t, opts = {}) {
  let child;
  const { helper } = await startNativeHelper({
    helperPath: process.execPath,
    useWsl: false,
    limits: { quitTimeoutMs: 400, stdioDrainMs: 400, signalTimeoutMs: 400, startupTimeoutMs: 3000, ...opts },
    spawnFn: (cmd) => {
      child = scriptedChild();
      setImmediate(() => child.say(`HELLO 2 4321 ${cmd.args.at(-1)} 2 60 - - fakesource`));
      return child;
    },
  });
  t.after(async () => { try { await helper.forceClose('test cleanup'); } catch { /* fine */ } });
  return { helper, child };
}

test('a BYE that arrives before stdio close but AFTER process exit is not missed',
  { timeout: 30_000 }, async (t) => {
    const { helper, child } = await startScripted(t);
    const closing = helper.close('drain').then(() => null, (e) => e.message);
    await waitUntil(() => child.stdin.written.includes('QUIT\n'), 'the QUIT');
    child.exitNow(0, null);                 // the process is gone...
    await new Promise((r) => setTimeout(r, 20));
    child.say('BYE');                       // ...but its final protocol byte was still in flight
    child.stdioCloseNow(0);                 // and the transcript really ends HERE
    assert.equal(await closing, null,
      'a canonical goodbye still in flight at exit must not be reported as no goodbye at all');
    assert.equal(helper.closed, true);
    assert.equal(helper.healthy, true);
    assert.deepEqual(helper.shutdownOutcome,
      { physicalReleaseConfirmed: true, gracefulProtocolShutdown: true, reason: null });
  });

test('a DECORATED BYE in that same window is parsed and surfaced, not swallowed',
  { timeout: 30_000 }, async (t) => {
    const { helper, child } = await startScripted(t);
    const closing = helper.close('drain').then(() => null, (e) => e.message);
    await waitUntil(() => child.stdin.written.includes('QUIT\n'), 'the QUIT');
    child.exitNow(0, null);
    await new Promise((r) => setTimeout(r, 20));
    child.say('BYE surprise');
    child.stdioCloseNow(0);
    const verdict = await closing;
    assert.ok(verdict, 'a protocol violation after exit is still a protocol violation');
    assert.match(verdict, /BYE takes no arguments/, `the violation must be named; saw ${verdict}`);
    assert.equal(helper.closed, true, 'the process is gone, so it is released');
    assert.equal(helper.shutdownOutcome.physicalReleaseConfirmed, true);
    assert.equal(helper.shutdownOutcome.gracefulProtocolShutdown, false);
  });

test('a DUPLICATE BYE in that same window is parsed and surfaced', { timeout: 30_000 }, async (t) => {
  const { helper, child } = await startScripted(t);
  const closing = helper.close('drain').then(() => null, (e) => e.message);
  await waitUntil(() => child.stdin.written.includes('QUIT\n'), 'the QUIT');
  child.say('BYE');
  child.exitNow(0, null);
  await new Promise((r) => setTimeout(r, 20));
  child.say('BYE');                          // a second one, after exit
  child.stdioCloseNow(0);
  const verdict = await closing;
  assert.ok(verdict, 'a second goodbye is not a goodbye');
  assert.match(verdict, /unsolicited BYE/, `saw ${verdict}`);
  assert.equal(helper.shutdownOutcome.gracefulProtocolShutdown, false);
});

test('a drain timeout cannot claim release while the parent still holds pipes or listeners',
  { timeout: 30_000 }, async (t) => {
    // Counting Node's Timeout resources proves nothing about pipes and listeners. This asserts the
    // handles themselves: after a result that claims full physical release, the exact listeners
    // this module installed must be gone and the three parent-owned streams must be destroyed.
    const { helper, child } = await startScripted(t, { stdioDrainMs: 150 });
    const before = process.getActiveResourcesInfo().filter((r) => r === 'Timeout').length;
    const closing = helper.close('drain').then(() => null, (e) => e.message);
    await waitUntil(() => child.stdin.written.includes('QUIT\n'), 'the QUIT');
    child.say('BYE');
    child.exitNow(0, null);
    // no stdioCloseNow() ever: the drain witness never arrives
    const verdict = await closing;

    assert.ok(verdict, 'without a drain witness there is no canonical verdict to give');
    assert.match(verdict, /stdio never closed/, `saw ${verdict}`);
    assert.equal(helper.shutdownOutcome.gracefulProtocolShutdown, false,
      'protocol health is permanently abnormal once the transcript is unverified');

    // THE LOCAL SIDE. Claiming release requires actually having let go.
    assert.equal(helper.shutdownOutcome.physicalReleaseConfirmed, true,
      'the process is gone AND this side released its handles, so release is claimable');
    assert.equal(child.stdout.listenerCount('data'), 0, 'no stdout listener may remain');
    assert.equal(child.stderr.listenerCount('data'), 0, 'no stderr listener may remain');
    assert.equal(child.listenerCount('close'), 0, 'no stdio-close listener may remain');
    assert.equal(child.stdout.destroyed, true, 'stdout is positively destroyed');
    assert.equal(child.stderr.destroyed, true, 'stderr is positively destroyed');
    assert.equal(child.stdin.destroyed, true, 'stdin is positively destroyed');

    // A LATE BYTE MUST NOT MUTATE AN ALREADY-RETURNED VERDICT. With the listener detached it
    // cannot even be parsed, which is the structural version of that guarantee.
    const frozen = JSON.stringify(helper.shutdownOutcome);
    child.say('BYE');
    child.stdioCloseNow(0);
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(JSON.stringify(helper.shutdownOutcome), frozen,
      'nothing arriving after the decision may change it');

    // Bounded: the wait ended on its own timer and that timer was cancelled.
    const after = process.getActiveResourcesInfo().filter((r) => r === 'Timeout').length;
    assert.ok(after <= before + 1, `a drain wait must not leave timers behind (${before} -> ${after})`);
  });

test('a stream that cannot be witnessed destroyed is NOT called released', { timeout: 30_000 }, async (t) => {
  // The fail-closed half of the rule above. A child whose pipes expose no destroy()/destroyed --
  // an exotic stdio option, or a fake that does not model them -- cannot be positively released,
  // and "cannot witness" is never "released".
  let child;
  const { helper } = await startNativeHelper({
    helperPath: process.execPath,
    useWsl: false,
    limits: { quitTimeoutMs: 300, stdioDrainMs: 120, signalTimeoutMs: 300, startupTimeoutMs: 3000 },
    spawnFn: (cmd) => {
      child = scriptedChild();
      child.stdout = new EventEmitter();   // no destroy(), no destroyed
      child.stderr = new EventEmitter();
      setImmediate(() => child.stdout.emit('data',
        Buffer.from(`HELLO 2 4321 ${cmd.args.at(-1)} 2 60 - - fakesource\n`, 'latin1')));
      return child;
    },
  });
  t.after(async () => { try { await helper.forceClose('test cleanup'); } catch { /* fine */ } });

  const closing = helper.close('unwitnessable').then(() => null, (e) => e.message);
  await waitUntil(() => child.stdin.written.includes('QUIT\n'), 'the QUIT');
  child.exitNow(0, null);
  const verdict = await closing;
  assert.match(String(verdict), /parent-owned stdio could not be released/);
  assert.equal(helper.shutdownOutcome.physicalReleaseConfirmed, false,
    'an unwitnessable handle keeps the resource owned rather than claimed released');
  assert.equal(helper.closed, false, 'so the pool retains it and a retry can reach it');
});

test('canonical BYE, drained stdio, exit 0 is still the one clean path', { timeout: 30_000 }, async (t) => {
  const { helper, child } = await startScripted(t);
  const closing = helper.close('canonical').then(() => null, (e) => e.message);
  await waitUntil(() => child.stdin.written.includes('QUIT\n'), 'the QUIT');
  child.say('BYE');
  child.exitNow(0, null);
  child.stdioCloseNow(0);
  assert.equal(await closing, null);
  assert.deepEqual(helper.shutdownOutcome,
    { physicalReleaseConfirmed: true, gracefulProtocolShutdown: true, reason: null });
});

// ---------------------------------------------------------------- a crash is never a graceful exit
//
// `attemptedExchange = !exited && !fault` skipped the ENTIRE goodbye/exit verdict when the helper
// had already died, and the later process-gone path then reported
// `{ physicalReleaseConfirmed: true, gracefulProtocolShutdown: true, reason: null }`. An idle crash
// with exit code 9 -- and even a silent exit 0 nobody asked for -- came back as a clean shutdown.
//
// A canonical shutdown is a REQUESTED exchange that completed. A child that died on its own never
// had one, so it can be physically gone and is always abnormal, with the original fault preserved.

for (const [label, exitCode] of [['crashes with exit 9', 9], ['exits 0 with nobody asking', 0]]) {
  test(`a helper that ${label} while idle is physically gone but NEVER graceful`,
    { timeout: 30_000 }, async (t) => {
      const faults = [];
      const helper = await startFake(t, fakeHelper(`${HELLO_OK}
setTimeout(() => process.exit(${exitCode}), 120);
`), { onFault: (err) => faults.push(err) });

      await waitUntil(() => helper.healthy === false, 'the idle crash to be latched');
      assert.equal(faults.length, 1, 'the crash was reported when it happened');

      let verdict = null;
      try { await helper.close('after an idle crash'); } catch (err) { verdict = err; }
      assert.ok(verdict, 'close must not resolve cleanly over a helper that died on its own');

      const outcome = helper.shutdownOutcome;
      assert.equal(outcome.gracefulProtocolShutdown, false, 'a crash is not a goodbye');
      assert.equal(outcome.physicalReleaseConfirmed, true, 'but the process really is gone');
      assert.match(outcome.reason, /faulted before shutdown/,
        `the ORIGINAL fault must be preserved; saw ${outcome.reason}`);
      assert.match(outcome.reason, new RegExp(`code=${exitCode}`), 'including its exit code');
      assert.match(outcome.reason, /before any QUIT was sent/,
        'and the fact that no exchange was ever requested');
      assert.equal(helper.closed, true, 'released: there is nothing left to own');
    });
}

test('beginClose, then the child exits before close() sends QUIT, is abnormal -- not graceful',
  { timeout: 30_000 }, async (t) => {
    // The pool's real ordering. beginClose() sets `closing`, which deliberately suppresses the
    // unexpected-exit latch -- so there is no fault to notice, and the exit code happens to be 0.
    // Neither of those makes it a completed goodbye.
    const helper = await startFake(t, fakeHelper(`${HELLO_OK}
process.stdin.resume();
setTimeout(() => process.exit(0), 200);
`));
    helper.beginClose('pool draining');
    await waitUntil(() => helper.exited, 'the child to exit on its own');

    let verdict = null;
    try { await helper.close('after the child left'); } catch (err) { verdict = err; }
    assert.ok(verdict, 'no QUIT was ever sent, so no goodbye was completed');
    assert.match(verdict.message, /before any QUIT was sent/, `saw ${verdict.message}`);
    assert.equal(helper.shutdownOutcome.gracefulProtocolShutdown, false,
      'an exit code of 0 does not make an unrequested exit canonical');
    assert.equal(helper.shutdownOutcome.physicalReleaseConfirmed, true);
  });

test('a BYE followed by unterminated trailing bytes is NOT a clean transcript',
  { timeout: 30_000 }, async (t) => {
    // The parser holds everything after the last LF. The helper acknowledged its goodbye and then
    // left an incomplete protocol line behind; the drain witness arrived, so we KNOW those bytes
    // are all there will ever be. No unparsed byte may coexist with a canonical verdict.
    const helper = await startFake(t, quitFake(
      "process.stdout.write('BYE\\nUNTERMINATED_GARBAGE'); process.exit(0);",
    ));
    let verdict = null;
    try { await helper.close('trailing fragment'); } catch (err) { verdict = err; }
    assert.ok(verdict, 'leftover bytes are a protocol anomaly');
    assert.match(verdict.message, /20 unterminated byte\(s\) on stdout/, `saw ${verdict.message}`);
    assert.match(verdict.message, /UNTERMINATED_GARBAGE/, 'the fragment is named, bounded');
    assert.equal(helper.shutdownOutcome.gracefulProtocolShutdown, false);
    assert.equal(helper.shutdownOutcome.physicalReleaseConfirmed, true, 'the process is still gone');
  });

test('an unterminated NON-ASCII fragment is reported without echoing raw bytes',
  { timeout: 30_000 }, async (t) => {
    const helper = await startFake(t, quitFake(
      "process.stdout.write(Buffer.from('BYE\\n', 'latin1')); "
      + "process.stdout.write(Buffer.from([0xff, 0x00, 0x41])); process.exit(0);",
    ));
    let verdict = null;
    try { await helper.close('non-ascii fragment'); } catch (err) { verdict = err; }
    assert.ok(verdict);
    assert.match(verdict.message, /3 unterminated byte\(s\) on stdout/, `saw ${verdict.message}`);
    assert.match(verdict.message, /\\x(ff|00)/, 'non-printable bytes are escaped, never emitted raw');
  });

test('the canonical shape -- requested QUIT, one BYE, empty buffer, natural close, exit 0 -- is clean',
  { timeout: 30_000 }, async (t) => {
    const faults = [];
    const helper = await startFake(t, quitFake("process.stdout.write('BYE\\n'); process.exit(0);"),
      { onFault: (err) => faults.push(err) });
    const outcome = await helper.close('canonical');
    assert.deepEqual(outcome,
      { physicalReleaseConfirmed: true, gracefulProtocolShutdown: true, reason: null });
    assert.equal(helper.healthy, true);
    assert.deepEqual(faults, []);
  });

// ---------------------------------------------------------------- the pre-spawn abort fence

test('an abort while parent-owned distro discovery is pending spawns NOTHING',
  { timeout: 30_000 }, async () => {
    // startNativeHelper checked signal.aborted BEFORE awaiting the lookup, and addEventListener is
    // not retroactive -- so a shutdown that won the race while the registry query was still in
    // flight was simply lost, and a helper was launched into a pool that had already closed.
    const spawnCalls = [];
    const controller = new AbortController();
    let releaseLookup;
    const held = new Promise((res) => { releaseLookup = res; });

    const startPromise = startNativeHelper({
      helperPath: process.execPath,
      useWsl: true,
      signal: controller.signal,
      resolveWslDistro: () => held,
      spawnFn: (cmd) => { spawnCalls.push(cmd.args); throw new Error('must not be reached'); },
    }).then(() => 'resolved', (err) => err);

    await new Promise((r) => setTimeout(r, 50));
    controller.abort();                 // shutdown wins the race
    await new Promise((r) => setTimeout(r, 20));
    releaseLookup('Ubuntu');            // the lookup only now comes back

    const err = await startPromise;
    assert.deepEqual(spawnCalls, [], 'the launch fence must hold after the awaited discovery');
    assert.ok(err instanceof HelperFaultError, `expected a cancellation; got ${err}`);
    assert.equal(err.cancelled, true, 'and it uses the existing cancellation shape');
    assert.match(err.message, /aborted before launch/);
  });

test('a synchronous abort from inside the spawn seam enters owned cleanup rather than being lost',
  { timeout: 30_000 }, async () => {
    // The narrow post-spawn/pre-listener seam. The listener is attached BEFORE the spawn and
    // rebound to the real handle as soon as it exists, so an abort raised synchronously by the
    // spawn itself is applied to that handle instead of vanishing.
    const controller = new AbortController();
    const children = [];
    const err = await startNativeHelper({
      helperPath: process.execPath,
      useWsl: false,
      limits: { startupTimeoutMs: 4000, quitTimeoutMs: 300, signalTimeoutMs: 300, stdioDrainMs: 300 },
      signal: controller.signal,
      spawnFn: (cmd) => {
        const child = scriptedChild();
        children.push(child);
        controller.abort();             // synchronously, while the handle does not exist yet
        void cmd;
        return child;
      },
    }).then(() => null, (e) => e);

    assert.ok(err, 'an aborted startup must not resolve');
    assert.equal(children.length, 1, 'exactly one child was created, and it is not orphaned');
    assert.ok(err.helper, 'ownership survives: the handle comes back on the error');
    assert.equal(err.helper.closing, true, 'the abort reached the handle and began cleanup');
    await err.helper.forceClose('test cleanup').catch(() => {});
  });
