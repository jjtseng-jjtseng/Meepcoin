// THE OPT-IN WINDOW REFRESH, AS A RUNNER OPTION AND AS EVIDENCE.
//
// NOTHING LIVE IS IN THIS FILE. No daemon, container, browser, listener, pool, socket or network is
// started: the runner's own pure text is lifted and executed, and the profile selector is imported
// and called directly. `startDevPool` is deliberately NOT called -- it would open a listener -- so
// the reachability proof is the selector plus the runner's single, conditional wiring line.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { selectSimulationProfile } from '../server.mjs';
import { classifyWslDockerEngine } from '../docker_engine_topology.mjs';
import { targetFromWideDifficulty } from '../difficulty.mjs';
import {
  REAL_P2P_PROFILE, REAL_P2P_SHARE_PROFILE, realRefreshProfile, realSequenceProfile,
  realSequenceShareProfile,
} from '../sim_session.mjs';
import { REAL_REFRESH_LIMITS, REAL_SEARCH_LIMITS } from '../../../web-miner/lib/shared/protocol.js';

const RUNNER_PATH = resolve(dirname(fileURLToPath(import.meta.url)), '../../../web-miner/tools/local_p2p_block.mjs');
const runnerSource = () => readFileSync(RUNNER_PATH, 'utf8');
const DOCKER_BUILD_PATH = resolve(dirname(fileURLToPath(import.meta.url)), '../../../node/docker-build.sh');
const PROBE_SHARE_TARGET = targetFromWideDifficulty('1').targetHexLE;
const PRIVATE_BLOCK_TARGET = targetFromWideDifficulty('500').targetHexLE;

const clientRefreshJob = (window, over = {}) => ({
  type: 'real_job',
  jobId: `realjob-w${window}`,
  issuanceId: String(window).repeat(32),
  contentDigest: (window + 2).toString(16).repeat(64),
  height: '1',
  epochKeyHex: (window + 4).toString(16).repeat(64),
  seedHashHex: (window + 6).toString(16).repeat(64),
  hashingTemplateHex: `10${window.toString(16).padStart(2, '0')}${'00'.repeat(74)}`,
  shareWork: true,
  shareTargetHexLE: PROBE_SHARE_TARGET,
  targetHexLE: PRIVATE_BLOCK_TARGET,
  nonceStart: (window - 1) * REAL_SEARCH_LIMITS.maxAttempts,
  nonceRange: REAL_SEARCH_LIMITS.maxAttempts,
  ...over,
});

const refreshFrameState = () => ({
  activeBinding: null, initialJobFacts: null, bindings: [], shares: [], blocks: [],
  truncated: false, captured: false, rejected: [], rejectedCount: 0,
});

const sequenceRefreshFrameState = () => ({
  activeBinding: null, initialJobFacts: null, bindings: [], readiness: [], shares: [], blocks: [],
  terminalBlocks: [], truncated: false, captured: false, rejected: [], rejectedCount: 0,
});

/**
 * Lift `function NAME(...) { ... }` out of the runner and make it callable with nothing in scope.
 * The point is to run the production text, not something resembling it. `deps` supplies any other
 * lifted production function the lifted one calls, so the REAL callee runs rather than a stub.
 */
function liftPureFunction(src, name, deps = {}) {
  const at = src.indexOf(`function ${name}(`);
  assert.notEqual(at, -1, `${name} is not defined in the runner`);
  let parens = 0;
  let paramsEnd = -1;
  for (let i = src.indexOf('(', at); i < src.length; i += 1) {
    if (src[i] === '(') parens += 1;
    else if (src[i] === ')') { parens -= 1; if (parens === 0) { paramsEnd = i; break; } }
  }
  const bodyAt = src.indexOf('{', paramsEnd);
  let depth = 0;
  let end = -1;
  for (let i = bodyAt; i < src.length; i += 1) {
    if (src[i] === '{') depth += 1;
    else if (src[i] === '}') { depth -= 1; if (depth === 0) { end = i + 1; break; } }
  }
  assert.notEqual(end, -1, `${name} is not a complete function`);
  const depNames = Object.keys(deps);
  // eslint-disable-next-line no-new-func
  return new Function(...depNames, `${src.slice(at, end)}\nreturn ${name};`)(...depNames.map((n) => deps[n]));
}

/** The refresh frame capture with its REAL production dependencies in scope. */
function liftRefreshCapture(src) {
  const refreshBrowserJobFacts = liftPureFunction(src, 'refreshBrowserJobFacts', { createHash });
  const classifyShareRefreshTransition = liftPureFunction(src, 'classifyShareRefreshTransition', {
    refreshBrowserJobFacts,
  });
  return liftPureFunction(src, 'captureShareRefreshFrame', {
    refreshBrowserJobFacts,
    classifyShareRefreshTransition,
    classifyServerFrame: liftPureFunction(src, 'classifyServerFrame'),
  });
}

/** The Cartesian frame capture with every REAL production dependency in scope. */
function liftSequenceRefreshCapture(src) {
  const refreshBrowserJobFacts = liftPureFunction(src, 'refreshBrowserJobFacts', { createHash });
  const classifyShareRefreshTransition = liftPureFunction(src, 'classifyShareRefreshTransition', {
    refreshBrowserJobFacts,
  });
  const classifyShareSequenceRefreshNext = liftPureFunction(src, 'classifyShareSequenceRefreshNext', {
    refreshBrowserJobFacts,
  });
  return liftPureFunction(src, 'captureShareSequenceRefreshFrame', {
    refreshBrowserJobFacts,
    classifyShareRefreshTransition,
    classifyShareSequenceRefreshNext,
    classifyServerFrame: liftPureFunction(src, 'classifyServerFrame'),
  });
}

function beginRefreshCapture(capture, state, binding, job, windowTotal, limit = 50) {
  assert.equal(capture({ state, frame: job, limit, windowTotal }).accepted, true,
    'the initial browser job was not captured');
  assert.equal(capture({ state, frame: { type: 'run_started', ...binding }, limit, windowTotal }).accepted, true,
    'run_started did not bind the initial browser job');
}

// ================================================================== the flag contract
test('RUNNER REFRESH FLAG: absent is the legacy run, and only 2..max is an opt-in on the share path', () => {
  const classify = liftPureFunction(runnerSource(), 'classifyRefreshWindowsFlag');
  const max = REAL_REFRESH_LIMITS.maxWindows;
  const maxContexts = 32;

  // ABSENT IS NOT "ONE": it is "this option was not used", and nothing is configured. This is the
  // legacy contract whatever the mode, so the default behaviour is unchanged.
  for (const mode of [
    { shareProfile: false, interactive: false },
    { shareProfile: false, interactive: true },
    { shareProfile: true, interactive: true },
  ]) {
    assert.deepEqual(classify({ raw: null, blocks: 1, maxWindows: max, maxContexts, ...mode }),
      { ok: true, windows: null, error: null });
    assert.deepEqual(classify({ raw: undefined, blocks: 1, maxWindows: max, maxContexts, ...mode }),
      { ok: true, windows: null, error: null });
  }

  // LEGAL: 2..max, and ONLY with both --share-profile and --interactive.
  for (const n of [2, 3, max]) {
    assert.deepEqual(classify({
      raw: String(n), blocks: 1, maxWindows: max, maxContexts, shareProfile: true, interactive: true,
    }),
      { ok: true, windows: n, error: null }, `windows ${n}`);
  }

  // Refused: a no-op that looks like an opt-in, an over-limit value, and anything not a number.
  for (const bad of ['1', '0', String(max + 1), '5', 'four', '2.5', '', '-2', ' 2', '02x']) {
    const v = classify({
      raw: bad, blocks: 1, maxWindows: max, maxContexts, shareProfile: true, interactive: true,
    });
    assert.equal(v.ok, false, `raw ${JSON.stringify(bad)} was accepted`);
    assert.equal(v.windows, null);
    assert.match(v.error, /--refresh-windows must be a whole number from 2 to/);
  }
  // The Cartesian mode is legal while blocks x windows fits the fixed core context ceiling.
  assert.deepEqual(classify({
    raw: '2', blocks: 2, maxWindows: max, maxContexts, shareProfile: true, interactive: true,
  }), { ok: true, windows: 2, error: null }, 'the supported 2-block x 2-window plan was refused');
  assert.deepEqual(classify({
    raw: '2', blocks: 16, maxWindows: max, maxContexts, shareProfile: true, interactive: true,
  }), { ok: true, windows: 2, error: null }, 'the exact 32-context ceiling was refused');
  const overCeiling = classify({
    raw: '2', blocks: 17, maxWindows: max, maxContexts, shareProfile: true, interactive: true,
  });
  assert.deepEqual(overCeiling, {
    ok: false, windows: null, error: '--blocks x --refresh-windows may issue at most 32 contexts',
  });

  // The share path still requires BOTH trusted modes.
  const nonShare = classify({
    raw: '2', blocks: 1, maxWindows: max, maxContexts, shareProfile: false, interactive: true,
  });
  assert.equal(nonShare.ok, false, 'a refresh was accepted without --share-profile');
  assert.match(nonShare.error, /--refresh-windows requires --share-profile/);
  const nonInteractive = classify({
    raw: '2', blocks: 1, maxWindows: max, maxContexts, shareProfile: true, interactive: false,
  });
  assert.equal(nonInteractive.ok, false, 'a refresh was accepted without --interactive');
  assert.match(nonInteractive.error, /--refresh-windows requires --interactive/);
});

test('RUNNER POWER: Online and Offline are exact states; failed or ambiguous reads fail closed', () => {
  const classify = liftPureFunction(runnerSource(), 'classifyPowerLineStatus');
  const online = { ok: true, state: 'Online', onBattery: false, warning: null, error: null };
  const offline = {
    ok: true,
    state: 'Offline',
    onBattery: true,
    warning: 'running on battery; hash rate may be lower and the bounded run may find no block',
    error: null,
  };
  for (const stdout of ['Online', 'Online\n', 'Online\r\n']) {
    assert.deepEqual(classify({ status: 0, stdout }), online, JSON.stringify(stdout));
  }
  for (const stdout of ['Offline', 'Offline\n', 'Offline\r\n']) {
    assert.deepEqual(classify({ status: 0, stdout }), offline, JSON.stringify(stdout));
  }

  const queryFailed = {
    ok: false, state: null, onBattery: null, warning: null, error: 'the power-state query failed',
  };
  for (const status of [1, -1, null, undefined]) {
    assert.deepEqual(classify({ status, stdout: 'Online' }), queryFailed, `status ${String(status)}`);
  }

  const ambiguous = {
    ok: false,
    state: null,
    onBattery: null,
    warning: null,
    error: 'the power-state query was unavailable or ambiguous',
  };
  for (const stdout of [
    '', 'Unknown', 'online', 'offline', ' Online', 'Online ', 'Online\nOffline', 'Online\n\n', null, undefined,
  ]) {
    assert.deepEqual(classify({ status: 0, stdout }), ambiguous, JSON.stringify(stdout));
  }
  assert.deepEqual(classify({ status: 0, stdout: 'Online\r\n', stderr: 'warning\r\n' }), ambiguous,
    'a nominal stdout with diagnostic stderr was treated as an exact power-state result');

  const src = runnerSource();
  const classifiedAt = src.indexOf('const power = classifyPowerLineStatus(powerQuery);');
  assert.notEqual(classifiedAt, -1, 'the full process result is not passed to the power classifier');
  assert.ok(src.includes('queryStdout: bounded(powerQuery.stdout, 160),'));
  assert.ok(src.includes('queryStderr: bounded(powerQuery.stderr, 160),'));
  assert.ok(src.indexOf('const reservation = reserveOneUse({') > classifiedAt,
    'a power refusal could happen only after consuming the one-use reservation');
});

test('RUNNER DOCKER TOPOLOGY: Desktop VM is refused before the one-use reservation', () => {
  const src = runnerSource();
  const classify = classifyWslDockerEngine;
  assert.deepEqual(classify({ status: 0, stdout: '[]\n' }), { ok: true, error: null });
  assert.deepEqual(classify({ status: 0, stdout: '["other.engine.label=value"]' }),
    { ok: true, error: null });
  assert.match(classify({ status: 0,
    stdout: '["com.docker.desktop.address=unix:///var/run/docker-cli.sock"]',
  }).error, /different host network/);
  for (const observation of [
    { status: 1, stdout: '[]' },
    { status: 0, stdout: '' },
    { status: 0, stdout: '{}' },
    { status: 0, stdout: '[42]' },
  ]) assert.equal(classify(observation).ok, false);

  const checkAt = src.indexOf('const dockerEngine = classifyWslDockerEngine(dockerInfo);');
  const reservationAt = src.indexOf('const reservation = reserveOneUse({');
  assert.ok(checkAt > 0 && reservationAt > checkAt,
    'a Desktop refusal must occur before the reservation is consumed');
  assert.ok(src.includes("wsl(['docker', 'info', '--format', '{{json .Labels}}'])"));
});

test('RUNNER CONVERTER RUNTIME GATE: manifest, bytes and complete loader resolution must all agree', () => {
  const classify = liftPureFunction(runnerSource(), 'classifyConverterRuntimeArtifacts');
  const hashes = ['1', '2', '3', '4'].map((digit) => digit.repeat(64));
  const requiredNames = [
    'meepcoind',
    'meepcoin-blockhashing',
    'runtime-libs/libboost_filesystem.so.1.83.0',
    'runtime-libs/libboost_thread.so.1.83.0',
  ];
  const runtimeLibraryDir = '/artifacts/runtime-libs';
  const manifestText = requiredNames.map((name, i) => `${name} = ${hashes[i]}`).join('\n');
  const loaderStdout = [
    'libc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6 (0x1)',
    `libboost_filesystem.so.1.83.0 => ${runtimeLibraryDir}/libboost_filesystem.so.1.83.0 (0x2)`,
    `libboost_thread.so.1.83.0 => ${runtimeLibraryDir}/libboost_thread.so.1.83.0 (0x3)`,
  ].join('\n');
  const base = {
    manifestText, requiredNames, actualHashes: hashes, sizes: [10, 20, 30, 40],
    loaderStatus: 0, loaderStdout, runtimeLibraryDir,
  };
  const ok = classify(base);
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.artifacts.map((item) => item.name), requiredNames);

  const failures = [
    [{ ...base, manifestText: manifestText.replace(`${requiredNames[3]} = ${hashes[3]}`, '') }, /omits/],
    [{ ...base, manifestText: `${manifestText}\n${requiredNames[0]} = ${hashes[0]}` }, /repeats/],
    [{ ...base, actualHashes: [hashes[0], hashes[1], hashes[2], 'f'.repeat(64)] }, /does not match/],
    [{ ...base, sizes: [10, 20, 30, 0] }, /observation/],
    [{ ...base, loaderStatus: 127 }, /loader check failed/],
    [{ ...base, loaderStdout: `${loaderStdout}\nlibmissing.so => not found` }, /unresolved library/],
    [{ ...base, loaderStdout: loaderStdout.replace(runtimeLibraryDir, '/usr/lib') }, /did not resolve/],
  ];
  for (const [input, expected] of failures) {
    const verdict = classify(input);
    assert.equal(verdict.ok, false);
    assert.match(verdict.error, expected);
  }
});

test('RUNNER CONVERTER RUNTIME GATE: build exports hashed libraries and live preflight precedes reservation', () => {
  const src = runnerSource();
  const build = readFileSync(DOCKER_BUILD_PATH, 'utf8');
  for (const text of [
    'REQUIRED_CONVERTER_RUNTIME_LIBRARIES=(libboost_filesystem.so.1.83.0 libboost_thread.so.1.83.0)',
    'REQUIRED_DAEMON_RUNTIME_LIBRARIES=(libboost_chrono.so.1.83.0 libboost_program_options.so.1.83.0 libboost_serialization.so.1.83.0)',
    'ldd "$WORK/build/release/bin/meepcoind"',
    'additional required daemon runtime libraries (sha256)',
    'copied daemon runtime library changed bytes',
    'runtime-libs/$lib',
    'refusing stale or caller-supplied libraries',
  ]) assert.ok(build.includes(text), `the canonical build omits: ${text}`);

  const classifyAt = src.indexOf('const runtimeArtifacts = classifyConverterRuntimeArtifacts({');
  const refuseAt = src.indexOf('if (!runtimeArtifacts.ok) throw new Error(runtimeArtifacts.error);');
  const reserveAt = src.indexOf('const reservation = reserveOneUse({');
  const startAt = src.indexOf('const pool = await lifecycle.startPool({');
  assert.ok(classifyAt !== -1 && refuseAt > classifyAt);
  assert.ok(refuseAt < reserveAt, 'runtime closure can consume the one-use reservation before refusing');
  assert.ok(reserveAt < startAt, 'the repaired preflight changed reservation-before-live-start ordering');
  assert.ok(src.includes("'/usr/bin/env', '-i', `LD_LIBRARY_PATH=${runtimeLibraryDir}`"));
});

test('RUNNER HANDOFF PROBE FLAG: only the one explicit bare two-window invocation is legal', () => {
  const classify = liftPureFunction(runnerSource(), 'classifyRefreshHandoffProbeFlag');
  const legal = [
    '--share-profile', '--interactive', '--blocks', '1', '--refresh-windows', '2',
    '--refresh-handoff-probe',
  ];
  const knownFlags = legal.filter((value) => value.startsWith('--'));
  const valueFlags = ['--blocks', '--refresh-windows'];
  const call = (argv, over = {}) => classify({
    argv,
    enabled: argv.includes('--refresh-handoff-probe'),
    blocks: 1,
    refreshWindows: 2,
    shareProfile: argv.includes('--share-profile'),
    interactive: argv.includes('--interactive'),
    knownFlags,
    valueFlags,
    ...over,
  });

  assert.deepEqual(call([]), { ok: true, error: null }, 'absence changed a historical mode');
  assert.deepEqual(call(legal), { ok: true, error: null });

  const refused = [
    [legal.filter((x) => x !== '--share-profile'), /exactly one --share-profile/],
    [legal.filter((x) => x !== '--interactive'), /exactly one --interactive/],
    [legal.filter((x) => !['--blocks', '1'].includes(x)), /explicit canonical pair --blocks 1/],
    [legal.filter((x) => !['--refresh-windows', '2'].includes(x)), /explicit canonical pair --refresh-windows 2/],
    [[...legal, '--refresh-handoff-probe'], /must appear exactly once/],
    [[...legal.slice(0, -1), '--refresh-handoff-probe', '1'], /bare flag and takes no value/],
    [[...legal.slice(0, -1), '--refresh-handoff-probe=false'], /attached values and alternate spellings/],
    [[...legal, '--surprise'], /unknown flag for --refresh-handoff-probe: --surprise/],
    [['--blocks', '--refresh-handoff-probe', '--share-profile', '--interactive', '--refresh-windows', '2'],
      /--blocks requires a value/],
  ];
  for (const [argv, message] of refused) {
    const verdict = call(argv);
    assert.equal(verdict.ok, false, argv.join(' '));
    assert.match(verdict.error, message);
  }
  assert.match(call(legal.map((x) => (x === '1' ? '2' : x)), { blocks: 2 }).error,
    /explicit canonical pair --blocks 1/);
  assert.match(call(legal.map((x) => (x === '2' ? '3' : x)), { refreshWindows: 3 }).error,
    /explicit canonical pair --refresh-windows 2/);
});

test('RUNNER HANDOFF PROBE DIFFICULTY: trusted selection is 1 only for the probe and 100 otherwise', () => {
  const choose = liftPureFunction(runnerSource(), 'selectTrustedShareDifficulty');
  const input = { normalDifficulty: 100, probeDifficulty: 1, blockDifficulty: 500 };
  assert.equal(choose({ ...input, probe: false }), 100);
  assert.equal(choose({ ...input, probe: true }), 1);
  assert.throws(() => choose({ ...input, probe: true, probeDifficulty: 501 }), /outside the private block target/);
  const src = runnerSource();
  assert.match(src, /const HANDOFF_PROBE_SHARE_DIFFICULTY = 1;/);
  assert.match(src, /const SHARE_PROFILE_DIFFICULTY = 100;/);
  assert.equal(/--share-difficulty|arg\('share-difficulty'/.test(src), false,
    'the fixed profile became a caller-selectable difficulty');
  assert.ok(src.includes('...(shareProfile ? { shareDifficulty: effectiveShareDifficulty } : {}),'));
});

test('RUNNER REFRESH FLAG: illegal values refuse before any prerequisite, spawn, listener or path inspection', () => {
  const src = runnerSource();
  // The verdict sits immediately after pure argument parsing and therefore BEFORE every prerequisite
  // with I/O or a side effect: default-browser candidate resolution, the explicit browser existence
  // check, the remaining usage contract, the screenshot stat, reservation, outputs, spawn and listen.
  const verdictAt = src.indexOf('const refreshVerdict = classifyRefreshWindowsFlag({');
  const probeVerdictAt = src.indexOf('const handoffProbeVerdict = classifyRefreshHandoffProbeFlag({');
  assert.notEqual(verdictAt, -1, 'the refresh verdict is not decided in one place');
  assert.ok(probeVerdictAt > verdictAt, 'the probe was classified before the refresh value existed');
  for (const later of [
    'const browserPath = browserPathRaw ?? CANDIDATES.find((p) => existsSync(p));',
    '!browserPath || !existsSync(browserPath)',
    "if (!artifactDir || !image",
    'const flagVerdict = classifyShareProfileFlags({',
    "if (shareProfile && !/^[0-9a-f]{40}$/.test(expectedHead ?? ''))",
    'if (!statSync(screenshotDir).isDirectory())',
    'const reservation = reserveOneUse({',
    'const present = paths.filter((x) => existsSync(x));',
    'const lifecycle = createRunLifecycle({',
  ]) {
    const at = src.indexOf(later);
    assert.ok(at > verdictAt, `the refresh verdict must precede: ${later.slice(0, 48)}`);
    assert.ok(at > probeVerdictAt, `the probe verdict must precede: ${later.slice(0, 48)}`);
  }
  assert.ok(src.indexOf("const browserPathRaw = arg('browser');") < verdictAt,
    'the raw browser argument was not parsed before classification');
  // The share path's own requirements are stated to a refresh caller in the usage text.
  assert.match(src, /--refresh-windows <2\.\./);
  assert.ok(src.includes('[--refresh-windows <2..${REAL_REFRESH_LIMITS.maxWindows}> --share-profile --interactive --blocks <1|2> '),
    'the usage text does not state the share-path requirements of a refresh run');
});

test('RUNNER HANDOFF PROBE FLAG: malformed requests win before browser and output I/O', (t) => {
  const dir = mkdtempSync(resolve(tmpdir(), 'meepcoin-handoff-probe-refusal-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const evidence = resolve(dir, 'evidence.json');
  const transcript = resolve(dir, 'transcript.txt');
  const reservation = resolve(dir, 'reservation.json');
  const base = [
    RUNNER_PATH,
    '--artifact-dir', dir,
    '--image', 'unused:test',
    '--image-id', `sha256:${'a'.repeat(64)}`,
    '--a-rpc-port', '38281', '--a-p2p-port', '38282',
    '--b-rpc-port', '38283', '--b-p2p-port', '38284',
    '--evidence', evidence,
    '--transcript', transcript,
    '--browser', resolve(dir, 'missing-browser.exe'),
    '--reservation', reservation, '--expected-head', 'b'.repeat(40), '--screenshot-dir', dir,
  ];
  const cases = [
    [
      ['--refresh-windows', '2', '--share-profile', '--interactive', '--refresh-handoff-probe'],
      /requires the explicit canonical pair --blocks 1/,
    ],
    [
      ['--blocks', '1', '--refresh-windows', '2', '--share-profile', '--interactive',
        '--refresh-handoff-probe', '--surprise'],
      /unknown flag for --refresh-handoff-probe: --surprise/,
    ],
    ...['--browser', '--evidence', '--reservation', '--artifact-dir'].map((flag) => [
      [flag, '--refresh-handoff-probe', '--blocks', '1', '--refresh-windows', '2',
        '--share-profile', '--interactive'],
      new RegExp(`${flag} requires a value`),
    ]),
  ];
  for (const [modeArgs, expected] of cases) {
    const result = spawnSync(process.execPath, [...base, ...modeArgs], {
      encoding: 'utf8', timeout: 10_000, windowsHide: true,
    });
    const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
    assert.equal(result.status, 2, output);
    assert.match(output, expected);
    assert.doesNotMatch(output, /usage: --artifact-dir/);
  }
  for (const path of [evidence, transcript, reservation]) assert.equal(existsSync(path), false);
});

test('RUNNER REFRESH FLAG: an over-ceiling Cartesian plan exits before browser or output I/O', (t) => {
  const dir = mkdtempSync(resolve(tmpdir(), 'meepcoin-refresh-refusal-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const evidence = resolve(dir, 'evidence.json');
  const transcript = resolve(dir, 'transcript.txt');
  const reservation = resolve(dir, 'reservation.json');
  const missingBrowser = resolve(dir, 'definitely-not-a-browser.exe');
  const result = spawnSync(process.execPath, [
    RUNNER_PATH,
    '--artifact-dir', dir,
    '--image', 'unused:test',
    '--image-id', `sha256:${'a'.repeat(64)}`,
    '--a-rpc-port', '38181', '--a-p2p-port', '38182',
    '--b-rpc-port', '38183', '--b-p2p-port', '38184',
    '--evidence', evidence,
    '--transcript', transcript,
    '--browser', missingBrowser,
    '--blocks', '17',
    '--refresh-windows', '2',
    '--share-profile',
    '--interactive',
    '--reservation', reservation,
    '--expected-head', 'b'.repeat(40),
    '--screenshot-dir', dir,
  ], { encoding: 'utf8', timeout: 10_000, windowsHide: true });
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;

  assert.equal(result.status, 2, output);
  assert.match(output, /--blocks x --refresh-windows may issue at most 32 contexts/);
  assert.doesNotMatch(output, /usage: --artifact-dir/, 'browser/path validation won over the context ceiling');
  for (const path of [evidence, transcript, reservation]) {
    assert.equal(existsSync(path), false, `early refusal created ${path}`);
  }
});

test('RUNNER REFRESH FLAG: it is wired ONCE, conditionally, and changes no existing gate', () => {
  const src = runnerSource();
  // The one wiring, and it is absent unless the flag was given.
  assert.ok(src.includes('...(refreshWindows === null ? {} : { refreshWindows }),'),
    'the refresh total is not wired through trusted startup configuration');
  assert.equal(src.split('{ refreshWindows }').length - 1, 1, 'the refresh total is wired more than once');
  assert.ok(src.includes("const refreshWindowsRaw = arg('refresh-windows');"));
  assert.ok(src.includes("'--refresh-windows',"), 'the flag is not in the known-flag list');
  // The existing share-profile gates are untouched: pin, screenshot directory, reservation, Start.
  for (const text of [
    "'--share-profile requires --expected-head <40 lowercase hex>",
    'if (!pin.ok) throw new Error(pin.error);',
    "requires --screenshot-dir <existing writable directory>",
    'const reservation = reserveOneUse({',
    'waiting for the operator or delegated agent to press Start',
  ]) assert.ok(src.includes(text), `a --share-profile gate was weakened: ${text}`);
  // Nothing enables the feature implicitly.
  assert.equal(/refreshWindows\s*=\s*[0-9]/.test(src), false, 'the runner assigns a refresh total by itself');
  // It is disclosed before Start, with both caps.
  assert.ok(src.includes('SAME-HEIGHT WINDOW REFRESH (before Start)'));
  assert.ok(src.includes('CONFIRMED before the next pair is built'));
});

test('RUNNER COMPOSED ROUTING: Cartesian capture and recorder precede both legacy branches', () => {
  const src = runnerSource();
  const websocketAt = src.indexOf("method === 'Network.webSocketFrameReceived'");
  const composedCaptureAt = src.indexOf('if (sequenceRefresh) {', websocketAt);
  const captureCallAt = src.indexOf('captureShareSequenceRefreshFrame({', composedCaptureAt);
  const legacySequenceCaptureAt = src.indexOf('if (blocks === 2) {', composedCaptureAt);
  const legacyRefreshCaptureAt = src.indexOf('if (refreshWindows !== null) {', composedCaptureAt);
  assert.ok(websocketAt !== -1 && composedCaptureAt > websocketAt,
    'the WebSocket route has no explicit Cartesian branch');
  assert.ok(captureCallAt > composedCaptureAt && captureCallAt < legacySequenceCaptureAt,
    'Cartesian frames do not reach their dedicated bound capture before the legacy sequence capture');
  assert.ok(legacySequenceCaptureAt < legacyRefreshCaptureAt,
    'the historical sequence and same-height refresh branches changed relative order');

  const terminalWaitAt = src.indexOf("label: 'the one attempt to finish'");
  const composedRecordAt = src.indexOf('if (sequenceRefresh) {', terminalWaitAt);
  const recordCallAt = src.indexOf('const outcome = await recordSequenceRefresh({', composedRecordAt);
  const legacyRecordAt = src.indexOf('if (blocks > 1) {', composedRecordAt);
  assert.ok(terminalWaitAt !== -1 && composedRecordAt > terminalWaitAt,
    'the terminal path has no explicit Cartesian branch');
  assert.ok(recordCallAt > composedRecordAt && recordCallAt < legacyRecordAt,
    'the Cartesian terminal result can fall through to the legacy sequence recorder');

  const recorderAt = src.indexOf('async function recordSequenceRefresh({');
  const evidenceAt = src.indexOf('const summary = sequenceRefreshEvidence({', recorderAt);
  const persistedAt = src.indexOf('evidence.sequenceRefresh = {', recorderAt);
  const runnerAt = src.indexOf('// ---------------------------------------------------------------- the run', recorderAt);
  assert.ok(recorderAt !== -1 && evidenceAt > recorderAt && evidenceAt < runnerAt,
    'the composed recorder does not build the Cartesian evidence summary');
  assert.ok(persistedAt > evidenceAt && persistedAt < runnerAt,
    'the composed recorder does not persist its dedicated evidence object');
  assert.ok(src.includes('frames: sequenceRefreshFrames,'),
    'the terminal recorder is not passed the same dedicated capture used by the WebSocket route');
  assert.ok(src.includes('? REAL_REFRESH_LIMITS.maxSessionMs + SEQUENCE_REFRESH_FINALIZATION_MS'),
    'the runner terminal wait can expire before the fixed ten-minute Cartesian core budget');
  assert.ok(src.includes('const SEQUENCE_REFRESH_FINALIZATION_MS = HELPER_LIMITS.requestTimeoutMs')
    && src.includes('+ REAL_RPC_LIMITS.submitTimeoutMs')
    && src.includes('+ PEER_PROPAGATION_TIMEOUT_MS')
    && src.includes('+ DAEMON_LIMITS.probeTimeoutMs'),
  'the post-deadline margin is not derived from the native, daemon, propagation, and probe ceilings');
});

// ================================================================== reachability of the profile
test('RUNNER REFRESH: a configured refresh total reaches the page profile, and absence does not', () => {
  const peer = { daemon: {} };
  // Absent: exactly the profile this build has always chosen.
  assert.equal(selectSimulationProfile({ peer, sequence: null, refresh: null }), REAL_P2P_PROFILE);
  assert.equal(selectSimulationProfile({ peer, sequence: null, refresh: null, shareWork: true }),
    REAL_P2P_SHARE_PROFILE);
  // Present: the refresh profile FOR THAT NUMBER, with and without share work.
  const three = selectSimulationProfile({ peer, sequence: null, refresh: { maxWindows: 3 } });
  assert.equal(three.refreshWindows, 3);
  assert.equal(three.shareWork, undefined);
  assert.deepEqual(three.labels, realRefreshProfile(3).labels);
  const shared = selectSimulationProfile({
    peer, sequence: null, refresh: { maxWindows: 2 }, shareWork: true, shareDifficulty: 100,
  });
  assert.equal(shared.refreshWindows, 2);
  assert.equal(shared.shareWork, true);
  assert.deepEqual(shared.labels, realRefreshProfile(2, { shareWork: true }).labels);
  assert.equal(shared.helloNotice, realRefreshProfile(2, { shareWork: true }).helloNotice,
    'ordinary D100 refresh gained probe-only wording');
  assert.equal(/fixes share difficulty/.test(shared.helloNotice), false,
    'ordinary D100 refresh disclosed the probe difficulty');
  const unmarkedOne = selectSimulationProfile({
    peer, sequence: null, refresh: { maxWindows: 2 }, shareWork: true, shareDifficulty: 1,
  });
  assert.equal(/fixes share difficulty/.test(unmarkedOne.helloNotice), false,
    'difficulty alone, without the trusted probe marker, changed disclosure');
  const probe = selectSimulationProfile({
    peer, sequence: null, refresh: { maxWindows: 2 }, shareWork: true, shareDifficulty: 1,
    refreshHandoffProbe: true,
  });
  assert.match(probe.helloNotice, /trusted startup configuration fixes share difficulty 1/);
  assert.match(probe.helloNotice, /block difficulty remains 500/);
  assert.match(probe.helloNotice, /genuine block result still wins immediately/);
  // A sequence still wins its own profiles, and never sees a window.
  assert.deepEqual(selectSimulationProfile({ peer, sequence: { total: 2 } }).labels, realSequenceProfile(2).labels);
  assert.deepEqual(selectSimulationProfile({ peer, sequence: { total: 2 }, shareWork: true }).labels,
    realSequenceShareProfile(2).labels);
});

// ================================================================== the evidence record
const windowRecordsFor = (n, {
  allocationStartedAt = (i) => 1000 + i * 100,
  record = () => ({}),
} = {}) => Array.from({ length: n }, (_, i) => ({
  window: i + 1,
  jobId: `realjob-${i + 1}`,
  issuanceId: String(i + 1).repeat(32),
  nonceStart: i * REAL_SEARCH_LIMITS.maxAttempts,
  nonceRange: REAL_SEARCH_LIMITS.maxAttempts,
  height: 1n,
  shareDifficulty: 1n,
  blockDifficulty: 500n,
  shareTargetHexLE: PROBE_SHARE_TARGET,
  blockTargetHexLE: PRIVATE_BLOCK_TARGET,
  contentDigest: (i + 3).toString(16).repeat(64),
  epochKeyHex: (i + 5).toString(16).repeat(64),
  seedHashHex: (i + 7).toString(16).repeat(64),
  hashingTemplateSha256: (i + 9).toString(16).repeat(64),
  verifierAllocationStartedAtMs: allocationStartedAt(i),
  ...record(i),
}));
const releasedVerifiers = (n, { releasedAt = (i) => 1050 + i * 100 } = {}) => Array.from({ length: n }, (_, i) => ({
  block: 1, window: i + 1, jobId: `realjob-${i + 1}`, issuanceId: String(i + 1).repeat(32),
  helperLinuxPid: 7000 + i, helperSourceId: 'f'.repeat(64), context: { height: '1' },
  releaseStartedAtMs: 1040 + i * 100, releasedAtMs: releasedAt(i), closed: true, forced: false,
}));
const facts = (over = {}) => [{
  sharesAccepted: 2, sharesAcceptedTotal: 14, invalidCandidatesTotal: 0,
  sessionDeadlineAtMs: 1_234_000, sessionBudgetSpent: false, ...over,
}];

test('RUNNER EVIDENCE: 2 to 4 windows are recorded per window, with serial release proved', () => {
  const refreshEvidence = liftPureFunction(runnerSource(), 'refreshEvidence');
  for (const n of [2, 3, REAL_REFRESH_LIMITS.maxWindows]) {
    const rec = refreshEvidence({
      requestedWindows: n,
      windowRecords: windowRecordsFor(n),
      sessionFacts: facts(),
      verifierHistory: releasedVerifiers(n - 1),
      currentVerifier: { helperLinuxPid: 9000, helperSourceId: 'a'.repeat(64), context: { height: '1' }, closed: false },
      attemptState: 'terminal_cancelled',
      attemptReason: 'search_bound_reached',
      submitBlockCount: 0,
      calcPowCount: 0,
      cumulativeAttempts: n * REAL_SEARCH_LIMITS.maxAttempts,
    });
    assert.equal(rec.requestedWindows, n);
    assert.equal(rec.windowsIssued, n);
    assert.deepEqual(rec.windows.map((w) => w.window), Array.from({ length: n }, (_, i) => i + 1));
    assert.deepEqual(rec.windows.map((w) => w.nonceStart),
      Array.from({ length: n }, (_, i) => i * REAL_SEARCH_LIMITS.maxAttempts));
    assert.deepEqual(rec.windows.map((w) => w.height), Array.from({ length: n }, () => '1'));
    assert.deepEqual(rec.windows.map((w) => w.shareDifficulty), Array.from({ length: n }, () => 1));
    assert.deepEqual(rec.windows.map((w) => w.blockDifficulty), Array.from({ length: n }, () => 500));
    assert.deepEqual(rec.windows.map((w) => w.shareTargetHexLE), Array.from({ length: n }, () => PROBE_SHARE_TARGET));
    assert.deepEqual(rec.windows.map((w) => w.blockTargetHexLE), Array.from({ length: n }, () => PRIVATE_BLOCK_TARGET));
    for (const field of ['contentDigest', 'epochKeyHex', 'seedHashHex', 'hashingTemplateSha256']) {
      assert.ok(rec.windows.every((w) => /^[0-9a-f]{64}$/.test(w[field])), `${field} was not retained as a digest/fact`);
    }
    assert.equal(rec.disjointWindows, true);
    // THE ALLOCATION-START READING IS PERSISTED PER WINDOW, and the unknown outcome/attempt facts
    // are labelled null rather than claimed.
    assert.deepEqual(rec.windows.map((w) => Number.isSafeInteger(w.verifierAllocationStartedAtMs)),
      Array.from({ length: n }, () => true));
    assert.deepEqual(rec.windows.map((w) => w.attempts), Array.from({ length: n }, () => null),
      'a per-window attempt count was invented');
    assert.deepEqual(rec.windows.map((w) => w.outcome), Array.from({ length: n }, () => null),
      'a per-window outcome was claimed without a runtime record');
    assert.equal(rec.verifiersReleased.length, n - 1, 'one verifier per handed-over window');
    assert.equal(rec.serialReleaseBeforeNextAllocation, true);
    assert.equal(rec.verifierLive.helperLinuxPid, 9000);
    // THE SESSION TOTAL, not only the window counter a rotation resets.
    assert.equal(rec.sharesAcceptedTotal, 14);
    assert.equal(rec.sharesAcceptedCurrentWindow, 2);
    assert.equal(rec.cumulativeAttempts, n * REAL_SEARCH_LIMITS.maxAttempts);
    assert.equal(rec.sessionDeadlineAtMs, 1_234_000);
    assert.equal(rec.terminalReason, 'search_bound_reached');
    assert.equal(rec.blockClaimed, false);
    // NOTHING SENSITIVE: the browser context is represented by fixed-size identities/digests, never
    // the raw hashing template or full block material.
    const text = JSON.stringify(rec);
    for (const f of ['hashingTemplateHex', 'fullBlockHex', 'blocktemplate_blob', 'private']) {
      assert.equal(text.includes(f), false, `the record carries raw/sensitive field ${f}`);
    }
  }
});

test('RUNNER EVIDENCE: a block on a later window is recorded as a claim', () => {
  const refreshEvidence = liftPureFunction(runnerSource(), 'refreshEvidence');
  const rec = refreshEvidence({
    requestedWindows: 3,
    windowRecords: windowRecordsFor(3),
    sessionFacts: facts({ sharesAccepted: 1, sharesAcceptedTotal: 9 }),
    verifierHistory: releasedVerifiers(2),
    currentVerifier: null,
    attemptState: 'terminal_complete',
    attemptReason: null,
    submitBlockCount: 1,
    calcPowCount: 1,
    cumulativeAttempts: 20_000,
  });
  assert.equal(rec.blockClaimed, true);
  assert.equal(rec.daemonSubmitBlock, 1);
  assert.equal(rec.daemonCalcPow, 1);
  assert.equal(rec.attemptState, 'terminal_complete');
  assert.equal(rec.windowsIssued, 3, 'the block window is not recorded');
  assert.equal(rec.verifierLive, null);
});

test('RUNNER EVIDENCE: unknown facts stay unknown and never collapse to zero', () => {
  const refreshEvidence = liftPureFunction(runnerSource(), 'refreshEvidence');
  // A closed socket disposed the session: there are no session facts to read at all.
  const rec = refreshEvidence({
    requestedWindows: 2,
    windowRecords: windowRecordsFor(2),
    sessionFacts: [],
    verifierHistory: [],
    currentVerifier: null,
    attemptState: 'terminal_cancelled',
    attemptReason: 'session_dispose',
    submitBlockCount: null,
    calcPowCount: null,
    cumulativeAttempts: null,
  });
  assert.equal(rec.sharesAcceptedTotal, null, 'an unknown share total was reported as zero');
  assert.equal(rec.sharesAcceptedCurrentWindow, null);
  assert.equal(rec.cumulativeAttempts, null);
  assert.equal(rec.sessionDeadlineAtMs, null);
  assert.equal(rec.blockClaimed, null, 'an unknown block claim was reported as false');
  assert.equal(rec.daemonSubmitBlock, null);
  // The releases cannot be proved when nothing was recorded.
  assert.equal(rec.serialReleaseBeforeNextAllocation, false);

  // An unconfirmed release is not a proof of serial release either.
  const unconfirmed = refreshEvidence({
    requestedWindows: 2,
    windowRecords: windowRecordsFor(2),
    sessionFacts: facts(),
    verifierHistory: releasedVerifiers(1).map((v) => ({ ...v, closed: false })),
    currentVerifier: null,
    attemptState: 'terminal_failed',
    attemptReason: 'verifier_release_unconfirmed',
    submitBlockCount: 0,
    calcPowCount: 0,
    cumulativeAttempts: 8192,
  });
  assert.equal(unconfirmed.serialReleaseBeforeNextAllocation, false);
  assert.equal(unconfirmed.terminalReason, 'verifier_release_unconfirmed');

  // Overlapping windows are reported as not disjoint rather than quietly accepted.
  const overlapping = refreshEvidence({
    requestedWindows: 2,
    windowRecords: [
      { window: 1, jobId: 'a', issuanceId: '1'.repeat(32), nonceStart: 0, nonceRange: 8192 },
      { window: 2, jobId: 'b', issuanceId: '2'.repeat(32), nonceStart: 8191, nonceRange: 8192 },
    ],
    sessionFacts: facts(),
    verifierHistory: releasedVerifiers(1),
    currentVerifier: null,
    attemptState: 'terminal_cancelled',
    attemptReason: 'search_bound_reached',
    submitBlockCount: 0,
    calcPowCount: 0,
    cumulativeAttempts: 16_000,
  });
  assert.equal(overlapping.disjointWindows, false);
});

test('RUNNER EVIDENCE: a legacy one-window run records nothing new, and nothing is overwritten', () => {
  const src = runnerSource();
  const refreshEvidence = liftPureFunction(src, 'refreshEvidence');
  // No opt-in: no record at all, so the legacy evidence document is exactly what it was.
  assert.equal(refreshEvidence({ requestedWindows: null, windowRecords: [], sessionFacts: [] }), null);
  assert.equal(refreshEvidence({ requestedWindows: 1, windowRecords: [], sessionFacts: [] }), null);

  // It is attached beside the share facts, never in place of them, and only for an opt-in run.
  assert.ok(src.includes('let refreshRecord = null;\n    if (refreshWindows !== null) {\n      refreshRecord = refreshEvidence({'),
    'the refresh record is not attached conditionally');
  assert.ok(src.includes('evidence.refresh = refreshRecord;'));
  assert.equal(src.includes('evidence = refreshRecord'), false);
  assert.ok(src.includes("note('SHARE RUN (server-side facts)'"), 'the share facts were replaced');
  // The publication remains the exclusive, no-replace one.
  assert.ok(src.includes('write: (candidate) => persistJsonAtomically(candidate, evidence, { expect, noReplace: true }),'));
  assert.equal(/rmSync\([^)]*evidence/i.test(src), false, 'the runner removes an evidence file');
  // The requested total is recorded in the reservation and in the evidence header.
  assert.ok(src.includes('refreshWindowsRequested: refreshWindows,'));
  assert.equal(src.split('refreshWindowsRequested: refreshWindows,').length - 1, 2,
    'the requested total is not recorded in both the reservation and the evidence');
});

// ================================================================== the serial-release proof, from timestamps
test('RUNNER EVIDENCE: serial release is proved from release-vs-allocation order, never assumed', () => {
  const refreshEvidence = liftPureFunction(runnerSource(), 'refreshEvidence');
  const base = {
    requestedWindows: 3,
    sessionFacts: facts(),
    currentVerifier: { helperLinuxPid: 9000, helperSourceId: 'a'.repeat(64), context: { height: '1' }, closed: false },
    attemptState: 'terminal_cancelled',
    attemptReason: 'search_bound_reached',
    submitBlockCount: 0,
    calcPowCount: 0,
    cumulativeAttempts: 24_576,
  };

  // ONE ISSUED WINDOW HAS NO RELEASE/NEXT-ALLOCATION RELATIONSHIP TO PROVE. It is not true and not
  // false: the question is not applicable until a successor was actually issued.
  assert.equal(refreshEvidence({
    ...base,
    windowRecords: windowRecordsFor(1),
    verifierHistory: [],
  }).serialReleaseBeforeNextAllocation, null);

  // ORDERED: every predecessor's release was confirmed no later than its successor's allocation.
  assert.equal(refreshEvidence({
    ...base,
    windowRecords: windowRecordsFor(3),
    verifierHistory: releasedVerifiers(2),
  }).serialReleaseBeforeNextAllocation, true, 'an ordered run was not proved serial');

  // RELEASE AFTER THE NEXT ALLOCATION: the predecessor was released too late. A count of closed
  // releases used to call this serial; the timestamps must not.
  assert.equal(refreshEvidence({
    ...base,
    windowRecords: windowRecordsFor(3),
    verifierHistory: releasedVerifiers(2, { releasedAt: (i) => (i === 0 ? 1600 : 900 + i * 100) }),
  }).serialReleaseBeforeNextAllocation, false, 'a release after the successor allocation was proved serial');

  // A release timestamp cannot precede the allocation of the verifier it supposedly released.
  assert.equal(refreshEvidence({
    ...base,
    windowRecords: windowRecordsFor(3),
    verifierHistory: releasedVerifiers(2, { releasedAt: (i) => (i === 0 ? 999 : 1050 + i * 100) }),
  }).serialReleaseBeforeNextAllocation, false, 'a release before its own allocation was proved serial');

  // Position alone is not identity: the release must name the exact predecessor capability and
  // context height whose record precedes the successor.
  assert.equal(refreshEvidence({
    ...base,
    windowRecords: windowRecordsFor(3),
    verifierHistory: releasedVerifiers(2).map((v, i) => (i === 0 ? { ...v, jobId: 'foreign-job' } : v)),
  }).serialReleaseBeforeNextAllocation, false, 'a release for another job was proved serial');
  assert.equal(refreshEvidence({
    ...base,
    windowRecords: windowRecordsFor(3),
    verifierHistory: releasedVerifiers(2).map((v, i) => (i === 0 ? { ...v, context: { height: '2' } } : v)),
  }).serialReleaseBeforeNextAllocation, false, 'a release for another height was proved serial');

  // A MISSING TIMESTAMP ON EITHER SIDE IS UNKNOWN, never a silent proof.
  const noAllocationStamp = refreshEvidence({
    ...base,
    windowRecords: windowRecordsFor(3).map((w, i) => (i === 1 ? { ...w, verifierAllocationStartedAtMs: undefined } : w)),
    verifierHistory: releasedVerifiers(2),
  });
  assert.equal(noAllocationStamp.serialReleaseBeforeNextAllocation, null,
    'a missing allocation timestamp was read as a proof');
  const noReleaseStamp = refreshEvidence({
    ...base,
    windowRecords: windowRecordsFor(3),
    verifierHistory: releasedVerifiers(2).map((v, i) => (i === 1 ? { ...v, releasedAtMs: null } : v)),
  });
  assert.equal(noReleaseStamp.serialReleaseBeforeNextAllocation, null,
    'a missing release timestamp was read as a proof');

  // AN OUT-OF-ORDER PAIR OUTWEIGHS A MISSING ONE: a provable violation is reported as false even
  // when another pair cannot be read.
  assert.equal(refreshEvidence({
    ...base,
    windowRecords: windowRecordsFor(3).map((w, i) => (i === 2 ? { ...w, verifierAllocationStartedAtMs: undefined } : w)),
    verifierHistory: releasedVerifiers(2, { releasedAt: (i) => (i === 0 ? 2000 : 900 + i * 100) }),
  }).serialReleaseBeforeNextAllocation, false);

  // What the runtime persisted about each retired window reaches the record; what it did not is
  // labelled null, not invented.
  const withOutcomes = refreshEvidence({
    ...base,
    windowRecords: windowRecordsFor(3),
    verifierHistory: releasedVerifiers(2),
    sessionFacts: facts({ windowOutcomes: [
      { window: 1, outcome: 'window_exhausted', sharesAccepted: 2, candidatesAdmitted: 2, invalidCandidates: 0 },
      { window: 2, outcome: 'window_exhausted', sharesAccepted: 1, candidatesAdmitted: 1, invalidCandidates: 0 },
    ] }),
  });
  assert.deepEqual(withOutcomes.windows.map((w) => w.outcome),
    ['window_exhausted', 'window_exhausted', null]);
});

test('RUNNER HANDOFF PROBE OUTCOME: only a real two-window handoff passes', () => {
  const classify = liftPureFunction(runnerSource(), 'classifyRefreshHandoffProbeOutcome');
  const assess = (input) => classify({
    expectedShareDifficulty: 1,
    expectedBlockDifficulty: 500,
    expectedShareTargetHexLE: PROBE_SHARE_TARGET,
    expectedBlockTargetHexLE: PRIVATE_BLOCK_TARGET,
    expectedNonceRange: REAL_SEARCH_LIMITS.maxAttempts,
    windowOneFacts: {
      window: 1,
      outcome: 'window_exhausted',
      sharesAccepted: 8,
      candidatesAdmitted: 8,
      invalidCandidates: 0,
    },
    expectedShareCap: 8,
    provenShareCount: 16,
    pageAcceptedShares: 16,
    agreement: { agreed: true, hashHexLE: 'b'.repeat(64) },
    ...input,
  });
  const record = {
    requestedWindows: 2,
    windowsIssued: 2,
    disjointWindows: true,
    serialReleaseBeforeNextAllocation: true,
    windows: windowRecordsFor(2).map((w, i) => ({
      ...w,
      height: '1',
      shareDifficulty: 1,
      blockDifficulty: 500,
      outcome: i === 0 ? 'window_exhausted' : null,
    })),
    blockClaimed: false,
    daemonCalcPow: 0,
    daemonSubmitBlock: 0,
  };
  const commonBinding = { clientStartId: 'c'.repeat(32), workerId: 'sim-1' };
  const binding1 = {
    ...commonBinding,
    window: 1,
    jobId: record.windows[0].jobId,
    issuanceId: record.windows[0].issuanceId,
    runGeneration: 1,
    jobFacts: {
      shareWork: true,
      jobId: record.windows[0].jobId,
      issuanceId: record.windows[0].issuanceId,
      height: record.windows[0].height,
      nonceStart: record.windows[0].nonceStart,
      nonceRange: record.windows[0].nonceRange,
      shareTargetHexLE: record.windows[0].shareTargetHexLE,
      blockTargetHexLE: record.windows[0].blockTargetHexLE,
      contentDigest: record.windows[0].contentDigest,
      epochKeyHex: record.windows[0].epochKeyHex,
      seedHashHex: record.windows[0].seedHashHex,
      hashingTemplateSha256: record.windows[0].hashingTemplateSha256,
    },
  };
  const binding2 = {
    ...commonBinding,
    window: 2,
    jobId: record.windows[1].jobId,
    issuanceId: record.windows[1].issuanceId,
    runGeneration: 2,
    jobFacts: {
      shareWork: true,
      height: record.windows[1].height,
      nonceStart: record.windows[1].nonceStart,
      nonceRange: record.windows[1].nonceRange,
      shareTargetHexLE: record.windows[1].shareTargetHexLE,
      blockTargetHexLE: record.windows[1].blockTargetHexLE,
      jobId: record.windows[1].jobId,
      issuanceId: record.windows[1].issuanceId,
      contentDigest: record.windows[1].contentDigest,
      epochKeyHex: record.windows[1].epochKeyHex,
      seedHashHex: record.windows[1].seedHashHex,
      hashingTemplateSha256: record.windows[1].hashingTemplateSha256,
    },
  };
  const boundTo2 = Object.fromEntries(
    ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration', 'window']
      .map((field) => [field, binding2[field]]),
  );
  const frameBase = {
    captured: true,
    truncated: false,
    bindings: [binding1, binding2],
    shares: [{
      type: 'share_accepted', window: 2, nonce: REAL_SEARCH_LIMITS.maxAttempts,
      hashHexLE: 'a'.repeat(64), boundTo: boundTo2,
    }],
    blocks: [],
  };

  assert.equal(assess({ enabled: false, refreshRecord: null, frames: null, shareOutcome: 'anything' }), null,
    'absence changed ordinary outcome semantics');
  assert.equal(assess({
    enabled: true,
    refreshRecord: { requestedWindows: 2, windowsIssued: 1, blockClaimed: true, windows: [{}] },
    frames: { bindings: [{ window: 1 }], shares: [], blocks: [{ window: 1 }] },
    shareOutcome: 'SHARE_RUN_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B_AFTER_1_ACCEPTED_SHARES',
  }), 'HANDOFF_PROBE_EARLY_BLOCK_ACCEPTED_HANDOFF_NOT_EXERCISED');
  assert.equal(assess({
    enabled: true, refreshRecord: record, frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'HANDOFF_PROBE_EXERCISED_BOUNDED_NO_BLOCK');
  assert.equal(assess({
    enabled: true,
    refreshRecord: record,
    frames: {
      ...frameBase,
      bindings: [binding1, { ...binding2, jobId: 'unrelated-window-two-job' }],
    },
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_binding_chain_not_proved',
  'a binding unrelated to the server window record passed');
  assert.equal(assess({
    enabled: true,
    refreshRecord: record,
    frames: {
      ...frameBase,
      bindings: [binding1, { ...binding2, jobFacts: { ...binding2.jobFacts, height: '2' } }],
    },
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_browser_window_two_facts_mismatch',
  'a browser transition for the wrong height passed');
  assert.equal(assess({
    enabled: true,
    refreshRecord: record,
    frames: {
      ...frameBase,
      bindings: [binding1, { ...binding2, jobFacts: {
        ...binding2.jobFacts, shareTargetHexLE: '0'.repeat(64),
      } }],
    },
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_browser_window_two_facts_mismatch',
  'a browser transition with another target passed');
  assert.equal(assess({
    enabled: true,
    refreshRecord: record,
    frames: {
      ...frameBase,
      shares: frameBase.shares.map((frame) => ({
        ...frame, boundTo: { ...frame.boundTo, issuanceId: 'f'.repeat(32) },
      })),
    },
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_window_two_hash_not_proved',
  'a result bound to another issuance passed');
  assert.equal(assess({
    enabled: true,
    refreshRecord: record,
    frames: {
      ...frameBase,
      shares: frameBase.shares.map((frame) => ({
        ...frame, nonce: 2 * REAL_SEARCH_LIMITS.maxAttempts,
      })),
    },
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_window_two_hash_not_proved',
  'a result at the exclusive end of window 2 passed');
  assert.equal(assess({
    enabled: true,
    refreshRecord: { ...record, blockClaimed: true, daemonCalcPow: 1, daemonSubmitBlock: 1 },
    frames: { ...frameBase, shares: [], blocks: [{
      type: 'block_accepted', window: 2, nonce: REAL_SEARCH_LIMITS.maxAttempts,
      hashHexLE: 'b'.repeat(64), blockId: 'b'.repeat(64), boundTo: boundTo2,
    }] },
    shareOutcome: 'SHARE_RUN_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B_AFTER_8_ACCEPTED_SHARES',
    provenShareCount: 8,
    pageAcceptedShares: 8,
    agreement: { agreed: true, hashHexLE: 'b'.repeat(64) },
  }), 'HANDOFF_PROBE_EXERCISED_WINDOW_2_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B');
  assert.equal(assess({
    enabled: true,
    refreshRecord: { ...record, blockClaimed: true, daemonCalcPow: 1, daemonSubmitBlock: 1 },
    frames: { ...frameBase, shares: [], blocks: [{
      type: 'block_accepted', window: 2, nonce: REAL_SEARCH_LIMITS.maxAttempts,
      hashHexLE: 'b'.repeat(64), blockId: 'b'.repeat(64), boundTo: boundTo2,
    }] },
    shareOutcome: 'SHARE_RUN_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B_AFTER_7_ACCEPTED_SHARES',
    provenShareCount: 7,
    pageAcceptedShares: 7,
    agreement: { agreed: true, hashHexLE: 'b'.repeat(64) },
  }), 'FAILED:handoff_probe_cumulative_share_count_not_proved',
  'a window-2 block passed without the separately proved eight-share window-1 cap in the cumulative count');
  assert.equal(assess({
    enabled: true, refreshRecord: record, frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_SHARE_COUNT_UNPROVEN_frames',
    provenShareCount: null,
  }), 'FAILED:handoff_probe_cumulative_share_count_not_proved',
  'an unproved cumulative count passed merely because a window-2 frame existed');
  assert.equal(assess({
    enabled: true, refreshRecord: record, frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_8_ACCEPTED_SHARES_0_CALC_POW',
    provenShareCount: 8,
    pageAcceptedShares: 8,
  }), 'FAILED:handoff_probe_cumulative_share_count_not_proved',
  'window-1 shares alone were mistaken for proof that window 2 hashed');
  assert.equal(assess({
    enabled: true, refreshRecord: record, frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
    pageAcceptedShares: null,
  }), 'FAILED:handoff_probe_page_acceptance_not_reconciled',
  'a missing page-owned accepted-share count passed');
  assert.equal(assess({
    enabled: true, refreshRecord: record, frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
    pageAcceptedShares: 15,
  }), 'FAILED:handoff_probe_page_acceptance_not_reconciled',
  'a page/server accepted-share mismatch passed');
  assert.equal(assess({
    enabled: true, refreshRecord: record, frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
    pageAcceptedShares: 17,
  }), 'FAILED:handoff_probe_page_acceptance_not_reconciled',
  'a page accepted-share overcount passed');
  assert.equal(assess({
    enabled: true,
    refreshRecord: record,
    frames: {
      ...frameBase,
      bindings: [{
        ...binding1,
        jobFacts: { ...binding1.jobFacts, contentDigest: '0'.repeat(64) },
      }, binding2],
    },
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_browser_window_one_facts_mismatch',
  'an initial browser job with different block content passed');
  assert.equal(assess({
    enabled: true,
    refreshRecord: record,
    frames: {
      ...frameBase,
      bindings: [binding1, {
        ...binding2,
        jobFacts: { ...binding2.jobFacts, epochKeyHex: '0'.repeat(64) },
      }],
    },
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_browser_window_two_facts_mismatch',
  'a window-2 browser job with a different epoch passed');
  assert.equal(assess({
    enabled: true,
    refreshRecord: record,
    frames: {
      ...frameBase,
      bindings: [binding1, {
        ...binding2,
        jobFacts: { ...binding2.jobFacts, hashingTemplateSha256: '0'.repeat(64) },
      }],
    },
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_browser_window_two_facts_mismatch',
  'a window-2 browser job with different hashing bytes passed');
  assert.equal(assess({
    enabled: true,
    refreshRecord: { ...record, blockClaimed: true, daemonCalcPow: 1, daemonSubmitBlock: 1 },
    frames: { ...frameBase, shares: [], blocks: [{
      type: 'block_accepted', window: 2, nonce: REAL_SEARCH_LIMITS.maxAttempts,
      hashHexLE: 'b'.repeat(64), blockId: 'b'.repeat(64), boundTo: boundTo2,
    }] },
    shareOutcome: 'SHARE_RUN_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B_AFTER_8_ACCEPTED_SHARES',
    provenShareCount: 8,
    pageAcceptedShares: 8,
    agreement: { agreed: true, hashHexLE: 'c'.repeat(64) },
  }), 'FAILED:handoff_probe_block_evidence_inconsistent',
  'a block frame whose hash disagreed with the independent hash agreement passed');
  assert.equal(assess({
    enabled: true,
    refreshRecord: { ...record, blockClaimed: true, daemonCalcPow: 1, daemonSubmitBlock: 1 },
    frames: { ...frameBase, shares: [], blocks: [
      {
        type: 'block_accepted', window: 2, nonce: REAL_SEARCH_LIMITS.maxAttempts,
        hashHexLE: 'b'.repeat(64), blockId: 'b'.repeat(64), boundTo: boundTo2,
      },
      {
        type: 'block_accepted', window: 2, nonce: REAL_SEARCH_LIMITS.maxAttempts + 1,
        hashHexLE: 'c'.repeat(64), blockId: 'c'.repeat(64), boundTo: boundTo2,
      },
    ] },
    shareOutcome: 'SHARE_RUN_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B_AFTER_9_ACCEPTED_SHARES',
    provenShareCount: 9,
    pageAcceptedShares: 9,
  }), 'FAILED:handoff_probe_block_evidence_inconsistent',
  'multiple block frames passed as a single block');
  assert.equal(assess({
    enabled: true,
    refreshRecord: record,
    frames: { ...frameBase, blocks: [{
      type: 'block_accepted', window: 1, nonce: 0, blockId: 'd'.repeat(64),
      hashHexLE: 'd'.repeat(64),
      boundTo: Object.fromEntries(
        ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration', 'window']
          .map((field) => [field, binding1[field]]),
      ),
    }] },
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_no_block_evidence_inconsistent',
  'a bounded-no-block outcome coexisted with a block frame');
  assert.equal(assess({
    enabled: true,
    refreshRecord: { ...record, serialReleaseBeforeNextAllocation: null },
    frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_serial_release_not_proved');
  assert.equal(assess({
    enabled: true, refreshRecord: record,
    frames: { ...frameBase, shares: [], blocks: [] },
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_8_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_window_two_hash_not_proved');
  assert.equal(assess({
    enabled: true, frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
    refreshRecord: {
      ...record,
      windows: record.windows.map((w, i) => (i === 0 ? { ...w, shareDifficulty: 100 } : w)),
    },
  }), 'FAILED:handoff_probe_window_runtime_facts_mismatch',
  'window 2 alone was allowed to stand in for a wrong window 1');
  assert.equal(assess({
    enabled: true,
    refreshRecord: {
      ...record,
      windows: record.windows.map((w, i) => (i === 1 ? { ...w, blockDifficulty: 499 } : w)),
    },
    frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_window_runtime_facts_mismatch');
  assert.equal(assess({
    enabled: true,
    refreshRecord: {
      ...record,
      windows: record.windows.map((w, i) => (i === 0 ? { ...w, shareTargetHexLE: '0'.repeat(64) } : w)),
    },
    frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_window_runtime_facts_mismatch');
  assert.equal(assess({
    enabled: true,
    refreshRecord: {
      ...record,
      windows: record.windows.map((w, i) => (i === 1 ? { ...w, blockTargetHexLE: '0'.repeat(64) } : w)),
    },
    frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_window_runtime_facts_mismatch');
  assert.equal(assess({
    enabled: true,
    refreshRecord: { ...record, windows: record.windows.map((w, i) => (i === 1 ? { ...w, height: '2' } : w)) },
    frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_same_height_not_proved');
  assert.equal(assess({
    enabled: true,
    refreshRecord: {
      ...record,
      disjointWindows: false,
      windows: record.windows.map((w, i) => (i === 1
        ? { ...w, nonceStart: REAL_SEARCH_LIMITS.maxAttempts - 1 }
        : w)),
    },
    frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_unexpected_nonce_windows', 'a partial nonce-range overlap passed');
  assert.equal(assess({
    enabled: true,
    refreshRecord: record,
    frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_15_ACCEPTED_SHARES_0_CALC_POW',
    windowOneFacts: {
      window: 1, outcome: 'window_exhausted', sharesAccepted: 7, candidatesAdmitted: 8,
      invalidCandidates: 0,
    },
  }), 'FAILED:handoff_probe_first_window_cap_not_proved');
  assert.equal(assess({
    enabled: true, refreshRecord: record, frames: { ...frameBase, truncated: true },
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
  }), 'FAILED:handoff_probe_frame_capture_incomplete');
  assert.equal(assess({
    enabled: true,
    refreshRecord: { ...record, daemonCalcPow: 1 },
    frames: frameBase,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_1_CALC_POW',
  }), 'FAILED:handoff_probe_no_block_evidence_inconsistent');
  assert.equal(assess({
    enabled: true,
    refreshRecord: { ...record, blockClaimed: true, daemonCalcPow: 1, daemonSubmitBlock: 1 },
    frames: frameBase,
    shareOutcome: 'SHARE_RUN_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B_AFTER_9_ACCEPTED_SHARES',
    provenShareCount: 9,
    pageAcceptedShares: 9,
  }), 'FAILED:handoff_probe_block_evidence_inconsistent');
});

test('RUNNER HANDOFF PROBE ISOLATION: ordinary event/evidence shape is unchanged and success needs exercise', () => {
  const src = runnerSource();
  const modeFacts = liftPureFunction(src, 'shareRunModeFacts');
  const probeEvents = liftPureFunction(src, 'shareRunProbeEvents');
  const finalize = liftPureFunction(src, 'finalizeShareRun');

  // This is the historical ordinary object after JSON persistence: its undefined generic share
  // fields are omitted, while the fixed block-difficulty field remains exactly as before.
  const ordinaryFacts = JSON.parse(JSON.stringify(modeFacts({
    probe: false,
    legacyShareWork: undefined,
    legacyShareDifficulty: undefined,
    fixedBlockDifficulty: 500,
    profileShareWork: true,
    jobShareDifficulty: 1,
    jobBlockDifficulty: 500,
  })));
  assert.deepEqual(ordinaryFacts, { blockDifficulty: 500 });
  assert.equal('shareWork' in ordinaryFacts, false);
  assert.equal('shareDifficulty' in ordinaryFacts, false);
  assert.deepEqual(probeEvents({ probe: false, shareOutcome: 'ordinary', handoffProbeOutcome: 'probe' }), [],
    'ordinary transcript gained probe-only event labels');

  const probeFacts = modeFacts({
    probe: true,
    legacyShareWork: undefined,
    legacyShareDifficulty: undefined,
    fixedBlockDifficulty: 500,
    profileShareWork: true,
    jobShareDifficulty: 1,
    jobBlockDifficulty: 500,
  });
  assert.deepEqual(probeFacts, { shareWork: true, shareDifficulty: 1, blockDifficulty: 500 });
  assert.deepEqual(probeEvents({ probe: true, shareOutcome: 'underlying', handoffProbeOutcome: 'handoff' }), [
    ['UNDERLYING SHARE/BLOCK OUTCOME', 'underlying'],
    ['HANDOFF PROBE OUTCOME', 'handoff'],
  ]);

  const ordinary = finalize({
    probe: false, shareOutcome: 'SHARE_RUN_BLOCK_ACCEPTED_OK', handoffProbeOutcome: null,
    okCode: 0, failedCode: 1,
  });
  assert.equal(ordinary.exitCode, 0);
  assert.deepEqual(ordinary.evidenceFields, {}, 'ordinary evidence gained probe keys');
  const exercised = finalize({
    probe: true,
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
    handoffProbeOutcome: 'HANDOFF_PROBE_EXERCISED_BOUNDED_NO_BLOCK',
    okCode: 0, failedCode: 1,
  });
  assert.equal(exercised.exitCode, 0);
  assert.deepEqual(exercised.evidenceFields, {
    shareOutcome: 'BOUNDED_OBSERVATION_NO_BLOCK_16_ACCEPTED_SHARES_0_CALC_POW',
    handoffProbeOutcome: 'HANDOFF_PROBE_EXERCISED_BOUNDED_NO_BLOCK',
  }, 'final probe evidence did not retain both meanings');
  const early = finalize({
    probe: true,
    shareOutcome: 'SHARE_RUN_BLOCK_ACCEPTED_OK',
    handoffProbeOutcome: 'HANDOFF_PROBE_EARLY_BLOCK_ACCEPTED_HANDOFF_NOT_EXERCISED',
    okCode: 0, failedCode: 1,
  });
  assert.equal(early.exitCode, 1, 'a real early block incorrectly passed the engineering probe');
});

test('RUNNER HANDOFF PROBE DISCLOSURE: reservation, evidence and pre-Start text state the exact scope', () => {
  const src = runnerSource();
  for (const text of [
    'one private interactive two-daemon same-height refresh-handoff engineering probe',
    'exercise exactly one same-height window-1-to-window-2 handoff',
    'REFRESH HANDOFF PROBE (before Start)',
    'source-fixed share difficulty 1 makes every completed hash a ',
    'qualifying share while block difficulty remains ${PEER_TEST_FIXED_DIFFICULTY}',
    'a genuine block still wins immediately',
    'ONE height; up to ${refreshWindows} serial job/template issuances for that same height',
    '${refreshWindows} job/template issuances of ONE height',
  ]) assert.ok(src.includes(text), `missing probe disclosure: ${text}`);
  assert.equal(src.includes('${blocks} context(s), each on its own fresh template'), false,
    'refresh consent still describes the block count as the issuance count');
  assert.ok(src.includes('...(refreshHandoffProbe ? { refreshHandoffProbe: true, handoffProbeContract: {'),
    'probe evidence is not conditional');
  assert.ok(src.includes('...(refreshHandoffProbe ? { refreshHandoffProbe: true } : {}),'),
    'probe reservation/startup wiring is not conditional');
  for (const text of [
    'windowFacts: refreshRecord?.windows ?? null',
    'expectedNonceRange: REAL_SEARCH_LIMITS.maxAttempts',
    'windowOneFacts: probeWindowOneFacts',
    'boundWindowTwoResult: refreshFrames.shares.some((f) => f.window === 2)',
    'Probe exit 0, if awarded, proves only that the window-1 to window-2 handoff was exercised.',
  ]) assert.ok(src.includes(text), `runtime probe evidence is missing: ${text}`);
});

// ========================================================== the composed sequence-refresh capture
test('RUNNER COMPOSED NEXT: only an accepted, chained next height at window 1 advances', () => {
  const src = runnerSource();
  const refreshBrowserJobFacts = liftPureFunction(src, 'refreshBrowserJobFacts', { createHash });
  const classify = liftPureFunction(src, 'classifyShareSequenceRefreshNext', { refreshBrowserJobFacts });
  const budget = REAL_REFRESH_LIMITS.maxSessionMs;
  const job1 = clientRefreshJob(1);
  const job2 = clientRefreshJob(1, {
    jobId: 'realjob-h2w1', issuanceId: 'a'.repeat(32), height: '2',
  });
  const active = {
    clientStartId: 'b'.repeat(32), workerId: 'sim-1-composed',
    jobId: job1.jobId, issuanceId: job1.issuanceId, runGeneration: 1,
    block: 1, window: 1, jobFacts: refreshBrowserJobFacts(job1),
  };
  const acceptedBlock = {
    block: 1, window: 1,
    boundTo: Object.fromEntries(
      ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration'].map((field) => [field, active[field]]),
    ),
  };
  const next = {
    type: 'sequence_next', cause: 'accepted',
    sequenceIndex: 2, sequenceTotal: 2, windowIndex: 1, windowTotal: 2,
    sessionBudgetMs: budget,
    previous: { jobId: active.jobId, issuanceId: active.issuanceId, runGeneration: active.runGeneration },
    clientStartId: active.clientStartId, workerId: active.workerId,
    jobId: job2.jobId, issuanceId: job2.issuanceId, runGeneration: 2,
    job: job2,
  };

  const accepted = classify({
    frame: next, active, blockTotal: 2, windowTotal: 2, sessionBudgetMs: budget, acceptedBlock,
  });
  assert.equal(accepted.accepted, true);
  assert.equal(accepted.reason, null);
  assert.equal(accepted.jobFacts.height, '2');
  assert.equal(accepted.jobFacts.nonceStart, 0, 'the next height did not restart its nonce space');

  assert.equal(classify({
    frame: next, active, blockTotal: 2, windowTotal: 2, sessionBudgetMs: budget,
    acceptedBlock: { ...acceptedBlock, block: 2 },
  }).reason, 'no_accepted_current_block');
  assert.equal(classify({
    frame: { ...next, previous: { ...next.previous, jobId: 'foreign-job' } },
    active, blockTotal: 2, windowTotal: 2, sessionBudgetMs: budget, acceptedBlock,
  }).reason, 'unchained_previous_binding');
  assert.equal(classify({
    frame: { ...next, job: { ...job2, height: '1' } },
    active, blockTotal: 2, windowTotal: 2, sessionBudgetMs: budget, acceptedBlock,
  }).reason, 'unexpected_next_height_or_window');
  assert.equal(classify({
    frame: { ...next, sessionBudgetMs: budget - 1 },
    active, blockTotal: 2, windowTotal: 2, sessionBudgetMs: budget, acceptedBlock,
  }).reason, 'unexpected_sequence_refresh_transition');
  for (const [label, over] of [
    ['wrong next sequence index', { sequenceIndex: 1 }],
    ['wrong next sequence total', { sequenceTotal: 3 }],
    ['wrong next window index', { windowIndex: 2 }],
    ['wrong next window total', { windowTotal: 3 }],
  ]) {
    assert.equal(classify({
      frame: { ...next, ...over },
      active, blockTotal: 2, windowTotal: 2, sessionBudgetMs: budget, acceptedBlock,
    }).reason, 'unexpected_sequence_refresh_transition', label);
  }
});

test('RUNNER COMPOSED FRAMES: early wins may complete 2x2 with one window per height', () => {
  const capture = liftSequenceRefreshCapture(runnerSource());
  const state = sequenceRefreshFrameState();
  const limit = 50;
  const blockTotal = 2;
  const windowTotal = 2;
  const sessionBudgetMs = REAL_REFRESH_LIMITS.maxSessionMs;
  const job1 = clientRefreshJob(1);
  const job2 = clientRefreshJob(1, {
    jobId: 'realjob-h2w1', issuanceId: 'a'.repeat(32), height: '2',
  });
  const bind1 = {
    clientStartId: 'b'.repeat(32), workerId: 'sim-1-composed',
    jobId: job1.jobId, issuanceId: job1.issuanceId, runGeneration: 1,
  };
  const bind2 = {
    clientStartId: bind1.clientStartId, workerId: bind1.workerId,
    jobId: job2.jobId, issuanceId: job2.issuanceId, runGeneration: 2,
  };
  const accept = (frame) => {
    const verdict = capture({ state, frame, limit, blockTotal, windowTotal, sessionBudgetMs });
    assert.equal(verdict.accepted, true, `${frame.type}: ${verdict.reason}`);
  };
  const ready = (binding, block) => ({
    type: 'mining_ready', ...binding,
    sequenceIndex: block, sequenceTotal: blockTotal,
    windowIndex: 1, windowTotal, sessionBudgetMs,
  });
  const heightBlock = (binding, block, height, hashHexLE, blockId) => ({
    type: 'sequence_block_accepted', ...binding,
    sequenceIndex: block, sequenceTotal: blockTotal,
    height, nonce: 7, hashHexLE, blockId,
  });

  accept(job1);
  accept({ type: 'run_started', ...bind1 });
  accept(ready(bind1, 1));
  const first = heightBlock(bind1, 1, '1', 'c'.repeat(64), 'd'.repeat(64));
  accept(first);
  accept({
    type: 'sequence_next', cause: 'accepted',
    sequenceIndex: 2, sequenceTotal: blockTotal,
    windowIndex: 1, windowTotal, sessionBudgetMs,
    previous: { jobId: bind1.jobId, issuanceId: bind1.issuanceId, runGeneration: bind1.runGeneration },
    job: job2,
    ...bind2,
  });
  accept(ready(bind2, 2));
  const second = heightBlock(bind2, 2, '2', 'e'.repeat(64), 'f'.repeat(64));
  accept(second);
  accept({ type: 'block_accepted', ...bind2, height: '2', nonce: 7,
    hashHexLE: second.hashHexLE, blockId: second.blockId });

  assert.deepEqual(state.bindings.map((binding) => [binding.block, binding.window]), [[1, 1], [2, 1]]);
  assert.deepEqual(state.readiness.map((record) => [record.block, record.window, record.sessionBudgetMs]), [
    [1, 1, sessionBudgetMs], [2, 1, sessionBudgetMs],
  ], 'readiness did not retain the fixed whole-Start budget it validated');
  assert.deepEqual(state.blocks.map((record) => [record.block, record.window, record.nonce]), [
    [1, 1, 7], [2, 1, 7],
  ], 'the same nonce was not retained independently at two heights');
  assert.equal(state.bindings.length, 2, 'an early-win success was incorrectly required to issue all four contexts');
  assert.equal(state.terminalBlocks.length, 1);
  assert.equal(state.rejectedCount, 0);
});

test('RUNNER COMPOSED FRAMES: canonical 2x2 chain binds all four contexts in order', () => {
  const capture = liftSequenceRefreshCapture(runnerSource());
  const state = sequenceRefreshFrameState();
  const options = {
    state, limit: 50, blockTotal: 2, windowTotal: 2,
    sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs,
  };
  const jobs = [
    clientRefreshJob(1),
    clientRefreshJob(2),
    clientRefreshJob(1, { jobId: 'realjob-h2w1', issuanceId: 'a'.repeat(32), height: '2' }),
    clientRefreshJob(2, { jobId: 'realjob-h2w2', issuanceId: 'b'.repeat(32), height: '2' }),
  ];
  const bindings = jobs.map((job, index) => ({
    clientStartId: 'b'.repeat(32), workerId: 'sim-1-composed',
    jobId: job.jobId, issuanceId: job.issuanceId, runGeneration: index + 1,
  }));
  const accept = (frame) => {
    const verdict = capture({ ...options, frame });
    assert.equal(verdict.accepted, true, `${frame.type}: ${verdict.reason}`);
  };
  const ready = (binding, block, window) => ({
    type: 'mining_ready', ...binding,
    sequenceIndex: block, sequenceTotal: 2, windowIndex: window, windowTotal: 2,
    sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs,
  });
  const refresh = (from, to, job, block) => ({
    type: 'job_refresh', terminal: false, cause: 'window_exhausted',
    sequenceIndex: block, sequenceTotal: 2, windowIndex: 2, windowTotal: 2,
    previous: { jobId: from.jobId, issuanceId: from.issuanceId, runGeneration: from.runGeneration },
    job,
    ...to,
  });
  const heightBlock = (binding, block, height, hashHexLE, blockId) => ({
    type: 'sequence_block_accepted', ...binding,
    sequenceIndex: block, sequenceTotal: 2,
    height, nonce: REAL_SEARCH_LIMITS.maxAttempts + 7, hashHexLE, blockId,
  });

  accept(jobs[0]);
  accept({ type: 'run_started', ...bindings[0] });
  accept(ready(bindings[0], 1, 1));
  accept(refresh(bindings[0], bindings[1], jobs[1], 1));
  accept(ready(bindings[1], 1, 2));
  const first = heightBlock(bindings[1], 1, '1', 'c'.repeat(64), 'd'.repeat(64));
  accept(first);
  accept({
    type: 'sequence_next', cause: 'accepted',
    sequenceIndex: 2, sequenceTotal: 2, windowIndex: 1, windowTotal: 2,
    sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs,
    previous: {
      jobId: bindings[1].jobId,
      issuanceId: bindings[1].issuanceId,
      runGeneration: bindings[1].runGeneration,
    },
    job: jobs[2],
    ...bindings[2],
  });
  accept(ready(bindings[2], 2, 1));
  accept(refresh(bindings[2], bindings[3], jobs[3], 2));
  accept(ready(bindings[3], 2, 2));
  const second = heightBlock(bindings[3], 2, '2', 'e'.repeat(64), 'f'.repeat(64));
  accept(second);
  accept({ type: 'block_accepted', ...bindings[3], height: '2', nonce: second.nonce,
    hashHexLE: second.hashHexLE, blockId: second.blockId });

  assert.deepEqual(state.bindings.map((binding) => [binding.block, binding.window]), [
    [1, 1], [1, 2], [2, 1], [2, 2],
  ]);
  assert.deepEqual(state.readiness.map((record) => [record.block, record.window, record.sessionBudgetMs]), [
    [1, 1, REAL_REFRESH_LIMITS.maxSessionMs],
    [1, 2, REAL_REFRESH_LIMITS.maxSessionMs],
    [2, 1, REAL_REFRESH_LIMITS.maxSessionMs],
    [2, 2, REAL_REFRESH_LIMITS.maxSessionMs],
  ]);
  assert.deepEqual(state.blocks.map((record) => [record.block, record.window]), [[1, 2], [2, 2]]);
  assert.equal(state.terminalBlocks.length, 1);
  assert.equal(state.rejectedCount, 0);
});

test('RUNNER COMPOSED FRAMES: budget and two-dimensional coordinates fail closed without advancing', () => {
  const capture = liftSequenceRefreshCapture(runnerSource());
  const budget = REAL_REFRESH_LIMITS.maxSessionMs;
  const options = { limit: 50, blockTotal: 2, windowTotal: 2, sessionBudgetMs: budget };
  const job1 = clientRefreshJob(1);
  const job2 = clientRefreshJob(2);
  const bind1 = {
    clientStartId: 'b'.repeat(32), workerId: 'sim-1-composed',
    jobId: job1.jobId, issuanceId: job1.issuanceId, runGeneration: 1,
  };
  const bind2 = {
    ...bind1, jobId: job2.jobId, issuanceId: job2.issuanceId, runGeneration: 2,
  };
  const ready = (over = {}) => ({
    type: 'mining_ready', ...bind1,
    sequenceIndex: 1, sequenceTotal: 2, windowIndex: 1, windowTotal: 2,
    sessionBudgetMs: budget, ...over,
  });
  const refresh = (over = {}) => ({
    type: 'job_refresh', terminal: false, cause: 'window_exhausted',
    sequenceIndex: 1, sequenceTotal: 2, windowIndex: 2, windowTotal: 2,
    previous: { jobId: bind1.jobId, issuanceId: bind1.issuanceId, runGeneration: 1 },
    job: job2, ...bind2, ...over,
  });

  for (const [label, readyFrame] of [
    ['missing readiness budget', (() => {
      const frame = ready();
      delete frame.sessionBudgetMs;
      return frame;
    })()],
    ['wrong readiness budget', ready({ sessionBudgetMs: budget - 1 })],
  ]) {
    const state = sequenceRefreshFrameState();
    assert.equal(capture({ ...options, state, frame: job1 }).accepted, true);
    assert.equal(capture({ ...options, state, frame: { type: 'run_started', ...bind1 } }).accepted, true);
    const verdict = capture({ ...options, state, frame: readyFrame });
    assert.equal(verdict.accepted, false, `${label} was accepted`);
    assert.equal(verdict.reason, 'ready_wrong_context_binding', label);
    assert.equal(state.readiness.length, 0, `${label} was retained as evidence`);
    assert.equal(state.activeBinding.jobId, bind1.jobId, `${label} advanced the binding`);
  }

  for (const [label, over] of [
    ['wrong job_refresh sequence index', { sequenceIndex: 2 }],
    ['wrong job_refresh sequence total', { sequenceTotal: 3 }],
  ]) {
    const state = sequenceRefreshFrameState();
    assert.equal(capture({ ...options, state, frame: job1 }).accepted, true);
    assert.equal(capture({ ...options, state, frame: { type: 'run_started', ...bind1 } }).accepted, true);
    assert.equal(capture({ ...options, state, frame: ready() }).accepted, true);
    const verdict = capture({ ...options, state, frame: refresh(over) });
    assert.equal(verdict.accepted, false, `${label} was accepted`);
    assert.equal(verdict.reason, 'refresh_wrong_sequence_coordinate', label);
    assert.equal(state.bindings.length, 1, `${label} advanced the binding`);
    assert.equal(state.activeBinding.jobId, bind1.jobId, `${label} changed the active job`);
  }
});

test('RUNNER COMPOSED FRAMES: stale prior-height work and a same-context duplicate are quarantined', () => {
  const capture = liftSequenceRefreshCapture(runnerSource());
  const budget = REAL_REFRESH_LIMITS.maxSessionMs;
  const options = { limit: 50, blockTotal: 2, windowTotal: 2, sessionBudgetMs: budget };
  const job1 = clientRefreshJob(1);
  const job2 = clientRefreshJob(1, {
    jobId: 'realjob-h2w1', issuanceId: 'a'.repeat(32), height: '2',
  });
  const bind1 = {
    clientStartId: 'b'.repeat(32), workerId: 'sim-1-composed',
    jobId: job1.jobId, issuanceId: job1.issuanceId, runGeneration: 1,
  };
  const bind2 = {
    clientStartId: bind1.clientStartId, workerId: bind1.workerId,
    jobId: job2.jobId, issuanceId: job2.issuanceId, runGeneration: 2,
  };
  const send = (state, frame) => capture({ ...options, state, frame });
  const state = sequenceRefreshFrameState();
  assert.equal(send(state, job1).accepted, true);
  assert.equal(send(state, { type: 'run_started', ...bind1 }).accepted, true);
  assert.equal(send(state, {
    type: 'mining_ready', ...bind1, sequenceIndex: 1, sequenceTotal: 2,
    windowIndex: 1, windowTotal: 2, sessionBudgetMs: budget,
  }).accepted, true);
  const firstBlock = {
    type: 'sequence_block_accepted', ...bind1, sequenceIndex: 1, sequenceTotal: 2,
    height: '1', nonce: 7, hashHexLE: 'c'.repeat(64), blockId: 'd'.repeat(64),
  };
  assert.equal(send(state, firstBlock).accepted, true);
  assert.equal(send(state, {
    type: 'sequence_next', cause: 'accepted',
    sequenceIndex: 2, sequenceTotal: 2, windowIndex: 1, windowTotal: 2,
    sessionBudgetMs: budget,
    previous: { jobId: bind1.jobId, issuanceId: bind1.issuanceId, runGeneration: 1 },
    job: job2, ...bind2,
  }).accepted, true);
  assert.equal(send(state, {
    type: 'mining_ready', ...bind2, sequenceIndex: 2, sequenceTotal: 2,
    windowIndex: 1, windowTotal: 2, sessionBudgetMs: budget,
  }).accepted, true);

  const stale = send(state, {
    type: 'share_accepted', ...bind1, sequenceIndex: 1, sequenceTotal: 2,
    nonce: 8, hashHexLE: 'e'.repeat(64), sharesAccepted: 1, sharesAcceptedTotal: 1,
  });
  assert.equal(stale.accepted, false);
  assert.equal(stale.reason, 'stale_context_binding');
  assert.equal(state.shares.length, 0, 'the stale prior-height share was counted');

  const current = {
    type: 'share_accepted', ...bind2, sequenceIndex: 2, sequenceTotal: 2,
    nonce: 7, hashHexLE: 'f'.repeat(64), sharesAccepted: 1, sharesAcceptedTotal: 1,
  };
  assert.equal(send(state, current).accepted, true);
  const duplicate = send(state, current);
  assert.equal(duplicate.accepted, false);
  assert.equal(duplicate.reason, 'duplicate_bound_frame');
  assert.deepEqual(state.shares.map((share) => [share.block, share.window, share.nonce]), [[2, 1, 7]]);
});

// ================================================================== the bound refresh frame capture
test('RUNNER REFRESH FRAMES: window 1 and window 2 shares are kept by their own window bindings', () => {
  const capture = liftRefreshCapture(runnerSource());
  const START = 'a'.repeat(32);
  const worker = 'sim-1-bbbb';
  const bind1 = { clientStartId: START, workerId: worker, jobId: 'realjob-w1', issuanceId: '1'.repeat(32), runGeneration: 1 };
  const bind2 = { ...bind1, jobId: 'realjob-w2', issuanceId: '2'.repeat(32), runGeneration: 2 };
  const JOB1 = clientRefreshJob(1);
  const JOB2 = clientRefreshJob(2);
  const s = refreshFrameState();
  const limit = 50;
  beginRefreshCapture(capture, s, bind1, JOB1, 3, limit);
  assert.equal(capture({
    state: s,
    frame: { type: 'share_accepted', ...bind1, nonce: 5, hashHexLE: 'ab'.repeat(32), sharesAccepted: 1, sharesAcceptedTotal: 1 },
    limit, windowTotal: 3,
  }).accepted, true);
  assert.equal(capture({
    state: s,
    frame: {
      type: 'job_refresh', terminal: false, cause: 'window_exhausted',
      windowIndex: 2, windowTotal: 3,
      previous: { jobId: bind1.jobId, issuanceId: bind1.issuanceId, runGeneration: 1 },
      job: JOB2, ...bind2,
    },
    limit, windowTotal: 3,
  }).accepted, true);
  assert.equal(capture({
    state: s,
    frame: { type: 'share_accepted', ...bind2, nonce: REAL_SEARCH_LIMITS.maxAttempts + 7, hashHexLE: 'cd'.repeat(32), sharesAccepted: 1, sharesAcceptedTotal: 2 },
    limit, windowTotal: 3,
  }).accepted, true);
  assert.equal(capture({
    state: s,
    frame: { type: 'block_accepted', ...bind2, nonce: REAL_SEARCH_LIMITS.maxAttempts + 9, blockId: 'ef'.repeat(32), hashHexLE: 'ef'.repeat(32) },
    limit, windowTotal: 3,
  }).accepted, true);

  assert.equal(s.bindings.length, 2);
  assert.deepEqual(s.bindings[0].jobFacts, {
    shareWork: true,
    jobId: JOB1.jobId,
    issuanceId: JOB1.issuanceId,
    height: JOB1.height,
    nonceStart: JOB1.nonceStart,
    nonceRange: JOB1.nonceRange,
    shareTargetHexLE: JOB1.shareTargetHexLE,
    blockTargetHexLE: JOB1.targetHexLE,
    contentDigest: JOB1.contentDigest,
    epochKeyHex: JOB1.epochKeyHex,
    seedHashHex: JOB1.seedHashHex,
    hashingTemplateSha256: createHash('sha256').update(Buffer.from(JOB1.hashingTemplateHex, 'hex')).digest('hex'),
  }, 'run_started did not retain the immutable facts of the initial browser job');
  assert.deepEqual(s.shares.map((x) => [x.window, x.nonce]), [[1, 5], [2, REAL_SEARCH_LIMITS.maxAttempts + 7]]);
  assert.deepEqual(s.blocks.map((x) => [x.window, x.nonce]), [[2, REAL_SEARCH_LIMITS.maxAttempts + 9]]);
  assert.equal(s.blocks[0].boundTo.jobId, bind2.jobId);
  assert.equal(s.rejectedCount, 0);
  // The cumulative reconciliation inputs are the DISTINCT nonces across both windows, and the
  // runner reconciles them against the session's cumulative sharesAcceptedTotal.
  assert.equal(new Set(s.shares.map((x) => x.nonce)).size, 2);
});

test('RUNNER REFRESH FRAMES: run_started cannot invent or substitute the initial browser job', () => {
  const capture = liftRefreshCapture(runnerSource());
  const JOB1 = clientRefreshJob(1);
  const binding = {
    clientStartId: 'a'.repeat(32), workerId: 'sim-1-bbbb',
    jobId: JOB1.jobId, issuanceId: JOB1.issuanceId, runGeneration: 1,
  };
  const limit = 50;

  const absent = refreshFrameState();
  assert.equal(capture({
    state: absent, frame: { type: 'run_started', ...binding }, limit, windowTotal: 2,
  }).reason, 'run_started_without_matching_initial_job');
  assert.equal(absent.activeBinding, null);
  assert.equal(absent.bindings.length, 0);

  const substituted = refreshFrameState();
  assert.equal(capture({ state: substituted, frame: JOB1, limit, windowTotal: 2 }).accepted, true);
  assert.equal(capture({
    state: substituted,
    frame: { type: 'run_started', ...binding, jobId: 'realjob-substitute' },
    limit,
    windowTotal: 2,
  }).reason, 'run_started_without_matching_initial_job');
  assert.equal(substituted.activeBinding, null);
  assert.equal(substituted.bindings.length, 0);
  assert.equal(capture({
    state: substituted, frame: { type: 'run_started', ...binding }, limit, windowTotal: 2,
  }).accepted, true, 'a refused substitution damaged the valid captured initial job');
});

test('RUNNER REFRESH FRAMES: a late prior-window frame is quarantined, never counted for the new window', () => {
  const capture = liftRefreshCapture(runnerSource());
  const START = 'a'.repeat(32);
  const bind1 = { clientStartId: START, workerId: 'sim-1-bbbb', jobId: 'realjob-w1', issuanceId: '1'.repeat(32), runGeneration: 1 };
  const bind2 = { ...bind1, jobId: 'realjob-w2', issuanceId: '2'.repeat(32), runGeneration: 2 };
  const JOB1 = clientRefreshJob(1);
  const JOB2 = clientRefreshJob(2);
  const s = refreshFrameState();
  const limit = 50;
  beginRefreshCapture(capture, s, bind1, JOB1, 2, limit);
  capture({
    state: s,
    frame: {
      type: 'job_refresh', terminal: false, cause: 'window_exhausted', windowIndex: 2, windowTotal: 2,
      previous: { jobId: bind1.jobId, issuanceId: bind1.issuanceId, runGeneration: 1 },
      job: JOB2, ...bind2,
    },
    limit, windowTotal: 2,
  });
  // A share for WINDOW 1 arriving after the handover: it names a binding this run held, so it is
  // quarantined by that name -- not counted, and not mistaken for a forgery either.
  const late = capture({
    state: s, frame: { type: 'share_accepted', ...bind1, nonce: 5, hashHexLE: 'ab'.repeat(32) }, limit, windowTotal: 2,
  });
  assert.equal(late.accepted, false);
  assert.equal(late.reason, 'stale_window_binding');
  assert.equal(s.shares.length, 0, 'a late prior-window share was counted');
  assert.deepEqual(s.rejected.map((r) => r.reason), ['stale_window_binding']);
  // A late prior-window BLOCK frame is quarantined the same way.
  const lateBlock = capture({
    state: s, frame: { type: 'block_accepted', ...bind1, nonce: 9, blockId: 'ef'.repeat(32) }, limit, windowTotal: 2,
  });
  assert.equal(lateBlock.reason, 'stale_window_binding');
  assert.equal(s.blocks.length, 0);
});

test('RUNNER REFRESH FRAMES: a forged or stale job_refresh changes nothing', () => {
  const capture = liftRefreshCapture(runnerSource());
  const START = 'a'.repeat(32);
  const bind1 = { clientStartId: START, workerId: 'sim-1-bbbb', jobId: 'realjob-w1', issuanceId: '1'.repeat(32), runGeneration: 1 };
  const JOB1 = clientRefreshJob(1);
  const JOB2 = clientRefreshJob(2);
  const transition = (over = {}) => ({
    type: 'job_refresh', terminal: false, cause: 'window_exhausted',
    windowIndex: 2, windowTotal: 3,
    previous: { jobId: bind1.jobId, issuanceId: bind1.issuanceId, runGeneration: 1 },
    job: JOB2,
    clientStartId: START, workerId: bind1.workerId,
    jobId: 'realjob-w2', issuanceId: '2'.repeat(32), runGeneration: 2,
    ...over,
  });
  for (const [label, over] of [
    ['a foreign previous binding', { previous: { jobId: 'other', issuanceId: '9'.repeat(32), runGeneration: 1 } }],
    ['a stale generation', { runGeneration: 1 }],
    ['a skipped window index', { windowIndex: 3 }],
    ['a different declared total', { windowTotal: 2 }],
    ['a reused job id', { job: { ...JOB2, jobId: bind1.jobId }, jobId: bind1.jobId }],
    ['a reused issuance', { job: { ...JOB2, issuanceId: bind1.issuanceId }, issuanceId: bind1.issuanceId }],
    ['another cause', { cause: 'accepted' }],
    ['a foreign worker', { workerId: 'sim-9-zzzz' }],
    ['a terminal refresh frame', { terminal: true }],
    ['a share target that is not hex', { job: { ...JOB2, shareTargetHexLE: 'zz'.repeat(32) } }],
    ['an overflowing nonce window', { job: { ...JOB2, nonceStart: 0xfffff000, nonceRange: REAL_SEARCH_LIMITS.maxAttempts } }],
    ['a changed height on the first handoff', { job: { ...JOB2, height: '2' } }],
    ['a one-nonce overlap on the first handoff', { job: { ...JOB2, nonceStart: REAL_SEARCH_LIMITS.maxAttempts - 1 } }],
  ]) {
    const s = refreshFrameState();
    beginRefreshCapture(capture, s, bind1, JOB1, 3);
    const verdict = capture({ state: s, frame: transition(over), limit: 50, windowTotal: 3 });
    assert.equal(verdict.accepted, false, `${label}: the forged transition was accepted`);
    assert.equal(s.bindings.length, 1, `${label}: the binding advanced anyway`);
    assert.equal(s.activeBinding.jobId, bind1.jobId, `${label}: the active binding changed`);
    // The window-1 binding still accepts its own work afterwards.
    const still = capture({
      state: s, frame: { type: 'share_accepted', ...bind1, nonce: 5, hashHexLE: 'ab'.repeat(32) }, limit: 50, windowTotal: 3,
    });
    assert.equal(still.accepted, true, `${label}: window 1 could no longer report its own share`);
  }
  // The same height and disjoint-window checks continue to apply after more than one handoff.
  const s2 = refreshFrameState();
  beginRefreshCapture(capture, s2, bind1, JOB1, 3);
  capture({ state: s2, frame: transition(), limit: 50, windowTotal: 3 });
  const JOB3 = { ...JOB2, jobId: 'realjob-w3', issuanceId: '3'.repeat(32), nonceStart: 2 * REAL_SEARCH_LIMITS.maxAttempts };
  const t3 = (over = {}) => transition({
    windowIndex: 3,
    previous: { jobId: 'realjob-w2', issuanceId: '2'.repeat(32), runGeneration: 2 },
    job: JOB3, jobId: JOB3.jobId, issuanceId: JOB3.issuanceId, runGeneration: 3, ...over,
  });
  assert.equal(capture({ state: s2, frame: t3({ job: { ...JOB3, height: '2' }, windowIndex: 3 }), limit: 50, windowTotal: 3 }).reason, 'refresh_height_changed');
  assert.equal(capture({ state: s2, frame: t3({ job: { ...JOB3, nonceStart: REAL_SEARCH_LIMITS.maxAttempts - 1 } }), limit: 50, windowTotal: 3 }).reason, 'refresh_window_overlap');
  assert.equal(capture({ state: s2, frame: t3(), limit: 50, windowTotal: 3 }).accepted, true);
});

test('RUNNER REFRESH FRAMES: the reconciled share count is the CUMULATIVE one, per the session and the frames', () => {
  const src = runnerSource();
  // The session figure reconciled is sharesAcceptedTotal -- the counter a refresh rotation does
  // NOT reset -- and never the current window's own sharesAccepted.
  assert.ok(src.includes('sessionShares: sessionFacts.reduce((n, f) => n + (f.sharesAcceptedTotal ?? 0), 0),'),
    'the reconciled session figure is not the cumulative accepted-share total');
  assert.equal(src.includes('n + (f.sharesAccepted ?? 0), 0)'), false,
    'the reconciled session figure still uses the per-window counter');
  // The frame figure is whichever bound capture this run actually used.
  assert.ok(src.includes('const boundFrames = refreshWindows !== null ? refreshFrames : serverFrames;'));
  assert.ok(src.includes('frameShareNonces: boundFrames.shares.map((f) => f.nonce),'));
  // And the outcome consumes that reconciled cumulative count.
  assert.ok(src.includes('const shareOutcome = classifyShareRunOutcome({'));
  assert.ok(src.includes('shares: shareCount.shares,'));
});

test('RUNNER EVIDENCE: the page attempt count is parsed canonically, and unknown never becomes zero', () => {
  const src = runnerSource();
  const parse = liftPureFunction(src, 'parseCanonicalUintText');

  // CANONICAL TEXT IS ACCEPTED, including a genuine zero.
  assert.equal(parse('0'), 0);
  assert.equal(parse('8192'), 8192);
  assert.equal(parse(String(REAL_SEARCH_LIMITS.maxAttempts)), REAL_SEARCH_LIMITS.maxAttempts);
  assert.equal(parse('9007199254740991'), 9007199254740991, 'the largest safe integer was refused');

  // NO NUMBER AT ALL: null, undefined, an empty string, whitespace, the page's dash placeholder and
  // any other non-string are UNKNOWN -- and Number() would have called most of them 0.
  for (const bad of [null, undefined, '', ' ', '   ', '\t', '—', '-', 'DASH', 8192, 0, 1.5, {}, [], true]) {
    assert.equal(parse(bad), null, `${JSON.stringify(bad)} was read as a number`);
  }

  // NONCANONICAL NUMBER TEXT: signs, exponents, decimals, leading zeros and padding are all refused.
  for (const bad of [' 8', '8 ', '+8', '-8', '-0', '8.0', '.5', '8.', '8e3', '0x10', '0o10', '0b1',
    '007', '00', '01', '0.0', '8,192', '8_192', 'Infinity', 'NaN', 'null', 'undefined', '1e21', '1_000']) {
    assert.equal(parse(bad), null, `${JSON.stringify(bad)} was accepted as canonical integer text`);
  }

  // AN UNSAFELY LARGE INTEGER TEXT is unknown too, not a silently rounded count.
  assert.equal(parse('9007199254740992'), null, 'an unsafe integer was accepted');
  assert.equal(parse('99999999999999999999999999'), null, 'an enormous integer was rounded into a number');

  // AND THE RUNNER USES THIS PARSER, not Number(), for the page's cumulative attempt count.
  assert.ok(src.includes('cumulativeAttempts: parseCanonicalUintText(page.totalAttempts),'),
    'the page attempt count is not parsed by the closed parser');
  assert.ok(src.includes("acceptedShares: t('accepted')"),
    'the page-owned accepted-share count is not captured');
  assert.ok(src.includes('pageAcceptedShares: parseCanonicalUintText(page.acceptedShares),'),
    'the page-owned accepted-share count is not parsed and reconciled');
  assert.equal(src.includes('Number(page.totalAttempts)'), false,
    'the page attempt count is still coerced with Number()');
});
