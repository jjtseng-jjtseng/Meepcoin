// ONE paired private P2P vertical run, in a real browser. Run once; it does not retry anything.
//
//   node web-miner/tools/local_p2p_block.mjs --artifact-dir <WSL artifact dir, optional /out> --image <tag>
//        --image-id sha256:<64 hex> --a-rpc-port <n> --a-p2p-port <n> --b-rpc-port <n> --b-p2p-port <n>
//        --evidence <file.json> --transcript <file.txt> [--browser <path>] [--blocks <1..32>]
//        [--interactive]
//
// --interactive is the OPERATOR-START mode -- the operator, or a delegated agent acting for them,
// presses Start in the visible page; this runner NEVER clicks it in this mode. It changes exactly
// two things: the owned throwaway
// browser is launched VISIBLY (no --headless=new), and the runner never clicks Start. It shows the
// same real loopback page, says it is waiting, and then waits for the SERVER's one attempt to leave
// IDLE -- a DOM click is not proof that Start reached the pool. The wait is one fixed source-defined
// budget (OPERATOR_START_TIMEOUT_MS); the browser exiting or that budget expiring fails through the
// same single finalization path, with no retry and no automatic Start. Everything else -- the gates,
// the pool, the daemon pair, the tip observer, the bounds, the evidence, the outcome and the cleanup
// -- is identical to the default run.
//
// --share-profile is the OPT-IN MULTI-SHARE path, and it is the only way this runner enables share
// work. Without it the pool is started exactly as before -- legacy fixed-difficulty, one candidate,
// one solution -- because the server's share profile is selected ONLY by trusted startup
// configuration (realDaemon.shareDifficulty), which the unflagged runner never passes.
//
// The share path is deliberately narrow: it REQUIRES --interactive and --blocks 1 or 2, it refuses any
// flag it does not itself define, and it fixes both difficulties in this source -- share 100 against
// the private block difficulty 500, so D_share <= D_block and the share target is numerically >= the
// block target. No caller can choose either number.
//
// It also refuses to touch anything until: HEAD is exactly the audited commit, the tracked tree is
// clean (only the user's own .wakatime-project and retypes/ may be untracked, and neither is read),
// the evidence, transcript and reservation paths are three distinct paths that do not exist, and a
// durable one-use RESERVATION file has been created exclusively and read back -- before the pool is
// started, so restarting the runner after any outcome cannot reconsume the authorization. There is
// no automatic retry anywhere.
//
// EXIT 0 ON THE ORDINARY SHARE PATH MEANS ONE THING ONLY: every configured block accepted by A and
// received by B. A run that verified shares and found no block is a VALID BOUNDED OBSERVATION and is
// reported as one, with exit 1 -- exit 1 there means "no block claim", not malfunction. The named
// refresh-handoff engineering probe is the sole exception: exit 0 means its two-window handoff was
// proved, while its separately recorded underlying outcome may still be a bounded no-block result.
//
// --blocks N selects a finite trusted development sequence: one Start, one Worker, and at most N
// consecutive fresh templates from A, each searched once under the same frozen bounds. Each next
// template is fetched only after the prior block is canonical on A and shown by B. Default: one block.
//
// Launch it ARGUMENT-NATIVELY from PowerShell or Node (never Git Bash) and propagate the exit code:
// `node web-miner/tools/local_p2p_block.mjs ...; exit $LASTEXITCODE`. Exit 0 ONLY for a block
// accepted by daemon A, received by daemon B through P2P (with --blocks 2: two consecutive blocks), with
// confirmed cleanup and the evidence file persisted and read back.
//
// WHAT IT OWNS, AND CLOSES ON EVERY OUTCOME
//   * one pool listener on an ephemeral loopback port, in real-local-daemon mode with a peer, owning
//     daemon A and daemon B (the same pinned image and read-only artifact, each naming only the other
//     as its exclusive numeric-loopback peer, fixed test difficulty 500) and the native helper;
//   * one browser with one throwaway profile directory -- headless by default, visible only with
//     the explicit --interactive flag, and owned through its own remote-debugging port either way.
// Both daemon data directories and logs are RETAINED for audit; only the throwaway profile is removed.
//
// BEFORE ANYTHING STARTS it records whether power is Online or Offline (battery is allowed, with an
// explicit warning), and refuses an unreadable/ambiguous power result; it also requires the image id,
// daemon binary matches its build manifest, the four daemon ports are free in WSL and on Windows, and
// no earlier meepcoin-private-* container exists. The daemon, converter, and converter runtime
// libraries must all match their fresh-build manifest, and the converter's loader closure must
// resolve completely from the pinned runtime directory before the one-use reservation is written.
//
// WHAT IT DOES NOT DO: widen the frozen bounds, supply a nonce, retry a submission, submit or
// calc_pow to daemon B, lower a target, touch a wallet, or contact anything but loopback.
//
// INTERRUPTION (live_run_lifecycle.mjs). SIGINT/SIGTERM set cancellation once and abort a startup
// still in progress; they never exit by themselves. The one finalization path waits for that startup
// to settle, closes whatever it produced, runs the cleanup observations once, persists the evidence
// and exits 130 / 143 (3 if release was not confirmed). SIGKILL or a crash of Node cannot be handled;
// the transcript records the container names and run directories needed to clean up by hand.
//
// EXIT CODES: 0 success; 1 any other outcome; 2 usage; 3 release unconfirmed; 4 the run succeeded but
// its evidence file could not be persisted and verified; 130 / 143 cancelled by SIGINT / SIGTERM.

import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  accessSync, appendFileSync, constants as fsConstants, existsSync, mkdtempSync, readFileSync,
  rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { startDevPool } from '../../pool/dev/server.mjs';
import { classifyWslDockerEngine } from '../../pool/dev/docker_engine_topology.mjs';
import { SIM_ATTEMPT_STATES } from '../../pool/dev/sim_session.mjs';
import { DAEMON_LIMITS, PEER_TEST_FIXED_DIFFICULTY } from '../../pool/dev/local_daemon.mjs';
import {
  PEER_PROPAGATION_TIMEOUT_MS, REAL_RPC_LIMITS,
} from '../../pool/dev/real_daemon_mode.mjs';
import { HELPER_LIMITS } from '../../pool/dev/native_helper.mjs';
import { targetFromWideDifficulty } from '../../pool/dev/difficulty.mjs';
import { computeSourceId } from '../../pool/dev/source_identity.mjs';
import {
  REAL_DAEMON_MODE, REAL_MAX_CONTEXTS_PER_START, REAL_REFRESH_LIMITS, REAL_SEARCH_LIMITS, REAL_SEQUENCE_DEV_MAX_BLOCKS,
  REAL_SHARE_LIMITS, isSupportedRefreshWindows, isSupportedSequenceBlocks,
} from '../lib/shared/protocol.js';
import { EXIT_CODES, createRunLifecycle, persistJsonAtomically } from './live_run_lifecycle.mjs';
import { connectCdp, evaluate } from './cdp_client.mjs';

const REPO = resolve(new URL('../..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const CANDIDATES = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
];
const WSL_DISTRO = 'Ubuntu';
const MAX_BROWSER_EVENTS = 50;
const CONVERTER_RUNTIME_LIBRARIES = Object.freeze([
  'libboost_filesystem.so.1.83.0',
  'libboost_thread.so.1.83.0',
]);

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => new Date().toISOString();
const bounded = (v, n = 300) => String(v ?? '').slice(0, n);

function run(file, args, timeout = 60_000) {
  const r = spawnSync(file, args, { encoding: 'utf8', timeout, windowsHide: true, shell: false });
  return { status: r.status, stdout: String(r.stdout ?? ''), stderr: bounded(r.stderr) };
}
const wsl = (args, timeout) => run('wsl.exe', ['-d', WSL_DISTRO, '--exec', ...args], timeout);
const sha256File = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');

/**
 * One fail-closed verdict for the runtime artifacts needed before the live reservation is spent.
 * The manifest is build output rather than an external signature, but requiring its exact entries,
 * the actual bytes and the dynamic loader's complete resolution prevents a partial/stale artifact
 * directory from reaching converter startup. The externally pinned image and commit remain the
 * surrounding build/source identity gates.
 */
function classifyConverterRuntimeArtifacts({
  manifestText, requiredNames, actualHashes, sizes, loaderStatus, loaderStdout, runtimeLibraryDir,
}) {
  if (!Array.isArray(requiredNames) || requiredNames.length < 2
      || new Set(requiredNames).size !== requiredNames.length
      || !requiredNames.every((name) => typeof name === 'string' && /^[A-Za-z0-9._/-]+$/.test(name))) {
    return { ok: false, error: 'the required runtime artifact inventory is invalid', artifacts: [] };
  }
  if (!Array.isArray(actualHashes) || actualHashes.length !== requiredNames.length
      || !Array.isArray(sizes) || sizes.length !== requiredNames.length) {
    return { ok: false, error: 'the runtime artifact observations are incomplete', artifacts: [] };
  }
  const manifest = new Map();
  for (const line of String(manifestText ?? '').split(/\r?\n/)) {
    const match = line.match(/^([A-Za-z0-9._/-]+)\s+=\s+([0-9a-f]{64})$/);
    if (!match || !requiredNames.includes(match[1])) continue;
    if (manifest.has(match[1])) {
      return { ok: false, error: `the build manifest repeats ${match[1]}`, artifacts: [] };
    }
    manifest.set(match[1], match[2]);
  }
  const artifacts = [];
  for (const [index, name] of requiredNames.entries()) {
    const actual = actualHashes[index];
    const size = sizes[index];
    if (!/^[0-9a-f]{64}$/.test(String(actual ?? '')) || !Number.isSafeInteger(size) || size < 1) {
      return { ok: false, error: `the observation for ${name} is invalid`, artifacts: [] };
    }
    const declared = manifest.get(name);
    if (declared === undefined) {
      return { ok: false, error: `the build manifest omits ${name}`, artifacts: [] };
    }
    if (declared !== actual) {
      return { ok: false, error: `${name} does not match its build manifest`, artifacts: [] };
    }
    artifacts.push({ name, bytes: size, sha256: actual });
  }
  if (loaderStatus !== 0) {
    return { ok: false, error: `the converter loader check failed (exit ${String(loaderStatus)})`, artifacts };
  }
  const loader = String(loaderStdout ?? '');
  if (/(^|\s)not found(\s|$)/m.test(loader)) {
    return { ok: false, error: 'the converter dynamic-link closure contains an unresolved library', artifacts };
  }
  for (const name of requiredNames.filter((item) => item.startsWith('runtime-libs/'))) {
    const lib = name.slice('runtime-libs/'.length);
    const expected = `${lib} => ${runtimeLibraryDir}/${lib} (`;
    if (!loader.split(/\r?\n/).some((line) => line.trim().startsWith(expected))) {
      return { ok: false, error: `${lib} did not resolve from the pinned runtime library directory`, artifacts };
    }
  }
  return { ok: true, error: null, artifacts };
}

// ---------------------------------------------------------------- configuration
const artifactDir = arg('artifact-dir');
const image = arg('image');
const imageId = arg('image-id');
const ports = {
  aRpc: Number(arg('a-rpc-port')), aP2p: Number(arg('a-p2p-port')),
  bRpc: Number(arg('b-rpc-port')), bP2p: Number(arg('b-p2p-port')),
};
const evidencePath = arg('evidence');
const transcriptPath = arg('transcript');
// RAW ONLY: resolving the default or checking an explicit path touches the filesystem, so both wait
// until the pure refresh-mode verdict has had the first chance to refuse an incompatible request.
const browserPathRaw = arg('browser');
/** OPERATOR START. A bare boolean flag; it takes no value a caller could widen. */
const interactive = process.argv.includes('--interactive');
/** THE OPT-IN SHARE PATH. Also a bare boolean: it selects a profile fixed in this source, nothing more. */
const shareProfile = process.argv.includes('--share-profile');
function sequenceRefreshSuccessOutcome(blocks, windows) {
  return `SHARE_SEQUENCE_REFRESH_${blocks}_BLOCKS_UP_TO_${windows}_WINDOWS_PER_HEIGHT_ACCEPTED_BY_A_AND_RECEIVED_BY_B`;
}

// A candidate admitted just before the whole-session deadline is allowed to finish honestly. The
// session therefore can still be inside each of these SERIAL bounded steps after its ten-minute
// admission budget expires: native HASH; calc_pow; submit_block; the block run's header/top
// readbacks; the propagation proof's A header/top anchor; and one B header/top poll which began
// before the propagation clock expired. The socket-table observation in that final poll has its own
// independent probe ceiling. Keep this derived from the same source constants as those operations;
// the outer runner must never time out first and overwrite a legitimate core terminal verdict.
const SEQUENCE_REFRESH_FINALIZATION_MS = HELPER_LIMITS.requestTimeoutMs
  + REAL_RPC_LIMITS.timeoutMs
  + REAL_RPC_LIMITS.submitTimeoutMs
  + (2 * REAL_RPC_LIMITS.timeoutMs)
  + (2 * REAL_RPC_LIMITS.timeoutMs)
  + PEER_PROPAGATION_TIMEOUT_MS
  + (2 * REAL_RPC_LIMITS.timeoutMs)
  + DAEMON_LIMITS.probeTimeoutMs;

/**
 * ONE DEVELOPMENT-ONLY HANDOFF PROBE. This is a bare flag, never a numeric tuning surface. Its
 * complete contract is checked below before a browser path or any other filesystem prerequisite is
 * inspected. It changes only the trusted share difficulty: the daemon's block difficulty, all
 * verification, the one-submission authority and every lifecycle fence remain exactly the same.
 */
const refreshHandoffProbe = process.argv.includes('--refresh-handoff-probe');
/**
 * OPT-IN SAME-HEIGHT WINDOW REFRESH, and nothing enables it implicitly.
 *
 * Absent, this runner is exactly what it has always been: ONE nonce window per requested height. Given
 * `--refresh-windows N` with N in 2..REAL_REFRESH_LIMITS.maxWindows, the trusted startup
 * configuration asks the pool for up to N SERIAL windows per requested height. IN THIS BUILD THE
 * OPTION IS LEGAL ONLY ON THE OPERATOR-STARTED SHARE PATH: it requires BOTH --share-profile and
 * --interactive, so the pinned expected head, the clean tree, the durable one-use reservation, the
 * exclusive no-replace transcript/evidence publication, the operator Start and the screenshot
 * directory are all part of a refresh run exactly as they are of any share run. The Cartesian
 * block-by-window plan must fit the core's fixed context ceiling, and it changes nothing about the
 * existing --share-profile gates. The verdict is decided IMMEDIATELY after the base argument parsing -- before any
 * screenshot, filesystem, path or share prerequisite is inspected -- so an illegal combination
 * fails for its own reason before a single side effect.
 */
const refreshWindowsRaw = arg('refresh-windows');
const blocks = Number(arg('blocks', '1'));
if (!isSupportedSequenceBlocks(blocks)) {
  console.error(`--blocks must be an integer from 1 to ${REAL_SEQUENCE_DEV_MAX_BLOCKS}`);
  process.exit(EXIT_CODES.USAGE);
}

/**
 * THE FIXED SHARE DIFFICULTY OF THIS PATH, prospectively chosen here and nowhere else.
 *
 * 100 against the private fixed block difficulty 500: D_share <= D_block, so the share target is
 * numerically >= the block target and every block is also a share. Neither number is reachable from
 * a flag, an environment variable or a client message.
 */
const SHARE_PROFILE_DIFFICULTY = 100;
/**
 * The probe makes every hash a qualifying SHARE while leaving the block target at difficulty 500.
 * The existing eight-result cap therefore normally retires the first window after eight real,
 * independently verified hashes. A genuine block still wins immediately; it is never suppressed to
 * manufacture a handoff, and the one-use run is never retried if that happens.
 */
const HANDOFF_PROBE_SHARE_DIFFICULTY = 1;
const HANDOFF_PROBE_SHARE_TARGET_HEX_LE = targetFromWideDifficulty(
  String(HANDOFF_PROBE_SHARE_DIFFICULTY),
).targetHexLE;
const PRIVATE_BLOCK_TARGET_HEX_LE = targetFromWideDifficulty(
  String(PEER_TEST_FIXED_DIFFICULTY),
).targetHexLE;

/**
 * THE AUTHORIZED COMMIT IS SUPPLIED FROM OUTSIDE, as --expected-head, and never derived here.
 *
 * A hash written into this file is self-invalidating: committing the file changes HEAD, so the pin
 * can never name the commit that contains it. Reading HEAD at runtime and calling it "expected" is
 * worse -- it would compare a value with itself and prove nothing. The pin therefore comes from the
 * auditor who granted the authorization, and this runner only compares it with what git reports.
 */
const expectedHead = arg('expected-head');

/** Untracked paths that belong to the USER, are never read, and do not make the tree dirty. */
const ALLOWED_UNTRACKED = Object.freeze(['.wakatime-project', 'retypes/']);

/** Every flag this runner defines. The share path refuses anything else outright. */
const KNOWN_FLAGS = Object.freeze([
  '--artifact-dir', '--image', '--image-id', '--a-rpc-port', '--a-p2p-port', '--b-rpc-port',
  '--b-p2p-port', '--evidence', '--transcript', '--browser', '--blocks', '--interactive',
  '--share-profile', '--reservation', '--expected-head', '--screenshot-dir', '--refresh-windows',
  '--refresh-handoff-probe',
]);
/** Flags whose following token is data, never another switch. Used by the pure probe stop gate. */
const VALUE_FLAGS = Object.freeze([
  '--artifact-dir', '--image', '--image-id', '--a-rpc-port', '--a-p2p-port', '--b-rpc-port',
  '--b-p2p-port', '--evidence', '--transcript', '--browser', '--blocks', '--reservation',
  '--expected-head', '--screenshot-dir', '--refresh-windows',
]);
// ---- the --refresh-windows contract, BEFORE any filesystem-dependent browser resolution ---------
// Pure numeric and mode compatibility only, decided before any screenshot, filesystem, path or share
// prerequisite is inspected: an illegal value or combination refuses here, for its own reason,
// before a single side effect -- no directory is stat'ed, no path is checked for existence, no
// reservation is created, nothing is spawned and nothing listens.
const refreshVerdict = classifyRefreshWindowsFlag({
  raw: refreshWindowsRaw,
  blocks,
  maxWindows: REAL_REFRESH_LIMITS.maxWindows,
  maxContexts: REAL_MAX_CONTEXTS_PER_START,
  shareProfile,
  interactive,
});
if (!refreshVerdict.ok) {
  console.error(refreshVerdict.error);
  process.exit(EXIT_CODES.USAGE);
}
const refreshWindows = refreshVerdict.windows;
const sequenceRefresh = blocks > 1 && refreshWindows !== null;
// The named probe has a still narrower, pure contract. In particular, it cannot silently inherit a
// default `--blocks 1`: all five pieces of the prospective invocation must be written explicitly.
const handoffProbeVerdict = classifyRefreshHandoffProbeFlag({
  argv: process.argv.slice(2),
  enabled: refreshHandoffProbe,
  blocks,
  refreshWindows,
  shareProfile,
  interactive,
  knownFlags: KNOWN_FLAGS,
  valueFlags: VALUE_FLAGS,
});
if (!handoffProbeVerdict.ok) {
  console.error(handoffProbeVerdict.error);
  process.exit(EXIT_CODES.USAGE);
}
const effectiveShareDifficulty = selectTrustedShareDifficulty({
  probe: refreshHandoffProbe,
  normalDifficulty: SHARE_PROFILE_DIFFICULTY,
  probeDifficulty: HANDOFF_PROBE_SHARE_DIFFICULTY,
  blockDifficulty: PEER_TEST_FIXED_DIFFICULTY,
});
// Only a refresh-compatible request may inspect browser candidates or the explicit browser path.
const browserPath = browserPathRaw ?? CANDIDATES.find((p) => existsSync(p));
if (!artifactDir || !image || !/^sha256:[0-9a-f]{64}$/.test(imageId ?? '') || !evidencePath || !transcriptPath
  || !browserPath || !existsSync(browserPath)
  || Object.values(ports).some((p) => !Number.isInteger(p) || p < 1024 || p > 65535) || new Set(Object.values(ports)).size !== 4) {
  console.error('usage: --artifact-dir <dir> --image <tag> --image-id sha256:<hex> --a-rpc-port <n> --a-p2p-port <n> '
    + '--b-rpc-port <n> --b-p2p-port <n> --evidence <file> --transcript <file> [--browser <path>] '
    + '[--blocks <1..32>] [--interactive] [--share-profile --interactive --blocks <1|2> --reservation <file> '
    + '--expected-head <40 hex> --screenshot-dir <existing dir>] '
     + `[--refresh-windows <2..${REAL_REFRESH_LIMITS.maxWindows}> --share-profile --interactive --blocks <1|2> `
    + '--reservation <file> --expected-head <40 hex> --screenshot-dir <existing dir>] '
    + '[--refresh-handoff-probe --refresh-windows 2 --share-profile --interactive --blocks 1]');
  process.exit(EXIT_CODES.USAGE);
}
// ---- the opt-in share path's own usage contract, before anything is created ------------------
const flagVerdict = classifyShareProfileFlags({
  argv: process.argv.slice(2),
  shareProfile,
  interactive,
  blocks,
  shareDifficulty: effectiveShareDifficulty,
  blockDifficulty: PEER_TEST_FIXED_DIFFICULTY,
  knownFlags: KNOWN_FLAGS,
});
if (!flagVerdict.ok) {
  console.error(flagVerdict.error);
  process.exit(EXIT_CODES.USAGE);
}
if (shareProfile && !/^[0-9a-f]{40}$/.test(expectedHead ?? '')) {
  console.error('--share-profile requires --expected-head <40 lowercase hex>, supplied by the authorizing audit');
  process.exit(EXIT_CODES.USAGE);
}
if (!shareProfile && expectedHead) {
  console.error('--expected-head is only meaningful with --share-profile');
  process.exit(EXIT_CODES.USAGE);
}
const screenshotDir = arg('screenshot-dir');
if (shareProfile) {
  // AN EXISTING, WRITABLE DIRECTORY. `existsSync` alone would accept a FILE, or a directory this
  // process cannot write, and the first thing anyone would learn about either is a failed
  // screenshot after the operator had already been asked to press Start.
  const dirVerdict = (() => {
    if (!screenshotDir) return 'is required';
    try {
      if (!statSync(screenshotDir).isDirectory()) return 'is not a directory';
    } catch (err) {
      return `could not be inspected: ${err?.code ?? err?.message ?? err}`;
    }
    try {
      accessSync(screenshotDir, fsConstants.W_OK);
    } catch {
      return 'is not writable by this process';
    }
    return null;
  })();
  if (dirVerdict !== null) {
    console.error(`--share-profile requires --screenshot-dir <existing writable directory>: it ${dirVerdict}`);
    process.exit(EXIT_CODES.USAGE);
  }
}
if (!shareProfile && screenshotDir) {
  console.error('--screenshot-dir is only meaningful with --share-profile');
  process.exit(EXIT_CODES.USAGE);
}
const reservationPath = arg('reservation');
if (shareProfile && !reservationPath) {
  console.error('--share-profile requires --reservation <file>: a fresh, absent, one-use path');
  process.exit(EXIT_CODES.USAGE);
}
if (!shareProfile && reservationPath) {
  console.error('--reservation is only meaningful with --share-profile');
  process.exit(EXIT_CODES.USAGE);
}
if (shareProfile) {
  // THREE DISTINCT PATHS THAT DO NOT EXIST. The legacy runner truncates its transcript on start;
  // on this path an existing transcript, evidence file or reservation is a refusal, because
  // overwriting either would destroy the record of whatever consumed them.
  const paths = [evidencePath, transcriptPath, reservationPath].map((x) => resolve(x));
  if (new Set(paths).size !== 3) {
    console.error('--evidence, --transcript and --reservation must be three distinct paths');
    process.exit(EXIT_CODES.USAGE);
  }
  const present = paths.filter((x) => existsSync(x));
  if (present.length > 0) {
    console.error(`--share-profile requires absent output paths; these exist: ${present.join(' ')}`);
    process.exit(EXIT_CODES.USAGE);
  }
}
const runId = randomBytes(8).toString('hex');
const runDirA = `/home/tseng/meepcoin-private-run-${runId}a`;
const runDirB = `/home/tseng/meepcoin-private-run-${runId}b`;
const common = { wslDistro: WSL_DISTRO, image, artifactDir, uid: 1000, gid: 1000, profile: 'private-exclusive-peer-test', fixedDifficulty: PEER_TEST_FIXED_DIFFICULTY, expectedImageId: imageId };
const configA = { ...common, runDir: runDirA, rpcPort: ports.aRpc, p2pPort: ports.aP2p, exclusivePeerP2pPort: ports.bP2p };
const configB = { ...common, runDir: runDirB, rpcPort: ports.bRpc, p2pPort: ports.bP2p, exclusivePeerP2pPort: ports.aP2p };

const evidence = {
  startedAt: now(), mode: REAL_DAEMON_MODE, bounds: REAL_SEARCH_LIMITS, fixedDifficulty: PEER_TEST_FIXED_DIFFICULTY,
  blocks, interactive, ports, configA, configB, outcome: null, transcriptAppendFailures: 0, events: [],
  shareProfile,
  ...(refreshHandoffProbe ? { refreshHandoffProbe: true, handoffProbeContract: {
    objective: 'exercise exactly one same-height window-1-to-window-2 handoff',
    requestedWindows: 2,
    shareDifficulty: HANDOFF_PROBE_SHARE_DIFFICULTY,
    blockDifficulty: PEER_TEST_FIXED_DIFFICULTY,
    validBlockStillWins: true,
    retries: 0,
  } } : {}),
  refreshWindowsRequested: refreshWindows,
  expectedHead: shareProfile ? expectedHead : null,
  screenshots: [],
  shareDifficulty: shareProfile ? effectiveShareDifficulty : null,
  maxShareResults: shareProfile ? REAL_SHARE_LIMITS.maxSharesPerJob : null,
};
// The legacy path truncates, as it always has. The share path creates EXCLUSIVELY: it must never
// overwrite a transcript belonging to an earlier run.
if (shareProfile) writeFileSync(transcriptPath, '', { flag: 'wx' });
else writeFileSync(transcriptPath, '');
const note = (label, value) => {
  evidence.events.push({ at: now(), label, value });
  const line = `${label.padEnd(36)} ${typeof value === 'string' ? value : JSON.stringify(value, (k, v) => (typeof v === 'bigint' ? v.toString() : v))}`;
  console.log(line);
  // A failed append is counted and reported; it never changes the JSON result.
  try { appendFileSync(transcriptPath, `${line}\n`); } catch { evidence.transcriptAppendFailures += 1; }
};

let chrome = null;
let chromeExited = false;
let cdp = null;
let profileDir = null;
let facts = { containers: [], pids: [], helperPids: [], poolPort: null };

const lifecycle = createRunLifecycle({
  startPool: startDevPool,
  exit: (code) => process.exit(code),
  note,
  persistEvidence: ({ exitCode }) => {
    evidence.finishedAt = now();
    evidence.exitCode = exitCode;
    const expect = { exitCode, finishedAt: evidence.finishedAt, outcome: evidence.outcome };
    // THE SHARE PATH NEVER REPLACES A FILE IT DID NOT CREATE, and does not decide that by looking
    // first: each candidate name is published by LINKING a fully written temporary file, which
    // either creates that name or fails EEXIST without touching what is there. The legacy path
    // keeps its atomic rename-replace of a path it owns, exactly as before.
    if (shareProfile) {
      const candidates = publishCandidates({ path: evidencePath, runId });
      // THE INTENDED DESTINATIONS ARE RECORDED BEFORE THE DOCUMENT IS SERIALISED, so they are really
      // inside the saved file. The RESULT of publishing cannot be: writing it into the document
      // would change the bytes that were just verified. It goes to the transcript and the console,
      // which is where the reader looks for it, and the field below says so rather than implying
      // the file contains an outcome it cannot contain.
      evidence.publish = {
        intendedPaths: candidates,
        policy: 'exclusive no-replace: each candidate is published by linking a fully written temporary '
          + 'file; a name already held by another file is left untouched and never deleted',
        resultRecordedIn: 'the transcript and the process output, not this field',
      };
      const published = publishNoReplace({
        candidates,
        write: (candidate) => persistJsonAtomically(candidate, evidence, { expect, noReplace: true }),
      });
      const r0 = published.ok
        ? { ok: true, path: published.path, fallback: published.fallback, attempts: published.attempts }
        : { ok: false, stage: 'publish_no_replace', message: published.reason, attempts: published.attempts };
      console.log(`${'evidence file'.padEnd(36)} ${JSON.stringify(r0)}`);
      // The transcript is where the publication RESULT lives: it is appended after the document was
      // serialised, so recording it cannot change the bytes that were just written and verified.
      note('evidence publication', r0);
      return r0;
    }
    const r = persistJsonAtomically(evidencePath, evidence, { expect });
    console.log(`${'evidence file'.padEnd(36)} ${JSON.stringify(r)}`);
    return r;
  },
});
lifecycle.installSignalHandlers(process);
// Unblock the body at once: the browser and DevTools go first, so a pending CDP call rejects.
lifecycle.onCancel(() => { try { cdp?.close(); } catch { /* gone */ } try { chrome?.kill(); } catch { /* gone */ } });

// ---------------------------------------------------------------- the operator-start primitives
//
// All of these are PURE and defined here so a non-live test can execute them against real inputs
// instead of reading the file and hoping.

/**
 * THE OPT-IN SHARE PATH'S FLAG CONTRACT, decided in one place from the raw argv.
 *
 * Without --share-profile this says nothing at all: the legacy runner keeps every behaviour it had.
 * With it, the path is narrow by construction -- an operator Start, one or two blocks, a share
 * difficulty fixed in this source and not harder than the block difficulty, and no flag this runner
 * does not define. An unknown flag is refused rather than ignored, because ignoring one is how a
 * caller silently gets a run it did not ask for.
 *
 * @returns {{ok:boolean, error:string|null}}
 */
function classifyShareProfileFlags({
  argv, shareProfile, interactive, blocks, shareDifficulty, blockDifficulty, knownFlags,
}) {
  if (shareProfile !== true) return { ok: true, error: null };
  const unknown = argv.filter((a) => a.startsWith('--') && !knownFlags.includes(a));
  if (unknown.length > 0) return { ok: false, error: `unknown flag for --share-profile: ${unknown.join(' ')}` };
  if (interactive !== true) return { ok: false, error: '--share-profile requires --interactive (a human presses Start)' };
  if (blocks !== 1 && blocks !== 2) return { ok: false, error: '--share-profile requires --blocks 1 or 2' };
  const at = argv.indexOf('--blocks');
  if (at >= 0 && argv[at + 1] !== String(blocks)) return { ok: false, error: '--share-profile requires canonical --blocks 1 or 2' };
  if (!Number.isSafeInteger(shareDifficulty) || shareDifficulty < 1) {
    return { ok: false, error: 'the fixed share difficulty is not a positive integer' };
  }
  if (!Number.isSafeInteger(blockDifficulty) || shareDifficulty > blockDifficulty) {
    return { ok: false, error: 'the share difficulty must not exceed the block difficulty' };
  }
  return { ok: true, error: null };
}

/**
 * THE `--refresh-windows` CONTRACT, decided in one place from the raw argument.
 *
 * Absent is not "one": absent is "this option was not used", and the caller then passes no refresh
 * configuration at all, so the pool builds exactly the run it always built. A present value must be
 * a whole number the build supports and at least two -- one window is what absence already means,
 * and `1` is refused rather than silently accepted as a no-op that looks like an opt-in. It is
 * bounded by the fixed Cartesian context ceiling, and IN THIS BUILD it is legal only on the
 * operator-started share path: without BOTH --share-profile and --interactive there is no refresh,
 * because the pinned head, the clean tree, the one-use reservation, the exclusive no-replace
 * publication and the human Start are part of what a refresh run is. Every verdict here is pure:
 * it inspects nothing on disk and creates nothing, so the caller can refuse before any side effect.
 *
 * @returns {{ok:boolean, windows:number|null, error:string|null}}
 */
function classifyRefreshWindowsFlag({ raw, blocks, maxWindows, maxContexts, shareProfile, interactive }) {
  if (raw === null || raw === undefined) return { ok: true, windows: null, error: null };
  if (!/^[0-9]{1,2}$/.test(String(raw))) {
    return { ok: false, windows: null, error: `--refresh-windows must be a whole number from 2 to ${maxWindows}` };
  }
  const windows = Number(raw);
  if (!Number.isSafeInteger(windows) || windows < 2 || windows > maxWindows) {
    return { ok: false, windows: null, error: `--refresh-windows must be a whole number from 2 to ${maxWindows}` };
  }
  if (!Number.isSafeInteger(blocks) || blocks < 1 || !Number.isSafeInteger(maxContexts)
    || maxContexts < 1 || blocks * windows > maxContexts) {
    return { ok: false, windows: null, error: `--blocks x --refresh-windows may issue at most ${maxContexts} contexts` };
  }
  if (shareProfile !== true) {
    return { ok: false, windows: null, error: '--refresh-windows requires --share-profile in this build: the pinned expected head, the one-use reservation, the exclusive no-replace evidence and the operator Start are part of a refresh run' };
  }
  if (interactive !== true) {
    return { ok: false, windows: null, error: '--refresh-windows requires --interactive (a human presses Start)' };
  }
  return { ok: true, windows, error: null };
}

/**
 * Power is an ENVIRONMENT FACT, not a mining authorization gate. `Offline` is Windows' explicit
 * battery state and is accepted with a warning because the operator allowed slower battery mining.
 * A failed query, Unknown, multiple lines, or any other text remains fail-closed: evidence must never
 * claim either AC or battery when the machine did not establish it.
 */
function classifyPowerLineStatus({ status, stdout, stderr }) {
  if (status !== 0) {
    return { ok: false, state: null, onBattery: null, warning: null, error: 'the power-state query failed' };
  }
  if (typeof stderr === 'string' && stderr.length > 0) {
    return { ok: false, state: null, onBattery: null, warning: null, error: 'the power-state query was unavailable or ambiguous' };
  }
  // PowerShell normally appends exactly one platform newline. Accept that transport terminator, but
  // do not trim arbitrary whitespace: leading/trailing spaces, an empty result, or a second line are
  // ambiguous environmental evidence and must fail closed.
  const match = typeof stdout === 'string' ? /^(Online|Offline)(?:\r?\n)?$/.exec(stdout) : null;
  const value = match?.[1] ?? null;
  if (value === 'Online') {
    return { ok: true, state: 'Online', onBattery: false, warning: null, error: null };
  }
  if (value === 'Offline') {
    return {
      ok: true, state: 'Offline', onBattery: true,
      warning: 'running on battery; hash rate may be lower and the bounded run may find no block', error: null,
    };
  }
  return { ok: false, state: null, onBattery: null, warning: null, error: 'the power-state query was unavailable or ambiguous' };
}

/**
 * THE NAMED HANDOFF PROBE'S COMPLETE CLI CONTRACT.
 *
 * This is deliberately not a general way to choose a share difficulty. The only legal spelling is
 * one occurrence of each named switch, with canonical `--blocks 1` and `--refresh-windows 2` values.
 * The caller cannot omit those values and inherit defaults, attach a value to the bare probe flag,
 * or combine it with another refresh length. Absent means every historical runner mode is untouched.
 * Pure by construction so the top-level caller can refuse before path inspection or any side effect.
 */
function classifyRefreshHandoffProbeFlag({
  argv, enabled, blocks, refreshWindows, shareProfile, interactive, knownFlags, valueFlags = [],
}) {
  const args = Array.isArray(argv) ? argv : [];
  const count = (flag) => args.filter((v) => v === flag).length;
  const spellings = args.filter((v) => String(v).startsWith('--refresh-handoff-probe'));
  if (spellings.length === 0 && enabled !== true) return { ok: true, error: null };
  if (spellings.some((v) => v !== '--refresh-handoff-probe')) {
    return { ok: false, error: '--refresh-handoff-probe is a bare flag; attached values and alternate spellings are refused' };
  }
  const known = Array.isArray(knownFlags) ? knownFlags : [];
  const unknown = args.filter((v) => String(v).startsWith('--') && !known.includes(v));
  if (unknown.length > 0) {
    return { ok: false, error: `unknown flag for --refresh-handoff-probe: ${unknown.join(' ')}` };
  }
  // The generic top-level value reader intentionally performs no I/O, but it can otherwise consume
  // the probe switch as another option's value (`--browser --refresh-handoff-probe`). Refuse every
  // missing value here, while the probe contract is still pure and before browser/path inspection.
  const takesValue = Array.isArray(valueFlags) ? valueFlags : [];
  for (let i = 0; i < args.length; i += 1) {
    if (!takesValue.includes(args[i])) continue;
    if (i + 1 >= args.length || String(args[i + 1]).startsWith('--')) {
      return { ok: false, error: `${args[i]} requires a value before --refresh-handoff-probe can run` };
    }
    i += 1;
  }
  if (count('--refresh-handoff-probe') !== 1) {
    return { ok: false, error: '--refresh-handoff-probe must appear exactly once' };
  }
  const probeAt = args.indexOf('--refresh-handoff-probe');
  if (probeAt + 1 < args.length && !String(args[probeAt + 1]).startsWith('--')) {
    return { ok: false, error: '--refresh-handoff-probe is a bare flag and takes no value' };
  }
  if (count('--share-profile') !== 1 || shareProfile !== true) {
    return { ok: false, error: '--refresh-handoff-probe requires exactly one --share-profile' };
  }
  if (count('--interactive') !== 1 || interactive !== true) {
    return { ok: false, error: '--refresh-handoff-probe requires exactly one --interactive' };
  }
  const blocksAt = args.indexOf('--blocks');
  if (count('--blocks') !== 1 || blocksAt < 0 || args[blocksAt + 1] !== '1' || blocks !== 1) {
    return { ok: false, error: '--refresh-handoff-probe requires the explicit canonical pair --blocks 1' };
  }
  const windowsAt = args.indexOf('--refresh-windows');
  if (count('--refresh-windows') !== 1 || windowsAt < 0 || args[windowsAt + 1] !== '2'
    || refreshWindows !== 2) {
    return { ok: false, error: '--refresh-handoff-probe requires the explicit canonical pair --refresh-windows 2' };
  }
  return { ok: true, error: null };
}

/** Source-owned selection only. No argv, environment, page or protocol value reaches this helper. */
function selectTrustedShareDifficulty({ probe, normalDifficulty, probeDifficulty, blockDifficulty }) {
  const chosen = probe === true ? probeDifficulty : normalDifficulty;
  if (!Number.isSafeInteger(chosen) || chosen < 1 || !Number.isSafeInteger(blockDifficulty)
    || chosen > blockDifficulty) {
    throw new TypeError('the source-fixed share difficulty is outside the private block target');
  }
  return chosen;
}

/**
 * THE PAGE'S CUMULATIVE ATTEMPT COUNT, parsed closed from its text.
 *
 * The page reports it as TEXT -- the rendered content of an element, or null when the element has
 * nothing to say. Number() would quietly turn null, an empty string and surrounding whitespace
 * into 0, manufacturing a proof of ZERO attempts nobody established; a sign, an exponent or a
 * decimal point would also slip through. So the text is accepted only in its CANONICAL form: a
 * non-negative base-10 integer with no sign, no exponent, no decimal point, no leading zero (0
 * itself excepted) and no whitespace, within Number's safe integer range. Everything else --
 * including null, undefined, a dash and any padding -- is UNKNOWN, and unknown is null, never 0.
 */
function parseCanonicalUintText(raw) {
  if (typeof raw !== 'string') return null;
  if (!/^(?:0|[1-9][0-9]*)$/.test(raw)) return null;
  const n = Number(raw);
  return Number.isSafeInteger(n) ? n : null;
}

/**
 * The browser-visible work context, reduced to immutable facts instead of retaining a block blob.
 * This is used for BOTH the initial real_job and every refresh. A frame missing even one context
 * component is not usable as proof that the browser received the server-owned job it later named.
 */
function refreshBrowserJobFacts(job) {
  const hex64 = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
  const template = job?.hashingTemplateHex;
  const height = String(job?.height ?? '');
  if (job?.type !== 'real_job' || typeof job.jobId !== 'string' || job.jobId.length === 0
    || !/^[0-9a-f]{32}$/.test(String(job.issuanceId ?? ''))
    || !hex64(job.contentDigest) || !hex64(job.epochKeyHex) || !hex64(job.seedHashHex)
    || !hex64(job.shareTargetHexLE) || !hex64(job.targetHexLE)
    || typeof template !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(template)
    || !/^(?:0|[1-9][0-9]*)$/.test(height) || job.shareWork !== true
    || !Number.isSafeInteger(job.nonceStart) || !Number.isSafeInteger(job.nonceRange)
    || job.nonceStart < 0 || job.nonceRange < 1 || job.nonceStart + job.nonceRange > 0x100000000) {
    return null;
  }
  return Object.freeze({
    shareWork: true,
    jobId: job.jobId,
    issuanceId: job.issuanceId,
    height,
    nonceStart: job.nonceStart,
    nonceRange: job.nonceRange,
    shareTargetHexLE: job.shareTargetHexLE,
    blockTargetHexLE: job.targetHexLE,
    contentDigest: job.contentDigest,
    epochKeyHex: job.epochKeyHex,
    seedHashHex: job.seedHashHex,
    hashingTemplateSha256: createHash('sha256').update(Buffer.from(template, 'hex')).digest('hex'),
  });
}

/**
 * WHAT A REFRESH RUN ESTABLISHED, PER WINDOW, from the server's own bounded records.
 *
 * Evidence, not a summary: which windows were actually issued and over which nonce ranges, which
 * verifier served each of them and whether its release was CONFIRMED before the next allocation,
 * the cumulative attempts and the session-wide accepted-share total (not only the current window's
 * counter, which a rotation resets), the advertised deadline, the terminal reason, and whether any
 * block claim happened at all. Unknown stays null; it never collapses to zero, and nothing here
 * copies a block blob, a template blob, a key or any other sensitive material.
 */
function refreshEvidence({
  requestedWindows, windowRecords, sessionFacts, verifierHistory, currentVerifier,
  attemptState, attemptReason, submitBlockCount, calcPowCount, cumulativeAttempts,
}) {
  if (!Number.isSafeInteger(requestedWindows) || requestedWindows < 2) return null;
  const safeUint = (raw) => {
    if (typeof raw === 'number') return Number.isSafeInteger(raw) && raw >= 0 ? raw : null;
    if (typeof raw === 'bigint') return raw >= 0n && raw <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(raw) : null;
    if (typeof raw === 'string' && /^(?:0|[1-9][0-9]*)$/.test(raw)) {
      const value = Number(raw);
      return Number.isSafeInteger(value) ? value : null;
    }
    return null;
  };
  const uintText = (raw) => {
    if (typeof raw === 'bigint') return raw >= 0n ? raw.toString() : null;
    if (typeof raw === 'number') return Number.isSafeInteger(raw) && raw >= 0 ? String(raw) : null;
    return typeof raw === 'string' && /^(?:0|[1-9][0-9]*)$/.test(raw) ? raw : null;
  };
  const targetHex = (raw) => (typeof raw === 'string' && /^[0-9a-fA-F]{64}$/.test(raw)
    ? raw.toLowerCase()
    : null);
  const records = Array.isArray(windowRecords) ? windowRecords : [];
  const facts = Array.isArray(sessionFacts) ? sessionFacts : [];
  const history = Array.isArray(verifierHistory) ? verifierHistory : [];
  const sum = (key) => (facts.length === 0 ? null : facts.reduce((n, f) => n + (f[key] ?? 0), 0));
  const released = history.map((v, i) => ({
    order: i + 1,
    block: v?.block ?? null,
    window: v?.window ?? null,
    jobId: v?.jobId ?? null,
    issuanceId: v?.issuanceId ?? null,
    helperLinuxPid: v?.helperLinuxPid ?? null,
    helperSourceId: v?.helperSourceId ?? null,
    contextHeight: v?.context?.height ?? null,
    releaseStartedAtMs: v?.releaseStartedAtMs ?? null,
    releasedAtMs: v?.releasedAtMs ?? null,
    closed: v?.closed ?? null,
    forced: v?.forced ?? null,
  }));
  const live = currentVerifier === null || currentVerifier === undefined ? null : {
    helperLinuxPid: currentVerifier.helperLinuxPid ?? null,
    helperSourceId: currentVerifier.helperSourceId ?? null,
    contextHeight: currentVerifier.context?.height ?? null,
    closed: currentVerifier.closed ?? null,
  };
  // SERIAL BY EVIDENCE, OR NOT CLAIMED. One verifier is released for every window after the first,
  // every one of those releases was confirmed, and -- the fact a mere count of closed releases
  // cannot establish -- each PREDECESSOR'S release was confirmed NO LATER than the moment its
  // successor's allocation began. The timestamps are compared pairwise across the complete order:
  // predecessor allocation <= predecessor physical release <= successor allocation. A reversed
  // edge yields false; a missing reading yields null (unknown, never a silent proof); a missing
  // release record or an unconfirmed one yields false. Never true on incomplete evidence.
  const expectedReleases = Math.max(0, records.length - 1);
  const nonEmptyIdentity = (value) => typeof value === 'string' && value.length > 0;
  const orderedPairs = () => {
    for (let i = 1; i < records.length; i += 1) {
      const predecessor = records[i - 1];
      const predecessorRelease = released[i - 1];
      const predecessorStarted = records[i - 1]?.verifierAllocationStartedAtMs;
      const successorStarted = records[i]?.verifierAllocationStartedAtMs;
      const predecessorReleased = released[i - 1]?.releasedAtMs;
      if (predecessorRelease?.window !== predecessor?.window
        || !nonEmptyIdentity(predecessorRelease?.jobId)
        || predecessorRelease.jobId !== predecessor?.jobId
        || !nonEmptyIdentity(predecessorRelease?.issuanceId)
        || predecessorRelease.issuanceId !== predecessor?.issuanceId
        || String(predecessorRelease?.contextHeight ?? '') !== String(predecessor?.height ?? '')) {
        return false;
      }
      if (Number.isSafeInteger(predecessorStarted) && Number.isSafeInteger(predecessorReleased)
        && predecessorStarted > predecessorReleased) {
        return false;
      }
      if (Number.isSafeInteger(predecessorReleased) && Number.isSafeInteger(successorStarted)
        && predecessorReleased > successorStarted) {
        return false;
      }
    }
    for (let i = 1; i < records.length; i += 1) {
      const predecessorStarted = records[i - 1]?.verifierAllocationStartedAtMs;
      const successorStarted = records[i]?.verifierAllocationStartedAtMs;
      const predecessorReleased = released[i - 1]?.releasedAtMs;
      if (!Number.isSafeInteger(predecessorStarted) || !Number.isSafeInteger(predecessorReleased)
        || !Number.isSafeInteger(successorStarted)) {
        return null;
      }
    }
    return true;
  };
  const serialReleaseBeforeNextAllocation = records.length < 2
    ? null
    : (released.length !== expectedReleases || !released.every((v) => v.closed === true)
      ? false
      : orderedPairs());
  // PER-WINDOW OUTCOME FACTS, from what the runtime actually retained. The session persists each
  // retired window's own settled counters and its cause; the FINAL window's outcome is the
  // session-level terminal reason recorded below, not a per-window claim. Hashing attempts per
  // window are a page-side count the server never makes, so `attempts` is labelled null rather
  // than rounded to any number.
  const outcomes = Array.isArray(facts[0]?.windowOutcomes) ? facts[0].windowOutcomes : null;
  const outcomeFor = (w) => (outcomes === null ? null : (outcomes.find((o) => o.window === w)?.outcome ?? null));
  return {
    requestedWindows,
    windowsIssued: records.length === 0 ? null : records.length,
    windows: records.map((w) => ({
      window: w.window ?? null,
      jobId: w.jobId ?? null,
      issuanceId: w.issuanceId ?? null,
      nonceStart: safeUint(w.nonceStart),
      nonceRange: safeUint(w.nonceRange),
      height: uintText(w.height),
      shareDifficulty: safeUint(w.shareDifficulty),
      blockDifficulty: safeUint(w.blockDifficulty),
      shareTargetHexLE: targetHex(w.shareTargetHexLE),
      blockTargetHexLE: targetHex(w.blockTargetHexLE),
      contentDigest: targetHex(w.contentDigest),
      epochKeyHex: targetHex(w.epochKeyHex),
      seedHashHex: targetHex(w.seedHashHex),
      hashingTemplateSha256: targetHex(w.hashingTemplateSha256),
      verifierAllocationStartedAtMs: Number.isSafeInteger(w.verifierAllocationStartedAtMs)
        ? w.verifierAllocationStartedAtMs
        : null,
      outcome: outcomeFor(w.window ?? -1),
      attempts: null,
    })),
    disjointWindows: records.length < 2 ? null : records.every((w, i) => (
      i === 0 || (Number.isSafeInteger(w.nonceStart) && Number.isSafeInteger(records[i - 1].nonceStart)
        && Number.isSafeInteger(records[i - 1].nonceRange)
        && w.nonceStart >= records[i - 1].nonceStart + records[i - 1].nonceRange)
    )),
    verifiersReleased: released,
    verifierLive: live,
    serialReleaseBeforeNextAllocation,
    // The session total, which a rotation does not reset, ALONGSIDE the current window's own count.
    sharesAcceptedTotal: sum('sharesAcceptedTotal'),
    sharesAcceptedCurrentWindow: sum('sharesAccepted'),
    invalidCandidatesTotal: sum('invalidCandidatesTotal'),
    cumulativeAttempts: Number.isSafeInteger(cumulativeAttempts) ? cumulativeAttempts : null,
    sessionDeadlineAtMs: facts.length === 0 ? null : (facts[0].sessionDeadlineAtMs ?? null),
    sessionBudgetSpent: facts.length === 0 ? null : (facts[0].sessionBudgetSpent ?? null),
    attemptState: attemptState ?? null,
    terminalReason: attemptReason ?? null,
    blockClaimed: Number.isSafeInteger(submitBlockCount) ? submitBlockCount > 0 : null,
    daemonSubmitBlock: Number.isSafeInteger(submitBlockCount) ? submitBlockCount : null,
    daemonCalcPow: Number.isSafeInteger(calcPowCount) ? calcPowCount : null,
  };
}

/** Evidence for the Cartesian sequenceBlocks x refreshWindows runner mode. */
function sequenceRefreshEvidence({
  requestedBlocks, requestedWindows, windowRecords, sessionFacts, verifierHistory, currentVerifier,
  pageBlocks, attemptState, attemptReason, submitBlockCount, calcPowCount, cumulativeAttempts,
}) {
  if (!Number.isSafeInteger(requestedBlocks) || requestedBlocks < 2
    || !Number.isSafeInteger(requestedWindows) || requestedWindows < 2
    || requestedBlocks * requestedWindows > REAL_MAX_CONTEXTS_PER_START) return null;
  const records = Array.isArray(windowRecords) ? windowRecords : [];
  const facts = Array.isArray(sessionFacts) ? sessionFacts : [];
  const history = Array.isArray(verifierHistory) ? verifierHistory : [];
  const blocks = Array.isArray(pageBlocks) ? pageBlocks : [];
  const nonEmpty = (v) => typeof v === 'string' && v.length > 0;
  const safeUint = (v) => (Number.isSafeInteger(v) && v >= 0 ? v : null);
  const outcomes = Array.isArray(facts[0]?.windowOutcomes) ? facts[0].windowOutcomes : null;
  const coordinateStep = (prev, current) => (
    current?.block === prev?.block
      ? current.window === prev.window + 1 && current.window <= requestedWindows
      : current?.block === prev?.block + 1 && current.window === 1 && current.block <= requestedBlocks
  );
  const expectedCoordinates = Array.from({ length: requestedBlocks }, (_, blockIndex) => (
    Array.from({ length: requestedWindows }, (_, windowIndex) => [blockIndex + 1, windowIndex + 1])
  )).flat();
  // A block may legally win before its final configured window. Exactness therefore means ordered,
  // contiguous prefixes (H1W1[,H1W2], then H2W1[,H2W2]), not that every maximum window existed.
  const coordinatesExact = records.length === 0 ? null : (
    records[0]?.block === 1 && records[0]?.window === 1
    && records.every((r, i) => i === 0 || coordinateStep(records[i - 1], r))
  );
  const fullGridIssued = records.length === expectedCoordinates.length
    && records.every((r, i) => r?.block === expectedCoordinates[i][0] && r?.window === expectedCoordinates[i][1]);
  const disjointWithinBlock = records.length < 2 ? null : records.every((r, i) => {
    if (i === 0 || r.block !== records[i - 1].block) return true;
    const prev = records[i - 1];
    return Number.isSafeInteger(r.nonceStart) && Number.isSafeInteger(prev.nonceStart)
      && Number.isSafeInteger(prev.nonceRange) && r.nonceStart >= prev.nonceStart + prev.nonceRange;
  });
  const perBlockNonceReset = records.length === 0 ? null : records
    .filter((r) => r?.window === 1)
    .every((r) => r?.nonceStart === 0);
  let serialReleaseBeforeNextAllocation = records.length < 2 ? null : true;
  if (records.length >= 2 && history.length !== records.length - 1) serialReleaseBeforeNextAllocation = false;
  for (let i = 1; i < records.length && serialReleaseBeforeNextAllocation !== false; i += 1) {
    const predecessor = records[i - 1];
    const successor = records[i];
    const release = history[i - 1];
    if (release?.closed !== true || release?.block !== predecessor?.block || release?.window !== predecessor?.window
      || !nonEmpty(release?.jobId) || release.jobId !== predecessor?.jobId
      || !nonEmpty(release?.issuanceId) || release.issuanceId !== predecessor?.issuanceId
      || String(release?.context?.height ?? '') !== String(predecessor?.height ?? '')) {
      serialReleaseBeforeNextAllocation = false;
      break;
    }
    const ownStart = predecessor?.verifierAllocationStartedAtMs;
    const releasedAt = release?.releasedAtMs;
    const nextStart = successor?.verifierAllocationStartedAtMs;
    if (Number.isSafeInteger(ownStart) && Number.isSafeInteger(releasedAt) && ownStart > releasedAt) {
      serialReleaseBeforeNextAllocation = false;
    } else if (Number.isSafeInteger(releasedAt) && Number.isSafeInteger(nextStart) && releasedAt > nextStart) {
      serialReleaseBeforeNextAllocation = false;
    } else if (!Number.isSafeInteger(ownStart) || !Number.isSafeInteger(releasedAt) || !Number.isSafeInteger(nextStart)) {
      serialReleaseBeforeNextAllocation = null;
    }
  }
  const mapped = records.map((r) => ({
    block: r.block ?? null, window: r.window ?? null, jobId: r.jobId ?? null,
    issuanceId: r.issuanceId ?? null, height: String(r.height ?? ''),
    nonceStart: safeUint(r.nonceStart), nonceRange: safeUint(r.nonceRange),
    verifierAllocationStartedAtMs: safeUint(r.verifierAllocationStartedAtMs),
    outcome: outcomes === null ? null
      : (outcomes.find((o) => o.block === r.block && o.window === r.window)?.outcome ?? null),
  }));
  const perBlock = Array.from({ length: requestedBlocks }, (_, index) => {
    const block = index + 1;
    const issued = mapped.filter((r) => r.block === block);
    const page = blocks.find((b) => b.block === block) ?? null;
    return {
      block, windowsIssued: issued.length === 0 ? null : issued.length,
      issuedCoordinates: issued.map((r) => [r.block, r.window]),
      acceptedJobId: page?.jobId ?? null,
      acceptedHeight: page?.height ?? null,
      attempts: safeUint(page?.attempts),
      blockId: page?.blockId ?? null,
    };
  });
  const sum = (key) => (facts.length === 0 ? null : facts.reduce((n, f) => n + (f[key] ?? 0), 0));
  return {
    requestedBlocks, requestedWindows, contextCeiling: REAL_MAX_CONTEXTS_PER_START,
    contextsIssued: records.length === 0 ? null : records.length,
    contexts: mapped, coordinatesExact, fullGridIssued, disjointWithinBlock, perBlockNonceReset,
    serialReleaseBeforeNextAllocation,
    verifiersReleased: history.map((v) => ({
      block: v?.block ?? null, window: v?.window ?? null, jobId: v?.jobId ?? null,
      issuanceId: v?.issuanceId ?? null, releasedAtMs: v?.releasedAtMs ?? null, closed: v?.closed ?? null,
    })),
    verifierLive: currentVerifier === null || currentVerifier === undefined ? null : {
      block: currentVerifier.block ?? null, window: currentVerifier.window ?? null,
      helperLinuxPid: currentVerifier.helperLinuxPid ?? null, closed: currentVerifier.closed ?? null,
    },
    perBlock,
    sharesAcceptedTotal: sum('sharesAcceptedTotal'),
    sharesAcceptedCurrentContext: sum('sharesAccepted'),
    invalidCandidatesTotal: sum('invalidCandidatesTotal'),
    cumulativeAttempts: safeUint(cumulativeAttempts),
    sessionDeadlineAtMs: facts.length === 0 ? null : (facts[0].sessionDeadlineAtMs ?? null),
    sessionBudgetSpent: facts.length === 0 ? null : (facts[0].sessionBudgetSpent ?? null),
    attemptState: attemptState ?? null, terminalReason: attemptReason ?? null,
    blockClaims: Number.isSafeInteger(submitBlockCount) ? submitBlockCount : null,
    daemonSubmitBlock: Number.isSafeInteger(submitBlockCount) ? submitBlockCount : null,
    daemonCalcPow: Number.isSafeInteger(calcPowCount) ? calcPowCount : null,
  };
}

/**
 * THE TRACKED TREE, from `git status --porcelain`, with the user's own untracked paths dropped BY
 * NAME. Nothing here opens, reads, stages or removes them: they are recognised from the status line
 * alone. Anything else -- a modification, a staged change, another untracked path -- is returned and
 * stops the run.
 */
function trackedDirtyEntries(porcelain, allowedUntracked) {
  return String(porcelain ?? '').split(/\r?\n/).filter(Boolean)
    .filter((line) => {
      if (!line.startsWith('?? ')) return true;              // tracked change: always dirty
      const path = line.slice(3).replace(/^"|"$/g, '');
      return !allowedUntracked.includes(path) && !allowedUntracked.includes(`${path}/`);
    });
}

/**
 * THE DURABLE ONE-USE RESERVATION, created before any live side effect.
 *
 * Exclusive creation ('wx') is the whole mechanism: the filesystem decides, once, whether this path
 * was already consumed. A second invocation -- a restart, a re-run after a failure, an accidental
 * double launch -- finds the file present and is refused, so one authorization cannot become two
 * runs. The payload is read back and compared before the caller is allowed to continue, so a write
 * that did not land is a refusal rather than a silent success. Nothing here ever deletes or
 * overwrites a reservation.
 *
 * @returns {{ok:boolean, reason:string|null, payload:object|null}}
 */
function reserveOneUse({ path, payload, writeFile, readFile }) {
  const text = `${JSON.stringify(payload, null, 2)}\n`;
  try {
    writeFile(path, text, { flag: 'wx' });
  } catch (err) {
    return {
      ok: false,
      reason: err?.code === 'EEXIST'
        ? 'this reservation path was already consumed; a new authorization needs a new path'
        : `the reservation could not be created: ${err?.code ?? err?.message ?? err}`,
      payload: null,
    };
  }
  let readBack = null;
  try {
    readBack = JSON.parse(readFile(path, 'utf8'));
  } catch (err) {
    return { ok: false, reason: `the reservation could not be read back: ${err?.message ?? err}`, payload: null };
  }
  if (JSON.stringify(readBack) !== JSON.stringify(payload)) {
    return { ok: false, reason: 'the reservation on disk is not what was written', payload: readBack };
  }
  return { ok: true, reason: null, payload: readBack };
}

/**
 * THE COMMIT PIN, decided from the AUDITOR'S value and git's answers, never from HEAD itself.
 *
 * Both git invocations must have SUCCEEDED: a `git status --porcelain` that failed (exit != 0) says
 * nothing about cleanliness, and treating its empty stdout as "clean" is exactly how a broken
 * working-tree check passes. An expected head that is not 40 lowercase hex is refused before it is
 * compared with anything.
 *
 * @returns {{ok:boolean, error:string|null, head:string|null, trackedDirty:string[]}}
 */
function classifyHeadPin({ expectedHead, headResult, statusResult, allowedUntracked, trackedDirty }) {
  if (!/^[0-9a-f]{40}$/.test(String(expectedHead ?? ''))) {
    return { ok: false, error: 'the supplied --expected-head is not 40 lowercase hex', head: null, trackedDirty: [] };
  }
  if (headResult?.status !== 0) {
    return { ok: false, error: `git rev-parse HEAD failed (exit ${headResult?.status ?? 'null'})`, head: null, trackedDirty: [] };
  }
  const head = String(headResult.stdout ?? '').trim();
  if (!/^[0-9a-f]{40}$/.test(head)) {
    return { ok: false, error: `git reported an unusable HEAD: ${head.slice(0, 80)}`, head: null, trackedDirty: [] };
  }
  if (head !== expectedHead) {
    return { ok: false, error: `HEAD ${head} is not the authorized commit ${expectedHead}`, head, trackedDirty: [] };
  }
  if (statusResult?.status !== 0) {
    return { ok: false, error: `git status --porcelain failed (exit ${statusResult?.status ?? 'null'}); cleanliness is unproven`, head, trackedDirty: [] };
  }
  const dirty = trackedDirty(String(statusResult.stdout ?? ''), allowedUntracked);
  if (dirty.length > 0) {
    return { ok: false, error: `the tracked tree is not clean: ${dirty.join(' | ')}`, head, trackedDirty: dirty };
  }
  return { ok: true, error: null, head, trackedDirty: [] };
}

/**
 * WHERE THE SHARE PATH'S EVIDENCE MAY BE PUBLISHED, AND IN WHAT ORDER.
 *
 * This returns candidates only: the primary name, then a unique sibling named after this run id.
 * NOTHING here checks whether they exist, because an existence check followed by a write is a race
 * -- between the look and the write, a third party can create the file, and a replacing writer then
 * destroys it. The decision belongs to the filesystem, made by exclusive creation in the writer.
 */
function publishCandidates({ path, runId }) {
  return [path, `${path}.${runId}.json`];
}

/**
 * PUBLISH WITHOUT EVER REPLACING SOMEBODY ELSE'S FILE.
 *
 * Each candidate is attempted with an EXCLUSIVE create: the write either lands on a name nobody
 * held, or it fails with 'exists' and that file is left exactly as it was -- never opened for
 * writing, never truncated, never removed. Only when every candidate is taken does this give up,
 * and giving up is reported, not worked around.
 *
 * @param {object} o
 * @param {string[]} o.candidates
 * @param {(path:string) => {ok:boolean, stage?:string}} o.write exclusive, no-replace writer
 * @returns {{ok:boolean, path:string|null, fallback:boolean, attempts:object[], reason:string|null}}
 */
function publishNoReplace({ candidates, write }) {
  const attempts = [];
  for (const [i, candidate] of candidates.entries()) {
    const r = write(candidate);
    attempts.push({ path: candidate, ok: r.ok === true, stage: r.stage ?? null, code: r.code ?? null });
    if (r.ok === true) {
      return {
        ok: true,
        path: candidate,
        fallback: i > 0,
        attempts,
        reason: i > 0
          ? 'the primary evidence path was taken by something else; this run published beside it and deleted nothing'
          : null,
      };
    }
    // Only a name that is TAKEN justifies trying the next one. A real write failure -- a full disk,
    // a read-only directory, a verification mismatch -- is reported as itself.
    if (r.stage !== 'exists') {
      return { ok: false, path: null, fallback: i > 0, attempts, reason: `the evidence could not be written: ${r.stage}` };
    }
  }
  return {
    ok: false,
    path: null,
    fallback: true,
    attempts,
    reason: 'every evidence path was already taken; nothing was overwritten and nothing was deleted',
  };
}

/**
 * ONE CAPTURED SERVER FRAME, ACCEPTED ONLY IF IT NAMES THIS EXACT RUN.
 *
 * A frame's `type` proves nothing. The server binds every run-scoped message with FIVE fields --
 * clientStartId, workerId, jobId, issuanceId, runGeneration -- and a frame that does not carry all
 * five, or carries different ones, belongs to another attempt, another page or another generation
 * of this one. Counting such a frame as a share, or trusting its block id, would let a stale or
 * replayed message decide what this run claims. The active binding is learned once, from the
 * server's own run_started, and is additionally cross-checked against the live template: the job id
 * and the issuance the pool is actually working on.
 *
 * @returns {{accepted:boolean, reason:string|null}}
 */
function classifyServerFrame({ frame, active, jobId, issuanceId }) {
  if (active === null || active === undefined) return { accepted: false, reason: 'no_active_binding' };
  const fields = ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration'];
  for (const f of fields) {
    const v = frame?.[f];
    if (v === null || v === undefined || v === '') return { accepted: false, reason: `missing_${f}` };
    // eslint-disable-next-line eqeqeq
    if (String(v) !== String(active[f])) return { accepted: false, reason: `mismatched_${f}` };
  }
  // The live template decides too: a binding for a job or issuance the pool is no longer working on
  // is stale, however well formed it is.
  if (jobId !== null && jobId !== undefined && String(frame.jobId) !== String(jobId)) {
    return { accepted: false, reason: 'stale_job' };
  }
  if (issuanceId !== null && issuanceId !== undefined && String(frame.issuanceId) !== String(issuanceId)) {
    return { accepted: false, reason: 'stale_issuance' };
  }
  if (frame.type === 'share_accepted') {
    if (!Number.isSafeInteger(frame.nonce) || frame.nonce < 0) return { accepted: false, reason: 'bad_nonce' };
    if (!/^[0-9a-f]{64}$/.test(String(frame.hashHexLE ?? ''))) return { accepted: false, reason: 'bad_hash' };
    return { accepted: true, reason: null };
  }
  if (frame.type === 'block_accepted' || frame.type === 'sequence_block_accepted') {
    if (!Number.isSafeInteger(frame.nonce) || frame.nonce < 0) return { accepted: false, reason: 'bad_nonce' };
    if (!/^[0-9a-f]{64}$/.test(String(frame.hashHexLE ?? ''))) return { accepted: false, reason: 'bad_hash' };
    if (!/^[0-9a-f]{64}$/.test(String(frame.blockId ?? ''))) return { accepted: false, reason: 'bad_block_id' };
    return { accepted: true, reason: null };
  }
  return { accepted: false, reason: 'not_an_evidence_frame' };
}

/** Advance the TWO-height share evidence binding only on a server-announced, chained next job. */
function classifyShareSequenceNext({ frame, active, firstBlockSeen }) {
  if (active?.sequenceIndex !== 1 || !firstBlockSeen) return { accepted: false, reason: 'no_accepted_first_block' };
  if (frame?.sequenceIndex !== 2 || frame.sequenceTotal !== 2 || frame.cause !== 'accepted') {
    return { accepted: false, reason: 'unexpected_sequence_transition' };
  }
  if (frame.previous?.jobId !== active.jobId || frame.previous?.issuanceId !== active.issuanceId
    || frame.previous?.runGeneration !== active.runGeneration) {
    return { accepted: false, reason: 'unchained_previous_binding' };
  }
  if (frame.clientStartId !== active.clientStartId || frame.workerId !== active.workerId
    || !Number.isSafeInteger(frame.runGeneration) || frame.runGeneration <= active.runGeneration
    || frame.jobId === active.jobId || frame.issuanceId === active.issuanceId
    || frame.job?.jobId !== frame.jobId || frame.job?.issuanceId !== frame.issuanceId
    || frame.job?.height !== '2' || frame.job?.shareWork !== true
    || !/^[0-9a-f]{64}$/.test(String(frame.job?.shareTargetHexLE ?? ''))) {
    return { accepted: false, reason: 'unusable_next_binding' };
  }
  return { accepted: true, reason: null };
}

/** Bound WebSocket evidence, kept by height so an old nonce can never count for the new template. */
function captureShareSequenceFrame({ state, frame, limit }) {
  const fields = ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration'];
  const reject = (reason) => {
    state.rejectedCount += 1;
    if (state.rejected.length < limit) state.rejected.push({ type: frame?.type ?? null, reason });
    return { accepted: false, reason };
  };
  if (frame?.type === 'run_started') {
    if (state.activeBinding !== null || fields.some((f) => frame[f] === null || frame[f] === undefined || frame[f] === '')) {
      return reject('invalid_or_duplicate_run_started');
    }
    state.activeBinding = Object.fromEntries(fields.map((f) => [f, frame[f]]));
    state.activeBinding.sequenceIndex = 1;
    state.bindings.push({ ...state.activeBinding });
    state.captured = true;
    return { accepted: true, reason: null };
  }
  if (frame?.type === 'sequence_next') {
    const verdict = classifyShareSequenceNext({
      frame, active: state.activeBinding, firstBlockSeen: state.blocks.some((b) => b.sequenceIndex === 1),
    });
    if (!verdict.accepted) return reject(verdict.reason);
    state.activeBinding = Object.fromEntries(fields.map((f) => [f, frame[f]]));
    state.activeBinding.sequenceIndex = 2;
    state.bindings.push({ ...state.activeBinding });
    state.captured = true;
    return { accepted: true, reason: null };
  }
  if (!['share_accepted', 'sequence_block_accepted', 'block_accepted'].includes(frame?.type)) {
    return { accepted: false, reason: 'not_an_evidence_frame' };
  }
  state.captured = true;
  const active = state.activeBinding;
  const verdict = classifyServerFrame({ frame, active, jobId: null, issuanceId: null });
  if (!verdict.accepted) return reject(verdict.reason);
  if (frame.type === 'share_accepted' && frame.sequenceIndex !== active.sequenceIndex) {
    return reject('share_wrong_sequence_index');
  }
  if (frame.type === 'sequence_block_accepted'
    && (frame.sequenceIndex !== active.sequenceIndex || frame.sequenceTotal !== 2
      || frame.height !== String(active.sequenceIndex)
      || !/^[0-9a-f]{64}$/.test(String(frame.hashHexLE ?? '')))) {
    return reject('block_wrong_sequence_index_or_hash');
  }
  if (frame.type === 'block_accepted'
    && (active.sequenceIndex !== 2 || frame.height !== '2'
      || !/^[0-9a-f]{64}$/.test(String(frame.hashHexLE ?? '')))) {
    return reject('terminal_block_wrong_height_or_hash');
  }
  const list = frame.type === 'share_accepted' ? state.shares
    : (frame.type === 'sequence_block_accepted' ? state.blocks : state.terminalBlocks);
  if (list.length >= limit) { state.truncated = true; return reject('capture_limit_reached'); }
  if (list.some((item) => item.sequenceIndex === active.sequenceIndex && item.nonce === frame.nonce)) {
    return reject('duplicate_bound_frame');
  }
  list.push({
    type: frame.type, sequenceIndex: active.sequenceIndex,
    nonce: frame.nonce, hashHexLE: frame.hashHexLE,
    blockId: frame.blockId ?? null, sharesAccepted: frame.sharesAccepted ?? null,
    sharesAcceptedTotal: frame.sharesAcceptedTotal ?? null,
    boundTo: { ...active },
  });
  return { accepted: true, reason: null };
}

/**
 * THE ONE LEGAL BINDING TRANSITION OF A SAME-HEIGHT REFRESH, as the bound frame must state it.
 *
 * The active binding is learned from the server's run_started and revised ONLY here. A job_refresh
 * advances it when it extends EXACTLY what the page holds: the same Start and worker, a previous
 * binding that is byte-for-byte the active one, a strictly newer run generation, the next window
 * index under the same declared total, a DIFFERENT job and issuance, and a job whose own facts are
 * usable -- share work on, a well-formed share target, and a nonce window that neither overflows
 * the uint32 space nor overlaps the window it replaces when that window's facts are known. Anything
 * else is a forged or stale transition and changes nothing.
 */
function classifyShareRefreshTransition({ frame, active, windowTotal }) {
  if (active === null || active === undefined) return { accepted: false, reason: 'no_active_binding' };
  if (frame?.type !== 'job_refresh') return { accepted: false, reason: 'not_a_refresh_transition' };
  if (frame.terminal === true) return { accepted: false, reason: 'terminal_refresh_frame' };
  if (frame.cause !== 'window_exhausted') return { accepted: false, reason: 'unexpected_refresh_cause' };
  if (frame.previous?.jobId !== active.jobId || frame.previous?.issuanceId !== active.issuanceId
    || frame.previous?.runGeneration !== active.runGeneration) {
    return { accepted: false, reason: 'unchained_previous_binding' };
  }
  if (frame.clientStartId !== active.clientStartId || frame.workerId !== active.workerId) {
    return { accepted: false, reason: 'foreign_start_or_worker' };
  }
  if (!Number.isSafeInteger(frame.runGeneration) || frame.runGeneration <= active.runGeneration) {
    return { accepted: false, reason: 'non_increasing_generation' };
  }
  if (frame.windowIndex !== active.window + 1 || frame.windowTotal !== windowTotal
    || frame.windowIndex > windowTotal) {
    return { accepted: false, reason: 'unexpected_window_progression' };
  }
  if (frame.jobId === active.jobId || frame.issuanceId === active.issuanceId
    || frame.job?.jobId !== frame.jobId || frame.job?.issuanceId !== frame.issuanceId) {
    return { accepted: false, reason: 'unusable_next_binding' };
  }
  const job = frame.job ?? {};
  const jobFacts = refreshBrowserJobFacts(job);
  if (jobFacts === null) return { accepted: false, reason: 'unusable_next_job' };
  // SAME HEIGHT AND A DISJOINT WINDOW, checked against the previous window's browser-visible job
  // facts. The initial real_job is captured before run_started, and every later job is captured as
  // part of its validated transition, so this comparison applies to every legal handoff.
  if (active.jobFacts !== null && active.jobFacts !== undefined) {
    if (job.height !== active.jobFacts.height) return { accepted: false, reason: 'refresh_height_changed' };
    if (job.nonceStart < active.jobFacts.nonceStart + active.jobFacts.nonceRange) {
      return { accepted: false, reason: 'refresh_window_overlap' };
    }
  }
  return { accepted: true, reason: null, jobFacts };
}

/**
 * BOUND SHARE EVIDENCE FOR A REFRESH RUN, kept BY WINDOW so an old nonce can never count for a
 * window it was not issued for.
 *
 * The active binding starts at the server's run_started and advances ONLY through a validated
 * job_refresh. A share or block frame counts only against the CURRENT window's binding; a frame
 * that names an already-replaced window -- a late prior-window frame -- is QUARANTINED by name
 * rather than counted, and a frame that names no binding this run ever held is rejected as such.
 */
function captureShareRefreshFrame({ state, frame, limit, windowTotal }) {
  const fields = ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration'];
  const reject = (reason) => {
    state.rejectedCount += 1;
    if (state.rejected.length < limit) state.rejected.push({ type: frame?.type ?? null, reason });
    return { accepted: false, reason };
  };
  if (frame?.type === 'real_job') {
    if (state.activeBinding !== null || state.initialJobFacts !== null) {
      return reject('invalid_or_duplicate_initial_job');
    }
    const facts = refreshBrowserJobFacts(frame);
    if (facts === null) return reject('unusable_initial_job');
    state.initialJobFacts = facts;
    state.captured = true;
    return { accepted: true, reason: null };
  }
  if (frame?.type === 'run_started') {
    if (state.activeBinding !== null || fields.some((f) => frame[f] === null || frame[f] === undefined || frame[f] === '')) {
      return reject('invalid_or_duplicate_run_started');
    }
    if (state.initialJobFacts === null || state.initialJobFacts === undefined
      || frame.jobId !== state.initialJobFacts.jobId || frame.issuanceId !== state.initialJobFacts.issuanceId) {
      return reject('run_started_without_matching_initial_job');
    }
    state.activeBinding = Object.fromEntries(fields.map((f) => [f, frame[f]]));
    state.activeBinding.window = 1;
    state.activeBinding.jobFacts = state.initialJobFacts;
    state.bindings.push({ ...state.activeBinding });
    state.captured = true;
    return { accepted: true, reason: null };
  }
  if (frame?.type === 'job_refresh') {
    const verdict = classifyShareRefreshTransition({ frame, active: state.activeBinding, windowTotal });
    if (!verdict.accepted) return reject(verdict.reason);
    state.activeBinding = Object.fromEntries(fields.map((f) => [f, frame[f]]));
    state.activeBinding.window = frame.windowIndex;
    state.activeBinding.jobFacts = verdict.jobFacts;
    state.bindings.push({ ...state.activeBinding });
    state.captured = true;
    return { accepted: true, reason: null };
  }
  if (!['share_accepted', 'block_accepted'].includes(frame?.type)) {
    return { accepted: false, reason: 'not_an_evidence_frame' };
  }
  state.captured = true;
  const active = state.activeBinding;
  const verdict = classifyServerFrame({ frame, active, jobId: null, issuanceId: null });
  if (!verdict.accepted) {
    // A LATE FRAME FOR A WINDOW THAT WAS ALREADY REPLACED is quarantined by its own name: it names
    // a binding this run genuinely held, so it is not a forgery -- it is prior-window work arriving
    // after the handover, and it must not count for the window that is live now.
    const prior = (state.bindings.slice(0, -1) ?? [])
      .find((b) => fields.every((f) => String(frame?.[f] ?? '\u0000') === String(b[f])));
    if (prior !== undefined) return reject('stale_window_binding');
    return reject(verdict.reason);
  }
  const list = frame.type === 'share_accepted' ? state.shares : state.blocks;
  if (list.length >= limit) { state.truncated = true; return reject('capture_limit_reached'); }
  if (list.some((item) => item.window === active.window && item.nonce === frame.nonce)) {
    return reject('duplicate_bound_frame');
  }
  list.push({
    type: frame.type,
    window: active.window,
    nonce: frame.nonce,
    hashHexLE: frame.hashHexLE ?? null,
    blockId: frame.blockId ?? null,
    sharesAccepted: frame.sharesAccepted ?? null,
    sharesAcceptedTotal: frame.sharesAcceptedTotal ?? null,
    boundTo: Object.fromEntries([...fields, 'window'].map((f) => [f, active[f]])),
  });
  return { accepted: true, reason: null };
}

/** The only legal next-height transition in a composed block-by-window run. */
function classifyShareSequenceRefreshNext({ frame, active, blockTotal, windowTotal, sessionBudgetMs, acceptedBlock }) {
  if (active === null || active === undefined) return { accepted: false, reason: 'no_active_binding' };
  const fields = ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration'];
  if (acceptedBlock?.block !== active.block || acceptedBlock?.window !== active.window
    || fields.some((field) => acceptedBlock?.boundTo?.[field] !== active[field])) {
    return { accepted: false, reason: 'no_accepted_current_block' };
  }
  if (frame?.type !== 'sequence_next' || frame.cause !== 'accepted'
    || frame.sequenceIndex !== active.block + 1 || frame.sequenceTotal !== blockTotal
    || frame.sequenceIndex > blockTotal || frame.windowIndex !== 1 || frame.windowTotal !== windowTotal
    || frame.sessionBudgetMs !== sessionBudgetMs) {
    return { accepted: false, reason: 'unexpected_sequence_refresh_transition' };
  }
  if (frame.previous?.jobId !== active.jobId || frame.previous?.issuanceId !== active.issuanceId
    || frame.previous?.runGeneration !== active.runGeneration) {
    return { accepted: false, reason: 'unchained_previous_binding' };
  }
  if (frame.clientStartId !== active.clientStartId || frame.workerId !== active.workerId
    || !Number.isSafeInteger(frame.runGeneration) || frame.runGeneration <= active.runGeneration
    || frame.jobId === active.jobId || frame.issuanceId === active.issuanceId
    || frame.job?.jobId !== frame.jobId || frame.job?.issuanceId !== frame.issuanceId) {
    return { accepted: false, reason: 'unusable_next_binding' };
  }
  const jobFacts = refreshBrowserJobFacts(frame.job);
  if (jobFacts === null) return { accepted: false, reason: 'unusable_next_job' };
  let priorHeight;
  let nextHeight;
  try {
    priorHeight = BigInt(active.jobFacts?.height ?? '-1');
    nextHeight = BigInt(jobFacts.height);
  } catch {
    return { accepted: false, reason: 'unusable_next_height' };
  }
  if (nextHeight !== priorHeight + 1n || jobFacts.nonceStart !== 0) {
    return { accepted: false, reason: 'unexpected_next_height_or_window' };
  }
  return { accepted: true, reason: null, jobFacts };
}

/**
 * TWO-DIMENSIONAL BOUND SERVER EVIDENCE. Each accepted frame is assigned to exactly the active
 * `(block, window)` binding. The binding advances only by a validated same-block `job_refresh` or a
 * validated next-block `sequence_next`; a late frame from any earlier context is quarantined.
 */
function captureShareSequenceRefreshFrame({ state, frame, limit, blockTotal, windowTotal, sessionBudgetMs }) {
  const fields = ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration'];
  const reject = (reason) => {
    state.rejectedCount += 1;
    if (state.rejected.length < limit) state.rejected.push({ type: frame?.type ?? null, reason });
    return { accepted: false, reason };
  };
  const snapshot = (active) => Object.fromEntries([...fields, 'block', 'window'].map((f) => [f, active[f]]));
  if (frame?.type === 'real_job') {
    if (state.activeBinding !== null || state.initialJobFacts !== null) return reject('invalid_or_duplicate_initial_job');
    const facts = refreshBrowserJobFacts(frame);
    if (facts === null) return reject('unusable_initial_job');
    state.initialJobFacts = facts;
    state.captured = true;
    return { accepted: true, reason: null };
  }
  if (frame?.type === 'run_started') {
    if (state.activeBinding !== null || fields.some((f) => frame[f] === null || frame[f] === undefined || frame[f] === '')) {
      return reject('invalid_or_duplicate_run_started');
    }
    if (state.initialJobFacts === null || frame.jobId !== state.initialJobFacts.jobId
      || frame.issuanceId !== state.initialJobFacts.issuanceId) {
      return reject('run_started_without_matching_initial_job');
    }
    state.activeBinding = {
      ...Object.fromEntries(fields.map((f) => [f, frame[f]])),
      block: 1, window: 1, jobFacts: state.initialJobFacts,
    };
    state.bindings.push({ ...state.activeBinding });
    state.captured = true;
    return { accepted: true, reason: null };
  }
  if (frame?.type === 'job_refresh') {
    if (state.blocks.some((b) => b.block === state.activeBinding?.block)
      || state.terminalBlocks.length > 0) return reject('refresh_after_accepted_block');
    if (!state.readiness.some((r) => r.block === state.activeBinding?.block
      && r.window === state.activeBinding?.window)) return reject('refresh_before_context_ready');
    if (frame.sequenceIndex !== state.activeBinding?.block || frame.sequenceTotal !== blockTotal) {
      return reject('refresh_wrong_sequence_coordinate');
    }
    const verdict = classifyShareRefreshTransition({ frame, active: state.activeBinding, windowTotal });
    if (!verdict.accepted) return reject(verdict.reason);
    state.activeBinding = {
      ...Object.fromEntries(fields.map((f) => [f, frame[f]])),
      block: frame.sequenceIndex, window: frame.windowIndex, jobFacts: verdict.jobFacts,
    };
    state.bindings.push({ ...state.activeBinding });
    state.captured = true;
    return { accepted: true, reason: null };
  }
  if (frame?.type === 'sequence_next') {
    const active = state.activeBinding;
    const acceptedForActive = state.blocks.filter((b) => b.block === active?.block);
    if (acceptedForActive.length !== 1 || state.terminalBlocks.length > 0) {
      return reject('missing_or_conflicting_accepted_current_block');
    }
    const verdict = classifyShareSequenceRefreshNext({
      frame, active, blockTotal, windowTotal, sessionBudgetMs,
      acceptedBlock: acceptedForActive[0],
    });
    if (!verdict.accepted) return reject(verdict.reason);
    state.activeBinding = {
      ...Object.fromEntries(fields.map((f) => [f, frame[f]])),
      block: frame.sequenceIndex, window: 1, jobFacts: verdict.jobFacts,
    };
    state.bindings.push({ ...state.activeBinding });
    state.captured = true;
    return { accepted: true, reason: null };
  }
  if (frame?.type === 'mining_ready') {
    const active = state.activeBinding;
    const verdict = classifyServerFrame({ frame: { ...frame, type: 'share_accepted', nonce: 0, hashHexLE: '0'.repeat(64) }, active, jobId: null, issuanceId: null });
    if (!verdict.accepted || frame.sequenceIndex !== active?.block || frame.sequenceTotal !== blockTotal
      || frame.windowIndex !== active?.window || frame.windowTotal !== windowTotal
      || frame.sessionBudgetMs !== sessionBudgetMs) return reject('ready_wrong_context_binding');
    if (state.readiness.some((r) => r.block === active.block && r.window === active.window)) return reject('duplicate_context_ready');
    if (state.readiness.length >= limit) { state.truncated = true; return reject('capture_limit_reached'); }
    state.readiness.push({
      block: active.block,
      window: active.window,
      sessionBudgetMs: frame.sessionBudgetMs,
      boundTo: snapshot(active),
    });
    state.captured = true;
    return { accepted: true, reason: null };
  }
  if (!['share_accepted', 'sequence_block_accepted', 'block_accepted'].includes(frame?.type)) {
    return { accepted: false, reason: 'not_an_evidence_frame' };
  }
  state.captured = true;
  const active = state.activeBinding;
  const verdict = classifyServerFrame({ frame, active, jobId: null, issuanceId: null });
  if (!verdict.accepted) {
    const prior = state.bindings.slice(0, -1)
      .find((b) => fields.every((f) => String(frame?.[f] ?? '\u0000') === String(b[f])));
    return reject(prior === undefined ? verdict.reason : 'stale_context_binding');
  }
  if (!state.readiness.some((r) => r.block === active?.block && r.window === active?.window)) {
    return reject('evidence_before_context_ready');
  }
  const nonce = frame.nonce;
  const nonceStart = active?.jobFacts?.nonceStart;
  const nonceRange = active?.jobFacts?.nonceRange;
  if (!Number.isSafeInteger(nonce) || nonce < 0 || nonce > 0xffffffff
    || !Number.isSafeInteger(nonceStart) || !Number.isSafeInteger(nonceRange)
    || nonce < nonceStart || nonce >= nonceStart + nonceRange) {
    return reject('nonce_outside_active_context');
  }
  if (frame.type === 'share_accepted'
    && (frame.sequenceIndex !== active.block || frame.sequenceTotal !== blockTotal)) {
    return reject('share_wrong_context_coordinate');
  }
  if (frame.type === 'sequence_block_accepted'
    && (frame.sequenceIndex !== active.block || frame.sequenceTotal !== blockTotal
      || frame.height !== active.jobFacts?.height)) {
    return reject('block_wrong_context_coordinate');
  }
  if (frame.type === 'block_accepted'
    && (active.block !== blockTotal || frame.height !== active.jobFacts?.height)) {
    return reject('terminal_block_wrong_context_coordinate');
  }
  if (frame.type === 'sequence_block_accepted'
    && state.blocks.some((item) => item.block === active.block)) {
    return reject('duplicate_block_for_height');
  }
  if (frame.type === 'sequence_block_accepted'
    && state.shares.some((item) => item.block === active.block && item.window === active.window
      && item.nonce === frame.nonce)) {
    return reject('block_nonce_already_counted_as_share');
  }
  if (frame.type === 'block_accepted') {
    if (state.terminalBlocks.length > 0) return reject('duplicate_terminal_block');
    const accepted = state.blocks.filter((item) => item.block === active.block);
    if (accepted.length !== 1 || accepted[0].window !== active.window
      || accepted[0].nonce !== frame.nonce || accepted[0].hashHexLE !== frame.hashHexLE
      || accepted[0].blockId !== frame.blockId) return reject('terminal_block_conflicts_with_height_acceptance');
  }
  if (frame.type === 'share_accepted' && state.blocks.some((item) => item.block === active.block)) {
    return reject('share_after_accepted_block');
  }
  const list = frame.type === 'share_accepted' ? state.shares
    : (frame.type === 'sequence_block_accepted' ? state.blocks : state.terminalBlocks);
  if (list.length >= limit) { state.truncated = true; return reject('capture_limit_reached'); }
  if (list.some((item) => item.block === active.block && item.window === active.window && item.nonce === frame.nonce)) {
    return reject('duplicate_bound_frame');
  }
  list.push({
    type: frame.type, block: active.block, window: active.window,
    nonce: frame.nonce, hashHexLE: frame.hashHexLE ?? null, blockId: frame.blockId ?? null,
    sharesAccepted: frame.sharesAccepted ?? null, sharesAcceptedTotal: frame.sharesAcceptedTotal ?? null,
    boundTo: snapshot(active),
  });
  return { accepted: true, reason: null };
}

/**
 * HOW MANY SHARES THE SERVER ACCEPTED -- or the honest admission that it is unknown.
 *
 * Two independent sources: the live pool sessions' own CUMULATIVE accepted-share totals, and the
 * distinct nonces of the bound server->browser frames this runner captured from the page's
 * WebSocket. A closed socket disposes the session, so
 * an empty session set is NOT zero shares; it is no evidence from that source. Zero is reported only
 * when a source actually observed zero. The sources must agree; if they do not, the count is unknown
 * and the disagreement is recorded rather than averaged away.
 *
 * @returns {{shares:number|null, source:string, detail:object}}
 */
function reconcileShareCount({ sessionsPresent, sessionShares, frameShareNonces, frameShareKeys, framesCaptured }) {
  const fromSessions = sessionsPresent ? sessionShares : null;
  // The one-height mode can use a nonce as its identity. Cartesian callers must provide a key that
  // includes block and window: nonce zero in H1W1 and nonce zero in H2W1 are two real shares.
  const identities = frameShareKeys ?? frameShareNonces ?? [];
  const fromFrames = framesCaptured ? new Set(identities).size : null;
  const detail = {
    sessionsPresent, sessionShares: fromSessions, distinctShareFrameIdentities: fromFrames,
    identityKind: frameShareKeys === undefined ? 'nonce' : 'context+nonce', framesCaptured,
    ...(frameShareKeys === undefined ? { distinctShareFrameNonces: fromFrames } : {}),
  };
  if (fromSessions === null && fromFrames === null) {
    return { shares: null, source: 'none', detail };
  }
  if (fromSessions === null) return { shares: fromFrames, source: 'websocket_frames', detail };
  if (fromFrames === null) return { shares: fromSessions, source: 'pool_sessions', detail };
  if (fromSessions !== fromFrames) return { shares: null, source: 'disagreement', detail };
  return { shares: fromSessions, source: 'pool_sessions+websocket_frames', detail };
}

/**
 * DAEMON A'S OWN ANSWER, read out of the raw evidence record rather than from any in-memory field.
 *
 * calc_pow returns the hash as a bare JSON-RPC string result. An unparseable body, a missing result
 * or anything that is not 64 lowercase hex yields null, which the agreement check treats as a
 * disagreement -- never as a match.
 */
function daemonPowHashFromRaw(record) {
  try {
    const body = JSON.parse(String(record?.responseText ?? ''));
    const result = body?.result;
    return typeof result === 'string' && /^[0-9a-f]{64}$/.test(result) ? result : null;
  } catch {
    return null;
  }
}

/** One unique, non-overwriting screenshot file per phase of this run. */
function screenshotFileName({ runId, phase }) {
  return `meepcoin-share-run-${runId}-${phase}.png`;
}

/**
 * Exactly one thing earns success: a block accepted by A, received by B, and agreed by this browser.
 *
 * Everything below is REQUIRED for that claim, and each is a separate fact:
 *   * the RPC evidence is non-lossy (nothing was dropped from the raw record);
 *   * exactly one calc_pow and exactly one submit_block reached daemon A;
 *   * the page's own nonce and hash, the server Wasm hash, the native helper hash and daemon A's
 *     calc_pow hash are ONE value -- browser agreement, computed here, not a label read off a page;
 *   * the accepted block id came from a bound server block_accepted frame AND is the id B converged
 *     on AND is what the page shows.
 * A missing one is a failure of PROOF, reported as such, never rounded up to success.
 *
 * Shares are not blocks. A run that verified shares and found no block is a bounded observation; an
 * unknown share count stays unknown, because "0" would be a claim nobody established.
 */
function classifyShareRunOutcome({
  attemptState, attemptReason, completeState, shares, shareSource, submitBlockCount, calcPowCount,
  rawDropped, propagation, bWriteMethods, agreement, rpcRequestBodies, blockIdFromFrame, pageBlockId,
}) {
  if (submitBlockCount > 1) return 'FAILED:more_than_one_submission';
  if (Array.isArray(bWriteMethods) && bWriteMethods.length > 0) return 'FAILED:rpc_write_to_daemon_b';
  if (attemptState === completeState) {
    if (rawDropped !== 0) return 'FAILED:rpc_evidence_truncated';
    if (submitBlockCount !== 1) return 'FAILED:complete_without_one_submission';
    if (calcPowCount !== 1) return `FAILED:expected_one_calc_pow_saw_${calcPowCount}`;
    if (rpcRequestBodies?.proven !== true) {
      return `FAILED:rpc_request_body_mismatch:${rpcRequestBodies?.reason ?? 'unknown'}`;
    }
    if (agreement?.agreed !== true) return `FAILED:browser_agreement_not_established:${agreement?.reason ?? 'unknown'}`;
    if (!/^[0-9a-f]{64}$/.test(String(blockIdFromFrame ?? ''))) return 'FAILED:no_bound_block_accepted_frame';
    if (propagation?.converged !== true) return `FAILED:${propagation?.reason ?? 'propagation_not_converged'}`;
    const peerId = propagation?.aHeader?.hash ?? null;
    if (peerId !== blockIdFromFrame) return 'FAILED:accepted_block_id_mismatch';
    // THE PAGE MUST SHOW THE SAME BLOCK. An absent id is not a pass: it means the browser never
    // displayed the accepted block, so the page's agreement with A and B is simply not established.
    if (!/^[0-9a-f]{64}$/.test(String(pageBlockId ?? ''))) return 'FAILED:page_block_id_missing';
    if (pageBlockId !== blockIdFromFrame) return 'FAILED:page_block_id_mismatch';
    return shares === null
      ? 'SHARE_RUN_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B_WITH_UNPROVEN_SHARE_COUNT'
      : `SHARE_RUN_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B_AFTER_${shares}_ACCEPTED_SHARES`;
  }
  // No block. Anything sent to the daemon here would be unexplained.
  if (submitBlockCount !== 0) return 'FAILED:submission_without_an_accepted_block';
  if (attemptReason === 'search_bound_reached' || attemptReason === 'search_deadline_exceeded') {
    if (rawDropped !== 0) return 'FAILED:rpc_evidence_truncated';
    return shares === null
      ? `BOUNDED_OBSERVATION_NO_BLOCK_SHARE_COUNT_UNPROVEN_${shareSource ?? 'none'}`
      : `BOUNDED_OBSERVATION_NO_BLOCK_${shares}_ACCEPTED_SHARES_${calcPowCount}_CALC_POW`;
  }
  return `FAILED:${attemptReason ?? 'unknown'}`;
}

/**
 * THE HANDOFF PROBE'S OWN RESULT, kept separate from the underlying share/block result.
 *
 * A block in window 1 remains a fully verified, propagated block success, but it did not exercise
 * the engineering objective and therefore cannot make this probe pass. A pass requires the exact
 * two-window binding chain, a cap/exhaustion retirement of window 1, proven release-before-next-
 * allocation order, and a bound result from window 2 proving its browser context actually hashed.
 * Window 2 may then end with either a real block or the ordinary bounded no-block result.
 */
function classifyRefreshHandoffProbeOutcome({
  enabled, refreshRecord, frames, shareOutcome,
  expectedShareDifficulty, expectedBlockDifficulty, expectedShareTargetHexLE, expectedBlockTargetHexLE,
  expectedNonceRange, windowOneFacts, expectedShareCap, provenShareCount, pageAcceptedShares, agreement,
}) {
  if (enabled !== true) return null;
  const outcome = String(shareOutcome ?? '');
  const acceptedBlock = outcome.startsWith('SHARE_RUN_BLOCK_ACCEPTED');
  const boundedNoBlock = outcome.startsWith('BOUNDED_OBSERVATION_');
  if (refreshRecord?.requestedWindows !== 2) return 'FAILED:handoff_probe_wrong_requested_window_total';
  if (refreshRecord?.windowsIssued !== 2) {
    if (refreshRecord?.windowsIssued === 1 && refreshRecord?.blockClaimed === true && acceptedBlock) {
      return 'HANDOFF_PROBE_EARLY_BLOCK_ACCEPTED_HANDOFF_NOT_EXERCISED';
    }
    return `FAILED:handoff_probe_expected_two_windows_saw_${refreshRecord?.windowsIssued ?? 'unknown'}`;
  }
  const windows = Array.isArray(refreshRecord?.windows) ? refreshRecord.windows : [];
  if (windows.length !== 2 || windows[0]?.window !== 1 || windows[1]?.window !== 2) {
    return 'FAILED:handoff_probe_exact_window_records_not_proved';
  }
  if (windows[0].height === null || windows[0].height !== windows[1].height) {
    return 'FAILED:handoff_probe_same_height_not_proved';
  }
  if (!windows.every((w) => w.shareDifficulty === expectedShareDifficulty
    && w.blockDifficulty === expectedBlockDifficulty
    && w.shareTargetHexLE === expectedShareTargetHexLE
    && w.blockTargetHexLE === expectedBlockTargetHexLE)) {
    return 'FAILED:handoff_probe_window_runtime_facts_mismatch';
  }
  if (!Number.isSafeInteger(expectedNonceRange) || expectedNonceRange < 1
    || windows[0].nonceStart !== 0 || windows[0].nonceRange !== expectedNonceRange
    || windows[1].nonceStart !== expectedNonceRange || windows[1].nonceRange !== expectedNonceRange) {
    return 'FAILED:handoff_probe_unexpected_nonce_windows';
  }
  if (refreshRecord.disjointWindows !== true) return 'FAILED:handoff_probe_windows_not_proved_disjoint';
  if (refreshRecord.serialReleaseBeforeNextAllocation !== true) {
    return 'FAILED:handoff_probe_serial_release_not_proved';
  }
  if (refreshRecord.windows?.[0]?.outcome !== 'window_exhausted') {
    return 'FAILED:handoff_probe_first_window_not_exhausted';
  }
  if (windowOneFacts?.window !== 1 || windowOneFacts?.outcome !== 'window_exhausted'
    || windowOneFacts?.sharesAccepted !== expectedShareCap
    || windowOneFacts?.candidatesAdmitted !== expectedShareCap
    || windowOneFacts?.invalidCandidates !== 0) {
    return 'FAILED:handoff_probe_first_window_cap_not_proved';
  }
  // A non-block share increments both the server and page share counters. A block-quality candidate
  // takes the separate block path and is deliberately NOT also emitted as share_accepted. Therefore
  // a window-2 block may leave the cumulative count exactly at window 1's cap; the independently
  // bound block frame and hash agreement prove window 2 hashed in that case. A bounded no-block run
  // still needs a later accepted share, so it must exceed the cap.
  if (!Number.isSafeInteger(provenShareCount) || provenShareCount < expectedShareCap
    || (!acceptedBlock && provenShareCount <= expectedShareCap)) {
    return 'FAILED:handoff_probe_cumulative_share_count_not_proved';
  }
  if (!Number.isSafeInteger(pageAcceptedShares) || pageAcceptedShares !== provenShareCount) {
    return 'FAILED:handoff_probe_page_acceptance_not_reconciled';
  }
  if (frames?.captured !== true || frames?.truncated === true) {
    return 'FAILED:handoff_probe_frame_capture_incomplete';
  }
  const bindings = Array.isArray(frames?.bindings) ? frames.bindings : [];
  if (bindings.length !== 2 || bindings[0]?.window !== 1 || bindings[1]?.window !== 2) {
    return 'FAILED:handoff_probe_binding_chain_not_proved';
  }
  // THE FRAME LABEL `window: 2` IS NOT EVIDENCE BY ITSELF. Tie both captured bindings back to the
  // exact server-owned issuance records, then tie the later result to every field of binding 2 and
  // to its half-open nonce range. This prevents an unrelated/stale frame from satisfying the probe
  // merely because somebody labelled it as the second window.
  const bindingFields = ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration', 'window'];
  const nonEmpty = (value) => value !== null && value !== undefined && value !== '';
  const recordBindingsMatch = bindings.every((binding, i) => (
    nonEmpty(binding?.jobId) && nonEmpty(binding?.issuanceId)
    && binding.jobId === windows[i].jobId && binding.issuanceId === windows[i].issuanceId
  ));
  if (!recordBindingsMatch || bindings[0].jobId === bindings[1].jobId
    || bindings[0].issuanceId === bindings[1].issuanceId) {
    return 'FAILED:handoff_probe_binding_chain_not_proved';
  }
  const browserFactsMatch = (browser, server) => browser?.shareWork === true
    && browser.jobId === server.jobId && browser.issuanceId === server.issuanceId
    && browser.height === server.height && browser.nonceStart === server.nonceStart
    && browser.nonceRange === server.nonceRange
    && browser.shareTargetHexLE === server.shareTargetHexLE
    && browser.blockTargetHexLE === server.blockTargetHexLE
    && browser.contentDigest === server.contentDigest
    && browser.epochKeyHex === server.epochKeyHex
    && browser.seedHashHex === server.seedHashHex
    && browser.hashingTemplateSha256 === server.hashingTemplateSha256;
  if (!browserFactsMatch(bindings[0]?.jobFacts, windows[0])) {
    return 'FAILED:handoff_probe_browser_window_one_facts_mismatch';
  }
  if (!browserFactsMatch(bindings[1]?.jobFacts, windows[1])) {
    return 'FAILED:handoff_probe_browser_window_two_facts_mismatch';
  }
  const inWindowTwo = (frame) => Number.isSafeInteger(frame?.nonce)
    && frame.nonce >= windows[1].nonceStart
    && frame.nonce < windows[1].nonceStart + windows[1].nonceRange;
  const boundToWindowTwo = (frame) => frame?.window === 2 && inWindowTwo(frame)
    && bindingFields.every((field) => nonEmpty(frame?.boundTo?.[field])
      && String(frame.boundTo[field]) === String(bindings[1][field]));
  const laterShare = Array.isArray(frames?.shares) && frames.shares.some((f) => (
    f?.type === 'share_accepted' && /^[0-9a-f]{64}$/.test(String(f?.hashHexLE ?? ''))
    && boundToWindowTwo(f)
  ));
  const laterBlock = Array.isArray(frames?.blocks) && frames.blocks.some((f) => (
    f?.type === 'block_accepted' && /^[0-9a-f]{64}$/.test(String(f?.blockId ?? ''))
    && /^[0-9a-f]{64}$/.test(String(f?.hashHexLE ?? ''))
    && boundToWindowTwo(f)
  ));
  if (!laterShare && !laterBlock) return 'FAILED:handoff_probe_window_two_hash_not_proved';
  if (acceptedBlock) {
    if (refreshRecord.blockClaimed !== true || refreshRecord.daemonCalcPow !== 1
      || refreshRecord.daemonSubmitBlock !== 1
      || !Array.isArray(frames?.blocks) || frames.blocks.length !== 1 || !laterBlock
      || agreement?.agreed !== true || frames.blocks[0].hashHexLE !== agreement.hashHexLE) {
      return 'FAILED:handoff_probe_block_evidence_inconsistent';
    }
    return 'HANDOFF_PROBE_EXERCISED_WINDOW_2_BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B';
  }
  if (boundedNoBlock) {
    if (refreshRecord.blockClaimed !== false || refreshRecord.daemonCalcPow !== 0
      || refreshRecord.daemonSubmitBlock !== 0
      || !Array.isArray(frames?.blocks) || frames.blocks.length !== 0) {
      return 'FAILED:handoff_probe_no_block_evidence_inconsistent';
    }
    return 'HANDOFF_PROBE_EXERCISED_BOUNDED_NO_BLOCK';
  }
  return `FAILED:handoff_probe_underlying_${outcome || 'unknown'}`;
}

/**
 * One pure finalization seam. Probe evidence contains BOTH meanings; ordinary evidence gains no
 * probe keys. Exit success for a probe is impossible unless the classifier says the handoff was
 * actually exercised, while the historical ordinary rule remains block-acceptance-only.
 */
function finalizeShareRun({ probe, shareOutcome, handoffProbeOutcome, okCode, failedCode }) {
  const finalOutcome = probe === true ? handoffProbeOutcome : shareOutcome;
  return {
    finalOutcome,
    evidenceFields: probe === true ? { shareOutcome, handoffProbeOutcome } : {},
    exitCode: probe === true
      ? (String(finalOutcome ?? '').startsWith('HANDOFF_PROBE_EXERCISED_') ? okCode : failedCode)
      : (String(shareOutcome ?? '').startsWith('SHARE_RUN_BLOCK_ACCEPTED') ? okCode : failedCode),
  };
}

/** Preserve the historical SHARE RUN event shape unless this exact probe was selected. */
function shareRunModeFacts({
  probe, legacyShareWork, legacyShareDifficulty, fixedBlockDifficulty,
  profileShareWork, jobShareDifficulty, jobBlockDifficulty,
}) {
  return probe === true
    ? { shareWork: profileShareWork === true, shareDifficulty: jobShareDifficulty, blockDifficulty: jobBlockDifficulty }
    : { shareWork: legacyShareWork, shareDifficulty: legacyShareDifficulty, blockDifficulty: fixedBlockDifficulty };
}

/** The two extra outcome labels are probe-only; ordinary transcripts remain byte-shape compatible. */
function shareRunProbeEvents({ probe, shareOutcome, handoffProbeOutcome }) {
  return probe === true
    ? [
      ['UNDERLYING SHARE/BLOCK OUTCOME', shareOutcome],
      ['HANDOFF PROBE OUTCOME', handoffProbeOutcome],
    ]
    : [];
}

/**
 * BROWSER AGREEMENT, computed from independent values rather than believed from a rendered label.
 *
 * One 64-hex hash must be reported by the page, recomputed by the server's Wasm, recomputed by the
 * native helper and returned by daemon A's calc_pow, and the page's found nonce must be the nonce
 * that was submitted. A missing value is a disagreement: nothing here defaults to "matched".
 */
function classifyBrowserAgreement({ pageNonce, submittedNonce, pageHash, serverWasmHash, nativeHash, daemonHash }) {
  const hashes = { pageHash, serverWasmHash, nativeHash, daemonHash };
  for (const [name, v] of Object.entries(hashes)) {
    if (!/^[0-9a-f]{64}$/.test(String(v ?? ''))) return { agreed: false, reason: `missing_${name}` };
  }
  const distinct = new Set(Object.values(hashes));
  if (distinct.size !== 1) return { agreed: false, reason: 'hash_disagreement' };
  if (pageNonce === null || pageNonce === undefined || submittedNonce === null || submittedNonce === undefined) {
    return { agreed: false, reason: 'missing_nonce' };
  }
  if (String(pageNonce) !== String(submittedNonce)) return { agreed: false, reason: 'nonce_mismatch' };
  return { agreed: true, reason: null, hashHexLE: pageHash };
}

/** Rebuild the exact nonce-bearing blob that block_run handed to the daemon adapter. */
function noncePatchedTemplateHex({ templateHex, nonce, nonceOffset, expectedBytes = null }) {
  if (typeof templateHex !== 'string' || templateHex.length === 0 || templateHex.length % 2 !== 0
    || !/^[0-9a-f]+$/.test(templateHex)
    || !Number.isSafeInteger(nonce) || nonce < 0 || nonce > 0xffffffff
    || !Number.isSafeInteger(nonceOffset) || nonceOffset < 0) return null;
  const bytes = Buffer.from(templateHex, 'hex');
  if ((expectedBytes !== null && (!Number.isSafeInteger(expectedBytes) || expectedBytes !== bytes.length))
    || nonceOffset + 4 > bytes.length) return null;
  bytes.writeUInt32LE(nonce, nonceOffset);
  return bytes.toString('hex');
}

/**
 * Prove the retained transport record is the adapter's canonical JSON serialization, byte for byte.
 * Parsing alone is insufficient: an extra field, reordered object or alternate serialization must not
 * be able to masquerade as the exact body that buildRequest emitted.
 */
function canonicalRpcRequestBodyMatches(record, method, params) {
  if (typeof record?.requestBody !== 'string') return false;
  try {
    const parsed = JSON.parse(record.requestBody);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)
      || parsed.jsonrpc !== '2.0' || typeof parsed.id !== 'string'
      || parsed.id.length === 0 || parsed.id.length > 64 || parsed.method !== method) return false;
    const expected = JSON.stringify({ jsonrpc: '2.0', id: parsed.id, method, params });
    return record.requestBody === expected;
  } catch {
    return false;
  }
}

/** Bind an accepted nonce to both exact daemon request bodies, reconstructed from retained template facts. */
function classifyAcceptedRpcRequestBodies({ templateFacts, nonce, calcRecord, submitRecord }) {
  const height = String(templateFacts?.height ?? '');
  if (!/^(?:0|[1-9][0-9]*)$/.test(height)
    || BigInt(height) > BigInt(Number.MAX_SAFE_INTEGER)
    || !Number.isInteger(templateFacts?.majorVersion)
    || templateFacts.majorVersion < 0 || templateFacts.majorVersion > 255
    || !/^[0-9a-f]{64}$/.test(String(templateFacts?.seedHashHex ?? ''))) {
    return { proven: false, reason: 'template_facts_invalid' };
  }
  const hashingBlob = noncePatchedTemplateHex({
    templateHex: templateFacts.blockhashingBlobHex,
    nonce,
    nonceOffset: templateFacts.hashingNonceOffset,
  });
  const fullBlock = noncePatchedTemplateHex({
    templateHex: templateFacts.blocktemplateBlobHex,
    nonce,
    nonceOffset: templateFacts.fullNonceOffset,
    expectedBytes: templateFacts.fullBlockBytes,
  });
  if (hashingBlob === null || fullBlock === null) {
    return { proven: false, reason: 'nonce_bearing_blob_invalid' };
  }
  const calcMatches = canonicalRpcRequestBodyMatches(calcRecord, 'calc_pow', {
    major_version: templateFacts.majorVersion,
    height: Number(height),
    block_blob: hashingBlob,
    seed_hash: templateFacts.seedHashHex,
  });
  if (!calcMatches) return { proven: false, reason: 'calc_pow_request_body_mismatch' };
  const submitMatches = canonicalRpcRequestBodyMatches(submitRecord, 'submit_block', [fullBlock]);
  if (!submitMatches) return { proven: false, reason: 'submit_block_request_body_mismatch' };
  return { proven: true, reason: null };
}

/** Require the same independent proof for EACH height of the bounded share sequence. */
function classifyShareSequenceOutcome({
  attemptState, attemptReason, completeState, currentHeight, records, raw, rawDropped,
  page, frames, sessionFacts, finalA, finalB, shareLimit,
}) {
  const fail = (reason, heights = []) => ({ outcome: `FAILED:${reason}`, heights });
  const bWrites = Object.keys(finalB ?? {}).filter((m) => ['submit_block', 'calc_pow', 'get_block_template'].includes(m));
  if (rawDropped !== 0) return fail('rpc_evidence_truncated');
  if (bWrites.length > 0) return fail('rpc_write_to_daemon_b');
  if (frames?.truncated || frames?.rejectedCount > 0 || frames?.captured !== true) return fail('server_frames_incomplete');
  if (attemptState !== completeState) {
    // A finite search can exhaust either height. It is an observation, never a block claim or a
    // reason to re-run, and no second template is inferred from the configured length.
    if (attemptReason === 'search_bound_reached' || attemptReason === 'search_deadline_exceeded') {
      if (!['1', '2'].includes(String(currentHeight))) return fail('unusable_bounded_height');
      return { outcome: `BOUNDED_OBSERVATION_NO_BLOCK_AT_HEIGHT_${currentHeight}`, heights: [] };
    }
    return fail(`${attemptReason ?? 'unknown'}@height${currentHeight}`);
  }
  if (records?.length !== 2 || frames.bindings?.length !== 2 || frames.blocks?.length !== 2
    || frames.terminalBlocks?.length !== 1 || page?.blocks?.length !== 2
    || Number(page.workersCreated) !== 1 || page.workerContexts?.length !== 2
    || (finalA?.get_block_template ?? 0) !== 2) return fail('two_height_shape_incomplete');
  if (sessionFacts?.length !== 1) return fail('session_share_counters_unavailable');
  const shares = frames.shares ?? [];
  if (shares.length > 2 * shareLimit) return fail('share_frame_budget_exceeded');
  let cumulativeShares = 0;
  const heights = [];
  for (let i = 1; i <= 2; i += 1) {
    const rec = records[i - 1];
    const binding = frames.bindings[i - 1];
    const blockFrame = frames.blocks.find((f) => f.sequenceIndex === i);
    const pageBlock = page.blocks.find((b) => b.block === i);
    const context = page.workerContexts.find((c) => c.jobId === binding?.jobId);
    const heightShares = shares.filter((f) => f.sequenceIndex === i);
    const calc = raw.filter((r) => r.block === i && r.method === 'calc_pow');
    const submits = raw.filter((r) => r.block === i && r.method === 'submit_block');
    const templates = raw.filter((r) => r.block === i && r.method === 'get_block_template');
    if (rec?.block !== i || !rec.accepted || !binding || !blockFrame || !pageBlock || !context
      || calc.length !== 1 || submits.length !== 1 || templates.length !== 1
      || heightShares.length >= shareLimit) return fail(`height_${i}_evidence_incomplete`, heights);
    if (binding.sequenceIndex !== i || rec.runGeneration !== binding.runGeneration
      || rec.accepted.jobId !== binding.jobId || rec.accepted.issuanceId !== binding.issuanceId
      || String(rec.accepted.height) !== String(i)
      || blockFrame.boundTo?.jobId !== binding.jobId || blockFrame.boundTo?.issuanceId !== binding.issuanceId
      || blockFrame.nonce !== rec.accepted.nonce || blockFrame.hashHexLE !== rec.accepted.hashHexLE
      || blockFrame.blockId !== rec.accepted.blockId
      || pageBlock.jobId !== binding.jobId || String(pageBlock.height) !== String(i)
      || pageBlock.nonce !== rec.accepted.nonce || pageBlock.hashHexLE !== rec.accepted.hashHexLE
      || pageBlock.blockId !== rec.accepted.blockId || pageBlock.browserMatched !== true) {
      return fail(`height_${i}_binding_or_block_mismatch`, heights);
    }
    if (rec.propagation?.converged !== true || rec.propagation.aHeader?.hash !== rec.accepted.blockId
      || rec.propagation.bHeader?.hash !== rec.accepted.blockId) {
      return fail(`height_${i}_exact_p2p_propagation_unproven`, heights);
    }
    const rpcBodies = classifyAcceptedRpcRequestBodies({
      templateFacts: rec.templateFacts,
      nonce: rec.accepted.nonce,
      calcRecord: calc[0],
      submitRecord: submits[0],
    });
    if (!rpcBodies.proven) return fail(`height_${i}_rpc_request_body_mismatch:${rpcBodies.reason}`, heights);
    const agreement = classifyBrowserAgreement({
      pageNonce: pageBlock.browserNonce, submittedNonce: blockFrame.nonce,
      pageHash: pageBlock.browserHashHexLE, serverWasmHash: rec.lastHashes?.serverWasmHex,
      nativeHash: rec.lastHashes?.nativeHelperHex, daemonHash: daemonPowHashFromRaw(calc[0]),
    });
    if (!agreement.agreed || agreement.hashHexLE !== rec.accepted.hashHexLE) {
      return fail(`height_${i}_hash_disagreement:${agreement.reason ?? 'accepted_hash'}`, heights);
    }
    for (let j = 0; j < heightShares.length; j += 1) {
      const share = heightShares[j];
      if (share.boundTo?.jobId !== binding.jobId || share.boundTo?.issuanceId !== binding.issuanceId
        || share.sharesAccepted !== j + 1 || share.sharesAcceptedTotal !== cumulativeShares + j + 1) {
        return fail(`height_${i}_share_count_or_binding_mismatch`, heights);
      }
    }
    cumulativeShares += heightShares.length;
    heights.push({
      height: i, jobId: binding.jobId, issuanceId: binding.issuanceId,
      nonce: rec.accepted.nonce, blockId: rec.accepted.blockId, hashHexLE: agreement.hashHexLE,
      acceptedNonBlockShares: heightShares.length, calcPow: 1, submitBlock: 1,
      exactPropagationToB: true, browserServerNativeDaemonHashAgreed: true,
    });
  }
  const finalFrame = frames.terminalBlocks[0];
  const last = heights[1];
  if (finalFrame.sequenceIndex !== 2 || finalFrame.nonce !== last.nonce
    || finalFrame.hashHexLE !== last.hashHexLE || finalFrame.blockId !== last.blockId) {
    return fail('terminal_block_frame_mismatch', heights);
  }
  if (sessionFacts[0].sharesAcceptedTotal !== cumulativeShares
    || sessionFacts[0].sharesAccepted !== heights[1].acceptedNonBlockShares
    || !String(page.outcome ?? '').startsWith('2 blocks accepted by node A')
    || (page.error && page.error !== '\u2014') || page.startDisabled !== true) {
    return fail('session_or_page_disagreement', heights);
  }
  if ((finalA.calc_pow ?? 0) !== 2 || (finalA.submit_block ?? 0) !== 2) return fail('extra_daemon_work', heights);
  return { outcome: 'SHARE_SEQUENCE_2_BLOCKS_ACCEPTED_BY_A_AND_RECEIVED_BY_B', heights };
}

/**
 * Require one composed proof, not a sequence proof plus an unrelated refresh summary. Every issued
 * context is named by (block, window, job, issuance), and each height is an exact contiguous window
 * prefix ending in its winning context. Thus the canonical 2x2 path is H1W1 -> H1W2 -> peer
 * convergence -> H2W1 -> H2W2, while a legitimate W1 win does not invent an unused W2.
 */
function classifyShareSequenceRefreshOutcome({
  attemptState, attemptReason, completeState, currentHeight, currentWindow,
  requestedBlocks, requestedWindows, maxAttempts, maxContexts, sessionBudgetMs,
  records, windowRecords, verifierHistory, currentVerifier, raw, rawDropped,
  page, frames, sessionFacts, finalA, finalB, shareLimit,
}) {
  const fail = (reason, contexts = [], heights = []) => ({ outcome: `FAILED:${reason}`, contexts, heights });
  const fields = ['clientStartId', 'workerId', 'jobId', 'issuanceId', 'runGeneration'];
  const sameBound = (bound, binding) => fields.every((field) => bound?.[field] === binding?.[field])
    && bound?.block === binding?.block && bound?.window === binding?.window;
  const templateExtendsRecordedTop = (template) => {
    const height = String(template?.height ?? '');
    const topBeforeHeight = String(template?.topBeforeHeight ?? '');
    if (!/^(?:0|[1-9][0-9]*)$/.test(height)
      || !/^(?:0|[1-9][0-9]*)$/.test(topBeforeHeight)) return false;
    return template?.prevHashHex === template?.topBeforeHash
      && BigInt(height) === BigInt(topBeforeHeight) + 1n;
  };
  const templateMatchesBinding = (template, binding) => (
    templateExtendsRecordedTop(template)
    && template?.block === binding?.block
    && template?.window === binding?.window
    && String(template?.height ?? '') === String(binding?.jobFacts?.height ?? '')
    && template?.jobId === binding?.jobId
    && template?.issuanceId === binding?.issuanceId
    && template?.nonceStart === binding?.jobFacts?.nonceStart
    && template?.nonceRange === binding?.jobFacts?.nonceRange
    && template?.targetHexLE === binding?.jobFacts?.blockTargetHexLE
    && template?.contentDigest === binding?.jobFacts?.contentDigest
    && template?.seedHashHex === binding?.jobFacts?.seedHashHex
  );
  const templateBuildsOnAccepted = (template, accepted) => {
    const templateHeight = String(template?.height ?? '');
    const acceptedHeight = String(accepted?.height ?? '');
    if (!/^(?:0|[1-9][0-9]*)$/.test(templateHeight)
      || !/^(?:0|[1-9][0-9]*)$/.test(acceptedHeight)) return false;
    return template?.prevHashHex === accepted?.blockId
      && template?.topBeforeHash === accepted?.blockId
      && String(template?.topBeforeHeight ?? '') === acceptedHeight
      && BigInt(templateHeight) === BigInt(acceptedHeight) + 1n;
  };
  const bWrites = Object.keys(finalB ?? {}).filter((method) => (
    ['submit_block', 'calc_pow', 'get_block_template'].includes(method)
  ));
  const capturedRpcMethods = new Set([
    'get_block_template', 'calc_pow', 'submit_block',
    'get_block_header_by_height', 'get_last_block_header',
  ]);
  if (!Number.isSafeInteger(requestedBlocks) || requestedBlocks < 2
    || !Number.isSafeInteger(requestedWindows) || requestedWindows < 2
    || requestedBlocks * requestedWindows > maxContexts) return fail('unsupported_sequence_refresh_shape');
  if (!Array.isArray(raw) || raw.some((item) => !capturedRpcMethods.has(item?.method))) {
    return fail('rpc_evidence_method_invalid');
  }
  if (rawDropped !== 0) return fail('rpc_evidence_truncated');
  if (bWrites.length > 0) return fail('rpc_write_to_daemon_b');
  if (frames?.truncated || frames?.rejectedCount > 0 || frames?.captured !== true) {
    return fail('server_frames_incomplete');
  }
  if (attemptState !== completeState) {
    if (attemptReason === 'search_bound_reached') {
      // A different bounded terminal exists between heights: the last admitted height was accepted,
      // independently read back and observed on peer B, but the one whole-Start clock passed before
      // a successor template could be issued. There is no current no-block height to describe. Keep
      // the accepted prefix, prove that every issued context ended with its verifier released, and
      // state explicitly that the successor was never observed rather than fabricating an H2 context
      // or collapsing valid H1 evidence into an undifferentiated failure.
      const acceptedBeforeSuccessor = Array.isArray(records)
        && records.length > 0
        && records.length < requestedBlocks
        && records.every((record) => record?.accepted !== null && record?.accepted !== undefined);
      if (acceptedBeforeSuccessor) {
        const acceptedCount = records.length;
        const issued = Array.isArray(windowRecords) ? windowRecords.length : 0;
        const active = frames.activeBinding;
        const rawTemplates = raw.filter((item) => item.method === 'get_block_template');
        const rawCalc = raw.filter((item) => item.method === 'calc_pow');
        const rawSubmit = raw.filter((item) => item.method === 'submit_block');
        const contexts = [];
        const heights = [];
        const lastAccepted = records.at(-1)?.accepted;
        if (issued < acceptedCount || issued > acceptedCount * requestedWindows
          || records.some((record, index) => record?.block !== index + 1)
          || frames.bindings?.length !== issued || frames.readiness?.length !== issued
          || frames.blocks?.length !== acceptedCount || frames.terminalBlocks?.length !== 0
          || page?.blocks?.length !== acceptedCount || Number(page?.workersCreated) !== 1
          || page?.workerContexts?.length !== issued || String(page?.staleWorkerMessages ?? '') !== '0'
          || verifierHistory?.length !== issued || currentVerifier !== null
          || sessionFacts?.length !== 1 || sessionFacts[0].sessionBudgetSpent !== true
          || !Number.isSafeInteger(sessionFacts[0].sessionDeadlineAtMs)
          || (finalA?.get_block_template ?? 0) !== issued
          || (finalA?.calc_pow ?? 0) !== acceptedCount
          || (finalA?.submit_block ?? 0) !== acceptedCount
          || rawTemplates.length !== issued || rawCalc.length !== acceptedCount
          || rawSubmit.length !== acceptedCount
          || String(currentHeight ?? '') !== String(lastAccepted?.height ?? '')
          || !Number.isSafeInteger(currentWindow)
          || currentWindow !== active?.window
          || active?.block !== acceptedCount) {
          return fail('accepted_prefix_before_successor_evidence_incomplete');
        }

        const bindingJobIds = frames.bindings.map((binding) => binding?.jobId);
        const bindingIssuanceIds = frames.bindings.map((binding) => binding?.issuanceId);
        if (new Set(bindingJobIds).size !== issued || new Set(bindingIssuanceIds).size !== issued
          || frames.bindings.some((binding, index) => !Number.isSafeInteger(binding?.runGeneration)
            || (index > 0 && binding.runGeneration !== frames.bindings[index - 1].runGeneration + 1))) {
          return fail('accepted_prefix_capability_reuse_or_generation_gap');
        }

        const windowsIssuedPerBlock = new Map();
        let cumulativeShares = 0;
        let contextIndex = 0;
        for (let block = 1; block <= acceptedCount; block += 1) {
          const windowsIssued = windowRecords.filter((record) => record?.block === block).length;
          if (windowsIssued < 1 || windowsIssued > requestedWindows) {
            return fail(`accepted_prefix_height_${block}_window_prefix_missing`, contexts, heights);
          }
          windowsIssuedPerBlock.set(block, windowsIssued);
          for (let window = 1; window <= windowsIssued; window += 1) {
            const record = windowRecords[contextIndex];
            const binding = frames.bindings[contextIndex];
            const ready = frames.readiness[contextIndex];
            const expectedNonceStart = (window - 1) * maxAttempts;
            const templates = rawTemplates.filter((item) => item.block === block && item.window === window);
            const workers = page.workerContexts.filter((worker) => worker?.jobId === binding?.jobId);
            if (record?.block !== block || record?.window !== window
              || binding?.block !== block || binding?.window !== window
              || ready?.block !== block || ready?.window !== window
              || ready?.sessionBudgetMs !== sessionBudgetMs || !sameBound(ready?.boundTo, binding)
              || record.jobId !== binding.jobId || record.issuanceId !== binding.issuanceId
              || String(record.height) !== String(binding.jobFacts?.height)
              || record.nonceStart !== expectedNonceStart || record.nonceRange !== maxAttempts
              || binding.jobFacts?.nonceStart !== record.nonceStart
              || binding.jobFacts?.nonceRange !== record.nonceRange
              || binding.jobFacts?.shareTargetHexLE !== record.shareTargetHexLE
              || binding.jobFacts?.blockTargetHexLE !== record.blockTargetHexLE
              || binding.jobFacts?.contentDigest !== record.contentDigest
              || binding.jobFacts?.epochKeyHex !== record.epochKeyHex
              || binding.jobFacts?.seedHashHex !== record.seedHashHex
              || binding.jobFacts?.hashingTemplateSha256 !== record.hashingTemplateSha256
              || templates.length !== 1 || templates[0].failure !== null
              || workers.length !== 1 || workers[0].contextIndex !== contextIndex + 1
              || workers[0].moduleInstances !== 1
              || !Number.isSafeInteger(workers[0].wasmHeapBytes) || workers[0].wasmHeapBytes < 1
              || (contextIndex === 0 && workers[0].rotated !== false)
              || (contextIndex > 0 && (workers[0].rotated !== true
                || workers[0].priorContextFreed !== true || workers[0].priorContextActive !== false))) {
              return fail('accepted_prefix_context_invalid', contexts, heights);
            }
            const release = verifierHistory[contextIndex];
            const successor = windowRecords[contextIndex + 1];
            if (release?.closed !== true || release.block !== block || release.window !== window
              || release.jobId !== binding.jobId || release.issuanceId !== binding.issuanceId
              || String(release.context?.height ?? '') !== String(record.height)
              || !Number.isSafeInteger(record.verifierAllocationStartedAtMs)
              || !Number.isSafeInteger(release.releasedAtMs)
              || record.verifierAllocationStartedAtMs > release.releasedAtMs
              || (successor !== undefined && (!Number.isSafeInteger(successor.verifierAllocationStartedAtMs)
                || release.releasedAtMs > successor.verifierAllocationStartedAtMs))) {
              return fail('accepted_prefix_release_chain_invalid', contexts, heights);
            }
            const contextShares = frames.shares.filter((share) => (
              share.block === block && share.window === window
            ));
            if (contextShares.length > shareLimit) {
              return fail('accepted_prefix_share_budget_exceeded', contexts, heights);
            }
            for (let shareIndex = 0; shareIndex < contextShares.length; shareIndex += 1) {
              const share = contextShares[shareIndex];
              if (!sameBound(share.boundTo, binding) || share.sharesAccepted !== shareIndex + 1
                || share.sharesAcceptedTotal !== cumulativeShares + shareIndex + 1) {
                return fail('accepted_prefix_share_count_or_binding_mismatch', contexts, heights);
              }
            }
            cumulativeShares += contextShares.length;
            contexts.push({
              block, window, height: String(record.height), jobId: binding.jobId,
              issuanceId: binding.issuanceId, nonceStart: record.nonceStart,
              nonceRange: record.nonceRange, workerContextIndex: workers[0].contextIndex,
              acceptedNonBlockShares: contextShares.length, templateRpc: 1,
              priorVerifierReleased: true,
            });
            contextIndex += 1;
          }
        }
        if (contextIndex !== issued) return fail('accepted_prefix_context_order_incomplete', contexts, heights);

        const issuedCoordinateKeys = new Set(windowRecords.map((record) => `${record.block}:${record.window}`));
        const shareKeys = frames.shares.map((share) => `${share.block}:${share.window}:${share.nonce}`);
        const finalContextShares = contexts.at(-1).acceptedNonBlockShares;
        if (raw.some((item) => !issuedCoordinateKeys.has(`${item?.block}:${item?.window}`))
          || new Set(shareKeys).size !== frames.shares.length
          || sessionFacts[0].sharesAcceptedTotal !== cumulativeShares
          || sessionFacts[0].sharesAccepted !== finalContextShares) {
          return fail('accepted_prefix_rpc_or_share_identity_mismatch', contexts, heights);
        }
        const expectedExhausted = [];
        for (let block = 1; block <= acceptedCount; block += 1) {
          for (let window = 1; window < windowsIssuedPerBlock.get(block); window += 1) {
            expectedExhausted.push([block, window]);
          }
        }
        const exhausted = sessionFacts[0].windowOutcomes;
        if (!Array.isArray(exhausted) || exhausted.length !== expectedExhausted.length
          || exhausted.some((entry, index) => entry?.block !== expectedExhausted[index][0]
            || entry?.window !== expectedExhausted[index][1] || entry?.outcome !== 'window_exhausted'
            || entry?.sharesAccepted !== contexts.find((context) => (
              context.block === entry.block && context.window === entry.window
            ))?.acceptedNonBlockShares)) {
          return fail('accepted_prefix_window_exhaustion_route_unproven', contexts, heights);
        }

        for (let block = 1; block <= acceptedCount; block += 1) {
          const winningWindow = windowsIssuedPerBlock.get(block);
          const binding = frames.bindings.find((item) => item.block === block && item.window === winningWindow);
          const record = records[block - 1];
          const blockFrame = frames.blocks.find((frame) => frame.block === block);
          const pageBlock = page.blocks.find((item) => item.block === block);
          const calc = rawCalc.filter((item) => item.block === block);
          const submits = rawSubmit.filter((item) => item.block === block);
          if (!binding || !blockFrame || !pageBlock || calc.length !== 1 || submits.length !== 1
            || !templateMatchesBinding(record.templateFacts, binding)
            || (block > 1 && !templateBuildsOnAccepted(record.templateFacts, records[block - 2]?.accepted))
            || record.accepted.jobId !== record.templateFacts.jobId
            || record.accepted.issuanceId !== record.templateFacts.issuanceId
            || String(record.accepted.height) !== String(record.templateFacts.height)
            || calc[0].failure !== null || submits[0].failure !== null
            || calc[0].window !== winningWindow || submits[0].window !== winningWindow
            || blockFrame.window !== winningWindow || !sameBound(blockFrame.boundTo, binding)
            || record.accepted.jobId !== binding.jobId || record.accepted.issuanceId !== binding.issuanceId
            || String(record.accepted.height) !== String(binding.jobFacts?.height)
            || blockFrame.nonce !== record.accepted.nonce || blockFrame.hashHexLE !== record.accepted.hashHexLE
            || blockFrame.blockId !== record.accepted.blockId || pageBlock.jobId !== binding.jobId
            || String(pageBlock.height) !== String(record.accepted.height)
            || pageBlock.nonce !== record.accepted.nonce || pageBlock.hashHexLE !== record.accepted.hashHexLE
            || pageBlock.blockId !== record.accepted.blockId || pageBlock.browserMatched !== true) {
            return fail(`accepted_prefix_height_${block}_winning_evidence_invalid`, contexts, heights);
          }
          if (record.propagation?.converged !== true
            || record.propagation.aHeader?.hash !== record.accepted.blockId
            || record.propagation.aTop?.hash !== record.accepted.blockId
            || record.propagation.bHeader?.hash !== record.accepted.blockId
            || record.propagation.bTop?.hash !== record.accepted.blockId
            || String(record.propagation.aHeader?.height) !== String(record.accepted.height)
            || String(record.propagation.aTop?.height) !== String(record.accepted.height)
            || String(record.propagation.bHeader?.height) !== String(record.accepted.height)
            || String(record.propagation.bTop?.height) !== String(record.accepted.height)) {
            return fail(`accepted_prefix_height_${block}_propagation_unproven`, contexts, heights);
          }
          const rpcBodies = classifyAcceptedRpcRequestBodies({
            templateFacts: record.templateFacts,
            nonce: record.accepted.nonce,
            calcRecord: calc[0],
            submitRecord: submits[0],
          });
          if (!rpcBodies.proven) {
            return fail(`accepted_prefix_height_${block}_rpc_request_body_mismatch:${rpcBodies.reason}`, contexts, heights);
          }
          if (block < acceptedCount) {
            const nextTemplate = rawTemplates.find((item) => (
              item.block === block + 1 && item.window === 1
            ));
            if (!Number.isSafeInteger(record.propagation.observedAtMs)
              || !Number.isSafeInteger(nextTemplate?.atMs)
              || record.propagation.observedAtMs > nextTemplate.atMs) {
              return fail(`accepted_prefix_height_${block}_convergence_after_successor`, contexts, heights);
            }
          }
          const agreement = classifyBrowserAgreement({
            pageNonce: pageBlock.browserNonce,
            submittedNonce: blockFrame.nonce,
            pageHash: pageBlock.browserHashHexLE,
            serverWasmHash: record.lastHashes?.serverWasmHex,
            nativeHash: record.lastHashes?.nativeHelperHex,
            daemonHash: daemonPowHashFromRaw(calc[0]),
          });
          if (!agreement.agreed || agreement.hashHexLE !== record.accepted.hashHexLE) {
            return fail(`accepted_prefix_height_${block}_hash_disagreement`, contexts, heights);
          }
          heights.push({
            block, height: String(record.accepted.height), window: winningWindow,
            jobId: binding.jobId, issuanceId: binding.issuanceId, nonce: record.accepted.nonce,
            blockId: record.accepted.blockId, hashHexLE: agreement.hashHexLE,
            calcPow: 1, submitBlock: 1, exactPropagationToB: true,
            browserServerNativeDaemonHashAgreed: true,
          });
        }

        const lastBinding = frames.bindings.at(-1);
        const lastRelease = verifierHistory.at(-1);
        if (!sameBound(active, lastBinding)
          || lastRelease?.block !== active.block || lastRelease?.window !== active.window
          || lastRelease?.jobId !== active.jobId || lastRelease?.issuanceId !== active.issuanceId
          || lastRelease?.closed !== true
          || !String(page.outcome ?? '').startsWith('BOUNDED_NO_SOLUTION')
          || (page.error && page.error !== '\u2014') || page.startDisabled !== true) {
          return fail('accepted_prefix_terminal_state_invalid', contexts, heights);
        }
        return {
          outcome: `BOUNDED_AFTER_${acceptedCount}_BLOCK${acceptedCount === 1 ? '' : 'S'}_ACCEPTED_BEFORE_SUCCESSOR_ISSUED`,
          contexts,
          heights,
        };
      }

      if (!Number.isSafeInteger(currentWindow) || currentWindow < 1 || currentWindow > requestedWindows
        || !/^(?:0|[1-9][0-9]*)$/.test(String(currentHeight ?? ''))) {
        return fail('unusable_bounded_coordinate');
      }

      // A bounded label is still an evidence claim: prove that the named browser/server context
      // actually existed and reached readiness. Previously this branch returned before looking at
      // any record, binding, Worker, template RPC, verifier, or session fact, so an empty fixture
      // could manufacture a scientific-sounding "observation". Validate the complete issued prefix
      // even though the result remains non-success and cannot make a block claim.
      const issued = Array.isArray(windowRecords) ? windowRecords.length : 0;
      const active = frames.activeBinding;
      // `blockRecords` is a record of STARTED heights, not only successful ones. The server creates
      // the current height's record before its verifier becomes ready and adds `accepted` only after
      // a block succeeds. A bounded H1 run therefore has one record and zero accepted heights; a
      // bounded H2 run has two records and exactly one accepted height. Counting the array itself as
      // successes makes every honest bounded runtime shape fail and lets unrealistic fixtures hide
      // that mistake.
      const acceptedHeights = Array.isArray(records)
        ? records.filter((record) => record?.accepted !== null && record?.accepted !== undefined).length
        : -1;
      const currentBlockRecord = Number.isSafeInteger(active?.block) && Array.isArray(records)
        ? records[active.block - 1]
        : null;
      const currentTemplate = currentBlockRecord?.templateFacts;
      const boundedContexts = [];
      const rawTemplates = Array.isArray(raw) ? raw.filter((item) => item.method === 'get_block_template') : [];
      const rawCalc = Array.isArray(raw) ? raw.filter((item) => item.method === 'calc_pow') : [];
      const rawSubmit = Array.isArray(raw) ? raw.filter((item) => item.method === 'submit_block') : [];
      if (issued < 1 || issued > requestedBlocks * requestedWindows
        || active === null || active === undefined
        || !Number.isSafeInteger(active.block) || active.block !== acceptedHeights + 1
        || active.block < 1 || active.block > requestedBlocks || active.window !== currentWindow
        || records?.length !== active.block
        || records.some((record, index) => record?.block !== index + 1
          || (index < acceptedHeights
            ? record.accepted === null || record.accepted === undefined
            : record.accepted !== null && record.accepted !== undefined))
        || !templateMatchesBinding(currentTemplate, active)
        || (active.block > 1
          && !templateBuildsOnAccepted(currentTemplate, records[active.block - 2]?.accepted))
        || String(active.jobFacts?.height ?? '') !== String(currentHeight)
        || frames.bindings?.length !== issued || frames.readiness?.length !== issued
        || frames.blocks?.length !== acceptedHeights || frames.terminalBlocks?.length !== 0
        || page?.blocks?.length !== acceptedHeights || Number(page?.workersCreated) !== 1
        || page?.workerContexts?.length !== issued || String(page?.staleWorkerMessages ?? '') !== '0'
        || verifierHistory?.length !== issued - 1 || sessionFacts?.length !== 1
        || (finalA?.get_block_template ?? 0) !== issued
        || (finalA?.calc_pow ?? 0) !== acceptedHeights
        || (finalA?.submit_block ?? 0) !== acceptedHeights
        || rawTemplates.length !== issued || rawCalc.length !== acceptedHeights
        || rawSubmit.length !== acceptedHeights
        || !Number.isSafeInteger(sessionFacts[0].sessionDeadlineAtMs)
        || typeof sessionFacts[0].sessionBudgetSpent !== 'boolean'
        // Exhausting a non-final window normally rotates immediately. If no successor window was
        // issued, the only successful bounded route is that the one whole-session clock had passed.
        || (currentWindow < requestedWindows && sessionFacts[0].sessionBudgetSpent !== true)) {
        return fail('bounded_observation_evidence_incomplete');
      }
      const bindingJobIds = frames.bindings.map((binding) => binding?.jobId);
      const bindingIssuanceIds = frames.bindings.map((binding) => binding?.issuanceId);
      if (new Set(bindingJobIds).size !== issued || new Set(bindingIssuanceIds).size !== issued
        || frames.bindings.some((binding, index) => !Number.isSafeInteger(binding?.runGeneration)
          || (index > 0 && binding.runGeneration !== frames.bindings[index - 1].runGeneration + 1))) {
        return fail('bounded_observation_capability_reuse_or_generation_gap');
      }
      let cumulativeShares = 0;
      for (let contextIndex = 0; contextIndex < issued; contextIndex += 1) {
        const record = windowRecords[contextIndex];
        const binding = frames.bindings[contextIndex];
        const ready = frames.readiness[contextIndex];
        const previous = contextIndex === 0 ? null : windowRecords[contextIndex - 1];
        const expectedNonceStart = (record?.window - 1) * maxAttempts;
        const coordinateExact = contextIndex === 0
          ? record?.block === 1 && record?.window === 1
          : (record?.block === previous?.block
            ? record?.window === previous.window + 1 && record.window <= requestedWindows
            : record?.block === previous?.block + 1 && record?.window === 1);
        const templates = rawTemplates.filter((item) => item.block === record?.block && item.window === record?.window);
        const workers = page.workerContexts.filter((worker) => worker?.jobId === binding?.jobId);
        if (!coordinateExact || binding?.block !== record.block || binding?.window !== record.window
          || ready?.block !== record.block || ready?.window !== record.window
          || ready?.sessionBudgetMs !== sessionBudgetMs || !sameBound(ready?.boundTo, binding)
          || record.jobId !== binding.jobId || record.issuanceId !== binding.issuanceId
          || String(record.height) !== String(binding.jobFacts?.height)
          || record.nonceStart !== expectedNonceStart || record.nonceRange !== maxAttempts
          || binding.jobFacts?.nonceStart !== record.nonceStart
          || binding.jobFacts?.nonceRange !== record.nonceRange
          || binding.jobFacts?.shareTargetHexLE !== record.shareTargetHexLE
          || binding.jobFacts?.blockTargetHexLE !== record.blockTargetHexLE
          || binding.jobFacts?.contentDigest !== record.contentDigest
          || binding.jobFacts?.epochKeyHex !== record.epochKeyHex
          || binding.jobFacts?.seedHashHex !== record.seedHashHex
          || binding.jobFacts?.hashingTemplateSha256 !== record.hashingTemplateSha256
          || templates.length !== 1 || templates[0].failure !== null
          || workers.length !== 1 || workers[0].contextIndex !== contextIndex + 1
          || workers[0].moduleInstances !== 1
          || !Number.isSafeInteger(workers[0].wasmHeapBytes) || workers[0].wasmHeapBytes < 1
          || (contextIndex === 0 && workers[0].rotated !== false)
          || (contextIndex > 0 && (workers[0].rotated !== true
            || workers[0].priorContextFreed !== true || workers[0].priorContextActive !== false))) {
          return fail('bounded_observation_context_prefix_invalid', boundedContexts);
        }
        if (contextIndex < issued - 1) {
          const release = verifierHistory[contextIndex];
          const successor = windowRecords[contextIndex + 1];
          if (release?.closed !== true || release.block !== record.block || release.window !== record.window
            || release.jobId !== binding.jobId || release.issuanceId !== binding.issuanceId
            || String(release.context?.height ?? '') !== String(record.height)
            || !Number.isSafeInteger(record.verifierAllocationStartedAtMs)
            || !Number.isSafeInteger(release.releasedAtMs)
            || !Number.isSafeInteger(successor?.verifierAllocationStartedAtMs)
            || record.verifierAllocationStartedAtMs > release.releasedAtMs
            || release.releasedAtMs > successor.verifierAllocationStartedAtMs) {
            return fail('bounded_observation_release_chain_invalid', boundedContexts);
          }
        }
        const contextShares = frames.shares.filter((share) => (
          share.block === record.block && share.window === record.window
        ));
        if (contextShares.length > shareLimit) {
          return fail('bounded_observation_share_budget_exceeded', boundedContexts);
        }
        for (let shareIndex = 0; shareIndex < contextShares.length; shareIndex += 1) {
          const share = contextShares[shareIndex];
          if (!sameBound(share.boundTo, binding) || share.sharesAccepted !== shareIndex + 1
            || share.sharesAcceptedTotal !== cumulativeShares + shareIndex + 1) {
            return fail('bounded_observation_share_count_or_binding_mismatch', boundedContexts);
          }
        }
        cumulativeShares += contextShares.length;
        boundedContexts.push({
          block: record.block, window: record.window, height: String(record.height),
          jobId: binding.jobId, issuanceId: binding.issuanceId,
          nonceStart: record.nonceStart, nonceRange: record.nonceRange,
          workerContextIndex: workers[0].contextIndex,
          acceptedNonBlockShares: contextShares.length, templateRpc: 1,
        });
      }

      const issuedCoordinateKeys = new Set(windowRecords.map((record) => `${record.block}:${record.window}`));
      if (raw.some((item) => !issuedCoordinateKeys.has(`${item?.block}:${item?.window}`))) {
        return fail('bounded_observation_rpc_coordinate_invalid', boundedContexts);
      }
      const shareKeys = frames.shares.map((share) => `${share.block}:${share.window}:${share.nonce}`);
      const currentContextShares = boundedContexts.at(-1).acceptedNonBlockShares;
      if (new Set(shareKeys).size !== frames.shares.length
        || sessionFacts[0].sharesAcceptedTotal !== cumulativeShares
        || sessionFacts[0].sharesAccepted !== currentContextShares) {
        return fail('bounded_observation_share_identity_or_total_mismatch', boundedContexts);
      }

      const windowsIssuedPerBlock = new Map();
      for (let block = 1; block <= active.block; block += 1) {
        const blockContexts = boundedContexts.filter((context) => context.block === block);
        if (blockContexts.length < 1 || blockContexts.length > requestedWindows
          || blockContexts.some((context, index) => context.window !== index + 1)) {
          return fail('bounded_observation_height_window_prefix_invalid', boundedContexts);
        }
        windowsIssuedPerBlock.set(block, blockContexts.length);
      }
      const expectedExhausted = [];
      for (let block = 1; block <= active.block; block += 1) {
        for (let window = 1; window < windowsIssuedPerBlock.get(block); window += 1) {
          expectedExhausted.push([block, window]);
        }
      }
      const exhausted = sessionFacts[0].windowOutcomes;
      if (!Array.isArray(exhausted) || exhausted.length !== expectedExhausted.length
        || exhausted.some((entry, index) => entry?.block !== expectedExhausted[index][0]
          || entry?.window !== expectedExhausted[index][1] || entry?.outcome !== 'window_exhausted'
          || entry?.sharesAccepted !== boundedContexts.find((context) => (
            context.block === entry.block && context.window === entry.window
          ))?.acceptedNonBlockShares)) {
        return fail('bounded_observation_window_exhaustion_route_unproven', boundedContexts);
      }

      const heights = [];
      for (let block = 1; block <= acceptedHeights; block += 1) {
        const winningWindow = windowsIssuedPerBlock.get(block);
        const binding = frames.bindings.find((item) => (
          item.block === block && item.window === winningWindow
        ));
        const record = records[block - 1];
        const blockFrame = frames.blocks.find((frame) => frame.block === block);
        const pageBlock = page.blocks.find((item) => item.block === block);
        const calc = rawCalc.filter((item) => item.block === block);
        const submits = rawSubmit.filter((item) => item.block === block);
        if (record?.block !== block || record.accepted === null || record.accepted === undefined
          || !binding || !blockFrame || !pageBlock || calc.length !== 1 || submits.length !== 1
          || !templateMatchesBinding(record.templateFacts, binding)
          || (block > 1 && !templateBuildsOnAccepted(record.templateFacts, records[block - 2]?.accepted))
          || record.accepted.jobId !== record.templateFacts.jobId
          || record.accepted.issuanceId !== record.templateFacts.issuanceId
          || String(record.accepted.height) !== String(record.templateFacts.height)
          || calc[0].failure !== null || submits[0].failure !== null
          || calc[0].window !== winningWindow || submits[0].window !== winningWindow
          || blockFrame.window !== winningWindow || !sameBound(blockFrame.boundTo, binding)
          || record.accepted.jobId !== binding.jobId || record.accepted.issuanceId !== binding.issuanceId
          || String(record.accepted.height) !== String(binding.jobFacts?.height)
          || blockFrame.nonce !== record.accepted.nonce || blockFrame.hashHexLE !== record.accepted.hashHexLE
          || blockFrame.blockId !== record.accepted.blockId || pageBlock.jobId !== binding.jobId
          || String(pageBlock.height) !== String(record.accepted.height)
          || pageBlock.nonce !== record.accepted.nonce || pageBlock.hashHexLE !== record.accepted.hashHexLE
          || pageBlock.blockId !== record.accepted.blockId || pageBlock.browserMatched !== true) {
          return fail('bounded_observation_prior_height_or_rpc_mismatch', boundedContexts, heights);
        }
        if (record.propagation?.converged !== true
          || record.propagation.aHeader?.hash !== record.accepted.blockId
          || record.propagation.aTop?.hash !== record.accepted.blockId
          || record.propagation.bHeader?.hash !== record.accepted.blockId
          || record.propagation.bTop?.hash !== record.accepted.blockId
          || String(record.propagation.aHeader?.height) !== String(record.accepted.height)
          || String(record.propagation.aTop?.height) !== String(record.accepted.height)
          || String(record.propagation.bHeader?.height) !== String(record.accepted.height)
          || String(record.propagation.bTop?.height) !== String(record.accepted.height)) {
          return fail('bounded_observation_prior_height_propagation_unproven', boundedContexts, heights);
        }
        const rpcBodies = classifyAcceptedRpcRequestBodies({
          templateFacts: record.templateFacts,
          nonce: record.accepted.nonce,
          calcRecord: calc[0],
          submitRecord: submits[0],
        });
        if (!rpcBodies.proven) {
          return fail(`bounded_observation_prior_height_rpc_request_body_mismatch:${rpcBodies.reason}`, boundedContexts, heights);
        }
        const nextTemplate = rawTemplates.find((item) => (
          item.block === block + 1 && item.window === 1
        ));
        if (!Number.isSafeInteger(record.propagation.observedAtMs)
          || !Number.isSafeInteger(nextTemplate?.atMs)
          || record.propagation.observedAtMs > nextTemplate.atMs) {
          return fail('bounded_observation_prior_height_convergence_after_successor', boundedContexts, heights);
        }
        const agreement = classifyBrowserAgreement({
          pageNonce: pageBlock.browserNonce,
          submittedNonce: blockFrame.nonce,
          pageHash: pageBlock.browserHashHexLE,
          serverWasmHash: record.lastHashes?.serverWasmHex,
          nativeHash: record.lastHashes?.nativeHelperHex,
          daemonHash: daemonPowHashFromRaw(calc[0]),
        });
        if (!agreement.agreed || agreement.hashHexLE !== record.accepted.hashHexLE) {
          return fail('bounded_observation_prior_height_hash_disagreement', boundedContexts, heights);
        }
        heights.push({
          block, height: String(record.accepted.height), window: winningWindow,
          jobId: binding.jobId, issuanceId: binding.issuanceId, nonce: record.accepted.nonce,
          blockId: record.accepted.blockId, hashHexLE: agreement.hashHexLE,
          calcPow: 1, submitBlock: 1, exactPropagationToB: true,
          browserServerNativeDaemonHashAgreed: true,
        });
      }
      const lastRecord = windowRecords.at(-1);
      const lastBinding = frames.bindings.at(-1);
      if (lastRecord?.block !== active.block || lastRecord?.window !== active.window
        || !sameBound(active, lastBinding)
        || currentVerifier?.block !== active.block || currentVerifier?.window !== active.window
        || currentVerifier?.jobId !== active.jobId || currentVerifier?.issuanceId !== active.issuanceId
        || currentVerifier?.closed !== false
        || String(currentVerifier?.context?.height ?? '') !== String(active.jobFacts?.height)) {
        return fail('bounded_observation_active_context_invalid', boundedContexts);
      }
      if (!String(page.outcome ?? '').startsWith('BOUNDED_NO_SOLUTION')
        || (page.error && page.error !== '\u2014') || page.startDisabled !== true) {
        return fail('bounded_observation_page_terminal_state_disagreement', boundedContexts, heights);
      }
      return {
        outcome: `BOUNDED_OBSERVATION_NO_BLOCK_AT_HEIGHT_${currentHeight}_WINDOW_${currentWindow}`,
        contexts: boundedContexts, heights,
      };
    }
    return fail(`${attemptReason ?? 'unknown'}@height${currentHeight}:window${currentWindow}`);
  }

  const issuedContexts = Array.isArray(windowRecords) ? windowRecords.length : 0;
  const rawTemplates = raw.filter((item) => item.method === 'get_block_template');
  const rawCalc = raw.filter((item) => item.method === 'calc_pow');
  const rawSubmit = raw.filter((item) => item.method === 'submit_block');
  if (records?.length !== requestedBlocks || issuedContexts < requestedBlocks
    || issuedContexts > requestedBlocks * requestedWindows
    || frames.bindings?.length !== issuedContexts || frames.readiness?.length !== issuedContexts
    || frames.blocks?.length !== requestedBlocks || frames.terminalBlocks?.length !== 1
    || page?.blocks?.length !== requestedBlocks || Number(page.workersCreated) !== 1
    || String(page.staleWorkerMessages ?? '') !== '0'
    || page.workerContexts?.length !== issuedContexts || verifierHistory?.length !== issuedContexts - 1
    || sessionFacts?.length !== 1 || (finalA?.get_block_template ?? 0) !== issuedContexts
    || (finalA?.calc_pow ?? 0) !== requestedBlocks || (finalA?.submit_block ?? 0) !== requestedBlocks
    || rawTemplates.length !== issuedContexts || rawCalc.length !== requestedBlocks
    || rawSubmit.length !== requestedBlocks) {
    return fail('sequence_refresh_shape_incomplete');
  }

  const bindingJobIds = frames.bindings.map((binding) => binding?.jobId);
  const bindingIssuanceIds = frames.bindings.map((binding) => binding?.issuanceId);
  if (new Set(bindingJobIds).size !== issuedContexts || new Set(bindingIssuanceIds).size !== issuedContexts
    || frames.bindings.some((binding, index) => !Number.isSafeInteger(binding?.runGeneration)
      || (index > 0 && binding.runGeneration !== frames.bindings[index - 1].runGeneration + 1))) {
    return fail('context_capability_reuse_or_generation_gap');
  }
  const contexts = [];
  const windowsIssuedPerBlock = new Map();
  let cumulativeShares = 0;
  let index = 0;
  for (let block = 1; block <= requestedBlocks; block += 1) {
    const windowsIssued = windowRecords.filter((record) => record?.block === block).length;
    if (windowsIssued < 1 || windowsIssued > requestedWindows) {
      return fail(`height_${block}_window_prefix_missing`, contexts);
    }
    windowsIssuedPerBlock.set(block, windowsIssued);
    for (let window = 1; window <= windowsIssued; window += 1) {
      const rec = windowRecords[index];
      const binding = frames.bindings[index];
      const ready = frames.readiness[index];
      const expectedNonceStart = (window - 1) * maxAttempts;
      const templates = raw.filter((item) => (
        item.block === block && item.window === window && item.method === 'get_block_template'
      ));
      if (rec?.block !== block || rec?.window !== window || binding?.block !== block
        || binding?.window !== window || ready?.block !== block || ready?.window !== window
        || ready?.sessionBudgetMs !== sessionBudgetMs || !sameBound(ready.boundTo, binding)
        || templates.length !== 1 || templates[0].failure !== null
        || rec.nonceStart !== expectedNonceStart || rec.nonceRange !== maxAttempts
        || rec.jobId !== binding.jobId || rec.issuanceId !== binding.issuanceId
        || String(rec.height) !== String(binding.jobFacts?.height)
        || binding.jobFacts?.nonceStart !== rec.nonceStart || binding.jobFacts?.nonceRange !== rec.nonceRange
        || binding.jobFacts?.shareTargetHexLE !== rec.shareTargetHexLE
        || binding.jobFacts?.blockTargetHexLE !== rec.blockTargetHexLE
        || binding.jobFacts?.contentDigest !== rec.contentDigest
        || binding.jobFacts?.epochKeyHex !== rec.epochKeyHex
        || binding.jobFacts?.seedHashHex !== rec.seedHashHex
        || binding.jobFacts?.hashingTemplateSha256 !== rec.hashingTemplateSha256) {
        return fail(`context_${block}_${window}_binding_or_template_mismatch`, contexts);
      }
      const workers = page.workerContexts.filter((worker) => worker?.jobId === binding.jobId);
      if (workers.length !== 1 || workers[0].contextIndex !== index + 1 || workers[0].moduleInstances !== 1
        || !Number.isSafeInteger(workers[0].wasmHeapBytes) || workers[0].wasmHeapBytes < 1
        || (index === 0 && workers[0].rotated !== false)
        || (index > 0 && (workers[0].rotated !== true || workers[0].priorContextFreed !== true
          || workers[0].priorContextActive !== false))) {
        return fail(`context_${block}_${window}_worker_rotation_unproven`, contexts);
      }
      if (index < issuedContexts - 1) {
        const release = verifierHistory[index];
        const successor = windowRecords[index + 1];
        if (release?.closed !== true || release.block !== block || release.window !== window
          || release.jobId !== binding.jobId || release.issuanceId !== binding.issuanceId
          || String(release.context?.height ?? '') !== String(rec.height)
          || !Number.isSafeInteger(rec.verifierAllocationStartedAtMs)
          || !Number.isSafeInteger(release.releasedAtMs)
          || !Number.isSafeInteger(successor?.verifierAllocationStartedAtMs)
          || rec.verifierAllocationStartedAtMs > release.releasedAtMs
          || release.releasedAtMs > successor.verifierAllocationStartedAtMs) {
          return fail(`context_${block}_${window}_release_chain_unproven`, contexts);
        }
      }
      const contextShares = frames.shares.filter((share) => share.block === block && share.window === window);
      if (contextShares.length > shareLimit) return fail(`context_${block}_${window}_share_budget_exceeded`, contexts);
      for (let shareIndex = 0; shareIndex < contextShares.length; shareIndex += 1) {
        const share = contextShares[shareIndex];
        if (!sameBound(share.boundTo, binding) || share.sharesAccepted !== shareIndex + 1
          || share.sharesAcceptedTotal !== cumulativeShares + shareIndex + 1) {
          return fail(`context_${block}_${window}_share_count_or_binding_mismatch`, contexts);
        }
      }
      cumulativeShares += contextShares.length;
      contexts.push({
        block, window, jobId: binding.jobId, issuanceId: binding.issuanceId,
        height: String(rec.height), nonceStart: rec.nonceStart, nonceRange: rec.nonceRange,
        workerContextIndex: workers[0].contextIndex, acceptedNonBlockShares: contextShares.length,
        templateRpc: 1, priorVerifierReleased: index === 0 ? null : true,
      });
      index += 1;
    }
  }
  if (index !== issuedContexts) return fail('issued_context_order_incomplete', contexts);

  const shareKeys = frames.shares.map((share) => `${share.block}:${share.window}:${share.nonce}`);
  if (new Set(shareKeys).size !== frames.shares.length
    || sessionFacts[0].sharesAcceptedTotal !== cumulativeShares) {
    return fail('context_share_identity_or_total_mismatch', contexts);
  }
  const finalContextShares = contexts.at(-1).acceptedNonBlockShares;
  if (sessionFacts[0].sharesAccepted !== finalContextShares
    || !Number.isSafeInteger(sessionFacts[0].sessionDeadlineAtMs)
    || typeof sessionFacts[0].sessionBudgetSpent !== 'boolean') {
    return fail('session_deadline_or_current_share_count_mismatch', contexts);
  }
  const expectedExhausted = [];
  for (let block = 1; block <= requestedBlocks; block += 1) {
    for (let window = 1; window < windowsIssuedPerBlock.get(block); window += 1) {
      expectedExhausted.push([block, window]);
    }
  }
  const exhausted = sessionFacts[0].windowOutcomes;
  if (!Array.isArray(exhausted) || exhausted.length !== expectedExhausted.length
    || exhausted.some((entry, index) => entry?.block !== expectedExhausted[index][0]
      || entry?.window !== expectedExhausted[index][1] || entry?.outcome !== 'window_exhausted'
      || entry?.sharesAccepted !== contexts.find((context) => (
        context.block === entry.block && context.window === entry.window
      ))?.acceptedNonBlockShares)) {
    return fail('window_exhaustion_route_unproven', contexts);
  }

  const heights = [];
  for (let block = 1; block <= requestedBlocks; block += 1) {
    const winningWindow = windowsIssuedPerBlock.get(block);
    const binding = frames.bindings.find((item) => item.block === block && item.window === winningWindow);
    const rec = records[block - 1];
    const blockFrame = frames.blocks.find((frame) => frame.block === block);
    const pageBlock = page.blocks.find((item) => item.block === block);
    const calc = raw.filter((item) => item.block === block && item.method === 'calc_pow');
    const submits = raw.filter((item) => item.block === block && item.method === 'submit_block');
    if (rec?.block !== block || rec.accepted === null || rec.accepted === undefined
      || !binding || !blockFrame || !pageBlock || calc.length !== 1 || submits.length !== 1
      || !templateMatchesBinding(rec.templateFacts, binding)
      || (block > 1 && !templateBuildsOnAccepted(rec.templateFacts, records[block - 2]?.accepted))
      || rec.accepted.jobId !== rec.templateFacts.jobId
      || rec.accepted.issuanceId !== rec.templateFacts.issuanceId
      || String(rec.accepted.height) !== String(rec.templateFacts.height)
      || calc[0].failure !== null || submits[0].failure !== null
      || calc[0].window !== winningWindow || submits[0].window !== winningWindow
      || blockFrame.window !== winningWindow || !sameBound(blockFrame.boundTo, binding)
      || rec.accepted.jobId !== binding.jobId || rec.accepted.issuanceId !== binding.issuanceId
      || String(rec.accepted.height) !== String(binding.jobFacts?.height)
      || blockFrame.nonce !== rec.accepted.nonce || blockFrame.hashHexLE !== rec.accepted.hashHexLE
      || blockFrame.blockId !== rec.accepted.blockId || pageBlock.jobId !== binding.jobId
      || String(pageBlock.height) !== String(rec.accepted.height) || pageBlock.nonce !== rec.accepted.nonce
      || pageBlock.hashHexLE !== rec.accepted.hashHexLE || pageBlock.blockId !== rec.accepted.blockId
      || pageBlock.browserMatched !== true) {
      return fail(`height_${block}_winning_context_or_rpc_mismatch`, contexts, heights);
    }
    if (rec.propagation?.converged !== true || rec.propagation.aHeader?.hash !== rec.accepted.blockId
      || rec.propagation.aTop?.hash !== rec.accepted.blockId
      || rec.propagation.bHeader?.hash !== rec.accepted.blockId
      || rec.propagation.bTop?.hash !== rec.accepted.blockId
      || String(rec.propagation.aHeader?.height) !== String(rec.accepted.height)
      || String(rec.propagation.aTop?.height) !== String(rec.accepted.height)
      || String(rec.propagation.bHeader?.height) !== String(rec.accepted.height)
      || String(rec.propagation.bTop?.height) !== String(rec.accepted.height)) {
      return fail(`height_${block}_exact_p2p_propagation_unproven`, contexts, heights);
    }
    const rpcBodies = classifyAcceptedRpcRequestBodies({
      templateFacts: rec.templateFacts,
      nonce: rec.accepted.nonce,
      calcRecord: calc[0],
      submitRecord: submits[0],
    });
    if (!rpcBodies.proven) {
      return fail(`height_${block}_rpc_request_body_mismatch:${rpcBodies.reason}`, contexts, heights);
    }
    if (block < requestedBlocks) {
      const nextTemplate = raw.find((item) => (
        item.block === block + 1 && item.window === 1 && item.method === 'get_block_template'
      ));
      if (!Number.isSafeInteger(rec.propagation.observedAtMs) || !Number.isSafeInteger(nextTemplate?.atMs)
        || rec.propagation.observedAtMs > nextTemplate.atMs) {
        return fail(`height_${block}_peer_convergence_after_next_height`, contexts, heights);
      }
    }
    const agreement = classifyBrowserAgreement({
      pageNonce: pageBlock.browserNonce, submittedNonce: blockFrame.nonce,
      pageHash: pageBlock.browserHashHexLE, serverWasmHash: rec.lastHashes?.serverWasmHex,
      nativeHash: rec.lastHashes?.nativeHelperHex, daemonHash: daemonPowHashFromRaw(calc[0]),
    });
    if (!agreement.agreed || agreement.hashHexLE !== rec.accepted.hashHexLE) {
      return fail(`height_${block}_hash_disagreement:${agreement.reason ?? 'accepted_hash'}`, contexts, heights);
    }
    heights.push({
      block, height: String(rec.accepted.height), window: winningWindow,
      jobId: binding.jobId, issuanceId: binding.issuanceId, nonce: rec.accepted.nonce,
      blockId: rec.accepted.blockId, hashHexLE: agreement.hashHexLE,
      calcPow: 1, submitBlock: 1, exactPropagationToB: true,
      browserServerNativeDaemonHashAgreed: true,
    });
  }

  const finalBinding = frames.bindings.at(-1);
  const finalFrame = frames.terminalBlocks[0];
  const last = heights.at(-1);
  if (finalFrame.block !== requestedBlocks || finalFrame.window !== last.window
    || !sameBound(finalFrame.boundTo, finalBinding) || finalFrame.nonce !== last.nonce
    || finalFrame.hashHexLE !== last.hashHexLE || finalFrame.blockId !== last.blockId
    || currentVerifier?.block !== requestedBlocks || currentVerifier?.window !== last.window
    || currentVerifier?.jobId !== finalBinding.jobId || currentVerifier?.issuanceId !== finalBinding.issuanceId
    || currentVerifier?.closed !== false
    || String(currentVerifier?.context?.height ?? '') !== String(finalBinding.jobFacts?.height)) {
    return fail('terminal_context_or_verifier_mismatch', contexts, heights);
  }
  if (!String(page.outcome ?? '').startsWith(`${requestedBlocks} blocks accepted by node A`)
    || (page.error && page.error !== '\u2014') || page.startDisabled !== true) {
    return fail('page_terminal_state_disagreement', contexts, heights);
  }
  return {
    outcome: sequenceRefreshSuccessOutcome(requestedBlocks, requestedWindows),
    contexts, heights, windowsIssuedPerBlock: Object.fromEntries(windowsIssuedPerBlock),
    distinctContextNonceShares: cumulativeShares,
  };
}

/**
 * THE ONE FIXED OPERATOR-START BUDGET. A human pressing a button is slower than a machine, but this
 * is still a bounded development run: no caller, flag or environment variable can widen or remove it,
 * and expiry is an ordinary failure through the single finalization path.
 */
const OPERATOR_START_TIMEOUT_MS = 10 * 60_000;

/**
 * The owned throwaway-profile browser's arguments. The ONLY difference an operator-start run makes is
 * that `--headless=new` is omitted: the same throwaway profile, the same private remote-debugging
 * port, the same disabled background networking/update/sync, the same about:blank first page.
 */
function browserLaunchArgs({ headed, profileDir: dir }) {
  return [
    ...(headed === true ? [] : ['--headless=new']),
    '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-extensions',
    '--disable-background-networking', '--disable-component-update', '--disable-sync',
    `--user-data-dir=${dir}`, '--remote-debugging-port=0', 'about:blank',
  ];
}

function initialBlankPageTarget(targetInfos) {
  if (!Array.isArray(targetInfos)) throw new Error('browser target inventory is missing');
  const pages = targetInfos.filter((target) => target.type === 'page');
  if (pages.length > 1) throw new Error('the owned browser unexpectedly opened more than one page');
  if (pages.length === 0) return null;
  if (pages[0].url !== 'about:blank' || typeof pages[0].targetId !== 'string'
      || pages[0].targetId.length === 0) {
    throw new Error('the owned initial browser page is not blank');
  }
  return pages[0];
}

/**
 * PROOF THAT START REACHED THE SERVER, and the only thing this runner accepts as proof. The one
 * attempt is IDLE until the pool itself reserves it, so any other state means the page's Start was
 * received and acted on. Nothing about the DOM -- a clicked button, a disabled control, a rendered
 * label -- is consulted: a page can show all of those without the server ever granting the attempt.
 */
function serverObservedStart(attemptState, idleState) {
  return typeof attemptState === 'string' && attemptState.length > 0 && attemptState !== idleState;
}

/**
 * THE FOUR JOINT CASES of the pre-Start wait, decided in ONE place from ONE snapshot of both facts.
 *
 * The first revision asked them in the wrong order: it threw on `chromeExited` BEFORE looking at the
 * server. If the operator pressed Start and then closed the window inside the same 250 ms poll gap,
 * both facts were true at once and the runner reported "the browser exited before Start" over an
 * attempt the pool had already reserved -- and possibly spent. SERVER EVIDENCE WINS: a non-IDLE
 * attempt state is proof that Start reached the pool, whatever the window did afterwards, and what
 * happens to that attempt is then the existing terminal wait's and the lifecycle's business.
 *
 * @returns {'observed'|'exited_before_start'|'waiting'}
 */
function classifyOperatorStart({ attemptState, idleState, browserExited }) {
  if (serverObservedStart(attemptState, idleState)) return 'observed';
  return browserExited === true ? 'exited_before_start' : 'waiting';
}

/** The closed codes for the ONE owned browser's startup. Nothing here is a retry or a second launch. */
const BROWSER_START_FAILED = 'browser_start_failed';
const BROWSER_EXITED_BEFORE_DEVTOOLS = 'browser_exited_before_devtools';

function browserStartupError(code, detail) {
  const err = new Error(code === BROWSER_START_FAILED
    ? `the owned browser could not be started: ${detail}`
    : `the owned browser exited before reporting a DevTools endpoint: ${detail}`);
  err.code = code;
  return err;
}

/**
 * WIRE THE ONE OWNED BROWSER CHILD, ERROR LISTENER FIRST.
 *
 * A ChildProcess that cannot be spawned at all -- an explicit --browser path that does not exist or
 * cannot be executed -- emits `error`, and an EventEmitter with no `error` listener THROWS it. That
 * throw is an uncaught exception, and this runner installs no uncaughtException handler, so Node
 * would die right there: after the pool already owned daemon A, daemon B and the native helper, and
 * outside lifecycle.run(), which means no beforePoolClose, no pool shutdown, no release observation
 * and no evidence file. Two containers would simply be left running.
 *
 * The listener is therefore attached in the SAME TICK as spawn, before any await, and both the spawn
 * failure and an exit that beats the DevTools endpoint become ordinary, closed-code failures that the
 * caller throws from its existing wait -- one body rejection, through the one finalization path.
 *
 * `onExit` carries the runner's existing `chromeExited` meaning: THERE IS NO LIVE BROWSER PROCESS.
 *
 * AN `error` EVENT IS NOT PROOF OF THAT. ChildProcess emits `error` for a spawn that never produced a
 * process AND for a later failure on an existing one -- notably a kill that could not be delivered.
 * The first revision of this helper treated both the same and marked the browser gone. That is worse
 * than the crash it fixed: stopBrowser() only escalates to SIGKILL while `chromeExited` is false, so a
 * failed kill could mark the browser gone, skip the escalation, and let observeRelease record
 * `released: true` over a Chrome that is still running.
 *
 * Only two things may say the browser is gone: an actual `exit` event, or an `error` on a child that
 * has NO pid, which is exactly the case where no process was ever created. Everything else is
 * classified (before DevTools it is still an ordinary startup failure) and left for the real cleanup.
 */
function observeBrowserStartup(child, { onExit = () => {} } = {}) {
  const state = { devtoolsUrl: null, failure: null, exited: false, exit: null, lastError: null };
  const fail = (err) => { if (state.failure === null && state.devtoolsUrl === null) state.failure = err; };
  child.on('error', (err) => {
    const detail = `${err?.code ?? ''} ${err?.message ?? err}`.trim();
    state.lastError = detail.slice(0, 240);
    // Conservative and directly observable: no pid means no process was ever created.
    const neverStarted = child.pid === null || child.pid === undefined;
    fail(browserStartupError(BROWSER_START_FAILED, neverStarted ? detail : `${detail} (pid ${child.pid})`));
    if (!neverStarted) return;               // a process exists: this error proves nothing about it
    state.exited = true;
    onExit();
  });
  child.once('exit', (code, signal) => {
    state.exited = true;
    state.exit = { code: code ?? null, signal: signal ?? null };
    fail(browserStartupError(BROWSER_EXITED_BEFORE_DEVTOOLS, `code ${code ?? 'null'} signal ${signal ?? 'null'}`));
    onExit();
  });
  child.stdout?.on('data', () => {});
  child.stderr?.on('data', (buf) => {
    const m = /ws:\/\/127\.0\.0\.1:\d+\/devtools\/browser\/[0-9a-f-]+/i.exec(buf.toString());
    if (m && state.devtoolsUrl === null) state.devtoolsUrl = m[0];
  });
  return state;
}

async function waitUntil(fn, { timeoutMs, everyMs = 100, label }) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    lifecycle.throwIfCancelled();
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await sleep(everyMs);
  }
}

// ---------------------------------------------------------------- cleanup (the lifecycle runs it once)
async function stopBrowser() {
  try { cdp?.close(); } catch { /* gone */ }
  if (chrome && !chromeExited) {
    const exited = new Promise((r) => chrome.once('exit', () => { chromeExited = true; r(); }));
    chrome.kill();
    await Promise.race([exited, sleep(5000)]);
    if (!chromeExited) { chrome.kill('SIGKILL'); await Promise.race([exited, sleep(5000)]); }
  }
}

async function observeRelease({ poolStarted, poolShutdown, poolListenerClosed }) {
  const c = { poolStarted, poolShutdown, poolListenerClosed };
  c.browserExited = chrome ? chromeExited : 'not started';
  c.browserPid = chrome?.pid ?? null;
  for (const [name, dir] of [['A', runDirA], ['B', runDirB]]) {
    const byMount = wsl(['docker', 'ps', '-a', '--no-trunc', '--filter', `volume=${dir}`, '--format', '{{.Names}}']);
    c[`containersMounting${name}`] = byMount.status === 0 ? byMount.stdout.trim().split('\n').filter(Boolean) : null;
  }
  c.containersGone = {};
  for (const name of facts.containers) {
    const ps = wsl(['docker', 'ps', '-a', '--no-trunc', '--filter', `name=^/${name}$`, '--format', '{{.ID}}']);
    c.containersGone[name] = ps.status === 0 && ps.stdout.trim() === '';
  }
  c.pidsGone = {};
  for (const pid of [...facts.pids, ...facts.helperPids].filter(Boolean)) {
    const ls = wsl(['ls', '-1', '-d', '--', '/proc/self', `/proc/${pid}`]);
    c.pidsGone[pid] = ls.stdout.includes('/proc/self') && !ls.stdout.split('\n').includes(`/proc/${pid}`);
  }
  const ss = wsl(['ss', '-H', '-ltn']);
  c.daemonPortsFreeWsl = ss.status === 0 && !new RegExp(`:(${Object.values(ports).join('|')})\\s`).test(ss.stdout);
  const winPorts = [...Object.values(ports), facts.poolPort].filter(Boolean);
  const win = run('powershell.exe', ['-NoProfile', '-Command',
    `@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in ${winPorts.join(',')} }).Count`]);
  c.usedPortsFreeWindows = win.status === 0 && win.stdout.trim() === '0';
  if (profileDir) {
    const safe = resolve(profileDir).startsWith(resolve(tmpdir())) && /meep-p2p-block-/.test(profileDir);
    if (safe) { try { rmSync(profileDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* reported */ } }
    c.profileRemoved = !existsSync(profileDir);
  }
  c.retained = {};
  for (const [name, dir] of [['A', runDirA], ['B', runDirB]]) {
    const st = wsl(['stat', '-c', '%d:%i:%u', '--', dir]);
    const log = wsl(['sha256sum', '--', `${dir}/meepcoind.log`]);
    const size = wsl(['stat', '-c', '%s', '--', `${dir}/meepcoind.log`]);
    c.retained[name] = {
      runDir: dir,
      identity: st.status === 0 ? st.stdout.trim() : null,
      log: log.status === 0 ? { path: `${dir}/meepcoind.log`, bytes: Number(size.stdout.trim()), sha256: log.stdout.split(/\s+/)[0] } : null,
      dataDir: `${dir}/data`,
    };
  }
  const git = run('git', ['-C', REPO, 'status', '--porcelain']);
  c.gitStatusAtEnd = git.status === 0 ? (git.stdout.trim() === '' ? 'clean' : 'dirty') : 'unknown';
  // A pool that never started owns nothing to shut down (startDevPool closed what it owned before
  // rejecting); its daemons are then judged by the container, mount and port observations, which are
  // required either way.
  const released = c.browserExited !== false
    && Object.values(c.containersGone).every(Boolean) && Object.values(c.pidsGone).every(Boolean)
    && Array.isArray(c.containersMountingA) && c.containersMountingA.length === 0
    && Array.isArray(c.containersMountingB) && c.containersMountingB.length === 0
    && c.daemonPortsFreeWsl && c.usedPortsFreeWindows && c.profileRemoved !== false;
  c.released = released;
  evidence.cleanup = c;
  note('cleanup', c);
  return { released };
}

// ---------------------------------------------------------------- the finite sequence's evidence
/**
 * Everything the finite run established, PER HEIGHT and never merged: the raw template, calc_pow,
 * submission and readback records tagged with their block; the server, native and daemon hashes; each
 * block's verifier identity and release; A's and B's canonical readbacks with their timestamps; the page's
 * own per-block facts and Worker contexts; and RPC counts per daemon/channel, split at each issuance
 * for the application/evidence channel and reported separately for the read-only tip observer.
 */
async function recordSequence({ pool, sim, ev, browserEvents, blocks: configuredBlocks, shareProfile: shareSequence, sequenceFrames }) {
  const raw = sim.rpcAudit.raw;
  const rawDropped = sim.rpcAudit.rawDropped;
  const records = sim.blockRecords;
  const snaps = sim.rpcAudit.snapshots;
  const finalA = sim.rpcAudit.counts;
  const observerA = sim.tipObservationRpcCounts;
  const finalB = sim.peer.rpcCounts;
  const addCounts = (...sets) => {
    const out = {};
    for (const set of sets) for (const [method, count] of Object.entries(set ?? {})) {
      out[method] = (out[method] ?? 0) + count;
    }
    return out;
  };
  const combinedA = addCounts(finalA, observerA);
  const delta = (to, from) => Object.fromEntries(Object.keys({ ...to, ...from }).map((m) => [m, (to?.[m] ?? 0) - (from?.[m] ?? 0)]).filter(([, n]) => n !== 0));
  const page = await evaluate(cdp, `(() => { const e = (id) => document.getElementById(id); const t = (id) => e(id)?.textContent?.trim() ?? null; return {
    outcome: t('real-outcome'), sequence: t('real-sequence'), blocksText: t('real-blocks'),
    blocks: JSON.parse(e('real-blocks')?.dataset?.blocks ?? 'null'), totalAttempts: t('real-total-attempts'),
    workersCreated: t('real-workers'), workerContexts: JSON.parse(e('real-workers')?.dataset?.contexts ?? 'null'),
    staleWorkerMessages: e('real-workers')?.dataset?.stale ?? null, note: t('controls-note'), state: t('state'), error: t('error'),
    startDisabled: e('start-btn').disabled }; })()`);
  note('RESULT (server and page)', {
    attemptState: sim.attemptState, attemptReason: sim.attemptReason, currentHeight: sim.job.height.toString(),
    page, applicationPathATotal: { ...sim.submissionDaemon.counters }, serverCountersTotal: { ...sim.counters },
    tipObserver: sim.tipObserverFacts,
  });
  note('raw evidence capture', { records: raw.length, limit: sim.rpcAudit.rawLimit, dropped: rawDropped });
  for (const [i, rec] of records.entries()) {
    const block = rec.block;
    const next = snaps[block] ?? null;
    note(`BLOCK ${block}`, {
      template: rec.templateFacts ?? (block === 1 ? sim.templateFacts : null),
      rawGetBlockTemplate: raw.filter((r) => r.block === block && r.method === 'get_block_template'),
      runGeneration: rec.runGeneration ?? null,
      browser: page.blocks?.find((b) => b.block === block) ?? null,
      workerContext: page.workerContexts?.find((c) => c.jobId === rec.accepted?.jobId) ?? null,
      serverWasmHash: rec.lastHashes?.serverWasmHex ?? null,
      nativeHelperHash: rec.lastHashes?.nativeHelperHex ?? null,
      rawCalcPow: raw.filter((r) => r.block === block && r.method === 'calc_pow'),
      rawSubmitBlock: raw.filter((r) => r.block === block && r.method === 'submit_block'),
      rawReadbacksA: raw.filter((r) => r.block === block && (r.method === 'get_block_header_by_height' || r.method === 'get_last_block_header')),
      accepted: rec.accepted ?? null,
      externalTip: rec.externalTip ?? null,
      tipObservationFailure: rec.tipObservationFailure ?? null,
      propagationReadOnlyB: rec.propagation ?? null,
      verifier: rec.verifier ?? null,
      rotationFailure: rec.rotationFailure ?? null,
      rpcCountsThisHeight: snaps[i] ? {
        AApplicationEvidenceExcludingTipObserver: delta(next ? next.totalA : finalA, snaps[i].totalA),
        B: delta(next ? next.totalB : finalB, snaps[i].totalB),
        applicationPathA: delta(next ? next.application : { ...sim.submissionDaemon.counters }, snaps[i].application),
      } : null,
    });
  }
  note('server verifiers (each prior verifier released before its successor; the last by pool shutdown)', {
    released: sim.verifierHistory,
    current: ev ? { helperLinuxPid: ev.helperLinuxPid, helperSourceId: ev.helperSourceId, context: ev.context, verifierCounters: ev.verifierCounters, closed: ev.closed } : null,
  });
  note('authority', {
    firstIssuanceSuperseded: records[0]?.accepted ? sim.authority.isSuperseded(records[0].accepted.issuanceId) : null,
    currentIssuanceId: sim.authority.currentIssuanceId, claimCount: sim.authority.claimCount, maxClaims: sim.authority.maxClaims,
  });
  note('RPC counts (truthful channel split; observer reads excluded from raw application evidence)', {
    daemonACombinedTotal: combinedA,
    daemonAApplicationEvidence: finalA,
    daemonATipObserverReadOnly: observerA,
    daemonBReadOnly: finalB,
    setupBeforeTemplate1: snaps[0] ? { AApplicationEvidence: snaps[0].totalA, B: snaps[0].totalB } : null,
  });
  note('daemon B received no RPC block delivery', {
    bMethodsSent: Object.keys(finalB),
    bWriteMethodsSent: Object.keys(finalB).filter((m) => ['submit_block', 'calc_pow', 'get_block_template'].includes(m)),
  });
  note('browser runtime/console/network observations', browserEvents);
  if (shareSequence) {
    const sessionFacts = [...pool.sessions].map((sess) => sess.stateFacts);
    const proof = classifyShareSequenceOutcome({
      attemptState: sim.attemptState, attemptReason: sim.attemptReason,
      completeState: SIM_ATTEMPT_STATES.TERMINAL_COMPLETE, currentHeight: sim.job.height.toString(),
      records, raw, rawDropped, page, frames: sequenceFrames, sessionFacts, finalA, finalB,
      shareLimit: REAL_SHARE_LIMITS.maxSharesPerJob,
    });
    note('TWO-BLOCK SHARE FRAMES (bound per height)', sequenceFrames);
    note('TWO-BLOCK SHARE PROOF', {
      ...proof, fixedShareDifficulty: SHARE_PROFILE_DIFFICULTY,
      fixedBlockDifficulty: PEER_TEST_FIXED_DIFFICULTY, sessionFacts,
    });
    note('OUTCOME', proof.outcome);
    return proof.outcome;
  }
  let outcome;
  const height = sim.job.height.toString();
  if (sim.attemptState === SIM_ATTEMPT_STATES.TERMINAL_COMPLETE) {
    const complete = rawDropped === 0
      && records.length === configuredBlocks
      && records.every((r, i) => r.block === i + 1 && r.accepted && r.propagation?.converged === true)
      && (finalA.get_block_template ?? 0) === configuredBlocks
      && !Object.keys(finalB).some((m) => ['submit_block', 'calc_pow', 'get_block_template'].includes(m));
    outcome = complete
      ? `${configuredBlocks}_BLOCKS_ACCEPTED_BY_A_AND_RECEIVED_BY_B`
      : 'FAILED:sequence_evidence_incomplete';
  } else if (sim.attemptReason === 'search_bound_reached') {
    outcome = `BOUNDED_NO_SOLUTION_AT_HEIGHT_${height}`;
  } else {
    outcome = `FAILED:${sim.attemptReason}@height${height}`;
  }
  note('OUTCOME', outcome);
  return outcome;
}

// ------------------------------------------------------- the Cartesian sequence-refresh evidence
async function recordSequenceRefresh({ pool, sim, ev, browserEvents, blocks: configuredBlocks, refreshWindows: configuredWindows, frames }) {
  const raw = sim.rpcAudit.raw;
  const rawDropped = sim.rpcAudit.rawDropped;
  const records = sim.blockRecords;
  const finalA = sim.rpcAudit.counts;
  const finalB = sim.peer.rpcCounts;
  const page = await evaluate(cdp, `(() => { const e = (id) => document.getElementById(id); const t = (id) => e(id)?.textContent?.trim() ?? null; return {
    outcome: t('real-outcome'), sequence: t('real-sequence'), blocksText: t('real-blocks'),
    blocks: JSON.parse(e('real-blocks')?.dataset?.blocks ?? 'null'), totalAttempts: t('real-total-attempts'),
    workersCreated: t('real-workers'), workerContexts: JSON.parse(e('real-workers')?.dataset?.contexts ?? 'null'),
    staleWorkerMessages: e('real-workers')?.dataset?.stale ?? null, note: t('controls-note'), state: t('state'), error: t('error'),
    startDisabled: e('start-btn').disabled }; })()`);
  const sessionFacts = [...pool.sessions].map((session) => session.stateFacts);
  const active = frames.activeBinding;
  const liveIdentityConsistent = active !== null && active !== undefined
    && active.block === sim.blockIndex && active.window === sim.windowIndex
    && active.jobId === sim.job?.jobId && active.issuanceId === sim.job?.issuanceId;
  // The verifier object owns resource facts but not the issuance coordinates. Synthesize those only
  // after the live sim job and the independently captured active five-field binding agree exactly.
  const currentVerifier = ev === null || ev === undefined || !liveIdentityConsistent ? null : {
    ...ev,
    block: active.block,
    window: active.window,
    jobId: active.jobId,
    issuanceId: active.issuanceId,
  };
  const summary = sequenceRefreshEvidence({
    requestedBlocks: configuredBlocks,
    requestedWindows: configuredWindows,
    windowRecords: sim.windowRecords,
    sessionFacts,
    verifierHistory: sim.verifierHistory,
    currentVerifier,
    pageBlocks: page.blocks,
    attemptState: sim.attemptState,
    attemptReason: sim.attemptReason,
    submitBlockCount: raw.filter((item) => item.method === 'submit_block').length,
    calcPowCount: raw.filter((item) => item.method === 'calc_pow').length,
    cumulativeAttempts: parseCanonicalUintText(page.totalAttempts),
  });
  const shareCount = reconcileShareCount({
    sessionsPresent: sessionFacts.length > 0,
    sessionShares: sessionFacts.reduce((sum, facts) => sum + (facts.sharesAcceptedTotal ?? 0), 0),
    frameShareKeys: frames.shares.map((share) => `${share.block}:${share.window}:${share.nonce}`),
    framesCaptured: frames.captured && !frames.truncated,
  });
  const proof = classifyShareSequenceRefreshOutcome({
    attemptState: sim.attemptState,
    attemptReason: sim.attemptReason,
    completeState: SIM_ATTEMPT_STATES.TERMINAL_COMPLETE,
    currentHeight: sim.job.height.toString(),
    currentWindow: sim.windowIndex,
    requestedBlocks: configuredBlocks,
    requestedWindows: configuredWindows,
    maxAttempts: REAL_SEARCH_LIMITS.maxAttempts,
    maxContexts: REAL_MAX_CONTEXTS_PER_START,
    sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs,
    records,
    windowRecords: sim.windowRecords,
    verifierHistory: sim.verifierHistory,
    currentVerifier,
    raw,
    rawDropped,
    page,
    frames,
    sessionFacts,
    finalA,
    finalB,
    shareLimit: REAL_SHARE_LIMITS.maxSharesPerJob,
  });
  note('RESULT (Cartesian server and page)', {
    attemptState: sim.attemptState,
    attemptReason: sim.attemptReason,
    currentCoordinate: { block: sim.blockIndex, window: sim.windowIndex, height: sim.job.height.toString() },
    page,
    applicationPathATotal: { ...sim.submissionDaemon.counters },
    serverCountersTotal: { ...sim.counters },
    tipObserver: sim.tipObserverFacts,
  });
  for (const block of Array.from({ length: configuredBlocks }, (_, index) => index + 1)) {
    const rec = records.find((item) => item.block === block) ?? null;
    note(`BLOCK ${block} x ${configuredWindows} WINDOWS`, {
      windows: sim.windowRecords.filter((item) => item.block === block),
      bindings: frames.bindings.filter((item) => item.block === block),
      readiness: frames.readiness.filter((item) => item.block === block),
      workerContextsByJobId: frames.bindings.filter((item) => item.block === block).map((binding) => ({
        block: binding.block,
        window: binding.window,
        jobId: binding.jobId,
        workerContext: page.workerContexts?.find((context) => context.jobId === binding.jobId) ?? null,
      })),
      rawGetBlockTemplate: raw.filter((item) => item.block === block && item.method === 'get_block_template'),
      rawCalcPow: raw.filter((item) => item.block === block && item.method === 'calc_pow'),
      rawSubmitBlock: raw.filter((item) => item.block === block && item.method === 'submit_block'),
      accepted: rec?.accepted ?? null,
      propagationReadOnlyB: rec?.propagation ?? null,
      serverWasmHash: rec?.lastHashes?.serverWasmHex ?? null,
      nativeHelperHash: rec?.lastHashes?.nativeHelperHex ?? null,
    });
  }
  evidence.sequenceRefresh = {
    summary,
    proof,
    shareCount,
    boundFrames: frames,
    sessionFacts,
  };
  note('SEQUENCE x WINDOW REFRESH (server-side facts)', summary);
  note('SEQUENCE x WINDOW BOUND FRAMES', frames);
  note('SEQUENCE x WINDOW PROOF', proof);
  note('RPC counts (application evidence A; read-only B)', { A: finalA, B: finalB });
  note('browser runtime/console/network observations', browserEvents);
  note('OUTCOME', proof.outcome);
  if (proof.outcome.startsWith('BOUNDED_AFTER_')) {
    note('what this handoff-boundary outcome does and does not claim',
      `${proof.heights.length} earlier height(s) were independently accepted and observed on both private peers. The fixed whole-session clock then passed before the successor height was ever issued, so there was no successor browser job or no-block observation. The accepted block evidence remains valid, the requested multi-height run is incomplete, and nothing is retried.`);
  } else if (proof.outcome.startsWith('BOUNDED_OBSERVATION_')) {
    const prior = proof.heights.length;
    note('what this bounded outcome does and does not claim', prior === 0
      ? 'the current height exhausted its authorised search/session bound without a block. This is a valid bounded engineering observation, not a mined-block claim, and it is not retried.'
      : `${prior} earlier height(s) were independently accepted and observed on both private peers; the current height then exhausted its authorised search/session bound without a block. The earlier block evidence remains valid, but the requested multi-height run is incomplete and is not retried.`);
  }
  return proof.outcome;
}

// ---------------------------------------------------------------- the run
lifecycle.run(async () => {
  // ---- gates before anything starts -----------------------------------------------------------
  const headResult = run('git', ['-C', REPO, 'rev-parse', 'HEAD']);
  const statusResult = run('git', ['-C', REPO, 'status', '--porcelain']);
  const head = headResult.stdout.trim();
  const porcelain = statusResult.stdout;
  const dirty = porcelain.trim() === '' ? 'clean' : 'dirty';
  const trackedDirty = trackedDirtyEntries(porcelain, ALLOWED_UNTRACKED);
  note('tested commit', {
    head, statusAtStart: dirty, statusCommandExit: statusResult.status, trackedDirty,
    allowedUntracked: ALLOWED_UNTRACKED, expectedHeadSuppliedExternally: shareProfile ? expectedHead : null,
  });
  if (shareProfile) {
    // THE AUTHORIZED TEXT OR NOTHING, against the pin the audit supplied. Both git commands must
    // have succeeded: a failed status proves nothing and is never read as "clean".
    const pin = classifyHeadPin({
      expectedHead, headResult, statusResult, allowedUntracked: ALLOWED_UNTRACKED,
      trackedDirty: trackedDirtyEntries,
    });
    note('authorized commit pin', { ok: pin.ok, error: pin.error, head: pin.head, expected: expectedHead });
    if (!pin.ok) throw new Error(pin.error);
  }
  const powerQuery = run('powershell.exe', ['-NoProfile', '-Command',
    'Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus']);
  const power = classifyPowerLineStatus(powerQuery);
  evidence.power = {
    queryExitStatus: powerQuery.status ?? null,
    queryStdout: bounded(powerQuery.stdout, 160),
    queryStderr: bounded(powerQuery.stderr, 160),
    state: power.state,
    onBattery: power.onBattery,
    warning: power.warning,
    established: power.ok,
  };
  note('power source', evidence.power);
  if (!power.ok) throw new Error(power.error);
  if (power.warning !== null) note('BATTERY WARNING', power.warning);
  const dockerInfo = wsl(['docker', 'info', '--format', '{{json .Labels}}']);
  const dockerEngine = classifyWslDockerEngine(dockerInfo);
  note('WSL Docker engine topology', { ...dockerEngine, labels: bounded(dockerInfo.stdout, 300) });
  if (!dockerEngine.ok) throw new Error(dockerEngine.error);
  const actualImage = wsl(['docker', 'image', 'inspect', '--format', '{{.Id}}', image]).stdout.trim();
  note('image', { tag: image, id: actualImage });
  if (actualImage !== imageId) throw new Error('the image id is not the pinned one');
  const runtimeLibraryDir = `${artifactDir}/runtime-libs`;
  const requiredArtifactNames = [
    'meepcoind',
    'meepcoin-blockhashing',
    ...CONVERTER_RUNTIME_LIBRARIES.map((name) => `runtime-libs/${name}`),
  ];
  const requiredArtifactPaths = requiredArtifactNames.map((name) => `${artifactDir}/${name}`);
  const manifestResult = wsl(['cat', '--', `${artifactDir}/BUILD_MANIFEST.txt`]);
  const hashResult = wsl(['sha256sum', '--', ...requiredArtifactPaths]);
  const sizeResult = wsl(['stat', '-c', '%s', '--', ...requiredArtifactPaths]);
  const loaderResult = wsl(['/usr/bin/env', '-i', `LD_LIBRARY_PATH=${runtimeLibraryDir}`,
    '/usr/bin/ldd', `${artifactDir}/meepcoin-blockhashing`]);
  const runtimeArtifacts = classifyConverterRuntimeArtifacts({
    manifestText: manifestResult.status === 0 ? manifestResult.stdout : '',
    requiredNames: requiredArtifactNames,
    actualHashes: hashResult.status === 0
      ? hashResult.stdout.trim().split(/\r?\n/).map((line) => line.trim().split(/\s+/)[0]) : [],
    sizes: sizeResult.status === 0 ? sizeResult.stdout.trim().split(/\r?\n/).map(Number) : [],
    loaderStatus: loaderResult.status,
    loaderStdout: loaderResult.stdout,
    runtimeLibraryDir,
  });
  const manifestObservation = {
    status: manifestResult.status,
    bytes: manifestResult.status === 0 ? Buffer.byteLength(manifestResult.stdout) : null,
    sha256: manifestResult.status === 0
      ? createHash('sha256').update(manifestResult.stdout).digest('hex') : null,
  };
  note('daemon and converter runtime artifacts', {
    ok: runtimeArtifacts.ok,
    error: runtimeArtifacts.error,
    artifacts: runtimeArtifacts.artifacts,
    manifest: manifestObservation,
    loader: { status: loaderResult.status, stdout: bounded(loaderResult.stdout, 4_000), stderr: loaderResult.stderr },
  });
  if (!runtimeArtifacts.ok) throw new Error(runtimeArtifacts.error);
  const helper = resolve(REPO, 'meepow/build/native-helper/meepow-v2-helper');
  note('browser/server/native artifacts', {
    wasmMjs: sha256File(resolve(REPO, 'meepow/wasm/meepow.mjs')),
    wasmWasm: sha256File(resolve(REPO, 'meepow/wasm/meepow.wasm')),
    nativeHelper: { bytes: readFileSync(helper).length, sha256: sha256File(helper) },
    nativeHelperSourceId: computeSourceId().sourceId,
  });
  const wslListen = wsl(['ss', '-H', '-ltnu']).stdout;
  const busyWsl = Object.values(ports).filter((p) => new RegExp(`:${p}\\s`).test(wslListen));
  const winBusy = run('powershell.exe', ['-NoProfile', '-Command',
    `@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in ${Object.values(ports).join(',')} }).Count`]).stdout.trim();
  const leftovers = wsl(['docker', 'ps', '-a', '--format', '{{.Names}}']).stdout.split('\n').filter((n) => n.startsWith('meepcoin-private-'));
  note('ports and leftovers', { busyWsl, windowsListenersOnDaemonPorts: winBusy, leftoverContainers: leftovers });
  if (busyWsl.length > 0 || winBusy !== '0' || leftovers.length > 0) throw new Error('a daemon port is occupied or a daemon container is left over');

  if (blocks > 1) {
    note('FROZEN SEQUENCE (before Start)', `one Start; one Worker for the whole session; at most ${blocks} consecutive fresh templates from A (heights 1 through ${blocks}); each next template after a block THIS BROWSER mined follows only once that block is canonical on A and identical on B, and only after the prior server verifier and helper are confirmed released; the pool also watches A's own canonical tip while a run is live, so a block another miner puts at the height being searched supersedes that job (a tip past it ends the run instead of guessing a catch-up template); never a template ${blocks + 1}`);
  }
  if (shareProfile) {
    const shareScope = refreshWindows !== null
      ? (sequenceRefresh
        ? `${blocks} heights; up to ${refreshWindows} serial job/template issuances per height (${blocks * refreshWindows} contexts total), one at a time`
        : `ONE height; up to ${refreshWindows} serial job/template issuances for that same height, one at a time`)
      : `${blocks} height/template context(s), one at a time`;
    note('FROZEN BOUNDS (before Start, opt-in share path)', `one explicit human Start; one Worker; ${shareScope}; each issuance names one disjoint nonce range of at most ${REAL_SEARCH_LIMITS.maxAttempts} values, issued once and never rescanned; the Worker searches a bounded prefix until the first applicable stop: ${REAL_SEARCH_LIMITS.maxAttempts} attempts, ${REAL_SEARCH_LIMITS.maxSearchMs / 1000} seconds, one block-target hit, or ${REAL_SHARE_LIMITS.maxSharesPerJob} qualifying hits PER ISSUANCE; the page reports at most ${REAL_SHARE_LIMITS.maxSharesPerJob} results per issuance, ONE AT A TIME; the server verifies one candidate at a time with its own Wasm and the native helper; a share that is not a block reaches no daemon at all; at most ONE calc_pow and ONE submit_block to daemon A PER HEIGHT; zero retry; no RPC delivery to B; no wallet; fixed difficulties ${effectiveShareDifficulty} share / ${PEER_TEST_FIXED_DIFFICULTY} block`);
  }
  if (!shareProfile) note(blocks > 1 ? 'FROZEN BOUNDS PER HEIGHT (before Start)' : 'FROZEN BOUNDS (before Start)', `one Worker; nonce window [0, ${REAL_SEARCH_LIMITS.maxAttempts}); at most ${REAL_SEARCH_LIMITS.maxAttempts} attempts; at most ${REAL_SEARCH_LIMITS.maxSearchMs / 1000} s in the Worker; server backstop +30 s; one candidate; one server Wasm, one native helper and one daemon-A calc_pow; at most one submit_block to A; zero retry; no RPC delivery to B; fixed test difficulty ${PEER_TEST_FIXED_DIFFICULTY}`);
  if (refreshWindows !== null) {
    note(sequenceRefresh ? 'SEQUENCE x WINDOW REFRESH (before Start)' : 'SAME-HEIGHT WINDOW REFRESH (before Start)',
      `one Start; ${sequenceRefresh ? `${blocks} consecutive heights` : 'ONE height'}; at most ${refreshWindows} nonce `
      + `windows per height, searched ONE AT A TIME; each further window is a fresh server-issued job and template `
      + `over a nonce range that does not overlap one already searched; the previous server verifier and native `
      + `helper are closed and their release CONFIRMED before the next pair is built; the whole session is `
      + `bounded by ${REAL_REFRESH_LIMITS.maxSessionMs / 60_000} minutes from the accepted Start; at most ONE `
      + `block submission per height; each next height starts again at nonce 0 only after the previous block is canonical on A and identical on B; no refresh after Stop, a hidden tab, a lost socket, a moved canonical `
      + 'tip, a claimed submission or the session budget; nothing is retried and nothing auto-resumes');
  }
  if (refreshHandoffProbe) {
    note('REFRESH HANDOFF PROBE (before Start)', `engineering objective only: exercise exactly one `
      + 'window-1 to window-2 handoff; source-fixed share difficulty 1 makes every completed hash a '
      + `qualifying share while block difficulty remains ${PEER_TEST_FIXED_DIFFICULTY}; the existing `
      + `${REAL_SHARE_LIMITS.maxSharesPerJob}-result cap normally retires window 1 after at most `
      + `${REAL_SHARE_LIMITS.maxSharesPerJob} hashes; a genuine block still wins immediately and this `
      + 'one-use run is not retried if the handoff is therefore not reached');
  }
  note('daemon run dirs', { A: runDirA, B: runDirB });

  // ---- the one-use reservation, BEFORE the first live side effect ------------------------------
  if (shareProfile) {
    const reservation = reserveOneUse({
      path: reservationPath,
      payload: {
        reservedAt: now(),
        expectedHeadSuppliedExternally: expectedHead,
        head,
        screenshotDir: resolve(screenshotDir),
        runId,
        purpose: refreshHandoffProbe
          ? 'one private interactive two-daemon same-height refresh-handoff engineering probe'
          : (sequenceRefresh
            ? `one private interactive two-daemon ${blocks}-block x ${refreshWindows}-window opt-in multi-share observation`
            : (blocks === 2
            ? 'one private interactive two-daemon two-block opt-in multi-share observation'
            : 'one private interactive two-daemon opt-in multi-share observation')),
        ...(refreshHandoffProbe ? { refreshHandoffProbe: true } : {}),
        shareDifficulty: effectiveShareDifficulty,
        blockDifficulty: PEER_TEST_FIXED_DIFFICULTY,
        blocks,
        refreshWindowsRequested: refreshWindows,
        interactive: true,
        evidencePath: resolve(evidencePath),
        transcriptPath: resolve(transcriptPath),
        oneUse: 'this file is never deleted or overwritten by this runner; a restart is refused',
      },
      writeFile: writeFileSync,
      readFile: readFileSync,
    });
    note('one-use reservation', { path: resolve(reservationPath), ok: reservation.ok, reason: reservation.reason });
    if (!reservation.ok) throw new Error(reservation.reason);
    const issuanceScope = refreshWindows !== null
      ? (sequenceRefresh
        ? `${blocks * refreshWindows} job/template issuances across ${blocks} heights (${refreshWindows} per height)`
        : `${refreshWindows} job/template issuances of ONE height`)
      : `${blocks} height/template(s)`;
    note('OPT-IN SHARE PROFILE (before the pool starts)', `share difficulty ${effectiveShareDifficulty} against block difficulty ${PEER_TEST_FIXED_DIFFICULTY} (D_share <= D_block, so the share target is numerically >= the block target); at most ${REAL_SHARE_LIMITS.maxSharesPerJob} verified results PER ISSUANCE over at most ${issuanceScope}, verified ONE AT A TIME; at most ONE submit_block to daemon A PER HEIGHT; no wallet and no write RPC to daemon B`);
  }

  // ---- the owned pair (the lifecycle passes the startup AbortSignal and assigns the pool) ------
  const pool = await lifecycle.startPool({
    host: '127.0.0.1', port: 0, mode: REAL_DAEMON_MODE, wslDistro: WSL_DISTRO,
    realDaemon: {
      daemon: configA,
      peer: { daemon: configB },
      // Every issuance is distinct server-owned work, derived by the native converter from a fresh
      // 16-byte reserve allocation. No browser field can select or observe that allocation.
      personalizeTemplates: true,
      // TRUSTED STARTUP CONFIGURATION IS THE ONLY WAY SHARE WORK IS ENABLED. Without the flag this
      // key is absent and the server runs the legacy one-candidate profile, exactly as before.
      ...(shareProfile ? { shareDifficulty: effectiveShareDifficulty } : {}),
      // OPT-IN AND EXPLICIT. Absent flag, absent key: the pool builds the legacy one-window run.
      ...(refreshWindows === null ? {} : { refreshWindows }),
      // Disclosure and evidence may call this the source-fixed probe only when this trusted marker
      // survives the real-daemon builder. Difficulty/window fields remain independently validated.
      ...(refreshHandoffProbe ? { refreshHandoffProbe: true } : {}),
      ...(blocks > 1 ? { sequenceBlocks: blocks } : {}),
    },
  });
  const sim = pool.simulation;
  const A = sim.daemonResource;
  const B = sim.peer.daemonResource;
  facts = { containers: [A.containerName, B.containerName], pids: [A.linuxPid, B.linuxPid], helperPids: [], poolPort: pool.port };
  note('pool', { url: pool.url, port: pool.port, nodePid: process.pid });
  for (const [name, r] of [['A', A], ['B', B]]) {
    note(`daemon ${name}`, {
      container: r.containerName, linuxPid: r.linuxPid, imageId: r.imageId, mounts: r.mounts,
      runDir: r.runDir, runDirIdentity: r.runDirIdentity, listeners: r.listeners, argv: r.launchArgs,
    });
  }
  note('shared genesis', sim.peer.genesis);
  note('A<->B link observations (before template)', sim.peer.linkObservations);
  note('fresh template (daemon A)', sim.templateFacts);
  note('raw get_block_template', sim.rpcAudit.raw.filter((r) => r.method === 'get_block_template'));

  // ---- the browser ------------------------------------------------------------------------------
  lifecycle.throwIfCancelled();
  profileDir = mkdtempSync(join(tmpdir(), 'meep-p2p-block-'));
  note('throwaway profile', profileDir);
  chrome = spawn(browserPath, browserLaunchArgs({ headed: interactive, profileDir }),
    { stdio: ['ignore', 'pipe', 'pipe'], shell: false });
  // Wired in this same tick, with no asynchronous gap: see observeBrowserStartup.
  const browserStartup = observeBrowserStartup(chrome, { onExit: () => { chromeExited = true; } });
  note('browser mode', interactive ? 'visible (operator start)' : 'headless');
  const devtoolsUrl = await waitUntil(() => {
    // A browser that could not start, or that died before saying where DevTools is, is an ordinary
    // body failure with a closed code -- not a 30-second wait and not an uncaught exception.
    if (browserStartup.failure !== null) throw browserStartup.failure;
    return browserStartup.devtoolsUrl;
  }, { timeoutMs: 30_000, label: 'DevTools' });
  note('browser pid', chrome.pid);
  const browserCdp = connectCdp(devtoolsUrl);
  await browserCdp.ready;
  // Chrome was launched with one about:blank page. Reuse that page instead of
  // adding a second tab that could accidentally background the mining page.
  const initialPage = await waitUntil(async () => {
    const { targetInfos } = await browserCdp.send('Target.getTargets');
    return initialBlankPageTarget(targetInfos);
  }, { timeoutMs: 5_000, label: 'the owned initial browser page' });
  const { targetId } = initialPage;
  cdp = connectCdp(devtoolsUrl.replace(/\/devtools\/browser\/.*$/, `/devtools/page/${targetId}`));
  await cdp.ready;
  browserCdp.close();

  const browserEvents = { exceptions: [], consoleErrors: [], logErrors: [], loadingFailed: [], httpErrors: [], workerSessions: 0 };
  const push = (list, item) => { if (list.length < MAX_BROWSER_EVENTS) list.push(item); };
  // THE SERVER'S OWN WORDS, AS THE PAGE RECEIVED THEM. A closed socket disposes the pool session and
  // its counters with it, so these bound frames are the second, durable source the share evidence
  // reconciles against. Bounded like every other capture: frames beyond the cap set `truncated`, and
  // a truncated capture is never treated as a complete count.
  const serverFrames = {
    shares: [], blocks: [], truncated: false, captured: false,
    activeBinding: null, rejected: [], rejectedCount: 0,
  };
  const sequenceFrames = {
    activeBinding: null, bindings: [], shares: [], blocks: [], terminalBlocks: [],
    truncated: false, captured: false, rejected: [], rejectedCount: 0,
  };
  // THE REFRESH RUN'S OWN BOUND CAPTURE: one binding per window, advanced only by a validated
  // job_refresh, with every share and block frame kept by the window it was bound to.
  const refreshFrames = {
    activeBinding: null, initialJobFacts: null, bindings: [], shares: [], blocks: [],
    truncated: false, captured: false, rejected: [], rejectedCount: 0,
  };
  // One chain for the Cartesian mode. It is deliberately separate from both one-dimensional
  // collectors: no frame may be counted once as a sequence fact and again as a refresh fact.
  const sequenceRefreshFrames = {
    activeBinding: null, initialJobFacts: null, bindings: [], readiness: [], shares: [], blocks: [],
    terminalBlocks: [], truncated: false, captured: false, rejected: [], rejectedCount: 0,
  };
  const noteFrame = (list, item) => {
    serverFrames.captured = true;
    if (list.length >= MAX_BROWSER_EVENTS) { serverFrames.truncated = true; return; }
    list.push(item);
  };
  const rejectFrame = (type, reason) => {
    serverFrames.rejectedCount += 1;
    if (serverFrames.rejected.length < MAX_BROWSER_EVENTS) serverFrames.rejected.push({ at: now(), type, reason });
  };
  cdp.onEvent((method, params, sessionId) => {
    const where = sessionId ? 'worker' : 'page';
    if (method === 'Target.attachedToTarget') {
      browserEvents.workerSessions += 1;
      const sid = params.sessionId;
      for (const d of ['Runtime.enable', 'Network.enable', 'Log.enable']) cdp.send(d, {}, sid).catch(() => {});
      cdp.send('Runtime.runIfWaitingForDebugger', {}, sid).catch(() => {});
    }
    if (method === 'Runtime.exceptionThrown') push(browserEvents.exceptions, { where, text: bounded(params.exceptionDetails?.exception?.description ?? params.exceptionDetails?.text) });
    if (method === 'Runtime.consoleAPICalled' && params.type === 'error') push(browserEvents.consoleErrors, { where, text: bounded((params.args ?? []).map((a) => a.value ?? a.description ?? '').join(' ')) });
    if (method === 'Log.entryAdded' && params.entry?.level === 'error') push(browserEvents.logErrors, { where, text: bounded(params.entry.text), url: bounded(params.entry.url, 120) });
    if (method === 'Network.loadingFailed') push(browserEvents.loadingFailed, { where, error: bounded(params.errorText, 120), canceled: params.canceled === true });
    if (method === 'Network.responseReceived' && params.response?.status >= 400) push(browserEvents.httpErrors, { where, status: params.response.status, url: bounded(params.response.url, 160) });
    if (method === 'Network.webSocketFrameReceived' && shareProfile) {
      let frame = null;
      try { frame = JSON.parse(params.response?.payloadData ?? ''); } catch { frame = null; }
      if (sequenceRefresh) {
        const verdict = captureShareSequenceRefreshFrame({
          state: sequenceRefreshFrames,
          frame,
          limit: MAX_BROWSER_EVENTS,
          blockTotal: blocks,
          windowTotal: refreshWindows,
          sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs,
        });
        if (!verdict.accepted && verdict.reason !== 'not_an_evidence_frame') {
          note('rejected sequence-refresh server frame', { type: frame?.type ?? null, reason: verdict.reason });
        }
        return;
      }
      if (blocks === 2) {
        const verdict = captureShareSequenceFrame({ state: sequenceFrames, frame, limit: MAX_BROWSER_EVENTS });
        if (!verdict.accepted && verdict.reason !== 'not_an_evidence_frame') {
          note('rejected two-block server frame', { type: frame?.type ?? null, reason: verdict.reason });
        }
        return;
      }
      if (refreshWindows !== null) {
        // A REFRESH RUN ADVANCES ITS BINDING ONLY THROUGH A VALIDATED job_refresh, and keeps every
        // share and block frame by the window it was bound to. A late prior-window frame is
        // quarantined, and a forged transition changes nothing.
        const verdict = captureShareRefreshFrame({
          state: refreshFrames, frame, limit: MAX_BROWSER_EVENTS, windowTotal: refreshWindows,
        });
        if (!verdict.accepted && verdict.reason !== 'not_an_evidence_frame') {
          note('rejected refresh server frame', { type: frame?.type ?? null, reason: verdict.reason });
        }
        return;
      }
      // THE ACTIVE BINDING IS LEARNED ONCE, from the server's own run_started, and never revised by
      // a later frame: a message claiming a different binding is the thing being defended against.
      if (frame?.type === 'run_started' && serverFrames.activeBinding === null) {
        const b = {
          clientStartId: frame.clientStartId, workerId: frame.workerId, jobId: frame.jobId,
          issuanceId: frame.issuanceId, runGeneration: frame.runGeneration,
        };
        if (Object.values(b).every((v) => v !== null && v !== undefined && v !== '')) {
          serverFrames.activeBinding = b;
        }
      }
      if (frame && (frame.type === 'share_accepted' || frame.type === 'block_accepted')) {
        const verdict = classifyServerFrame({
          frame,
          active: serverFrames.activeBinding,
          jobId: sim?.job?.jobId ?? null,
          issuanceId: sim?.authority?.currentIssuanceId ?? null,
        });
        if (!verdict.accepted) {
          rejectFrame(frame.type, verdict.reason);
        } else {
          const record = {
            at: now(), type: frame.type, nonce: frame.nonce,
            hashHexLE: bounded(frame.hashHexLE, 64) || null, blockId: bounded(frame.blockId, 64) || null,
            shareIndex: frame.shareIndex ?? null,
            boundTo: {
              clientStartId: bounded(frame.clientStartId, 80), workerId: bounded(frame.workerId, 80),
              jobId: bounded(frame.jobId, 80), issuanceId: bounded(frame.issuanceId, 80),
              runGeneration: frame.runGeneration,
            },
          };
          noteFrame(frame.type === 'share_accepted' ? serverFrames.shares : serverFrames.blocks, record);
        }
      }
    }
  });

  /**
   * ONE SCREENSHOT, CREATED EXCLUSIVELY, NEVER OVERWRITING. A failure is recorded as missing
   * evidence and never retried: the run is not repeated for a picture.
   */
  const captureScreenshot = async (phase) => {
    const file = join(resolve(screenshotDir), screenshotFileName({ runId, phase }));
    const record = { phase, path: file, ok: false, reason: null, bytes: 0 };
    try {
      const shot = await cdp.send('Page.captureScreenshot', { format: 'png' });
      const bytes = Buffer.from(shot.data, 'base64');
      writeFileSync(file, bytes, { flag: 'wx' });
      record.ok = true;
      record.bytes = bytes.length;
      record.sha256 = createHash('sha256').update(bytes).digest('hex');
    } catch (err) {
      record.reason = bounded(err?.code ?? err?.message ?? err, 160);
    }
    evidence.screenshots.push(record);
    note(`screenshot (${phase})`, record);
    return record;
  };
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Network.enable');
  await cdp.send('Log.enable');
  await cdp.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true });

  await cdp.send('Page.navigate', { url: pool.url });
  await waitUntil(() => evaluate(cdp, 'document.readyState === "complete"'), { timeoutMs: 30_000, label: 'page load' });
  await waitUntil(() => evaluate(cdp, '!!document.getElementById("real-banner") && !document.getElementById("real-banner").hidden'),
    { timeoutMs: 30_000, label: 'the real-daemon banner' });
  note('page before Start', await evaluate(cdp, '({ hashes: document.getElementById("hashes").textContent.trim(), start: document.getElementById("start-btn").textContent.trim(), window: document.getElementById("real-window").textContent.trim(), labels: [...document.querySelectorAll("#real-labels li")].map((l) => l.textContent) })'));
  if (shareProfile) {
    // FAIL CLOSED BEFORE ANYONE IS ASKED TO PRESS START, AND SAY WHAT THAT DOES AND DOES NOT MEAN.
    //
    // By this point the reservation file exists, both daemons are running, the helper is up and the
    // browser is open: the SETUP has happened and the one-use reservation is CONSUMED. What has not
    // happened is the browser mining Start -- no Worker searched, no candidate was submitted, no
    // block was claimed. If the pre-Start picture cannot be written the terminal one will not be
    // either, so the run stops here rather than asking a human to press Start for evidence that is
    // already incomplete. Throwing goes through the single finalization path, which closes the
    // browser, the pool, both daemons and the helper. Nothing is retried, silently or otherwise:
    // another attempt needs a new authorization and a new reservation path.
    const pre = await captureScreenshot('pre-start');
    if (!pre.ok) {
      note('PRE-START SCREENSHOT FAILED -- STOPPING BEFORE START', {
        reason: pre.reason,
        browserMiningStarted: false,
        reservationConsumed: true,
        reservationPath: resolve(reservationPath),
        daemonsLaunched: true,
        meaning: 'setup ran and the one-use reservation is spent; no Start, no search, no submission. '
          + 'This is not retried: a further attempt needs a new authorization and a new reservation path.',
      });
      throw new Error(`the pre-Start screenshot could not be written (${pre.reason}); the browser mining Start `
        + 'was never requested, but the setup and the one-use reservation are already consumed');
    }
  }
  note('server before Start', { verifierAbsent: sim.verifier === null, counters: { ...sim.counters }, applicationPathA: { ...sim.submissionDaemon.counters }, totalRpcA: sim.rpcAudit.counts, totalRpcB: sim.peer.rpcCounts });

  // ---- THE ONE START ------------------------------------------------------------------------------
  lifecycle.throwIfCancelled();
  if (interactive) {
    // OPERATOR START. This branch cannot reach the programmatic click above or below it: the runner
    // brings its own page forward, says what it is waiting for, and then watches the SERVER.
    await cdp.send('Page.bringToFront');
    const readVisibility = () => evaluate(cdp,
      '({ state: document.visibilityState, hidden: document.hidden, focused: document.hasFocus() })');
    let visibilityBeforeStart = await readVisibility();
    if (visibilityBeforeStart.state !== 'visible' || visibilityBeforeStart.hidden !== false) {
      note('waiting for the operator to foreground the mining page', visibilityBeforeStart);
      visibilityBeforeStart = await waitUntil(async () => {
        const visibility = await readVisibility();
        return visibility.state === 'visible' && visibility.hidden === false ? visibility : null;
      }, { timeoutMs: 120_000, everyMs: 250, label: 'the mining page to become visible before Start' });
    }
    note('page visibility before operator Start', visibilityBeforeStart);
    note('waiting for the operator or delegated agent to press Start on the page (this runner never clicks)', {
      page: pool.url, timeoutMs: OPERATOR_START_TIMEOUT_MS, runnerClicksStart: false,
      attemptState: sim.attemptState,
    });
    await waitUntil(() => {
      // ONE snapshot of both facts, classified in one place. The operator closing the visible browser
      // while the attempt is still IDLE is an ordinary failure -- not a reason to wait out the whole
      // budget, and never a reason to start the run on their behalf. A window closed AFTER the pool
      // observed Start is not a pre-Start failure at all.
      const verdict = classifyOperatorStart({
        attemptState: sim.attemptState,
        idleState: SIM_ATTEMPT_STATES.IDLE,
        browserExited: chromeExited,
      });
      if (verdict === 'exited_before_start') {
        throw new Error('the visible browser exited before the server observed Start');
      }
      return verdict === 'observed';
    }, { timeoutMs: OPERATOR_START_TIMEOUT_MS, everyMs: 250, label: 'the operator to press Start' });
    note('Start by the operator or delegated agent, observed by the server', {
      at: now(), attemptState: sim.attemptState, attemptReason: sim.attemptReason,
    });
  } else {
    note('Start clicked', now());
    await evaluate(cdp, 'document.getElementById("start-btn").click()');
  }
  await waitUntil(() => [SIM_ATTEMPT_STATES.TERMINAL_COMPLETE, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, SIM_ATTEMPT_STATES.TERMINAL_FAILED]
    .includes(sim.attemptState), {
    // The Cartesian core owns one ten-minute session budget across every height/window. The runner
    // must outwait that whole budget, plus bounded server/propagation finalization, or it could time
    // out first and mislabel a valid core terminal state.
    timeoutMs: sequenceRefresh
      ? REAL_REFRESH_LIMITS.maxSessionMs + SEQUENCE_REFRESH_FINALIZATION_MS
      : (blocks > 1 ? blocks * (REAL_SEARCH_LIMITS.maxSearchMs + 30_000) + 120_000 : 400_000),
    everyMs: 250,
    label: 'the one attempt to finish',
  });
  await sleep(1500);
  const ev = pool.simulationEvidence;
  facts.helperPids = [...sim.verifierHistory.map((v) => v.helperLinuxPid), ev?.helperLinuxPid ?? null].filter(Boolean);
  if (sequenceRefresh) {
    const outcome = await recordSequenceRefresh({
      pool,
      sim,
      ev,
      browserEvents,
      blocks,
      refreshWindows,
      frames: sequenceRefreshFrames,
    });
    // One terminal picture while the owned browser still exists. As everywhere else, a failed
    // picture never spends a second Start or turns this one-use run into a retry loop.
    const terminalShot = await captureScreenshot('terminal');
    if (!terminalShot.ok) {
      note('INCOMPLETE SCREENSHOT EVIDENCE', `the terminal screenshot could not be written: ${terminalShot.reason}; the run is not retried`);
      evidence.outcome = `EVIDENCE_INCOMPLETE_TERMINAL_SCREENSHOT_AFTER_${outcome}`;
      return EXIT_CODES.FAILED;
    }
    evidence.outcome = outcome;
    return outcome === sequenceRefreshSuccessOutcome(blocks, refreshWindows)
      ? EXIT_CODES.OK : EXIT_CODES.FAILED;
  }
  if (blocks > 1) {
    const outcome = await recordSequence({ pool, sim, ev, browserEvents, blocks, shareProfile, sequenceFrames });
    if (shareProfile) {
      // One terminal picture while the owned browser still exists. A failure of this last capture
      // never causes another Start; preserve the underlying result and report incomplete evidence.
      const terminalShot = await captureScreenshot('terminal');
      if (!terminalShot.ok) {
        note('INCOMPLETE SCREENSHOT EVIDENCE', `the terminal screenshot could not be written: ${terminalShot.reason}; the run is not retried`);
        evidence.outcome = `EVIDENCE_INCOMPLETE_TERMINAL_SCREENSHOT_AFTER_${outcome}`;
        return EXIT_CODES.FAILED;
      }
    }
    evidence.outcome = outcome;
    return outcome === (shareProfile
      ? 'SHARE_SEQUENCE_2_BLOCKS_ACCEPTED_BY_A_AND_RECEIVED_BY_B'
      : `${blocks}_BLOCKS_ACCEPTED_BY_A_AND_RECEIVED_BY_B`) ? EXIT_CODES.OK : EXIT_CODES.FAILED;
  }

  const page = await evaluate(cdp, `(() => { const t = (id) => document.getElementById(id)?.textContent?.trim() ?? null; return {
    outcome: t('real-outcome'), searched: t('real-searched'), foundNonce: t('real-found-nonce'),
    browserHash: t('real-browser-hash'), serverHash: t('real-server-hash'), blockId: t('real-block-id'),
    counters: t('real-counters'), note: t('controls-note'), state: t('state'), error: t('error'),
    // The page's own cumulative count across the windows of this height; a dash when it has none.
    totalAttempts: t('real-total-attempts'), acceptedShares: t('accepted'), windowPosition: t('real-sequence'),
    startDisabled: document.getElementById('start-btn').disabled }; })()`);
  const raw = sim.rpcAudit.raw;
  note('RESULT (server and page)', {
    attemptState: sim.attemptState,
    attemptReason: sim.attemptReason,
    browser: { attempts: page.searched, foundNonce: page.foundNonce, hash: page.browserHash },
    serverWasmHash: sim.lastHashes.serverWasmHex,
    nativeHelperHash: sim.lastHashes.nativeHelperHex,
    daemonACalcPow: raw.filter((r) => r.method === 'calc_pow'),
    submitBlock: raw.filter((r) => r.method === 'submit_block'),
    applicationPathA: { ...sim.submissionDaemon.counters },
    serverCounters: { ...sim.counters },
    verifierCounters: ev?.verifierCounters ?? null,
    helper: ev ? { pid: ev.helperLinuxPid, distro: ev.helperDistro, sourceId: ev.helperSourceId } : null,
    page,
  });
  note('raw canonical readbacks (application path, A)', raw.filter((r) => r.method === 'get_block_header_by_height' || r.method === 'get_last_block_header'));

  // ---- the opt-in share path's own evidence ---------------------------------------------------
  if (shareProfile) {
    const sessionFacts = [...pool.sessions].map((sess) => sess.stateFacts);
    const submits = raw.filter((r) => r.method === 'submit_block');
    const calcPows = raw.filter((r) => r.method === 'calc_pow');
    // TWO INDEPENDENT SOURCES, AND "UNKNOWN" IS A REAL ANSWER. A closed socket disposes the pool
    // session and its counters, so an empty session set is not zero shares; the bound frames the
    // page received are the second source. They must agree, or the count is unproven. The session
    // figure is the CUMULATIVE sharesAcceptedTotal -- a refresh rotation resets the per-window
    // sharesAccepted counter, so reconciling against it would undercount every window after the
    // first -- and the frame figure is the DISTINCT nonces across ALL windows, which the disjoint
    // nonce windows make a true cumulative count. classifyShareRunOutcome consumes this cumulative
    // proven count and nothing else.
    const boundFrames = refreshWindows !== null ? refreshFrames : serverFrames;
    const shareCount = reconcileShareCount({
      sessionsPresent: sessionFacts.length > 0,
      sessionShares: sessionFacts.reduce((n, f) => n + (f.sharesAcceptedTotal ?? 0), 0),
      frameShareNonces: boundFrames.shares.map((f) => f.nonce),
      framesCaptured: boundFrames.captured && !boundFrames.truncated,
    });
    // Every frame in this list already passed the five-field binding check against its own window;
    // the first is this run's.
    const blockFrame = boundFrames.blocks[0] ?? null;
    const daemonCalcPowHash = calcPows.length === 1 ? daemonPowHashFromRaw(calcPows[0]) : null;
    const agreement = classifyBrowserAgreement({
      pageNonce: page.foundNonce,
      submittedNonce: blockFrame?.nonce ?? null,
      pageHash: page.browserHash,
      serverWasmHash: sim.lastHashes.serverWasmHex,
      nativeHash: sim.lastHashes.nativeHelperHex,
      daemonHash: daemonCalcPowHash,
    });
    // Counts establish that one calc_pow and one submit_block occurred. This separately proves that
    // their exact serialized JSON request bodies carried THIS retained template with THIS accepted
    // nonce. A no-block observation records the negative result but does not consume it as a gate.
    const acceptedRpcRequestBodies = classifyAcceptedRpcRequestBodies({
      templateFacts: sim.templateFacts,
      nonce: blockFrame?.nonce ?? null,
      calcRecord: calcPows.length === 1 ? calcPows[0] : null,
      submitRecord: submits.length === 1 ? submits[0] : null,
    });
    note('SHARE RUN (server-side facts)', {
      ...shareRunModeFacts({
        probe: refreshHandoffProbe,
        legacyShareWork: sim.shareWork,
        legacyShareDifficulty: sim.shareDifficulty,
        fixedBlockDifficulty: PEER_TEST_FIXED_DIFFICULTY,
        profileShareWork: sim.profile?.shareWork,
        jobShareDifficulty: typeof sim.job.shareDifficulty === 'bigint' ? Number(sim.job.shareDifficulty) : null,
        jobBlockDifficulty: typeof sim.job.difficulty === 'bigint' ? Number(sim.job.difficulty) : null,
      }),
      shareTargetHexLE: sim.job.shareTargetHexLE ?? null,
      blockTargetHexLE: sim.job.targetHexLE,
      sessionFacts,
      sharesAccepted: shareCount.shares,
      shareCountSource: shareCount.source,
      shareCountDetail: shareCount.detail,
      boundServerFrames: serverFrames,
      ...(refreshWindows !== null ? { refreshBoundFrames: refreshFrames } : {}),
      candidatesVerified: sessionFacts.reduce((n, f) => n + (f.candidatesAdmittedThisBlock ?? 0), 0),
      invalidCandidates: sessionFacts.reduce((n, f) => n + (f.invalidCandidates ?? 0), 0),
      distinctNoncesAdmitted: sessionFacts.reduce((n, f) => n + (f.admittedNonces ?? 0), 0),
      serverWasmHashes: sim.counters.serverWasmHashes,
      nativeHelperHashes: sim.counters.nativeHelperHashes,
      daemonCalcPow: calcPows.length,
      daemonSubmitBlock: submits.length,
      rawEvidenceDropped: sim.rpcAudit.rawDropped,
      browserAgreement: agreement,
      acceptedRpcRequestBodies,
      attemptState: sim.attemptState,
      attemptReason: sim.attemptReason,
      note: 'an accepted share that is NOT a block costs the daemon nothing -- no calc_pow, no claim, '
        + 'no submit_block. A block-quality result is also a share by construction, and it DOES use '
        + 'one calc_pow and at most one submit_block, so a run with a block shows those alongside '
        + 'its accepted shares.',
    });
    // THE REFRESH RECORD, per window, alongside the share facts and never instead of them.
    let refreshRecord = null;
    if (refreshWindows !== null) {
      refreshRecord = refreshEvidence({
        requestedWindows: refreshWindows,
        windowRecords: sim.windowRecords,
        sessionFacts,
        verifierHistory: sim.verifierHistory,
        currentVerifier: sim.verifier,
        attemptState: sim.attemptState,
        attemptReason: sim.attemptReason,
        submitBlockCount: submits.length,
        calcPowCount: calcPows.length,
        cumulativeAttempts: parseCanonicalUintText(page.totalAttempts),
      });
      evidence.refresh = refreshRecord;
      note('SAME-HEIGHT WINDOW REFRESH (server-side facts)', refreshRecord);
    }
    const bWrite = Object.keys(sim.peer.rpcCounts).filter((m) => ['submit_block', 'calc_pow', 'get_block_template'].includes(m));
    let propagation = null;
    if (sim.attemptState === SIM_ATTEMPT_STATES.TERMINAL_COMPLETE && blockFrame !== null) {
      note('propagation wait begins', { at: now(), expectedBlockId: blockFrame.blockId });
      // THE EXACT BLOCK, not merely a converged tip: B must show the id the server announced.
      propagation = await sim.peer.awaitPropagation({ expectedBlockId: blockFrame.blockId });
      note('PROPAGATION (read-only on B)', propagation);
    } else if (sim.attemptState === SIM_ATTEMPT_STATES.TERMINAL_COMPLETE) {
      note('propagation not attempted', 'the attempt completed but no bound block_accepted frame was captured, '
        + 'so there is no block id to require of daemon B');
    }
    const shareOutcome = classifyShareRunOutcome({
      attemptState: sim.attemptState,
      attemptReason: sim.attemptReason,
      completeState: SIM_ATTEMPT_STATES.TERMINAL_COMPLETE,
      shares: shareCount.shares,
      shareSource: shareCount.source,
      submitBlockCount: submits.length,
      calcPowCount: calcPows.length,
      rawDropped: sim.rpcAudit.rawDropped,
      propagation,
      bWriteMethods: bWrite,
      agreement,
      rpcRequestBodies: acceptedRpcRequestBodies,
      blockIdFromFrame: blockFrame?.blockId ?? null,
      pageBlockId: /^[0-9a-f]{64}$/.test(String(page.blockId ?? '')) ? page.blockId : null,
    });
    const rawWindowOneFacts = Array.isArray(sessionFacts[0]?.windowOutcomes)
      ? (sessionFacts[0].windowOutcomes.find((item) => item?.window === 1) ?? null)
      : null;
    const probeWindowOneFacts = rawWindowOneFacts === null ? null : {
      window: rawWindowOneFacts.window ?? null,
      outcome: rawWindowOneFacts.outcome ?? null,
      sharesAccepted: Number.isSafeInteger(rawWindowOneFacts.sharesAccepted)
        ? rawWindowOneFacts.sharesAccepted
        : null,
      candidatesAdmitted: Number.isSafeInteger(rawWindowOneFacts.candidatesAdmitted)
        ? rawWindowOneFacts.candidatesAdmitted
        : null,
      invalidCandidates: Number.isSafeInteger(rawWindowOneFacts.invalidCandidates)
        ? rawWindowOneFacts.invalidCandidates
        : null,
    };
    const handoffProbeOutcome = classifyRefreshHandoffProbeOutcome({
      enabled: refreshHandoffProbe,
      refreshRecord,
      frames: refreshFrames,
      shareOutcome,
      expectedShareDifficulty: HANDOFF_PROBE_SHARE_DIFFICULTY,
      expectedBlockDifficulty: PEER_TEST_FIXED_DIFFICULTY,
      expectedShareTargetHexLE: HANDOFF_PROBE_SHARE_TARGET_HEX_LE,
      expectedBlockTargetHexLE: PRIVATE_BLOCK_TARGET_HEX_LE,
      expectedNonceRange: REAL_SEARCH_LIMITS.maxAttempts,
      windowOneFacts: probeWindowOneFacts,
      expectedShareCap: REAL_SHARE_LIMITS.maxSharesPerJob,
      provenShareCount: shareCount.shares,
      pageAcceptedShares: parseCanonicalUintText(page.acceptedShares),
      agreement,
    });
    const finalization = finalizeShareRun({
      probe: refreshHandoffProbe,
      shareOutcome,
      handoffProbeOutcome,
      okCode: EXIT_CODES.OK,
      failedCode: EXIT_CODES.FAILED,
    });
    const finalShareOutcome = finalization.finalOutcome;
    note('RPC counts (total, setup and audit included)', { A: sim.rpcAudit.counts, B: sim.peer.rpcCounts });
    note('daemon B received no RPC block delivery', { bMethodsSent: Object.keys(sim.peer.rpcCounts), bWriteMethodsSent: bWrite });
    note('browser runtime/console/network observations', browserEvents);
    // THE TERMINAL PICTURE, TAKEN WHILE THE BROWSER IS STILL ALIVE. Cleanup closes it moments later.
    const terminalShot = await captureScreenshot('terminal');
    if (!terminalShot.ok) {
      note('INCOMPLETE SCREENSHOT EVIDENCE', 'the terminal screenshot could not be written: '
        + `${terminalShot.reason}. The run is NOT repeated for a picture; the JSON evidence and the `
        + 'transcript are the record.');
    }
    for (const [label, value] of shareRunProbeEvents({
      probe: refreshHandoffProbe, shareOutcome, handoffProbeOutcome,
    })) note(label, value);
    note('OUTCOME', finalShareOutcome);
    if (shareOutcome.startsWith('BOUNDED_OBSERVATION_')) {
      const boundedMeaning = refreshHandoffProbe
        ? 'a bounded no-block observation: both issued windows stayed within the frozen bounds and '
          + 'whatever shares the server verified are recorded. It is NOT a claim that a block was mined. '
          + 'Probe exit 0, if awarded, proves only that the window-1 to window-2 handoff was exercised.'
        : 'a bounded observation: the window was searched under the frozen bounds and whatever shares '
          + 'the server verified are recorded. It is NOT a claim that a block was mined, and exit 1 here '
          + 'means "no block claim", not malfunction.';
      note('what this outcome does and does not claim', boundedMeaning);
    }
    if (refreshHandoffProbe) {
      evidence.handoffProbeRuntime = {
        windowFacts: refreshRecord?.windows ?? null,
        windowOneFacts: probeWindowOneFacts,
        windowsIssued: refreshRecord?.windowsIssued ?? null,
        boundWindowTwoResult: refreshFrames.shares.some((f) => f.window === 2)
          || refreshFrames.blocks.some((f) => f.window === 2),
        bindingCount: refreshFrames.bindings.length,
      };
    }
    Object.assign(evidence, finalization.evidenceFields);
    evidence.outcome = finalShareOutcome;
    return finalization.exitCode;
  }

  let outcome;
  if (sim.attemptState === SIM_ATTEMPT_STATES.TERMINAL_COMPLETE) {
    note('propagation wait begins', now());
    const p = await sim.peer.awaitPropagation();
    note('PROPAGATION (read-only on B)', p);
    outcome = p.converged ? 'BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B' : p.reason;
  } else if (sim.attemptReason === 'search_bound_reached') {
    outcome = 'BOUNDED_NO_SOLUTION';
  } else {
    outcome = `FAILED:${sim.attemptReason}`;
  }
  note('RPC counts (total, setup and audit included)', { A: sim.rpcAudit.counts, B: sim.peer.rpcCounts });
  note('daemon B received no RPC block delivery', {
    bMethodsSent: Object.keys(sim.peer.rpcCounts),
    bWriteMethodsSent: Object.keys(sim.peer.rpcCounts).filter((m) => ['submit_block', 'calc_pow', 'get_block_template'].includes(m)),
  });
  note('browser runtime/console/network observations', browserEvents);
  note('OUTCOME', outcome);
  evidence.outcome = outcome;
  return outcome === 'BLOCK_ACCEPTED_BY_A_AND_RECEIVED_BY_B' ? EXIT_CODES.OK : EXIT_CODES.FAILED;
}, {
  beforePoolClose: stopBrowser,
  afterPoolClose: observeRelease,
  onBodyError: (err) => {
    note('RUN ERROR', bounded(err?.message, 400));
    if (err?.code) note('RUN ERROR code', bounded(err.code, 80));
    if (err?.retainedResources) note('retained after startup failure', err.retainedResources.map((r) => r.label));
    if (evidence.outcome === null) evidence.outcome = `FAILED:${bounded(err?.code ?? 'run_error', 80)}`;
  },
});
