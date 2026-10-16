// Launcher and strict protocol client for meepow-v2-helper, the long-lived native frozen-v2
// hashing service the pool cross-checks its WebAssembly result against.
//
// OWNERSHIP IS THE HARD PART, not the hashing. On Windows the helper runs inside WSL, so this
// module owns THREE things: the Node ChildProcess for wsl.exe, the Linux PID the helper reports in
// its HELLO line, and every short-lived probe/signal process it spawns to inspect that PID.
// Killing wsl.exe is not by itself proof that the Linux process died, so escalation observes
// /proc/<pid>/cmdline and requires an exact argv match against the path we launched and the random
// startup token before signalling -- and signals only that exact PID, in the PARENT-PINNED
// distribution. There is no kill-by-name, no wildcard and no `wsl --shutdown` anywhere here.
//
// OBSERVATION IS FOUR-STATE, AND FAILURE IS NOT ABSENCE. "I could not look" is not "it is gone".
// A probe that fails to spawn, times out, or comes back unrecognisable yields UNKNOWN -- which
// RETAINS ownership and makes close() fail honestly.
//
// ABSENCE MUST BE ESTABLISHED POSITIVELY, NEVER INFERRED FROM A FAILED READ. `cat boot_id
// /proc/<pid>/cmdline` returns byte-identical stdout and the same nonzero exit whether the entry
// is MISSING or merely UNREADABLE, and stderr wording is not a portable discriminator. So an empty
// cmdline is not a verdict: a second, separate probe (`ls -1 -d -- /proc/self /proc/<pid>`) asks
// the unambiguous question, with the probe's own /proc entry as the control operand. Only "the
// listing came back, contained its control, and did not contain our pid" -- or an ANCHORED boot-id
// change -- authorises CONFIRMED_ABSENT.
//
// A VALUE THE CHILD REPORTS ABOUT ITSELF IS NOT EVIDENCE ABOUT ITS OWN FATE. The launch boot id
// arrives in HELLO from the process it will later be used to judge, so a WSL launch requires a
// canonical distribution and a canonical UUID boot id and corroborates that boot id once, through
// a parent-owned observation in the named distribution, before it may support any absence claim.
//
// A DEADLINE IS NOT A REAPING. An expired observation deadline and a confirmed-dead probe are two
// different facts. A timed-out probe is asked to terminate, then JOINED, then escalated -- and it
// leaves the ownership set only on a confirmed exit, never because kill() was called or returned
// true. A probe that cannot be confirmed gone fails shutdown and stays reachable by retry.
//
// A GRACEFUL CLOSE IS QUIT -> exactly one canonical BYE -> exit 0, with no signal. Anything else --
// exit before BYE, no BYE, nonzero exit, signal exit, a duplicate or decorated BYE -- is reported
// distinctly. Physical release is tracked SEPARATELY from protocol health: a process that is
// positively gone releases the handle, and the anomaly is still raised so nobody can read a
// resolved close as a healthy goodbye.
//
// EVERYTHING IS ARGUMENT-NATIVE. Every child is spawned with an argv array and shell:false. No
// path, token, request id, nonce, pid or job field is ever interpolated into a shell string, and
// no shell is invoked on either side of the WSL boundary.
//
// FAIL CLOSED, AND TELL SOMEONE. Any protocol violation, timeout, unexpected exit, malformed or
// unsolicited output, wrong request id or oversized line is a fatal fault: pending requests reject,
// the helper latches unhealthy, and `onFault` fires IMMEDIATELY -- it does not wait for someone to
// happen to be awaiting a hash. A helper that dies while idle must stop the pool now, not at the
// next submission.
//
// CANCELLATION IS NOT A FAULT. Deliberate shutdown settles outstanding work through a cancellation
// error that is explicitly flagged and never reaches `onFault`. Ordinary close must not be
// reported as a verifier failure, and the QUIT/BYE exchange must still be validated afterwards --
// which is why cancelling outstanding work and latching a fatal fault are two separate operations.

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { platform } from 'node:process';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(__dirname, '../..');

/** Where scripts/build-native-helper.sh puts the (gitignored) executable. */
export const HELPER_BUILD_PATH = resolve(REPO_ROOT, 'meepow/build/native-helper/meepow-v2-helper');

// v2 added distro / bootid / sourceid to HELLO. The parent refuses a version it does not know.
export const HELPER_PROTOCOL_VERSION = 2;
export const HELPER_ALGO_VERSION = 2;
export const HELPER_PARAM_SET_ID = 60;

// The frozen-v2 allocation, exactly. READY is checked against these rather than merely parsed:
// a helper that reports a different dataset or scratchpad size is not running the algorithm this
// pool cross-checks against, whatever it says its version is.
export const HELPER_DATASET_BYTES = 33_554_432; // 32 MiB
export const HELPER_SCRATCH_BYTES = 8_388_608;  // 8 MiB

// Bounds. Every one of these is a fail-closed limit, not a hint. Byte limits are BYTES: a helper
// that emits multi-byte UTF-8 must not be able to exceed the advertised memory bound because the
// count was done in UTF-16 code units.
export const HELPER_LIMITS = Object.freeze({
  maxLineBytes: 8192,
  maxStderrBytes: 8192, // ring buffer; a flooding helper cannot grow our memory
  startupTimeoutMs: 15_000,
  initTimeoutMs: 60_000, // the 32 MiB dataset build is ~350 ms native, but a cold FS can be slow
  requestTimeoutMs: 30_000,
  quitTimeoutMs: 5_000,
  signalTimeoutMs: 5_000,
  probeTimeoutMs: 5_000,
  // How long to wait for a probe to actually EXIT after we asked it to. Deliberately separate
  // from probeTimeoutMs: "the observation deadline expired" and "the probe process is confirmed
  // gone" are two different facts, and collapsing them is how a live child got dropped.
  probeReapMs: 3_000,
  // How long to wait, AFTER the process has terminated, for its stdio to actually finish. The
  // ChildProcess 'exit' event does not mean the transcript is complete: bytes already written can
  // still be delivered afterwards, and the ChildProcess 'close' event is what says there are no
  // more. Judging the transcript at 'exit' both missed a real BYE and missed a malformed one.
  stdioDrainMs: 2_000,
  // Bound on the parent-owned discovery of the default WSL distribution.
  distroLookupMs: 5_000,
});

/**
 * A WSL distribution name, as ONE bounded argv value -- and SPACE-FREE.
 *
 * Never interpolated into a command string: it is passed as a single element of an argv array to a
 * `shell: false` spawn, so this is a well-formedness bound, not an escaping scheme.
 *
 * SPACES ARE REJECTED BEFORE THE SPAWN, deliberately. The name has to survive a round trip the
 * argv does not control: the helper echoes $WSL_DISTRO_NAME back in HELLO, whose grammar is
 * space-separated with exact arity, and the C++ hello_field() turns any value containing a space
 * into "-". So a distribution named "Ubuntu 22.04" would launch correctly and then FAIL
 * corroboration every time. Refusing it up front, with a message that says why, beats launching a
 * child that cannot possibly be verified. Escaping it, or a protocol v3 that quotes fields, is out
 * of scope here: this development helper supports space-free WSL distribution names only.
 */
export const WSL_DISTRO_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;

export class WslDistroError extends Error {
  constructor(message) {
    super(message);
    this.name = 'WslDistroError';
  }
}

/** What a single observation of the Linux process actually established. */
export const OBSERVATION = Object.freeze({
  PRESENT_MATCH: 'CONFIRMED_PRESENT_MATCH',
  PRESENT_MISMATCH: 'CONFIRMED_PRESENT_MISMATCH',
  ABSENT: 'CONFIRMED_ABSENT',
  UNKNOWN: 'INSPECTION_FAILED',
});

export class HelperFaultError extends Error {
  constructor(message, detail = {}) {
    super(message);
    this.name = 'HelperFaultError';
    this.detail = detail;
    // A DELIBERATE CANCELLATION, not a fault to report to anyone. Shutdown settles every
    // outstanding request through this class, and a caller must be able to tell "we asked this to
    // stop" from "the child died on us" -- one is silence, the other is a latched pool fault.
    this.cancelled = detail.cancelled === true;
  }
}

export class HelperMissingError extends Error {
  constructor(path) {
    super(
      `native verifier not built: ${path}\n`
      + 'The pool requires the native frozen-v2 helper so it can cross-check its own WebAssembly\n'
      + 'result. It is a BUILD ARTIFACT and is never committed. Build it with:\n'
      + '  npm run build:native-helper          (from the repository root)\n'
      + 'The pool does not build it for you and will not fall back to Wasm-only verification.',
    );
    this.name = 'HelperMissingError';
    this.path = path;
  }
}

/** Windows path -> WSL path. Only used for the /mnt/<drive> form this checkout lives on. */
export function toWslPath(winPath) {
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(winPath);
  if (!m) throw new HelperFaultError(`cannot convert to a WSL path: ${winPath}`);
  return `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, '/')}`;
}

/**
 * The exact command that launches the helper. Returned as { file, args } so callers can log it and
 * so tests can assert there is no shell anywhere.
 */
export function helperLaunchCommand({
  helperPath = HELPER_BUILD_PATH, token, useWsl = platform === 'win32', wslDistro = null,
}) {
  if (!useWsl) return { file: helperPath, args: [token] };
  // EXPLICIT `-d`. Launching with default routing and then letting HELLO name the distribution is
  // circular: the child chooses where the parent looks for it. On this very host Ubuntu and
  // docker-desktop report the SAME boot UUID with DIFFERENT pid namespaces, so a wrong
  // child-reported distribution passes the boot-id anchor and then reports a live helper as
  // confirmed absent. The parent decides, before the child exists.
  if (!wslDistro || !WSL_DISTRO_RE.test(wslDistro)) {
    throw new WslDistroError(
      `a WSL launch requires a parent-pinned distribution; got ${JSON.stringify(wslDistro)}`,
    );
  }
  return { file: 'wsl.exe', args: ['-d', wslDistro, '--exec', toWslPath(helperPath), token] };
}

/**
 * Discover the default WSL distribution, in a machine-shaped way, before anything is launched.
 *
 * Reads HKCU\...\Lxss: `DefaultDistribution` is a GUID, and that GUID's subkey carries
 * `DistributionName`. Both are registry values, not console prose -- unlike `wsl --status` or the
 * `wsl -l -v` table, whose headers are localized. Two bounded, argv-native `reg.exe` calls; no
 * shell, and nothing interpolated into a command string.
 *
 * Fails closed. If the key is missing, the value is absent, the output is ambiguous, or the name
 * does not validate, this throws rather than guessing -- and the caller refuses to start.
 */
export async function resolveDefaultWslDistro({ runReg = null, timeoutMs = HELPER_LIMITS.distroLookupMs } = {}) {
  const LXSS = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss';
  const run = runReg ?? ((args) => new Promise((resolvePromise) => {
    let settled = false;
    const d = deadline(timeoutMs);
    const done = (r) => { if (!settled) { settled = true; d.cancel(); resolvePromise(r); } };
    let child;
    try {
      child = spawn('reg.exe', args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, shell: false });
    } catch (err) {
      done({ ok: false, stdout: '', reason: `reg.exe could not be started: ${err.message}` });
      return;
    }
    let out = '';
    child.stdout.setEncoding('latin1');
    child.stdout.on('data', (c) => { out = (out + c).slice(0, 64 * 1024); });
    child.on('error', (err) => done({ ok: false, stdout: out, reason: `reg.exe failed: ${err.message}` }));
    child.on('close', (code) => done({ ok: code === 0, stdout: out, reason: code === 0 ? null : `reg.exe exited ${code}` }));
    d.promise.then(() => {
      try { child.kill(); } catch { /* already gone */ }
      done({ ok: false, stdout: out, reason: `reg.exe timed out after ${timeoutMs} ms` });
    });
  }));

  /** The single REG_SZ value named `name`, or null when it is absent or ambiguous. */
  const readValue = (text, name) => {
    const hits = [];
    for (const raw of String(text).split('\n')) {
      const m = new RegExp(`^\\s+${name}\\s+REG_SZ\\s+(.+?)\\s*$`).exec(raw.replace(/\r$/, ''));
      if (m) hits.push(m[1]);
    }
    return hits.length === 1 ? hits[0] : null;
  };

  const top = await run(['query', LXSS, '/v', 'DefaultDistribution']);
  if (!top.ok) throw new WslDistroError(`cannot read the default WSL distribution: ${top.reason}`);
  const guid = readValue(top.stdout, 'DefaultDistribution');
  // The CANONICAL braced 8-4-4-4-12 shape. `[0-9a-fA-F-]{36}` also accepted misplaced or repeated
  // hyphens, so a value that is not a GUID at all could be pasted straight into the next key path.
  if (guid === null || !/^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$/.test(guid)) {
    throw new WslDistroError(
      'the default WSL distribution registry value is missing, ambiguous, or not a canonical GUID',
    );
  }
  const sub = await run(['query', `${LXSS}\\${guid}`, '/v', 'DistributionName']);
  if (!sub.ok) throw new WslDistroError(`cannot read the default WSL distribution name: ${sub.reason}`);
  const name = readValue(sub.stdout, 'DistributionName');
  if (name === null) throw new WslDistroError('the default WSL distribution name is missing or ambiguous');
  if (!WSL_DISTRO_RE.test(name)) {
    throw new WslDistroError(`the default WSL distribution name is not a usable argv value: ${JSON.stringify(name)}`);
  }
  return name;
}

/**
 * A timeout that can be cancelled. Every deadline in this module uses one.
 *
 * A `Promise.race([work, sleep(ms)])` leaves the loser scheduled: the timer keeps the event loop
 * referenced long after the operation finished, so a pool that closed in 2 ms could still hold the
 * process open for the full timeout. Losing timers are cancelled here, always, in a finally.
 */
function deadline(ms) {
  let timer = null;
  let fired = false;
  const promise = new Promise((resolvePromise) => {
    timer = setTimeout(() => { fired = true; timer = null; resolvePromise('timeout'); }, ms);
  });
  return {
    promise,
    get fired() { return fired; },
    cancel() { if (timer !== null) { clearTimeout(timer); timer = null; } },
  };
}

/** Race `work` against a bounded deadline, and never leave the losing timer scheduled. */
async function withDeadline(work, ms) {
  const d = deadline(ms);
  try {
    return await Promise.race([work, d.promise]);
  } finally {
    d.cancel();
  }
}

/**
 * Canonical unsigned decimal. This is the whole numeric grammar of the protocol.
 *
 * Rejects "1e0", "01", "+1", "-1", "1.0", "NaN", "Infinity", "0x10", whitespace and anything past
 * the safe-integer range. `Number()` accepts most of those, which is exactly how "READY 01 NaN -1"
 * became a healthy helper reporting a NaN dataset size.
 */
const CANONICAL_UINT = /^(0|[1-9][0-9]*)$/;
function parseCanonicalUint(text, { min = 0 } = {}) {
  if (typeof text !== 'string' || !CANONICAL_UINT.test(text)) return null;
  if (text.length > 16) return null; // beyond Number.MAX_SAFE_INTEGER's digit count
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value < min) return null;
  return value;
}

/**
 * A BOUNDED description of leftover stdout bytes. Never the raw fragment: a child that ends
 * mid-line could otherwise write anything it liked into a diagnostic the operator will read.
 */
function describeFragment(buf, max = 32) {
  const shown = buf.subarray(0, max);
  let text = '';
  for (const byte of shown) {
    text += (byte >= 0x20 && byte <= 0x7e) ? String.fromCharCode(byte) : `\\x${byte.toString(16).padStart(2, '0')}`;
  }
  return `"${text}"${buf.length > max ? ` (+${buf.length - max} more)` : ''}`;
}

/** A HELLO identity field: non-empty printable ASCII with no spaces, or the explicit "-". */
const HELLO_FIELD = /^[\x21-\x7e]{1,128}$/; // eslint-disable-line no-control-regex

/**
 * Start the helper and complete its HELLO handshake.
 *
 * OWNERSHIP BEGINS AT SPAWN, NOT AT HELLO. If the handshake fails this still tries to reap the
 * child, and then attaches the handle to the thrown error (`err.helper`, `err.releaseConfirmed`)
 * rather than dropping it. A factory that rejects while a child's fate is unknown has lost the
 * only reference to a process nobody will ever clean up.
 *
 * @param {object} o
 * @param {string} [o.helperPath]  the executable (a test may point this at a fake)
 * @param {(err:Error) => void} [o.onFault]  called ONCE, immediately, on the first non-cancellation
 *                                           fault -- including one that happens while idle
 * @param {(cmd:{file:string,args:string[]}) => import('node:child_process').ChildProcess} [o.spawnFn]
 */
export async function startNativeHelper({
  helperPath = HELPER_BUILD_PATH,
  limits = {},
  spawnFn = null,
  useWsl = platform === 'win32',
  onFault = () => {},
  /**
   * Test seam for the WSL probe/signal channel: (args, timeoutMs) -> the same
   * { ok, code, stdout, reason } shape runWsl produces. It exists so the four observation states
   * -- and the failures that must NOT be read as absence -- can be exercised deterministically.
   * The REAL WSL path is exercised separately, against the real helper, in dual_verifier.test.mjs.
   */
  wslRunner = null,
  /**
   * Test seam for the PROBE CHILD ITSELF: (args) -> a ChildProcess-shaped handle. `wslRunner`
   * replaces the whole probe and therefore cannot exercise ownership or reaping; this one keeps
   * the real runWsl body -- including the timeout, the termination request and the exit join --
   * and only substitutes the process, which is the part a test cannot make misbehave on cue.
   */
  probeSpawnFn = null,
  /**
   * THE PARENT-PINNED WSL DISTRIBUTION. Authoritative, chosen before the child exists, and used
   * for the launch AND for every later boot-id, /proc, existence and signal operation. Never
   * supplied by the child. When omitted, it is discovered from the registry below.
   */
  wslDistro = null,
  /** Test seam for that discovery only. Cannot redirect anything once a distribution is pinned. */
  resolveWslDistro = resolveDefaultWslDistro,
  signal,
} = {}) {
  const cfg = { ...HELPER_LIMITS, ...limits };
  if (!spawnFn && !existsSync(helperPath)) throw new HelperMissingError(helperPath);
  if (signal?.aborted) throw new HelperFaultError('helper startup aborted before launch', { cancelled: true });

  // ---------------------------------------------------------------- pin the distribution FIRST
  //
  // Before the token, before the spawn, before anything the child could influence. A discovery
  // that fails, or a name that does not validate, refuses the launch rather than falling back to
  // default routing -- default routing is what made the child's own claim authoritative.
  let pinnedDistro = null;
  if (useWsl) {
    pinnedDistro = wslDistro ?? await resolveWslDistro();
    if (typeof pinnedDistro !== 'string' || !WSL_DISTRO_RE.test(pinnedDistro)) {
      throw new WslDistroError(
        `the WSL distribution to launch in is not a usable argv value: ${JSON.stringify(pinnedDistro)}`,
      );
    }
  }

  // THE LAUNCH FENCE. The abort check above happened BEFORE awaiting discovery, and
  // addEventListener is not retroactive -- so a shutdown that won the race while the registry
  // lookup was still pending was simply lost, and a helper was spawned into a pool that had
  // already closed. Every awaited pre-spawn step is followed by a recheck, immediately before the
  // only statement that can create a process.
  if (signal?.aborted) {
    throw new HelperFaultError('helper startup aborted before launch', { cancelled: true });
  }

  // The parent chooses the token. The helper echoes it with its Linux PID, which is how shutdown
  // later proves "the process at this PID is still the child I launched".
  const token = randomBytes(8).toString('hex');
  const command = helperLaunchCommand({ helperPath, token, useWsl, wslDistro: pinnedDistro });
  // The exact argv the Linux process must still show. Position matters: argv[0] is the executable
  // we named and argv[1] is the token, and nothing else may be there.
  const expectedLinuxArgv = useWsl ? [toWslPath(helperPath), token] : [helperPath, token];

  // THE LIFETIME ABORT LISTENER IS ATTACHED BEFORE THE SPAWN, not after the handshake. It cannot
  // reference `helper` yet, so it sets a flag and calls a late-bound hook; the hook is rebound to
  // helper.beginClose() the moment the handle exists, and the flag is re-read there. That closes
  // the seam where an abort arriving during spawn -- including a SYNCHRONOUS abort from inside an
  // injected spawnFn -- had no listener to reach and was dropped.
  let abortedDuringStartup = false;
  let onAbortHook = () => { abortedDuringStartup = true; };
  const onAbort = () => { onAbortHook(); };
  if (signal) signal.addEventListener('abort', onAbort, { once: true });
  const detachAbort = () => { if (signal) signal.removeEventListener('abort', onAbort); };

  let child;
  try {
    child = (spawnFn ?? ((cmd) => spawn(cmd.file, cmd.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      shell: false, // never a shell: nothing here may be re-parsed
    })))(command);
  } catch (err) {
    detachAbort();
    throw err;
  }

  // ---------------------------------------------------------------- state

  let fault = null;              // latched: once set, this helper never answers again
  let cancellation = null;       // deliberate shutdown; NOT a fault, never reported as one
  let faultNotified = false;
  let helloSeen = false;
  let linuxPid = null;
  // The distribution HELLO claimed. CORROBORATION ONLY -- it must equal `pinnedDistro`, and it
  // never chooses where a probe goes. `pinnedDistro` is the only value wslArgs() ever uses.
  let helloDistro = null;
  let linuxBootId = null;        // pinned from HELLO; changes when the WSL VM restarts
  // Whether that pinned boot id was corroborated by a PARENT-OWNED observation in the reported
  // distribution. Until it is, a later boot-id change is just the child's own word against
  // itself, and must never authorise a clean-release claim.
  let bootIdAnchored = false;
  let sourceId = null;
  let closing = false;
  let released = false;
  let exited = false;
  let exitInfo = null;
  let quitAcknowledged = false;
  // Whether a QUIT was ever actually written. A canonical shutdown is a REQUESTED exchange that
  // completed; a child that died on its own before anyone asked it to stop did not have one.
  let quitRequested = false;
  let nextId = 1;
  let stdoutBuf = Buffer.alloc(0);
  let stderrRing = Buffer.alloc(0);
  const pending = new Map();     // request id -> { resolve, reject, cancelTimer, kind }
  // Replies parsed out of the CURRENT chunk but not yet delivered. See the acceptance barrier in
  // the stdout handler.
  let settling = [];
  const counters = { selfTestHashes: 0, shareHashes: 0, initCalls: 0 };
  // Short-lived probe/signal children. Owned and reaped like everything else. Each entry is a
  // RECORD, not a bare ChildProcess: ownership is released on a confirmed exit, never on a kill.
  const probes = new Set();

  const exitPromise = new Promise((resolveExit) => {
    child.once('exit', (code, sig) => {
      exited = true;
      exitInfo = { code, signal: sig };
      resolveExit(exitInfo);
    });
  });

  // THE STDIO DRAIN WITNESS, which is NOT the same fact as process exit.
  //
  // Node's ChildProcess emits 'exit' when the process is gone and 'close' when its stdio streams
  // have all ended -- and bytes the child already wrote can still be delivered in between. Judging
  // the transcript at 'exit' therefore both MISSED a real BYE that was still in flight (slandering
  // a well-behaved helper) and MISSED a malformed one (hiding a real protocol violation).
  //
  // Named for the stream event, deliberately: `stdioClosed` is the ChildProcess 'close' EVENT, and
  // has nothing to do with this module's public close() METHOD or its `closed` getter.
  let stdioClosed = false;
  let onStdioClose = null;
  const stdioClosedPromise = new Promise((resolveClosed) => {
    onStdioClose = () => { stdioClosed = true; resolveClosed(true); };
    child.once('close', onStdioClose);
  });

  /**
   * Release the PARENT'S OWN handles on this child, and say whether that succeeded.
   *
   * Process exit says the child is gone. It says nothing about the pipes and listeners on this
   * side, which is why a drain timeout used to report `physicalReleaseConfirmed: true` while
   * stdout and stderr each still carried a live 'data' listener, none of the three pipes was
   * destroyed, and a 'close' listener remained attached.
   *
   * Removes ONLY the listeners this module installed, and destroys ONLY these three parent-owned
   * streams. Nothing here signals, kills or touches any process. Returns the reasons it could not
   * finish; an empty array is the only thing that lets a caller claim the local side is released.
   *
   * Detaching the stdout listener is also what makes the verdict final: once it is gone, a byte
   * arriving after the decision cannot be parsed, so it cannot mutate a result already returned.
   */
  function releaseLocalStdio() {
    const stuck = [];
    const off = (target, event, fn) => {
      if (!target || !fn) return;
      try { (target.off ?? target.removeListener).call(target, event, fn); } catch { /* already gone */ }
    };
    off(child.stdout, 'data', onStdoutData);
    off(child.stderr, 'data', onStderrData);
    off(child, 'error', onChildError);
    off(child, 'close', onStdioClose);
    for (const [name, stream] of [['stdin', child.stdin], ['stdout', child.stdout], ['stderr', child.stderr]]) {
      if (!stream) continue;
      try {
        if (stream.destroyed !== true) stream.destroy?.();
      } catch (err) {
        stuck.push(`${name}: destroy threw ${err.message}`);
        continue;
      }
      // A stream with no destroy()/destroyed at all (a minimal fake, or an exotic stdio option)
      // cannot be positively witnessed, and "cannot witness" is never "released".
      if (stream.destroyed !== true) stuck.push(`${name} could not be confirmed destroyed`);
    }
    return stuck;
  }

  function notifyFault(err) {
    if (faultNotified || err?.cancelled) return;
    faultNotified = true;
    try {
      onFault(err);
    } catch {
      // A fault notifier that throws must not prevent the latch itself.
    }
  }

  /**
   * Settle every outstanding and undelivered request. Used by BOTH cancellation and the fatal
   * latch; on its own it says nothing about health. Keeping this separate from latch() is what
   * lets close() cancel in-flight hashing and then still register and validate the QUIT/BYE
   * exchange, instead of poisoning the helper before it has said goodbye.
   */
  function settleOutstanding(err, { keepBye = false } = {}) {
    for (const [key, entry] of [...pending]) {
      if (keepBye && key === 'bye') {
        // THE GOODBYE OUTLIVES THE PROCESS. Its deadline does not: waiting for an answer from a
        // process that has already exited is meaningless, and letting that timer fire would latch
        // a spurious fatal fault during the drain below. The drain barrier bounds the wait now.
        entry.cancelTimer();
        continue;
      }
      entry.cancelTimer();
      entry.reject(err);
      pending.delete(key);
    }
    const undelivered = settling;
    settling = keepBye ? undelivered.filter((x) => x.entry.kind === 'quit') : [];
    for (const x of undelivered) {
      if (keepBye && x.entry.kind === 'quit') continue;
      x.entry.reject(err);
    }
  }

  /** Latch a FATAL fault: irreversible, and reported to the owner immediately. */
  function latch(message, detail = {}) {
    const err = fault ?? new HelperFaultError(message, {
      ...detail,
      stderr: stderrRing.subarray(-1024).toString('utf8'),
    });
    if (!fault) {
      fault = err;
      notifyFault(err);
    }
    settleOutstanding(err);
    return err;
  }

  // NAMED, so every listener this module installs can later be removed again -- and ONLY the ones
  // it installed. "The process exited" and "the parent is no longer holding its pipes" are two
  // different facts, and a shutdown that claims full release must be able to establish both.
  const onStderrData = (chunk) => {
    // Bounded in BYTES. Buffer.concat + subarray keeps the advertised memory bound honest for
    // multi-byte output, which a string ring measured in UTF-16 units does not.
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
    stderrRing = Buffer.concat([stderrRing, buf]);
    if (stderrRing.length > cfg.maxStderrBytes) {
      stderrRing = stderrRing.subarray(stderrRing.length - cfg.maxStderrBytes);
    }
  };
  const onChildError = (err) => latch(`helper process error: ${err.message}`);
  child.stderr.on('data', onStderrData);
  child.on('error', onChildError);
  child.once('exit', (code, sig) => {
    if (closing) {
      // Expected. Not a health fault -- but the exit status is remembered, and close() reports an
      // abnormal one rather than hiding a real crash behind "we were shutting down anyway".
      //
      // THE BYE WAITER IS KEPT. Process exit is not the end of the transcript: a final BYE the
      // child already wrote can still be delivered before its stdio closes. Tearing the waiter
      // down here made handleLine call that legitimate goodbye "unsolicited" -- and made a
      // DECORATED one unreachable, so a real protocol violation went unreported.
      settleOutstanding(
        cancellation ?? new HelperFaultError('helper exited during shutdown', { cancelled: true }),
        { keepBye: true },
      );
      return;
    }
    latch(`helper exited unexpectedly (code=${code}, signal=${sig})`, { code, signal: sig });
  });

  const onStdoutData = (chunk) => {
    if (fault) return;
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
    stdoutBuf = stdoutBuf.length === 0 ? buf : Buffer.concat([stdoutBuf, buf]);
    if (stdoutBuf.length > cfg.maxLineBytes) {
      latch('helper wrote an oversized line', { bytes: stdoutBuf.length });
      return;
    }
    for (;;) {
      const nl = stdoutBuf.indexOf(0x0a);
      if (nl < 0) break;
      let lineBuf = stdoutBuf.subarray(0, nl);
      if (lineBuf.length > 0 && lineBuf[lineBuf.length - 1] === 0x0d) {
        lineBuf = lineBuf.subarray(0, lineBuf.length - 1); // tolerate CRLF
      }
      stdoutBuf = stdoutBuf.subarray(nl + 1);
      handleLine(lineBuf);
      if (fault) break;
    }
    // THE ACCEPTANCE BARRIER. A correct RESULT followed by a protocol violation IN THE SAME CHUNK
    // must not be accepted merely because the promise could have been resolved first. Nothing
    // parsed here is delivered until the whole received chunk is known to be well-formed; if any
    // part of it faulted, latch() has already rejected these instead.
    if (fault) return;
    const ready = settling;
    settling = [];
    for (const s of ready) s.deliver();
  };
  child.stdout.on('data', onStdoutData);

  /** Move a matched request out of `pending` and queue its result behind the chunk barrier. */
  function defer(entry, deliver) {
    entry.cancelTimer();
    settling.push({ entry, deliver });
  }

  function handleLine(lineBuf) {
    // Printable ASCII only, checked on BYTES. No encoding ambiguity to reason about.
    for (const byte of lineBuf) {
      if (byte < 0x20 || byte > 0x7e) return void latch('helper wrote a non-ASCII line');
    }
    const line = lineBuf.toString('latin1');
    const tok = line.split(' ');
    if (tok.length === 0 || tok[0].length === 0) return void latch('helper wrote an empty line');
    // Exactly one space between fields. Runs of spaces would make arity checks meaningless.
    if (tok.some((t) => t.length === 0)) return void latch('helper wrote a malformed (double-spaced) line');

    if (tok[0] === 'HELLO') {
      if (helloSeen) return void latch('helper sent HELLO twice');
      if (tok.length !== 9) return void latch(`HELLO arity ${tok.length}, expected 9`);
      const proto = parseCanonicalUint(tok[1]);
      if (proto !== HELPER_PROTOCOL_VERSION) {
        return void latch(`helper protocol version ${tok[1]} is not supported (expected ${HELPER_PROTOCOL_VERSION})`);
      }
      const pid = parseCanonicalUint(tok[2], { min: 1 });
      if (pid === null) return void latch('HELLO reported a bad pid');
      if (tok[3] !== token) return void latch('HELLO did not echo the startup token');
      if (parseCanonicalUint(tok[4]) !== HELPER_ALGO_VERSION) return void latch(`helper algo version ${tok[4]} is wrong`);
      if (parseCanonicalUint(tok[5]) !== HELPER_PARAM_SET_ID) return void latch(`helper param set ${tok[5]} is wrong`);
      for (const field of [tok[6], tok[7], tok[8]]) {
        if (!HELLO_FIELD.test(field)) return void latch('HELLO carried a malformed identity field');
      }
      const waiter = pending.get('hello');
      if (!waiter) return void latch('helper sent HELLO with no handshake outstanding');
      helloSeen = true;
      linuxPid = pid;
      helloDistro = tok[6] === '-' ? null : tok[6];
      linuxBootId = tok[7] === '-' ? null : tok[7];
      sourceId = tok[8];
      pending.delete('hello');
      const greeting = { linuxPid: pid, distro: helloDistro, bootId: linuxBootId, sourceId };
      defer(waiter, () => waiter.resolve(greeting));
      return;
    }

    if (tok[0] === 'READY' || tok[0] === 'RESULT') {
      if (tok.length !== (tok[0] === 'READY' ? 4 : 3)) return void latch(`${tok[0]} arity`);
      const id = parseCanonicalUint(tok[1], { min: 1 });
      if (id === null) return void latch(`${tok[0]} had a non-canonical id ${tok[1].slice(0, 24)}`);
      const entry = pending.get(id);
      // An unsolicited, duplicate, stale or wrong id is FATAL. Ignoring it would mean the next
      // reply could be matched to the wrong question.
      if (!entry) return void latch(`helper sent ${tok[0]} for unknown/duplicate request id ${id}`);
      if (entry.kind !== (tok[0] === 'READY' ? 'init' : 'hash')) {
        return void latch(`helper answered request ${id} with the wrong message type ${tok[0]}`);
      }
      if (tok[0] === 'READY') {
        // Validated as EXACT frozen-v2 allocation values, not merely parsed. A helper reporting a
        // different dataset or scratchpad is not running the algorithm we cross-check against.
        const datasetBytes = parseCanonicalUint(tok[2], { min: 1 });
        const scratchBytes = parseCanonicalUint(tok[3], { min: 1 });
        if (datasetBytes !== HELPER_DATASET_BYTES || scratchBytes !== HELPER_SCRATCH_BYTES) {
          return void latch(
            `helper reported allocation ${tok[2]}/${tok[3]}, expected `
            + `${HELPER_DATASET_BYTES}/${HELPER_SCRATCH_BYTES}`,
          );
        }
        pending.delete(id);
        defer(entry, () => entry.resolve({ datasetBytes, scratchBytes }));
      } else {
        if (!/^[0-9a-f]{64}$/.test(tok[2])) return void latch('helper returned a malformed hash', { id });
        pending.delete(id);
        defer(entry, () => entry.resolve(tok[2]));
      }
      return;
    }

    if (tok[0] === 'BYE') {
      // Exactly arity one, exactly once, and ONLY while a QUIT is outstanding. An early, extra or
      // decorated BYE is a helper that is not speaking this protocol.
      if (tok.length !== 1) return void latch('BYE takes no arguments');
      const waiter = pending.get('bye');
      if (!waiter) return void latch('helper sent an unsolicited BYE');
      pending.delete('bye');
      quitAcknowledged = true;
      defer(waiter, () => waiter.resolve(true));
      return;
    }

    latch(`helper wrote an unknown message: ${tok[0].slice(0, 32)}`);
  }

  /**
   * Register a request and its bounded deadline.
   *
   * New work is refused once cancellation has begun -- except the 'bye' waiter, which exists
   * precisely so a closing helper's goodbye can still be validated.
   */
  function request(key, kind, timeoutMs) {
    return new Promise((resolvePromise, rejectPromise) => {
      if (fault) return rejectPromise(fault);
      if (closing && key !== 'bye') return rejectPromise(cancellation);
      if (pending.has(key)) return rejectPromise(latch(`duplicate outstanding request ${key}`));
      const d = deadline(timeoutMs);
      d.promise.then(() => {
        if (!pending.has(key)) return; // already answered; nothing to time out
        rejectPromise(latch(`helper ${kind} timed out after ${timeoutMs} ms`, { key }));
      });
      pending.set(key, { resolve: resolvePromise, reject: rejectPromise, cancelTimer: () => d.cancel(), kind });
    });
  }

  function writeLine(line) {
    if (fault) throw fault;
    if (!child.stdin.writable) throw latch('helper stdin is not writable');
    try {
      child.stdin.write(`${line}\n`);
    } catch (err) {
      throw latch(`helper stdin write failed: ${err.message}`);
    }
  }

  // ---------------------------------------------------------------- exact-process observation

  /**
   * Start owning one probe child. Ownership is released on a CONFIRMED exit, and on nothing else.
   *
   * `kill()` returning true means a signal was delivered, not that the process is gone. Deleting
   * the record there is how a timed-out `wsl.exe` outlived the operation that started it with its
   * only tracked handle already discarded.
   */
  function trackProbe(child, args) {
    const rec = { child, args, reaped: false, resolveExit: null };
    rec.exited = new Promise((res) => { rec.resolveExit = res; });
    const confirmGone = () => {
      if (rec.reaped) return;
      rec.reaped = true;
      probes.delete(rec);
      rec.resolveExit();
    };
    // Either event is positive evidence the process ended. Both are idempotent here, so a child
    // that emits 'exit' and then 'close' is released exactly once.
    child.once('exit', confirmGone);
    child.once('close', confirmGone);
    probes.add(rec);
    return rec;
  }

  /**
   * Ask exactly this probe to terminate, then JOIN it. Escalates once, to this child only.
   *
   * Returns `{ reaped }`. A false answer keeps the record in `probes`: the handle stays in the
   * ownership graph, shutdown fails honestly, and a later retry can still reach it.
   */
  async function terminateProbe(rec) {
    if (rec.reaped) return { reaped: true, detail: 'already exited' };
    for (const sig of ['SIGTERM', 'SIGKILL']) {
      try { rec.child.kill(sig); } catch { /* may already be gone; the join below decides */ }
      await withDeadline(rec.exited, cfg.probeReapMs);
      if (rec.reaped) return { reaped: true, detail: `exited after ${sig}` };
    }
    return {
      reaped: false,
      detail: `probe (pid ${rec.child.pid ?? 'unknown'}, ${rec.args.join(' ').slice(0, 120)}) `
        + 'did not exit after SIGTERM and SIGKILL',
    };
  }

  /**
   * Run one bounded, owned, argument-native WSL command.
   *
   * THE DEADLINE AND THE REAPING ARE TWO DIFFERENT FACTS. When the observation deadline expires
   * the result is reported immediately -- a caller must not be able to hang here -- but the probe
   * is not disowned until its exit is confirmed. `probeReaped` says which happened.
   */
  function runWsl(args, timeoutMs) {
    if (wslRunner) return Promise.resolve(wslRunner(args, timeoutMs));
    return new Promise((resolvePromise) => {
      let settled = false;
      const d = deadline(timeoutMs);
      const finish = (result) => {
        if (settled) return;
        settled = true;
        d.cancel();
        resolvePromise(result);
      };
      let probe;
      try {
        probe = (probeSpawnFn ?? ((a) => spawn('wsl.exe', a, {
          stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, shell: false,
        })))(args);
      } catch (err) {
        finish({ ok: false, code: null, stdout: Buffer.alloc(0), reason: `spawn threw: ${err.message}`, probeReaped: true });
        return;
      }
      const rec = trackProbe(probe, args);
      let out = Buffer.alloc(0);
      probe.stdout?.on('data', (c) => {
        // Bounded: a probe cannot grow our memory either.
        out = Buffer.concat([out, Buffer.isBuffer(c) ? c : Buffer.from(String(c), 'latin1')]).subarray(0, 64 * 1024);
      });
      probe.on('error', (err) => {
        // A spawn that never produced a process owns nothing. A signal-delivery error later does
        // NOT release the record -- only a confirmed exit does.
        if (probe.pid === undefined) { rec.reaped = true; probes.delete(rec); rec.resolveExit(); }
        finish({ ok: false, code: null, stdout: out, reason: `spawn failed: ${err.message}`, probeReaped: rec.reaped });
      });
      probe.on('close', (code) => finish({ ok: true, code, stdout: out, reason: null, probeReaped: true }));
      d.promise.then(async () => {
        if (settled) return;
        const reap = await terminateProbe(rec);
        finish({
          ok: false,
          code: null,
          stdout: out,
          reason: reap.reaped
            ? `probe timed out after ${timeoutMs} ms`
            : `probe timed out after ${timeoutMs} ms and could not be confirmed reaped: ${reap.detail}`,
          probeReaped: reap.reaped,
        });
      });
    });
  }

  /**
   * `wsl.exe` argv, always routed to the PARENT-PINNED distribution.
   *
   * This used to route to whatever HELLO said, which let the process under examination choose the
   * pid namespace its examiner looked in. That is not a theoretical hazard: on the development
   * host Ubuntu and docker-desktop report the SAME boot UUID with DIFFERENT pid namespaces, so a
   * wrong child-reported name passes the boot-id anchor and then finds no /proc entry for a
   * perfectly live helper -- a false CONFIRMED_ABSENT, which is a false clean release.
   */
  function wslArgs(rest) {
    return ['-d', pinnedDistro, '--exec', ...rest];
  }

  const BOOT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  /** The probe's own /proc entry: an operand that must always be found if the probe worked. */
  const PROC_SELF = '/proc/self';

  /**
   * Does /proc/<pid> EXIST? A separate, positive, machine-readable question.
   *
   * `ls -1 -d` needs only to stat the operand, which succeeds even when the entry's contents are
   * unreadable, and it names each operand it found on stdout. `/proc/self` -- the probe's own
   * entry, which always exists -- is the control operand in the same invocation, so "the listing
   * came back and our pid is not in it" is evidence rather than an inference from an exit code.
   *
   * Nothing here reads the exit status or stderr: `cat` exits 1 for a missing file AND for a
   * permission denial, and stderr wording is neither stable nor portable.
   */
  async function observeProcEntryExists() {
    const probe = await runWsl(
      wslArgs(['ls', '-1', '-d', '--', PROC_SELF, `/proc/${linuxPid}`]),
      cfg.probeTimeoutMs,
    );
    if (!probe.ok) return { known: false, detail: probe.reason };
    const lines = probe.stdout.toString('latin1').split('\n').map((l) => l.replace(/\r$/, ''));
    if (!lines.includes(PROC_SELF)) {
      return { known: false, detail: 'the existence probe did not return its own control entry' };
    }
    return { known: true, exists: lines.includes(`/proc/${linuxPid}`) };
  }

  /**
   * Observe the Linux process. Returns one of OBSERVATION's four states, never a bare boolean.
   *
   * STEP 1 reads TWO files in one `cat`: the WSL VM's boot id, which always exists, and the
   * target's cmdline, which exists only while the process does. The boot id is the CONTROL
   * CHANNEL -- if it comes back in the expected shape, the mechanism demonstrably worked. Argv
   * bytes settle the question outright: an exact positional match, or somebody else's process.
   *
   * STEP 2 exists because "cat printed the control line and then failed" is AMBIGUOUS. It is the
   * wire shape of a missing /proc entry AND the wire shape of a cmdline we were not allowed to
   * read (and of an I/O error), byte for byte and exit code for exit code -- so it cannot on its
   * own authorise CONFIRMED_ABSENT. Absence is claimed only when a SEPARATE probe positively
   * establishes that /proc/<pid> is not there.
   *
   * A boot id that no longer matches the one pinned at launch means the WSL VM restarted and every
   * PID in the old namespace went with it -- but only once that launch boot id has been anchored
   * by a parent-owned observation. Otherwise the only evidence that the namespace changed is a
   * value reported by the very child under examination.
   */
  async function observeLinuxProcess() {
    if (!useWsl || linuxPid === null) {
      return { state: exited ? OBSERVATION.ABSENT : OBSERVATION.UNKNOWN, detail: 'not a WSL child' };
    }
    const probe = await runWsl(
      wslArgs(['cat', '/proc/sys/kernel/random/boot_id', `/proc/${linuxPid}/cmdline`]),
      cfg.probeTimeoutMs,
    );
    if (!probe.ok) return { state: OBSERVATION.UNKNOWN, detail: probe.reason };

    const text = probe.stdout;
    const nl = text.indexOf(0x0a);
    if (nl !== 36) {
      return { state: OBSERVATION.UNKNOWN, detail: 'probe control channel did not return a boot id' };
    }
    const bootNow = text.subarray(0, 36).toString('latin1');
    if (!BOOT_ID_RE.test(bootNow)) {
      return { state: OBSERVATION.UNKNOWN, detail: 'probe control channel returned an unrecognisable boot id' };
    }
    if (linuxBootId && bootNow !== linuxBootId) {
      if (!bootIdAnchored) {
        return {
          state: OBSERVATION.UNKNOWN,
          detail: `the boot id changed (${linuxBootId} -> ${bootNow}) but the launch boot id was `
            + 'never independently anchored, so a VM restart is not established',
        };
      }
      return {
        state: OBSERVATION.ABSENT,
        detail: `the WSL VM restarted (boot id ${linuxBootId} -> ${bootNow}); the old pid namespace is gone`,
      };
    }

    const rest = text.subarray(37);
    if (rest.length === 0) {
      // AMBIGUOUS BY CONSTRUCTION. The control line proves the probe ran; it proves nothing about
      // WHY the cmdline read produced no bytes. Ask the unambiguous question instead of guessing.
      const entry = await observeProcEntryExists();
      if (!entry.known) {
        return {
          state: OBSERVATION.UNKNOWN,
          detail: `the cmdline read produced no bytes and the existence probe failed: ${entry.detail}`,
        };
      }
      if (!entry.exists) {
        return { state: OBSERVATION.ABSENT, detail: 'no /proc entry for the pid (independently confirmed)' };
      }
      return {
        state: OBSERVATION.UNKNOWN,
        detail: `/proc/${linuxPid} exists but its cmdline could not be read (denied, empty, or an `
          + 'I/O error); the pid is occupied and this is not absence',
      };
    }

    const argv = rest.toString('latin1').split('\0').filter((a) => a.length > 0);
    // EXACT argv, by position: the executable we named, then the token, and nothing else. A
    // suffix-and-contains heuristic would accept an unrelated process that happened to be started
    // with a similar path.
    const matches = argv.length === expectedLinuxArgv.length
      && argv.every((a, i) => a === expectedLinuxArgv[i]);
    return {
      state: matches ? OBSERVATION.PRESENT_MATCH : OBSERVATION.PRESENT_MISMATCH,
      argv,
      detail: matches ? 'exact argv match' : `argv is not this helper: ${argv.join(' ').slice(0, 160)}`,
    };
  }

  /**
   * THE SIGNAL FENCE. Send one signal to exactly this PID -- and ONLY behind a FRESH positive
   * identity, taken immediately before the signal, by this function itself.
   *
   * The rule is: no TERM and no KILL unless the immediately preceding observation is
   * CONFIRMED_PRESENT_MATCH for the parent-pinned distribution, the exact Linux PID, the exact
   * argv and the exact startup token. Escalation previously sent KILL when the post-TERM state was
   * PRESENT_MATCH *or* INSPECTION_FAILED, and the signal helper itself checked nothing -- so a pid
   * that had exited (and possibly been recycled) could be killed on the strength of an observation
   * that had already stopped working. The check lives HERE, not at a call site, so no future
   * caller can route around it.
   */
  async function signalLinux(sig) {
    if (!useWsl || linuxPid === null) return { ok: false, refused: true, detail: 'not a WSL child' };
    const obs = await observeLinuxProcess();
    if (obs.state !== OBSERVATION.PRESENT_MATCH) {
      return {
        ok: false,
        refused: true,
        observation: obs.state,
        detail: `refusing to send ${sig} to Linux pid ${linuxPid}: identity is ${obs.state} (${obs.detail})`,
      };
    }
    const result = await runWsl(wslArgs(['kill', `-${sig}`, String(linuxPid)]), cfg.signalTimeoutMs);
    // `kill` exits nonzero when the pid is gone or not ours. Treating every close event as success
    // is how a failed signal became "we terminated it".
    if (!result.ok) return { ok: false, detail: result.reason };
    return { ok: result.code === 0, code: result.code, detail: `kill exited ${result.code}` };
  }

  /** Poll for confirmed absence within a bound. Anything else is not absence. */
  async function waitForLinuxAbsence(timeoutMs) {
    const end = Date.now() + timeoutMs;
    let last = { state: OBSERVATION.UNKNOWN, detail: 'not observed' };
    for (;;) {
      last = await observeLinuxProcess();
      if (last.state === OBSERVATION.ABSENT || last.state === OBSERVATION.PRESENT_MISMATCH) return last;
      if (Date.now() >= end) return last;
      await withDeadline(new Promise(() => {}), 150);
    }
  }

  /**
   * Do not claim released unless absence was POSITIVELY established.
   *
   * PRESENT_MISMATCH counts: the pid is no longer our helper, so our helper is not running under
   * it. UNKNOWN does not count -- a failed inspection retains ownership and fails the close.
   */
  async function confirmLinuxProcessGone() {
    if (!useWsl || linuxPid === null) return;
    const obs = await observeLinuxProcess();
    if (obs.state === OBSERVATION.ABSENT || obs.state === OBSERVATION.PRESENT_MISMATCH) return;
    if (obs.state === OBSERVATION.PRESENT_MATCH) {
      throw new HelperFaultError(
        `helper Linux pid ${linuxPid} is still running after shutdown`,
        { linuxPid, observation: obs.state, argv: obs.argv },
      );
    }
    throw new HelperFaultError(
      `cannot confirm the helper Linux pid ${linuxPid} is gone: ${obs.detail}. `
      + 'Inspection failed, which is not the same as absence, so this resource stays owned.',
      { linuxPid, observation: obs.state },
    );
  }

  /**
   * Reap every probe still owned. Called last, so nothing this module started outlives it.
   *
   * Returns the descriptions of the probes that could NOT be confirmed gone. An empty array is the
   * only thing that lets a close claim release; anything else keeps the record owned and retryable.
   */
  async function reapProbes() {
    const unreaped = [];
    for (const rec of [...probes]) {
      const outcome = await terminateProbe(rec);
      if (!outcome.reaped) unreaped.push(outcome.detail);
    }
    return unreaped;
  }

  // ---------------------------------------------------------------- api

  /**
   * The shutdown verdict, as TWO independent facts.
   *
   *   physicalReleaseConfirmed -- nothing is owned any more: the process is positively gone and
   *                               every probe is reaped. Retrying cleanup would be pointless.
   *   gracefulProtocolShutdown -- the exchange was canonical: QUIT, exactly one canonical BYE,
   *                               fully drained stdio, exit code 0, no signal.
   *
   * They are genuinely independent. A helper that dies mid-goodbye is gone (nothing to retain) AND
   * abnormal (something to report). Collapsing the two is precisely how an abnormal shutdown
   * reached the user as exit code 0 with no visible warning.
   */
  let outcome = { physicalReleaseConfirmed: false, gracefulProtocolShutdown: false, reason: null };
  function recordOutcome(anomalies) {
    outcome = {
      physicalReleaseConfirmed: released,
      gracefulProtocolShutdown: anomalies.length === 0 && released,
      reason: anomalies.length > 0 ? anomalies.join('; ').slice(0, 400) : null,
    };
    return outcome;
  }

  const helper = {
    get shutdownOutcome() { return { ...outcome }; },
    get linuxPid() { return linuxPid; },
    /** The PARENT-PINNED distribution: what every probe and signal actually targets. */
    get linuxDistro() { return pinnedDistro; },
    /** What HELLO claimed. Kept only so a mismatch can be reported; never used to route. */
    get helloDistro() { return helloDistro; },
    get linuxBootId() { return linuxBootId; },
    get sourceId() { return sourceId; },
    get token() { return token; },
    get pid() { return child.pid; },
    get command() { return command; },
    get expectedLinuxArgv() { return [...expectedLinuxArgv]; },
    get healthy() { return fault === null; },
    get fault() { return fault; },
    get exited() { return exited; },
    get exitInfo() { return exitInfo; },
    get counters() { return { ...counters }; },
    get stderrTail() { return stderrRing.subarray(-1024).toString('utf8'); },
    get pendingCount() { return pending.size + settling.length; },

    /**
     * Latch this helper unusable from OUTSIDE, and settle everything outstanding now.
     *
     * The owner calls this when it has decided the helper's answers can no longer be trusted --
     * a build disagreement, say, where neither side is proven wrong but neither may be used
     * again. Sibling requests must not be left to run to completion and hand back a "successful"
     * hash after the decision was already made.
     */
    fail(reason) { return latch(reason); },
    get probeCount() { return probes.size; },
    observeLinuxProcess,

    /** Build the Dataset + Hasher for a fixed context. Exactly once per process. */
    async init({ epochKeyHex, seedHashHex, height, templateHex }) {
      if (fault) throw fault;
      if (closing) throw cancellation;
      if (counters.initCalls > 0) throw latch('helper INIT called twice');
      counters.initCalls++;
      const id = nextId++;
      const wait = request(id, 'init', cfg.initTimeoutMs);
      writeLine(`INIT ${id} ${epochKeyHex} ${seedHashHex} ${height} ${templateHex}`);
      return wait;
    },

    /** One nonce -> 64 lowercase hex characters. `selfTest` only selects which counter moves. */
    async hash(nonce, { selfTest = false } = {}) {
      if (fault) throw fault;
      if (closing) throw cancellation;
      const id = nextId++; // monotonic, never reused for the life of this process
      const wait = request(id, 'hash', cfg.requestTimeoutMs);
      writeLine(`HASH ${id} ${nonce >>> 0}`);
      const hex = await wait;
      if (selfTest) counters.selfTestHashes++;
      else counters.shareHashes++;
      return hex;
    },

    /**
     * PHASE 1: synchronous cancellation. Settles every outstanding request fail-closed so the
     * pool can drain the session operations waiting on them.
     *
     * This is NOT a fault. It does not latch, does not fire onFault, and leaves `healthy` true --
     * which is what allows close() below to register a BYE waiter and actually validate the
     * goodbye rather than poisoning the helper before it can say one.
     */
    beginClose(reason = 'helper shutting down') {
      if (closing) return;
      closing = true;
      cancellation = new HelperFaultError(reason, { cancelled: true });
      settleOutstanding(cancellation);
    },

    /**
     * PHASE 2: graceful QUIT, then bounded exact-process escalation.
     *
     * A GRACEFUL CLOSE IS QUIT -> exactly one canonical BYE -> exit 0, with no signal. Nothing
     * less. Racing the BYE waiter against process exit -- and reporting a bad exit status only if
     * a BYE had already arrived -- meant a helper that died on QUIT without ever answering
     * produced `close() resolved, closed=true, healthy=true`, for exit 0 AND for exit 7 alike.
     * The exchange is now evaluated after the outcome is known, and every way it can go wrong is
     * reported distinctly.
     *
     * PROTOCOL HEALTH AND PHYSICAL RELEASE ARE SEPARATE. If the process is positively gone and
     * every probe is reaped, the handle records release -- there is nothing left to own. The
     * anomaly is still raised, so no caller can read a resolved close as a healthy goodbye.
     */
    async close(reason = 'helper shutting down') {
      if (released) return outcome;
      // THE FAULT THAT WAS ALREADY THERE. Captured before beginClose(), because beginClose()
      // installs a cancellation and `closing` suppresses the unexpected-exit latch -- so after it,
      // a helper that had already crashed becomes indistinguishable from one we asked to stop.
      // Skipping the whole verdict for such a helper is exactly how an idle crash (exit 9, and
      // even exit 0) came back as `gracefulProtocolShutdown: true, reason: null`.
      const preCloseFault = fault && !fault.cancelled ? fault : null;
      const preCloseExit = exited ? exitInfo : null;
      this.beginClose(reason);
      const anomalies = [];
      // Only ASK for a goodbye from a live, unfaulted child. Whether one was asked for is recorded
      // in `quitRequested` and graded below either way -- there is no path that skips grading.
      const attemptedExchange = !exited && !fault;
      if (attemptedExchange) {
        try {
          const bye = request('bye', 'quit', cfg.quitTimeoutMs);
          if (child.stdin.writable) {
            child.stdin.write('QUIT\n');
            quitRequested = true;
          }
          // The BYE is validated by handleLine like any other message: wrong arity, a second one,
          // or one nobody asked for is fatal. Settling here is NOT acceptance -- the verdict is
          // read from quitAcknowledged/exitInfo/stdioClosed below, once ALL of them are known.
          await Promise.race([bye.catch(() => null), exitPromise]);
        } catch {
          // fall through; the verdict below does not depend on how we got here
        }
        try { child.stdin.end(); } catch { /* already closed */ }
        await withDeadline(exitPromise, cfg.quitTimeoutMs);
      }

      // THE DRAIN BARRIER, on EVERY path. Process exit is not the end of the transcript: a final
      // BYE, a duplicate one, or a decorated one may still be in flight. It runs for an
      // already-exited child too, so its last bytes are read before anything is judged.
      if (exited && !stdioClosed) await withDeadline(stdioClosedPromise, cfg.stdioDrainMs);
      // The transcript is over now, one way or the other. Release the goodbye waiter that was
      // deliberately kept alive across process exit; nothing further can arrive for it.
      if (pending.has('bye')) {
        settleOutstanding(cancellation ?? new HelperFaultError('helper shutdown complete', { cancelled: true }));
      }

      // ---------------------------------------------------------- the canonical predicate
      //
      // EXACTLY ONE SHAPE IS A GRACEFUL PROTOCOL SHUTDOWN:
      //
      //   a QUIT we asked for -> exactly one canonical BYE -> no unparsed bytes left on stdout
      //   -> a natural ChildProcess stdio-close -> exit code 0 with no signal -> no latched fault.
      //
      // Every conjunct is graded separately and contributes its own named reason. Nothing is
      // skipped because the child happened to be gone already: a helper that crashed before the
      // exchange is physically gone AND abnormal, and the crash is the reason.
      if (preCloseFault) {
        anomalies.push(`helper faulted before shutdown: ${preCloseFault.message}`);
      }
      if (!quitRequested) {
        anomalies.push(preCloseExit
          ? `helper exited (code=${preCloseExit.code}, signal=${preCloseExit.signal}) before any QUIT was sent`
          : 'no QUIT was ever sent, so no goodbye was requested or completed');
      } else if (!quitAcknowledged) {
        anomalies.push(exited ? 'helper exited without sending BYE' : 'helper never sent BYE');
      }
      if (!stdioClosed) {
        // Its OWN fact, separate from the process state. Without a drain witness we do not know
        // the transcript was complete, so no canonical verdict is available.
        anomalies.push(exited
          ? 'the helper process exited but its stdio never closed, so the transcript is unverified'
          : 'the helper stdio never closed, so the transcript is unverified');
      } else if (stdoutBuf.length > 0) {
        // FULLY DRAINED, AND STILL HOLDING BYTES. The parser keeps everything after the last LF,
        // so a helper that wrote `BYE\nUNTERMINATED_GARBAGE` acknowledged its goodbye and left an
        // incomplete protocol line behind. No unparsed byte may coexist with a canonical verdict.
        anomalies.push(
          `the helper left ${stdoutBuf.length} unterminated byte(s) on stdout after its stdio `
          + `closed: ${describeFragment(stdoutBuf)}`,
        );
      }
      if (exitInfo?.signal) {
        anomalies.push(`helper was terminated by signal ${exitInfo.signal} instead of exiting cleanly`);
      } else if (exitInfo && exitInfo.code !== 0) {
        anomalies.push(quitAcknowledged
          ? `helper exited ${exitInfo.code} after acknowledging QUIT`
          : `helper exited ${exitInfo.code} without acknowledging QUIT`);
      }
      // A duplicate or decorated BYE is latched by handleLine -- possibly only during the drain
      // above. It happened DURING shutdown, so it is reported here rather than left as a fault
      // nobody reads on the way out. `preCloseFault` is excluded: it already has its own line.
      if (fault && !fault.cancelled && fault !== preCloseFault) {
        anomalies.push(`helper protocol fault during shutdown: ${fault.message}`);
      }

      if (!exited) {
        anomalies.push(attemptedExchange
          ? 'the helper did not exit after QUIT; escalated to termination'
          : 'the helper was still running at close (it had already faulted); escalated to termination');
        // Escalation confirms the exact process is gone, releases the local handles and reaps every
        // probe, or throws and keeps the handle owned. It sets `released` itself on success.
        await this.forceClose(`${reason} (graceful QUIT did not exit)`);
      } else {
        await confirmLinuxProcessGone();
        const unreaped = await reapProbes();
        // THE LOCAL SIDE IS A SEPARATE RELEASE. The process being gone does not release the
        // parent's pipes and listeners; only this does, and only if it can be witnessed.
        const stuck = releaseLocalStdio();
        if (stuck.length > 0) {
          anomalies.push(`parent-owned stdio could not be released: ${stuck.join('; ')}`);
        }
        if (unreaped.length > 0) {
          anomalies.push(`probe(s) not confirmed reaped: ${unreaped.join('; ')}`);
        }
        // Released only when the process is gone, every probe is reaped, AND this side let go.
        if (unreaped.length === 0 && stuck.length === 0) released = true;
      }
      // TWO FACTS, KEPT APART AND BOTH REPORTED. `physicalReleaseConfirmed` says nothing is owned
      // any more -- neither the process nor this side's handles; `gracefulProtocolShutdown` says
      // the canonical exchange above actually happened. A caller that reads only one of them will
      // be wrong about the other.
      recordOutcome(anomalies);
      if (anomalies.length > 0) {
        throw new HelperFaultError(anomalies.join('; '), {
          released,
          physicalReleaseConfirmed: released,
          gracefulProtocolShutdown: false,
          reason: outcome.reason,
        });
      }
      return outcome;
    },

    /**
     * Bounded escalation against EXACTLY the process this launcher created, in EXACTLY the
     * distribution it reported. Identity is re-observed before every signal; a pid that is no
     * longer ours is never signalled, and an inspection that failed is never treated as absence.
     */
    async forceClose(reason = 'helper force close') {
      this.beginClose(reason);
      const failures = [];
      if (useWsl && linuxPid !== null) {
        const obs = await observeLinuxProcess();
        if (obs.state === OBSERVATION.PRESENT_MATCH) {
          const term = await signalLinux('TERM');
          if (!term.ok) failures.push(`TERM failed: ${term.detail}`);
          let after = await waitForLinuxAbsence(cfg.signalTimeoutMs);
          // ONLY a fresh PRESENT_MATCH may escalate. An identity we can no longer establish is not
          // a licence to kill: the pid may have exited and been recycled, or inspection may simply
          // be unavailable, and neither is "still our helper".
          if (after.state === OBSERVATION.PRESENT_MATCH) {
            const kill = await signalLinux('KILL');
            if (!kill.ok) failures.push(`KILL failed: ${kill.detail}`);
            after = await waitForLinuxAbsence(cfg.signalTimeoutMs);
          }
          if (after.state === OBSERVATION.PRESENT_MATCH) {
            failures.push(`Linux pid ${linuxPid} survived TERM and KILL`);
          } else if (after.state === OBSERVATION.UNKNOWN) {
            failures.push(
              `cannot confirm Linux pid ${linuxPid} is gone: ${after.detail}. `
              + 'Not escalating to KILL without a fresh identity; this resource stays owned.',
            );
          }
        } else if (obs.state === OBSERVATION.PRESENT_MISMATCH) {
          // Someone else owns that pid now. Signalling it would be exactly the mistake this whole
          // identity dance exists to prevent.
          failures.push(`refusing to signal Linux pid ${linuxPid}: ${obs.detail}`);
        } else if (obs.state === OBSERVATION.UNKNOWN) {
          failures.push(`cannot inspect Linux pid ${linuxPid}: ${obs.detail}`);
        }
      }
      // Join the owned wsl.exe (or direct) child.
      if (!exited) {
        try { child.kill(); } catch { /* already gone */ }
        await withDeadline(exitPromise, cfg.signalTimeoutMs);
      }
      if (!exited) {
        try { child.kill('SIGKILL'); } catch { /* already gone */ }
        await withDeadline(exitPromise, cfg.signalTimeoutMs);
      }
      if (!exited) failures.push(`the helper launcher process (pid ${child.pid}) did not exit`);
      // Probes are part of the ownership graph. A probe we could not confirm gone is an unreleased
      // resource, so it fails the close and stays reachable by a later retry.
      const unreaped = await reapProbes();
      for (const detail of unreaped) failures.push(`probe not confirmed reaped: ${detail}`);
      // And so are this side's pipes and listeners: a termination that leaves them attached has
      // not released the whole child resource.
      if (exited) {
        for (const detail of releaseLocalStdio()) failures.push(`parent-owned stdio: ${detail}`);
      }
      if (failures.length > 0) {
        // NOT released. The handle stays valid and a caller can retry.
        recordOutcome(failures);
        throw new HelperFaultError(`helper force close could not be confirmed: ${failures.join('; ')}`,
          { pid: child.pid, linuxPid, physicalReleaseConfirmed: false, gracefulProtocolShutdown: false });
      }
      released = true;
      // A forced close releases the process; it is never a canonical protocol shutdown.
      recordOutcome(['the helper was terminated rather than completing a QUIT/BYE exchange']);
    },

    get closed() { return released; },
    get closing() { return closing; },
    waitForExit: () => exitPromise,
  };

  // ---------------------------------------------------------------- handshake

  // The listener attached before the spawn now points at the real handle. It stays attached for
  // the WHOLE lifetime, not just HELLO: INIT and the startup self-test happen after this point and
  // the server has no completed handle yet, so without it a pool closing during INIT waits out the
  // full 60 s init timeout with a child it cannot reach.
  onAbortHook = () => helper.beginClose('helper startup aborted');
  helper.detachAbort = detachAbort;
  // An abort that arrived between attaching the listener and binding it -- including one raised
  // synchronously by an injected spawnFn -- is applied now, so it enters OWNED cleanup instead of
  // being lost. Rechecking the signal too covers an abort that raced the rebinding itself.
  if (abortedDuringStartup || signal?.aborted) helper.beginClose('helper startup aborted');

  /**
   * OWNERSHIP SURVIVES A FAILED STARTUP. Try to reap, then hand the handle to the caller either
   * way: a rejected factory that dropped its only reference to a live child is how an invisible
   * process happens.
   */
  async function abandonStartup(err, why) {
    detachAbort(); // a rejected startup must not leave a listener on the caller's signal
    let releaseConfirmed = false;
    let cleanupError = null;
    try {
      await helper.forceClose(why);
      releaseConfirmed = helper.closed;
    } catch (cleanupErr) {
      cleanupError = cleanupErr;
    }
    err.helper = helper;
    err.releaseConfirmed = releaseConfirmed;
    if (cleanupError) err.cleanupError = cleanupError;
    throw err;
  }

  let hello;
  try {
    hello = await request('hello', 'startup', cfg.startupTimeoutMs);
  } catch (err) {
    return await abandonStartup(err, 'helper handshake failed');
  }

  // ---------------------------------------------------------------- identity corroboration
  //
  // WHY THE CHILD'S OWN WORD IS NOT ENOUGH. Two of the values HELLO carries would otherwise decide
  // where the parent looks for the child and whether it may conclude the child is gone -- both
  // supplied by the process under examination.
  //
  //   DISTRIBUTION. The launch now uses an explicit parent-pinned `-d`, and every probe routes
  //   there, so HELLO's distribution is CORROBORATION ONLY. It must match exactly. A mismatch is
  //   fatal rather than a redirection: on the development host two distributions report the SAME
  //   boot UUID with DIFFERENT pid namespaces, so accepting a different name would sail past the
  //   boot-id anchor and then report a live helper as confirmed absent.
  //
  //   BOOT ID. It is what later authorises the strongest conclusion this module can draw -- "the
  //   WSL VM restarted, so every PID in the old namespace is gone". Accepting a malformed value
  //   made that worse, not merely weaker: a non-dash value that never matches any real boot id
  //   would differ from the next VALID observed boot id, and "differs" was read as "restarted",
  //   which authorised a clean-release claim. So it must be a canonical UUID, and it is
  //   corroborated ONCE, here, by a PARENT-OWNED observation in the PARENT-PINNED distribution.
  //
  // If the environment cannot supply that evidence, startup fails closed and the child is reaped
  // or honestly retained.
  if (useWsl) {
    try {
      if (!helloDistro) {
        throw new HelperFaultError(
          'HELLO did not name a WSL distribution, so it cannot corroborate the parent-pinned '
          + `distribution ${JSON.stringify(pinnedDistro)}. Refusing to start.`,
          { pinnedDistro, helloDistro: null },
        );
      }
      if (helloDistro !== pinnedDistro) {
        throw new HelperFaultError(
          `the helper reports distribution ${JSON.stringify(helloDistro)} but the parent launched `
          + `it in ${JSON.stringify(pinnedDistro)}. A child cannot choose where its examiner looks: `
          + 'two distributions can share a boot id and NOT share a pid namespace, which would make '
          + 'a live helper look confirmed absent. Refusing to start.',
          { pinnedDistro, helloDistro },
        );
      }
      if (!linuxBootId || !BOOT_ID_RE.test(linuxBootId)) {
        throw new HelperFaultError(
          `HELLO carried the boot id ${JSON.stringify(linuxBootId)}, which is not a canonical `
          + 'UUID. A boot id that cannot be compared cannot support the pinned-boot safety claim, '
          + 'and a malformed one would later look like a VM restart. Refusing to start.',
          { bootId: linuxBootId },
        );
      }
      const anchor = await runWsl(
        wslArgs(['cat', '/proc/sys/kernel/random/boot_id']),
        cfg.probeTimeoutMs,
      );
      if (!anchor.ok) {
        throw new HelperFaultError(`cannot anchor the WSL boot id: ${anchor.reason}`, { bootId: linuxBootId });
      }
      const observed = anchor.stdout.toString('latin1').split('\n')[0].replace(/\r$/, '');
      if (!BOOT_ID_RE.test(observed)) {
        throw new HelperFaultError(
          'the parent-owned boot-id observation was unrecognisable, so the launch boot id is not anchored',
          { bootId: linuxBootId },
        );
      }
      if (observed !== linuxBootId) {
        throw new HelperFaultError(
          `the helper reported boot id ${linuxBootId} but ${pinnedDistro} reports ${observed}. `
          + 'The child is not in the pid namespace this parent can observe. Refusing to start.',
          { bootId: linuxBootId, observed },
        );
      }
      bootIdAnchored = true;
    } catch (err) {
      return await abandonStartup(err, 'helper boot identity could not be anchored');
    }
  }

  return { helper, hello };
}
