// Physical custody for one ALREADY-SPAWNED process inside one parent-pinned WSL distribution.
//
// This is deliberately independent of any application protocol. The caller still owns the
// protocol handshake and graceful shutdown; this layer answers only the harder physical question:
// is the exact Linux process we anchored at startup still present, and if shutdown is required can
// we prove that process, its wsl.exe wrapper, and every observation/signal probe are gone?
//
// Failure to inspect is never absence. A signal is sent only after a fresh exact argv match. A
// Windows wrapper exit is never evidence about the Linux process. No name-based or wildcard signal
// exists here, and the parent-pinned distribution is used for every probe.

import { spawn } from 'node:child_process';

import { OBSERVATION, WSL_DISTRO_RE } from './native_helper.mjs';

const BOOT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PROC_SELF = '/proc/self';

export const WSL_CUSTODY_LIMITS = Object.freeze({
  probeTimeoutMs: 5_000,
  probeReapMs: 3_000,
  signalTimeoutMs: 5_000,
  absenceTimeoutMs: 5_000,
  wrapperTimeoutMs: 3_000,
  pollMs: 100,
  maxProbeOutputBytes: 64 * 1024,
});

export class WslCustodyError extends Error {
  constructor(code, message, detail = {}) {
    super(message);
    this.name = 'WslCustodyError';
    this.code = code;
    this.detail = detail;
  }
}

function fail(code, message, detail = {}) {
  return new WslCustodyError(code, message, detail);
}

function boundedInteger(value, fallback, name, { min, max }) {
  const actual = value ?? fallback;
  if (!Number.isSafeInteger(actual) || actual < min || actual > max) {
    throw fail('bad_config', `${name} must be an integer in [${min}, ${max}]`);
  }
  return actual;
}

function validateChild(child) {
  if (child === null || typeof child !== 'object' || typeof child.once !== 'function'
      || typeof child.kill !== 'function') {
    throw fail('bad_config', 'wrapperChild must be a ChildProcess-shaped owned handle');
  }
}

function validateExpectedArgv(argv, maxFields = 16) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.length > maxFields) {
    throw fail('bad_config', `expectedLinuxArgv must contain 1..${maxFields} argv fields`);
  }
  for (const field of argv) {
    if (typeof field !== 'string' || field.length === 0 || field.length > 4096
        || field.includes('\0') || field.includes('\n') || field.includes('\r')) {
      throw fail('bad_config', 'expectedLinuxArgv contains an unusable field');
    }
  }
}

function deadline(ms) {
  let timer = null;
  const promise = new Promise((resolve) => {
    timer = setTimeout(() => { timer = null; resolve('timeout'); }, ms);
  });
  return { promise, cancel: () => { if (timer !== null) clearTimeout(timer); timer = null; } };
}

async function withDeadline(work, ms) {
  const d = deadline(ms);
  try { return await Promise.race([work, d.promise]); } finally { d.cancel(); }
}

/**
 * Take custody of an already-spawned WSL process and its exact Windows wrapper.
 *
 * `anchor()` must succeed before `release()` may signal or claim absence. The initial parent-owned
 * observation establishes the WSL boot id and exact `/proc/<pid>/cmdline` together.
 */
export function createWslProcessCustody({
  wrapperChild,
  distro,
  linuxPid,
  expectedLinuxArgv,
  additionalExpectedLinuxArgv = null,
  limits = {},
  probeSpawnFn = null,
  probeRunner = null,
} = {}) {
  validateChild(wrapperChild);
  if (typeof distro !== 'string' || !WSL_DISTRO_RE.test(distro)) {
    throw fail('bad_config', 'distro must be one parent-pinned, space-free WSL distribution name');
  }
  if (!Number.isSafeInteger(linuxPid) || linuxPid < 1) {
    throw fail('bad_config', 'linuxPid must be a positive safe integer');
  }
  // A direct daemon's gated shell carries the eventual daemon flag list as positional argv. Keep
  // the original 16-field converter boundary; permit 64 only for the explicitly exec-capable owner.
  validateExpectedArgv(expectedLinuxArgv, additionalExpectedLinuxArgv === null ? 16 : 64);
  if (additionalExpectedLinuxArgv !== null) {
    validateExpectedArgv(additionalExpectedLinuxArgv, 64);
    if (additionalExpectedLinuxArgv.length === expectedLinuxArgv.length
        && additionalExpectedLinuxArgv.every((field, index) => field === expectedLinuxArgv[index])) {
      throw fail('bad_config', 'additionalExpectedLinuxArgv must differ from the initial argv');
    }
  }
  if (limits === null || typeof limits !== 'object' || Array.isArray(limits)) {
    throw fail('bad_config', 'limits must be an object');
  }
  const allowedLimits = new Set(Object.keys(WSL_CUSTODY_LIMITS));
  for (const key of Object.keys(limits)) {
    if (!allowedLimits.has(key)) throw fail('bad_config', `unknown custody limit ${key.slice(0, 40)}`);
  }
  if (probeSpawnFn !== null && typeof probeSpawnFn !== 'function') {
    throw fail('bad_config', 'probeSpawnFn must be a function');
  }
  if (probeRunner !== null && typeof probeRunner !== 'function') {
    throw fail('bad_config', 'probeRunner must be a function');
  }

  const cfg = Object.freeze({
    probeTimeoutMs: boundedInteger(limits.probeTimeoutMs, WSL_CUSTODY_LIMITS.probeTimeoutMs,
      'probeTimeoutMs', { min: 1, max: 60_000 }),
    probeReapMs: boundedInteger(limits.probeReapMs, WSL_CUSTODY_LIMITS.probeReapMs,
      'probeReapMs', { min: 1, max: 30_000 }),
    signalTimeoutMs: boundedInteger(limits.signalTimeoutMs, WSL_CUSTODY_LIMITS.signalTimeoutMs,
      'signalTimeoutMs', { min: 1, max: 60_000 }),
    absenceTimeoutMs: boundedInteger(limits.absenceTimeoutMs, WSL_CUSTODY_LIMITS.absenceTimeoutMs,
      'absenceTimeoutMs', { min: 1, max: 60_000 }),
    wrapperTimeoutMs: boundedInteger(limits.wrapperTimeoutMs, WSL_CUSTODY_LIMITS.wrapperTimeoutMs,
      'wrapperTimeoutMs', { min: 1, max: 30_000 }),
    pollMs: boundedInteger(limits.pollMs, WSL_CUSTODY_LIMITS.pollMs,
      'pollMs', { min: 1, max: 1_000 }),
    maxProbeOutputBytes: boundedInteger(
      limits.maxProbeOutputBytes, WSL_CUSTODY_LIMITS.maxProbeOutputBytes,
      'maxProbeOutputBytes', { min: 256, max: 1024 * 1024 },
    ),
  });

  const probes = new Set();
  let anchoredBootId = null;
  let execObserved = false;
  let released = false;
  let releaseOutcome = null;
  let releasePromise = null;
  let wrapperClosed = false;
  let wrapperCloseInfo = null;
  let resolveWrapperClose;
  const wrapperClose = new Promise((resolve) => { resolveWrapperClose = resolve; });
  // A ChildProcess that was already closed before custody was constructed is still positive wrapper
  // evidence, but never Linux-process evidence.
  if (wrapperChild.exitCode !== null || wrapperChild.signalCode !== null) {
    wrapperClosed = true;
    wrapperCloseInfo = { code: wrapperChild.exitCode, signal: wrapperChild.signalCode };
    resolveWrapperClose(wrapperCloseInfo);
  } else {
    wrapperChild.once('close', (code, signal) => {
      wrapperClosed = true;
      wrapperCloseInfo = { code, signal };
      resolveWrapperClose(wrapperCloseInfo);
    });
  }

  const wslArgs = (rest) => ['-d', distro, '--exec', ...rest];

  function trackProbe(child, args) {
    const rec = { child, args: [...args], reaped: false, resolveExit: null };
    rec.exited = new Promise((resolve) => { rec.resolveExit = resolve; });
    const confirmGone = () => {
      if (rec.reaped) return;
      rec.reaped = true;
      probes.delete(rec);
      rec.resolveExit();
    };
    child.once('exit', confirmGone);
    child.once('close', confirmGone);
    probes.add(rec);
    return rec;
  }

  async function terminateProbe(rec) {
    if (rec.reaped) return { reaped: true, detail: 'already exited' };
    for (const signal of ['SIGTERM', 'SIGKILL']) {
      try { rec.child.kill(signal); } catch { /* the join decides */ }
      await withDeadline(rec.exited, cfg.probeReapMs);
      if (rec.reaped) return { reaped: true, detail: `exited after ${signal}` };
    }
    return {
      reaped: false,
      detail: `probe pid ${rec.child.pid ?? 'unknown'} did not exit after SIGTERM and SIGKILL`,
    };
  }

  function runProbe(args, timeoutMs) {
    if (probeRunner !== null) return Promise.resolve(probeRunner([...args], timeoutMs));
    return new Promise((resolve) => {
      let settled = false;
      const d = deadline(timeoutMs);
      const finish = (result) => {
        if (settled) return;
        settled = true;
        d.cancel();
        resolve(result);
      };
      let child;
      try {
        child = (probeSpawnFn ?? ((a) => spawn('wsl.exe', a, {
          stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true, shell: false,
        })))([...args]);
      } catch (error) {
        finish({ ok: false, code: null, stdout: Buffer.alloc(0),
          reason: `probe spawn threw: ${error.message}`, probeReaped: true });
        return;
      }
      const rec = trackProbe(child, args);
      let stdout = Buffer.alloc(0);
      let overflow = false;
      child.stdout?.on('data', (chunk) => {
        const bytes = Buffer.from(chunk);
        if (stdout.length + bytes.length > cfg.maxProbeOutputBytes) overflow = true;
        stdout = Buffer.concat([stdout, bytes]).subarray(0, cfg.maxProbeOutputBytes);
      });
      child.on('error', (error) => {
        if (child.pid === undefined && !rec.reaped) {
          rec.reaped = true;
          probes.delete(rec);
          rec.resolveExit();
        }
        finish({ ok: false, code: null, stdout,
          reason: `probe spawn failed: ${error.message}`, probeReaped: rec.reaped });
      });
      child.on('close', (code) => finish({
        ok: !overflow,
        code,
        stdout,
        reason: overflow ? 'probe stdout exceeded its bound' : null,
        probeReaped: true,
      }));
      d.promise.then(async () => {
        if (settled) return;
        const reaping = await terminateProbe(rec);
        finish({
          ok: false,
          code: null,
          stdout,
          reason: reaping.reaped
            ? `probe timed out after ${timeoutMs} ms`
            : `probe timed out and could not be reaped: ${reaping.detail}`,
          probeReaped: reaping.reaped,
        });
      });
    });
  }

  async function observeProcEntryExists() {
    const result = await runProbe(
      wslArgs(['ls', '-1', '-d', '--', PROC_SELF, `/proc/${linuxPid}`]),
      cfg.probeTimeoutMs,
    );
    if (!result.ok) return { known: false, detail: result.reason };
    const lines = Buffer.from(result.stdout).toString('latin1').split('\n')
      .map((line) => line.replace(/\r$/, ''));
    if (!lines.includes(PROC_SELF)) {
      return { known: false, detail: 'existence probe omitted its /proc/self control' };
    }
    return { known: true, exists: lines.includes(`/proc/${linuxPid}`) };
  }

  async function observe({ allowUnanchored = false } = {}) {
    if (!allowUnanchored && anchoredBootId === null) {
      return { state: OBSERVATION.UNKNOWN, detail: 'custody is not anchored' };
    }
    const result = await runProbe(
      wslArgs(['cat', '/proc/sys/kernel/random/boot_id', `/proc/${linuxPid}/cmdline`]),
      cfg.probeTimeoutMs,
    );
    if (!result.ok) return { state: OBSERVATION.UNKNOWN, detail: result.reason };
    const bytes = Buffer.from(result.stdout);
    const newline = bytes.indexOf(0x0a);
    if (newline !== 36) {
      return { state: OBSERVATION.UNKNOWN, detail: 'probe did not return a canonical boot-id control line' };
    }
    const bootId = bytes.subarray(0, 36).toString('latin1');
    if (!BOOT_ID_RE.test(bootId)) {
      return { state: OBSERVATION.UNKNOWN, detail: 'probe returned an unrecognisable boot id' };
    }
    if (anchoredBootId !== null && bootId !== anchoredBootId) {
      return {
        state: OBSERVATION.ABSENT,
        bootId,
        detail: `WSL boot id changed from ${anchoredBootId} to ${bootId}`,
      };
    }
    const rest = bytes.subarray(37);
    if (rest.length === 0) {
      const entry = await observeProcEntryExists();
      if (!entry.known) {
        return { state: OBSERVATION.UNKNOWN,
          detail: `cmdline was unreadable and existence could not be established: ${entry.detail}` };
      }
      return entry.exists
        ? { state: OBSERVATION.UNKNOWN, bootId,
          detail: `/proc/${linuxPid} exists but its cmdline was unreadable` }
        : { state: OBSERVATION.ABSENT, bootId,
          detail: `no /proc/${linuxPid} entry (independently confirmed)` };
    }
    // Linux exposes argv as NUL-terminated fields. Require the final terminator and preserve every
    // interior empty field: dropping empty strings would let `expected0\0\0expected1\0` masquerade
    // as the exact two-element argv. An unterminated read may be partial, so it is UNKNOWN rather
    // than evidence that our process disappeared.
    if (rest[rest.length - 1] !== 0) {
      return { state: OBSERVATION.UNKNOWN, bootId,
        detail: 'cmdline was not terminated and may be a partial observation' };
    }
    const argv = rest.subarray(0, -1).toString('latin1').split('\0');
    const matchesInitial = !execObserved && argv.length === expectedLinuxArgv.length
      && argv.every((field, index) => field === expectedLinuxArgv[index]);
    // A controlled wrapper may print its PID, wait for the parent's signal, then exec the daemon
    // without changing PID. The parent anchors the initial wrapper first; only then may the
    // second exact argv be recognised. A different process at that PID remains a mismatch and is
    // never signalled. Ordinary converter callers provide no additional argv and are unchanged.
    const matchesAfterExec = anchoredBootId !== null && additionalExpectedLinuxArgv !== null
      && argv.length === additionalExpectedLinuxArgv.length
      && argv.every((field, index) => field === additionalExpectedLinuxArgv[index]);
    if (matchesAfterExec) execObserved = true; // the transition is one-way
    const matches = matchesInitial || matchesAfterExec;
    return {
      state: matches ? OBSERVATION.PRESENT_MATCH : OBSERVATION.PRESENT_MISMATCH,
      bootId,
      argv,
      matchedArgv: matchesInitial ? 'initial' : (matchesAfterExec ? 'after_exec' : null),
      detail: matches ? 'exact argv match' : 'pid is occupied by different argv',
    };
  }

  async function anchor() {
    if (anchoredBootId !== null) return { bootId: anchoredBootId, linuxPid, distro };
    const result = await observe({ allowUnanchored: true });
    if (result.state !== OBSERVATION.PRESENT_MATCH || !BOOT_ID_RE.test(result.bootId ?? '')) {
      throw fail('anchor_failed',
        `cannot anchor WSL pid ${linuxPid}: ${result.state} (${result.detail})`, { observation: result });
    }
    anchoredBootId = result.bootId;
    return Object.freeze({ bootId: anchoredBootId, linuxPid, distro });
  }

  async function signalExact(signal) {
    const identity = await observe();
    if (identity.state !== OBSERVATION.PRESENT_MATCH) {
      return { ok: false, refused: true, observation: identity,
        detail: `refusing ${signal}: fresh identity is ${identity.state}` };
    }
    const result = await runProbe(
      wslArgs(['kill', `-${signal}`, String(linuxPid)]), cfg.signalTimeoutMs,
    );
    if (!result.ok || result.code !== 0) {
      return { ok: false, refused: false, observation: identity,
        detail: result.reason ?? `kill exited ${result.code}` };
    }
    return { ok: true, observation: identity };
  }

  async function waitForAbsence() {
    const end = Date.now() + cfg.absenceTimeoutMs;
    let last = await observe();
    while (last.state === OBSERVATION.PRESENT_MATCH && Date.now() < end) {
      await withDeadline(new Promise(() => {}), cfg.pollMs);
      last = await observe();
    }
    return last;
  }

  async function reapWrapperAfterLinuxGone() {
    if (wrapperClosed) return;
    await withDeadline(wrapperClose, cfg.wrapperTimeoutMs);
    if (wrapperClosed) return;
    for (const signal of ['SIGTERM', 'SIGKILL']) {
      try { wrapperChild.kill(signal); } catch { /* join below decides */ }
      await withDeadline(wrapperClose, cfg.wrapperTimeoutMs);
      if (wrapperClosed) return;
    }
    throw fail('wrapper_retained', 'the exact wsl.exe wrapper could not be confirmed closed');
  }

  async function reapAllProbes() {
    const retained = [];
    for (const rec of [...probes]) {
      const result = await terminateProbe(rec);
      if (!result.reaped) retained.push(result.detail);
    }
    if (retained.length > 0) {
      throw fail('probe_retained', 'one or more custody probes could not be confirmed reaped', { retained });
    }
  }

  async function performRelease() {
    if (anchoredBootId === null) {
      throw fail('unanchored', 'custody cannot signal or claim release before a successful anchor');
    }
    let observation = await observe();
    if (observation.state === OBSERVATION.PRESENT_MATCH) {
      const term = await signalExact('TERM');
      if (!term.ok) {
        throw fail('term_refused', `TERM did not run: ${term.detail}`, { observation: term.observation });
      }
      observation = await waitForAbsence();
    }
    if (observation.state === OBSERVATION.PRESENT_MATCH) {
      const kill = await signalExact('KILL');
      if (!kill.ok) {
        throw fail('kill_refused', `KILL did not run: ${kill.detail}`, { observation: kill.observation });
      }
      observation = await waitForAbsence();
    }
    // With an exec-capable process a mismatching argv could be another exec by the SAME pid, not
    // pid reuse. Only an independently observed missing /proc entry or a changed WSL boot proves
    // absence. The legacy single-argv owner retains its prior mismatch policy.
    if (observation.state !== OBSERVATION.ABSENT
        && (observation.state !== OBSERVATION.PRESENT_MISMATCH
          || additionalExpectedLinuxArgv !== null)) {
      throw fail('release_unconfirmed',
        `Linux process release is unconfirmed: ${observation.state} (${observation.detail})`,
        { observation });
    }
    await reapWrapperAfterLinuxGone();
    await reapAllProbes();
    releaseOutcome = Object.freeze({
      physicalReleaseConfirmed: true,
      linuxObservation: observation.state,
      wrapperExited: true,
      probesReaped: true,
    });
    released = true;
    return releaseOutcome;
  }

  const api = {
    get distro() { return distro; },
    get linuxPid() { return linuxPid; },
    get expectedLinuxArgv() { return [...expectedLinuxArgv]; },
    get additionalExpectedLinuxArgv() {
      return additionalExpectedLinuxArgv === null ? null : [...additionalExpectedLinuxArgv];
    },
    get anchoredBootId() { return anchoredBootId; },
    get anchored() { return anchoredBootId !== null; },
    get execObserved() { return execObserved; },
    get released() { return released; },
    get wrapperExited() { return wrapperClosed; },
    get wrapperExitInfo() { return wrapperCloseInfo === null ? null : { ...wrapperCloseInfo }; },
    get probeCount() { return probes.size; },
    anchor,
    observe: () => observe(),
    async release() {
      if (released) return releaseOutcome;
      if (releasePromise !== null) return await releasePromise;
      releasePromise = performRelease();
      try { return await releasePromise; } finally { releasePromise = null; }
    },
  };
  return api;
}
