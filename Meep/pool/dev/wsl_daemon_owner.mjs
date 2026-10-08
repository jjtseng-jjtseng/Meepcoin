// Exact-process owner for a directly launched, private WSL daemon.
//
// This is an alternate transport to the Docker-local daemon owner, not a public-network or
// production mode. The fixed shell prints its own PID and waits for a GO line. The parent first
// anchors that PID, WSL boot ID and full shell argv. Only then may GO cause an exec into the
// source-pinned daemon. Custody recognises that one-way, same-PID argv transition and never treats
// an unexpected third argv as proof of release. This module does not create data directories,
// validate build hashes or check ports; those are required preflight responsibilities of its caller.

import { spawn } from 'node:child_process';

import { artifactDirectoryUser, checkDaemonConfig, daemonFlags } from './local_daemon.mjs';
import { OBSERVATION } from './native_helper.mjs';
import { createWslProcessCustody } from './wsl_process_custody.mjs';

const PID_LINE_RE = /^MEEPCOIN_PID ([1-9][0-9]{0,9})\n$/;

export class WslDaemonOwnerError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'WslDaemonOwnerError';
    this.code = code;
  }
}

function fail(code, message) {
  return new WslDaemonOwnerError(code, message);
}

function boundedMs(value, fallback, name) {
  const actual = value ?? fallback;
  if (!Number.isSafeInteger(actual) || actual < 1 || actual > 60_000) {
    throw fail('bad_config', `${name} must be an integer in [1, 60000]`);
  }
  return actual;
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function wslDaemonLaunchArgs(config) {
  const cfg = checkDaemonConfig(config);
  const artifactUser = artifactDirectoryUser(cfg.artifactDir);
  const binary = `${cfg.artifactDir}/meepcoind`;
  const daemonArgv = [binary, ...daemonFlags(cfg)];
  // Numbers came through checkDaemonConfig; no untrusted string enters shell source. Verify the
  // named WSL user really resolves to the requested non-root uid/gid BEFORE printing a PID or
  // opening the GO gate. A stale/default-user mismatch can never start a daemon.
  const trampoline = `[ "$(/usr/bin/id -u)" = "${cfg.uid}" ] && [ "$(/usr/bin/id -g)" = "${cfg.gid}" ] || exit 65; `
    + 'printf "MEEPCOIN_PID %s\\n" "$$"; IFS= read -r gate || exit 64; [ "$gate" = GO ] || exit 64; exec "$@" 1>&2';
  const shellArgv = ['/bin/sh', '-c', trampoline, '--', '/usr/bin/env', '-i',
    `LD_LIBRARY_PATH=${cfg.artifactDir}/runtime-libs`, ...daemonArgv];
  return Object.freeze({
    cfg,
    daemonArgv: Object.freeze(daemonArgv),
    shellArgv: Object.freeze(shellArgv),
    wslArgs: Object.freeze(['-d', cfg.wslDistro, '-u', artifactUser, '--exec', ...shellArgv]),
  });
}

function readPidLine(child, timeoutMs) {
  if (!child.stdout || typeof child.stdout.on !== 'function') {
    return Promise.reject(fail('bad_child', 'WSL child has no stdout pipe for the PID handshake'));
  }
  const line = new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0);
    let settled = false;
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      child.stdout.off('data', onData);
      child.stdout.off('error', onError);
      child.off('error', onError);
      child.off('close', onClose);
    };
    const finish = (error, pid) => {
      if (settled) return;
      settled = true;
      cleanup();
      // After the one-line handshake, keep draining the pipe even if a broken daemon writes to it.
      child.stdout.on('data', () => {});
      if (error) reject(error); else resolve(pid);
    };
    const onError = () => finish(fail('wrapper_failed', 'WSL wrapper failed before PID handshake'));
    const onClose = () => finish(fail('wrapper_closed', 'WSL wrapper closed before PID handshake'));
    const onData = (chunk) => {
      bytes = Buffer.concat([bytes, Buffer.from(chunk)]);
      if (bytes.length > 64) return finish(fail('bad_pid_line', 'PID handshake exceeded 64 bytes'));
      const newline = bytes.indexOf(0x0a);
      if (newline < 0) return;
      if (newline !== bytes.length - 1) return finish(fail('bad_pid_line', 'PID handshake carried extra bytes'));
      const match = PID_LINE_RE.exec(bytes.toString('latin1'));
      if (!match) return finish(fail('bad_pid_line', 'PID handshake was not canonical'));
      const pid = Number(match[1]);
      if (!Number.isSafeInteger(pid) || pid < 1 || pid > 0x7fffffff) {
        return finish(fail('bad_pid_line', 'PID handshake was outside the Linux PID range'));
      }
      finish(null, pid);
    };
    child.stdout.on('data', onData);
    child.stdout.once('error', onError);
    child.once('error', onError);
    child.once('close', onClose);
    timer = setTimeout(() => finish(fail('pid_handshake_timeout',
      `PID handshake timed out after ${timeoutMs} ms`)), timeoutMs);
  });
  return line;
}

function writeGate(child, gate) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error); else resolve();
    };
    const timer = setTimeout(() => finish(fail('gate_write_timeout',
      'the daemon launch gate write did not settle')), 3_000);
    if (!child.stdin || typeof child.stdin.write !== 'function') {
      finish(fail('bad_child', 'WSL child has no stdin pipe for the launch gate'));
      return;
    }
    try {
      child.stdin.write(`${gate}\n`, (error) => {
        finish(error ? fail('gate_write_failed', 'could not write the daemon launch gate') : null);
      });
    } catch {
      finish(fail('gate_write_failed', 'could not write the daemon launch gate'));
    }
  });
}

/** Return an owned handle immediately, so even a failed asynchronous startup has a close path. */
export function launchWslDaemonOwner({
  config,
  spawnFn = spawn,
  custodyFactory = createWslProcessCustody,
  pidHandshakeTimeoutMs = 15_000,
  execTimeoutMs = 5_000,
  onFault = () => {},
} = {}) {
  const plan = wslDaemonLaunchArgs(config);
  const handshakeMs = boundedMs(pidHandshakeTimeoutMs, 15_000, 'pidHandshakeTimeoutMs');
  const transitionMs = boundedMs(execTimeoutMs, 5_000, 'execTimeoutMs');
  if (typeof spawnFn !== 'function' || typeof custodyFactory !== 'function'
      || typeof onFault !== 'function') throw fail('bad_config', 'owner dependencies must be functions');
  let child;
  try {
    child = spawnFn('wsl.exe', [...plan.wslArgs], {
      stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false,
    });
  } catch {
    throw fail('spawn_failed', 'WSL wrapper could not be started');
  }
  if (!child || typeof child.once !== 'function' || typeof child.kill !== 'function') {
    throw fail('spawn_failed', 'WSL spawn returned no owned child handle');
  }
  // Drain daemon stderr; a full pipe must never block daemon shutdown. No output is recorded here.
  child.stderr?.resume?.();

  let custody = null;
  let linuxPid = null;
  let goSent = false;
  let closing = false;
  let closed = false;
  let state = 'STARTING';
  let closePromise = null;
  let closeOutcome = null;
  let wrapperClosed = child.exitCode !== null || child.signalCode !== null;
  // ChildProcess pipes emit 'error' as well as invoking write callbacks. Keep those errors from
  // becoming uncaught process exceptions; the PID/gate promises and custody observations decide
  // the actual startup or release verdict.
  child.stdin?.on?.('error', () => {});
  child.stdout?.on?.('error', () => {});
  child.stderr?.on?.('error', () => {});
  child.on('error', () => {
    if (!closing && state === 'READY') {
      try { onFault('daemon_wrapper_error'); } catch { /* owner retains state */ }
    }
  });
  child.once('close', () => {
    wrapperClosed = true;
    if (!closing && state === 'READY') {
      try { onFault('daemon_wrapper_closed'); } catch { /* owner retains state */ }
    }
  });

  const ready = (async () => {
    try {
      linuxPid = await readPidLine(child, handshakeMs);
      custody = custodyFactory({
        wrapperChild: child,
        distro: plan.cfg.wslDistro,
        linuxPid,
        expectedLinuxArgv: plan.shellArgv,
        additionalExpectedLinuxArgv: plan.daemonArgv,
      });
      await custody.anchor();
      if (closing) throw fail('closing', 'daemon launch cancelled before GO');
      await writeGate(child, 'GO');
      goSent = true;
      // The daemon is non-interactive. Leaving WSL's stdin pipe open can keep the Windows wrapper
      // alive even after the Linux process exits, so close it immediately after the one gate line.
      child.stdin.end();
      const deadline = Date.now() + transitionMs;
      while (Date.now() <= deadline) {
        const observed = await custody.observe();
        if (observed.state === OBSERVATION.PRESENT_MATCH && observed.matchedArgv === 'after_exec') {
          if (closing) throw fail('closing', 'daemon launch cancelled during exec');
          state = 'READY';
          return api;
        }
        if (observed.state === OBSERVATION.ABSENT || wrapperClosed) {
          throw fail('daemon_exited', 'daemon exited before the exec identity was observed');
        }
        if (closing) throw fail('closing', 'daemon launch cancelled during exec');
        await wait(50);
      }
      throw fail('exec_timeout', 'daemon exec identity was not observed in time');
    } catch (error) {
      state = 'FAILED';
      throw error;
    }
  })();
  ready.catch(() => {});

  async function performClose() {
    closing = true;
    if (state !== 'FAILED') state = 'CLOSING';
    if (!goSent) {
      try { await writeGate(child, 'STOP'); } catch { /* custody still decides release */ }
    }
    try { await ready; } catch { /* readiness failure is not release evidence */ }
    if (custody === null) {
      // The fixed shell cannot exec the daemon without GO. Do not confuse that invariant with a
      // positive observation that the wrapper or shell exited; retain ownership for diagnosis.
      for (let i = 0; i < 10 && !wrapperClosed; i++) await wait(100);
      if (!wrapperClosed) {
        try { child.kill('SIGTERM'); } catch { /* still unconfirmed */ }
      }
      throw fail('custody_unavailable', 'PID handshake failed; WSL process release is unconfirmed');
    }
    const release = await custody.release();
    if (release.physicalReleaseConfirmed !== true) {
      throw fail('release_unconfirmed', 'WSL daemon release was not positively confirmed');
    }
    closed = true;
    state = 'CLOSED';
    closeOutcome = Object.freeze({ ...release, linuxPid, daemonExecObserved: custody.execObserved });
    return closeOutcome;
  }

  const api = {
    get ready() { return ready; },
    get state() { return state; },
    get linuxPid() { return linuxPid; },
    get closed() { return closed; },
    get closing() { return closing; },
    get daemonExecObserved() { return custody?.execObserved === true; },
    get launchArgs() { return [...plan.wslArgs]; },
    get daemonArgv() { return [...plan.daemonArgv]; },
    beginClose() { closing = true; if (state === 'STARTING' || state === 'READY') state = 'CLOSING'; },
    async close() {
      if (closeOutcome !== null) return closeOutcome;
      if (closePromise !== null) return await closePromise;
      closePromise = performClose();
      try { return await closePromise; } finally { if (!closed) closePromise = null; }
    },
    async forceClose() { return await api.close(); },
  };
  return api;
}
