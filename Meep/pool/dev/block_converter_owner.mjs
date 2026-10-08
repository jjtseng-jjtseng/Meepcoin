// One owner for the WSL wrapper, the converter protocol, and the corroborated Linux process.
//
// READY means BOTH that the child completed its private-pipe HELLO and that a parent-owned WSL
// observation matched the HELLO pid to the exact argv we launched. Protocol health and physical
// release remain separate facts: close() always attempts physical custody release after the
// graceful protocol attempt, and it reports a protocol anomaly even when release was proven.

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';

import { createBlockConverterProtocol } from './block_converter_protocol.mjs';
import { WSL_DISTRO_RE } from './native_helper.mjs';
import { createWslProcessCustody } from './wsl_process_custody.mjs';

const LINUX_PATH_MAX = 4096;
const TOKEN_BYTES = 16;

export class BlockConverterOwnerError extends Error {
  constructor(code, message, detail = {}) {
    super(message);
    this.name = 'BlockConverterOwnerError';
    this.code = code;
    this.detail = Object.freeze({ ...detail });
  }
}

function fail(code, message, detail = {}) {
  return new BlockConverterOwnerError(code, message, detail);
}

function errorCode(error) {
  return typeof error?.code === 'string' ? error.code : 'unspecified_error';
}

function validateBinaryPath(value) {
  if (typeof value !== 'string' || value.length < 2 || value.length > LINUX_PATH_MAX
      || value[0] !== '/' || value.includes('\0') || value.includes('\n') || value.includes('\r')) {
    throw fail('bad_config', 'binaryPath must be a bounded absolute Linux path without control bytes');
  }
}

function validateRuntimeLibraryDir(value) {
  if (value === null || value === undefined) return;
  if (typeof value !== 'string' || value.length < 2 || value.length > LINUX_PATH_MAX
      || value[0] !== '/' || value.includes('\0') || value.includes('\n') || value.includes('\r')
      || value.includes(':')) {
    throw fail('bad_config', 'runtimeLibraryDir must be one bounded absolute Linux path without control bytes or path-list separators');
  }
  const segments = value.split('/').slice(1);
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw fail('bad_config', 'runtimeLibraryDir must use canonical absolute path segments');
  }
}

function validateDependencies(dependencies) {
  if (dependencies === null || typeof dependencies !== 'object' || Array.isArray(dependencies)) {
    throw fail('bad_config', 'dependencies must be an object');
  }
  const allowed = new Set(['spawnFn', 'randomBytesFn', 'protocolFactory', 'custodyFactory']);
  for (const [key, value] of Object.entries(dependencies)) {
    if (!allowed.has(key)) throw fail('bad_config', `unknown owner dependency ${key.slice(0, 40)}`);
    if (typeof value !== 'function') throw fail('bad_config', `${key} must be a function`);
  }
}

/**
 * Launch one converter and return its owner immediately.
 *
 * The immediate return is deliberate. If the asynchronous HELLO or parent-owned anchor fails, the
 * caller still retains the only object allowed to join cleanup. Await `owner.ready` before convert.
 * Dependency injection exists only so non-live tests can exercise every ownership edge without WSL.
 */
export function launchBlockConverterOwner({
  distro,
  binaryPath,
  runtimeLibraryDir = null,
  onFault = () => {},
  dependencies = {},
} = {}) {
  if (typeof distro !== 'string' || !WSL_DISTRO_RE.test(distro)) {
    throw fail('bad_config', 'distro must be one parent-pinned, space-free WSL distribution name');
  }
  validateBinaryPath(binaryPath);
  validateRuntimeLibraryDir(runtimeLibraryDir);
  if (typeof onFault !== 'function') throw fail('bad_config', 'onFault must be a function');
  validateDependencies(dependencies);

  const spawnFn = dependencies.spawnFn ?? spawn;
  const randomBytesFn = dependencies.randomBytesFn ?? randomBytes;
  const protocolFactory = dependencies.protocolFactory ?? createBlockConverterProtocol;
  const custodyFactory = dependencies.custodyFactory ?? createWslProcessCustody;

  let tokenBytes;
  try { tokenBytes = randomBytesFn(TOKEN_BYTES); } catch {
    throw fail('token_failed', 'the converter startup token could not be generated');
  }
  if (!Buffer.isBuffer(tokenBytes) || tokenBytes.length !== TOKEN_BYTES) {
    throw fail('token_failed', 'the converter startup token source did not return exactly 16 bytes');
  }
  const token = tokenBytes.toString('hex');
  const linuxArgv = Object.freeze([binaryPath, '--server', token]);
  // `env` replaces itself with the converter. Custody therefore still anchors the final Linux
  // process to linuxArgv, while `-i` prevents ambient LD_PRELOAD/LD_AUDIT/library search settings
  // from entering this security boundary. No shell parses any part of either path.
  const launchArgs = Object.freeze(runtimeLibraryDir === null
    ? ['-d', distro, '--exec', ...linuxArgv]
    : ['-d', distro, '--exec', '/usr/bin/env', '-i',
      `LD_LIBRARY_PATH=${runtimeLibraryDir}`, ...linuxArgv]);

  let child;
  try {
    child = spawnFn('wsl.exe', [...launchArgs], {
      stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false,
    });
  } catch {
    throw fail('spawn_failed', 'wsl.exe threw before returning an owned process handle');
  }
  if (child === null || typeof child !== 'object' || typeof child.once !== 'function'
      || typeof child.kill !== 'function') {
    throw fail('spawn_failed', 'wsl.exe did not return a usable owned process handle');
  }

  let wrapperClosed = child?.exitCode !== null || child?.signalCode !== null;
  let wrapperCloseInfo = wrapperClosed
    ? { code: child.exitCode, signal: child.signalCode }
    : null;
  let resolveWrapperClose;
  const wrapperClose = new Promise((resolve) => { resolveWrapperClose = resolve; });
  if (wrapperClosed) {
    resolveWrapperClose(wrapperCloseInfo);
  } else if (child !== null && typeof child === 'object' && typeof child.once === 'function') {
    child.once('close', (code, signal) => {
      wrapperClosed = true;
      wrapperCloseInfo = { code, signal };
      resolveWrapperClose(wrapperCloseInfo);
    });
  }

  let protocol = null;
  let protocolConstructionError = null;
  try {
    protocol = protocolFactory({ child, token, onFault });
  } catch (error) {
    protocolConstructionError = error;
  }

  let custody = null;
  let readyState = 'STARTING';
  let closing = false;
  let physicalReleased = false;
  let shutdownAnomaly = null;
  let closePromise = null;
  let closeOutcome = null;
  let protocolCloseAttempted = false;
  let protocolCloseError = null;
  let readinessError = protocolConstructionError;
  let api = null;

  const ready = (async () => {
    try {
      if (protocolConstructionError !== null) {
        throw fail('protocol_attach_failed', 'the protocol owner could not attach to the spawned child', {
          protocolCode: errorCode(protocolConstructionError),
        });
      }
      await protocol.ready;
      if (!Number.isSafeInteger(protocol.linuxPid) || protocol.linuxPid < 1) {
        throw fail('bad_linux_pid', 'the ready protocol did not expose a canonical Linux pid');
      }
      custody = custodyFactory({
        wrapperChild: child,
        distro,
        linuxPid: protocol.linuxPid,
        expectedLinuxArgv: linuxArgv,
      });
      await custody.anchor();
      readyState = closing ? 'CLOSING' : 'READY';
      return api;
    } catch (error) {
      readinessError = error;
      readyState = 'FAILED';
      throw error;
    }
  })();
  // A caller may choose to call close() without separately awaiting ready. Keep the rejected
  // readiness promise from becoming process-global noise; it still rejects for its consumer.
  ready.catch(() => {});

  async function waitWrapper(ms) {
    if (wrapperClosed) return true;
    let timer;
    const result = await Promise.race([
      wrapperClose.then(() => true),
      new Promise((resolve) => { timer = setTimeout(() => resolve(false), ms); }),
    ]).finally(() => clearTimeout(timer));
    return result;
  }

  async function boundedUnanchoredWrapperCleanup() {
    // This can reap only the exact Windows handle. It intentionally NEVER returns a physical Linux
    // release claim, even if EOF or a signal makes the wrapper close.
    try { child?.stdin?.end(); } catch { /* bounded exact-handle fallback below */ }
    if (await waitWrapper(250)) return;
    for (const signal of ['SIGTERM', 'SIGKILL']) {
      try { child?.kill?.(signal); } catch { /* the close join decides */ }
      if (await waitWrapper(1_000)) return;
    }
  }

  async function performClose() {
    api.beginClose('converter owner closing');
    try { await ready; } catch { /* readinessError is retained without secret-bearing text */ }

    if (!protocolCloseAttempted) {
      protocolCloseAttempted = true;
      if (protocol === null) {
        protocolCloseError = protocolConstructionError ?? fail('protocol_missing', 'protocol unavailable');
      } else {
        try { await protocol.close('converter owner closing'); } catch (error) { protocolCloseError = error; }
      }
    }

    let release = null;
    let releaseError = null;
    if (custody !== null) {
      try { release = await custody.release(); } catch (error) { releaseError = error; }
    } else {
      await boundedUnanchoredWrapperCleanup();
      releaseError = fail('custody_unavailable',
        'physical Linux release is unconfirmed because parent-owned custody was never anchored');
    }

    if (releaseError !== null) {
      readyState = 'RELEASE_UNCONFIRMED';
      throw fail('physical_release_unconfirmed',
        'the converter protocol stopped, but physical process release was not confirmed', {
          physicalReleaseConfirmed: false,
          readinessCode: readinessError === null ? null : errorCode(readinessError),
          protocolCode: protocolCloseError === null ? null : errorCode(protocolCloseError),
          releaseCode: errorCode(releaseError),
          wrapperExited: wrapperClosed,
        });
    }

    const outcome = Object.freeze({
      gracefulProtocolShutdown: protocolCloseError === null && readinessError === null,
      physicalReleaseConfirmed: release.physicalReleaseConfirmed === true,
      linuxObservation: release.linuxObservation,
      wrapperExited: release.wrapperExited === true,
      probesReaped: release.probesReaped === true,
    });
    physicalReleased = outcome.physicalReleaseConfirmed;
    readyState = 'CLOSED';
    if (protocolCloseError !== null || readinessError !== null) {
      shutdownAnomaly = [
        readinessError === null ? null : `readiness ${errorCode(readinessError)}`,
        protocolCloseError === null ? null : `protocol ${errorCode(protocolCloseError)}`,
      ].filter(Boolean).join('; ').slice(0, 400);
      throw fail('protocol_anomaly_after_release',
        'physical release was confirmed after a converter readiness or protocol anomaly', {
          physicalReleaseConfirmed: true,
          readinessCode: readinessError === null ? null : errorCode(readinessError),
          protocolCode: protocolCloseError === null ? null : errorCode(protocolCloseError),
          linuxObservation: release.linuxObservation,
        });
    }
    closeOutcome = outcome;
    return closeOutcome;
  }

  api = {
    get ready() { return ready; },
    get state() { return readyState; },
    get closing() { return closing; },
    get closed() { return physicalReleased; },
    get shutdownOutcome() {
      return {
        physicalReleaseConfirmed: physicalReleased,
        gracefulProtocolShutdown: physicalReleased && shutdownAnomaly === null,
        reason: shutdownAnomaly,
      };
    },
    get wrapperExited() { return wrapperClosed; },
    get wrapperExitInfo() { return wrapperCloseInfo === null ? null : { ...wrapperCloseInfo }; },
    async convert(fullHex) {
      await ready;
      if (closing || readyState !== 'READY') throw fail('closing', 'the converter owner is not accepting work');
      return await protocol.convert(fullHex);
    },
    beginClose(reason = 'converter owner closing') {
      if (closing) return;
      closing = true;
      if (readyState === 'STARTING' || readyState === 'READY') readyState = 'CLOSING';
      if (protocol !== null) {
        try { protocol.beginClose(reason); } catch { /* close() grades the protocol transcript */ }
      }
    },
    async close() {
      if (closeOutcome !== null) return closeOutcome;
      if (closePromise !== null) return await closePromise;
      closePromise = performClose();
      try {
        return await closePromise;
      } catch (error) {
        // A physically released process is terminal even when its protocol verdict is anomalous.
        // If release itself was unconfirmed, clear only the operation join so custody can retry.
        if (error?.detail?.physicalReleaseConfirmed !== true) closePromise = null;
        throw error;
      }
    },
    async forceClose(reason = 'converter owner force close') {
      api.beginClose(reason);
      return await api.close();
    },
  };

  return api;
}
