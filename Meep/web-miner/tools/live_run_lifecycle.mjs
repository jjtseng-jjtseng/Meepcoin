// THE ONE startup / cancellation / finalization boundary the live runners share
// (local_daemon_block.mjs and local_p2p_block.mjs). Everything with side effects is injected, so the
// signal races below are driven by tests against this exact code.
//
// WHY IT EXISTS. Each runner used to install SIGINT/SIGTERM handlers that ran cleanup and called
// process.exit() at once, while the main path could still be awaiting startDevPool(). During that
// await the pool's own ownership graph may already hold daemon A, or A and B, but the runner's `pool`
// variable was still null -- so the handler observed "nothing started", exited, and Node died before
// the pending startup could finish its transactional teardown. Two further defects: the startup was
// never handed an AbortSignal, and a failure to write the required evidence file was swallowed, so a
// run could exit 0 with nothing saved.
//
// THE RULES, each tested behaviourally (web-miner/tests/live_run_lifecycle.test.mjs):
//   * startPool() creates the AbortController BEFORE startup, passes its signal inside the trusted
//     realDaemon options, and stores the whole startup promise. `pool` is assigned in that promise's
//     own fulfilment handler, so no waiter can continue without it.
//   * A signal sets cancellation ONCE (repeats are ignored, never re-armed, and never fall through to
//     Node's default kill), aborts startup, and runs the runner's onCancel hook to unblock the body.
//     It does NOT clean up and does NOT exit.
//   * There is ONE terminal path, run()'s: await the body, then await the startup promise's
//     settlement -- a pool that fulfilled at the race boundary is closed; a startup that rejected has
//     already finished startDevPool's own transactional cleanup -- then close the pool, observe,
//     persist the evidence atomically, and call exit() exactly once.
//   * Exit status: the body's outcome; 130 / 143 if a SIGINT / SIGTERM cancelled the run; 3 if
//     physical release is unconfirmed (that wins over everything); and a required evidence file that
//     could not be persisted and verified turns an otherwise-successful 0 into 4 (it never lowers a
//     nonzero code).

import { createHash, randomBytes } from 'node:crypto';
import * as nodeFs from 'node:fs';
import { basename, dirname, join } from 'node:path';

export const EXIT_CODES = Object.freeze({
  OK: 0,
  FAILED: 1,
  USAGE: 2,
  RELEASE_UNCONFIRMED: 3,
  EVIDENCE_NOT_PERSISTED: 4,
  SIGINT: 130,
  SIGTERM: 143,
});

const bigintSafe = (k, v) => (typeof v === 'bigint' ? v.toString() : v);
const bounded = (v, n = 300) => String(v ?? '').slice(0, n);

export class RunCancelledError extends Error {
  constructor(signal) {
    super(`cancelled by ${signal}`);
    this.name = 'RunCancelledError';
    this.code = 'run_cancelled';
    this.signal = signal;
  }
}

/**
 * Persist one JSON document so that "saved" means saved.
 *
 * ALWAYS through a temporary sibling on the same directory: created exclusively, fully written,
 * flushed and closed BEFORE it is published under the final name. Only then is the final name
 * produced, and the result is REOPENED, length-checked, parsed, checked for the expected terminal
 * fields and compared byte-for-byte with what was written. Any failure returns { ok: false, stage }
 * -- it never throws -- and removes only this call's OWN temporary file.
 *
 * Two publication modes, and the temp sibling is what makes both safe:
 *
 *   default (legacy)  renameSync(temp, final). The final name is REPLACED atomically. Correct for a
 *                     path this run owns; a crash can never leave a half-written final file,
 *                     because the bytes were complete before the rename.
 *
 *   noReplace         linkSync(temp, final). A hard link is an ATOMIC EXCLUSIVE publish: it either
 *                     creates the final name or fails EEXIST, and it never truncates, opens or
 *                     replaces an existing file. EEXIST therefore means "somebody else holds that
 *                     name and their file is untouched", reported as stage 'exists'. The final name
 *                     is NEVER unlinked by this function -- not on failure, not on cleanup -- so a
 *                     replacement another actor published cannot be destroyed by our own tidying.
 *                     Only the temp is removed, always, whether or not the link succeeded.
 */
export function persistJsonAtomically(path, value, {
  expect = {},
  fs = nodeFs,
  suffix = () => randomBytes(6).toString('hex'),
  noReplace = false,
} = {}) {
  let text;
  try {
    text = JSON.stringify(value, bigintSafe, 2);
  } catch (err) {
    return { ok: false, stage: 'serialize', code: null, message: bounded(err?.message) };
  }
  const bytes = Buffer.from(text, 'utf8');
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.${suffix()}.tmp`);
  let stage = 'open';
  let fd = null;
  let tmpLives = false;                  // our own temporary file exists and is ours to remove
  try {
    fd = fs.openSync(tmp, 'wx');
    tmpLives = true;
    stage = 'write';
    let off = 0;
    while (off < bytes.length) {
      const n = fs.writeSync(fd, bytes, off, bytes.length - off);
      if (!Number.isInteger(n) || n <= 0) throw new Error('the write made no progress');
      off += n;
    }
    stage = 'flush';
    fs.fsyncSync(fd);
    stage = 'close';
    fs.closeSync(fd);
    fd = null;
    if (noReplace) {
      stage = 'link';
      fs.linkSync(tmp, path);            // atomic exclusive publish; EEXIST leaves theirs alone
      stage = 'cleanup_temp';
      try { fs.unlinkSync(tmp); } catch { /* the published link is what matters */ }
      tmpLives = false;
    } else {
      stage = 'rename';
      fs.renameSync(tmp, path);          // atomic replace of a path this run owns
      tmpLives = false;
    }
    stage = 'readback';
    const back = fs.readFileSync(path);
    if (back.length !== bytes.length) throw new Error(`read back ${back.length} of ${bytes.length} bytes`);
    stage = 'parse';
    const parsed = JSON.parse(back.toString('utf8'));
    stage = 'verify';
    for (const [key, want] of Object.entries(expect)) {
      if (JSON.stringify(parsed?.[key], bigintSafe) !== JSON.stringify(want, bigintSafe)) {
        throw new Error(`field ${key} did not read back as written`);
      }
    }
    if (!Buffer.from(back).equals(bytes)) throw new Error('the file read back differs from what was written');
    return { ok: true, path, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
  } catch (err) {
    if (fd !== null) { try { fs.closeSync(fd); } catch { /* already closed */ } }
    // ONLY OUR OWN TEMPORARY FILE. The final name is never unlinked here: in no-replace mode it may
    // be another actor's file or another actor's replacement of ours, and in replace mode it is the
    // published result. A partly written temp cannot be mistaken for evidence -- it was never
    // published under the final name.
    if (tmpLives) { try { fs.unlinkSync(tmp); } catch { /* already gone */ } }
    const code = typeof err?.code === 'string' ? err.code : null;
    return {
      ok: false,
      stage: noReplace && stage === 'link' && code === 'EEXIST' ? 'exists' : stage,
      code,
      message: bounded(err?.message),
    };
  }
}

/**
 * @param {object} o
 * @param {Function} o.startPool        startDevPool, or a test stand-in with the same contract
 * @param {(code:number) => void} o.exit called exactly once, at the very end
 * @param {Function} [o.persistEvidence] ({ exitCode, cancelledBy }) => { ok, ... } | null when nothing is required
 * @param {Function} [o.note]           (label, value) => void; diagnostics only, never on the critical path
 */
export function createRunLifecycle({ startPool, exit, persistEvidence = null, note = () => {} }) {
  if (typeof startPool !== 'function' || typeof exit !== 'function') {
    throw new TypeError('createRunLifecycle needs startPool and exit');
  }
  const startupAbort = new AbortController();
  let startup = null;
  let pool = null;
  let cancelledBy = null;
  const cancelHooks = [];
  let runPromise = null;
  let exited = false;

  const safeNote = (label, value) => { try { note(label, value); } catch { /* diagnostics only */ } };

  function cancel(signal) {
    if (cancelledBy !== null) return false;                    // once; a repeat changes nothing
    cancelledBy = signal;
    safeNote('SIGNAL', `${signal}: cancellation requested; the one finalization path will clean up`);
    try { startupAbort.abort(new RunCancelledError(signal)); } catch { /* already aborted */ }
    for (const fn of cancelHooks) {
      try {
        const r = fn(signal);
        if (r && typeof r.then === 'function') r.then(() => {}, () => {});
      } catch { /* a hook cannot stop cancellation */ }
    }
    return true;
  }

  const api = {
    get pool() { return pool; },
    get cancelledBy() { return cancelledBy; },
    get startupSignal() { return startupAbort.signal; },
    get startupPromise() { return startup; },

    /** Throws RunCancelledError once a signal has cancelled the run. For the body's own waits. */
    throwIfCancelled() {
      if (cancelledBy !== null) throw new RunCancelledError(cancelledBy);
    },

    /** The runner's way to unblock its body on a signal (kill the browser, close DevTools). */
    onCancel(fn) { cancelHooks.push(fn); },

    /** SIGINT/SIGTERM set cancellation once. `on`, not `once`: a second Ctrl-C must not kill Node. */
    installSignalHandlers(proc = process) {
      for (const sig of ['SIGINT', 'SIGTERM']) proc.on(sig, () => { cancel(sig); });
    },
    cancel,

    /**
     * Start THE pool. The startup AbortSignal is passed inside the trusted realDaemon options; the
     * pool is assigned in the fulfilment handler itself. A pool that fulfils after a signal is still
     * assigned -- the finalization path closes it -- and the body is told it was cancelled.
     */
    async startPool(options) {
      if (startup !== null) throw new Error('startPool may be called once');
      api.throwIfCancelled();
      const realDaemon = options?.realDaemon ? { ...options.realDaemon, signal: startupAbort.signal } : options?.realDaemon;
      startup = Promise.resolve()
        .then(() => startPool({ ...options, realDaemon }))
        .then((p) => { pool = p; return p; });
      startup.catch(() => {});                                   // owned below; never unhandled
      const p = await startup;
      api.throwIfCancelled();
      return p;
    },

    /**
     * THE ONE TERMINAL PATH.
     *
     * @param {Function} body  async (lifecycle) => exit code for the run's own outcome (0 or 1)
     * @param {object}   [h]
     * @param {Function} [h.beforePoolClose]  async () => void, e.g. stop the browser
     * @param {Function} [h.afterPoolClose]   async ({ poolShutdown, poolStarted }) => { released: boolean }
     * @param {Function} [h.onBodyError]      (err) => void
     */
    run(body, { beforePoolClose = async () => {}, afterPoolClose = async () => ({ released: true }), onBodyError = () => {} } = {}) {
      if (runPromise !== null) return runPromise;
      runPromise = (async () => {
        let code = EXIT_CODES.FAILED;
        try {
          const outcome = await body(api);
          code = Number.isInteger(outcome) ? outcome : EXIT_CODES.FAILED;
        } catch (err) {
          try { onBodyError(err); } catch { /* diagnostics only */ }
          code = EXIT_CODES.FAILED;
        }
        // The pending startup settles FIRST: fulfilled -> `pool` is assigned and closed below;
        // rejected -> startDevPool has already closed everything it owned.
        if (startup !== null) { try { await startup; } catch { /* its own cleanup already ran */ } }

        let released = false;
        const facts = { poolStarted: pool !== null, poolShutdown: null, poolListenerClosed: null };
        try {
          try { await beforePoolClose(); } catch (err) { safeNote('cleanup step failed', bounded(err?.message)); }
          if (pool !== null) {
            try {
              facts.poolShutdown = await pool.close();
            } catch (err) {
              facts.poolShutdown = { failed: bounded(err?.message), retained: (pool.retainedResources ?? []).map((r) => r.label) };
            }
            facts.poolListenerClosed = pool.httpServer?.listening === false;
          }
          const poolReleased = pool === null
            || (facts.poolShutdown?.ok === true && facts.poolShutdown?.physicalReleaseConfirmed === true
              && facts.poolListenerClosed === true);
          const after = await afterPoolClose(facts);
          released = poolReleased && after?.released === true;
          // A runner may discover during final read-only observation that its provisional body
          // success was not actually proved. It can demote 0 to 1; it cannot erase a prior failure.
          if (code === EXIT_CODES.OK && after?.outcomeCode === EXIT_CODES.FAILED) {
            code = EXIT_CODES.FAILED;
          }
        } catch (err) {
          safeNote('cleanup failed', bounded(err?.message));
          released = false;
        }
        facts.released = released;

        if (cancelledBy === 'SIGINT') code = EXIT_CODES.SIGINT;
        else if (cancelledBy === 'SIGTERM') code = EXIT_CODES.SIGTERM;
        if (!released) code = EXIT_CODES.RELEASE_UNCONFIRMED;

        let persisted = null;
        if (typeof persistEvidence === 'function') {
          try {
            persisted = await persistEvidence({ exitCode: code, cancelledBy, cleanup: facts });
          } catch (err) {
            persisted = { ok: false, stage: 'persist', message: bounded(err?.message) };
          }
          if (persisted !== null && persisted.ok !== true && code === EXIT_CODES.OK) code = EXIT_CODES.EVIDENCE_NOT_PERSISTED;
        }
        safeNote('FINAL', { exitCode: code, cancelledBy, released, evidence: persisted });
        if (!exited) {
          exited = true;
          exit(code);
        }
        return { code, released, cancelledBy, persisted, facts };
      })();
      return runPromise;
    },
  };
  return api;
}
