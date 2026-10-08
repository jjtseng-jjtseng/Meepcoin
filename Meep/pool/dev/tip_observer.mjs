// THE DAEMON-A CANONICAL TIP OBSERVER: the one piece a sustained browser sequence was missing.
//
// pool.notifyCanonicalTip() and sim_session's handleExternalTip() already do the right thing when
// somebody TELLS the pool that another miner took the height this browser is searching. Until now
// nothing ever told it: web-miner/tools/local_p2p_block.mjs said so in its own transcript. This file
// closes that gap and nothing else. It is a small bounded poller with exactly one job: notice, from
// daemon A's own strict RPC readback, that A's canonical tip is no longer the parent of the job this
// session is working on, and hand that ONE observation to the existing trusted seam.
//
// WHAT IT IS NOT. Not a second source of truth: the only thing it reads is daemon A's
// get_last_block_header through the same validated adapter every other read uses, and the only thing
// it does with the answer is call the trusted seam, which re-proves the tip on A before issuing
// anything. Not a monitor, scheduler, retry engine or queue: one timer, one in-flight read, no
// backlog, no history beyond the last observation it acted on. Not reachable from a browser: it is
// constructed by the server from server-side collaborators, and no client message can start it, stop
// it, change its interval or feed it a tip.
//
// THE RULES IT APPLIES, ALL BEFORE THE SEAM IS TOUCHED
//
//   idle    the session has no live consented run -> nothing is read at all;
//   busy    a candidate is in flight, a block was just accepted, or a rotation is running -> skip
//           this cycle entirely. This is what keeps the observer out of the OWN-BLOCK path: while
//           this session's own submission is settling, the observer does not look at the tip;
//   own     at or above the job height, a block this session produced is inert: the acceptance and
//           readback path owns that transition. Below the job height, exact-parent continuity wins;
//   parent  the tip is the exact parent named by the issued template -> inert. A different block at
//           that height, or a rollback below it, proves the template stale and stops fail-closed;
//   dup     the same tip already produced an observation for this same job -> inert;
//   act     otherwise the tip is at or above the current job's height, which means the height this
//           browser is searching is (or is already past being) taken. ONE call to the seam. The
//           session decides: an exact competing height rotates, a tip ahead ends the run fail-closed.
//
// FAILURE IS TERMINAL, NOT SWALLOWED. A read that throws, or an answer that is not a well-formed
// height and block id, stops the observer and ends the attempt through the failure hook. A browser
// that cannot be told the chain moved must not keep hashing.

/** The closed failure this observer can cause. Also listed in the shared protocol vocabulary. */
export const TIP_OBSERVATION_FAILED = 'tip_observation_failed';
/** The daemon was readable, but the issued template's exact parent is no longer canonical. */
export const TIP_PARENT_CHANGED = 'canonical_parent_changed';

/** How often A's tip is read while a run is live. Small, fixed, and not reachable from a page. */
export const TIP_OBSERVER_DEFAULT_INTERVAL_MS = 2_000;

const HEX64 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]{0,19})$/;

/**
 * @param {object} o
 * @param {() => Promise<{height:string, blockId:string}>} o.readTip   daemon A's strict readback
 * @param {() => object} o.state    { active, busy, jobId, jobHeight, parentBlockId,
 *                                   isOwnBlock } of the live run
 * @param {(tip:object) => Promise<object>} o.notify   the TRUSTED canonical-tip seam
 * @param {(code:string, detail:string) => void} o.onFailure           ends the attempt, fail-closed
 */
export function createTipObserver({
  readTip,
  state,
  notify,
  onFailure = () => {},
  intervalMs = TIP_OBSERVER_DEFAULT_INTERVAL_MS,
  setTimer = (fn, ms) => { const t = setTimeout(fn, ms); t.unref?.(); return t; },
  clearTimer = (t) => clearTimeout(t),
  label = 'daemon A tip observer',
} = {}) {
  if (typeof readTip !== 'function' || typeof state !== 'function' || typeof notify !== 'function') {
    throw new TypeError('createTipObserver needs readTip, state and notify');
  }
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 1 || intervalMs > 60_000) {
    throw new TypeError('intervalMs must be an integer from 1 to 60000');
  }

  // GENERATION IS THE ONLY DEFENCE AGAINST A LATE CALLBACK. Every stop and every close bumps it, so
  // a read that resolves after the observer was stopped cannot schedule, notify or fail anything.
  let generation = 0;
  let timer = null;
  let running = false;
  let closing = false;
  let closed = false;
  let cycling = false;
  let activeCycle = null;
  let closePromise = null;
  // The last observation that reached the seam: one record, replaced, never appended to.
  let acted = null;                 // { blockId, jobId }
  let lastSkip = null;              // a bounded reason string, for diagnostics only
  const counts = { cycles: 0, reads: 0, idle: 0, busy: 0, own: 0, behind: 0, duplicate: 0, notified: 0, failures: 0 };

  function schedule() {
    if (!running || closed || timer !== null) return;
    const gen = generation;
    // The callback RETURNS the cycle promise. Production ignores it (setTimeout does), and an
    // injected timer in a non-live test can await exactly one cycle instead of racing it.
    timer = setTimer(() => {
      timer = null;
      if (gen !== generation || !running || closing || closed) return undefined;
      const launched = cycle(gen);
      activeCycle = launched;
      // Keep the exact in-flight operation reachable so close() can join it. The rejection handler
      // also prevents a test collaborator throwing outside the observer's normal failure paths from
      // becoming an unhandled rejection; cycle() itself converts it to the closed failure below.
      launched.finally(() => {
        if (activeCycle === launched) activeCycle = null;
      }).catch(() => {});
      return launched;
    }, intervalMs);
  }

  function skip(reason) {
    lastSkip = reason;
    counts[reason] = (counts[reason] ?? 0) + 1;
  }

  function fail(detail, gen = generation, code = TIP_OBSERVATION_FAILED) {
    if (gen !== generation || !running || closing || closed) return false;
    counts.failures += 1;
    stop(code);
    try { onFailure(code, String(detail ?? '').slice(0, 240)); } catch { /* the attempt is already ending */ }
    return true;
  }

  async function cycle(gen) {
    if (gen !== generation || !running || closing || closed || cycling) return;
    cycling = true;
    try {
      counts.cycles += 1;
      const st = state() ?? {};
      if (st.active !== true) {
        // The run is over, or was never consented to. Nothing is read, and the observer stops
        // itself rather than idling against a daemon for the rest of the process's life.
        skip('idle');
        stop('no_live_run');
        return;
      }
      if (st.busy === true) { skip('busy'); return; }
      const jobId = st.jobId;
      const jobHeight = st.jobHeight;
      const parentBlockId = st.parentBlockId;
      if (typeof jobId !== 'string' || typeof jobHeight !== 'string' || !DECIMAL.test(jobHeight)
        || BigInt(jobHeight) < 1n || typeof parentBlockId !== 'string' || !HEX64.test(parentBlockId)) {
        fail('the live run did not describe its own job and exact parent', gen);
        return;
      }

      counts.reads += 1;
      let tip;
      try {
        tip = await readTip();
      } catch (err) {
        fail(`daemon A tip read failed: ${err?.code ?? err?.message ?? err}`, gen);
        return;
      }
      if (gen !== generation || !running || closing || closed) return; // stopped while the read was in flight

      const height = typeof tip?.height === 'string' ? tip.height : null;
      const blockId = typeof tip?.blockId === 'string' ? tip.blockId : null;
      if (height === null || blockId === null || !DECIMAL.test(height) || !HEX64.test(blockId)) {
        fail('daemon A reported a malformed canonical tip', gen);
        return;
      }

      // The job may have rotated while the read was in flight: this observation describes a state
      // that is already gone, and acting on it would rotate twice for one event.
      const after = state() ?? {};
      if (after.active !== true) { skip('idle'); stop('no_live_run'); return; }
      if (after.jobId !== jobId || after.jobHeight !== jobHeight
        || after.parentBlockId !== parentBlockId) { skip('duplicate'); return; }
      if (after.busy === true) { skip('busy'); return; }

      const tipHeight = BigInt(height);
      const wantedHeight = BigInt(jobHeight);
      if (tipHeight < wantedHeight) {
        // Only the exact parent named by the issued template is ordinary. A different block at the
        // parent height, or a rollback below it, means this template is stale. Refreshing a template
        // at the same height would require a larger state-machine design, so this bounded slice stops
        // fail-closed instead of guessing.
        if (tipHeight === wantedHeight - 1n && blockId === parentBlockId) { skip('behind'); return; }
        fail('daemon A canonical tip no longer matches the issued template parent', gen, TIP_PARENT_CHANGED);
        return;
      }
      // Own-block identity is relevant only at or above the job height. Below it, exact parent
      // continuity wins: a rollback to one of this session's older blocks still makes the issued
      // template stale and must not be hidden by the bounded own-block memory.
      if (typeof after.isOwnBlock === 'function' && after.isOwnBlock(blockId) === true) { skip('own'); return; }
      if (acted !== null && acted.blockId === blockId && acted.jobId === jobId) { skip('duplicate'); return; }

      acted = Object.freeze({ blockId, jobId });
      counts.notified += 1;
      try {
        const result = await notify({ height, blockId });
        if (gen !== generation || !running || closing || closed) return;
        if (result?.ok !== true) {
          // A concurrent accepted-block rotation or terminal transition can make the seam refuse an
          // observation that was valid when its read began. Re-read the binding: changed/busy/ended
          // is a benign race; an unchanged live job refusing its own trusted observation is not.
          const latest = state() ?? {};
          if (latest.active !== true) return;
          if (latest.jobId !== jobId || latest.jobHeight !== jobHeight
            || latest.parentBlockId !== parentBlockId || latest.busy === true) {
            skip('duplicate');
            return;
          }
          fail(`the canonical-tip seam refused the observation: ${result?.reason ?? 'unknown refusal'}`, gen);
        }
      } catch (err) {
        fail(`the canonical-tip seam refused the observation: ${err?.message ?? err}`, gen);
      }
    } catch (err) {
      fail(`tip observer cycle failed: ${err?.message ?? err}`, gen);
    } finally {
      cycling = false;
      try {
        schedule();
      } catch (err) {
        // Start-time scheduling is guarded above, but every completed cycle also re-arms the one
        // timer. Losing that later timer must be just as terminal: otherwise `running` would remain
        // true while the browser hashes forever with no canonical-tip observation.
        fail(`tip observer could not reschedule: ${err?.message ?? err}`, gen);
      }
    }
  }

  function stop(reason = 'stopped') {
    if (!running) return false;
    running = false;
    generation += 1;                  // every in-flight read and pending timer is now inert
    if (timer !== null) { try { clearTimer(timer); } catch { /* already fired */ } timer = null; }
    lastSkip = String(reason).slice(0, 64);
    return true;
  }

  function closeObserver(reason = 'pool shutting down') {
    if (closed) return Promise.resolve();
    if (closePromise !== null) return closePromise;
    closing = true;
    stop(reason);
    const pending = activeCycle;
    closePromise = (async () => {
      if (pending !== null) await Promise.allSettled([pending]);
      closed = true;
    })();
    return closePromise;
  }

  return {
    label,
    /** Called when, and only when, an explicit Start has reserved the one attempt. */
    start() {
      if (closing || closed || running) return false;
      running = true;
      generation += 1;
      try {
        schedule();
      } catch (err) {
        fail(`tip observer could not schedule: ${err?.message ?? err}`, generation);
        return false;
      }
      return true;
    },
    stop,
    get running() { return running; },
    get closed() { return closed; },
    get closing() { return closing; },

    // ---- the verifier-shaped resource protocol, so the pool's ownership graph owns it ----------
    beginClose(reason = 'pool shutting down') { closing = true; stop(reason); },
    close: closeObserver,
    forceClose(reason = 'pool shutdown escalation') {
      // The loopback RPC itself has a finite transport deadline. There is no unsafe way to abandon
      // the promise while calling it physically released, so escalation joins the same bounded close.
      return closeObserver(reason);
    },
    get shutdownOutcome() {
      // A poller holds no child process and no protocol: releasing it is just not polling again.
      return { physicalReleaseConfirmed: closed, gracefulProtocolShutdown: true, reason: null };
    },

    /** Sizes and counters only. Every number below is bounded by the run, not by its length. */
    get stateFacts() {
      return Object.freeze({
        running, closing, closed, cycling,
        timers: timer === null ? 0 : 1,
        activeCycles: activeCycle === null ? 0 : 1,
        actedRecords: acted === null ? 0 : 1,
        lastSkip,
        intervalMs,
        counts: Object.freeze({ ...counts }),
      });
    },
  };
}
