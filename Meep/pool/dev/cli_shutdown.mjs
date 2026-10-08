// The command-line pool's shutdown controller.
//
// Factored out of run.mjs so it can be tested directly. A launcher that cannot honestly handle a
// failed close is not a small problem: `void pool.close()` with no catch turns a retained child
// process into an unhandled rejection, prints nothing useful, and exits as though everything had
// been cleaned up.
//
// THE RULES THIS ENCODES:
//
//   * Signals are SINGLE-FLIGHT. A second Ctrl-C during a shutdown joins the one already running;
//     it never starts a second teardown racing the first over the same child.
//   * A failed close is REPORTED, with the resources that are still owned, and retried a bounded
//     number of times.
//   * The process NEVER exits 0 while a resource is unconfirmed. Exiting would orphan exactly the
//     child we could not confirm was gone, and print success over it.
//   * If retries are exhausted the owner STAYS ALIVE, says precisely what is still held, and
//     accepts another signal as an explicit request to try again.

export const SHUTDOWN_DEFAULTS = Object.freeze({
  maxRetriesPerSignal: 2,
  retryDelayMs: 500,
});

/**
 * Everything was released, but the helper's QUIT/BYE/exit transcript was not canonical.
 *
 * Distinct from 0 (clean) and from staying alive (something is still owned). The process MAY exit
 * -- it owns nothing -- but it must not report success: an abnormal goodbye used to reach the user
 * as exit code 0 with nothing printed at all, because the anomaly existed only as an event handed
 * to a logger the CLI never installs.
 */
export const EXIT_PROTOCOL_ANOMALY = 3;

function activitySummary(pool) {
  if (pool?.mode === 'real-local-daemon') {
    const state = pool.simulation?.attemptState ?? 'unavailable';
    const reason = pool.simulation?.attemptReason;
    if (state === 'terminal_complete' && reason === 'complete') {
      return 'private block attempt complete (accepted with canonical readback)';
    }
    return `private block attempt ${state}${reason ? ` (reason ${reason})` : ''}`;
  }
  return `accepted ${pool.stats.accepted}, rejected ${pool.stats.rejected}`;
}

/**
 * @param {object} o
 * @param {{close:Function, retryClose:Function, retainedResources:any[], stats:object}} o.pool
 * @param {(text:string)=>void} [o.log]
 * @param {(text:string)=>void} [o.error]
 * @param {(code:number)=>void} [o.exit]
 * @param {(ms:number)=>Promise<void>} [o.wait]
 */
export function createShutdownController({
  pool,
  log = (t) => console.log(t),
  error = (t) => console.error(t),
  exit = (code) => process.exit(code),
  wait = (ms) => new Promise((r) => { setTimeout(r, ms).unref?.(); }),
  maxRetriesPerSignal = SHUTDOWN_DEFAULTS.maxRetriesPerSignal,
  retryDelayMs = SHUTDOWN_DEFAULTS.retryDelayMs,
} = {}) {
  let inFlight = null;
  let signalCount = 0;
  let attempts = 0;
  let lastFailure = null;

  function retained() {
    // A pool that predates `retainedResources` still answers `retainedVerifier`.
    if (Array.isArray(pool.retainedResources)) return pool.retainedResources;
    return pool.retainedVerifier ? [{ label: 'verifier', resource: pool.retainedVerifier }] : [];
  }

  function reportRetained() {
    const held = retained();
    if (held.length === 0) return;
    error(`  still owned: ${held.map((h) => h.label).join(', ')}`);
    const pid = held.find((h) => h.resource?.helperLinuxPid != null)?.resource.helperLinuxPid;
    if (pid != null) error(`  native helper Linux pid ${pid} was NOT confirmed gone`);
  }

  let anomalies = [];

  async function runOnce(isRetry) {
    attempts++;
    try {
      const result = await (isRetry ? pool.retryClose() : pool.close());
      lastFailure = null;
      // A structured result carries the abnormal-but-released facts. A pool that predates it
      // simply resolves with undefined, which is "nothing to report".
      anomalies = Array.isArray(result?.protocolAnomalies) ? result.protocolAnomalies : [];
      return true;
    } catch (err) {
      lastFailure = err;
      return false;
    }
  }

  async function drive(signal) {
    log(`\n${signal}: shutting down (${activitySummary(pool)})`);
    let ok = await runOnce(false);
    for (let retry = 0; !ok && retry < maxRetriesPerSignal; retry++) {
      error(`shutdown could not be confirmed: ${lastFailure?.message ?? lastFailure}`);
      reportRetained();
      error(`retrying (${retry + 1}/${maxRetriesPerSignal})...`);
      await wait(retryDelayMs);
      ok = await runOnce(true);
    }

    if (ok && retained().length === 0) {
      if (anomalies.length > 0) {
        // Released, so exiting orphans nothing -- but this was not a clean shutdown and must not
        // be reported as one.
        error('\nSHUTDOWN COMPLETED, BUT THE HELPER GOODBYE WAS ABNORMAL.');
        for (const a of anomalies) error(`  ${a.label}: ${a.reason}`);
        error('  Every process was released, so nothing is orphaned; the exchange itself was wrong.');
        error(`  Exiting ${EXIT_PROTOCOL_ANOMALY} rather than 0.\n`);
        exit(EXIT_PROTOCOL_ANOMALY);
        return true;
      }
      exit(0);
      return true;
    }

    // NOT exiting is the honest outcome. The process owns something whose release could not be
    // confirmed; exiting would orphan it and report success over it.
    error('\nSHUTDOWN INCOMPLETE. This process is staying alive on purpose.');
    error(`  reason: ${lastFailure?.message ?? 'a resource never confirmed release'}`);
    reportRetained();
    error('  Exiting now would orphan it and print success over a process nobody is holding.');
    error('  Send the signal again to retry, or investigate the resource above first.\n');
    return false;
  }

  return {
    /** Single-flight. A signal arriving during a shutdown joins it rather than racing it. */
    requestShutdown(signal = 'SIGINT') {
      signalCount++;
      if (inFlight) {
        log(`${signal}: shutdown already in progress; waiting for it rather than starting a second`);
        return inFlight;
      }
      inFlight = drive(signal).finally(() => { inFlight = null; });
      inFlight.catch(() => {});
      return inFlight;
    },
    get running() { return inFlight !== null; },
    get signalCount() { return signalCount; },
    get attempts() { return attempts; },
    get lastFailure() { return lastFailure; },
    /** Abnormal-but-released shutdown facts from the last attempt. */
    get protocolAnomalies() { return anomalies.map((a) => ({ ...a })); },
  };
}
