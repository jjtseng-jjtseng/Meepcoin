// DOM wiring for the MeepCoin local browser miner. This file contains no mining logic and no
// protocol logic: it owns the buttons and the readouts, and hands everything else to
// lib/controller.js. Keeping it this thin is what lets the voluntary-mining rules be tested
// without a browser.
//
// Nothing here runs mining on load. The only call to controller.start() is inside the Start
// button's click handler.

import { createMiningController, STATES } from './lib/controller.js';
import {
  REAL_DAEMON_MODE, REAL_REFRESH_LIMITS, REAL_SEARCH_LIMITS, RECORDED_SIMULATION_MODE, selectModeView,
} from './lib/shared/protocol.js';

/** The frozen per-window bounds, written once, in the page's own words. */
const WINDOW_BOUND_TEXT = `${REAL_SEARCH_LIMITS.maxAttempts.toLocaleString('en-US')} nonces or `
  + `${REAL_SEARCH_LIMITS.maxSearchMs / 1000} seconds`;

/**
 * WHAT THIS START MAY ACTUALLY DO, said from the numbers the server declared and this build's own
 * frozen bounds -- never from a sentence written for a different mode.
 *
 * One window is one window. A refresh run may search several windows of the SAME height, so its
 * prospective bound is the per-window bound AND the whole-session budget, and the status must say
 * which window it is on. Everything here is a pure function of the snapshot, so it can be checked
 * without a browser.
 */
export function realProspectiveBoundsText(s) {
  const windows = Number.isSafeInteger(s.realWindowTotal) ? s.realWindowTotal : 1;
  if (windows <= 1) return `at most ${WINDOW_BOUND_TEXT}`;
  const blocks = Number.isSafeInteger(s.realSequenceTotal) ? s.realSequenceTotal : 1;
  const minutes = REAL_REFRESH_LIMITS.maxSessionMs / 60_000;
  if (blocks > 1) {
    return `each window at most ${WINDOW_BOUND_TEXT}, at most ${windows} windows per block across `
      + `${blocks} blocks, and at most ${minutes} minutes for the whole Start`;
  }
  return `each window at most ${WINDOW_BOUND_TEXT}, at most ${windows} windows of this one height, `
    + `and at most ${minutes} minutes for the whole session`;
}

/**
 * WHERE THIS START IS, AND WHETHER ANYTHING IS ACTUALLY HASHING.
 *
 * The server may have ISSUED the next window while the browser worker still holds the previous
 * context. The ACTIVE window is the one the Worker's live context was built for; the issued one is
 * only what the server has prepared. The handover has two phases and the words must not blur them:
 * while the old context is still RETIRING (its search has not settled) the page says so and claims
 * only that no NEW-window hashing has begun; once it has settled, the page may say that nothing is
 * being hashed at all until the rotated readiness makes the next window active.
 */
export function realWindowPositionText(s) {
  const windows = Number.isSafeInteger(s.realWindowTotal) ? s.realWindowTotal : 1;
  if (windows <= 1) return null;
  const blocks = Number.isSafeInteger(s.realSequenceTotal) ? s.realSequenceTotal : 1;
  const issued = Number.isSafeInteger(s.realWindowIndex) ? s.realWindowIndex : 1;
  const active = Number.isSafeInteger(s.realActiveWindowIndex) ? s.realActiveWindowIndex : 1;
  const issuedBlock = Number.isSafeInteger(s.realBlockIndex) ? s.realBlockIndex : 1;
  const activeBlock = Number.isSafeInteger(s.realActiveBlockIndex) ? s.realActiveBlockIndex : 1;
  if (blocks > 1) {
    if (s.realWindowHandoff === true || issued !== active || issuedBlock !== activeBlock) {
      return s.realWindowRetiring === true
        ? `block ${activeBlock} of ${blocks}, window ${active} of ${windows} retiring; preparing block ${issuedBlock} of ${blocks}, window ${issued} of ${windows}`
        : `block ${activeBlock} of ${blocks}, window ${active} of ${windows} searched; preparing block ${issuedBlock} of ${blocks}, window ${issued} of ${windows}`;
    }
    return `block ${activeBlock} of ${blocks}, window ${active} of ${windows}`;
  }
  if (s.realWindowHandoff === true || issued !== active) {
    return s.realWindowRetiring === true
      ? `window ${active} of ${windows} retiring; preparing window ${issued} (same block height)`
      : `window ${active} of ${windows} searched; preparing window ${issued} (same block height)`;
  }
  return `window ${active} of ${windows} (same block height)`;
}

/** True while the server has issued a window the browser worker has not been given yet. */
export function realWindowHandoff(s) {
  const windows = Number.isSafeInteger(s.realWindowTotal) ? s.realWindowTotal : 1;
  if (windows <= 1) return false;
  const issued = Number.isSafeInteger(s.realWindowIndex) ? s.realWindowIndex : 1;
  const active = Number.isSafeInteger(s.realActiveWindowIndex) ? s.realActiveWindowIndex : 1;
  const issuedBlock = Number.isSafeInteger(s.realBlockIndex) ? s.realBlockIndex : 1;
  const activeBlock = Number.isSafeInteger(s.realActiveBlockIndex) ? s.realActiveBlockIndex : 1;
  return s.realWindowHandoff === true || issued !== active || issuedBlock !== activeBlock;
}

const $ = (id) => document.getElementById(id);

const els = {
  start: $('start-btn'),
  pace: $('search-pace'),
  paceWrap: $('search-pace-wrap'),
  stop: $('stop-btn'),
  note: $('controls-note'),
  state: $('state'),
  connection: $('connection'),
  jobId: $('job-id'),
  algorithm: $('algorithm'),
  hashes: $('hashes'),
  hps: $('hps'),
  accepted: $('accepted'),
  rejected: $('rejected'),
  rejectReason: $('reject-reason'),
  heap: $('heap'),
  serverHeap: $('server-heap'),
  serverNative: $('server-native'),
  verifierMode: $('verifier-mode'),
  error: $('error'),
  batch: $('batch-size'),
  destOrigin: $('dest-origin'),
  footerOrigin: $('footer-origin'),
  // Exactly one of these three is shown at a time, decided by selectModeView().
  connectingNote: $('connecting-note'),
  syntheticConsent: $('synthetic-consent'),
  footerSynthetic: $('footer-synthetic'),
  footerSimulation: $('footer-simulation'),
  // Recorded-template simulation. Hidden until the SERVER says it is in that mode.
  simBanner: $('sim-banner'),
  simLabels: $('sim-labels'),
  simNotice: $('sim-notice'),
  simAllocate: $('sim-allocate'),
  simHeight: $('sim-height'),
  simNonce: $('sim-nonce'),
  simBrowserHash: $('sim-browser-hash'),
  simServerHash: $('sim-server-hash'),
  simExpectedHash: $('sim-expected-hash'),
  simCounters: $('sim-counters'),
  simHashCounts: $('sim-hash-counts'),
  simNativeAlloc: $('sim-native-alloc'),
  // Real local daemon. Hidden until the SERVER says it is in that mode.
  realBanner: $('real-banner'),
  realLabels: $('real-labels'),
  realNotice: $('real-notice'),
  realAllocate: $('real-allocate'),
  realHeight: $('real-height'),
  realWindow: $('real-window'),
  realSearched: $('real-searched'),
  realFoundNonce: $('real-found-nonce'),
  realBrowserHash: $('real-browser-hash'),
  realServerHash: $('real-server-hash'),
  realBlockId: $('real-block-id'),
  realOutcome: $('real-outcome'),
  realSequence: $('real-sequence'),
  realBlocks: $('real-blocks'),
  realTotalAttempts: $('real-total-attempts'),
  realWorkers: $('real-workers'),
  realCounters: $('real-counters'),
  footerNoDaemon: $('footer-no-daemon'),
  footerReal: $('footer-real'),
  footerNoRewards: $('footer-no-rewards'),
  footerRealRewards: $('footer-real-rewards'),
};

const DASH = '—';

function mib(bytes) {
  return `${(bytes / 1048576).toFixed(1)} MiB`;
}

const VERIFIER_MODE_TEXT = {
  dual: 'two independent builds must agree byte-for-byte',
  wasm: 'single build (WebAssembly only) — no cross-check',
};

const STATE_TEXT = {
  [STATES.IDLE]: 'idle',
  [STATES.STARTING]: 'starting — waiting for the local pool to load its verifier',
  [STATES.MINING]: 'mining',
  [STATES.STOPPED]: 'stopped',
  [STATES.STOPPED_HIDDEN]: 'stopped because the tab was hidden',
  [STATES.ERROR]: 'error',
};

const controller = createMiningController({
  // One dedicated module Web Worker, constructed here and nowhere else. Reached only from
  // controller.start(), which is reached only from the Start click handler below.
  createWorker: () => new Worker('/worker.js', { type: 'module', name: 'meep-miner' }),
  createSocket: (url) => new WebSocket(url),
  onChange: render,
});

/**
 * Show the copy for the mode the SERVER declared, and nothing else.
 *
 * Before server_hello the mode is unknown, and the synthetic consent panel was previously visible
 * in that window -- and in simulation mode it stayed visible, stating a synthetic job, accepted
 * shares, two independently built copies, a native child process, a four-hash batch and "press
 * Start again for another run", none of which is true there.
 */
function renderModeView(s) {
  const view = selectModeView(s.mode);
  els.connectingNote.hidden = !view.showConnecting;
  els.syntheticConsent.hidden = !view.showSynthetic;
  els.simBanner.hidden = !view.showSimulation;
  els.footerSynthetic.hidden = !view.showSynthetic;
  els.footerSimulation.hidden = !view.showSimulation;
  els.realBanner.hidden = view.showRealDaemon !== true;
  els.footerReal.hidden = view.showRealDaemon !== true;
  els.footerNoDaemon.hidden = view.showRealDaemon === true;
  // "No rewards" is true of the synthetic and replay modes and false of a real private chain, whose
  // accepted block pays a coinbase to a destination the local operator fixed before this page loaded.
  els.footerRealRewards.hidden = view.showRealDaemon !== true;
  els.footerNoRewards.hidden = view.showRealDaemon === true;
}

const realSequenceCompleteText = (count) => `${count} blocks accepted by node A (canonical readback matched) and shown by node B`;

/** Scope shared by fixed-target and daemon-selected private sequences. */
export function realSequenceSuccessNote(count) {
  return `Node A accepted ${count} consecutive blocks found by this browser, each confirmed by its canonical readback, `
    + 'and node B shows them. One Start, one browser worker. Test coins only, private local nodes; '
    + 'this does not establish public-network mining or a final difficulty policy. Restart the local server to try again.';
}

const REAL_OUTCOME_TEXT = {
  block_accepted: 'block accepted by the private daemon (canonical readback matched)',
  bounded_no_solution: 'BOUNDED_NO_SOLUTION: no block-quality nonce before the preset search limit',
  other_browser_won: 'the other browser claimed the single permitted block submission',
  failed: 'did not succeed',
  stopped: 'stopped',
};

/** The real-daemon readouts. Every value comes from the server or this page's own Worker. */
function renderRealDaemon(s) {
  if (s.mode !== REAL_DAEMON_MODE) return;
  if (s.simLabels && els.realLabels.childElementCount === 0) {
    for (const label of s.simLabels) {
      const li = document.createElement('li');
      li.textContent = label;
      els.realLabels.append(li);
    }
  }
  const job = controller.realJob;
  els.realNotice.textContent = s.simNotice ?? '';
  els.realAllocate.textContent = s.simAllocateNotice ?? '';
  els.realHeight.textContent = s.simHeight ?? DASH;
  // THE WINDOW THE WORKER IS ACTUALLY ON. During a handover the server's newest job is not the one
  // any context holds, and showing its range would claim work that has not started.
  const activeJob = controller.activeRealJob ?? job;
  els.realWindow.textContent = activeJob
    ? `[${activeJob.nonceStart}, ${activeJob.nonceStart + activeJob.nonceRange})`
    : DASH;
  els.realSearched.textContent = String(s.hashes);
  els.realFoundNonce.textContent = s.realFoundNonce === null ? DASH : String(s.realFoundNonce);
  els.realBrowserHash.textContent = s.simBrowserHashHexLE ?? DASH;
  els.realServerHash.textContent = s.simVerifiedHashHexLE ?? DASH;
  els.realBlockId.textContent = s.realBlockId ?? DASH;
  const sequence = s.realSequenceTotal > 1;
  const windowPosition = realWindowPositionText(s);
  els.realOutcome.textContent = s.realOutcome
    ? `${sequence && s.realSequenceComplete ? realSequenceCompleteText(s.realSequenceTotal) : (REAL_OUTCOME_TEXT[s.realOutcome] ?? s.realOutcome)}`
      + `${s.simFailureCode ? ` (${s.simFailureCode})` : ''}${sequence && !s.realSequenceComplete && s.realOutcome !== 'block_accepted' ? ` at height ${s.simHeight ?? DASH}` : ''}`
    : DASH;
  // WHERE THIS START IS. A sequence counts BLOCKS; a same-height refresh counts WINDOWS of one
  // block, and saying so is the difference between "we are on block 2" and "we are still on block 1".
  els.realSequence.textContent = windowPosition ?? (sequence
    ? `block ${s.realBlockIndex} of ${s.realSequenceTotal}`
    : DASH);
  els.realBlocks.textContent = s.realBlocks.length > 0
    ? s.realBlocks.map((b) => `height ${b.height}: nonce ${b.nonce}, ${Number.isSafeInteger(b.attempts) ? `${b.attempts} nonces` : 'final nonce count unavailable'}, block ${b.blockId}`
      + `${b.browserMatched ? '' : ' (this browser\u2019s result did not match)'}`).join('; ')
    : DASH;
  els.realBlocks.dataset.blocks = JSON.stringify(s.realBlocks);
  // CUMULATIVE ATTEMPTS ARE NOT A SEQUENCE FEATURE. A refresh run searches several windows under one
  // Start, so the total across them is exactly as real as a sequence's, and showing only the current
  // window's count would understate the work this page actually did.
  els.realTotalAttempts.textContent = (sequence || windowPosition !== null) && Number.isSafeInteger(s.realTotalAttempts)
    ? String(s.realTotalAttempts)
    : DASH;
  els.realWorkers.textContent = String(s.realWorkersCreated);
  els.realWorkers.dataset.contexts = JSON.stringify(s.realWorkerContexts);
  els.realWorkers.dataset.stale = String(s.realStaleWorkerMessages);
  els.realCounters.textContent = s.simCounters
    ? Object.entries(s.simCounters).map(([k, v]) => `${k}=${v}`).join('  ')
    : DASH;
  els.start.textContent = s.simActionLabel ?? 'Search the fresh template once';
}

/**
 * Make the page unmistakable BEFORE Start.
 *
 * Everything here is driven by what the server said, never by a local guess: the labels, the
 * action label and the notices all come from the server_hello.
 */
function renderSimulation(s) {
  if (s.mode !== RECORDED_SIMULATION_MODE) return;
  if (s.simLabels && els.simLabels.childElementCount === 0) {
    for (const label of s.simLabels) {
      const dt = document.createElement('dt');
      dt.textContent = label;
      const dd = document.createElement('dd');
      dd.textContent = '';
      els.simLabels.append(dt, dd);
    }
  }
  els.simNotice.textContent = s.simNotice ?? '';
  els.simAllocate.textContent = s.simAllocateNotice ?? '';
  els.simHeight.textContent = s.simHeight ?? DASH;
  els.simNonce.textContent = s.simNonce === undefined || s.simNonce === null ? DASH : String(s.simNonce);
  els.simBrowserHash.textContent = s.simBrowserHashHexLE ?? DASH;
  els.simServerHash.textContent = s.simVerifiedHashHexLE ?? DASH;
  els.simExpectedHash.textContent = s.simExpectedHashHexLE ?? DASH;
  els.simCounters.textContent = s.simCounters
    ? Object.entries(s.simCounters).map(([k, v]) => `${k}=${v}`).join('  ')
    : DASH;
  // Three separate counts, never summed: the browser's own, and the two the server reports.
  els.simHashCounts.textContent = s.simCounters
    ? `browser Wasm=${s.hashes}  server Wasm=${s.simCounters.serverWasmHashes}  `
      + `native helper=${s.simCounters.nativeHelperHashes}`
    : `browser Wasm=${s.hashes}`;
  els.simNativeAlloc.textContent = s.simNativeDatasetBytes && s.simNativeScratchBytes
    ? `dataset ${mib(s.simNativeDatasetBytes)} + scratchpad ${mib(s.simNativeScratchBytes)} (not process RSS)`
    : DASH;
  // The action is a one-hash simulation, not mining.
  els.start.textContent = s.simActionLabel ?? 'Run one-hash simulation';
}

function render(s) {  els.state.textContent = STATE_TEXT[s.state] ?? s.state;
  els.state.setAttribute('data-state', s.state);
  els.connection.textContent = s.connection;
  els.jobId.textContent = s.jobId ?? DASH;
  els.algorithm.textContent = s.algorithm ?? DASH;
  els.hashes.textContent = String(s.hashes);
  els.hps.textContent = s.hashesPerSecond.toFixed(1);
  // The shared "Shares accepted" readout names verified ordinary shares in opt-in real share
  // mode. Those are counted separately from synthetic-pool acceptances in the controller; using
  // the generic counter here displayed zero even after the real server had accepted shares.
  els.accepted.textContent = String(s.mode === REAL_DAEMON_MODE && s.realShareMode === true
    ? s.realSharesAccepted : s.accepted);
  els.rejected.textContent = String(s.rejected);
  els.rejectReason.textContent = s.lastRejectReason ?? DASH;
  els.heap.textContent = s.wasmHeapBytes ? `${mib(s.wasmHeapBytes)} (${s.wasmHeapBytes} B)` : DASH;
  els.serverHeap.textContent = s.serverVerifierHeapBytes
    ? `${mib(s.serverVerifierHeapBytes)} (${s.serverVerifierHeapBytes} B)`
    : DASH;
  // Shown on its own line and never added to the Wasm figure above. This is the native build's
  // dataset + scratchpad, which is what the algorithm allocates -- not the child process's RSS,
  // which nothing in this slice measures.
  els.serverNative.textContent = s.serverNativeAlgorithmBytes
    ? `${mib(s.serverNativeAlgorithmBytes)} (${s.serverNativeAlgorithmBytes} B)`
    : DASH;
  els.verifierMode.textContent = VERIFIER_MODE_TEXT[s.serverVerifierMode] ?? DASH;
  els.error.textContent = s.error ?? DASH;

  renderModeView(s);
  renderSimulation(s);
  renderRealDaemon(s);

  const real = s.mode === REAL_DAEMON_MODE;
  const sim = s.mode === RECORDED_SIMULATION_MODE;
  const job = sim || real ? controller.realJob : controller.currentJob;
  if (job && job.batch !== undefined) els.batch.textContent = String(job.batch);

  const running = s.state === STATES.STARTING || s.state === STATES.MINING;
  els.paceWrap.hidden = !real;
  els.pace.disabled = running || !real;
  // A real pool may explicitly promise to mint this browser's personalized job only after the
  // correlated Start request. No other mode, omitted field, false value or malformed value enables
  // a jobless Start; the controller independently enforces the same gate.
  const canAwaitRealJob = real && s.realJobIssuedOnStart === true;
  // A spent server process disables Start for good: its one attempt is over, whatever the outcome.
  els.start.disabled = running || s.connection !== 'connected' || (!job && !canAwaitRealJob)
    || ((sim || real) && s.simProcessSpent);
  els.stop.disabled = !running;

  if (real && s.realSequenceTotal > 1 && s.realOutcome === 'block_accepted') {
    els.note.textContent = s.simBrowserMatched
      ? realSequenceSuccessNote(s.realSequenceTotal)
      : `The sequence ended after ${s.realSequenceTotal} positions, but not every position was an accepted block `
        + 'found by this browser, so full browser agreement was not established.';
  } else if (real && s.realSequenceTotal > 1 && running && s.realBlocks.at(-1)?.block === s.realBlockIndex) {
    els.note.textContent = `Block ${s.realBlockIndex} was accepted. Waiting for node B to show it and for the next `
      + 'template; nothing is being hashed. Press Stop, or hide this tab, to end the whole session.';
  } else if (real && s.realSequenceTotal > 1 && s.realWindowTotal <= 1 && running) {
    els.note.textContent = `Searching block ${s.realBlockIndex} of ${s.realSequenceTotal} once (at most ${WINDOW_BOUND_TEXT}). `
      + 'Press Stop, or hide this tab, to end the whole session immediately.';
  } else if (real && s.realOutcome === 'block_accepted') {
    els.note.textContent = s.simBrowserMatched
      ? 'The private local daemon accepted one block: its canonical readback shows this exact block, '
        + 'found by this browser, on top of its chain. Test coins only, private local node(s), not '
        + 'final. Restart the local server to try again.'
      : 'The private local daemon accepted the block and its canonical readback matched, but this '
        + 'browser\u2019s own reported result did not match, so browser agreement was not established.';
  } else if (real && s.realOutcome === 'bounded_no_solution') {
    els.note.textContent = 'BOUNDED_NO_SOLUTION. The search reached a preset limit (attempts, time, or '
      + 'qualifying-result cap) without a block-quality nonce. Only the displayed attempts were searched; '
      + 'no block was submitted for this height, and the run is not repeated automatically.';
  } else if (real && s.realOutcome === 'other_browser_won') {
    els.note.textContent = 'This browser stopped because the other browser claimed the one permitted '
      + 'submission. This page does not claim that its own block was accepted. Nothing is retried.';
  } else if (real && s.simFinished) {
    els.note.textContent = `The block run did not succeed (${s.simFailureCode ?? 'stopped'}). Nothing `
      + 'is retried. Restart the local server to try again.';
  } else if (real && s.simProcessSpent && !running) {
    els.note.textContent = 'This local server has already used its one fresh template. Restart it to run another.';
  } else if (real && s.state === STATES.STARTING) {
    // BEFORE ANY WINDOW WORD: a refresh run that has not been made ready yet is still PREPARING,
    // and saying "Searching window 1" here would claim a search that has not begun.
    els.note.textContent = 'Preparing the server\u2019s WebAssembly verifier and the local native helper for '
      + 'the fresh template. No worker exists and nothing is hashed until the server is ready.';
  } else if (real && s.realWindowTotal > 1 && running && realWindowHandoff(s) && s.realWindowRetiring === true) {
    // THE FIRST PART OF THE HANDOVER: the old context is still settling, so its search may still be
    // finishing. The page says THAT, and claims only that no hashing of the NEW window has begun --
    // never that nothing at all is hashing, which would not be true here.
    const position = realWindowPositionText(s);
    const noun = s.realSequenceTotal > 1 ? 'context' : 'window';
    const lead = s.realSequenceTotal > 1
      ? position
      : `Window ${s.realActiveWindowIndex} of ${s.realWindowTotal} is retiring and the server is preparing window ${s.realWindowIndex} of the same block height`;
    els.note.textContent = `${lead}. No hashing of the NEW ${noun} has `
      + 'begun. Press Stop, or hide this tab, to end the whole session immediately.';
  } else if (real && s.realWindowTotal > 1 && running && realWindowHandoff(s)) {
    const position = realWindowPositionText(s);
    els.note.textContent = `${position}: NOTHING IS BEING HASHED `
      + 'while the server releases its verifier and the browser worker is re-contextualised. '
      + 'Press Stop, or hide this tab, to end the whole session immediately.';
  } else if (real && s.realWindowTotal > 1 && running) {
    els.note.textContent = `Searching ${realWindowPositionText(s)}: ${realProspectiveBoundsText(s)}. `
      + 'Press Stop, or hide this tab, to end the whole session immediately.';
  } else if (real && running) {
    els.note.textContent = `Searching the fresh template once (${realProspectiveBoundsText(s)}). `
      + 'Press Stop, or hide this tab, to end it immediately.';
  } else if (sim && s.simComplete && s.simBrowserMatched) {
    els.note.textContent =
      'Simulation complete. The browser, the server\u2019s WebAssembly build and the live local '
      + 'native helper each computed the recorded hash once, and the mock daemon path ran. No '
      + 'daemon or chain was contacted; nothing was mined, submitted or created. Restart the local '
      + 'server to run it again.';
  } else if (sim && s.simComplete) {
    // The server-side paths completed; this browser's agreement was NOT established.
    els.note.textContent =
      'The server\u2019s WebAssembly build and the live local native helper verified the recorded '
      + 'hash and the mock daemon path ran, but this browser\u2019s own result did not match, so '
      + 'browser agreement was not established. No daemon or chain was contacted. Restart the local '
      + 'server to run it again.';
  } else if (sim && s.simFinished) {
    // FINISHED WITHOUT SUCCEEDING. Never the success wording.
    els.note.textContent =
      `The simulation did not succeed (${s.simFailureCode ?? 'stopped'}). No daemon or chain was `
      + 'contacted; nothing was mined, submitted or created. Restart the local server to try again.';
  } else if (sim && s.simProcessSpent && !running) {
    els.note.textContent =
      'This server process has already used its one recorded-template simulation. Restart the '
      + 'local server to run another.';
  } else if (sim && s.state === STATES.STARTING) {
    els.note.textContent =
      'Preparing the server\u2019s WebAssembly verifier and starting the local native helper for the '
      + 'recorded block. Nothing is hashed yet and no worker exists until the server is ready.';
  } else if (sim && running) {
    els.note.textContent = 'Computing exactly one hash for the recorded nonce.';
  } else if (s.state === STATES.STARTING) {
    els.note.textContent =
      'Asking the local pool to load its verifier. Nothing is being hashed yet, and no worker '
      + 'exists until the pool answers.';
  } else if (s.demoComplete && !running) {
    els.note.textContent = s.demoWon
      ? 'Synthetic demonstration complete — one share was found, recomputed by the local pool and '
        + 'accepted. It stopped on purpose. Press Start again for another run.'
      : 'The shared synthetic demonstration was completed by another connection on this machine, '
        + 'so this run stopped. Press Start again for another run.';
  } else if (running && controller.awaitingWork) {
    els.note.textContent =
      'Finished this job’s nonce window and waiting for the pool to issue new work. '
      + 'Nothing is being hashed right now.';
  } else if (running) {
    els.note.textContent = 'Mining. Press Stop, or hide this tab, to end it immediately.';
  } else if (s.connection !== 'connected') {
    els.note.textContent = 'Not connected to the local development pool. Nothing is running.';
  } else if (!job) {
    els.note.textContent = 'Waiting for a job from the local development pool…';
  } else if (s.state === STATES.STOPPED_HIDDEN) {
    els.note.textContent =
      'Mining stopped because the tab was hidden. It did not resume when you came back — '
      + 'press Start again if you want it to run.';
  } else {
    els.note.textContent = 'Ready. Nothing is running until you press Start.';
  }
}

// The ONLY place mining is ever started.
els.start.addEventListener('click', () => {
  const selected = els.pace.value;
  controller.start({ pacingMs: selected === '0' ? 0 : selected === '100' ? 100 : null });
});

els.stop.addEventListener('click', () => {
  controller.stop();
});

// Hiding the tab stops mining. Becoming visible again intentionally does nothing: the controller
// treats "visible" as a no-op, so the miner stays stopped until Start is pressed again.
document.addEventListener('visibilitychange', () => {
  controller.setHidden(document.visibilityState === 'hidden');
});

// Leaving the page terminates the worker and closes the socket. No resume intent is written
// anywhere, so returning via the back/forward cache or a reload lands on a stopped page.
window.addEventListener('pagehide', () => controller.teardown());

const origin = `${location.protocol}//${location.host}`;
els.destOrigin.textContent = origin;
els.footerOrigin.textContent = origin;

// Opening the socket before Start is deliberate and harmless: it is how the page learns the job
// parameters it must show you first. It allocates no dataset and computes no hash.
controller.connect(`ws://${location.host}/ws`);
render(controller.snapshot());
