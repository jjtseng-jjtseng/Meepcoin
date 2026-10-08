// The browser Worker's command dispatcher, with every dependency injected.
//
// worker.js is now only wiring: it imports the Wasm module from its served URL and hands this
// dispatcher the real hasher factories. Everything that decides WHETHER a hash may happen lives
// here, so the rules can be driven in Node against the same code the browser runs.
//
// ONE WORKER, ONE MODE, CHOSEN ONCE.
//
//   init          selects SYNTHETIC scan mode (the default miner's bounded nonce scan).
//   init_context  selects RECORDED one-shot mode (one exact server-authoritative nonce).
//
// The first initialization command irreversibly selects the mode -- locked when the command is
// accepted, before its asynchronous setup, so a second command racing that setup cannot select the
// other one. After that:
//
//   RECORDED  refuses init, work, any second init_context, and every hash_one except the single
//             one its permit authorises.
//   SYNTHETIC refuses init_context and hash_one.
//
// The previous revision limited repeated hash_one but still accepted `work` after init_context, so
// the SAME contextual Worker could enter searchNonces and hash a whole window.
//
// `stop` is irreversible in both modes. The page terminates a Worker after stopping it and never
// reuses one, so nothing legitimate needs a stopped Worker to hash again.
//
// THE GENERATION IS LATCHED ONCE, BY THE ACCEPTED INITIALIZATION, AND NEVER MOVED AGAIN. The previous
// revision copied every message's `gen` into the Worker BEFORE validating the command, so a refused
// wrong-mode `work` at generation 5 advanced the Worker past its armed generation 4 and the page's
// legitimate hash_one was then dropped as stale -- zero hashes, an unspent permit, a stuck page. Now
// a command must carry exactly the active generation, and a refused command changes nothing.
//
// `stop` is GENERATION-INDEPENDENT, deliberately. The page bumps its own generation when it stops,
// so a stop arrives tagged with a newer one; honouring any stop is safe because stop only ever
// removes capability, and it is final.

//   init_search   selects CONTEXTUAL SEARCH mode (real-local-daemon): the server's fresh context,
//                 one issued nonce window, the daemon target, and ONE bounded `search` over it.
//
// SEARCH refuses init, init_context, work, hash_one, any second init_search and any second search
// of the same context. Its window and time bound are capped here at REAL_SEARCH_LIMITS whatever the
// page asks for, the search stops at the FIRST nonce that meets the target, and at most one `found`
// is ever posted per context.
//
//   init_search_next  THE FINITE SEQUENCE: the SAME Worker, re-contextualised for the server's next
//                     template. Accepted only in SEARCH mode, at the SAME Worker generation, naming the
//                     previous job, once that job's one search has COMPLETELY SETTLED (searched, not
//                     running). The previous contextual hasher is freed FIRST -- before the new window is
//                     even validated -- so a malformed or failed rotation leaves no context able to hash.
//                     Every contextual hasher of this Worker is built on ONE module instance, so the old
//                     dataset is torn down inside that heap before the next is allocated: at most one
//                     live context and dataset at a time. The initial command latches the declared
//                     run limit, which can never exceed REAL_SEQUENCE_DEV_MAX_BLOCKS.
//
//   supersede_search  retires only the current search after a trusted external-tip transition. It is
//                     not Stop: the Worker settles that context, then may accept init_search_next.

import { createOneShotPermit, isExactUint32 } from './shared/one_shot.js';
import {
  REAL_SEARCH_LIMITS, REAL_SEQUENCE_DEV_MAX_BLOCKS, REAL_SEQUENCE_MAX_BLOCKS, REAL_SHARE_LIMITS,
  isSupportedRefreshWindows, isSupportedSequenceBlocks,
} from './shared/protocol.js';
import { meetsTargetLE, targetAtLeastLE } from './shared/target.js';

export const WORKER_MODES = Object.freeze({
  NONE: 'none',
  SYNTHETIC: 'synthetic',
  RECORDED: 'recorded',
  SEARCH: 'search',
});

export const WORKER_REFUSED = Object.freeze({
  MODE_LOCKED: 'mode_locked',
  WRONG_MODE: 'wrong_mode',
  NOT_READY: 'not_ready',
  STOPPED: 'stopped',
  BUSY: 'already_running',
  STALE_GENERATION: 'stale_generation',
  BAD_WINDOW: 'bad_search_window',
  ALREADY_SEARCHED: 'already_searched',
  WRONG_JOB: 'wrong_job',
  NOT_SETTLED: 'previous_search_not_settled',
  SEQUENCE_EXHAUSTED: 'sequence_exhausted',
  BAD_SEQUENCE: 'bad_sequence_length',
  BAD_PACING: 'bad_search_pacing',
});

/** The window rules init_search and init_search_next share: raw values, never wider than the bound. */
function checkSearchWindow(msg) {
  const w = msg.window ?? {};
  return typeof msg.jobId === 'string' && msg.jobId.length > 0 && msg.jobId.length <= 64
    && isExactUint32(w.nonceStart)
    && Number.isSafeInteger(w.nonceRange) && w.nonceRange >= 1
    && w.nonceRange <= REAL_SEARCH_LIMITS.maxAttempts
    && w.nonceStart + w.nonceRange <= 0x100000000
    && Number.isSafeInteger(w.maxSearchMs) && w.maxSearchMs >= 1
    && w.maxSearchMs <= REAL_SEARCH_LIMITS.maxSearchMs
    && typeof w.targetHexLE === 'string' && /^[0-9a-f]{64}$/.test(w.targetHexLE)
    && checkShareWindow(w);
}

/**
 * THE OPT-IN SHARE FIELDS, or nothing at all.
 *
 * A window either carries BOTH a share target and a share cap, or neither. The share target must be
 * well formed and must not be HARDER than the block target -- the Worker refuses to search a target
 * that would make a "share" rarer than a block, which is the only direction that could turn this
 * feature into extra work for nothing. The cap is small and fixed by the shared protocol; a page
 * cannot raise it.
 */
function checkShareWindow(w) {
  if (w.shareTargetHexLE === undefined && w.maxShares === undefined) return true;
  if (typeof w.shareTargetHexLE !== 'string' || !/^[0-9a-f]{64}$/.test(w.shareTargetHexLE)) return false;
  if (!Number.isSafeInteger(w.maxShares) || w.maxShares < 1) return false;
  if (w.maxShares > REAL_SHARE_LIMITS.maxSharesPerJob) return false;
  try {
    return targetAtLeastLE(hexToBytesStrict(w.shareTargetHexLE), hexToBytesStrict(w.targetHexLE));
  } catch {
    return false;
  }
}

/** Local strict hex, so the window check does not depend on an injected converter. */
function hexToBytesStrict(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/**
 * @param {object} deps
 * @param {Function} deps.createModule              the Emscripten module factory
 * @param {Function} deps.createV2Hasher            synthetic-context hasher factory
 * @param {Function} deps.createV2HasherForContext  explicit-context hasher factory
 * @param {Function} deps.searchNonces              the bounded synthetic scan
 * @param {Function} deps.hexToBytes
 * @param {Function} deps.bytesToHex
 * @param {Function} deps.nonceToHex
 * @param {(msg:object) => void} deps.postMessage
 * @param {() => number} [deps.now]
 * @param {(ms:number) => Promise<void>} [deps.pauseAfterBatch]
 */
export function createWorkerCore({
  createModule,
  createV2Hasher,
  createV2HasherForContext,
  searchNonces,
  hexToBytes,
  bytesToHex,
  nonceToHex,
  postMessage,
  now = () => 0,
  pauseAfterBatch = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  let hasher = null;
  let mode = WORKER_MODES.NONE;
  let stopped = false;
  let stopRequested = false;
  let running = false;
  // null until the first initialization command is ACCEPTED; then fixed for this Worker's life.
  let activeGen = null;
  const permit = createOneShotPermit();
  // SEARCH mode: the one issued window, frozen at init_search, and whether its one search happened.
  let searchWindow = null;
  let searched = false;
  let searchPacingMs = 0;
  // SEARCH mode's ONE module instance, and how many contextual hashers were built on it.
  let searchModule = null;
  let modulesCreated = 0;
  let contextsBuilt = 0;
  let sequenceLimit = 1;
  // WHICH KIND OF BUDGET `sequenceLimit` COUNTS, latched once at init_search and never revised.
  // 'sequence': the finite BLOCK total a multi-height run declared (or the historical direct-caller
  // capability when it declared none). 'refresh': the nonce-WINDOW total of one height.
  // 'composed': the Cartesian context ceiling (blocks * windows), with both coordinates checked on
  // every handoff. Every successor command must repeat the exact totals latched here.
  let contextBudgetKind = 'sequence';
  // The EXPLICIT sequence total the init declared, when it declared one: a successor must repeat
  // exactly this number, not merely stay under the historical ceiling the init fell back to.
  let declaredSequenceTotal = null;
  let declaredWindowTotal = 1;
  let currentSequenceIndex = 1;
  let currentWindowIndex = 1;
  let supersedeRequested = false;
  let rotating = false;
  // A context factory is asynchronous while Worker messages remain concurrent. Remember the exact
  // job being built so an external-tip supersession can be latched instead of being refused or
  // falsely announced settled before the hasher exists.
  let buildingJobId = null;
  const searchModuleFactory = () => {
    if (searchModule === null) {
      modulesCreated += 1;
      searchModule = Promise.resolve().then(() => createModule());
    }
    return searchModule;
  };

  function post(ev, extra = {}) {
    postMessage({ ev, gen: activeGen ?? 0, ...extra });
  }

  /** A refusal performs no hash, allocates nothing and changes no mode. */
  function refuse(cmd, reason) {
    post('command_refused', { cmd: String(cmd).slice(0, 32), reason });
    return { ok: false, reason };
  }

  async function handle(msg) {
    if (!msg || typeof msg.cmd !== 'string') return { ok: false, reason: 'malformed' };

    const isInit = msg.cmd === 'init' || msg.cmd === 'init_context' || msg.cmd === 'init_search';
    // init_search_next is NOT an initialization: it needs the generation the first init_search latched.

    try {
      if (msg.cmd === 'stop') {
        stopRequested = true;
        stopped = true;
        permit.terminate();
        return { ok: true };
      }
      if (stopped) return refuse(msg.cmd, WORKER_REFUSED.STOPPED);

      // THE GENERATION GATE. Nothing here writes a generation; only an accepted init does, below.
      if (activeGen !== null) {
        if (msg.gen !== activeGen) return refuse(msg.cmd, WORKER_REFUSED.STALE_GENERATION);
      } else if (isInit && (!Number.isSafeInteger(msg.gen) || msg.gen < 0)) {
        return refuse(msg.cmd, WORKER_REFUSED.STALE_GENERATION);
      }

      if (msg.cmd === 'init') {
        if (mode === WORKER_MODES.RECORDED || mode === WORKER_MODES.SEARCH) {
          return refuse('init', WORKER_REFUSED.MODE_LOCKED);
        }
        if (mode === WORKER_MODES.SYNTHETIC) {
          if (!hasher) return refuse('init', WORKER_REFUSED.NOT_READY);
          post('ready', { wasmHeapBytes: hasher.wasmHeapBytes(), reused: true });
          return { ok: true };
        }
        mode = WORKER_MODES.SYNTHETIC;                  // locked BEFORE the await
        activeGen = msg.gen;
        const t0 = now();
        hasher = await createV2Hasher(createModule);
        post('ready', { wasmHeapBytes: hasher.wasmHeapBytes(), setupMs: now() - t0 });
        return { ok: true };
      }

      if (msg.cmd === 'init_context') {
        if (mode !== WORKER_MODES.NONE) return refuse('init_context', WORKER_REFUSED.MODE_LOCKED);
        // Arm with the RAW server-authoritative nonce. A malformed one refuses the whole init: a
        // recorded Worker that cannot name its one nonce has nothing it is allowed to do.
        const armed = permit.arm({ gen: msg.gen, jobId: msg.jobId, nonce: msg.nonce });
        if (!armed.ok) return refuse('init_context', armed.reason);
        mode = WORKER_MODES.RECORDED;                   // locked BEFORE the await
        activeGen = msg.gen;
        const c = msg.context ?? {};
        const t0 = now();
        hasher = await createV2HasherForContext(createModule, {
          epochKey: hexToBytes(c.epochKeyHex),
          seedHash: hexToBytes(c.seedHashHex),
          height: c.height,                 // a decimal STRING: a uint64 must not ride on a Number
          template: hexToBytes(c.hashingTemplateHex),
        });
        post('ready', { wasmHeapBytes: hasher.wasmHeapBytes(), setupMs: now() - t0, context: true });
        return { ok: true };
      }

      if (msg.cmd === 'init_search') {
        if (mode !== WORKER_MODES.NONE) return refuse('init_search', WORKER_REFUSED.MODE_LOCKED);
        if (msg.pacingMs !== undefined && msg.pacingMs !== 0 && msg.pacingMs !== 100) {
          return refuse('init_search', WORKER_REFUSED.BAD_PACING);
        }
        // The window is validated RAW, like the recorded nonce: no coercion, and never wider than
        // the frozen bound. A malformed window refuses the whole init.
        const w = msg.window ?? {};
        if (!checkSearchWindow(msg)) return refuse('init_search', WORKER_REFUSED.BAD_WINDOW);
        // Missing means the historical two-context capability for direct callers; the page now
        // always sends the exact server-declared total. Either way, the value is latched once.
        const declaredLimit = msg.sequenceTotal === undefined
          ? REAL_SEQUENCE_MAX_BLOCKS
          : msg.sequenceTotal;
        if (!isSupportedSequenceBlocks(declaredLimit)) {
          return refuse('init_search', WORKER_REFUSED.BAD_SEQUENCE);
        }
        // HOW MANY CONTEXTS THIS WORKER MAY EVER BUILD, latched once, here.
        //
        // A finite block sequence declares a BLOCK total. `contextLimit` declares the number of
        // nonce WINDOWS available at each height. Either form is independently bounded, and a
        // composed run is additionally capped by the same 32-context development ceiling as the
        // sequence feature. All of this is checked before the mode lock, generation latch, or first
        // allocation.
        let declaredContexts = declaredLimit;
        if (msg.contextLimit !== undefined) {
          if (msg.sequenceTotal === undefined) {
            return refuse('init_search', WORKER_REFUSED.BAD_SEQUENCE);
          }
          if (!isSupportedRefreshWindows(msg.contextLimit) || msg.contextLimit < 2) {
            return refuse('init_search', WORKER_REFUSED.BAD_SEQUENCE);
          }
          if (declaredLimit > 1) {
            const product = declaredLimit * msg.contextLimit;
            if (!Number.isSafeInteger(product) || product > REAL_SEQUENCE_DEV_MAX_BLOCKS
              || msg.sequenceIndex !== 1 || msg.windowIndex !== 1) {
              return refuse('init_search', WORKER_REFUSED.BAD_SEQUENCE);
            }
            declaredContexts = product;
            contextBudgetKind = 'composed';
          } else {
            declaredContexts = msg.contextLimit;
            contextBudgetKind = 'refresh';
          }
        }
        declaredSequenceTotal = msg.sequenceTotal === undefined ? null : declaredLimit;
        declaredWindowTotal = msg.contextLimit === undefined ? 1 : msg.contextLimit;
        currentSequenceIndex = contextBudgetKind === 'composed' ? msg.sequenceIndex : 1;
        currentWindowIndex = contextBudgetKind === 'composed' ? msg.windowIndex : 1;
        mode = WORKER_MODES.SEARCH;                     // locked BEFORE the await
        searchPacingMs = msg.pacingMs ?? 0;
        activeGen = msg.gen;
        sequenceLimit = declaredContexts;
        searchWindow = Object.freeze({
          jobId: msg.jobId,
          nonceStart: w.nonceStart,
          nonceRange: w.nonceRange,
          maxSearchMs: w.maxSearchMs,
          target: hexToBytes(w.targetHexLE),
          // OPT-IN ONLY. Null here is the whole of the legacy behaviour: one solution, then stop.
          shareTarget: w.shareTargetHexLE === undefined ? null : hexToBytes(w.shareTargetHexLE),
          maxShares: w.shareTargetHexLE === undefined ? 0 : w.maxShares,
        });
        const c = msg.context ?? {};
        const t0 = now();
        contextsBuilt += 1;
        buildingJobId = msg.jobId;
        let built;
        try {
          built = await createV2HasherForContext(searchModuleFactory, {
            epochKey: hexToBytes(c.epochKeyHex),
            seedHash: hexToBytes(c.seedHashHex),
            height: c.height,                 // a decimal STRING: a uint64 must not ride on a Number
            template: hexToBytes(c.hashingTemplateHex),
          });
        } finally {
          buildingJobId = null;
        }
        if (stopped) {
          try { built?.free?.(); } catch { /* the Worker is going away */ }
          return { ok: false, reason: WORKER_REFUSED.STOPPED };
        }
        hasher = built;
        if (supersedeRequested) {
          searched = true;
          post('finished', {
            jobId: searchWindow.jobId, hashes: 0, found: 0, stopped: true,
            exhausted: false, timedOut: false, superseded: true, elapsedMs: 0, wasmHashCalls: 0,
          });
          return { ok: true, superseded: true };
        }
        post('ready', {
          jobId: msg.jobId, wasmHeapBytes: hasher.wasmHeapBytes(), setupMs: now() - t0, context: true, search: true,
          contextIndex: contextsBuilt, moduleInstances: modulesCreated,
        });
        return { ok: true };
      }

      if (msg.cmd === 'init_search_next') {
        if (mode !== WORKER_MODES.SEARCH) return refuse('init_search_next', WORKER_REFUSED.WRONG_MODE);
        if (running || rotating) return refuse('init_search_next', WORKER_REFUSED.BUSY);
        // THE PREVIOUS SEARCH MUST BE COMPLETELY SETTLED: its one search ran and finished.
        if (!searched || hasher === null || searchWindow === null) return refuse('init_search_next', WORKER_REFUSED.NOT_SETTLED);
        // THE BUDGET FORM IS LATCHED, AND EVERY SUCCESSOR MUST REPEAT IT EXACTLY -- before the old
        // context is touched, so a wrong form leaves it live and allocates nothing. A refresh
        // successor repeats sequenceTotal 1 plus the exact window total; a sequence successor
        // repeats its block total and carries no window total. A composed successor repeats both
        // totals and advances exactly one coordinate: the next window of this block, or window 1 of
        // the next block. Skipping, replaying, or moving both coordinates arbitrarily is refused.
        if (contextBudgetKind === 'refresh') {
          if (msg.sequenceTotal !== 1 || msg.contextLimit !== sequenceLimit) {
            return refuse('init_search_next', WORKER_REFUSED.BAD_SEQUENCE);
          }
        } else if (contextBudgetKind === 'composed') {
          if (msg.sequenceTotal !== declaredSequenceTotal || msg.contextLimit !== declaredWindowTotal
            || !Number.isSafeInteger(msg.sequenceIndex) || !Number.isSafeInteger(msg.windowIndex)) {
            return refuse('init_search_next', WORKER_REFUSED.BAD_SEQUENCE);
          }
          const nextWindow = msg.sequenceIndex === currentSequenceIndex
            && msg.windowIndex === currentWindowIndex + 1
            && msg.windowIndex <= declaredWindowTotal;
          const nextBlock = msg.sequenceIndex === currentSequenceIndex + 1
            && msg.sequenceIndex <= declaredSequenceTotal
            && msg.windowIndex === 1;
          if (!nextWindow && !nextBlock) {
            return refuse('init_search_next', WORKER_REFUSED.BAD_SEQUENCE);
          }
        } else {
          if (msg.contextLimit !== undefined) {
            return refuse('init_search_next', WORKER_REFUSED.BAD_SEQUENCE);
          }
          if (declaredSequenceTotal !== null) {
            if (msg.sequenceTotal !== declaredSequenceTotal) {
              return refuse('init_search_next', WORKER_REFUSED.BAD_SEQUENCE);
            }
          } else if (msg.sequenceTotal !== undefined && msg.sequenceTotal !== sequenceLimit) {
            return refuse('init_search_next', WORKER_REFUSED.BAD_SEQUENCE);
          }
        }
        if (contextsBuilt >= sequenceLimit) return refuse('init_search_next', WORKER_REFUSED.SEQUENCE_EXHAUSTED);
        if (msg.prevJobId !== searchWindow.jobId || typeof msg.jobId !== 'string' || msg.jobId === searchWindow.jobId) {
          return refuse('init_search_next', WORKER_REFUSED.WRONG_JOB);
        }
        // TEAR DOWN FIRST. From here the previous context cannot hash, whatever happens below.
        const previous = hasher;
        hasher = null;
        searchWindow = null;
        searched = false;
        supersedeRequested = false;
        // Release must be positively proved before the next dataset can even begin allocation.
        // Swallowing a teardown error here could leave the old Wasm dataset alive while building
        // another one in the same heap. The outer command error makes the controller terminate the
        // Worker, which is the only safe recovery when teardown cannot be confirmed.
        if (typeof previous.free !== 'function' || typeof previous.isActive !== 'function') {
          throw new Error('previous search context has no confirmable release interface');
        }
        previous.free();
        const priorContextActive = previous.isActive();
        if (priorContextActive !== false) {
          throw new Error('previous search context release was not confirmed');
        }
        const priorFreed = true;
        if (!checkSearchWindow(msg)) return refuse('init_search_next', WORKER_REFUSED.BAD_WINDOW);
        const w = msg.window;
        const next = Object.freeze({
          jobId: msg.jobId,
          nonceStart: w.nonceStart,
          nonceRange: w.nonceRange,
          maxSearchMs: w.maxSearchMs,
          target: hexToBytes(w.targetHexLE),
          // OPT-IN ONLY. Null here is the whole of the legacy behaviour: one solution, then stop.
          shareTarget: w.shareTargetHexLE === undefined ? null : hexToBytes(w.shareTargetHexLE),
          maxShares: w.shareTargetHexLE === undefined ? 0 : w.maxShares,
        });
        const c = msg.context ?? {};
        const t0 = now();
        contextsBuilt += 1;
        rotating = true;
        buildingJobId = msg.jobId;
        let built;
        try {
          built = await createV2HasherForContext(searchModuleFactory, {
            epochKey: hexToBytes(c.epochKeyHex),
            seedHash: hexToBytes(c.seedHashHex),
            height: c.height,
            template: hexToBytes(c.hashingTemplateHex),
          });
        } finally {
          buildingJobId = null;
          rotating = false;
        }
        // A Stop that arrived while the next context was being built: it never becomes usable.
        if (stopped) {
          try { built.free?.(); } catch { /* the Worker is going away */ }
          return { ok: false, reason: WORKER_REFUSED.STOPPED };
        }
        hasher = built;
        searchWindow = next;
        if (contextBudgetKind === 'composed') {
          currentSequenceIndex = msg.sequenceIndex;
          currentWindowIndex = msg.windowIndex;
        }
        if (supersedeRequested) {
          searched = true;
          post('finished', {
            jobId: next.jobId, hashes: 0, found: 0, stopped: true,
            exhausted: false, timedOut: false, superseded: true, elapsedMs: 0, wasmHashCalls: 0,
          });
          return { ok: true, superseded: true };
        }
        post('ready', {
          jobId: msg.jobId, wasmHeapBytes: hasher.wasmHeapBytes(), setupMs: now() - t0, context: true, search: true,
          rotated: true, contextIndex: contextsBuilt, moduleInstances: modulesCreated,
          priorContextFreed: priorFreed, priorContextActive,
        });
        return { ok: true };
      }

      if (msg.cmd === 'supersede_search') {
        if (mode !== WORKER_MODES.SEARCH) return refuse('supersede_search', WORKER_REFUSED.WRONG_MODE);
        const currentJobId = buildingJobId ?? searchWindow?.jobId ?? null;
        if (msg.jobId !== currentJobId) {
          return refuse('supersede_search', WORKER_REFUSED.WRONG_JOB);
        }
        if (supersedeRequested) return { ok: true, idempotent: true };
        // A settled search needs no second finished event. The controller already has the fence it
        // needs and can rotate as soon as the server's next context is ready.
        if (searched && !running) return { ok: true, alreadySettled: true };
        supersedeRequested = true;
        // Construction is already in flight. Do not claim settlement until it returns; doing so
        // lets the controller send init_search_next against a hasher that does not exist yet.
        if (buildingJobId === msg.jobId) return { ok: true, pending: true };
        if (!running) {
          searched = true;
          post('finished', {
            jobId: searchWindow.jobId, hashes: 0, found: 0, stopped: true,
            exhausted: false, timedOut: false, superseded: true, elapsedMs: 0, wasmHashCalls: 0,
          });
        }
        return { ok: true };
      }

      if (msg.cmd === 'search') {
        if (mode !== WORKER_MODES.SEARCH) return refuse('search', WORKER_REFUSED.WRONG_MODE);
        if (!hasher) return refuse('search', WORKER_REFUSED.NOT_READY);
        if (msg.jobId !== searchWindow.jobId) return refuse('search', WORKER_REFUSED.WRONG_JOB);
        if (searched) return refuse('search', WORKER_REFUSED.ALREADY_SEARCHED);
        searched = true;                                 // spent BEFORE the first hash
        running = true;
        const win = searchWindow;
        const t0 = now();
        const startCalls = hasher.hashCalls;
        // SHARE MODE IS THE OPT-IN ONE. Without a share target this is the original loop, exactly:
        // scan the block target, stop at the first solution.
        const shareMode = win.shareTarget !== null;
        let foundOne = false;                            // legacy: the one solution
        let shares = 0;                                  // share mode: qualifying hits so far
        let blockFound = false;
        let capReached = false;
        let timedOut = false;
        try {
          const result = await searchNonces({
            hashOne: (n) => hasher.hashOne(n),
            // In share mode the SCAN target is the server's share target; each hit is then measured
            // against the block target as well. Both targets are the server's; neither is chosen here.
            target: shareMode ? win.shareTarget : win.target,
            nonceStart: win.nonceStart,
            nonceRange: win.nonceRange,
            batch: 4,
            ...(searchPacingMs > 0 ? { yieldFn: () => pauseAfterBatch(searchPacingMs) } : {}),
            // First bound reached wins: Stop, a block, the share cap, the attempt window, or the
            // frozen wall-clock bound. In legacy mode the first solution still ends it.
            shouldStop: () => {
              if (stopRequested || supersedeRequested) return true;
              if (shareMode ? (blockFound || capReached) : foundOne) return true;
              if (now() - t0 >= win.maxSearchMs) { timedOut = true; return true; }
              return false;
            },
            onProgress: ({ hashes }) => {
              post('progress', { jobId: win.jobId, hashes, elapsedMs: now() - t0 });
            },
            onFound: ({ nonce, hash }) => {
              if (!shareMode) {
                if (foundOne) return;                    // never a second candidate
                foundOne = true;
                post('found', {
                  jobId: win.jobId,
                  nonce,
                  nonceHex: nonceToHex(nonce),
                  // A diagnostic only. The server recomputes it three ways and never trusts this.
                  hashHexLE: bytesToHex(hash),
                  elapsedMs: now() - t0,
                });
                return;
              }
              if (blockFound || capReached) return;       // the loop is already stopping
              const isBlock = meetsTargetLE(hash, win.target);
              shares += 1;
              if (isBlock) blockFound = true;
              if (shares >= win.maxShares) capReached = true;
              // EVERY hit is reported the same way and the SERVER decides what it is. `block` is the
              // Worker's own reading of the block target and is a hint for pacing only: nothing here
              // declares a block, and the server recomputes both the hash and the comparison.
              post('share', {
                jobId: win.jobId,
                nonce,
                nonceHex: nonceToHex(nonce),
                hashHexLE: bytesToHex(hash),
                block: isBlock,
                shareIndex: shares,
                elapsedMs: now() - t0,
              });
            },
          });
          const wasmHashCalls = hasher.hashCalls - startCalls;
          if (!Number.isSafeInteger(wasmHashCalls) || wasmHashCalls !== result.hashes) {
            throw new Error('search count disagrees with the Wasm hash-call counter');
          }
          post('finished', {
            jobId: win.jobId,
            hashes: result.hashes,
            found: shareMode ? (blockFound ? 1 : 0) : (foundOne ? 1 : 0),
            stopped: result.stopped,
            exhausted: result.exhausted && !(shareMode ? blockFound || capReached : foundOne),
            timedOut,
            superseded: supersedeRequested,
            ...(shareMode ? {
              shares,
              blockFound,
              // Exactly why this bounded search ended, in the Worker's own words.
              stopCause: stopRequested || supersedeRequested ? 'stopped'
                : blockFound ? 'block_found'
                  : capReached ? 'share_cap'
                    : timedOut ? 'time_bound' : 'window_exhausted',
            } : {}),
            elapsedMs: now() - t0,
            wasmHashCalls,
          });
        } finally {
          running = false;
        }
        return { ok: true };
      }

      if (msg.cmd === 'hash_one') {
        if (mode !== WORKER_MODES.RECORDED) return refuse('hash_one', WORKER_REFUSED.WRONG_MODE);
        if (!hasher) return refuse('hash_one', WORKER_REFUSED.NOT_READY);
        // THE PERMIT DECIDES, with the RAW nonce. Spent before the hash.
        const admitted = permit.admit({ gen: msg.gen, jobId: msg.jobId, nonce: msg.nonce });
        if (!admitted.ok) return refuse('hash_one', admitted.reason);
        const nonce = admitted.nonce;                   // the ARMED value, never the message's
        const t0 = now();
        const hash = hasher.hashOne(nonce);
        post('hashed_one', {
          jobId: msg.jobId,
          nonce,
          nonceHex: nonceToHex(nonce),
          // Reported for the readout only. The server recomputes it and never trusts this value.
          hashHexLE: bytesToHex(hash),
          elapsedMs: now() - t0,
          wasmHashCalls: hasher.hashCalls,
        });
        return { ok: true };
      }

      if (msg.cmd === 'work') {
        if (mode !== WORKER_MODES.SYNTHETIC) return refuse('work', WORKER_REFUSED.WRONG_MODE);
        if (!hasher) return refuse('work', WORKER_REFUSED.NOT_READY);
        if (running) return refuse('work', WORKER_REFUSED.BUSY);
        running = true;
        stopRequested = false;

        const job = msg.job;
        const target = hexToBytes(job.targetHexLE);
        const t0 = now();
        const startCalls = hasher.hashCalls;
        try {
          const result = await searchNonces({
            hashOne: (n) => hasher.hashOne(n),
            target,
            nonceStart: job.nonceStart,
            nonceRange: job.nonceRange,
            batch: job.batch ?? 4,
            shouldStop: () => stopRequested,
            onProgress: ({ hashes }) => {
              post('progress', { jobId: job.jobId, hashes, elapsedMs: now() - t0 });
            },
            onFound: ({ nonce, hash }) => {
              post('found', {
                jobId: job.jobId,
                nonce,
                nonceHex: nonceToHex(nonce),
                // Reported for the UI and for the server's optional untrusted-diagnostic field.
                // The pool recomputes the hash itself; this value can never accept a share.
                hashHexLE: bytesToHex(hash),
              });
            },
          });
          post('finished', {
            jobId: job.jobId,
            hashes: result.hashes,
            found: result.found,
            stopped: result.stopped,
            exhausted: result.exhausted,
            elapsedMs: now() - t0,
            wasmHashCalls: hasher.hashCalls - startCalls,
          });
        } finally {
          running = false;
        }
        return { ok: true };
      }

      post('error', { message: `unknown command ${String(msg.cmd).slice(0, 32)}` });
      return { ok: false, reason: 'unknown_command' };
    } catch (err) {
      running = false;
      post('error', { message: err && err.message ? err.message : String(err) });
      return { ok: false, reason: 'error' };
    }
  }

  return {
    handle,
    get mode() { return mode; },
    get stopped() { return stopped; },
    get activeGeneration() { return activeGen; },
    get permit() { return permit; },
    get hashCalls() { return hasher ? hasher.hashCalls : 0; },
    get contextsBuilt() { return contextsBuilt; },
    get sequenceLimit() { return sequenceLimit; },
    get contextBudgetKind() { return contextBudgetKind; },
    get declaredSequenceTotal() { return declaredSequenceTotal; },
    get declaredWindowTotal() { return declaredWindowTotal; },
    get currentSequenceIndex() { return currentSequenceIndex; },
    get currentWindowIndex() { return currentWindowIndex; },
    get modulesCreated() { return modulesCreated; },
    get hasContext() { return hasher !== null; },
  };
}
