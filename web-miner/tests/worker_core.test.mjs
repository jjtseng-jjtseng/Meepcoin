// The browser Worker's REAL command dispatcher, driven in Node.
//
// worker.js is wiring: it hands every message to createWorkerCore(). This file drives that same
// function with counting stand-ins for the two Wasm hasher factories and the REAL bounded scan
// (lib/shared/search.js), so "zero hashes" below is a count of hashOne() calls, not an argument
// about control flow. No browser, no Wasm, no server.
//
// EACH WITNESS IS A DEFECT THAT WAS REACHABLE AT d225dbd0:
//   * init_context followed by `work` entered searchNonces on the contextual Worker;
//   * `msg.nonce >>> 0` ran before validation, so -1, 2^32, 1.5 and "7" became valid uint32s.

import test from 'node:test';
import assert from 'node:assert/strict';

import { WORKER_MODES, WORKER_REFUSED, createWorkerCore } from '../lib/worker_core.js';
import { ONE_SHOT_REFUSED } from '../lib/shared/one_shot.js';
import { searchNonces } from '../lib/shared/search.js';
import { bytesToHex, hexToBytes, nonceToHex } from '../lib/shared/target.js';

const GEN = 4;
const JOB = 'realjob-1111111111111111';
const NONCE = 1325931723;
const CONTEXT = {
  epochKeyHex: 'f'.repeat(64),
  seedHashHex: 'f'.repeat(64),
  height: '2113',
  hashingTemplateHex: `1010${'00'.repeat(74)}`,
};

/** A counting stand-in for a hasher: every hashOne() is recorded with the nonce it was given. */
function fakeHasher(kind, log) {
  let calls = 0;
  return {
    kind,
    hashOne(nonce) {
      calls++;
      log.hashes.push({ kind, nonce });
      const out = new Uint8Array(32);
      out[0] = nonce & 0xff;
      out[31] = 0xff;          // never meets an all-zero-ish target by accident
      return out;
    },
    get hashCalls() { return calls; },
    wasmHeapBytes: () => 48_562_176,
  };
}

function makeCore() {
  const log = { posted: [], hashes: [], synthInits: 0, contextInits: 0, contexts: [] };
  const core = createWorkerCore({
    createModule: () => ({}),
    createV2Hasher: async () => { log.synthInits++; return fakeHasher('synthetic', log); },
    createV2HasherForContext: async (_m, ctx) => {
      log.contextInits++;
      log.contexts.push(ctx);
      return fakeHasher('contextual', log);
    },
    searchNonces,
    hexToBytes,
    bytesToHex,
    nonceToHex,
    postMessage: (m) => log.posted.push(m),
  });
  const say = (msg) => core.handle(msg);
  const events = (ev) => log.posted.filter((m) => m.ev === ev);
  return { core, log, say, events };
}

const INIT_CONTEXT = { cmd: 'init_context', gen: GEN, jobId: JOB, nonce: NONCE, context: CONTEXT };
const HASH_ONE = { cmd: 'hash_one', gen: GEN, jobId: JOB, nonce: NONCE };
const WORK = {
  cmd: 'work',
  gen: GEN,
  job: { jobId: 'devjob-1', targetHexLE: '00'.repeat(32), nonceStart: 0, nonceRange: 64, batch: 4 },
};

// ================================================================== the mode lock
test('init_context then WORK: zero search and zero hashes', async () => {
  const { core, log, say, events } = makeCore();
  await say(INIT_CONTEXT);
  assert.equal(core.mode, WORKER_MODES.RECORDED);

  const r = await say(WORK);
  assert.equal(r.ok, false);
  assert.equal(r.reason, WORKER_REFUSED.WRONG_MODE);
  assert.equal(log.hashes.length, 0, 'a contextual Worker scanned nonces');
  assert.equal(events('progress').length, 0);
  assert.equal(events('finished').length, 0);
  assert.equal(events('command_refused').at(-1).reason, WORKER_REFUSED.WRONG_MODE);
});

test('init_context then INIT: no mode switch and no new allocation', async () => {
  const { core, log, say } = makeCore();
  await say(INIT_CONTEXT);
  const r = await say({ cmd: 'init', gen: GEN });
  assert.equal(r.reason, WORKER_REFUSED.MODE_LOCKED);
  assert.equal(core.mode, WORKER_MODES.RECORDED);
  assert.equal(log.synthInits, 0, 'a synthetic dataset was allocated in a recorded Worker');
  assert.equal(log.contextInits, 1);
  // And a second init_context is refused too: no second dataset, no re-arming.
  const again = await say({ ...INIT_CONTEXT, nonce: NONCE + 1 });
  assert.equal(again.reason, WORKER_REFUSED.MODE_LOCKED);
  assert.equal(log.contextInits, 1);
  assert.equal(core.permit.nonce, NONCE);
});

test('init then init_context / hash_one: no contextual hash, no contextual dataset', async () => {
  const { core, log, say } = makeCore();
  await say({ cmd: 'init', gen: GEN });
  assert.equal(core.mode, WORKER_MODES.SYNTHETIC);

  assert.equal((await say(INIT_CONTEXT)).reason, WORKER_REFUSED.MODE_LOCKED);
  assert.equal((await say(HASH_ONE)).reason, WORKER_REFUSED.WRONG_MODE);
  assert.equal(log.contextInits, 0);
  assert.equal(log.hashes.length, 0);
  assert.equal(core.mode, WORKER_MODES.SYNTHETIC);
});

test('the mode is locked BEFORE the asynchronous setup, so a racing command cannot pick the other', async () => {
  const { core, log, say } = makeCore();
  // Both arrive before either setup finishes.
  const a = say(INIT_CONTEXT);
  const b = say({ cmd: 'init', gen: GEN });
  const [ra, rb] = await Promise.all([a, b]);
  assert.equal(ra.ok, true);
  assert.equal(rb.reason, WORKER_REFUSED.MODE_LOCKED);
  assert.equal(core.mode, WORKER_MODES.RECORDED);
  assert.equal(log.synthInits, 0);
});

// ================================================================== the exact nonce
test('malformed RAW nonces perform zero hashes and do not spend the permit', async () => {
  const raws = [
    ['-1', -1],
    ['2^32', 2 ** 32],
    ['2^32+1', 2 ** 32 + 1],
    ['fractional', NONCE + 0.5],
    ['NaN', NaN],
    ['numeric string', `${NONCE}`],
    ['missing', undefined],
  ];
  for (const [name, nonce] of raws) {
    const { core, log, say } = makeCore();
    await say(INIT_CONTEXT);
    const msg = { cmd: 'hash_one', gen: GEN, jobId: JOB };
    if (nonce !== undefined) msg.nonce = nonce;
    const r = await say(msg);
    assert.equal(r.ok, false, name);
    assert.equal(r.reason, ONE_SHOT_REFUSED.BAD_NONCE, name);
    assert.equal(log.hashes.length, 0, `${name}: hashed`);
    assert.equal(core.permit.spent, false, `${name}: spent the permit`);
    // The exact armed nonce still works afterwards.
    assert.equal((await say(HASH_ONE)).ok, true, name);
    assert.deepEqual(log.hashes, [{ kind: 'contextual', nonce: NONCE }], name);
  }
});

test('a WRONG but valid uint32 performs zero hashes', async () => {
  for (const wrong of [0, NONCE - 1, NONCE + 1, 0xffffffff]) {
    const { log, say } = makeCore();
    await say(INIT_CONTEXT);
    const r = await say({ ...HASH_ONE, nonce: wrong });
    assert.equal(r.reason, ONE_SHOT_REFUSED.WRONG_NONCE, String(wrong));
    assert.equal(log.hashes.length, 0, String(wrong));
  }
});

test('a malformed nonce at init_context refuses the whole recorded mode', async () => {
  for (const bad of [-1, 2 ** 32, 1.5, '7', undefined]) {
    const { core, log, say } = makeCore();
    const r = await say({ ...INIT_CONTEXT, nonce: bad });
    assert.equal(r.reason, ONE_SHOT_REFUSED.BAD_NONCE, String(bad));
    assert.equal(core.mode, WORKER_MODES.NONE, `${String(bad)} selected a mode`);
    assert.equal(log.contextInits, 0, `${String(bad)} allocated a dataset`);
  }
});

test('the EXACT armed nonce performs ONE hash, of the armed value, and says so', async () => {
  const { log, say, events } = makeCore();
  await say(INIT_CONTEXT);
  assert.equal(log.contexts.length, 1);
  assert.equal(log.contexts[0].height, '2113', 'the uint64 height rode on a Number');

  const r = await say(HASH_ONE);
  assert.equal(r.ok, true);
  assert.deepEqual(log.hashes, [{ kind: 'contextual', nonce: NONCE }]);
  const [hashed] = events('hashed_one');
  assert.equal(hashed.nonce, NONCE);
  assert.equal(hashed.nonceHex, nonceToHex(NONCE));
  assert.equal(hashed.jobId, JOB);
});

test('repeated, post-stop, stale-generation and wrong-job commands add zero hashes', async () => {
  const { log, say } = makeCore();
  await say(INIT_CONTEXT);
  await say(HASH_ONE);
  assert.equal(log.hashes.length, 1);

  assert.equal((await say(HASH_ONE)).reason, ONE_SHOT_REFUSED.ALREADY_HASHED);
  assert.equal((await say({ ...HASH_ONE, jobId: 'realjob-other' })).reason, ONE_SHOT_REFUSED.WRONG_JOB);
  // Any generation but the active one is refused, and refusing it changes nothing.
  assert.equal((await say({ ...HASH_ONE, gen: GEN - 1 })).reason, WORKER_REFUSED.STALE_GENERATION);
  assert.equal((await say({ ...HASH_ONE, gen: GEN + 1 })).reason, WORKER_REFUSED.STALE_GENERATION);
  assert.equal((await say({ ...WORK, gen: GEN + 1 })).reason, WORKER_REFUSED.STALE_GENERATION);
  // The active generation is still the active generation, so current-generation work meets the mode lock.
  assert.equal((await say(WORK)).reason, WORKER_REFUSED.WRONG_MODE);
  assert.equal(log.hashes.length, 1, 'a repeated or stale command hashed again');
});

test('A REFUSED FUTURE-GENERATION COMMAND CANNOT POISON THE ACTIVE RUN', async () => {
  // THE WITNESS: init_context accepted at generation 4; a wrong-mode `work` at generation 5 was
  // refused but advanced the Worker's generation; the legitimate armed hash_one at generation 4 was
  // then dropped as stale -- zero hashes, an unspent permit, a stuck page.
  const { core, log, say, events } = makeCore();
  assert.equal((await say(INIT_CONTEXT)).ok, true);
  assert.equal(core.activeGeneration, GEN);

  const poison = await say({ ...WORK, gen: GEN + 1 });
  assert.equal(poison.ok, false);
  assert.equal(poison.reason, WORKER_REFUSED.STALE_GENERATION);
  assert.equal(core.activeGeneration, GEN, 'a refused command moved the active generation');
  assert.equal(core.mode, WORKER_MODES.RECORDED);
  assert.equal(core.permit.spent, false);
  assert.equal(log.hashes.length, 0);

  // Other refused shapes change nothing either.
  for (const bad of [
    { cmd: 'hash_one', gen: GEN + 7, jobId: JOB, nonce: NONCE },
    { cmd: 'init', gen: GEN + 1 },
    { cmd: 'work', gen: 'x', job: WORK.job },
    { cmd: 'bogus', gen: GEN + 99 },
  ]) {
    await say(bad);
    assert.equal(core.activeGeneration, GEN, `${JSON.stringify(bad)} moved the generation`);
  }

  // The legitimate hash still executes, exactly once.
  const good = await say(HASH_ONE);
  assert.equal(good.ok, true, `the legitimate hash was refused: ${good.reason}`);
  assert.deepEqual(log.hashes, [{ kind: 'contextual', nonce: NONCE }]);
  assert.equal(events('hashed_one').length, 1);
  assert.equal(events('hashed_one')[0].gen, GEN);
});

test('STOP is generation-independent and final; nothing re-arms a stopped Worker', async () => {
  const { core, log, say } = makeCore();
  await say(INIT_CONTEXT);
  // The page bumps its own generation when it stops, so stop arrives tagged with a newer one.
  assert.equal((await say({ cmd: 'stop', gen: GEN + 1 })).ok, true);
  assert.equal(core.stopped, true);
  assert.equal(core.activeGeneration, GEN, 'stop moved the generation');
  assert.equal((await say(HASH_ONE)).reason, WORKER_REFUSED.STOPPED);
  assert.equal(log.hashes.length, 0);
});

test('STOP is final: nothing hashes afterwards, in either mode', async () => {
  // Recorded: stop BEFORE the one hash. The permit is never spent, and nothing can spend it.
  const rec = makeCore();
  await rec.say(INIT_CONTEXT);
  await rec.say({ cmd: 'stop', gen: GEN });
  assert.equal(rec.core.stopped, true);
  for (const cmd of [HASH_ONE, WORK, { cmd: 'init', gen: GEN }, INIT_CONTEXT]) {
    assert.equal((await rec.say(cmd)).reason, WORKER_REFUSED.STOPPED, cmd.cmd);
  }
  assert.equal(rec.log.hashes.length, 0);
  assert.equal(rec.core.permit.spent, false);

  // Synthetic: a stopped Worker does not scan again.
  const syn = makeCore();
  await syn.say({ cmd: 'init', gen: GEN });
  await syn.say({ cmd: 'stop', gen: GEN });
  assert.equal((await syn.say(WORK)).reason, WORKER_REFUSED.STOPPED);
  assert.equal(syn.log.hashes.length, 0);
});

// ================================================================== the synthetic path still works
test('the synthetic path still scans its bounded window after init', async () => {
  const { core, log, say, events } = makeCore();
  await say({ cmd: 'init', gen: GEN });
  const r = await say(WORK);
  assert.equal(r.ok, true);
  assert.equal(core.mode, WORKER_MODES.SYNTHETIC);
  assert.equal(log.hashes.length, 64, 'the synthetic scan did not cover its window');
  assert.ok(log.hashes.every((h) => h.kind === 'synthetic'));
  assert.equal(events('finished').length, 1);
  assert.equal(events('finished')[0].hashes, 64);
});

// ================================================================== CONTEXTUAL SEARCH (real local daemon)
import { REAL_REFRESH_LIMITS, REAL_SEARCH_LIMITS } from '../lib/shared/protocol.js';

/** A search core whose hasher meets the target only at `winner` (or never), with an injected clock. */
function makeSearchCore({ winner = null, clock = { ms: 0 }, msPerHash = 0 } = {}) {
  const log = { posted: [], hashes: [], contexts: [], pauses: [] };
  const hasher = {
    calls: 0,
    hashOne(nonce) {
      this.calls++;
      log.hashes.push(nonce);
      clock.ms += msPerHash;
      return new Uint8Array(32).fill(nonce === winner ? 0x00 : 0xff);
    },
    get hashCalls() { return this.calls; },
    wasmHeapBytes: () => 48_562_176,
  };
  const core = createWorkerCore({
    createModule: () => ({}),
    createV2Hasher: async () => { throw new Error('the synthetic hasher must not be built'); },
    createV2HasherForContext: async (_m, ctx) => { log.contexts.push(ctx); return hasher; },
    searchNonces,
    hexToBytes,
    bytesToHex,
    nonceToHex,
    postMessage: (m) => log.posted.push(m),
    now: () => clock.ms,
    pauseAfterBatch: async (ms) => { log.pauses.push(ms); clock.ms += ms; },
  });
  const say = (msg) => core.handle(msg);
  const events = (ev) => log.posted.filter((m) => m.ev === ev);
  return { core, log, say, events, clock };
}

// A target only an all-zero hash meets (little-endian: the most significant byte is the last).
const SEARCH_TARGET = `${'00'.repeat(31)}01`;
const INIT_SEARCH = {
  cmd: 'init_search',
  gen: GEN,
  jobId: JOB,
  window: { nonceStart: 0, nonceRange: 64, targetHexLE: SEARCH_TARGET, maxSearchMs: 120_000 },
  context: CONTEXT,
};
const SEARCH = { cmd: 'search', gen: GEN, jobId: JOB };

test('SEARCH: invalid pace refuses before allocation; quiet pace pauses only between four-hash batches', async () => {
  for (const bad of [-1, 50, '100', NaN, null]) {
    const { core, log, say } = makeSearchCore();
    assert.equal((await say({ ...INIT_SEARCH, pacingMs: bad })).reason, WORKER_REFUSED.BAD_PACING);
    assert.equal(core.mode, WORKER_MODES.NONE);
    assert.equal(log.contexts.length, 0);
    assert.equal(log.hashes.length, 0);
  }
  const quiet = makeSearchCore({ winner: null });
  await quiet.say({ ...INIT_SEARCH, pacingMs: 100, window: { ...INIT_SEARCH.window, nonceRange: 8 } });
  await quiet.say(SEARCH);
  assert.deepEqual(quiet.log.hashes, [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual(quiet.log.pauses, [100, 100]);

  const full = makeSearchCore({ winner: null });
  await full.say({ ...INIT_SEARCH, pacingMs: 0, window: { ...INIT_SEARCH.window, nonceRange: 8 } });
  await full.say(SEARCH);
  assert.deepEqual(full.log.hashes, quiet.log.hashes);
  assert.deepEqual(full.log.pauses, []);
});

test('SEARCH: the fresh context is used, the window is searched, and the FIRST solution is the only candidate', async () => {
  const { core, log, say, events } = makeSearchCore({ winner: 9 });
  assert.equal((await say(INIT_SEARCH)).ok, true);
  assert.equal(core.mode, WORKER_MODES.SEARCH);
  assert.deepEqual(log.contexts[0].height, CONTEXT.height);
  assert.equal(log.hashes.length, 0, 'init hashed');
  assert.equal((await say(SEARCH)).ok, true);
  // Nonces 0..9 were hashed and the search stopped at the first solution.
  assert.deepEqual(log.hashes, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(events('found').length, 1);
  assert.equal(events('found')[0].nonce, 9);
  assert.equal(events('found')[0].nonceHex, nonceToHex(9));
  const fin = events('finished')[0];
  assert.equal(fin.found, 1);
  assert.equal(fin.hashes, 10);
  assert.equal(fin.wasmHashCalls, fin.hashes, 'reported search work must match actual hasher calls');
  assert.equal(fin.timedOut, false);
});

test('SEARCH: no solution inside the window ends exhausted, with zero candidates', async () => {
  const { log, say, events } = makeSearchCore({ winner: null });
  await say(INIT_SEARCH);
  await say(SEARCH);
  assert.equal(log.hashes.length, 64);
  assert.equal(events('found').length, 0);
  const fin = events('finished')[0];
  assert.equal(fin.found, 0);
  assert.equal(fin.exhausted, true);
});

test('SEARCH: the frozen 120-second bound stops the search, whatever the window', async () => {
  const { log, say, events } = makeSearchCore({ winner: null, msPerHash: 1000 });
  await say({ ...INIT_SEARCH, window: { ...INIT_SEARCH.window, nonceRange: REAL_SEARCH_LIMITS.maxAttempts } });
  await say(SEARCH);
  assert.equal(log.hashes.length, 120, 'hashed past the time bound');
  const fin = events('finished')[0];
  assert.equal(fin.timedOut, true);
  assert.equal(fin.found, 0);
});

test('SEARCH: a window wider than 8,192, a longer time bound, or a bad target is refused before any hash', async () => {
  for (const [name, window] of [
    ['range 8193', { ...INIT_SEARCH.window, nonceRange: REAL_SEARCH_LIMITS.maxAttempts + 1 }],
    ['range 0', { ...INIT_SEARCH.window, nonceRange: 0 }],
    ['time 120001', { ...INIT_SEARCH.window, maxSearchMs: REAL_SEARCH_LIMITS.maxSearchMs + 1 }],
    ['past uint32', { ...INIT_SEARCH.window, nonceStart: 0xffffffff, nonceRange: 2 }],
    ['string start', { ...INIT_SEARCH.window, nonceStart: '0' }],
    ['bad target', { ...INIT_SEARCH.window, targetHexLE: 'zz' }],
  ]) {
    const { core, log, say } = makeSearchCore({ winner: 0 });
    const r = await say({ ...INIT_SEARCH, window });
    assert.equal(r.reason, WORKER_REFUSED.BAD_WINDOW, name);
    assert.equal(core.mode, WORKER_MODES.NONE, `${name}: the mode was locked`);
    assert.equal(log.contexts.length, 0, `${name}: a hasher was built`);
    assert.equal((await say(SEARCH)).reason, WORKER_REFUSED.WRONG_MODE, name);
    assert.equal(log.hashes.length, 0, name);
  }
});

test('SEARCH: one search only, the mode is locked, and a different job is refused', async () => {
  const { log, say } = makeSearchCore({ winner: null });
  await say(INIT_SEARCH);
  assert.equal((await say({ ...SEARCH, jobId: 'realjob-other' })).reason, WORKER_REFUSED.WRONG_JOB);
  assert.equal(log.hashes.length, 0);
  await say(SEARCH);
  const after = log.hashes.length;
  assert.equal((await say(SEARCH)).reason, WORKER_REFUSED.ALREADY_SEARCHED);
  for (const cmd of [HASH_ONE, WORK, { cmd: 'init', gen: GEN }, { ...INIT_CONTEXT }, { ...INIT_SEARCH }]) {
    const r = await say(cmd);
    assert.equal(r.ok, false, `${cmd.cmd} was accepted in search mode`);
  }
  assert.equal(log.hashes.length, after, 'a refused command hashed');
});

test('SEARCH: Stop ends the search and nothing re-arms it', async () => {
  const { log, say, events } = makeSearchCore({ winner: null });
  await say(INIT_SEARCH);
  const running = say(SEARCH);
  await say({ cmd: 'stop', gen: GEN + 1 });
  await running;
  assert.ok(log.hashes.length < 64, 'Stop did not end the search');
  assert.equal(events('found').length, 0);
  assert.equal((await say(SEARCH)).reason, WORKER_REFUSED.STOPPED);
});

test('SEARCH: recorded and synthetic Workers refuse the search commands', async () => {
  const rec = makeCore();
  await rec.say(INIT_CONTEXT);
  assert.equal((await rec.say(INIT_SEARCH)).reason, WORKER_REFUSED.MODE_LOCKED);
  assert.equal((await rec.say(SEARCH)).reason, WORKER_REFUSED.WRONG_MODE);
  const syn = makeCore();
  await syn.say({ cmd: 'init', gen: GEN });
  assert.equal((await syn.say(INIT_SEARCH)).reason, WORKER_REFUSED.MODE_LOCKED);
  assert.equal((await syn.say(SEARCH)).reason, WORKER_REFUSED.WRONG_MODE);
  assert.equal(rec.log.hashes.length + syn.log.hashes.length, 0);
});

// ================================================================== the two-block sequence: ONE Worker, re-contextualised
const JOB2 = 'realjob-2222222222222222';
const CONTEXT2 = { ...CONTEXT, height: '2114', hashingTemplateHex: `2020${'00'.repeat(74)}` };
const NEXT = {
  cmd: 'init_search_next',
  gen: GEN,
  prevJobId: JOB,
  jobId: JOB2,
  window: { nonceStart: 0, nonceRange: 64, targetHexLE: SEARCH_TARGET, maxSearchMs: 120_000 },
  context: CONTEXT2,
};
const SEARCH2 = { cmd: 'search', gen: GEN, jobId: JOB2 };

/**
 * A search core whose hashers model ONE module instance with ONE active context, as the real Wasm
 * adapter does: building a context tears the active one down first, free() tears it down, and a freed
 * or inactive hasher refuses to hash. Hashers are recorded so a test can prove which one ran.
 */
function makeRotatingCore({ winners = {}, buildFails = null, buildGate = null, searchImpl = searchNonces } = {}) {
  const log = { posted: [], hashes: [], contexts: [], hashers: [], modules: 0, frees: [], pauses: [] };
  const module = { active: null };
  const core = createWorkerCore({
    createModule: () => { log.modules += 1; return module; },
    createV2Hasher: async () => { throw new Error('the synthetic hasher must not be built'); },
    createV2HasherForContext: async (factory, ctx) => {
      const M = await factory();
      if (buildGate) await buildGate(log.hashers.length + 1);
      if (buildFails === log.hashers.length + 1) throw new Error('context setup failed');
      const id = log.hashers.length + 1;
      M.active = id;                                     // setup tears down whatever was active
      log.contexts.push(ctx);
      let freed = false;
      const h = {
        id,
        calls: 0,
        hashOne(nonce) {
          if (freed || M.active !== id) throw new Error(`hasher ${id} is not the active context`);
          this.calls++;
          log.hashes.push({ hasher: id, nonce });
          return new Uint8Array(32).fill(nonce === winners[id] ? 0x00 : 0xff);
        },
        get hashCalls() { return this.calls; },
        wasmHeapBytes: () => 48_562_176,
        isActive: () => !freed && M.active === id,
        free() { if (freed) return; freed = true; log.frees.push(id); if (M.active === id) M.active = null; },
      };
      log.hashers.push(h);
      return h;
    },
    searchNonces: searchImpl,
    hexToBytes,
    bytesToHex,
    nonceToHex,
    postMessage: (m) => log.posted.push(m),
    pauseAfterBatch: async (ms) => { log.pauses.push(ms); },
  });
  const say = (msg) => core.handle(msg);
  const events = (ev) => log.posted.filter((m) => m.ev === ev);
  return { core, log, say, events, module };
}

test('a search count that disagrees with the hasher cannot become an exact finished record', async () => {
  const c = makeRotatingCore({
    searchImpl: async (o) => {
      o.hashOne(o.nonceStart);
      return { hashes: 2, found: 0, stopped: false, exhausted: true };
    },
  });
  assert.equal((await c.say(INIT_SEARCH)).ok, true);
  const result = await c.say(SEARCH);
  assert.equal(result.ok, false);
  assert.match(c.events('error').at(-1).message, /count disagrees/);
  assert.equal(c.events('finished').length, 0, 'a false exact count escaped');
  assert.equal(c.log.hashes.length, 1);
  assert.equal((await c.say(SEARCH)).reason, WORKER_REFUSED.ALREADY_SEARCHED);
  assert.equal(c.log.hashes.length, 1, 'the mismatch was retried');
});

test('ROTATION: the SAME Worker, after its first search settled, frees the old context and searches the next one once', async () => {
  const { core, log, say, events, module } = makeRotatingCore({ winners: { 1: 5, 2: 7 } });
  await say(INIT_SEARCH);
  await say(SEARCH);
  assert.equal(events('found')[0].jobId, JOB);
  const r = await say(NEXT);
  assert.equal(r.ok, true, JSON.stringify(log.posted.at(-1)));
  const ready = events('ready').at(-1);
  assert.equal(ready.jobId, JOB2);
  assert.equal(ready.rotated, true);
  assert.equal(ready.contextIndex, 2);
  assert.equal(ready.moduleInstances, 1, 'a second module instance was created');
  assert.equal(ready.priorContextFreed, true);
  assert.equal(ready.priorContextActive, false);
  assert.equal(log.modules, 1);
  assert.deepEqual(log.frees, [1], 'the previous context was not freed');
  assert.equal(module.active, 2);
  assert.equal(log.contexts[1].height, CONTEXT2.height);
  // The old hasher can never hash again.
  assert.throws(() => log.hashers[0].hashOne(1), /not the active context/);
  // A late job-1 search is refused with zero hashes; the job-2 search runs on hasher 2 only.
  const before = log.hashes.length;
  assert.equal((await say(SEARCH)).reason, WORKER_REFUSED.WRONG_JOB);
  assert.equal(log.hashes.length, before);
  await say(SEARCH2);
  const job2Hashes = log.hashes.slice(before);
  assert.deepEqual(job2Hashes.map((h) => h.hasher), Array(8).fill(2));
  assert.equal(events('found').at(-1).jobId, JOB2);
  assert.equal(events('found').at(-1).nonce, 7);
  assert.equal(events('finished').at(-1).jobId, JOB2);
  assert.ok(log.posted.slice(log.posted.indexOf(ready)).every((m) => m.jobId === undefined || m.jobId === JOB2),
    'a message after the rotation named job 1');
  assert.equal((await say(SEARCH2)).reason, WORKER_REFUSED.ALREADY_SEARCHED);
  // No third context, ever.
  assert.equal((await say({ ...NEXT, prevJobId: JOB2, jobId: 'realjob-3333333333333333' })).reason, WORKER_REFUSED.SEQUENCE_EXHAUSTED);
  assert.equal(core.contextsBuilt, 2);
  assert.equal(core.activeGeneration, GEN, 'the rotation moved the generation');
});

test('ROTATION: the chosen pace remains latched across a fresh second block context', async () => {
  const { log, say } = makeRotatingCore({ winners: { 1: 4, 2: 4 } });
  await say({ ...INIT_SEARCH, pacingMs: 100 });
  await say(SEARCH);
  assert.deepEqual(log.pauses, [100]);
  await say({ ...NEXT, pacingMs: 0 }); // a successor cannot change the first Start's choice
  await say(SEARCH2);
  assert.deepEqual(log.pauses, [100, 100]);
  assert.equal(log.modules, 1);
});

test('ROTATION is refused -- with the old context untouched -- unless the previous search completely settled and is named exactly', async () => {
  // Before any search.
  let c = makeRotatingCore({ winners: { 1: 5 } });
  await c.say(INIT_SEARCH);
  assert.equal((await c.say(NEXT)).reason, WORKER_REFUSED.NOT_SETTLED);
  assert.deepEqual(c.log.frees, []);
  // While the search is running.
  c = makeRotatingCore({ winners: {} });
  await c.say(INIT_SEARCH);
  const running = c.say(SEARCH);
  assert.equal((await c.say(NEXT)).reason, WORKER_REFUSED.BUSY);
  await running;
  assert.deepEqual(c.log.frees, []);
  // Settled, but mis-bound.
  for (const [name, msg, reason] of [
    ['stale generation', { ...NEXT, gen: GEN + 1 }, WORKER_REFUSED.STALE_GENERATION],
    ['wrong previous job', { ...NEXT, prevJobId: 'realjob-9999999999999999' }, WORKER_REFUSED.WRONG_JOB],
    ['same job again', { ...NEXT, jobId: JOB }, WORKER_REFUSED.WRONG_JOB],
    ['no job', { ...NEXT, jobId: undefined }, WORKER_REFUSED.WRONG_JOB],
  ]) {
    const d = makeRotatingCore({ winners: { 1: 5 } });
    await d.say(INIT_SEARCH);
    await d.say(SEARCH);
    assert.equal((await d.say(msg)).reason, reason, name);
    assert.deepEqual(d.log.frees, [], `${name}: the old context was freed by a refused rotation`);
    assert.equal(d.log.hashers.length, 1, `${name}: a context was built`);
  }
  // Not a search Worker at all.
  const rec = makeCore();
  await rec.say(INIT_CONTEXT);
  assert.equal((await rec.say(NEXT)).reason, WORKER_REFUSED.WRONG_MODE);
  const fresh = makeRotatingCore();
  assert.equal((await fresh.say(NEXT)).reason, WORKER_REFUSED.WRONG_MODE);
  assert.equal(fresh.log.hashers.length, 0);
  // After Stop.
  const stopped = makeRotatingCore({ winners: { 1: 5 } });
  await stopped.say(INIT_SEARCH);
  await stopped.say(SEARCH);
  await stopped.say({ cmd: 'stop', gen: GEN + 1 });
  assert.equal((await stopped.say(NEXT)).reason, WORKER_REFUSED.STOPPED);
  assert.equal(stopped.log.hashers.length, 1);
});

test('ROTATION that is MALFORMED or FAILS leaves no context able to hash, and cannot be retried', async () => {
  for (const [name, msg, opts] of [
    ['window wider than 8,192', { ...NEXT, window: { ...NEXT.window, nonceRange: REAL_SEARCH_LIMITS.maxAttempts + 1 } }, {}],
    ['bad target', { ...NEXT, window: { ...NEXT.window, targetHexLE: 'zz' } }, {}],
    ['context setup failure', NEXT, { buildFails: 2 }],
  ]) {
    const { core, log, say, events } = makeRotatingCore({ winners: { 1: 5, 2: 3 }, ...opts });
    await say(INIT_SEARCH);
    await say(SEARCH);
    const hashesBefore = log.hashes.length;
    const r = await say(msg);
    assert.equal(r.ok, false, name);
    assert.deepEqual(log.frees, [1], `${name}: the old context survived`);
    assert.equal(log.hashers[0].isActive(), false, name);
    assert.equal(core.hasContext, false, name);
    assert.equal(events('ready').length, 1, `${name}: a ready was posted`);
    for (const cmd of [SEARCH, SEARCH2]) assert.equal((await say(cmd)).reason, WORKER_REFUSED.NOT_READY, `${name}: ${cmd.jobId}`);
    assert.equal((await say(NEXT)).reason, WORKER_REFUSED.NOT_SETTLED, `${name}: retried`);
    assert.equal(log.hashes.length, hashesBefore, `${name}: something hashed`);
  }
});

test('ROTATION fails closed before allocation when prior-context release throws or stays active', async () => {
  for (const [name, corrupt] of [
    ['free throws', (h) => { h.free = () => { throw new Error('teardown failed'); }; }],
    ['context stays active', (h) => { h.isActive = () => true; }],
  ]) {
    const { core, log, say, events } = makeRotatingCore({ winners: { 1: 5, 2: 3 } });
    await say(INIT_SEARCH);
    await say(SEARCH);
    corrupt(log.hashers[0]);
    const hashesBefore = log.hashes.length;
    const r = await say(NEXT);
    assert.equal(r.ok, false, name);
    assert.equal(r.reason, 'error', name);
    assert.equal(log.hashers.length, 1, `${name}: a replacement context was allocated`);
    assert.equal(log.contexts.length, 1, `${name}: replacement context bytes were accepted`);
    assert.equal(log.modules, 1, `${name}: another module was created`);
    assert.equal(core.contextsBuilt, 1, `${name}: the context counter advanced`);
    assert.equal(core.hasContext, false, `${name}: an unconfirmed context stayed usable`);
    assert.equal(events('ready').length, 1, `${name}: replacement readiness was announced`);
    assert.equal(events('error').length, 1, `${name}: the Worker did not signal a terminal error`);
    assert.equal((await say(SEARCH2)).reason, WORKER_REFUSED.NOT_READY, name);
    assert.equal(log.hashes.length, hashesBefore, `${name}: something hashed after release failure`);
  }
});

test('ROTATION: a Stop while the next context is being built means it never becomes usable', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const { log, say, events } = makeRotatingCore({ winners: { 1: 5 }, buildGate: async (n) => { if (n === 2) await gate; } });
  await say(INIT_SEARCH);
  await say(SEARCH);
  const rotating = say(NEXT);
  await say({ cmd: 'stop', gen: GEN + 1 });
  release();
  const r = await rotating;
  assert.equal(r.reason, WORKER_REFUSED.STOPPED);
  assert.deepEqual(log.frees, [1, 2], 'the context built after Stop was not freed');
  assert.equal(events('ready').length, 1);
  assert.equal((await say(SEARCH2)).reason, WORKER_REFUSED.STOPPED);
  assert.equal(log.hashes.filter((h) => h.hasher === 2).length, 0);
});

// ================================================================== configured finite sequences and external supersession
const sequenceJob = (n) => `realjob-${String(n).padStart(16, '0')}`;
const sequenceContext = (n) => ({
  ...CONTEXT,
  height: String(2112 + n),
  hashingTemplateHex: `${(n & 0xff).toString(16).padStart(2, '0')}10${'00'.repeat(74)}`,
});
const sequenceInit = (total) => ({
  ...INIT_SEARCH,
  jobId: sequenceJob(1),
  sequenceTotal: total,
  window: { ...INIT_SEARCH.window, nonceRange: 1 },
  context: sequenceContext(1),
});
const sequenceNext = (from, to, total) => ({
  ...NEXT,
  prevJobId: sequenceJob(from),
  jobId: sequenceJob(to),
  sequenceTotal: total,
  window: { ...NEXT.window, nonceRange: 1 },
  context: sequenceContext(to),
});
const sequenceSearch = (n) => ({ cmd: 'search', gen: GEN, jobId: sequenceJob(n) });

for (const total of [3, 12, 32]) {
  test(`ROTATION LIMIT ${total}: one module builds exactly ${total} contexts and refuses context ${total + 1}`, async () => {
    const c = makeRotatingCore();
    assert.equal((await c.say(sequenceInit(total))).ok, true);
    for (let n = 1; n <= total; n += 1) {
      assert.equal((await c.say(sequenceSearch(n))).ok, true, `search ${n}`);
      if (n < total) assert.equal((await c.say(sequenceNext(n, n + 1, total))).ok, true, `context ${n + 1}`);
    }
    assert.equal(c.core.contextsBuilt, total);
    assert.equal(c.core.sequenceLimit, total);
    assert.equal(c.log.modules, 1);
    assert.deepEqual(c.log.frees, Array.from({ length: total - 1 }, (_, i) => i + 1));
    for (let i = 0; i < total - 1; i += 1) {
      assert.equal(c.log.hashers[i].isActive(), false, `old context ${i + 1} is still active`);
    }
    const before = { contexts: c.log.contexts.length, frees: c.log.frees.length, hashes: c.log.hashes.length };
    const over = await c.say(sequenceNext(total, total + 1, total));
    assert.equal(over.reason, WORKER_REFUSED.SEQUENCE_EXHAUSTED);
    assert.deepEqual({ contexts: c.log.contexts.length, frees: c.log.frees.length, hashes: c.log.hashes.length }, before);
  });
}

test('ROTATION LIMIT: malformed initial totals fail before mode lock or allocation; a changed total leaves the live context intact', async () => {
  for (const bad of [0, 33, 2.5, '3', null]) {
    const c = makeRotatingCore();
    const r = await c.say(sequenceInit(bad));
    assert.equal(r.reason, WORKER_REFUSED.BAD_SEQUENCE, String(bad));
    assert.equal(c.core.mode, WORKER_MODES.NONE, String(bad));
    assert.equal(c.log.contexts.length, 0, String(bad));
  }

  const c = makeRotatingCore();
  await c.say(sequenceInit(3));
  await c.say(sequenceSearch(1));
  const r = await c.say(sequenceNext(1, 2, 4));
  assert.equal(r.reason, WORKER_REFUSED.BAD_SEQUENCE);
  assert.equal(c.log.hashers[0].isActive(), true);
  assert.deepEqual(c.log.frees, []);
  assert.equal(c.log.contexts.length, 1);
});

test('SUPERSESSION before search settles once, hashes zero, is idempotent, and permits the next context', async () => {
  const c = makeRotatingCore();
  await c.say(sequenceInit(3));
  const first = await c.say({ cmd: 'supersede_search', gen: GEN, jobId: sequenceJob(1) });
  assert.equal(first.ok, true);
  const [finished] = c.events('finished');
  assert.deepEqual({ jobId: finished.jobId, hashes: finished.hashes, superseded: finished.superseded },
    { jobId: sequenceJob(1), hashes: 0, superseded: true });
  assert.equal((await c.say({ cmd: 'supersede_search', gen: GEN, jobId: sequenceJob(1) })).idempotent, true);
  assert.equal(c.events('finished').length, 1);
  assert.equal((await c.say(sequenceNext(1, 2, 3))).ok, true);
  assert.equal(c.core.contextsBuilt, 2);
  assert.equal(c.log.modules, 1);
});

test('SUPERSESSION during an active search stops that context and reuses the same Worker for the next one', async () => {
  let entered;
  let release;
  const atBatch = new Promise((resolve) => { entered = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const controlledSearch = async (o) => {
    for (let nonce = 0; nonce < 4; nonce += 1) o.hashOne(nonce);
    o.onProgress({ hashes: 4, lastNonce: 3 });
    entered();
    await gate;
    return { hashes: 4, found: 0, stopped: o.shouldStop(), exhausted: false };
  };
  const c = makeRotatingCore({ searchImpl: controlledSearch });
  await c.say(sequenceInit(3));
  const searching = c.say(sequenceSearch(1));
  await atBatch;
  assert.equal((await c.say({ cmd: 'supersede_search', gen: GEN, jobId: sequenceJob(1) })).ok, true);
  release();
  await searching;
  assert.equal(c.events('found').length, 0);
  const finished = c.events('finished').at(-1);
  assert.deepEqual({ hashes: finished.hashes, superseded: finished.superseded }, { hashes: 4, superseded: true });
  assert.equal((await c.say(sequenceNext(1, 2, 3))).ok, true);
  assert.equal(c.core.contextsBuilt, 2);
  assert.equal(c.log.modules, 1);
});

test('SUPERSESSION while the first context is building is deferred until the hasher exists', async () => {
  let entered;
  let release;
  const atBuild = new Promise((resolve) => { entered = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const c = makeRotatingCore({ buildGate: async (n) => { if (n === 1) { entered(); await gate; } } });
  const init = c.say(sequenceInit(3));
  await atBuild;
  const supersede = await c.say({ cmd: 'supersede_search', gen: GEN, jobId: sequenceJob(1) });
  assert.equal(supersede.pending, true);
  assert.equal(c.events('finished').length, 0, 'settlement was announced before construction returned');
  release();
  assert.equal((await init).superseded, true);
  assert.equal(c.events('ready').length, 0, 'the obsolete context became ready');
  assert.equal(c.events('finished').at(-1).jobId, sequenceJob(1));
  assert.equal((await c.say(sequenceNext(1, 2, 3))).ok, true);
});

test('SUPERSESSION while a rotated context is building skips its ready/search and can rotate again', async () => {
  let entered;
  let release;
  const atBuild = new Promise((resolve) => { entered = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const c = makeRotatingCore({ buildGate: async (n) => { if (n === 2) { entered(); await gate; } } });
  await c.say(sequenceInit(3));
  await c.say(sequenceSearch(1));
  const rotating = c.say(sequenceNext(1, 2, 3));
  await atBuild;
  const supersede = await c.say({ cmd: 'supersede_search', gen: GEN, jobId: sequenceJob(2) });
  assert.equal(supersede.pending, true);
  release();
  assert.equal((await rotating).superseded, true);
  assert.equal(c.events('ready').some((e) => e.jobId === sequenceJob(2)), false, 'obsolete context 2 became ready');
  assert.equal(c.events('finished').at(-1).jobId, sequenceJob(2));
  assert.equal((await c.say(sequenceNext(2, 3, 3))).ok, true);
  assert.equal(c.core.contextsBuilt, 3);
  assert.equal(c.log.modules, 1);
  assert.deepEqual(c.log.frees, [1, 2]);
});

test('SUPERSESSION refuses a wrong job, wrong mode, stale generation and post-Stop request without work', async () => {
  const c = makeRotatingCore();
  await c.say(sequenceInit(3));
  const before = () => ({ hashes: c.log.hashes.length, contexts: c.log.contexts.length, frees: c.log.frees.length });
  const original = before();
  assert.equal((await c.say({ cmd: 'supersede_search', gen: GEN, jobId: 'realjob-wrong' })).reason, WORKER_REFUSED.WRONG_JOB);
  assert.equal((await c.say({ cmd: 'supersede_search', gen: GEN + 1, jobId: sequenceJob(1) })).reason, WORKER_REFUSED.STALE_GENERATION);
  assert.deepEqual(before(), original);
  await c.say({ cmd: 'stop', gen: GEN + 1 });
  assert.equal((await c.say({ cmd: 'supersede_search', gen: GEN, jobId: sequenceJob(1) })).reason, WORKER_REFUSED.STOPPED);
  assert.deepEqual(before(), original);

  const recorded = makeCore();
  await recorded.say(INIT_CONTEXT);
  assert.equal((await recorded.say({ cmd: 'supersede_search', gen: GEN, jobId: JOB })).reason, WORKER_REFUSED.WRONG_MODE);
  assert.equal(recorded.log.hashes.length, 0);
});

// ---------------------------------------------------------------- the refresh context budget
//
// `contextLimit` is the OPT-IN per-block WINDOW total. It is independently bounded by the refresh
// limit; when a block total is also present, their product is the Worker's immutable total-context
// ceiling and may not exceed the 32-context development cap.

test('CONTEXT BUDGET: a refresh window total is accepted, and an over-limit one is refused unallocated', async () => {
  const ok = makeSearchCore();
  const accepted = await ok.say({
    ...INIT_SEARCH, sequenceTotal: 1, contextLimit: REAL_REFRESH_LIMITS.maxWindows,
  });
  assert.equal(accepted.ok, true, JSON.stringify(accepted));
  assert.equal(ok.core.sequenceLimit, REAL_REFRESH_LIMITS.maxWindows);
  assert.equal(ok.core.mode, WORKER_MODES.SEARCH);

  // FIVE IS NOT A WINDOW TOTAL THIS BUILD HAS. The 32-block sequence validator used to accept it.
  for (const bad of [REAL_REFRESH_LIMITS.maxWindows + 1, 8, 32, 0, 1.5, '3', null]) {
    const h = makeSearchCore();
    const r = await h.say({ ...INIT_SEARCH, sequenceTotal: 1, contextLimit: bad });
    assert.equal(r.ok, false, `contextLimit ${JSON.stringify(bad)} was accepted`);
    assert.equal(r.reason, WORKER_REFUSED.BAD_SEQUENCE, JSON.stringify(bad));
    assert.equal(h.core.mode, WORKER_MODES.NONE, `contextLimit ${JSON.stringify(bad)} locked the mode`);
    assert.equal(h.core.hasContext, false, `contextLimit ${JSON.stringify(bad)} allocated a context`);
    assert.equal(h.log.contexts.length, 0, `contextLimit ${JSON.stringify(bad)} built a dataset`);
    assert.equal(h.core.sequenceLimit, 1);
  }
});

test('CONTEXT BUDGET: blocks and windows compose under one 32-context ceiling', async () => {
  const h = makeSearchCore();
  const accepted = await h.say({
    ...INIT_SEARCH, sequenceTotal: 8, contextLimit: 4, sequenceIndex: 1, windowIndex: 1,
  });
  assert.equal(accepted.ok, true);
  assert.equal(h.core.contextBudgetKind, 'composed');
  assert.equal(h.core.sequenceLimit, 32);
  assert.equal(h.core.declaredSequenceTotal, 8);
  assert.equal(h.core.declaredWindowTotal, 4);
  assert.deepEqual([h.core.currentSequenceIndex, h.core.currentWindowIndex], [1, 1]);

  for (const [label, over] of [
    ['a product above 32', { sequenceTotal: 9, contextLimit: 4, sequenceIndex: 1, windowIndex: 1 }],
    ['a missing block coordinate', { sequenceTotal: 2, contextLimit: 2, windowIndex: 1 }],
    ['a non-initial block coordinate', { sequenceTotal: 2, contextLimit: 2, sequenceIndex: 2, windowIndex: 1 }],
    ['a non-initial window coordinate', { sequenceTotal: 2, contextLimit: 2, sequenceIndex: 1, windowIndex: 2 }],
  ]) {
    const invalid = makeSearchCore();
    const r = await invalid.say({ ...INIT_SEARCH, ...over });
    assert.equal(r.reason, WORKER_REFUSED.BAD_SEQUENCE, label);
    assert.equal(invalid.core.mode, WORKER_MODES.NONE, label);
    assert.equal(invalid.log.contexts.length, 0, `${label}: a dataset was allocated`);
  }

  // A window total with no declared sequence total at all is refused too: the page always sends it.
  const bare = makeSearchCore();
  const r = await bare.say({ ...INIT_SEARCH, contextLimit: 2 });
  assert.equal(r.ok, false);
  assert.equal(r.reason, WORKER_REFUSED.BAD_SEQUENCE);
  assert.equal(bare.core.mode, WORKER_MODES.NONE);

  // And a plain block sequence still latches its own block total, exactly as before.
  const blocks = makeSearchCore();
  assert.equal((await blocks.say({ ...INIT_SEARCH, sequenceTotal: 3 })).ok, true);
  assert.equal(blocks.core.sequenceLimit, 3);
});

// ---------------------------------------------------------------- the successor budget form
//
// The budget KIND is latched at init_search -- 'sequence' (blocks) or 'refresh' (windows of one
// height) -- and EVERY init_search_next must repeat the exact form it was given, before the old
// context is touched. A wrong, omitted or combined form refuses with zero frees and zero
// allocations, and the old context stays live.

test('SUCCESSOR FORM: a refresh run repeats sequenceTotal 1 plus the exact window total, or refuses unharmed', async () => {
  const c = makeRotatingCore();
  assert.equal((await c.say({ ...INIT_SEARCH, jobId: sequenceJob(1), sequenceTotal: 1, contextLimit: 3, window: { ...INIT_SEARCH.window, nonceRange: 1 }, context: sequenceContext(1) })).ok, true);
  assert.equal(c.core.contextBudgetKind, 'refresh');
  await c.say(sequenceSearch(1));

  // The exact form is accepted.
  const next = (over = {}) => c.say({
    ...NEXT,
    prevJobId: sequenceJob(1),
    jobId: sequenceJob(2),
    sequenceTotal: 1,
    contextLimit: 3,
    window: { ...NEXT.window, nonceRange: 1 },
    context: sequenceContext(2),
    ...over,
  });
  // Every wrong form refuses, with the old context INTACT: no free, no new allocation, and the
  // live context still able to hash.
  for (const [label, over] of [
    ['an omitted window total', { contextLimit: undefined }],
    ['a wrong window total', { contextLimit: 2 }],
    ['an over-limit window total', { contextLimit: REAL_REFRESH_LIMITS.maxWindows + 1 }],
    ['an omitted sequenceTotal', { sequenceTotal: undefined }],
    ['a block-sequence sequenceTotal', { sequenceTotal: 3 }],
  ]) {
    const before = { contexts: c.log.contexts.length, frees: c.log.frees.length, hashes: c.log.hashes.length };
    const r = await next(over);
    assert.equal(r.ok, false, `${label}: the wrong successor form was accepted`);
    assert.equal(r.reason, WORKER_REFUSED.BAD_SEQUENCE, label);
    assert.deepEqual(
      { contexts: c.log.contexts.length, frees: c.log.frees.length, hashes: c.log.hashes.length },
      before,
      `${label}: the refusal freed or allocated something`,
    );
    assert.equal(c.log.hashers[0].isActive(), true, `${label}: the old context was torn down`);
  }
  // The exact form still succeeds afterwards, on the same Worker.
  assert.equal((await next()).ok, true);
  assert.equal(c.core.contextsBuilt, 2);
  assert.deepEqual(c.log.frees, [1]);
});

test('SUCCESSOR FORM: a composed run advances one exact block/window coordinate before teardown', async () => {
  const c = makeRotatingCore();
  assert.equal((await c.say({
    ...sequenceInit(3), contextLimit: 2, sequenceIndex: 1, windowIndex: 1,
  })).ok, true);
  assert.equal(c.core.contextBudgetKind, 'composed');
  assert.equal(c.core.sequenceLimit, 6);
  await c.say(sequenceSearch(1));

  const successor = (from, to, sequenceIndex, windowIndex, over = {}) => c.say({
    ...sequenceNext(from, to, 3),
    contextLimit: 2,
    sequenceIndex,
    windowIndex,
    ...over,
  });
  for (const [label, sequenceIndex, windowIndex, over] of [
    ['a replayed coordinate', 1, 1, {}],
    ['a skipped window', 1, 3, {}],
    ['a next block that did not reset its window', 2, 2, {}],
    ['a skipped block', 3, 1, {}],
    ['a changed block total', 1, 2, { sequenceTotal: 2 }],
    ['a changed window total', 1, 2, { contextLimit: 3 }],
    ['an omitted coordinate', undefined, 2, {}],
  ]) {
    const before = { contexts: c.log.contexts.length, frees: c.log.frees.length };
    const r = await successor(1, 2, sequenceIndex, windowIndex, over);
    assert.equal(r.reason, WORKER_REFUSED.BAD_SEQUENCE, label);
    assert.deepEqual({ contexts: c.log.contexts.length, frees: c.log.frees.length }, before,
      `${label}: validation happened after teardown or allocation`);
    assert.equal(c.log.hashers[0].isActive(), true, `${label}: the old context was not left live`);
  }

  assert.equal((await successor(1, 2, 1, 2)).ok, true, 'the next window was refused');
  assert.deepEqual([c.core.currentSequenceIndex, c.core.currentWindowIndex], [1, 2]);
  await c.say(sequenceSearch(2));
  assert.equal((await successor(2, 3, 2, 1)).ok, true, 'the next block/window reset was refused');
  assert.deepEqual([c.core.currentSequenceIndex, c.core.currentWindowIndex], [2, 1]);
  assert.equal(c.core.contextsBuilt, 3);
  assert.equal(c.log.modules, 1);
  assert.deepEqual(c.log.frees, [1, 2]);
});

test('SUCCESSOR FORM: a pure sequence repeats its declared block total and cannot switch budget kind', async () => {
  const c = makeRotatingCore();
  await c.say(sequenceInit(3));
  assert.equal(c.core.contextBudgetKind, 'sequence');
  await c.say(sequenceSearch(1));

  const next = (over = {}) => c.say({ ...sequenceNext(1, 2, 3), ...over });
  // A window total was not part of this init, so it cannot be added mid-run.
  for (const [label, over] of [
    ['a window total beside the block total', { contextLimit: 2 }],
    ['a window total replacing the block total', { contextLimit: 2, sequenceTotal: undefined }],
    ['a changed block total', { sequenceTotal: 4 }],
    ['an omitted block total after an explicit declaration', { sequenceTotal: undefined }],
  ]) {
    const before = { contexts: c.log.contexts.length, frees: c.log.frees.length, hashes: c.log.hashes.length };
    const r = await next(over);
    assert.equal(r.ok, false, `${label}: the wrong successor form was accepted`);
    assert.equal(r.reason, WORKER_REFUSED.BAD_SEQUENCE, label);
    assert.deepEqual(
      { contexts: c.log.contexts.length, frees: c.log.frees.length, hashes: c.log.hashes.length },
      before,
      `${label}: the refusal freed or allocated something`,
    );
    assert.equal(c.log.hashers[0].isActive(), true, `${label}: the old context was torn down`);
  }
  assert.equal((await next()).ok, true);

  // The historical direct-caller form -- an init that declared NO total -- keeps accepting a
  // successor that also declares none, exactly as before.
  const legacy = makeRotatingCore();
  await legacy.say({ ...INIT_SEARCH, jobId: sequenceJob(1), window: { ...INIT_SEARCH.window, nonceRange: 1 }, context: sequenceContext(1) });
  await legacy.say(sequenceSearch(1));
  assert.equal((await legacy.say({ ...NEXT, prevJobId: sequenceJob(1), jobId: sequenceJob(2), window: { ...NEXT.window, nonceRange: 1 }, context: sequenceContext(2) })).ok, true,
    'the historical no-total rotation was refused');
});
