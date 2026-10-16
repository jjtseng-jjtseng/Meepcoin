// THE PAGE'S OWN WORDS ABOUT A SAME-HEIGHT REFRESH RUN. The real app.js rendering, with only an
// in-memory DOM, socket and Worker: no browser, no listener, no server.
//
// What is checked is FACT, not phrasing: that the status names which window of how many this Start
// is on, that the cumulative attempt count across windows is shown at all, and that the prospective
// bounds are derived from the shared constants rather than from a sentence written for a run that
// searches one window. The two text helpers are pure functions of the snapshot, so the numbers can
// be checked exactly without asserting a wording snapshot.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  REAL_DAEMON_MODE, REAL_REFRESH_LIMITS, REAL_SEARCH_LIMITS,
} from '../lib/shared/protocol.js';

const BLOCK_TARGET = `01${'00'.repeat(31)}`;
const SHARE_TARGET = `${'00'.repeat(31)}01`;
let appImportId = 0;

async function appHarness() {
  const previous = Object.fromEntries(['document', 'window', 'location', 'WebSocket', 'Worker']
    .map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  const elements = new Map();
  const sockets = [];
  const workers = [];
  const element = () => ({
    textContent: '', hidden: false, disabled: false, dataset: {}, childElementCount: 0,
    handlers: new Map(),
    addEventListener(type, fn) { this.handlers.set(type, fn); },
    setAttribute() {},
    append(...children) { this.childElementCount += children.length; },
    click() { this.handlers.get('click')?.(); },
  });
  elements.set('search-pace', { ...element(), value: '0' });
  globalThis.document = {
    visibilityState: 'visible',
    getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); },
    createElement: element,
    addEventListener() {},
  };
  globalThis.window = { addEventListener() {} };
  globalThis.location = { protocol: 'http:', host: '127.0.0.1:8171' };
  globalThis.WebSocket = class {
    constructor(url) { this.url = url; this.sent = []; sockets.push(this); }
    send(raw) { this.sent.push(JSON.parse(raw)); }
    close() {}
    open() { this.onopen?.(); }
    deliver(msg) { this.onmessage?.({ data: JSON.stringify(msg) }); }
  };
  globalThis.Worker = class {
    constructor() { this.posted = []; workers.push(this); }
    postMessage(msg) { this.posted.push(msg); }
    terminate() {}
    emit(msg) { this.onmessage?.({ data: msg }); }
  };
  const mod = await import(`../app.js?window-refresh-test=${++appImportId}`);
  const restore = () => {
    for (const [name, descriptor] of Object.entries(previous)) {
      if (descriptor === undefined) delete globalThis[name];
      else Object.defineProperty(globalThis, name, descriptor);
    }
  };
  return { elements, socket: sockets[0], workers, restore, mod };
}

const JOB1 = {
  type: 'real_job', jobId: 'realjob-w1', issuanceId: '1'.repeat(32), contentDigest: 'c'.repeat(64),
  algorithm: 'meephash-w-v2-frozen-real-template', height: '1', majorVersion: 16,
  epochKeyHex: 'e'.repeat(64), seedHashHex: 'e'.repeat(64),
  hashingTemplateHex: `1010${'00'.repeat(74)}`, targetHexLE: BLOCK_TARGET,
  shareWork: true, shareTargetHexLE: SHARE_TARGET,
  nonceStart: 0, nonceRange: REAL_SEARCH_LIMITS.maxAttempts, expiresAtMs: 1,
};
const JOB2 = {
  ...JOB1, jobId: 'realjob-w2', issuanceId: '2'.repeat(32), nonceStart: REAL_SEARCH_LIMITS.maxAttempts,
};

test('APP REFRESH TEXT: the prospective bounds and window position are computed from the constants', async () => {
  const h = await appHarness();
  try {
    const { realProspectiveBoundsText, realWindowPositionText } = h.mod;
    // A single-window run says what it has always said, and names no window.
    const one = { realWindowTotal: 1, realWindowIndex: 1 };
    assert.equal(realWindowPositionText(one), null);
    assert.match(realProspectiveBoundsText(one), /at most 8,192 nonces or 120 seconds/);
    assert.equal(/windows/.test(realProspectiveBoundsText(one)), false,
      'a one-window run advertised several windows');

    // A refresh run states BOTH caps, from the shared constants, and which window it is on.
    const many = {
      realWindowTotal: REAL_REFRESH_LIMITS.maxWindows, realWindowIndex: 2, realActiveWindowIndex: 2,
    };
    const text = realProspectiveBoundsText(many);
    assert.match(text, /each window at most 8,192 nonces or 120 seconds/);
    assert.match(text, new RegExp(`at most ${REAL_REFRESH_LIMITS.maxWindows} windows`));
    assert.match(text, new RegExp(`at most ${REAL_REFRESH_LIMITS.maxSessionMs / 60000} minutes`));
    assert.equal(realWindowPositionText(many), `window 2 of ${REAL_REFRESH_LIMITS.maxWindows} (same block height)`);
    assert.equal(realWindowPositionText({ realWindowTotal: 3 }), 'window 1 of 3 (same block height)');
    // THE TWO HANDOVER PHASES ARE SAID OUT LOUD AND DISTINCTLY: while the old context is still
    // settling it is RETIRING (the page may not claim nothing at all is hashing); once it has
    // settled, the page may say nothing is being hashed while the next window is prepared.
    assert.equal(
      realWindowPositionText({ realWindowTotal: 3, realWindowIndex: 2, realActiveWindowIndex: 1, realWindowRetiring: true }),
      'window 1 of 3 retiring; preparing window 2 (same block height)',
    );
    assert.equal(
      realWindowPositionText({ realWindowTotal: 3, realWindowIndex: 2, realActiveWindowIndex: 1, realWindowRetiring: false }),
      'window 1 of 3 searched; preparing window 2 (same block height)',
    );
  } finally {
    h.restore();
  }
});

test('APP SEQUENCE TEXT: success does not mislabel daemon-selected difficulty as fixed', async () => {
  const h = await appHarness();
  try {
    const note = h.mod.realSequenceSuccessNote(3);
    assert.match(note, /3 consecutive blocks/);
    assert.match(note, /private local nodes/);
    assert.doesNotMatch(note, /fixed test difficulty/i);
    assert.match(note, /does not establish public-network mining or a final difficulty policy/i);
  } finally {
    h.restore();
  }
});

test('APP COMPOSED TEXT: block and window coordinates plus the whole-Start bound are explicit', async () => {
  const h = await appHarness();
  try {
    const { realProspectiveBoundsText, realWindowPositionText, realWindowHandoff } = h.mod;
    const active = {
      realSequenceTotal: 3, realBlockIndex: 2, realActiveBlockIndex: 2,
      realWindowTotal: 4, realWindowIndex: 3, realActiveWindowIndex: 3,
    };
    assert.equal(realWindowPositionText(active), 'block 2 of 3, window 3 of 4');
    const bounds = realProspectiveBoundsText(active);
    assert.match(bounds, /at most 4 windows per block across 3 blocks/);
    assert.match(bounds, new RegExp(`at most ${REAL_REFRESH_LIMITS.maxSessionMs / 60000} minutes for the whole Start`));

    const betweenBlocks = {
      ...active, realBlockIndex: 3, realWindowIndex: 1, realWindowHandoff: true,
      realWindowRetiring: false,
    };
    assert.equal(realWindowHandoff(betweenBlocks), true);
    assert.equal(
      realWindowPositionText(betweenBlocks),
      'block 2 of 3, window 3 of 4 searched; preparing block 3 of 3, window 1 of 4',
    );
  } finally {
    h.restore();
  }
});

test('APP REFRESH: the live status shows the window position, the cumulative attempts and the real bounds', async () => {
  const h = await appHarness();
  try {
    const { socket } = h;
    socket.open();
    socket.deliver({
      type: 'server_hello', protocolVersion: 1, mode: REAL_DAEMON_MODE, workerId: 'sim-1-bbbb',
      labels: [], alreadyCompleted: false, searchLimits: REAL_SEARCH_LIMITS,
      windowTotal: 3, sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs,
    });
    socket.deliver(JOB1);
    h.elements.get('start-btn').click();
    const start = socket.sent.find((m) => m.type === 'start_request');
    const bind1 = {
      clientStartId: start.clientStartId, workerId: 'sim-1-bbbb', jobId: JOB1.jobId,
      issuanceId: JOB1.issuanceId, runGeneration: 1,
    };
    socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...bind1 });
    // PRE-READY: the page is PREPARING, and must not say "Searching window 1" of a refresh run.
    assert.equal(h.elements.get('state').textContent.length > 0, true);
    const preReadyNote = h.elements.get('controls-note').textContent;
    assert.equal(/Searching window 1/.test(preReadyNote), false,
      'the page claimed a search before the server was ready');
    assert.match(preReadyNote, /Preparing the server/);
    socket.deliver({
      type: 'mining_ready', mode: REAL_DAEMON_MODE, ...bind1, windowIndex: 1, windowTotal: 3,
      sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs,
    });
    const w = h.workers[0];
    w.emit({ ev: 'ready', jobId: JOB1.jobId, contextIndex: 1, moduleInstances: 1 });
    w.emit({ ev: 'progress', jobId: JOB1.jobId, hashes: 4096, elapsedMs: 100 });

    assert.equal(h.elements.get('real-sequence').textContent, 'window 1 of 3 (same block height)',
      'the page does not say which window of how many this is');
    const note = h.elements.get('controls-note').textContent;
    assert.match(note, /window 1 of 3/);
    assert.match(note, /at most 3 windows/);
    assert.match(note, new RegExp(`at most ${REAL_REFRESH_LIMITS.maxSessionMs / 60000} minutes`));
    assert.equal(/Searching the fresh template once/.test(note), false,
      'the page still promises a single search');

    // The second window: the position advances and the CUMULATIVE attempts are shown, not just this
    // window's own count. The refresh arrives while the Worker is STILL on window 1 -- the exact
    // gap order the handover fence exists for -- so the retiring phase is rendered first.
    const bind2 = {
      clientStartId: start.clientStartId, workerId: 'sim-1-bbbb', jobId: JOB2.jobId,
      issuanceId: JOB2.issuanceId, runGeneration: 2,
    };
    socket.deliver({
      type: 'job_refresh', terminal: false, cause: 'window_exhausted', windowIndex: 2, windowTotal: 3,
      previous: { jobId: JOB1.jobId, issuanceId: JOB1.issuanceId, runGeneration: 1 }, job: JOB2, ...bind2,
    });
    // THE RETIRING PHASE: the old window's search has not settled yet, so the page says it is
    // retiring and that no NEW-window hashing has begun -- and does NOT claim that nothing at all
    // is hashing, which would not be true here.
    let handoverNote = h.elements.get('controls-note').textContent;
    assert.match(handoverNote, /window 1 of 3 is retiring/i);
    assert.match(handoverNote, /No hashing of the NEW window has begun/);
    assert.equal(/NOTHING IS BEING HASHED/.test(handoverNote), false,
      'the retiring phase claimed nothing at all is hashing');
    assert.equal(h.elements.get('real-sequence').textContent, 'window 1 of 3 retiring; preparing window 2 (same block height)');
    // The old context settles: from here the handover gap really does hash nothing.
    w.emit({ ev: 'finished', jobId: JOB1.jobId, hashes: 8192, found: 0, shares: 8, blockFound: false, stopCause: 'share_cap' });
    socket.deliver({
      type: 'mining_ready', mode: REAL_DAEMON_MODE, ...bind2, windowIndex: 2, windowTotal: 3,
      sessionBudgetMs: REAL_REFRESH_LIMITS.maxSessionMs,
    });
    // THE PREPARING PHASE: the old search has settled, nothing is hashing, and the page may say so.
    handoverNote = h.elements.get('controls-note').textContent;
    assert.match(handoverNote, /NOTHING IS BEING HASHED/);
    assert.equal(h.elements.get('real-sequence').textContent, 'window 1 of 3 searched; preparing window 2 (same block height)');
    w.emit({ ev: 'ready', jobId: JOB2.jobId, contextIndex: 2, moduleInstances: 1, rotated: true, priorContextFreed: true, priorContextActive: false });
    // ONLY THE ROTATED READINESS MAKES IT A SEARCH OF WINDOW 2.
    handoverNote = h.elements.get('controls-note').textContent;
    assert.match(handoverNote, /Searching window 2 of 3/);
    assert.equal(h.elements.get('real-sequence').textContent, 'window 2 of 3 (same block height)');
    w.emit({ ev: 'progress', jobId: JOB2.jobId, hashes: 100, elapsedMs: 20 });

    assert.equal(h.elements.get('real-sequence').textContent, 'window 2 of 3 (same block height)');
    assert.match(h.elements.get('controls-note').textContent, /window 2 of 3/);
    const total = Number(h.elements.get('real-total-attempts').textContent);
    assert.equal(Number.isSafeInteger(total), true, 'the cumulative attempt count is not shown at all');
    assert.equal(total, 8192 + 100, 'the page shows only the current window\'s attempts');
    assert.equal(h.elements.get('real-window').textContent,
      `[${REAL_SEARCH_LIMITS.maxAttempts}, ${2 * REAL_SEARCH_LIMITS.maxAttempts})`,
      'the issued nonce window is not the new one');
    assert.equal(h.workers.length, 1, 'a second Worker was created');
  } finally {
    h.restore();
  }
});
