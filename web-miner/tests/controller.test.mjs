// The voluntary-mining guarantees, tested without a browser.
//
// Everything the ethics rules promise is a property of lib/controller.js: no mining before an
// explicit Start, exactly one worker, one shared stop path that really terminates the worker,
// hidden-tab stop, and no auto-resume of any kind. The Worker and WebSocket are injected, so a
// test can count precisely how many workers were constructed and what was sent.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { createMiningController, STATES, STOP_REASONS } from '../lib/controller.js';
import { ALGORITHM_LABEL } from '../lib/shared/protocol.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function makeFakeWorker(registry) {
  const w = {
    posted: [],
    terminated: 0,
    onmessage: null,
    onerror: null,
    postMessage(m) {
      this.posted.push(m);
    },
    terminate() {
      this.terminated++;
    },
    /** Deliver a message as the real Worker would. */
    emit(data) {
      if (this.onmessage) this.onmessage({ data });
    },
  };
  registry.push(w);
  return w;
}

function makeFakeSocket(registry) {
  const s = {
    sent: [],
    closed: 0,
    url: null,
    onopen: null,
    onmessage: null,
    onclose: null,
    onerror: null,
    send(text) {
      this.sent.push(JSON.parse(text));
    },
    close() {
      this.closed++;
    },
    open() {
      if (this.onopen) this.onopen();
    },
    deliver(obj) {
      if (this.onmessage) this.onmessage({ data: JSON.stringify(obj) });
    },
  };
  registry.push(s);
  return s;
}

const JOB = {
  type: 'job',
  jobId: 'devjob-1',
  generation: 1,
  algorithm: ALGORITHM_LABEL,
  targetHexLE: 'ff'.repeat(32),
  nonceStart: 0,
  nonceRange: 16,
  batchHint: 4,
};

/** Controller connected, greeted and holding a job -- i.e. ready but definitely not mining. */
function makeReadyController() {
  const workers = [];
  const sockets = [];
  const ctl = createMiningController({
    createWorker: () => makeFakeWorker(workers),
    createSocket: () => makeFakeSocket(sockets),
    now: () => 1_000_000,
  });
  ctl.connect('ws://127.0.0.1:1/ws');
  const socket = sockets[0];
  socket.open();
  socket.deliver({ type: 'server_hello', protocolVersion: 1, workerId: 'w-test' });
  socket.deliver(JOB);
  return { ctl, workers, sockets, socket };
}

/** Deliver the server's mining_ready, which is what actually constructs the Worker. */
function serverReady(socket) {
  socket.deliver({ type: 'mining_ready', workerId: 'w-test', verifierWasmHeapBytes: 48_562_176 });
}

/** Start, let the server answer, and bring the resulting worker up to MINING. */
function startAndMine(ctl, workers, socket) {
  ctl.start();
  serverReady(socket);
  const worker = workers.at(-1);
  const gen = worker.posted.find((m) => m.cmd === 'init').gen;
  worker.emit({ ev: 'ready', gen, wasmHeapBytes: 48_562_176 });
  return gen;
}

/** Drive an already-constructed fake worker through init -> ready -> mining. */
function bringWorkerUp(ctl, worker) {
  const gen = worker.posted.find((m) => m.cmd === 'init').gen;
  worker.emit({ ev: 'ready', gen, wasmHeapBytes: 48_562_176 });
  return gen;
}

// ---------------------------------------------------------------- nothing before Start

test('constructing the controller creates no worker and sends nothing', () => {
  const workers = [];
  const sockets = [];
  const ctl = createMiningController({
    createWorker: () => makeFakeWorker(workers),
    createSocket: () => makeFakeSocket(sockets),
  });
  assert.equal(ctl.workersCreated, 0);
  assert.equal(workers.length, 0);
  assert.equal(sockets.length, 0);
  assert.equal(ctl.snapshot().state, STATES.IDLE);
  assert.equal(ctl.runIntent, false);
});

test('connecting, being greeted and receiving a job still creates no worker', () => {
  const { ctl, workers, socket } = makeReadyController();
  assert.equal(ctl.workersCreated, 0, 'no Worker may exist before Start');
  assert.equal(workers.length, 0, 'no Wasm module can have been loaded: there is no worker to load it');
  assert.equal(ctl.snapshot().state, STATES.IDLE);
  assert.equal(ctl.snapshot().hashes, 0);
  // Only the protocol handshake went out; no share and no work request.
  assert.deepEqual(socket.sent.map((m) => m.type), ['client_hello']);
});

test('an unexpected server message cannot start mining', () => {
  const { ctl, socket } = makeReadyController();
  socket.deliver({ type: 'share_accepted', jobId: 'devjob-1', nonce: '00000001' });
  socket.deliver({ type: 'start' });
  socket.deliver({ type: 'job', ...JOB, jobId: 'devjob-2' });
  assert.equal(ctl.workersCreated, 0);
  assert.equal(ctl.runIntent, false);
});

// ---------------------------------------------------------------- exactly one worker

test('Start asks the server first and creates NO worker until it answers', () => {
  const { ctl, workers, socket } = makeReadyController();
  assert.equal(ctl.start(), true);
  assert.equal(ctl.snapshot().state, STATES.STARTING);
  assert.equal(ctl.pendingStart, true);
  assert.equal(ctl.workersCreated, 0, 'no Worker may exist before the server verifier is ready');
  assert.equal(workers.length, 0);
  assert.deepEqual(socket.sent.map((m) => m.type), ['client_hello', 'start_request']);

  serverReady(socket);
  assert.equal(ctl.workersCreated, 1, 'mining_ready constructs exactly one Worker');
  assert.equal(workers.length, 1);
  assert.equal(ctl.pendingStart, false);
  assert.equal(ctl.snapshot().serverVerifierHeapBytes, 48_562_176);
});

test('repeated Start clicks cannot create a second concurrent worker', () => {
  const { ctl, workers, socket } = makeReadyController();
  startAndMine(ctl, workers, socket);
  assert.equal(ctl.snapshot().state, STATES.MINING);
  for (let i = 0; i < 5; i++) assert.equal(ctl.start(), false, 'a second Start must be refused');
  assert.equal(ctl.workersCreated, 1);
  assert.equal(workers.length, 1);
});

test('after Stop, Start creates one new worker -- never two live at once', () => {
  const { ctl, workers, socket } = makeReadyController();
  startAndMine(ctl, workers, socket);
  ctl.stop();
  assert.equal(workers[0].terminated, 1);
  startAndMine(ctl, workers, socket);
  assert.equal(ctl.workersCreated, 2, 'two runs total');
  assert.equal(workers.length, 2);
  assert.equal(workers[0].terminated, 1, 'the first worker stayed terminated');
});

// ---------------------------------------------------------------- the single stop path

test('explicit Stop terminates the worker, clears run intent and ignores its late messages', () => {
  const { ctl, workers, socket } = makeReadyController();
  const gen = startAndMine(ctl, workers, socket);
  workers[0].emit({ ev: 'progress', gen, hashes: 8 });
  assert.equal(ctl.snapshot().hashes, 8);

  ctl.stop();
  assert.equal(workers[0].terminated, 1, 'Stop must terminate the Worker, not relabel the UI');
  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.snapshot().state, STATES.STOPPED);
  assert.equal(ctl.snapshot().stopReason, STOP_REASONS.USER);

  // A message already queued by the abandoned worker must change nothing -- above all it must
  // not submit a share.
  const sentBefore = socket.sent.length;
  workers[0].emit({ ev: 'progress', gen, hashes: 9999 });
  workers[0].emit({ ev: 'found', gen, jobId: 'devjob-1', nonce: 3, nonceHex: '00000003', hashHexLE: '00'.repeat(32) });
  assert.equal(ctl.snapshot().hashes, 8, 'stale progress must be dropped');
  assert.equal(socket.sent.length, sentBefore, 'a stale find must not be submitted');
});

test('Stop is idempotent and safe before any run', () => {
  const { ctl, workers, socket } = makeReadyController();
  assert.equal(ctl.stop(), false);
  startAndMine(ctl, workers, socket);
  assert.equal(ctl.stop(), true);
  assert.equal(ctl.stop(), false);
  assert.equal(workers[0].terminated, 1, 'terminate is not called again on an already-stopped run');
});

test('a worker error routes through the same stop path', () => {
  const { ctl, workers, socket } = makeReadyController();
  const gen = startAndMine(ctl, workers, socket);
  workers[0].emit({ ev: 'error', gen, message: 'wasm failed' });
  assert.equal(workers[0].terminated, 1);
  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.snapshot().error, 'wasm failed');
});

test('losing the socket stops mining rather than leaving the worker hashing', () => {
  const { ctl, workers, socket } = makeReadyController();
  startAndMine(ctl, workers, socket);
  socket.onclose();
  assert.equal(workers[0].terminated, 1);
  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.snapshot().stopReason, STOP_REASONS.DISCONNECTED);
});

// ---------------------------------------------------------------- hidden tab, no auto-resume

test('hiding the tab uses the stop path and reports why', () => {
  const { ctl, workers, socket } = makeReadyController();
  startAndMine(ctl, workers, socket);
  ctl.setHidden(true);
  assert.equal(workers[0].terminated, 1, 'a hidden tab must terminate the worker');
  assert.equal(ctl.runIntent, false, 'a hidden tab must clear run intent');
  assert.equal(ctl.snapshot().state, STATES.STOPPED_HIDDEN);
  assert.equal(ctl.snapshot().stopReason, STOP_REASONS.HIDDEN);
});

test('becoming visible again never resumes mining', () => {
  const { ctl, workers, socket } = makeReadyController();
  startAndMine(ctl, workers, socket);
  ctl.setHidden(true);
  const createdAfterHide = ctl.workersCreated;

  for (let i = 0; i < 3; i++) {
    ctl.setHidden(false); // visible
    ctl.setHidden(true);  // hidden again
  }
  ctl.setHidden(false);

  assert.equal(ctl.workersCreated, createdAfterHide, 'visibility must never construct a worker');
  assert.equal(ctl.runIntent, false, 'run intent must stay cleared');
  assert.equal(ctl.snapshot().state, STATES.STOPPED_HIDDEN);

  // Only another explicit Start brings it back, and only via the server handshake.
  assert.equal(ctl.start(), true);
  assert.equal(ctl.workersCreated, createdAfterHide, 'Start alone still constructs nothing');
  serverReady(socket);
  assert.equal(ctl.workersCreated, createdAfterHide + 1);
});

test('hiding while idle does nothing at all', () => {
  const { ctl, workers } = makeReadyController();
  ctl.setHidden(true);
  assert.equal(ctl.workersCreated, 0);
  assert.equal(ctl.snapshot().state, STATES.IDLE, 'an idle page is not "stopped"; it never started');
  assert.equal(workers.length, 0);
});

// ---------------------------------------------------------------- pagehide / unload

test('pagehide closes the worker and the socket and records no resume intent', () => {
  const { ctl, workers, socket } = makeReadyController();
  startAndMine(ctl, workers, socket);

  ctl.teardown();
  assert.equal(workers[0].terminated, 1);
  assert.equal(socket.closed, 1);
  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.snapshot().connection, 'disconnected');
  assert.equal(ctl.snapshot().stopReason, STOP_REASONS.PAGEHIDE);
});

test('reconnecting after teardown lands on a stopped page, not a mining one', () => {
  const { ctl, workers, sockets, socket } = makeReadyController();
  startAndMine(ctl, workers, socket);
  ctl.teardown();

  // Simulate the page reconnecting (as a reload or a restored tab would).
  ctl.connect('ws://127.0.0.1:1/ws');
  const socket2 = sockets[1];
  socket2.open();
  socket2.deliver({ type: 'server_hello', protocolVersion: 1, workerId: 'w-test-2' });
  socket2.deliver(JOB);

  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.workersCreated, 1, 'reconnecting must not construct a worker');
  assert.deepEqual(socket2.sent.map((m) => m.type), ['client_hello']);
});

// ---------------------------------------------------------------- submission shape

test('a find submits jobId, nonce and workerId ONLY', () => {
  const { ctl, workers, socket } = makeReadyController();
  const gen = startAndMine(ctl, workers, socket);
  workers[0].emit({
    ev: 'found',
    gen,
    jobId: 'devjob-1',
    nonce: 15,
    nonceHex: '0000000f',
    hashHexLE: 'ab'.repeat(32),
  });
  const submit = socket.sent.find((m) => m.type === 'submit_share');
  assert.ok(submit, 'a qualifying nonce must be submitted');
  assert.deepEqual(Object.keys(submit).sort(), ['jobId', 'nonce', 'type', 'workerId']);
  assert.equal(submit.nonce, '0000000f');
  assert.equal(submit.workerId, 'w-test');
  assert.equal(submit.resultHash, undefined, 'the client hash must not be sent in normal operation');
});

test('a job with an unexpected algorithm is refused rather than mined', () => {
  const { ctl, socket } = makeReadyController();
  socket.deliver({ ...JOB, jobId: 'devjob-9', algorithm: 'something-else' });
  assert.equal(ctl.snapshot().state, STATES.ERROR);
  assert.equal(ctl.start(), false);
  assert.equal(ctl.workersCreated, 0);
});

// ---------------------------------------------------------------- no persisted intent

/**
 * Strip comments so the source scans below judge CODE, not prose. These files discuss
 * localStorage and service workers at length precisely to explain why they are not used, and a
 * scan that could not tell the difference would be worthless.
 */
function stripComments(src) {
  return src
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    // Not preceded by ':' so that URLs such as ws://host survive intact.
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

test('the comment stripper does not hide code', () => {
  assert.match(stripComments('a(); // localStorage\nlocalStorage.x'), /localStorage\.x/);
  assert.doesNotMatch(stripComments('// mentions localStorage only'), /localStorage/);
  assert.doesNotMatch(stripComments('/* localStorage */'), /localStorage/);
  assert.match(stripComments("const u = 'ws://h/ws'; localStorage.y"), /localStorage\.y/);
});

test('no browser-side file persists auto-start intent anywhere', () => {
  const files = ['app.js', 'worker.js', 'lib/controller.js', 'index.html'];
  // A service worker would let mining survive the tab entirely; storage APIs would let a reload
  // restore run intent. Neither may appear in the client at all.
  const forbidden = [
    /localStorage/,
    /sessionStorage/,
    /indexedDB/i,
    /document\.cookie/,
    /serviceWorker/i,
    /<iframe/i,
    /window\.open\s*\(/,
  ];
  for (const rel of files) {
    const src = stripComments(readFileSync(resolve(__dirname, '..', rel), 'utf8'));
    for (const pattern of forbidden) {
      assert.equal(pattern.test(src), false, `${rel} must not reference ${pattern}`);
    }
  }
});

test('the page constructs its Worker in exactly one place', () => {
  const app = stripComments(readFileSync(resolve(__dirname, '../app.js'), 'utf8'));
  const constructions = app.match(/new\s+Worker\s*\(/g) ?? [];
  assert.equal(constructions.length, 1, 'exactly one `new Worker(` in the whole client');
  const starts = app.match(/controller\.start\s*\(/g) ?? [];
  assert.equal(starts.length, 1, 'start() may be called from exactly one place: the Start click');
});

// ---------------------------------------------------------------- job windows within one run

test('an exhausted window waits for new work instead of rescanning it', () => {
  const { ctl, workers, socket } = makeReadyController();
  const gen = startAndMine(ctl, workers, socket);
  const workPosts = () => workers[0].posted.filter((m) => m.cmd === 'work');
  assert.equal(workPosts().length, 1, 'one window dispatched on ready');

  workers[0].emit({ ev: 'finished', gen, jobId: 'devjob-1', hashes: 16, found: 1, stopped: false, exhausted: true });
  assert.equal(workPosts().length, 1, 'the same window must not be dispatched again');
  assert.equal(ctl.awaitingWork, true);
  assert.equal(ctl.runIntent, true, 'the run is still live, just waiting for the pool');

  // The pool pushes new work; the SAME worker picks it up.
  socket.deliver({ ...JOB, jobId: 'devjob-2', generation: 2 });
  assert.equal(workPosts().length, 2);
  assert.equal(workPosts()[1].job.jobId, 'devjob-2');
  assert.equal(ctl.awaitingWork, false);
  assert.equal(ctl.workersCreated, 1, 'new work must not create a second worker');
});

test('hashes accumulate across windows rather than restarting each time', () => {
  const { ctl, workers, socket } = makeReadyController();
  const gen = startAndMine(ctl, workers, socket);

  workers[0].emit({ ev: 'progress', gen, hashes: 8 });
  assert.equal(ctl.snapshot().hashes, 8);
  workers[0].emit({ ev: 'finished', gen, jobId: 'devjob-1', hashes: 16, found: 1, stopped: false, exhausted: true });
  assert.equal(ctl.snapshot().hashes, 16);

  socket.deliver({ ...JOB, jobId: 'devjob-2', generation: 2 });
  workers[0].emit({ ev: 'progress', gen, hashes: 4 });
  assert.equal(ctl.snapshot().hashes, 20, 'the second window continues the count');
  workers[0].emit({ ev: 'finished', gen, jobId: 'devjob-2', hashes: 16, found: 1, stopped: false, exhausted: true });
  assert.equal(ctl.snapshot().hashes, 32);
});

test('a new Start resets the run counters', () => {
  const { ctl, workers, socket } = makeReadyController();
  const gen = startAndMine(ctl, workers, socket);
  workers[0].emit({ ev: 'finished', gen, jobId: 'devjob-1', hashes: 16, found: 1, stopped: false, exhausted: true });
  assert.equal(ctl.snapshot().hashes, 16);
  ctl.stop();
  ctl.start();
  assert.equal(ctl.snapshot().hashes, 0);
  assert.equal(ctl.awaitingWork, false);
});

test('a job arriving while a window is running is picked up when that window ends', () => {
  const { ctl, workers, socket } = makeReadyController();
  const gen = startAndMine(ctl, workers, socket);
  const workPosts = () => workers[0].posted.filter((m) => m.cmd === 'work');

  socket.deliver({ ...JOB, jobId: 'devjob-2', generation: 2 });
  assert.equal(workPosts().length, 1, 'the running window is not interrupted mid-flight');
  workers[0].emit({ ev: 'finished', gen, jobId: 'devjob-1', hashes: 16, found: 1, stopped: false, exhausted: true });
  assert.equal(workPosts().length, 2);
  assert.equal(workPosts()[1].job.jobId, 'devjob-2');
  assert.equal(ctl.awaitingWork, false);
});

test('a stopped run does not pick up new work', () => {
  const { ctl, workers, socket } = makeReadyController();
  const gen = startAndMine(ctl, workers, socket);
  workers[0].emit({ ev: 'finished', gen, jobId: 'devjob-1', hashes: 16, found: 1, stopped: false, exhausted: true });
  ctl.stop();

  socket.deliver({ ...JOB, jobId: 'devjob-3', generation: 3 });
  assert.equal(ctl.workersCreated, 1);
  assert.equal(ctl.runIntent, false);
  assert.equal(workers.length, 1);
  assert.equal(workers[0].terminated, 1);
});
