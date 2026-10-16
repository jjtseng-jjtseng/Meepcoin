// Corrective regressions for the Phase 1B consent and fail-closed defects.
//
//   * start() must not construct a Worker; only the LOCAL SERVER's mining_ready may, and only
//     while the human's run intent from that same run is still held.
//   * every socket failure -- close, error, and a THROWING send -- must funnel into one
//     idempotent fail-closed stop. A browser is not obliged to deliver `close` after `error`, so
//     the controller must own that invariant rather than hoping for it.
//   * the structural scan must cover the COMPLETE set of client modules the server actually
//     serves, derived from the route table, not a handpicked subset.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { createMiningController, STATES, STOP_REASONS } from '../lib/controller.js';
import { ALGORITHM_LABEL } from '../lib/shared/protocol.js';
import { ROUTES } from '../../pool/dev/static.mjs';

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

function harness({ sendThrows = () => false } = {}) {
  const workers = [];
  const sockets = [];
  const ctl = createMiningController({
    createWorker: () => {
      const w = {
        posted: [], terminated: 0, onmessage: null, onerror: null,
        postMessage(m) { this.posted.push(m); },
        terminate() { this.terminated++; },
        emit(d) { if (this.onmessage) this.onmessage({ data: d }); },
      };
      workers.push(w);
      return w;
    },
    createSocket: () => {
      const s = {
        sent: [], closed: 0, onopen: null, onmessage: null, onclose: null, onerror: null,
        send(text) {
          const msg = JSON.parse(text);
          if (sendThrows(msg)) throw new Error('send failed: socket closing');
          this.sent.push(msg);
        },
        close() { this.closed++; },
        open() { if (this.onopen) this.onopen(); },
        deliver(o) { if (this.onmessage) this.onmessage({ data: JSON.stringify(o) }); },
      };
      sockets.push(s);
      return s;
    },
    now: () => 1_000_000,
  });
  ctl.connect('ws://127.0.0.1:1/ws');
  const socket = sockets[0];
  socket.open();
  socket.deliver({ type: 'server_hello', protocolVersion: 1, workerId: 'w-test' });
  socket.deliver(JOB);
  return { ctl, workers, sockets, socket };
}

const ready = (socket) => socket.deliver({ type: 'mining_ready', workerId: 'w-test', verifierWasmHeapBytes: 48_562_176 });

function mine(ctl, workers, socket) {
  ctl.start();
  ready(socket);
  const w = workers.at(-1);
  const gen = w.posted.find((m) => m.cmd === 'init').gen;
  w.emit({ ev: 'ready', gen, wasmHeapBytes: 48_562_176 });
  return gen;
}

// ---------------------------------------------------------------- consent boundary

test('Start sends start_request and constructs nothing until the server answers', () => {
  const { ctl, workers, socket } = harness();
  ctl.start();
  assert.equal(ctl.workersCreated, 0);
  assert.equal(ctl.pendingStart, true);
  assert.equal(ctl.snapshot().state, STATES.STARTING);
  assert.deepEqual(socket.sent.map((m) => m.type), ['client_hello', 'start_request']);

  // Nothing else the server might say may substitute for mining_ready.
  socket.deliver({ ...JOB, jobId: 'devjob-2', generation: 2 });
  socket.deliver({ type: 'share_accepted', jobId: 'devjob-1', nonce: '00000001' });
  socket.deliver({ type: 'pong' });
  assert.equal(ctl.workersCreated, 0, 'only mining_ready may construct the Worker');

  ready(socket);
  assert.equal(ctl.workersCreated, 1);
});

test('repeated Start clicks while the server is still thinking send one request and build one worker', () => {
  const { ctl, workers, socket } = harness();
  for (let i = 0; i < 5; i++) ctl.start();
  assert.equal(socket.sent.filter((m) => m.type === 'start_request').length, 1);
  ready(socket);
  assert.equal(ctl.workersCreated, 1);
  assert.equal(workers.length, 1);

  // A duplicated or replayed readiness message must not build a second worker either.
  ready(socket);
  ready(socket);
  assert.equal(ctl.workersCreated, 1);
});

test('Stop while the start is pending makes a late mining_ready inert', () => {
  const { ctl, workers, socket } = harness();
  ctl.start();
  assert.equal(ctl.pendingStart, true);

  ctl.stop();
  assert.equal(ctl.pendingStart, false);
  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.snapshot().state, STATES.STOPPED);

  ready(socket); // arrives after the human already gave up
  assert.equal(ctl.workersCreated, 0, 'a late readiness reply must NOT construct a Worker');
  assert.equal(workers.length, 0);
  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.snapshot().state, STATES.STOPPED);
});

test('hiding the tab while the start is pending also makes a late mining_ready inert', () => {
  const { ctl, workers, socket } = harness();
  ctl.start();
  ctl.setHidden(true);
  assert.equal(ctl.snapshot().state, STATES.STOPPED_HIDDEN);
  assert.equal(ctl.pendingStart, false);

  ready(socket);
  assert.equal(ctl.workersCreated, 0);
  ctl.setHidden(false);
  assert.equal(ctl.workersCreated, 0, 'and coming back does not build one either');
});

test('pagehide while the start is pending makes a late mining_ready inert', () => {
  const { ctl, workers, socket } = harness();
  ctl.start();
  ctl.teardown();
  assert.equal(ctl.pendingStart, false);
  ready(socket);
  assert.equal(ctl.workersCreated, 0);
});

test('mining_unavailable creates no worker and surfaces an actionable error', () => {
  const { ctl, workers, socket } = harness();
  ctl.start();
  socket.deliver({ type: 'mining_unavailable', reason: 'verifier_unavailable', detail: 'Wasm identity mismatch' });
  assert.equal(ctl.workersCreated, 0, 'a failed server init must never leave a Worker behind');
  assert.equal(workers.length, 0);
  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.pendingStart, false);
  assert.equal(ctl.snapshot().state, STATES.ERROR);
  assert.match(ctl.snapshot().error, /Wasm identity mismatch/);
});

test('Start is refused outright when the socket is not connected', () => {
  const { ctl, workers, socket } = harness();
  socket.onclose();
  assert.equal(ctl.start(), false);
  assert.equal(ctl.workersCreated, 0);
});

// ---------------------------------------------------------------- one fail-closed path

test('socket.onerror stops mining, exactly like a close', () => {
  const { ctl, workers, socket } = harness();
  mine(ctl, workers, socket);
  assert.equal(ctl.snapshot().state, STATES.MINING);

  socket.onerror(new Error('socket blew up'));
  assert.equal(workers[0].terminated, 1, 'an error must terminate the Worker');
  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.snapshot().stopReason, STOP_REASONS.SOCKET_ERROR);
  assert.match(ctl.snapshot().error, /connection to the local pool failed/);
});

test('socket.onerror during a pending start is fail-closed too', () => {
  const { ctl, workers, socket } = harness();
  ctl.start();
  socket.onerror(new Error('socket blew up'));
  assert.equal(ctl.pendingStart, false);
  assert.equal(ctl.runIntent, false);
  ready(socket);
  assert.equal(ctl.workersCreated, 0);
});

test('repeated error and close events are harmless', () => {
  const { ctl, workers, socket } = harness();
  mine(ctl, workers, socket);
  socket.onerror(new Error('one'));
  socket.onerror(new Error('two'));
  socket.onclose();
  socket.onclose();
  assert.equal(workers[0].terminated, 1, 'terminate must not be called repeatedly');
  assert.equal(ctl.runIntent, false);
});

test('a throwing send does not escape, and stops mining', () => {
  const { ctl, workers, socket } = harness({ sendThrows: (m) => m.type === 'submit_share' });
  const gen = mine(ctl, workers, socket);

  // The exception used to propagate out of the Worker message handler and leave it hashing.
  assert.doesNotThrow(() => {
    workers[0].emit({ ev: 'found', gen, jobId: 'devjob-1', nonce: 15, nonceHex: '0000000f', hashHexLE: 'ab'.repeat(32) });
  });
  assert.equal(workers[0].terminated, 1, 'a share that cannot be sent must stop the Worker');
  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.snapshot().stopReason, STOP_REASONS.SEND_FAILED);
  assert.match(ctl.snapshot().error, /could not reach the local pool/);
});

test('a throwing start_request is fail-closed and reports false', () => {
  const { ctl, workers, socket } = harness({ sendThrows: (m) => m.type === 'start_request' });
  assert.equal(ctl.start(), false);
  assert.equal(ctl.workersCreated, 0);
  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.pendingStart, false);
  assert.match(ctl.snapshot().error, /could not reach the local pool/);
  ready(socket);
  assert.equal(ctl.workersCreated, 0, 'and a late readiness still constructs nothing');
});

test('a fail-closed stop while waiting for work also terminates the worker', () => {
  const { ctl, workers, socket } = harness();
  const gen = mine(ctl, workers, socket);
  workers[0].emit({ ev: 'finished', gen, jobId: 'devjob-1', hashes: 16, found: 1, stopped: false, exhausted: true });
  assert.equal(ctl.awaitingWork, true, 'idle inside a live run');

  socket.onerror(new Error('dropped while waiting'));
  assert.equal(workers[0].terminated, 1);
  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.awaitingWork, false);
});

// ---------------------------------------------------------------- terminal demonstration

test('demo_complete stops the run and requires another explicit Start', () => {
  const { ctl, workers, socket } = harness();
  const gen = mine(ctl, workers, socket);
  socket.deliver({ type: 'share_accepted', jobId: 'devjob-1', nonce: '0000000f', hashHexLE: 'ab'.repeat(32), serverRecomputed: true });
  socket.deliver({ type: 'demo_complete', jobId: 'devjob-1', nonce: '0000000f' });

  assert.equal(workers[0].terminated, 1, 'a completed demonstration terminates the Worker');
  assert.equal(ctl.runIntent, false);
  assert.equal(ctl.snapshot().demoComplete, true);
  assert.equal(ctl.snapshot().accepted, 1);

  // Late worker chatter after completion changes nothing.
  const sentBefore = socket.sent.length;
  workers[0].emit({ ev: 'found', gen, jobId: 'devjob-1', nonce: 15, nonceHex: '0000000f', hashHexLE: 'ab'.repeat(32) });
  assert.equal(socket.sent.length, sentBefore);

  // Another run needs another Start AND another server readiness.
  assert.equal(ctl.start(), true);
  assert.equal(ctl.workersCreated, 1);
  ready(socket);
  assert.equal(ctl.workersCreated, 2);
  assert.equal(ctl.snapshot().demoComplete, false, 'the new run starts clean');
});

// ---------------------------------------------------------------- complete client scan

/** Strip comments so the scans below judge CODE, not the prose that explains these very rules. */
function stripComments(src) {
  return src
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

/**
 * Every file the development pool actually serves to the browser, derived from the route table
 * rather than listed by hand -- so a new client module cannot be added without being scanned.
 */
function servedClientFiles() {
  const seen = new Map();
  for (const [route, entry] of Object.entries(ROUTES)) {
    if (route.startsWith('/wasm/')) continue; // the generated algorithm build, covered by identity pinning
    if (!/\.(js|html|css)$/.test(entry.file)) continue;
    seen.set(entry.file, route);
  }
  return [...seen.entries()];
}

test('the scanned set IS the complete served client, not a subset', () => {
  const files = servedClientFiles();
  const names = files.map(([file]) => file.replace(/\\/g, '/').split('/web-miner/')[1]).sort();
  // index.html is served on two routes; the map de-duplicates by file.
  assert.deepEqual(names, [
    'app.js',
    'index.html',
    'lib/controller.js',
    'lib/shared/one_shot.js',
    'lib/shared/protocol.js',
    'lib/shared/search.js',
    'lib/shared/target.js',
    'lib/shared/wasm_hasher.js',
    'lib/worker_core.js',
    'styles.css',
    'worker.js',
  ]);
  assert.ok(files.length >= 11, 'every served client file must be scanned');
});

test('every module the served client imports is itself served', () => {
  // THE DEFECT THIS CATCHES SHIPPED. worker.js imported ./lib/shared/one_shot.js while the route
  // table did not serve it, so in a real browser the module Worker failed to load -- in synthetic
  // mode as well as simulation mode -- and no Node test noticed, because Node resolves the file from
  // disk. This walks the static import graph from the two entry points and requires every edge to
  // land on a route.
  const served = new Map(Object.entries(ROUTES).map(([route, entry]) => [route, entry.file]));
  const IMPORT_RE = /^\s*import\s+(?:[^'"]*?\sfrom\s+)?['"]([^'"]+)['"]/gm;
  const queue = ['/app.js', '/worker.js'];
  const visited = new Set();
  while (queue.length > 0) {
    const route = queue.shift();
    if (visited.has(route)) continue;
    visited.add(route);
    assert.ok(served.has(route), `the served client imports ${route}, which the pool does not serve`);
    const src = stripComments(readFileSync(served.get(route), 'utf8'));
    for (const m of src.matchAll(IMPORT_RE)) {
      const spec = m[1];
      const next = spec.startsWith('/')
        ? spec
        : new URL(spec, `http://pool.invalid${route}`).pathname;
      queue.push(next);
    }
  }
  // Both entry points were walked, and the Worker's own dispatcher and permit were reached.
  for (const expected of ['/worker.js', '/lib/worker_core.js', '/lib/shared/one_shot.js', '/wasm/meepow.mjs']) {
    assert.ok(visited.has(expected), `${expected} was not reached from the entry points`);
  }
});

test('no served client file can persist run intent or start mining on its own', () => {
  const forbidden = [
    /localStorage/,
    /sessionStorage/,
    /indexedDB/i,
    /document\.cookie/,
    /serviceWorker/i,
    /navigator\.storage/i,
    /<iframe/i,
    /window\.open\s*\(/,
    /SharedWorker/,
    /BroadcastChannel/,
  ];
  for (const [file, route] of servedClientFiles()) {
    const src = stripComments(readFileSync(file, 'utf8'));
    for (const pattern of forbidden) {
      assert.equal(pattern.test(src), false, `${route} must not reference ${pattern}`);
    }
  }
});

test('exactly one Worker is constructed anywhere in the served client', () => {
  let constructions = 0;
  let starts = 0;
  for (const [file] of servedClientFiles()) {
    const src = stripComments(readFileSync(file, 'utf8'));
    constructions += (src.match(/new\s+Worker\s*\(/g) ?? []).length;
    starts += (src.match(/controller\.start\s*\(/g) ?? []).length;
  }
  assert.equal(constructions, 1, 'exactly one `new Worker(` across the whole served client');
  assert.equal(starts, 1, 'start() may be called from exactly one place: the Start click');
});
