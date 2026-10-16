// Real app.js rendering, with only an in-memory DOM, socket and Worker. No browser or listener.
import test from 'node:test';
import assert from 'node:assert/strict';

import { ALGORITHM_LABEL, REAL_DAEMON_MODE, REAL_SEARCH_LIMITS } from '../lib/shared/protocol.js';

const BLOCK_TARGET = `01${'00'.repeat(31)}`;
const SHARE_TARGET = `${'00'.repeat(31)}01`;
const SHARE_HASH = `10${'00'.repeat(31)}`;
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
  try {
    await import(`../app.js?share-count-test=${++appImportId}`);
  } catch (error) {
    for (const [name, descriptor] of Object.entries(previous)) {
      if (descriptor === undefined) delete globalThis[name];
      else Object.defineProperty(globalThis, name, descriptor);
    }
    throw error;
  }
  const restore = () => {
    for (const [name, descriptor] of Object.entries(previous)) {
      if (descriptor === undefined) delete globalThis[name];
      else Object.defineProperty(globalThis, name, descriptor);
    }
  };
  return { elements, socket: sockets[0], workers, restore };
}

test('APP SHARE COUNT: real share acceptance renders its verified count, without counting a replay', async () => {
  const h = await appHarness();
  try {
    const { socket } = h;
    socket.open();
    socket.deliver({
      type: 'server_hello', protocolVersion: 1, mode: REAL_DAEMON_MODE, workerId: 'sim-1-bbbb',
      labels: [], alreadyCompleted: false, searchLimits: REAL_SEARCH_LIMITS,
    });
    const job = {
      type: 'real_job', jobId: 'realjob-1111', issuanceId: '1'.repeat(32), contentDigest: '1'.repeat(64),
      algorithm: 'meephash-w-v2-frozen-real-template', height: '1', majorVersion: 16,
      epochKeyHex: 'e'.repeat(64), seedHashHex: 'e'.repeat(64),
      hashingTemplateHex: `1010${'00'.repeat(74)}`, targetHexLE: BLOCK_TARGET,
      shareWork: true, shareTargetHexLE: SHARE_TARGET, nonceStart: 0, nonceRange: 8192, expiresAtMs: 1,
    };
    socket.deliver(job);
    assert.equal(h.elements.get('search-pace-wrap').hidden, false);
    h.elements.get('search-pace').value = '100';
    h.elements.get('start-btn').click();
    const start = socket.sent.find((m) => m.type === 'start_request');
    assert.ok(start);
    const bind = {
      clientStartId: start.clientStartId, workerId: 'sim-1-bbbb', jobId: job.jobId,
      issuanceId: job.issuanceId, runGeneration: 1,
    };
    socket.deliver({ type: 'run_started', mode: REAL_DAEMON_MODE, ...bind });
    socket.deliver({ type: 'mining_ready', mode: REAL_DAEMON_MODE, ...bind });
    assert.equal(h.workers.length, 1);
    assert.equal(h.workers[0].posted.find((m) => m.cmd === 'init_search').pacingMs, 100);
    assert.equal(h.elements.get('search-pace').disabled, true);
    h.workers[0].emit({ ev: 'ready', jobId: job.jobId, contextIndex: 1, moduleInstances: 1 });
    h.workers[0].emit({ ev: 'share', jobId: job.jobId, nonce: 3, nonceHex: '00000003', hashHexLE: SHARE_HASH });
    const accepted = { type: 'share_accepted', terminal: false, nonce: 3, hashHexLE: SHARE_HASH, ...bind };
    socket.deliver(accepted);
    assert.equal(h.elements.get('accepted').textContent, '1');
    socket.deliver(accepted);
    assert.equal(h.elements.get('accepted').textContent, '1', 'a replay was shown as a second verified share');
    socket.deliver({ type: 'run_stopped', terminal: true, accepted: true,
      reason: 'search_bound_reached', ...bind });
    assert.equal(h.elements.get('accepted').textContent, '1', 'the terminal screen lost the verified share');
    assert.match(h.elements.get('real-outcome').textContent, /no block-quality nonce/);
    assert.doesNotMatch(h.elements.get('real-outcome').textContent, /no nonce met the target/);
    assert.match(h.elements.get('controls-note').textContent, /Only the displayed attempts were searched/);
    assert.match(h.elements.get('controls-note').textContent, /no block was submitted for this height/);
  } finally {
    h.restore();
  }
});

test('APP SHARE COUNT: synthetic mode retains the original generic accepted counter', async () => {
  const h = await appHarness();
  try {
    const { socket } = h;
    socket.open();
    socket.deliver({ type: 'server_hello', protocolVersion: 1, workerId: 'w-test' });
    socket.deliver({
      type: 'job', jobId: 'devjob-1', generation: 1, algorithm: ALGORITHM_LABEL,
      targetHexLE: 'ff'.repeat(32), nonceStart: 0, nonceRange: 16, batchHint: 4,
    });
    socket.deliver({ type: 'share_accepted', jobId: 'devjob-1', nonce: '00000001' });
    assert.equal(h.elements.get('accepted').textContent, '1');
  } finally {
    h.restore();
  }
});

test('APP DELAYED JOB: Start is enabled only by the explicit real-mode capability and allocates no Worker', async () => {
  const h = await appHarness();
  try {
    const { socket } = h;
    socket.open();
    assert.equal(h.elements.get('start-btn').disabled, true, 'pre-hello Start was enabled');
    socket.deliver({
      type: 'server_hello', protocolVersion: 1, mode: REAL_DAEMON_MODE, workerId: 'sim-1-bbbb',
      labels: [], alreadyCompleted: false, searchLimits: REAL_SEARCH_LIMITS, jobIssuedOnStart: true,
    });
    assert.equal(h.elements.get('start-btn').disabled, false);
    h.elements.get('start-btn').click();
    assert.equal(socket.sent.filter((m) => m.type === 'start_request').length, 1);
    assert.equal(h.workers.length, 0);
    assert.equal(h.elements.get('start-btn').disabled, true, 'a second Start was offered while pending');
  } finally {
    h.restore();
  }
});

test('APP DELAYED JOB: omitted or false capability leaves jobless real Start disabled', async () => {
  for (const capability of [undefined, false]) {
    const h = await appHarness();
    try {
      const { socket } = h;
      socket.open();
      const hello = {
        type: 'server_hello', protocolVersion: 1, mode: REAL_DAEMON_MODE, workerId: 'sim-1-bbbb',
        labels: [], alreadyCompleted: false, searchLimits: REAL_SEARCH_LIMITS,
      };
      if (capability !== undefined) hello.jobIssuedOnStart = capability;
      socket.deliver(hello);
      assert.equal(h.elements.get('start-btn').disabled, true, String(capability));
      h.elements.get('start-btn').click();
      assert.equal(socket.sent.filter((m) => m.type === 'start_request').length, 0, String(capability));
      assert.equal(h.workers.length, 0, String(capability));
    } finally {
      h.restore();
    }
  }
});
