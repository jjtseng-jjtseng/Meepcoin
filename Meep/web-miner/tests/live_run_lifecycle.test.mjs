// The live runners' ONE startup / cancellation / finalization boundary, driven behaviourally.
//
// THE DEFECT (Regression testing, af3bc0ca): both runners' SIGINT/SIGTERM handlers ran cleanup and called
// process.exit() while `await startDevPool()` was still pending. The pool's ownership graph could
// already hold daemon A (or A and B) while the runner's `pool` was still null, so the handler saw
// nothing to close and Node exited before startDevPool's transactional teardown could run. These
// tests pause an injected realDaemonFactory INSIDE the real startDevPool after it has registered A,
// or A and B, deliver the signal there, and check what is true when the (simulated) exit happens.
//
// No daemon, WSL, Docker, helper or browser. startDevPool is the real one; the only listener is its own
// in-process loopback listener on an ephemeral port, in the cases where startup is allowed to finish.

import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import * as realFs from 'node:fs';
import { mkdtempSync, readdirSync, readFileSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { EXIT_CODES, RunCancelledError, createRunLifecycle, persistJsonAtomically } from '../tools/live_run_lifecycle.mjs';
import { startDevPool } from '../../pool/dev/server.mjs';
import { REAL_DAEMON_MODE } from '../lib/shared/protocol.js';

function fakeResource(label, { confirmClose = true, confirmForce = true } = {}) {
  return {
    label,
    closed: false,
    closeCalls: 0,
    forceCloseCalls: 0,
    beginClose() {},
    async close() { this.closeCalls += 1; if (confirmClose) this.closed = true; },
    async forceClose() { this.forceCloseCalls += 1; if (confirmForce) this.closed = true; },
  };
}

/** What the real-daemon factory hands startDevPool: enough for createSimulationContext and a listener. */
const FAKE_BUILT = () => ({
  job: {}, latch: {}, authority: {}, daemon: { counters: {} },
  makeServerVerifier: () => null, expectedHashHexLE: null, recordedContext: {},
});

/** Resolves only when `signal` aborts, rejecting the way startLocalDaemon does. */
function untilAborted(signal) {
  return new Promise((_, reject) => {
    const fail = () => reject(Object.assign(new Error('startup was aborted'), { code: 'aborted' }));
    if (signal.aborted) { fail(); return; }
    signal.addEventListener('abort', fail, { once: true });
  });
}

function harness({ startPool = startDevPool, persistEvidence = null, resources = [] } = {}) {
  const proc = new EventEmitter();
  const exits = [];
  let resolveExit;
  const exited = new Promise((r) => { resolveExit = r; });
  let lc = null;
  lc = createRunLifecycle({
    startPool,
    persistEvidence,
    exit: (code) => {
      // WHAT IS TRUE AT THE MOMENT OF EXIT. Nothing may still be starting, open or listening.
      exits.push({
        code,
        pool: lc.pool,
        listening: lc.pool ? lc.pool.httpServer.listening : null,
        retained: lc.pool ? lc.pool.retainedResources.map((r) => r.label) : [],
        resources: resources.map((r) => ({ label: r.label, closed: r.closed, closeCalls: r.closeCalls, forceCloseCalls: r.forceCloseCalls })),
      });
      resolveExit(code);
    },
  });
  lc.installSignalHandlers(proc);
  return { proc, lc, exits, exited };
}

const POOL_OPTIONS = { host: '127.0.0.1', port: 0, mode: REAL_DAEMON_MODE, realDaemon: { daemon: {} } };

// ================================================================== signal during a pending startup
test('SIGINT while startup is pending with daemon A owned: startup settles, A closes exactly once, then exit 130', async () => {
  const A = fakeResource('meepcoind A');
  let paused;
  const atPause = new Promise((r) => { paused = r; });
  let signalSeen = null;
  const h = harness({ resources: [A] });
  let bodyContinued = false;
  const done = h.lc.run(async (lc) => {
    await lc.startPool({
      ...POOL_OPTIONS,
      realDaemonFactory: async ({ ownResource, signal }) => {
        signalSeen = signal;
        ownResource('meepcoind A', A);
        paused();
        return untilAborted(signal);
      },
    });
    bodyContinued = true;
    return EXIT_CODES.OK;
  });
  await atPause;
  // The runner-visible state the old handler judged by: no pool yet, although A is owned.
  assert.equal(h.lc.pool, null);
  assert.equal(A.closed, false);
  assert.ok(signalSeen instanceof AbortSignal, 'the startup AbortSignal did not reach the factory');
  assert.equal(signalSeen, h.lc.startupSignal);

  h.proc.emit('SIGINT');
  const result = await done;
  assert.equal(bodyContinued, false);
  assert.equal(h.exits.length, 1, 'exit was called more than once');
  assert.equal(h.exits[0].code, EXIT_CODES.SIGINT);
  assert.deepEqual(h.exits[0].resources, [{ label: 'meepcoind A', closed: true, closeCalls: 1, forceCloseCalls: 0 }]);
  assert.equal(h.exits[0].pool, null, 'a rejected startup produced a pool');
  assert.equal(result.released, true);
});

test('SIGTERM while startup is pending with A and B owned: both close once, force ONLY after an unconfirmed close, exit 143', async () => {
  const A = fakeResource('meepcoind A');
  const B = fakeResource('meepcoind B', { confirmClose: false });   // its ordinary close never confirms
  let paused;
  const atPause = new Promise((r) => { paused = r; });
  const h = harness({ resources: [A, B] });
  const done = h.lc.run(async (lc) => {
    await lc.startPool({
      ...POOL_OPTIONS,
      realDaemonFactory: async ({ ownResource, signal }) => {
        ownResource('meepcoind A', A);
        await Promise.resolve();
        ownResource('meepcoind B', B);
        paused();
        return untilAborted(signal);
      },
    });
    return EXIT_CODES.OK;
  });
  await atPause;
  assert.equal(h.lc.pool, null);
  h.proc.emit('SIGTERM');
  await done;
  assert.equal(h.exits.length, 1);
  assert.equal(h.exits[0].code, EXIT_CODES.SIGTERM);
  assert.deepEqual(h.exits[0].resources, [
    { label: 'meepcoind A', closed: true, closeCalls: 1, forceCloseCalls: 0 },
    { label: 'meepcoind B', closed: true, closeCalls: 1, forceCloseCalls: 1 },
  ]);
});

test('a signal IMMEDIATELY BEFORE startup fulfils: the pool is assigned, closed and its listener gone before exit', async () => {
  const A = fakeResource('meepcoind A');
  let h = null;
  let bodyContinued = false;
  h = harness({
    resources: [A],
    // The pool exists in full; the signal lands in the same turn, before the lifecycle's fulfilment.
    startPool: async (options) => {
      const pool = await startDevPool(options);
      h.proc.emit('SIGTERM');
      return pool;
    },
  });
  const done = h.lc.run(async (lc) => {
    await lc.startPool({
      ...POOL_OPTIONS,
      realDaemonFactory: async ({ ownResource }) => { ownResource('meepcoind A', A); return FAKE_BUILT(); },
    });
    bodyContinued = true;
    return EXIT_CODES.OK;
  });
  const result = await done;
  assert.equal(bodyContinued, false, 'the body carried on after cancellation');
  assert.equal(h.exits.length, 1);
  assert.equal(h.exits[0].code, EXIT_CODES.SIGTERM);
  assert.ok(h.exits[0].pool, 'the pool that fulfilled at the boundary was never assigned');
  assert.equal(h.exits[0].listening, false, 'the listener outlived the exit');
  assert.deepEqual(h.exits[0].retained, []);
  assert.deepEqual(h.exits[0].resources, [{ label: 'meepcoind A', closed: true, closeCalls: 1, forceCloseCalls: 0 }]);
  assert.equal(result.facts.poolShutdown.ok, true);
});

test('a signal after the factory returned but before listen completes: startup still fulfils and is closed', async () => {
  const A = fakeResource('meepcoind A');
  const h = harness({ resources: [A] });
  const done = h.lc.run(async (lc) => {
    await lc.startPool({
      ...POOL_OPTIONS,
      realDaemonFactory: async ({ ownResource }) => {
        ownResource('meepcoind A', A);
        queueMicrotask(() => h.proc.emit('SIGINT'));
        return FAKE_BUILT();
      },
    });
    return EXIT_CODES.OK;
  });
  await done;
  assert.equal(h.exits.length, 1);
  assert.equal(h.exits[0].code, EXIT_CODES.SIGINT);
  assert.ok(h.exits[0].pool);
  assert.equal(h.exits[0].listening, false);
  assert.equal(A.closeCalls, 1);
});

test('REPEATED signals are one cancellation: one exit, first signal wins, nothing closes twice', async () => {
  const A = fakeResource('meepcoind A');
  let paused;
  const atPause = new Promise((r) => { paused = r; });
  const h = harness({ resources: [A] });
  const done = h.lc.run(async (lc) => {
    await lc.startPool({
      ...POOL_OPTIONS,
      realDaemonFactory: async ({ ownResource, signal }) => { ownResource('meepcoind A', A); paused(); return untilAborted(signal); },
    });
    return EXIT_CODES.OK;
  });
  await atPause;
  h.proc.emit('SIGINT');
  h.proc.emit('SIGINT');
  h.proc.emit('SIGTERM');
  await done;
  h.proc.emit('SIGINT');                  // after the terminal path, too
  assert.equal(h.exits.length, 1);
  assert.equal(h.exits[0].code, EXIT_CODES.SIGINT);
  assert.equal(A.closeCalls, 1);
  assert.equal(A.forceCloseCalls, 0);
  // `on`, not `once`: a second Ctrl-C must hit this handler rather than Node's default kill.
  assert.equal(h.proc.listenerCount('SIGINT'), 1);
  assert.equal(h.proc.listenerCount('SIGTERM'), 1);
});

test('a signal before startup (during the gates) starts nothing and still exits through the one path', async () => {
  let factoryCalls = 0;
  const h = harness();
  const done = h.lc.run(async (lc) => {
    h.proc.emit('SIGTERM');
    await lc.startPool({ ...POOL_OPTIONS, realDaemonFactory: async () => { factoryCalls += 1; return FAKE_BUILT(); } });
    return EXIT_CODES.OK;
  });
  await done;
  assert.equal(factoryCalls, 0);
  assert.equal(h.lc.startupPromise, null);
  assert.deepEqual(h.exits.map((e) => e.code), [EXIT_CODES.SIGTERM]);
});

test('a signal while the body waits after startup: the body unblocks, the pool closes, one exit', async () => {
  const A = fakeResource('meepcoind A');
  const h = harness({ resources: [A] });
  let hookCalls = 0;
  h.lc.onCancel(() => { hookCalls += 1; });
  const done = h.lc.run(async (lc) => {
    await lc.startPool({
      ...POOL_OPTIONS,
      realDaemonFactory: async ({ ownResource }) => { ownResource('meepcoind A', A); return FAKE_BUILT(); },
    });
    setTimeout(() => h.proc.emit('SIGINT'), 5);
    for (;;) {                             // the runner's waitUntil shape
      lc.throwIfCancelled();
      await new Promise((r) => setTimeout(r, 2));
    }
  });
  await done;
  assert.equal(hookCalls, 1);
  assert.deepEqual(h.exits.map((e) => [e.code, e.listening]), [[EXIT_CODES.SIGINT, false]]);
  assert.equal(A.closeCalls, 1);
});

// ================================================================== exit codes on the normal path
test('normal success exits 0 once; a body error exits 1; unconfirmed release is 3 whatever else happened', async () => {
  {
    const A = fakeResource('meepcoind A');
    const h = harness({ resources: [A] });
    await h.lc.run(async (lc) => {
      await lc.startPool({ ...POOL_OPTIONS, realDaemonFactory: async ({ ownResource }) => { ownResource('meepcoind A', A); return FAKE_BUILT(); } });
      return EXIT_CODES.OK;
    });
    assert.deepEqual(h.exits.map((e) => [e.code, e.listening]), [[0, false]]);
  }
  {
    const errors = [];
    const h = harness();
    await h.lc.run(async () => { throw new Error('gate refused'); }, { onBodyError: (e) => errors.push(e.message) });
    assert.deepEqual(h.exits.map((e) => e.code), [1]);
    assert.deepEqual(errors, ['gate refused']);
  }
  {
    // A resource that never confirms, even when forced: the pool cannot claim release.
    const stuck = fakeResource('meepcoind A', { confirmClose: false, confirmForce: false });
    const h = harness({ resources: [stuck] });
    await h.lc.run(async (lc) => {
      await lc.startPool({ ...POOL_OPTIONS, realDaemonFactory: async ({ ownResource }) => { ownResource('meepcoind A', stuck); return FAKE_BUILT(); } });
      return EXIT_CODES.OK;
    });
    assert.deepEqual(h.exits.map((e) => e.code), [EXIT_CODES.RELEASE_UNCONFIRMED]);
  }
  {
    // The runner's own observations (containers, ports, profile) cannot confirm release: 3, also on a signal.
    const h = harness();
    await h.lc.run(async () => { h.proc.emit('SIGINT'); return EXIT_CODES.OK; }, { afterPoolClose: async () => ({ released: false }) });
    assert.deepEqual(h.exits.map((e) => e.code), [EXIT_CODES.RELEASE_UNCONFIRMED]);
  }
});

test('REQUIRED EVIDENCE: a success whose evidence cannot be persisted exits 4; a failure keeps its nonzero code', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'meep-lifecycle-'));
  try {
    const failingFs = { ...realFs, renameSync: () => { throw Object.assign(new Error('EPERM'), { code: 'EPERM' }); } };
    const persist = ({ exitCode }) => persistJsonAtomically(join(dir, 'evidence.json'), { exitCode }, { expect: { exitCode }, fs: failingFs });
    let h = harness({ persistEvidence: persist });
    let r = await h.lc.run(async () => EXIT_CODES.OK);
    assert.deepEqual(h.exits.map((e) => e.code), [EXIT_CODES.EVIDENCE_NOT_PERSISTED]);
    assert.equal(r.persisted.ok, false);
    assert.equal(r.persisted.stage, 'rename');

    h = harness({ persistEvidence: persist });
    await h.lc.run(async () => EXIT_CODES.FAILED);
    assert.deepEqual(h.exits.map((e) => e.code), [EXIT_CODES.FAILED]);

    // And a persisted, verified file on success exits 0 and reads back with the exit code in it.
    const good = ({ exitCode }) => persistJsonAtomically(join(dir, 'good.json'), { exitCode, outcome: 'X' }, { expect: { exitCode, outcome: 'X' } });
    h = harness({ persistEvidence: good });
    r = await h.lc.run(async () => EXIT_CODES.OK);
    assert.deepEqual(h.exits.map((e) => e.code), [0]);
    assert.equal(JSON.parse(readFileSync(join(dir, 'good.json'), 'utf8')).exitCode, 0);
    // A persistEvidence that throws is a failed persistence, not a crash.
    h = harness({ persistEvidence: () => { throw new Error('disk gone'); } });
    await h.lc.run(async () => EXIT_CODES.OK);
    assert.deepEqual(h.exits.map((e) => e.code), [EXIT_CODES.EVIDENCE_NOT_PERSISTED]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a post-close observation can demote provisional success before evidence is written', async () => {
  const seen = [];
  const h = harness({ persistEvidence: ({ exitCode }) => {
    seen.push(exitCode);
    return { ok: true };
  } });
  const result = await h.lc.run(async () => EXIT_CODES.OK, {
    afterPoolClose: async () => ({ released: true, outcomeCode: EXIT_CODES.FAILED }),
  });
  assert.equal(result.code, EXIT_CODES.FAILED);
  assert.deepEqual(seen, [EXIT_CODES.FAILED]);
  assert.deepEqual(h.exits.map((entry) => entry.code), [EXIT_CODES.FAILED]);
});

// ================================================================== atomic persistence, fault-injected
test('ATOMIC EVIDENCE: written, flushed, renamed, reopened, parsed and verified -- and only then ok', () => {
  const dir = mkdtempSync(join(tmpdir(), 'meep-evidence-'));
  try {
    const path = join(dir, 'run.json');
    writeFileSync(path, '{"old":true}');                                  // an earlier file is replaced atomically
    const value = { exitCode: 0, outcome: 'BLOCK', big: 12345678901234567890n, events: [{ a: 1 }] };
    const calls = [];
    const spyFs = new Proxy(realFs, { get: (t, k) => (typeof t[k] === 'function' ? (...a) => { calls.push(k); return t[k](...a); } : t[k]) });
    const r = persistJsonAtomically(path, value, { expect: { exitCode: 0, outcome: 'BLOCK' }, fs: spyFs });
    assert.equal(r.ok, true, JSON.stringify(r));
    const bytes = readFileSync(path);
    assert.equal(r.bytes, bytes.length);
    assert.equal(r.sha256, createHash('sha256').update(bytes).digest('hex'));
    assert.equal(JSON.parse(bytes).big, '12345678901234567890');
    assert.deepEqual(readdirSync(dir), ['run.json'], 'a temporary sibling was left behind');
    // The order that makes "saved" mean saved.
    const order = ['openSync', 'writeSync', 'fsyncSync', 'closeSync', 'renameSync', 'readFileSync'];
    assert.deepEqual(calls.filter((c) => order.includes(c)).filter((c, i, arr) => arr.indexOf(c) === i), order);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('ATOMIC EVIDENCE: write, rename, truncated readback, parse and field-verification failures are all reported, never thrown', () => {
  const dir = mkdtempSync(join(tmpdir(), 'meep-evidence-'));
  try {
    const value = { exitCode: 0, outcome: 'BLOCK', finishedAt: '2026-09-15T00:00:00.000Z' };
    const expect = { exitCode: 0, outcome: 'BLOCK', finishedAt: value.finishedAt };
    const cases = [
      ['write', { writeSync: () => { throw Object.assign(new Error('no space'), { code: 'ENOSPC' }); } }, 'write', false],
      ['a write that makes no progress', { writeSync: () => 0 }, 'write', false],
      ['flush', { fsyncSync: () => { throw Object.assign(new Error('io'), { code: 'EIO' }); } }, 'flush', false],
      ['rename', { renameSync: () => { throw Object.assign(new Error('denied'), { code: 'EPERM' }); } }, 'rename', false],
      ['truncated readback', { readFileSync: (p, ...rest) => realFs.readFileSync(p, ...rest).subarray(0, 10) }, 'readback', true],
      ['final parse', { readFileSync: (p, ...rest) => Buffer.alloc(realFs.readFileSync(p, ...rest).length, 0x78) }, 'parse', true],
    ];
    for (const [name, override, stage, reachedRename] of cases) {
      const path = join(dir, `${stage}-${name.length}.json`);
      const r = persistJsonAtomically(path, value, { expect, fs: { ...realFs, ...override } });
      assert.equal(r.ok, false, name);
      assert.equal(r.stage, stage, name);
      assert.equal(existsSync(path), reachedRename, `${name}: final file presence`);
      assert.equal(readdirSync(dir).some((f) => f.endsWith('.tmp')), false, `${name}: temporary sibling left behind`);
      if (existsSync(path)) rmSync(path);
    }
    // A readback that parses but does not carry the expected terminal fields is not preserved evidence.
    const r = persistJsonAtomically(join(dir, 'verify.json'), value, { expect: { exitCode: 3 } });
    assert.equal(r.ok, false);
    assert.equal(r.stage, 'verify');
    // Unserializable input is refused before any file exists.
    const cyclic = {}; cyclic.self = cyclic;
    assert.equal(persistJsonAtomically(join(dir, 'cyclic.json'), cyclic).stage, 'serialize');
    assert.equal(existsSync(join(dir, 'cyclic.json')), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('RunCancelledError names the signal and carries a stable code', () => {
  const e = new RunCancelledError('SIGINT');
  assert.equal(e.code, 'run_cancelled');
  assert.equal(e.signal, 'SIGINT');
});
