// The command-line launcher's shutdown path.
//
// run.mjs used to do `void pool.close()` with no catch, a plain boolean guard, and `process.exit(0)`
// on the other side. If close rejected -- which is exactly what it now does when a native child
// cannot be confirmed gone -- the launcher produced an unhandled rejection, ignored every later
// signal, and had no way to reach the retained-resource retry path at all.
//
// The controller is factored out precisely so this can be tested without spawning a CLI and sending
// it real signals.

import test from 'node:test';
import assert from 'node:assert/strict';

import { EXIT_PROTOCOL_ANOMALY, createShutdownController } from '../cli_shutdown.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A pool stand-in whose close/retry behaviour the test dictates. */
function fakePool({ closeResults = [], retained = [], result = undefined,
  mode = 'synthetic', attemptState = undefined, attemptReason = undefined } = {}) {
  const calls = [];
  let inFlight = 0;
  let maxConcurrent = 0;
  const queue = [...closeResults];
  const run = async (kind) => {
    calls.push(kind);
    inFlight++;
    maxConcurrent = Math.max(maxConcurrent, inFlight);
    await sleep(30);
    inFlight--;
    const next = queue.shift() ?? 'ok';
    if (next !== 'ok') throw new Error(next);
  };
  return {
    calls,
    get maxConcurrent() { return maxConcurrent; },
    mode,
    ...(attemptState === undefined ? {} : { simulation: { attemptState, attemptReason } }),
    stats: { accepted: 0, rejected: 0 },
    retainedResources: retained,
    close: async () => { await run('close'); return result; },
    retryClose: async () => { await run('retry'); return result; },
  };
}

function recorder() {
  const out = [];
  const err = [];
  const exits = [];
  return {
    out,
    err,
    exits,
    io: {
      log: (t) => out.push(String(t)),
      error: (t) => err.push(String(t)),
      exit: (c) => exits.push(c),
      wait: () => Promise.resolve(),
    },
  };
}

test('a clean shutdown exits 0 exactly once', { timeout: 30_000 }, async () => {
  const pool = fakePool();
  const r = recorder();
  const c = createShutdownController({ pool, ...r.io });
  await c.requestShutdown('SIGINT');
  assert.deepEqual(pool.calls, ['close']);
  assert.deepEqual(r.exits, [0]);
});

test('real-daemon shutdown reports the block outcome, not unrelated share counters',
  { timeout: 30_000 }, async () => {
    const pool = fakePool({
      mode: 'real-local-daemon', attemptState: 'terminal_complete', attemptReason: 'complete',
    });
    const r = recorder();
    const c = createShutdownController({ pool, ...r.io });
    await c.requestShutdown('SIGINT');

    assert.match(r.out[0], /private block attempt complete \(accepted with canonical readback\)/);
    assert.doesNotMatch(r.out[0], /accepted 0, rejected 0/,
      'generic share counters must not contradict a completed real block attempt');
    assert.deepEqual(r.exits, [0]);
  });

test('real-daemon shutdown names a non-success terminal state and reason',
  { timeout: 30_000 }, async () => {
    const pool = fakePool({
      mode: 'real-local-daemon', attemptState: 'terminal_cancelled', attemptReason: 'search_bound_reached',
    });
    const r = recorder();
    const c = createShutdownController({ pool, ...r.io });
    await c.requestShutdown('SIGTERM');

    assert.match(r.out[0], /private block attempt terminal_cancelled \(reason search_bound_reached\)/);
    assert.doesNotMatch(r.out[0], /accepted with canonical readback/);
  });

test('a second signal during a shutdown JOINS it instead of starting a second teardown',
  { timeout: 30_000 }, async () => {
    const pool = fakePool();
    const r = recorder();
    const c = createShutdownController({ pool, ...r.io });
    const a = c.requestShutdown('SIGINT');
    const b = c.requestShutdown('SIGINT');
    const d = c.requestShutdown('SIGTERM');
    await Promise.all([a, b, d]);

    assert.equal(pool.maxConcurrent, 1, 'never two teardowns at once');
    assert.deepEqual(pool.calls, ['close'], 'and only one teardown happened at all');
    assert.equal(c.signalCount, 3);
    assert.ok(r.out.some((l) => /already in progress/.test(l)), 'the extra signals are acknowledged');
  });

test('a close that fails and then succeeds is retried, reported, and exits 0 only at the end',
  { timeout: 30_000 }, async () => {
    const pool = fakePool({ closeResults: ['pool shutdown could not be confirmed: verifier'] });
    const r = recorder();
    const c = createShutdownController({ pool, ...r.io });
    await c.requestShutdown('SIGINT');

    assert.deepEqual(pool.calls, ['close', 'retry'], 'the retained-resource retry path is reachable');
    assert.ok(r.err.some((l) => /could not be confirmed/.test(l)), 'the failure is reported, not swallowed');
    assert.deepEqual(r.exits, [0], 'and success is only claimed once it really succeeded');
  });

test('an unconfirmed resource means the process STAYS ALIVE and never exits 0',
  { timeout: 30_000 }, async () => {
    const helper = { helperLinuxPid: 4242 };
    const pool = fakePool({
      closeResults: ['cannot confirm the helper is gone', 'still cannot confirm', 'still cannot confirm'],
      retained: [{ label: 'verifier', resource: helper }],
    });
    const r = recorder();
    const c = createShutdownController({ pool, ...r.io });
    await c.requestShutdown('SIGINT');

    assert.deepEqual(r.exits, [], 'exiting would orphan the child and print success over it');
    assert.ok(r.err.some((l) => /SHUTDOWN INCOMPLETE/.test(l)));
    assert.ok(r.err.some((l) => /still owned: verifier/.test(l)), 'and it says exactly what is held');
    assert.ok(r.err.some((l) => /Linux pid 4242 was NOT confirmed gone/.test(l)));
    assert.equal(pool.calls.length, 3, 'retries are bounded, not infinite');
    assert.equal(pool.maxConcurrent, 1);
  });

test('a later signal after an exhausted attempt is an explicit, non-overlapping retry',
  { timeout: 30_000 }, async () => {
    const pool = fakePool({ closeResults: ['nope', 'nope', 'nope'] });
    const r = recorder();
    const c = createShutdownController({ pool, ...r.io });
    await c.requestShutdown('SIGINT');
    assert.deepEqual(r.exits, []);
    const before = pool.calls.length;

    // The operator investigated and the resource is releasable now.
    await c.requestShutdown('SIGINT');
    assert.ok(pool.calls.length > before, 'the second signal really does try again');
    assert.equal(pool.maxConcurrent, 1, 'and still never overlaps');
    assert.deepEqual(r.exits, [0], 'and now it may exit');
  });

test('a rejected close never escapes as an unhandled rejection', { timeout: 30_000 }, async (t) => {
  const unhandled = [];
  const onUnhandled = (e) => unhandled.push(e);
  process.on('unhandledRejection', onUnhandled);
  t.after(() => process.off('unhandledRejection', onUnhandled));

  const pool = fakePool({ closeResults: ['a', 'b', 'c'], retained: [{ label: 'verifier', resource: {} }] });
  const r = recorder();
  const c = createShutdownController({ pool, ...r.io });
  c.requestShutdown('SIGINT'); // deliberately NOT awaited, exactly as a signal handler calls it
  await sleep(400);
  assert.deepEqual(unhandled, []);
});

// ---------------------------------------------------------------- abnormal, but released
//
// A helper that is positively gone owns nothing, so the launcher MAY exit -- but its QUIT/BYE/exit
// transcript being wrong is not success. It used to reach the user as exit code 0 and complete
// silence: the anomaly existed only as an event handed to a logger that the pool defaults to a
// no-op and that the CLI never replaces.

test('an abnormal-but-released shutdown prints the anomaly and exits NONZERO',
  { timeout: 30_000 }, async () => {
    const r = recorder();
    const pool = fakePool({
      result: {
        ok: true,
        physicalReleaseConfirmed: true,
        gracefulProtocolShutdown: false,
        protocolAnomalies: [{ label: 'verifier', reason: 'native helper: helper exited without sending BYE' }],
      },
    });
    const ctl = createShutdownController({ pool, ...r.io });
    await ctl.requestShutdown('SIGINT');

    assert.deepEqual(r.exits, [EXIT_PROTOCOL_ANOMALY],
      'released means it may exit; abnormal means it must not exit 0');
    assert.notEqual(EXIT_PROTOCOL_ANOMALY, 0);
    assert.ok(r.err.some((line) => /THE HELPER GOODBYE WAS ABNORMAL/.test(line)),
      `the operator must SEE it; stderr was ${JSON.stringify(r.err)}`);
    assert.ok(r.err.some((line) => /exited without sending BYE/.test(line)),
      'and the specific reason must be named, not just that something was wrong');
    assert.deepEqual(ctl.protocolAnomalies,
      [{ label: 'verifier', reason: 'native helper: helper exited without sending BYE' }]);
  });

test('a clean structured result still exits 0 and says nothing alarming', { timeout: 30_000 }, async () => {
  const r = recorder();
  const pool = fakePool({
    result: { ok: true, physicalReleaseConfirmed: true, gracefulProtocolShutdown: true, protocolAnomalies: [] },
  });
  const ctl = createShutdownController({ pool, ...r.io });
  await ctl.requestShutdown('SIGINT');
  assert.deepEqual(r.exits, [0]);
  assert.deepEqual(r.err, [], 'a canonical shutdown produces no error output at all');
  assert.deepEqual(ctl.protocolAnomalies, []);
});

test('an unreleased resource still outranks an anomaly: the process STAYS ALIVE',
  { timeout: 30_000 }, async () => {
    // Ordering matters. "Something is still owned" is the stronger condition and must win: exiting
    // would orphan it, whatever the transcript said.
    const r = recorder();
    const pool = fakePool({
      closeResults: ['close failed', 'retry failed', 'retry failed'],
      retained: [{ label: 'native helper', resource: {} }],
    });
    const ctl = createShutdownController({ pool, ...r.io });
    await ctl.requestShutdown('SIGINT');
    assert.deepEqual(r.exits, [], 'never exit while a child is unaccounted for');
    assert.ok(r.err.some((line) => /SHUTDOWN INCOMPLETE/.test(line)));
  });
