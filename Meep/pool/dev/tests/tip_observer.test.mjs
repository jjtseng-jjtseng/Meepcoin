// THE CANONICAL-TIP OBSERVER, alone, with every collaborator injected and in memory.
//
// The observer is the real one. Its clock, its daemon read, the live-run state it is allowed to see
// and the trusted seam it reports to are all plain objects in this process, so every decision it can
// make is exercised without a daemon, a socket, a timer of its own or any other real resource.
//
// NO PROCESS, LISTENER, DAEMON, BROWSER, WALLET OR NETWORK is created or contacted by this file.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  TIP_OBSERVATION_FAILED, TIP_OBSERVER_DEFAULT_INTERVAL_MS, TIP_PARENT_CHANGED, createTipObserver,
} from '../tip_observer.mjs';

const hex = (c) => c.repeat(64);
const JOB = 'job-7';

/** One observer with a hand-driven timer: `world.tick()` runs exactly one cycle and awaits it. */
function world({ tip = { height: '4', blockId: hex('a') }, live = {}, notifyResult = { ok: true } } = {}) {
  const pending = [];
  const notified = [];
  const failures = [];
  const state = {
    active: true,
    busy: false,
    jobId: JOB,
    jobHeight: '5',
    parentBlockId: hex('a'),
    ownBlocks: [],
    ...live,
  };
  let current = tip;
  let readError = null;
  let reads = 0;

  const observer = createTipObserver({
    readTip: async () => {
      reads += 1;
      if (readError !== null) throw readError;
      return current;
    },
    state: () => ({
      active: state.active,
      busy: state.busy,
      jobId: state.jobId,
      jobHeight: state.jobHeight,
      parentBlockId: state.parentBlockId,
      isOwnBlock: (id) => state.ownBlocks.includes(id),
    }),
    notify: async (t) => { notified.push(t); return notifyResult; },
    onFailure: (code, detail) => failures.push({ code, detail }),
    intervalMs: 10,
    setTimer: (fn) => { pending.push(fn); return { fn }; },
    clearTimer: (t) => {
      const i = pending.indexOf(t.fn);
      if (i >= 0) pending.splice(i, 1);
    },
  });

  return {
    observer,
    state,
    notified,
    failures,
    get reads() { return reads; },
    get scheduled() { return pending.length; },
    setTip(next) { current = next; },
    failNextRead(err) { readError = err; },
    /** Run the one scheduled cycle, if any, and wait for it to finish. */
    async tick() {
      const fn = pending.shift();
      if (!fn) return false;
      await fn();
      return true;
    },
  };
}

// ================================================================== nothing happens before Start
test('TIP OBSERVER: nothing is read before start(), and start() is the only thing that arms it', async () => {
  const w = world();
  assert.equal(w.scheduled, 0, 'a timer existed before start()');
  assert.equal(await w.tick(), false);
  assert.equal(w.reads, 0);

  assert.equal(w.observer.start(), true);
  assert.equal(w.observer.start(), false, 'start() is not idempotent');
  assert.equal(w.scheduled, 1);
  assert.equal(w.reads, 0, 'arming the observer already read the daemon');
});

// ================================================================== the inert observations
test('TIP OBSERVER: the parent tip, this session\'s own block, and a repeat all cost one read and nothing else', async () => {
  const w = world();
  w.observer.start();

  // The ordinary state of the world: A's tip is the PARENT of the job being searched.
  await w.tick();
  assert.deepEqual(w.notified, [], 'the parent tip was reported as a competing tip');
  assert.equal(w.observer.stateFacts.counts.behind, 1);

  // This session's own accepted block at the job's height: the acceptance path owns that.
  w.state.ownBlocks.push(hex('b'));
  w.setTip({ height: '5', blockId: hex('b') });
  await w.tick();
  assert.deepEqual(w.notified, [], 'the observer manufactured an external tip for our own block');
  assert.equal(w.observer.stateFacts.counts.own, 1);

  // A competing block at the job's height: exactly one observation reaches the seam...
  w.setTip({ height: '5', blockId: hex('c') });
  await w.tick();
  assert.deepEqual(w.notified, [{ height: '5', blockId: hex('c') }]);

  // ...and seeing the same tip again, for the same job, is not a second rotation.
  await w.tick();
  await w.tick();
  assert.equal(w.notified.length, 1, 'a repeated observation rotated twice');
  assert.equal(w.observer.stateFacts.counts.duplicate, 2);
  assert.equal(w.observer.stateFacts.counts.notified, 1);
});

test('TIP OBSERVER: a busy session is not observed at all, and an idle one stops the observer', async () => {
  const w = world({ live: { busy: true } });
  w.observer.start();
  w.setTip({ height: '9', blockId: hex('d') });
  await w.tick();
  assert.equal(w.reads, 0, 'the observer read daemon A while this session was mid-candidate');
  assert.deepEqual(w.notified, []);
  assert.equal(w.observer.running, true, 'busy is a skipped cycle, not the end of the observer');

  w.state.busy = false;
  await w.tick();
  assert.deepEqual(w.notified, [{ height: '9', blockId: hex('d') }]);

  // A terminal attempt: the observer stops itself rather than polling a daemon forever.
  w.state.active = false;
  await w.tick();
  assert.equal(w.observer.running, false);
  assert.equal(w.scheduled, 0, 'a stopped observer left a timer behind');
});

test('TIP OBSERVER: a tip AHEAD of the job is still exactly one observation -- the session decides', async () => {
  const w = world({ tip: { height: '11', blockId: hex('e') } });
  w.observer.start();
  await w.tick();
  assert.deepEqual(w.notified, [{ height: '11', blockId: hex('e') }],
    'the observer swallowed a tip past this job instead of reporting it');
  assert.deepEqual(w.failures, [], 'reporting an ahead tip is the session\'s decision, not a failure');
});

test('TIP OBSERVER: only the exact issued parent is inert; every replacement or rollback fails closed', async () => {
  for (const { tip, live = {} } of [
    { tip: { height: '4', blockId: hex('b') } }, // same parent height, different identity
    { tip: { height: '3', blockId: hex('c') } }, // canonical rollback below the issued parent
    // Remembering this as one of our own older blocks must not mask the same rollback.
    { tip: { height: '3', blockId: hex('d') }, live: { ownBlocks: [hex('d')] } },
  ]) {
    const w = world({ tip, live });
    w.observer.start();
    await w.tick();
    assert.equal(w.observer.running, false, `stale template kept running for ${JSON.stringify(tip)}`);
    assert.equal(w.failures.length, 1);
    assert.equal(w.failures[0].code, TIP_PARENT_CHANGED);
    assert.match(w.failures[0].detail, /no longer matches the issued template parent/);
    assert.deepEqual(w.notified, []);
  }
});

// ================================================================== races
test('TIP OBSERVER: an observation whose job rotated under it is discarded, not acted on', async () => {
  const notified = [];
  const live = { jobId: JOB, jobHeight: '5' };
  let armed = null;
  const observer = createTipObserver({
    // The job rotates WHILE the read is in flight, so the answer describes a state already gone.
    readTip: async () => { live.jobId = 'job-8'; live.jobHeight = '6'; return { height: '5', blockId: hex('c') }; },
    state: () => ({
      active: true, busy: false, jobId: live.jobId, jobHeight: live.jobHeight,
      parentBlockId: hex('a'), isOwnBlock: () => false,
    }),
    notify: async (t) => { notified.push(t); return { ok: true }; },
    intervalMs: 10,
    setTimer: (fn) => { armed = fn; return { fn }; },
    clearTimer: () => { armed = null; },
  });
  observer.start();
  await armed();

  assert.deepEqual(notified, [], 'a stale-generation observation rotated the new job');
  assert.equal(observer.stateFacts.counts.duplicate, 1, 'the rotated-away observation was not discarded');
  assert.equal(observer.running, true, 'discarding one observation must not end the observer');
  observer.stop('test');
});

test('TIP OBSERVER: stopping during an in-flight read makes the late answer inert', async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const notified = [];
  let armed = null;
  const observer = createTipObserver({
    readTip: async () => { await gate; return { height: '5', blockId: hex('c') }; },
    state: () => ({
      active: true, busy: false, jobId: JOB, jobHeight: '5', parentBlockId: hex('a'),
      isOwnBlock: () => false,
    }),
    notify: async (t) => { notified.push(t); return { ok: true }; },
    intervalMs: 10,
    setTimer: (fn) => { armed = fn; return { fn }; },
    clearTimer: () => { armed = null; },
  });
  observer.start();
  const cycle = armed();                 // the read is now in flight, awaiting the gate
  observer.stop('user_stop');            // Stop, hidden tab, socket loss, shutdown: all land here
  release();
  await cycle;
  await new Promise((r) => setImmediate(r));

  assert.deepEqual(notified, [], 'a read that resolved after stop() still reached the seam');
  assert.equal(observer.running, false);
  assert.equal(observer.stateFacts.timers, 0, 'a late cycle re-armed a stopped observer');
});

test('TIP OBSERVER: a late rejected read or notification after stop is inert', async () => {
  for (const stage of ['read', 'notify']) {
    let rejectGate;
    const gate = new Promise((resolve, reject) => { void resolve; rejectGate = reject; });
    const failures = [];
    let armed = null;
    const observer = createTipObserver({
      readTip: stage === 'read'
        ? async () => gate
        : async () => ({ height: '5', blockId: hex('c') }),
      state: () => ({
        active: true, busy: false, jobId: JOB, jobHeight: '5', parentBlockId: hex('a'),
        isOwnBlock: () => false,
      }),
      notify: stage === 'notify' ? async () => gate : async () => ({ ok: true }),
      onFailure: (code, detail) => failures.push({ code, detail }),
      intervalMs: 10,
      setTimer: (fn) => { armed = fn; return { fn }; },
      clearTimer: () => { armed = null; },
    });
    observer.start();
    const cycle = armed();
    await Promise.resolve();
    observer.stop('test stop');
    rejectGate(new Error(`late ${stage} rejection`));
    await cycle;
    assert.deepEqual(failures, [], `${stage}: a stopped observer emitted a failure`);
    assert.equal(observer.stateFacts.counts.failures, 0, `${stage}: diagnostics changed after stop`);
    assert.equal(observer.stateFacts.timers, 0);
  }
});

// ================================================================== failure is terminal
test('TIP OBSERVER: a read that throws stops the observer and fails the attempt closed', async () => {
  const w = world();
  w.observer.start();
  w.failNextRead(Object.assign(new Error('daemon unreachable'), { code: 'rpc_unavailable' }));
  await w.tick();

  assert.equal(w.observer.running, false, 'the observer kept polling after a failed read');
  assert.equal(w.scheduled, 0);
  assert.equal(w.failures.length, 1);
  assert.equal(w.failures[0].code, TIP_OBSERVATION_FAILED);
  assert.match(w.failures[0].detail, /rpc_unavailable/);
  assert.deepEqual(w.notified, []);

  // Nothing re-arms it, and nothing is read again.
  assert.equal(w.observer.start(), true, 'start() after a failure is the caller\'s decision');
  w.observer.stop('test');
});

test('TIP OBSERVER: a malformed height or block id is a failure, never a coerced observation', async () => {
  for (const bad of [
    { height: '5', blockId: 'not-a-hash' },
    { height: 'five', blockId: hex('c') },
    { height: 5, blockId: hex('c') },
    { height: '5', blockId: hex('C') },
    null,
  ]) {
    const w = world({ tip: bad });
    w.observer.start();
    await w.tick();
    assert.deepEqual(w.notified, [], `a malformed tip was acted on: ${JSON.stringify(bad)}`);
    assert.equal(w.failures.length, 1, `a malformed tip was swallowed: ${JSON.stringify(bad)}`);
    assert.equal(w.failures[0].code, TIP_OBSERVATION_FAILED);
    assert.equal(w.observer.running, false);
  }
});

test('TIP OBSERVER: internal state, scheduler and unchanged-live seam refusals fail closed', async () => {
  // A state hook failure must not masquerade as an ordinary idle/finished run.
  let armed = null;
  const stateFailures = [];
  const stateObserver = createTipObserver({
    readTip: async () => ({ height: '4', blockId: hex('a') }),
    state: () => { throw new Error('state exploded'); },
    notify: async () => ({ ok: true }),
    onFailure: (code, detail) => stateFailures.push({ code, detail }),
    intervalMs: 10,
    setTimer: (fn) => { armed = fn; return { fn }; },
    clearTimer: () => { armed = null; },
  });
  stateObserver.start();
  await armed();
  assert.equal(stateFailures[0].code, TIP_OBSERVATION_FAILED);
  assert.match(stateFailures[0].detail, /state exploded/);

  const scheduleFailures = [];
  const scheduleObserver = createTipObserver({
    readTip: async () => ({ height: '4', blockId: hex('a') }),
    state: () => ({ active: true }),
    notify: async () => ({ ok: true }),
    onFailure: (code, detail) => scheduleFailures.push({ code, detail }),
    setTimer: () => { throw new Error('timer unavailable'); },
  });
  assert.equal(scheduleObserver.start(), false);
  assert.equal(scheduleFailures[0].code, TIP_OBSERVATION_FAILED);
  assert.match(scheduleFailures[0].detail, /timer unavailable/);

  const refused = world({
    tip: { height: '5', blockId: hex('c') },
    notifyResult: { ok: false, reason: 'scripted_refusal' },
  });
  refused.observer.start();
  await refused.tick();
  assert.equal(refused.failures[0].code, TIP_OBSERVATION_FAILED);
  assert.match(refused.failures[0].detail, /scripted_refusal/);
  assert.equal(refused.observer.running, false);
});

test('TIP OBSERVER: losing the timer while re-arming after a cycle fails closed', async () => {
  let armed = null;
  let schedules = 0;
  const failures = [];
  const observer = createTipObserver({
    readTip: async () => ({ height: '4', blockId: hex('a') }),
    state: () => ({
      active: true, busy: false, jobId: JOB, jobHeight: '5', parentBlockId: hex('a'),
      isOwnBlock: () => false,
    }),
    notify: async () => ({ ok: true }),
    onFailure: (code, detail) => failures.push({ code, detail }),
    intervalMs: 10,
    setTimer: (fn) => {
      schedules += 1;
      if (schedules === 2) throw new Error('timer lost after first poll');
      armed = fn;
      return { fn };
    },
    clearTimer: () => { armed = null; },
  });

  assert.equal(observer.start(), true);
  await armed();
  assert.equal(observer.running, false, 'observer stayed live without a future poll');
  assert.equal(observer.stateFacts.timers, 0);
  assert.equal(observer.stateFacts.counts.cycles, 1);
  assert.equal(observer.stateFacts.counts.failures, 1);
  assert.equal(failures[0].code, TIP_OBSERVATION_FAILED);
  assert.match(failures[0].detail, /could not reschedule: timer lost after first poll/);
});

// ================================================================== closing and boundedness
test('TIP OBSERVER: close() releases it, and nothing reads, notifies or schedules afterwards', async () => {
  const w = world();
  w.observer.start();
  await w.observer.close('pool shutting down');

  assert.equal(w.observer.closed, true);
  assert.equal(w.observer.running, false);
  assert.equal(w.scheduled, 0, 'close() left a timer armed');
  assert.equal(w.observer.start(), false, 'a closed observer could be restarted');
  w.setTip({ height: '9', blockId: hex('f') });
  assert.equal(await w.tick(), false);
  assert.equal(w.reads, 0);
  assert.deepEqual(w.notified, []);
  assert.deepEqual(w.observer.shutdownOutcome,
    { physicalReleaseConfirmed: true, gracefulProtocolShutdown: true, reason: null });
  await w.observer.forceClose('again');   // idempotent
  assert.equal(w.observer.closed, true);
});

test('TIP OBSERVER: close joins an in-flight read before confirming physical release', async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let armed = null;
  const observer = createTipObserver({
    readTip: async () => { await gate; return { height: '4', blockId: hex('a') }; },
    state: () => ({
      active: true, busy: false, jobId: JOB, jobHeight: '5', parentBlockId: hex('a'),
      isOwnBlock: () => false,
    }),
    notify: async () => ({ ok: true }),
    intervalMs: 10,
    setTimer: (fn) => { armed = fn; return { fn }; },
    clearTimer: () => { armed = null; },
  });
  observer.start();
  const cycle = armed();
  await Promise.resolve();
  const closing = observer.close('pool shutting down');
  let settled = false;
  closing.finally(() => { settled = true; });
  await Promise.resolve();
  assert.equal(settled, false, 'close returned while the read was still in flight');
  assert.equal(observer.closed, false);
  assert.equal(observer.shutdownOutcome.physicalReleaseConfirmed, false);
  assert.equal(observer.stateFacts.activeCycles, 1);

  release();
  await cycle;
  await closing;
  assert.equal(observer.closed, true);
  assert.equal(observer.stateFacts.cycling, false);
  assert.equal(observer.stateFacts.activeCycles, 0);
  assert.equal(observer.shutdownOutcome.physicalReleaseConfirmed, true);
});

test('TIP OBSERVER: its whole memory is one timer, one acted-on record and counters', async () => {
  const w = world();
  w.observer.start();
  for (let i = 0; i < 40; i += 1) {
    w.setTip({ height: String(5 + i), blockId: hex((i % 10).toString()) });
    await w.tick();
  }
  const facts = w.observer.stateFacts;
  assert.equal(facts.timers, 1, 'more than one timer is armed');
  assert.equal(facts.actedRecords, 1, 'the observer kept a history of observations');
  assert.equal(facts.intervalMs, 10);
  assert.equal(typeof facts.counts.cycles, 'number');
  assert.equal(facts.counts.cycles, 40);
  assert.equal(Object.keys(facts.counts).length, 9, 'the counter set grew');
  w.observer.stop('test');
});

test('TIP OBSERVER: construction refuses missing collaborators and an unbounded interval', () => {
  assert.throws(() => createTipObserver({}), /readTip, state and notify/);
  const ok = { readTip: async () => ({}), state: () => ({}), notify: async () => ({ ok: true }) };
  assert.throws(() => createTipObserver({ ...ok, intervalMs: 0 }), /intervalMs/);
  assert.throws(() => createTipObserver({ ...ok, intervalMs: 60_001 }), /intervalMs/);
  assert.throws(() => createTipObserver({ ...ok, intervalMs: 1.5 }), /intervalMs/);
  assert.equal(createTipObserver(ok).stateFacts.intervalMs, TIP_OBSERVER_DEFAULT_INTERVAL_MS);
});
