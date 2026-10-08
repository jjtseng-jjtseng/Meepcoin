// DIRECT POOL INTEGRATION FOR SUSTAINED ROTATION. These tests join the trusted canonical-tip
// seam, the simulation session, the ownership graph and pool shutdown. Every daemon/verifier is an
// in-memory scripted collaborator. The only real resource is startDevPool's ephemeral loopback
// listener; no browser, wallet, key, child process, container, WSL instance or external network is
// created or contacted.

import test from 'node:test';
import assert from 'node:assert/strict';

import { startDevPool } from '../server.mjs';
import { createSimulationSession } from '../sim_session.mjs';
import { REAL_DAEMON_MODE } from '../../../web-miner/lib/shared/protocol.js';
import { CHAIN_A, buildScriptedChain, powFor } from './in_memory_chain.mjs';

const START_ID = '0123456789abcdef0123456789abcdef';

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

function driver(sim, clock) {
  const sent = [];
  const session = createSimulationSession({
    sim,
    now: () => clock.ms,
    send: (message) => sent.push(message),
    setTimer: () => ({ fake: true }),
    clearTimer: () => {},
  });
  const say = (message) => {
    const text = JSON.stringify(message);
    return session.handleRaw(Buffer.byteLength(text), text);
  };
  const last = (type) => [...sent].reverse().find((message) => message.type === type);
  return { session, sent, say, last };
}

async function startedPool(t, {
  sequenceBlocks = 3, verifierOptions = () => ({}), tipSource = null, start = true,
  observerOptions = {},
} = {}) {
  let chain = null;
  // The observer's clock is INJECTED: `armed()` runs exactly one observation cycle and resolves when
  // it is done, so nothing in these tests depends on a real timer.
  const timers = [];
  const pool = await startDevPool({
    host: '127.0.0.1',
    port: 0,
    mode: REAL_DAEMON_MODE,
    realDaemon: { daemon: CHAIN_A, sequenceBlocks },
    tipObserverOptions: {
      intervalMs: 10,
      setTimer: (fn) => { timers.push(fn); return { fn }; },
      clearTimer: (handle) => {
        const i = timers.indexOf(handle.fn);
        if (i >= 0) timers.splice(i, 1);
      },
      ...observerOptions,
    },
    realDaemonFactory: async ({ ownResource }) => {
      // Forward each daemon handle into the production pool graph at the exact instant the
      // scripted builder creates it. Adopting a collected list afterward would weaken the startup
      // ownership guarantee this integration test is meant to exercise.
      chain = await buildScriptedChain({}, {
        sequenceBlocks,
        verifierOptions,
        ownLog: { push: ({ label, r }) => ownResource(label, r) },
      });
      return tipSource === null ? chain.built : { ...chain.built, tipSource };
    },
  });
  t.after(() => pool.close().catch(() => {}));

  const d = driver(pool.simulation, chain.clock);
  /** Run the one armed observation cycle, if any, and wait for everything it caused. */
  const armed = async () => {
    const fn = timers.shift();
    if (!fn) return false;
    await fn();
    return true;
  };
  await d.say({ type: 'client_hello', protocolVersion: 1 });
  if (!start) return { pool, chain, d, armed, timers };
  await d.say({ type: 'start_request', clientStartId: START_ID });
  assert.ok(d.last('mining_ready'), 'the injected sequence did not become ready');
  return { pool, chain, d, armed, timers };
}

function addForeignTip(chain, height, hash = 'a'.repeat(64)) {
  const foreign = {
    hash,
    height,
    nonce: 4242,
    powHash: powFor(height),
    prevHash: chain.net.blocksA.at(-1).hash,
  };
  chain.net.blocksA.push(foreign);
  return foreign;
}

test('POOL ROTATION: trusted tip routing disowns the old verifier but preserves its shutdown anomaly', async (t) => {
  const reason = 'scripted QUIT transcript was non-canonical';
  const { pool, chain, d } = await startedPool(t, {
    verifierOptions: (index) => (index === 1 ? { shutdownGraceful: false, shutdownReason: reason } : {}),
  });

  // Two daemons, one verifier and the canonical-tip observer, which a sequence now owns as well.
  assert.equal(pool.ownedResourceCount, 4, 'two daemons, one verifier and the tip observer should be owned after Start');
  const beforeStart = await pool.notifyCanonicalTip({ height: '0', blockId: 'b'.repeat(64) });
  assert.deepEqual(beforeStart, { ok: false, reason: 'tip_behind' });

  const first = chain.journal.created[0];
  const foreign = addForeignTip(chain, 1);
  const moved = await pool.notifyCanonicalTip({ height: '1', blockId: foreign.hash });
  assert.equal(moved.ok, true, JSON.stringify(moved));
  assert.equal(d.last('sequence_next').cause, 'external_tip');
  assert.equal(d.last('mining_ready').sequenceIndex, 2);
  assert.equal(first.closed, true, 'the rotated verifier was not physically released');
  assert.equal(chain.journal.created.length, 2, 'the replacement verifier was not constructed exactly once');
  assert.equal(pool.ownedResourceCount, 4,
    'the released verifier stayed owned or the one replacement verifier was not adopted');
  assert.deepEqual(pool.shutdownOutcome.protocolAnomalies,
    [{ label: 'simulation verifier', reason }],
    'the abnormal-but-released verifier disappeared from the append-only anomaly ledger');
  assert.equal(pool.shutdownOutcome.gracefulProtocolShutdown, false);

  d.session.dispose();
  const closed = await pool.close();
  assert.equal(closed.physicalReleaseConfirmed, true);
  assert.equal(closed.gracefulProtocolShutdown, false);
  assert.deepEqual(closed.protocolAnomalies, [{ label: 'simulation verifier', reason }]);
  assert.equal(pool.ownedResourceCount, 0);
});

test('POOL ROTATION: a tip operation is admitted before shutdown and close drains it', async (t) => {
  const releaseGate = deferred();
  let releaseEntered;
  const atRelease = new Promise((resolve) => { releaseEntered = resolve; });
  const { pool, chain } = await startedPool(t, {
    verifierOptions: (index) => (index === 1 ? {
      closeGate: async () => { releaseEntered(); await releaseGate.promise; },
    } : {}),
  });

  const foreign = addForeignTip(chain, 1, 'c'.repeat(64));
  const moving = pool.notifyCanonicalTip({ height: '1', blockId: foreign.hash });
  await atRelease;
  assert.equal(pool.pendingOperationCount, 1, 'the trusted tip operation escaped the shutdown drain');

  let closeSettled = false;
  const closing = pool.close().then((outcome) => { closeSettled = true; return outcome; });
  assert.deepEqual(await pool.notifyCanonicalTip({ height: '2', blockId: 'd'.repeat(64) }),
    { ok: false, reason: 'pool_closing' },
    'shutdown admitted a second trusted tip operation');
  assert.equal(pool.pendingOperationCount, 1, 'the refused operation changed the drain set');
  let timeoutId;
  let timeoutRescueUsed = false;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      timeoutRescueUsed = true;
      releaseGate.resolve();
      reject(new Error('pool.close did not force the admitted tip rotation before its drain'));
    }, 1_500);
  });
  const [moved, closed] = await Promise.race([
    Promise.all([moving, closing]),
    timeout,
  ]).finally(() => clearTimeout(timeoutId));
  releaseGate.resolve(); // settle the deliberately abandoned graceful-close promise after the proof
  assert.equal(timeoutRescueUsed, false, 'only the test timeout, not pool shutdown, released the gate');
  assert.equal(closeSettled, true, 'pool.close did not reach a terminal result');
  assert.equal(moved.ok, true, JSON.stringify(moved));
  assert.equal(chain.journal.created.length, 1, 'shutdown allowed a replacement verifier to start');
  assert.equal(chain.net.counts.A.get_block_template, 1, 'shutdown allowed a replacement template to be fetched');
  assert.equal(closed.physicalReleaseConfirmed, true);
  assert.equal(pool.pendingOperationCount, 0);
  assert.equal(pool.ownedResourceCount, 0);
  assert.deepEqual(await pool.notifyCanonicalTip({ height: '2', blockId: 'd'.repeat(64) }),
    { ok: false, reason: 'pool_closing' },
    'shutdown admitted a new trusted tip operation');
  assert.equal(pool.pendingOperationCount, 0);
});

test('POOL ROTATION: shutdown force-recovers a graceful verifier release that never settles itself', async (t) => {
  let firstVerifier = null;
  let releaseEntered;
  const atRelease = new Promise((resolve) => { releaseEntered = resolve; });
  const { pool, chain } = await startedPool(t, {
    verifierOptions: (index) => (index === 1 ? {
      // This gate has no normal/manual release. It returns only after the production shutdown path
      // force-closes this exact verifier. A timeout below is test cleanup, not the success path.
      closeGate: async () => {
        releaseEntered();
        while (firstVerifier?.closed !== true) await new Promise((resolve) => setImmediate(resolve));
      },
      forceCloseError: 'scripted forceClose threw after physical release',
    } : {}),
  });
  firstVerifier = chain.journal.created[0];

  const foreign = addForeignTip(chain, 1, '9'.repeat(64));
  const moving = pool.notifyCanonicalTip({ height: '1', blockId: foreign.hash });
  await atRelease;
  assert.equal(pool.pendingOperationCount, 1, 'the stuck rotation is not inside the shutdown drain');
  assert.equal(pool.simulation.stateFacts.releasingVerifiers, 1,
    'the verifier disappeared from the explicit releasing-resource slot');

  let timeoutId;
  let timeoutRescueUsed = false;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      timeoutRescueUsed = true;
      Promise.resolve(firstVerifier.forceClose('test timeout rescue')).then(
        () => reject(new Error('pool.close did not force the in-flight rotation before its drain')),
        () => reject(new Error('pool.close did not force the in-flight rotation before its drain')),
      );
    }, 1_500);
  });
  const closing = pool.close();
  const [moved, closed] = await Promise.race([
    Promise.all([moving, closing]),
    timeout,
  ]).finally(() => clearTimeout(timeoutId));

  assert.equal(timeoutRescueUsed, false, 'only the test timeout, not pool shutdown, released the verifier');
  assert.equal(moved.ok, true, JSON.stringify(moved));
  assert.equal(chain.journal.created.length, 1, 'shutdown allowed a replacement verifier to start');
  assert.equal(chain.net.counts.A.get_block_template, 1, 'shutdown fetched a replacement template');
  assert.equal(firstVerifier.closed, true, 'the in-flight verifier was not physically released');
  assert.equal(closed.physicalReleaseConfirmed, true);
  assert.equal(closed.gracefulProtocolShutdown, false);
  assert.equal(closed.protocolAnomalies.length, 1, JSON.stringify(closed.protocolAnomalies));
  assert.match(closed.protocolAnomalies[0].reason,
    /graceful rotation close did not settle before shutdown escalation/);
  assert.match(closed.protocolAnomalies[0].reason,
    /forceClose threw: scripted forceClose threw after physical release/);
  assert.equal(pool.simulation.stateFacts.releasingVerifiers, 0);
  assert.equal(pool.pendingOperationCount, 0);
  assert.equal(pool.ownedResourceCount, 0);
});

test('POOL ROTATION: a throwing graceful close remains visible after confirmed release', async (t) => {
  const closeError = 'scripted close threw after physical release';
  const { pool, chain } = await startedPool(t, {
    verifierOptions: (index) => (index === 1 ? { closeError } : {}),
  });

  const first = chain.journal.created[0];
  const foreign = addForeignTip(chain, 1, '8'.repeat(64));
  const moved = await pool.notifyCanonicalTip({ height: '1', blockId: foreign.hash });
  assert.equal(moved.ok, true, JSON.stringify(moved));
  assert.equal(first.closed, true, 'the throwing close did not positively release the verifier');
  assert.equal(pool.ownedResourceCount, 4, 'the released verifier remained in the ownership graph');
  assert.equal(pool.shutdownOutcome.gracefulProtocolShutdown, false);
  assert.equal(pool.shutdownOutcome.protocolAnomalies.length, 1);
  assert.match(pool.shutdownOutcome.protocolAnomalies[0].reason,
    /close threw: scripted close threw after physical release/);
  assert.equal(pool.simulation.verifierHistory[0].closeError, closeError);

  const closed = await pool.close();
  assert.equal(closed.physicalReleaseConfirmed, true);
  assert.equal(closed.gracefulProtocolShutdown, false);
  assert.equal(closed.protocolAnomalies.length, 1);
  assert.match(closed.protocolAnomalies[0].reason,
    /close threw: scripted close threw after physical release/);
  assert.equal(pool.ownedResourceCount, 0);
});

test('POOL ROTATION: failed pre-drain force stays owned and retry never re-enters abandoned close', async (t) => {
  let firstVerifier = null;
  let releaseEntered;
  const atRelease = new Promise((resolve) => { releaseEntered = resolve; });
  const { pool, chain } = await startedPool(t, {
    verifierOptions: (index) => (index === 1 ? {
      closeGate: async () => {
        releaseEntered();
        while (firstVerifier?.closed !== true) await new Promise((resolve) => setImmediate(resolve));
      },
      // Call 1 is the pre-drain escalation. Call 2 is the same shutdown's ownership sweep. Both
      // fail without release. Call 3 is the explicit retry and confirms physical release.
      forceCloseConfirms: [false, false, true],
      forceCloseError: [
        'scripted pre-drain force failure',
        'scripted ownership-sweep force failure',
        null,
      ],
      shutdownGraceful: false,
      shutdownReason: 'scripted final force-close protocol anomaly',
    } : {}),
  });
  firstVerifier = chain.journal.created[0];

  const foreign = addForeignTip(chain, 1, '7'.repeat(64));
  const moving = pool.notifyCanonicalTip({ height: '1', blockId: foreign.hash });
  await atRelease;

  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      // Test cleanup only. A correct first close rejects before this fires.
      firstVerifier.forceClose('test timeout rescue').catch(() => {});
      reject(new Error('pool.close hung by re-awaiting the abandoned graceful close'));
    }, 1_500);
  });
  await assert.rejects(
    Promise.race([pool.close(), timeout]).finally(() => clearTimeout(timeoutId)),
    /pool shutdown could not be confirmed/,
  );
  const moved = await moving;
  assert.equal(moved.ok, false, JSON.stringify(moved));
  assert.equal(moved.reason, 'verifier_release_unconfirmed');
  assert.equal(chain.journal.created.length, 1, 'failed release allowed a replacement verifier');
  assert.equal(chain.net.counts.A.get_block_template, 1, 'failed release fetched a replacement template');
  assert.equal(firstVerifier.closed, false);
  assert.equal(firstVerifier.forceCloseCalls, 2, 'the first close did not exercise both bounded force attempts');
  assert.equal(chain.journal.events.filter((event) => event === 'close 1').length, 1,
    'the ownership sweep re-entered the abandoned graceful close');
  assert.equal(pool.ownedResourceCount, 1, 'the unclosed verifier was lost from the ownership graph');
  assert.equal(pool.retainedVerifier, firstVerifier);
  assert.equal(pool.shutdownOutcome.physicalReleaseConfirmed, false);
  assert.equal(pool.shutdownOutcome.gracefulProtocolShutdown, false);
  assert.equal(pool.shutdownOutcome.protocolAnomalies.length, 1,
    'one verifier produced more than one append-only anomaly row');
  assert.match(pool.shutdownOutcome.protocolAnomalies[0].reason,
    /graceful rotation close did not settle before shutdown escalation/);
  assert.match(pool.shutdownOutcome.protocolAnomalies[0].reason,
    /forceClose threw: scripted pre-drain force failure/);
  assert.ok(pool.shutdownOutcome.protocolAnomalies.some((entry) =>
    /scripted ownership-sweep force failure/.test(entry.reason)),
  'the failed ownership-sweep escalation disappeared before retry');

  const retried = await pool.retryClose();
  assert.equal(retried.physicalReleaseConfirmed, true);
  assert.equal(retried.gracefulProtocolShutdown, false,
    'a clean retry erased the earlier rotation shutdown failure');
  assert.equal(firstVerifier.closed, true);
  assert.equal(firstVerifier.forceCloseCalls, 3);
  assert.equal(chain.journal.events.filter((event) => event === 'close 1').length, 1,
    'retry re-entered the abandoned graceful close');
  assert.equal(pool.ownedResourceCount, 0);
  assert.equal(pool.shutdownOutcome.protocolAnomalies.length, 1,
    'retry created a second anomaly row for the same verifier');
  assert.match(pool.shutdownOutcome.protocolAnomalies[0].reason,
    /scripted final force-close protocol anomaly/,
    'the resource final shutdownOutcome was hidden by the abandoned-close path');
});

test('POOL ROTATION: shutdown joining ordinary escalation does not invent graceful abandonment', async (t) => {
  const forceGate = deferred();
  let forceEntered;
  const atForce = new Promise((resolve) => { forceEntered = resolve; });
  const reason = 'scripted ordinary escalation after an unconfirmed graceful close';
  const { pool, chain } = await startedPool(t, {
    verifierOptions: (index) => (index === 1 ? {
      closeConfirms: false,
      forceCloseConfirms: true,
      forceCloseGate: async () => { forceEntered(); await forceGate.promise; },
      shutdownGraceful: false,
      shutdownReason: reason,
    } : {}),
  });

  const foreign = addForeignTip(chain, 1, '6'.repeat(64));
  const moving = pool.notifyCanonicalTip({ height: '1', blockId: foreign.hash });
  await atForce;
  const closing = pool.close();
  forceGate.resolve();
  const [moved, closed] = await Promise.all([moving, closing]);

  assert.equal(moved.ok, true, JSON.stringify(moved));
  assert.equal(chain.journal.created.length, 1, 'shutdown allowed a replacement verifier');
  assert.equal(chain.net.counts.A.get_block_template, 1, 'shutdown fetched a replacement template');
  assert.equal(closed.physicalReleaseConfirmed, true);
  assert.equal(closed.gracefulProtocolShutdown, false);
  assert.equal(closed.protocolAnomalies.length, 1);
  assert.match(closed.protocolAnomalies[0].reason, new RegExp(reason));
  assert.doesNotMatch(closed.protocolAnomalies[0].reason,
    /graceful rotation close did not settle before shutdown escalation/);
  assert.equal(pool.simulation.verifierHistory[0].gracefulCloseAbandoned, undefined);
  assert.equal(pool.ownedResourceCount, 0);
});

test('POOL ROTATION: retry releases a verifier even when its final shutdownOutcome getter throws', async (t) => {
  let firstVerifier = null;
  let releaseEntered;
  const atRelease = new Promise((resolve) => { releaseEntered = resolve; });
  const { pool, chain } = await startedPool(t, {
    verifierOptions: (index) => (index === 1 ? {
      closeGate: async () => {
        releaseEntered();
        while (firstVerifier?.closed !== true) await new Promise((resolve) => setImmediate(resolve));
      },
      forceCloseConfirms: [false, false, true],
      forceCloseError: ['scripted force 1 failed', 'scripted force 2 failed', null],
      // Read 1 is the rotation's captured evidence. The server callback consumes that snapshot;
      // read 2 is after retry has positively closed the resource in the ownership sweep.
      shutdownOutcomeErrorAt: [2],
    } : {}),
  });
  firstVerifier = chain.journal.created[0];

  const foreign = addForeignTip(chain, 1, '5'.repeat(64));
  const moving = pool.notifyCanonicalTip({ height: '1', blockId: foreign.hash });
  await atRelease;
  await assert.rejects(pool.close(), /pool shutdown could not be confirmed/);
  const moved = await moving;
  assert.equal(moved.ok, false, JSON.stringify(moved));
  assert.equal(moved.reason, 'verifier_release_unconfirmed');
  assert.equal(firstVerifier.closed, false);
  assert.equal(firstVerifier.shutdownOutcomeReads, 1);
  assert.equal(pool.ownedResourceCount, 1);

  const retried = await pool.retryClose();
  assert.equal(retried.physicalReleaseConfirmed, true);
  assert.equal(retried.gracefulProtocolShutdown, false);
  assert.equal(firstVerifier.closed, true);
  assert.equal(firstVerifier.shutdownOutcomeReads, 2);
  assert.equal(pool.ownedResourceCount, 0,
    'a throwing diagnostic getter kept a positively released resource owned');
  assert.equal(retried.protocolAnomalies.length, 1,
    'the getter failure split one resource into multiple anomaly rows');
  assert.match(retried.protocolAnomalies[0].reason,
    /shutdownOutcome read threw: scripted shutdownOutcome read failure 2/);
});

test('POOL ROTATION: the trusted tip seam refuses the default synthetic pool without work', async (t) => {
  const pool = await startDevPool({ host: '127.0.0.1', port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close().catch(() => {}));
  assert.deepEqual(await pool.notifyCanonicalTip({ height: '1', blockId: 'e'.repeat(64) }),
    { ok: false, reason: 'not_a_sequence' });
  assert.equal(pool.pendingOperationCount, 0);
  assert.equal(pool.ownedResourceCount, 0);
});

test('POOL ROTATION: more than 32 distinct released-resource anomalies remain visible', async (t) => {
  const anomalyCount = 40;
  let chain = null;
  const pool = await startDevPool({
    host: '127.0.0.1',
    port: 0,
    mode: REAL_DAEMON_MODE,
    realDaemon: { daemon: CHAIN_A, sequenceBlocks: 3 },
    realDaemonFactory: async ({ ownResource }) => {
      for (let i = 0; i < anomalyCount; i += 1) {
        const reason = `scripted anomaly ${i}`;
        const resource = {
          closed: false,
          beginClose() {},
          async close() { this.closed = true; },
          async forceClose() { this.closed = true; },
          get shutdownOutcome() {
            return {
              physicalReleaseConfirmed: this.closed,
              gracefulProtocolShutdown: false,
              reason,
            };
          },
        };
        ownResource(`scripted resource ${i}`, resource);
      }
      chain = await buildScriptedChain({}, {
        sequenceBlocks: 3,
        ownLog: { push: ({ label, r }) => ownResource(label, r) },
      });
      return chain.built;
    },
  });
  t.after(() => pool.close().catch(() => {}));
  assert.equal(pool.ownedResourceCount, anomalyCount + 3, 'the test did not enter every resource in the graph');

  const closed = await pool.close();
  assert.equal(closed.physicalReleaseConfirmed, true);
  assert.equal(closed.gracefulProtocolShutdown, false);
  assert.equal(closed.protocolAnomalies.length, anomalyCount, 'the old 32-entry cap silently dropped facts');
  assert.deepEqual(closed.protocolAnomalies.map((entry) => entry.reason),
    Array.from({ length: anomalyCount }, (_, i) => `scripted anomaly ${i}`));
  assert.equal(pool.ownedResourceCount, 0);
});

// ================================================================== the automatic tip observation
//
// Everything below used to require an operator or a test to call pool.notifyCanonicalTip() by hand:
// the sustained sequence could rotate on a competing tip, but nothing ever noticed one. These tests
// exercise the observer the pool now owns, through its injected clock and the in-memory daemon A.

test('TIP OBSERVATION: a real sequence without its trusted daemon-A tip source is refused before listen', async () => {
  let chain = null;
  const owned = [];
  await assert.rejects(
    startDevPool({
      host: '127.0.0.1', port: 0, mode: REAL_DAEMON_MODE,
      realDaemon: { daemon: CHAIN_A, sequenceBlocks: 3 },
      realDaemonFactory: async ({ ownResource }) => {
        chain = await buildScriptedChain({}, {
          sequenceBlocks: 3,
          ownLog: { push: ({ label, r }) => { owned.push(r); ownResource(label, r); } },
        });
        return { ...chain.built, tipSource: null };
      },
    }),
    /requires its trusted daemon-A tip source/,
  );
  assert.ok(owned.length >= 2 && owned.every((r) => r.closed === true),
    'startup refusal left an injected daemon/verifier resource open');
});

test('TIP OBSERVATION: a competing block on daemon A rotates the session with no operator call', async (t) => {
  const { pool, chain, d, armed, timers } = await startedPool(t);
  assert.equal(timers.length, 1, 'Start did not arm exactly one observation cycle');
  assert.equal(pool.simulation.stateFacts.tipObserverRunning, 1);

  // First cycle: A's tip is still the PARENT of the job being searched. Nothing happens.
  const mainBefore = { ...pool.simulation.rpcAudit.counts };
  assert.equal(await armed(), true);
  assert.equal(d.last('sequence_next'), undefined, 'the parent tip caused a rotation');
  assert.equal(chain.net.counts.A.get_block_template, 1);
  assert.deepEqual(pool.simulation.rpcAudit.counts, mainBefore,
    'observer traffic contaminated the application/evidence RPC channel');
  assert.equal(pool.simulation.tipObservationRpcCounts.get_last_block_header, 1,
    'the separate read-only observer RPC was omitted');

  // Another miner takes this height.
  const foreign = addForeignTip(chain, 1, '9'.repeat(64));
  assert.equal(await armed(), true);

  const next = d.last('sequence_next');
  assert.ok(next, JSON.stringify(d.sent.map((m) => [m.type, m.reason])));
  assert.equal(next.cause, 'external_tip');
  assert.equal(next.sequenceIndex, 2);
  assert.equal(chain.journal.created[0].closed, true, 'the superseded verifier was not released');
  assert.equal(chain.net.counts.A.get_block_template, 2, 'exactly one replacement template');
  assert.equal(d.last('mining_ready').sequenceIndex, 2);
  assert.equal(chain.net.blocksA.at(-1).hash, foreign.hash);

  // Seeing the same tip again is inert: no second rotation, no extra template.
  assert.equal(await armed(), true);
  assert.equal(await armed(), true);
  assert.equal(chain.net.counts.A.get_block_template, 2, 'a repeated observation fetched another template');
  assert.equal(d.sent.filter((m) => m.type === 'sequence_next').length, 1);
  assert.deepEqual(pool.simulation.blockRecords[0].externalTip,
    { height: '1', blockId: foreign.hash, atMs: chain.clock.ms });
});

test('TIP OBSERVATION: a replaced parent or rollback ends stale work fail-closed', async (t) => {
  for (const mode of ['replaced_parent', 'rollback']) {
    const { pool, chain, d, armed } = await startedPool(t);
    if (mode === 'replaced_parent') {
      chain.net.blocksA[0] = { ...chain.net.blocksA[0], hash: '8'.repeat(64) };
    } else {
      // A height-2 job is needed to represent a rollback below its expected height-1 parent.
      const ready = d.last('mining_ready');
      await d.say({
        type: 'submit_real_candidate', clientStartId: START_ID, jobId: ready.jobId,
        issuanceId: ready.issuanceId, workerId: ready.workerId, runGeneration: ready.runGeneration,
        nonce: '0000000b',
      });
      assert.equal(d.last('sequence_next').sequenceIndex, 2);
      chain.net.blocksA.splice(0, chain.net.blocksA.length,
        { ...chain.net.blocksA[0], hash: '7'.repeat(64), height: 0 });
    }

    assert.equal(await armed(), true);
    const failed = d.last('block_rejected') ?? d.last('simulation_failed');
    assert.equal(failed?.reason, 'canonical_parent_changed', `${mode}: ${JSON.stringify(d.sent)}`);
    assert.equal(pool.simulation.attemptState, 'terminal_failed');
    assert.match(pool.simulation.blockRecords.at(-1).tipObservationFailure.detail,
      /no longer matches the issued template parent/);
    assert.equal(pool.simulation.stateFacts.tipObserverRunning, 0);
  }
});

test('TIP OBSERVATION: rolling back to this session\'s older block still ends stale work', async (t) => {
  const { pool, chain, d, armed } = await startedPool(t, { sequenceBlocks: 3 });
  const submitCurrent = async () => {
    const ready = d.last('mining_ready');
    await d.say({
      type: 'submit_real_candidate', clientStartId: START_ID, jobId: ready.jobId,
      issuanceId: ready.issuanceId, workerId: ready.workerId, runGeneration: ready.runGeneration,
      nonce: '0000000b',
    });
  };

  await submitCurrent();
  assert.equal(d.last('sequence_next').sequenceIndex, 2);
  const olderOwnBlock = { ...chain.net.blocksA[1] };
  await submitCurrent();
  assert.equal(d.last('sequence_next').sequenceIndex, 3);
  assert.equal(chain.net.blocksA.at(-1).height, 2);

  // Daemon A reorganizes back to our own height-1 block while the browser holds a height-3 job.
  // `isOwnBlock` is true for this hash, but it is not the issued height-2 parent.
  chain.net.blocksA.splice(0, chain.net.blocksA.length, chain.net.blocksA[0], olderOwnBlock);
  assert.equal(await armed(), true);

  const failed = d.last('block_rejected') ?? d.last('simulation_failed');
  assert.equal(failed?.reason, 'canonical_parent_changed');
  assert.equal(pool.simulation.attemptState, 'terminal_failed');
  assert.equal(pool.simulation.stateFacts.tipObserverRunning, 0);
  assert.match(pool.simulation.blockRecords.at(-1).tipObservationFailure.detail,
    /no longer matches the issued template parent/);
});

test('TIP OBSERVATION: an automatically observed tip ahead stops instead of guessing catch-up', async (t) => {
  const { pool, chain, d, armed } = await startedPool(t);
  addForeignTip(chain, 1, '6'.repeat(64));
  const ahead = addForeignTip(chain, 2, '5'.repeat(64));
  const templates = chain.net.counts.A.get_block_template;
  assert.equal(await armed(), true);

  const failed = d.last('block_rejected') ?? d.last('simulation_failed');
  assert.equal(failed?.reason, 'external_tip_superseded');
  assert.equal(pool.simulation.attemptState, 'terminal_cancelled');
  assert.equal(chain.net.counts.A.get_block_template, templates, 'an ahead tip fetched a catch-up template');
  assert.deepEqual(pool.simulation.blockRecords[0].externalTip,
    { height: '2', blockId: ahead.hash, atMs: chain.clock.ms, ahead: true });
});

test('TIP OBSERVATION: this session own accepted block never becomes an external-tip event', async (t) => {
  const { pool, chain, d, armed } = await startedPool(t);
  const ready = d.last('mining_ready');

  await d.say({
    type: 'submit_real_candidate', clientStartId: START_ID, jobId: ready.jobId,
    issuanceId: ready.issuanceId, workerId: ready.workerId, runGeneration: ready.runGeneration,
    nonce: '0000000b',
  });
  const accepted = d.sent.find((m) => m.type === 'sequence_block_accepted');
  assert.ok(accepted, 'the in-memory chain did not accept this browser session block');
  assert.equal(d.last('sequence_next').cause, 'accepted', 'the own-block rotation was mislabelled');
  const templates = chain.net.counts.A.get_block_template;

  // A's tip is now this session's own block, at the height of the job it just finished.
  assert.equal(chain.net.blocksA.at(-1).hash, accepted.blockId);
  assert.equal(await armed(), true);
  assert.equal(await armed(), true);

  assert.equal(chain.net.counts.A.get_block_template, templates,
    'the observer manufactured an external tip for a block this session mined');
  assert.equal(d.sent.filter((m) => m.type === 'sequence_next').length, 1);
  assert.equal(pool.simulation.stateFacts.tipObserverRunning, 1);
});

test('TIP OBSERVATION: a daemon read that fails ends the attempt closed and stops polling', async (t) => {
  const { pool, chain, d, armed, timers } = await startedPool(t, {
    tipSource: { readTip: async () => { throw Object.assign(new Error('gone'), { code: 'rpc_unavailable' }); } },
  });
  assert.equal(await armed(), true);

  const failed = d.last('block_rejected') ?? d.last('simulation_failed');
  assert.equal(failed?.reason, 'tip_observation_failed', JSON.stringify(d.sent.map((m) => [m.type, m.reason])));
  assert.equal(failed.terminal, true);
  assert.equal(pool.simulation.attemptState, 'terminal_failed');
  assert.equal(pool.simulation.stateFacts.tipObserverRunning, 0, 'the observer kept polling after failing');
  assert.equal(timers.length, 0, 'a failed observer left a cycle armed');
  assert.equal(chain.net.counts.A.get_block_template, 1, 'a failed observation fetched a template');
});

test('TIP OBSERVATION: a scheduler failure at Start terminalizes instead of silently disabling observation', async (t) => {
  const { pool, d } = await startedPool(t, {
    start: false,
    observerOptions: { setTimer: () => { throw new Error('timer unavailable'); } },
  });
  const result = await d.say({ type: 'start_request', clientStartId: START_ID });
  assert.deepEqual(result, { ok: false, terminal: true, reason: 'tip_observation_failed' });
  const failed = d.last('block_rejected') ?? d.last('simulation_failed');
  assert.equal(failed?.reason, 'tip_observation_failed');
  assert.equal(pool.simulation.attemptState, 'terminal_failed');
  assert.equal(pool.simulation.stateFacts.tipObserverRunning, 0);
  assert.match(pool.simulation.blockRecords[0].tipObservationFailure.detail, /timer unavailable/);
});

test('TIP OBSERVATION: nothing is armed before Start, and shutdown releases the observer', async (t) => {
  const { pool, d, armed, timers } = await startedPool(t, { start: false });
  assert.equal(timers.length, 0, 'the observer was armed before an explicit Start');
  assert.equal(pool.simulation.stateFacts.tipObservers, 1);
  assert.equal(pool.simulation.stateFacts.tipObserverRunning, 0);

  await d.say({ type: 'start_request', clientStartId: START_ID });
  assert.equal(timers.length, 1);
  assert.equal(pool.simulation.stateFacts.tipObserverRunning, 1);

  d.session.dispose();
  const closed = await pool.close();
  assert.equal(closed.physicalReleaseConfirmed, true);
  assert.equal(pool.ownedResourceCount, 0, 'the observer was left in the ownership graph');
  assert.equal(pool.simulation.stateFacts.tipObserverRunning, 0);
  assert.equal(await armed(), false, 'a cycle was still armed after shutdown');
  assert.deepEqual(await pool.notifyCanonicalTip({ height: '1', blockId: 'c'.repeat(64) }),
    { ok: false, reason: 'pool_closing' });
});

test('TIP OBSERVATION: pool shutdown joins an in-flight observer read', async (t) => {
  const entered = deferred();
  const release = deferred();
  const { pool, chain, armed } = await startedPool(t, {
    tipSource: {
      counts: {},
      async readTip() {
        entered.resolve();
        await release.promise;
        return { height: '0', blockId: chain.net.blocksA[0].hash };
      },
    },
  });
  const cycle = armed();
  await entered.promise;
  const closing = pool.close();
  let settled = false;
  closing.finally(() => { settled = true; });
  await Promise.resolve();
  assert.equal(settled, false, 'pool.close returned while observer RPC was still in flight');
  assert.equal(pool.simulation.tipObserverFacts.closed, false);
  assert.equal(pool.simulation.tipObserverFacts.activeCycles, 1);

  release.resolve();
  await cycle;
  const result = await closing;
  assert.equal(result.physicalReleaseConfirmed, true);
  assert.equal(pool.simulation.tipObserverFacts.closed, true);
  assert.equal(pool.simulation.tipObserverFacts.activeCycles, 0);
});

test('TIP OBSERVATION: no client message can reach the trusted seam', async (t) => {
  const { chain, d, armed } = await startedPool(t);
  const templates = chain.net.counts.A.get_block_template;
  for (const forged of [
    { type: 'canonical_tip', height: '1', blockId: 'a'.repeat(64) },
    { type: 'notify_canonical_tip', height: '1', blockId: 'a'.repeat(64) },
    { type: 'external_tip', clientStartId: START_ID, height: '1', blockId: 'a'.repeat(64) },
    { type: 'sequence_next', clientStartId: START_ID, sequenceIndex: 2 },
  ]) {
    const r = await d.say(forged);
    assert.equal(r.ok, false, JSON.stringify(forged));
  }
  assert.equal(chain.net.counts.A.get_block_template, templates, 'a client message moved the sequence');
  assert.equal(d.sent.filter((m) => m.type === 'sequence_next').length, 0);
  // And the only thing that can: the observer's own cycle, which is server-side.
  addForeignTip(chain, 1, '4'.repeat(64));
  assert.equal(await armed(), true);
  assert.equal(await armed(), true);
  assert.equal(d.sent.filter((m) => m.type === 'sequence_next').length, 1);
});
