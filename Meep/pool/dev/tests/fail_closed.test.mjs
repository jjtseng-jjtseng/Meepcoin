// The health latch as an ACCEPTANCE FENCE, and faults that arrive when nobody is looking.
//
// Regression testing reproduced a share being accepted AFTER the pool had already latched unhealthy. The shape
// is simple and the consequence is not: two verifications are in flight, both pass the check on
// the way in, the first exposes a build disagreement and latches, and the second -- already past
// its only gate -- comes back agreeing and is accepted. `mining_unavailable` and `share_accepted`
// in the same transcript.
//
// A gate at the door is not a fence. These tests hold the stronger contract: once the latch has
// flipped, NOTHING that has not already synchronously committed may commit. That is enforced in
// three independent places, and a test here fails if any of them is removed --
//
//   * the dual verifier rechecks after every await and immediately before returning success;
//   * a latch synchronously settles the sibling's outstanding native request, so it cannot even
//     finish computing;
//   * the session rechecks health immediately before consumeIfActive(), with no await in between.
//
// Everything here runs through the real startDevPool, real WebSocket sessions and the real
// createDualVerifier comparison. The native side is a fake ONLY where a real one cannot be made to
// disagree or die on cue; the client, server, session, queue and comparison code are production.

import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { startDevPool } from '../server.mjs';
import { EXIT_PROTOCOL_ANOMALY, createShutdownController } from '../cli_shutdown.mjs';
import { HELPER_PROTOCOL_VERSION } from '../native_helper.mjs';
import { SYNTHETIC_CONTEXT, loadSyntheticFixture } from '../identity.mjs';
import { computeSourceId } from '../source_identity.mjs';
import { nonceToHex } from '../../../web-miner/lib/shared/target.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const { sourceId: SOURCE_ID } = computeSourceId();
let scratch;
let fixture;

before(() => {
  scratch = mkdtempSync(join(tmpdir(), 'meep-fence-'));
  fixture = loadSyntheticFixture();
});
after(async () => {
  if (!scratch) return;
  for (let i = 0; i < 10 && existsSync(scratch); i++) {
    try { rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* retry */ }
    await sleep(200);
  }
  if (existsSync(scratch)) console.error(`# LEFTOVER TEMP DIRECTORY NOT REMOVED: ${scratch}`);
});

async function waitUntil(fn, { timeoutMs = 30_000, everyMs = 25, label = 'condition' } = {}) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    if (await fn()) return true;
    if (Date.now() > end) return false;
    await sleep(everyMs);
  }
}

/** Write a fake native helper and return the launch options a real pool will use for it. */
function fakeHelperOptions(body, name) {
  const file = join(scratch, `${name}-${Math.random().toString(36).slice(2)}.mjs`);
  writeFileSync(file,
    `const token = process.argv[2];\n`
    + `process.stdout.write(\`HELLO ${HELPER_PROTOCOL_VERSION} \${process.pid} \${token} 2 60 - - ${SOURCE_ID}\\n\`);\n`
    + body, 'utf8');
  return {
    helperPath: process.execPath,
    helperOptions: {
      useWsl: false,
      spawnFn: (cmd) => spawn(process.execPath, [file, cmd.args.at(-1)], {
        stdio: ['pipe', 'pipe', 'pipe'], shell: false,
      }),
    },
  };
}

/**
 * A field-level witness of the pool's CURRENT unconsumed job.
 *
 * Object identity, not a jobId string: the pipeline commits against the exact object it validated,
 * so a resurrected id could never match and neither may this.
 */
function captureJob(pool) {
  const job = pool.jobs.active();
  assert.ok(job, 'there must be an active job to witness');
  assert.equal(job.consumed, false, 'and it must start unconsumed');
  return { job, generation: pool.jobs.generation, lastConsumed: pool.jobs.lastConsumedJob() };
}

/** Every way a consumption would show, checked against the captured witness. */
function assertJobUnconsumed(pool, before, why) {
  assert.equal(pool.jobs.active(), before.job, `${why}: it is still the SAME active job object`);
  assert.equal(before.job.consumed, false, `${why}: the job object was never marked consumed`);
  assert.equal(pool.jobs.generation, before.generation, `${why}: the generation never advanced`);
  assert.equal(pool.jobs.lastConsumedJob(), before.lastConsumed,
    `${why}: nothing was recorded as the last completed job`);
}

/** A greeted client on a real pool. */
async function connect(pool) {
  const got = [];
  const ws = new WebSocket(pool.wsUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('open failed')); });
  ws.onmessage = (e) => got.push(JSON.parse(e.data));
  ws.send(JSON.stringify({ type: 'client_hello', protocolVersion: 1 }));
  await waitUntil(() => got.some((m) => m.type === 'job'), { label: 'a job' });
  return {
    ws,
    got,
    hello: got.find((m) => m.type === 'server_hello'),
    job: got.find((m) => m.type === 'job'),
    send: (o) => ws.send(JSON.stringify(o)),
    close: () => { try { ws.close(); } catch { /* gone */ } },
  };
}

// ---------------------------------------------------------------- P0: the concurrent acceptance

test('a share whose sibling latched the pool mid-flight is NEVER accepted',
  { timeout: 90_000 }, async (t) => {
    // Two submissions, both admitted, both past the entry check. Reply A disagrees with the Wasm
    // build and latches. Reply B -- the QUALIFYING nonce, which would otherwise be accepted -- is
    // still in flight and must not be allowed to commit.
    const options = fakeHelperOptions(`
const vectors = ${JSON.stringify(Object.fromEntries(
      [...Array(16).keys()].map((n) => [n, SYNTHETIC_CONTEXT.vectorFor(n)]),
    ))};
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') {
      const id = t[1], n = Number(t[2]);
      if (n === ${fixture.nonQualifyingNonce}) {
        // A: a well-formed hash that is simply NOT what the Wasm build computes.
        setTimeout(() => process.stdout.write(\`RESULT \${id} \${'c'.repeat(64)}\\n\`), 120);
      } else {
        // B: perfectly correct, and deliberately later, so it is still in flight when A latches.
        setTimeout(() => process.stdout.write(\`RESULT \${id} \${vectors[n]}\\n\`), 900);
      }
    } else if (t[0] === 'QUIT') { process.stdout.write('BYE\\n'); process.exit(0); }
  }
});
`, 'racing-helper');

    const pool = await startDevPool({
      port: 0,
      limits: { maxVerificationQueue: 4, maxGlobalVerificationQueue: 4, rateCapacity: 64 },
      ...options,
    });
    t.after(() => pool.close().catch(() => {}));

    const c = await connect(pool);
    t.after(() => c.close());
    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));

    const jobId = c.job.jobId;
    c.got.length = 0;

    // Both in one turn, so both are admitted before either answer arrives.
    // The exact job object and generation the pool is holding RIGHT NOW: the witness the
    // assertion below compares against, captured before anything could consume it.
    const jobBefore = captureJob(pool);

    c.send({ type: 'submit_share', jobId, workerId: c.hello.workerId, nonce: nonceToHex(fixture.nonQualifyingNonce) });
    c.send({ type: 'submit_share', jobId, workerId: c.hello.workerId, nonce: nonceToHex(fixture.qualifyingNonce) });

    assert.ok(await waitUntil(() => pool.verifierHealth.healthy === false, { label: 'the latch' }),
      'the disagreement must latch the pool');
    assert.equal(pool.verifierHealth.reason, 'verifier_build_disagreement');

    // Give the SECOND, agreeing reply every chance to land and be accepted.
    await sleep(2500);

    const accepted = c.got.filter((m) => m.type === 'share_accepted');
    assert.deepEqual(accepted, [], `nothing may be accepted after the latch; saw ${JSON.stringify(accepted)}`);
    assert.equal(pool.stats.accepted, 0, 'and the pool counted no acceptance');
    assert.equal(c.got.filter((m) => m.type === 'demo_complete').length, 0, 'no run completed');

    const rejected = c.got.filter((m) => m.type === 'share_rejected');
    assert.equal(rejected.length, 2, `both submissions must fail; saw ${JSON.stringify(c.got.map((m) => m.type))}`);
    assert.ok(c.got.some((m) => m.type === 'mining_unavailable'), 'and the miner was halted');

    // The job was never consumed: a latched pool must not quietly retire the work either.
    //
    // This used to read `active() !== null || active() === null`, which is true of every possible
    // program and therefore witnesses nothing. The witness is the job OBJECT captured before the
    // submissions: consumeIfActive() sets `consumed`, bumps the generation, records the job in
    // lastConsumedJob() and makes active() return null, so each of these four assertions fails
    // under a real consumption. `assertJobUnconsumed` is exercised against a deliberate mutation
    // in its own test below, so it cannot silently stop discriminating.
    assertJobUnconsumed(pool, jobBefore, 'a latched pool must not quietly retire the work');
    assert.equal(pool.stats.accepted, 0);

    // Counters stop. Nothing kept hashing after the decision was made.
    const frozen = pool.verifierCounters;
    await sleep(600);
    assert.deepEqual(pool.verifierCounters, frozen, 'no build kept hashing after the latch');

    // And it is over for good.
    c.got.length = 0;
    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_unavailable'), { label: 'the refusal' }));
    assert.equal(c.got.find((m) => m.type === 'mining_unavailable').reason, 'verifier_build_disagreement');
    assert.equal(pool.verifierInitCount, 1, 'and no second verifier was built');
  });

test('a held, otherwise-successful verification cannot accept after the latch flips',
  { timeout: 90_000 }, async (t) => {
    // The narrowest version of the same defect: ONE verification, already past every check, its
    // native reply deliberately held. The pool latches while it waits. Releasing it must not
    // produce an acceptance -- and the injected seam must hit the same fence a real mismatch does.
    let release = null;
    const held = new Promise((r) => { release = r; });
    const options = fakeHelperOptions(`
const vectors = ${JSON.stringify(Object.fromEntries(
      [...Array(16).keys()].map((n) => [n, SYNTHETIC_CONTEXT.vectorFor(n)]),
    ))};
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') {
      const id = t[1], n = Number(t[2]);
      // Long enough that the test can latch the pool while this is outstanding.
      setTimeout(() => process.stdout.write(\`RESULT \${id} \${vectors[n]}\\n\`), 1500);
    } else if (t[0] === 'QUIT') { process.stdout.write('BYE\\n'); process.exit(0); }
  }
});
`, 'slow-correct-helper');

    const pool = await startDevPool({ port: 0, limits: { rateCapacity: 64 }, ...options });
    t.after(() => pool.close().catch(() => {}));
    const c = await connect(pool);
    t.after(() => c.close());
    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));
    c.got.length = 0;

    c.send({
      type: 'submit_share', jobId: c.job.jobId, workerId: c.hello.workerId,
      nonce: nonceToHex(fixture.qualifyingNonce),
    });
    // Wait until the verification is genuinely in flight, then latch underneath it.
    assert.ok(await waitUntil(() => pool.globalVerificationDepth > 0, { label: 'the verification starting' }));
    pool.injectVerifierFault(new Error('latched while a good result was in flight'));
    release();
    await held;

    await sleep(2500);
    assert.equal(pool.stats.accepted, 0, 'a result computed before the latch may not commit after it');
    assert.deepEqual(c.got.filter((m) => m.type === 'share_accepted'), []);
    const rejected = c.got.find((m) => m.type === 'share_rejected');
    assert.ok(rejected, `the submission must be refused; saw ${JSON.stringify(c.got.map((m) => m.type))}`);
    assert.equal(rejected.reason, 'verifier_fault', 'and refused with the latched reason');
  });

// ---------------------------------------------------------------- faults nobody was awaiting

test('a helper that dies while IDLE halts a live miner without waiting for a submission',
  { timeout: 90_000 }, async (t) => {
    const options = fakeHelperOptions(`
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') process.stdout.write(\`RESULT \${t[1]} \${'${SYNTHETIC_CONTEXT.vectorFor(SYNTHETIC_CONTEXT.selfTestNonce)}'}\\n\`);
  }
});
// Die a moment after the pool is ready, with nothing outstanding.
setTimeout(() => process.exit(7), 1200);
`, 'idle-death-helper');

    const pool = await startDevPool({ port: 0, ...options });
    t.after(() => pool.close().catch(() => {}));
    const c = await connect(pool);
    t.after(() => c.close());
    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));
    assert.equal(pool.verifierHealth.healthy, true, 'healthy at the moment mining starts');
    c.got.length = 0;

    // NOTHING is submitted. The halt must arrive anyway.
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_unavailable'),
      { label: 'the halt', timeoutMs: 15_000 }),
    'a browser told nothing keeps a CPU core hashing for a pool that can no longer verify');
    assert.equal(pool.verifierHealth.healthy, false);
    assert.equal(pool.verifierHealth.reason, 'verifier_fault');
    assert.equal(pool.stats.accepted, 0);
  });

test('a correct RESULT followed by a duplicate in the same chunk latches and accepts nothing',
  { timeout: 90_000 }, async (t) => {
    const options = fakeHelperOptions(`
const vectors = ${JSON.stringify(Object.fromEntries(
      [...Array(16).keys()].map((n) => [n, SYNTHETIC_CONTEXT.vectorFor(n)]),
    ))};
let buf = '';
let served = 0;
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') {
      const id = t[1], n = Number(t[2]);
      served++;
      if (served === 1) { process.stdout.write(\`RESULT \${id} \${vectors[n]}\\n\`); return; } // self-test
      // The share: correct, then a duplicate, in ONE write.
      process.stdout.write(\`RESULT \${id} \${vectors[n]}\\n\` + \`RESULT \${id} \${vectors[n]}\\n\`);
    }
  }
});
`, 'trailing-dup-helper');

    const pool = await startDevPool({ port: 0, ...options });
    t.after(() => pool.close().catch(() => {}));
    const c = await connect(pool);
    t.after(() => c.close());
    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));
    c.got.length = 0;

    c.send({
      type: 'submit_share', jobId: c.job.jobId, workerId: c.hello.workerId,
      nonce: nonceToHex(fixture.qualifyingNonce),
    });

    assert.ok(await waitUntil(() => pool.verifierHealth.healthy === false, { label: 'the global latch' }),
      'the protocol violation must reach the POOL, not just the helper');
    await sleep(500);
    assert.equal(pool.stats.accepted, 0, 'the otherwise-correct hash must not be accepted');
    assert.deepEqual(c.got.filter((m) => m.type === 'share_accepted'), []);
  });

test('unsolicited helper output while idle latches globally and halts the session',
  { timeout: 90_000 }, async (t) => {
    const options = fakeHelperOptions(`
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') process.stdout.write(\`RESULT \${t[1]} \${'${SYNTHETIC_CONTEXT.vectorFor(SYNTHETIC_CONTEXT.selfTestNonce)}'}\\n\`);
  }
});
// Chatter with nothing outstanding.
setTimeout(() => process.stdout.write('RESULT 999 ' + 'd'.repeat(64) + '\\n'), 1200);
setTimeout(() => {}, 30000);
`, 'chatty-helper');

    const pool = await startDevPool({ port: 0, ...options });
    t.after(() => pool.close().catch(() => {}));
    const c = await connect(pool);
    t.after(() => c.close());
    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));
    c.got.length = 0;

    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_unavailable'),
      { label: 'the halt', timeoutMs: 15_000 }));
    assert.equal(pool.verifierHealth.healthy, false);
    assert.equal(pool.stats.accepted, 0);
  });

// ---------------------------------------------------------------- startup disagreement

test('a startup self-test disagreement latches ONCE, and a second Start spawns nothing',
  { timeout: 90_000 }, async (t) => {
    let launches = 0;
    const options = fakeHelperOptions(`
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') process.stdout.write(\`RESULT \${t[1]} \${'0'.repeat(64)}\\n\`);
    else if (t[0] === 'QUIT') { process.stdout.write('BYE\\n'); process.exit(0); }
  }
});
`, 'selftest-mismatch-helper');
    const counted = {
      ...options,
      helperOptions: {
        ...options.helperOptions,
        spawnFn: (cmd) => { launches++; return options.helperOptions.spawnFn(cmd); },
      },
    };

    const pool = await startDevPool({ port: 0, ...counted });
    t.after(() => pool.close().catch(() => {}));
    const c = await connect(pool);
    t.after(() => c.close());

    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_unavailable'), { label: 'attempt 1' }));
    const first = c.got.find((m) => m.type === 'mining_unavailable');
    assert.equal(first.reason, 'verifier_build_disagreement',
      'a startup disagreement is not a generic retryable initialization failure');
    assert.equal(pool.verifierHealth.healthy, false, 'and it latches the POOL, not just that attempt');
    const afterFirst = { init: pool.verifierInitCount, launches };
    assert.equal(afterFirst.launches, 1);

    c.got.length = 0;
    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_unavailable'), { label: 'attempt 2' }));
    assert.equal(c.got.find((m) => m.type === 'mining_unavailable').reason, 'verifier_build_disagreement',
      'the same latched reason, not verifier_unavailable');
    assert.equal(pool.verifierInitCount, afterFirst.init, 'no second initialization');
    assert.equal(launches, 1, 'and NO second helper process was spawned');
    assert.equal(pool.verifier, null);
  });

// ---------------------------------------------------------------- cancellation is not a fault

test('an ordinary close cancels in-flight native work without ever reporting a fault',
  { timeout: 90_000 }, async (t) => {
    const faults = [];
    const healthChanges = [];
    const options = fakeHelperOptions(`
let buf = '';
let served = 0;
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') {
      served++;
      if (served === 1) { process.stdout.write(\`RESULT \${t[1]} \${'${SYNTHETIC_CONTEXT.vectorFor(SYNTHETIC_CONTEXT.selfTestNonce)}'}\\n\`); return; }
      // The share request is simply never answered: only cancellation can settle it.
    } else if (t[0] === 'QUIT') { process.stdout.write('BYE\\n'); process.exit(0); }
  }
});
`, 'never-answers-helper');

    const pool = await startDevPool({
      port: 0,
      log: (e) => { if (e.kind === 'verifier_unhealthy') faults.push(e); },
      ...options,
    });
    pool.onVerifierHealthChange((h) => healthChanges.push(h));
    const c = await connect(pool);
    t.after(() => c.close());
    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));
    c.got.length = 0;

    c.send({
      type: 'submit_share', jobId: c.job.jobId, workerId: c.hello.workerId,
      nonce: nonceToHex(fixture.qualifyingNonce),
    });
    assert.ok(await waitUntil(() => pool.globalVerificationDepth > 0, { label: 'the request being in flight' }));

    // A perfectly ordinary shutdown, with real native work outstanding.
    await pool.close();

    assert.equal(pool.verifierState, 'closed', 'the close completed');
    assert.deepEqual(healthChanges, [], 'health was never relabeled by an ordinary shutdown');
    assert.deepEqual(faults, [], 'and no verifier_unhealthy was ever logged');
    assert.equal(pool.verifierHealth.healthy, true, 'a pool that shut down cleanly is not "faulted"');
    await sleep(200);
    assert.deepEqual(c.got.filter((m) => m.type === 'mining_unavailable'), [],
      'and the client was not sent a fault halt for something we asked for');
  });

// ---------------------------------------------------------------- abort through every phase

for (const [phase, body] of [
  ['HELLO', 'setTimeout(() => {}, 60000);'], // never greets
  ['INIT', 'process.stdin.on("data", () => {});'], // greets, never answers INIT
  ['the self-test HASH', `
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    // HASH is never answered.
  }
});
`],
]) {
  test(`shutdown during ${phase} is prompt, and leaves nothing owned`, { timeout: 90_000 }, async (t) => {
    // The default path removed the abort listener right after HELLO, so a close during INIT waited
    // out the full 60 s init timeout with a child the server had no handle to. These use the REAL
    // native-helper path, with a fake child -- not a cooperative whole-verifier mock.
    const greets = phase === 'HELLO' ? '' : null;
    const options = fakeHelperOptions(body, `abort-${phase.replace(/\s+/g, '-')}`);
    if (greets === '') {
      // Suppress the greeting for the HELLO-phase case.
      const file = join(scratch, `no-hello-${Math.random().toString(36).slice(2)}.mjs`);
      writeFileSync(file, 'setTimeout(() => {}, 60000);\n', 'utf8');
      options.helperOptions.spawnFn = (cmd) => spawn(process.execPath, [file, cmd.args.at(-1)], {
        stdio: ['pipe', 'pipe', 'pipe'], shell: false,
      });
    }

    const pool = await startDevPool({
      port: 0,
      ...options,
      helperOptions: {
        ...options.helperOptions,
        // Long enough that waiting one out would be obvious in the elapsed time below.
        limits: { startupTimeoutMs: 30_000, initTimeoutMs: 30_000, requestTimeoutMs: 30_000 },
      },
    });
    const c = await connect(pool);
    t.after(() => c.close());
    c.send({ type: 'start_request' });
    // Let initialization reach the phase under test.
    await waitUntil(() => pool.verifierState === 'initializing', { label: 'initialization starting' });
    await sleep(400);

    const t0 = Date.now();
    await pool.close().catch(() => {});
    const elapsed = Date.now() - t0;

    assert.ok(elapsed < 15_000,
      `shutdown must not wait out the ${phase} timeout; took ${elapsed} ms`);
    assert.deepEqual(pool.retainedResources, [],
      `nothing may still be owned after a shutdown during ${phase}`);
    assert.equal(pool.verifier, null);
  });
}

// ---------------------------------------------------------------- diagnostics never break cleanup

test('a logger that returns a rejected promise cannot defeat cleanup or crash the process',
  { timeout: 60_000 }, async (t) => {
    // safeLog caught a synchronous throw but ignored a returned rejection: `async () => { throw x }`
    // sails past try/catch and becomes an unhandled rejection -- during shutdown, of all times.
    const unhandled = [];
    const onUnhandled = (err) => unhandled.push(err);
    process.on('unhandledRejection', onUnhandled);
    t.after(() => process.off('unhandledRejection', onUnhandled));

    const pool = await startDevPool({
      port: 0,
      verifierMode: 'wasm',
      log: async () => { throw new Error('the logger is having a bad day'); },
    });
    const c = await connect(pool);
    t.after(() => c.close());
    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));
    c.send({
      type: 'submit_share', jobId: c.job.jobId, workerId: c.hello.workerId,
      nonce: nonceToHex(fixture.qualifyingNonce),
    });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'share_accepted'), { label: 'the acceptance' }),
      'a broken logger must not stop the pool working');

    await pool.close();
    assert.equal(pool.verifierState, 'closed', 'and must not stop it shutting down');
    await sleep(200);
    assert.deepEqual(unhandled, [], 'and must not produce an unhandled rejection');
  });

// ---------------------------------------------------------------- the witness discriminates
//
// An assertion that cannot fail is not evidence. This drives a REAL consumption through the real
// job store and requires assertJobUnconsumed() to reject it -- on every one of its four fields.

test('assertJobUnconsumed fails under a controlled consumption', { timeout: 30_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close().catch(() => {}));

  const before = captureJob(pool);
  assertJobUnconsumed(pool, before, 'nothing has happened yet'); // holds, as it must

  // The mutation: exactly what an accepted share does, through the production primitive.
  assert.equal(pool.jobs.consumeIfActive(before.job), true, 'the job was consumable');

  assert.throws(() => assertJobUnconsumed(pool, before, 'after a consumption'),
    (err) => err instanceof assert.AssertionError,
    'the assertion must FAIL once the job is consumed, or it witnesses nothing');

  // And every individual field moved, so no single one is carrying the whole assertion.
  assert.equal(before.job.consumed, true);
  assert.equal(pool.jobs.active(), null);
  assert.notEqual(pool.jobs.generation, before.generation);
  assert.equal(pool.jobs.lastConsumedJob(), before.job);
});

// ---------------------------------------------------------------- the helper option contract
//
// THE DEFECT. createDualVerifier called
//
//   startNativeHelper({ helperPath, signal, onFault: onHelperFault, ...helperOptions })
//
// with the caller's nested options spread LAST, so a caller could replace onFault, signal and
// helperPath. Regression testing reproduced it end to end: with `helperOptions.onFault = () => {}` the helper
// died after mining_ready, pool.verifierHealth stayed { healthy: true }, verifier.healthy went
// false, and the active client was never sent mining_unavailable. The pool went quietly deaf.
//
// These run through the PUBLIC startDevPool -> session -> dual verifier path, with a real native
// helper client and a controlled child.

/** A fake that answers the self-test correctly and then dies while IDLE, with nobody waiting. */
function idleCrashHelperOptions() {
  const vectors = Object.fromEntries(
    [...Array(16).keys()].map((n) => [n, SYNTHETIC_CONTEXT.vectorFor(n)]),
  );
  return fakeHelperOptions(`
const V = ${JSON.stringify(vectors)};
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') {
      process.stdout.write(\`RESULT \${t[1]} \${V[t[2]]}\\n\`);
      // The startup self-test is answered. Now crash while idle, exactly like a real helper would.
      setTimeout(() => process.exit(9), 400);
    } else if (t[0] === 'QUIT') { process.stdout.write('BYE\\n'); process.exit(0); }
  }
});
`, 'idle-crash-helper');
}

test('a nested onFault cannot suppress an idle helper crash: it is REFUSED',
  { timeout: 90_000 }, async (t) => {
    const options = idleCrashHelperOptions();
    const pool = await startDevPool({
      port: 0,
      ...options,
      helperOptions: { ...options.helperOptions, onFault: () => {} },
    });
    t.after(() => pool.close().catch(() => {}));
    const c = await connect(pool);
    t.after(() => c.close());

    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_unavailable'),
      { label: 'the refusal' }), 'a reserved nested option must fail the start, not be honoured');

    // It never became ready, so the deaf-pool state the override produced is unreachable.
    assert.deepEqual(c.got.filter((m) => m.type === 'mining_ready'), [],
      'mining must never have started with the safety wiring replaced');
    assert.equal(pool.verifier, null, 'and no verifier was left behind');
    assert.deepEqual(pool.retainedResources, [], 'nothing was spawned to leak');
  });

test('the SAME fake, with the safety wiring intact, DOES halt the pool when it crashes idle',
  { timeout: 90_000 }, async (t) => {
    // The control for the test above: proves the fake really does produce the idle crash, so the
    // refusal is what prevented the deafness rather than the fake being harmless.
    const options = idleCrashHelperOptions();
    const pool = await startDevPool({ port: 0, ...options });
    t.after(() => pool.close().catch(() => {}));
    const c = await connect(pool);
    t.after(() => c.close());

    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));

    assert.ok(await waitUntil(() => pool.verifierHealth.healthy === false, { label: 'the idle-crash latch' }),
      'a helper that dies while idle must stop the pool now, not at the next submission');
    assert.equal(pool.verifierHealth.reason, 'verifier_fault');
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_unavailable'),
      { label: 'the halt reaching the client' }), 'and the active miner is told');
  });

for (const key of ['onFault', 'signal', 'helperPath']) {
  test(`a nested ${key} is refused by name, before anything is spawned`, { timeout: 60_000 }, async (t) => {
    let spawned = 0;
    const options = fakeHelperOptions('setTimeout(() => {}, 60000);', `reserved-${key}`);
    const inner = options.helperOptions.spawnFn;
    const pool = await startDevPool({
      port: 0,
      ...options,
      helperOptions: {
        ...options.helperOptions,
        spawnFn: (cmd) => { spawned++; return inner(cmd); },
        // A plausible-looking value for each reserved key. None may take effect.
        [key]: key === 'helperPath' ? 'C:/nowhere/other-helper' : (key === 'signal' ? new AbortController().signal : () => {}),
      },
    });
    t.after(() => pool.close().catch(() => {}));
    const c = await connect(pool);
    t.after(() => c.close());

    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_unavailable'), { label: 'the refusal' }));
    assert.equal(spawned, 0, 'the refusal happens before any child exists');
    assert.deepEqual(pool.retainedResources, [], 'so there is nothing to retain');
  });
}

test('an unknown nested option is refused rather than silently ignored', { timeout: 60_000 }, async (t) => {
  const options = fakeHelperOptions('setTimeout(() => {}, 60000);', 'unknown-opt');
  const pool = await startDevPool({
    port: 0,
    ...options,
    helperOptions: { ...options.helperOptions, spwanFn: () => { throw new Error('typo'); } },
  });
  t.after(() => pool.close().catch(() => {}));
  const c = await connect(pool);
  t.after(() => c.close());
  c.send({ type: 'start_request' });
  assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_unavailable'), { label: 'the refusal' }),
    'a misspelled option that silently does nothing is how a test believes it configured something');
});

test('the legitimate nested seams still work', { timeout: 90_000 }, async (t) => {
  // The contract must not be a blanket ban: the deterministic-launch seams the lifecycle tests
  // depend on are exactly what makes these regressions possible in the first place.
  let spawned = 0;
  const vectors = Object.fromEntries([...Array(16).keys()].map((n) => [n, SYNTHETIC_CONTEXT.vectorFor(n)]));
  const options = fakeHelperOptions(`
const V = ${JSON.stringify(vectors)};
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') process.stdout.write(\`RESULT \${t[1]} \${V[t[2]]}\\n\`);
    else if (t[0] === 'QUIT') { process.stdout.write('BYE\\n'); process.exit(0); }
  }
});
`, 'allowed-seams');
  const inner = options.helperOptions.spawnFn;
  const pool = await startDevPool({
    port: 0,
    ...options,
    helperOptions: {
      useWsl: false,                                   // allowed
      spawnFn: (cmd) => { spawned++; return inner(cmd); }, // allowed
      limits: { startupTimeoutMs: 20_000 },            // allowed
    },
  });
  t.after(() => pool.close().catch(() => {}));
  const c = await connect(pool);
  t.after(() => c.close());
  c.send({ type: 'start_request' });
  assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));
  assert.equal(spawned, 1, 'the injected spawn seam was used');
  assert.equal(pool.verifierHealth.healthy, true);
});

// ---------------------------------------------------------------- a nested signal, per phase
//
// The startup AbortSignal is how shutdown reaches a verifier that is still in HELLO, INIT or the
// self-test. A caller who replaced it with a controller it never aborts would have left the pool
// with no way to reach that child: close() would wait out the full startup/init timeout with a
// live process the server had no handle to. The contract refuses the substitution, so for each
// phase this proves BOTH that the start is refused and that shutdown stays prompt and empty.

for (const [phase, body, suppressHello] of [
  ['HELLO', 'setTimeout(() => {}, 60000);', true],
  ['INIT', 'process.stdin.on("data", () => {});', false],
  ['the self-test HASH', `
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\n\`);
  }
});
`, false],
]) {
  test(`a nested signal cannot defeat shutdown during ${phase}`, { timeout: 90_000 }, async (t) => {
    const options = fakeHelperOptions(body, `nested-signal-${phase.replace(/\s+/g, '-')}`);
    if (suppressHello) {
      const file = join(scratch, `no-hello-${Math.random().toString(36).slice(2)}.mjs`);
      writeFileSync(file, 'setTimeout(() => {}, 60000);\n', 'utf8');
      options.helperOptions.spawnFn = (cmd) => spawn(process.execPath, [file, cmd.args.at(-1)], {
        stdio: ['pipe', 'pipe', 'pipe'], shell: false,
      });
    }
    // A controller nobody will ever abort: the substitution that used to strand the child.
    const hijack = new AbortController();
    const pool = await startDevPool({
      port: 0,
      ...options,
      helperOptions: {
        ...options.helperOptions,
        signal: hijack.signal,
        limits: { startupTimeoutMs: 30_000, initTimeoutMs: 30_000, requestTimeoutMs: 30_000 },
      },
    });
    const c = await connect(pool);
    t.after(() => c.close());

    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_unavailable'), { label: 'the refusal' }),
      'the substitution must be refused rather than honoured');

    const t0 = Date.now();
    await pool.close().catch(() => {});
    const elapsed = Date.now() - t0;

    assert.equal(hijack.signal.aborted, false, 'the pool never used the caller-supplied controller');
    assert.ok(elapsed < 15_000,
      `shutdown must not wait out the ${phase} timeout; took ${elapsed} ms`);
    assert.deepEqual(pool.retainedResources, [],
      `nothing may still be owned after a shutdown during ${phase}`);
    assert.equal(pool.verifier, null);
  });
}

// ---------------------------------------------------------------- the PUBLIC shutdown boundary
//
// native_helper.close() correctly refuses to call an abnormal goodbye clean, and dual_verifier
// propagated that failure -- but the pool then caught it, escalated, saw the process physically
// released, wrote a `verifier_escalated` event through safeLog(), deleted the resource and
// resolved pool.close(). The default pool logger is a no-op and the CLI supplies no replacement,
// so the whole thing reached the user as exit code 0 with nothing printed.
//
// Two facts now travel all the way out, separately: the process IS gone (so nothing is retained,
// nothing is re-signalled, and the launcher may exit) AND the exchange was abnormal (so it is
// printed, and the exit code is not 0).

/** A fake that answers the self-test correctly and then says goodbye badly, on cue. */
function badGoodbyeOptions(quitBody, name) {
  const vectors = Object.fromEntries(
    [...Array(16).keys()].map((n) => [n, SYNTHETIC_CONTEXT.vectorFor(n)]),
  );
  return fakeHelperOptions(`
const V = ${JSON.stringify(vectors)};
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') process.stdout.write(\`RESULT \${t[1]} \${V[t[2]]}\\n\`);
    else if (t[0] === 'QUIT') { ${quitBody} }
  }
});
setTimeout(() => {}, 60000);
`, name);
}

async function readyPool(t, options, extra = {}) {
  const pool = await startDevPool({ port: 0, ...options, ...extra });
  const c = await connect(pool);
  t.after(() => c.close());
  c.send({ type: 'start_request' });
  assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));
  return { pool, c };
}

for (const [label, quitBody, expected] of [
  ['exits 0 without ever sending BYE', 'process.exit(0);', /exited without sending BYE/],
  ['sends BYE and then exits nonzero',
    "process.stdout.write('BYE\\n'); setTimeout(() => process.exit(7), 30);",
    /exited 7 after acknowledging QUIT/],
]) {
  test(`a helper that ${label} reaches pool.close() as ABNORMAL, released, not retained`,
    { timeout: 90_000 }, async (t) => {
      const options = badGoodbyeOptions(quitBody, `bad-goodbye-${label.slice(0, 8).replace(/\s+/g, '-')}`);
      const { pool } = await readyPool(t, options);

      const result = await pool.close();

      // THE STRUCTURED RESULT, not a log line a caller had to subscribe to in advance.
      assert.equal(result?.ok, true, 'shutdown succeeded: nothing is owned any more');
      assert.equal(result.physicalReleaseConfirmed, true);
      assert.equal(result.gracefulProtocolShutdown, false, 'but it was NOT a canonical goodbye');
      assert.equal(result.protocolAnomalies.length, 1);
      assert.match(result.protocolAnomalies[0].reason, expected,
        `the specific anomaly must be named; saw ${JSON.stringify(result.protocolAnomalies)}`);
      assert.deepEqual(pool.shutdownOutcome.protocolAnomalies, result.protocolAnomalies);

      // EXACT OWNERSHIP STATE. A released process is not retained and is not re-signalled just to
      // make the anomaly go away.
      assert.deepEqual(pool.retainedResources, [], 'nothing is retained');
      assert.equal(pool.retainedVerifier, null);
      assert.equal(pool.verifierState, 'closed');
      assert.equal(pool.closeFailure, null, 'this is not a failed close');
    });

  test(`the CLI reports that helper (${label}) and exits ${EXIT_PROTOCOL_ANOMALY}`,
    { timeout: 90_000 }, async (t) => {
      const options = badGoodbyeOptions(quitBody, `cli-bad-${label.slice(0, 8).replace(/\s+/g, '-')}`);
      // NO logger, exactly as pool/dev/run.mjs constructs the pool: the anomaly must not depend on
      // anyone having installed a diagnostic sink beforehand.
      const { pool } = await readyPool(t, options);

      const out = []; const errs = []; const exits = [];
      const ctl = createShutdownController({
        pool,
        log: (x) => out.push(String(x)),
        error: (x) => errs.push(String(x)),
        exit: (code) => exits.push(code),
        wait: () => Promise.resolve(),
      });
      await ctl.requestShutdown('SIGINT');

      assert.deepEqual(exits, [EXIT_PROTOCOL_ANOMALY],
        `the launcher must not report success; stderr was ${JSON.stringify(errs)}`);
      assert.ok(errs.some((line) => expected.test(line)),
        `the operator must see the reason; stderr was ${JSON.stringify(errs)}`);
      assert.deepEqual(pool.retainedResources, [], 'and it was safe to exit: nothing is owned');
    });
}

test('a canonical goodbye still resolves clean and exits 0 through the same public path',
  { timeout: 90_000 }, async (t) => {
    const options = badGoodbyeOptions("process.stdout.write('BYE\\n'); process.exit(0);", 'good-goodbye');
    const { pool } = await readyPool(t, options);

    const result = await pool.close();
    assert.equal(result.gracefulProtocolShutdown, true, 'QUIT -> one BYE -> drained stdio -> exit 0');
    assert.deepEqual(result.protocolAnomalies, []);
    assert.deepEqual(pool.retainedResources, []);

    const errs = []; const exits = [];
    const ctl = createShutdownController({
      pool, log: () => {}, error: (x) => errs.push(String(x)), exit: (c) => exits.push(c), wait: () => Promise.resolve(),
    });
    await ctl.requestShutdown('SIGINT');
    assert.deepEqual(exits, [0], 'a clean shutdown is still a clean exit');
    assert.deepEqual(errs, [], 'and says nothing alarming');
  });

// ---------------------------------------------------------------- a crash reaches the operator
//
// `attemptedExchange = !exited && !fault` skipped the whole goodbye verdict for a helper that had
// already died, so an idle crash came back as `gracefulProtocolShutdown: true, reason: null` --
// and therefore reached pool.close() with no anomaly and the CLI with exit 0. The crash is
// reported when it happens AND again at shutdown, because those are two different audiences.

for (const [label, exitCode] of [['crashes with exit 9', 9], ['exits 0 unasked', 0]]) {
  test(`a helper that ${label} while idle reaches pool.close() and the CLI as ABNORMAL`,
    { timeout: 90_000 }, async (t) => {
      const vectors = Object.fromEntries(
        [...Array(16).keys()].map((n) => [n, SYNTHETIC_CONTEXT.vectorFor(n)]),
      );
      const options = fakeHelperOptions(`
const V = ${JSON.stringify(vectors)};
let buf = '';
process.stdin.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    const t = line.split(' ');
    if (t[0] === 'INIT') process.stdout.write(\`READY \${t[1]} 33554432 8388608\\n\`);
    else if (t[0] === 'HASH') {
      process.stdout.write(\`RESULT \${t[1]} \${V[t[2]]}\\n\`);
      setTimeout(() => process.exit(${exitCode}), 300);   // die while IDLE
    }
  }
});
setTimeout(() => {}, 60000);
`, `idle-crash-public-${exitCode}`);

      const pool = await startDevPool({ port: 0, ...options });
      const c = await connect(pool);
      t.after(() => c.close());
      c.send({ type: 'start_request' });
      assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));
      assert.ok(await waitUntil(() => pool.verifierHealth.healthy === false, { label: 'the idle crash' }),
        'the crash must halt the pool the moment it happens');

      const errs = []; const exits = [];
      const ctl = createShutdownController({
        pool,
        log: () => {},
        error: (x) => errs.push(String(x)),
        exit: (code) => exits.push(code),
        wait: () => Promise.resolve(),
      });
      await ctl.requestShutdown('SIGINT');

      const outcome = pool.shutdownOutcome;
      assert.equal(outcome.gracefulProtocolShutdown, false,
        `a helper that ${label} did not say goodbye`);
      assert.equal(outcome.protocolAnomalies.length >= 1, true,
        `the reason must reach the public result; saw ${JSON.stringify(outcome)}`);
      assert.match(outcome.protocolAnomalies[0].reason, /faulted before shutdown|before any QUIT was sent/,
        `the ORIGINAL fault must survive to the public layer; saw ${outcome.protocolAnomalies[0].reason}`);
      assert.match(outcome.protocolAnomalies[0].reason, new RegExp(`code=${exitCode}`),
        'including the exit code it actually died with');

      assert.deepEqual(exits, [EXIT_PROTOCOL_ANOMALY],
        `the launcher must not report success; stderr was ${JSON.stringify(errs)}`);
      assert.ok(errs.some((line) => /GOODBYE WAS ABNORMAL/.test(line)));
      assert.deepEqual(pool.retainedResources, [],
        'and the process really is gone, so nothing is retained to fake ownership');
    });
}
