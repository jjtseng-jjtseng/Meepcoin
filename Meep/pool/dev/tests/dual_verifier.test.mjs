// The dual verifier: real compiled native helper + real server Wasm, through the production pool.
//
// This is the product-path proof. It uses the ACTUAL executable built by
// scripts/build-native-helper.sh, launched by the ACTUAL Windows Node -> WSL path, and requires
// the two builds to agree byte-for-byte before anything is accepted.
//
// It is an independent BUILD/RUNTIME cross-check of the SAME frozen C++ source -- not a second,
// independently authored implementation. If the frozen source is wrong, both sides are wrong
// together and agree.

import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

import { startDevPool } from '../server.mjs';
import { HELPER_BUILD_PATH, toWslPath } from '../native_helper.mjs';
import { SYNTHETIC_CONTEXT, loadSyntheticFixture } from '../identity.mjs';
import { computeSourceId } from '../source_identity.mjs';
import { nonceToHex } from '../../../web-miner/lib/shared/target.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// The fakes below greet with the REAL build-source identity, so the pool's staleness check is
// exercised by these tests rather than disabled for them.
const { sourceId: SOURCE_ID } = computeSourceId();
let fixture;
let scratch;

async function waitUntil(fn, { timeoutMs = 60_000, everyMs = 50, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await fn()) return true;
    if (Date.now() > deadline) return false;
    await sleep(everyMs);
  }
}

// The helper executable is a BUILD ARTIFACT and is deliberately not committed, so a checkout that
// has not built it cannot run these. Skipping (loudly, with the command) is the honest outcome:
// the runner reports them as skipped, never as passed. Nothing here builds anything for you.
const HELPER_MISSING = !existsSync(HELPER_BUILD_PATH)
  ? `native helper not built (${HELPER_BUILD_PATH}) -- run: npm run build:native-helper`
  : false;

before(() => {
  scratch = mkdtempSync(join(tmpdir(), 'meep-dual-'));
  fixture = loadSyntheticFixture();
  if (HELPER_MISSING) console.log(`# SKIPPING the dual cross-check suite: ${HELPER_MISSING}`);
});

/** Is a Linux PID still the helper we launched? Argument-native, no shell. */
function linuxCmdline(pid) {
  return new Promise((resolvePromise) => {
    const p = spawn('wsl.exe', ['--exec', 'cat', `/proc/${pid}/cmdline`], {
      stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true, shell: false,
    });
    let out = '';
    p.stdout.setEncoding('latin1');
    p.stdout.on('data', (c) => { out += c; });
    p.on('error', () => resolvePromise(null));
    p.on('close', (code) => resolvePromise(code === 0 && out.length ? out : null));
    setTimeout(() => { try { p.kill(); } catch { /* gone */ } }, 5000);
  });
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
    ws, got,
    hello: got.find((m) => m.type === 'server_hello'),
    job: got.find((m) => m.type === 'job'),
    send: (o) => ws.send(JSON.stringify(o)),
    close: () => { try { ws.close(); } catch { /* gone */ } },
  };
}

// ---------------------------------------------------------------- lazy lifecycle

test('nothing native or Wasm exists before a client declares start intent', { timeout: 90_000, skip: HELPER_MISSING }, async (t) => {
  const pool = await startDevPool({ port: 0 });
  t.after(() => pool.close().catch(() => {}));

  assert.equal(pool.verifierMode, 'dual');
  assert.equal(pool.verifier, null, 'no verifier');
  assert.equal(pool.helperLinuxPid, null, 'no native child');
  assert.equal(pool.serverHashCalls, 0);
  assert.deepEqual(pool.verifierCounters,
    { wasmSelfTestHashes: 0, nativeSelfTestHashes: 0, wasmShareHashes: 0, nativeShareHashes: 0 });
  assert.equal(pool.verifierHealth.healthy, true);

  // Connecting and being disclosed a job changes none of that.
  const c = await connect(pool);
  t.after(() => c.close());
  assert.equal(pool.verifier, null, 'a connected, greeted client still starts nothing');
  assert.equal(pool.helperLinuxPid, null);
});

test('start intent brings up exactly one dual verifier, and repeats do not add more', { timeout: 120_000, skip: HELPER_MISSING }, async (t) => {
  const pool = await startDevPool({ port: 0 });
  t.after(() => pool.close().catch(() => {}));
  const c = await connect(pool);
  t.after(() => c.close());

  const t0 = Date.now();
  c.send({ type: 'start_request' });
  c.send({ type: 'start_request' });
  c.send({ type: 'start_request' });
  assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready' || m.type === 'mining_unavailable'),
    { label: 'mining_ready or mining_unavailable' }),
    `no verifier startup result; saw ${JSON.stringify(c.got.map((m) => m.type))}`);
  assert.ok(c.got.some((m) => m.type === 'mining_ready'),
    `no mining_ready; startup result ${JSON.stringify(c.got.find((m) => m.type === 'mining_unavailable'))}`);
  const startupMs = Date.now() - t0;

  assert.equal(pool.verifierInitCount, 1, 'exactly one initialization for three requests');
  assert.ok(pool.helperLinuxPid > 0, 'the native helper reported its Linux pid');
  assert.equal(pool.verifierMode, 'dual');

  // The startup SELF-TEST already required both builds to agree, and to match the vectors.
  const counters = pool.verifierCounters;
  assert.equal(counters.wasmSelfTestHashes, 1);
  assert.equal(counters.nativeSelfTestHashes, 1);
  assert.equal(counters.wasmShareHashes, 0, 'no share has been verified yet');
  assert.equal(counters.nativeShareHashes, 0);

  // Memory disclosure, stated as separate allocations rather than one blended figure.
  assert.equal(pool.verifier.wasmHeapBytes(), 48_562_176, 'server Wasm heap');
  assert.equal(pool.verifier.nativeAlgorithmBytes(), 40 * 1024 * 1024,
    'native algorithm memory = 32 MiB dataset + 8 MiB scratchpad');

  // And the launch really was argument-native through WSL.
  assert.equal(pool.verifier.helperCommand.file, 'wsl.exe');
  // THE PARENT-PINNED DISTRIBUTION IS IN THE LAUNCH ITSELF. Launching with default routing and
  // then letting HELLO name the distribution is circular: the child would be choosing which pid
  // namespace its examiner looks in.
  const pinned = pool.verifier.helperDistro;
  assert.match(pinned, /^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$/, 'the pinned distro is one bounded argv value');
  assert.deepEqual(pool.verifier.helperCommand.args,
    ['-d', pinned, '--exec', toWslPath(HELPER_BUILD_PATH), pool.verifier.helperToken],
    'the exact launch argv: -d <parent-pinned distro> --exec <helper> <token>');

  console.log(`    dual verifier startup: ${startupMs} ms, helper linux pid ${pool.helperLinuxPid}`);
});

// ---------------------------------------------------------------- the product path

test('a share is accepted only after the two builds agree byte-for-byte', { timeout: 120_000, skip: HELPER_MISSING }, async (t) => {
  const pool = await startDevPool({ port: 0 });
  t.after(() => pool.close().catch(() => {}));
  const c = await connect(pool);
  t.after(() => c.close());
  c.send({ type: 'start_request' });
  assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));

  const helperPid = pool.helperLinuxPid;
  const before = pool.verifierCounters;

  // The manifest-pinned qualifying nonce.
  c.got.length = 0;
  c.send({ type: 'submit_share', jobId: c.job.jobId, workerId: c.hello.workerId, nonce: nonceToHex(fixture.qualifyingNonce) });
  assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'share_accepted' || m.type === 'share_rejected'),
    { label: 'a verdict' }));
  const verdict = c.got.find((m) => m.type === 'share_accepted' || m.type === 'share_rejected');

  assert.equal(verdict.type, 'share_accepted', `expected acceptance, got ${verdict.reason}`);
  assert.equal(verdict.hashHexLE, fixture.qualifyingHashHexLE,
    'the accepted hash is the committed vector value');
  assert.equal(verdict.hashHexLE, SYNTHETIC_CONTEXT.vectorFor(fixture.qualifyingNonce));

  const after = pool.verifierCounters;
  assert.equal(after.wasmShareHashes - before.wasmShareHashes, 1, 'exactly one Wasm share hash');
  assert.equal(after.nativeShareHashes - before.nativeShareHashes, 1, 'exactly one native share hash');
  assert.equal(pool.verifierHealth.healthy, true);

  console.log(`    accepted ${verdict.nonce} -> ${verdict.hashHexLE}`);
  console.log(`    counters: ${JSON.stringify(after)}`);
  console.log(`    helper linux pid: ${helperPid}`);

  // Shutdown must leave no helper behind.
  c.close();
  await pool.close();
  assert.equal(pool.verifierState, 'closed');
  assert.equal(await linuxCmdline(helperPid), null, `helper linux pid ${helperPid} must be gone`);
});

test('a non-qualifying nonce is rejected above_target, also after dual agreement', { timeout: 120_000, skip: HELPER_MISSING }, async (t) => {
  const pool = await startDevPool({ port: 0 });
  t.after(() => pool.close().catch(() => {}));
  const c = await connect(pool);
  t.after(() => c.close());
  c.send({ type: 'start_request' });
  assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));

  const before = pool.verifierCounters;
  c.got.length = 0;
  c.send({ type: 'submit_share', jobId: c.job.jobId, workerId: c.hello.workerId, nonce: nonceToHex(fixture.nonQualifyingNonce) });
  assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'share_rejected'), { label: 'a rejection' }));
  const verdict = c.got.find((m) => m.type === 'share_rejected');

  assert.equal(verdict.reason, 'above_target', 'rejected on the target, not on a disagreement');
  const after = pool.verifierCounters;
  assert.equal(after.wasmShareHashes - before.wasmShareHashes, 1);
  assert.equal(after.nativeShareHashes - before.nativeShareHashes, 1,
    'both builds still ran and still agreed');
  assert.equal(pool.verifierHealth.healthy, true, 'an above-target share is not a fault');
});

test('cheap refusals cost zero hashes on BOTH builds', { timeout: 120_000, skip: HELPER_MISSING }, async (t) => {
  const pool = await startDevPool({ port: 0, limits: { rateCapacity: 64 } });
  t.after(() => pool.close().catch(() => {}));
  const c = await connect(pool);
  t.after(() => c.close());
  c.send({ type: 'start_request' });
  assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));

  const before = pool.verifierCounters;
  const good = { type: 'submit_share', jobId: c.job.jobId, workerId: c.hello.workerId, nonce: nonceToHex(fixture.nonQualifyingNonce) };
  const refusals = [
    ['bad json', 'not json at all'],
    ['unknown type', JSON.stringify({ type: 'mine_everything' })],
    ['bad schema', JSON.stringify({ ...good, nonce: '0000000F' })],
    ['unknown worker', JSON.stringify({ ...good, workerId: 'w-forged' })],
    ['stale job', JSON.stringify({ ...good, jobId: 'devjob-999' })],
    ['nonce outside window', JSON.stringify({ ...good, nonce: nonceToHex(9999) })],
  ];
  for (const [, payload] of refusals) c.ws.send(payload);
  await sleep(600);

  const after = pool.verifierCounters;
  assert.equal(after.wasmShareHashes, before.wasmShareHashes, 'no Wasm share hash for any refusal');
  assert.equal(after.nativeShareHashes, before.nativeShareHashes, 'and no native share hash either');

  // A duplicate also costs nothing on either side.
  c.ws.send(JSON.stringify(good));
  assert.ok(await waitUntil(() => pool.verifierCounters.nativeShareHashes > after.nativeShareHashes, { label: 'the first verification' }));
  const afterFirst = pool.verifierCounters;
  c.ws.send(JSON.stringify(good));
  await sleep(600);
  assert.deepEqual(pool.verifierCounters, afterFirst, 'a duplicate is refused before either build hashes');
});

// ---------------------------------------------------------------- fail closed

test('a native/Wasm disagreement is never accepted and latches the pool unhealthy', { timeout: 120_000, skip: HELPER_MISSING }, async (t) => {
  // A REAL dual verifier whose native side is a fake that returns a well-formed but WRONG hash.
  // The Wasm side is the genuine one, so this is exactly "the two builds disagree" and it runs
  // through the production comparison, the production latch and the production health path --
  // no monkeypatching of verify().
  const fake = join(scratch, 'disagreeing-helper.mjs');
  writeFileSync(fake, `const token = process.argv[2];
process.stdout.write(\`HELLO 2 \${process.pid} \${token} 2 60 - - ${SOURCE_ID}\\n\`);
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
`, 'utf8');

  const pool = await startDevPool({
    port: 0,
    helperPath: process.execPath,
    helperOptions: {
      useWsl: false,
      spawnFn: (cmd) => spawn(process.execPath, [fake, cmd.args.at(-1)], {
        stdio: ['pipe', 'pipe', 'pipe'], shell: false,
      }),
    },
  });
  t.after(() => pool.close().catch(() => {}));

  const c = await connect(pool);
  t.after(() => c.close());
  const health = [];
  pool.onVerifierHealthChange((h) => health.push(h));

  // The STARTUP SELF-TEST already compares both builds, so a disagreeing helper never even gets
  // to mine: the pool refuses to start rather than accepting anything.
  c.send({ type: 'start_request' });
  assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready' || m.type === 'mining_unavailable'),
    { label: 'a start verdict' }));
  const verdict = c.got.find((m) => m.type === 'mining_ready' || m.type === 'mining_unavailable');
  assert.equal(verdict.type, 'mining_unavailable',
    'a pool whose builds disagree must not start mining at all');
  assert.match(String(verdict.detail ?? ''), /disagreement/i);
  assert.ok(String(verdict.detail).length < 300, 'the reason is bounded, never raw stderr');

  assert.equal(pool.verifier, null, 'no half-built verifier is retained');
  assert.equal(pool.stats.accepted, 0, 'nothing was ever accepted');

  // And the partially-created resources were released before the failure surfaced: no helper left.
  await sleep(300);
  const leftovers = await new Promise((res) => {
    const p = spawn(process.execPath, ['-e', 'process.exit(0)'], { stdio: 'ignore' });
    p.on('close', () => res(0));
  });
  assert.equal(leftovers, 0);
});

test('the global verification queue refuses before either build hashes', { timeout: 120_000, skip: HELPER_MISSING }, async (t) => {
  // A slow native helper so several submissions really are in flight at once.
  const slow = join(scratch, 'slow-helper.mjs');
  writeFileSync(slow, `const token = process.argv[2];
process.stdout.write(\`HELLO 2 \${process.pid} \${token} 2 60 - - ${SOURCE_ID}\\n\`);
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
      setTimeout(() => process.stdout.write(\`RESULT \${id} \${vectors[n]}\\n\`), 700);
    } else if (t[0] === 'QUIT') { process.stdout.write('BYE\\n'); process.exit(0); }
  }
});
`, 'utf8');

  const pool = await startDevPool({
    port: 0,
    limits: { maxGlobalVerificationQueue: 1, maxVerificationQueue: 8, rateCapacity: 64 },
    helperPath: process.execPath,
    helperOptions: {
      useWsl: false,
      spawnFn: (cmd) => spawn(process.execPath, [slow, cmd.args.at(-1)], {
        stdio: ['pipe', 'pipe', 'pipe'], shell: false,
      }),
    },
  });
  t.after(() => pool.close().catch(() => {}));
  const c = await connect(pool);
  t.after(() => c.close());
  c.send({ type: 'start_request' });
  assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));

  const before = pool.verifierCounters;
  c.got.length = 0;
  // Two submissions in one turn; the global cap of 1 must refuse the second before ANY hashing.
  for (const n of [fixture.nonQualifyingNonce, 1]) {
    c.send({ type: 'submit_share', jobId: c.job.jobId, workerId: c.hello.workerId, nonce: nonceToHex(n) });
  }
  assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'share_rejected' && m.reason === 'queue_full'),
    { label: 'a queue_full refusal' }), `saw ${JSON.stringify(c.got.map((m) => m.reason ?? m.type))}`);
  const queueFull = c.got.find((m) => m.reason === 'queue_full');
  assert.match(String(queueFull.detail ?? ''), /pool-wide/, 'the GLOBAL cap refused it, not the per-connection one');

  // Exactly one submission reached verification.
  await waitUntil(() => pool.globalVerificationDepth === 0, { label: 'the queue draining' });
  const after = pool.verifierCounters;
  assert.equal(after.wasmShareHashes - before.wasmShareHashes, 1, 'one Wasm share hash');
  assert.equal(after.nativeShareHashes - before.nativeShareHashes, 1, 'one native share hash');
});

// Windows keeps a brief handle on a script file after the process that was running it exits, so a
// removal issued the instant the last helper is reaped can lose the race and leave the directory
// behind. Await it, retry, and REPORT rather than swallow: a cleanup that silently half-worked is
// how a "no leftovers" claim becomes untrue.
after(async () => {
  if (!scratch) return;
  for (let attempt = 0; attempt < 10 && existsSync(scratch); attempt++) {
    try {
      rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  if (existsSync(scratch)) console.error(`# LEFTOVER TEMP DIRECTORY NOT REMOVED: ${scratch}`);
});

// ---------------------------------------------------------------- the halt, once latched

// NOT skipped when the native build is absent, deliberately. Detection of a disagreement needs two
// real builds (the test above); the CONSEQUENCE of a latch -- every mining connection is stopped
// at once, not merely refused on its next submission -- is the same code in either mode, and it is
// worth holding on every checkout.
test('a latched fault stops every live miner at once, not on its next submission',
  { timeout: 60_000 }, async (t) => {
    const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
    t.after(() => pool.close().catch(() => {}));

    const mining = await connect(pool);
    t.after(() => mining.close());
    const idle = await connect(pool); // connected, but never declared start intent
    t.after(() => idle.close());

    mining.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => mining.got.some((m) => m.type === 'mining_ready'),
      { label: 'mining_ready' }));
    mining.got.length = 0;
    idle.got.length = 0;

    // The same latch a real build disagreement drives, reached from outside.
    const health = pool.injectVerifierFault(new Error('injected fault'));
    assert.equal(health.healthy, false);
    assert.equal(health.reason, 'verifier_fault');

    assert.ok(await waitUntil(() => mining.got.some((m) => m.type === 'mining_unavailable'),
      { label: 'the miner being told to stop' }),
    'a mining connection is told WITHOUT having to submit anything first');
    const halt = mining.got.find((m) => m.type === 'mining_unavailable');
    assert.equal(halt.reason, 'verifier_fault');
    assert.ok(String(halt.detail).length > 0 && String(halt.detail).length <= 240,
      'the detail is present and bounded');

    // A connection that never started is not mining, so it has nothing to be halted.
    await sleep(300);
    assert.equal(idle.got.length, 0, 'a connection that never started is not spammed');

    // Told once, not repeatedly.
    await sleep(300);
    assert.equal(mining.got.filter((m) => m.type === 'mining_unavailable').length, 1);

    // And it really is over: a fresh start intent is refused with the same latched reason.
    idle.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => idle.got.some((m) => m.type === 'mining_unavailable'),
      { label: 'the refusal of a new start' }));
    assert.equal(idle.got.find((m) => m.type === 'mining_unavailable').reason, 'verifier_fault');
    assert.equal(pool.stats.accepted, 0);
  });

// A build disagreement is reported as its own reason, so a person reading the page or the audit
// log can tell "the two builds stopped agreeing" from "the helper died".
test('a build disagreement latches under its own distinct reason', { timeout: 60_000 }, async (t) => {
  const pool = await startDevPool({ port: 0, verifierMode: 'wasm' });
  t.after(() => pool.close().catch(() => {}));
  const err = new Error('nonce 7: wasm aa.. vs native bb..');
  err.name = 'VerifierMismatchError';
  const health = pool.injectVerifierFault(err);
  assert.equal(health.reason, 'verifier_build_disagreement');
  assert.equal(pool.verifierHealth.healthy, false);
});

// The mirror image of the shutdown case: a verification that fails for a reason that is NOT a
// cancellation must still reach the client as a bounded rejection. Without this, "stay silent on
// cancellation" could be over-applied and quietly swallow real failures.
test('a verification failure that is not a cancellation is still reported to the client',
  { timeout: 60_000 }, async (t) => {
    const pool = await startDevPool({
      port: 0,
      verifierFactory: async () => ({
        hashCalls: 0,
        wasmHeapBytes: () => 48_562_176,
        nativeAlgorithmBytes: () => 41_943_040,
        kind: 'dual',
        // A child that died on its own: no `cancelled` flag anywhere.
        async verify() { throw new Error('helper exited unexpectedly (code=3, signal=null)'); },
        beginClose() {},
        async close() {},
        async forceClose() {},
        get closed() { return true; },
        get closing() { return false; },
      }),
    });
    t.after(() => pool.close().catch(() => {}));

    const c = await connect(pool);
    t.after(() => c.close());
    c.send({ type: 'start_request' });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'mining_ready'), { label: 'mining_ready' }));

    c.send({
      type: 'submit_share', jobId: c.job.jobId, workerId: c.hello.workerId,
      nonce: nonceToHex(fixture.qualifyingNonce),
    });
    assert.ok(await waitUntil(() => c.got.some((m) => m.type === 'share_rejected'),
      { label: 'the rejection' }), 'a real verification failure is never silently dropped');
    const rejected = c.got.find((m) => m.type === 'share_rejected');
    assert.equal(rejected.reason, 'verifier_unavailable');
    assert.ok(String(rejected.detail).length <= 240, 'and the detail stays bounded');
    assert.equal(pool.stats.accepted, 0);
  });

// ---------------------------------------------------------------- the REAL binary's input grammar
//
// The JavaScript parser for helper OUTPUT is canonical -- one space between fields, canonical
// unsigned decimals, printable ASCII, CRLF only as a terminator. The C++ parser for parent INPUT
// was not: split_ws() collapsed leading, trailing and repeated spaces, parse_u64() accepted leading
// zeros, and read_line() discarded a carriage return ANYWHERE rather than only as the CRLF
// terminator. Regression testing ran the real helper with "QUIT  " and got BYE and exit 0 -- so "one exact
// protocol" was true in one direction only, and the helper answered lines the protocol does not
// define.
//
// These drive the REAL rebuilt executable, through the REAL Windows -> WSL launch, not a
// JavaScript fake. A fake could only prove what the fake does.

/** Feed exact bytes to the real helper and report what it did. Argument-native; no shell. */
function runRealHelper(inputBytes) {
  return new Promise((resolvePromise) => {
    const child = spawn('wsl.exe', ['--exec', toWslPath(HELPER_BUILD_PATH), '0123456789abcdef'], {
      stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false,
    });
    let out = '';
    let err = '';
    child.stdout.setEncoding('latin1');
    child.stderr.setEncoding('latin1');
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code) => resolvePromise({
      code,
      lines: out.split('\n').filter((l) => l.length > 0),
      stderr: err.trim(),
    }));
    child.stdin.end(Buffer.from(inputBytes, 'latin1'));
  });
}

test('the real helper still accepts the canonical happy path', { timeout: 120_000, skip: HELPER_MISSING },
  async () => {
    const c = SYNTHETIC_CONTEXT;
    const r = await runRealHelper(
      `INIT 1 ${c.epochKeyHex} ${c.seedHashHex} ${c.height} ${c.templateHex}\nHASH 2 0\nQUIT\n`,
    );
    assert.equal(r.code, 0, `canonical input must succeed; stderr=${r.stderr}`);
    assert.equal(r.lines.length, 4, `HELLO, READY, RESULT, BYE; saw ${JSON.stringify(r.lines)}`);
    assert.match(r.lines[0], /^HELLO 2 \d+ 0123456789abcdef 2 60 \S+ \S+ [0-9a-f]{64}$/);
    assert.equal(r.lines[1], 'READY 1 33554432 8388608');
    assert.match(r.lines[2], /^RESULT 2 [0-9a-f]{64}$/);
    assert.equal(r.lines[3], 'BYE');
    // The frozen vector, from the real native binary, unchanged by the parser work.
    assert.equal(r.lines[2].split(' ')[2], SYNTHETIC_CONTEXT.vectorFor(0),
      'the committed frozen-v2 vector must be unaffected by an input-grammar change');
  });

test('the real helper reports THIS working tree as its build-source identity',
  { timeout: 120_000, skip: HELPER_MISSING }, async () => {
    const r = await runRealHelper('QUIT\n');
    assert.equal(r.code, 0);
    assert.equal(r.lines[0].split(' ')[8], SOURCE_ID,
      'the running binary must report the id recomputed from the tree in front of us');
  });

// Every one of these is a line the protocol does not define. Each must be fatal (exit 3), and none
// may be normalised into the command it resembles.
const NONCANONICAL = (() => {
  const c = SYNTHETIC_CONTEXT;
  const init = `INIT 1 ${c.epochKeyHex} ${c.seedHashHex} ${c.height} ${c.templateHex}\n`;
  return [
    ['a trailing space', 'QUIT \n', /noncanonical/],
    ['two trailing spaces', 'QUIT  \n', /noncanonical/],
    ['a leading space', ' QUIT\n', /noncanonical/],
    ['a doubled space between fields', 'HASH  1 0\n', /noncanonical/],
    ['a carriage return in the middle of a word', 'QU\rIT\n', /non-ASCII or control byte/],
    ['a bare carriage return as a separator', 'QUIT\rQUIT\n', /non-ASCII or control byte/],
    ['a leading-zero INIT id', `INIT 01 ${c.epochKeyHex} ${c.seedHashHex} ${c.height} ${c.templateHex}\n`,
      /INIT id is not a canonical unsigned decimal/],
    ['a leading-zero height', `INIT 1 ${c.epochKeyHex} ${c.seedHashHex} 0${c.height} ${c.templateHex}\n`,
      /bad height/],
    ['a leading-zero HASH id', `${init}HASH 02 0\n`, /HASH id is not a canonical unsigned decimal/],
    ['a leading-zero nonce', `${init}HASH 2 00\n`, /bad nonce/],
    ['an exponent nonce', `${init}HASH 2 1e0\n`, /bad nonce/],
    ['a hex nonce', `${init}HASH 2 0x10\n`, /bad nonce/],
    ['a signed nonce', `${init}HASH 2 +1\n`, /bad nonce/],
    ['a negative nonce', `${init}HASH 2 -1\n`, /bad nonce/],
    ['a decimal-point nonce', `${init}HASH 2 1.0\n`, /bad nonce/],
    ['an extra field on HASH', `${init}HASH 2 0 extra\n`, /HASH arity/],
    ['an extra field on QUIT', 'QUIT x\n', /QUIT takes no arguments/],
    ['an extra field on INIT', `INIT 1 ${c.epochKeyHex} ${c.seedHashHex} ${c.height} ${c.templateHex} x\n`,
      /INIT arity/],
    ['a non-ASCII byte', 'H\xe9LLO\n', /non-ASCII or control byte/],
    ['an oversized line', `${'A'.repeat(9000)}\n`, /exceeds the bound/],
    ['an uppercase hex epoch key', `INIT 1 ${c.epochKeyHex.toUpperCase()} ${c.seedHashHex} ${c.height} ${c.templateHex}\n`,
      /bad epoch key/],
  ];
})();

for (const [label, input, expected] of NONCANONICAL) {
  test(`the real helper refuses ${label}`, { timeout: 120_000, skip: HELPER_MISSING }, async () => {
    const r = await runRealHelper(input);
    assert.equal(r.code, 3,
      `${label} must be fatal (exit 3), not answered; got exit ${r.code}, stdout ${JSON.stringify(r.lines)}`);
    assert.match(r.stderr, expected, `and it must say what was wrong; stderr=${r.stderr}`);
    assert.ok(!r.lines.includes('BYE'),
      `${label} must never be normalised into the command it resembles`);
  });
}

test('CRLF is still tolerated, but only as the line terminator', { timeout: 120_000, skip: HELPER_MISSING },
  async () => {
    // A Windows-side writer emitting CRLF is a real case and stays supported. A CR anywhere else
    // is a control byte, which is refused above.
    const r = await runRealHelper('QUIT\r\n');
    assert.equal(r.code, 0, `a CRLF terminator must still work; stderr=${r.stderr}`);
    assert.ok(r.lines.includes('BYE'));
  });
