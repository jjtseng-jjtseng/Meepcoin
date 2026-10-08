// Real-browser smoke for the local MeepCoin miner page.
//
//   node web-miner/tools/browser_smoke.mjs [--browser <path>] [--profile-dir <dir>] [--keep-profile]
//
// Drives a REAL headless Chrome/Chromium/Edge through the DevTools Protocol -- using Node's own
// WebSocket client, so no automation library is installed -- and checks the things only a browser
// can show:
//
//   * the page loads idle with no browser Worker and no browser Wasm request, and the server has
//     no Wasm instance, no dataset and no hash call (it has read ~58.1 KiB of build files, which
//     is not importing, compiling, instantiating or hashing)
//   * Stop during the server's readiness wait leaves a late mining_ready inert: no Worker at all
//   * Start -> readiness -> exactly one Worker -> real hashes -> server recomputation -> accepted
//   * Stop terminates a live Worker before it ever hashes
//   * a genuinely backgrounded tab stops mining, and returning to it does not resume
//   * reloading lands on an idle page that loads no Wasm
//   * a latched verifier fault HALTS a live run: the browser is told, its Worker is terminated,
//     and hashing stops without anyone touching the page
//
// The two verification builds are disclosed separately and never summed: the pool's Wasm heap is
// measured, the native figure is the algorithm's own dataset+scratchpad allocation, and NEITHER is
// the pool process's resident set size, which this script does not measure.
//
// A green result must mean what the report says, so this fails on console.error, on a failed
// console.assert, on any visible page error text, on the spawned Chrome not exiting, and on the
// throwaway profile not being removable.
//
// It uses a throwaway profile directory, never the user's own browser profile, and only ever
// signals the exact process it spawned. If no suitable browser is installed it prints SKIPPED and
// exits 0: this script never invents browser evidence.
//
// --keep-profile is DIAGNOSTIC MODE ONLY. It retains the profile for inspection and therefore
// FAILS the cleanup check: a run with that flag can never be cited as evidence that cleanup works.

import { spawn } from 'node:child_process';
import { existsSync, readFileSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { startDevPool } from '../../pool/dev/server.mjs';
import { ROUTES } from '../../pool/dev/static.mjs';
import { HELPER_BUILD_PATH } from '../../pool/dev/native_helper.mjs';

const CANDIDATES = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
];

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}
const flag = (name) => process.argv.includes(`--${name}`);

const checks = [];
function check(ok, label, detail = '') {
  checks.push({ ok, label, detail });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `  -- ${detail}` : ''}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitUntil(fn, { timeoutMs = 30_000, everyMs = 25, label = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await sleep(everyMs);
  }
}

// ---------------------------------------------------------------- CDP client

function connectCdp(url) {
  const socket = new WebSocket(url);
  const pending = new Map();
  const listeners = [];
  let nextId = 1;
  const ready = new Promise((resolve, reject) => {
    socket.onopen = resolve;
    socket.onerror = () => reject(new Error(`could not connect to DevTools at ${url}`));
  });
  socket.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(`${msg.error.message} (${JSON.stringify(msg.error)})`));
      else resolve(msg.result);
    } else if (msg.method) {
      for (const fn of listeners) fn(msg.method, msg.params);
    }
  };
  return {
    ready,
    onEvent(fn) { listeners.push(fn); },
    send(method, params = {}) {
      const id = nextId++;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        try {
          socket.send(JSON.stringify({ id, method, params }));
        } catch (err) {
          pending.delete(id);
          reject(err);
          return;
        }
        setTimeout(() => {
          if (pending.delete(id)) reject(new Error(`CDP ${method} timed out`));
        }, 30_000);
      });
    },
    close() {
      try { socket.close(); } catch { /* already gone */ }
    },
  };
}

async function evaluate(cdp, expression) {
  const r = await cdp.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error(`page threw: ${r.exceptionDetails.text}`);
  return r.result.value;
}

// ---------------------------------------------------------------- setup

const browserPath = arg('browser', CANDIDATES.find((p) => existsSync(p)));
if (!browserPath || !existsSync(browserPath)) {
  console.log('SKIPPED: no Chrome/Chromium/Edge binary found.');
  console.log('  This script installs nothing. Pass --browser <path> if one exists elsewhere.');
  console.log('  A real-browser end-to-end smoke therefore did NOT run.');
  process.exit(0);
}

// The product path is dual verification, which needs the native helper build. Refusing here, with
// the command to fix it, is better than a run that quietly falls back to a single build and then
// reports "the server recomputed it" as though two builds had agreed.
if (!existsSync(HELPER_BUILD_PATH)) {
  console.log('SKIPPED: the native frozen-v2 helper is not built.');
  console.log(`  expected: ${HELPER_BUILD_PATH}`);
  console.log('  build it with:  npm run build:native-helper');
  console.log('  This script builds nothing on your behalf, and a dual-verification smoke did NOT run.');
  process.exit(0);
}

const profileRoot = arg('profile-dir', tmpdir());
const profileDir = mkdtempSync(join(profileRoot, 'meep-smoke-'));
let chrome = null;
let chromePid = null;
let chromeExited = false;
let cdp = null;
let browserCdp = null;
let pool = null;
let profileRemoved = false;
let profileKept = false;
let cleanupNote = '';

/**
 * Shut down ONLY what this script started: ask the browser to close through DevTools, wait, and
 * fall back to killing the exact pid we spawned. Never touches another chrome.exe.
 */
async function cleanup() {
  cdp?.close();
  if (chrome && !chromeExited) {
    const exited = new Promise((resolve) => chrome.once('exit', () => { chromeExited = true; resolve(); }));
    try {
      await browserCdp?.send('Browser.close');
    } catch {
      // DevTools may already be gone; the fallback below covers it.
    }
    browserCdp?.close();
    await Promise.race([exited, sleep(5000)]);
    if (!chromeExited) {
      chrome.kill(); // the exact spawned process, by handle -- never by name
      await Promise.race([exited, sleep(5000)]);
    }
    if (!chromeExited) {
      chrome.kill('SIGKILL');
      await Promise.race([exited, sleep(5000)]);
    }
  } else {
    browserCdp?.close();
  }
  await pool?.close();

  if (flag('keep-profile')) {
    // DIAGNOSTIC MODE. The profile is deliberately retained for inspection, so this run cannot be
    // used as evidence that cleanup works -- it did not run. A cleanup claim requires a normal run.
    profileKept = true;
    profileRemoved = false;
    return;
  }
  // Chrome can hold the profile briefly after exit; retry, then report honestly.
  for (let attempt = 0; attempt < 10 && existsSync(profileDir); attempt++) {
    try {
      rmSync(profileDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    } catch (err) {
      cleanupNote = err.message;
      await sleep(300);
    }
  }
  profileRemoved = !existsSync(profileDir);
}

// ---------------------------------------------------------------- main

try {
  pool = await startDevPool({ host: '127.0.0.1', port: 0, nonceRange: 16 });
  console.log(`local development pool: ${pool.url}`);
  console.log(`browser:                ${browserPath}`);
  console.log(`throwaway profile:      ${profileDir}\n`);

  chrome = spawn(browserPath, [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--disable-background-networking',
    '--disable-component-update',
    '--no-startup-window',
    `--user-data-dir=${profileDir}`,
    '--remote-debugging-port=0',
    '--remote-allow-origins=*',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  chromePid = chrome.pid;
  chrome.once('exit', () => { chromeExited = true; });
  chrome.stderr.on('data', () => {});
  chrome.stdout.on('data', () => {});

  const portFile = join(profileDir, 'DevToolsActivePort');
  await waitUntil(() => existsSync(portFile) && readFileSync(portFile, 'utf8').includes('\n'),
    { label: 'DevToolsActivePort', timeoutMs: 30_000, everyMs: 100 });
  const [cdpPort, wsPathSuffix] = readFileSync(portFile, 'utf8').trim().split('\n');
  const version = await (await fetch(`http://127.0.0.1:${cdpPort}/json/version`)).json();
  console.log(`engine:                 ${version.Browser}`);
  console.log(`user agent:             ${version['User-Agent']}`);
  console.log(`spawned pid:            ${chromePid}\n`);

  browserCdp = connectCdp(`ws://127.0.0.1:${cdpPort}${wsPathSuffix}`);
  await browserCdp.ready;
  const { targetId } = await browserCdp.send('Target.createTarget', { url: 'about:blank' });
  const list = await (await fetch(`http://127.0.0.1:${cdpPort}/json/list`)).json();
  cdp = connectCdp(list.find((tgt) => tgt.id === targetId).webSocketDebuggerUrl);
  await cdp.ready;
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Log.enable').catch(() => {});

  // Real subscriptions. console.error and a failed console.assert are delivered ONLY through
  // Runtime.consoleAPICalled -- not exceptionThrown, not Log.entryAdded -- so a smoke that
  // ignores it can report green through a page that is visibly failing.
  const pageProblems = [];
  cdp.onEvent((method, params) => {
    if (method === 'Runtime.exceptionThrown') {
      pageProblems.push(`uncaught: ${params?.exceptionDetails?.text ?? 'exception'}`);
    } else if (method === 'Log.entryAdded' && params?.entry?.level === 'error') {
      pageProblems.push(`log(${params.entry.source}): ${params.entry.text}`);
    } else if (method === 'Runtime.consoleAPICalled' && (params?.type === 'error' || params?.type === 'assert')) {
      const text = (params.args ?? []).map((a) => a.value ?? a.description ?? a.type).join(' ');
      pageProblems.push(`console.${params.type}: ${text}`);
    }
  });

  const wasmRequests = () => pool.stats.requests.filter((r) => r.url.startsWith('/wasm/'));
  const dom = (id) => evaluate(cdp, `document.getElementById('${id}').textContent`);
  const num = async (id) => Number(await dom(id));
  const click = (id) => evaluate(cdp, `document.getElementById('${id}').click()`);
  const errorText = async () => {
    const t = (await dom('error')).trim();
    return t === '\u2014' || t === '' ? null : t;
  };

  // ---- A. nothing on either side before Start -----------------------------
  await cdp.send('Page.navigate', { url: pool.url });
  await waitUntil(async () => (await evaluate(cdp, 'document.readyState')) === 'complete', { label: 'page load' });
  await waitUntil(async () => (await dom('connection')) === 'connected', { label: 'websocket connection' });

  check((await dom('state')) === 'idle', 'page loads in the idle state', `state="${await dom('state')}"`);
  await sleep(1500); // a generous window in which to misbehave
  check(wasmRequests().length === 0 && (await num('hashes')) === 0,
    'BROWSER: no Wasm requested and no hashes before Start',
    `${wasmRequests().length} /wasm/ requests, ${await num('hashes')} hashes`);
  const c0 = pool.verifierCounters;
  check(pool.verifierMode === 'dual'
    && c0.wasmSelfTestHashes === 0 && c0.nativeSelfTestHashes === 0
    && c0.wasmShareHashes === 0 && c0.nativeShareHashes === 0
    && pool.helperLinuxPid === null,
    'neither verification build exists before Start: no native child process, zero hashes on both',
    `mode=${pool.verifierMode} helperPid=${pool.helperLinuxPid} counters=${JSON.stringify(c0)}`);
  check(pool.verifier === null && pool.serverHashCalls === 0 && pool.verifierInitCount === 0,
    'SERVER: not imported/compiled/instantiated, no dataset, no MeepHash-W call before Start',
    `verifier=${pool.verifier}, state=${pool.verifierState}, hashCalls=${pool.serverHashCalls}`);
  check((await evaluate(cdp, "document.getElementById('stop-btn').disabled")) === true,
    'the Stop button is disabled while nothing is running');

  // Only the expected client modules were ever fetched by the browser.
  const expected = new Set(Object.keys(ROUTES).filter((p) => !p.startsWith('/wasm/')));
  const fetched = await evaluate(cdp,
    "JSON.stringify(performance.getEntriesByType('resource').map(e => new URL(e.name).pathname))");
  const unexpected = JSON.parse(fetched).filter((p) => !expected.has(p));
  check(unexpected.length === 0, 'the page fetched only files from the server route table',
    unexpected.length ? unexpected.join(', ') : JSON.parse(fetched).join(', '));

  // ---- B. Stop while the server is still getting ready --------------------
  // The FIRST start_request genuinely takes about a second: the pool has to build its 32 MiB
  // dataset. Stopping inside that real window is what proves a late mining_ready is inert.
  await click('start-btn');
  check((await dom('state')).startsWith('starting'), 'Start puts the page in a waiting state, not mining',
    `state="${await dom('state')}"`);
  await click('stop-btn');
  await waitUntil(() => pool.verifierState === 'ready', { label: 'the server verifier becoming ready' });
  await sleep(2000); // let the late mining_ready arrive and be ignored

  // Note on timing: building the pool's 32 MiB dataset blocks its Node event loop for about a
  // second, and this driver shares that process, so wall-clock stamps taken here are distorted.
  // The evidence that matters is page-side and is not: the server DID become ready (so a
  // mining_ready really was sent), and the page still never fetched the Wasm or built a worker.
  check(pool.verifierState === 'ready',
    'the server did become ready, so there really was a late mining_ready to ignore',
    `verifierState=${pool.verifierState}, initCount=${pool.verifierInitCount}`);
  check(wasmRequests().length === 0 && (await num('hashes')) === 0,
    'Stop during the readiness wait leaves that mining_ready inert: NO worker, no Wasm',
    `${wasmRequests().length} /wasm/ requests, ${await num('hashes')} hashes`);
  check((await dom('state')) === 'stopped', 'and the page stays stopped', `state="${await dom('state')}"`);
  check(pool.verifierInitCount === 1, 'the server initialised exactly one verifier',
    `initCount=${pool.verifierInitCount}`);

  // ---- C. Stop terminates a live worker before it hashes ------------------
  await click('start-btn');
  await waitUntil(() => wasmRequests().some((r) => r.url === '/wasm/meepow.wasm'),
    { label: 'the worker fetching the Wasm module', timeoutMs: 30_000 });
  const hashesWhenWorkerLoaded = await num('hashes');
  await click('stop-btn');
  await sleep(2500);
  const hashesAfterStop = await num('hashes');
  // "before it hashed" has to mean zero, not merely "unchanged": if the worker had already
  // hashed, an unchanged count would still pass and the label would be wrong.
  check(hashesWhenWorkerLoaded === 0 && hashesAfterStop === 0 && (await dom('state')) === 'stopped',
    'Stop terminates a worker that had already loaded the Wasm, before it hashed even once',
    `hashes at Stop = ${hashesWhenWorkerLoaded}, after = ${hashesAfterStop}`);

  // ---- D. the full run ----------------------------------------------------
  const wasmBeforeRun = wasmRequests().length;
  await click('start-btn');
  await waitUntil(async () => (await num('hashes')) > 0, { label: 'the first hashes', timeoutMs: 40_000 });
  check(wasmRequests().length > wasmBeforeRun && (await num('hashes')) > 0,
    'Start loads the identity-pinned MeepHash-W build in a real Web Worker and hashes',
    `${await num('hashes')} hashes, heap ${await dom('heap')}`);
  const serverHeapText = await dom('server-heap');
  const serverNativeText = await dom('server-native');
  check(/MiB/.test(serverHeapText) && /MiB/.test(serverNativeText)
    && serverHeapText !== serverNativeText,
    "the page discloses the pool's two builds as SEPARATE figures, never as one total",
    `wasm heap ${serverHeapText}; native algorithm ${serverNativeText} (dataset+scratchpad, not RSS)`);
  check(/byte-for-byte/.test(await dom('verifier-mode')),
    'and says on the page that a share needs both builds to agree',
    await dom('verifier-mode'));
  check(pool.helperLinuxPid !== null,
    'the native helper is a real, separately-identified child process',
    `helper Linux pid ${pool.helperLinuxPid}`);

  await waitUntil(async () => (await num('accepted')) > 0, { label: 'an accepted share', timeoutMs: 40_000 });
  const cAccept = pool.verifierCounters;
  check((await num('accepted')) >= 1 && pool.stats.accepted >= 1,
    'a share found in the browser was recomputed by the server and accepted',
    `page=${await num('accepted')} server=${pool.stats.accepted}, server hashCalls=${pool.serverHashCalls}`);
  check(cAccept.wasmShareHashes >= 1 && cAccept.wasmShareHashes === cAccept.nativeShareHashes,
    'every share the server judged was recomputed by BOTH builds, not one',
    `wasm ${cAccept.wasmShareHashes} share hashes, native ${cAccept.nativeShareHashes}`);

  // The demonstration is terminal by design.
  await waitUntil(async () => !(await dom('state')).startsWith('mining'), { label: 'the run ending itself' });
  const hashesAtEnd = await num('hashes');
  await sleep(2000);
  check((await num('hashes')) === hashesAtEnd && pool.jobs.active() === null,
    'one accepted share ends the run, and hashing really stops',
    `hashes frozen at ${hashesAtEnd}, state="${await dom('state')}"`);

  // ---- E. a genuinely hidden tab ------------------------------------------
  let otherTargetId = null;
  try {
    await click('start-btn');
    // A new run resets the counter, so this is "> 0", not "> the previous run's total".
    await waitUntil(async () => (await num('hashes')) > 0, { label: 'mining again', timeoutMs: 40_000 });

    otherTargetId = (await browserCdp.send('Target.createTarget', { url: 'about:blank' })).targetId;
    await browserCdp.send('Target.activateTarget', { targetId: otherTargetId });
    await waitUntil(async () => (await evaluate(cdp, 'document.visibilityState')) === 'hidden',
      { label: 'the page actually becoming hidden', timeoutMs: 10_000 });

    const hiddenHashes = await num('hashes');
    const hiddenState = await dom('state');
    await sleep(2000);
    check(hiddenState.includes('hidden') && (await num('hashes')) === hiddenHashes && hiddenHashes > 0,
      'switching to another tab stops mining that was actually running',
      `state="${hiddenState}", hashes frozen at ${hiddenHashes}`);

    await browserCdp.send('Target.activateTarget', { targetId });
    await waitUntil(async () => (await evaluate(cdp, 'document.visibilityState')) === 'visible',
      { label: 'the page becoming visible again', timeoutMs: 10_000 });
    await sleep(2500);
    check((await dom('state')).includes('hidden') && (await num('hashes')) === hiddenHashes,
      'coming back to the tab does NOT resume mining',
      `state="${await dom('state')}" hashes ${hiddenHashes} -> ${await num('hashes')}`);
  } finally {
    if (otherTargetId) await browserCdp.send('Target.closeTarget', { targetId: otherTargetId }).catch(() => {});
  }

  // ---- F. reload ----------------------------------------------------------
  // Sample the visible error field FIRST: navigating replaces the document, so an error raised
  // during the run above would be wiped out and the later check would pass vacuously.
  const errorBeforeReload = await errorText();
  const problemsBeforeReload = [...pageProblems];

  const wasmBeforeReload = wasmRequests().length;
  await cdp.send('Page.navigate', { url: pool.url });
  await waitUntil(async () => (await dom('connection')) === 'connected', { label: 'the reloaded page connecting' });
  await sleep(1500);
  check((await dom('state')) === 'idle' && (await num('hashes')) === 0
    && wasmRequests().length === wasmBeforeReload,
    'reloading the page lands on idle and loads no Wasm',
    `state="${await dom('state')}" hashes=${await num('hashes')}`);

  // ---- G. nothing went visibly wrong --------------------------------------
  check(errorBeforeReload === null && (await errorText()) === null,
    'the visible page error field stayed empty throughout the run and after reload',
    `during run: ${errorBeforeReload ?? 'empty'}; after reload: ${(await errorText()) ?? 'empty'}`);
  check(problemsBeforeReload.length === 0 && pageProblems.length === 0,
    'no console errors, failed assertions or uncaught exceptions',
    pageProblems.join(' | ') || 'none');

  // ---- H. a latched verifier fault halts a LIVE run ------------------------
  // Deliberately AFTER G: this section makes the page show an error on purpose, so it must not be
  // able to contaminate the "nothing went visibly wrong" sampling above.
  //
  // Scope, stated exactly. injectVerifierFault() drives the same latch a real fault drives, from
  // outside. This proves the HALT: the server tells every mining connection, the page terminates
  // its Worker, and hashing stops. It does NOT prove that a genuine byte-level disagreement
  // between the two builds is DETECTED -- that is proven separately, against a real Wasm build and
  // a native side that returns a different hash, in pool/dev/tests/dual_verifier.test.mjs.
  await click('start-btn');
  await waitUntil(async () => (await num('hashes')) > 0,
    { label: 'a live run to interrupt', timeoutMs: 40_000 });
  const acceptedBeforeFault = pool.stats.accepted;
  const health = pool.injectVerifierFault(new Error('smoke-injected verifier fault'));

  await waitUntil(async () => !(await dom('state')).startsWith('mining'),
    { label: 'the page reacting to the fault', timeoutMs: 15_000 });
  const hashesAtHalt = await num('hashes');
  await sleep(2000);
  check((await num('hashes')) === hashesAtHalt,
    'a latched verifier fault stops the browser Worker: hashing halts and does not resume',
    `state="${await dom('state')}" hashes frozen at ${hashesAtHalt}, reason=${health.reason}`);
  check(/halted/i.test((await errorText()) ?? ''),
    'and the page says so, naming the halt rather than a failed start',
    (await errorText()) ?? 'empty');
  check(pool.stats.accepted === acceptedBeforeFault && pool.verifierHealth.healthy === false,
    'nothing was accepted after the latch, and the pool stays unhealthy',
    `accepted ${acceptedBeforeFault} -> ${pool.stats.accepted}, healthy=${pool.verifierHealth.healthy}`);

  // ---- I. shut down, and prove it -----------------------------------------
  await cleanup();
  check(chromeExited, 'the exact spawned Chrome process exited', `pid ${chromePid}, exitCode=${chrome.exitCode}`);
  if (profileKept) {
    check(false, 'the throwaway profile was removed',
      '--keep-profile is DIAGNOSTIC MODE: the profile was deliberately retained, so this run is '
      + 'not evidence that cleanup works. Re-run without --keep-profile for a cleanup claim.');
  } else {
    check(profileRemoved, 'the throwaway profile was removed',
      profileRemoved ? profileDir : `${profileDir} still present: ${cleanupNote}`);
  }

  const failed = checks.filter((c) => !c.ok);
  console.log(`\n${checks.length - failed.length}/${checks.length} browser checks passed`);
  if (failed.length) {
    console.log('FAILED:');
    for (const f of failed) console.log(`  - ${f.label}${f.detail ? `: ${f.detail}` : ''}`);
  }
  process.exit(failed.length === 0 ? 0 : 1);
} catch (err) {
  console.error(`\nbrowser smoke FAILED: ${err.stack ?? err.message}`);
  await cleanup();
  console.error(`  spawned Chrome exited: ${chromeExited} (pid ${chromePid})`);
  console.error(`  throwaway profile removed: ${profileRemoved}${cleanupNote ? ` (${cleanupNote})` : ''}`);
  process.exit(1);
}
