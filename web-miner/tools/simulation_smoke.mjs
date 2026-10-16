// ONE short recorded-template simulation smoke, in a real browser.
//
// SCOPE, DELIBERATELY NARROW:
//   * one ephemeral loopback listener, started and stopped by this script;
//   * one throwaway browser profile, removed afterwards;
//   * one tab, one browser Worker, ONE browser hash, ONE server Wasm hash, ONE native HASH;
//   * the native check is the LIVE local native helper (in WSL on Windows), started only by Start;
//   * the daemon is an in-memory mock with counters;
//   * no real daemon, no external network, no Docker.
//
// WHY IT DOES NOT TRUST THE PAGE'S OWN TEXT. Page copy is the easiest thing to get right and the
// least meaningful. The mock counters are read from the SERVER's own simulation context, and the
// browser-side evidence (hash count, Wasm heap) from the page's live readouts -- not from a
// reassuring sentence in the DOM.
//
// ONE MEASUREMENT LIMIT, STATED RATHER THAN GLOSSED. Network.enable on the PAGE target does not see
// requests made by a dedicated Worker, because a Worker is its own CDP target. So this script does
// NOT use the request log as evidence that no Wasm was fetched; it uses the hash count and the Wasm
// heap, which are properties of the thing actually being claimed.
//
// It installs nothing. With no Chrome/Chromium/Edge present it prints SKIPPED and exits 0.
//
// Usage:
//   node web-miner/tools/simulation_smoke.mjs [--browser <path>] [--screenshot-dir <dir>]

import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { startDevPool } from '../../pool/dev/server.mjs';
import { EXPECTED } from '../../pool/dev/recorded_simulation.mjs';
import { SIM_ATTEMPT_STATES } from '../../pool/dev/sim_session.mjs';

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

const checks = [];
function check(ok, label, detail = '') {
  checks.push({ ok, label, detail });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `  -- ${detail}` : ''}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitUntil(fn, { timeoutMs = 60_000, everyMs = 50, label = 'condition' } = {}) {
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
      if (msg.error) reject(new Error(msg.error.message));
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
        try { socket.send(JSON.stringify({ id, method, params })); } catch (err) { pending.delete(id); reject(err); return; }
        setTimeout(() => { if (pending.delete(id)) reject(new Error(`CDP ${method} timed out`)); }, 60_000);
      });
    },
    close() { try { socket.close(); } catch { /* already gone */ } },
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
  console.log('  A real-browser simulation smoke therefore did NOT run.');
  process.exit(0);
}

const screenshotDir = arg('screenshot-dir', null);
const profileDir = mkdtempSync(join(tmpdir(), 'meep-sim-smoke-'));
let chrome = null;
let chromePid = null;
let chromeExited = false;
let pool = null;
let cdp = null;

/** Stop ONLY the browser this script spawned, by handle. Never by process name. */
async function stopChrome() {
  if (chrome && !chromeExited) {
    const exited = new Promise((resolve) => chrome.once('exit', () => { chromeExited = true; resolve(); }));
    chrome.kill();
    await Promise.race([exited, sleep(4000)]);
    if (!chromeExited) { chrome.kill('SIGKILL'); await Promise.race([exited, sleep(4000)]); }
  }
}

let helperFacts = null;
async function cleanup() {
  try { cdp?.close(); } catch { /* already closed */ }
  await stopChrome();
  if (pool) {
    // NOT SWALLOWED. With a native child in the ownership graph, an unconfirmed close is a failure.
    try {
      const outcome = await pool.close();
      console.log(`pool shutdown:          ${JSON.stringify(outcome)}`);
    } catch (err) {
      console.log(`pool shutdown FAILED:   ${err?.message ?? err}`);
      console.log(`retained resources:     ${pool.retainedResources.map((r) => r.label).join(', ')}`);
      exitCode = 1;
    }
    if (helperFacts?.linuxPid && helperFacts?.distro) {
      // An INDEPENDENT look after the pool's own confirmation: is /proc/<pid> gone in that distro?
      const probe = spawnSync('wsl.exe', ['-d', helperFacts.distro, '--exec', 'ls', '-d', `/proc/${helperFacts.linuxPid}`],
        { encoding: 'utf8', timeout: 30_000, windowsHide: true });
      const gone = probe.status !== 0 && !String(probe.stdout).includes(`/proc/${helperFacts.linuxPid}`);
      console.log(`helper pid ${helperFacts.linuxPid} in ${helperFacts.distro}: ${gone ? 'GONE' : 'STILL PRESENT'} `
        + `(ls exit ${probe.status})`);
      if (!gone) exitCode = 1;
    }
  }
  try { rmSync(profileDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* leave it */ }
  console.log(`throwaway profile removed: ${!existsSync(profileDir)}`);
}

let exitCode = 0;
try {
  console.log('MeepCoin RECORDED-TEMPLATE SIMULATION smoke');
  console.log('LIVE LOCAL NATIVE HELPER / MOCK DAEMON / NO DAEMON OR BLOCKCHAIN CONTACTED\n');
  console.log(`browser:                ${browserPath}`);
  console.log(`throwaway profile:      ${profileDir}`);

  // ONE ephemeral loopback listener, in simulation mode.
  pool = await startDevPool({ host: '127.0.0.1', port: 0, mode: 'recorded-template-simulation' });
  console.log(`pool:                   ${pool.url}  (ephemeral port ${pool.port})`);
  console.log(`recorded height:        ${pool.simulation.job.height}`);
  console.log(`the one nonce:          ${pool.simulation.job.nonceStart}`);
  console.log(`expected hash:          ${pool.simulation.expectedHashHexLE}\n`);

  const cdpPort = 0;
  chrome = spawn(browserPath, [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    `--user-data-dir=${profileDir}`,
    `--remote-debugging-port=${cdpPort}`,
    'about:blank',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  chromePid = chrome.pid;
  chrome.once('exit', () => { chromeExited = true; });
  chrome.stdout.on('data', () => {});

  // The DevTools endpoint is printed on stderr when the port is ephemeral.
  let devtoolsUrl = null;
  chrome.stderr.on('data', (buf) => {
    const m = /ws:\/\/127\.0\.0\.1:\d+\/devtools\/browser\/[0-9a-f-]+/i.exec(buf.toString());
    if (m && !devtoolsUrl) devtoolsUrl = m[0];
  });
  await waitUntil(() => devtoolsUrl, { timeoutMs: 30_000, label: 'the DevTools endpoint' });
  console.log(`spawned pid:            ${chromePid}\n`);

  const browserCdp = connectCdp(devtoolsUrl);
  await browserCdp.ready;
  const { targetId } = await browserCdp.send('Target.createTarget', { url: 'about:blank' });
  const wsForTarget = devtoolsUrl.replace(/\/devtools\/browser\/.*$/, `/devtools/page/${targetId}`);
  cdp = connectCdp(wsForTarget);
  await cdp.ready;
  browserCdp.close();

  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Network.enable');

  // Record every request the page makes, so "no mining Wasm was fetched" is an observation.
  const requests = [];
  cdp.onEvent((method, params) => {
    if (method === 'Network.requestWillBeSent') requests.push(params.request.url);
  });
  const pageErrors = [];
  cdp.onEvent((method, params) => {
    if (method === 'Runtime.exceptionThrown') pageErrors.push(params.exceptionDetails?.text ?? 'exception');
  });

  await cdp.send('Page.navigate', { url: pool.url });
  await waitUntil(async () => evaluate(cdp, 'document.readyState === "complete"'),
    { label: 'the page to load' });
  // Wait for the server_hello to have been applied.
  await waitUntil(async () => evaluate(cdp, 'document.getElementById("sim-banner") && !document.getElementById("sim-banner").hidden'),
    { label: 'the simulation banner' });

  // ---------------------------------------------------------------- BEFORE START
  console.log('BEFORE START');
  const bannerText = await evaluate(cdp, 'document.getElementById("sim-banner").innerText');
  for (const label of [
    'RECORDED-TEMPLATE SIMULATION', 'LIVE LOCAL NATIVE HELPER', 'MOCK DAEMON',
    'NO DAEMON OR BLOCKCHAIN CONTACTED', 'NO BLOCK MINED, SUBMITTED, OR ACCEPTED',
  ]) {
    check(bannerText.includes(label), `label visible: ${label}`);
  }
  const startLabel = await evaluate(cdp, 'document.getElementById("start-btn").textContent.trim()');
  check(startLabel === 'Run one-hash simulation', 'the action is labelled a simulation', startLabel);

  // NOTE ON WHAT THIS LOG CAN AND CANNOT SEE. Network.enable on the PAGE target does not capture
  // requests a dedicated Worker makes -- a Worker is its own CDP target. So an absence here is NOT
  // evidence that no Worker fetched the module, and it is not claimed as such. The real
  // before/after evidence is the Worker count and the Wasm heap, read from the page below.
  const wasmFetchesBefore = requests.filter((u) => /\/wasm\/meepow\.(mjs|wasm)$/.test(u));
  console.log(`  note: page-target Wasm requests before Start: ${wasmFetchesBefore.length} `
    + '(worker-initiated fetches are NOT visible to this log)');
  const before = await evaluate(cdp, `(() => ({
    hashes: document.getElementById('hashes').textContent.trim(),
    heap: document.getElementById('heap').textContent.trim(),
  }))()`);
  check(before.hashes === '0', 'the browser has performed ZERO hashes before Start', before.hashes);
  check(before.heap === '—', 'no browser Wasm heap exists before Start', before.heap);
  check(pool.simulation.serverVerifierReady === false, 'the server holds no verifier before Start');
  check(pool.simulation.counters.serverWasmHashes === 0, 'server hash count is 0 before Start');
  check(pool.simulation.verifier === null, 'NO native helper and no server Wasm verifier exist before Start');
  check(pool.simulation.createdResources.length === 0, 'the simulation has created no resource before Start');
  check(pool.simulation.counters.nativeHashRequests === 0, 'native HASH requests are 0 before Start');
  check(pool.simulation.mockDaemon.counters.dispatchSubmission === 0, 'mock submit count is 0 before Start');

  if (screenshotDir) {
    const shot = await cdp.send('Page.captureScreenshot', { format: 'png' });
    writeFileSync(join(screenshotDir, 'sim-before-start.png'), Buffer.from(shot.data, 'base64'));
  }

  // ---------------------------------------------------------------- RUN ONCE
  console.log('\nRUN ONCE');
  await evaluate(cdp, 'document.getElementById("start-btn").click()');

  // The SUCCESSFUL terminal specifically. `state.completed` is true for every terminal state --
  // stopped and failed included, because the one attempt is spent either way -- so waiting on it
  // would let a failed attempt fall through into the counter checks below with a confusing message.
  await waitUntil(async () => pool.simulation.attemptState === SIM_ATTEMPT_STATES.TERMINAL_COMPLETE,
    { timeoutMs: 120_000, label: 'the server to complete the simulation' });
  // AND wait for the PAGE to have received and rendered the terminal frame. The server sets its
  // completed flag immediately BEFORE sending, so reading the DOM on the server flag alone races
  // the WebSocket frame -- which is exactly how the first run of this script produced a spurious
  // failure on a field that only arrives with that frame.
  await waitUntil(async () => evaluate(cdp,
    'document.getElementById("sim-expected-hash").textContent.trim().length === 64'),
    { timeoutMs: 30_000, label: 'the page to render the terminal message' });

  const evidence = pool.simulationEvidence;
  helperFacts = { linuxPid: evidence?.helperLinuxPid, distro: evidence?.helperDistro };
  console.log(`  helper:               pid ${evidence.helperLinuxPid} in ${evidence.helperDistro}`);
  console.log(`  helper command:       ${JSON.stringify(evidence.helperCommand)}`);
  console.log(`  helper source id:     ${evidence.helperSourceId}`);
  console.log(`  helper allocation:    dataset ${evidence.datasetBytes} B, scratchpad ${evidence.scratchBytes} B`);
  console.log(`  context:              height ${evidence.context.height}, epoch ${evidence.context.epochKeyHex}`);
  console.log(`  verifier counters:    ${JSON.stringify(evidence.verifierCounters)}`);
  check(evidence.context.height === '2113', 'the helper context is height 2113', evidence.context.height);
  check(evidence.verifierCounters.nativeShareHashes === 1, 'exactly ONE native HASH', String(evidence.verifierCounters.nativeShareHashes));
  check(evidence.verifierCounters.wasmShareHashes === 1, 'exactly ONE server Wasm hash (verifier)', String(evidence.verifierCounters.wasmShareHashes));
  check(evidence.verifierCounters.nativeSelfTestHashes === 0 && evidence.verifierCounters.wasmSelfTestHashes === 0,
    'no synthetic self-test hash on either build');

  const counters = {
    serverWasmHashes: pool.simulation.counters.serverWasmHashes,
    nativeHashRequests: pool.simulation.counters.nativeHashRequests,
    nativeHelperHashes: pool.simulation.counters.nativeHelperHashes,
    mockCalcPow: pool.simulation.mockDaemon.counters.calcPow,
    mockDispatch: pool.simulation.mockDaemon.counters.dispatchSubmission,
    mockReadback: pool.simulation.mockDaemon.counters.readback,
    realTransport: pool.simulation.mockDaemon.counters.transportCalls,
  };
  console.log(`  server counters:      ${JSON.stringify(counters)}`);

  check(counters.serverWasmHashes === 1, 'exactly ONE server Wasm hash', String(counters.serverWasmHashes));
  check(counters.nativeHashRequests === 1, 'exactly ONE native helper HASH request', String(counters.nativeHashRequests));
  check(counters.nativeHelperHashes === 1, 'exactly ONE native helper hash', String(counters.nativeHelperHashes));
  check(counters.mockCalcPow === 1, 'exactly ONE mock calc_pow', String(counters.mockCalcPow));
  check(counters.mockDispatch === 1, 'exactly ONE mock submit', String(counters.mockDispatch));
  check(counters.mockReadback === 1, 'exactly ONE mock readback', String(counters.mockReadback));
  check(counters.realTransport === 0, 'ZERO real transport calls', String(counters.realTransport));

  // From inside the page: the Worker count and the browser's own single hash.
  const page = await evaluate(cdp, `(() => {
    const el = (id) => document.getElementById(id)?.textContent?.trim() ?? null;
    return {
      browserHash: el('sim-browser-hash'),
      serverHash: el('sim-server-hash'),
      expected: el('sim-expected-hash'),
      nonce: el('sim-nonce'),
      hashCounts: el('sim-hash-counts'),
      nativeAlloc: el('sim-native-alloc'),
      hashes: el('hashes'),
      heap: el('heap'),
      note: el('controls-note'),
      startDisabled: document.getElementById('start-btn').disabled,
      body: document.body.innerText,
    };
  })()`);

  check(page.browserHash === EXPECTED.powHash, 'the BROWSER computed the recorded hash', page.browserHash);
  check(page.serverHash === EXPECTED.powHash, 'the SERVER recomputed the recorded hash', page.serverHash);
  check(page.expected === EXPECTED.powHash, 'the recorded expected hash is shown');
  check(page.nonce === String(EXPECTED.nonce), 'the one nonce is the recorded one', page.nonce);
  check(page.hashes === '1', 'the browser performed exactly ONE hash', page.hashes);
  check(/browser Wasm=1\s+server Wasm=1\s+native helper=1/.test(page.hashCounts ?? ''),
    'the page shows three separate candidate-hash counts of 1', page.hashCounts);
  console.log(`  page native alloc:    ${page.nativeAlloc}`);

  // The honest after-Start evidence: a Wasm heap now exists in the page, and it did not before.
  check(page.heap !== '—' && page.heap.length > 1,
    'a browser Wasm heap exists only AFTER Start', page.heap);

  // No forbidden wording anywhere on the page.
  const forbidden = ['block_accepted', 'share_accepted', 'daemon accepted', 'block submitted', 'block accepted'];
  const found = forbidden.filter((f) => page.body.toLowerCase().includes(f.toLowerCase()));
  check(found.length === 0, 'no real-acceptance wording on the page', found.join(', '));

  check(page.startDisabled === true, 'Start is disabled after the one-shot run');

  if (screenshotDir) {
    const shot = await cdp.send('Page.captureScreenshot', { format: 'png' });
    writeFileSync(join(screenshotDir, 'sim-completed.png'), Buffer.from(shot.data, 'base64'));
  }

  // The Worker must be gone and the counters frozen.
  await sleep(500);
  const frozen = {
    serverWasmHashes: pool.simulation.counters.serverWasmHashes,
    mockDispatch: pool.simulation.mockDaemon.counters.dispatchSubmission,
  };
  check(frozen.serverWasmHashes === 1 && frozen.mockDispatch === 1,
    'counters are frozen after completion', JSON.stringify(frozen));
  check(pageErrors.length === 0, 'no uncaught page exception', pageErrors.join(' | '));

  console.log('');
  const failed = checks.filter((c) => !c.ok);
  console.log(`RESULT: ${checks.length - failed.length} passed, ${failed.length} failed`);
  exitCode = failed.length === 0 ? 0 : 1;
} catch (err) {
  console.error(`\nSMOKE ERROR: ${err?.message ?? err}`);
  exitCode = 1;
} finally {
  await cleanup();
}
process.exit(exitCode);
