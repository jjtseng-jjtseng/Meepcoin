// One private, one-use acceptance probe: one offline daemon and TWO independent Chrome profiles.
// This is a bounded engineering run, not a pool service, wallet test or public-network test.
// A real block may arrive before both browsers are ready; that is preserved as block evidence but
// is NOT adjudicated as a two-browser handoff. No retry exists in this process.
//
// node web-miner/tools/local_two_browser_block.mjs --expected-head <40 hex>
//   --artifact-dir /home/<user>/meepcoin-<build> --image meepcoin-build:<tag>
//   --image-id sha256:<64 hex> --rpc-port <n> --p2p-port <n>
//   --output-dir C:/Users/<user>/Downloads/MeepCoin-two-browser-<unique>

import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  closeSync, existsSync, fsyncSync, mkdirSync, mkdtempSync, openSync, readFileSync,
  realpathSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { startDevPool } from '../../pool/dev/server.mjs';
import { checkDaemonConfig } from '../../pool/dev/local_daemon.mjs';
import { REAL_DAEMON_MODE, REAL_SEARCH_LIMITS } from '../lib/shared/protocol.js';
import { connectCdp, evaluate } from './cdp_client.mjs';
import { adjudicateTwoBrowser } from './two_browser_verdict.mjs';
import { createRunLifecycle, persistJsonAtomically } from './live_run_lifecycle.mjs';

const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const WSL = 'Ubuntu';
const MAX_FRAMES = 80;
const MAX_LOGS = 120;
const TERMINAL = new Set(['block_accepted', 'block_rejected', 'run_stopped', 'run_unavailable']);
const CHROME = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
];
const REQUIRED_ARTIFACTS = [
  'meepcoind', 'meepcoin-blockhashing',
  'runtime-libs/libboost_filesystem.so.1.83.0',
  'runtime-libs/libboost_thread.so.1.83.0',
];
const now = () => new Date().toISOString();
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

function parseArgs(argv) {
  const flags = new Set(['expected-head', 'artifact-dir', 'image', 'image-id', 'rpc-port',
    'p2p-port', 'output-dir', 'browser']);
  const values = new Map();
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i]?.startsWith('--') ? argv[i].slice(2) : null;
    if (!flags.has(k) || values.has(k) || !argv[i + 1] || argv[i + 1].startsWith('--')) {
      throw new Error(`invalid or repeated option ${String(argv[i]).slice(0, 80)}`);
    }
    values.set(k, argv[i + 1]);
  }
  const required = (k) => {
    if (!values.has(k)) throw new Error(`missing --${k}`);
    return values.get(k);
  };
  const expectedHead = required('expected-head');
  const imageId = required('image-id');
  if (!/^[0-9a-f]{40}$/.test(expectedHead) || !/^sha256:[0-9a-f]{64}$/.test(imageId)) {
    throw new Error('expected HEAD or image ID has the wrong shape');
  }
  const port = (k) => {
    const v = required(k);
    if (!/^[1-9][0-9]*$/.test(v) || Number(v) < 1024 || Number(v) > 65535) {
      throw new Error(`--${k} must be a canonical port from 1024 through 65535`);
    }
    return Number(v);
  };
  const rpcPort = port('rpc-port');
  const p2pPort = port('p2p-port');
  if (rpcPort === p2pPort) throw new Error('RPC and P2P ports must differ');
  const outputDir = resolve(required('output-dir'));
  const downloads = resolve(homedir(), 'Downloads');
  if (dirname(outputDir).toLowerCase() !== downloads.toLowerCase()
    || realpathSync(dirname(outputDir)).toLowerCase() !== realpathSync(downloads).toLowerCase()
    || !/^MeepCoin-two-browser-[A-Za-z0-9_-]{8,64}$/.test(basename(outputDir))
    || existsSync(outputDir)) {
    throw new Error('--output-dir must be a fresh MeepCoin-two-browser-* direct child of Downloads');
  }
  const browser = values.get('browser') ?? CHROME.find((p) => existsSync(p));
  if (!browser || !existsSync(browser) || !statSync(browser).isFile()) {
    throw new Error('the specified Chrome binary is not an existing file');
  }
  return {
    expectedHead, artifactDir: required('artifact-dir'), image: required('image'), imageId,
    rpcPort, p2pPort, outputDir, browser,
  };
}

function command(file, args, timeout = 30_000) {
  const result = spawnSync(file, args, { cwd: REPO, encoding: 'utf8', timeout, windowsHide: true });
  if (result.status !== 0 || result.error) {
    throw new Error(`${file} ${String(args[0]).slice(0, 40)} failed: `
      + String(result.stderr || result.error?.message || `exit ${result.status}`).slice(0, 350));
  }
  return result.stdout.trim();
}
const wsl = (args, timeout) => command('wsl.exe', ['-d', WSL, '--exec', ...args], timeout);

function preflight(options) {
  const head = command('git', ['rev-parse', 'HEAD']);
  if (head !== options.expectedHead) throw new Error(`HEAD moved: ${head}`);
  if (command('git', ['branch', '--show-current']) !== 'browser-miner-phase1b') {
    throw new Error('the private runner requires the browser-miner-phase1b branch');
  }
  // Ordinary porcelain deliberately does NOT enumerate the user's retypes/ directory. These two
  // untracked entries are user-owned and never opened, staged, ignored, cleaned or modified here.
  const status = command('git', ['status', '--porcelain']);
  const entries = status.split(/\r?\n/).filter(Boolean);
  if (entries.some((line) => line !== '?? .wakatime-project' && line !== '?? retypes/')) {
    throw new Error('tracked or unfamiliar untracked repository changes appeared');
  }
  const imageId = wsl(['docker', 'image', 'inspect', options.image, '--format', '{{.Id}}']);
  if (imageId !== options.imageId) throw new Error('Docker image tag does not resolve to the pinned ID');
  const existing = wsl(['docker', 'ps', '-a', '--format', '{{.Names}}'])
    .split(/\r?\n/).filter((name) => name.startsWith('meepcoin-private-'));
  if (existing.length) throw new Error('an earlier private MeepCoin container still exists');
  if (wsl(['ps', '-eo', 'comm=']).split(/\r?\n/).some((name) => name.trim() === 'meepcoind')) {
    throw new Error('an existing WSL meepcoind is running');
  }
  const windowsDaemons = command('powershell.exe', ['-NoProfile', '-Command',
    '@(Get-Process -Name meepcoind -ErrorAction SilentlyContinue).Count']);
  if (windowsDaemons !== '0') throw new Error('an existing Windows meepcoind is running');
  const manifest = wsl(['cat', '--', `${options.artifactDir}/BUILD_MANIFEST.txt`]);
  const hashes = {};
  for (const relative of REQUIRED_ARTIFACTS) {
    const row = manifest.split(/\r?\n/).find((line) => line.trim().startsWith(`${relative} `));
    const digest = row && /= ([0-9a-f]{64})\s*$/.exec(row)?.[1];
    if (!digest) throw new Error(`build manifest lacks ${relative}`);
    const actual = wsl(['sha256sum', '--', `${options.artifactDir}/${relative}`]).split(/\s+/)[0];
    if (actual !== digest) throw new Error(`build artifact digest differs: ${relative}`);
    hashes[relative] = actual;
  }
  const listen = wsl(['ss', '-H', '-ltn']);
  if ([options.rpcPort, options.p2pPort].some((p) => new RegExp(`:${p}\\s`).test(listen))) {
    throw new Error('a selected daemon port is already listening in WSL');
  }
  const winPorts = command('powershell.exe', ['-NoProfile', '-Command',
    `@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in ${options.rpcPort},${options.p2pPort} }).Count`]);
  if (winPorts !== '0') throw new Error('a selected daemon port is already listening on Windows');
  return { head, imageId, artifacts: hashes, trackedClean: true, privateContainersAtStart: 0 };
}

function reserve(path, payload) {
  const bytes = Buffer.from(JSON.stringify(payload, null, 2));
  const fd = openSync(path, 'wx', 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  const readback = readFileSync(path);
  if (!readback.equals(bytes)) throw new Error('one-use reservation readback differs');
  return createHash('sha256').update(bytes).digest('hex');
}

function ownedBrowser(label, binary) {
  const profileDir = mkdtempSync(join(tmpdir(), 'meep-two-browser-'));
  const child = spawn(binary, [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-background-networking', '--disable-component-update',
    '--disable-sync', `--user-data-dir=${profileDir}`, '--remote-debugging-port=0', 'about:blank',
  ], { stdio: ['ignore', 'pipe', 'pipe'], shell: false, windowsHide: true });
  const browser = { label, child, profileDir, exited: false, spawnError: null,
    stderr: '', cdp: null, frames: [], truncated: false, errors: [], screenshots: [] };
  // Own these events immediately: a spawn failure can precede connection setup.
  child.once('error', (err) => { browser.spawnError = String(err?.message ?? err).slice(0, 200); });
  child.stderr?.on('data', (chunk) => { browser.stderr = (browser.stderr + String(chunk)).slice(-4000); });
  child.once('exit', () => { browser.exited = true; });
  child.once('close', () => { browser.exited = true; });
  return browser;
}

async function connectBrowser(browser, url) {
  const endpoint = await new Promise((accept, reject) => {
    let settled = false;
    const done = (fn, value) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        browser.child.stderr?.off('data', onData);
        fn(value);
      }
    };
    const timer = setTimeout(() => done(reject, new Error(`${browser.label} DevTools timeout`)), 30_000);
    const onData = (chunk) => {
      const hit = /ws:\/\/127\.0\.0\.1:\d+\/devtools\/browser\/[0-9a-f-]+/i.exec(String(chunk));
      if (hit) done(accept, hit[0]);
    };
    if (browser.spawnError) { done(reject, new Error(browser.spawnError)); return; }
    if (browser.exited) { done(reject, new Error(`${browser.label} Chrome exited before DevTools`)); return; }
    const existing = /ws:\/\/127\.0\.0\.1:\d+\/devtools\/browser\/[0-9a-f-]+/i.exec(browser.stderr);
    if (existing) { done(accept, existing[0]); return; }
    browser.child.once('error', (err) => done(reject, err));
    browser.child.once('exit', (code) => done(reject, new Error(`${browser.label} Chrome exited ${code}`)));
    browser.child.stderr?.on('data', onData);
  });
  const root = connectCdp(endpoint);
  try {
    await root.ready;
    let page;
    const deadline = Date.now() + 5_000;
    do {
      const targets = (await root.send('Target.getTargets')).targetInfos.filter((t) => t.type === 'page');
      if (targets.length > 1) throw new Error(`${browser.label} unexpectedly opened more than one tab`);
      page = targets.find((t) => t.url === 'about:blank');
      if (!page) await sleep(50);
    } while (!page && Date.now() < deadline);
    if (!page) throw new Error(`${browser.label} has no blank initial page`);
    browser.cdp = connectCdp(endpoint.replace(/\/devtools\/browser\/.*$/, `/devtools/page/${page.targetId}`));
    await browser.cdp.ready;
  } finally { root.close(); }
  const cdp = browser.cdp;
  cdp.onEvent((method, params) => {
    if (method === 'Network.webSocketFrameReceived') {
      try {
        const frame = JSON.parse(params.response?.payloadData ?? '');
        if (browser.frames.length < MAX_FRAMES) browser.frames.push(frame);
        else browser.truncated = true;
      } catch { if (browser.errors.length < 20) browser.errors.push('unparseable WebSocket frame'); }
    }
    if (method === 'Runtime.exceptionThrown' && browser.errors.length < 20) {
      browser.errors.push(String(params.exceptionDetails?.text ?? 'page exception').slice(0, 200));
    }
  });
  await Promise.all([cdp.send('Network.enable'), cdp.send('Page.enable'), cdp.send('Runtime.enable')]);
  await cdp.send('Page.navigate', { url });
}

async function waitUntil(fn, label, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await fn()) return;
    if (Date.now() >= deadline) throw new Error(`timed out waiting for ${label}`);
    await sleep(100);
  }
}

async function pageSnapshot(browser) {
  return evaluate(browser.cdp, `(() => {
    const el = (id) => document.getElementById(id);
    const txt = (id) => el(id)?.textContent?.trim() ?? null;
    return { state: el('state')?.dataset?.state ?? null, connected: txt('connection'),
      startDisabled: el('start-btn')?.disabled ?? null, jobId: txt('job-id'),
      hashes: txt('hashes'), outcome: txt('real-outcome'), error: txt('error') };
  })()`);
}

async function screenshot(browser, outputDir, phase) {
  if (phase === 'after') {
    // Put the result readout in the pixels, not only in the JSON snapshot. This is a throwaway
    // profile; no user tab is moved and no second Start is issued.
    await evaluate(browser.cdp,
      "document.getElementById('state').scrollIntoView({ block: 'start', behavior: 'instant' }); true");
    await sleep(100);
  }
  const name = `${browser.label}-${phase}.png`;
  const path = join(outputDir, name);
  const result = await browser.cdp.send('Page.captureScreenshot', { format: 'png' });
  const bytes = Buffer.from(result.data, 'base64');
  writeFileSync(path, bytes, { flag: 'wx' });
  const digest = createHash('sha256').update(readFileSync(path)).digest('hex');
  browser.screenshots.push({ name, bytes: bytes.length, sha256: digest });
}

async function stopBrowsersOnce(browsers) {
  for (const browser of browsers) { try { browser.cdp?.close(); } catch { /* already gone */ } }
  for (const browser of browsers) {
    if (browser.child && !browser.exited && browser.child.pid) {
      const exit = new Promise((done) => browser.child.once('exit', done));
      browser.child.kill();
      await Promise.race([exit, sleep(5_000)]);
      if (!browser.exited) { browser.child.kill('SIGKILL'); await Promise.race([exit, sleep(5_000)]); }
    }
    // Recursive removal is limited to this run's exact generated throwaway profile, not a caller
    // path, Downloads, the repository, or any broad parent directory.
    const dir = resolve(browser.profileDir);
    const parent = resolve(tmpdir());
    if (browser.exited && dirname(dir).toLowerCase() === parent.toLowerCase()
      && basename(dir).startsWith('meep-two-browser-')) {
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    }
  }
}
let browserStopPromise = null;
const stopBrowsers = (browsers) => {
  browserStopPromise ??= stopBrowsersOnce(browsers);
  return browserStopPromise;
};

let options;
try { options = parseArgs(process.argv.slice(2)); }
catch (err) { console.error(`USAGE REFUSED: ${err.message}`); process.exit(2); }
const runId = randomBytes(8).toString('hex');
let config;
let pre;
try {
  config = checkDaemonConfig({ wslDistro: WSL, image: options.image,
    expectedImageId: options.imageId, artifactDir: options.artifactDir,
    runDir: `/home/tseng/meepcoin-private-run-${runId}`,
    rpcPort: options.rpcPort, p2pPort: options.p2pPort, uid: 1000, gid: 1000 });
  pre = preflight(options);
} catch (err) { console.error(`PREFLIGHT REFUSED: ${err.message}`); process.exit(2); }

mkdirSync(options.outputDir, { mode: 0o700 });
const reservationPath = join(options.outputDir, 'RESERVATION.json');
const evidencePath = join(options.outputDir, 'EVIDENCE.json');
const evidence = { schema: 'meepcoin-private-two-browser-acceptance/1', runId, startedAt: now(),
  expectedHead: options.expectedHead, image: options.image, imageId: options.imageId,
  artifactDir: options.artifactDir, daemonRunDir: config.runDir,
  ports: { rpc: options.rpcPort, p2p: options.p2pPort }, preflight: pre,
  bounds: { browsers: 2, startsPerBrowser: 1, maxAttempts: REAL_SEARCH_LIMITS.maxAttempts,
    maxSearchMs: REAL_SEARCH_LIMITS.maxSearchMs, automaticRetry: false }, events: [] };
const note = (kind, value) => {
  if (evidence.events.length < MAX_LOGS) evidence.events.push({ at: now(), kind, value });
  console.log(`${kind}: ${JSON.stringify(value).slice(0, 500)}`);
};
try {
  evidence.reservationSha256 = reserve(reservationPath, {
    schema: 'meepcoin-one-use-reservation/1', runId, createdAt: now(),
    expectedHead: options.expectedHead, expectedImageId: options.imageId,
    outputDir: options.outputDir, noRetry: true,
  });
} catch (err) { console.error(`RESERVATION FAILED: ${err.message}`); process.exit(2); }

const browsers = [];
let poolAtTerminal = null;
let browserAtTerminal = null;
let cleanupDetails = null;
let finalAdjudication = null;
const lifecycle = createRunLifecycle({ startPool: startDevPool, exit: (code) => { process.exitCode = code; },
  note,
  persistEvidence: ({ exitCode, cancelledBy, cleanup }) => {
    const pool = lifecycle.pool;
    const adjudication = finalAdjudication ?? adjudicateTwoBrowser({
      browsers: browsers.map((b) => ({ frames: b.frames, truncated: b.truncated })),
      poolState: pool?.twoSlotState ?? null,
      poolEvidence: pool?.twoSlotEvidence ?? null,
      cleanup: { released: cleanup.released },
    });
    Object.assign(evidence, { endedAt: now(), exitCode, cancelledBy, adjudication,
      browserAtTerminal, poolAtTerminal, poolFinal: pool ? {
        twoSlotState: pool.twoSlotState, twoSlotEvidence: pool.twoSlotEvidence,
      } : null,
      browsers: browsers.map((b) => ({ label: b.label, pid: b.child?.pid ?? null,
        frames: b.frames, truncated: b.truncated, errors: b.errors,
        screenshots: b.screenshots, exited: b.exited })),
      cleanup, cleanupDetails });
    return persistJsonAtomically(evidencePath, evidence, {
      noReplace: true, expect: { schema: evidence.schema, runId, exitCode },
    });
  },
});
lifecycle.installSignalHandlers();
lifecycle.onCancel(() => { void stopBrowsers(browsers); });

await lifecycle.run(async (run) => {
  note('live-start', 'one offline daemon and two headless throwaway Chrome processes; no wallet');
  const pool = await run.startPool({ host: '127.0.0.1', port: 0,
    mode: REAL_DAEMON_MODE, realDaemon: { daemon: config, personalizeTemplates: true },
    twoSlotAssignments: true, wslDistro: WSL, log: (event) => note('pool-event', event) });
  note('pool-listening', { url: pool.url, daemon: pool.twoSlotEvidence?.daemon });
  for (const label of ['A', 'B']) {
    run.throwIfCancelled();
    const browser = ownedBrowser(label, options.browser);
    browsers.push(browser);
    await connectBrowser(browser, pool.url);
  }
  await Promise.all(browsers.map((browser) => waitUntil(async () => {
    const page = await pageSnapshot(browser);
    return page.connected === 'connected' && page.startDisabled === false;
  }, `${browser.label} Start readiness`)));
  for (const browser of browsers) await screenshot(browser, options.outputDir, 'before');
  note('browser-start', 'pressing Start exactly once in each real browser page');
  await Promise.all(browsers.map((browser) => evaluate(browser.cdp,
    "document.getElementById('start-btn').click(); true")));
  await waitUntil(() => browsers.every((browser) =>
    browser.frames.some((frame) => TERMINAL.has(frame?.type))),
  'both browser terminals', REAL_SEARCH_LIMITS.maxSearchMs + 90_000);
  await waitUntil(() => pool.twoSlotState?.active === 0, 'both assignment releases', 30_000);
  browserAtTerminal = await Promise.all(browsers.map((browser) => pageSnapshot(browser)));
  poolAtTerminal = { state: pool.twoSlotState, evidence: pool.twoSlotEvidence };
  for (const browser of browsers) await screenshot(browser, options.outputDir, 'after');
  const preliminary = adjudicateTwoBrowser({
    browsers: browsers.map((b) => ({ frames: b.frames, truncated: b.truncated, errors: b.errors })),
    poolState: pool.twoSlotState, poolEvidence: pool.twoSlotEvidence,
    cleanup: { released: true },
  });
  note('pre-cleanup-verdict', preliminary);
  return preliminary.ok ? 0 : 1;
}, {
  beforePoolClose: () => stopBrowsers(browsers),
  afterPoolClose: async ({ poolStarted, poolShutdown, poolListenerClosed }) => {
    const pool = lifecycle.pool;
    const daemon = pool?.twoSlotEvidence?.daemon;
    let containerGone = false;
    let portsFree = false;
    let windowsPortsFree = false;
    try {
      const containers = wsl(['docker', 'ps', '-a', '--format', '{{.Names}}'])
        .split(/\r?\n/).filter((name) => name.startsWith('meepcoin-private-'));
      containerGone = containers.length === 0;
      const listen = wsl(['ss', '-H', '-ltn']);
      portsFree = ![options.rpcPort, options.p2pPort]
        .some((p) => new RegExp(`:${p}\\s`).test(listen));
      const winPorts = command('powershell.exe', ['-NoProfile', '-Command',
        `@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in ${options.rpcPort},${options.p2pPort} }).Count`]);
      windowsPortsFree = winPorts === '0';
    } catch { /* observation failure means not released */ }
    const profilesGone = browsers.every((b) => b.exited && !existsSync(b.profileDir));
    cleanupDetails = { poolStarted, poolShutdown, poolListenerClosed,
      daemon, containerGone, portsFree, windowsPortsFree, profilesGone,
      browserPids: browsers.map((b) => ({ label: b.label, pid: b.child?.pid ?? null, exited: b.exited })),
    };
    note('release-observation', cleanupDetails);
    const released = containerGone && portsFree && windowsPortsFree && profilesGone;
    finalAdjudication = adjudicateTwoBrowser({
      browsers: browsers.map((b) => ({ frames: b.frames, truncated: b.truncated, errors: b.errors })),
      poolState: pool?.twoSlotState ?? null, poolEvidence: pool?.twoSlotEvidence ?? null,
      cleanup: { released: released && (!poolStarted || (poolShutdown?.ok === true
        && poolShutdown?.physicalReleaseConfirmed === true && poolListenerClosed === true)) },
    });
    return { released, outcomeCode: finalAdjudication.ok ? 0 : 1 };
  },
  onBodyError: (err) => { note('run-failed', { code: err?.code ?? null, message: String(err?.message ?? err).slice(0, 400) }); },
});
