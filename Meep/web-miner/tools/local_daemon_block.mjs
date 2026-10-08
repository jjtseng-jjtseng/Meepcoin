// ONE real-local-daemon vertical run, in a real browser. Run once; it does not retry anything.
//
//   node web-miner/tools/local_daemon_block.mjs --artifact-dir <WSL artifact dir, optional /out> --image <tag>
//        --rpc-port <n> --p2p-port <n> [--browser <path>] [--evidence <file>]
//        [--coinbase-address <addr>] [--keep-chain (requires --evidence)]
//
// --coinbase-address is TRUSTED LOCAL STARTUP CONFIGURATION: this process's own argv, chosen by the
// operator who starts it. It reaches the daemon's get_block_template and nothing else; no page,
// message, query string or share can set or change it. Omit it and the committed neutral dev/test
// address is still the destination. The shape is checked here before anything is started; the daemon
// itself decides whether the address parses on this network, before the listener exists.
//
// --keep-chain leaves the daemon's data directory in place (mode 0700) instead of deleting it, for a
// follow-on round that must read the chain this run produced. Without it the chain is deleted as
// before. It REQUIRES --evidence, because a retained chain whose hashes exist only in this console
// cannot be compared against later. Retention counts as released only when the run directory's
// identity still matches, the tightening is READ BACK as mode with no group/other bits and owner
// uid:gid, and the discovered inventory is EXACTLY <data root>/testnet/lmdb/{data,lock}.mdb -- no
// extra file of ANY kind, no duplicate, no path outside the root, no odd spelling
// (retained_chain.mjs). Discovery enumerates every regular file, not just *.mdb, and an identity
// mismatch runs no command at all against the unverified path.
//
// WHAT IT OWNS, AND CLOSES ON EVERY OUTCOME
//   * one pool listener on an ephemeral loopback port, in real-local-daemon mode, which itself owns:
//       - ONE private offline meepcoind (the fresh artifact, in its build image, numeric loopback),
//       - the native helper, started only by Start;
//   * one headless browser with one throwaway profile directory.
// After closing it checks, independently of the pool's own confirmation, that the exact daemon
// container, the exact helper PID and the two daemon ports are gone, then removes ONLY the throwaway
// profile and the daemon's disposable data directory, each after validating its identity. The daemon
// log is kept outside Git and its SHA-256 recorded.
//
// WHAT IT DOES NOT DO: widen the frozen bounds (8,192 nonces, 120 s), supply a nonce, retry a
// submission, lower a target, touch a wallet, or contact anything but loopback.
//
// LAUNCH IT ARGUMENT-NATIVELY (PowerShell or Node, never Git Bash, whose path conversion rewrites
// `/home/...` arguments), and propagate its exit code: `node web-miner/tools/local_daemon_block.mjs
// ...; exit $LASTEXITCODE`. Exit 0 only for an accepted block with confirmed cleanup (and, when
// --evidence is given, that file persisted and read back).
//
// INTERRUPTION (live_run_lifecycle.mjs). SIGINT (Ctrl-C) and SIGTERM set cancellation once and abort a
// startup still in progress; they never exit by themselves. The one finalization path waits for that
// startup to settle, closes what it produced, runs the cleanup once and exits 130 / 143 (3 if release
// was not confirmed). A hard termination (SIGKILL, closing the console window, a crash of Node itself)
// cannot be handled by any code in this process; the pool's owned resources would then need the
// recorded container name and run directory to be cleaned up by hand.
//
// EXIT CODES: 0 success; 1 any other outcome; 2 usage; 3 release unconfirmed; 4 the run succeeded but
// the requested evidence file could not be persisted and verified; 130 / 143 cancelled.

import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { startDevPool } from '../../pool/dev/server.mjs';
import { REAL_COINBASE_ADDRESS, coinbaseAddressShapeProblem } from '../../pool/dev/real_daemon_mode.mjs';
import { SIM_ATTEMPT_STATES } from '../../pool/dev/sim_session.mjs';
import { REAL_DAEMON_MODE, REAL_SEARCH_LIMITS } from '../lib/shared/protocol.js';
import { EXIT_CODES, createRunLifecycle, persistJsonAtomically } from './live_run_lifecycle.mjs';
import { connectCdp, evaluate } from './cdp_client.mjs';
import { collectRetainedChain } from './retained_chain.mjs';
import { evaluateRelease } from './release_decision.mjs';

const CANDIDATES = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
];
const WSL_DISTRO = 'Ubuntu';

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => new Date().toISOString();

function wsl(args, timeout = 60_000) {
  const r = spawnSync('wsl.exe', ['-d', WSL_DISTRO, '--exec', ...args], { encoding: 'utf8', timeout, windowsHide: true });
  return { status: r.status, stdout: String(r.stdout ?? ''), stderr: String(r.stderr ?? '') };
}

// ---------------------------------------------------------------- configuration
const artifactDir = arg('artifact-dir');
const image = arg('image');
const rpcPort = Number(arg('rpc-port'));
const p2pPort = Number(arg('p2p-port'));
const browserPath = arg('browser', CANDIDATES.find((p) => existsSync(p)));
const evidencePath = arg('evidence', null);
const coinbaseAddress = arg('coinbase-address', null);
const keepChain = process.argv.includes('--keep-chain');
if (!artifactDir || !image || !Number.isInteger(rpcPort) || !Number.isInteger(p2pPort) || !browserPath) {
  console.error('usage: --artifact-dir <dir> --image <tag> --rpc-port <n> --p2p-port <n> [--browser <path>]'
    + ' [--evidence <file>] [--coinbase-address <addr>] [--keep-chain (requires --evidence)]');
  process.exit(EXIT_CODES.USAGE);
}
// A retained chain whose hashes exist only in this console is not retained evidence: the next round
// would have nothing to compare against. --keep-chain therefore REQUIRES a durable evidence file.
if (keepChain && evidencePath === null) {
  console.error('--keep-chain requires --evidence <file>: the retained chain hashes must be persisted, not printed');
  process.exit(EXIT_CODES.USAGE);
}
// Cheap, local and FIRST: a malformed destination stops here, before a container, profile, browser,
// Worker, dataset, verifier or hash exists.
if (coinbaseAddress !== null) {
  const problem = coinbaseAddressShapeProblem(coinbaseAddress);
  if (problem !== null) { console.error(`--coinbase-address: ${problem}`); process.exit(EXIT_CODES.USAGE); }
}
const runDir = `/home/tseng/meepcoin-private-run-${randomBytes(8).toString('hex')}`;
const daemonConfig = { wslDistro: WSL_DISTRO, image, artifactDir, runDir, rpcPort, p2pPort, uid: 1000, gid: 1000 };

const evidence = {
  startedAt: now(), bounds: REAL_SEARCH_LIMITS, daemonConfig, keepChain, outcome: null, events: [],
  coinbaseDestination: {
    requested: coinbaseAddress, effective: coinbaseAddress ?? REAL_COINBASE_ADDRESS,
    source: coinbaseAddress === null ? 'committed neutral default' : 'trusted startup argv',
  },
};
const note = (label, value) => { evidence.events.push({ at: now(), label, value }); console.log(`${label.padEnd(34)} ${typeof value === 'string' ? value : JSON.stringify(value)}`); };

let chrome = null;
let chromeExited = false;
let cdp = null;
let profileDir = null;
let daemonFacts = null;
let helperFacts = null;

const lifecycle = createRunLifecycle({
  startPool: startDevPool,
  exit: (code) => process.exit(code),
  note,
  // SUPPLIED MEANS REQUIRED: a requested evidence file that cannot be persisted fails the run.
  persistEvidence: evidencePath === null ? null : ({ exitCode }) => {
    evidence.finishedAt = now();
    evidence.exitCode = exitCode;
    const r = persistJsonAtomically(evidencePath, evidence, {
      expect: { exitCode, finishedAt: evidence.finishedAt, outcome: evidence.outcome },
    });
    console.log(`${'evidence file'.padEnd(34)} ${JSON.stringify(r)}`);
    return r;
  },
});
lifecycle.installSignalHandlers(process);
lifecycle.onCancel(() => { try { cdp?.close(); } catch { /* gone */ } try { chrome?.kill(); } catch { /* gone */ } });

async function waitUntil(fn, { timeoutMs, everyMs = 100, label }) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    lifecycle.throwIfCancelled();
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await sleep(everyMs);
  }
}

async function stopBrowser() {
  try { cdp?.close(); } catch { /* gone */ }
  if (chrome && !chromeExited) {
    const exited = new Promise((r) => chrome.once('exit', () => { chromeExited = true; r(); }));
    chrome.kill();
    await Promise.race([exited, sleep(5000)]);
    if (!chromeExited) { chrome.kill('SIGKILL'); await Promise.race([exited, sleep(5000)]); }
  }
}

async function observeRelease({ poolStarted, poolShutdown, poolListenerClosed }) {
  const c = { poolStarted, poolShutdown, poolListenerClosed };
  c.browserExited = chrome ? chromeExited : 'not started';
  c.browserPid = chrome?.pid ?? null;
  // Independent observations after the pool's own confirmation. Any container that mounts THIS run's
  // directory -- found by its unique path, whether or not startup got far enough to report a name.
  {
    const byMount = wsl(['docker', 'ps', '-a', '--no-trunc', '--filter', `volume=${runDir}`, '--format', '{{.Names}}']);
    c.containersMountingRunDir = byMount.status === 0 ? byMount.stdout.trim().split('\n').filter(Boolean) : null;
  }
  if (daemonFacts?.containerName) {
    const ps = wsl(['docker', 'ps', '-a', '--no-trunc', '--filter', `name=^/${daemonFacts.containerName}$`, '--format', '{{.ID}}']);
    c.daemonContainerGone = ps.status === 0 && ps.stdout.trim() === '';
  }
  if (daemonFacts?.linuxPid) {
    const ls = wsl(['ls', '-1', '-d', '--', '/proc/self', `/proc/${daemonFacts.linuxPid}`]);
    c.daemonPidGone = ls.stdout.includes('/proc/self') && !ls.stdout.includes(`/proc/${daemonFacts.linuxPid}\n`);
  }
  if (helperFacts?.linuxPid) {
    const ls = wsl(['ls', '-1', '-d', '--', '/proc/self', `/proc/${helperFacts.linuxPid}`]);
    c.helperPidGone = ls.stdout.includes('/proc/self') && !ls.stdout.includes(`/proc/${helperFacts.linuxPid}\n`);
  }
  const ss = wsl(['ss', '-H', '-ltn']);
  c.daemonPortsFree = ss.status === 0
    && !new RegExp(`:(${rpcPort}|${p2pPort})\\s`).test(ss.stdout);
  // Disposable paths, identity-checked.
  if (profileDir) {
    const safe = resolve(profileDir).startsWith(resolve(tmpdir())) && /meep-daemon-block-/.test(profileDir);
    if (safe) { try { rmSync(profileDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* reported */ } }
    c.profileRemoved = !existsSync(profileDir);
  }
  if (daemonFacts?.runDirIdentity) {
    const st = wsl(['stat', '-c', '%d:%i:%u', '--', runDir]);
    const same = st.status === 0 && st.stdout.trim() === daemonFacts.runDirIdentity;
    c.runDirIdentityMatched = same;
    // IDENTITY MISMATCH SHORT-CIRCUITS EVERY READ OF THAT PATH. This used to hash the daemon log --
    // and, under --keep-chain, find/hash and stat the tree -- against a directory already known not
    // to be the daemon's. Nothing below aims a command at an unverified path.
    if (same) {
      const log = wsl(['sha256sum', '--', `${runDir}/meepcoind.log`]);
      c.daemonLog = log.status === 0 ? { path: `${runDir}/meepcoind.log`, sha256: log.stdout.split(/\s+/)[0] } : null;
    } else {
      c.daemonLog = null;
      c.daemonLogSkipped = 'run-directory identity did not match';
    }
    if (keepChain) {
      // Deliberately retained for a follow-on round. Tightened to 0700 and hashed, never committed.
      // Retention only counts as released if identity, tightening, discovery and the EXACT inventory
      // ALL hold -- see retained_chain.mjs. Anything less fails closed below.
      c.daemonDataRemoved = 'kept by --keep-chain';
      const { record, commands } = collectRetainedChain({
        run: wsl,
        runDir,
        dataRoot: `${runDir}/data`,
        identityMatched: same,
        evidenceRequested: evidencePath !== null,
        owner: { uid: daemonConfig.uid, gid: daemonConfig.gid },
      });
      c.daemonDataKept = record;
      c.daemonDataKeptCommands = commands.map((a) => a[0]);
      if (!record.ok) note('RETAINED CHAIN NOT CONFIRMED', record.problems);
    } else if (same && c.daemonContainerGone) {
      const rm = wsl(['rm', '-rf', '--', `${runDir}/data`]);
      c.daemonDataRemoved = rm.status === 0 && wsl(['ls', '-d', '--', `${runDir}/data`]).status !== 0;
    } else {
      c.daemonDataRemoved = false;
    }
  }
  evidence.cleanup = c;
  console.log(`cleanup                            ${JSON.stringify(c)}`);
  // With --keep-chain, retention must be positively confirmed: an absent record (no run-dir identity
  // was ever established) is a failure, not a pass. The predicate is pure and tested.
  const { released, blockers } = evaluateRelease({ cleanup: c, keepChain });
  if (!released) note('RELEASE NOT CONFIRMED', blockers);
  evidence.releaseBlockers = blockers;
  return { released };
}

lifecycle.run(async () => {
  note('mode', REAL_DAEMON_MODE);
  note('FROZEN BOUNDS (before Start)', `at most ${REAL_SEARCH_LIMITS.maxAttempts} browser attempts, at most ${REAL_SEARCH_LIMITS.maxSearchMs / 1000} s, one Worker, one candidate, one submit_block, zero retry`);
  note('daemon run dir', runDir);
  note('coinbase destination', evidence.coinbaseDestination);

  const pool = await lifecycle.startPool({
    host: '127.0.0.1',
    port: 0,
    mode: REAL_DAEMON_MODE,
    wslDistro: WSL_DISTRO,
    realDaemon: {
      daemon: daemonConfig,
      personalizeTemplates: true,
      ...(coinbaseAddress === null ? {} : { walletAddress: coinbaseAddress }),
    },
  });
  const sim = pool.simulation;
  const dr = sim.daemonResource;
  daemonFacts = { containerName: dr.containerName, linuxPid: dr.linuxPid, runDirIdentity: dr.runDirIdentity };
  note('pool', `${pool.url} (pid ${process.pid})`);
  note('daemon container', dr.containerName);
  note('daemon linux pid', dr.linuxPid);
  note('daemon launch argv', dr.launchArgs);
  note('daemon listeners (proved)', dr.listeners);
  note('rpc endpoint', sim.rpcEndpoint);
  note('fresh template', sim.templateFacts);

  lifecycle.throwIfCancelled();
  profileDir = mkdtempSync(join(tmpdir(), 'meep-daemon-block-'));
  note('throwaway profile', profileDir);
  chrome = spawn(browserPath, [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-extensions',
    '--disable-background-networking', '--disable-component-update', '--disable-sync',
    `--user-data-dir=${profileDir}`, '--remote-debugging-port=0', 'about:blank',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  chrome.once('exit', () => { chromeExited = true; });
  chrome.stdout.on('data', () => {});
  let devtoolsUrl = null;
  chrome.stderr.on('data', (buf) => {
    const m = /ws:\/\/127\.0\.0\.1:\d+\/devtools\/browser\/[0-9a-f-]+/i.exec(buf.toString());
    if (m && !devtoolsUrl) devtoolsUrl = m[0];
  });
  await waitUntil(() => devtoolsUrl, { timeoutMs: 30_000, label: 'DevTools' });
  note('browser pid', chrome.pid);
  const browserCdp = connectCdp(devtoolsUrl);
  await browserCdp.ready;
  const { targetId } = await browserCdp.send('Target.createTarget', { url: 'about:blank' });
  cdp = connectCdp(devtoolsUrl.replace(/\/devtools\/browser\/.*$/, `/devtools/page/${targetId}`));
  await cdp.ready;
  browserCdp.close();
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  const pageErrors = [];
  cdp.onEvent((method, params) => { if (method === 'Runtime.exceptionThrown') pageErrors.push(params.exceptionDetails?.text ?? 'exception'); });

  await cdp.send('Page.navigate', { url: pool.url });
  await waitUntil(() => evaluate(cdp, 'document.readyState === "complete"'), { timeoutMs: 30_000, label: 'page load' });
  await waitUntil(() => evaluate(cdp, '!!document.getElementById("real-banner") && !document.getElementById("real-banner").hidden'),
    { timeoutMs: 30_000, label: 'the real-daemon banner' });
  const before = await evaluate(cdp, '({ hashes: document.getElementById("hashes").textContent.trim(), start: document.getElementById("start-btn").textContent.trim(), window: document.getElementById("real-window").textContent.trim() })');
  note('page before Start', before);
  note('server before Start', { verifierAbsent: sim.verifier === null, counters: { ...sim.counters }, daemon: { ...sim.submissionDaemon.counters } });

  // ---- THE ONE START ---------------------------------------------------------------------------
  lifecycle.throwIfCancelled();
  note('Start clicked', now());
  await evaluate(cdp, 'document.getElementById("start-btn").click()');
  await waitUntil(() => [SIM_ATTEMPT_STATES.TERMINAL_COMPLETE, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED, SIM_ATTEMPT_STATES.TERMINAL_FAILED]
    .includes(sim.attemptState), { timeoutMs: 400_000, everyMs: 250, label: 'the one attempt to finish' });
  await sleep(1500);   // the page receives and renders the terminal frame

  const ev = pool.simulationEvidence;
  helperFacts = ev ? { linuxPid: ev.helperLinuxPid, distro: ev.helperDistro } : null;
  const page = await evaluate(cdp, `(() => { const t = (id) => document.getElementById(id)?.textContent?.trim() ?? null; return {
    outcome: t('real-outcome'), searched: t('real-searched'), foundNonce: t('real-found-nonce'),
    browserHash: t('real-browser-hash'), serverHash: t('real-server-hash'), blockId: t('real-block-id'),
    counters: t('real-counters'), note: t('controls-note'), state: t('state'), error: t('error'),
    height: t('real-height'), window: t('real-window'), workers: t('real-workers'), blocks: t('real-blocks'),
    startDisabled: document.getElementById('start-btn').disabled }; })()`);
  const result = {
    attemptState: sim.attemptState,
    attemptReason: sim.attemptReason,
    serverCounters: { ...sim.counters },
    daemonCounters: { ...sim.submissionDaemon.counters },
    verifierCounters: ev?.verifierCounters ?? null,
    helper: ev ? { pid: ev.helperLinuxPid, distro: ev.helperDistro, sourceId: ev.helperSourceId } : null,
    page,
    pageErrors,
  };
  note('RESULT', result);

  // Canonical top, read directly once more for the record (read-only).
  if (sim.attemptState === SIM_ATTEMPT_STATES.TERMINAL_COMPLETE) {
    const top = await sim.submissionDaemon.submissionAdapter.getLastBlockHeader({ fillPowHash: true });
    const atHeight = await sim.submissionDaemon.submissionAdapter.getBlockHeaderByHeight(sim.templateFacts.height, { fillPowHash: true });
    note('independent readback: top', top);
    note('independent readback: height', atHeight);
  }
  note('daemon established connections', await dr.observeConnections());
  evidence.outcome = sim.attemptState === SIM_ATTEMPT_STATES.TERMINAL_COMPLETE ? 'BLOCK_ACCEPTED' : `FAILED:${sim.attemptReason}`;
  return sim.attemptState === SIM_ATTEMPT_STATES.TERMINAL_COMPLETE ? EXIT_CODES.OK : EXIT_CODES.FAILED;
}, {
  beforePoolClose: stopBrowser,
  afterPoolClose: observeRelease,
  onBodyError: (err) => {
    note('RUN ERROR', String(err?.message ?? err).slice(0, 400));
    if (err?.retainedResources) note('retained after startup failure', err.retainedResources.map((r) => r.label));
    if (evidence.outcome === null) evidence.outcome = 'FAILED:run_error';
  },
});
