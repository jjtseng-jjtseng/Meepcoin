#!/usr/bin/env node
// One one-use, fresh-genesis, two-peer arm with three measured Wasm miners.
// The command never builds a daemon, creates a wallet, touches a transaction, or uses a public peer.

import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createServer } from 'node:net';
import { createWriteStream, mkdirSync, openSync, closeSync, readFileSync, writeFileSync } from 'node:fs';
import { Worker } from 'node:worker_threads';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { DAEMON_LIMITS, DAEMON_PROFILES, checkDaemonConfig, startLocalDaemon } from '../pool/dev/local_daemon.mjs';
import { REACHABILITY_MODES, ASSIGNED_HASHES_PER_SECOND, assignedThirdShare } from './fresh_reachability_core.mjs';
import { sourcePreflight, linked, post, info, header, headers, genesisGate } from './honest_launch_pilot.mjs';

const HEX64 = /^[0-9a-f]{64}$/;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/;
const RUN_ID = /^[a-z][a-z0-9-]{7,63}$/;
const SAMPLE_MS = 15_000;
const LINK_WAIT_MS = 60_000;
const MAX_GENESIS_AGE_S = 1800;
const HEIGHT_CAP = 90;
const POST_STOP_OBSERVE_MS = 10 * 60_000;
const WORKER_STOP_TIMEOUT_MS = 150_000;
// The honest pilot's daemon shutdown took about four minutes. Its generic 30-second
// probe timed out before Docker's stop completed, so this arm owns a longer bound.
const DAEMON_CLOSE_LIMITS = Object.freeze({ ...DAEMON_LIMITS,
  probeTimeoutMs: 390_000, stopGraceSeconds: 360, stopTimeoutMs: 420_000 });

function must(ok, why) { if (!ok) throw new Error(`reachability arm: ${why}`); }
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const sha = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
const execFileAsync = promisify(execFile);
const COMPETING_NAME = /^(?:p2pool|xmrig|monerod|meepcoind)(?:\.exe)?$/i;
// Capture receiver-side validation errors, including timestamp-median refusals.
// This affects diagnostic logging only; it does not change consensus or mining rules.
const RECEIVER_VERIFY_CATEGORIES = '*:WARNING,verify:ERROR,global:INFO';

export async function enableReceiverVerificationLog(port, send = post) {
  const response = await send(port, '/set_log_categories',
    { categories: RECEIVER_VERIFY_CATEGORIES });
  must(response?.status === 'OK' && response.categories === RECEIVER_VERIFY_CATEGORIES,
    `daemon ${port} did not confirm receiver verification logging`);
  return { port, categories: response.categories };
}

async function portFree(port) {
  const server = createServer();
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen({ host: '127.0.0.1', port, exclusive: true }, resolve);
    });
  } finally {
    if (server.listening) await new Promise((resolve) => server.close(resolve));
  }
}

// Read-only, fail-closed machine check before consuming the one-use reservation.
export async function environmentPreflight(cfg) {
  const { stdout: windows } = await execFileAsync('powershell.exe', ['-NoProfile', '-Command',
    "Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.Name -match '^(p2pool|xmrig|monerod|meepcoind)([.]exe)?$' } | Select-Object -ExpandProperty Name"],
  { windowsHide: true, timeout: 30_000, maxBuffer: 64 * 1024 });
  const { stdout: linux } = await execFileAsync('wsl.exe', ['-d', cfg.raw.wslDistro, '--exec',
    'ps', '-eo', 'comm='], { windowsHide: true, timeout: 30_000, maxBuffer: 1024 * 1024 });
  const found = [...windows.split(/\r?\n/), ...linux.split(/\r?\n/)]
    .map((name) => name.trim()).filter((name) => COMPETING_NAME.test(name));
  must(found.length === 0, `competing miner process present: ${found.join(',')}`);
  const { stdout: containers } = await execFileAsync('wsl.exe', ['-d', cfg.raw.wslDistro, '--exec',
    'docker', 'ps', '--format', '{{.Names}}|{{.Image}}'],
  { windowsHide: true, timeout: 30_000, maxBuffer: 1024 * 1024 });
  must(!containers.split(/\r?\n/).some((line) => /meepcoin/i.test(line)),
    'an existing MeepCoin container is running');
  for (const port of Object.values(cfg.raw.ports)) await portFree(port);
  return { checkedAtUtc: new Date().toISOString(), competingMinerCount: 0,
    meepcoinContainerCount: 0, privatePortsFree: Object.values(cfg.raw.ports) };
}

async function copyOwnedLog({ distro, runDir, destination }) {
  const { stdout } = await execFileAsync('wsl.exe', ['-d', distro, '--exec', 'cat', '--',
    `${runDir}/meepcoind.log`], { encoding: 'buffer', windowsHide: true, timeout: 30_000,
    maxBuffer: 32 * 1024 * 1024 });
  must(Buffer.isBuffer(stdout) && stdout.length > 0, 'owned daemon log is empty or unavailable');
  writeFileSync(destination, stdout, { flag: 'wx', mode: 0o600 });
  return { bytes: stdout.length, sha256: sha(destination) };
}

export function validateReachabilityConfig(raw) {
  const keys = [
    'arm', 'artifactDir', 'budgetSeconds', 'buildManifestSha256', 'evidenceDir', 'expectedImageId',
    'genesisHash', 'genesisTimestamp', 'gid', 'image', 'pairId', 'ports', 'repoCommit', 'runId',
    'uid', 'variantId', 'wslDistro',
  ];
  must(raw && typeof raw === 'object' && !Array.isArray(raw)
    && Object.keys(raw).sort().join('|') === keys.sort().join('|'), 'config keys differ from the closed arm schema');
  must([REACHABILITY_MODES.CONTROL, REACHABILITY_MODES.ATTACK].includes(raw.arm), 'bad arm');
  must(RUN_ID.test(raw.runId) && RUN_ID.test(raw.pairId), 'bad run or pair ID');
  must(/^[0-9a-f]{40}$/.test(raw.repoCommit), 'bad repo commit');
  must(RUN_ID.test(raw.variantId), 'bad variant ID');
  must(Number.isSafeInteger(raw.genesisTimestamp) && raw.genesisTimestamp > 1785283200,
    'bad genesis timestamp');
  must(HEX64.test(raw.genesisHash) && HEX64.test(raw.buildManifestSha256), 'bad genesis/build hash');
  must(/^meepcoin-build:[a-z0-9][a-z0-9._-]{0,127}$/.test(raw.image) && IMAGE_ID.test(raw.expectedImageId),
    'bad pinned image');
  must(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/.test(raw.wslDistro), 'bad WSL distro');
  must(Number.isInteger(raw.uid) && raw.uid >= 1 && raw.uid <= 60000
    && Number.isInteger(raw.gid) && raw.gid >= 1 && raw.gid <= 60000, 'bad nonroot UID/GID');
  must(raw.ports && Object.keys(raw.ports).sort().join('|') === 'p2pA|p2pB|rpcA|rpcB'
    && new Set(Object.values(raw.ports)).size === 4, 'bad port map');
  for (const value of Object.values(raw.ports)) must(Number.isInteger(value) && value >= 1024 && value <= 65535,
    'bad private port');
  must(Number.isInteger(raw.budgetSeconds) && raw.budgetSeconds >= 3600 && raw.budgetSeconds <= 21600,
    'arm budget must be 1..6 hours');
  must(typeof raw.evidenceDir === 'string'
    && raw.evidenceDir === `C:\\Users\\tseng\\meepcoin-reachability-runs\\${raw.runId}`,
    'evidence path must be the exact fresh run directory');
  assignedThirdShare();
  const common = { wslDistro: raw.wslDistro, image: raw.image, artifactDir: raw.artifactDir,
    uid: raw.uid, gid: raw.gid, expectedImageId: raw.expectedImageId,
    profile: DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_NATURAL };
  const nonce = randomBytes(6).toString('hex');
  const daemonId = createHash('sha256').update(`${raw.runId}:${nonce}`).digest('hex').slice(0, 20);
  const a = checkDaemonConfig({ ...common, runDir: `/home/tseng/meepcoin-private-run-${daemonId}a`,
    rpcPort: raw.ports.rpcA, p2pPort: raw.ports.p2pA, exclusivePeerP2pPort: raw.ports.p2pB });
  const b = checkDaemonConfig({ ...common, runDir: `/home/tseng/meepcoin-private-run-${daemonId}b`,
    rpcPort: raw.ports.rpcB, p2pPort: raw.ports.p2pB, exclusivePeerP2pPort: raw.ports.p2pA });
  return Object.freeze({ raw: Object.freeze({ ...raw, ports: Object.freeze({ ...raw.ports }) }), a, b });
}

function ownedWorker({ role, mode, port, peerPort, write }) {
  const worker = new Worker(new URL('./fresh_reachability_worker.mjs', import.meta.url),
    { workerData: { role, mode, port, peerPort } });
  let result = null;
  let failure = null;
  let exited = false;
  let exitCode = null;
  let started = false;
  let firstHash = false;
  worker.on('message', (message) => {
    if (message?.kind === 'EVENT') {
      if (message.event?.phase === 'MINER_STARTED') started = true;
      if (message.event?.phase === 'FIRST_HASH') firstHash = true;
      write({ worker: role, ...message.event });
    }
    else if (message?.kind === 'DONE') { result = message.summary; write({ phase: 'WORKER_DONE', worker: role, result }); }
    else if (message?.kind === 'ERROR') {
      failure = message; write({ phase: 'WORKER_ERROR', worker: role, ...message });
    } else { failure = { code: 'bad_worker_message' }; write({ phase: 'WORKER_ERROR', worker: role, ...failure }); }
  });
  worker.on('error', (error) => {
    failure = { code: 'worker_exception', message: String(error).slice(0, 300) };
    write({ phase: 'WORKER_ERROR', worker: role, ...failure });
  });
  worker.on('exit', (code) => {
    exited = true; exitCode = code;
    if (code !== 0 || result === null) failure ??= { code: 'unexpected_worker_exit', exitCode: code };
  });
  return Object.freeze({ role, worker, get started() { return started; }, get firstHash() { return firstHash; },
    get result() { return result; }, get failure() { return failure; },
    get exited() { return exited; }, get exitCode() { return exitCode; },
    stop() { worker.postMessage('STOP'); }, terminate() { return worker.terminate(); } });
}

export async function runReachabilityArm(cfg, { signal = null, startDaemon = startLocalDaemon,
  preflight = sourcePreflight, machinePreflight = environmentPreflight,
  observeLink = linked, api = { info, header, headers,
    enableReceiverVerificationLog },
  clock = () => Date.now(), sleep = wait, makeWorker = ownedWorker,
  copyLog = copyOwnedLog } = {}) {
  const { raw, a: ca, b: cb } = cfg;
  const assertLive = () => must(signal?.aborted !== true, 'run interrupted');
  assertLive();
  const identity = await preflight(cfg);
  assertLive();
  const machine = await machinePreflight(cfg);
  assertLive();
  const beforeAge = Math.floor(clock() / 1000) - raw.genesisTimestamp;
  must(beforeAge >= 0 && beforeAge <= MAX_GENESIS_AGE_S, 'genesis is already stale before reservation');
  const evidenceDir = resolve(raw.evidenceDir);
  mkdirSync(dirname(evidenceDir), { recursive: true });
  mkdirSync(evidenceDir); // one use: never overwrite an earlier result or failure
  const reservation = { schema: 'meepcoin-fresh-reachability-arm/1', state: 'CONSUMED_ONE_USE',
    createdUtc: new Date(clock()).toISOString(), scope: 'PRIVATE_NO_WALLET_NO_TRANSACTION',
    config: raw, identity, machine, maxGenesisAgeSeconds: MAX_GENESIS_AGE_S,
    assignedRates: ASSIGNED_HASHES_PER_SECOND, heightCap: HEIGHT_CAP,
    postStopObservationMs: POST_STOP_OBSERVE_MS, sampleMs: SAMPLE_MS };
  const fd = openSync(`${evidenceDir}/reservation.json`, 'wx', 0o600);
  try { writeFileSync(fd, JSON.stringify(reservation, null, 2) + '\n'); } finally { closeSync(fd); }
  const events = createWriteStream(`${evidenceDir}/events.jsonl`, { flags: 'wx' });
  const write = (event) => events.write(JSON.stringify({ atUtc: new Date(clock()).toISOString(), ...event }) + '\n');
  const resources = [];
  const workers = [];
  let observation = null;
  let closeResults = [];
  let daemonLogs = [];
  let workerResults = [];
  let stopReason = 'ERROR';
  try {
    const ownStart = async (config) => {
      try { const resource = await startDaemon({ config, signal,
        limits: DAEMON_CLOSE_LIMITS,
        isRpcReady: async () => (await api.info(config.rpcPort)).height >= 1 });
        resources.push(resource); return resource; }
      catch (error) { if (error.resource) resources.push(error.resource); throw error; }
    };
    const a = await ownStart(ca);
    assertLive();
    const b = await ownStart(cb);
    write({ phase: 'DAEMONS_READY', a: { runDir: a.runDir, imageId: a.imageId, listeners: a.listeners },
      b: { runDir: b.runDir, imageId: b.imageId, listeners: b.listeners } });
    // A finished chain cannot reconstruct transient P2P refusals. Require both
    // owned daemons to confirm their logging policy before any miner starts.
    const loggingAttempts = await Promise.allSettled([
      api.enableReceiverVerificationLog(ca.rpcPort),
      api.enableReceiverVerificationLog(cb.rpcPort),
    ]);
    must(loggingAttempts.every((attempt) => attempt.status === 'fulfilled'
      && attempt.value?.categories === RECEIVER_VERIFY_CATEGORIES),
    'receiver verification logs were not confirmed on both daemons');
    const verificationLogs = loggingAttempts.map((attempt) => attempt.value);
    write({ phase: 'RECEIVER_VERIFICATION_LOGGING_CONFIRMED', daemons: verificationLogs });
    const age = genesisGate([await api.header(ca.rpcPort, 0), await api.header(cb.rpcPort, 0)],
      raw.genesisTimestamp, raw.genesisHash, Math.floor(clock() / 1000));
    write({ phase: 'GENESIS_VERIFIED', ageSeconds: age, hash: raw.genesisHash });
    const linkDeadline = clock() + LINK_WAIT_MS;
    for (;;) {
      assertLive();
      const [pair, ia, ib] = await Promise.all([observeLink(a, b), api.info(ca.rpcPort), api.info(cb.rpcPort)]);
      must(pair.ok, `unexpected P2P connection: ${pair.bad.join(',')}`);
      if (pair.linked && ia.synchronized && ib.synchronized && ia.height === 1 && ib.height === 1) break;
      must(clock() < linkDeadline, 'pair did not link and synchronize at genesis');
      await sleep(500);
    }
    write({ phase: 'PEER_LINK_VERIFIED' });
    workers.push(makeWorker({ role: 'h1', mode: REACHABILITY_MODES.HONEST,
      port: ca.rpcPort, peerPort: cb.rpcPort, write }));
    workers.push(makeWorker({ role: 'h2', mode: REACHABILITY_MODES.HONEST,
      port: cb.rpcPort, peerPort: ca.rpcPort, write }));
    // Honest work is already started before the third miner exists.
    const honestDeadline = clock() + 30_000;
    while (workers.some((w) => !w.started || !w.firstHash) && clock() < honestDeadline) {
      must(workers.every((w) => !w.failure && !w.exited), 'honest miner failed before third miner start');
      await sleep(100);
    }
    must(workers.every((w) => w.started && w.firstHash && !w.failure && !w.exited),
      'both honest miners must prove at least one hash before the third miner');
    workers.push(makeWorker({ role: 'third', mode: raw.arm,
      port: ca.rpcPort, peerPort: cb.rpcPort, write }));
    const startMs = clock();
    const deadline = startMs + raw.budgetSeconds * 1000;
    write({ phase: 'ALL_MINERS_STARTED', deadlineUtc: new Date(deadline).toISOString(),
      assignedRates: ASSIGNED_HASHES_PER_SECOND, arm: raw.arm });
    for (;;) {
      assertLive();
      must(workers.every((w) => !w.failure && !w.exited), 'a miner failed during the arm');
      const [ia, ib, pair] = await Promise.all([api.info(ca.rpcPort), api.info(cb.rpcPort), observeLink(a, b)]);
      must(pair.ok && pair.linked, 'private link lost or unexpected peer appeared');
      const [ha, hb] = await Promise.all([api.header(ca.rpcPort, ia.height - 1),
        api.header(cb.rpcPort, ib.height - 1)]);
      write({ phase: 'SAMPLE', elapsedSeconds: Math.round((clock() - startMs) / 1000),
        a: ia, b: ib, headerA: ha, headerB: hb, reciprocalLink: pair.linked });
      if (clock() >= deadline) { stopReason = 'FIXED_WALL_BUDGET'; break; }
      if (ia.height >= HEIGHT_CAP + 1 && ib.height >= HEIGHT_CAP + 1) {
        stopReason = 'BOTH_AT_HEIGHT_CAP'; break;
      }
      await sleep(Math.min(SAMPLE_MS, Math.max(0, deadline - clock())));
    }
    for (const worker of workers) worker.stop();
    const workerStopDeadline = clock() + WORKER_STOP_TIMEOUT_MS;
    while (workers.some((w) => !w.exited) && clock() < workerStopDeadline) await sleep(100);
    must(workers.every((w) => w.exited && w.exitCode === 0 && w.result),
      'a worker did not end cleanly before the stop timeout');
    workerResults = workers.map((w) => w.result);
    write({ phase: 'MINERS_STOPPED', workerResults, stopReason });
    // No further mining; fixed post-stop interval can reveal a delayed convergence or stall.
    const observeUntil = clock() + POST_STOP_OBSERVE_MS;
    while (clock() < observeUntil) {
      const [ia, ib, pair] = await Promise.all([api.info(ca.rpcPort), api.info(cb.rpcPort), observeLink(a, b)]);
      write({ phase: 'POST_STOP_SAMPLE', a: ia, b: ib, reciprocalLink: pair.linked, unexpected: pair.bad });
      must(pair.ok && pair.linked, 'private link lost during post-stop observation');
      await sleep(Math.min(SAMPLE_MS, Math.max(0, observeUntil - clock())));
    }
    const [fa, fb] = await Promise.all([api.info(ca.rpcPort), api.info(cb.rpcPort)]);
    const [ha, hb] = await Promise.all([api.headers(ca.rpcPort, fa.height - 1),
      api.headers(cb.rpcPort, fb.height - 1)]);
    must(ha.at(-1)?.hash === fa.tip && hb.at(-1)?.hash === fb.tip,
      'independent final canonical histories do not match final tips');
    observation = { schema: 'meepcoin-fresh-reachability-observation/1', final: false,
      arm: raw.arm, pairId: raw.pairId, stopReason, workerResults,
      a: { ...fa, canonical: ha, runDir: a.runDir },
      b: { ...fb, canonical: hb, runDir: b.runDir },
      interpretation: 'DESCRIPTIVE_ONLY_PENDING_CROSS_NODE_REJECTION_AUDIT',
      limitations: ['A single arm is not an independent replicate or a security verdict.',
        'A producer-side accepted block alone does not prove a receiver median rejection.'] };
    writeFileSync(`${evidenceDir}/observation.json`, JSON.stringify(observation, null, 2) + '\n', { flag: 'wx' });
  } catch (error) {
    write({ phase: 'FAILURE', code: error?.code ?? 'run_error', message: String(error).slice(0, 400) });
    throw error;
  } finally {
    for (const worker of workers) {
      if (!worker.exited) worker.stop();
    }
    const until = clock() + WORKER_STOP_TIMEOUT_MS;
    while (workers.some((w) => !w.exited) && clock() < until) await sleep(100);
    for (const worker of workers.filter((w) => !w.exited)) {
      const exitCode = await worker.terminate();
      write({ phase: 'WORKER_FORCE_TERMINATED', worker: worker.role, exitCode });
    }
    for (const resource of resources.slice().reverse()) {
      try { await resource.close(); closeResults.push({ runDir: resource.runDir, closed: resource.closed }); }
      catch (error) {
        let forceClosed = false;
        try { await resource.forceClose(); forceClosed = resource.closed; } catch { /* retain uncertainty */ }
        closeResults.push({ runDir: resource.runDir, closed: forceClosed,
          graceful: false, error: String(error).slice(0, 300) });
      }
    }
    for (const [index, resource] of resources.entries()) {
      try {
        const destination = `${evidenceDir}/daemon-${index === 0 ? 'A' : 'B'}.log`;
        const copied = await copyLog({ distro: raw.wslDistro, runDir: resource.runDir, destination });
        daemonLogs.push({ runDir: resource.runDir, path: destination, ...copied });
      } catch (error) {
        daemonLogs.push({ runDir: resource.runDir, error: String(error).slice(0, 300) });
      }
    }
    write({ phase: 'CLEANUP', closeResults });
    writeFileSync(`${evidenceDir}/cleanup.json`, JSON.stringify(closeResults, null, 2) + '\n', { flag: 'wx' });
    writeFileSync(`${evidenceDir}/daemon_logs.json`, JSON.stringify(daemonLogs, null, 2) + '\n', { flag: 'wx' });
    await new Promise((done) => events.end(done));
  }
  must(closeResults.length === 2 && closeResults.every((x) => x.closed && x.graceful !== false),
    'the daemon pair did not close gracefully and confirm gone');
  must(daemonLogs.length === 2 && daemonLogs.every((x) => HEX64.test(x.sha256)),
    'the two daemon logs were not preserved');
  const result = { ...observation, final: true, cleanupConfirmed: true,
    daemonLogs,
    reservationSha256: sha(`${evidenceDir}/reservation.json`),
    observationSha256: sha(`${evidenceDir}/observation.json`),
    eventsSha256: sha(`${evidenceDir}/events.jsonl`), cleanupSha256: sha(`${evidenceDir}/cleanup.json`),
    daemonLogsManifestSha256: sha(`${evidenceDir}/daemon_logs.json`) };
  writeFileSync(`${evidenceDir}/result.json`, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    console.error('Usage: node node/fresh_reachability_arm.mjs <closed-config.json>');
    process.exitCode = 2;
  } else {
    const abort = new AbortController();
    const stop = () => abort.abort();
    process.on('SIGINT', stop); process.on('SIGTERM', stop);
    try {
      const cfg = validateReachabilityConfig(JSON.parse(readFileSync(process.argv[2], 'utf8')));
      const result = await runReachabilityArm(cfg, { signal: abort.signal });
      console.log(JSON.stringify({ arm: result.arm, stopReason: result.stopReason,
        finalHeights: [result.a.height, result.b.height], cleanupConfirmed: true }));
    } catch (error) { console.error(`REACHABILITY ARM FAILED: ${String(error)}`); process.exitCode = 1; }
    finally { process.off('SIGINT', stop); process.off('SIGTERM', stop); }
  }
}
