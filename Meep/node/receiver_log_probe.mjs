#!/usr/bin/env node
// One-use, offline, one-daemon diagnostic of the compiled timestamp-refusal log.
// A copy of an already sealed chain is used. No miner, wallet, peer or transaction is started.

import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { DAEMON_LIMITS, DAEMON_PROFILES, checkDaemonConfig, startLocalDaemon } from '../pool/dev/local_daemon.mjs';
import { REAL_COINBASE_ADDRESS } from '../pool/dev/real_daemon_mode.mjs';
import { environmentPreflight, enableReceiverVerificationLog } from './fresh_reachability_arm.mjs';
import { header, headers, info, post, rpc, sourcePreflight } from './honest_launch_pilot.mjs';
import { parseReceiverTimestampRefusals } from './receiver_timestamp_verdict.mjs';

const execFileAsync = promisify(execFile);
const HISTORICAL_DIR = 'C:\\Users\\tseng\\meepcoin-reachability-runs\\reach-c2-20260929t0627';
const HISTORICAL_RESULT_SHA = '9502cd559e5b6b8b9183e75801b3ca15ac43a6701ae8d5ff817a4f21470e7915';
const HISTORICAL_DB_SHA = '1184d2df11932c628bfb7a8545d156cf0cacca0606842b9d9c9ea940ffb8f05d';
const HISTORICAL_DB = '/home/tseng/meepcoin-private-run-b0a9a8175476d51403c2a/data/testnet/lmdb/data.mdb';
const HISTORICAL_TIP = '15d988b703d55776de02ee042a218f19cb3ef65e64389c3ae11bf02e5419ea9d';
// Ubuntu's local engine still has the original C2 image. Use its exact historical image ID;
// a similarly named image from Docker Desktop's separate VM is not interchangeable.
const RUNTIME_IMAGE = 'meepcoin-build:runtimeclosure-d37b174-20260924t201500z';
const RUNTIME_IMAGE_ID = 'sha256:7eff53d041d9e1cfac1c22badcd92694d2756cb2bb088d66d35ddee1a50f19b2';
const RUN_ID = /^logprobe-[a-z0-9-]{8,48}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const HEX = /^[0-9a-f]+$/;
const CLOSE_LIMITS = Object.freeze({ ...DAEMON_LIMITS,
  probeTimeoutMs: 390_000, stopGraceSeconds: 360, stopTimeoutMs: 420_000 });

function must(ok, message) { if (!ok) throw new Error(`receiver log probe: ${message}`); }
function sha(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function fileSha(path) { return sha(readFileSync(path)); }
async function wsl(distro, argv, options = {}) {
  const { stdout } = await execFileAsync('wsl.exe', ['-d', distro, '--exec', ...argv],
    { windowsHide: true, timeout: 30_000, maxBuffer: 2 * 1024 * 1024, ...options });
  return stdout;
}

// Parse only the block header's first two varints and its timestamp varint. Never guess
// a fixed byte offset: changing the timestamp can change its serialized length.
export function readVarint(bytes, offset) {
  let value = 0n;
  let shift = 0n;
  for (let i = offset; i < Math.min(bytes.length, offset + 10); i += 1) {
    const b = bytes[i];
    value |= BigInt(b & 127) << shift;
    if (!(b & 128)) {
      must(value <= BigInt(Number.MAX_SAFE_INTEGER), 'varint is not a safe integer');
      return { value: Number(value), end: i + 1 };
    }
    shift += 7n;
  }
  throw new Error('receiver log probe: truncated or oversized varint');
}

export function encodeVarint(value) {
  must(Number.isSafeInteger(value) && value >= 0, 'timestamp must be a safe non-negative integer');
  let n = BigInt(value);
  const out = [];
  do {
    let b = Number(n & 127n);
    n >>= 7n;
    if (n) b |= 128;
    out.push(b);
  } while (n);
  return Buffer.from(out);
}

export function belowMedianCandidate(templateHex, timestamp, expectedParent) {
  must(typeof templateHex === 'string' && templateHex.length % 2 === 0 && HEX.test(templateHex),
    'template blob must be lowercase even-length hex');
  must(/^[0-9a-f]{64}$/.test(expectedParent), 'expected parent must be a block hash');
  const blob = Buffer.from(templateHex, 'hex');
  let off = 0;
  for (let i = 0; i < 2; i += 1) off = readVarint(blob, off).end;
  const old = readVarint(blob, off);
  must(blob.length >= old.end + 32 + 4, 'template block header is truncated');
  must(blob.subarray(old.end, old.end + 32).toString('hex') === expectedParent,
    'template is not on the copied canonical tip');
  const changed = Buffer.concat([blob.subarray(0, off), encodeVarint(timestamp), blob.subarray(old.end)]);
  must(changed.toString('hex') !== templateHex, 'candidate timestamp was not changed');
  return { fullBlockHex: changed.toString('hex'), originalTimestamp: old.value,
    candidateTimestamp: timestamp, parent: expectedParent };
}

export function lowerMedian60(chain) {
  must(Array.isArray(chain) && chain.length >= 61, 'chain has no complete median window');
  const tail = chain.slice(-60);
  must(tail.every((h) => Number.isSafeInteger(h.timestamp) && h.timestamp >= 0),
    'canonical history has an invalid timestamp');
  const sorted = tail.map((h) => h.timestamp).sort((a, b) => a - b);
  return Math.floor((sorted[29] + sorted[30]) / 2);
}

export function configForProbe({ runId, repoCommit, rpcPort, p2pPort, oldReservation }) {
  must(RUN_ID.test(runId) && COMMIT.test(repoCommit), 'run id and source commit must be pinned');
  must(Number.isInteger(rpcPort) && Number.isInteger(p2pPort)
    && rpcPort >= 1024 && p2pPort >= 1024 && rpcPort <= 65535 && p2pPort <= 65535
    && rpcPort !== p2pPort, 'two distinct private ports are required');
  const old = oldReservation.config;
  must(oldReservation.state === 'CONSUMED_ONE_USE' && old.runId === 'reach-c2-20260929t0627',
    'historical reservation identity differs');
  must(old.image === RUNTIME_IMAGE && old.expectedImageId === RUNTIME_IMAGE_ID,
    'historical Docker image identity differs');
  const evidenceDir = `C:\\Users\\tseng\\meepcoin-logging-probe-runs\\${runId}`;
  const raw = Object.freeze({ scope: 'RECEIVER_LOG_PROBE', runId, evidenceDir, repoCommit,
    artifactDir: old.artifactDir, buildManifestSha256: old.buildManifestSha256,
    variantId: old.variantId, genesisTimestamp: old.genesisTimestamp,
    genesisHash: old.genesisHash, wslDistro: old.wslDistro, uid: old.uid, gid: old.gid,
    image: RUNTIME_IMAGE, expectedImageId: RUNTIME_IMAGE_ID,
    ports: { rpcA: rpcPort, p2pA: p2pPort } });
  const runDir = `/home/tseng/meepcoin-private-run-${randomBytes(12).toString('hex')}`;
  const a = checkDaemonConfig({ wslDistro: old.wslDistro, image: RUNTIME_IMAGE,
    artifactDir: old.artifactDir, uid: old.uid, gid: old.gid,
    expectedImageId: RUNTIME_IMAGE_ID, profile: DAEMON_PROFILES.OFFLINE_SINGLE,
    rpcPort, p2pPort, runDir });
  return Object.freeze({ raw, a, runId, historicalImage: old.image,
    historicalImageId: old.expectedImageId,
    evidenceDir });
}

export async function runReceiverLogProbe(cfg, { signal = null, startDaemon = startLocalDaemon,
  preflightSource = sourcePreflight, preflightMachine = environmentPreflight,
  daemonApi = { info, header, headers, rpc, post, enableReceiverVerificationLog },
  wslCall = wsl } = {}) {
  const { raw, a, evidenceDir } = cfg;
  const alive = () => must(!signal?.aborted, 'interrupted');
  alive();
  must(fileSha(`${HISTORICAL_DIR}\\result.json`) === HISTORICAL_RESULT_SHA,
    'historical result bytes differ');
  const old = JSON.parse(readFileSync(`${HISTORICAL_DIR}\\result.json`, 'utf8'));
  must(old.final === true && old.cleanupConfirmed === true && old.stopReason === 'BOTH_AT_HEIGHT_CAP'
    && old.a?.tip === HISTORICAL_TIP && old.b?.tip === HISTORICAL_TIP
    && old.a?.height === 91 && old.b?.height === 91, 'historical result is not the pinned chain');
  must(fileSha(`${HISTORICAL_DIR}\\reservation.json`) === old.reservationSha256,
    'historical reservation checksum differs');
  const sourceIdentity = await preflightSource(cfg);
  const machine = await preflightMachine(cfg);
  const sourceStat = String(await wslCall(raw.wslDistro, ['stat', '-c', '%F %u:%g %s', '--', HISTORICAL_DB])).trim();
  must(/^regular file 1000:1000 [1-9][0-9]*$/.test(sourceStat), 'historical LMDB file type or ownership differs');
  const symlink = await wslCall(raw.wslDistro, ['readlink', '--', HISTORICAL_DB]).then(() => true, () => false);
  must(!symlink, 'historical LMDB file is a symbolic link');
  const sourceDbHash = String(await wslCall(raw.wslDistro, ['sha256sum', '--', HISTORICAL_DB])).split(/\s+/)[0];
  must(sourceDbHash === HISTORICAL_DB_SHA, 'historical LMDB bytes differ');
  alive();

  mkdirSync('C:\\Users\\tseng\\meepcoin-logging-probe-runs', { recursive: true });
  mkdirSync(evidenceDir); // a prior reservation or attempt is never replaced
  const reservation = { schema: 'meepcoin-receiver-log-probe/1', state: 'CONSUMED_ONE_USE',
    createdUtc: new Date().toISOString(), scope: 'OFFLINE_SINGLE_DAEMON_ONE_INVALID_BLOCK_NO_MINING',
    runId: cfg.runId, raw, daemonConfig: a, historicalResultSha256: HISTORICAL_RESULT_SHA,
    historicalDbSha256: HISTORICAL_DB_SHA, historicalImage: cfg.historicalImage,
    historicalImageId: cfg.historicalImageId,
    runtimeImageSubstitution: false,
    sourceIdentity, machine };
  writeFileSync(`${evidenceDir}\\reservation.json`, JSON.stringify(reservation, null, 2) + '\n',
    { flag: 'wx', mode: 0o600 });
  const event = (phase, details = {}) => appendFileSync(`${evidenceDir}\\events.jsonl`,
    JSON.stringify({ atUtc: new Date().toISOString(), phase, ...details }) + '\n');
  let resource = null;
  let failure = null;
  let response = null;
  let candidate = null;
  let decision = null;
  let logRecord = null;
  let copiedDbSha = null;
  let copiedChainTip = null;
  let expectedMedian = null;
  let cleanup = { confirmed: false };
  try {
    resource = await startDaemon({ config: a, signal, limits: CLOSE_LIMITS,
      isRpcReady: async () => (await daemonApi.info(a.rpcPort)).height === 91,
      prepareRunDir: async ({ runDir }) => {
        must(runDir === a.runDir, 'directory ownership changed');
        const dest = `${runDir}/data/testnet/lmdb`;
        await wslCall(raw.wslDistro, ['mkdir', '-m', '700', '-p', '--', dest]);
        await wslCall(raw.wslDistro, ['cp', '--reflink=auto', '--', HISTORICAL_DB, `${dest}/data.mdb`]);
        copiedDbSha = String(await wslCall(raw.wslDistro,
          ['sha256sum', '--', `${dest}/data.mdb`])).split(/\s+/)[0];
        must(copiedDbSha === HISTORICAL_DB_SHA, 'fresh copy differs from its source');
      } });
    event('DAEMON_READY', { runDir: resource.runDir, runDirIdentity: resource.runDirIdentity,
      containerName: resource.containerName, imageId: resource.imageId,
      listeners: resource.listeners, copiedDbSha });
    alive();
    const logging = await daemonApi.enableReceiverVerificationLog(a.rpcPort);
    event('VERIFY_LOG_ACK', { logging });
    const state = await daemonApi.info(a.rpcPort);
    const top = await daemonApi.header(a.rpcPort, 90);
    must(state.height === 91 && state.tip === HISTORICAL_TIP && top.hash === HISTORICAL_TIP,
      'copied chain did not reopen at the pinned tip');
    copiedChainTip = state.tip;
    const chain = await daemonApi.headers(a.rpcPort, 90);
    must(chain.length === 91 && chain[0].hash === raw.genesisHash, 'copied canonical history differs');
    const median = lowerMedian60(chain);
    expectedMedian = median;
    const template = await daemonApi.rpc(a.rpcPort, 'get_block_template',
      { wallet_address: REAL_COINBASE_ADDRESS, reserve_size: 0 });
    must(template.status === 'OK' && template.height === 91,
      'template is not the next block on the copied chain');
    candidate = belowMedianCandidate(template.blocktemplate_blob, median - 1, HISTORICAL_TIP);
    must(candidate.originalTimestamp >= median, 'unmodified template is not median-valid');
    writeFileSync(`${evidenceDir}\\candidate.json`, JSON.stringify({ ...candidate,
      median, templateHeight: template.height, fullBlockSha256: sha(Buffer.from(candidate.fullBlockHex, 'hex')) }, null, 2) + '\n',
    { flag: 'wx', mode: 0o600 });
    event('ONE_SUBMISSION_DISPATCH', { candidateTimestamp: candidate.candidateTimestamp,
      median, candidateFileSha256: fileSha(`${evidenceDir}\\candidate.json`) });
    alive();
    try {
      // Exactly one call. A timeout or transport error is UNKNOWN and is never retried.
      response = await daemonApi.post(a.rpcPort, '/json_rpc',
        { jsonrpc: '2.0', id: 'receiver-log-probe', method: 'submit_block', params: [candidate.fullBlockHex] });
      event('SUBMISSION_RETURNED', { response });
    } catch (error) {
      response = { transportUnknown: true, message: String(error).slice(0, 300) };
      event('SUBMISSION_UNKNOWN', { response });
    }
    const after = await daemonApi.info(a.rpcPort);
    must(after.height === 91 && after.tip === HISTORICAL_TIP,
      'deliberately invalid block changed the copied chain');
  } catch (error) {
    if (error.resource) resource = error.resource;
    failure = { code: error?.code ?? 'probe_failed', message: String(error).slice(0, 400),
      retainedPaths: error?.retainedPaths ?? null };
    event('FAILURE', failure);
  } finally {
    if (resource) {
      try { await resource.close(); cleanup.confirmed = resource.closed;
        cleanup.shutdown = resource.shutdownOutcome; }
      catch (error) { cleanup.error = String(error).slice(0, 300);
        try { await resource.forceClose(); cleanup.confirmed = resource.closed; cleanup.forced = true; }
        catch (second) { cleanup.forceError = String(second).slice(0, 300); } }
      try {
        const bytes = await wslCall(raw.wslDistro, ['cat', '--', `${a.runDir}/meepcoind.log`],
          { encoding: 'buffer', maxBuffer: 32 * 1024 * 1024 });
        must(Buffer.isBuffer(bytes) && bytes.length > 0, 'owned daemon log is empty');
        writeFileSync(`${evidenceDir}\\daemon.log`, bytes, { flag: 'wx', mode: 0o600 });
        cleanup.logSha256 = sha(bytes);
        const rows = parseReceiverTimestampRefusals(bytes.toString('utf8'));
        const matching = rows.filter((r) => candidate && r.timestamp === candidate.candidateTimestamp);
        decision = { allRefusals: rows, candidateRefusals: matching,
          canonicalTipHasNoFalseRefusal: !rows.some((r) => r.blockHash === HISTORICAL_TIP) };
        logRecord = { bytes: bytes.length, sha256: cleanup.logSha256 };
      } catch (error) { cleanup.logError = String(error).slice(0, 300); }
    }
    event('CLEANUP', { cleanup, logRecord });
    writeFileSync(`${evidenceDir}\\cleanup.json`, JSON.stringify({ cleanup, logRecord }, null, 2) + '\n',
      { flag: 'wx', mode: 0o600 });
  }
  const matched = decision?.candidateRefusals?.length === 1
    && decision.candidateRefusals[0].path === 'MAIN'
    && decision.candidateRefusals[0].timestamp === expectedMedian - 1
    && decision.candidateRefusals[0].median === expectedMedian
    && decision.canonicalTipHasNoFalseRefusal === true
    && failure === null;
  const result = { schema: 'meepcoin-receiver-log-probe-result/1', final: true,
    loggingDiagnosticOnly: true, acceptedControlExercised: false,
    matched, response, candidateTimestamp: candidate?.candidateTimestamp ?? null,
    expectedMedian, copiedChainTip, copiedDbSha, decision, failure, cleanup,
    reservationSha256: fileSha(`${evidenceDir}\\reservation.json`),
    eventsSha256: fileSha(`${evidenceDir}\\events.jsonl`),
    cleanupSha256: fileSha(`${evidenceDir}\\cleanup.json`),
    candidateSha256: candidate ? fileSha(`${evidenceDir}\\candidate.json`) : null };
  writeFileSync(`${evidenceDir}\\result.json`, JSON.stringify(result, null, 2) + '\n',
    { flag: 'wx', mode: 0o600 });
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 6) {
    console.error('Usage: node node/receiver_log_probe.mjs <one-use-run-id> <pinned-HEAD> <rpc-port> <p2p-port>');
    process.exitCode = 2;
  } else {
    const abort = new AbortController();
    const stop = () => abort.abort();
    process.on('SIGINT', stop); process.on('SIGTERM', stop);
    try {
      const oldReservation = JSON.parse(readFileSync(`${HISTORICAL_DIR}\\reservation.json`, 'utf8'));
      const cfg = configForProbe({ runId: process.argv[2], repoCommit: process.argv[3],
        rpcPort: Number(process.argv[4]), p2pPort: Number(process.argv[5]), oldReservation });
      const result = await runReceiverLogProbe(cfg, { signal: abort.signal });
      console.log(JSON.stringify({ matched: result.matched, failure: result.failure, cleanup: result.cleanup }));
      if (!result.matched || result.failure || !result.cleanup.confirmed || !result.cleanup.logSha256) process.exitCode = 1;
    } catch (error) { console.error(`RECEIVER LOG PROBE FAILED: ${String(error)}`); process.exitCode = 1; }
    finally { process.off('SIGINT', stop); process.off('SIGTERM', stop); }
  }
}
