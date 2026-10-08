#!/usr/bin/env node
// One-use accepted-block control on a disposable, offline copy of the C2 chain.
// No miner, wallet, ordinary transaction, peer, or public network is involved.

import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { DAEMON_LIMITS, startLocalDaemon } from '../pool/dev/local_daemon.mjs';
import { environmentPreflight, enableReceiverVerificationLog } from './fresh_reachability_arm.mjs';
import { header, info, post, rpc, sourcePreflight } from './honest_launch_pilot.mjs';
import { configForProbe } from './receiver_log_probe.mjs';
import { parseReceiverTimestampRefusals } from './receiver_timestamp_verdict.mjs';

const execFileAsync = promisify(execFile);
const OLD_DIR = 'C:\\Users\\tseng\\meepcoin-reachability-runs\\reach-c2-20260929t0627';
const OLD_RESULT_SHA = '9502cd559e5b6b8b9183e75801b3ca15ac43a6701ae8d5ff817a4f21470e7915';
const OLD_DB = '/home/tseng/meepcoin-private-run-b0a9a8175476d51403c2a/data/testnet/lmdb/data.mdb';
const OLD_DB_SHA = '1184d2df11932c628bfb7a8545d156cf0cacca0606842b9d9c9ea940ffb8f05d';
const OLD_TIP = '15d988b703d55776de02ee042a218f19cb3ef65e64389c3ae11bf02e5419ea9d';
const HEX = /^[0-9a-f]+$/;
const LIMITS = Object.freeze({ ...DAEMON_LIMITS,
  probeTimeoutMs: 390_000, stopGraceSeconds: 360, stopTimeoutMs: 420_000 });

function must(ok, message) { if (!ok) throw new Error(`accepted control: ${message}`); }
function sha(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function fileSha(path) { return sha(readFileSync(path)); }
async function wsl(distro, args, options = {}) {
  const { stdout } = await execFileAsync('wsl.exe', ['-d', distro, '--exec', ...args],
    { windowsHide: true, timeout: 30_000, maxBuffer: 2 * 1024 * 1024, ...options });
  return stdout;
}

export function acceptedControlVerdict({ before, popped, after, block, popResponse,
  submitResponse, refusals, cleanup }) {
  const restored = before?.height === 91 && before?.tip === OLD_TIP
    && popped?.height === 90 && popped?.tip === block?.parent
    && after?.height === 91 && after?.tip === OLD_TIP;
  const submitted = submitResponse?.result?.status === 'OK'
    && submitResponse.result.block_id === OLD_TIP;
  const noFalseRefusal = Array.isArray(refusals)
    && !refusals.some((row) => row.blockHash === OLD_TIP);
  return { restored, submitted,
    popAcknowledged: popResponse?.status === 'OK' && popResponse?.height === 90,
    noFalseRefusal,
    cleanupConfirmed: cleanup?.confirmed === true,
    pass: restored && submitted && popResponse?.status === 'OK' && popResponse?.height === 90
      && noFalseRefusal && cleanup?.confirmed === true };
}

export function inspectKnownBlock(fetched, expectedHash, expectedParent) {
  const checks = {
    statusOk: fetched?.status === 'OK',
    hashMatches: fetched?.block_header?.hash === expectedHash,
    parentMatches: fetched?.block_header?.prev_hash === expectedParent,
    noOrdinaryTransactions: fetched?.block_header?.num_txes === 0
      && (fetched?.tx_hashes === undefined
        || (Array.isArray(fetched.tx_hashes) && fetched.tx_hashes.length === 0)),
    blobValid: typeof fetched?.blob === 'string' && fetched.blob.length > 0
      && fetched.blob.length % 2 === 0 && HEX.test(fetched.blob),
  };
  return { checks, observed: { status: fetched?.status ?? null,
    hash: fetched?.block_header?.hash ?? null,
    parent: fetched?.block_header?.prev_hash ?? null,
    headerTxCount: fetched?.block_header?.num_txes ?? null,
    txCount: Array.isArray(fetched?.tx_hashes) ? fetched.tx_hashes.length : null,
    blobLength: typeof fetched?.blob === 'string' ? fetched.blob.length : null },
  allPass: Object.values(checks).every(Boolean) };
}

export async function runAcceptedControl(cfg, { signal = null,
  startDaemon = startLocalDaemon, preflightSource = sourcePreflight,
  preflightMachine = environmentPreflight,
  api = { info, header, rpc, post, enableReceiverVerificationLog },
  wslCall = wsl } = {}) {
  const { raw, a, evidenceDir } = cfg;
  const alive = () => must(!signal?.aborted, 'interrupted');
  alive();
  must(fileSha(`${OLD_DIR}\\result.json`) === OLD_RESULT_SHA, 'historical result bytes differ');
  const old = JSON.parse(readFileSync(`${OLD_DIR}\\result.json`, 'utf8'));
  must(old.final === true && old.cleanupConfirmed === true && old.stopReason === 'BOTH_AT_HEIGHT_CAP'
    && old.a?.height === 91 && old.b?.height === 91 && old.a?.tip === OLD_TIP
    && old.b?.tip === OLD_TIP && old.a?.canonical?.[90]?.num_txes === 0,
  'historical tip is not the pinned transaction-free block');
  must(fileSha(`${OLD_DIR}\\reservation.json`) === old.reservationSha256,
    'historical reservation bytes differ');
  const sourceIdentity = await preflightSource(cfg);
  const machine = await preflightMachine(cfg);
  const sourceStat = String(await wslCall(raw.wslDistro,
    ['stat', '-c', '%F %u:%g %s', '--', OLD_DB])).trim();
  must(/^regular file 1000:1000 [1-9][0-9]*$/.test(sourceStat),
    'historical DB type or ownership differs');
  const symlink = await wslCall(raw.wslDistro, ['readlink', '--', OLD_DB]).then(() => true, () => false);
  must(!symlink, 'historical DB is a symbolic link');
  must(String(await wslCall(raw.wslDistro, ['sha256sum', '--', OLD_DB])).split(/\s+/)[0]
    === OLD_DB_SHA, 'historical DB bytes differ');
  alive();

  mkdirSync('C:\\Users\\tseng\\meepcoin-logging-probe-runs', { recursive: true });
  mkdirSync(evidenceDir); // any prior attempt is never overwritten or reused
  const reservation = { schema: 'meepcoin-receiver-accepted-control/1',
    state: 'CONSUMED_ONE_USE', createdUtc: new Date().toISOString(), runId: cfg.runId,
    scope: 'OFFLINE_SINGLE_DAEMON_ONE_POP_ONE_KNOWN_BLOCK_NO_MINING', raw,
    daemonConfig: a, sourceIdentity, machine, historicalResultSha256: OLD_RESULT_SHA,
    historicalDbSha256: OLD_DB_SHA };
  writeFileSync(`${evidenceDir}\\reservation.json`, JSON.stringify(reservation, null, 2) + '\n',
    { flag: 'wx', mode: 0o600 });
  const event = (phase, details = {}) => appendFileSync(`${evidenceDir}\\events.jsonl`,
    JSON.stringify({ atUtc: new Date().toISOString(), phase, ...details }) + '\n');
  let resource = null;
  let failure = null;
  let copiedDbSha = null;
  let block = null;
  let before = null;
  let popped = null;
  let after = null;
  let popResponse = null;
  let submitResponse = null;
  let refusals = null;
  const cleanup = { confirmed: false };
  try {
    resource = await startDaemon({ config: a, signal, limits: LIMITS,
      isRpcReady: async () => (await api.info(a.rpcPort)).height === 91,
      prepareRunDir: async ({ runDir }) => {
        must(runDir === a.runDir, 'directory ownership changed');
        const dest = `${runDir}/data/testnet/lmdb`;
        await wslCall(raw.wslDistro, ['mkdir', '-m', '700', '-p', '--', dest]);
        await wslCall(raw.wslDistro, ['cp', '--reflink=auto', '--', OLD_DB, `${dest}/data.mdb`]);
        copiedDbSha = String(await wslCall(raw.wslDistro,
          ['sha256sum', '--', `${dest}/data.mdb`])).split(/\s+/)[0];
        must(copiedDbSha === OLD_DB_SHA, 'fresh DB copy differs');
      } });
    event('DAEMON_READY', { runDir: resource.runDir, runDirIdentity: resource.runDirIdentity,
      containerName: resource.containerName, imageId: resource.imageId,
      listeners: resource.listeners, copiedDbSha });
    alive();
    event('VERIFY_LOG_ACK', { logging: await api.enableReceiverVerificationLog(a.rpcPort) });
    before = await api.info(a.rpcPort);
    const tip = await api.header(a.rpcPort, 90);
    must(before.height === 91 && before.tip === OLD_TIP && tip.hash === OLD_TIP
      && tip.num_txes === 0 && /^[0-9a-f]{64}$/.test(tip.prev_hash),
    'copied tip identity or transaction count differs');
    const fetched = await api.rpc(a.rpcPort, 'get_block', { hash: OLD_TIP, height: 90 });
    const inspected = inspectKnownBlock(fetched, OLD_TIP, tip.prev_hash);
    event('FETCHED_BLOCK_SHAPE', inspected);
    must(inspected.allPass, `fetched block mismatch: ${Object.entries(inspected.checks)
      .filter(([, ok]) => !ok).map(([name]) => name).join(', ')}`);
    block = { hash: OLD_TIP, parent: tip.prev_hash, height: 90,
      blob: fetched.blob, blobSha256: sha(Buffer.from(fetched.blob, 'hex')) };
    writeFileSync(`${evidenceDir}\\known_block.json`, JSON.stringify(block, null, 2) + '\n',
      { flag: 'wx', mode: 0o600 });
    event('ONE_POP_DISPATCH', { blockHash: OLD_TIP, knownBlockSha256: fileSha(`${evidenceDir}\\known_block.json`) });
    alive();
    popResponse = await api.post(a.rpcPort, '/pop_blocks', { nblocks: 1 });
    event('POP_RETURNED', { popResponse });
    must(popResponse?.status === 'OK' && popResponse.height === 90,
      'one-block pop was not acknowledged');
    popped = await api.info(a.rpcPort);
    must(popped.height === 90 && popped.tip === block.parent,
      'disposable chain was not rewound to the exact parent');
    event('ONE_SUBMISSION_DISPATCH', { blockHash: OLD_TIP,
      knownBlockSha256: fileSha(`${evidenceDir}\\known_block.json`) });
    alive();
    try {
      submitResponse = await api.post(a.rpcPort, '/json_rpc',
        { jsonrpc: '2.0', id: 'receiver-accepted-control', method: 'submit_block',
          params: [block.blob] });
      event('SUBMISSION_RETURNED', { submitResponse });
    } catch (error) {
      submitResponse = { transportUnknown: true, message: String(error).slice(0, 300) };
      event('SUBMISSION_UNKNOWN', { submitResponse });
    }
    after = await api.info(a.rpcPort);
    must(after.height === 91 && after.tip === OLD_TIP,
      'known block did not restore the exact copied tip');
  } catch (error) {
    if (error.resource) resource = error.resource;
    failure = { code: error?.code ?? 'control_failed',
      message: String(error).slice(0, 400), retainedPaths: error?.retainedPaths ?? null };
    event('FAILURE', failure);
  } finally {
    if (resource) {
      try {
        await resource.close();
        cleanup.confirmed = resource.closed;
        cleanup.shutdown = resource.shutdownOutcome;
      } catch (error) {
        cleanup.error = String(error).slice(0, 300);
        try { await resource.forceClose(); cleanup.confirmed = resource.closed; cleanup.forced = true; }
        catch (second) { cleanup.forceError = String(second).slice(0, 300); }
      }
      try {
        const bytes = await wslCall(raw.wslDistro, ['cat', '--', `${a.runDir}/meepcoind.log`],
          { encoding: 'buffer', maxBuffer: 32 * 1024 * 1024 });
        must(Buffer.isBuffer(bytes) && bytes.length > 0, 'owned daemon log is empty');
        writeFileSync(`${evidenceDir}\\daemon.log`, bytes, { flag: 'wx', mode: 0o600 });
        cleanup.logSha256 = sha(bytes);
        refusals = parseReceiverTimestampRefusals(bytes.toString('utf8'));
      } catch (error) { cleanup.logError = String(error).slice(0, 300); }
    }
    event('CLEANUP', { cleanup, refusals });
    writeFileSync(`${evidenceDir}\\cleanup.json`, JSON.stringify({ cleanup }, null, 2) + '\n',
      { flag: 'wx', mode: 0o600 });
  }
  const verdict = acceptedControlVerdict({ before, popped, after, block, popResponse,
    submitResponse, refusals, cleanup });
  const result = { schema: 'meepcoin-receiver-accepted-control-result/1', final: true,
    pass: verdict.pass && failure === null && !!cleanup.logSha256, verdict, failure,
    before, popped, after, blockHash: block?.hash ?? null,
    popResponse, submitResponse, refusals, cleanup, copiedDbSha,
    reservationSha256: fileSha(`${evidenceDir}\\reservation.json`),
    eventsSha256: fileSha(`${evidenceDir}\\events.jsonl`),
    cleanupSha256: fileSha(`${evidenceDir}\\cleanup.json`),
    knownBlockSha256: block ? fileSha(`${evidenceDir}\\known_block.json`) : null };
  writeFileSync(`${evidenceDir}\\result.json`, JSON.stringify(result, null, 2) + '\n',
    { flag: 'wx', mode: 0o600 });
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 6) {
    console.error('Usage: node node/receiver_accepted_control.mjs <one-use-run-id> <pinned-HEAD> <rpc-port> <p2p-port>');
    process.exitCode = 2;
  } else {
    const abort = new AbortController();
    const stop = () => abort.abort();
    process.on('SIGINT', stop); process.on('SIGTERM', stop);
    try {
      const oldReservation = JSON.parse(readFileSync(`${OLD_DIR}\\reservation.json`, 'utf8'));
      const cfg = configForProbe({ runId: process.argv[2], repoCommit: process.argv[3],
        rpcPort: Number(process.argv[4]), p2pPort: Number(process.argv[5]), oldReservation });
      const result = await runAcceptedControl(cfg, { signal: abort.signal });
      console.log(JSON.stringify({ pass: result.pass, failure: result.failure,
        verdict: result.verdict, cleanup: result.cleanup }));
      if (!result.pass) process.exitCode = 1;
    } catch (error) {
      console.error(`ACCEPTED CONTROL FAILED: ${String(error)}`);
      process.exitCode = 1;
    } finally { process.off('SIGINT', stop); process.off('SIGTERM', stop); }
  }
}
