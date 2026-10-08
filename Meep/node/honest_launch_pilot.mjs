#!/usr/bin/env node
// One prospective, honest-only private launch feasibility pilot. This is not an attack experiment.
// The two owned daemons use the existing natural-difficulty loopback P2P profile. No browser,
// wallet, transaction, public listener, fixed difficulty, or automatic retry is involved.

import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createWriteStream, mkdirSync, openSync, closeSync, readFileSync, writeFileSync } from 'node:fs';
import { promisify } from 'node:util';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DAEMON_PROFILES, checkDaemonConfig, checkPairConnections, parseConnections, startLocalDaemon,
} from '../pool/dev/local_daemon.mjs';
import { REAL_COINBASE_ADDRESS } from '../pool/dev/real_daemon_mode.mjs';
import { classifyWslDockerEngine } from '../pool/dev/docker_engine_topology.mjs';

const execFileAsync = promisify(execFile);
const HEX64 = /^[0-9a-f]{64}$/;
const SHA_IMAGE = /^sha256:[0-9a-f]{64}$/;
const ID = /^[a-z][a-z0-9-]{0,63}$/;
const MAX_GENESIS_AGE_S = 1800;
const TARGET_BLOCK_HEIGHT = 61;
const POLL_MS = 15_000;
const LINK_WAIT_MS = 60_000;
const RPC_TIMEOUT_MS = 15_000;

function must(condition, message) {
  if (!condition) throw new Error(message);
}

export function validatePilotConfig(raw) {
  must(raw && typeof raw === 'object' && !Array.isArray(raw), 'config must be an object');
  const keys = [
    'repoCommit', 'variantId', 'genesisTimestamp', 'genesisHash', 'artifactDir', 'buildManifestSha256',
    'image', 'expectedImageId', 'wslDistro', 'uid', 'gid', 'ports', 'threadsA', 'threadsB',
    'budgetSeconds', 'evidenceDir',
  ];
  must(Object.keys(raw).sort().join('|') === keys.sort().join('|'), 'config keys differ from the closed pilot schema');
  must(/^[0-9a-f]{40}$/.test(raw.repoCommit), 'invalid repo commit');
  must(ID.test(raw.variantId), 'invalid variant ID');
  must(Number.isSafeInteger(raw.genesisTimestamp) && raw.genesisTimestamp > 1785283200,
    'invalid variant genesis timestamp');
  must(HEX64.test(raw.genesisHash), 'invalid expected genesis hash');
  must(HEX64.test(raw.buildManifestSha256), 'invalid build manifest hash');
  must(/^meepcoin-build:[a-z0-9][a-z0-9._-]{0,127}$/.test(raw.image), 'invalid image tag');
  must(SHA_IMAGE.test(raw.expectedImageId), 'invalid image ID');
  must(typeof raw.wslDistro === 'string' && /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/.test(raw.wslDistro),
    'invalid WSL distro');
  for (const key of ['uid', 'gid']) must(Number.isInteger(raw[key]) && raw[key] > 0 && raw[key] <= 60000, `invalid ${key}`);
  must(raw.ports && typeof raw.ports === 'object' && !Array.isArray(raw.ports)
    && Object.keys(raw.ports).sort().join('|') === 'p2pA|p2pB|rpcA|rpcB', 'invalid ports');
  must(new Set(Object.values(raw.ports)).size === 4, 'the four ports must be distinct');
  for (const [name, value] of Object.entries(raw.ports)) {
    must(Number.isInteger(value) && value >= 1024 && value <= 65535, `invalid ${name}`);
  }
  for (const key of ['threadsA', 'threadsB']) must(Number.isInteger(raw[key]) && raw[key] >= 1 && raw[key] <= 4, `invalid ${key}`);
  must(raw.threadsA + raw.threadsB <= 8, 'pilot thread budget exceeds eight');
  must(Number.isInteger(raw.budgetSeconds) && raw.budgetSeconds >= 60 && raw.budgetSeconds <= 86400,
    'budget must be 60..86400 seconds');
  must(typeof raw.evidenceDir === 'string' && /^C:\\Users\\tseng\\meepcoin-pilot-runs\\[a-z0-9-]{8,64}$/.test(raw.evidenceDir),
    'evidenceDir must be a new exact path below C:\\Users\\tseng\\meepcoin-pilot-runs');
  const runId = randomBytes(8).toString('hex');
  const common = {
    wslDistro: raw.wslDistro, image: raw.image, artifactDir: raw.artifactDir,
    uid: raw.uid, gid: raw.gid, expectedImageId: raw.expectedImageId,
    profile: DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_NATURAL,
  };
  const a = checkDaemonConfig({ ...common, runDir: `/home/tseng/meepcoin-private-run-${runId}a`,
    rpcPort: raw.ports.rpcA, p2pPort: raw.ports.p2pA, exclusivePeerP2pPort: raw.ports.p2pB });
  const b = checkDaemonConfig({ ...common, runDir: `/home/tseng/meepcoin-private-run-${runId}b`,
    rpcPort: raw.ports.rpcB, p2pPort: raw.ports.p2pB, exclusivePeerP2pPort: raw.ports.p2pA });
  return { raw: Object.freeze({ ...raw, ports: Object.freeze({ ...raw.ports }) }), a, b };
}

export function genesisGate(headers, expectedTimestamp, expectedHash, nowSeconds) {
  must(Array.isArray(headers) && headers.length === 2, 'two genesis headers required');
  const age = nowSeconds - expectedTimestamp;
  must(age >= 0 && age <= MAX_GENESIS_AGE_S, `genesis age ${age}s is outside 0..${MAX_GENESIS_AGE_S}s`);
  for (const [i, h] of headers.entries()) {
    must(h && Number(h.height) === 0 && Number(h.timestamp) === expectedTimestamp
      && h.hash === expectedHash, `daemon ${i === 0 ? 'A' : 'B'} genesis mismatch`);
  }
  return age;
}

export function trajectoryVerdict(a, b, stopReason) {
  const reached = a.some((h) => h.height === TARGET_BLOCK_HEIGHT)
    && b.some((h) => h.height === TARGET_BLOCK_HEIGHT);
  const agreement = reached && a.find((h) => h.height === TARGET_BLOCK_HEIGHT)?.hash
    === b.find((h) => h.height === TARGET_BLOCK_HEIGHT)?.hash;
  const observedBeforeBudget = stopReason === 'BOTH_AT_HEIGHT_61' && agreement;
  return { reachedCompletePostGenesisWindow: reached, agreementAt61: Boolean(agreement),
    observedBeforeBudget: Boolean(observedBeforeBudget), stopReason,
    interpretation: observedBeforeBudget ? 'FEASIBILITY_OBSERVED_NOT_ATTACK_RESULT'
      : 'FEASIBILITY_INCOMPLETE_OR_DIVERGENT_NOT_ATTACK_RESULT' };
}

async function wsl(args, distro) {
  const { stdout } = await execFileAsync('wsl.exe', ['-d', distro, '--exec', ...args],
    { windowsHide: true, timeout: 30_000, maxBuffer: 2 * 1024 * 1024 });
  return stdout;
}

async function post(port, path, body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RPC_TIMEOUT_MS);
  try {
    const r = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
      signal: controller.signal,
    });
    must(r.ok, `${path} on port ${port}: HTTP ${r.status}`);
    const size = Number(r.headers.get('content-length'));
    must(!Number.isFinite(size) || size <= 2 * 1024 * 1024, 'RPC reply exceeds 2 MiB');
    const text = await r.text();
    must(text.length <= 2 * 1024 * 1024, 'RPC reply exceeds 2 MiB');
    return JSON.parse(text);
  } finally { clearTimeout(timer); }
}

async function rpc(port, method, params = {}) {
  const r = await post(port, '/json_rpc', { jsonrpc: '2.0', id: 'pilot', method, params });
  must(!r.error && r.result, `${method} on port ${port} refused`);
  return r.result;
}

async function info(port) {
  const r = await post(port, '/get_info', {});
  must(r.status === 'OK' && Number.isInteger(r.height) && HEX64.test(r.top_block_hash),
    `invalid get_info on port ${port}`);
  return { height: r.height, tip: r.top_block_hash, synchronized: r.synchronized === true,
    incoming: r.incoming_connections_count, outgoing: r.outgoing_connections_count };
}

async function header(port, height) {
  const r = await rpc(port, 'get_block_header_by_height', { height });
  must(r.status === 'OK' && r.block_header && Number(r.block_header.height) === height,
    `invalid block header ${height} on port ${port}`);
  return r.block_header;
}

async function headers(port, topHeight) {
  const r = await rpc(port, 'get_block_headers_range', { start_height: 0, end_height: topHeight });
  const hs = r.headers;
  must(r.status === 'OK' && Array.isArray(hs) && hs.length === topHeight + 1,
    `incomplete canonical history on port ${port}`);
  for (let i = 0; i < hs.length; i++) {
    must(Number(hs[i].height) === i && (i === 0 || hs[i].prev_hash === hs[i - 1].hash),
      `incoherent canonical history at ${i}`);
  }
  return hs;
}

async function sourcePreflight(cfg) {
  const { raw, a } = cfg;
  const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
  const actualCommit = (await execFileAsync('git', ['rev-parse', 'HEAD'], { cwd: repoRoot })).stdout.trim();
  must(actualCommit === raw.repoCommit, 'repository HEAD differs from pinned commit');
  const trackedStatus = (await execFileAsync('git', ['status', '--porcelain=v1', '-uno'], { cwd: repoRoot })).stdout;
  must(trackedStatus.trim() === '', 'tracked repository files are not clean');
  const manifestPath = `${a.artifactDir}/BUILD_MANIFEST.txt`;
  const out = await wsl(['sha256sum', '--', manifestPath], raw.wslDistro);
  must(out.split(/\s+/)[0] === raw.buildManifestSha256, 'build manifest SHA-256 mismatch');
  const manifest = await wsl(['cat', '--', manifestPath], raw.wslDistro);
  const field = (name) => new RegExp(`^${name}\\s*=\\s*(.*)$`, 'm').exec(manifest)?.[1]?.trim();
  must(field('source_variant_mode') === 'PRIVATE_GENESIS_SOURCE_VARIANT', 'not a private source variant');
  must(field('source_variant_id') === raw.variantId, 'build variant ID mismatch');
  must(field('source_variant_genesis_ts') === String(raw.genesisTimestamp), 'build genesis timestamp mismatch');
  must(field('meepcoin_source_tree') === '9ce29e2c482910d911d8d3277bf7de4e85fd679b', 'base source tree mismatch');
  const daemonSha = field('meepcoind');
  must(HEX64.test(daemonSha), 'manifest lacks daemon digest');
  const observedSha = (await wsl(['sha256sum', '--', `${a.artifactDir}/meepcoind`], raw.wslDistro)).split(/\s+/)[0];
  must(daemonSha === observedSha, 'daemon artifact differs from build manifest');
  const variantSha = field('source_variant_manifest_sha256');
  must(HEX64.test(variantSha), 'manifest lacks source variant digest');
  const observedVariantSha = (await wsl(['sha256sum', '--', `${a.artifactDir}/VARIANT_SOURCE_MANIFEST.json`], raw.wslDistro)).split(/\s+/)[0];
  must(variantSha === observedVariantSha, 'source variant manifest differs from build');
  const imageId = (await wsl(['docker', 'image', 'inspect', '--format', '{{.Id}}', raw.image], raw.wslDistro)).trim();
  must(imageId === raw.expectedImageId, 'Docker image ID mismatch');
  const labels = await wsl(['docker', 'info', '--format', '{{json .Labels}}'], raw.wslDistro);
  const topology = classifyWslDockerEngine({ status: 0, stdout: labels });
  must(topology.ok, `Docker engine topology refused: ${topology.error}`);
  return { actualCommit, manifestSha256: raw.buildManifestSha256, daemonSha256: daemonSha,
    variantManifestSha256: variantSha, imageId, dockerTopology: topology };
}

async function linked(a, b) {
  const table = await a.observeSocketTable();
  const aConns = table === null ? null : parseConnections(table, a.linuxPid);
  const bConns = table === null ? null : parseConnections(table, b.linuxPid);
  return checkPairConnections({ aConns, bConns, a: a.config, b: b.config });
}

// Shared read-only preflight and observation primitives for the separately identified
// minority experiment. Exporting these does not alter the historical honest pilot path.
export { sourcePreflight, linked, post, rpc, info, header, headers };

export async function runPilot(cfg, { startDaemon = startLocalDaemon, sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  clock = () => Date.now(), preflight = sourcePreflight,
  api = { post, info, header, headers }, observeLink = linked, signal = null } = {}) {
  const { raw, a: ca, b: cb } = cfg;
  const notAborted = () => must(signal?.aborted !== true, 'pilot interrupted; preserving the one-use attempt');
  notAborted();
  const identity = await preflight(cfg); // No reservation or daemon if the pinned build is wrong.
  notAborted();
  const ageBeforeReservation = Math.floor(clock() / 1000) - raw.genesisTimestamp;
  must(ageBeforeReservation >= 0 && ageBeforeReservation <= MAX_GENESIS_AGE_S,
    'genesis is already outside the predeclared age limit');
  const evidenceDir = resolve(raw.evidenceDir);
  mkdirSync(dirname(evidenceDir), { recursive: true });
  mkdirSync(evidenceDir); // Must be new. A failed run is never overwritten or retried under this ID.
  const reservation = { schema: 'meepcoin-honest-launch-pilot/1', state: 'RESERVED_ONE_USE',
    createdUtc: new Date(clock()).toISOString(), scope: 'HONEST_ONLY_PRIVATE_NO_WALLET_NO_ATTACK',
    config: raw, buildIdentity: identity, maxGenesisAgeSeconds: MAX_GENESIS_AGE_S,
    targetBlockHeight: TARGET_BLOCK_HEIGHT };
  const fd = openSync(`${evidenceDir}/reservation.json`, 'wx', 0o600);
  try { writeFileSync(fd, JSON.stringify(reservation, null, 2) + '\n'); } finally { closeSync(fd); }
  const events = createWriteStream(`${evidenceDir}/events.jsonl`, { flags: 'wx' });
  const write = (event) => events.write(JSON.stringify({ atUtc: new Date(clock()).toISOString(), ...event }) + '\n');
  let a = null, b = null, startedA = false, startedB = false, stopReason = 'ERROR';
  let report = null;
  let closeResults = [];
  const cleanup = [];
  try {
    notAborted();
    const ownStart = async (config) => {
      try { return await startDaemon({ config, signal,
        isRpcReady: async () => (await api.info(config.rpcPort)).height >= 1 }); }
      catch (e) { if (e.resource) cleanup.push(e.resource); throw e; }
    };
    a = await ownStart(ca); cleanup.push(a);
    notAborted();
    b = await ownStart(cb); cleanup.push(b);
    notAborted();
    write({ phase: 'DAEMONS_READY', a: { runDir: a.runDir, imageId: a.imageId, listeners: a.listeners },
      b: { runDir: b.runDir, imageId: b.imageId, listeners: b.listeners } });
    const ageAtStart = genesisGate([await api.header(ca.rpcPort, 0), await api.header(cb.rpcPort, 0)],
      raw.genesisTimestamp, raw.genesisHash, Math.floor(clock() / 1000));
    write({ phase: 'GENESIS_VERIFIED', ageSeconds: ageAtStart, hash: raw.genesisHash });
    const linkDeadline = clock() + LINK_WAIT_MS;
    for (;;) {
      notAborted();
      const [pair, ia, ib] = await Promise.all([observeLink(a, b), api.info(ca.rpcPort), api.info(cb.rpcPort)]);
      must(pair.ok, `unexpected P2P connection: ${pair.bad.join(',')}`);
      if (pair.linked && ia.synchronized && ib.synchronized && ia.height === 1 && ib.height === 1) break;
      must(clock() < linkDeadline, 'pair failed to link and synchronize at genesis');
      await sleep(500);
    }
    notAborted();
    write({ phase: 'PEER_LINK_VERIFIED' });
    startedA = true; // A lost response is ambiguous: stop even if start may not have taken effect.
    const first = await api.post(ca.rpcPort, '/start_mining', { miner_address: REAL_COINBASE_ADDRESS,
      threads_count: raw.threadsA, do_background_mining: false, ignore_battery: true });
    must(first.status === 'OK', 'A refused start_mining');
    notAborted();
    startedB = true;
    const second = await api.post(cb.rpcPort, '/start_mining', { miner_address: REAL_COINBASE_ADDRESS,
      threads_count: raw.threadsB, do_background_mining: false, ignore_battery: true });
    must(second.status === 'OK', 'B refused start_mining');
    notAborted();
    const [miningA, miningB] = await Promise.all([
      api.post(ca.rpcPort, '/mining_status', {}), api.post(cb.rpcPort, '/mining_status', {}),
    ]);
    must(miningA.active === true && miningB.active === true
      && miningA.threads_count === raw.threadsA && miningB.threads_count === raw.threadsB,
    'both daemon miners must report active at their assigned thread counts');
    const miningStart = clock();
    const deadline = miningStart + raw.budgetSeconds * 1000;
    write({ phase: 'MINING_STARTED', budgetSeconds: raw.budgetSeconds, deadlineUtc: new Date(deadline).toISOString(),
      threadsA: raw.threadsA, threadsB: raw.threadsB, miningStatusA: miningA, miningStatusB: miningB });
    for (;;) {
      notAborted();
      const [ia, ib, pair] = await Promise.all([api.info(ca.rpcPort), api.info(cb.rpcPort), observeLink(a, b)]);
      write({ phase: 'SAMPLE', secondsElapsed: Math.round((clock() - miningStart) / 1000), a: ia, b: ib,
        reciprocalLink: pair.linked, unexpectedConnections: pair.bad });
      must(pair.ok && pair.linked, 'private P2P link lost or unexpected peer appeared');
      if (clock() >= deadline) { stopReason = 'FIXED_WALL_BUDGET'; break; }
      if (ia.height >= TARGET_BLOCK_HEIGHT + 1 && ib.height >= TARGET_BLOCK_HEIGHT + 1) {
        stopReason = 'BOTH_AT_HEIGHT_61'; break;
      }
      await sleep(Math.min(POLL_MS, Math.max(0, deadline - clock())));
    }
    notAborted();
    const stopped = await Promise.all([api.post(ca.rpcPort, '/stop_mining', {}), api.post(cb.rpcPort, '/stop_mining', {})]);
    must(stopped.every((r) => r.status === 'OK'), 'a daemon did not acknowledge stop_mining');
    startedA = false; startedB = false;
    const [miningStoppedA, miningStoppedB] = await Promise.all([
      api.post(ca.rpcPort, '/mining_status', {}), api.post(cb.rpcPort, '/mining_status', {}),
    ]);
    must(miningStoppedA.active === false && miningStoppedB.active === false,
      'a daemon miner still reported active after stop_mining');
    write({ phase: 'MINING_STOP_CONFIRMED', stopped, miningStoppedA, miningStoppedB });
    const [fa, fb] = await Promise.all([api.info(ca.rpcPort), api.info(cb.rpcPort)]);
    const [ha, hb] = await Promise.all([api.headers(ca.rpcPort, fa.height - 1), api.headers(cb.rpcPort, fb.height - 1)]);
    must(ha.at(-1)?.hash === fa.tip && hb.at(-1)?.hash === fb.tip,
      'a final canonical history does not match its independently captured tip');
    report = { schema: 'meepcoin-honest-launch-pilot-result/1', stopReason,
      a: { ...fa, canonical: ha, runDir: a.runDir }, b: { ...fb, canonical: hb, runDir: b.runDir },
      verdict: trajectoryVerdict(ha, hb, stopReason),
      limitations: ['No direct internal hash-call counter; assigned threads and elapsed time are recorded, not achieved hash capacity.',
        'One engineering pilot cannot establish attack reachability, honest liveness probability, or consensus safety.'] };
    // Preserve the measurements before cleanup, but never present them as a completed run.
    writeFileSync(`${evidenceDir}/observation.json`, JSON.stringify({
      schema: 'meepcoin-honest-launch-pilot-observation/1', final: false,
      cleanupConfirmed: false, report,
    }, null, 2) + '\n', { flag: 'wx' });
  } catch (e) {
    write({ phase: 'FAILURE', error: String(e) });
    throw e;
  } finally {
    if (startedA) write({ phase: 'STOP_A_AFTER_FAILURE', result: await api.post(ca.rpcPort, '/stop_mining', {}).catch((e) => ({ unconfirmed: String(e) })) });
    if (startedB) write({ phase: 'STOP_B_AFTER_FAILURE', result: await api.post(cb.rpcPort, '/stop_mining', {}).catch((e) => ({ unconfirmed: String(e) })) });
    for (const resource of cleanup.filter((x) => typeof x.close === 'function').reverse()) {
      try { await resource.close(); closeResults.push({ runDir: resource.runDir, closed: resource.closed }); }
      catch (e) { closeResults.push({ runDir: resource.runDir, closed: false, error: String(e) }); }
    }
    write({ phase: 'CLEANUP', closeResults });
    writeFileSync(`${evidenceDir}/cleanup.json`, JSON.stringify(closeResults, null, 2) + '\n', { flag: 'wx' });
    await new Promise((r) => events.end(r));
  }
  must(closeResults.length === 2 && closeResults.every((r) => r.closed === true),
    'the owned daemon pair was not confirmed closed');
  report.cleanup = closeResults;
  report.observationSha256 = createHash('sha256').update(readFileSync(`${evidenceDir}/observation.json`)).digest('hex');
  report.eventsSha256 = createHash('sha256').update(readFileSync(`${evidenceDir}/events.jsonl`)).digest('hex');
  report.cleanupSha256 = createHash('sha256').update(readFileSync(`${evidenceDir}/cleanup.json`)).digest('hex');
  writeFileSync(`${evidenceDir}/result.json`, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const path = process.argv[2];
  if (process.argv.length !== 3 || !path) {
    console.error('Usage: node node/honest_launch_pilot.mjs <closed-config.json>');
    process.exitCode = 2;
  } else {
    const controller = new AbortController();
    const interrupt = () => controller.abort();
    process.on('SIGINT', interrupt);
    process.on('SIGTERM', interrupt);
    try {
      const cfg = validatePilotConfig(JSON.parse(readFileSync(path, 'utf8')));
      const result = await runPilot(cfg, { signal: controller.signal });
      console.log(JSON.stringify({ stopReason: result.stopReason, verdict: result.verdict }));
    } catch (e) { console.error(`HONEST PILOT FAILED: ${String(e)}`); process.exitCode = controller.signal.aborted ? 130 : 1; }
    finally { process.off('SIGINT', interrupt); process.off('SIGTERM', interrupt); }
  }
}
