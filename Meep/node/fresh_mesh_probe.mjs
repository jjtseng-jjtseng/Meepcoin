#!/usr/bin/env node
// One-use private three-daemon connectivity probe. It creates no miner, wallet or transaction.
// This is a topology preflight, not an attack arm or a timestamp-result measurement.

import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { checkThreeNodeConfigs, checkThreeNodeConnections, DAEMON_LIMITS,
  DAEMON_PROFILES, parseConnections, startLocalDaemon } from '../pool/dev/local_daemon.mjs';
import { environmentPreflight, enableReceiverVerificationLog } from './fresh_reachability_arm.mjs';
import { header, info, sourcePreflight } from './honest_launch_pilot.mjs';

const execFileAsync = promisify(execFile);
const HEX64 = /^[0-9a-f]{64}$/;
const RUN_ID = /^meshprobe-[a-z0-9-]{8,54}$/;
const PORT_KEYS = ['p2pA', 'p2pB', 'p2pC', 'rpcA', 'rpcB', 'rpcC'];
const LINK_WAIT_MS = 60_000;
const OBSERVE_MS = 30_000;
const SAMPLE_MS = 5_000;
const CLOSE_LIMITS = Object.freeze({ ...DAEMON_LIMITS,
  probeTimeoutMs: 390_000, stopGraceSeconds: 360, stopTimeoutMs: 420_000 });
const wait = (ms) => new Promise((done) => setTimeout(done, ms));
const sha = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
function must(condition, message) { if (!condition) throw new Error(`mesh probe: ${message}`); }

export function validateMeshProbeConfig(raw) {
  const keys = ['artifactDir', 'buildManifestSha256', 'evidenceDir', 'expectedImageId',
    'genesisHash', 'genesisTimestamp', 'gid', 'image', 'ports', 'repoCommit', 'runId',
    'uid', 'variantId', 'wslDistro'];
  must(raw && typeof raw === 'object' && !Array.isArray(raw)
    && Object.keys(raw).sort().join('|') === keys.sort().join('|'), 'closed configuration keys differ');
  must(RUN_ID.test(raw.runId), 'bad one-use run id');
  must(raw.evidenceDir === `C:\\Users\\tseng\\meepcoin-mesh-probe-runs\\${raw.runId}`,
    'evidence directory must be the exact private one-use path');
  must(/^[0-9a-f]{40}$/.test(raw.repoCommit) && HEX64.test(raw.genesisHash)
    && HEX64.test(raw.buildManifestSha256), 'source or build identity is not pinned');
  must(Number.isSafeInteger(raw.genesisTimestamp) && raw.genesisTimestamp > 0,
    'genesis timestamp is not pinned');
  must(raw.ports && Object.keys(raw.ports).sort().join('|') === [...PORT_KEYS].sort().join('|'),
    'the exact six ports are required');
  const ports = Object.values(raw.ports);
  must(new Set(ports).size === 6 && ports.every((p) => Number.isInteger(p) && p >= 1024 && p <= 65535),
    'six distinct private ports are required');
  const suffix = randomBytes(8).toString('hex');
  const common = { wslDistro: raw.wslDistro, image: raw.image, artifactDir: raw.artifactDir,
    uid: raw.uid, gid: raw.gid, expectedImageId: raw.expectedImageId,
    profile: DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL };
  const node = (letter) => ({ ...common,
    runDir: `/home/tseng/meepcoin-private-run-${suffix}${letter}`,
    rpcPort: raw.ports[`rpc${letter}`], p2pPort: raw.ports[`p2p${letter}`],
    exclusivePeerP2pPorts: ['A', 'B', 'C'].filter((other) => other !== letter)
      .map((other) => raw.ports[`p2p${other}`]) });
  const configs = checkThreeNodeConfigs({ a: node('A'), b: node('B'), c: node('C') });
  return Object.freeze({ raw: Object.freeze({ ...raw, ports: Object.freeze({ ...raw.ports }) }),
    ...configs });
}

export async function observeMesh(resources) {
  const table = await resources[0].observeSocketTable();
  return checkThreeNodeConnections({ nodes: resources.map((resource, i) => ({
    name: ['A', 'B', 'C'][i], rpcPort: resource.config.rpcPort, p2pPort: resource.config.p2pPort,
    connections: table === null ? null : parseConnections(table, resource.linuxPid),
  })) });
}

async function copyLog({ distro, runDir, destination }) {
  const { stdout } = await execFileAsync('wsl.exe', ['-d', distro, '--exec', 'cat', '--',
    `${runDir}/meepcoind.log`], { encoding: 'buffer', windowsHide: true,
    timeout: 30_000, maxBuffer: 16 * 1024 * 1024 });
  must(Buffer.isBuffer(stdout) && stdout.length > 0, 'daemon log unavailable or empty');
  writeFileSync(destination, stdout, { flag: 'wx', mode: 0o600 });
  return { bytes: stdout.length, sha256: sha(destination) };
}

export async function runMeshProbe(cfg, { signal = null, startDaemon = startLocalDaemon,
  identityPreflight = sourcePreflight, machinePreflight = environmentPreflight,
  observe = observeMesh, api = { info, header, enableReceiverVerificationLog },
  clock = () => Date.now(), sleep = wait, preserveLog = copyLog } = {}) {
  const { raw } = cfg;
  const alive = () => must(!signal?.aborted, 'interrupted');
  alive();
  const identity = await identityPreflight(cfg);
  alive();
  const machine = await machinePreflight(cfg);
  alive();
  const evidenceDir = resolve(raw.evidenceDir);
  mkdirSync(dirname(evidenceDir), { recursive: true });
  mkdirSync(evidenceDir); // No -p: a prior reservation is never replaced or resumed.
  const reservation = { schema: 'meepcoin-private-mesh-probe/1', state: 'CONSUMED_ONE_USE',
    createdUtc: new Date(clock()).toISOString(), scope: 'THREE_DAEMONS_NO_MINING_NO_WALLET',
    raw, configs: { a: cfg.a, b: cfg.b, c: cfg.c }, identity, machine,
    linkWaitMs: LINK_WAIT_MS, observeMs: OBSERVE_MS, sampleMs: SAMPLE_MS };
  writeFileSync(`${evidenceDir}/reservation.json`, JSON.stringify(reservation, null, 2) + '\n',
    { flag: 'wx', mode: 0o600 });
  const event = (phase, details = {}) => appendFileSync(`${evidenceDir}/events.jsonl`,
    JSON.stringify({ atUtc: new Date(clock()).toISOString(), phase, ...details }) + '\n');
  const resources = [];
  const closed = [];
  const logs = [];
  let failure = null;
  let observations = 0;
  try {
    for (const config of [cfg.a, cfg.b, cfg.c]) {
      alive();
      try {
        const resource = await startDaemon({ config, signal, limits: CLOSE_LIMITS,
          isRpcReady: async () => (await api.info(config.rpcPort)).height >= 1 });
        resources.push(resource);
      } catch (error) {
        if (error.resource) resources.push(error.resource);
        throw error;
      }
    }
    event('DAEMONS_READY', { daemons: resources.map((r) => ({ runDir: r.runDir,
      containerName: r.containerName, imageId: r.imageId, linuxPid: r.linuxPid,
      listeners: r.listeners })) });
    for (const config of [cfg.a, cfg.b, cfg.c]) {
      const receipt = await api.enableReceiverVerificationLog(config.rpcPort);
      event('VERIFY_LOG_ACK', { receipt });
    }
    const genesis = await Promise.all([cfg.a, cfg.b, cfg.c].map((config) => api.header(config.rpcPort, 0)));
    must(genesis.every((h) => h.hash === raw.genesisHash && Number(h.height) === 0),
      'compiled genesis differs on a daemon');
    event('GENESIS_VERIFIED', { hash: raw.genesisHash });
    const deadline = clock() + LINK_WAIT_MS;
    for (;;) {
      alive();
      const [mesh, ...states] = await Promise.all([observe(resources),
        ...[cfg.a, cfg.b, cfg.c].map((config) => api.info(config.rpcPort))]);
      event('LINK_WAIT', { mesh, states });
      must(mesh.ok, `unexpected connection: ${mesh.bad.join('; ')}`);
      must(states.every((s) => s.height === 1 && s.tip === raw.genesisHash),
        'the no-mining chain changed or differs');
      if (mesh.linked && states.every((s) => s.synchronized)) break;
      must(clock() < deadline, 'full mesh did not synchronize before deadline');
      await sleep(1000);
    }
    const until = clock() + OBSERVE_MS;
    do {
      alive();
      const [mesh, ...states] = await Promise.all([observe(resources),
        ...[cfg.a, cfg.b, cfg.c].map((config) => api.info(config.rpcPort))]);
      event('MESH_SAMPLE', { mesh, states });
      must(mesh.ok && mesh.linked && mesh.links.length === 3, 'a private mesh link was lost');
      must(states.every((s) => s.height === 1 && s.tip === raw.genesisHash && s.synchronized),
        'the no-mining chain changed or unsynchronized');
      observations += 1;
      if (clock() >= until) break;
      await sleep(Math.min(SAMPLE_MS, Math.max(0, until - clock())));
    } while (true);
    event('OBSERVATION_COMPLETE', { observations });
  } catch (error) {
    failure = { code: error?.code ?? 'probe_failed', message: String(error).slice(0, 400) };
    event('FAILURE', failure);
  } finally {
    for (const resource of [...resources].reverse()) {
      try {
        await resource.close();
        closed.push({ runDir: resource.runDir, closed: resource.closed,
          shutdown: resource.shutdownOutcome });
      } catch (error) {
        let confirmed = false;
        try { await resource.forceClose(); confirmed = resource.closed; } catch { /* retain uncertainty */ }
        closed.push({ runDir: resource.runDir, closed: confirmed, forced: true,
          error: String(error).slice(0, 300) });
      }
    }
    for (let i = 0; i < resources.length; i += 1) {
      try {
        const copied = await preserveLog({ distro: raw.wslDistro, runDir: resources[i].runDir,
          destination: `${evidenceDir}/daemon-${['A', 'B', 'C'][i]}.log` });
        logs.push({ runDir: resources[i].runDir, ...copied });
      } catch (error) {
        logs.push({ runDir: resources[i].runDir, error: String(error).slice(0, 300) });
      }
    }
    event('CLEANUP', { closed, logs });
    writeFileSync(`${evidenceDir}/cleanup.json`, JSON.stringify({ closed, logs }, null, 2) + '\n',
      { flag: 'wx' });
  }
  const cleanupConfirmed = closed.length === 3 && closed.every((x) => x.closed && !x.forced
    && x.shutdown?.gracefulProtocolShutdown === true);
  const logsPreserved = logs.length === 3 && logs.every((x) => HEX64.test(x.sha256));
  const result = { schema: 'meepcoin-private-mesh-probe-result/1', final: true,
    connectivityOnly: true, observations, linked: failure === null && observations > 0,
    cleanupConfirmed, logsPreserved, failure,
    reservationSha256: sha(`${evidenceDir}/reservation.json`),
    eventsSha256: sha(`${evidenceDir}/events.jsonl`),
    cleanupSha256: sha(`${evidenceDir}/cleanup.json`) };
  writeFileSync(`${evidenceDir}/result.json`, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    console.error('Usage: node node/fresh_mesh_probe.mjs <closed-config.json>');
    process.exitCode = 2;
  } else {
    const abort = new AbortController();
    const stop = () => abort.abort();
    process.on('SIGINT', stop); process.on('SIGTERM', stop);
    try {
      const cfg = validateMeshProbeConfig(JSON.parse(readFileSync(process.argv[2], 'utf8')));
      const result = await runMeshProbe(cfg, { signal: abort.signal });
      console.log(JSON.stringify(result));
      if (!result.linked || !result.cleanupConfirmed || !result.logsPreserved) process.exitCode = 1;
    } catch (error) { console.error(`MESH PROBE FAILED: ${String(error)}`); process.exitCode = 1; }
    finally { process.off('SIGINT', stop); process.off('SIGTERM', stop); }
  }
}
