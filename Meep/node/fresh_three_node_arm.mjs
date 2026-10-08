// Prospective three-daemon fresh-launch arm. The headless CLI requires an
// assigned slot, pinned config, and the protocol's separate source/build gate.
// No wallet, transaction, public peer, or daemon build occurs here.

import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { Worker } from 'node:worker_threads';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { checkListeners, checkThreeNodeConfigs, DAEMON_LIMITS, DAEMON_PROFILES,
  parseListeners,
  startLocalDaemon } from '../pool/dev/local_daemon.mjs';
import { environmentPreflight, enableReceiverVerificationLog } from './fresh_reachability_arm.mjs';
import { REACHABILITY_MODES, ASSIGNED_HASHES_PER_SECOND } from './fresh_reachability_core.mjs';
import { observeMesh } from './fresh_mesh_probe.mjs';
import { sourcePreflight, info, header, headers } from './honest_launch_pilot.mjs';
import { verifyThreeNodeEvidence } from './verify_three_node_evidence.mjs';

const execFileAsync = promisify(execFile);
const HEX64 = /^[0-9a-f]{64}$/;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/;
const RUN_ID = /^[a-z][a-z0-9-]{7,63}$/;
const PORT_KEYS = ['p2pA', 'p2pB', 'p2pC', 'rpcA', 'rpcB', 'rpcC'];
const ASSIGNED_PORT_ORDER = ['rpcA', 'p2pA', 'rpcB', 'p2pB', 'rpcC', 'p2pC'];
const SERIES_ROOT = 'C:\\Users\\tseng\\meepcoin-three-node-runs';
const V2_SERIES_ROOT = 'C:\\Users\\tseng\\meepcoin-three-node-v2-runs';
function freezeAssignments(slots) {
  for (const assigned of Object.values(slots)) {
    Object.freeze(assigned.ports);
    Object.freeze(assigned);
  }
  return Object.freeze(slots);
}
const ASSIGNED_SLOTS = freezeAssignments({
  C1: { arm: 'CONTROL', pairId: 'fresh3-pair1', ports: [59480, 59481, 59490, 59491, 59500, 59501] },
  A1: { arm: 'ATTACK', pairId: 'fresh3-pair1', ports: [59580, 59581, 59590, 59591, 59600, 59601] },
  A2: { arm: 'ATTACK', pairId: 'fresh3-pair2', ports: [59680, 59681, 59690, 59691, 59700, 59701] },
  C2: { arm: 'CONTROL', pairId: 'fresh3-pair2', ports: [59780, 59781, 59790, 59791, 59800, 59801] },
});
const V2_ASSIGNED_SLOTS = freezeAssignments({
  C1: { arm: 'CONTROL', pairId: 'fresh3v2-pair1', ports: [60480, 60481, 60490, 60491, 60500, 60501] },
  A1: { arm: 'ATTACK', pairId: 'fresh3v2-pair1', ports: [60580, 60581, 60590, 60591, 60600, 60601] },
  A2: { arm: 'ATTACK', pairId: 'fresh3v2-pair2', ports: [60680, 60681, 60690, 60691, 60700, 60701] },
  C2: { arm: 'CONTROL', pairId: 'fresh3v2-pair2', ports: [60780, 60781, 60790, 60791, 60800, 60801] },
});
// Two fixed campaigns, not caller-selected roots or a general experiment framework.
// Legacy names retain their original root and consumed slot ledger.
export function threeNodeSeriesFor(raw) {
  const v2 = typeof raw?.runId === 'string' && raw.runId.startsWith('fresh3v2-');
  return Object.freeze({ root: v2 ? V2_SERIES_ROOT : SERIES_ROOT,
    prefix: v2 ? 'fresh3v2' : 'fresh3', slots: v2 ? V2_ASSIGNED_SLOTS : ASSIGNED_SLOTS,
    freezeSchema: `meepcoin-three-node-series-freeze/${v2 ? 2 : 1}`,
    protocol: `FRESH_LAUNCH_THREE_NODE_${v2 ? 'V2_' : ''}PROTOCOL.md`,
    schedule: `FRESH_LAUNCH_THREE_NODE_${v2 ? 'V2_' : ''}SCHEDULE.md` });
}
const RECEIVER_VERIFY_CATEGORIES = '*:WARNING,verify:ERROR,global:INFO';
const MAX_GENESIS_AGE_S = 1800;
const LINK_WAIT_MS = 60_000;
const TOPOLOGY_SAMPLE_MS = 5_000;
const DETAIL_SAMPLE_MS = 15_000;
const POST_STOP_OBSERVE_MS = 10 * 60_000;
const HEIGHT_CAP = 90;
const WORKER_STOP_TIMEOUT_MS = 150_000;
const CLOSE_LIMITS = Object.freeze({ ...DAEMON_LIMITS,
  probeTimeoutMs: 390_000, stopGraceSeconds: 360, stopTimeoutMs: 420_000 });
const wait = (ms) => new Promise((done) => setTimeout(done, ms));
const sha = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
const shaBytes = (bytes) => createHash('sha256').update(bytes).digest('hex');
function must(ok, message) { if (!ok) throw new Error(`three-node arm: ${message}`); }

export function validateThreeNodeArmConfig(raw) {
  const keys = ['arm', 'artifactDir', 'budgetSeconds', 'buildManifestSha256', 'evidenceDir',
    'expectedImageId', 'genesisHash', 'genesisTimestamp', 'gid', 'image', 'pairId',
    'ports', 'repoCommit', 'runId', 'seriesFreezeSha256', 'uid', 'variantId', 'wslDistro'];
  must(raw && typeof raw === 'object' && !Array.isArray(raw)
    && Object.keys(raw).sort().join('|') === keys.sort().join('|'), 'closed config keys differ');
  must([REACHABILITY_MODES.CONTROL, REACHABILITY_MODES.ATTACK].includes(raw.arm), 'bad arm');
  must(RUN_ID.test(raw.runId) && RUN_ID.test(raw.pairId), 'bad run or pair ID');
  must(raw.evidenceDir === `${threeNodeSeriesFor(raw).root}\\${raw.runId}`,
    'evidence directory must be the exact private one-use path');
  must(/^[0-9a-f]{40}$/.test(raw.repoCommit) && HEX64.test(raw.buildManifestSha256)
    && HEX64.test(raw.genesisHash) && HEX64.test(raw.seriesFreezeSha256),
  'source/build/genesis/series identity is not pinned');
  must(RUN_ID.test(raw.variantId) && Number.isSafeInteger(raw.genesisTimestamp)
    && raw.genesisTimestamp > 1785283200, 'bad variant or genesis timestamp');
  must(/^meepcoin-build:[a-z0-9][a-z0-9._-]{0,127}$/.test(raw.image)
    && IMAGE_ID.test(raw.expectedImageId), 'bad pinned image');
  must(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/.test(raw.wslDistro), 'bad WSL distro');
  must(Number.isInteger(raw.uid) && raw.uid >= 1 && raw.uid <= 60000
    && Number.isInteger(raw.gid) && raw.gid >= 1 && raw.gid <= 60000, 'bad nonroot UID/GID');
  must(raw.ports && Object.keys(raw.ports).sort().join('|') === [...PORT_KEYS].sort().join('|'),
    'six exact private ports are required');
  must(new Set(Object.values(raw.ports)).size === 6
    && Object.values(raw.ports).every((p) => Number.isInteger(p) && p >= 1024 && p <= 65535),
  'six distinct numeric private ports are required');
  must(raw.budgetSeconds === 21600, 'draft arm budget is fixed at six hours');
  const nonce = randomBytes(10).toString('hex');
  const common = { wslDistro: raw.wslDistro, image: raw.image, artifactDir: raw.artifactDir,
    uid: raw.uid, gid: raw.gid, expectedImageId: raw.expectedImageId,
    profile: DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL };
  const node = (letter) => ({ ...common,
    runDir: `/home/tseng/meepcoin-private-run-${nonce}${letter.toLowerCase()}`,
    rpcPort: raw.ports[`rpc${letter}`], p2pPort: raw.ports[`p2p${letter}`],
    exclusivePeerP2pPorts: ['A', 'B', 'C'].filter((other) => other !== letter)
      .map((other) => raw.ports[`p2p${other}`]) });
  return Object.freeze({ raw: Object.freeze({ ...raw, ports: Object.freeze({ ...raw.ports }) }),
    ...checkThreeNodeConfigs({ a: node('A'), b: node('B'), c: node('C') }) });
}

export function validateThreeNodeRunConfig(cfg) {
  must(cfg && typeof cfg === 'object', 'missing checked config');
  validateThreeNodeArmConfig(cfg.raw);
  const checked = checkThreeNodeConfigs({ a: cfg.a, b: cfg.b, c: cfg.c });
  for (const letter of ['A', 'B', 'C']) {
    const node = checked[letter.toLowerCase()];
    must(node.rpcPort === cfg.raw.ports[`rpc${letter}`]
      && node.p2pPort === cfg.raw.ports[`p2p${letter}`]
      && node.image === cfg.raw.image && node.artifactDir === cfg.raw.artifactDir
      && node.expectedImageId === cfg.raw.expectedImageId
      && node.wslDistro === cfg.raw.wslDistro
      && node.uid === cfg.raw.uid && node.gid === cfg.raw.gid,
    `${letter} daemon does not match pinned raw config`);
  }
  return true;
}

export function validateThreeNodeAssignedSlot(raw, slot) {
  const series = threeNodeSeriesFor(raw);
  const assigned = series.slots[slot];
  must(assigned !== undefined, 'slot is not in the prospective four-arm schedule');
  must(raw.arm === assigned.arm && raw.pairId === assigned.pairId,
    'arm or pair differs from assigned slot');
  must(new RegExp(`^${series.prefix}-\\d{8}t\\d{6}z-${slot.toLowerCase()}$`).test(raw.runId),
    'run ID does not name its assigned slot');
  must(ASSIGNED_PORT_ORDER.every((key, i) => raw.ports[key] === assigned.ports[i]),
    'six ports differ from assigned slot');
  return true;
}

export function validateThreeNodeSeriesFreeze(raw, freezeBytes, protocolBytes, scheduleBytes) {
  must(Buffer.isBuffer(freezeBytes) && shaBytes(freezeBytes) === raw.seriesFreezeSha256,
    'external series freeze differs from pinned digest');
  const freeze = JSON.parse(freezeBytes.toString('utf8'));
  const series = threeNodeSeriesFor(raw);
  must(freeze?.schema === series.freezeSchema
    && freeze.status === 'AUTHORIZED'
    && freeze.repoCommit === raw.repoCommit
    && freeze.builderImageId === raw.expectedImageId
    && freeze.protocolSha256 === shaBytes(protocolBytes)
    && freeze.scheduleSha256 === shaBytes(scheduleBytes),
  'series source, builder, or protocol differs from authorized freeze');
  if (series.prefix === 'fresh3v2') {
    must(freeze.seriesId === 'fresh3v2-20260930'
      && freeze.evidenceRoot === series.root
      && freeze.windowRecoveryLimit === 8,
    'v2 campaign identity, evidence root, or recovery limit differs');
  }
  return true;
}

export function claimThreeNodeSlot(raw, root = threeNodeSeriesFor(raw).root) {
  const slot = /-(c1|a1|a2|c2)$/.exec(raw.runId)?.[1];
  must(slot !== undefined, 'one-use slot name is missing');
  validateThreeNodeAssignedSlot(raw, slot.toUpperCase());
  const slotsRoot = join(root, 'slots');
  mkdirSync(slotsRoot, { recursive: true });
  for (const prior of ['c1', 'a1', 'a2', 'c2'].slice(0,
    ['c1', 'a1', 'a2', 'c2'].indexOf(slot))) {
    const priorClaim = JSON.parse(readFileSync(join(slotsRoot, prior, 'claim.json'), 'utf8'));
    const audit = JSON.parse(readFileSync(join(slotsRoot, prior, 'audit.json'), 'utf8'));
    must(priorClaim?.state === 'CONSUMED_ONE_USE'
      && priorClaim?.slot === prior.toUpperCase()
      && priorClaim?.repoCommit === raw.repoCommit
      && priorClaim?.seriesFreezeSha256 === raw.seriesFreezeSha256
      && audit?.schema === 'meepcoin-three-node-slot-audit/1'
      && audit?.status === 'INDEPENDENTLY_AUDITED_COMPLETE'
      && audit?.slot === prior.toUpperCase()
      && audit?.runId === priorClaim.runId && HEX64.test(audit.resultSha256),
    `prior ${prior.toUpperCase()} arm lacks a matching independent audit`);
    verifyThreeNodeEvidence(join(root, priorClaim.runId), audit.resultSha256);
  }
  const claimDir = join(slotsRoot, slot);
  mkdirSync(claimDir); // atomic across processes; a failed attempt consumes the assigned slot
  writeFileSync(join(claimDir, 'claim.json'), JSON.stringify({
    schema: 'meepcoin-three-node-slot-claim/1', state: 'CONSUMED_ONE_USE',
    slot: slot.toUpperCase(), runId: raw.runId, repoCommit: raw.repoCommit,
    seriesFreezeSha256: raw.seriesFreezeSha256,
    claimedAtUtc: new Date().toISOString(),
  }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return claimDir;
}

export async function observeThreeNodeBoundary(resources) {
  must(Array.isArray(resources) && resources.length === 3,
    'exactly three owned daemons are required for boundary observation');
  const [mesh, table] = await Promise.all([
    observeMesh(resources), resources[0].observeListenerTable(),
  ]);
  const listeners = resources.map((resource, i) => {
    const observed = table === null ? null : parseListeners(table, resource.linuxPid);
    return { name: ['A', 'B', 'C'][i], observed,
      verdict: checkListeners(observed, resource.config) };
  });
  const listenerBad = listeners.filter((row) => !row.verdict.ok)
    .map((row) => `${row.name}: listener ${row.verdict.reason}`);
  return { ...mesh, ok: mesh.ok && listenerBad.length === 0,
    bad: [...mesh.bad, ...listenerBad], listeners };
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
    } else if (message?.kind === 'DONE') {
      result = message.summary; write({ phase: 'WORKER_DONE', worker: role, result });
    } else if (message?.kind === 'ERROR') {
      failure = message; write({ phase: 'WORKER_ERROR', worker: role, ...message });
    } else {
      failure = { code: 'bad_worker_message' };
      write({ phase: 'WORKER_ERROR', worker: role, ...failure });
    }
  });
  worker.on('error', (error) => {
    failure = { code: 'worker_exception', message: String(error).slice(0, 300) };
    write({ phase: 'WORKER_ERROR', worker: role, ...failure });
  });
  worker.on('exit', (code) => {
    exited = true; exitCode = code;
    if (code !== 0 || result === null) failure ??= { code: 'unexpected_worker_exit', exitCode: code };
  });
  return Object.freeze({ role, get started() { return started; }, get firstHash() { return firstHash; },
    get result() { return result; }, get failure() { return failure; },
    get exited() { return exited; }, get exitCode() { return exitCode; },
    stop() { worker.postMessage('STOP'); }, terminate() { return worker.terminate(); } });
}

async function copyOwnedLog({ distro, runDir, destination }) {
  const { stdout } = await execFileAsync('wsl.exe', ['-d', distro, '--exec', 'cat', '--',
    `${runDir}/meepcoind.log`], { encoding: 'buffer', windowsHide: true,
    timeout: 30_000, maxBuffer: 32 * 1024 * 1024 });
  must(Buffer.isBuffer(stdout) && stdout.length > 0, 'owned daemon log is empty or unavailable');
  writeFileSync(destination, stdout, { flag: 'wx', mode: 0o600 });
  return { bytes: stdout.length, sha256: sha(destination) };
}

export function checkWslPortInventory(output, ports) {
  must(typeof output === 'string', 'WSL listener inventory is unavailable');
  const occupied = new Set();
  for (const line of output.split(/\r?\n/).filter((row) => row.trim())) {
    const fields = line.trim().split(/\s+/);
    const local = fields.at(-2);
    const match = /:(\d+)$/.exec(local ?? '');
    must(match !== null, 'WSL listener inventory is malformed');
    occupied.add(Number(match[1]));
  }
  const conflicts = Object.values(ports).filter((port) => occupied.has(port));
  must(conflicts.length === 0, `WSL private ports occupied: ${conflicts.join(',')}`);
  return { checkedPorts: Object.values(ports), listenerCount: occupied.size };
}

export async function threeNodeEnvironmentPreflight(cfg, base = environmentPreflight,
  readWslListeners = async (distro) => (await execFileAsync('wsl.exe',
    ['-d', distro, '--exec', 'ss', '-H', '-ltn'],
    { windowsHide: true, timeout: 30_000, maxBuffer: 1024 * 1024 })).stdout) {
  const machine = await base(cfg);
  const wslPorts = checkWslPortInventory(await readWslListeners(cfg.raw.wslDistro), cfg.raw.ports);
  return { ...machine, wslPorts };
}

export async function runThreeNodeArm(cfg, { signal = null, preflight = sourcePreflight,
  machinePreflight = threeNodeEnvironmentPreflight, startDaemon = startLocalDaemon,
  observe = observeThreeNodeBoundary, api = { info, header, headers, enableReceiverVerificationLog },
  makeWorker = ownedWorker, preserveLog = copyOwnedLog, appendEvent = appendFileSync,
  validateConfig = validateThreeNodeRunConfig, claimSlot = claimThreeNodeSlot,
  clock = () => Date.now(), sleep = wait } = {}) {
  validateConfig(cfg);
  const { raw } = cfg;
  const configs = [cfg.a, cfg.b, cfg.c];
  let evidenceWriteFailed = false;
  const alive = () => {
    must(signal?.aborted !== true, 'interrupted');
    must(!evidenceWriteFailed, 'event evidence write failed');
  };
  alive();
  const identity = await preflight(cfg);
  alive();
  const machine = await machinePreflight(cfg);
  alive();
  const ageBefore = Math.floor(clock() / 1000) - raw.genesisTimestamp;
  must(ageBefore >= 0 && ageBefore <= MAX_GENESIS_AGE_S,
    'genesis is stale before reservation');
  claimSlot(raw);
  const evidenceDir = resolve(raw.evidenceDir);
  mkdirSync(dirname(evidenceDir), { recursive: true });
  mkdirSync(evidenceDir); // never reuse a consumed attempt
  writeFileSync(`${evidenceDir}/reservation.json`, JSON.stringify({
    schema: 'meepcoin-three-node-arm-reservation/1', state: 'CONSUMED_ONE_USE',
    createdUtc: new Date(clock()).toISOString(), raw, configs, identity, machine,
    assignedRates: ASSIGNED_HASHES_PER_SECOND, heightCap: HEIGHT_CAP,
    topologySampleMs: TOPOLOGY_SAMPLE_MS, detailSampleMs: DETAIL_SAMPLE_MS,
    postStopObservationMs: POST_STOP_OBSERVE_MS,
  }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  const eventsPath = `${evidenceDir}/events.jsonl`;
  writeFileSync(eventsPath, '', { flag: 'wx', mode: 0o600 });
  const write = (event) => {
    try {
      appendEvent(eventsPath, JSON.stringify({ atUtc: new Date(clock()).toISOString(), ...event }) + '\n');
    } catch {
      // Worker event callbacks must not throw outside the runner's try/finally cleanup boundary.
      evidenceWriteFailed = true;
    }
  };
  const resources = [];
  const workers = [];
  const closeResults = [];
  const logs = [];
  let observation = null;
  let stopReason = 'ERROR';
  try {
    for (const config of configs) {
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
    write({ phase: 'DAEMONS_READY', daemons: resources.map((r) => ({ runDir: r.runDir,
      containerName: r.containerName, imageId: r.imageId, linuxPid: r.linuxPid,
      listeners: r.listeners })) });
    const receipts = await Promise.all(configs.map((c) => api.enableReceiverVerificationLog(c.rpcPort)));
    must(receipts.every((r, i) => r?.port === configs[i].rpcPort
      && r.categories === RECEIVER_VERIFY_CATEGORIES), 'three receiver log acknowledgements required');
    write({ phase: 'RECEIVER_VERIFICATION_LOGGING_CONFIRMED', receipts });
    const genesis = await Promise.all(configs.map((c) => api.header(c.rpcPort, 0)));
    const age = Math.floor(clock() / 1000) - raw.genesisTimestamp;
    must(age >= 0 && age <= MAX_GENESIS_AGE_S
      && genesis.every((h) => Number(h?.height) === 0 && h.hash === raw.genesisHash
        && Number(h.timestamp) === raw.genesisTimestamp), 'compiled fresh genesis mismatch');
    write({ phase: 'GENESIS_VERIFIED', ageSeconds: age, hash: raw.genesisHash });
    const linkDeadline = clock() + LINK_WAIT_MS;
    for (;;) {
      alive();
      const [mesh, ...states] = await Promise.all([observe(resources),
        ...configs.map((c) => api.info(c.rpcPort))]);
      write({ phase: 'LINK_WAIT', mesh, states });
      must(mesh.ok, `unexpected private connection: ${mesh.bad.join('; ')}`);
      must(states.every((s) => s.height === 1 && s.tip === raw.genesisHash),
        'chain changed before mining');
      if (mesh.linked && mesh.links.length === 3 && states.every((s) => s.synchronized)) break;
      must(clock() < linkDeadline, 'three-daemon mesh did not link and synchronize');
      await sleep(1000);
    }
    write({ phase: 'FULL_MESH_VERIFIED' });
    alive();
    workers.push(makeWorker({ role: 'h1', mode: REACHABILITY_MODES.HONEST,
      port: cfg.a.rpcPort, peerPort: cfg.b.rpcPort, write }));
    workers.push(makeWorker({ role: 'h2', mode: REACHABILITY_MODES.HONEST,
      port: cfg.b.rpcPort, peerPort: cfg.a.rpcPort, write }));
    const honestDeadline = clock() + 30_000;
    while (workers.some((w) => !w.started || !w.firstHash) && clock() < honestDeadline) {
      alive();
      must(workers.every((w) => !w.failure && !w.exited), 'honest miner failed before third start');
      await sleep(100);
    }
    must(workers.every((w) => w.started && w.firstHash && !w.failure && !w.exited),
      'both honest miners must prove a hash before the third starts');
    const [preThirdMesh, ...preThirdStates] = await Promise.all([observe(resources),
      ...configs.map((c) => api.info(c.rpcPort))]);
    write({ phase: 'PRE_THIRD_MESH', mesh: preThirdMesh, states: preThirdStates });
    alive();
    must(preThirdMesh.ok && preThirdMesh.linked && preThirdMesh.links.length === 3
      && preThirdStates.every((s) => s.synchronized),
      'private full mesh lost before third miner start');
    workers.push(makeWorker({ role: 'third', mode: raw.arm,
      port: cfg.c.rpcPort, peerPort: cfg.a.rpcPort, write }));
    const startMs = clock();
    const deadline = startMs + raw.budgetSeconds * 1000;
    let nextDetail = startMs;
    write({ phase: 'ALL_MINERS_STARTED', deadlineUtc: new Date(deadline).toISOString(),
      routes: { h1: 'A', h2: 'B', third: 'C' }, assignedRates: ASSIGNED_HASHES_PER_SECOND,
      arm: raw.arm });
    for (;;) {
      alive();
      must(workers.every((w) => !w.failure && !w.exited), 'miner failed during arm');
      const [mesh, ...states] = await Promise.all([observe(resources),
        ...configs.map((c) => api.info(c.rpcPort))]);
      write({ phase: 'TOPOLOGY_SAMPLE', elapsedSeconds: Math.round((clock() - startMs) / 1000), mesh });
      must(mesh.ok && mesh.linked && mesh.links.length === 3,
        'private full mesh lost or unexpected peer appeared');
      if (clock() >= nextDetail) {
        const tips = await Promise.all(configs.map((c, i) => api.header(c.rpcPort, states[i].height - 1)));
        write({ phase: 'CHAIN_SAMPLE', elapsedSeconds: Math.round((clock() - startMs) / 1000),
          states, tips });
        nextDetail = clock() + DETAIL_SAMPLE_MS;
      }
      if (clock() >= deadline) { stopReason = 'FIXED_WALL_BUDGET'; break; }
      if (states.every((s) => s.height >= HEIGHT_CAP + 1)) {
        stopReason = 'ALL_AT_HEIGHT_CAP'; break;
      }
      await sleep(Math.min(TOPOLOGY_SAMPLE_MS, Math.max(0, deadline - clock())));
    }
    for (const worker of workers) worker.stop();
    const stopDeadline = clock() + WORKER_STOP_TIMEOUT_MS;
    while (workers.some((w) => !w.exited) && clock() < stopDeadline) await sleep(100);
    must(workers.every((w) => w.exited && w.exitCode === 0 && w.result && !w.failure),
      'worker did not stop cleanly');
    write({ phase: 'MINERS_STOPPED', stopReason, workerResults: workers.map((w) => w.result) });
    const observeUntil = clock() + POST_STOP_OBSERVE_MS;
    let nextPostStopDetail = clock();
    while (clock() < observeUntil) {
      alive();
      const [mesh, ...states] = await Promise.all([observe(resources),
        ...configs.map((c) => api.info(c.rpcPort))]);
      write({ phase: 'POST_STOP_SAMPLE', mesh, states });
      must(mesh.ok && mesh.linked && mesh.links.length === 3,
        'private full mesh lost during post-stop observation');
      if (clock() >= nextPostStopDetail) {
        const tips = await Promise.all(configs.map((c, i) => api.header(c.rpcPort, states[i].height - 1)));
        write({ phase: 'POST_STOP_CHAIN_SAMPLE', states, tips });
        nextPostStopDetail = clock() + DETAIL_SAMPLE_MS;
      }
      await sleep(Math.min(TOPOLOGY_SAMPLE_MS, Math.max(0, observeUntil - clock())));
    }
    const finalStates = await Promise.all(configs.map((c) => api.info(c.rpcPort)));
    const chains = await Promise.all(configs.map((c, i) => api.headers(c.rpcPort, finalStates[i].height - 1)));
    must(chains.every((chain, i) => chain.at(-1)?.hash === finalStates[i].tip),
      'final canonical history does not match a daemon tip');
    observation = { schema: 'meepcoin-three-node-observation/1', final: false,
      arm: raw.arm, pairId: raw.pairId, stopReason,
      workerResults: workers.map((w) => w.result),
      nodes: Object.fromEntries(['A', 'B', 'C'].map((letter, i) => [letter,
        { ...finalStates[i], canonical: chains[i], runDir: resources[i].runDir }])),
      interpretation: 'DESCRIPTIVE_ONLY_PENDING_RECEIVER_VERDICT_AUDIT',
      limitations: ['A sampled full mesh is not proof of connectivity between samples.',
        'No automatic attack verdict follows from height, tip divergence, or a log line alone.'] };
    writeFileSync(`${evidenceDir}/observation.json`, JSON.stringify(observation, null, 2) + '\n',
      { flag: 'wx', mode: 0o600 });
  } catch (error) {
    write({ phase: 'FAILURE', code: error?.code ?? 'run_error', message: String(error).slice(0, 400) });
    throw error;
  } finally {
    for (const worker of workers) if (!worker.exited) worker.stop();
    const until = clock() + WORKER_STOP_TIMEOUT_MS;
    while (workers.some((w) => !w.exited) && clock() < until) await sleep(100);
    for (const worker of workers.filter((w) => !w.exited)) {
      const exitCode = await worker.terminate();
      write({ phase: 'WORKER_FORCE_TERMINATED', worker: worker.role, exitCode });
    }
    for (const resource of [...resources].reverse()) {
      try {
        await resource.close();
        closeResults.push({ runDir: resource.runDir, closed: resource.closed,
          shutdown: resource.shutdownOutcome });
      } catch (error) {
        let confirmed = false;
        try { await resource.forceClose(); confirmed = resource.closed; } catch { /* retain uncertainty */ }
        closeResults.push({ runDir: resource.runDir, closed: confirmed, forced: true,
          error: String(error).slice(0, 300) });
      }
    }
    for (let i = 0; i < resources.length; i++) {
      try {
        logs.push({ runDir: resources[i].runDir, ...await preserveLog({
          distro: raw.wslDistro, runDir: resources[i].runDir,
          destination: `${evidenceDir}/daemon-${['A', 'B', 'C'][i]}.log`,
        }) });
      } catch (error) {
        logs.push({ runDir: resources[i].runDir, error: String(error).slice(0, 300) });
      }
    }
    write({ phase: 'CLEANUP', closeResults, logs });
    writeFileSync(`${evidenceDir}/cleanup.json`, JSON.stringify({ closeResults, logs }, null, 2) + '\n',
      { flag: 'wx', mode: 0o600 });
  }
  must(!evidenceWriteFailed, 'event evidence write failed');
  must(closeResults.length === 3 && closeResults.every((x) => x.closed && !x.forced
    && x.shutdown?.gracefulProtocolShutdown === true), 'three daemons did not close gracefully');
  must(logs.length === 3 && logs.every((x) => HEX64.test(x.sha256)),
    'three daemon logs were not preserved');
  const result = { ...observation, final: true, cleanupConfirmed: true, logs,
    reservationSha256: sha(`${evidenceDir}/reservation.json`),
    observationSha256: sha(`${evidenceDir}/observation.json`),
    eventsSha256: sha(`${evidenceDir}/events.jsonl`),
    cleanupSha256: sha(`${evidenceDir}/cleanup.json`) };
  writeFileSync(`${evidenceDir}/result.json`, JSON.stringify(result, null, 2) + '\n',
    { flag: 'wx', mode: 0o600 });
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4) {
    console.error('Usage: node node/fresh_three_node_arm.mjs <C1|A1|A2|C2> <closed-config.json>');
    process.exitCode = 2;
  } else {
    const abort = new AbortController();
    const stop = () => abort.abort();
    process.on('SIGINT', stop); process.on('SIGTERM', stop);
    try {
      const raw = JSON.parse(readFileSync(process.argv[3], 'utf8'));
      validateThreeNodeAssignedSlot(raw, process.argv[2]);
      const series = threeNodeSeriesFor(raw);
      validateThreeNodeSeriesFreeze(raw, readFileSync(join(series.root, 'SERIES_FREEZE.json')),
        readFileSync(new URL(`../docs/${series.protocol}`, import.meta.url)),
        readFileSync(new URL(`../docs/${series.schedule}`, import.meta.url)));
      const cfg = validateThreeNodeArmConfig(raw);
      const result = await runThreeNodeArm(cfg, { signal: abort.signal });
      console.log(JSON.stringify({ arm: result.arm, stopReason: result.stopReason,
        finalHeights: ['A', 'B', 'C'].map((node) => result.nodes[node].height),
        cleanupConfirmed: true }));
    } catch (error) {
      console.error(`THREE-NODE ARM FAILED: ${String(error)}`);
      process.exitCode = 1;
    } finally {
      process.off('SIGINT', stop); process.off('SIGTERM', stop);
    }
  }
}
