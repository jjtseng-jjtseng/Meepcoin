// The one owned daemon, driven with injected stand-ins for the long-lived `wsl.exe docker run` child
// and for every probe. NO WSL, DOCKER, DAEMON OR SOCKET is started by this file; a guard below fails
// if any test could reach the real spawn.

import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  DAEMON_PROFILES, LocalDaemonError, PEER_TEST_FIXED_DIFFICULTY, artifactDirectoryUser, checkDaemonConfig, checkListeners,
  checkPairConnections, checkThreeNodeConfigs, checkThreeNodeConnections, daemonFlags, daemonLaunchArgs,
  PRIVATE_MESH_LOOPBACK_MAX_CONNECTIONS_PER_IP,
  parseConnections, parseListeners, startLocalDaemon,
} from '../local_daemon.mjs';

const CONFIG = Object.freeze({
  wslDistro: 'Ubuntu',
  image: 'meepcoin-build:roundg-build3-20260914t221939z',
  artifactDir: '/home/tseng/meepcoin-roundg-build3-20260914T221939Z/out',
  runDir: '/home/tseng/meepcoin-private-run-abcdef0123456789',
  rpcPort: 28081,
  p2pPort: 28080,
  uid: 1000,
  gid: 1000,
});
const PID = 4321;
const IMAGE_ID = `sha256:${'d'.repeat(64)}`;
const PEER_CONFIG = Object.freeze({
  ...CONFIG,
  profile: DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_TEST,
  exclusivePeerP2pPort: 28090,
  fixedDifficulty: PEER_TEST_FIXED_DIFFICULTY,
  expectedImageId: IMAGE_ID,
});
const SS_LOOPBACK = [
  `tcp   LISTEN 0      4096       127.0.0.1:28081      0.0.0.0:*    users:(("meepcoind",pid=${PID},fd=12))`,
  'tcp   LISTEN 0      4096       127.0.0.1:2375       0.0.0.0:*    users:(("other",pid=99,fd=3))',
].join('\n');

test('artifact paths accept the legacy out layout and the fresh direct-export layout only', () => {
  for (const path of [
    '/home/tseng/meepcoin-roundg-build3-20260914T221939Z/out',
    '/home/tseng/meepcoin-runtimeclosure-build-20260924T201900Z',
  ]) assert.equal(artifactDirectoryUser(path), 'tseng', path);

  for (const path of [
    '/home/tseng/meepcoin-runtimeclosure-build-20260924T201900Z/',
    '/home/tseng/meepcoin-runtimeclosure-build-20260924T201900Z/out/extra',
    '/home/tseng/meepcoin-runtimeclosure-build-20260924T201900Z/../other',
    '/home/tseng//meepcoin-runtimeclosure-build-20260924T201900Z',
    '/tmp/meepcoin-runtimeclosure-build-20260924T201900Z',
    'C:/home/tseng/meepcoin-runtimeclosure-build-20260924T201900Z',
    '/home/tseng/not-meepcoin-build',
    '/home/tseng/meepcoin-build\n/out',
  ]) assert.equal(artifactDirectoryUser(path), null, path);
  assert.equal(artifactDirectoryUser(null), null);
});

/**
 * A scripted machine. `ss` is what the listener probe returns; `gone` decides whether the container is
 * observed gone after a stop; `mkdirOk`, `exitDuringStartup` script failures.
 */
function machine({
  ss = SS_LOOPBACK, gone = true, mkdirOk = true, exitDuringStartup = false, rpcReadyAfter = 1,
  statOut = '2096:555:1000\n', rmdirOk = true, desktopEngine = false,
  inspectIdentity = `${IMAGE_ID}|${CONFIG.artifactDir}=/opt/meepcoin:false;${CONFIG.runDir}=${CONFIG.runDir}:true;`,
} = {}) {
  const log = { spawned: [], probes: [], stopped: 0, killed: 0 };
  let child = null;
  let exited = false;
  const state = { gone, runDirPresent: false };
  const spawnFn = (args) => {
    log.spawned.push(args);
    child = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => { if (!exited) { exited = true; setImmediate(() => child.emit('exit', null, 'SIGTERM')); } return true; };
    if (exitDuringStartup) setImmediate(() => { exited = true; child.emit('exit', 1, null); });
    return child;
  };
  const exitChild = (code) => { if (child && !exited) { exited = true; setImmediate(() => child.emit('exit', code, null)); } };
  const runProbe = async (argv) => {
    const cmd = argv.slice(3);
    log.probes.push(cmd);
    const [c0, c1] = cmd;
    if (c0 === 'docker' && c1 === 'info') return { ok: true, code: 0,
      stdout: desktopEngine ? '["com.docker.desktop.address=unix:///var/run/docker-cli.sock"]\n' : '[]\n' };
    if (c0 === 'mkdir') { if (mkdirOk) state.runDirPresent = true; return { ok: mkdirOk, code: mkdirOk ? 0 : 1, stdout: '' }; }
    if (c0 === 'stat') return { ok: true, code: 0, stdout: statOut };
    if (c0 === 'rmdir') { if (rmdirOk) state.runDirPresent = false; return { ok: rmdirOk, code: rmdirOk ? 0 : 1, stdout: '' }; }
    if (c0 === 'ls' && cmd.includes('/')) return { ok: true, code: 0, stdout: `/\n${state.runDirPresent ? `${cmd.at(-1)}\n` : ''}` };
    if (c0 === 'docker' && c1 === 'inspect' && cmd[3].startsWith('{{.Image}}')) return { ok: true, code: 0, stdout: `${inspectIdentity}\n` };
    if (c0 === 'docker' && c1 === 'inspect') return { ok: true, code: 0, stdout: exited ? '' : `true ${PID}\n` };
    if (c0 === 'ss' && cmd.includes('-ltnup')) return { ok: true, code: 0, stdout: ss };
    if (c0 === 'ss') return { ok: true, code: 0, stdout: `ESTAB 0 0 127.0.0.1:28081 127.0.0.1:50000 users:(("meepcoind",pid=${PID},fd=20))\n` };
    if (c0 === 'docker' && c1 === 'stop') { log.stopped += 1; exitChild(0); return { ok: true, code: 0, stdout: '' }; }
    if (c0 === 'docker' && c1 === 'kill') { log.killed += 1; exitChild(137); return { ok: true, code: 0, stdout: '' }; }
    if (c0 === 'docker' && c1 === 'ps') return { ok: true, code: 0, stdout: state.gone ? '' : 'deadbeef\n' };
    if (c0 === 'ls') return { ok: true, code: 0, stdout: state.gone ? '/proc/self\n' : `/proc/self\n/proc/${PID}\n` };
    return { ok: false, code: 1, stdout: '' };
  };
  let readyCalls = 0;
  const isRpcReady = async () => { readyCalls += 1; return readyCalls >= rpcReadyAfter; };
  return { log, spawnFn, runProbe, isRpcReady, state };
}

test('Docker Desktop host network is refused before a run directory or daemon exists', async () => {
  const m = machine({ desktopEngine: true });
  await assert.rejects(startScripted(m), (err) => err.code === 'docker_topology_mismatch');
  assert.equal(m.log.spawned.length, 0);
  assert.equal(m.state.runDirPresent, false);
  assert.deepEqual(m.log.probes.map((argv) => argv.slice(0, 2)), [['docker', 'info']]);
});

const FAST = { probeTimeoutMs: 100, readyTimeoutMs: 2000, readyPollMs: 1, stopGraceSeconds: 1, stopTimeoutMs: 200, exitJoinMs: 100 };

/** THE ONLY WAY THIS FILE STARTS A DAEMON: every seam is injected. */
function startScripted(m, over = {}) {
  return startLocalDaemon({
    config: CONFIG,
    isRpcReady: m.isRpcReady,
    spawnFn: m.spawnFn,
    runProbe: m.runProbe,
    limits: FAST,
    sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 2))),
    ...over,
  });
}

test('the daemon flags are the closed private-offline list, word for word', () => {
  const flags = daemonFlags(CONFIG);
  assert.deepEqual(flags, [
    '--testnet', '--offline', '--no-igd', '--hide-my-port', '--disable-dns-checkpoints', '--no-zmq',
    '--non-interactive', '--rpc-ssl', 'disabled',
    '--p2p-bind-ip', '127.0.0.1', '--p2p-bind-port', '28080',
    '--rpc-bind-ip', '127.0.0.1', '--rpc-bind-port', '28081',
    '--data-dir', `${CONFIG.runDir}/data`, '--log-file', `${CONFIG.runDir}/meepcoind.log`, '--log-level', '0',
  ]);
  for (const forbidden of [
    '--fixed-difficulty', '--seed-node', '--add-peer', '--add-priority-node', '--add-exclusive-node',
    '--check-updates', '--enable-dns-blocklist', '--rpc-restricted-bind-port', '--confirm-external-bind',
    '--zmq-rpc-bind-ip', '--p2p-external-port', '--igd',
  ]) {
    assert.equal(flags.includes(forbidden), false, forbidden);
  }
  assert.equal(flags.some((f) => f.includes('0.0.0.0')), false);
});

test('the PEER-TEST profile: fixed difficulty 500, exactly one loopback exclusive peer, no --offline', () => {
  const flags = daemonFlags(checkDaemonConfig(PEER_CONFIG));
  assert.deepEqual(flags, [
    '--testnet', '--fixed-difficulty', '500', '--add-exclusive-node', '127.0.0.1:28090',
    '--no-igd', '--hide-my-port', '--disable-dns-checkpoints', '--no-zmq', '--non-interactive', '--rpc-ssl', 'disabled',
    '--p2p-bind-ip', '127.0.0.1', '--p2p-bind-port', '28080',
    '--rpc-bind-ip', '127.0.0.1', '--rpc-bind-port', '28081',
    '--data-dir', `${CONFIG.runDir}/data`, '--log-file', `${CONFIG.runDir}/meepcoind.log`, '--log-level', '0',
  ]);
  for (const forbidden of ['--offline', '--seed-node', '--add-peer', '--add-priority-node', '--igd', '--zmq-rpc-bind-ip']) {
    assert.equal(flags.includes(forbidden), false, forbidden);
  }
  assert.equal(flags.filter((f) => f === '--add-exclusive-node').length, 1);
  // The offline default is untouched by the new profile.
  assert.equal(daemonFlags(CONFIG).includes('--offline'), true);
  assert.equal(daemonFlags(CONFIG).includes('--fixed-difficulty'), false);
});

test('the natural pair has one exclusive loopback peer and no fixed-difficulty flag', () => {
  const natural = checkDaemonConfig({
    ...PEER_CONFIG, profile: DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_NATURAL,
    fixedDifficulty: undefined,
  });
  const flags = daemonFlags(natural);
  assert.equal(flags.includes('--fixed-difficulty'), false);
  assert.equal(flags.includes('--offline'), false);
  assert.equal(flags.filter((f) => f === '--add-exclusive-node').length, 1);
  assert.deepEqual(flags.slice(0, 3), ['--testnet', '--add-exclusive-node', '127.0.0.1:28090']);
  assert.equal('fixedDifficulty' in natural, false);
  assert.deepEqual(checkListeners([{ proto: 'tcp', local: '127.0.0.1:28081' }], natural),
    { ok: false, reason: 'p2p_not_listening' });
  for (const over of [{ fixedDifficulty: 500 }, { expectedImageId: undefined }, { exclusivePeerP2pPort: undefined }]) {
    assert.throws(() => checkDaemonConfig({ ...natural, ...over }), LocalDaemonError);
  }
});

test('the prospective natural mesh has exactly two frozen exclusive peers and cannot alter pair flags', () => {
  const mesh = checkDaemonConfig({
    ...PEER_CONFIG, profile: DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL,
    exclusivePeerP2pPort: undefined, exclusivePeerP2pPorts: [28090, 28100], fixedDifficulty: undefined,
  });
  assert.equal(PRIVATE_MESH_LOOPBACK_MAX_CONNECTIONS_PER_IP, 8);
  assert.deepEqual(daemonFlags(mesh).slice(0, 7), [
    '--testnet', '--max-connections-per-ip', '8',
    '--add-exclusive-node', '127.0.0.1:28090', '--add-exclusive-node', '127.0.0.1:28100',
  ]);
  assert.equal(daemonFlags(mesh).includes('--fixed-difficulty'), false);
  assert.equal(daemonFlags(mesh).includes('--offline'), false);
  assert.deepEqual(daemonFlags(checkDaemonConfig(PEER_CONFIG)).slice(0, 5), [
    '--testnet', '--fixed-difficulty', '500', '--add-exclusive-node', '127.0.0.1:28090',
  ]);
  assert.equal(daemonFlags(checkDaemonConfig(PEER_CONFIG)).includes('--max-connections-per-ip'), false);
  assert.equal(daemonFlags(CONFIG).includes('--max-connections-per-ip'), false);
  assert.equal(Object.isFrozen(mesh.exclusivePeerP2pPorts), true);
  assert.deepEqual(checkListeners([{ proto: 'tcp', local: '127.0.0.1:28081' }], mesh),
    { ok: false, reason: 'p2p_not_listening' });
  for (const over of [
    { exclusivePeerP2pPorts: undefined }, { exclusivePeerP2pPorts: [28090] },
    { exclusivePeerP2pPorts: [28090, 28090] }, { exclusivePeerP2pPorts: [28081, 28100] },
    { exclusivePeerP2pPorts: [28080, 28100] }, { exclusivePeerP2pPorts: ['28090', 28100] },
    { exclusivePeerP2pPorts: [28090, 65536] }, { exclusivePeerP2pPort: 28090 },
    { fixedDifficulty: 500 }, { expectedImageId: undefined },
  ]) assert.throws(() => checkDaemonConfig({ ...mesh, ...over }), LocalDaemonError);
  assert.throws(() => checkDaemonConfig({ ...PEER_CONFIG, exclusivePeerP2pPorts: [28100, 28110] }), /pair profile takes one peer/);
  assert.throws(() => checkDaemonConfig({ ...CONFIG, exclusivePeerP2pPorts: [28090, 28100] }), /offline profile takes no peer/);
});

test('three mesh launch configs agree on identity and name only each other before allocation', () => {
  const base = { ...PEER_CONFIG, profile: DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL,
    exclusivePeerP2pPort: undefined, fixedDifficulty: undefined };
  const a = { ...base, exclusivePeerP2pPorts: [28090, 28100] };
  const b = { ...base, runDir: '/home/tseng/meepcoin-private-run-abcdef0123456788',
    rpcPort: 28091, p2pPort: 28090, exclusivePeerP2pPorts: [28080, 28100] };
  const c = { ...base, runDir: '/home/tseng/meepcoin-private-run-abcdef0123456787',
    rpcPort: 28101, p2pPort: 28100, exclusivePeerP2pPorts: [28080, 28090] };
  const checked = checkThreeNodeConfigs({ a, b, c });
  assert.deepEqual(checked.a.exclusivePeerP2pPorts, [28090, 28100]);
  assert.deepEqual(checked.b.exclusivePeerP2pPorts, [28080, 28100]);
  assert.deepEqual(checked.c.exclusivePeerP2pPorts, [28080, 28090]);
  for (const [name, changed] of [
    ['missing C', { a, b }],
    ['pair profile', { a, b: { ...b, profile: DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_NATURAL,
      exclusivePeerP2pPorts: undefined, exclusivePeerP2pPort: 28080 }, c }],
    ['duplicate P2P port', { a, b: { ...b, p2pPort: 28080 }, c }],
    ['duplicate run directory', { a, b: { ...b, runDir: a.runDir }, c }],
    ['wrong peer', { a, b: { ...b, exclusivePeerP2pPorts: [28080, 28110] }, c }],
    ['different artifact', { a, b: { ...b, artifactDir: '/home/tseng/meepcoin-other-build' }, c }],
    ['different image digest', { a, b: { ...b, expectedImageId: `sha256:${'e'.repeat(64)}` }, c }],
  ]) assert.throws(() => checkThreeNodeConfigs(changed), LocalDaemonError, name);
});

test('three-node mesh requires all exact reciprocal links and refuses unexpected traffic', () => {
  const E = (local, peer, state = 'ESTAB') => ({ state, local: `127.0.0.1:${local}`, peer: `127.0.0.1:${peer}` });
  const nodes = [
    { name: 'A', rpcPort: 28081, p2pPort: 28080, connections: [E(41000, 28090), E(41001, 28100), E(28081, 50001)] },
    { name: 'B', rpcPort: 28091, p2pPort: 28090, connections: [E(28090, 41000), E(42000, 28100)] },
    { name: 'C', rpcPort: 28101, p2pPort: 28100, connections: [E(28100, 41001), E(28100, 42000)] },
  ];
  const verdict = (changed = nodes) => checkThreeNodeConnections({ nodes: changed });
  assert.deepEqual(verdict(), { ok: true, linked: true, links: ['A-B', 'A-C', 'B-C'], bad: [] });
  assert.deepEqual(verdict(nodes.map((n) => ({ ...n, connections: [...n.connections] }))), verdict());
  const without = (name, index) => nodes.map((n) => ({ ...n, connections: n.name === name
    ? n.connections.filter((_, i) => i !== index) : n.connections }));
  assert.deepEqual(verdict(without('C', 1)).links, ['A-B', 'A-C']);
  assert.equal(verdict(without('C', 1)).linked, false);
  assert.equal(verdict(without('C', 1)).ok, false); // established B->C has no C-owned reverse
  assert.equal(verdict(without('A', 0)).linked, false);
  assert.equal(verdict(without('A', 0)).ok, false); // B's incoming row has no owner-side reverse
  for (const extra of [
    E(41002, 18080), E(41002, 18080, 'SYN-SENT'),
    { state: 'SYN-SENT', local: '127.0.0.1:41002', peer: '8.8.8.8:18080' },
    { state: 'ESTAB', local: '127.0.0.2:41002', peer: '127.0.0.1:28090' },
    E(28081, 28090), // An RPC listener must not impersonate a P2P client.
    E(28100, 28090), // Nor may any other mesh listener impersonate one.
    E(28080, 43000),
  ]) {
    const changed = nodes.map((n) => ({ ...n, connections: n.name === 'A' ? [...n.connections, extra] : n.connections }));
    assert.equal(verdict(changed).ok, false);
    assert.equal(verdict(changed).linked, false);
  }
  const forgedReverse = nodes.map((n) => ({ ...n, connections: n.name === 'A'
    ? [...n.connections, E(28081, 28090)] : n.name === 'B'
      ? [...n.connections, E(28090, 28081)] : n.connections }));
  assert.equal(verdict(forgedReverse).ok, false, 'an exact RPC-port reverse tuple is not a peer');
  assert.equal(verdict(forgedReverse).linked, false);
  assert.deepEqual(verdict(null), { ok: false, linked: false, links: [], bad: ['unobservable_or_bad_mesh'] });
  assert.deepEqual(verdict(nodes.map((n) => n.name === 'C' ? { ...n, rpcPort: 28081 } : n)),
    { ok: false, linked: false, links: [], bad: ['colliding_or_bad_mesh_ports'] });
});

test('the peer-test profile refuses every other difficulty, peer shape or missing image pin', async () => {
  for (const [name, over] of [
    ['difficulty 1', { fixedDifficulty: 1 }],
    ['difficulty 501', { fixedDifficulty: 501 }],
    ['difficulty string', { fixedDifficulty: '500' }],
    ['no peer', { exclusivePeerP2pPort: undefined }],
    ['peer is itself', { exclusivePeerP2pPort: CONFIG.p2pPort }],
    ['peer is its rpc', { exclusivePeerP2pPort: CONFIG.rpcPort }],
    ['peer host string', { exclusivePeerP2pPort: '10.0.0.5:28090' }],
    ['no image pin', { expectedImageId: undefined }],
    ['bad image pin', { expectedImageId: 'sha256:abc' }],
    ['unknown profile', { profile: 'public-peer' }],
  ]) {
    const m = machine();
    await assert.rejects(startScripted(m, { config: { ...PEER_CONFIG, ...over } }), LocalDaemonError, name);
    assert.equal(m.log.spawned.length + m.log.probes.length, 0, name);
  }
  for (const over of [{ fixedDifficulty: 500 }, { exclusivePeerP2pPort: 28090 }]) {
    assert.throws(() => checkDaemonConfig({ ...CONFIG, ...over }), /offline profile takes no peer/);
  }
});

test('startup proves the pinned image and the read-only artifact mount, and the peer profile needs P2P listening', async () => {
  const SS_BOTH = `${SS_LOOPBACK}\ntcp LISTEN 0 4096 127.0.0.1:28080 0.0.0.0:* users:(("meepcoind",pid=${PID},fd=13))`;
  const good = machine({ ss: SS_BOTH });
  const d = await startScripted(good, { config: PEER_CONFIG });
  assert.equal(d.imageId, IMAGE_ID);
  assert.ok(d.mounts.includes(`${CONFIG.artifactDir}=/opt/meepcoin:false`));
  await d.close();
  for (const [name, opts, code] of [
    ['other image', { ss: SS_BOTH, inspectIdentity: `sha256:${'e'.repeat(64)}|${CONFIG.artifactDir}=/opt/meepcoin:false;` }, 'image_mismatch'],
    ['writable artifact', { ss: SS_BOTH, inspectIdentity: `${IMAGE_ID}|${CONFIG.artifactDir}=/opt/meepcoin:true;` }, 'artifact_mount_mismatch'],
    ['unobservable', { ss: SS_BOTH, inspectIdentity: 'garbage' }, 'identity_unobservable'],
    ['p2p not listening', { ss: SS_LOOPBACK }, 'listener_check_failed'],
  ]) {
    const m = machine(opts);
    let err = null;
    try { await startScripted(m, { config: PEER_CONFIG }); } catch (e) { err = e; }
    assert.equal(err?.code, code, name);
    assert.ok(err.resource, `${name}: the started container was not handed back`);
    await err.resource.close();
    assert.equal(err.resource.closed, true);
  }
});

test('a mesh daemon uses only its two declared peers and keeps owned startup/cleanup', async () => {
  const mesh = checkDaemonConfig({
    ...PEER_CONFIG, profile: DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL,
    exclusivePeerP2pPort: undefined, exclusivePeerP2pPorts: [28090, 28100], fixedDifficulty: undefined,
  });
  const ss = `${SS_LOOPBACK}\ntcp LISTEN 0 4096 127.0.0.1:28080 0.0.0.0:* users:(("meepcoind",pid=${PID},fd=13))`;
  const m = machine({ ss });
  const d = await startScripted(m, { config: mesh });
  assert.deepEqual(d.launchArgs.filter((arg) => arg === '--add-exclusive-node').length, 2);
  assert.equal(d.launchArgs.includes('127.0.0.1:28090'), true);
  assert.equal(d.launchArgs.includes('127.0.0.1:28100'), true);
  assert.equal(d.launchArgs.includes('--fixed-difficulty'), false);
  assert.equal(d.launchArgs.includes('--offline'), false);
  await d.close();
  assert.equal(d.closed, true);
});

test('PAIR CONNECTIONS: only RPC clients and the one A<->B P2P link are acceptable, all numeric loopback', () => {
  const a = { rpcPort: 28081, p2pPort: 28080 };
  const b = { rpcPort: 28091, p2pPort: 28090 };
  const aOut = { state: 'ESTAB', local: '127.0.0.1:41000', peer: '127.0.0.1:28090' };   // A -> B
  const bIn = { state: 'ESTAB', local: '127.0.0.1:28090', peer: '127.0.0.1:41000' };    // B accepted it
  const rpc = { state: 'ESTAB', local: '127.0.0.1:28081', peer: '127.0.0.1:50001' };
  let v = checkPairConnections({ aConns: [aOut, rpc], bConns: [bIn], a, b });
  assert.deepEqual(v, { ok: true, linked: true, bad: [] });
  v = checkPairConnections({ aConns: [rpc], bConns: [], a, b });
  assert.deepEqual(v, { ok: true, linked: false, bad: [] });
  for (const [name, aConns, bConns] of [
    ['A to a LAN address', [{ state: 'ESTAB', local: '192.168.1.5:41000', peer: '192.168.1.9:28090' }], []],
    ['A to a public peer', [{ state: 'ESTAB', local: '127.0.0.1:41000', peer: '8.8.8.8:18080' }], []],
    ['A half-open to a public peer', [{ state: 'SYN-SENT', local: '127.0.0.1:41000', peer: '8.8.8.8:18080' }], []],
    ['A to another local port', [{ state: 'ESTAB', local: '127.0.0.1:41000', peer: '127.0.0.1:18080' }], []],
    ['incoming P2P from a process that is not B', [{ state: 'ESTAB', local: '127.0.0.1:28080', peer: '127.0.0.1:43000' }], []],
    ['ipv6', [{ state: 'ESTAB', local: '[::1]:41000', peer: '[::1]:28090' }], []],
  ]) {
    const r = checkPairConnections({ aConns, bConns, a, b });
    assert.equal(r.ok, false, name);
    assert.ok(r.bad.length > 0, name);
  }
  assert.equal(checkPairConnections({ aConns: null, bConns: [], a, b }).ok, false);
  // A loopback connection that is still opening or already closing is not paired, so it cannot be
  // mistaken for a foreign peer when its other end is in a different state in the same snapshot.
  v = checkPairConnections({ aConns: [{ state: 'CLOSE-WAIT', local: '127.0.0.1:28080', peer: '127.0.0.1:43000' }], bConns: [], a, b });
  assert.deepEqual(v, { ok: true, linked: false, bad: [] });
  assert.deepEqual(parseConnections(`ESTAB 0 0 127.0.0.1:41000 127.0.0.1:28090 users:(("meepcoind",pid=7,fd=9))\nESTAB 0 0 127.0.0.1:1 127.0.0.1:2 users:(("x",pid=8,fd=1))`, 7),
    [{ state: 'ESTAB', local: '127.0.0.1:41000', peer: '127.0.0.1:28090' }]);
});

test('PAIR LINK: linked needs ONE EXACT RECIPROCAL established tuple in the same snapshot', () => {
  // THE WITNESS (Regression testing, af3bc0ca): one expected-port row set linked by itself, and an incoming row was
  // paired with the other daemon by port number alone.
  const a = { rpcPort: 28081, p2pPort: 28080 };
  const b = { rpcPort: 28091, p2pPort: 28090 };
  const E = (local, peer, state = 'ESTAB') => ({ state, local: `127.0.0.1:${local}`, peer: `127.0.0.1:${peer}` });
  const verdict = (aConns, bConns) => checkPairConnections({ aConns, bConns, a, b });

  // A valid reciprocal link, in each direction.
  assert.deepEqual(verdict([E(41000, 28090)], [E(28090, 41000)]), { ok: true, linked: true, bad: [] });
  assert.deepEqual(verdict([E(28080, 42000)], [E(42000, 28080)]), { ok: true, linked: true, bad: [] });

  // A one-sided expected-port row: A's outgoing row alone is not a link (B's end may not be accepted yet).
  assert.deepEqual(verdict([E(41000, 28090)], []), { ok: true, linked: false, bad: [] });

  // Coincidental local-port reuse: B owns local port 41000 only in an unrelated RPC-server row, and
  // separately only through a closing row on the right tuple. Neither is an established reciprocal.
  assert.deepEqual(verdict([E(41000, 28090)], [E(28091, 41000)]), { ok: true, linked: false, bad: [] });
  assert.deepEqual(verdict([E(28080, 41000)], [E(41000, 28080, 'FIN-WAIT-2')]), { ok: true, linked: false, bad: [] });

  // A mismatched reverse tuple: B's incoming row names 41001, A's outgoing row is from 41000. B's row
  // has no exact reverse on A, so it is an unexpected peer, and nothing is linked.
  let v = verdict([E(41000, 28090)], [E(28090, 41001)]);
  assert.equal(v.ok, false);
  assert.equal(v.linked, false);
  assert.deepEqual(v.bad, ['B: unexpected peer 127.0.0.1:28090 -> 127.0.0.1:41001']);
  // ...and the same port on another loopback address is not the same tuple.
  v = checkPairConnections({ aConns: [E(41000, 28090)], bConns: [{ state: 'ESTAB', local: '127.0.0.1:28090', peer: '127.0.0.2:41000' }], a, b });
  assert.equal(v.ok, false);
  assert.equal(v.linked, false);

  // A half-open attempt to a public address fails closed even next to a valid reciprocal link.
  v = verdict([E(41000, 28090), { state: 'SYN-SENT', local: '127.0.0.1:41002', peer: '8.8.8.8:18080' }], [E(28090, 41000)]);
  assert.equal(v.ok, false);
  assert.equal(v.linked, false);
  assert.match(v.bad[0], /non-loopback/);
});

test('the launch is one named, removable, non-root container running the fresh artifact read-only', () => {
  const args = daemonLaunchArgs(checkDaemonConfig(CONFIG), 'meepcoin-private-0123456789abcdef');
  assert.deepEqual(args.slice(0, 16), [
    '-d', 'Ubuntu', '--exec', 'docker', 'run', '--rm', '--name', 'meepcoin-private-0123456789abcdef',
    '--network', 'host', '--user', '1000:1000', '--pull', 'never',
    '-v', `${CONFIG.artifactDir}:/opt/meepcoin:ro`,
  ]);
  assert.ok(args.includes('--entrypoint'));
  assert.equal(args[args.indexOf('--entrypoint') + 1], '/opt/meepcoin/meepcoind');
  assert.equal(args.includes('--privileged'), false);
});

test('a bad configuration is refused before anything is spawned', async () => {
  for (const [name, over] of [
    ['no distro', { wslDistro: '' }],
    ['shell in distro', { wslDistro: 'Ubuntu; rm -rf /' }],
    ['other image', { image: 'ubuntu:24.04' }],
    ['old artifact dir', { artifactDir: '/home/tseng/meepcoin-node/build/release/bin' }],
    ['run dir elsewhere', { runDir: '/tmp/run' }],
    ['run dir traversal', { runDir: '/home/tseng/meepcoin-private-run-abcdef01/../x' }],
    ['privileged port', { rpcPort: 80 }],
    ['same ports', { p2pPort: 28081 }],
    ['root', { uid: 0 }],
  ]) {
    const m = machine();
    await assert.rejects(startScripted(m, { config: { ...CONFIG, ...over } }), LocalDaemonError, name);
    assert.equal(m.log.spawned.length, 0, `${name}: spawned`);
    assert.equal(m.log.probes.length, 0, `${name}: probed`);
  }
});

test('listeners are parsed per process, and only the two numeric loopback ports are acceptable', () => {
  const parsed = parseListeners(SS_LOOPBACK, PID);
  assert.deepEqual(parsed, [{ proto: 'tcp', local: '127.0.0.1:28081' }]);
  assert.equal(checkListeners(parsed, CONFIG).ok, true);
  for (const [name, text, reason] of [
    ['wildcard rpc', `tcp LISTEN 0 1 0.0.0.0:28081 0.0.0.0:* users:(("meepcoind",pid=${PID},fd=1))`, 'unexpected_listener'],
    ['ipv6 wildcard', `tcp LISTEN 0 1 [::]:28080 [::]:* users:(("meepcoind",pid=${PID},fd=1))`, 'unexpected_listener'],
    ['extra port', `tcp LISTEN 0 1 127.0.0.1:28081 0.0.0.0:* users:(("meepcoind",pid=${PID},fd=1))\ntcp LISTEN 0 1 127.0.0.1:18082 0.0.0.0:* users:(("meepcoind",pid=${PID},fd=2))`, 'unexpected_listener'],
    ['udp', `udp UNCONN 0 0 127.0.0.1:28081 0.0.0.0:* users:(("meepcoind",pid=${PID},fd=1))`, 'unexpected_listener'],
    ['rpc absent', '', 'rpc_not_listening'],
  ]) {
    assert.equal(checkListeners(parseListeners(text, PID), CONFIG).reason, reason, name);
  }
  assert.equal(checkListeners(null, CONFIG).reason, 'unobservable');
  assert.equal(parseListeners('garbage', PID), null);
});

test('startup: fresh run dir, container pid, RPC readiness, and the listener proof -- then close is confirmed', async () => {
  const m = machine({ rpcReadyAfter: 3 });
  const d = await startScripted(m);
  assert.equal(m.log.spawned.length, 1);
  assert.equal(d.linuxPid, PID);
  assert.equal(d.runDirIdentity, '2096:555:1000');
  assert.deepEqual(d.listeners, [{ proto: 'tcp', local: '127.0.0.1:28081' }]);
  assert.match(d.containerName, /^meepcoin-private-[0-9a-f]{16}$/);
  // The run directory was created with mkdir WITHOUT -p: an existing path fails.
  assert.deepEqual(m.log.probes[0], ['docker', 'info', '--format', '{{json .Labels}}']);
  assert.deepEqual(m.log.probes[1], ['mkdir', '-m', '700', '--', CONFIG.runDir]);
  assert.deepEqual(await d.observeConnections(), [{ state: 'ESTAB', local: '127.0.0.1:28081', peer: '127.0.0.1:50000' }]);
  assert.match(await d.observeSocketTable(), /pid=4321,/);
  assert.equal(await d.observeListenerTable(), SS_LOOPBACK);
  assert.equal(d.imageId, IMAGE_ID);
  assert.equal(d.closed, false);
  await d.close();
  assert.equal(d.closed, true);
  assert.equal(m.log.stopped, 1);
  assert.equal(m.log.killed, 0);
  assert.equal(d.shutdownOutcome.gracefulProtocolShutdown, true);
});

test('a non-loopback listener fails startup, and the running container is handed back to be owned and closed', async () => {
  const m = machine({ ss: `tcp LISTEN 0 1 0.0.0.0:28081 0.0.0.0:* users:(("meepcoind",pid=${PID},fd=1))` });
  let err = null;
  try { await startScripted(m); } catch (e) { err = e; }
  assert.ok(err);
  assert.equal(err.code, 'listener_check_failed');
  assert.ok(err.resource, 'the started container was not handed back');
  assert.equal(err.resource.closed, false);
  await err.resource.close();
  assert.equal(err.resource.closed, true);
});

test('an existing run directory refuses startup before any container exists', async () => {
  const m = machine({ mkdirOk: false });
  await assert.rejects(startScripted(m), (e) => e.code === 'run_dir_exists_or_unwritable');
  assert.equal(m.log.spawned.length, 0);
});

test('optional owned-directory preparation occurs only after identity and before launch', async () => {
  const m = machine();
  let seen = null;
  const d = await startScripted(m, { prepareRunDir: async (context) => {
    seen = context;
    assert.deepEqual(m.log.probes.slice(0, 3).map((x) => x[0]), ['docker', 'mkdir', 'stat']);
    assert.equal(m.log.spawned.length, 0);
  } });
  assert.equal(seen.runDir, CONFIG.runDir);
  assert.equal(seen.runDirIdentity, '2096:555:1000');
  assert.equal(seen.config.runDir, CONFIG.runDir);
  await d.close();
});

test('failed owned-directory preparation retains its exact path and launches nothing', async () => {
  const m = machine();
  let err = null;
  try {
    await startScripted(m, { prepareRunDir: async () => { throw new Error('copy failed'); } });
  } catch (e) { err = e; }
  assert.equal(err?.code, 'run_dir_preparation_failed');
  assert.deepEqual(err.retainedPaths, [CONFIG.runDir]);
  assert.equal(err.cause.message, 'copy failed');
  assert.equal(m.log.spawned.length, 0);
  assert.equal(m.state.runDirPresent, true);
});

test('RUN DIR: a failed identity check removes ONLY the directory mkdir just created, non-recursively', async () => {
  // THE WITNESS: the directory was created, the identity check failed, and the error was thrown with
  // the new directory left behind and no resource or retained state to say so.
  for (const statOut of ['garbage\n', '2096:555:0\n', '']) {
    const m = machine({ statOut });
    let err = null;
    try { await startScripted(m); } catch (e) { err = e; }
    assert.equal(err?.code, 'run_dir_identity', JSON.stringify(statOut));
    assert.equal(err.runDirRemoved, true);
    assert.equal(err.retainedPaths, undefined);
    assert.equal(m.state.runDirPresent, false);
    assert.equal(m.log.spawned.length, 0, 'a daemon was started');
    assert.deepEqual(m.log.probes.find((c) => c[0] === 'rmdir'), ['rmdir', '--', CONFIG.runDir]);
    assert.equal(m.log.probes.some((c) => c[0] === 'rm'), false, 'a recursive removal was attempted');
  }
});

test('RUN DIR: if even the rmdir cannot be confirmed, the path is reported as retained, not claimed clean', async () => {
  const m = machine({ statOut: 'garbage\n', rmdirOk: false });
  let err = null;
  try { await startScripted(m); } catch (e) { err = e; }
  assert.equal(err?.code, 'run_dir_identity');
  assert.equal(err.runDirRemoved, false);
  assert.deepEqual(err.retainedPaths, [CONFIG.runDir]);
  assert.equal(m.log.spawned.length, 0);
});

test('a daemon that exits during startup is a startup failure, not a hang', async () => {
  const m = machine({ exitDuringStartup: true, rpcReadyAfter: 1e9 });
  await assert.rejects(startScripted(m), (e) => e.code === 'daemon_exited' || e.code === 'ready_timeout');
});

test('an UNCONFIRMED release keeps ownership; close fails honestly and a later confirmed close releases', async () => {
  const m = machine({ gone: false });
  const d = await startScripted(m);
  await assert.rejects(d.close(), (e) => e.code === 'release_unconfirmed');
  assert.equal(d.closed, false, 'claimed closed without a positive observation');
  await assert.rejects(d.forceClose(), (e) => e.code === 'release_unconfirmed');
  assert.equal(d.closed, false);
  m.state.gone = true;
  await d.forceClose();
  assert.equal(d.closed, true);
});

test('GUARD: no test in this file can reach the real spawn', () => {
  const code = readFileSync(fileURLToPath(import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((line) => line.replace(/\/\/.*$/, '').replace(/'[^']*'/g, "''"))
    .join('\n');
  const calls = code.match(/startLocalDaemon\(/g) ?? [];
  assert.equal(calls.length, 1, 'startLocalDaemon is called outside startScripted()');
  assert.equal(code.includes('child' + '_process'), false, 'this file imports the process module');
});
