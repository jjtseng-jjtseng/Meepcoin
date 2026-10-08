// ONE private meepcoind, owned by the pool that started it. Closed profiles: the offline single
// daemon (the default), the private exclusive-peer pair, and a separate natural-difficulty
// three-node mesh profile. Every named peer is a numeric-loopback P2P port.
//
// WHAT RUNS. The freshly built daemon artifact, executed inside the pinned build image (which holds
// exactly the runtime libraries it was linked against) through the Docker engine in the
// parent-pinned WSL distribution:
//
//   wsl.exe -d <distro> --exec docker run --rm --name <random> --network host --user <uid>:<gid>
//       --pull never -v <artifactDir>:/opt/meepcoin:ro -v <runDir>:<runDir>
//       --entrypoint /opt/meepcoin/meepcoind <image>  <daemon flags>
//
// `--network host` shares the WSL network namespace only with a WSL-local Docker engine. Docker
// Desktop's separate VM is refused before any run directory or daemon is created. With the local
// engine, the Windows-side pool reaches RPC through WSL's localhost forwarding. This is NOT an
// exposure decision: every bind is the numeric
// address 127.0.0.1, and the daemon's actual listeners are observed and checked before any template
// is requested (observeListeners).
//
// THE DAEMON FLAGS ARE A CLOSED LIST, built here and nowhere else: testnet, --no-igd,
// --hide-my-port, --disable-dns-checkpoints, no ZMQ, no RPC TLS, non-interactive,
// numeric-loopback P2P and RPC on two caller-prechecked ports, and a data dir and log in the one
// run directory. The default profile is --offline with no peers or seeds. The PEER-TEST profile
// adds exactly `--fixed-difficulty 500` and one exclusive loopback peer; the natural pair has one
// exclusive peer without fixed difficulty; the prospective natural mesh has exactly two. None
// sets a wallet, genesis, target, or timestamp override.
// The source-locked defaults keep update checks and the DNS blocklist disabled; nothing enables them.
//
// IDENTITY. After start, the container's image id (checked against a pin when one is given) and its
// read-only /opt/meepcoin artifact mount are observed, before readiness is trusted.
//
// OWNERSHIP. This resource is entered into the pool's ownership graph the moment it exists. close()
// asks Docker to stop the named container, joins the wsl.exe child, and only then -- after a
// positive observation that the named container no longer exists and the container's Linux PID has
// no /proc entry -- reports `closed`. A failed or unknown observation RETAINS ownership. There is no
// kill-by-name outside this one container name, no wildcard and no `wsl --shutdown`.
//
// EVERYTHING IS ARGUMENT-NATIVE. Every child is spawned with an argv array and shell:false.

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { classifyWslDockerEngine } from './docker_engine_topology.mjs';

export const DAEMON_LIMITS = Object.freeze({
  probeTimeoutMs: 30_000,
  readyTimeoutMs: 120_000,
  readyPollMs: 500,
  stopGraceSeconds: 60,
  stopTimeoutMs: 120_000,
  exitJoinMs: 30_000,
});

export class LocalDaemonError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.name = 'LocalDaemonError';
    this.code = code;
  }
}

const WSL_DISTRO_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const IMAGE_RE = /^meepcoin-build:[a-z0-9][a-z0-9._-]{0,127}$/;
const ARTIFACT_DIR_RE = /^\/home\/([a-z_][a-z0-9_-]{0,31})\/meepcoin-[A-Za-z0-9._-]{1,96}(?:\/out)?$/;
const RUN_DIR_RE = /^\/home\/[a-z_][a-z0-9_-]{0,31}\/meepcoin-private-run-[A-Za-z0-9]{8,64}$/;
const CONTAINER_RE = /^meepcoin-private-[0-9a-f]{16}$/;
const IMAGE_ID_RE = /^sha256:[0-9a-f]{64}$/;

/**
 * Return the owner of one sanctioned WSL artifact layout, or null.
 *
 * Older reconstructed builds place their exported artifacts in a final `out/` directory. Newer
 * fresh builds export the same closed artifact set directly in the uniquely named `meepcoin-*`
 * directory. Keep the grammar here so CLI validation and daemon validation cannot drift again.
 */
export function artifactDirectoryUser(value) {
  return typeof value === 'string' ? (ARTIFACT_DIR_RE.exec(value)?.[1] ?? null) : null;
}

/**
 * THE CLOSED SET OF DAEMON PROFILES. The offline single-daemon and existing pair flag lists are
 * unchanged. The mesh profile is prospective and accepts exactly two numeric-loopback peers.
 * All three nodes share one loopback IP, so the mesh alone raises the daemon's default one-inbound
 * per-IP cap. The socket-table gate still refuses every unowned peer.
 */
export const DAEMON_PROFILES = Object.freeze({
  OFFLINE_SINGLE: 'offline-single',
  PRIVATE_EXCLUSIVE_PEER_TEST: 'private-exclusive-peer-test',
  PRIVATE_EXCLUSIVE_PEER_NATURAL: 'private-exclusive-peer-natural',
  PRIVATE_EXCLUSIVE_MESH_NATURAL: 'private-exclusive-mesh-natural',
});

/**
 * The ONE fixed difficulty the paired test may use: an existing upstream daemon test option, frozen
 * before any run. It fixes the target; every daemon still computes and validates real MeepHash-W.
 * It is a development control, not a difficulty policy.
 */
export const PEER_TEST_FIXED_DIFFICULTY = 500;
export const PRIVATE_MESH_LOOPBACK_MAX_CONNECTIONS_PER_IP = 8;

function requirePort(p, what) {
  if (!Number.isInteger(p) || p < 1024 || p > 65535) throw new LocalDaemonError('bad_config', `${what} must be 1024..65535`);
  return p;
}

/** The closed daemon flag list for a profile. Exported so a test can assert it word for word. */
export function daemonFlags({
  runDir, rpcPort, p2pPort, profile = DAEMON_PROFILES.OFFLINE_SINGLE,
  exclusivePeerP2pPort, exclusivePeerP2pPorts, fixedDifficulty,
}) {
  if (profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_TEST
    || profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_NATURAL
    || profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL) {
    return [
      '--testnet',
      ...(profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_TEST
        ? ['--fixed-difficulty', String(fixedDifficulty)] : []),
      ...(profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL
        ? ['--max-connections-per-ip', String(PRIVATE_MESH_LOOPBACK_MAX_CONNECTIONS_PER_IP)] : []),
      ...(profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL
        ? exclusivePeerP2pPorts.flatMap((port) => ['--add-exclusive-node', `127.0.0.1:${port}`])
        : ['--add-exclusive-node', `127.0.0.1:${exclusivePeerP2pPort}`]),
      '--no-igd',
      '--hide-my-port',
      '--disable-dns-checkpoints',
      '--no-zmq',
      '--non-interactive',
      '--rpc-ssl', 'disabled',
      '--p2p-bind-ip', '127.0.0.1',
      '--p2p-bind-port', String(p2pPort),
      '--rpc-bind-ip', '127.0.0.1',
      '--rpc-bind-port', String(rpcPort),
      '--data-dir', `${runDir}/data`,
      '--log-file', `${runDir}/meepcoind.log`,
      '--log-level', '0',
    ];
  }
  return [
    '--testnet',
    '--offline',
    '--no-igd',
    '--hide-my-port',
    '--disable-dns-checkpoints',
    '--no-zmq',
    '--non-interactive',
    '--rpc-ssl', 'disabled',
    '--p2p-bind-ip', '127.0.0.1',
    '--p2p-bind-port', String(p2pPort),
    '--rpc-bind-ip', '127.0.0.1',
    '--rpc-bind-port', String(rpcPort),
    '--data-dir', `${runDir}/data`,
    '--log-file', `${runDir}/meepcoind.log`,
    '--log-level', '0',
  ];
}

/** Validate a whole configuration before anything is spawned. */
export function checkDaemonConfig(cfg) {
  const {
    wslDistro, image, artifactDir, runDir, rpcPort, p2pPort, uid, gid,
    profile = DAEMON_PROFILES.OFFLINE_SINGLE, exclusivePeerP2pPort, exclusivePeerP2pPorts,
    fixedDifficulty, expectedImageId,
  } = cfg ?? {};
  if (!Object.values(DAEMON_PROFILES).includes(profile)) throw new LocalDaemonError('bad_config', 'unknown daemon profile');
  if (typeof wslDistro !== 'string' || !WSL_DISTRO_RE.test(wslDistro)) {
    throw new LocalDaemonError('bad_config', 'a parent-pinned WSL distribution is required');
  }
  if (typeof image !== 'string' || !IMAGE_RE.test(image)) throw new LocalDaemonError('bad_config', 'image must be a meepcoin-build tag');
  if (artifactDirectoryUser(artifactDir) === null) {
    throw new LocalDaemonError('bad_config', 'artifactDir must be a /home/<user>/meepcoin-* build output directory, optionally ending in /out');
  }
  if (typeof runDir !== 'string' || !RUN_DIR_RE.test(runDir)) {
    throw new LocalDaemonError('bad_config', 'runDir must be /home/<user>/meepcoin-private-run-<id>');
  }
  requirePort(rpcPort, 'rpcPort');
  requirePort(p2pPort, 'p2pPort');
  if (rpcPort === p2pPort) throw new LocalDaemonError('bad_config', 'rpcPort and p2pPort must differ');
  for (const [v, what] of [[uid, 'uid'], [gid, 'gid']]) {
    if (!Number.isInteger(v) || v < 1 || v > 60000) throw new LocalDaemonError('bad_config', `${what} must be a non-root id`);
  }
  if (expectedImageId !== undefined && (typeof expectedImageId !== 'string' || !IMAGE_ID_RE.test(expectedImageId))) {
    throw new LocalDaemonError('bad_config', 'expectedImageId must be a sha256 image id');
  }
  if (profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_TEST
    || profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_NATURAL) {
    if (exclusivePeerP2pPorts !== undefined) throw new LocalDaemonError('bad_config', 'pair profile takes one peer');
    if (profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_TEST
      && fixedDifficulty !== PEER_TEST_FIXED_DIFFICULTY) {
      throw new LocalDaemonError('bad_config', `the peer test accepts only fixed difficulty ${PEER_TEST_FIXED_DIFFICULTY}`);
    }
    if (profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_NATURAL && fixedDifficulty !== undefined) {
      throw new LocalDaemonError('bad_config', 'the natural-difficulty pair cannot set fixedDifficulty');
    }
    requirePort(exclusivePeerP2pPort, 'exclusivePeerP2pPort');
    if (exclusivePeerP2pPort === rpcPort || exclusivePeerP2pPort === p2pPort) {
      throw new LocalDaemonError('bad_config', 'the exclusive peer must be the OTHER daemon\'s P2P port');
    }
    if (expectedImageId === undefined) throw new LocalDaemonError('bad_config', 'the peer pair requires expectedImageId');
  } else if (profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL) {
    if (exclusivePeerP2pPort !== undefined || fixedDifficulty !== undefined) {
      throw new LocalDaemonError('bad_config', 'the natural mesh takes exactly two peers and no fixed difficulty');
    }
    if (!Array.isArray(exclusivePeerP2pPorts) || exclusivePeerP2pPorts.length !== 2) {
      throw new LocalDaemonError('bad_config', 'the natural mesh requires exactly two peers');
    }
    for (const port of exclusivePeerP2pPorts) requirePort(port, 'exclusivePeerP2pPorts entry');
    if (new Set(exclusivePeerP2pPorts).size !== 2
      || exclusivePeerP2pPorts.includes(rpcPort) || exclusivePeerP2pPorts.includes(p2pPort)) {
      throw new LocalDaemonError('bad_config', 'mesh peers must be two distinct other P2P ports');
    }
    if (expectedImageId === undefined) throw new LocalDaemonError('bad_config', 'the peer mesh requires expectedImageId');
  } else if (exclusivePeerP2pPort !== undefined || exclusivePeerP2pPorts !== undefined || fixedDifficulty !== undefined) {
    throw new LocalDaemonError('bad_config', 'the offline profile takes no peer and no fixed difficulty');
  }
  return Object.freeze({
    wslDistro, image, artifactDir, runDir, rpcPort, p2pPort, uid, gid, profile,
    ...([DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_TEST, DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_NATURAL].includes(profile)
      ? { exclusivePeerP2pPort } : {}),
    ...(profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL
      ? { exclusivePeerP2pPorts: Object.freeze([...exclusivePeerP2pPorts]) } : {}),
    ...(profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_TEST ? { fixedDifficulty } : {}),
    ...(expectedImageId !== undefined ? { expectedImageId } : {}),
  });
}

/** Cross-check all three launch configs before reserving or starting any member of a private mesh. */
export function checkThreeNodeConfigs({ a, b, c } = {}) {
  const nodes = [a, b, c].map(checkDaemonConfig);
  if (nodes.some((n) => n.profile !== DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL)) {
    throw new LocalDaemonError('bad_config', 'all three daemons require the natural mesh profile');
  }
  const ports = nodes.flatMap((n) => [n.rpcPort, n.p2pPort]);
  if (new Set(ports).size !== 6 || new Set(nodes.map((n) => n.runDir)).size !== 3) {
    throw new LocalDaemonError('bad_config', 'three daemons require distinct run directories and six ports');
  }
  for (const n of nodes) {
    const peers = nodes.filter((other) => other !== n).map((other) => other.p2pPort).sort((x, y) => x - y);
    if ([...n.exclusivePeerP2pPorts].sort((x, y) => x - y).join(',') !== peers.join(',')) {
      throw new LocalDaemonError('bad_config', 'mesh peer ports must name exactly the other two daemons');
    }
    for (const key of ['wslDistro', 'image', 'artifactDir', 'uid', 'gid', 'expectedImageId']) {
      if (n[key] !== nodes[0][key]) {
        throw new LocalDaemonError('bad_config', `mesh ${key} identity differs`);
      }
    }
  }
  return Object.freeze({ a: nodes[0], b: nodes[1], c: nodes[2] });
}

export function daemonLaunchArgs(cfg, containerName) {
  if (!CONTAINER_RE.test(containerName)) throw new LocalDaemonError('bad_config', 'bad container name');
  return [
    '-d', cfg.wslDistro, '--exec',
    'docker', 'run', '--rm', '--name', containerName,
    '--network', 'host',
    '--user', `${cfg.uid}:${cfg.gid}`,
    '--pull', 'never',
    '-v', `${cfg.artifactDir}:/opt/meepcoin:ro`,
    '-v', `${cfg.runDir}:${cfg.runDir}`,
    '--entrypoint', '/opt/meepcoin/meepcoind',
    cfg.image,
    ...daemonFlags(cfg),
  ];
}

/**
 * Parse `ss -H -ltnup` output into the listeners owned by `pid`.
 * Returns [{ proto, local }] or null when the output is unrecognisable (fail closed).
 */
export function parseListeners(text, pid) {
  const out = [];
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const cols = line.split(/\s+/);
    if (cols.length < 5) return null;
    if (!line.includes(`pid=${pid},`)) continue;
    const proto = cols[0];
    // tcp: State Recv-Q Send-Q Local Peer [Process]; udp (UNCONN) has the same column layout.
    const local = cols[4];
    out.push({ proto, local });
  }
  return out;
}

/**
 * Every daemon listener must be numeric loopback on one of the two configured ports. RPC must
 * listen; in every peer profile P2P must listen too (with --offline it does not).
 */
export function checkListeners(listeners, { rpcPort, p2pPort, profile = DAEMON_PROFILES.OFFLINE_SINGLE }) {
  if (!Array.isArray(listeners)) return { ok: false, reason: 'unobservable' };
  const allowed = new Set([`127.0.0.1:${rpcPort}`, `127.0.0.1:${p2pPort}`]);
  const bad = listeners.filter((l) => l.proto !== 'tcp' || !allowed.has(l.local));
  if (bad.length > 0) return { ok: false, reason: 'unexpected_listener', bad };
  if (!listeners.some((l) => l.local === `127.0.0.1:${rpcPort}`)) return { ok: false, reason: 'rpc_not_listening' };
  if ((profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_TEST
      || profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_PEER_NATURAL
      || profile === DAEMON_PROFILES.PRIVATE_EXCLUSIVE_MESH_NATURAL)
    && !listeners.some((l) => l.local === `127.0.0.1:${p2pPort}`)) {
    return { ok: false, reason: 'p2p_not_listening' };
  }
  return { ok: true, listeners: listeners.map((l) => `${l.proto} ${l.local}`) };
}

/** Parse `ss -H -tnp` output into the TCP connections owned by `pid` ({ state, local, peer }), or null. */
export function parseConnections(text, pid) {
  const out = [];
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const cols = line.split(/\s+/);
    if (cols.length < 5) return null;
    if (!line.includes(`pid=${pid},`)) continue;
    out.push({ state: cols[0], local: cols[3], peer: cols[4] });
  }
  return out;
}

const LOOPBACK_ENDPOINT_RE = /^127\.0\.0\.1:(\d{1,5})$/;
const portOf = (endpoint) => Number(LOOPBACK_ENDPOINT_RE.exec(endpoint)?.[1] ?? NaN);

/**
 * One bounded observation of a daemon PAIR's TCP connections, taken from ONE socket-table snapshot.
 *
 * EVERY connection, in any state, must be numeric loopback at both ends: a half-open attempt to a
 * non-loopback address is still an egress attempt. Each ESTABLISHED connection of daemon X must be one
 * of: an RPC client on X's RPC port; an outgoing P2P connection to the OTHER daemon's P2P port; or an
 * incoming connection on X's P2P port whose EXACT REVERSE TUPLE (local and remote swapped) is a
 * connection the OTHER daemon's process owns, in any state. Anything else is an unexpected peer.
 * Connections still opening or closing are not judged as peers, because their other end may
 * legitimately be in a different state at that instant.
 *
 * `linked` REQUIRES ONE EXACT RECIPROCAL ESTABLISHED PAIR in this same snapshot: A's row
 * `X -> B:p2p` together with B's row `B:p2p -> X` (or the same with A and B exchanged). An outgoing
 * row on one side alone, or an incoming row that merely shares a port number with something the other
 * daemon owns, is not a link. It used to be: one expected-port row set linked by itself.
 * A snapshot, not a continuous no-egress proof.
 */
export function checkPairConnections({ aConns, bConns, a, b }) {
  if (!Array.isArray(aConns) || !Array.isArray(bConns)) return { ok: false, linked: false, bad: ['unobservable'] };
  const bad = [];
  const established = (c) => c.state === undefined || c.state === 'ESTAB';
  const reverseOf = (c, conns) => conns.find((o) => o.local === c.peer && o.peer === c.local) ?? null;
  const judge = (conns, self, other, otherConns, name) => {
    for (const c of conns) {
      const lp = portOf(c.local);
      const pp = portOf(c.peer);
      if (Number.isNaN(lp) || Number.isNaN(pp)) { bad.push(`${name}: non-loopback ${c.local} -> ${c.peer}`); continue; }
      if (!established(c)) continue;                                        // opening or closing: loopback is enough
      if (lp === self.rpcPort) continue;                                    // an RPC client
      if (pp === other.p2pPort) continue;                                   // outgoing to the other daemon
      if (lp === self.p2pPort && reverseOf(c, otherConns) !== null) continue; // incoming from exactly it
      bad.push(`${name}: unexpected peer ${c.local} -> ${c.peer}`);
    }
  };
  judge(aConns, a, b, bConns, 'A');
  judge(bConns, b, a, aConns, 'B');
  // An exact reciprocal ESTABLISHED pair: an outgoing row to the other daemon's P2P port whose reverse
  // tuple is established on the other daemon, in either direction.
  const reciprocal = (outConns, inConns, other) => outConns.some((c) => established(c)
    && c.peer === `127.0.0.1:${other.p2pPort}` && !Number.isNaN(portOf(c.local))
    && inConns.some((o) => established(o) && o.local === c.peer && o.peer === c.local));
  const linked = bad.length === 0 && (reciprocal(aConns, bConns, b) || reciprocal(bConns, aConns, a));
  return { ok: bad.length === 0, linked, bad };
}

/**
 * One socket-table snapshot for a prospective A/B/C mesh. This does not infer peer identity from
 * a port number alone: an incoming P2P row must have its exact reverse tuple in the named peer's
 * process, and each of the three links needs two ESTABLISHED reverse rows in the same snapshot.
 * RPC clients may use any numeric-loopback source port. No pair-run rule is changed by this helper.
 */
export function checkThreeNodeConnections({ nodes } = {}) {
  const bad = [];
  const links = [];
  if (!Array.isArray(nodes) || nodes.length !== 3
    || nodes.map((n) => n?.name).join(',') !== 'A,B,C'
    || nodes.some((n) => !Array.isArray(n?.connections)
      || !Number.isInteger(n?.rpcPort) || !Number.isInteger(n?.p2pPort))) {
    return { ok: false, linked: false, links, bad: ['unobservable_or_bad_mesh'] };
  }
  const allPorts = nodes.flatMap((n) => [n.rpcPort, n.p2pPort]);
  if (new Set(allPorts).size !== 6 || allPorts.some((p) => p < 1024 || p > 65535)) {
    return { ok: false, linked: false, links, bad: ['colliding_or_bad_mesh_ports'] };
  }
  const reservedPorts = new Set(allPorts);
  // A P2P client's source must not impersonate any of the six listener ports. In particular,
  // a row on another daemon's RPC listener must never satisfy the reverse-tuple link proof.
  const clientEndpoint = (endpoint) => !Number.isNaN(portOf(endpoint))
    && !reservedPorts.has(portOf(endpoint));
  const established = (c) => c?.state === 'ESTAB';
  const reverseOf = (c, other) => other.connections.find((o) => o.local === c.peer && o.peer === c.local) ?? null;
  for (const self of nodes) {
    for (const c of self.connections) {
      if (!c || Number.isNaN(portOf(c.local)) || Number.isNaN(portOf(c.peer))) {
        bad.push(`${self.name}: non-loopback ${c?.local} -> ${c?.peer}`);
        continue;
      }
      if (c.local === `127.0.0.1:${self.rpcPort}`) {
        if (!clientEndpoint(c.peer)) bad.push(`${self.name}: RPC client uses a reserved port ${c.local} -> ${c.peer}`);
        continue;
      }
      const outgoing = nodes.find((n) => n !== self && c.peer === `127.0.0.1:${n.p2pPort}`);
      if (outgoing) {
        if (!clientEndpoint(c.local)) {
          bad.push(`${self.name}: peer source uses a reserved port ${c.local} -> ${c.peer}`);
          continue;
        }
        if (!established(c) || established(reverseOf(c, outgoing))) continue;
        bad.push(`${self.name}: established peer lacks established owner reverse ${c.local} -> ${c.peer}`);
        continue;
      }
      const incoming = c.local === `127.0.0.1:${self.p2pPort}`
        ? nodes.find((n) => n !== self && clientEndpoint(c.peer) && reverseOf(c, n) !== null) : null;
      if (incoming) {
        if (!established(c) || established(reverseOf(c, incoming))) continue;
        bad.push(`${self.name}: established peer lacks established owner reverse ${c.local} -> ${c.peer}`);
        continue;
      }
      bad.push(`${self.name}: unexpected peer ${c.local} -> ${c.peer}`);
    }
  }
  for (let i = 0; i < nodes.length; i += 1) {
    for (let j = i + 1; j < nodes.length; j += 1) {
      const a = nodes[i];
      const b = nodes[j];
      const reciprocal = (from, to) => from.connections.some((c) => established(c)
        && c.peer === `127.0.0.1:${to.p2pPort}`
        && clientEndpoint(c.local)
        && to.connections.some((r) => established(r) && r.local === c.peer && r.peer === c.local));
      if (reciprocal(a, b) || reciprocal(b, a)) links.push(`${a.name}-${b.name}`);
    }
  }
  return { ok: bad.length === 0, linked: bad.length === 0 && links.length === 3, links, bad };
}

/**
 * @param {object} o
 * @param {object} o.config          see checkDaemonConfig
 * @param {Function} o.isRpcReady     async () => boolean; the pool's own read-only RPC health check
 * @param {Function} [o.spawnFn]      test seam for the long-lived `wsl.exe docker run` child
 * @param {Function} [o.runProbe]     test seam: async (argv) => { ok, code, stdout }
 * @param {Function} [o.prepareRunDir] Optional, bounded setup of the newly owned run directory.
 *                                    Failure retains the directory and starts no container.
 * @param {AbortSignal} [o.signal]
 */
export async function startLocalDaemon({
  config,
  isRpcReady,
  spawnFn = (args) => spawn('wsl.exe', args, { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true, shell: false }),
  runProbe = null,
  prepareRunDir = null,
  signal = null,
  limits = DAEMON_LIMITS,
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  now = () => Date.now(),
} = {}) {
  const cfg = checkDaemonConfig(config);
  if (typeof isRpcReady !== 'function') throw new LocalDaemonError('bad_config', 'isRpcReady is required');
  if (prepareRunDir !== null && typeof prepareRunDir !== 'function') {
    throw new LocalDaemonError('bad_config', 'prepareRunDir must be a function');
  }
  const containerName = `meepcoin-private-${randomBytes(8).toString('hex')}`;
  const wsl = (rest) => ['-d', cfg.wslDistro, '--exec', ...rest];

  const probe = runProbe ?? ((argv) => new Promise((resolve) => {
    let child;
    try {
      child = spawn('wsl.exe', argv, { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true, shell: false });
    } catch {
      resolve({ ok: false, code: null, stdout: '' });
      return;
    }
    let out = '';
    let done = false;
    const timer = setTimeout(() => { if (!done) { try { child.kill(); } catch { /* gone */ } } }, limits.probeTimeoutMs);
    child.stdout.on('data', (c) => { out = (out + c.toString('utf8')).slice(0, 64 * 1024); });
    child.on('error', () => { if (!done) { done = true; clearTimeout(timer); resolve({ ok: false, code: null, stdout: out }); } });
    child.on('close', (code) => { if (!done) { done = true; clearTimeout(timer); resolve({ ok: code === 0, code, stdout: out }); } });
  }));

  // A Desktop engine can run a healthy daemon that WSL 127.0.0.1 cannot reach. Refuse the known
  // topology mismatch before even allocating a private run directory. The browser runner performs
  // this same gate earlier still, before consuming its durable one-use reservation.
  const dockerInfo = await probe(wsl(['docker', 'info', '--format', '{{json .Labels}}']));
  const dockerEngine = classifyWslDockerEngine({
    status: dockerInfo.ok ? 0 : dockerInfo.code,
    stdout: dockerInfo.stdout,
  });
  if (!dockerEngine.ok) throw new LocalDaemonError('docker_topology_mismatch', dockerEngine.error);

  // ---- the run directory: created HERE, so "new" is a fact, and its identity is recorded -------
  const mk = await probe(wsl(['mkdir', '-m', '700', '--', cfg.runDir]));
  if (!mk.ok) throw new LocalDaemonError('run_dir_exists_or_unwritable', 'the run directory could not be created fresh');
  const st = await probe(wsl(['stat', '-c', '%d:%i:%u', '--', cfg.runDir]));
  const runDirIdentity = st.ok ? st.stdout.trim() : null;
  if (!runDirIdentity || !/^\d+:\d+:\d+$/.test(runDirIdentity) || runDirIdentity.split(':')[2] !== String(cfg.uid)) {
    // THE DIRECTORY mkdir JUST CREATED, and nothing else. No daemon has started, so the only thing
    // that may be undone is that one empty directory: a NON-recursive rmdir of the exact validated
    // path, then a positive observation that it is gone (with `/` as the control operand). If that
    // cannot be confirmed the path is reported as retained -- never silently claimed clean, and never
    // removed recursively.
    const err = new LocalDaemonError('run_dir_identity', 'the run directory identity could not be recorded');
    const rm = await probe(wsl(['rmdir', '--', cfg.runDir]));
    const ls = await probe(wsl(['ls', '-1', '-d', '--', '/', cfg.runDir]));
    const lines = String(ls.stdout).split('\n').map((l) => l.trim());
    err.runDirRemoved = rm.ok && lines.includes('/') && !lines.includes(cfg.runDir);
    if (!err.runDirRemoved) err.retainedPaths = [cfg.runDir];
    throw err;
  }

  if (prepareRunDir !== null) {
    try {
      if (signal?.aborted) throw new LocalDaemonError('aborted', 'startup was aborted');
      await prepareRunDir({ runDir: cfg.runDir, runDirIdentity, config: cfg });
      if (signal?.aborted) throw new LocalDaemonError('aborted', 'startup was aborted');
    } catch (cause) {
      const err = new LocalDaemonError('run_dir_preparation_failed', 'owned run directory preparation failed');
      err.cause = cause;
      err.retainedPaths = [cfg.runDir];
      throw err;
    }
  }

  const launchArgs = daemonLaunchArgs(cfg, containerName);
  let child = null;
  let childExited = false;
  let childExit = null;
  let closed = false;
  let closing = null;
  let linuxPid = null;
  let listeners = null;
  let imageId = null;
  let mounts = null;
  const anomalies = [];

  const resource = {
    get closed() { return closed; },
    get containerName() { return containerName; },
    get linuxPid() { return linuxPid; },
    get runDir() { return cfg.runDir; },
    get runDirIdentity() { return runDirIdentity; },
    get launchArgs() { return [...launchArgs]; },
    get listeners() { return listeners; },
    get childExit() { return childExit; },
    get shutdownOutcome() {
      return { gracefulProtocolShutdown: anomalies.length === 0, reason: anomalies.join('; ') || null };
    },
    beginClose() { if (!closing && !closed) closing = stopAndConfirm({ force: false }); },
    close() { return closeWith(false); },
    forceClose() { return closeWith(true); },
    /** Established TCP connections of the daemon process, as `local peer` pairs. */
    get imageId() { return imageId; },
    get mounts() { return mounts; },
    get config() { return cfg; },
    /** TCP connections of the daemon process, as { state, local, peer }, or null. */
    async observeConnections() {
      if (linuxPid === null) return null;
      const r = await probe(wsl(['ss', '-H', '-tnp']));
      if (!r.ok) return null;
      return parseConnections(r.stdout, linuxPid);
    },
    /** ONE raw `ss -H -tnp` snapshot of the shared WSL network namespace, or null. */
    async observeSocketTable() {
      const r = await probe(wsl(['ss', '-H', '-tnp']));
      return r.ok ? r.stdout : null;
    },
    /** ONE raw listener-table snapshot for rechecking this private daemon set during a run. */
    async observeListenerTable() {
      const r = await probe(wsl(['ss', '-H', '-ltnup']));
      return r.ok ? r.stdout : null;
    },
  };

  async function containerGone() {
    const ps = await probe(wsl(['docker', 'ps', '-a', '--no-trunc', '--filter', `name=^/${containerName}$`, '--format', '{{.ID}}']));
    if (!ps.ok) return false;
    if (ps.stdout.trim() !== '') return false;
    if (linuxPid !== null) {
      const ls = await probe(wsl(['ls', '-1', '-d', '--', '/proc/self', `/proc/${linuxPid}`]));
      // The control operand must be listed and our pid must not be.
      const lines = ls.stdout.split('\n').map((s) => s.trim());
      if (!lines.includes('/proc/self') || lines.includes(`/proc/${linuxPid}`)) return false;
    }
    return true;
  }

  async function joinChild(ms) {
    if (!child || childExited) return true;
    const deadlineAt = now() + ms;
    while (!childExited && now() < deadlineAt) await sleep(100);
    return childExited;
  }

  async function stopAndConfirm({ force }) {
    const r = await probe(wsl(force
      ? ['docker', 'kill', containerName]
      : ['docker', 'stop', '--time', String(limits.stopGraceSeconds), containerName]));
    if (!r.ok && !force) anomalies.push('docker stop did not confirm');
    if (!(await joinChild(force ? limits.exitJoinMs : limits.stopTimeoutMs))) {
      try { child?.kill(); } catch { /* already gone */ }
      await joinChild(limits.exitJoinMs);
    }
    if (childExit && childExit.code !== 0 && !force) anomalies.push(`docker run exited ${childExit.code}`);
    if (await containerGone()) {
      closed = true;
      return true;
    }
    return false;
  }

  async function closeWith(force) {
    if (closed) return;
    if (closing) {
      const ok = await closing;
      closing = null;
      if (ok || closed) return;
    }
    closing = stopAndConfirm({ force });
    const ok = await closing;
    closing = null;
    if (!ok) throw new LocalDaemonError('release_unconfirmed', 'the daemon container could not be confirmed gone');
  }

  // ---- launch ------------------------------------------------------------------------------------
  try {
    child = spawnFn(launchArgs);
  } catch {
    throw Object.assign(new LocalDaemonError('spawn_failed', 'could not start the daemon'), { resource });
  }
  child.on?.('exit', (code, sig) => { childExited = true; childExit = { code, signal: sig ?? null }; });
  child.on?.('error', () => { childExited = true; childExit = childExit ?? { code: null, signal: null }; });
  child.stderr?.on?.('data', () => { /* drained; never logged -- dependency text is not a sink */ });

  // Everything below can fail; the resource is handed back on the error so the caller can own it.
  const fail = (code, message) => Object.assign(new LocalDaemonError(code, message), { resource });
  try {
    // The container's PID, as Docker reports it, once it is running.
    const t0 = now();
    while (linuxPid === null) {
      if (signal?.aborted) throw fail('aborted', 'startup was aborted');
      if (childExited) throw fail('daemon_exited', 'the daemon exited during startup');
      if (now() - t0 > limits.readyTimeoutMs) throw fail('ready_timeout', 'the daemon container did not start');
      const ins = await probe(wsl(['docker', 'inspect', '--format', '{{.State.Running}} {{.State.Pid}}', containerName]));
      const m = ins.ok ? /^true (\d+)$/.exec(ins.stdout.trim()) : null;
      if (m && Number(m[1]) > 0) linuxPid = Number(m[1]);
      else await sleep(limits.readyPollMs);
    }
    // Healthy enough to answer a read-only RPC.
    for (;;) {
      if (signal?.aborted) throw fail('aborted', 'startup was aborted');
      if (childExited) throw fail('daemon_exited', 'the daemon exited during startup');
      if (now() - t0 > limits.readyTimeoutMs) throw fail('ready_timeout', 'the daemon RPC did not become ready');
      let ready = false;
      try { ready = await isRpcReady(); } catch { ready = false; }
      if (ready) break;
      await sleep(limits.readyPollMs);
    }
    // WHAT IS ACTUALLY RUNNING: the image the container was created from, and its mounts. The
    // artifact directory must be mounted read-only at /opt/meepcoin, and a pinned image id must match.
    const ins = await probe(wsl(['docker', 'inspect', '--format',
      '{{.Image}}|{{range .Mounts}}{{.Source}}={{.Destination}}:{{.RW}};{{end}}', containerName]));
    const [img, mountText] = ins.ok ? ins.stdout.trim().split('|') : [null, ''];
    imageId = IMAGE_ID_RE.test(img ?? '') ? img : null;
    mounts = String(mountText ?? '').split(';').filter(Boolean);
    if (imageId === null) throw fail('identity_unobservable', 'the container image could not be observed');
    if (cfg.expectedImageId !== undefined && imageId !== cfg.expectedImageId) {
      throw fail('image_mismatch', 'the container is not running the pinned image');
    }
    if (!mounts.includes(`${cfg.artifactDir}=/opt/meepcoin:false`)) {
      throw fail('artifact_mount_mismatch', 'the artifact directory is not mounted read-only at /opt/meepcoin');
    }
    // Its ACTUAL listeners, before any template is requested.
    const ss = await probe(wsl(['ss', '-H', '-ltnup']));
    const parsed = ss.ok ? parseListeners(ss.stdout, linuxPid) : null;
    const verdict = checkListeners(parsed, cfg);
    listeners = parsed;
    if (!verdict.ok) throw fail('listener_check_failed', `daemon listeners are not exactly the intended loopback ports (${verdict.reason})`);
  } catch (err) {
    if (err instanceof LocalDaemonError && err.resource) throw err;
    throw fail('startup_failed', 'daemon startup failed');
  }
  return resource;
}
