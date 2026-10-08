import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { parseRealPoolCli, RealPoolCliError } from '../run_config.mjs';
import { REAL_DAEMON_MODE } from '../../../web-miner/lib/shared/protocol.js';

const RUN_ID = '0123456789abcdef';
const RUN_PATH = fileURLToPath(new URL('../run.mjs', import.meta.url));
const SERVER_PATH = fileURLToPath(new URL('../server.mjs', import.meta.url));
const base = [
  '--mode', REAL_DAEMON_MODE,
  '--artifact-dir', '/home/tseng/meepcoin-roundg-build-20260914T014827Z/out',
  '--image', 'meepcoin-build:roundg-20260914t014827z',
  '--rpc-port', '50481',
  '--p2p-port', '50480',
];
const imagePin = ['--expected-image-id', `sha256:${'a'.repeat(64)}`];
const peerPorts = ['--peer-rpc-port', '50491', '--peer-p2p-port', '50490'];
const genesisPin = ['--expected-genesis-hash', 'a'.repeat(64)];

const parse = (args = base) => parseRealPoolCli(args, { runId: RUN_ID });
const refused = (args, pattern) => assert.throws(() => parse(args), (err) => {
  assert.ok(err instanceof RealPoolCliError);
  assert.match(err.message, pattern);
  return true;
});

test('real CLI: an explicit minimal configuration produces one private offline daemon', () => {
  const got = parse();
  assert.equal(got.mode, REAL_DAEMON_MODE);
  assert.equal(got.host, '127.0.0.1');
  assert.equal(got.port, 8171);
  assert.deepEqual(got.realDaemon.daemon, {
    wslDistro: 'Ubuntu',
    image: 'meepcoin-build:roundg-20260914t014827z',
    artifactDir: '/home/tseng/meepcoin-roundg-build-20260914T014827Z/out',
    runDir: '/home/tseng/meepcoin-private-run-0123456789abcdef',
    rpcPort: 50481,
    p2pPort: 50480,
    uid: 1000,
    gid: 1000,
    profile: 'offline-single',
  });
  assert.equal(got.realDaemon.personalizeTemplates, true);
  assert.equal(got.twoSlotAssignments, false);
  assert.equal('walletAddress' in got.realDaemon, false);
  assert.equal('maxAttempts' in got.realDaemon, false, 'the launcher silently enabled re-arm');
});

test('real CLI: two-slot assignment mode is explicit and rejects misspelled or false values', () => {
  const got = parse([...base, ...imagePin, '--two-slot-assignments', 'true']);
  assert.equal(got.twoSlotAssignments, true);
  assert.equal(got.realDaemon.personalizeTemplates, true);
  assert.equal(got.realDaemon.daemon.expectedImageId, imagePin[1]);
  refused([...base, '--two-slot-assignments', 'true'], /requires --expected-image-id/);
  refused([...base, '--two-slot-assignments', 'false'], /must be exactly true/);
  refused([...base, '--two-slot-assignments', 'yes'], /must be exactly true/);
  refused([...base, '--two-slot-assignments', 'true', '--two-slot-assignments', 'true'], /more than once/);
});

test('real CLI: an explicit pair exposes the existing finite sequence/refresh plan', () => {
  const got = parse([...base, ...imagePin, ...peerPorts,
    '--sequence-blocks', '2', '--refresh-windows', '2']);
  assert.equal(got.twoSlotAssignments, false);
  assert.equal(got.realDaemon.sequenceBlocks, 2);
  assert.equal(got.realDaemon.refreshWindows, 2);
  const a = got.realDaemon.daemon;
  const b = got.realDaemon.peer.daemon;
  assert.equal(a.profile, 'private-exclusive-peer-test');
  assert.equal(b.profile, a.profile);
  assert.equal(a.fixedDifficulty, 500);
  assert.equal(b.fixedDifficulty, 500);
  assert.equal(a.expectedImageId, imagePin[1]);
  assert.equal(b.expectedImageId, a.expectedImageId);
  assert.equal(a.runDir, '/home/tseng/meepcoin-private-run-0123456789abcdefa');
  assert.equal(b.runDir, '/home/tseng/meepcoin-private-run-0123456789abcdefb');
  assert.equal(a.exclusivePeerP2pPort, b.p2pPort);
  assert.equal(b.exclusivePeerP2pPort, a.p2pPort);
  assert.equal(got.realDaemon.personalizeTemplates, true);
  assert.equal('shareDifficulty' in got.realDaemon, false);
});

test('real CLI: natural difficulty is a distinct, tightly bounded private pair', () => {
  const args = [...base, ...imagePin, ...peerPorts, '--natural-difficulty', 'true',
    '--expected-genesis-timestamp', '1785283200', ...genesisPin, '--sequence-blocks', '3'];
  const got = parse(args);
  assert.equal(got.realDaemon.daemon.profile, 'private-exclusive-peer-natural');
  assert.equal(got.realDaemon.peer.daemon.profile, 'private-exclusive-peer-natural');
  assert.equal('fixedDifficulty' in got.realDaemon.daemon, false);
  assert.equal('fixedDifficulty' in got.realDaemon.peer.daemon, false);
  assert.equal(got.realDaemon.sequenceBlocks, 3);
  assert.equal(got.realDaemon.expectedGenesisTimestamp, 1785283200);
  assert.equal(got.realDaemon.expectedGenesisHash, genesisPin[1]);
  assert.equal('maxGenesisAgeSeconds' in got.realDaemon, false);
  const fresh = parse([...args, '--max-genesis-age-seconds', '1800']);
  assert.equal(fresh.realDaemon.maxGenesisAgeSeconds, 1800);
  refused([...base, '--max-genesis-age-seconds', '1800'], /requires --natural-difficulty/);
  for (const bad of ['0', '-1', '1.5', '01800', '9007199254740992']) {
    refused([...args, '--max-genesis-age-seconds', bad], /max-genesis-age-seconds/);
  }
  refused([...base, '--natural-difficulty', 'true'], /requires a private daemon pair/);
  refused([...base, ...imagePin, ...peerPorts, '--natural-difficulty', 'true'], /requires --expected-genesis-timestamp/);
  refused([...base, ...imagePin, ...peerPorts, '--natural-difficulty', 'true',
    '--expected-genesis-timestamp', '1785283200'], /requires --expected-genesis-hash/);
  refused([...base, ...imagePin, ...peerPorts, '--expected-genesis-timestamp', '1785283200', ...genesisPin],
    /requires --natural-difficulty/);
  refused([...base, ...imagePin, ...peerPorts, ...genesisPin], /requires --natural-difficulty/);
  for (const bad of ['0', '-1', '01785283200', '1.5', '9007199254740992']) {
    refused([...base, ...imagePin, ...peerPorts, '--natural-difficulty', 'true',
      '--expected-genesis-timestamp', bad, ...genesisPin], /expected-genesis-timestamp/);
  }
  for (const bad of ['0', 'A'.repeat(64), 'a'.repeat(63), 'g'.repeat(64)]) {
    refused([...base, ...imagePin, ...peerPorts, '--natural-difficulty', 'true',
      '--expected-genesis-timestamp', '1785283200', '--expected-genesis-hash', bad], /expected-genesis-hash/);
  }
  refused([...base, ...imagePin, ...peerPorts, '--natural-difficulty', 'false'], /exactly true/);
  refused([...args, '--sequence-blocks', '4'], /more than once/);
  refused([...base, ...imagePin, ...peerPorts, '--natural-difficulty', 'true',
    '--expected-genesis-timestamp', '1785283200', ...genesisPin, '--sequence-blocks', '4'],
    /at most three heights/);
  refused([...args, '--refresh-windows', '2'], /one window each/);
  refused([...args, '--share-difficulty', '1'], /no fixed share target/);
});

test('real CLI: paired share work is explicit and stays below the fixed block difficulty', () => {
  const got = parse([...base, ...imagePin, ...peerPorts,
    '--sequence-blocks', '2', '--refresh-windows', '2', '--share-difficulty', '50']);
  assert.equal(got.realDaemon.shareDifficulty, 50);
  assert.equal(got.realDaemon.daemon.fixedDifficulty, 500);
  assert.equal(got.realDaemon.peer.daemon.fixedDifficulty, 500);
  for (const value of ['0', '501', '050', '-1', '1.5', '1e2']) {
    refused([...base, ...imagePin, ...peerPorts, '--share-difficulty', value],
      /share-difficulty/);
  }
  refused([...base, '--share-difficulty', '50'], /require a private daemon pair/);
  refused([...base, ...imagePin, '--two-slot-assignments', 'true', '--share-difficulty', '50'],
    /require a private daemon pair/);
});

test('real CLI: pair and context plan refuse incomplete, unsafe or excessive configurations', () => {
  refused([...base, '--peer-rpc-port', '50491'], /both --peer-rpc-port and --peer-p2p-port/);
  refused([...base, '--peer-p2p-port', '50490'], /both --peer-rpc-port and --peer-p2p-port/);
  refused([...base, ...peerPorts], /requires --expected-image-id/);
  refused([...base, ...imagePin, ...peerPorts, '--two-slot-assignments', 'true'], /cannot use --two-slot/);
  refused([...base, '--sequence-blocks', '2'], /require a private daemon pair/);
  refused([...base, '--refresh-windows', '2'], /require a private daemon pair/);
  refused([...base, ...imagePin, ...peerPorts, '--sequence-blocks', '0'], /\[2, 32\]/);
  refused([...base, ...imagePin, ...peerPorts, '--refresh-windows', '5'], /\[2, 4\]/);
  refused([...base, ...imagePin, ...peerPorts, '--sequence-blocks', '17', '--refresh-windows', '2'], /32-context/);
  refused([...base, ...imagePin, '--peer-rpc-port', '50480', '--peer-p2p-port', '50490'], /five distinct ports/);
  refused([...base, ...imagePin, '--peer-rpc-port', '50491', '--peer-p2p-port', '50491'], /five distinct ports/);
  refused([...base, ...imagePin, '--peer-rpc-port', '50491', '--peer-p2p-port', '8171'], /five distinct ports/);
});

test('real CLI: a fresh direct-export artifact directory retains its owner and exact path', () => {
  const direct = '/home/tseng/meepcoin-runtimeclosure-build-20260924T201900Z';
  const args = base.map((value, index) => base[index - 1] === '--artifact-dir' ? direct : value);
  const got = parse(args);
  assert.equal(got.realDaemon.daemon.artifactDir, direct);
  assert.equal(got.realDaemon.daemon.runDir, '/home/tseng/meepcoin-private-run-0123456789abcdef');
});

test('real CLI: optional pins and a public coinbase destination are passed only from trusted argv', () => {
  const address = '9' + 'A'.repeat(94);
  const got = parse([...base,
    '--host', '127.0.0.2', '--port', '51871', '--wsl-distro', 'Ubuntu-24.04',
    '--uid', '1001', '--gid', '1002', '--expected-image-id', `sha256:${'a'.repeat(64)}`,
    '--coinbase-address', address,
  ]);
  assert.equal(got.host, '127.0.0.2');
  assert.equal(got.port, 51871);
  assert.equal(got.realDaemon.walletAddress, address);
  assert.equal(got.realDaemon.daemon.expectedImageId, `sha256:${'a'.repeat(64)}`);
  assert.equal(got.realDaemon.daemon.uid, 1001);
  assert.equal(got.realDaemon.daemon.gid, 1002);
});

test('real CLI: missing, duplicate and unknown options fail before any side effect', () => {
  refused(base.filter((_, i) => i < 2 || i > 3), /artifact-dir/);
  refused([...base, '--rpc-port', '50482'], /more than once/);
  refused([...base, '--retry', 'true'], /unknown option --retry/);
  refused([...base, '--coinbase-address'], /requires one value/);
  refused(['not-a-flag', 'x', ...base], /unexpected argument/);
});

test('real CLI: ports are canonical, bounded and pairwise distinct', () => {
  const replace = (name, value) => base.map((v, i) => base[i - 1] === `--${name}` ? value : v);
  refused(replace('rpc-port', '050481'), /canonical decimal/);
  refused(replace('rpc-port', '80'), /\[1024, 65535\]/);
  refused([...base, '--port', '50481'], /three different ports/);
  refused(replace('p2p-port', '50481'), /three different ports/);
});

test('real CLI: mode, run identity, artifact path and address are fail-closed', () => {
  refused(base.map((v) => v === REAL_DAEMON_MODE ? 'synthetic' : v), /--mode must be/);
  assert.throws(() => parseRealPoolCli(base, { runId: '../bad' }), /runId/);
  refused(base.map((v) => v.includes('/meepcoin-roundg-') ? 'C:/build/out' : v), /artifact-dir/);
  for (const bad of [
    '/home/tseng/meepcoin-build/',
    '/home/tseng/meepcoin-build/out/extra',
    '/home/tseng/meepcoin-build/../other',
    '/home/tseng/not-meepcoin-build',
  ]) refused(base.map((v, i) => base[i - 1] === '--artifact-dir' ? bad : v), /artifact-dir/);
  refused([...base, '--coinbase-address', 'not-an-address'], /coinbase-address/);
});

test('real CLI: the executable threads the config into the pool without an automatic browser or retry', () => {
  const source = readFileSync(RUN_PATH, 'utf8');
  assert.ok(source.includes('realDaemon: realCli.realDaemon'));
  assert.match(readFileSync(SERVER_PATH, 'utf8'), /realDaemonFactory\(\{\s*\.\.\.realDaemon,/,
    'the pool must forward both genesis pins from the parsed CLI into the real builder');
  assert.ok(source.includes('twoSlotAssignments: true'));
  assert.ok(source.includes('realCli.realDaemon.peer'));
  assert.ok(source.includes('ONE EXPLICIT START / ONE ATTEMPT / NO AUTOMATIC RETRY'));
  assert.ok(source.includes('--simulation cannot be combined with an explicit --mode'));
  assert.equal(/spawn\s*\(/.test(source), false, 'the launcher opens a browser or another process itself');
  assert.equal(source.includes('maxAttempts'), false, 'the launcher added a hidden multi-attempt option');
  assert.equal(source.includes('wallet-rpc'), false, 'the launcher gained a wallet path');
});

test('real CLI: conflicting mode selectors and a public bind are refused by the executable', () => {
  const run = (args) => spawnSync(process.execPath, [RUN_PATH, ...args], {
    encoding: 'utf8',
    timeout: 10_000,
  });

  const conflict = run(['--simulation', '--mode', REAL_DAEMON_MODE]);
  assert.equal(conflict.status, 2);
  assert.match(conflict.stderr, /cannot be combined/);

  const publicBind = run([...base, '--host', '0.0.0.0']);
  assert.equal(publicBind.status, 2);
  assert.match(publicBind.stderr, /loopback only/);
  assert.doesNotMatch(publicBind.stderr, /Wasm build artifacts are missing|could not start the daemon/,
    'the public bind reached artifact loading or daemon startup');

  const twoSlotPublicBind = run([...base, ...imagePin, '--two-slot-assignments', 'true', '--host', '0.0.0.0']);
  assert.equal(twoSlotPublicBind.status, 2);
  assert.match(twoSlotPublicBind.stderr, /loopback only/);
  assert.doesNotMatch(twoSlotPublicBind.stderr, /Wasm build artifacts are missing|could not start the daemon/);

  const pairedPublicBind = run([...base, ...imagePin, ...peerPorts, '--host', '0.0.0.0']);
  assert.equal(pairedPublicBind.status, 2);
  assert.match(pairedPublicBind.stderr, /loopback only/);
  assert.doesNotMatch(pairedPublicBind.stderr, /Wasm build artifacts are missing|could not start the daemon/);
});
