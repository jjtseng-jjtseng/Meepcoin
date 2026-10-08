import test from 'node:test';
import assert from 'node:assert/strict';
import { belowMedianCandidate, configForProbe, encodeVarint, lowerMedian60,
  readVarint } from './receiver_log_probe.mjs';

const PARENT = 'a'.repeat(64);
const oldReservation = { state: 'CONSUMED_ONE_USE', config: {
  runId: 'reach-c2-20260929t0627', wslDistro: 'Ubuntu',
  image: 'meepcoin-build:runtimeclosure-d37b174-20260924t201500z',
  artifactDir: '/home/tseng/meepcoin-reach-control2-variant-20260929T0618Z',
  expectedImageId: 'sha256:7eff53d041d9e1cfac1c22badcd92694d2756cb2bb088d66d35ddee1a50f19b2', uid: 1000, gid: 1000,
} };

test('a changed-length timestamp preserves exactly the parent and trailing block bytes', () => {
  const blob = Buffer.concat([encodeVarint(16), encodeVarint(16), encodeVarint(127),
    Buffer.from(PARENT, 'hex'), Buffer.from('04030201ff', 'hex')]).toString('hex');
  const out = belowMedianCandidate(blob, 128, PARENT);
  assert.equal(out.originalTimestamp, 127);
  assert.equal(out.candidateTimestamp, 128);
  assert.equal(out.fullBlockHex, `10108001${PARENT}04030201ff`);
  assert.throws(() => belowMedianCandidate(blob, 128, 'b'.repeat(64)), /copied canonical tip/);
  assert.throws(() => belowMedianCandidate('zz', 1, PARENT), /lowercase/);
});

test('varints refuse unsafe or truncated serialization', () => {
  for (const n of [0, 127, 128, 1790668111, Number.MAX_SAFE_INTEGER]) {
    assert.equal(readVarint(encodeVarint(n), 0).value, n);
  }
  assert.throws(() => readVarint(Buffer.from([128]), 0), /truncated/);
  assert.throws(() => encodeVarint(-1), /non-negative/);
});

test('median is the integer average of the central pair of the trailing 60 only', () => {
  const chain = [{ timestamp: 999 }, ...Array.from({ length: 60 }, (_, i) => ({ timestamp: i }))];
  assert.equal(lowerMedian60(chain), 29);
  assert.throws(() => lowerMedian60(chain.slice(0, 60)), /complete median window/);
});

test('probe config is offline, no peer, fresh run dir, exact two private ports', () => {
  const cfg = configForProbe({ runId: 'logprobe-20260929-test', repoCommit: 'c'.repeat(40),
    rpcPort: 59980, p2pPort: 59981, oldReservation });
  assert.equal(cfg.a.profile, 'offline-single');
  assert.equal(cfg.raw.scope, 'RECEIVER_LOG_PROBE');
  assert.equal(cfg.raw.runId, cfg.runId);
  assert.equal(cfg.raw.evidenceDir, cfg.evidenceDir);
  assert.equal(cfg.raw.arm, undefined);
  assert.equal(cfg.a.image, oldReservation.config.image);
  assert.equal(cfg.historicalImage, oldReservation.config.image);
  assert.equal(cfg.a.expectedImageId, oldReservation.config.expectedImageId);
  assert.equal(cfg.a.exclusivePeerP2pPort, undefined);
  assert.match(cfg.a.runDir, /^\/home\/tseng\/meepcoin-private-run-[0-9a-f]{24}$/);
  assert.deepEqual(cfg.raw.ports, { rpcA: 59980, p2pA: 59981 });
  assert.throws(() => configForProbe({ runId: cfg.runId, repoCommit: 'c'.repeat(40),
    rpcPort: 59980, p2pPort: 59980, oldReservation }), /private ports/);
  assert.throws(() => configForProbe({ runId: cfg.runId, repoCommit: 'c'.repeat(40),
    rpcPort: 59980, p2pPort: 59981, oldReservation: { ...oldReservation,
      config: { ...oldReservation.config, expectedImageId: `sha256:${'b'.repeat(64)}` } } }),
  /historical Docker image identity/);
});
