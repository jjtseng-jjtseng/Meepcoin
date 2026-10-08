// Read-only consistency audit for a completed prospective three-node arm.
// An independently recorded result digest is required: internal hashes alone are circular.
// This verifies evidence shape and custody, not the scientific receiver-timestamp event.

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { screenThreeNodeReceiverEvents } from './three_node_receiver_screen.mjs';

const HEX64 = /^[0-9a-f]{64}$/;
const NAMES = ['reservation.json', 'events.jsonl', 'observation.json', 'cleanup.json',
  'daemon-A.log', 'daemon-B.log', 'daemon-C.log', 'result.json'];
const REQUIRED_PHASES = ['DAEMONS_READY', 'RECEIVER_VERIFICATION_LOGGING_CONFIRMED',
  'GENESIS_VERIFIED', 'FULL_MESH_VERIFIED', 'PRE_THIRD_MESH', 'ALL_MINERS_STARTED',
  'MINERS_STOPPED', 'CLEANUP'];
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
function need(ok, message) { if (!ok) throw new Error(`three-node evidence: ${message}`); }

export function verifyThreeNodeEvidence(root, expectedResultSha256) {
  need(typeof expectedResultSha256 === 'string' && HEX64.test(expectedResultSha256),
    'an external result SHA-256 pin is required');
  const entries = readdirSync(root, { withFileTypes: true });
  need(entries.every((entry) => entry.isFile())
    && entries.map((entry) => entry.name).sort().join('|') === [...NAMES].sort().join('|'),
  'file inventory is not the closed eight-file bundle');
  const bytes = Object.fromEntries(NAMES.map((name) => [name, readFileSync(join(root, name))]));
  need(sha(bytes['result.json']) === expectedResultSha256, 'result differs from external pin');
  // Parse the same byte buffers that were hashed, never a second read of mutable files.
  const parsed = (name) => JSON.parse(bytes[name].toString('utf8'));
  const result = parsed('result.json');
  const reservation = parsed('reservation.json');
  const observation = parsed('observation.json');
  const cleanup = parsed('cleanup.json');
  for (const [name, digest] of [
    ['reservation.json', result.reservationSha256], ['events.jsonl', result.eventsSha256],
    ['observation.json', result.observationSha256], ['cleanup.json', result.cleanupSha256],
  ]) need(HEX64.test(digest) && sha(bytes[name]) === digest, `${name} digest mismatch`);
  need(reservation.schema === 'meepcoin-three-node-arm-reservation/1'
    && reservation.state === 'CONSUMED_ONE_USE'
    && Array.isArray(reservation.configs) && reservation.configs.length === 3,
  'reservation identity or three-daemon assignment differs');
  need(observation.schema === 'meepcoin-three-node-observation/1'
    && observation.final === false && result.final === true && result.cleanupConfirmed === true
    && result.schema === observation.schema && result.arm === observation.arm
    && result.pairId === observation.pairId && result.stopReason === observation.stopReason
    && result.arm === reservation.raw.arm && result.pairId === reservation.raw.pairId
    && ['FIXED_WALL_BUDGET', 'ALL_AT_HEIGHT_CAP'].includes(result.stopReason)
    && result.interpretation === 'DESCRIPTIVE_ONLY_PENDING_RECEIVER_VERDICT_AUDIT',
  'result, observation, and reservation disagree');
  need(JSON.stringify(result.nodes) === JSON.stringify(observation.nodes)
    && JSON.stringify(result.workerResults) === JSON.stringify(observation.workerResults),
  'result rewrote the pre-cleanup observation');
  need(Array.isArray(result.workerResults) && result.workerResults.length === 3
    && result.workerResults.map((worker) => worker.role).join(',') === 'h1,h2,third',
  'worker assignment is incomplete');
  need(Array.isArray(cleanup.closeResults) && cleanup.closeResults.length === 3
    && cleanup.closeResults.every((row) => row.closed === true && !row.forced
      && row.shutdown?.gracefulProtocolShutdown === true)
    && cleanup.closeResults.map((row) => row.runDir).join('|')
      === [...reservation.configs].reverse().map((config) => config.runDir).join('|'),
  'owned daemon shutdown was not confirmed graceful');
  need(Array.isArray(result.logs) && result.logs.length === 3
    && JSON.stringify(result.logs) === JSON.stringify(cleanup.logs),
  'log inventory differs between result and cleanup');
  for (let i = 0; i < 3; i++) {
    const letter = ['A', 'B', 'C'][i];
    const log = result.logs[i];
    const name = `daemon-${letter}.log`;
    need(log.runDir === reservation.configs[i].runDir
      && log.bytes === bytes[name].length && HEX64.test(log.sha256)
      && sha(bytes[name]) === log.sha256,
    `${name} is missing, changed, or misattributed`);
    const state = result.nodes?.[letter];
    const chain = state?.canonical;
    need(state?.runDir === log.runDir && Number.isInteger(state?.height)
      && state.height >= 1 && Array.isArray(chain) && chain.length === state.height
      && chain.at(-1)?.hash === state.tip,
    `${letter} final canonical tip is incomplete`);
    for (let height = 0; height < chain.length; height++) {
      need(Number(chain[height]?.height) === height && HEX64.test(chain[height]?.hash)
        && (height === 0 || chain[height]?.prev_hash === chain[height - 1].hash),
      `${letter} canonical ancestry fails at height ${height}`);
    }
    need(chain[0].hash === reservation.raw.genesisHash
      && Number(chain[0].timestamp) === reservation.raw.genesisTimestamp,
      `${letter} final chain has the wrong pinned genesis`);
  }
  const lines = bytes['events.jsonl'].toString('utf8').trim().split('\n');
  const events = lines.map((line) => JSON.parse(line));
  const phases = events.map((event) => event.phase);
  need(REQUIRED_PHASES.every((phase) => phases.includes(phase)), 'required lifecycle events are missing');
  need(REQUIRED_PHASES.every((phase, i) => i === 0
    || phases.indexOf(REQUIRED_PHASES[i - 1]) < phases.indexOf(phase)),
  'lifecycle events are out of order');
  need(!phases.some((phase) => ['FAILURE', 'WORKER_ERROR', 'WORKER_FORCE_TERMINATED'].includes(phase)),
    'failure or forced termination exists in a final bundle');
  for (const phase of ['PRE_THIRD_MESH', 'TOPOLOGY_SAMPLE', 'POST_STOP_SAMPLE']) {
    const samples = events.filter((event) => event.phase === phase);
    need(samples.length > 0 && samples.every((event) => event.mesh?.ok === true
      && event.mesh?.linked === true && event.mesh?.links?.length === 3),
    `${phase} contains missing or broken private mesh evidence`);
    if (phase === 'PRE_THIRD_MESH') need(samples.length === 1
      && samples[0].states?.length === 3
      && samples[0].states.every((state) => state.synchronized === true),
    'pre-third synchronization evidence is missing or broken');
  }
  const receiverScreen = screenThreeNodeReceiverEvents(events,
    Object.fromEntries(['A', 'B', 'C'].map((node) =>
      [node, bytes[`daemon-${node}.log`].toString('utf8')])));
  return Object.freeze({ ok: true, scope: 'INTEGRITY_AND_STRUCTURE_ONLY',
    resultSha256: expectedResultSha256, arm: result.arm, stopReason: result.stopReason,
    finalHeights: Object.fromEntries(['A', 'B', 'C'].map((name) => [name, result.nodes[name].height])),
    topologySamples: phases.filter((phase) => phase === 'TOPOLOGY_SAMPLE').length,
    postStopSamples: phases.filter((phase) => phase === 'POST_STOP_SAMPLE').length,
    receiverScreen, scientificVerdict: 'NOT_EVALUATED' });
}
