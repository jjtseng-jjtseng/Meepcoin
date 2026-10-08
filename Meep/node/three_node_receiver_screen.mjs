// Candidate screen over bytes already authenticated by verifyThreeNodeEvidence.
// This is not an independent PoW verifier or a final scientific adjudication.

import { findNonceOffset, hexToBlob, readNonce } from '../pool/dev/block_blob.mjs';
import { matchingReceiverRefusal, parseReceiverTimestampRefusals } from './receiver_timestamp_verdict.mjs';

const HASH = /^[0-9a-f]{64}$/;
const ROUTES = Object.freeze({ h1: ['A', 'B'], h2: ['B', 'A'] });
const goodMesh = (event) => event?.mesh?.ok === true && event.mesh.linked === true
  && event.mesh.links?.length === 3;

function blockHeader(fullBlockHex) {
  if (typeof fullBlockHex !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(fullBlockHex)) return null;
  try {
    const blob = hexToBlob(fullBlockHex);
    const header = findNonceOffset(blob);
    const timestamp = Number(header.timestamp);
    if (!Number.isSafeInteger(timestamp)) return null;
    return { timestamp, nonce: readNonce(blob, header.offset) };
  } catch { return null; }
}

export function screenThreeNodeReceiverEvents(events, logTextByNode) {
  if (!Array.isArray(events) || !logTextByNode
    || ['A', 'B', 'C'].some((node) => typeof logTextByNode[node] !== 'string')) {
    throw new TypeError('screen requires verified events and three daemon logs');
  }
  const refusals = Object.fromEntries(['A', 'B', 'C'].map((node) =>
    [node, parseReceiverTimestampRefusals(logTextByNode[node])]));
  const candidates = [];
  const incomplete = [];
  let acceptedHonestReadbacks = 0;
  let leadInHonestReadbacks = 0;
  const measurementStartIndex = events.findIndex((event) => event?.phase === 'ALL_MINERS_STARTED');
  for (let i = 0; i < events.length; i++) {
    const answer = events[i];
    if (answer?.phase !== 'BLOCK_ANSWER_AND_READBACK' || !ROUTES[answer.worker]
      || answer.canonical !== true) continue;
    acceptedHonestReadbacks += 1;
    const [producer, receiver] = ROUTES[answer.worker];
    const sameBlock = (event) => event?.worker === answer.worker
      && event.height === answer.height && event.nonce === answer.nonce
      && event.fullBlockHex === answer.fullBlockHex;
    const handoffIndex = events.slice(0, i).findLastIndex((event) =>
      event.phase === 'BLOCK_HANDED_OFF' && sameBlock(event));
    const foundIndex = handoffIndex < 0 ? -1 : events.slice(0, handoffIndex).findLastIndex((event) =>
      event.phase === 'FOUND_PRE_SUBMIT' && sameBlock(event));
    if (measurementStartIndex < 0 || i <= measurementStartIndex
      || (foundIndex >= 0 && foundIndex <= measurementStartIndex)) {
      leadInHonestReadbacks += 1;
      continue;
    }
    const found = events[foundIndex];
    const handoff = events[handoffIndex];
    const observed = answer.observed;
    const header = blockHeader(answer.fullBlockHex);
    const snapshot = found?.receiverPreSubmit;
    const snapshotWindow = snapshot?.predecessorWindow;
    const before = events.slice(0, foundIndex < 0 ? i : foundIndex).findLast((event) =>
      ['PRE_THIRD_MESH', 'TOPOLOGY_SAMPLE'].includes(event.phase));
    const after = events.slice(i + 1).find((event) =>
      ['TOPOLOGY_SAMPLE', 'POST_STOP_SAMPLE'].includes(event.phase));
    const checks = {
      handoff: handoffIndex >= 0 && foundIndex >= 0,
      identity: HASH.test(answer.blockId ?? '') && HASH.test(found?.parentHash ?? '')
        && HASH.test(found?.localHashHex ?? '')
        && handoff?.localHashHex === found?.localHashHex,
      readback: observed?.hash === answer.blockId && observed?.orphanStatus === false
        && observed?.height === answer.height && observed?.nonce === answer.nonce
        && observed?.powHash === found?.localHashHex
        && observed?.prevHash === found?.parentHash,
      blob: header?.nonce === answer.nonce && Number(observed?.timestamp) === header?.timestamp,
      snapshot: Number.isSafeInteger(snapshot?.height) && HASH.test(snapshot?.tip ?? '')
        && Array.isArray(snapshotWindow) && snapshotWindow.length > 0
        && snapshotWindow.length <= 60 && snapshotWindow.at(-1)?.hash === snapshot.tip
        && snapshotWindow.at(-1)?.height === snapshot.height - 1
        && snapshotWindow.every((block, index) => Number.isSafeInteger(block?.height)
          && HASH.test(block?.hash ?? '')
          && (index === 0 || (block.height === snapshotWindow[index - 1].height + 1
            && block.prev_hash === snapshotWindow[index - 1].hash))),
      topology: goodMesh(before) && goodMesh(after),
    };
    const failedChecks = Object.keys(checks).filter((name) => !checks[name]);
    if (failedChecks.length > 0) {
      incomplete.push({ worker: answer.worker, producer, receiver,
        blockHash: HASH.test(answer.blockId ?? '') ? answer.blockId : null,
        failedChecks });
      continue;
    }
    const refusal = matchingReceiverRefusal(refusals[receiver],
      { blockHash: answer.blockId, timestamp: header.timestamp });
    if (refusal) candidates.push({ worker: answer.worker, producer, receiver,
      blockHash: answer.blockId, height: answer.height, timestamp: header.timestamp,
      receiverMedian: refusal.median, receiverLogLine: refusal.line,
      topologyBeforeUtc: before.atUtc, topologyAfterUtc: after.atUtc,
      classification: 'CANDIDATE_FOR_INDEPENDENT_SCIENTIFIC_AUDIT' });
  }
  return Object.freeze({ scope: 'CANDIDATE_SCREEN_ONLY', acceptedHonestReadbacks,
    leadInHonestReadbacks,
    mainRefusalsByNode: Object.fromEntries(['A', 'B', 'C'].map((node) =>
      [node, refusals[node].filter((row) => row.path === 'MAIN').length])),
    candidates, incomplete, scientificVerdict: 'NOT_EVALUATED' });
}
