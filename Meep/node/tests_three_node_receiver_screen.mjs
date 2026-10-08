import test from 'node:test';
import assert from 'node:assert/strict';
import { screenThreeNodeReceiverEvents } from './three_node_receiver_screen.mjs';

const BLOCK = 'a'.repeat(64);
const PARENT = 'b'.repeat(64);
const PROOF = '0'.repeat(64);
const RECEIVER_TIP = 'c'.repeat(64);
const TIMESTAMP = 1790666320;
const MEDIAN = TIMESTAMP + 1;
const NONCE = 7;

function varint(number) {
  const bytes = [];
  while (number >= 128) {
    bytes.push((number % 128) | 128);
    number = Math.floor(number / 128);
  }
  bytes.push(number);
  return Buffer.from(bytes);
}

function fixture(worker = 'h1') {
  const nonce = Buffer.alloc(4);
  nonce.writeUInt32LE(NONCE);
  const fullBlockHex = Buffer.concat([Buffer.from([2, 0]), varint(TIMESTAMP),
    Buffer.from(PARENT, 'hex'), nonce, Buffer.from([0])]).toString('hex');
  const mesh = { ok: true, linked: true, links: ['A-B', 'A-C', 'B-C'] };
  const common = { worker, height: 91, nonce: NONCE, fullBlockHex };
  const events = [
    { phase: 'ALL_MINERS_STARTED', atUtc: '2026-09-28T23:59:59.000Z' },
    { phase: 'TOPOLOGY_SAMPLE', atUtc: '2026-09-29T00:00:00.000Z', mesh },
    { phase: 'FOUND_PRE_SUBMIT', atUtc: '2026-09-29T00:00:01.000Z',
      ...common, parentHash: PARENT, localHashHex: PROOF,
      receiverPreSubmit: { height: 91, tip: RECEIVER_TIP,
        predecessorWindow: [{ height: 90, hash: RECEIVER_TIP }] } },
    { phase: 'BLOCK_HANDED_OFF', atUtc: '2026-09-29T00:00:02.000Z',
      ...common, localHashHex: PROOF },
    { phase: 'BLOCK_ANSWER_AND_READBACK', atUtc: '2026-09-29T00:00:03.000Z',
      ...common, blockId: BLOCK, canonical: true,
      observed: { hash: BLOCK, height: 91, nonce: NONCE, timestamp: TIMESTAMP,
        prevHash: PARENT, powHash: PROOF, orphanStatus: false } },
    { phase: 'TOPOLOGY_SAMPLE', atUtc: '2026-09-29T00:00:04.000Z', mesh },
  ];
  const prefix = '2026-09-29 20:09:46.549\t[RPC1]\tERROR\tverify\t';
  const refusal = `${prefix}src/cryptonote_core/blockchain.cpp:4035\t`
    + `Timestamp of block with id: <${BLOCK}>, ${TIMESTAMP}, less than median of last 60 blocks, ${MEDIAN}\n`
    + `${prefix}src/cryptonote_core/blockchain.cpp:4156\tBlock with id: <${BLOCK}>\n`
    + `${prefix}src/cryptonote_core/blockchain.cpp:4156\thas invalid timestamp: ${TIMESTAMP}\n`;
  return { events, logs: { A: '', B: '', C: '' }, refusal };
}

test('only a bound honest acceptance and the other honest receiver MAIN refusal is a candidate', () => {
  const { events, logs, refusal } = fixture();
  logs.B = refusal;
  const screen = screenThreeNodeReceiverEvents(events, logs);
  assert.equal(screen.scope, 'CANDIDATE_SCREEN_ONLY');
  assert.equal(screen.scientificVerdict, 'NOT_EVALUATED');
  assert.equal(screen.acceptedHonestReadbacks, 1);
  assert.equal(screen.leadInHonestReadbacks, 0);
  assert.deepEqual(screen.mainRefusalsByNode, { A: 0, B: 1, C: 0 });
  assert.deepEqual(screen.incomplete, []);
  assert.deepEqual(screen.candidates, [{ worker: 'h1', producer: 'A', receiver: 'B',
    blockHash: BLOCK, height: 91, timestamp: TIMESTAMP, receiverMedian: MEDIAN,
    receiverLogLine: 1, topologyBeforeUtc: '2026-09-29T00:00:00.000Z',
    topologyAfterUtc: '2026-09-29T00:00:04.000Z',
    classification: 'CANDIDATE_FOR_INDEPENDENT_SCIENTIFIC_AUDIT' }]);
});

test('an honest block found before the third miner starts is excluded from the arm', () => {
  const { events, logs, refusal } = fixture();
  logs.B = refusal;
  events.splice(0, 1);
  events.splice(4, 0, { phase: 'ALL_MINERS_STARTED', atUtc: '2026-09-29T00:00:03.500Z' });
  const screen = screenThreeNodeReceiverEvents(events, logs);
  assert.equal(screen.acceptedHonestReadbacks, 1);
  assert.equal(screen.leadInHonestReadbacks, 1);
  assert.deepEqual(screen.candidates, []);
});

test('h2 is paired with A, never its own B log or C', () => {
  const { events, logs, refusal } = fixture('h2');
  logs.B = refusal;
  logs.C = refusal;
  assert.equal(screenThreeNodeReceiverEvents(events, logs).candidates.length, 0);
  logs.A = refusal;
  const candidates = screenThreeNodeReceiverEvents(events, logs).candidates;
  assert.equal(candidates.length, 1);
  assert.deepEqual([candidates[0].producer, candidates[0].receiver], ['B', 'A']);
});

test('the fixed post-stop observation may supply the next sampled link', () => {
  const { events, logs, refusal } = fixture();
  logs.B = refusal;
  events.at(-1).phase = 'POST_STOP_SAMPLE';
  assert.equal(screenThreeNodeReceiverEvents(events, logs).candidates.length, 1);
});

test('alternative path and unpaired caller lines cannot produce a candidate', () => {
  const { events, logs, refusal } = fixture();
  logs.B = refusal.replace('has invalid timestamp:', 'for alternative chain, has invalid timestamp:');
  assert.equal(screenThreeNodeReceiverEvents(events, logs).candidates.length, 0);
  logs.B = refusal.replace(`Block with id: <${BLOCK}>`, `Block with id: <${'d'.repeat(64)}>`);
  assert.equal(screenThreeNodeReceiverEvents(events, logs).candidates.length, 0);
});

test('a malformed blob, readback, missing handoff, snapshot, or mesh is incomplete', () => {
  for (const change of [
    (f) => { f.events[4].fullBlockHex = 'zz'; },
    (f) => { f.events[4].observed.timestamp += 1; },
    (f) => { f.events.splice(3, 1); },
    (f) => { f.events[2].receiverPreSubmit = null; },
    (f) => { f.events[5].mesh.linked = false; },
  ]) {
    const f = fixture();
    f.logs.B = f.refusal;
    change(f);
    const screen = screenThreeNodeReceiverEvents(f.events, f.logs);
    assert.equal(screen.candidates.length, 0);
    assert.equal(screen.incomplete.length, 1);
  }
});
