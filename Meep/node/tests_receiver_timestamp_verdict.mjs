import test from 'node:test';
import assert from 'node:assert/strict';
import { matchingReceiverRefusal, parseReceiverTimestampRefusals } from './receiver_timestamp_verdict.mjs';

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);
const main = `[2026-09-29] ERROR verify Timestamp of block with id: ${A}, 1234, less than median of last 60 blocks, 1235\n`
  + `[2026-09-29] ERROR verify Block with id: ${A}\nhas invalid timestamp: 1234\n`;
const alternative = `[2026-09-29] ERROR verify Timestamp of block with id: ${B}, 300, less than median of last 60 blocks, 400\n`
  + `[2026-09-29] ERROR verify Block with id: ${B}\n for alternative chain, has invalid timestamp: 300\n`;

test('retained 2026-09-29 daemon-only probe lines parse as a MAIN refusal', () => {
  // Exact lines 30-32 from daemon.log SHA-256 763ba18c334a98137ab8320f5f25fc9151aff9b991590cf2c50b78bda75608cf.
  const hash = '65d0895c0a139f9fe089d0aa3905bfb77d5bd9396427e97423954e8c53151479';
  const prefix = '2026-09-29 20:09:46.549\t[RPC1]\tERROR\tverify\t';
  const log = `${prefix}src/cryptonote_core/blockchain.cpp:4035\tTimestamp of block with id: <${hash}>, 1790666320, less than median of last 60 blocks, 1790666321\n`
    + `${prefix}src/cryptonote_core/blockchain.cpp:4156\tBlock with id: <${hash}>\n`
    + `${prefix}src/cryptonote_core/blockchain.cpp:4156\thas invalid timestamp: 1790666320\n`;
  assert.deepEqual(parseReceiverTimestampRefusals(log), [
    { blockHash: hash, timestamp: 1790666320, median: 1790666321, path: 'MAIN', line: 1 },
  ]);
});

test('source-format receiver line binds hash, computed median and main versus alternative path', () => {
  const rows = parseReceiverTimestampRefusals(main + alternative);
  assert.deepEqual(rows, [
    { blockHash: A, timestamp: 1234, median: 1235, path: 'MAIN', line: 1 },
    { blockHash: B, timestamp: 300, median: 400, path: 'ALTERNATIVE', line: 4 },
  ]);
  assert.deepEqual(matchingReceiverRefusal(rows, { blockHash: A, timestamp: 1234 }), rows[0]);
  assert.equal(matchingReceiverRefusal(rows, { blockHash: B, timestamp: 300 }), null);
  assert.deepEqual(matchingReceiverRefusal(rows, { blockHash: B, timestamp: 300, requireMain: false }), rows[1]);
});

test('angle-bracketed hashes in the recorded daemon report remain parseable', () => {
  // Verbatim message bodies from docs/CROSS_NODE_ALTPATH_T1T2.md, first case.
  const hash = 'bb403b05814d60745c32cfcd4b08ffe7bf9d49cf2b4f945897054526787bc266';
  const medianLine = `Timestamp of block with id: <${hash}>, 1785721266, less than median of last 60 blocks, 1785721267\n`;
  const mainLine = `Block with id: <${hash}>\nhas invalid timestamp: 1785721266\n`;
  const alternativeLine = `Block with id: <${hash}>\n for alternative chain, has invalid timestamp: 1785721266\n`;
  const mainRows = parseReceiverTimestampRefusals(medianLine + mainLine);
  const altRows = parseReceiverTimestampRefusals(medianLine + alternativeLine);
  assert.deepEqual(mainRows, [{ blockHash: hash, timestamp: 1785721266,
    median: 1785721267, path: 'MAIN', line: 1 }]);
  assert.deepEqual(altRows, [{ blockHash: hash, timestamp: 1785721266,
    median: 1785721267, path: 'ALTERNATIVE', line: 1 }]);
  assert.deepEqual(matchingReceiverRefusal(mainRows, { blockHash: hash, timestamp: 1785721266 }), mainRows[0]);
  assert.equal(matchingReceiverRefusal(altRows, { blockHash: hash, timestamp: 1785721266 }), null);
  assert.deepEqual(matchingReceiverRefusal(altRows,
    { blockHash: hash, timestamp: 1785721266, requireMain: false }), altRows[0]);
  assert.deepEqual(parseReceiverTimestampRefusals(medianLine.replace(`<${hash}>`, `<${hash}`) + mainLine), []);
});

test('file logger prefixes both std::endl caller fragments and still binds the same decision', () => {
  const prefix = '2026-09-29 20:09:46.549\t[RPC1]\tERROR\tverify\t';
  const medianLine = `${prefix}src/cryptonote_core/blockchain.cpp:4035\t`
    + `Timestamp of block with id: <${A}>, 1790666320, less than median of last 60 blocks, 1790666321\n`;
  const callerPrefix = `${prefix}src/cryptonote_core/blockchain.cpp:4156\t`;
  const caller = `${callerPrefix}Block with id: <${A}>\n`
    + `${callerPrefix}has invalid timestamp: 1790666320\n`;
  assert.deepEqual(parseReceiverTimestampRefusals(medianLine + caller), [
    { blockHash: A, timestamp: 1790666320, median: 1790666321, path: 'MAIN', line: 1 },
  ]);
  assert.equal(parseReceiverTimestampRefusals(medianLine + caller.replace('has invalid',
    'for alternative chain, has invalid'))[0].path, 'ALTERNATIVE');
  for (const mismatch of [
    caller.replace('[RPC1]', '[RPC2]'),
    caller.replace('20:09:46.549', '20:09:46.550'),
    caller.replace('blockchain.cpp:4156\thas', 'blockchain.cpp:4157\thas'),
    caller.replace(`Block with id: <${A}>`, `Block with id: <${B}>`),
    caller.replace('has invalid timestamp: 1790666320', 'has invalid timestamp: 1790666321'),
  ]) assert.equal(parseReceiverTimestampRefusals(medianLine + mismatch)[0].path, 'UNKNOWN');
});

test('silence, unknown path, wrong hash, wrong timestamp and non-median errors never become positives', () => {
  assert.deepEqual(parseReceiverTimestampRefusals('ordinary block accepted\n'), []);
  assert.deepEqual(parseReceiverTimestampRefusals(`[verify] Block with id: ${A} has invalid timestamp: 1234`), []);
  assert.deepEqual(parseReceiverTimestampRefusals(`Timestamp of block with id: ${A}, 1235, less than median of last 60 blocks, 1235`), []);
  assert.deepEqual(parseReceiverTimestampRefusals(`Timestamp of block with id: ${A}, 1234, less than median of last 11 blocks, 1235`), []);
  const rows = parseReceiverTimestampRefusals(`Timestamp of block with id: ${A}, 1234, less than median of last 60 blocks, 1235\n`
    + `Block with id: ${B} has invalid timestamp: 1234`);
  assert.equal(rows[0].path, 'UNKNOWN');
  assert.equal(matchingReceiverRefusal(rows, { blockHash: A, timestamp: 1234 }), null);
  assert.equal(matchingReceiverRefusal(rows, { blockHash: A, timestamp: 1234, requireMain: false }), null);
  assert.equal(matchingReceiverRefusal(rows, { blockHash: B, timestamp: 1234, requireMain: false }), null);
  assert.equal(matchingReceiverRefusal(rows, { blockHash: A, timestamp: 1233, requireMain: false }), null);
  assert.throws(() => parseReceiverTimestampRefusals(null), TypeError);
});
