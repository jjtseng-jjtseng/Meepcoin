import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { acceptedControlVerdict, inspectKnownBlock } from './receiver_accepted_control.mjs';

const TIP = '15d988b703d55776de02ee042a218f19cb3ef65e64389c3ae11bf02e5419ea9d';
const PARENT = 'a'.repeat(64);
const good = () => ({ before: { height: 91, tip: TIP },
  popped: { height: 90, tip: PARENT }, after: { height: 91, tip: TIP },
  block: { hash: TIP, parent: PARENT }, popResponse: { status: 'OK', height: 90 },
  submitResponse: { result: { status: 'OK', block_id: TIP } }, refusals: [],
  cleanup: { confirmed: true } });

test('only the exact known block restored to the copied chain passes', () => {
  const baseline = good();
  assert.deepEqual(acceptedControlVerdict(baseline), {
    restored: true, submitted: true, popAcknowledged: true,
    noFalseRefusal: true, cleanupConfirmed: true, pass: true,
  });
  for (const mutant of [
    { popped: { height: 90, tip: 'b'.repeat(64) } },
    { after: { height: 91, tip: 'b'.repeat(64) } },
    { popResponse: { status: 'OK', height: 89 } },
    { submitResponse: { result: { status: 'OK', block_id: 'b'.repeat(64) } } },
    { submitResponse: { transportUnknown: true } },
    { refusals: null },
    { refusals: [{ blockHash: TIP, timestamp: 1, median: 2, path: 'MAIN' }] },
    { cleanup: { confirmed: false } },
  ]) assert.equal(acceptedControlVerdict({ ...baseline, ...mutant }).pass, false);
});

test('fetched block inspection identifies only structural mismatches without recording the blob', () => {
  const fetched = { status: 'OK', block_header: { hash: TIP, prev_hash: PARENT, num_txes: 0 },
    tx_hashes: [], blob: 'aabb' };
  const good = inspectKnownBlock(fetched, TIP, PARENT);
  assert.equal(good.allPass, true);
  assert.equal(JSON.stringify(good).includes('aabb'), false);
  assert.equal(inspectKnownBlock({ ...fetched, tx_hashes: undefined }, TIP, PARENT).allPass, true);
  const bad = inspectKnownBlock({ ...fetched, tx_hashes: ['b'.repeat(64)], blob: 'ZZ' }, TIP, PARENT);
  assert.equal(bad.allPass, false);
  assert.equal(bad.checks.noOrdinaryTransactions, false);
  assert.equal(bad.checks.blobValid, false);
  assert.equal(inspectKnownBlock({ ...fetched,
    block_header: { ...fetched.block_header, num_txes: 1 }, tx_hashes: undefined }, TIP, PARENT)
    .checks.noOrdinaryTransactions, false);
});

test('the accepted control source has one pop and one submission, no mining or wallet path', () => {
  const source = readFileSync(new URL('./receiver_accepted_control.mjs', import.meta.url), 'utf8');
  assert.equal((source.match(/'\/pop_blocks'/g) ?? []).length, 1);
  assert.equal((source.match(/method: 'submit_block'/g) ?? []).length, 1);
  for (const forbidden of ['start_mining', 'generateblocks', 'transfer(', 'wallet-rpc',
    'get_block_template', 'new Worker(']) assert.equal(source.includes(forbidden), false);
});
