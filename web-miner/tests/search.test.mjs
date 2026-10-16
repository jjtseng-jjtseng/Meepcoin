// The shared nonce-search loop: bounded, stoppable, and yielding often enough that a Stop
// message can actually be delivered (docs/BROWSER_V2.md).

import test from 'node:test';
import assert from 'node:assert/strict';

import { searchNonces } from '../lib/shared/search.js';

/** Deterministic stand-in for MeepHash-W: hash value == nonce, little-endian. */
function counterHash(nonce) {
  const out = new Uint8Array(32);
  out[0] = nonce & 0xff;
  out[1] = (nonce >> 8) & 0xff;
  return out;
}

function targetFor(value) {
  const t = new Uint8Array(32);
  t[0] = value & 0xff;
  t[1] = (value >> 8) & 0xff;
  return t;
}

test('scans exactly the window it was given', async () => {
  let calls = 0;
  const r = await searchNonces({
    hashOne: (n) => { calls++; return counterHash(n); },
    target: new Uint8Array(32), // only nonce 0 could ever qualify
    nonceStart: 100,
    nonceRange: 7,
  });
  assert.equal(calls, 7);
  assert.equal(r.hashes, 7);
  assert.equal(r.exhausted, true);
  assert.equal(r.stopped, false);
});

test('reports every qualifying nonce and no others', async () => {
  const found = [];
  const r = await searchNonces({
    hashOne: counterHash,
    target: targetFor(3), // nonces 0,1,2,3 qualify
    nonceStart: 0,
    nonceRange: 10,
    onFound: ({ nonce }) => found.push(nonce),
  });
  assert.deepEqual(found, [0, 1, 2, 3]);
  assert.equal(r.found, 4);
});

test('a nonce whose hash exactly equals the target qualifies', async () => {
  const found = [];
  await searchNonces({
    hashOne: counterHash,
    target: targetFor(5),
    nonceStart: 5,
    nonceRange: 1,
    onFound: ({ nonce }) => found.push(nonce),
  });
  assert.deepEqual(found, [5], 'equality must pass, as in meepow/src/target.hpp');
});

test('stops promptly when the stop flag is set, without finishing the window', async () => {
  let calls = 0;
  let stop = false;
  const r = await searchNonces({
    hashOne: (n) => { calls++; if (calls === 5) stop = true; return counterHash(n); },
    target: new Uint8Array(32),
    nonceStart: 0,
    nonceRange: 100000,
    batch: 2,
    shouldStop: () => stop,
  });
  assert.equal(r.stopped, true);
  assert.equal(r.exhausted, false);
  assert.equal(calls, 5, 'the loop must not run another hash after the flag is seen');
});

test('yields between batches so a queued stop message can be delivered', async () => {
  const order = [];
  let stop = false;
  // The yield stands in for the event loop turn during which a postMessage would arrive.
  const yieldFn = async () => {
    order.push('yield');
    if (order.filter((x) => x === 'yield').length === 2) stop = true;
  };
  const r = await searchNonces({
    hashOne: (n) => { order.push('hash'); return counterHash(n); },
    target: new Uint8Array(32),
    nonceStart: 0,
    nonceRange: 1000,
    batch: 3,
    shouldStop: () => stop,
    yieldFn,
  });
  assert.equal(order.slice(0, 4).join(','), 'hash,hash,hash,yield', 'must yield every `batch` hashes');
  assert.equal(r.stopped, true);
  assert.equal(r.hashes, 6, 'stopped after the second batch, having yielded twice');
});

test('progress is reported per batch, not per hash', async () => {
  const progress = [];
  await searchNonces({
    hashOne: counterHash,
    target: new Uint8Array(32),
    nonceStart: 0,
    nonceRange: 12,
    batch: 4,
    onProgress: (p) => progress.push(p.hashes),
  });
  // Three batch reports plus one final report.
  assert.deepEqual(progress, [4, 8, 12, 12]);
});

test('a stop flag that is already set means zero hashes', async () => {
  let calls = 0;
  const r = await searchNonces({
    hashOne: (n) => { calls++; return counterHash(n); },
    target: new Uint8Array(32),
    nonceStart: 0,
    nonceRange: 50,
    shouldStop: () => true,
  });
  assert.equal(calls, 0);
  assert.equal(r.hashes, 0);
  assert.equal(r.stopped, true);
});

test('rejects nonsensical windows instead of looping forever', async () => {
  const base = { hashOne: counterHash, target: new Uint8Array(32), nonceStart: 0, nonceRange: 4 };
  await assert.rejects(() => searchNonces({ ...base, nonceRange: 0 }), RangeError);
  await assert.rejects(() => searchNonces({ ...base, nonceRange: -1 }), RangeError);
  await assert.rejects(() => searchNonces({ ...base, nonceStart: -5 }), RangeError);
  await assert.rejects(() => searchNonces({ ...base, nonceStart: 0x100000000 }), RangeError);
  await assert.rejects(() => searchNonces({ ...base, nonceStart: 0xffffffff, nonceRange: 2 }), RangeError);
  await assert.rejects(() => searchNonces({ ...base, nonceStart: 0, nonceRange: 0x100000001 }), RangeError);
  await assert.rejects(() => searchNonces({ ...base, batch: 0 }), RangeError);
});

test('the last uint32 nonce is searchable without wrapping', async () => {
  const observed = [];
  const result = await searchNonces({
    hashOne: (nonce) => { observed.push(nonce); return counterHash(nonce); },
    target: new Uint8Array(32),
    nonceStart: 0xffffffff,
    nonceRange: 1,
  });
  assert.deepEqual(observed, [0xffffffff]);
  assert.equal(result.hashes, 1);
  assert.equal(result.exhausted, true);
});
