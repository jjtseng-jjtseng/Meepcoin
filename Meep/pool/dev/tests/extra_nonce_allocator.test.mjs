// Pure allocation tests: no process, daemon, browser, socket, hash or filesystem mutation.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  EXTRA_NONCE_BYTES, ExtraNonceAllocatorError, createExtraNonceAllocator,
} from '../extra_nonce_allocator.mjs';

const ns = (hex) => () => Buffer.from(hex, 'hex');

test('one namespace plus a big-endian uint32 counter produces exact unique reserved bytes', () => {
  let mints = 0;
  const allocator = createExtraNonceAllocator({
    mintNamespace: () => { mints += 1; return Buffer.from('0102030405060708090a0b0c', 'hex'); },
  });
  assert.equal(allocator.reserveSize, EXTRA_NONCE_BYTES);
  assert.equal(allocator.issue(), '0102030405060708090a0b0c00000000');
  assert.equal(allocator.issue(), '0102030405060708090a0b0c00000001');
  assert.equal(allocator.issue(), '0102030405060708090a0b0c00000002');
  assert.equal(mints, 1, 'the process namespace changed between jobs');
});

test('a large allocation sample has exact lowercase shape and no duplicates', () => {
  const allocator = createExtraNonceAllocator({ mintNamespace: ns('a1a2a3a4a5a6a7a8a9aaabac') });
  const values = new Set();
  for (let i = 0; i < 10_000; i++) {
    const value = allocator.issue();
    assert.match(value, /^[0-9a-f]{32}$/);
    values.add(value);
  }
  assert.equal(values.size, 10_000);
});

test('different allocation domains do not share the same values at the same counters', () => {
  const a = createExtraNonceAllocator({ mintNamespace: ns('000000000000000000000001') });
  const b = createExtraNonceAllocator({ mintNamespace: ns('000000000000000000000002') });
  assert.notEqual(a.issue(), b.issue());
  assert.notEqual(a.issue(), b.issue());
});

test('the final uint32 value is issued once and exhaustion then fails closed', () => {
  const allocator = createExtraNonceAllocator({
    mintNamespace: ns('ffffffffffffffffffffffff'), initialCounter: (1n << 32n) - 1n,
  });
  assert.equal(allocator.issue(), 'ffffffffffffffffffffffffffffffff');
  assert.throws(
    () => allocator.issue(),
    (err) => err instanceof ExtraNonceAllocatorError && err.code === 'exhausted',
  );
});

test('namespace and configuration seams are closed and strictly validated', () => {
  for (const bad of [null, [], 'x']) {
    assert.throws(() => createExtraNonceAllocator(bad), ExtraNonceAllocatorError);
  }
  for (const bad of [
    () => Buffer.alloc(11), () => Buffer.alloc(13), () => '00'.repeat(12), () => null,
  ]) {
    assert.throws(
      () => createExtraNonceAllocator({ mintNamespace: bad }),
      (err) => err.code === 'bad_namespace',
    );
  }
  for (const initialCounter of [-1n, 1n << 32n, 0, '0']) {
    assert.throws(
      () => createExtraNonceAllocator({ mintNamespace: ns('00'.repeat(12)), initialCounter }),
      (err) => err.code === 'bad_options',
    );
  }
  assert.throws(
    () => createExtraNonceAllocator({ mintNamespace: ns('00'.repeat(12)), reset: true }),
    (err) => err.code === 'bad_options',
  );
});
