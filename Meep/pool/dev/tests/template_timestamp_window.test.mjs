import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { PREV_ID_BYTES, blobToHex, findNonceOffset, hexToBlob } from '../block_blob.mjs';
import { createDaemonRpc } from '../daemon_rpc.mjs';
import { TemplateWindowError, readTemplateTimestampWindow } from '../template_timestamp_window.mjs';

const vector = JSON.parse(readFileSync(new URL('../../../meepow/vectors/block_vectors_v16_devnet.json', import.meta.url))).vectors[1];
const hash = (height) => height.toString(16).padStart(64, '0');

function chain(length, timestamp = (height) => 100 + height) {
  return Array.from({ length }, (_, height) => ({
    height, hash: hash(height), prevHash: height ? hash(height - 1) : 'f'.repeat(64),
    timestamp: timestamp(height), orphanStatus: false,
  }));
}

function patchParent(hex, parent) {
  const blob = hexToBlob(hex);
  const { offset } = findNonceOffset(blob);
  blob.set(hexToBlob(parent), offset - PREV_ID_BYTES);
  return blobToHex(blob);
}

function templateFor(headers) {
  const parent = headers.at(-1).hash;
  return {
    height: headers.length, prevHashHex: parent,
    blockhashingBlobHex: patchParent(vector.block_hashing_blob, parent),
    blocktemplateBlobHex: patchParent(vector.full_block_blob, parent),
  };
}

function fakeRpc(headers, { beforeLast = () => {}, beforeHeight = () => {} } = {}) {
  const calls = [];
  let lastReads = 0;
  return {
    calls,
    async getLastBlockHeader(options) {
      calls.push(['last', options]);
      lastReads++;
      return { ...headers.at(-1), ...beforeLast(lastReads) };
    },
    async getBlockHeaderByHeight(height, options) {
      calls.push(['height', height, options]);
      const numeric = Number(height);
      return { ...headers[numeric], ...beforeHeight(numeric) };
    },
  };
}

async function reason(promise, expected) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof TemplateWindowError);
    assert.equal(error.reason, expected);
    return true;
  });
}

test('height 1 reads genesis once, fences its tip twice, and records the exact median', async () => {
  const headers = chain(1, () => 1785283200);
  const rpc = fakeRpc(headers);
  const receipt = await readTemplateTimestampWindow({ rpc, template: templateFor(headers) });
  assert.equal(receipt.candidateHeight, 1);
  assert.equal(receipt.parentHeight, 0);
  assert.equal(receipt.parentHash, headers[0].hash);
  assert.equal(receipt.startHeight, 0);
  assert.deepEqual(receipt.timestamps, [1785283200]);
  assert.equal(receipt.medianTimestamp, 1785283200);
  assert.deepEqual(rpc.calls, [
    ['last', { fillPowHash: false }],
    ['height', '0', { fillPowHash: false }],
    ['last', { fillPowHash: false }],
  ]);
  assert.equal(Object.isFrozen(receipt), true);
  assert.equal(Object.isFrozen(receipt.headers[0]), true);
  assert.equal(Object.isFrozen(receipt.timestamps), true);
});

test('strict daemon RPC normalization preserves the read-only receipt boundary', async () => {
  const headers = chain(1, () => 1785283200);
  const template = templateFor(headers);
  const methods = [];
  const transport = async (request) => {
    const body = JSON.parse(request.body);
    methods.push(body);
    request.handoff();
    const header = {
      hash: headers[0].hash, height: 0, nonce: 0,
      prev_hash: headers[0].prevHash, timestamp: headers[0].timestamp,
      orphan_status: false,
    };
    const result = body.method === 'get_block_template' ? {
      status: 'OK', height: 1, wide_difficulty: '0x1', seed_hash: 'a'.repeat(64),
      seed_height: 0, prev_hash: template.prevHashHex,
      blockhashing_blob: template.blockhashingBlobHex,
      blocktemplate_blob: template.blocktemplateBlobHex, reserved_offset: 0,
    } : { status: 'OK', block_header: header };
    return JSON.stringify({ jsonrpc: '2.0', id: body.id, result });
  };
  const rpc = createDaemonRpc({ transport });
  const daemonTemplate = await rpc.getBlockTemplate({ walletAddress: 'NON_SECRET_TEST_ADDRESS' });
  const receipt = await readTemplateTimestampWindow({ rpc, template: daemonTemplate });
  assert.deepEqual(receipt.timestamps, [1785283200]);
  assert.deepEqual(methods.map((call) => call.method), [
    'get_block_template', 'get_last_block_header',
    'get_block_header_by_height', 'get_last_block_header',
  ]);
  assert.ok(methods.slice(1).every((call) => call.params.fill_pow_hash === false));
});

test('height 60 includes genesis; height 61 excludes it and reads exactly 60 linked headers', async () => {
  const sixty = chain(60, (height) => height === 0 ? 1 : 100 + height);
  const a = await readTemplateTimestampWindow({ rpc: fakeRpc(sixty), template: templateFor(sixty) });
  assert.equal(a.startHeight, 0);
  assert.equal(a.headers.length, 60);
  assert.equal(a.medianTimestamp, 129);

  const sixtyOne = chain(61, (height) => height === 0 ? 1 : 99 + height);
  const rpc = fakeRpc(sixtyOne);
  const b = await readTemplateTimestampWindow({ rpc, template: templateFor(sixtyOne) });
  assert.equal(b.startHeight, 1);
  assert.deepEqual(b.headers.map((header) => header.height), Array.from({ length: 60 }, (_, i) => i + 1));
  assert.equal(b.medianTimestamp, 129); // floor((129 + 130) / 2), not the upper middle
  assert.equal(rpc.calls.filter(([method]) => method === 'height').length, 60);
  assert.ok(rpc.calls.every(([method]) => method === 'last' || method === 'height'));
});

test('template parent must agree with both parsed blob headers before any RPC', async () => {
  const headers = chain(2);
  const input = templateFor(headers);
  const wrongDeclared = { ...input, prevHashHex: 'e'.repeat(64) };
  const rpc = fakeRpc(headers);
  await reason(readTemplateTimestampWindow({ rpc, template: wrongDeclared }), 'template_mismatch');
  assert.equal(rpc.calls.length, 0);

  const wrongFull = { ...input, blocktemplateBlobHex: patchParent(vector.full_block_blob, 'd'.repeat(64)) };
  await reason(readTemplateTimestampWindow({ rpc, template: wrongFull }), 'template_mismatch');
  assert.equal(rpc.calls.length, 0);
});

test('malformed template, missing adapter and noncanonical input fail closed', async () => {
  const headers = chain(1);
  const template = templateFor(headers);
  await reason(readTemplateTimestampWindow({ rpc: {}, template }), 'bad_rpc');
  for (const change of [
    { height: 0 }, { height: Number.MAX_SAFE_INTEGER + 1 },
    { prevHashHex: 'A'.repeat(64) }, { blockhashingBlobHex: 'abc' },
  ]) {
    const rpc = fakeRpc(headers);
    await assert.rejects(readTemplateTimestampWindow({ rpc, template: { ...template, ...change } }));
    assert.equal(rpc.calls.length, 0);
  }
});

test('initial tip must equal the template parent', async () => {
  const headers = chain(3);
  const rpc = fakeRpc(headers, { beforeLast: () => ({ hash: 'e'.repeat(64) }) });
  await reason(readTemplateTimestampWindow({ rpc, template: templateFor(headers) }), 'template_tip_mismatch');
  assert.equal(rpc.calls.length, 1);
});

test('a valid tip height advance before the first read is stale, not malformed history', async () => {
  const headers = chain(2);
  const rpc = fakeRpc(headers, { beforeLast: () => ({ height: 2, hash: hash(2) }) });
  await reason(readTemplateTimestampWindow({ rpc, template: templateFor(headers) }),
    'template_tip_mismatch');
  assert.deepEqual(rpc.calls, [['last', { fillPowHash: false }]]);
  const malformed = fakeRpc(headers, { beforeLast: () => ({ height: 2, timestamp: null }) });
  await reason(readTemplateTimestampWindow({ rpc: malformed, template: templateFor(headers) }),
    'bad_header');
  const negative = fakeRpc(headers, { beforeLast: () => ({ height: -1 }) });
  await reason(readTemplateTimestampWindow({ rpc: negative, template: templateFor(headers) }),
    'bad_header');
});

test('every history read needs an exact height, timestamp and canonical flag', async () => {
  const headers = chain(3);
  for (const override of [{ height: 9 }, { timestamp: null }, { orphanStatus: true }]) {
    const rpc = fakeRpc(headers, { beforeHeight: (height) => height === 1 ? override : {} });
    await reason(readTemplateTimestampWindow({ rpc, template: templateFor(headers) }), 'bad_header');
  }
});

test('all 60 predecessors must link by hash', async () => {
  const headers = chain(61);
  const rpc = fakeRpc(headers, { beforeHeight: (height) => height === 35 ? { prevHash: 'e'.repeat(64) } : {} });
  await reason(readTemplateTimestampWindow({ rpc, template: templateFor(headers) }), 'history_unlinked');
});

test('height-read parent must equal the first tip observation', async () => {
  const headers = chain(2);
  const rpc = fakeRpc(headers, { beforeHeight: (height) => height === 1 ? { timestamp: 999 } : {} });
  await reason(readTemplateTimestampWindow({ rpc, template: templateFor(headers) }), 'history_tip_mismatch');
});

test('tip change during reads is refused even if the original history was coherent', async () => {
  const headers = chain(2);
  const rpc = fakeRpc(headers, { beforeLast: (read) => read === 2 ? { hash: 'e'.repeat(64) } : {} });
  await reason(readTemplateTimestampWindow({ rpc, template: templateFor(headers) }), 'tip_changed');
  const taller = fakeRpc(headers, { beforeLast: (read) => read === 2 ? { height: 2 } : {} });
  await reason(readTemplateTimestampWindow({ rpc: taller, template: templateFor(headers) }), 'tip_changed');
});

test('abort before and during the read never returns a receipt', async () => {
  const headers = chain(2);
  const controller = new AbortController();
  controller.abort();
  const before = fakeRpc(headers);
  await reason(readTemplateTimestampWindow({ rpc: before, template: templateFor(headers), signal: controller.signal }), 'aborted');
  assert.equal(before.calls.length, 0);

  const during = new AbortController();
  const rpc = fakeRpc(headers, { beforeHeight: () => { during.abort(); return {}; } });
  await reason(readTemplateTimestampWindow({ rpc, template: templateFor(headers), signal: during.signal }), 'aborted');
  assert.equal(rpc.calls.filter(([method]) => method === 'height').length, 1);
});
