import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { blobToHex, findNonceOffset, hexToBlob } from '../pool/dev/block_blob.mjs';
import { hashingContextFor } from '../pool/dev/real_template.mjs';
import { createV2HasherForContext } from '../web-miner/lib/shared/wasm_hasher.js';
import { createDaemonRpc } from '../pool/dev/daemon_rpc.mjs';
import { TemplateWindowError } from '../pool/dev/template_timestamp_window.mjs';
import { roleConfig, prepareAppliedTemplate, runFreshMiner,
  submitFoundBlock } from './fresh_reachability_miner.mjs';
import { REACHABILITY_MODES } from './fresh_reachability_core.mjs';

const row = JSON.parse(readFileSync(new URL('../meepow/vectors/block_vectors_v16_devnet.json',
  import.meta.url), 'utf8')).vectors[1];
const original = hexToBlob(row.block_hashing_blob);
const parentOffset = findNonceOffset(original).offset;
const parent = Buffer.from(original.subarray(parentOffset - 32, parentOffset)).toString('hex');
const template = {
  height: row.height, wideDifficulty: String(row.difficulty), seedHashHex: row.epoch_key,
  prevHashHex: parent, blockhashingBlobHex: row.block_hashing_blob,
  blocktemplateBlobHex: row.full_block_blob,
};

test('role assignments have distinct nonce domains and the declared rates', () => {
  assert.deepEqual(roleConfig('h1'), { role: 'h1', nonceBase: 0, assignedRate: 45 });
  assert.deepEqual(roleConfig('h2'), { role: 'h2', nonceBase: 1_000_000_000, assignedRate: 45 });
  assert.deepEqual(roleConfig('third'), { role: 'third', nonceBase: 3_000_000_000, assignedRate: 9 });
  assert.throws(() => roleConfig('attacker'), /unknown/);
});

test('applied timestamp changes only the paired header timestamp, preserving parent', () => {
  const honest = prepareAppliedTemplate(template);
  const alternate = prepareAppliedTemplate(template, {
    appliedTimestamp: 1790000000, appliedStrategy: 'max-legal-future',
  });
  assert.equal(honest.job.height, alternate.job.height);
  assert.equal(honest.job.seedHashHex, alternate.job.seedHashHex);
  assert.equal(findNonceOffset(hexToBlob(alternate.job.hashingTemplateHex)).timestamp, 1790000000n);
  assert.notEqual(honest.job.contentDigest, alternate.job.contentDigest);
  assert.deepEqual(hashingContextFor(honest.job).seedHash,
    hashingContextFor(alternate.job).seedHash);
});

test('full and hashing blob disagreement fails before allocation', () => {
  assert.throws(() => prepareAppliedTemplate({ ...template, prevHashHex: '0'.repeat(64) }), /parent/);
  assert.throws(() => prepareAppliedTemplate({ ...template, blocktemplateBlobHex: '00' }), /./);
});

test('real Wasm hashes the altered template rather than a synthetic context', async () => {
  const moduleFactory = (await import('../meepow/wasm/meepow.mjs')).default;
  const alt = prepareAppliedTemplate(template, {
    appliedTimestamp: 1790000000, appliedStrategy: 'max-legal-future',
  });
  const hasher = await createV2HasherForContext(moduleFactory, hashingContextFor(alt.job));
  try {
    const hash = hasher.hashOne(123);
    assert.equal(hash.length, 32);
    assert.equal(hasher.hashCalls, 1);
  } finally { hasher.free(); }
});

test('one found block follows the exact adapter handoff and canonical readback path', async () => {
  const events = [];
  const abort = new AbortController();
  const zeroHash = '0'.repeat(64);
  const candidateId = 'a'.repeat(64);
  const rpc = createDaemonRpc({
    endpoint: 'http://127.0.0.1:19081/json_rpc',
    transport: async (req) => {
      req.handoff();
      const request = JSON.parse(req.body);
      const method = request.method;
      let result;
      if (method === 'get_block_template') result = {
        status: 'OK', height: template.height, wide_difficulty: '0x1', seed_hash: template.seedHashHex,
        prev_hash: template.prevHashHex, blockhashing_blob: template.blockhashingBlobHex,
        blocktemplate_blob: template.blocktemplateBlobHex, reserved_offset: 0,
      };
      else if (method === 'get_last_block_header') result = { status: 'OK', block_header: {
        height: template.height - 1, hash: template.prevHashHex, nonce: 0,
        timestamp: 1785283200, orphan_status: false, prev_hash: 'b'.repeat(64),
      } };
      else if (method === 'calc_pow') result = zeroHash;
      else if (method === 'submit_block') result = { status: 'OK', block_id: candidateId };
      else if (method === 'get_block_header_by_height') result = { status: 'OK', block_header: {
        height: template.height, hash: candidateId, nonce: 0, timestamp: 1785283201,
        orphan_status: false, pow_hash: zeroHash, prev_hash: template.prevHashHex,
      } };
      else throw new Error(`unexpected method ${method}`);
      return JSON.stringify({ jsonrpc: '2.0', id: request.id, result });
    },
  });
  let freed = 0;
  const summary = await runFreshMiner({ role: 'h1', mode: REACHABILITY_MODES.HONEST, rpc,
    moduleFactory: async () => ({}), createHasher: async () => ({
      hashOne: () => new Uint8Array(32), free: () => { freed++; },
    }), signal: abort.signal, sleep: async () => {},
    readReceiver: async () => ({ height: template.height, tip: template.prevHashHex,
      predecessorWindow: [{ height: template.height - 1, hash: template.prevHashHex,
        timestamp: 1785283200 }] }),
    onEvent: (event) => {
      events.push(event);
      if (event.phase === 'BLOCK_ANSWER_AND_READBACK') abort.abort();
    },
  });
  assert.equal(summary.actualHashes, 1);
  assert.equal(summary.submissions, 1);
  assert.equal(summary.accepted, 1);
  assert.equal(freed, 1);
  assert.deepEqual(events.filter((e) => e.phase === 'BLOCK_HANDED_OFF').length, 1);
  assert.equal(events.find((e) => e.phase === 'FOUND_PRE_SUBMIT').receiverPreSubmit.tip,
    template.prevHashHex);
  assert.equal(events.find((e) => e.phase === 'BLOCK_ANSWER_AND_READBACK').canonical, true);
});

test('stop during native PoW readback cannot dispatch a block', async () => {
  const abort = new AbortController();
  const methods = [];
  const rpc = createDaemonRpc({ endpoint: 'http://127.0.0.1:19081/json_rpc',
    transport: async (req) => {
      req.handoff();
      const request = JSON.parse(req.body);
      methods.push(request.method);
      if (request.method !== 'calc_pow') throw new Error('unexpected RPC after stop');
      abort.abort();
      return JSON.stringify({ jsonrpc: '2.0', id: request.id, result: '0'.repeat(64) });
    },
  });
  const outcome = await submitFoundBlock({ rpc, job: prepareAppliedTemplate(template).job,
    nonce: 0, localHashHex: '0'.repeat(64), onEvent: () => {}, signal: abort.signal });
  assert.equal(outcome, 'CANCELLED_BEFORE_HANDOFF');
  assert.deepEqual(methods, ['calc_pow']);
});

function windowRetryFixture({ mode = REACHABILITY_MODES.CONTROL, readWindow }) {
  const abort = new AbortController();
  const events = [];
  let templates = 0;
  let allocations = 0;
  let frees = 0;
  const rpc = {
    async getBlockTemplate() { templates++; return template; },
    async getLastBlockHeader() {
      return { height: template.height - 1, hash: template.prevHashHex, orphanStatus: false };
    },
  };
  const timestamp = Number(findNonceOffset(original).timestamp);
  const run = () => runFreshMiner({ role: 'third', mode, rpc,
    moduleFactory: async () => ({}), signal: abort.signal,
    clock: () => timestamp * 1000, sleep: async () => {},
    readWindow: (args) => readWindow(args, { timestamp, abort }),
    createHasher: async () => {
      allocations++;
      return { hashOne() { throw new Error('hashing was not authorized by this fixture'); },
        free() { frees++; } };
    },
    onEvent: (event) => {
      events.push(event);
      if (event.phase === 'TEMPLATE_READY') abort.abort();
    },
  });
  return { run, events, abort, get templates() { return templates; },
    get allocations() { return allocations; }, get frees() { return frees; } };
}

test('a changed window tip discards stale work and requests a fresh template in both arms', async () => {
  for (const mode of [REACHABILITY_MODES.CONTROL, REACHABILITY_MODES.ATTACK]) {
    for (const reason of ['tip_changed', 'template_tip_mismatch']) {
      let reads = 0;
      const f = windowRetryFixture({ mode, readWindow: async (_args, { timestamp }) => {
        if (++reads === 1) throw new TemplateWindowError(reason, 'tip advanced');
        return { medianTimestamp: timestamp - 1 };
      } });
      const summary = await f.run();
      assert.equal(f.templates, 2);
      assert.equal(reads, 2);
      assert.equal(f.allocations, 1);
      assert.equal(f.frees, 1);
      assert.equal(summary.actualHashes, 0);
      assert.equal(summary.stale, 1);
      assert.deepEqual(f.events.filter((e) => e.phase === 'WINDOW_STALE')
        .map((e) => e.reason), [reason]);
      assert.equal(f.events.filter((e) => e.phase === 'TEMPLATE_READY').length, 1);
    }
  }
});

test('real window reader and miner recover from a block arriving at the final tip fence', async () => {
  const timestamp = Number(findNonceOffset(original).timestamp);
  const nextHash = 'e'.repeat(64);
  const nextBlob = (hex) => {
    const blob = hexToBlob(hex);
    const offset = findNonceOffset(blob).offset;
    blob.set(hexToBlob(nextHash), offset - 32);
    return blobToHex(blob);
  };
  const nextTemplate = { ...template, height: template.height + 1, prevHashHex: nextHash,
    blockhashingBlobHex: nextBlob(template.blockhashingBlobHex),
    blocktemplateBlobHex: nextBlob(template.blocktemplateBlobHex) };
  const genesis = { height: 0, hash: template.prevHashHex, prevHash: 'f'.repeat(64),
    timestamp: timestamp - 1, orphanStatus: false };
  const successor = { height: 1, hash: nextHash, prevHash: genesis.hash,
    timestamp, orphanStatus: false };
  const abort = new AbortController();
  const events = [];
  let templateReads = 0;
  let tipReads = 0;
  let allocations = 0;
  const rpc = {
    async getBlockTemplate() { return ++templateReads === 1 ? template : nextTemplate; },
    async getLastBlockHeader() { return ++tipReads <= 2 ? genesis : successor; },
    async getBlockHeaderByHeight(height) {
      return Number(height) === 0 ? genesis : successor;
    },
  };
  const summary = await runFreshMiner({ role: 'third', mode: REACHABILITY_MODES.CONTROL,
    rpc, moduleFactory: async () => ({}), signal: abort.signal,
    clock: () => timestamp * 1000, sleep: async () => {},
    createHasher: async () => {
      allocations++;
      return { hashOne() { throw new Error('unexpected hash'); }, free() {} };
    },
    onEvent: (event) => {
      events.push(event);
      if (event.phase === 'TEMPLATE_READY') abort.abort();
    },
  });
  assert.equal(templateReads, 2);
  assert.equal(allocations, 1);
  assert.equal(summary.stale, 1);
  assert.equal(summary.actualHashes, 0);
  assert.deepEqual(events.filter((e) => e.phase === 'WINDOW_STALE')
    .map((e) => [e.height, e.reason]), [[1, 'tip_changed']]);
  assert.deepEqual(events.filter((e) => e.phase === 'TEMPLATE_READY')
    .map((e) => e.height), [2]);
});

test('tip recovery keeps the original assigned hash schedule without catch-up', async () => {
  const timestamp = Number(findNonceOffset(original).timestamp);
  let now = timestamp * 1000;
  let reads = 0;
  const abort = new AbortController();
  const rpc = {
    async getBlockTemplate() { return template; },
    async getLastBlockHeader() {
      return { height: template.height - 1, hash: template.prevHashHex, orphanStatus: false };
    },
  };
  const summary = await runFreshMiner({ role: 'third', mode: REACHABILITY_MODES.CONTROL,
    rpc, moduleFactory: async () => ({}), signal: abort.signal,
    clock: () => now, sleep: async () => {},
    readWindow: async () => {
      if (++reads === 1) {
        now += 1200;
        throw new TemplateWindowError('tip_changed', 'tip advanced');
      }
      return { medianTimestamp: timestamp - 1 };
    },
    createHasher: async () => ({ hashOne: () => new Uint8Array(32).fill(0xff), free() {} }),
    onEvent: (event) => { if (event.phase === 'FIRST_HASH') abort.abort(); },
  });
  assert.equal(summary.actualHashes, 1);
  assert.equal(summary.missedSlots, 10);
  assert.equal(summary.stale, 1);
  assert.equal(reads, 2);
  assert.equal(summary.submissions, 0);
});

test('repeated tip races have a fixed retry ceiling and never allocate a hasher', async () => {
  const f = windowRetryFixture({ readWindow: async () => {
    throw new TemplateWindowError('tip_changed', 'tip advanced');
  } });
  await assert.rejects(f.run(), (error) => error instanceof TemplateWindowError
    && error.reason === 'tip_changed');
  assert.equal(f.templates, 9);
  assert.equal(f.events.filter((e) => e.phase === 'WINDOW_STALE').length, 8);
  assert.equal(f.allocations, 0);
});

test('history inconsistency and forged tip-change errors remain fatal', async () => {
  for (const error of [new TemplateWindowError('history_unlinked', 'bad chain'),
    Object.assign(new Error('forged'), { reason: 'tip_changed' })]) {
    const f = windowRetryFixture({ readWindow: async () => { throw error; } });
    await assert.rejects(f.run(), (caught) => caught === error);
    assert.equal(f.templates, 1);
    assert.equal(f.events.filter((e) => e.phase === 'WINDOW_STALE').length, 0);
    assert.equal(f.allocations, 0);
  }
});

test('stop during a changed-tip read does not fetch a second template', async () => {
  const f = windowRetryFixture({ readWindow: async (_args, { abort }) => {
    abort.abort();
    throw new TemplateWindowError('tip_changed', 'tip advanced');
  } });
  const summary = await f.run();
  assert.equal(f.templates, 1);
  assert.equal(summary.actualHashes, 0);
  assert.equal(f.events.filter((e) => e.phase === 'WINDOW_STALE').length, 0);
});
