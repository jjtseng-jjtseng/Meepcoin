// THE WORKER ROTATION ON THE PRODUCTION HASHING PATH: the real Worker dispatcher (lib/worker_core.js),
// the real contextual hasher factory (lib/shared/wasm_hasher.js), the real bounded scan and the pinned
// MeepHash-W v2 Wasm build, in Node. No browser, server or daemon.
//
// WHAT IT PROVES, AND HOW. One Worker searches a real daemon-produced block context (devnet height 0)
// and then, re-contextualised, a second one across a seed/epoch transition (height 2113). Each search
// must reproduce the DAEMON's recorded proof-of-work hash for its own block -- values from a committed
// vector file the daemon generated, which a bug here cannot move. Between the two, the previous hasher
// must be inactive and refuse to hash, only ONE module instance may exist, and the Wasm heap must not
// grow: the second 32 MiB dataset is allocated only after the first was torn down in the same heap.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';

import { createWorkerCore } from '../lib/worker_core.js';
import { createV2HasherForContext } from '../lib/shared/wasm_hasher.js';
import { searchNonces } from '../lib/shared/search.js';
import { bytesToHex, hexToBytes, nonceToHex } from '../lib/shared/target.js';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const createModuleReal = (await import(pathToFileURL(resolve(REPO, 'meepow/wasm/meepow.mjs')).href)).default;
const VECTORS = JSON.parse(readFileSync(resolve(REPO, 'meepow/vectors/block_vectors_v16_devnet.json'), 'utf8')).vectors;
const rowAt = (h) => VECTORS.find((v) => v.height === h);

function searchMessages(row, gen, jobId, prevJobId = null) {
  const common = {
    gen,
    jobId,
    // Exactly the recorded nonce, so each search computes ONE real hash.
    window: { nonceStart: row.nonce, nonceRange: 1, targetHexLE: row.target_le_hex, maxSearchMs: 120_000 },
    context: { epochKeyHex: row.epoch_key, seedHashHex: row.delayed_seed_input, height: String(row.height), hashingTemplateHex: row.blob_nonce_zeroed },
  };
  return prevJobId === null ? { cmd: 'init_search', ...common } : { cmd: 'init_search_next', prevJobId, ...common };
}

test('ONE Worker, TWO real block contexts: the old context is torn down in the same heap before the new one hashes', async () => {
  const modules = [];
  const hashers = [];
  const posted = [];
  const core = createWorkerCore({
    createModule: async () => { const M = await createModuleReal(); modules.push(M); return M; },
    createV2Hasher: async () => { throw new Error('the synthetic hasher must not be built'); },
    createV2HasherForContext: async (factory, ctx) => { const h = await createV2HasherForContext(factory, ctx); hashers.push(h); return h; },
    searchNonces,
    hexToBytes,
    bytesToHex,
    nonceToHex,
    postMessage: (m) => posted.push(m),
    now: () => Date.now(),
  });
  const events = (ev) => posted.filter((m) => m.ev === ev);
  const [first, second] = [rowAt(0), rowAt(2113)];
  assert.notEqual(first.epoch_key, second.epoch_key, 'the two contexts must differ in their epoch key');

  assert.equal((await core.handle(searchMessages(first, 3, 'realjob-a'))).ok, true);
  const heapAfterFirst = modules[0].HEAPU8.length;
  assert.equal((await core.handle({ cmd: 'search', gen: 3, jobId: 'realjob-a' })).ok, true);
  assert.equal(events('found').length, 1);
  assert.equal(events('found')[0].hashHexLE, first.daemon_pow_hash, 'block 1 did not reproduce the daemon hash');
  assert.equal(hashers[0].isActive(), true);

  const r = await core.handle(searchMessages(second, 3, 'realjob-b', 'realjob-a'));
  assert.equal(r.ok, true, JSON.stringify(posted.at(-1)));
  const ready = events('ready').at(-1);
  assert.equal(ready.rotated, true);
  assert.equal(ready.moduleInstances, 1);
  assert.equal(ready.priorContextFreed, true);
  assert.equal(ready.priorContextActive, false);
  assert.equal(modules.length, 1, 'a second Wasm module instance (and heap) was created');
  // THE TEARDOWN BOUNDARY on the real adapter: the first hasher is freed and refuses to hash, the second
  // is the only active context, and the heap did not grow for a second dataset.
  assert.equal(hashers[0].isActive(), false);
  assert.throws(() => hashers[0].hashOne(first.nonce), /already freed/);
  assert.equal(hashers[1].isActive(), true);
  assert.equal(modules[0].ccall('meep_v2_active', 'number', [], []), 1);
  assert.equal(modules[0].HEAPU8.length, heapAfterFirst, 'the Wasm heap grew: two datasets coexisted');
  assert.equal(ready.wasmHeapBytes, heapAfterFirst);

  assert.equal((await core.handle({ cmd: 'search', gen: 3, jobId: 'realjob-b' })).ok, true);
  assert.equal(events('found').length, 2);
  assert.equal(events('found')[1].jobId, 'realjob-b');
  assert.equal(events('found')[1].nonce, second.nonce);
  assert.equal(events('found')[1].hashHexLE, second.daemon_pow_hash, 'block 2 did not reproduce the daemon hash');
  assert.equal(hashers[1].hashCalls, 1);
  assert.equal(hashers[0].hashCalls, 1);
  hashers[1].free();
});
