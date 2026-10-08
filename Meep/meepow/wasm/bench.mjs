// Node.js Wasm benchmark (allocation-free steady-state via the reusable context). Builds the
// epoch dataset AND the per-job context ONCE, then hashes many nonces with zero per-hash heap
// allocation, so the hashrate is steady-state per-hash cost — comparable to the native benchmark.
//
// Usage: node bench.mjs [--param dev|fast] [--hashes N] [--construction A|B]
import createModule from './meepow.mjs';

const args = process.argv.slice(2);
const getArg = (name, def) => {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : def;
};
const paramName = getArg('--param', 'dev');
const param = paramName === 'fast' ? 1 : 0;
const construction = getArg('--construction', 'B') === 'A' ? 0 : 1;
const hashes = parseInt(getArg('--hashes', '300'), 10);

const Module = await createModule();
const HEAP = () => Module.HEAPU8;

const epochKey = new Uint8Array(32).map((_, i) => (i * 7 + 1) & 0xff);
const seedHash = new Uint8Array(32).map((_, i) => (i * 3 + 9) & 0xff);
const tmpl = new Uint8Array(32);

const ek = Module._malloc(32); HEAP().set(epochKey, ek);
const sh = Module._malloc(32); HEAP().set(seedHash, sh);
const tp = Module._malloc(32); HEAP().set(tmpl, tp);
const outHash = Module._malloc(32);

// one-time: dataset init
let t = process.hrtime.bigint();
const ds = Module.ccall('meepow_dataset_create', 'number', ['number','number','number'],
  [param, construction, ek]);
const datasetMs = Number(process.hrtime.bigint() - t) / 1e6;
if (ds === 0) { console.error('dataset_create failed'); process.exit(1); }

// one-time: context creation (program derivation + buffers)
t = process.hrtime.bigint();
const ctx = Module.ccall('meepow_ctx_create', 'number',
  ['number','number','bigint','number','number'], [ds, sh, 4096n, tp, tmpl.length]);
const ctxMs = Number(process.hrtime.bigint() - t) / 1e6;
if (ctx === 0) { console.error('ctx_create failed'); process.exit(1); }

const hashNonce = (nonce) =>
  Module.ccall('meepow_ctx_hash', 'number', ['number','number','number','number','number'],
    [ctx, nonce >>> 0, outHash, 0, 0]);

hashNonce(0); // warm

// Wasm heap size before/after the loop: no growth => no per-hash wasm allocation.
const heapBefore = HEAP().length;
const per = [];
for (let n = 0; n < hashes; n++) {
  const t0 = process.hrtime.bigint();
  hashNonce(n + 1);
  per.push(Number(process.hrtime.bigint() - t0) / 1e6);
}
const heapAfter = HEAP().length;

per.sort((a, b) => a - b);
const mean = per.reduce((a, b) => a + b, 0) / per.length;
const p50 = per[Math.floor(per.length / 2)];
const p95 = per[Math.floor(per.length * 0.95)];
const p99 = per[Math.floor(per.length * 0.99)];

Module.ccall('meepow_ctx_free', null, ['number'], [ctx]);
Module.ccall('meepow_dataset_free', null, ['number'], [ds]);
[ek, sh, tp, outHash].forEach((p) => Module._free(p));

console.log(JSON.stringify({
  target: 'wasm-node-portable', param: paramName, construction: construction ? 'B' : 'A', hashes,
  dataset_init_ms: +datasetMs.toFixed(2), ctx_create_ms: +ctxMs.toFixed(4),
  per_hash_mean_ms: +mean.toFixed(4), p50_ms: +p50.toFixed(4), p95_ms: +p95.toFixed(4),
  p99_ms: +p99.toFixed(4), p99_over_p50: +(p99 / p50).toFixed(3), hps: +(1000 / mean).toFixed(1),
  wasm_heap_growth_bytes_during_loop: heapAfter - heapBefore,
  node_rss_mib: +(process.memoryUsage().rss / 1048576).toFixed(1),
}, null, 2));
