// v2 native/Wasm regression: verify Wasm reproduces the native v2 known-answer hashes byte-for-byte,
// and measure the v2 reference per-hash (for the native:browser ratio).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import createModule from './meepow.mjs';
const __dirname = dirname(fileURLToPath(import.meta.url));
const M = await createModule();

const NP = 4;
const native = readFileSync(resolve(__dirname, '../vectors/vectors_v2.txt'), 'utf8')
  .trim().split('\n').map((l) => l.split(' '));  // [v2, nparents, nonce, hex]
const count = native.length;

const ptr = M._malloc(count * 32);
M.ccall('meep_v2_hashes', null, ['number', 'number', 'number'], [NP, count, ptr]);
let fail = 0;
for (const [, , nonce, hex] of native) {
  const b = M.HEAPU8.slice(ptr + (+nonce) * 32, ptr + (+nonce) * 32 + 32);
  const got = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  if (got !== hex) { fail++; if (fail <= 3) console.error(`MISMATCH nonce ${nonce}: wasm ${got} != native ${hex}`); }
}
M._free(ptr);
console.log(`v2 native/Wasm equivalence (nparents=${NP}): ${count - fail}/${count} identical`);

const p50 = M.ccall('meep_v2_bench', 'number', ['number', 'number'], [NP, 200]);
console.log(`v2 Wasm reference per-hash p50 = ${p50.toFixed(3)} ms  (${(1000 / p50).toFixed(1)} H/s)`);
process.exit(fail === 0 ? 0 : 1);
