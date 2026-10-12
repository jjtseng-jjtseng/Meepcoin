// Verify Wasm reproduces the native v1 known-answer hashes byte-for-byte (native/Wasm equivalence).
// Reads the native dump (finalist + fast profiles) and compares to Wasm output.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import createModule from './meepow.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const M = await createModule();

function wasmHashes(profile, count) {
  const ptr = M._malloc(count * 32);
  M.ccall('meep_v1_hashes', null, ['number', 'number', 'number'], [profile, count, ptr]);
  const out = [];
  for (let n = 0; n < count; n++) {
    const b = M.HEAPU8.slice(ptr + n * 32, ptr + n * 32 + 32);
    out.push([...b].map((x) => x.toString(16).padStart(2, '0')).join(''));
  }
  M._free(ptr);
  return out;
}

const native = readFileSync(resolve(__dirname, '../vectors/vectors_v1.txt'), 'utf8')
  .trim().split('\n').map((l) => l.split(' '));  // [label, nonce, hex]

const finN = native.filter((r) => r[0] === 'finalist').length;
const fastN = native.filter((r) => r[0] === 'fast').length;
const wasmFin = wasmHashes(0, finN);
const wasmFast = wasmHashes(1, fastN);

let fail = 0, total = 0;
for (const [label, nonce, hex] of native) {
  total++;
  const got = label === 'finalist' ? wasmFin[+nonce] : wasmFast[+nonce];
  if (got !== hex) { fail++; if (fail <= 3) console.error(`MISMATCH ${label} ${nonce}: wasm ${got} != native ${hex}`); }
}
console.log(`v1 native/Wasm equivalence: ${total - fail}/${total} identical`);
process.exit(fail === 0 ? 0 : 1);
