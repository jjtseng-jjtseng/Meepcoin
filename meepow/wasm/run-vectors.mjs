// Node.js Wasm known-answer-test runner. Loads the same committed vectors as the native KAT
// runner and requires byte-for-byte identical output (spec §11). Also independently recomputes
// the difficulty target with JS BigInt as a cross-check of the C 256-bit math.
//
// Usage: node run-vectors.mjs [vectors_fast.json vectors_dev.json ...]
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import createModule from './meepow.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

function hexToBytes(h) {
  if (h.length % 2 !== 0) throw new Error('odd hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(h.substr(2 * i, 2), 16);
    if (Number.isNaN(b)) throw new Error('bad hex');
    out[i] = b;
  }
  return out;
}
function bytesToHex(u8) {
  return [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function hexBeToBigInt(h) {
  return BigInt('0x' + h);
}
// Little-endian 256-bit target from difficulty, as 32 bytes (spec §10), computed with BigInt.
function difficultyToTargetLE(diff) {
  if (diff === 0n) throw new Error('difficulty 0 invalid');
  const t = ((1n << 256n) - 1n) / diff;
  const out = new Uint8Array(32);
  let v = t;
  for (let i = 0; i < 32; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
function leBytesToBigInt(u8) {
  let v = 0n;
  for (let i = u8.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(u8[i]);
  return v;
}

const Module = await createModule();
const HEAP = () => Module.HEAPU8;

function withBuf(bytes, fn) {
  const ptr = Module._malloc(Math.max(1, bytes.length));
  if (bytes.length) HEAP().set(bytes, ptr);
  try { return fn(ptr, bytes.length); } finally { Module._free(ptr); }
}

function runHash(param, constr, epochKey, seedHash, height, tmpl, nonce) {
  const outHash = Module._malloc(32), outC1 = Module._malloc(32), outCh = Module._malloc(32);
  const ek = Module._malloc(32), sh = Module._malloc(32);
  const tp = Module._malloc(Math.max(1, tmpl.length));
  HEAP().set(epochKey, ek);
  HEAP().set(seedHash, sh);
  if (tmpl.length) HEAP().set(tmpl, tp);
  const rc = Module.ccall(
    'meep_run_hash', 'number',
    ['number','number','number','number','bigint','number','number','number','number','number','number'],
    [param, constr, ek, sh, BigInt(height), tp, tmpl.length, nonce >>> 0, outHash, outC1, outCh]);
  const hash = HEAP().slice(outHash, outHash + 32);
  const c1 = HEAP().slice(outC1, outC1 + 32);
  const ch = HEAP().slice(outCh, outCh + 32);
  [outHash, outC1, outCh, ek, sh, tp].forEach((p) => Module._free(p));
  return { rc, hash, c1, ch };
}

function meetsTarget(hashLE, targetLE) {
  return withBuf(hashLE, (hp) => withBuf(targetLE, (tp) =>
    Module.ccall('meepow_hash_meets_target', 'number', ['number', 'number'], [hp, tp])));
}

let files = process.argv.slice(2);
if (files.length === 0) {
  files = ['vectors_fast.json', 'vectors_dev.json'].map((f) => resolve(__dirname, '../vectors', f));
}

let total = 0, failed = 0;
for (const file of files) {
  const vectors = JSON.parse(readFileSync(file, 'utf8'));
  let localFail = 0;
  for (const v of vectors) {
    total++;
    const param = v.paramSetId;
    const constr = v.datasetConstruction === 'A' ? 0 : 1;
    const epochKey = hexToBytes(v.epochKey);
    const seedHash = hexToBytes(v.seedBlockHash);
    const height = hexBeToBigInt(v.blockHeight);
    const tmpl = hexToBytes(v.templateBlob);
    const nonce = Number(hexBeToBigInt(v.nonce));
    const difficulty = hexBeToBigInt(v.difficulty);

    const { rc, hash, c1, ch } = runHash(param, constr, epochKey, seedHash, height, tmpl, nonce);
    const targetJS = difficultyToTargetLE(difficulty);
    const passesJS = leBytesToBigInt(hash) <= leBytesToBigInt(targetJS);
    const passesWasm = meetsTarget(hash, hexToBytes(v.target)) !== 0;

    const ok =
      rc === 0 &&
      bytesToHex(hash) === v.finalHash &&
      bytesToHex(c1) === v.checkpointRound1 &&
      bytesToHex(ch) === v.checkpointRoundHalf &&
      bytesToHex(targetJS) === v.target &&           // JS BigInt target == committed C target
      passesJS === v.passes &&
      passesWasm === v.passes;
    if (!ok) {
      localFail++; failed++;
      if (localFail <= 3) {
        console.error(`  vector ${total} MISMATCH`);
        console.error(`    got hash ${bytesToHex(hash)}`);
        console.error(`    exp hash ${v.finalHash}`);
        if (bytesToHex(targetJS) !== v.target)
          console.error(`    target JS ${bytesToHex(targetJS)} != ${v.target}`);
      }
    }
  }
  console.error(`${file}: ${vectors.length - localFail}/${vectors.length} passed`);
}
console.error(`TOTAL: ${total - failed}/${total} passed`);
process.exit(failed === 0 ? 0 : 1);
