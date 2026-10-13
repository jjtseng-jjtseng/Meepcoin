// Bounded nonce search shared by the browser Web Worker and the Node end-to-end test.
//
// The hash function itself is injected, so this module contains no algorithm and no I/O: both
// callers pass a `hashOne` backed by the SAME MeepHash-W v2 Wasm build
// (meepow/wasm/meepow.mjs, entry points meep_v2_setup / meep_v2_run1). That file is a gitignored
// BUILD OUTPUT of the committed frozen source, pinned by SHA-256 in pool/dev/wasm_identity.json.
//
// The loop batches and yields. docs/BROWSER_V2.md records why: a synchronous hash loop in a
// worker cannot process a queued `stop` message at all, so batch-and-yield is what makes Stop
// responsive. Page-side Worker.terminate() remains the final guarantee.

import { meetsTargetLE } from './target.js';

const defaultYield = () => new Promise((resolve) => setTimeout(resolve, 0));

/**
 * Scan [nonceStart, nonceStart + nonceRange) and report every nonce whose hash meets `target`.
 *
 * @param {object} o
 * @param {(nonce:number)=>Uint8Array} o.hashOne  32-byte little-endian hash for one nonce.
 * @param {Uint8Array} o.target                   32-byte little-endian target.
 * @param {number} o.nonceStart
 * @param {number} o.nonceRange
 * @param {number} [o.batch]                      hashes between yields (stop responsiveness).
 * @param {()=>boolean} [o.shouldStop]            checked between hashes and between batches.
 * @param {(p:{hashes:number,lastNonce:number})=>void} [o.onProgress] called once per batch.
 * @param {(f:{nonce:number,hash:Uint8Array})=>void} [o.onFound]
 * @param {()=>Promise<void>} [o.yieldFn]
 * @returns {Promise<{hashes:number, found:number, stopped:boolean, exhausted:boolean}>}
 */
export async function searchNonces({
  hashOne,
  target,
  nonceStart,
  nonceRange,
  batch = 4,
  shouldStop = () => false,
  onProgress = () => {},
  onFound = () => {},
  yieldFn = defaultYield,
}) {
  if (!Number.isInteger(nonceStart) || nonceStart < 0 || nonceStart > 0xffffffff) {
    throw new RangeError('nonceStart must be a uint32');
  }
  if (!Number.isInteger(nonceRange) || nonceRange <= 0 || nonceRange > 0x100000000 - nonceStart) {
    throw new RangeError('nonceRange must fit without wrapping the uint32 nonce space');
  }
  if (!Number.isInteger(batch) || batch <= 0) throw new RangeError('batch must be a positive integer');

  let hashes = 0;
  let found = 0;
  let stopped = false;

  for (let i = 0; i < nonceRange; i++) {
    if (shouldStop()) { stopped = true; break; }
    const nonce = (nonceStart + i) >>> 0;
    const hash = hashOne(nonce);
    hashes++;
    if (meetsTargetLE(hash, target)) {
      found++;
      onFound({ nonce, hash });
    }
    if (hashes % batch === 0) {
      onProgress({ hashes, lastNonce: nonce });
      await yieldFn();
    }
  }

  onProgress({ hashes, lastNonce: (nonceStart + Math.max(0, hashes - 1)) >>> 0 });
  return { hashes, found, stopped, exhausted: !stopped };
}
