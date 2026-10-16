// Node worker_threads twin of web-miner/worker.js, for the end-to-end test.
//
// WHAT IS SHARED WITH THE BROWSER, EXACTLY: the Wasm module (meepow/wasm/meepow.mjs), the hasher
// factory (lib/shared/wasm_hasher.js) and the search loop (lib/shared/search.js) are the same
// files the browser worker imports. So the hashing and the target comparison this file exercises
// ARE the browser's.
//
// WHAT IS NOT: this is a node:worker_threads worker, not a Web Worker, and it is driven by a Node
// WebSocket client rather than by lib/controller.js and a DOM. The real Web Worker path is
// covered by the Chrome smoke in web-miner/tools/browser_smoke.mjs, not by this file. Do not
// describe a run of this worker as a browser test.

import { parentPort, workerData } from 'node:worker_threads';
import { pathToFileURL } from 'node:url';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createV2Hasher } from '../lib/shared/wasm_hasher.js';
import { searchNonces } from '../lib/shared/search.js';
import { bytesToHex, hexToBytes, nonceToHex } from '../lib/shared/target.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WASM_MJS = resolve(__dirname, '../../meepow/wasm/meepow.mjs');

let stopRequested = false;
parentPort.on('message', (msg) => {
  if (msg && msg.cmd === 'stop') stopRequested = true;
});

const createModule = (await import(pathToFileURL(WASM_MJS).href)).default;
const hasher = await createV2Hasher(createModule);
parentPort.postMessage({ ev: 'ready', wasmHeapBytes: hasher.wasmHeapBytes(), wasmModulePath: WASM_MJS });

const job = workerData.job;
const result = await searchNonces({
  hashOne: (nonce) => hasher.hashOne(nonce),
  target: hexToBytes(job.targetHexLE),
  nonceStart: job.nonceStart,
  nonceRange: job.nonceRange,
  batch: job.batchHint ?? 4,
  shouldStop: () => stopRequested,
  onProgress: ({ hashes }) => parentPort.postMessage({ ev: 'progress', hashes }),
  onFound: ({ nonce, hash }) => parentPort.postMessage({
    ev: 'found',
    nonce,
    nonceHex: nonceToHex(nonce),
    hashHexLE: bytesToHex(hash),
  }),
});

parentPort.postMessage({ ev: 'finished', ...result, wasmHashCalls: hasher.hashCalls });
hasher.free();
