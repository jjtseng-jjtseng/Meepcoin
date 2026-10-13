// The MeepCoin browser mining worker. ONE dedicated Web Worker, created only after an explicit
// Start click, torn down by Worker.terminate() from the page.
//
// It does exactly three things: load the MeepHash-W v2 Wasm build (a gitignored build output of
// the committed frozen source, whose SHA-256 the pool checks before serving it), hash what the
// SERVER handed out, and report results. It never opens a socket, never spawns another worker, and
// never decides whether a share is valid -- the pool recomputes every share itself.
//
// THIS FILE IS WIRING ONLY. The command dispatcher -- which mode this Worker is in, which commands
// it may accept, and whether a hash is allowed -- is lib/worker_core.js, so the rules the browser
// runs are the rules the tests drive.

import createModule from '/wasm/meepow.mjs';
import { createV2Hasher, createV2HasherForContext } from './lib/shared/wasm_hasher.js';
import { searchNonces } from './lib/shared/search.js';
import { bytesToHex, hexToBytes, nonceToHex } from './lib/shared/target.js';
import { createWorkerCore } from './lib/worker_core.js';

const core = createWorkerCore({
  createModule,
  createV2Hasher,
  createV2HasherForContext,
  searchNonces,
  hexToBytes,
  bytesToHex,
  nonceToHex,
  postMessage: (msg) => self.postMessage(msg),
  now: () => performance.now(),
});

self.onmessage = (event) => { core.handle(event.data); };
