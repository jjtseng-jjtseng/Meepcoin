import { parentPort } from 'node:worker_threads';
import { performance } from 'node:perf_hooks';
import createModule from '../vendor/meephash/meepow.mjs';
import { createV2HasherForContext } from '../vendor/meephash/wasm_hasher.js';
import { hexToBytes, bytesToHex, meetsTargetLE } from '../vendor/meephash/target.js';
import { validJob } from './protocol.mjs';

let hasher, currentRound, generation = 0;
let duty = 50;
async function prepare(job) {
  if (!validJob(job)) throw new Error('Invalid work assignment.');
  if (currentRound !== job.round) {
    hasher?.free();
    hasher = await createV2HasherForContext(createModule, { epochKey: hexToBytes(job.seed), seedHash: hexToBytes(job.seed), height: job.height, template: hexToBytes(job.template) });
    currentRound = job.round;
  }
  return hasher;
}

parentPort.on('message', async message => {
  try {
    if (message.type === 'duty') { duty = message.duty; return; }
    if (message.type === 'verify') {
      const h = await prepare(message.job);
      const proof = bytesToHex(h.hashOne(message.nonce));
      parentPort.postMessage({ type: 'verified', requestId: message.requestId, proof, valid: meetsTargetLE(hexToBytes(proof), hexToBytes(message.job.target)) });
      return;
    }
    if (message.type !== 'mine') return;
    const mineGeneration = ++generation;
    duty = message.duty;
    const job = message.job;
    parentPort.postMessage({ type: 'status', status: 'Preparing MeepHash-W dataset' });
    const h = await prepare(job);
    if (mineGeneration !== generation) return;
    const target = hexToBytes(job.target);
    let nonce = job.start, intervalHashes = 0, totalHashes = 0;
    let intervalStart = performance.now();
    const step = () => {
      if (mineGeneration !== generation) return;
      try {
        const started = performance.now();
        while (nonce <= job.end && performance.now() - started < 45) {
          const n = nonce++;
          const proof = h.hashOne(n);
          intervalHashes++; totalHashes++;
          if (meetsTargetLE(proof, target)) {
            parentPort.postMessage({ type: 'stats', hashes: intervalHashes, elapsed: performance.now() - intervalStart });
            parentPort.postMessage({ type: 'proof', round: job.round, nonce: n, proof: bytesToHex(proof), totalHashes });
            return;
          }
        }
        const now = performance.now();
        if (now - intervalStart >= 750) {
          parentPort.postMessage({ type: 'stats', hashes: intervalHashes, elapsed: now - intervalStart });
          intervalHashes = 0; intervalStart = now;
        }
        if (nonce > job.end) { parentPort.postMessage({ type: 'error', error: 'Nonce partition exhausted. Stop and restart the room.' }); return; }
        const work = performance.now() - started;
        setTimeout(step, Math.max(0, work * (100 - duty) / duty));
      } catch (e) { parentPort.postMessage({ type: 'error', error: e.message }); }
    };
    step();
  } catch (e) { parentPort.postMessage({ type: 'error', requestId: message.requestId, error: e.message }); }
});
