import { Worker } from 'node:worker_threads';
import { EventEmitter } from 'node:events';
import { readFile } from 'node:fs/promises';
import { HASH_IDENTITY, sha256, randomId } from './protocol.mjs';

export async function checkHashIdentity() {
  for (const [file, expected] of Object.entries(HASH_IDENTITY)) {
    if (sha256(await readFile(new URL(`../vendor/meephash/${file}`, import.meta.url))) !== expected) throw new Error(`Hasher integrity check failed: ${file}. Reinstall the app.`);
  }
}

export class Miner extends EventEmitter {
  constructor() { super(); this.worker = null; this.duty = 50; this.hashes = 0; this.rate = 0; this.status = 'Stopped'; this.running = false; this.samples = []; this.measurementStarted = 0; }
  sampleRate() {
    if (!this.running || !this.measurementStarted) return this.rate = 0;
    const now = Date.now(), from = Math.max(this.measurementStarted, now - 10_000);
    this.samples = this.samples.filter(s => s.at >= from);
    this.rate = this.samples.reduce((sum, s) => sum + s.hashes, 0) * 1000 / Math.max(100, now - from);
    return this.rate;
  }
  mine(job) {
    if (!this.running) return;
    if (!this.measurementStarted) this.measurementStarted = Date.now();
    this.retire();
    const worker = this.worker = new Worker(new URL('./hash-worker.mjs', import.meta.url));
    this.status = 'Preparing MeepHash-W dataset';
    worker.on('message', m => {
      if (worker !== this.worker) return;
      if (m.type === 'stats') { this.hashes += m.hashes; this.samples.push({ at: Date.now(), hashes: m.hashes }); this.sampleRate(); this.status = 'Mining'; this.emit('stats'); }
      if (m.type === 'status') this.status = m.status;
      if (m.type === 'proof') { this.status = 'Proof submitted'; this.emit('proof', m); }
      if (m.type === 'error') { this.stop(); this.emit('failure', m.error); }
    });
    worker.on('error', e => { if (worker === this.worker) { this.stop(); this.emit('failure', e.message); } });
    worker.postMessage({ type: 'mine', job, duty: this.duty });
  }
  retire() { const w = this.worker; this.worker = null; if (w) { const done = w.terminate(); this.retiring = Promise.all([this.retiring, done]); } }
  stop() { this.running = false; this.rate = 0; this.samples = []; this.measurementStarted = 0; this.status = 'Stopped'; this.retire(); }
  setDuty(duty) { if (![25, 50, 75, 100].includes(duty)) throw new Error('Invalid workload limit.'); this.duty = duty; this.worker?.postMessage({ type: 'duty', duty }); }
  async close() { this.stop(); await this.retiring; }
}

export class Verifier {
  constructor() { this.worker = null; this.pending = null; }
  async verify(job, nonce) {
    if (this.pending) throw new Error('Verifier busy.');
    const w = this.worker ??= new Worker(new URL('./hash-worker.mjs', import.meta.url));
    const requestId = randomId();
    return new Promise((resolve, reject) => {
      const done = (error, result) => {
        clearTimeout(timer); w.off('message', receive); w.off('error', fail); w.off('exit', exit);
        this.pending = null; error ? reject(error) : resolve(result);
      };
      const receive = m => { if (m.requestId === requestId) done(m.type === 'error' ? new Error(m.error) : null, m); };
      const fail = error => done(error);
      const exit = () => done(new Error('Verifier closed.'));
      const timer = setTimeout(() => { this.worker = null; w.terminate(); done(new Error('Proof verification timed out.')); }, 30_000);
      this.pending = { reject: () => done(new Error('Room closed.')) };
      w.on('message', receive); w.once('error', fail); w.once('exit', exit);
      w.postMessage({ type: 'verify', requestId, job, nonce });
    });
  }
  async close() { this.pending?.reject(); const w = this.worker; this.worker = null; if (w) await w.terminate(); }
}
