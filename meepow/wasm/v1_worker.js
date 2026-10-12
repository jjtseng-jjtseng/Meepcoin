// Dedicated Web Worker running the FROZEN v2 (v1 pipeline + v2 dataset) Wasm. Measures per-hash latency and
// checks a stop flag between hashes so stop responsiveness can be measured. No mining, no network.
import createModule from './meepow.mjs';

let M = null;
let stop = false;
let stopRecvAt = 0;

self.onmessage = async (e) => {
  const msg = e.data;
  if (msg.cmd === 'init') {
    M = await createModule();
    const rc = M.ccall('meep_v2_setup', 'number', [], []);   // FROZEN v2
    self.postMessage({ ev: 'ready', rc, heap: M.HEAPU8.length });
  } else if (msg.cmd === 'run') {
    stop = false;
    const out = M._malloc(32);
    const lat = [];
    let n = 0;
    const batch = msg.batch || 4;  // yield to the event loop every `batch` hashes so a queued
                                   // 'stop' message can be delivered (a synchronous loop cannot be
                                   // stopped mid-flight — the key browser stop-responsiveness fact).
    const t0 = performance.now();
    while (n < msg.count && !stop) {
      const a = performance.now();
      M.ccall('meep_v2_run1', null, ['number', 'number'], [n, out]);
      lat.push(performance.now() - a);
      n++;
      if (n % batch === 0) await new Promise((r) => setTimeout(r, 0));
    }
    const idleAt = performance.now();
    M._free(out);
    const mem = { wasmHeapBytes: M.HEAPU8.length };
    if (performance.memory) mem.usedJSHeapBytes = performance.memory.usedJSHeapSize;
    self.postMessage({
      ev: 'done', latencies: lat, hashes: n, wallMs: idleAt - t0,
      stopResponsivenessMs: stop ? idleAt - stopRecvAt : null, mem,
    });
  } else if (msg.cmd === 'stop') {
    stop = true;
    stopRecvAt = performance.now();
  }
};
