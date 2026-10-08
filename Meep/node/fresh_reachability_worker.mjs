// One private miner thread. The parent owns lifetime/evidence and never gives this worker
// a wallet, key, non-loopback endpoint, or a second attempt identity.

import { parentPort, workerData } from 'node:worker_threads';
import { createDaemonRpc } from '../pool/dev/daemon_rpc.mjs';
import { createLoopbackTransport } from '../pool/dev/loopback_transport.mjs';
import { REAL_RPC_LIMITS } from '../pool/dev/real_daemon_mode.mjs';
import { headers, info } from './honest_launch_pilot.mjs';
import { runFreshMiner } from './fresh_reachability_miner.mjs';

if (!parentPort || !workerData) throw new Error('fresh miner must be started as an owned worker');
const abort = new AbortController();
parentPort.on('message', (message) => {
  if (message === 'STOP') abort.abort();
});
const { role, mode, port, peerPort } = workerData;
if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
  throw new Error('worker RPC port must be a numeric private port');
}
if (!Number.isSafeInteger(peerPort) || peerPort < 1024 || peerPort > 65535
  || peerPort === port) throw new Error('worker receiver port must be a distinct private port');
const endpoint = `http://127.0.0.1:${port}/json_rpc`;
const rpc = createDaemonRpc({ transport: createLoopbackTransport({ endpoint }).transport,
  endpoint, limits: REAL_RPC_LIMITS });
const onEvent = (event) => parentPort.postMessage({ kind: 'EVENT', event });
const readReceiver = async () => {
  for (let attempt = 0; attempt < 3; attempt++) {
    const before = await info(peerPort);
    const chain = await headers(peerPort, before.height - 1);
    const after = await info(peerPort);
    if (before.tip === after.tip && before.height === after.height
      && chain.at(-1)?.hash === before.tip) {
      return { height: before.height, tip: before.tip, predecessorWindow: chain.slice(-60) };
    }
  }
  throw new Error('receiver tip changed during all three snapshot attempts');
};
try {
  const moduleFactory = (await import('../meepow/wasm/meepow.mjs')).default;
  const summary = await runFreshMiner({ role, mode, rpc, moduleFactory, signal: abort.signal,
    onEvent, readReceiver });
  parentPort.postMessage({ kind: 'DONE', summary });
} catch (error) {
  parentPort.postMessage({ kind: 'ERROR', code: error?.code ?? error?.reason ?? 'worker_error',
    message: String(error?.message ?? error).slice(0, 300) });
} finally {
  parentPort.close();
}
