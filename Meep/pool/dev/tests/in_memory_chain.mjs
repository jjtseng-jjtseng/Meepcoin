// TEST SUPPORT ONLY (not a test file): two in-memory daemons with a real little chain behind the real
// daemon_rpc adapters, for the two-block sequence tests.
//
// Daemon A hands out a template for the block on its current tip (the committed devnet block's blobs,
// with the previous-block id patched to that tip), computes a height-specific proof-of-work in calc_pow,
// accepts a submitted block only if it builds on the tip, and answers header readbacks from its chain.
// Daemon B receives each of A's blocks only after a few of its own reads -- the stand-in for P2P -- and
// its transport is read-only: a write method reaching it is recorded and refused.
//
// Every step can be paused (`gate`) or scripted (`options`), so a test can stop, fault or tamper at
// each boundary of the rotation. No socket, process, WSL, Docker, daemon or helper exists.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { buildRealDaemonMode } from '../real_daemon_mode.mjs';
import { PREV_ID_BYTES, blobToHex, findNonceOffset, hexToBlob } from '../block_blob.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
export const ROW = JSON.parse(readFileSync(resolve(REPO, 'meepow/vectors/block_vectors_v16_devnet.json'), 'utf8')).vectors[1];
export const GENESIS = (() => {
  const b = hexToBlob(ROW.full_block_blob);
  const { offset } = findNonceOffset(b);
  return blobToHex(b.subarray(offset - PREV_ID_BYTES, offset));
})();
const GENESIS_TIMESTAMP = 1785283200;

/** A proof-of-work hash below the difficulty-500 target, different at every height. */
export function powFor(height) {
  const h = Number(height);
  return `${h.toString(16).padStart(2, '0').repeat(30)}0000`;
}

export const IMAGE_ID = `sha256:${'d'.repeat(64)}`;
const BASE = Object.freeze({
  wslDistro: 'Ubuntu',
  image: 'meepcoin-build:roundg-build3-20260914t221939z',
  artifactDir: '/home/tseng/meepcoin-roundg-build3-20260914T221939Z/out',
  uid: 1000,
  gid: 1000,
  profile: 'private-exclusive-peer-test',
  fixedDifficulty: 500,
  expectedImageId: IMAGE_ID,
});
export const CHAIN_A = Object.freeze({ ...BASE, rpcPort: 28781, p2pPort: 28780, exclusivePeerP2pPort: 28790, runDir: '/home/tseng/meepcoin-private-run-cccccccccccccccc' });
export const CHAIN_B = Object.freeze({ ...BASE, rpcPort: 28791, p2pPort: 28790, exclusivePeerP2pPort: 28780, runDir: '/home/tseng/meepcoin-private-run-dddddddddddddddd' });

function patchPrev(blobHex, prevHex) {
  const b = hexToBlob(blobHex);
  const { offset } = findNonceOffset(b);
  b.set(hexToBlob(prevHex), offset - PREV_ID_BYTES);
  return blobToHex(b);
}
function nonceOf(blobHex) {
  const b = hexToBlob(blobHex);
  const off = findNonceOffset(b).offset;
  return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
}
function prevOf(blobHex) {
  const b = hexToBlob(blobHex);
  const { offset } = findNonceOffset(b);
  return blobToHex(b.subarray(offset - PREV_ID_BYTES, offset));
}

/**
 * @param {object} [o]
 * @param {Record<number,'ok'|'refuse'|'lost'|'lost_unresolvable'>} [o.submit]  per height
 * @param {Record<number,boolean>} [o.neverPropagate]  per height
 * @param {number} [o.propagateAfterBReads]
 * @param {(method:string, n:number, side:'A'|'B', chain:{blocksA,blocksB}) => Promise<void>|void} [o.gate]
 *        called before each request is answered
 * @param {(state) => void} [o.beforeTemplate]  called with the chain before each get_block_template is answered
 */
export function inMemoryChain({ submit = {}, neverPropagate = {}, propagateAfterBReads = 1, gate = () => {}, beforeTemplate = () => {}, difficultyForHeight = () => 500 } = {}) {
  const blocksA = [{ hash: GENESIS, height: 0, nonce: 0, powHash: '0'.repeat(64), prevHash: '0'.repeat(64) }];
  const blocksB = [blocksA[0]];
  const seenAtBRead = new Map();      // height -> B read count when A first had it
  const log = { A: [], B: [], submitBodies: [], calcPow: [], templates: [], bWrites: [] };
  let bReads = 0;
  const counts = { A: {}, B: {} };
  const ok = (id, result) => JSON.stringify({ jsonrpc: '2.0', id, result });
  const err = (id, code, message) => JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } });
  const header = (b) => ({
    hash: b.hash, height: b.height, nonce: b.nonce, orphan_status: false, pow_hash: b.powHash, prev_hash: b.prevHash,
    major_version: 16, minor_version: 16, timestamp: b.height === 0 ? GENESIS_TIMESTAMP : 0,
    difficulty: 500, wide_difficulty: '0x1f4',
  });

  function syncB() {
    for (let h = blocksB.length; h < blocksA.length; h++) {
      if (neverPropagate[h]) return;
      if (!seenAtBRead.has(h)) seenAtBRead.set(h, bReads);
      if (bReads - seenAtBRead.get(h) < propagateAfterBReads) return;
      blocksB.push(blocksA[h]);
    }
  }

  const aTransport = async (req) => {
    const body = JSON.parse(req.body);
    counts.A[body.method] = (counts.A[body.method] ?? 0) + 1;
    log.A.push(body.method);
    await gate(body.method, counts.A[body.method], 'A', { blocksA, blocksB });
    req.handoff();
    const tip = blocksA.at(-1);
    switch (body.method) {
      case 'get_info':
        return ok(body.id, { status: 'OK', height: blocksA.length, top_block_hash: tip.hash, synchronized: true, outgoing_connections_count: 1, incoming_connections_count: 1, nettype: 'testnet' });
      case 'get_last_block_header':
        return ok(body.id, { status: 'OK', block_header: header(blocksA.at(-1)) });
      case 'get_block_header_by_height': {
        const b = blocksA[Number(body.params.height)];
        return b ? ok(body.id, { status: 'OK', block_header: header(b) }) : err(body.id, -2, 'too big height');
      }
      case 'get_block_template': {
        beforeTemplate({ blocksA, blocksB });
        const t = blocksA.at(-1);
        const difficulty = difficultyForHeight(blocksA.length);
        const tpl = {
          status: 'OK', height: blocksA.length, wide_difficulty: `0x${difficulty.toString(16)}`, difficulty,
          seed_hash: ROW.epoch_key, seed_height: 0, prev_hash: t.hash,
          blockhashing_blob: patchPrev(ROW.block_hashing_blob, t.hash),
          blocktemplate_blob: patchPrev(ROW.full_block_blob, t.hash),
          reserved_offset: 0,
          expected_reward: 1,
        };
        log.templates.push({ height: tpl.height, prev: t.hash });
        return ok(body.id, tpl);
      }
      case 'calc_pow':
        log.calcPow.push(body.params);
        return ok(body.id, powFor(body.params.height));
      case 'submit_block': {
        const blob = body.params[0];
        log.submitBodies.push(blob);
        const height = blocksA.length;
        const mode = submit[height] ?? 'ok';
        if (mode === 'refuse') return err(body.id, -7, 'Block not accepted');
        if (prevOf(blob) !== blocksA.at(-1).hash) return err(body.id, -7, 'Block not accepted');
        const hash = createHash('sha256').update(blob).digest('hex');
        if (mode !== 'lost_unresolvable') {
          blocksA.push({ hash, height, nonce: nonceOf(blob), powHash: powFor(height), prevHash: blocksA.at(-1).hash });
        }
        if (mode === 'lost' || mode === 'lost_unresolvable') throw new Error('reset after handoff');
        return ok(body.id, { status: 'OK', block_id: hash });
      }
      default:
        throw new Error(`daemon A was asked for ${body.method}`);
    }
  };

  const bTransport = async (req) => {
    const body = JSON.parse(req.body);
    counts.B[body.method] = (counts.B[body.method] ?? 0) + 1;
    log.B.push(body.method);
    if (['submit_block', 'calc_pow', 'get_block_template'].includes(body.method)) log.bWrites.push(body.method);
    await gate(body.method, counts.B[body.method], 'B', { blocksA, blocksB });
    req.handoff();
    bReads += 1;
    syncB();
    switch (body.method) {
      case 'get_info':
        return ok(body.id, { status: 'OK', height: blocksB.length, top_block_hash: blocksB.at(-1).hash, synchronized: true, outgoing_connections_count: 1, incoming_connections_count: 1, nettype: 'testnet' });
      case 'get_last_block_header':
        return ok(body.id, { status: 'OK', block_header: header(blocksB.at(-1)) });
      case 'get_block_header_by_height': {
        const b = blocksB[Number(body.params.height)];
        return b ? ok(body.id, { status: 'OK', block_header: header(b) }) : err(body.id, -2, 'too big height');
      }
      default:
        throw new Error(`daemon B was asked for ${body.method}`);
    }
  };

  // ONE shared socket table: an exact reciprocal established A->B link plus an RPC client row on each.
  const socketTable = () => [
    `ESTAB 0 0 127.0.0.1:41000 127.0.0.1:${CHAIN_B.p2pPort} users:(("meepcoind",pid=1001,fd=9))`,
    `ESTAB 0 0 127.0.0.1:${CHAIN_A.rpcPort} 127.0.0.1:50000 users:(("meepcoind",pid=1001,fd=10))`,
    `ESTAB 0 0 127.0.0.1:${CHAIN_B.p2pPort} 127.0.0.1:41000 users:(("meepcoind",pid=1002,fd=9))`,
  ].join('\n');
  const resource = (name, cfg) => ({
    closed: false, name, imageId: IMAGE_ID, linuxPid: name === 'A' ? 1001 : 1002,
    containerName: `meepcoin-private-${name === 'A' ? 'e' : 'f'}${'0'.repeat(15)}`, config: cfg,
    beginClose() {}, async close() { this.closed = true; }, async forceClose() { this.closed = true; },
    async observeSocketTable() { return socketTable(); },
  });
  return { aTransport, bTransport, resource, blocksA, blocksB, log, counts };
}

/**
 * A dual-verifier-shaped object over ONE server-owned context: both paths return that height's
 * proof-of-work. It records its life so a test can prove the previous one was released before the next.
 */
export function contextualVerifier(context, journal, {
  closeConfirms = true,
  closeGate = null,
  closeError = null,
  forceCloseConfirms = closeConfirms,
  forceCloseError = null,
  forceCloseGate = null,
  wasmGate = null,
  shutdownGraceful = null,
  shutdownReason = null,
  shutdownOutcomeErrorAt = [],
} = {}) {
  const index = journal.created.length + 1;
  const v = {
    index,
    context,
    helperLinuxPid: 7000 + index,
    helperSourceId: 'f'.repeat(64),
    helperDistro: 'Ubuntu',
    datasetBytes: 33_554_432,
    scratchBytes: 8_388_608,
    closed: false,
    counters: { wasmShareHashes: 0, nativeShareHashes: 0 },
    forceCloseCalls: 0,
    shutdownOutcomeReads: 0,
    wasmHeapBytes: () => 48_562_176,
    nativeAlgorithmBytes: () => 41_943_040,
    async hashWasm() {
      if (v.closed || v.closing) throw new Error('hashWasm on a released verifier');
      if (wasmGate) await wasmGate();
      journal.events.push(`wasm ${index}`);
      v.counters.wasmShareHashes += 1;
      return hexToBlob(powFor(context.height));
    },
    async hashNative() {
      if (v.closed || v.closing) throw new Error('hashNative on a released verifier');
      journal.events.push(`native ${index}`);
      v.counters.nativeShareHashes += 1;
      return hexToBlob(powFor(context.height));
    },
    beginClose() { v.closing = true; },
    async close() {
      journal.events.push(`close ${index}`);
      if (closeGate) await closeGate();
      if (closeConfirms) { v.closed = true; journal.events.push(`closed ${index}`); }
      if (closeError !== null) throw new Error(closeError);
    },
    async forceClose() {
      journal.events.push(`force ${index}`);
      v.forceCloseCalls += 1;
      if (forceCloseGate) await forceCloseGate(v.forceCloseCalls);
      const confirms = Array.isArray(forceCloseConfirms)
        ? forceCloseConfirms[v.forceCloseCalls - 1] === true
        : forceCloseConfirms === true;
      const error = Array.isArray(forceCloseError)
        ? (forceCloseError[v.forceCloseCalls - 1] ?? null)
        : forceCloseError;
      if (confirms) { v.closed = true; journal.events.push(`closed ${index}`); }
      if (error !== null) throw new Error(error);
    },
    get shutdownOutcome() {
      v.shutdownOutcomeReads += 1;
      if (shutdownOutcomeErrorAt.includes(v.shutdownOutcomeReads)) {
        throw new Error(`scripted shutdownOutcome read failure ${v.shutdownOutcomeReads}`);
      }
      const graceful = v.closed && (shutdownGraceful ?? true);
      return {
        physicalReleaseConfirmed: v.closed,
        gracefulProtocolShutdown: graceful,
        reason: v.closed && !graceful
          ? (shutdownReason ?? 'scripted verifier protocol shutdown was not graceful')
          : null,
      };
    },
  };
  journal.created.push(v);
  journal.events.push(`created ${index} height ${context.height}`);
  return v;
}

/** THE ONLY WAY THE SEQUENCE TESTS BUILD A CONTEXT: every live seam injected. */
export async function buildScriptedChain(chainOptions = {}, {
  sequenceBlocks = 2, clock = { ms: 1_000_000 }, verifierOptions = () => ({}), makeVerifierGate = null, ownLog = [], signal = null,
  // OPT-IN share work, exactly as trusted startup configuration supplies it. Omitted by default, so
  // every existing caller of this helper builds precisely the job it always built.
  shareDifficulty = null,
  // OPT-IN same-height refresh, exactly as trusted startup configuration supplies it.
  refreshWindows = 1,
  // The one source-fixed handoff probe's trusted marker; absent for every historical fixture.
  refreshHandoffProbe = false,
  naturalDifficulty = false,
} = {}) {
  const net = inMemoryChain(chainOptions);
  const journal = { created: [], events: [], signals: [] };
  const built = await buildRealDaemonMode({
    daemon: naturalDifficulty
      ? { ...CHAIN_A, profile: 'private-exclusive-peer-natural', fixedDifficulty: undefined } : CHAIN_A,
    peer: { daemon: naturalDifficulty
      ? { ...CHAIN_B, profile: 'private-exclusive-peer-natural', fixedDifficulty: undefined } : CHAIN_B },
    ...(naturalDifficulty ? { expectedGenesisTimestamp: GENESIS_TIMESTAMP, expectedGenesisHash: GENESIS } : {}),
    sequenceBlocks,
    ...(shareDifficulty === null ? {} : { shareDifficulty }),
    ...(refreshWindows === 1 ? {} : { refreshWindows }),
    ...(refreshHandoffProbe ? { refreshHandoffProbe: true } : {}),
    signal,
    now: () => clock.ms,
    sleep: async (ms) => { clock.ms += ms; await Promise.resolve(); },
    ownResource: (label, r) => ownLog.push({ label, r }),
    startDaemon: async ({ config, isRpcReady }) => {
      await isRpcReady();
      return net.resource(config.rpcPort === CHAIN_A.rpcPort ? 'A' : 'B', config);
    },
    makeTransport: (endpoint) => (endpoint.includes(`:${CHAIN_B.rpcPort}/`) ? net.bTransport : net.aTransport),
    makeVerifier: async ({ context, signal: sig }) => {
      journal.signals.push(sig);
      const n = journal.created.length + 1;
      if (makeVerifierGate) await makeVerifierGate(n, sig);
      if (sig?.aborted) throw Object.assign(new Error('verifier startup cancelled'), { cancelled: true });
      return contextualVerifier(context, journal, verifierOptions(n));
    },
  });
  return { built, net, journal, clock, ownLog };
}
