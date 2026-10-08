// The REAL-LOCAL-DAEMON connected path, end to end on the server side, with every live dependency
// injected: an in-memory daemon behind the real daemon_rpc adapter, a scripted daemon resource, and a
// scripted verifier. The session, block_run, template binding, one-attempt reservation and profile
// are the real ones.
//
// NO WSL, DOCKER, DAEMON, HELPER, BROWSER, LISTENER OR SOCKET is started by this file. A guard below
// fails if any test could reach the real daemon, transport or verifier builders.

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  REAL_COINBASE_ADDRESS,
  auditedTransport,
  buildRealDaemonMode,
  createServerOwnedPersonalizedWorkIssuer,
} from '../real_daemon_mode.mjs';
import {
  REAL_DAEMON_PROFILE, REAL_P2P_PROFILE, REAL_P2P_NATURAL_PROFILE, SERVER_SEARCH_GRACE_MS, SIM_ATTEMPT_STATES, createSimulationContext,
  createSimulationSession,
} from '../sim_session.mjs';
import { startDevPool } from '../server.mjs';
import { PREV_ID_BYTES, blobToHex, findNonceOffset, hexToBlob, patchNonce } from '../block_blob.mjs';
import { fullBlockBlobOf } from '../real_template.mjs';
import {
  REAL_DAEMON_MODE, REAL_SEARCH_LIMITS, parseClientMessage,
} from '../../../web-miner/lib/shared/protocol.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, '../../..');
// TEST DATA ONLY: the in-memory daemon below hands out a structurally valid committed block as its
// "template". The live mode never reads this file.
const ROW = JSON.parse(readFileSync(resolve(REPO, 'meepow/vectors/block_vectors_v16_devnet.json'), 'utf8')).vectors[1];
const PREV = (() => {
  const b = hexToBlob(ROW.full_block_blob);
  const { offset } = findNonceOffset(b);
  return blobToHex(b.subarray(offset - PREV_ID_BYTES, offset));
})();
const POW = 'ab'.repeat(32);
const BLOCK_ID = 'c'.repeat(64);
const DAEMON_CONFIG = Object.freeze({
  wslDistro: 'Ubuntu',
  image: 'meepcoin-build:roundg-build3-20260914t221939z',
  artifactDir: '/home/tseng/meepcoin-roundg-build3-20260914T221939Z/out',
  runDir: '/home/tseng/meepcoin-private-run-abcdef0123456789',
  rpcPort: 28081,
  p2pPort: 28080,
  uid: 1000,
  gid: 1000,
});

test('personalized issuance rejects symbol options before consuming an allocation', async () => {
  let allocations = 0;
  const issuer = createServerOwnedPersonalizedWorkIssuer({
    extraNonceAllocator: {
      reserveSize: 16,
      issue() { allocations += 1; return '01'.repeat(16); },
    },
    convertFullBlock: async () => '',
    personalizeTemplate: async () => { throw new Error('must not personalize'); },
  });
  await assert.rejects(
    issuer.issue({}, { [Symbol('hidden')]: true }),
    (error) => error?.code === 'bad_config',
  );
  assert.equal(allocations, 0);
});

/**
 * An in-memory daemon speaking JSON-RPC through the adapter's transport contract. `submit` scripts
 * submit_block; `header`/`top` override the readback; `template` overrides template fields.
 */
function inMemoryDaemon({
  submit = 'ok', header = {}, top = {}, template = {}, powHex = POW, acceptAddress = null,
  orphanTopAfter = null, topForRead = null, genesisTimestamp = 1785283200,
} = {}) {
  const log = {
    methods: [], submitBodies: [], calcPow: [], templateAddresses: [], templateReserveSizes: [],
  };
  let accepted = false;
  let submittedNonce = null;
  let topReads = 0;
  const transport = async (req) => {
    const body = JSON.parse(req.body);
    log.methods.push(body.method);
    req.handoff();
    const ok = (result) => JSON.stringify({ jsonrpc: '2.0', id: body.id, result });
    switch (body.method) {
      case 'get_last_block_header': {
        topReads += 1;
        let h = accepted
          ? { hash: BLOCK_ID, height: 1, nonce: submittedNonce, orphan_status: false, prev_hash: PREV, ...top }
          : { hash: PREV, height: 0, nonce: 0,
            ...(genesisTimestamp === null ? {} : { timestamp: genesisTimestamp }),
            orphan_status: false, prev_hash: '0'.repeat(64) };
        if (typeof topForRead === 'function') h = topForRead(topReads, { ...h }) ?? h;
        if (orphanTopAfter !== null && topReads >= orphanTopAfter) h.orphan_status = true;
        return ok({ status: 'OK', block_header: h });
      }
      case 'get_block_template': {
        const requested = body.params?.wallet_address ?? null;
        const requestedReserve = body.params?.reserve_size ?? null;
        log.templateAddresses.push(requested);
        log.templateReserveSizes.push(requestedReserve);
        // THE AUTHORITATIVE CHECK, standing in for the daemon's own address parsing: a well-shaped
        // address for another network parses to a prefix this chain does not know, and the daemon
        // answers with an error rather than a template.
        if (acceptAddress !== null && requested !== acceptAddress) {
          return JSON.stringify({
            jsonrpc: '2.0', id: body.id, error: { code: -2, message: 'Failed to parse wallet address' },
          });
        }
        return ok({
          status: 'OK',
          height: 1,
          wide_difficulty: '0x1',
          difficulty: 1,
          seed_hash: ROW.epoch_key,
          seed_height: 0,
          prev_hash: PREV,
          blockhashing_blob: ROW.block_hashing_blob,
          blocktemplate_blob: ROW.full_block_blob,
          reserved_offset: requestedReserve === 0 ? 0 : (ROW.full_block_blob.length / 2) - requestedReserve,
          expected_reward: 1,
          ...template,
        });
      }
      case 'calc_pow':
        log.calcPow.push(body.params);
        return ok(powHex);
      case 'submit_block': {
        log.submitBodies.push(body.params[0]);
        if (submit === 'lost') {
          accepted = true;
          submittedNonce = Number.parseInt(body.params[0].slice(2 * findNonceOffset(hexToBlob(body.params[0])).offset, 2 * findNonceOffset(hexToBlob(body.params[0])).offset + 8).match(/../g).reverse().join(''), 16);
          throw new Error('reset after handoff');
        }
        if (submit === 'refuse') return JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: -7, message: 'Block not accepted' } });
        accepted = true;
        const b = hexToBlob(body.params[0]);
        const off = findNonceOffset(b).offset;
        submittedNonce = (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
        return ok({ status: 'OK', block_id: BLOCK_ID });
      }
      case 'get_block_header_by_height':
        return ok({
          status: 'OK',
          block_header: {
            hash: BLOCK_ID, height: 1, nonce: submittedNonce, orphan_status: false, pow_hash: POW, prev_hash: PREV, ...header,
          },
        });
      default:
        throw new Error('unexpected method');
    }
  };
  return { transport, log };
}

/** A daemon resource that owns nothing real. */
function scriptedDaemonResource(log) {
  return {
    closed: false,
    containerName: 'meepcoin-private-0000000000000000',
    linuxPid: 4321,
    shutdownOutcome: { gracefulProtocolShutdown: true, reason: null },
    beginClose() { log.push('beginClose'); },
    async close() { log.push('close'); this.closed = true; },
    async forceClose() { log.push('forceClose'); this.closed = true; },
  };
}

/** A converter owner that owns no process but has the production ownership and conversion shape. */
function scriptedConverterResource(log, {
  readyError = null, convertedHex = ROW.block_hashing_blob, beforeConvert = null,
} = {}) {
  const resource = {
    closed: false,
    shutdownOutcome: { physicalReleaseConfirmed: false, gracefulProtocolShutdown: false, reason: null },
    beginClose() { log.events.push('converterBeginClose'); },
    async close() {
      log.events.push('converterClose');
      this.closed = true;
      this.shutdownOutcome = { physicalReleaseConfirmed: true, gracefulProtocolShutdown: true, reason: null };
    },
    async forceClose() { await this.close(); },
    async convert(fullHex) {
      if (beforeConvert !== null) await beforeConvert(fullHex);
      log.converted.push(fullHex);
      return typeof convertedHex === 'function' ? convertedHex(fullHex) : convertedHex;
    },
  };
  resource.ready = readyError === null ? Promise.resolve(resource) : Promise.reject(readyError);
  resource.ready.catch(() => {});
  return resource;
}

/** A dual-verifier-shaped object that hashes nothing: both paths return `bytes`. */
function scriptedVerifier(counts, bytes = hexToBlob(POW)) {
  return {
    closed: false,
    datasetBytes: 33_554_432,
    scratchBytes: 8_388_608,
    wasmHeapBytes: () => 48_562_176,
    nativeAlgorithmBytes: () => 41_943_040,
    async hashWasm() { counts.wasm += 1; return bytes.slice(); },
    async hashNative() { counts.native += 1; return bytes.slice(); },
    beginClose() {},
    async close() { this.closed = true; },
    async forceClose() { this.closed = true; },
  };
}

/** THE ONLY WAY THIS FILE BUILDS A REAL-DAEMON CONTEXT: every live seam is injected. */
async function buildScriptedReal({
  daemon = inMemoryDaemon(), verifierBytes, clock = { ms: 1_000_000 }, walletAddress,
  personalizeTemplates = false, converterOptions = {}, extraNonces = ['01'.repeat(16)],
  signal = null, makeTemplateAuthority = undefined,
} = {}) {
  const owned = [];
  const resourceLog = [];
  const converterLog = { launches: [], converted: [], events: [] };
  const converter = scriptedConverterResource(converterLog, converterOptions);
  let extraNonceIndex = 0;
  const counts = { wasm: 0, native: 0, readyChecks: 0 };
  const built = await buildRealDaemonMode({
    daemon: DAEMON_CONFIG,
    ...(walletAddress === undefined ? {} : { walletAddress }),
    personalizeTemplates,
    signal,
    now: () => clock.ms,
    ownResource: (label, r) => owned.push({ label, r }),
    startDaemon: async ({ isRpcReady }) => { counts.readyChecks += 1; await isRpcReady(); return scriptedDaemonResource(resourceLog); },
    makeTransport: () => daemon.transport,
    makeVerifier: async () => scriptedVerifier(counts, verifierBytes),
    ...(makeTemplateAuthority === undefined ? {} : { makeTemplateAuthority }),
    launchConverter: (config) => { converterLog.launches.push(config); return converter; },
    makeExtraNonceAllocator: () => ({
      reserveSize: 16,
      issue() {
        const value = extraNonces[extraNonceIndex];
        extraNonceIndex += 1;
        if (value === undefined) throw new Error('scripted extra-nonce allocator exhausted');
        return value;
      },
    }),
  });
  const sim = createSimulationContext({ ...built, profile: REAL_DAEMON_PROFILE });
  return {
    built, sim, owned, resourceLog, counts, daemon, clock, converterLog, converter,
    templateAddresses: daemon.log.templateAddresses,
  };
}

function driver(sim, clock) {
  const sent = [];
  const timers = [];
  const session = createSimulationSession({
    sim,
    now: () => clock.ms,
    send: (o) => sent.push(o),
    setTimer: (fn, ms) => { const t = { fn, ms, cleared: false }; timers.push(t); return t; },
    clearTimer: (t) => { t.cleared = true; },
  });
  const say = (obj) => {
    const text = JSON.stringify(obj);
    return session.handleRaw(Buffer.byteLength(text), text);
  };
  const last = (type) => [...sent].reverse().find((m) => m.type === type);
  const all = (type) => sent.filter((m) => m.type === type);
  return { session, sent, timers, say, last, all };
}

const START_ID = '0123456789abcdef0123456789abcdef';

async function startedRun(opts = {}) {
  const ctx = await buildScriptedReal(opts);
  const d = driver(ctx.sim, ctx.clock);
  await d.say({ type: 'client_hello', protocolVersion: 1 });
  await d.say({ type: 'start_request', clientStartId: START_ID });
  const ready = d.last('mining_ready');
  const candidate = (nonce, over = {}) => ({
    type: 'submit_real_candidate',
    clientStartId: START_ID,
    jobId: ctx.sim.job.jobId,
    issuanceId: ctx.sim.job.issuanceId,
    workerId: ready.workerId,
    runGeneration: ready.runGeneration,
    nonce: nonce.toString(16).padStart(8, '0'),
    ...over,
  });
  return { ...ctx, d, ready, candidate };
}

// ================================================================== the fresh template
test('ONE fresh get_block_template, bound exactly, with the daemon owned and no known nonce', async () => {
  const { built, sim, owned, daemon, counts } = await buildScriptedReal();
  assert.equal(daemon.log.methods.filter((m) => m === 'get_block_template').length, 1);
  assert.deepEqual(daemon.log.templateReserveSizes, [0]);
  assert.equal(built.personalizedTemplates, false);
  assert.equal(counts.readyChecks, 1);
  assert.equal(owned.length, 1);
  assert.equal(owned[0].label, 'meepcoind');
  assert.equal(sim.job.height, 1n);
  assert.equal(sim.job.nonceStart, 0);
  assert.equal(sim.job.nonceRange, REAL_SEARCH_LIMITS.maxAttempts);
  assert.equal(built.templateFacts.prevHashHex, PREV);
  assert.equal(built.canonical.prevHashHex, PREV);
  assert.equal(built.expectedHashHexLE, null, 'a fresh template must carry no known answer');
  assert.equal(built.recordedContext.height, '1');
  assert.equal(sim.submissionDaemon.counters.getBlockTemplate, 1);
  assert.equal(sim.submissionDaemon.counters.calcPow + sim.submissionDaemon.counters.dispatchSubmission, 0);

  // What the page is told before Start: the mode, the bounds, the public job -- and no answer.
  const d = driver(sim, { ms: 1_000_000 });
  await d.say({ type: 'client_hello', protocolVersion: 1 });
  const hello = d.last('server_hello');
  assert.equal(hello.mode, REAL_DAEMON_MODE);
  assert.deepEqual(hello.searchLimits, REAL_SEARCH_LIMITS);
  const job = d.last('real_job');
  assert.equal(job.nonceStart, 0);
  assert.equal(job.nonceRange, 8192);
  assert.equal(job.height, '1');
  const text = JSON.stringify(d.sent);
  assert.equal(text.includes(ROW.full_block_blob), false, 'the full block reached the page');
  assert.equal(/expected|answer|winning/i.test(Object.keys(job).join(' ')), false);
});

test('trusted personalization owns and readies one converter, reserves 16 bytes and binds its exact output', async () => {
  const extraNonceHex = '0102030405060708090a0b0c0d0e0f10';
  const r = await buildScriptedReal({ personalizeTemplates: true, extraNonces: [extraNonceHex] });

  assert.equal(r.built.personalizedTemplates, true);
  assert.deepEqual(r.owned.map((entry) => entry.label), ['block converter', 'meepcoind']);
  assert.deepEqual(r.converterLog.launches, [{
    distro: DAEMON_CONFIG.wslDistro,
    binaryPath: `${DAEMON_CONFIG.artifactDir}/meepcoin-blockhashing`,
    runtimeLibraryDir: `${DAEMON_CONFIG.artifactDir}/runtime-libs`,
  }]);
  assert.deepEqual(r.daemon.log.templateReserveSizes, [16]);
  assert.equal(r.converterLog.converted.length, 1);

  const personalizedFullHex = r.converterLog.converted[0];
  const offset = r.built.templateFacts.reservedOffset;
  assert.equal(r.built.templateFacts.reservedSize, 16);
  assert.equal(personalizedFullHex.slice(offset * 2, offset * 2 + 32), extraNonceHex);
  assert.equal(blobToHex(fullBlockBlobOf(r.built.job)), personalizedFullHex);
  assert.equal(r.built.templateFacts.blocktemplateBlobHex, personalizedFullHex);
  assert.equal(r.built.templateFacts.blockhashingBlobHex, r.built.job.hashingTemplateHex);
  assert.equal(r.built.templateFacts.personalized, true);
  assert.equal(r.built.templateFacts.topAfterHeight, r.built.templateFacts.topBeforeHeight);
  assert.equal(r.built.templateFacts.topAfterHash, r.built.templateFacts.topBeforeHash);
  assert.equal(r.daemon.log.methods.filter((method) => method === 'get_last_block_header').length, 3,
    'readiness, pre-template tip and post-conversion publication fence were not all observed');
  assert.match(r.built.templateFacts.extraNonceDigest, /^[0-9a-f]{64}$/);
  assert.notEqual(r.built.templateFacts.extraNonceDigest, extraNonceHex);

  const d = driver(r.sim, r.clock);
  await d.say({ type: 'client_hello', protocolVersion: 1 });
  const browserText = JSON.stringify(d.sent);
  assert.equal(browserText.includes(extraNonceHex), false, 'the raw pool allocation reached the browser');
  for (const forbidden of ['reservedOffset', 'reservedSize', 'extraNonceDigest', 'blocktemplateBlobHex']) {
    assert.equal(browserText.includes(forbidden), false, `${forbidden} reached the browser`);
  }
});

test('personalized work is not published when the canonical tip changes during conversion', async () => {
  let conversions = 0;
  let publications = 0;
  const moved = 'dd'.repeat(32);
  const daemon = inMemoryDaemon({
    topForRead: (read, h) => read === 3 ? { ...h, hash: moved } : h,
  });

  await assert.rejects(buildScriptedReal({
    daemon,
    personalizeTemplates: true,
    converterOptions: {
      convertedHex: () => { conversions += 1; return ROW.block_hashing_blob; },
    },
    makeTemplateAuthority: () => ({ publish() { publications += 1; } }),
  }), (err) => err?.code === 'template_tip_changed');

  assert.equal(conversions, 1, 'the scripted move did not occur after personalization work');
  assert.equal(publications, 0, 'a stale personalized job reached the authority');
  assert.equal(daemon.log.methods.filter((method) => method === 'get_block_template').length, 1);
  assert.equal(daemon.log.methods.filter((method) => method === 'get_last_block_header').length, 3);
});

test('an orphaned or malformed post-conversion tip recheck yields no publication or usable build', async () => {
  for (const [name, daemon, code] of [
    ['orphaned', inMemoryDaemon({ orphanTopAfter: 3 }), 'template_tip_not_canonical'],
    ['malformed', inMemoryDaemon({
      topForRead: (read, h) => read === 3 ? { ...h, hash: 'not-a-block-id' } : h,
    }), 'rpc_bad_response'],
  ]) {
    let publications = 0;
    let resolved = false;
    try {
      await buildScriptedReal({
        daemon,
        personalizeTemplates: true,
        makeTemplateAuthority: () => ({ publish() { publications += 1; } }),
      });
      resolved = true;
    } catch (err) {
      assert.equal(err?.code, code, name);
    }
    assert.equal(resolved, false, `${name}: a usable build was returned`);
    assert.equal(publications, 0, `${name}: a job reached the authority`);
    assert.equal(daemon.log.methods.filter((method) => method === 'get_last_block_header').length, 3, name);
  }
});

test('an abort during the post-conversion tip recheck yields no publication or usable build', async () => {
  const controller = new AbortController();
  let publications = 0;
  let conversions = 0;
  const daemon = inMemoryDaemon({
    topForRead: (read, h) => {
      if (read === 3) controller.abort();
      return h;
    },
  });

  await assert.rejects(buildScriptedReal({
    daemon,
    personalizeTemplates: true,
    signal: controller.signal,
    converterOptions: {
      convertedHex: () => { conversions += 1; return ROW.block_hashing_blob; },
    },
    makeTemplateAuthority: () => ({ publish() { publications += 1; } }),
  }), (err) => err?.code === 'startup_cancelled');

  assert.equal(conversions, 1);
  assert.equal(publications, 0);
  assert.equal(daemon.log.methods.filter((method) => method === 'get_last_block_header').length, 3);
});

test('converter readiness is owned and awaited before any daemon may start', async () => {
  const daemon = inMemoryDaemon();
  const converterLog = { launches: [], converted: [], events: [] };
  const converter = scriptedConverterResource(converterLog);
  let releaseReady;
  converter.ready = new Promise((resolveReady) => { releaseReady = resolveReady; });
  let daemonStarts = 0;
  const owned = [];

  const building = buildRealDaemonMode({
    daemon: DAEMON_CONFIG,
    personalizeTemplates: true,
    ownResource: (label, resource) => owned.push({ label, resource }),
    startDaemon: async ({ isRpcReady }) => {
      daemonStarts += 1;
      await isRpcReady();
      return scriptedDaemonResource([]);
    },
    makeTransport: () => daemon.transport,
    makeVerifier: async () => scriptedVerifier({ wasm: 0, native: 0 }),
    launchConverter: () => converter,
    makeExtraNonceAllocator: () => ({ reserveSize: 16, issue: () => '11'.repeat(16) }),
  });
  await new Promise((resolveTurn) => setImmediate(resolveTurn));
  assert.deepEqual(owned.map((entry) => entry.label), ['block converter']);
  assert.equal(daemonStarts, 0, 'a daemon started before converter readiness');

  releaseReady(converter);
  const built = await building;
  assert.equal(daemonStarts, 1);
  assert.deepEqual(owned.map((entry) => entry.label), ['block converter', 'meepcoind']);
  assert.equal(built.personalizedTemplates, true);
});

test('converter readiness failure remains owned and prevents every daemon and template', async () => {
  const daemon = inMemoryDaemon();
  const converterLog = { launches: [], converted: [], events: [] };
  const failure = new Error('scripted converter readiness failure');
  const converter = scriptedConverterResource(converterLog, { readyError: failure });
  const owned = [];
  let daemonStarts = 0;

  await assert.rejects(buildRealDaemonMode({
    daemon: DAEMON_CONFIG,
    personalizeTemplates: true,
    ownResource: (label, resource) => owned.push({ label, resource }),
    startDaemon: async () => { daemonStarts += 1; throw new Error('must not start'); },
    makeTransport: () => daemon.transport,
    makeVerifier: async () => scriptedVerifier({ wasm: 0, native: 0 }),
    launchConverter: () => converter,
    makeExtraNonceAllocator: () => ({ reserveSize: 16, issue: () => '11'.repeat(16) }),
  }), (err) => err === failure);
  assert.deepEqual(owned.map((entry) => entry.label), ['block converter']);
  assert.equal(daemonStarts, 0);
  assert.equal(daemon.log.methods.length, 0);
});

test('server startup transaction closes an owned converter when readiness fails', async () => {
  const daemon = inMemoryDaemon();
  const converterLog = { launches: [], converted: [], events: [] };
  const failure = new Error('scripted converter startup failure');
  const converter = scriptedConverterResource(converterLog, { readyError: failure });
  let daemonStarts = 0;

  await assert.rejects(startDevPool({
    mode: REAL_DAEMON_MODE,
    port: 0,
    realDaemon: {
      daemon: DAEMON_CONFIG,
      personalizeTemplates: true,
      startDaemon: async () => { daemonStarts += 1; throw new Error('must not start'); },
      makeTransport: () => daemon.transport,
      makeVerifier: async () => scriptedVerifier({ wasm: 0, native: 0 }),
      launchConverter: () => converter,
      makeExtraNonceAllocator: () => ({ reserveSize: 16, issue: () => '11'.repeat(16) }),
    },
  }), (err) => err === failure);
  assert.equal(daemonStarts, 0);
  assert.equal(converter.closed, true, 'the startup transaction left the converter owned and running');
  assert.deepEqual(converterLog.events, ['converterClose']);
});

test('a template that is not the next block on the current top, or whose blob names another parent, is refused', async () => {
  for (const [name, template] of [
    ['wrong height', { height: 2 }],
    ['wrong parent', { prev_hash: 'd'.repeat(64) }],
  ]) {
    const daemon = inMemoryDaemon({ template });
    await assert.rejects(buildScriptedReal({ daemon }), (e) => /template_/.test(e.code), name);
  }
});

// ================================================================== the trusted coinbase destination
// The reward address is TRUSTED LOCAL SERVER STARTUP CONFIGURATION. These tests fix three things: the
// default is unchanged, an override travels to get_block_template and nowhere else, and everything a
// client can reach -- a message, a share, a forged job field -- cannot select or move it.
// A real, public, well-shaped MONERO MAINNET address: 95 Base58 characters, and not this network's.
const OTHER_NETWORK_ADDRESS =
  '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A';

test('NO OVERRIDE: the committed neutral address is still the exact destination', async () => {
  const r = await buildScriptedReal();
  assert.deepEqual(r.templateAddresses, [REAL_COINBASE_ADDRESS]);
  assert.equal(r.built.coinbaseAddress, REAL_COINBASE_ADDRESS);
  assert.equal(r.built.templateFacts.coinbaseAddress, REAL_COINBASE_ADDRESS);
  assert.equal(r.built.templateFacts.coinbaseIsNeutralDefault, true);
  // The raw request the daemon actually received, not a re-rendering of the option.
  const raw = r.built.rpcAudit.raw.find((x) => x.method === 'get_block_template');
  assert.equal(JSON.parse(raw.requestBody).params.wallet_address, REAL_COINBASE_ADDRESS);
});

test('A TRUSTED STARTUP OVERRIDE reaches get_block_template unchanged, exactly once', async () => {
  const r = await buildScriptedReal({ walletAddress: OTHER_NETWORK_ADDRESS, daemon: inMemoryDaemon() });
  assert.deepEqual(r.templateAddresses, [OTHER_NETWORK_ADDRESS]);
  assert.equal(r.built.coinbaseAddress, OTHER_NETWORK_ADDRESS);
  assert.equal(r.built.templateFacts.coinbaseAddress, OTHER_NETWORK_ADDRESS);
  assert.equal(r.built.templateFacts.coinbaseIsNeutralDefault, false);
  assert.equal(r.daemon.log.methods.filter((m) => m === 'get_block_template').length, 1);
  // Nothing else about the run moved: the same one template, bound the same way.
  assert.equal(r.built.templateFacts.jobId, r.built.job.jobId);
  assert.equal(r.built.templateFacts.contentDigest, r.built.job.contentDigest);
});

test('a malformed destination is refused CHEAPLY: no daemon, no transport, no verifier, no template', async () => {
  for (const [name, walletAddress] of [
    ['not a string', 12345],
    ['null', null],
    ['object', { toString: () => REAL_COINBASE_ADDRESS }],
    ['empty', ''],
    ['one character short', REAL_COINBASE_ADDRESS.slice(0, -1)],
    ['one character long', `${REAL_COINBASE_ADDRESS}1`],
    ['non-Base58 (0)', `${REAL_COINBASE_ADDRESS.slice(0, -1)}0`],
    ['non-Base58 (O)', `${REAL_COINBASE_ADDRESS.slice(0, -1)}O`],
    ['non-Base58 (l)', `${REAL_COINBASE_ADDRESS.slice(0, -1)}l`],
    ['whitespace', `${REAL_COINBASE_ADDRESS.slice(0, -1)} `],
  ]) {
    let started = 0;
    await assert.rejects(buildRealDaemonMode({
      daemon: DAEMON_CONFIG,
      walletAddress,
      ownResource: () => { throw new Error('must not own anything'); },
      startDaemon: async () => { started += 1; throw new Error('must not start'); },
      makeTransport: () => async () => { throw new Error('must not transport'); },
      makeVerifier: async () => { throw new Error('must not build'); },
    }), (e) => e.code === 'bad_coinbase_address', name);
    assert.equal(started, 0, `${name} started a daemon`);
  }
});

test('a VALID-SHAPE WRONG-NETWORK destination is refused by the daemon, before verifier/dataset/hash', async () => {
  // The shape check cannot tell networks apart, and does not pretend to: this address is 95 Base58
  // characters. The daemon is asked, and its refusal is the startup failure.
  assert.equal(OTHER_NETWORK_ADDRESS.length, REAL_COINBASE_ADDRESS.length);
  const daemon = inMemoryDaemon({ acceptAddress: REAL_COINBASE_ADDRESS });
  const owned = [];
  const counts = { verifiers: 0 };
  await assert.rejects(buildRealDaemonMode({
    daemon: DAEMON_CONFIG,
    walletAddress: OTHER_NETWORK_ADDRESS,
    ownResource: (label, r) => owned.push({ label, r }),
    startDaemon: async ({ isRpcReady }) => { await isRpcReady(); return scriptedDaemonResource([]); },
    makeTransport: () => daemon.transport,
    makeVerifier: async () => { counts.verifiers += 1; throw new Error('must not build'); },
  }), (e) => e.name === 'DaemonRpcError' && /get_block_template/.test(e.message));
  // The daemon WAS started (it is the authority) and is owned, so startDevPool's transactional
  // cleanup closes it; no verifier, dataset or hash was ever created, and no listener exists --
  // startDevPool calls this factory before httpServer.listen(), which the startup-failure test
  // above proves against the real server.
  assert.deepEqual(owned.map((o) => o.label), ['meepcoind']);
  assert.equal(counts.verifiers, 0);
  assert.deepEqual(daemon.log.templateAddresses, [OTHER_NETWORK_ADDRESS]);
  assert.equal(daemon.log.submitBodies.length, 0);
});

test('NO CLIENT INPUT can select or change the destination: messages, shares and forged job fields', async () => {
  // 1. The wire parser drops the field outright, in every message a client may send.
  for (const msg of [
    { type: 'client_hello', protocolVersion: 1, walletAddress: OTHER_NETWORK_ADDRESS },
    { type: 'start_request', clientStartId: START_ID, walletAddress: OTHER_NETWORK_ADDRESS },
    { type: 'start_request', clientStartId: START_ID, coinbaseAddress: OTHER_NETWORK_ADDRESS },
  ]) {
    const t = JSON.stringify(msg);
    const parsed = parseClientMessage(Buffer.byteLength(t), t);
    if (parsed.ok) {
      assert.equal('walletAddress' in parsed.message, false, t);
      assert.equal('coinbaseAddress' in parsed.message, false, t);
    }
  }
  // 2. A WINNING SHARE THAT CARRIES A FORGED DESTINATION is refused outright, and no block is
  //    submitted at all: the extra field never becomes something the server has to ignore correctly.
  const forged = await startedRun();
  await forged.d.say(forged.candidate(5, {
    walletAddress: OTHER_NETWORK_ADDRESS, coinbaseAddress: OTHER_NETWORK_ADDRESS,
  }));
  assert.equal(forged.d.last('block_accepted'), undefined, 'a share with a forged destination was accepted');
  assert.equal(forged.daemon.log.submitBodies.length, 0);
  assert.deepEqual(forged.daemon.log.templateAddresses, [REAL_COINBASE_ADDRESS]);

  // 3. A whole real run over the session: the ONE template was requested before the socket existed
  //    and is never re-requested, so a client has nothing to redirect.
  const r = await startedRun();
  await r.d.say(r.candidate(5));
  assert.ok(r.d.last('block_accepted'));
  assert.deepEqual(r.daemon.log.templateAddresses, [REAL_COINBASE_ADDRESS]);
  assert.equal(r.daemon.log.methods.filter((m) => m === 'get_block_template').length, 1);
  // The block the daemon accepted is the template it produced, with only the nonce moved.
  const submitted = r.daemon.log.submitBodies[0];
  const template = r.built.templateFacts.blocktemplateBlobHex;
  const off = findNonceOffset(hexToBlob(template)).offset;
  assert.equal(submitted.length, template.length);
  assert.equal(submitted.slice(0, 2 * off), template.slice(0, 2 * off));
  assert.equal(submitted.slice(2 * (off + 4)), template.slice(2 * (off + 4)));
  // 4. Nothing sent to the browser carries a destination it could echo back.
  const sentText = JSON.stringify(r.d.sent);
  assert.equal(/D1Awzzi|44AFFq5|walletAddress|coinbaseAddress/.test(sentText), false,
    'a reward address, or an option name a client could echo back, reached the client');
});

// ================================================================== one candidate, one of each, canonical
test('the ONE found candidate: one server Wasm, one native, one calc_pow, one submit, canonical success', async () => {
  const r = await startedRun();
  assert.equal(r.ready.mode, REAL_DAEMON_MODE);
  assert.deepEqual(r.ready.searchLimits, REAL_SEARCH_LIMITS);
  await r.d.say(r.candidate(5));
  const done = r.d.last('block_accepted');
  assert.ok(done, `no block_accepted: ${JSON.stringify(r.d.sent.map((m) => m.type))}`);
  assert.equal(done.terminal, true);
  assert.equal(done.blockId, BLOCK_ID);
  assert.equal(done.nonce, 5);
  assert.equal(done.hashHexLE, POW);
  assert.equal(done.confirmedBy, 'immediate_canonical_readback_top_block_with_matching_pow_hash');
  assert.equal(r.counts.wasm, 1);
  assert.equal(r.counts.native, 1);
  const c = r.sim.submissionDaemon.counters;
  assert.deepEqual({ ...c }, {
    getBlockTemplate: 1, calcPow: 1, prepareSubmission: 1, dispatchSubmission: 1, headerReadback: 1, topReadback: 1,
  });
  assert.equal(r.daemon.log.submitBodies.length, 1);
  // The exact nonce-bearing full block was submitted, and calc_pow saw the nonce-bearing hashing blob.
  assert.equal(r.daemon.log.submitBodies[0], blobToHex(patchNonce(hexToBlob(ROW.full_block_blob), 5).blob));
  assert.equal(r.daemon.log.calcPow[0].block_blob, blobToHex(patchNonce(hexToBlob(ROW.block_hashing_blob), 5).blob));
  assert.equal(done.counters.daemonDispatchSubmission, 1);
  assert.equal(r.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_COMPLETE);
  assert.equal(JSON.stringify(r.d.sent).includes(ROW.full_block_blob.slice(0, 80)), false, 'block blob leaked');
});

test('a SECOND candidate is refused before verification, even while the first is in flight', async () => {
  const r = await startedRun();
  const first = r.d.say(r.candidate(5));
  const second = await r.d.say(r.candidate(6));
  await first;
  assert.equal(second.ok, false);
  assert.equal(second.reason, 'candidate_limit_reached');
  assert.equal(r.counts.wasm, 1);
  assert.equal(r.counts.native, 1);
  assert.equal(r.sim.submissionDaemon.counters.calcPow, 1);
  assert.equal(r.daemon.log.submitBodies.length, 1);
});

test('a forged, stale or out-of-window candidate does not spend the one candidate', async () => {
  const r = await startedRun();
  for (const over of [
    { workerId: 'sim-9-deadbeef' },
    { jobId: 'realjob-00000000000000000000000000000000' },
    { issuanceId: 'f'.repeat(32) },
    { runGeneration: 99 },
    { nonce: (REAL_SEARCH_LIMITS.maxAttempts).toString(16).padStart(8, '0') },
  ]) {
    await r.d.say(r.candidate(1, over));
  }
  assert.equal(r.counts.wasm, 0, 'a forged candidate was hashed');
  assert.equal(r.daemon.log.submitBodies.length, 0);
  await r.d.say(r.candidate(7));
  assert.ok(r.d.last('block_accepted'), 'the genuine candidate was refused after forgeries');
});

test('an explicit daemon refusal is a rejection, with exactly one submission and no readback resolution', async () => {
  const r = await startedRun({ daemon: inMemoryDaemon({ submit: 'refuse' }) });
  await r.d.say(r.candidate(5));
  const fail = r.d.last('block_rejected');
  assert.equal(fail.reason, 'submit_rejected');
  assert.equal(r.daemon.log.submitBodies.length, 1);
  assert.equal(r.sim.submissionDaemon.counters.headerReadback, 0);
});

test('an AMBIGUOUS submission is resolved only by exact canonical readback, and never resubmitted', async () => {
  const r = await startedRun({ daemon: inMemoryDaemon({ submit: 'lost' }) });
  await r.d.say(r.candidate(5));
  const done = r.d.last('block_accepted');
  assert.ok(done, JSON.stringify(r.d.sent.map((m) => [m.type, m.reason])));
  assert.equal(done.confirmedBy, 'canonical_readback_resolved_an_ambiguous_submission');
  assert.equal(r.daemon.log.submitBodies.length, 1);
  assert.equal(r.sim.submissionDaemon.counters.dispatchSubmission, 1);

  // A readback that names a DIFFERENT block at the height leaves it ambiguous -- still one submission.
  const other = await startedRun({ daemon: inMemoryDaemon({ submit: 'lost', header: { pow_hash: 'ee'.repeat(32) } }) });
  await other.d.say(other.candidate(5));
  assert.equal(other.d.last('block_rejected')?.reason, 'submit_outcome_ambiguous');
  assert.equal(other.daemon.log.submitBodies.length, 1);
});

test('canonical readback mismatches are never success', async () => {
  for (const [name, opts, reason] of [
    ['top is another block', { top: { hash: 'd'.repeat(64) } }, 'readback_mismatch'],
    ['top height', { top: { height: 7 } }, 'readback_mismatch'],
    ['parent', { header: { prev_hash: 'e'.repeat(64) } }, 'readback_mismatch'],
    ['another block at height', { header: { hash: 'f'.repeat(64) } }, 'readback_mismatch'],
    ['orphan', { header: { orphan_status: true } }, 'submitted_but_untrusted'],
  ]) {
    const r = await startedRun({ daemon: inMemoryDaemon(opts) });
    await r.d.say(r.candidate(5));
    assert.equal(r.d.last('block_accepted'), undefined, `${name}: success`);
    assert.equal(r.d.last('block_rejected')?.reason, reason, name);
    assert.equal(r.daemon.log.submitBodies.length, 1, name);
  }
});

test('three-way disagreement stops before any submission', async () => {
  const r = await startedRun({ daemon: inMemoryDaemon({ powHex: 'cd'.repeat(32) }) });
  await r.d.say(r.candidate(5));
  assert.equal(r.d.last('block_rejected')?.reason, 'fatal_verifier');
  assert.equal(r.daemon.log.submitBodies.length, 0);
  assert.equal(r.sim.latch.tripped, true);
});

// ================================================================== bounds and revocation
test('NO SOLUTION: the server backstop ends the attempt with zero hashes and zero submissions', async () => {
  const r = await startedRun();
  const timer = r.d.timers.at(-1);
  assert.equal(timer.ms, REAL_SEARCH_LIMITS.maxSearchMs + SERVER_SEARCH_GRACE_MS);
  timer.fn();
  const stopped = r.d.last('run_stopped');
  assert.equal(stopped.reason, 'search_bound_reached');
  assert.equal(stopped.terminal, true);
  await r.d.say(r.candidate(5));
  assert.equal(r.counts.wasm + r.counts.native, 0);
  assert.equal(r.sim.submissionDaemon.counters.calcPow, 0);
  assert.equal(r.daemon.log.submitBodies.length, 0);
});

test('NO SOLUTION reported by the page: the bound stop ends the run with zero submissions', async () => {
  const r = await startedRun();
  await r.d.say({
    type: 'stop_request', clientStartId: START_ID, workerId: r.ready.workerId, runGeneration: r.ready.runGeneration,
    jobId: r.sim.job.jobId, issuanceId: r.sim.job.issuanceId, reason: 'search_bound_reached',
  });
  assert.equal(r.d.last('run_stopped')?.reason, 'search_bound_reached');
  assert.equal(r.d.timers.at(-1).cleared, true, 'the backstop timer outlived the run');
  await r.d.say(r.candidate(5));
  assert.equal(r.daemon.log.submitBodies.length, 0);
});

test('a candidate after the frozen deadline is refused with zero hashes', async () => {
  const r = await startedRun();
  r.clock.ms += REAL_SEARCH_LIMITS.maxSearchMs + SERVER_SEARCH_GRACE_MS + 1;
  await r.d.say(r.candidate(5));
  assert.equal(r.d.last('block_rejected')?.reason, 'search_deadline_exceeded');
  assert.equal(r.counts.wasm + r.counts.native, 0);
  assert.equal(r.daemon.log.submitBodies.length, 0);
});

test('Stop, hidden, pagehide or socket loss before the claim prevents any submission', async () => {
  for (const reason of ['user_stop', 'page_hidden', 'page_unload', 'socket_close']) {
    const r = await startedRun();
    await r.d.say({
      type: 'stop_request', clientStartId: START_ID, workerId: r.ready.workerId, runGeneration: r.ready.runGeneration,
      jobId: r.sim.job.jobId, issuanceId: r.sim.job.issuanceId, reason,
    });
    await r.d.say(r.candidate(5));
    assert.equal(r.daemon.log.submitBodies.length, 0, reason);
    assert.equal(r.counts.wasm, 0, reason);
  }
  const lost = await startedRun();
  lost.d.session.dispose();
  await lost.d.say(lost.candidate(5));
  assert.equal(lost.daemon.log.submitBodies.length, 0, 'socket dispose');
  assert.equal(lost.sim.attemptState, SIM_ATTEMPT_STATES.TERMINAL_CANCELLED);
});

// ================================================================== off by default, owned, cleaned up
test('real mode is OFF by default and no client message can select it', async () => {
  await assert.rejects(startDevPool({ mode: REAL_DAEMON_MODE }), /requires the explicit realDaemon option/);
  for (const msg of [
    { type: 'client_hello', protocolVersion: 1, mode: REAL_DAEMON_MODE },
    { type: 'start_request', clientStartId: START_ID, mode: REAL_DAEMON_MODE },
  ]) {
    const t = JSON.stringify(msg);
    assert.equal(parseClientMessage(Buffer.byteLength(t), t).ok, false, msg.type);
  }
  const src = readFileSync(resolve(REPO, 'pool/dev/server.mjs'), 'utf8');
  assert.match(src, /mode = 'synthetic',/);
});

test('a real-mode startup failure closes and awaits the already-owned daemon, before any listener', async () => {
  const resourceLog = [];
  let resource = null;
  let err = null;
  try {
    await startDevPool({
      mode: REAL_DAEMON_MODE,
      port: 0,
      realDaemon: { daemon: DAEMON_CONFIG },
      realDaemonFactory: async ({ ownResource }) => {
        resource = scriptedDaemonResource(resourceLog);
        ownResource('meepcoind', resource);
        throw new Error('template refused');
      },
    });
  } catch (e) { err = e; }
  assert.ok(err);
  assert.equal(err.message, 'template refused');
  assert.equal(resource.closed, true, 'the owned daemon was left running');
  assert.deepEqual(resourceLog, ['close']);
  assert.equal(err.retainedResources, undefined);
});

test('EADDRINUSE AFTER THE DAEMON IS OWNED: the bind failure closes and awaits the daemon, and keeps its code', async () => {
  // THE WITNESS (Regression testing, af1385fe): the bind await sat outside the startup cleanup, so an occupied
  // port rejected EADDRINUSE with the owned daemon still open: closed false, zero close calls.
  // The only listener here is an ordinary Node HTTP server this test owns, occupying the port.
  const blocker = http.createServer();
  await new Promise((r) => blocker.listen(0, '127.0.0.1', r));
  const fake = {
    closed: false, closeCalls: 0, forceCloseCalls: 0,
    beginClose() {},
    async close() { this.closeCalls += 1; this.closed = true; },
    async forceClose() { this.forceCloseCalls += 1; this.closed = true; },
  };
  let err = null;
  try {
    await startDevPool({
      mode: REAL_DAEMON_MODE,
      host: '127.0.0.1',
      port: blocker.address().port,
      realDaemon: { daemon: DAEMON_CONFIG },
      realDaemonFactory: async ({ ownResource }) => {
        ownResource('meepcoind', fake);
        return {
          job: {}, latch: {}, authority: {}, daemon: { counters: {} },
          makeServerVerifier: () => null, expectedHashHexLE: null, recordedContext: {},
        };
      },
    });
  } catch (e) { err = e; } finally {
    await new Promise((r) => blocker.close(r));
  }
  assert.ok(err, 'startup succeeded on an occupied port');
  assert.equal(err.code, 'EADDRINUSE', 'the original bind error was not preserved');
  assert.equal(fake.closeCalls, 1, 'the owned daemon was not closed exactly once');
  assert.equal(fake.closed, true);
  assert.equal(fake.forceCloseCalls, 0, 'an ordinary confirmed close was escalated');
  assert.equal(err.retainedResources, undefined);
  assert.equal(blocker.listening, false);
});

test('a resource whose ordinary close does not confirm release is force-closed once, else reported as retained', async () => {
  const blocker = http.createServer();
  await new Promise((r) => blocker.listen(0, '127.0.0.1', r));
  const stubborn = {
    closed: false, closeCalls: 0, forceCloseCalls: 0, beginClose() {},
    async close() { this.closeCalls += 1; },                         // returns, but never confirms
    async forceClose() { this.forceCloseCalls += 1; this.closed = true; },
  };
  const stuck = {
    closed: false, closeCalls: 0, forceCloseCalls: 0, beginClose() {},
    async close() { this.closeCalls += 1; },
    async forceClose() { this.forceCloseCalls += 1; },               // never confirms either
  };
  let err = null;
  try {
    await startDevPool({
      mode: REAL_DAEMON_MODE,
      host: '127.0.0.1',
      port: blocker.address().port,
      realDaemon: { daemon: DAEMON_CONFIG },
      realDaemonFactory: async ({ ownResource }) => {
        ownResource('daemon A', stubborn);
        ownResource('daemon B', stuck);
        return {
          job: {}, latch: {}, authority: {}, daemon: { counters: {} },
          makeServerVerifier: () => null, expectedHashHexLE: null, recordedContext: {},
        };
      },
    });
  } catch (e) { err = e; } finally {
    await new Promise((r) => blocker.close(r));
  }
  assert.equal(err?.code, 'EADDRINUSE');
  assert.deepEqual([stubborn.closeCalls, stubborn.forceCloseCalls, stubborn.closed], [1, 1, true]);
  assert.deepEqual([stuck.closeCalls, stuck.forceCloseCalls, stuck.closed], [1, 1, false]);
  assert.deepEqual(err.retainedResources.map((r) => r.label), ['daemon B']);
});

// ================================================================== the paired private P2P test
const IMAGE_ID = `sha256:${'d'.repeat(64)}`;
// Below the difficulty-500 target (little-endian: the two most significant bytes are zero).
const PAIR_POW = `${'ab'.repeat(30)}0000`;
const PEER_A = Object.freeze({
  ...DAEMON_CONFIG, profile: 'private-exclusive-peer-test', fixedDifficulty: 500,
  rpcPort: 28581, p2pPort: 28580, exclusivePeerP2pPort: 28590, expectedImageId: IMAGE_ID,
  runDir: '/home/tseng/meepcoin-private-run-aaaaaaaaaaaaaaaa',
});
const PEER_B = Object.freeze({
  ...DAEMON_CONFIG, profile: 'private-exclusive-peer-test', fixedDifficulty: 500,
  rpcPort: 28591, p2pPort: 28590, exclusivePeerP2pPort: 28580, expectedImageId: IMAGE_ID,
  runDir: '/home/tseng/meepcoin-private-run-bbbbbbbbbbbbbbbb',
});

/**
 * Two in-memory daemons behind the real adapters. A's accepted block reaches B only when
 * `propagateAfterBReads` read calls to B have happened -- the stand-in for P2P. B's transport logs
 * every method it is asked for, so a write reaching it would be visible.
 */
function inMemoryPair({
  wide = '0x1f4', genesisB = PREV, linkAfter = 2, connsA = null, connsB = null,
  propagateAfterBReads = 2, bHeaderOverride = {}, neverPropagate = false,
  aOrphanTopAfter = null, genesisTimestampA = 1785283200,
  genesisTimestampB = 1785283200,
} = {}) {
  const a = inMemoryDaemon({
    template: { wide_difficulty: wide, difficulty: 500 }, powHex: PAIR_POW,
    header: { pow_hash: PAIR_POW }, top: { pow_hash: PAIR_POW }, orphanTopAfter: aOrphanTopAfter,
    genesisTimestamp: genesisTimestampA,
  });
  const bLog = { methods: [] };
  let bReads = 0;
  let observations = 0;
  // AS THE REAL DAEMON DOES: until the pair has synchronised, the gated methods answer BUSY and
  // get_info reports synchronized false. (The first live attempt deadlocked on exactly this.)
  const isLinked = () => observations > linkAfter;
  const busy = (id) => JSON.stringify({ jsonrpc: '2.0', id, result: { status: 'BUSY' } });
  const bTransport = async (req) => {
    const body = JSON.parse(req.body);
    bLog.methods.push(body.method);
    req.handoff();
    const ok = (result) => JSON.stringify({ jsonrpc: '2.0', id: body.id, result });
    const aHasBlock = a.log.submitBodies.length > 0;
    bReads += 1;
    const propagated = aHasBlock && !neverPropagate && bReads > propagateAfterBReads;
    const aBody = a.log.submitBodies[0];
    const nonce = aBody ? (() => { const bb = hexToBlob(aBody); const off = findNonceOffset(bb).offset; return (bb[off] | (bb[off + 1] << 8) | (bb[off + 2] << 16) | (bb[off + 3] << 24)) >>> 0; })() : 0;
    if (!isLinked() && body.method !== 'get_info') return busy(body.id);
    switch (body.method) {
      case 'get_last_block_header':
        return ok({ status: 'OK', block_header: propagated
          ? { hash: BLOCK_ID, height: 1, nonce, orphan_status: false, pow_hash: PAIR_POW, prev_hash: PREV }
          : { hash: genesisB, height: 0, nonce: 0,
            ...(genesisTimestampB === null ? {} : { timestamp: genesisTimestampB }),
            orphan_status: false, pow_hash: '0'.repeat(64), prev_hash: '0'.repeat(64) } });
      case 'get_block_header_by_height':
        if (!propagated) return JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: -2, message: 'too big height' } });
        return ok({ status: 'OK', block_header: { hash: BLOCK_ID, height: 1, nonce, orphan_status: false, pow_hash: PAIR_POW, prev_hash: PREV, ...bHeaderOverride } });
      case 'get_info':
        return ok({ status: 'OK', height: propagated ? 2 : 1, top_block_hash: propagated ? BLOCK_ID : genesisB, synchronized: isLinked(), outgoing_connections_count: isLinked() ? 1 : 0, incoming_connections_count: isLinked() ? 1 : 0, nettype: 'testnet' });
      default:
        throw new Error(`daemon B was asked for ${body.method}`);
    }
  };
  // A's get_info is needed for the link wait.
  const aTransport = async (req) => {
    const body = JSON.parse(req.body);
    if (body.method === 'get_info') {
      req.handoff();
      return JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { status: 'OK', height: 1, top_block_hash: PREV, synchronized: isLinked(), outgoing_connections_count: isLinked() ? 1 : 0, incoming_connections_count: isLinked() ? 1 : 0, nettype: 'testnet' } });
    }
    if (!isLinked() && ['get_last_block_header', 'get_block_template', 'calc_pow', 'submit_block', 'get_block_header_by_height'].includes(body.method)) {
      req.handoff();
      return busy(body.id);
    }
    return a.transport(req);
  };
  const linkA = [{ local: '127.0.0.1:41000', peer: '127.0.0.1:28590' }, { local: '127.0.0.1:28581', peer: '127.0.0.1:50000' }];
  const linkB = [{ local: '127.0.0.1:28590', peer: '127.0.0.1:41000' }];
  // ONE shared socket table for both daemons, as `ss -H -tnp` prints it.
  const row = (c, pid) => `${c.state ?? 'ESTAB'} 0 0 ${c.local} ${c.peer} users:(("meepcoind",pid=${pid},fd=9))`;
  const socketTable = () => {
    observations += 1;
    const aRows = (connsA ?? (isLinked() ? linkA : [])).map((c) => row(c, 1001));
    const bRows = (connsB ?? (isLinked() ? linkB : [])).map((c) => row(c, 1002));
    return [...aRows, ...bRows].join('\n');
  };
  const resource = (name, cfg) => ({
    closed: false, name, imageId: IMAGE_ID, linuxPid: name === 'A' ? 1001 : 1002, containerName: `meepcoin-private-${name === 'A' ? 'a' : 'b'}${'0'.repeat(15)}`,
    config: cfg, beginClose() {}, async close() { this.closed = true; }, async forceClose() { this.closed = true; },
    async observeSocketTable() { return socketTable(); },
  });
  return { a, aTransport, bTransport, bLog, resource };
}

/** THE ONLY WAY THIS FILE BUILDS A PAIRED CONTEXT: every live seam injected, clock and sleep too. */
async function buildScriptedPair(opts = {}, { failB = false, ownLog = [] } = {}) {
  const net = inMemoryPair(opts);
  opts.onNetwork?.(net);
  const natural = opts.naturalDifficulty === true;
  const aConfig = natural ? { ...PEER_A, profile: 'private-exclusive-peer-natural', fixedDifficulty: undefined } : PEER_A;
  const bConfig = natural ? { ...PEER_B, profile: 'private-exclusive-peer-natural', fixedDifficulty: undefined } : PEER_B;
  const clock = { ms: opts.initialMs ?? 1_000_000 };
  const counts = { wasm: 0, native: 0 };
  const converterLog = { launches: [], converted: [], events: [] };
  // A fake canonical conversion still has to make distinct personalized full blocks produce
  // distinct hashing contexts. Preserve the exact header, and derive one stand-in merkle-root byte
  // from the full block. Production uses the owned native converter; this is only a deterministic
  // non-live test seam.
  const converter = scriptedConverterResource(converterLog, {
    ...(opts.converterOptions ?? {}),
    convertedHex: (fullHex) => {
      const out = hexToBlob(ROW.block_hashing_blob);
      const headerEnd = findNonceOffset(out).offset + 4;
      const full = hexToBlob(fullHex);
      let folded = 0;
      for (const byte of full) folded = (folded + byte) & 0xff;
      out[headerEnd] = folded;
      return blobToHex(out);
    },
  });
  const extraNonces = opts.extraNonces ?? ['01'.repeat(16)];
  let extraNonceIndex = 0;
  const built = await buildRealDaemonMode({
    daemon: aConfig,
    peer: { daemon: bConfig },
    ...(natural ? { expectedGenesisTimestamp: Object.hasOwn(opts, 'expectedGenesisTimestamp')
      ? opts.expectedGenesisTimestamp : 1785283200,
    expectedGenesisHash: Object.hasOwn(opts, 'expectedGenesisHash') ? opts.expectedGenesisHash : PREV } : {}),
    ...(Object.hasOwn(opts, 'maxGenesisAgeSeconds') ? { maxGenesisAgeSeconds: opts.maxGenesisAgeSeconds } : {}),
    sequenceBlocks: opts.sequenceBlocks ?? 1,
    refreshWindows: opts.refreshWindows ?? 1,
    personalizeTemplates: opts.personalizeTemplates ?? false,
    now: () => clock.ms,
    sleep: async (ms) => { clock.ms += ms; opts.onSleep?.(); },
    signal: opts.signal ?? null,
    peerLinkTimeoutMs: opts.peerLinkTimeoutMs ?? 60_000,
    ownResource: (label, r) => ownLog.push({ label, r }),
    startDaemon: async ({ config, isRpcReady }) => {
      if (failB && config.rpcPort === PEER_B.rpcPort) throw new Error('daemon B failed to start');
      await isRpcReady();
      return net.resource(config.rpcPort === PEER_A.rpcPort ? 'A' : 'B', config);
    },
    makeTransport: (endpoint) => (endpoint.includes(`:${PEER_B.rpcPort}/`) ? net.bTransport : net.aTransport),
    makeVerifier: async () => scriptedVerifier(counts, hexToBlob(PAIR_POW)),
    launchConverter: (config) => { converterLog.launches.push(config); return converter; },
    makeExtraNonceAllocator: () => ({
      reserveSize: 16,
      issue() {
        const value = extraNonces[extraNonceIndex];
        extraNonceIndex += 1;
        if (value === undefined) throw new Error('scripted extra-nonce allocator exhausted');
        return value;
      },
    }),
  });
  const sim = createSimulationContext({ ...built,
    profile: natural ? REAL_P2P_NATURAL_PROFILE : REAL_P2P_PROFILE });
  return {
    built, sim, net, clock, counts, ownLog, converterLog, converter,
    get extraNonceIssues() { return extraNonceIndex; },
  };
}

const WRITE_METHODS = ['submit_block', 'calc_pow', 'get_block_template'];

test('PAIR SEQUENCE: the observer tip source refuses an orphan-marked last header', async () => {
  // Build consumes three A-side last-header reads (shared genesis, template parent and the
  // post-conversion publication fence). The separate observer client performs the fourth, which
  // this scripted daemon marks orphaned.
  const { built } = await buildScriptedPair({ sequenceBlocks: 2, aOrphanTopAfter: 4 });
  await assert.rejects(
    built.tipSource.readTip(),
    (err) => err?.code === 'tip_not_canonical' && /orphaned/.test(err.message),
  );
  assert.deepEqual(built.tipSource.counts, { get_last_block_header: 1 });
});

test('PAIR REFRESH: every issuance consumes distinct server-owned work through the same converter', async () => {
  const firstExtraNonce = '11'.repeat(16);
  const secondExtraNonce = '22'.repeat(16);
  const r = await buildScriptedPair({
    personalizeTemplates: true,
    refreshWindows: 2,
    extraNonces: [firstExtraNonce, secondExtraNonce],
  });

  const next = await r.built.refresh.issueRefresh();
  assert.equal(r.converterLog.launches.length, 1, 'a refresh started another converter owner');
  assert.deepEqual(r.net.a.log.templateReserveSizes, [16, 16]);
  assert.equal(r.converterLog.converted.length, 2);
  assert.notEqual(r.converterLog.converted[0], r.converterLog.converted[1]);

  const firstOffset = r.built.templateFacts.reservedOffset * 2;
  const nextOffset = next.templateFacts.reservedOffset * 2;
  assert.equal(r.converterLog.converted[0].slice(firstOffset, firstOffset + 32), firstExtraNonce);
  assert.equal(r.converterLog.converted[1].slice(nextOffset, nextOffset + 32), secondExtraNonce);
  assert.notEqual(r.built.templateFacts.extraNonceDigest, next.templateFacts.extraNonceDigest);
  assert.notEqual(r.built.job.issuanceId, next.job.issuanceId);
  assert.notEqual(r.built.job.jobId, next.job.jobId);
  assert.notEqual(r.built.job.contentDigest, next.job.contentDigest);
  assert.notEqual(r.built.job.hashingTemplateHex, next.job.hashingTemplateHex);
  assert.notEqual(r.built.recordedContext.templateHex, next.context.templateHex);
  assert.deepEqual(
    Object.keys(r.built.personalizedWorkIssuer).sort(),
    ['issue', 'reserveSize'],
    'the server-only issuer exposed an allocator, converter or raw extra nonce',
  );
  assert.equal(r.built.personalizedWorkIssuer.reserveSize, 16);
  assert.equal(next.templateFacts.personalized, true);
});

test('PAIR PERSONALIZED SOURCE: initial work is lent once and later same-tip work is serialized through one owner', async () => {
  let conversionCalls = 0;
  let activeConversions = 0;
  let maxActiveConversions = 0;
  let announceSecond;
  let releaseSecond;
  const secondStarted = new Promise((resolve) => { announceSecond = resolve; });
  const secondGate = new Promise((resolve) => { releaseSecond = resolve; });
  const r = await buildScriptedPair({
    personalizeTemplates: true,
    extraNonces: ['11'.repeat(16), '22'.repeat(16), '33'.repeat(16)],
    converterOptions: {
      async beforeConvert() {
        conversionCalls += 1;
        if (conversionCalls === 1) return; // startup's already-fenced first job
        activeConversions += 1;
        maxActiveConversions = Math.max(maxActiveConversions, activeConversions);
        if (conversionCalls === 2) {
          announceSecond();
          await secondGate;
        }
        activeConversions -= 1;
      },
    },
  });
  const source = r.built.serializedPersonalizedTemplateIssuer;
  assert.deepEqual(Object.keys(source), ['issue']);

  const first = await source.issue();
  assert.equal(first, Object.freeze(first));
  assert.equal(first.job, r.built.job);
  assert.equal(r.converterLog.launches.length, 1);
  assert.equal(r.converterLog.converted.length, 1, 'lending the initial job converted it again');

  const secondPromise = source.issue();
  const thirdPromise = source.issue();
  await secondStarted;
  await Promise.resolve();
  assert.equal(activeConversions, 1);
  assert.equal(conversionCalls, 2, 'the queued third issuance entered conversion concurrently');
  releaseSecond();
  const [second, third] = await Promise.all([secondPromise, thirdPromise]);

  assert.equal(maxActiveConversions, 1);
  assert.equal(conversionCalls, 3);
  assert.equal(r.converterLog.launches.length, 1, 'serialized issuance launched another converter');
  assert.deepEqual(r.net.a.log.templateReserveSizes, [16, 16, 16]);
  assert.deepEqual(
    [first.job.height.toString(), second.job.height.toString(), third.job.height.toString()],
    ['1', '1', '1'],
  );
  assert.deepEqual(
    [first.canonical.prevHashHex, second.canonical.prevHashHex, third.canonical.prevHashHex],
    [PREV, PREV, PREV],
  );
  assert.equal(new Set([first.job.jobId, second.job.jobId, third.job.jobId]).size, 3);
  assert.equal(new Set([first.job.contentDigest, second.job.contentDigest, third.job.contentDigest]).size, 3);
});

test('PAIR PERSONALIZED SOURCE: cancellation is fail-closed before lending, after queue wait and before return', async () => {
  const r = await buildScriptedPair({
    personalizeTemplates: true,
    extraNonces: ['11'.repeat(16), '22'.repeat(16)],
  });
  const source = r.built.serializedPersonalizedTemplateIssuer;
  await assert.rejects(
    source.issue({ stillWanted: () => false }),
    (error) => error?.code === 'personalized_issue_cancelled',
  );
  assert.equal(r.converterLog.converted.length, 1);

  let checks = 0;
  await assert.rejects(
    source.issue({ stillWanted: () => { checks += 1; return checks < 3; } }),
    (error) => error?.code === 'personalized_issue_cancelled',
  );
  assert.equal(checks, 3);
  assert.equal(r.converterLog.converted.length, 1, 'the cancelled initial lend minted replacement work');

  const first = await source.issue();
  assert.equal(first.job, r.built.job, 'a cancelled lend consumed the initial job');
  assert.equal(r.converterLog.converted.length, 1);
});

test('PAIR PERSONALIZED SOURCE: pending overflow is cheap and never reaches template or conversion work', async () => {
  let conversionCalls = 0;
  let announceBlocked;
  let releaseBlocked;
  const blocked = new Promise((resolve) => { announceBlocked = resolve; });
  const gate = new Promise((resolve) => { releaseBlocked = resolve; });
  const r = await buildScriptedPair({
    personalizeTemplates: true,
    extraNonces: ['11'.repeat(16), '22'.repeat(16), '33'.repeat(16)],
    converterOptions: {
      async beforeConvert() {
        conversionCalls += 1;
        if (conversionCalls === 2) {
          announceBlocked();
          await gate;
        }
      },
    },
  });
  const source = r.built.serializedPersonalizedTemplateIssuer;
  await source.issue(); // initial lend; later calls must fetch and personalize
  const active = source.issue();
  await blocked;
  const queued = source.issue();
  const templatesBeforeOverflow = r.net.a.log.templateReserveSizes.length;
  const conversionsBeforeOverflow = conversionCalls;
  const allocationsBeforeOverflow = r.extraNonceIssues;

  await assert.rejects(
    source.issue(),
    (error) => error?.code === 'personalized_issue_queue_full',
  );
  assert.equal(r.net.a.log.templateReserveSizes.length, templatesBeforeOverflow);
  assert.equal(conversionCalls, conversionsBeforeOverflow);
  assert.equal(r.extraNonceIssues, allocationsBeforeOverflow);
  assert.equal(r.converterLog.converted.length, 1, 'overflow allocated or completed another conversion');

  releaseBlocked();
  await Promise.all([active, queued]);
  assert.deepEqual(r.net.a.log.templateReserveSizes, [16, 16, 16]);
  assert.equal(conversionCalls, 3);
});

test('PAIR PERSONALIZED SOURCE: lifetime admission stops at 32 contexts with zero overflow work', async () => {
  const extraNonces = Array.from({ length: 32 }, (_, i) => (i + 1).toString(16).padStart(2, '0').repeat(16));
  const r = await buildScriptedPair({ personalizeTemplates: true, extraNonces });
  const source = r.built.serializedPersonalizedTemplateIssuer;
  const issued = [];
  for (let i = 0; i < 32; i += 1) issued.push(await source.issue());

  assert.equal(issued.length, 32);
  assert.equal(new Set(issued.map((entry) => entry.job.jobId)).size, 32);
  assert.equal(new Set(issued.map((entry) => entry.job.contentDigest)).size, 32);
  assert.equal(r.net.a.log.templateReserveSizes.length, 32);
  assert.equal(r.converterLog.converted.length, 32);
  assert.equal(r.extraNonceIssues, 32);
  assert.equal(r.built.rpcAudit.rawDropped, 0);
  assert.ok(r.built.rpcAudit.raw.length <= r.built.rpcAudit.rawLimit);
  const templatesBeforeOverflow = r.net.a.log.templateReserveSizes.length;
  const conversionsBeforeOverflow = r.converterLog.converted.length;
  const allocationsBeforeOverflow = r.extraNonceIssues;

  await assert.rejects(
    source.issue(),
    (error) => error?.code === 'personalized_issue_exhausted',
  );
  assert.equal(r.net.a.log.templateReserveSizes.length, templatesBeforeOverflow);
  assert.equal(r.converterLog.converted.length, conversionsBeforeOverflow);
  assert.equal(r.extraNonceIssues, allocationsBeforeOverflow);
  assert.equal(r.built.rpcAudit.rawDropped, 0);
});

test('SERIALIZED PERSONALIZED SOURCE: unavailable without personalized mode and rejects open options', async () => {
  const plain = await buildScriptedPair();
  assert.equal(plain.built.serializedPersonalizedTemplateIssuer, null);

  const personalized = await buildScriptedPair({ personalizeTemplates: true });
  await assert.rejects(
    personalized.built.serializedPersonalizedTemplateIssuer.issue({ hidden: true }),
    (error) => error?.code === 'bad_config',
  );
  await assert.rejects(
    personalized.built.serializedPersonalizedTemplateIssuer.issue({ stillWanted: true }),
    (error) => error?.code === 'bad_config',
  );
});

test('SERIALIZED PERSONALIZED SOURCE: only the personalized one-height one-window profile exposes it', async () => {
  const oneShot = await buildScriptedPair({ personalizeTemplates: true });
  assert.deepEqual(Object.keys(oneShot.built.serializedPersonalizedTemplateIssuer), ['issue']);
  assert.equal(oneShot.built.rpcAudit.rawDropped, 0);
  assert.ok(oneShot.built.rpcAudit.raw.length <= oneShot.built.rpcAudit.rawLimit);

  for (const [name, options] of [
    ['sequence', { sequenceBlocks: 2 }],
    ['refresh', { refreshWindows: 2 }],
    ['composed sequence and refresh', { sequenceBlocks: 2, refreshWindows: 2 }],
  ]) {
    const r = await buildScriptedPair({ personalizeTemplates: true, ...options });
    assert.equal(r.built.serializedPersonalizedTemplateIssuer, null, name);
    assert.equal(r.built.rpcAudit.rawDropped, 0, `${name}: raw evidence was dropped during startup`);
    assert.ok(r.built.rpcAudit.raw.length <= r.built.rpcAudit.rawLimit, `${name}: raw evidence exceeded its bound`);
    assert.equal(r.net.a.log.templateReserveSizes.length, 1, `${name}: capability gating issued extra work`);
    assert.equal(r.extraNonceIssues, 1, `${name}: capability gating consumed an extra allocation`);
    assert.equal(r.converterLog.converted.length, 1, `${name}: capability gating converted extra work`);
  }
});

test('PAIR: both daemons owned, same image and genesis, a proved loopback link, then ONE template from A at difficulty 500', async () => {
  const ownLog = [];
  const { built, sim, net } = await buildScriptedPair({}, { ownLog });
  assert.deepEqual(ownLog.map((o) => o.label), ['meepcoind A', 'meepcoind B']);
  assert.equal(sim.job.difficulty, 500n);
  assert.equal(built.templateFacts.difficulty, '500');
  assert.equal(built.templateFacts.height, '1');
  assert.equal(built.templateFacts.prevHashHex, PREV);
  assert.equal(built.peer.genesis.hash, PREV);
  assert.ok(built.peer.linkObservations.length >= 2, 'the link was not waited for');
  assert.equal(built.peer.linkObservations.at(-1).linked, true);
  assert.equal(net.a.log.methods.filter((m) => m === 'get_block_template').length, 1);
  assert.equal(net.bLog.methods.some((m) => WRITE_METHODS.includes(m)), false, 'a write reached daemon B');
  // Raw evidence is kept from the template onwards: the exact template reply with both blobs.
  const rawTpl = built.rpcAudit.raw.find((r) => r.method === 'get_block_template');
  assert.ok(rawTpl.responseText.includes(ROW.block_hashing_blob) && rawTpl.responseText.includes(ROW.full_block_blob));
  assert.equal(sim.profile, REAL_P2P_PROFILE);
});

test('NATURAL PAIR: a non-500 daemon target is accepted and disclosed without a fixed-target claim', async () => {
  const { built, sim, net } = await buildScriptedPair({ naturalDifficulty: true, wide: '0x384' });
  assert.equal(built.naturalDifficulty, true);
  assert.equal(sim.job.difficulty, 900n);
  assert.equal(built.templateFacts.difficulty, '900');
  assert.equal(sim.profile, REAL_P2P_NATURAL_PROFILE);
  assert.equal(built.peer.genesis.timestamp, 1785283200);
  assert.match(sim.profile.helloNotice, /No fixed-difficulty option is set/);
  assert.equal(sim.profile.labels.some((label) => /FIXED TEST DIFFICULTY 500/.test(label)), false);
  assert.equal(net.a.log.methods.filter((m) => m === 'get_block_template').length, 1);
  assert.equal(net.bLog.methods.some((m) => WRITE_METHODS.includes(m)), false);
});

test('NATURAL PAIR: missing or mismatched daemon-read genesis time refuses before a template', async () => {
  for (const opts of [
    { genesisTimestampA: null, genesisTimestampB: null },
    { genesisTimestampA: 1785283200, genesisTimestampB: null },
    { genesisTimestampA: 1785283200, genesisTimestampB: 1785283201 },
  ]) {
    const ownLog = [];
    await assert.rejects(buildScriptedPair({ naturalDifficulty: true, ...opts }, { ownLog }),
      (e) => e.code === 'genesis_timestamp_unverified');
    assert.deepEqual(ownLog.map((o) => o.label), ['meepcoind A', 'meepcoind B']);
  }
});

test('NATURAL PAIR: a valid but unexpected genesis time refuses before a template', async () => {
  const ownLog = [];
  await assert.rejects(buildScriptedPair({ naturalDifficulty: true,
    expectedGenesisTimestamp: 1785283201 }, { ownLog }),
  (e) => e.code === 'genesis_timestamp_mismatch');
  assert.deepEqual(ownLog.map((o) => o.label), ['meepcoind A', 'meepcoind B']);
});

test('NATURAL PAIR: a valid but unexpected genesis hash refuses before a template', async () => {
  const ownLog = [];
  await assert.rejects(buildScriptedPair({ naturalDifficulty: true,
    expectedGenesisHash: 'a'.repeat(64) }, { ownLog }),
  (e) => e.code === 'genesis_hash_mismatch');
  assert.deepEqual(ownLog.map((o) => o.label), ['meepcoind A', 'meepcoind B']);
});

test('NATURAL PAIR: optional genesis age is checked before any template', async () => {
  const genesis = 1785283200;
  // The scripted P2P link consumes two 500 ms sleeps before the block-0 readback.
  for (const age of [0, 1800]) {
    const { net } = await buildScriptedPair({ naturalDifficulty: true,
      maxGenesisAgeSeconds: 1800, initialMs: (genesis + age - 1) * 1000 });
    assert.equal(net.a.log.methods.filter((m) => m === 'get_block_template').length, 1);
  }
  for (const age of [-1, 1801]) {
    let net;
    const ownLog = [];
    await assert.rejects(buildScriptedPair({ naturalDifficulty: true,
      maxGenesisAgeSeconds: 1800, initialMs: (genesis + age - 1) * 1000,
      onNetwork: (network) => { net = network; } }, { ownLog }),
    (e) => e.code === 'genesis_age_out_of_bounds');
    assert.deepEqual(ownLog.map((o) => o.label), ['meepcoind A', 'meepcoind B']);
    assert.equal(net.a.log.methods.includes('get_block_template'), false);
  }
  let net;
  await assert.rejects(buildScriptedPair({ naturalDifficulty: true,
    maxGenesisAgeSeconds: 1800, initialMs: NaN,
    onNetwork: (network) => { net = network; } }),
  (e) => e.code === 'genesis_age_unverified');
  assert.equal(net.a.log.methods.includes('get_block_template'), false);
});

test('NATURAL PAIR: malformed age limit is refused before daemon startup', async () => {
  for (const cap of [0, -1, 1.5, NaN, Infinity, '1800', Number.MAX_SAFE_INTEGER + 1]) {
    const ownLog = [];
    await assert.rejects(buildScriptedPair({ naturalDifficulty: true,
      maxGenesisAgeSeconds: cap }, { ownLog }),
    (e) => e.code === 'bad_config' && /maxGenesisAgeSeconds/.test(e.message));
    assert.deepEqual(ownLog, []);
  }
  const ownLog = [];
  await assert.rejects(buildScriptedPair({ maxGenesisAgeSeconds: 1800 }, { ownLog }),
    (e) => e.code === 'bad_config' && /maxGenesisAgeSeconds/.test(e.message));
  assert.deepEqual(ownLog, []);
});

test('NATURAL PAIR: missing expected genesis pin is refused before any daemon starts', async () => {
  const ownLog = [];
  await assert.rejects(buildScriptedPair({ naturalDifficulty: true,
    expectedGenesisTimestamp: null }, { ownLog }),
  (e) => e.code === 'bad_config' && /expectedGenesisTimestamp/.test(e.message));
  assert.deepEqual(ownLog, []);
  for (const hash of [null, 'A'.repeat(64), '0'.repeat(63)]) {
    const log = [];
    await assert.rejects(buildScriptedPair({ naturalDifficulty: true,
      expectedGenesisHash: hash }, { ownLog: log }),
    (e) => e.code === 'bad_config' && /expectedGenesisHash/.test(e.message));
    assert.deepEqual(log, []);
  }
});

test('PAIR: a mined candidate is submitted to A once, and B converges by reading only', async () => {
  const { built, sim, net, clock, counts } = await buildScriptedPair();
  const d = driver(sim, clock);
  await d.say({ type: 'client_hello', protocolVersion: 1 });
  assert.deepEqual(d.last('server_hello').labels, [...REAL_P2P_PROFILE.labels]);
  await d.say({ type: 'start_request', clientStartId: START_ID });
  const ready = d.last('mining_ready');
  await d.say({
    type: 'submit_real_candidate', clientStartId: START_ID, jobId: sim.job.jobId, issuanceId: sim.job.issuanceId,
    workerId: ready.workerId, runGeneration: ready.runGeneration, nonce: '0000002a',
  });
  const done = d.last('block_accepted');
  assert.ok(done, JSON.stringify(d.sent.map((m) => [m.type, m.reason])));
  assert.equal(done.nonce, 42);
  assert.deepEqual([counts.wasm, counts.native, sim.submissionDaemon.counters.calcPow, sim.submissionDaemon.counters.dispatchSubmission], [1, 1, 1, 1]);
  assert.equal(net.a.log.submitBodies.length, 1);
  assert.equal(sim.lastHashes.serverWasmHex, PAIR_POW);
  assert.equal(sim.lastHashes.nativeHelperHex, PAIR_POW);

  const p = await built.peer.awaitPropagation({ timeoutMs: 60_000, pollMs: 500 });
  assert.equal(p.converged, true, JSON.stringify(p.reason));
  assert.equal(p.bHeader.hash, p.aHeader.hash);
  assert.equal(p.bTop.hash, BLOCK_ID);
  assert.equal(p.bHeader.nonce, 42);
  assert.equal(net.bLog.methods.some((m) => WRITE_METHODS.includes(m)), false, 'a write reached daemon B');
  assert.deepEqual(Object.keys(built.peer.rpcCounts).sort().filter((m) => !['get_block_header_by_height', 'get_info', 'get_last_block_header'].includes(m)), []);
  // Application-path counters are distinct from total RPC traffic.
  assert.ok(built.rpcAudit.counts.get_last_block_header > sim.submissionDaemon.counters.topReadback);
});

test('PAIR: B that never receives the block is P2P_PROPAGATION_FAILED -- still with no write to B', async () => {
  const { built, sim, net, clock } = await buildScriptedPair({ neverPropagate: true });
  const d = driver(sim, clock);
  await d.say({ type: 'client_hello', protocolVersion: 1 });
  await d.say({ type: 'start_request', clientStartId: START_ID });
  const ready = d.last('mining_ready');
  await d.say({
    type: 'submit_real_candidate', clientStartId: START_ID, jobId: sim.job.jobId, issuanceId: sim.job.issuanceId,
    workerId: ready.workerId, runGeneration: ready.runGeneration, nonce: '00000007',
  });
  assert.ok(d.last('block_accepted'));
  const p = await built.peer.awaitPropagation({ timeoutMs: 5_000, pollMs: 500 });
  assert.equal(p.converged, false);
  assert.equal(p.reason, 'P2P_PROPAGATION_FAILED');
  assert.equal(net.bLog.methods.some((m) => WRITE_METHODS.includes(m)), false);
  assert.equal(net.a.log.submitBodies.length, 1, 'the block was resubmitted');

  const mism = await buildScriptedPair({ bHeaderOverride: { pow_hash: 'ee'.repeat(32) } });
  const d2 = driver(mism.sim, mism.clock);
  await d2.say({ type: 'client_hello', protocolVersion: 1 });
  await d2.say({ type: 'start_request', clientStartId: START_ID });
  const r2 = d2.last('mining_ready');
  await d2.say({
    type: 'submit_real_candidate', clientStartId: START_ID, jobId: mism.sim.job.jobId, issuanceId: mism.sim.job.issuanceId,
    workerId: r2.workerId, runGeneration: r2.runGeneration, nonce: '00000007',
  });
  const p2 = await mism.built.peer.awaitPropagation({ timeoutMs: 5_000, pollMs: 500 });
  assert.equal(p2.converged, false, 'a different pow_hash on B was accepted as convergence');
});

test('PAIR: difficulty other than 500, another genesis, a non-loopback or foreign connection, or no link, stops before any template use', async () => {
  for (const [name, opts, code] of [
    ['difficulty 1', { wide: '0x1' }, 'template_difficulty'],
    ['difficulty 501', { wide: '0x1f5' }, 'template_difficulty'],
    ['other genesis', { genesisB: 'f'.repeat(64) }, 'genesis_mismatch'],
    ['LAN connection', { connsA: [{ local: '192.168.1.5:41000', peer: '192.168.1.9:28590' }] }, 'unexpected_connection'],
    ['foreign peer', { connsA: [{ local: '127.0.0.1:41000', peer: '127.0.0.1:18080' }] }, 'unexpected_connection'],
    ['no link', { linkAfter: 1e9, peerLinkTimeoutMs: 3_000 }, 'peer_link_timeout'],
  ]) {
    const ownLog = [];
    let err = null;
    try { await buildScriptedPair(opts, { ownLog }); } catch (e) { err = e; }
    assert.equal(err?.code, code, name);
    assert.deepEqual(ownLog.map((o) => o.label), ['meepcoind A', 'meepcoind B'], `${name}: a daemon was not owned`);
  }
});

test('PAIR: an aborted startup stops at the next step boundary -- during the link wait -- with both daemons owned', async () => {
  const ac = new AbortController();
  let sleeps = 0;
  const ownLog = [];
  let err = null;
  try {
    await buildScriptedPair({ linkAfter: 1e9, signal: ac.signal, onSleep: () => { sleeps += 1; if (sleeps === 3) ac.abort(); } }, { ownLog });
  } catch (e) { err = e; }
  assert.equal(err?.code, 'startup_cancelled');
  assert.equal(sleeps, 3, 'the link wait carried on after the abort');
  assert.deepEqual(ownLog.map((o) => o.label), ['meepcoind A', 'meepcoind B']);

  // Already aborted: nothing is started at all.
  const pre = new AbortController();
  pre.abort();
  const none = [];
  await assert.rejects(buildScriptedPair({ signal: pre.signal }, { ownLog: none }), (e) => e.code === 'startup_cancelled');
  assert.deepEqual(none, []);
});

test('PAIR: a mis-paired configuration is refused before any daemon starts', async () => {
  for (const [name, a, b] of [
    ['B names itself', PEER_A, { ...PEER_B, exclusivePeerP2pPort: PEER_B.rpcPort }],
    ['not cross-referenced', PEER_A, { ...PEER_B, exclusivePeerP2pPort: 28999 }],
    ['different image pin', PEER_A, { ...PEER_B, expectedImageId: `sha256:${'e'.repeat(64)}` }],
    ['shared run dir', PEER_A, { ...PEER_B, runDir: PEER_A.runDir }],
    ['offline profile', { ...PEER_A, profile: 'offline-single' }, PEER_B],
    ['difficulty 1', { ...PEER_A, fixedDifficulty: 1 }, { ...PEER_B, fixedDifficulty: 1 }],
  ]) {
    let started = 0;
    await assert.rejects(buildRealDaemonMode({
      daemon: a, peer: { daemon: b }, ownResource: () => {},
      startDaemon: async () => { started += 1; throw new Error('must not start'); },
      makeTransport: () => async () => '',
      makeVerifier: async () => { throw new Error('must not build'); },
    }), (e) => e.code === 'bad_pair_config', name);
    assert.equal(started, 0, name);
  }
});

test('PAIR: the B client is read-only below the adapter -- a write method never reaches its transport', async () => {
  let entered = 0;
  const audited = auditedTransport(async () => { entered += 1; return '{}'; }, { allowed: ['get_info', 'get_last_block_header', 'get_block_header_by_height'] });
  for (const method of ['submit_block', 'calc_pow', 'get_block_template']) {
    assert.throws(() => audited.transport({ method, body: '{}', handoff() {} }), (e) => e.code === 'method_not_allowed', method);
  }
  assert.equal(entered, 0);
  assert.deepEqual(audited.counts, {});
});

test('PAIR: if daemon B fails to start, the pool closes and awaits the already-owned daemon A before any listener', async () => {
  const ownLog = [];
  let err = null;
  try {
    await startDevPool({
      mode: REAL_DAEMON_MODE,
      port: 0,
      realDaemon: { daemon: PEER_A, peer: { daemon: PEER_B } },
      realDaemonFactory: async ({ ownResource }) => buildScriptedPair({}, {
        failB: true,
        ownLog: { push: (entry) => { ownLog.push(entry); ownResource(entry.label, entry.r); } },
      }),
    });
  } catch (e) { err = e; }
  assert.equal(err?.message, 'daemon B failed to start');
  assert.deepEqual(ownLog.map((o) => o.label), ['meepcoind A']);
  assert.equal(ownLog[0].r.closed, true, 'daemon A was left running');
  assert.equal(err.retainedResources, undefined);
});

test('GUARD: no test in this file can reach the real daemon, transport, verifier or a listener', () => {
  const code = readFileSync(fileURLToPath(import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((line) => line.replace(/\/\/.*$/, '').replace(/'[^']*'/g, "''"))
    .join('\n');
  const builds = code.match(/buildRealDaemonMode\(/g) ?? [];
  const injectedBuilds = code.match(/buildRealDaemonMode\(\{[\s\S]*?startDaemon:[\s\S]*?makeTransport:[\s\S]*?makeVerifier:/g) ?? [];
  assert.equal(builds.length, injectedBuilds.length, 'a real-daemon build without all three seams injected');
  // startDevPool is reached only in ways that stop before listen(): no realDaemon option, or a
  // factory that throws.
  const pools = code.match(/startDevPool\(/g) ?? [];
  assert.equal(pools.length, 6);
  assert.equal(/realDaemonFactory: async/.test(code), true);
});
