// One worker's actual-hash-counting mining engine for the private fresh-chain experiment.
// No daemon is launched here. The owning runner supplies a loopback RPC adapter and stop signal.

import { blobToHex, hexToBlob, patchNonce, patchTimestamp, findNonceOffset } from '../pool/dev/block_blob.mjs';
import { createRealTemplateJob, fullBlockBlobOf, hashingContextFor, hashingTemplateOf,
  targetBytesOf } from '../pool/dev/real_template.mjs';
import { readTemplateTimestampWindow, TemplateWindowError } from '../pool/dev/template_timestamp_window.mjs';
import { submissionProofs } from '../pool/dev/daemon_rpc.mjs';
import { REAL_COINBASE_ADDRESS } from '../pool/dev/real_daemon_mode.mjs';
import { meetsTargetLE, bytesToHex } from '../web-miner/lib/shared/target.js';
import { createV2HasherForContext } from '../web-miner/lib/shared/wasm_hasher.js';
import { ASSIGNED_HASHES_PER_SECOND, REACHABILITY_MODES, createHashSchedule,
  thirdTimestampDecision } from './fresh_reachability_core.mjs';

const TEMPLATE_LIFETIME_MS = 20_000;
const TIP_POLL_MS = 3_000;
const MAX_CONSECUTIVE_WINDOW_STALES = 8;
const NONCE_BASE = Object.freeze({ h1: 0, h2: 1_000_000_000, third: 3_000_000_000 });

function fail(message) { throw new Error(`fresh miner: ${message}`); }
function waiting(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function sameTip(tip, template) {
  return tip.height === template.height - 1 && tip.hash === template.prevHashHex
    && tip.orphanStatus === false;
}

export function roleConfig(role) {
  if (!Object.hasOwn(NONCE_BASE, role)) fail('unknown miner role');
  return Object.freeze({ role, nonceBase: NONCE_BASE[role], assignedRate: role === 'third'
    ? ASSIGNED_HASHES_PER_SECOND.third : ASSIGNED_HASHES_PER_SECOND[role] });
}

export function prepareAppliedTemplate(template, decision = null) {
  if (!template || !Number.isSafeInteger(template.height) || template.height < 1
    || !/^[0-9a-f]{64}$/.test(template.prevHashHex ?? '')) fail('incomplete daemon template');
  const applied = decision?.appliedTimestamp;
  let hashingHex = template.blockhashingBlobHex;
  let fullHex = template.blocktemplateBlobHex;
  if (applied !== undefined && decision.appliedStrategy !== 'honest-template') {
    const hashing = patchTimestamp(hexToBlob(hashingHex), BigInt(applied)).blob;
    const full = patchTimestamp(hexToBlob(fullHex), BigInt(applied)).blob;
    hashingHex = blobToHex(hashing);
    fullHex = blobToHex(full);
  }
  const job = createRealTemplateJob({ height: template.height,
    wideDifficulty: template.wideDifficulty, seedHashHex: template.seedHashHex,
    seedHeight: template.seedHeight ?? undefined,
    blockhashingBlobHex: hashingHex, blocktemplateBlobHex: fullHex });
  const hashing = hashingTemplateOf(job);
  const full = fullBlockBlobOf(job);
  const offset = findNonceOffset(hashing).offset;
  if (blobToHex(hashing.subarray(offset - 32, offset)) !== template.prevHashHex) {
    fail('altered hashing blob parent differs from daemon template');
  }
  return Object.freeze({ job, hashing, full });
}

// A submission is one-use. An ambiguous transport outcome terminates the worker; never resend.
export async function submitFoundBlock({ rpc, job, nonce, localHashHex, onEvent, signal,
  readReceiver = null }) {
  if (signal?.aborted) return 'CANCELLED_BEFORE_HANDOFF';
  const proofs = submissionProofs(rpc);
  if (!proofs) fail('submission adapter provenance is unavailable');
  const hashBlobHex = blobToHex(patchNonce(hashingTemplateOf(job), nonce).blob);
  const daemonHash = await rpc.calcPow({ majorVersion: job.majorVersion, height: job.height.toString(),
    blockBlobHex: hashBlobHex, seedHashHex: job.seedHashHex });
  if (signal?.aborted) return 'CANCELLED_BEFORE_HANDOFF';
  if (daemonHash !== localHashHex) fail('Wasm and daemon disagree on candidate proof of work');
  const fullBlockHex = blobToHex(patchNonce(fullBlockBlobOf(job), nonce).blob);
  const before = await rpc.getLastBlockHeader({ fillPowHash: false });
  if (signal?.aborted) return 'CANCELLED_BEFORE_HANDOFF';
  const receiverPreSubmit = readReceiver === null ? null : await readReceiver();
  if (signal?.aborted) return 'CANCELLED_BEFORE_HANDOFF';
  const context = { height: Number(job.height), nonce, localHashHex, parentHash: before.hash,
    fullBlockHex, blockTemplateDigest: job.contentDigest, receiverPreSubmit };
  onEvent({ phase: 'FOUND_PRE_SUBMIT', ...context });
  if (before.height !== Number(job.height) - 1) {
    onEvent({ phase: 'STALE_PRE_SUBMIT', ...context, reason: 'height_changed' });
    return 'STALE';
  }
  // The job's parent is parsed from the actual hashing blob, not asserted from an unbound field.
  const hashBlob = hashingTemplateOf(job);
  const offset = findNonceOffset(hashBlob).offset;
  if (blobToHex(hashBlob.subarray(offset - 32, offset)) !== before.hash) {
    onEvent({ phase: 'STALE_PRE_SUBMIT', ...context, reason: 'parent_changed' });
    return 'STALE';
  }
  if (signal?.aborted) return 'CANCELLED_BEFORE_HANDOFF';
  const operation = {};
  const capability = rpc.prepareSubmission(fullBlockHex, operation);
  if (!proofs.capabilityFor(operation, capability, fullBlockHex)) fail('prepared block proof failed');
  if (signal?.aborted) return 'CANCELLED_BEFORE_HANDOFF';
  const handle = rpc.dispatchSubmission(capability);
  const record = proofs.dispatchFor(operation, handle);
  if (!record) fail('dispatch proof failed');
  const receipt = await handle.receipt;
  if (!proofs.receiptFor(record, receipt)) fail('submission handoff was not proven');
  onEvent({ phase: 'BLOCK_HANDED_OFF', height: Number(job.height), nonce,
    localHashHex, fullBlockHex, handedOffAtMs: receipt.handedOffAtMs });
  let answer;
  try { answer = await handle.outcome; }
  catch (error) {
    if (proofs.refusalFor(record, error)) {
      onEvent({ phase: 'BLOCK_REFUSED', height: Number(job.height), nonce,
        code: error.code ?? 'daemon_refusal', fullBlockHex });
      return 'REFUSED';
    }
    fail(`ambiguous submit outcome: ${error?.code ?? 'unknown'}`);
  }
  const observed = await rpc.getBlockHeaderByHeight(job.height.toString(), { fillPowHash: true });
  const canonical = observed.hash === answer.blockId && observed.orphanStatus === false
    && observed.nonce === nonce && observed.powHash === localHashHex;
  onEvent({ phase: 'BLOCK_ANSWER_AND_READBACK', height: Number(job.height), nonce,
    blockId: answer.blockId, observed, canonical, fullBlockHex });
  return canonical ? 'CANONICAL' : 'READBACK_UNCONFIRMED';
}

export async function runFreshMiner({ role, mode, rpc, moduleFactory, signal, onEvent,
  clock = () => Date.now(), sleep = waiting, createHasher = createV2HasherForContext,
  readWindow = readTemplateTimestampWindow, readReceiver = null } = {}) {
  const cfg = roleConfig(role);
  if (role === 'third' ? ![REACHABILITY_MODES.CONTROL, REACHABILITY_MODES.ATTACK].includes(mode)
    : mode !== REACHABILITY_MODES.HONEST) fail('role/mode combination is invalid');
  if (!rpc || typeof rpc.getBlockTemplate !== 'function' || typeof rpc.getLastBlockHeader !== 'function'
    || typeof onEvent !== 'function' || typeof moduleFactory !== 'function') fail('missing worker dependency');
  let nonce = cfg.nonceBase;
  let actualHashes = 0;
  let submissions = 0;
  let accepted = 0;
  let stale = 0;
  let refusals = 0;
  let consecutiveWindowStales = 0;
  let lastProgress = clock();
  const schedule = createHashSchedule({ startMs: clock(), ratePerSecond: cfg.assignedRate });
  onEvent({ phase: 'MINER_STARTED', role, mode, assignedRate: cfg.assignedRate,
    nonceBase: cfg.nonceBase, startMs: clock() });
  while (!signal?.aborted) {
    let template;
    try { template = await rpc.getBlockTemplate({ walletAddress: REAL_COINBASE_ADDRESS }); }
    catch (error) { if (signal?.aborted) break; throw error; }
    if (signal?.aborted) break;
    const tip = await rpc.getLastBlockHeader({ fillPowHash: false });
    if (!sameTip(tip, template)) { stale++; continue; }
    let decision = null;
    let window = null;
    if (role === 'third') {
      try { window = await readWindow({ rpc, template, signal }); }
      catch (error) {
        if (signal?.aborted) break;
        // A block may arrive during the read-only window RPCs. One such move
        // invalidates this template; repeated moves still hit the safety cap.
        if (error instanceof TemplateWindowError
          && (error.reason === 'tip_changed' || error.reason === 'template_tip_mismatch')) {
          if (++consecutiveWindowStales > MAX_CONSECUTIVE_WINDOW_STALES) throw error;
          stale++;
          onEvent({ phase: 'WINDOW_STALE', role, mode, height: template.height,
            parentHash: template.prevHashHex, reason: error.reason,
            consecutive: consecutiveWindowStales });
          continue; // fresh daemon template; the fixed hash schedule never catches up
        }
        throw error;
      }
      if (signal?.aborted) break;
      consecutiveWindowStales = 0;
      const templateTimestamp = Number(findNonceOffset(hexToBlob(template.blockhashingBlobHex)).timestamp);
      decision = thirdTimestampDecision({ mode, height: template.height,
        medianTimestamp: window.medianTimestamp, nowSeconds: Math.floor(clock() / 1000),
        templateTimestamp });
    }
    const { job } = prepareAppliedTemplate(template, decision);
    const hasher = await createHasher(moduleFactory, hashingContextFor(job));
    if (signal?.aborted) { hasher.free(); break; }
    const target = targetBytesOf(job);
    const preparedMs = clock();
    let nextTipPoll = preparedMs + TIP_POLL_MS;
    onEvent({ phase: 'TEMPLATE_READY', role, mode, height: template.height,
      parentHash: template.prevHashHex, difficulty: job.difficulty.toString(),
      templateTimestamp: findNonceOffset(hexToBlob(template.blockhashingBlobHex)).timestamp.toString(),
      decision, window, preparedMs, jobDigest: job.contentDigest });
    try {
      while (!signal?.aborted && clock() - preparedMs < TEMPLATE_LIFETIME_MS) {
        const now = clock();
        if (now >= nextTipPoll) {
          const current = await rpc.getLastBlockHeader({ fillPowHash: false });
          if (!sameTip(current, template)) { stale++; break; }
          nextTipPoll = clock() + TIP_POLL_MS;
        }
        const claim = schedule.claim(now);
        if (!claim.ready) { await sleep(Math.min(claim.waitMs, 100)); continue; }
        if (nonce > 0xffffffff) fail('assigned nonce domain exhausted');
        const useNonce = nonce++;
        const hash = hasher.hashOne(useNonce);
        actualHashes++;
        if (actualHashes === 1) onEvent({ phase: 'FIRST_HASH', role, mode, nonce: useNonce });
        if (meetsTargetLE(hash, target)) {
          submissions++;
          const outcome = await submitFoundBlock({ rpc, job, nonce: useNonce,
            localHashHex: bytesToHex(hash), onEvent, signal, readReceiver });
          if (outcome === 'CANONICAL') accepted++;
          else if (outcome === 'REFUSED') refusals++;
          else if (outcome !== 'CANCELLED_BEFORE_HANDOFF') stale++;
          break;
        }
        if (clock() - lastProgress >= 5000) {
          lastProgress = clock();
          onEvent({ phase: 'MINER_PROGRESS', role, mode, actualHashes,
            missedSlots: schedule.missedSlots, submissions, accepted, stale, refusals });
        }
        await sleep(0); // release the event loop; stop and RPC completions must remain responsive
      }
    } finally { hasher.free(); }
  }
  const summary = { role, mode, actualHashes, missedSlots: schedule.missedSlots,
    submissions, accepted, stale, refusals, assignedRate: cfg.assignedRate };
  onEvent({ phase: 'MINER_STOPPED', ...summary });
  return summary;
}
