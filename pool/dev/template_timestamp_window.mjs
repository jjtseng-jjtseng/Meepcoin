// Read-only chain-history receipt for one daemon-issued template. The private
// fresh-chain miner uses it, but it is NOT a timestamp-validity oracle: the
// daemon's future-time bound depends on its clock, and the chain can move
// after this receipt is returned.

import { PREV_ID_BYTES, blobToHex, findNonceOffset, hexToBlob } from './block_blob.mjs';

const HEX64 = /^[0-9a-f]{64}$/;
const WINDOW = 60;

export class TemplateWindowError extends Error {
  constructor(reason, message) {
    super(message);
    this.name = 'TemplateWindowError';
    this.reason = reason;
  }
}

function refuse(reason, message) {
  throw new TemplateWindowError(reason, message);
}

function checkAbort(signal) {
  if (signal?.aborted) refuse('aborted', 'timestamp-window read was aborted');
}

function checkedHeader(header, height) {
  if (header === null || typeof header !== 'object'
    || header.height !== height || typeof header.hash !== 'string'
    || !HEX64.test(header.hash) || typeof header.prevHash !== 'string'
    || !HEX64.test(header.prevHash) || header.orphanStatus !== false
    || !Number.isSafeInteger(header.timestamp) || header.timestamp < 0) {
    refuse('bad_header', `canonical header ${height} is missing or malformed`);
  }
  return Object.freeze({
    height, hash: header.hash, prevHash: header.prevHash, timestamp: header.timestamp,
  });
}

function templateParent(template) {
  if (template === null || typeof template !== 'object'
    || !Number.isSafeInteger(template.height) || template.height < 1
    || typeof template.prevHashHex !== 'string' || !HEX64.test(template.prevHashHex)) {
    refuse('bad_template', 'template height or previous hash is malformed');
  }
  const hashing = hexToBlob(template.blockhashingBlobHex, { what: 'hashing blob' });
  const full = hexToBlob(template.blocktemplateBlobHex, { what: 'full block blob' });
  const h = findNonceOffset(hashing);
  const f = findNonceOffset(full);
  if (h.offset !== f.offset || h.timestamp !== f.timestamp) {
    refuse('template_mismatch', 'the two template blobs have different headers');
  }
  for (let i = 0; i < h.offset; i++) {
    if (hashing[i] !== full[i]) {
      refuse('template_mismatch', 'the two template blobs have different headers');
    }
  }
  const parent = blobToHex(hashing.subarray(h.offset - PREV_ID_BYTES, h.offset));
  if (parent !== template.prevHashHex) {
    refuse('template_mismatch', 'template previous hash differs from both block blobs');
  }
  return parent;
}

function median(timestamps) {
  const ordered = timestamps.map(BigInt).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const mid = ordered.length >> 1;
  return Number(ordered.length % 2
    ? ordered[mid]
    : (ordered[mid - 1] + ordered[mid]) / 2n);
}

/**
 * Bind a template to its canonical predecessor window on ONE daemon.
 *
 * RPC must be the strict daemon_rpc adapter. The receipt is immutable, includes
 * the actual headers rather than only their median, and is limited to 60 reads.
 * A before/after tip fence rejects a moving chain. Neither this fence nor a
 * local median proves that another daemon has the same history or clock.
 */
export async function readTemplateTimestampWindow({ rpc, template, signal } = {}) {
  if (!rpc || typeof rpc.getLastBlockHeader !== 'function'
    || typeof rpc.getBlockHeaderByHeight !== 'function') {
    refuse('bad_rpc', 'a read-only daemon RPC adapter is required');
  }
  const parentHash = templateParent(template);
  const parentHeight = template.height - 1;
  checkAbort(signal);
  const firstRaw = await rpc.getLastBlockHeader({ fillPowHash: false });
  // A valid, different canonical tip height makes this template stale. Keep a
  // malformed RPC response distinct from that ordinary chain movement.
  if (Number.isSafeInteger(firstRaw?.height) && firstRaw.height >= 0
    && firstRaw.height !== parentHeight) {
    checkedHeader(firstRaw, firstRaw.height);
    refuse('template_tip_mismatch', 'template parent height is not the canonical tip');
  }
  const first = checkedHeader(firstRaw, parentHeight);
  checkAbort(signal);
  if (first.hash !== parentHash) {
    refuse('template_tip_mismatch', 'template parent is not the canonical tip');
  }

  const startHeight = Math.max(0, template.height - WINDOW);
  const headers = [];
  for (let height = startHeight; height <= parentHeight; height++) {
    checkAbort(signal);
    const header = checkedHeader(
      await rpc.getBlockHeaderByHeight(String(height), { fillPowHash: false }), height,
    );
    checkAbort(signal);
    if (headers.length && header.prevHash !== headers.at(-1).hash) {
      refuse('history_unlinked', `header ${height} does not link to its predecessor`);
    }
    headers.push(header);
  }
  const last = headers.at(-1);
  if (last.hash !== first.hash || last.prevHash !== first.prevHash
    || last.timestamp !== first.timestamp) {
    refuse('history_tip_mismatch', 'height readback differs from the initial canonical tip');
  }

  checkAbort(signal);
  const afterRaw = await rpc.getLastBlockHeader({ fillPowHash: false });
  checkAbort(signal);
  if (afterRaw?.height !== parentHeight) {
    refuse('tip_changed', 'canonical tip height changed while reading the timestamp window');
  }
  const after = checkedHeader(afterRaw, parentHeight);
  if (after.hash !== first.hash || after.prevHash !== first.prevHash
    || after.timestamp !== first.timestamp) {
    refuse('tip_changed', 'canonical tip changed while reading the timestamp window');
  }
  const timestamps = Object.freeze(headers.map((header) => header.timestamp));
  return Object.freeze({
    candidateHeight: template.height,
    parentHeight,
    parentHash,
    startHeight,
    headers: Object.freeze(headers),
    timestamps,
    medianTimestamp: median(timestamps),
  });
}
