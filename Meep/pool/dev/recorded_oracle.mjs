// The two PRETEND components of the recorded-template simulation.
//
// NEITHER OF THESE IS A REAL THING, AND NEITHER PRETENDS TO BE.
//
//   createRecordedOracle()  a lookup table over ONE committed vector row. It spawns no process,
//                           loads no library and computes no hash. The recorded-template simulation
//                           NO LONGER uses it as a native check -- the live local native helper does
//                           that -- and keeps only its bindTo(job) precondition, which proves the
//                           committed row describes this exact job before the mock daemon answers.
//
//   createMockDaemon()      stands in for the daemon RPC. It is an in-memory object with counters
//                           and exact expected inputs. It opens no socket, resolves no name and
//                           touches no chain. A "submission" here is a counter increment.
//
// BOTH ARE STRICT ON PURPOSE. They refuse any byte, context, nonce or blob they were not told to
// expect, because a permissive mock would let a real defect pass as a green run. Every refusal is a
// thrown error, never a quietly different answer.
//
// BOUND BEFORE THEY WILL WORK. The oracle used to answer on the nonce alone, so it would have
// returned the recorded hash for a job describing a DIFFERENT block, and the mock daemon would have
// worked whether or not the oracle was answering for the same context. Both now refuse every call
// until bindTo(job) has checked the height, seed hash, epoch key, nonce-zeroed template, nonce and
// expected hash against the job the run will actually use; the mock daemon additionally refuses to
// do anything while the oracle is unbound.
//
// THE MOCK'S SUBMIT PATH IS THE REAL ADAPTER. prepareSubmission() and dispatchSubmission() are
// daemon_rpc.mjs's own, running over an IN-MEMORY transport function that answers like a daemon
// holding this one block. So the capability, the handoff receipt and the dispatch record are the
// adapter's authenticated ones: the previous mock minted a lookalike `{ boundaryEntered, receipt }`
// object, and a lookalike is exactly what block_run now refuses to believe. There is still no
// socket, no DNS and no daemon; `transportCalls` (REAL transport) stays 0, and the in-memory
// function's invocations are counted separately as `inMemoryTransportCalls`.

import { blobToHex, hexToBlob, readNonce } from './block_blob.mjs';
import { hashingTemplateOf } from './real_template.mjs';
import { createDaemonRpc } from './daemon_rpc.mjs';

export class OracleMismatchError extends Error {
  constructor(what, expected, actual) {
    super(`recorded oracle: ${what} does not match the recorded vector`);
    this.name = 'OracleMismatchError';
    this.what = what;
    // Deliberately NOT the values: this message can reach a log, and the point of the oracle is
    // that it knows the answer. `what` names the field that disagreed.
    this.expectedLength = typeof expected === 'string' ? expected.length : null;
    this.actualLength = typeof actual === 'string' ? actual.length : null;
  }
}

export class OracleUnboundError extends Error {
  constructor(what) {
    super(`recorded oracle: ${what} before the oracle was bound to a job`);
    this.name = 'OracleUnboundError';
    this.what = what;
  }
}

/**
 * The MOCK NATIVE check.
 *
 * Given the one nonce the recorded row describes, it returns the recorded hash bytes. Given
 * anything else -- a different nonce, an unbound oracle, a job describing a different block -- it
 * throws.
 *
 * @param {object} row  a committed block_vectors_v16_devnet.json row
 */
export function createRecordedOracle(row) {
  const expectedNonce = row.nonce;
  const expectedHash = hexToBlob(row.expected_meephash_w_v2);
  let calls = 0;
  let bound = null;

  const context = Object.freeze({
    height: row.height,
    epochKeyHex: row.epoch_key,
    seedHashHex: row.delayed_seed_input,
    templateHex: row.blob_nonce_zeroed,
    nonce: expectedNonce,
    expectedHashHexLE: row.expected_meephash_w_v2,
  });

  return {
    kind: 'recorded-oracle',
    get calls() { return calls; },
    get bound() { return bound !== null; },
    /** The context this oracle will answer for, so a caller can assert it matches the job. */
    context,

    /**
     * BIND, AND CHECK EVERY FIELD THAT DECIDES WHAT THE ANSWER MEANS.
     *
     * The nonce-zeroed template is compared against the job's PRIVATE hashing template, not against
     * anything public, so a job whose public projection was edited cannot bind.
     */
    bindTo(job) {
      if (!job || job.kind !== 'real') throw new OracleMismatchError('job kind');
      if (String(job.height) !== String(context.height)) throw new OracleMismatchError('height');
      if (job.seedHashHex !== context.seedHashHex) throw new OracleMismatchError('seed_hash');
      if (job.epochKeyHex !== context.epochKeyHex) throw new OracleMismatchError('epoch_key');
      const templateHex = blobToHex(hashingTemplateOf(job));
      if (templateHex !== context.templateHex) {
        throw new OracleMismatchError('blob_nonce_zeroed', context.templateHex, templateHex);
      }
      if (job.nonceStart !== context.nonce || job.nonceRange !== 1) {
        throw new OracleMismatchError('nonce window');
      }
      bound = Object.freeze({ jobId: job.jobId, issuanceId: job.issuanceId, ...context });
      return bound;
    },

    async hashOne(nonce) {
      if (bound === null) throw new OracleUnboundError('hashOne');
      calls += 1;
      if (nonce !== expectedNonce) {
        throw new OracleMismatchError(`nonce (recorded row covers only ${expectedNonce})`);
      }
      // A fresh copy: a caller that mutates the result must not corrupt the table.
      return expectedHash.slice();
    },
  };
}

/**
 * The MOCK DAEMON.
 *
 * Validates exact inputs against the recorded row, counts every call, and returns exactly what a
 * daemon holding that block would. It performs NO transport of any kind.
 *
 * `oracle` is REQUIRED and must be bound: a mock daemon that answered while the "native" check was
 * unbound would let a run look complete when only one of the two pretend components was actually
 * describing the block in front of it.
 */
export function createMockDaemon(row, { blockId = row.block_hash, oracle } = {}) {
  const counters = {
    calcPow: 0,
    prepareSubmission: 0,
    dispatchSubmission: 0,
    readback: 0,
    inMemoryTransportCalls: 0,   // the in-memory function the adapter hands requests to
    transportCalls: 0,           // REAL transport: stays 0 forever, there is none
  };
  // What calc_pow must be asked, byte for byte.
  const expectedCalcBlob = row.block_hashing_blob;
  const expectedFullBlock = row.full_block_blob;
  const expectedPow = row.expected_meephash_w_v2;
  let submittedNonce = null;

  function requireBoundOracle(what) {
    if (!oracle || oracle.bound !== true) throw new OracleUnboundError(what);
  }

  /**
   * The in-memory "daemon". It accepts only submit_block with exactly the recorded full block,
   * reports the handoff the moment it has the bytes, and answers with a canonical JSON-RPC result.
   */
  function inMemoryTransport(req) {
    counters.inMemoryTransportCalls += 1;
    const body = JSON.parse(req.body);
    if (body.method !== 'submit_block' || !Array.isArray(body.params) || body.params.length !== 1) {
      throw new OracleMismatchError('in-memory daemon method');
    }
    const [fullBlockHex] = body.params;
    // The bytes have arrived: this is the handoff, and only the adapter's function can record it.
    req.handoff();
    if (fullBlockHex !== expectedFullBlock) {
      return Promise.resolve(JSON.stringify({
        jsonrpc: '2.0', id: body.id, error: { code: -7, message: 'Block not accepted' },
      }));
    }
    submittedNonce = readNonce(hexToBlob(fullBlockHex));
    return Promise.resolve(JSON.stringify({
      jsonrpc: '2.0', id: body.id, result: { status: 'OK', block_id: blockId },
    }));
  }

  const adapter = createDaemonRpc({
    transport: inMemoryTransport,
    // Validated like any endpoint and never contacted: the transport above is in-memory.
    endpoint: 'http://127.0.0.1:18081/json_rpc',
  });

  return {
    kind: 'mock-daemon',
    counters,

    async calcPow({ majorVersion, height, blockBlobHex, seedHashHex }) {
      requireBoundOracle('calc_pow');
      counters.calcPow += 1;
      if (majorVersion !== row.major_version) throw new OracleMismatchError('major_version');
      if (height !== String(row.height)) throw new OracleMismatchError('height');
      if (seedHashHex !== row.delayed_seed_input) throw new OracleMismatchError('seed_hash');
      // The nonce-bearing hashing blob must be EXACTLY the recorded one.
      if (blockBlobHex !== expectedCalcBlob) throw new OracleMismatchError('block_blob', expectedCalcBlob, blockBlobHex);
      return expectedPow;
    },

    /** The REAL adapter's prepareSubmission: an opaque, adapter-bound, one-use capability. */
    /** The adapter whose private proofs cover this mock's submit path. */
    submissionAdapter: adapter,

    prepareSubmission(fullBlockHex, operation) {
      requireBoundOracle('prepare_submission');
      counters.prepareSubmission += 1;
      if (fullBlockHex !== expectedFullBlock) throw new OracleMismatchError('full_block_blob');
      return adapter.prepareSubmission(fullBlockHex, operation);
    },

    /** The REAL adapter's dispatchSubmission: an authenticated dispatch record and receipt. */
    dispatchSubmission(capability) {
      requireBoundOracle('dispatch_submission');
      counters.dispatchSubmission += 1;
      return adapter.dispatchSubmission(capability);
    },

    async getBlockHeaderByHeight(height, { fillPowHash = true } = {}) {
      requireBoundOracle('readback');
      counters.readback += 1;
      if (height !== String(row.height)) throw new OracleMismatchError('readback height');
      if (fillPowHash !== true) throw new OracleMismatchError('fill_pow_hash must be requested');
      return {
        hash: blockId,
        height: row.height,
        nonce: submittedNonce,
        powHash: expectedPow,
        orphanStatus: false,
        prevHash: row.prev_hash ?? null,
      };
    },
  };
}
