// The strict daemon RPC adapter. NO SOCKET IS OPENED ANYWHERE IN THIS FILE.
//
// Every case drives an in-memory fake transport: a function that receives a request body and
// returns response text. No fetch, no DNS, no listener, no daemon. The adapter's job here is to be
// strict about what it will send and what it will believe.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  LIMIT_BOUNDS, RPC_CODES, SUBMIT_DISPOSITION, assertLoopbackEndpoint, auditRecord,
  classifySubmitFailure, createDaemonRpc, isDefiniteRejection, redact, submissionProofs,
  validateLimit,
} from '../daemon_rpc.mjs';

const SEED = 'a'.repeat(64);
const BLOCK_ID = 'b'.repeat(64);
const POW = 'c'.repeat(64);

/**
 * A fake transport that answers with whatever `reply(parsedRequest)` returns. Records calls.
 *
 * IT CALLS req.handoff(). That is the contract a real transport must honour: the adapter's own
 * one-use function, invoked at the moment the bytes are written. A transport that does not call it
 * gets no receipt, which is the point of several tests below.
 */
function fakeTransport(reply) {
  const calls = [];
  const fn = async (req) => {
    const parsed = JSON.parse(req.body);
    calls.push({ ...req, parsed });
    req.handoff();
    const out = reply(parsed, req);
    return typeof out === 'string' ? out : JSON.stringify(out);
  };
  fn.calls = calls;
  return fn;
}

function ok(id, result) {
  return { jsonrpc: '2.0', id, result };
}

const TEMPLATE_RESULT = {
  status: 'OK',
  height: 5,
  difficulty: 500,
  wide_difficulty: '0x1f4',
  difficulty_top64: 0,
  seed_height: 0,
  seed_hash: SEED,
  next_seed_hash: '',
  prev_hash: 'd'.repeat(64),
  reserved_offset: 0,
  expected_reward: 1,
  blockhashing_blob: '1010101001' + '0'.repeat(70),
  blocktemplate_blob: '1010101001' + '0'.repeat(110),
};

test('the FULL loopback URL is preserved, path included', () => {
  // The reproduced defect: the endpoint was reduced to its origin, silently dropping /json_rpc, so
  // a transport handed the "validated" endpoint would have posted to /.
  const t = assertLoopbackEndpoint('http://127.0.0.1:19081/json_rpc');
  assert.equal(t.url, 'http://127.0.0.1:19081/json_rpc');
  assert.equal(t.pathname, '/json_rpc');
  assert.equal(t.origin, 'http://127.0.0.1:19081');
  assert.equal(assertLoopbackEndpoint('http://[::1]:19081/json_rpc').url, 'http://[::1]:19081/json_rpc');
});

test('only literal loopback JSON-RPC endpoints are accepted; a hostname is refused, not resolved', () => {
  for (const good of [
    'http://127.0.0.1:19081/json_rpc', 'http://127.0.0.1:28081/json_rpc', 'http://[::1]:19081/json_rpc',
  ]) {
    assert.equal(assertLoopbackEndpoint(good).pathname, '/json_rpc');
  }
  for (const bad of [
    'http://localhost:19081/json_rpc',     // a NAME: what it resolves to is not ours to decide
    'http://meepcoin.example:19081/json_rpc',
    'http://10.0.0.5:19081/json_rpc',
    'http://192.168.1.7:19081/json_rpc',
    'http://0.0.0.0:19081/json_rpc',
    'https://127.0.0.1:19081/json_rpc',    // no TLS in this slice
    'http://user:pass@127.0.0.1:19081/json_rpc',
    'http://127.0.0.1:19081/json_rpc?x=1',
    'http://127.0.0.1:19081/json_rpc#f',
    'http://127.0.0.1:19081/',             // the path is part of the contract
    'http://127.0.0.1:19081/admin',
    'ftp://127.0.0.1/json_rpc',
    'not a url',
  ]) {
    // Asserted on the structured reason, so rewording a message cannot turn this check off.
    assert.throws(() => assertLoopbackEndpoint(bad),
      (e) => e.name === 'DaemonRpcError' && e.code === RPC_CODES.BAD_ENDPOINT,
      `${bad} should be refused`);
  }
});

test('the injected transport receives the FULL url, not just the origin', async () => {
  const t = fakeTransport((req) => ok(req.id, POW));
  const rpc = createDaemonRpc({ transport: t, endpoint: 'http://127.0.0.1:19081/json_rpc' });
  await rpc.calcPow({ majorVersion: 16, height: '5', blockBlobHex: 'ab', seedHashHex: SEED });
  assert.equal(t.calls[0].url, 'http://127.0.0.1:19081/json_rpc');
  assert.equal(rpc.endpoint, 'http://127.0.0.1:19081/json_rpc');
});

test('configurable limits must be finite integers inside hard bounds', () => {
  assert.equal(validateLimit('timeoutMs', undefined), LIMIT_BOUNDS.timeoutMs.dflt);
  assert.equal(validateLimit('timeoutMs', 5000), 5000);
  for (const bad of [Infinity, -Infinity, NaN, 0, -1, 1.5, '5000', null, 1 << 30]) {
    assert.throws(() => validateLimit('timeoutMs', bad),
      (e) => e.code === RPC_CODES.BAD_LIMIT, `timeoutMs=${String(bad)} should be refused`);
  }
  for (const bad of [Infinity, 0, -1, 1 << 30]) {
    assert.throws(() => validateLimit('maxResponseBytes', bad), (e) => e.code === RPC_CODES.BAD_LIMIT);
  }
  // And through the constructor.
  assert.throws(() => createDaemonRpc({ transport: async () => '', limits: { timeoutMs: Infinity } }),
    (e) => e.code === RPC_CODES.BAD_LIMIT);
  assert.throws(() => createDaemonRpc({ transport: async () => '', limits: { nonsense: 1 } }),
    (e) => e.code === RPC_CODES.BAD_LIMIT);
});

test('a transport must be injected; the adapter never creates one', () => {
  assert.throws(() => createDaemonRpc({}), /transport function must be injected/);
  assert.throws(() => createDaemonRpc({ transport: 'nope' }), /transport function must be injected/);
});

test('get_block_template reads wide_difficulty and refuses a malformed result', async () => {
  const t = fakeTransport((req) => ok(req.id, TEMPLATE_RESULT));
  const rpc = createDaemonRpc({ transport: t });
  const got = await rpc.getBlockTemplate({ walletAddress: 'FAKE_UNUSABLE_PLACEHOLDER_ADDRESS' });
  assert.equal(got.wideDifficulty, '0x1f4');
  assert.equal(got.seedHashHex, SEED);
  assert.equal(got.height, 5);
  assert.equal(got.reservedOffset, 0);
  assert.equal(got.reservedSize, 0);
  assert.equal(t.calls[0].parsed.method, 'get_block_template');
  assert.equal(t.calls[0].parsed.params.wallet_address, 'FAKE_UNUSABLE_PLACEHOLDER_ADDRESS');
  // The transport contract the future real one must honour is passed down explicitly.
  assert.equal(t.calls[0].followRedirects, false);
  assert.equal(t.calls[0].useProxyEnv, false);

  for (const [name, patch] of [
    ['no wide_difficulty', { wide_difficulty: undefined }],
    ['bad seed hash', { seed_hash: 'abcd' }],
    ['uppercase blob', { blockhashing_blob: 'AABB' }],
    ['odd-length blob', { blocktemplate_blob: 'abc' }],
    ['not OK', { status: 'BUSY' }],
  ]) {
    const bad = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, { ...TEMPLATE_RESULT, ...patch })) });
    await assert.rejects(() => bad.getBlockTemplate({ walletAddress: 'FAKE' }), /./, name);
  }
});

test('get_block_template binds the requested reserve size to the daemon-authored byte offset', async () => {
  const fullBytes = TEMPLATE_RESULT.blocktemplate_blob.length / 2;
  const t = fakeTransport((req) => ok(req.id, { ...TEMPLATE_RESULT, reserved_offset: fullBytes - 8 }));
  const rpc = createDaemonRpc({ transport: t });
  const got = await rpc.getBlockTemplate({ walletAddress: 'FAKE', reserveSize: 8 });

  assert.equal(t.calls[0].parsed.params.reserve_size, 8);
  assert.equal(got.reservedOffset, fullBytes - 8);
  assert.equal(got.reservedSize, 8);

  for (const [name, reserved_offset] of [
    ['missing', undefined], ['negative', -1], ['fractional', 1.5],
    ['unsafe', Number.MAX_SAFE_INTEGER + 1], ['huge safe', Number.MAX_SAFE_INTEGER],
    ['past end', fullBytes - 7],
  ]) {
    const bad = createDaemonRpc({
      transport: fakeTransport((r) => ok(r.id, { ...TEMPLATE_RESULT, reserved_offset })),
    });
    await assert.rejects(
      () => bad.getBlockTemplate({ walletAddress: 'FAKE', reserveSize: 8 }),
      (err) => err.code === RPC_CODES.BAD_RESPONSE,
      name,
    );
  }
});

test('calc_pow sends the nonce-bearing blob and requires a bare hex string result', async () => {
  const t = fakeTransport((req) => ok(req.id, POW));
  const rpc = createDaemonRpc({ transport: t });
  const got = await rpc.calcPow({
    majorVersion: 16, height: '5', blockBlobHex: 'deadbeef', seedHashHex: SEED,
  });
  assert.equal(got, POW);
  const p = t.calls[0].parsed.params;
  // Exactly the four fields COMMAND_RPC_CALCPOW declares.
  assert.deepEqual(Object.keys(p).sort(), ['block_blob', 'height', 'major_version', 'seed_hash']);
  assert.equal(p.block_blob, 'deadbeef');
  assert.equal(p.height, 5);

  // calc_pow's response is a STRING in the daemon source, not an object.
  const objResult = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, { pow_hash: POW })) });
  await assert.rejects(() => objResult.calcPow({ majorVersion: 16, height: '5', blockBlobHex: 'ab', seedHashHex: SEED }),
    /must be a 64-character lowercase hex hash/);
  const shortResult = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, 'abcd')) });
  await assert.rejects(() => shortResult.calcPow({ majorVersion: 16, height: '5', blockBlobHex: 'ab', seedHashHex: SEED }),
    /64-character/);
});

test('submit_block sends an array of one hex string, as the daemon requires', async () => {
  const t = fakeTransport((req) => ok(req.id, { status: 'OK', block_id: BLOCK_ID }));
  const rpc = createDaemonRpc({ transport: t });
  const got = await rpc.submitBlock('aabbcc');
  assert.equal(got.blockId, BLOCK_ID);
  assert.ok(Array.isArray(t.calls[0].parsed.params));
  assert.equal(t.calls[0].parsed.params.length, 1);
  assert.equal(t.calls[0].parsed.params[0], 'aabbcc');

  await assert.rejects(() => rpc.submitBlock('NOTHEX'), /lowercase hex/);
  await assert.rejects(() => rpc.submitBlock(''), /non-empty/);
});

test('a response whose id does not match the request is refused', async () => {
  const rpc = createDaemonRpc({ transport: fakeTransport(() => ok('some-other-id', POW)) });
  await assert.rejects(
    () => rpc.calcPow({ majorVersion: 16, height: '5', blockBlobHex: 'ab', seedHashHex: SEED }),
    /response id does not match/,
  );
});

test('request ids are unique per call', async () => {
  const t = fakeTransport((req) => ok(req.id, POW));
  const rpc = createDaemonRpc({ transport: t });
  for (let i = 0; i < 3; i++) {
    await rpc.calcPow({ majorVersion: 16, height: '5', blockBlobHex: 'ab', seedHashHex: SEED });
  }
  const ids = t.calls.map((c) => c.parsed.id);
  assert.equal(new Set(ids).size, 3, 'request ids were reused');
});

test('malformed envelopes are refused', async () => {
  const cases = [
    ['not JSON', () => 'not json', /not valid JSON/],
    ['root not an object', () => '[]', /root is not an object/],
    ['wrong jsonrpc', (r) => ({ jsonrpc: '1.0', id: r.id, result: POW }), /jsonrpc must be/],
    ['both result and error', (r) => ({ jsonrpc: '2.0', id: r.id, result: POW, error: { code: -1, message: 'x' } }), /both result and error/],
    ['neither', (r) => ({ jsonrpc: '2.0', id: r.id }), /neither result nor error/],
    ['unknown top-level field', (r) => ({ jsonrpc: '2.0', id: r.id, result: POW, extra: 1 }), /unexpected top-level field/],
    ['an rpc error', (r) => ({ jsonrpc: '2.0', id: r.id, error: { code: -9, message: 'nope' } }), /daemon returned an error/],
  ];
  for (const [name, reply, re] of cases) {
    const rpc = createDaemonRpc({ transport: fakeTransport(reply) });
    await assert.rejects(
      () => rpc.calcPow({ majorVersion: 16, height: '5', blockBlobHex: 'ab', seedHashHex: SEED }),
      re, name,
    );
  }
});

test('an oversized response is refused before it is parsed as truth', async () => {
  const huge = JSON.stringify({ jsonrpc: '2.0', id: 'meepcoin-1', result: POW, }) + ' '.repeat(2_000_000);
  const rpc = createDaemonRpc({ transport: fakeTransport(() => huge), limits: { maxResponseBytes: 1024 } });
  await assert.rejects(
    () => rpc.calcPow({ majorVersion: 16, height: '5', blockBlobHex: 'ab', seedHashHex: SEED }),
    /response exceeds/,
  );
});

test('the adapter is not a general JSON-RPC proxy', async () => {
  const rpc = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, {})) });
  // There is no public method that takes a method name, so an arbitrary call is not a matter of
  // validation -- there is no code path for it at all.
  assert.equal(typeof rpc.call, 'undefined');
  const exposed = Object.keys(rpc).filter((k) => typeof rpc[k] === 'function').sort();
  // The two-phase submit boundary adds prepare/dispatch. Still a closed list of daemon operations,
  // with no caller-controlled method name anywhere.
  assert.deepEqual(exposed, [
    'calcPow', 'dispatchSubmission', 'getBlockHeaderByHeight', 'getBlockTemplate', 'getInfo',
    'getLastBlockHeader', 'prepareSubmission', 'submitBlock',
  ]);
});

test('hex, credentials and addresses are redacted from anything reportable', () => {
  const blob = 'ab'.repeat(200);
  assert.equal(redact(blob).includes(blob), false);
  assert.match(redact(blob), /<redacted-hex>/);
  // A BARE 64-hex value is exactly a hash, a key or a block id. It must go too -- that was the
  // reported gap: the old rule needed 65+ characters, so every 64-hex secret survived.
  const sixtyFour = 'c'.repeat(64);
  assert.equal(redact(sixtyFour).includes(sixtyFour), false, 'a 64-hex value survived redaction');
  assert.equal(redact(`hash=${sixtyFour}`).includes(sixtyFour), false);
  assert.match(redact({ password: 'hunter2' }), /<redacted>/);
  assert.equal(redact({ rpc_login: 'user:secret' }).includes('secret'), false);
  assert.equal(redact('Authorization: Bearer abc.def.ghi').includes('abc.def.ghi'), false);
  assert.equal(redact('Basic dXNlcjpwYXNz').includes('dXNlcjpwYXNz'), false);
  const addr = `4${'A'.repeat(94)}`;
  assert.equal(redact(`addr ${addr}`).includes(addr), false, 'a wallet-shaped address survived');
  assert.equal(redact('http://user:pass@127.0.0.1:19081/json_rpc').includes('pass@'), false);
  assert.equal(redact(null), '');
});

test('every failure carries a stable structured code', async () => {
  const cases = [
    [() => 'not json', RPC_CODES.BAD_RESPONSE],
    [(r) => ({ jsonrpc: '2.0', id: 'other', result: POW }), RPC_CODES.ID_MISMATCH],
    [(r) => ({ jsonrpc: '2.0', id: r.id, error: { code: -9, message: 'nope' } }), RPC_CODES.DAEMON_ERROR],
  ];
  for (const [reply, code] of cases) {
    const rpc = createDaemonRpc({ transport: fakeTransport(reply) });
    await assert.rejects(
      () => rpc.calcPow({ majorVersion: 16, height: '5', blockBlobHex: 'ab', seedHashHex: SEED }),
      (e) => e.code === code, code,
    );
  }
  // A transport that throws is reported as a code, and its raw message is not the caller's problem.
  const boom = createDaemonRpc({ transport: async () => { throw new Error('ECONNREFUSED 127.0.0.1:19081'); } });
  await assert.rejects(
    () => rpc0(boom), (e) => e.code === RPC_CODES.TRANSPORT_FAILED,
  );
  function rpc0(a) { return a.calcPow({ majorVersion: 16, height: '5', blockBlobHex: 'ab', seedHashHex: SEED }); }
});

test('a rejected submit_block does not leak the block blob into the error', async () => {
  const blob = 'ab'.repeat(300);
  const rpc = createDaemonRpc({
    transport: fakeTransport((r) => ({ jsonrpc: '2.0', id: r.id, error: { code: -7, message: `bad block ${blob}` } })),
  });
  await assert.rejects(() => rpc.submitBlock(blob), (err) => {
    assert.equal(String(err.message).includes(blob), false, 'the blob leaked into the message');
    assert.equal(String(err.detail).includes(blob), false, 'the blob leaked into the detail');
    return true;
  });
});

const HEADER_OK = {
  status: 'OK',
  block_header: {
    hash: BLOCK_ID, height: 5, nonce: 42, timestamp: 1785283200, prev_hash: 'd'.repeat(64),
    orphan_status: false, pow_hash: POW,
  },
};

test('the readback REQUESTS fill_pow_hash and requires a well-formed pow_hash', async () => {
  const t = fakeTransport((r) => ok(r.id, HEADER_OK));
  const rpc = createDaemonRpc({ transport: t });
  const got = await rpc.getBlockHeaderByHeight('5');
  assert.deepEqual(got, {
    hash: BLOCK_ID, height: 5, nonce: 42, timestamp: 1785283200,
    powHash: POW, orphanStatus: false, prevHash: 'd'.repeat(64),
  });
  // The daemon only computes pow_hash when asked: fill_block_header_response() sets it to "" other-
  // wise. So the request must carry it.
  assert.equal(t.calls[0].parsed.params.fill_pow_hash, true);
  assert.equal(t.calls[0].parsed.params.height, 5);

  await assert.rejects(() => rpc.getBlockHeaderByHeight('007'), /canonical decimal/);
});

test('a missing, empty or malformed pow_hash is refused, never treated as a match', async () => {
  for (const [name, header] of [
    ['absent', { ...HEADER_OK.block_header, pow_hash: undefined }],
    ['empty string (what the daemon returns when not asked)', { ...HEADER_OK.block_header, pow_hash: '' }],
    ['too short', { ...HEADER_OK.block_header, pow_hash: 'abcd' }],
    ['uppercase', { ...HEADER_OK.block_header, pow_hash: POW.toUpperCase() }],
    ['not a string', { ...HEADER_OK.block_header, pow_hash: 12345 }],
  ]) {
    const rpc = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, { status: 'OK', block_header: header })) });
    await assert.rejects(() => rpc.getBlockHeaderByHeight('5'),
      (e) => e.code === RPC_CODES.BAD_RESPONSE, name);
  }
});

test('orphan_status must be an explicit boolean', async () => {
  for (const value of [undefined, null, 'false', 0, 1]) {
    const header = { ...HEADER_OK.block_header, orphan_status: value };
    const rpc = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, { status: 'OK', block_header: header })) });
    await assert.rejects(() => rpc.getBlockHeaderByHeight('5'),
      (e) => e.code === RPC_CODES.BAD_RESPONSE, `orphan_status=${String(value)}`);
  }
  // true is well-formed here; refusing an ORPHAN is block_run's decision, not the parser's.
  const orphan = { ...HEADER_OK.block_header, orphan_status: true };
  const rpc = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, { status: 'OK', block_header: orphan })) });
  assert.equal((await rpc.getBlockHeaderByHeight('5')).orphanStatus, true);
});

test('a malformed header field is refused', async () => {
  const badNonce = createDaemonRpc({
    transport: fakeTransport((r) => ok(r.id, { status: 'OK', block_header: { ...HEADER_OK.block_header, nonce: -1 } })),
  });
  await assert.rejects(() => badNonce.getBlockHeaderByHeight('5'), /nonce malformed/);
  for (const timestamp of [-1, '1785283200', 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    const badTime = createDaemonRpc({
      transport: fakeTransport((r) => ok(r.id, {
        status: 'OK', block_header: { ...HEADER_OK.block_header, timestamp },
      })),
    });
    await assert.rejects(() => badTime.getBlockHeaderByHeight('5'), /timestamp malformed/);
  }
});

test('a height that a JSON number cannot carry exactly is refused, not rounded', async () => {
  const rpc = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, POW)) });
  await assert.rejects(
    () => rpc.calcPow({ majorVersion: 16, height: '9007199254740993', blockBlobHex: 'ab', seedHashHex: SEED }),
    /exceeds what a JSON number can carry exactly/,
  );
});


// ---------------------------------------------------------------- A5 two-phase submission
/**
 * One submission on `rpc` under a fresh operation token, with its instance-bound lineage: the
 * adapter's own proofs, the operation, the capability, the handle and the authenticated record.
 */
function submitOnce(rpc, hex) {
  const operation = Object.freeze({});
  const capability = rpc.prepareSubmission(hex, operation);
  const handle = rpc.dispatchSubmission(capability);
  const proofs = submissionProofs(rpc);
  return { operation, capability, handle, proofs, record: proofs.dispatchFor(operation, handle) };
}

test('A5: prepareSubmission never touches the transport, and returns an OPAQUE capability', () => {
  const t = fakeTransport((r) => ok(r.id, { status: 'OK', block_id: BLOCK_ID }));
  const rpc = createDaemonRpc({ transport: t });
  const operation = Object.freeze({});
  const capability = rpc.prepareSubmission('aabbcc', operation);
  assert.equal(t.calls.length, 0, 'prepare invoked the transport');
  // NOTHING USEFUL IS PUBLIC. Dispatch used to read `prepared.method` and `prepared.body` straight
  // off the object it was handed, which is why a forged object worked.
  assert.deepEqual(Object.keys(capability), ['kind']);
  assert.equal(Object.isFrozen(capability), true);
  assert.equal(capability.body, undefined);
  assert.equal(capability.requestBytes, undefined);
  assert.equal(JSON.stringify(capability).includes('aabbcc'), false);
  assert.equal(submissionProofs(rpc).capabilityFor(operation, capability, 'aabbcc'), true);
});

test('A1: a capability authenticates ONLY against the exact block body it was prepared from', () => {
  const t = fakeTransport((r) => ok(r.id, { status: 'OK', block_id: BLOCK_ID }));
  const rpc = createDaemonRpc({ transport: t });
  const proofs = submissionProofs(rpc);
  const operation = Object.freeze({});
  const capability = rpc.prepareSubmission('aabbcc', operation);
  assert.equal(proofs.capabilityFor(operation, capability, 'aabbcc'), true, 'the right body did not authenticate');
  // A different WELL-FORMED body -- one byte changed, one byte longer, one byte shorter -- does not.
  for (const other of ['aabbcd', 'aabbccdd', 'aabb']) {
    assert.equal(proofs.capabilityFor(operation, capability, other), false, `${other} authenticated`);
  }
  // Omitting the expected body is not a wildcard.
  for (const missing of [undefined, null, '', 0, ['aabbcc'], { toString: () => 'aabbcc' }]) {
    assert.equal(proofs.capabilityFor(operation, capability, missing), false, `${String(missing)} was a wildcard`);
  }
  assert.equal(t.calls.length, 0);
});

test('A5: an oversized submission is refused LOCALLY, and proven not sent FOR ITS OPERATION', () => {
  const t = fakeTransport((r) => ok(r.id, { status: 'OK', block_id: BLOCK_ID }));
  // The committed height-2113 full block is only 127 bytes, so a cap-exercising block is built
  // here. The exact sizes are asserted rather than assumed.
  const bigBlock = 'ab'.repeat(1400);                 // 1400 bytes -> 2800 hex chars
  const rpc = createDaemonRpc({ transport: t, limits: { maxRequestBytes: 1024 } });
  const operation = Object.freeze({});
  let thrown = null;
  try { rpc.prepareSubmission(bigBlock, operation); } catch (e) { thrown = e; }
  assert.ok(thrown, 'an oversized submission was accepted');
  assert.equal(thrown.code, RPC_CODES.REQUEST_TOO_LARGE);
  const proofs = submissionProofs(rpc);
  assert.equal(proofs.notSentFor(operation, thrown), true, 'a local size refusal must be PROVEN not-sent');
  assert.equal(proofs.notSentFor(Object.freeze({}), thrown), false, 'the proof leaked to another operation');
  assert.equal(submissionProofs(createDaemonRpc({ transport: t })).notSentFor(operation, thrown), false,
    'the proof leaked to another adapter');
  assert.equal(t.calls.length, 0, 'the transport was invoked for an oversized request');
  // And the same block under a sufficient cap prepares and dispatches fine, so the cap is what
  // refused it.
  const okRpc = createDaemonRpc({ transport: t, limits: { maxRequestBytes: 8192 } });
  const { record } = submitOnce(okRpc, bigBlock);
  assert.ok(record.requestBytes > 1024, `expected >1024 bytes, got ${record.requestBytes}`);
});

test('A5: dispatchSubmission enters the transport and the RECEIPT comes from the handoff', async () => {
  const t = fakeTransport((r) => ok(r.id, { status: 'OK', block_id: BLOCK_ID }));
  const rpc = createDaemonRpc({ transport: t });
  const { handle, proofs, record } = submitOnce(rpc, 'aabbcc');
  assert.ok(record, 'the adapter did not register its own dispatch handle');
  assert.equal(t.calls.length, 1, 'dispatch did not invoke the transport');
  assert.equal(t.calls[0].url, 'http://127.0.0.1:19081/json_rpc');
  assert.equal(typeof t.calls[0].handoff, 'function', 'the transport was not given a handoff');
  const receipt = await record.receipt;
  assert.ok(receipt, 'a transport that called handoff produced no receipt');
  assert.equal(proofs.receiptFor(record, receipt), true);
  assert.equal(receipt.method, 'submit_block');
  assert.ok(receipt.requestBytes > 0);
  // The OUTCOME is a separate, later fact.
  const out = await handle.outcome;
  assert.equal(out.blockId, BLOCK_ID);
});

test('A5: the handoff is ONE receipt however many times a transport calls it', async () => {
  const seen = [];
  const rpc = createDaemonRpc({
    transport: async (req) => {
      seen.push(req.handoff());
      seen.push(req.handoff());
      seen.push(req.handoff());
      return JSON.stringify(ok(JSON.parse(req.body).id, { status: 'OK', block_id: BLOCK_ID }));
    },
  });
  const { handle, record } = submitOnce(rpc, 'aabbcc');
  const receipt = await record.receipt;
  assert.equal(seen.length, 3);
  assert.equal(seen[0], seen[1], 'a second handoff minted a second receipt');
  assert.equal(seen[1], seen[2]);
  assert.equal(receipt, seen[0]);
  await handle.outcome;
});

test('A5: a transport that WRITES and THEN THROWS synchronously is never definitely-not-sent', async () => {
  const writes = [];
  const rpc = createDaemonRpc({
    transport: (req) => {
      writes.push(req.body);      // the side effect
      req.handoff();              // and it did hand over
      throw new Error('socket closed right after the write');
    },
  });
  const { operation, proofs, record } = submitOnce(rpc, 'aabbcc');
  assert.equal(writes.length, 1);
  assert.ok(record);
  const receipt = await record.receipt;
  assert.ok(receipt, 'a transport that wrote and handed off produced no receipt');
  await assert.rejects(() => record.outcome, (e) => {
    assert.equal(proofs.notSentFor(operation, e), false, 'a post-write throw was called definitely-not-sent');
    assert.equal(e.definitelyNotSent, false);
    assert.equal(e.ambiguous, true);
    assert.equal(classifySubmitFailure(proofs, { operation, record }, e), SUBMIT_DISPOSITION.AMBIGUOUS);
    return true;
  });
});

test('A5: a bare synchronous throw is ambiguous too -- entering is not proof of nothing', async () => {
  const rpc = createDaemonRpc({ transport: () => { throw new Error('no socket'); } });
  const { operation, proofs, record } = submitOnce(rpc, 'aabbcc');
  assert.ok(record);
  assert.equal(await record.receipt, null, 'a receipt appeared without a handoff');
  await assert.rejects(() => record.outcome,
    (e) => proofs.notSentFor(operation, e) === false && e.ambiguous === true);
});

test('A5: an async transport that returns BEFORE any handoff yields no receipt', async () => {
  let resolveBody;
  const gate = new Promise((r) => { resolveBody = r; });
  let receiptSeen = 'not-settled';
  const rpc = createDaemonRpc({
    transport: async (req) => {
      await gate;
      return JSON.stringify(ok(JSON.parse(req.body).id, { status: 'OK', block_id: BLOCK_ID }));
    },
  });
  const { handle, record } = submitOnce(rpc, 'aabbcc');
  record.receipt.then((r) => { receiptSeen = r; });
  assert.equal(handle.handedOff, false, 'dispatch claimed a handoff that never happened');
  await new Promise((r) => setImmediate(r));
  assert.equal(receiptSeen, 'not-settled', 'the receipt settled before the outcome did');
  resolveBody();
  await handle.outcome;
  assert.equal(await record.receipt, null, 'no handoff must settle the receipt as null');
});

test('A5: a prepared capability is ONE-USE, and a consumed-capability refusal proves nothing about the operation', () => {
  const t = fakeTransport((r) => ok(r.id, { status: 'OK', block_id: BLOCK_ID }));
  const rpc = createDaemonRpc({ transport: t });
  const { operation, capability, proofs } = submitOnce(rpc, 'aabbcc');
  assert.equal(t.calls.length, 1);
  let thrown = null;
  try { rpc.dispatchSubmission(capability); } catch (e) { thrown = e; }
  assert.ok(thrown, 'the same prepared submission was dispatched twice');
  assert.equal(thrown.code, RPC_CODES.PREPARED_CONSUMED);
  assert.equal(t.calls.length, 1, 'a second dispatch reached the transport');
  // THIS call did not transport -- but the OPERATION was already sent, so this is no proof of it.
  assert.equal(proofs.notSentFor(operation, thrown), false, 'a consumed refusal was taken as not-sent');
});

test('A5: a FORGED capability cannot reach the transport or bypass the size cap', () => {
  const t = fakeTransport((r) => ok(r.id, { status: 'OK', block_id: BLOCK_ID }));
  const rpc = createDaemonRpc({ transport: t, limits: { maxRequestBytes: 1024 } });
  const forgeries = [
    { method: 'submit_block', body: JSON.stringify({ blob: 'ab'.repeat(50000) }), requestBytes: 4, id: 'x' },
    { method: 'submit_block' },
    { kind: 'meepcoin-prepared-submission' },
    Object.freeze({ kind: 'meepcoin-prepared-submission' }),
    null,
    undefined,
    'meepcoin-prepared-submission',
    42,
  ];
  for (const forged of forgeries) {
    let thrown = null;
    try { rpc.dispatchSubmission(forged); } catch (e) { thrown = e; }
    assert.ok(thrown, `a forged capability was accepted: ${JSON.stringify(forged)}`);
    assert.equal(thrown.code, RPC_CODES.PREPARED_UNKNOWN, JSON.stringify(forged));
  }
  assert.equal(t.calls.length, 0, 'a forged capability reached the transport');
});

test('A5: a capability prepared by ANOTHER adapter is refused before the transport', () => {
  const mine = fakeTransport((r) => ok(r.id, { status: 'OK', block_id: BLOCK_ID }));
  const theirs = fakeTransport((r) => ok(r.id, { status: 'OK', block_id: BLOCK_ID }));
  const a = createDaemonRpc({ transport: mine });
  const b = createDaemonRpc({ transport: theirs });
  const foreignOp = Object.freeze({});
  const foreign = b.prepareSubmission('aabbcc', foreignOp);
  let thrown = null;
  try { a.dispatchSubmission(foreign); } catch (e) { thrown = e; }
  assert.ok(thrown, 'a foreign adapter capability was accepted');
  assert.equal(thrown.code, RPC_CODES.PREPARED_FOREIGN);
  assert.equal(mine.calls.length, 0);
  assert.equal(theirs.calls.length, 0);
  // Adapter A's refusal is no proof about B's operation, on either adapter.
  assert.equal(submissionProofs(a).notSentFor(foreignOp, thrown), false);
  assert.equal(submissionProofs(b).notSentFor(foreignOp, thrown), false);
  // And it still works in its own adapter, so it was refused for whose it is, not for being broken.
  b.dispatchSubmission(foreign);
  assert.equal(theirs.calls.length, 1);
});

test('A5: a dispatched request that fails is classified FOR ITS OWN DISPATCH, not guessed', async () => {
  const refused = createDaemonRpc({
    transport: fakeTransport((r) => ({ jsonrpc: '2.0', id: r.id, error: { code: -7, message: 'Block not accepted' } })),
  });
  const a = submitOnce(refused, 'aabbcc');
  let refusal = null;
  await assert.rejects(() => a.record.outcome, (e) => {
    refusal = e;
    return isDefiniteRejection(e.code) === true && e.code === RPC_CODES.DAEMON_ERROR
      && classifySubmitFailure(a.proofs, { operation: a.operation, record: a.record }, e)
        === SUBMIT_DISPOSITION.EXPLICIT_REJECTION;
  });
  // The same authentic refusal is NOT a refusal of a different dispatch on the same adapter.
  const b = submitOnce(refused, 'ddeeff');
  await b.record.outcome.catch(() => {});
  assert.equal(b.proofs.refusalFor(b.record, refusal), false, 'a refusal was rebound to another dispatch');
  assert.equal(classifySubmitFailure(b.proofs, { operation: b.operation, record: b.record }, refusal),
    SUBMIT_DISPOSITION.AMBIGUOUS);

  const busy = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, { status: 'BUSY', block_id: BLOCK_ID })) });
  const bz = submitOnce(busy, 'aabbcc');
  await assert.rejects(() => bz.record.outcome,
    (e) => e.code === RPC_CODES.DAEMON_STATUS && bz.proofs.refusalFor(bz.record, e) === true);

  const cases = [
    ['transport threw after handoff', async (req) => { req.handoff(); throw new Error('ETIMEDOUT'); }, RPC_CODES.TRANSPORT_FAILED],
    ['malformed json', async (req) => { req.handoff(); return 'not json'; }, RPC_CODES.BAD_RESPONSE],
    ['id mismatch', async (req) => {
      req.handoff();
      return JSON.stringify({ jsonrpc: '2.0', id: 'other', result: { status: 'OK', block_id: BLOCK_ID } });
    }, RPC_CODES.ID_MISMATCH],
    ['an old authentic refusal thrown by the transport', async (req) => { req.handoff(); throw refusal; }, RPC_CODES.TRANSPORT_FAILED],
  ];
  for (const [name, transport, code] of cases) {
    const rpc = createDaemonRpc({ transport });
    const c = submitOnce(rpc, 'aabbcc');
    assert.ok(await c.record.receipt, `${name}: no receipt`);
    await assert.rejects(() => c.record.outcome,
      (e) => e.code === code && classifySubmitFailure(c.proofs, { operation: c.operation, record: c.record }, e)
        === SUBMIT_DISPOSITION.AMBIGUOUS, name);
  }
});

// ---------------------------------------------------------------- the response envelope
test('a JSON-RPC error is an explicit refusal ONLY when it is shaped like one', async () => {
  const malformed = [
    ['error: null', null],
    ['error: a string', 'Block not accepted'],
    ['error: empty object', {}],
    ['error: code missing', { message: 'x' }],
    ['error: string code', { code: '-7', message: 'x' }],
    ['error: fractional code', { code: -7.5, message: 'x' }],
    ['error: message missing', { code: -7 }],
    ['error: non-string message', { code: -7, message: 42 }],
    ['error: unbounded message', { code: -7, message: 'x'.repeat(10_000) }],
    ['error: array', [-7, 'x']],
  ];
  for (const [name, error] of malformed) {
    const rpc = createDaemonRpc({ transport: fakeTransport((r) => ({ jsonrpc: '2.0', id: r.id, error })) });
    const c = submitOnce(rpc, 'aabbcc');
    await assert.rejects(() => c.record.outcome, (e) => {
      assert.equal(e.code, RPC_CODES.BAD_RESPONSE, name);
      assert.equal(c.proofs.refusalFor(c.record, e), false, name);
      assert.equal(classifySubmitFailure(c.proofs, { operation: c.operation, record: c.record }, e),
        SUBMIT_DISPOSITION.AMBIGUOUS, name);
      return true;
    });
  }
  const rpc = createDaemonRpc({
    transport: fakeTransport((r) => ({ jsonrpc: '2.0', id: r.id, error: { code: -7, message: 'Block not accepted' } })),
  });
  const c = submitOnce(rpc, 'aabbcc');
  await assert.rejects(() => c.record.outcome,
    (e) => e.code === RPC_CODES.DAEMON_ERROR
      && classifySubmitFailure(c.proofs, { operation: c.operation, record: c.record }, e)
        === SUBMIT_DISPOSITION.EXPLICIT_REJECTION);
});

test('a non-OK status is an explicit refusal ONLY when the status is a bounded string', async () => {
  const malformed = [
    ['status missing', {}],
    ['status null', { status: null }],
    ['status number', { status: 7 }],
    ['status object', { status: { value: 'BUSY' } }],
    ['status array', { status: ['BUSY'] }],
    ['status empty', { status: '' }],
    ['status unbounded', { status: 'B'.repeat(1000) }],
    ['status control chars', { status: 'BUSY\n\u0000' }],
  ];
  for (const [name, patch] of malformed) {
    const rpc = createDaemonRpc({
      transport: fakeTransport((r) => ok(r.id, { block_id: BLOCK_ID, ...patch })),
    });
    const c = submitOnce(rpc, 'aabbcc');
    await assert.rejects(() => c.record.outcome, (e) => {
      assert.equal(e.code, RPC_CODES.BAD_RESPONSE, name);
      assert.equal(classifySubmitFailure(c.proofs, { operation: c.operation, record: c.record }, e),
        SUBMIT_DISPOSITION.AMBIGUOUS, name);
      return true;
    });
  }
  const busy = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, { status: 'BUSY' })) });
  const c = submitOnce(busy, 'aabbcc');
  await assert.rejects(() => c.record.outcome,
    (e) => e.code === RPC_CODES.DAEMON_STATUS
      && classifySubmitFailure(c.proofs, { operation: c.operation, record: c.record }, e)
        === SUBMIT_DISPOSITION.EXPLICIT_REJECTION);
});

// ---------------------------------------------------------------- provenance, bound to the lineage
test('a caller-set definitelyNotSent or daemon code proves NOTHING', () => {
  const rpc = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, { status: 'OK', block_id: BLOCK_ID })) });
  const proofs = submissionProofs(rpc);
  const operation = Object.freeze({});
  rpc.prepareSubmission('aabbcc', operation);
  const forgedNotSent = Object.assign(new Error('x'), { code: RPC_CODES.PREPARED_CONSUMED, definitelyNotSent: true });
  assert.equal(proofs.notSentFor(operation, forgedNotSent), false);
  assert.equal(classifySubmitFailure(proofs, { operation }, forgedNotSent), SUBMIT_DISPOSITION.AMBIGUOUS);
  const forgedRefusal = Object.assign(new Error('x'), { code: RPC_CODES.DAEMON_ERROR });
  assert.equal(classifySubmitFailure(proofs, { operation, record: {} }, forgedRefusal), SUBMIT_DISPOSITION.AMBIGUOUS);
  for (const v of [null, undefined, 'x', 42, {}, []]) {
    assert.equal(proofs.notSentFor(operation, v), false);
    assert.equal(classifySubmitFailure(proofs, { operation }, v), SUBMIT_DISPOSITION.AMBIGUOUS);
  }
  // There is no proof object for something that is not an adapter, and no module-wide one.
  for (const v of [null, undefined, {}, { submissionAdapter: rpc }, 'x']) {
    assert.equal(submissionProofs(v), null);
  }
  assert.equal(classifySubmitFailure(null, { operation }, forgedNotSent), SUBMIT_DISPOSITION.AMBIGUOUS);
});

test('a LOOKALIKE or COPIED dispatch handle, or a read receipt, is not authenticated', async () => {
  const rpc = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, { status: 'OK', block_id: BLOCK_ID })) });
  const proofs = submissionProofs(rpc);
  const { operation, handle, record } = submitOnce(rpc, 'aabbcc');
  const lookalike = {
    kind: 'meepcoin-dispatch',
    handedOff: true,
    receipt: Promise.resolve({ method: 'submit_block', requestBytes: 1 }),
    outcome: Promise.resolve({ blockId: BLOCK_ID }),
  };
  assert.equal(proofs.dispatchFor(operation, lookalike), null);
  assert.equal(proofs.receiptFor(record, await lookalike.receipt), false);
  for (const v of [null, undefined, 'x', 42, Object.freeze({ kind: 'meepcoin-dispatch' })]) {
    assert.equal(proofs.dispatchFor(operation, v), null);
  }
  assert.ok(proofs.dispatchFor(operation, handle));
  assert.equal(proofs.dispatchFor(operation, { ...handle }), null, 'a spread copy of a handle authenticated');
  assert.equal(proofs.dispatchFor(Object.freeze({}), handle), null, 'a handle authenticated for another operation');
  // A read's handoff receipt is not a SUBMISSION receipt.
  let readReceipt = null;
  const reader = createDaemonRpc({
    transport: async (req) => {
      readReceipt = req.handoff();
      return JSON.stringify(ok(JSON.parse(req.body).id, POW));
    },
  });
  await reader.calcPow({ majorVersion: 16, height: '1', blockBlobHex: 'aabb', seedHashHex: SEED });
  assert.ok(readReceipt);
  assert.equal(submissionProofs(reader).receiptFor(record, readReceipt), false);
  assert.equal(proofs.receiptFor(record, readReceipt), false, 'a read receipt passed as a submission receipt');
  await handle.outcome;
});

test('an operation token is single-use, and a missing token proves nothing', () => {
  const rpc = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, { status: 'OK', block_id: BLOCK_ID })) });
  const proofs = submissionProofs(rpc);
  const operation = Object.freeze({});
  rpc.prepareSubmission('aabbcc', operation);
  let reused = null;
  try { rpc.prepareSubmission('ddeeff', operation); } catch (e) { reused = e; }
  assert.ok(reused, 'an operation token was accepted twice');
  // Without a token there is nothing for a refusal to be bound to.
  let untokened = null;
  try { rpc.prepareSubmission('zz'); } catch (e) { untokened = e; }
  assert.ok(untokened);
  assert.equal(proofs.notSentFor(undefined, untokened), false);
});

test('submitBlock is non-authoritative: it returns only the answer, never a certainty', async () => {
  const rpc = createDaemonRpc({ transport: fakeTransport((r) => ok(r.id, { status: 'OK', block_id: BLOCK_ID })) });
  const out = await rpc.submitBlock('aabbcc');
  assert.deepEqual(Object.keys(out), ['blockId']);
  assert.equal(submissionProofs(rpc).dispatchFor(undefined, out), null);
});

// ---------------------------------------------------------------- A9 allowlisted audit
test('A9: the audit record is an allowlist and cannot carry arbitrary material', () => {
  const meepAddress = `C${'x'.repeat(94)}`;          // a C-prefixed MeepCoin-style example address
  const secret = 'token hunter2-please-do-not-log-me';
  const rec = auditRecord({
    code: RPC_CODES.DAEMON_ERROR,
    method: 'submit_block',
    requestBytes: 321,
    responseBytes: 88,
    endpoint: { origin: 'http://127.0.0.1:19081', pathname: '/json_rpc' },
    // Fields a caller might try to smuggle in. None is on the allowlist.
    detail: `${secret} ${meepAddress}`,
    body: 'ab'.repeat(200),
    headers: { authorization: 'Bearer abc.def' },
  });
  const json = JSON.stringify(rec);
  assert.equal(json.includes(secret), false, 'arbitrary text reached the audit record');
  assert.equal(json.includes(meepAddress), false, 'a C-prefixed address reached the audit record');
  assert.equal(json.includes('Bearer'), false);
  assert.equal(json.includes('ab'.repeat(200)), false);
  assert.deepEqual(Object.keys(rec).sort(),
    ['code', 'endpointOrigin', 'endpointPath', 'method', 'requestBytes', 'responseBytes']);
  // An unknown method is normalised rather than echoed.
  assert.equal(auditRecord({ method: 'rm -rf' }).method, 'unknown');
  assert.equal(auditRecord({ code: 12345 }).code, 'rpc_unknown');
});

test('A9: every audit field is a CLOSED shape, not a pass-through string', () => {
  // `code`, `endpointOrigin` and `endpointPath` used to accept any string, which is a sink for an
  // arbitrary value dressed as a structured one.
  const secretish = 'hunter2-please-do-not-log-me';
  const rec = auditRecord({
    code: `rpc_${secretish}`,
    method: 'submit_block',
    requestBytes: 1.5,                                   // not an integer
    responseBytes: -4,                                   // not a count
    endpoint: { origin: `http://evil.example.com/?k=${secretish}`, pathname: `/${secretish}` },
  });
  assert.equal(rec.code, 'rpc_unknown', 'an unrecognised code was echoed verbatim');
  assert.equal(rec.endpointOrigin, null, 'a non-loopback origin passed through the audit record');
  assert.equal(rec.endpointPath, null, 'an arbitrary path passed through the audit record');
  assert.equal(rec.requestBytes, null);
  assert.equal(rec.responseBytes, null);
  assert.equal(JSON.stringify(rec).includes(secretish), false);

  // Every real code from the adapter's own closed set IS accepted, so the rule is closedness and
  // not merely rejection.
  for (const code of Object.values(RPC_CODES)) {
    assert.equal(auditRecord({ code }).code, code, code);
  }
  // And a genuine loopback endpoint survives intact.
  const good = auditRecord({ endpoint: { origin: 'http://[::1]:19081', pathname: '/json_rpc' } });
  assert.equal(good.endpointOrigin, 'http://[::1]:19081');
  assert.equal(good.endpointPath, '/json_rpc');
});

test('A9: redact() is documented as best-effort, and its known gaps are stated not hidden', () => {
  // What it DOES remove.
  assert.equal(redact('a'.repeat(64)).includes('a'.repeat(64)), false);
  assert.equal(redact('Authorization: Bearer abc.def.ghi').includes('abc.def.ghi'), false);
  assert.equal(redact('http://user:pass@127.0.0.1:19081/json_rpc').includes('pass@'), false);
  // What it does NOT: a C-prefixed address and arbitrary plaintext survive. This is asserted so the
  // limitation is visible in the suite rather than only in a comment -- and it is why auditRecord()
  // exists and why `.detail` is never an approved sink.
  const meepAddress = `C${'x'.repeat(94)}`;
  assert.equal(redact(`addr ${meepAddress}`).includes(meepAddress), true,
    'if this now passes, update the comment: redact() started covering C-prefixed addresses');
  assert.equal(redact('token hunter2').includes('hunter2'), true,
    'arbitrary plaintext is not removable by pattern; the allowlist is the protection');
});

test('get_info is read-only, strictly validated, and copies only fields that validate', async () => {
  const good = {
    status: 'OK', height: 2, top_block_hash: 'a'.repeat(64), synchronized: true,
    outgoing_connections_count: 1, incoming_connections_count: 1, nettype: 'testnet', offline: false,
    wide_difficulty: '0x1f4', some_unlisted_field: 'x'.repeat(100),
  };
  const t = fakeTransport((req) => ok(req.id, good));
  const rpc = createDaemonRpc({ transport: t });
  const info = await rpc.getInfo();
  // get_info's height is the chain LENGTH: 2 means the top block is at height 1.
  assert.deepEqual(info, {
    chainLength: 2, topHeight: 1, topBlockHash: 'a'.repeat(64), synchronized: true, outgoingConnections: 1,
    incomingConnections: 1, nettype: 'testnet', offline: false, wideDifficulty: '0x1f4',
  });
  assert.equal(t.calls[0].parsed.method, 'get_info');
  for (const [name, over] of [
    ['height', { height: -1 }],
    ['zero chain length', { height: 0 }],
    ['top hash', { top_block_hash: 'zz' }],
    ['synchronized', { synchronized: 'true' }],
    ['outgoing', { outgoing_connections_count: 1.5 }],
  ]) {
    const bad = createDaemonRpc({ transport: fakeTransport((req) => ok(req.id, { ...good, ...over })) });
    await assert.rejects(bad.getInfo(), (e) => e.code === RPC_CODES.BAD_RESPONSE, name);
  }
});
