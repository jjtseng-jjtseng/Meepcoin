// The JavaScript client-message validator against the rules pool/protocol/pool_message.hpp
// already fixes. It is a second implementation of that schema, so the limits and the awkward
// details (nonce is exactly 8 lowercase hex chars; hex strings must have EVEN length because
// they are byte strings) are pinned here rather than left to drift.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  parseClientMessage,
  REJECT_REASONS,
  MAX_MESSAGE_BYTES,
  MAX_ID_LEN,
  MAX_RUN_GENERATION,
  MAX_VERSION_LEN,
  MAX_HASH_HEX,
  PROTOCOL_VERSION,
  RECORDED_SIMULATION_MODE,
  SYNTHETIC_MODE,
  selectModeView,
} from '../lib/shared/protocol.js';

const ISSUANCE = 'abcdef0123456789abcdef0123456789';
const START_ID = '0123456789abcdef0123456789abcdef';

const parse = (obj, byteLengthOverride) => {
  const text = JSON.stringify(obj);
  return parseClientMessage(byteLengthOverride ?? Buffer.byteLength(text, 'utf8'), text);
};

test('the limits match pool/protocol/pool_message.hpp', () => {
  assert.equal(MAX_MESSAGE_BYTES, 4096);
  assert.equal(MAX_ID_LEN, 64);
  assert.equal(MAX_VERSION_LEN, 32);
  assert.equal(MAX_HASH_HEX, 64);
});

test('the size cap is applied to the wire length before parsing', () => {
  const r = parseClientMessage(MAX_MESSAGE_BYTES + 1, '{"type":"ping"}');
  assert.equal(r.ok, false);
  assert.equal(r.reason, REJECT_REASONS.MESSAGE_TOO_LARGE);
  assert.equal(parseClientMessage(MAX_MESSAGE_BYTES, '{"type":"ping"}').ok, true);
});

test('valid client messages parse', () => {
  assert.equal(parse({ type: 'client_hello', protocolVersion: 1 }).ok, true);
  assert.equal(parse({ type: 'client_hello', protocolVersion: 1, clientVersion: 'x/1' }).ok, true);
  assert.equal(parse({ type: 'start_request' }).ok, true);
  assert.equal(parse({ type: 'ping' }).ok, true);
  assert.equal(parse({ type: 'pong' }).ok, true);
  const s = parse({ type: 'submit_share', jobId: 'devjob-1', workerId: 'w-1', nonce: '0000002a' });
  assert.equal(s.ok, true);
  assert.equal(s.nonce, 42, 'the nonce is decoded from big-endian hex');
  assert.equal(s.nonceHex, '0000002a');
  assert.equal(s.untrustedResultHash, '');
});

test('the nonce rule is exactly 8 lowercase hex characters', () => {
  const base = { type: 'submit_share', jobId: 'j', workerId: 'w' };
  assert.equal(parse({ ...base, nonce: '00000000' }).nonce, 0);
  assert.equal(parse({ ...base, nonce: 'ffffffff' }).nonce, 0xffffffff);
  for (const nonce of ['', '0', '2a', '0000002', '000000002a', '0000002A', '0000002g', ' 0000002a', 42, null, ['0000002a']]) {
    assert.equal(parse({ ...base, nonce }).ok, false, `nonce ${JSON.stringify(nonce)} must be refused`);
  }
});

test('hex fields require even length, as the C++ is_lower_hex does', () => {
  const base = { type: 'submit_share', jobId: 'j', workerId: 'w', nonce: '00000000' };
  assert.equal(parse({ ...base, resultHash: 'ab' }).ok, true);
  assert.equal(parse({ ...base, resultHash: 'ab'.repeat(32) }).ok, true, '64 chars is the cap, not an error');
  assert.equal(parse({ ...base, resultHash: 'abc' }).ok, false, 'odd length is not a byte string');
  assert.equal(parse({ ...base, resultHash: '' }).ok, false, 'empty is not valid hex');
  assert.equal(parse({ ...base, resultHash: 'ab'.repeat(33) }).ok, false, 'over the 64-char cap');
  assert.equal(parse({ ...base, resultHash: 'AB' }).ok, false, 'uppercase');
  assert.equal(parse({ ...base, resultHash: null }).ok, false);
  assert.equal(parse({ ...base, resultHash: 1234 }).ok, false);
  assert.equal(parse({ ...base, resultHash: {} }).ok, false);
});

test('the schema is closed: unknown fields are errors, not ignored', () => {
  assert.equal(parse({ type: 'ping', extra: 1 }).reason, REJECT_REASONS.BAD_SCHEMA);
  assert.equal(parse({ type: 'client_hello', protocolVersion: 1, address: 'abc' }).reason, REJECT_REASONS.BAD_SCHEMA);
  assert.equal(
    parse({ type: 'submit_share', jobId: 'j', workerId: 'w', nonce: '00000000', difficulty: 1 }).reason,
    REJECT_REASONS.BAD_SCHEMA,
  );
});

test('server-only and unknown message types are refused', () => {
  for (const type of ['job', 'share_accepted', 'share_rejected', 'server_hello', 'set_difficulty',
    'new_block', 'error', 'nonsense', 'mining_ready', 'mining_unavailable', 'demo_complete']) {
    assert.equal(parse({ type }).reason, REJECT_REASONS.UNKNOWN_TYPE, type);
  }
});

test('authorize_address is not part of this slice', () => {
  // There is no wallet, no address and no payout here, so the message type the C++ parser knows
  // about is deliberately not accepted by this server.
  assert.equal(parse({ type: 'authorize_address', address: 'Meep123' }).reason, REJECT_REASONS.UNKNOWN_TYPE);
});

test('non-object and unparseable roots are refused', () => {
  for (const text of ['', 'null', '[]', '"str"', '42', 'true', '{', '{"type":}', "{'type':'ping'}"]) {
    const r = parseClientMessage(Buffer.byteLength(text), text);
    assert.equal(r.ok, false, JSON.stringify(text));
    assert.ok([REJECT_REASONS.BAD_JSON, REJECT_REASONS.BAD_SCHEMA].includes(r.reason), `${text} -> ${r.reason}`);
  }
});

test('id and version length caps are enforced', () => {
  const ok = { type: 'submit_share', jobId: 'j'.repeat(MAX_ID_LEN), workerId: 'w'.repeat(MAX_ID_LEN), nonce: '00000000' };
  assert.equal(parse(ok).ok, true, 'exactly at the cap is allowed');
  assert.equal(parse({ ...ok, jobId: 'j'.repeat(MAX_ID_LEN + 1) }).ok, false);
  assert.equal(parse({ ...ok, workerId: 'w'.repeat(MAX_ID_LEN + 1) }).ok, false);
  assert.equal(parse({ ...ok, clientVersion: 'v'.repeat(MAX_VERSION_LEN) }).ok, true);
  assert.equal(parse({ ...ok, clientVersion: 'v'.repeat(MAX_VERSION_LEN + 1) }).ok, false);
});

test('protocolVersion must be a non-negative integer AND exactly the supported one', () => {
  // Malformed values are a schema error...
  for (const v of [-1, 1.5, '1', null, undefined, NaN, {}]) {
    const r = parse({ type: 'client_hello', protocolVersion: v });
    assert.equal(r.ok, false, String(v));
    assert.equal(r.reason, REJECT_REASONS.BAD_SCHEMA, String(v));
  }
  // ...and a well-formed but unsupported version is refused for being unsupported. This is where
  // the JavaScript pool is deliberately STRICTER than pool/protocol/pool_message.hpp, which
  // accepts any non-negative integer.
  for (const v of [0, 2, 999]) {
    const r = parse({ type: 'client_hello', protocolVersion: v });
    assert.equal(r.ok, false, String(v));
    assert.equal(r.reason, REJECT_REASONS.UNSUPPORTED_VERSION, String(v));
  }
  assert.equal(parse({ type: 'client_hello', protocolVersion: PROTOCOL_VERSION }).ok, true);
});

test('start_request is a closed consent message carrying at most a start correlation', () => {
  // The synthetic path sends it bare, and that must keep working byte for byte.
  const bare = parse({ type: 'start_request' });
  assert.equal(bare.ok, true);
  assert.equal(bare.clientStartId, null);
  assert.equal(parse({ type: 'start_request', force: true }).reason, REJECT_REASONS.BAD_SCHEMA);
  assert.equal(parse({ type: 'start_request', workerId: 'w-1' }).reason, REJECT_REASONS.BAD_SCHEMA);

  const withId = parse({ type: 'start_request', clientStartId: START_ID });
  assert.equal(withId.ok, true);
  assert.equal(withId.clientStartId, START_ID);

  // A CLOSED VALIDATED SHAPE: exactly 32 lowercase hex, nothing else.
  for (const bad of ['', 'abcd', START_ID.toUpperCase(), `${START_ID}0`, START_ID.slice(0, 31), 7, null, {}]) {
    assert.equal(parse({ type: 'start_request', clientStartId: bad }).reason,
      REJECT_REASONS.BAD_SCHEMA, JSON.stringify(bad));
  }
});

test('a real candidate REQUIRES its start correlation; a stop may carry one', () => {
  const candidate = {
    type: 'submit_real_candidate',
    jobId: 'realjob-x',
    issuanceId: ISSUANCE,
    workerId: 'w1',
    runGeneration: 3,
    nonce: 'deadbeef',
    clientStartId: START_ID,
  };
  assert.equal(parse(candidate).clientStartId, START_ID);
  const { clientStartId, ...withoutId } = candidate;
  assert.equal(parse(withoutId).reason, REJECT_REASONS.BAD_SCHEMA,
    'a candidate without a start correlation was accepted');
  assert.equal(parse({ ...candidate, clientStartId: 'abcd' }).reason, REJECT_REASONS.BAD_SCHEMA);

  const stop = {
    type: 'stop_request', workerId: 'w1', runGeneration: 3, jobId: 'j', issuanceId: ISSUANCE,
  };
  assert.equal(parse(stop).ok, true, 'the bare bound stop must still parse');
  assert.equal(parse(stop).clientStartId, null);
  assert.equal(parse({ ...stop, clientStartId: START_ID }).clientStartId, START_ID);
  assert.equal(parse({ ...stop, clientStartId: 'nope' }).reason, REJECT_REASONS.BAD_SCHEMA);
});

test('every protocol count is a SAFE integer inside a range, not merely an integer', () => {
  // Number.isInteger(2**53) is true, and 2**53 + 1 === 2**53, so two different generations would
  // compare equal. Each of these must be refused rather than silently collapsed.
  const stop = {
    type: 'stop_request', workerId: 'w1', jobId: 'j', issuanceId: ISSUANCE,
  };
  const candidate = {
    type: 'submit_real_candidate', jobId: 'j', issuanceId: ISSUANCE, workerId: 'w1',
    nonce: 'deadbeef', clientStartId: START_ID,
  };
  const unsafe = [
    Number.MAX_SAFE_INTEGER + 1,
    2 ** 53,
    1e300,
    Infinity,
    -Infinity,
    NaN,
    -1,
    1.5,
    MAX_RUN_GENERATION + 1,
    '3',
  ];
  for (const runGeneration of unsafe) {
    assert.equal(parse({ ...stop, runGeneration }).reason, REJECT_REASONS.BAD_SCHEMA, `stop ${runGeneration}`);
    assert.equal(parse({ ...candidate, runGeneration }).reason, REJECT_REASONS.BAD_SCHEMA,
      `candidate ${runGeneration}`);
  }
  // The bounds themselves are accepted.
  for (const runGeneration of [0, 1, MAX_RUN_GENERATION]) {
    assert.equal(parse({ ...stop, runGeneration }).ok, true, `stop ${runGeneration}`);
    assert.equal(parse({ ...candidate, runGeneration }).ok, true, `candidate ${runGeneration}`);
  }
});

test('selectModeView shows exactly one block, and NEITHER before the server has spoken', () => {
  const before = selectModeView(undefined);
  assert.deepEqual(before, { showConnecting: true, showSynthetic: false, showSimulation: false });
  // An unrecognised mode is treated as "not yet known", never as synthetic.
  for (const unknown of [null, '', 'simluation', 'recorded', 0, {}]) {
    assert.equal(selectModeView(unknown).showSynthetic, false, JSON.stringify(unknown));
    assert.equal(selectModeView(unknown).showSimulation, false, JSON.stringify(unknown));
  }
  assert.deepEqual(selectModeView(SYNTHETIC_MODE),
    { showConnecting: false, showSynthetic: true, showSimulation: false });
  assert.deepEqual(selectModeView(RECORDED_SIMULATION_MODE),
    { showConnecting: false, showSynthetic: false, showSimulation: true });
  // Never two at once.
  for (const mode of [undefined, SYNTHETIC_MODE, RECORDED_SIMULATION_MODE, 'nonsense']) {
    const v = selectModeView(mode);
    assert.equal([v.showConnecting, v.showSynthetic, v.showSimulation].filter(Boolean).length, 1,
      String(mode));
  }
});

test('prototype-pollution shaped payloads are refused, not merged', () => {
  const r = parseClientMessage(200, '{"type":"submit_share","jobId":"j","workerId":"w","nonce":"00000000","__proto__":{"admin":true}}');
  // Either the key is seen as unexpected, or JSON.parse drops it; neither may grant anything.
  assert.equal({}.admin, undefined);
  assert.ok(r.ok === false || r.admin === undefined);
});
