import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ASSIGNED_HASHES_PER_SECOND, REACHABILITY_MODES, assignedThirdShare,
  candidateTimestamp, createHashSchedule, thirdTimestampDecision,
} from './fresh_reachability_core.mjs';

test('assigned resources make the third miner a minority before outcome', () => {
  assert.deepEqual(assignedThirdShare(), { numerator: 9, denominator: 99 });
  assert.deepEqual(ASSIGNED_HASHES_PER_SECOND, { h1: 45, h2: 45, third: 9 });
  assert.throws(() => assignedThirdShare({ h1: 4, h2: 4, third: 9 }), /minority/);
});

test('both arms calculate the same legal candidate; only attack applies it', () => {
  for (const height of [1, 2, 61, 62]) {
    const args = { height, medianTimestamp: 1000, nowSeconds: 2000, templateTimestamp: 2000 };
    const control = thirdTimestampDecision({ mode: REACHABILITY_MODES.CONTROL, ...args });
    const attack = thirdTimestampDecision({ mode: REACHABILITY_MODES.ATTACK, ...args });
    assert.equal(control.computedTimestamp, attack.computedTimestamp);
    assert.equal(control.appliedTimestamp, 2000);
    assert.equal(attack.appliedTimestamp, height % 2 ? 1000 : 9195);
    assert.equal(control.candidateDiscarded, true);
    assert.equal(attack.candidateDiscarded, false);
  }
});

test('timestamp policy refuses stale or malformed conditions', () => {
  assert.throws(() => candidateTimestamp({ height: 0, medianTimestamp: 0, nowSeconds: 1 }), /height/);
  assert.throws(() => candidateTimestamp({ height: 1, medianTimestamp: 10000, nowSeconds: 1 }), /legal/);
  assert.throws(() => thirdTimestampDecision({ mode: 'HONEST', height: 1, medianTimestamp: 1,
    nowSeconds: 2, templateTimestamp: 2 }), /mode/);
  assert.throws(() => thirdTimestampDecision({ mode: 'ATTACK', height: 1, medianTimestamp: 3,
    nowSeconds: 4, templateTimestamp: 2 }), /template timestamp/);
});

test('fixed schedule never catches up missed hash opportunities', () => {
  const s = createHashSchedule({ startMs: 1000, ratePerSecond: 10 });
  assert.deepEqual(s.claim(900), { ready: false, waitMs: 100 });
  assert.deepEqual(s.claim(1000), { ready: true, slot: 0, skippedBefore: 0 });
  assert.deepEqual(s.claim(1001), { ready: false, waitMs: 99 });
  assert.deepEqual(s.claim(1350), { ready: true, slot: 3, skippedBefore: 2 });
  assert.equal(s.missedSlots, 2);
  assert.deepEqual(s.claim(1351), { ready: false, waitMs: 49 });
});
