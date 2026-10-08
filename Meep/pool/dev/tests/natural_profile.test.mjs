// The natural-difficulty page contract is selected only from trusted builder output.
// No daemon, listener, browser or worker is started by this file.
import test from 'node:test';
import assert from 'node:assert/strict';

import { selectSimulationProfile } from '../server.mjs';
import { REAL_P2P_NATURAL_PROFILE, realNaturalSequenceProfile } from '../sim_session.mjs';

test('one-height natural pair discloses daemon-selected difficulty', () => {
  const profile = selectSimulationProfile({ naturalDifficulty: true, peer: {} });
  assert.equal(profile, REAL_P2P_NATURAL_PROFILE);
  assert.match(profile.helloNotice, /No fixed-difficulty option is set/);
  assert.equal(profile.labels.some((label) => /FIXED TEST DIFFICULTY 500/.test(label)), false);
});

test('natural pair discloses the exact two- or three-height bound and no fixed target', () => {
  for (const total of [2, 3]) {
    const profile = selectSimulationProfile({ naturalDifficulty: true, peer: {}, sequence: { total } });
    assert.deepEqual(profile.labels, realNaturalSequenceProfile(total).labels);
    assert.match(profile.helloNotice, new RegExp(`at most ${total === 2 ? 'two' : 'three'} \\(${total}\\) consecutive heights`));
    assert.match(profile.helloNotice, /selects difficulty independently/);
    assert.match(profile.helloNotice, /A block may not be found/);
    assert.equal(profile.labels.some((label) => /FIXED TEST DIFFICULTY 500/.test(label)), false);
  }
});

test('natural profile refuses incompatible or forged builder shapes', () => {
  for (const built of [
    { naturalDifficulty: true },
    { naturalDifficulty: true, peer: {}, shareWork: true },
    { naturalDifficulty: true, peer: {}, refresh: {} },
    { naturalDifficulty: true, peer: {}, sequence: { total: 4 } },
  ]) assert.throws(() => selectSimulationProfile(built), TypeError);
});
