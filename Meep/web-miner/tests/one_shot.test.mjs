// The Worker's own one-hash permit, and the page's mode-specific copy.
//
// NO BROWSER, NO WASM, NO SERVER. worker.js cannot be imported outside a browser (it imports
// /wasm/meepow.mjs from an absolute URL), so the permit lives in its own pure module and is
// exercised directly here; a source check then proves worker.js actually consults it.
//
// THE DEFECT BEING FIXED. "Exactly one hash" was guaranteed only by the page sending exactly one
// hash_one command. The Worker checked nothing but "is a hasher present", so a duplicate, stale,
// cross-run or post-stop command would have hashed again.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { ONE_SHOT_REFUSED, createOneShotPermit } from '../lib/shared/one_shot.js';
import { selectModeView } from '../lib/shared/protocol.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WEB = resolve(__dirname, '..');
const WORKER_SRC = readFileSync(resolve(WEB, 'worker.js'), 'utf8');
const INDEX_HTML = readFileSync(resolve(WEB, 'index.html'), 'utf8');
const APP_SRC = readFileSync(resolve(WEB, 'app.js'), 'utf8');

const GEN = 3;
const JOB = 'realjob-1111111111111111';
const NONCE = 1325931723;

// ================================================================== the permit
test('one permit, bound to the exact nonce, spent once and never reissued', () => {
  const p = createOneShotPermit();
  assert.equal(p.armed, false);
  // Nothing may be admitted before the permit exists.
  assert.equal(p.admit({ gen: GEN, jobId: JOB, nonce: NONCE }).reason, ONE_SHOT_REFUSED.NOT_ARMED);

  assert.equal(p.arm({ gen: GEN, jobId: JOB, nonce: NONCE }).ok, true);
  assert.equal(p.nonce, NONCE);
  assert.equal(p.spent, false);

  const admitted = p.admit({ gen: GEN, jobId: JOB, nonce: NONCE });
  assert.deepEqual(admitted, { ok: true, nonce: NONCE });
  assert.equal(p.spent, true);

  // A DUPLICATE COMMAND PERFORMS ZERO HASHES.
  for (let i = 0; i < 5; i++) {
    assert.equal(p.admit({ gen: GEN, jobId: JOB, nonce: NONCE }).reason, ONE_SHOT_REFUSED.ALREADY_HASHED);
  }
  // And re-arming -- even with a different nonce -- cannot restore or redirect it.
  assert.equal(p.arm({ gen: GEN, jobId: JOB, nonce: NONCE + 1 }).reason, ONE_SHOT_REFUSED.ALREADY_ARMED);
  assert.equal(p.nonce, NONCE);
});

test('arming refuses a nonce that is not ALREADY an exact uint32', () => {
  for (const bad of [-1, 2 ** 32, 2 ** 32 + 1, 1.5, NaN, Infinity, '7', `${NONCE}`, undefined, null, {}]) {
    const p = createOneShotPermit();
    assert.equal(p.arm({ gen: GEN, jobId: JOB, nonce: bad }).reason, ONE_SHOT_REFUSED.BAD_NONCE, String(bad));
    assert.equal(p.armed, false, String(bad));
  }
});

test('admission receives the RAW nonce and never coerces it', () => {
  // THE WITNESS: `msg.nonce >>> 0` ran before validation, so each of these became a valid uint32
  // -- -1 -> 4294967295, 2^32 -> 0, 2^32+1 -> 1, 1.5 -> 1, "7" -> 7 -- and could spend the permit.
  const coercible = [-1, 2 ** 32, 2 ** 32 + 1, 1.5, NaN, '7', `${NONCE}`, undefined, null, [NONCE]];
  for (const raw of coercible) {
    const p = createOneShotPermit();
    p.arm({ gen: GEN, jobId: JOB, nonce: NONCE });
    assert.equal(p.admit({ gen: GEN, jobId: JOB, nonce: raw }).reason, ONE_SHOT_REFUSED.BAD_NONCE, String(raw));
    assert.equal(p.spent, false, `${String(raw)} spent the permit`);
  }
  // A perfectly valid uint32 that is not the armed one is refused too.
  const p = createOneShotPermit();
  p.arm({ gen: GEN, jobId: JOB, nonce: NONCE });
  assert.equal(p.admit({ gen: GEN, jobId: JOB, nonce: NONCE + 1 }).reason, ONE_SHOT_REFUSED.WRONG_NONCE);
  assert.equal(p.admit({ gen: GEN, jobId: JOB, nonce: 0 }).reason, ONE_SHOT_REFUSED.WRONG_NONCE);
  assert.equal(p.spent, false);
});

test('a stale, cross-run or post-stop command is refused and costs nothing', () => {
  for (const [name, cmd, reason] of [
    ['older generation', { gen: GEN - 1, jobId: JOB, nonce: NONCE }, ONE_SHOT_REFUSED.STALE_GENERATION],
    ['newer generation', { gen: GEN + 1, jobId: JOB, nonce: NONCE }, ONE_SHOT_REFUSED.STALE_GENERATION],
    ['missing generation', { jobId: JOB, nonce: NONCE }, ONE_SHOT_REFUSED.STALE_GENERATION],
    ['another job', { gen: GEN, jobId: 'realjob-elsewhere', nonce: NONCE }, ONE_SHOT_REFUSED.WRONG_JOB],
    ['no job', { gen: GEN, nonce: NONCE }, ONE_SHOT_REFUSED.WRONG_JOB],
  ]) {
    const p = createOneShotPermit();
    p.arm({ gen: GEN, jobId: JOB, nonce: NONCE });
    assert.equal(p.admit(cmd).reason, reason, name);
    assert.equal(p.spent, false, `${name}: the permit was spent by a refused command`);
    assert.equal(p.admit({ gen: GEN, jobId: JOB, nonce: NONCE }).ok, true, name);
  }
  const stopped = createOneShotPermit();
  stopped.arm({ gen: GEN, jobId: JOB, nonce: NONCE });
  stopped.terminate();
  assert.equal(stopped.admit({ gen: GEN, jobId: JOB, nonce: NONCE }).reason, ONE_SHOT_REFUSED.TERMINATED);
  assert.equal(stopped.arm({ gen: GEN, jobId: JOB, nonce: NONCE }).reason, ONE_SHOT_REFUSED.TERMINATED);
  assert.equal(stopped.spent, false);
});

test('worker.js is wiring only: its onmessage hands every command to createWorkerCore', () => {
  // Wiring evidence only. The BEHAVIOUR is proven by web-miner/tests/worker_core.test.mjs, which
  // drives that same dispatcher.
  const code = WORKER_SRC.replace(/\/\/[^\n]*/g, '');
  assert.match(code, /import \{ createWorkerCore \} from '\.\/lib\/worker_core\.js';/);
  assert.match(code, /self\.onmessage = \(event\) => \{ core\.handle\(event\.data\); \};/);
  assert.equal(/hashOne\(/.test(code), false, 'worker.js hashes outside the dispatcher');
  assert.equal(/searchNonces\(\{/.test(code), false, 'worker.js scans outside the dispatcher');
});

// ================================================================== the page's mode-specific copy
test('the page shows exactly one mode block, and neither before the server has spoken', () => {
  // The mode-specific sections exist, and both start hidden.
  for (const id of ['synthetic-consent', 'sim-banner']) {
    const tag = INDEX_HTML.match(new RegExp(`<section[^>]*id="${id}"[^>]*>`));
    assert.ok(tag, `the page has no #${id} section`);
    assert.match(tag[0], /\shidden\b/, `#${id} does not start hidden`);
  }
  assert.match(INDEX_HTML, /<section[^>]*id="connecting-note"/);
  // app.js drives all three from selectModeView, not from a local guess.
  assert.match(APP_SRC, /selectModeView/);
  for (const el of ['connectingNote', 'syntheticConsent', 'simBanner']) {
    assert.match(APP_SRC, new RegExp(`els\\.${el}\\.hidden = !view\\.`), el);
  }
  // And the decision itself never shows two at once (also covered in protocol.test.mjs).
  assert.equal(selectModeView(undefined).showSynthetic, false);
});

test('the SIMULATION view states what is true here and nothing that is not', () => {
  const banner = INDEX_HTML.slice(INDEX_HTML.indexOf('id="sim-banner"'),
    INDEX_HTML.indexOf('id="connecting-note"'));

  // The statements this mode is required to make.
  const required = [
    /one predetermined nonce/i,
    /committed, daemon-generated local-devnet vector/i,
    /same implementation lineage/i,
    /live local native helper/i,
    /native C\+\+ child process/i,
    /exact same recorded context/i,
    /mock daemon.*in-memory|in-memory object with counters/i,
    /no daemon and no blockchain is contacted/i,
    /no block is mined, submitted or accepted/i,
  ];
  for (const re of required) {
    assert.match(banner, re, `the simulation view is missing: ${re}`);
  }
  // THE LOOKUP TABLE IS GONE FROM THE VERIFICATION PATH, so the page must not still describe it.
  assert.equal(/mock native/i.test(banner), false, 'the page still claims a mock native check');
  assert.equal(/lookup table/i.test(banner), false, 'the page still describes a lookup-table native check');

  // THE CONTRADICTORY SYNTHETIC CLAIMS LIVE ONLY IN THE SYNTHETIC SECTION.
  const consentStart = INDEX_HTML.indexOf('id="synthetic-consent"');
  const consentEnd = INDEX_HTML.indexOf('id="controls-h"');
  assert.ok(consentStart > 0 && consentEnd > consentStart);
  const consent = INDEX_HTML.slice(consentStart, consentEnd);
  const contradictions = [
    ['an accepted share', /accepted share/i],
    ['a synthetic job', /synthetic development job/i],
    ['two independently built copies', /two independently built copies/i],
    ['a live native child process', /native build, in its own child process/i],
    ['a four-hash batch', /every\s*<output id="batch-size">/i],
    ['pressing Start again for another run', /Press Start again for another run/i],
  ];
  for (const [what, re] of contradictions) {
    assert.match(consent, re, `the synthetic section no longer states: ${what}`);
    assert.equal(re.test(banner), false, `the simulation view states ${what}`);
  }

  // The footer's mode-specific halves are separate and both start hidden.
  for (const id of ['footer-synthetic', 'footer-simulation']) {
    const tag = INDEX_HTML.match(new RegExp(`<span[^>]*id="${id}"[^>]*>`));
    assert.ok(tag, `the footer has no #${id}`);
    assert.match(tag[0], /\shidden\b/, `#${id} does not start hidden`);
  }
  assert.equal(/the job is a fixed\s+synthetic one<\/span>/.test(INDEX_HTML), true);
});
