// PRE-START TRUTH in real-local-daemon mode: before Start, before any Worker, verifier, helper, allocation
// or hash, what this page states must not contradict the server-selected sequenceTotal.
//
// THE WITNESS (Regression testing, b6d8df25): in the trusted two-block mode the server's labels and notice said one
// Start covers at most two templates, while the page's own always-visible real-mode fact said the browser
// searches "one fresh block template ... once" -- both on screen before Start. The lede also said there
// is no MeepCoin network at all while real mode runs a private local devnet, and the footer said "no
// testnet" beside labels describing private testnet nodes.
//
// The static facts are now neutral (exactly true in both real modes) and the count comes only from the
// server. This drives a real server hello, for both paired profiles, into the real page controller.
// No browser, socket, listener, daemon or helper.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { createMiningController } from '../lib/controller.js';
import {
  REAL_DAEMON_PROFILE, REAL_P2P_PROFILE, REAL_P2P_SEQUENCE_PROFILE, createSimulationContext,
  createSimulationSession, realSequenceProfile,
} from '../../pool/dev/sim_session.mjs';
import { buildScriptedChain } from '../../pool/dev/tests/in_memory_chain.mjs';

const HTML = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '../index.html'), 'utf8');
const text = (fragment) => fragment.replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/g, ' ').replace(/\s+/g, ' ').trim();
const section = (re) => { const m = re.exec(HTML); assert.ok(m, `missing ${re}`); return text(m[1]); };

/** What the page holds before Start for one server profile, through a real hello and the real controller. */
async function beforeStart(sequenceBlocks) {
  const chain = await buildScriptedChain({}, { sequenceBlocks });
  // The server's own selection (server.mjs): the sequence profile only when the builder produced one.
  const profile = chain.built.sequence ? realSequenceProfile(chain.built.sequence.total) : REAL_P2P_PROFILE;
  const sim = createSimulationContext({ ...chain.built, profile });
  let session = null;
  const socket = { onopen: null, onmessage: null, onclose: null, onerror: null, send(t) { session.handleRaw(Buffer.byteLength(t), t); }, close() {} };
  const hellos = [];
  session = createSimulationSession({
    sim,
    send: (o) => { if (o.type === 'server_hello') hellos.push(o); socket.onmessage?.({ data: JSON.stringify(o) }); },
    setTimer: () => ({}),
    clearTimer: () => {},
  });
  const controller = createMiningController({ createSocket: () => socket, createWorker: () => { throw new Error('a Worker before Start'); } });
  controller.connect('ws://127.0.0.1:1/ws');
  socket.onopen();
  await new Promise((r) => setImmediate(r));
  return { hello: hellos[0], snapshot: controller.snapshot(), controller, sim };
}

test('PRE-START TRUTH: the static page facts are exactly true in both real modes, and the count comes from the server', async () => {
  // ---- the page's own always-visible real-mode facts: per template, no count of its own -------------
  const truths = section(/<ul class="facts" id="real-truths">([\s\S]*?)<\/ul>/);
  assert.equal(/one fresh block template/i.test(truths), false, 'the page claims one template');
  assert.equal(/at most once, never retried/i.test(truths), false, 'the page claims one submission overall');
  assert.match(truths, /each fresh block template it actually starts at most once/);
  assert.match(truths, /may supersede queued work before the browser starts it; that skipped template is never searched/);
  assert.equal(/each fresh block template the server issues exactly once/.test(truths), false,
    'the page must not claim that every server-issued template reaches the Worker');
  assert.match(truths, /per template/);
  assert.match(truths, /one, or a finite development sequence of at most 32/);
  assert.match(truths, /at most once per template, never retried/);
  // ---- no absolute "no network" / "no testnet" beside private testnet nodes --------------------------
  const lede = section(/<p class="lede">([\s\S]*?)<\/p>/);
  assert.equal(/there is no such network/i.test(lede), false);
  assert.match(lede, /no public MeepCoin network and no coin of value/);
  assert.match(lede, /private development network on this computer only/);
  const footer = section(/<footer>([\s\S]*?)<\/footer>/);
  assert.equal(/no mainnet, no testnet/i.test(footer), false);
  assert.match(footer, /no public mainnet, no public testnet and no coin of value/);

  // ---- ONE-SHOT pair: the server says one template, and nothing says two ----------------------------
  const one = await beforeStart(1);
  assert.equal(one.hello.sequenceTotal, undefined);
  assert.equal(one.snapshot.realSequenceTotal, 1);
  const oneSays = [...one.snapshot.simLabels, one.snapshot.simNotice, one.snapshot.simAllocateNotice].join(' | ');
  assert.match(oneSays, /ONE FRESH BLOCK TEMPLATE FROM NODE A/);
  assert.match(oneSays, /Start runs ONE bounded browser search/);
  assert.equal(/\bTWO\b[^|]*(TEMPLATES|BLOCKS)|second template/i.test(oneSays), false, `one-shot text mentions a second template: ${oneSays}`);

  // ---- TWO-BLOCK: the server says at most two, and nothing says one template or one search ----------
  const two = await beforeStart(2);
  assert.equal(two.hello.sequenceTotal, 2);
  assert.equal(two.snapshot.realSequenceTotal, 2);
  const twoSays = [...two.snapshot.simLabels, two.snapshot.simNotice, two.snapshot.simAllocateNotice].join(' | ');
  assert.match(twoSays, /AT MOST TWO \(2\) SEQUENTIAL FRESH BLOCK TEMPLATES/);
  assert.match(twoSays, /at most TWO \(2\) consecutive positions/);
  assert.match(twoSays, /Before each further template the server closes that verifier and helper/);
  assert.equal(/ONE FRESH BLOCK TEMPLATE|Start runs ONE bounded browser search/.test(twoSays), false, `two-block text claims one: ${twoSays}`);

  // ---- TWELVE-BLOCK: the exact configured count reaches the page; no old "two" cap survives ----
  const twelve = await beforeStart(12);
  assert.equal(twelve.hello.sequenceTotal, 12);
  assert.equal(twelve.snapshot.realSequenceTotal, 12);
  const twelveSays = [...twelve.snapshot.simLabels, twelve.snapshot.simNotice, twelve.snapshot.simAllocateNotice].join(' | ');
  assert.match(twelveSays, /AT MOST TWELVE \(12\) SEQUENTIAL FRESH BLOCK TEMPLATES/);
  assert.match(twelveSays, /at most TWELVE \(12\) consecutive positions/);
  assert.equal(/AT MOST TWO \(2\)|at most TWO \(2\)/.test(twelveSays), false, `twelve-block text still claims two: ${twelveSays}`);

  // The smallest extended sequence and the absolute build ceiling are exact too.
  const configured = [];
  for (const total of [3, 32]) {
    const run = await beforeStart(total);
    configured.push(run);
    const says = [...run.snapshot.simLabels, run.snapshot.simNotice].join(' | ');
    assert.equal(run.hello.sequenceTotal, total);
    assert.equal(run.snapshot.realSequenceTotal, total);
    assert.ok(says.includes(`(${total})`), `configured count ${total} is absent`);
  }

  // ---- all of this is said before anything exists -------------------------------------------------
  for (const s of [one, two, twelve, ...configured]) {
    assert.equal(s.controller.workersCreated, 0);
    assert.equal(s.sim.verifier, null);
    assert.equal(s.snapshot.hashes, 0);
  }
  // The single offline daemon keeps its one-template wording, and only the sequence profile has a count.
  assert.match(REAL_DAEMON_PROFILE.helloNotice, /Start runs ONE bounded browser search/);
  assert.deepEqual([REAL_DAEMON_PROFILE.sequenceBlocks, REAL_P2P_PROFILE.sequenceBlocks, REAL_P2P_SEQUENCE_PROFILE.sequenceBlocks], [undefined, undefined, 2]);
});
