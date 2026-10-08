import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as httpRequest } from 'node:http';
import { Application } from '../src/application.mjs';
import { dashboard } from '../src/dashboard.mjs';
import { privateIPv4, difficultyTarget, parseInvite, newJob, validateLedger, blockDigest } from '../src/protocol.mjs';
import { checkHashIdentity } from '../src/workers.mjs';
import createModule from '../vendor/meephash/meepow.mjs';
import { createV2Hasher } from '../vendor/meephash/wasm_hasher.js';
import { bytesToHex, hexToBytes, meetsTargetLE } from '../vendor/meephash/target.js';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(predicate, timeout = 90_000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { const result = await predicate(); if (result) return result; await delay(80); }
  throw new Error('Timed out waiting for the expected lab behavior.');
}
const directory = () => mkdtemp(join(tmpdir(), 'meep-lab-test-'));

test('only private numeric IPv4 and valid, unexpired invites are accepted', () => {
  assert.equal(privateIPv4('192.168.1.10'), true); assert.equal(privateIPv4('172.16.3.1'), true);
  for (const ip of ['0.0.0.0', '8.8.8.8', '127.0.0.1', '192.168.1.999', '192.168.01.2', 'localhost', '169.254.1.2']) assert.equal(privateIPv4(ip), false);
  assert.equal(privateIPv4('127.0.0.1', true), true);
  assert.throws(() => parseInvite('http://example.com')); assert.throws(() => parseInvite('MEEP-LAB1:bad'));
  assert.throws(() => difficultyTarget(1)); assert.equal(difficultyTarget(8).length, 64);
});

test('bundled MeepHash-W v2 artifact pins and all 20 known-answer vectors match', async () => {
  await checkHashIdentity();
  const hasher = await createV2Hasher(createModule);
  try {
    const lines = (await readFile(new URL('../vendor/meephash/vectors_v2.txt', import.meta.url), 'utf8')).trim().split(/\r?\n/);
    assert.equal(lines.length, 20);
    for (const line of lines) { const [, , nonce, hash] = line.trim().split(/\s+/); assert.equal(bytesToHex(hasher.hashOne(Number(nonce))), hash); }
  } finally { hasher.free(); }
});

test('real solo proof, verified credit, export, clean stop and restart persistence', async t => {
  const dir = await directory(); const app = await Application.create(dir);
  t.after(() => app.close());
  assert.equal(app.miner.worker, null);
  await app.createRoom({ name: 'Solo test', difficulty: 8 });
  assert.equal(app.miner.worker, null); assert.equal(app.room.blocks.length, 0);
  app.miner.setDuty(100); app.startMining();
  await until(() => app.room.blocks.length >= 1);
  await app.command('stop');
  const state = await app.snapshot();
  assert.ok(state.miner.hashes > 0); assert.equal(state.miner.hashrate, 0); assert.equal(state.miner.running, false); assert.equal(app.miner.worker, null);
  assert.equal(state.ownBalance, state.room.height * 10);
  for (const b of app.room.blocks) assert.equal(meetsTargetLE(hexToBytes(b.proof), hexToBytes(b.target)), true);
  const id = app.room.id, height = app.room.blocks.length, tip = app.room.tip;
  assert.equal(validateLedger(app.room.data).id, id);
  const exported = await app.exportLedger(); assert.match((await readFile(exported.path, 'utf8')), /Non-spendable/);
  await app.leave(); await app.createRoom({ resumeId: id });
  assert.equal(app.room.blocks.length, height); assert.equal(app.room.tip, tip); assert.equal(app.miner.running, false); assert.equal(app.miner.worker, null);
});

test('TLS room approval, two real miners, same history, replay refusal and host-loss stop', async t => {
  const host = await Application.create(await directory()), guest = await Application.create(await directory());
  t.after(async () => { await guest.close(); await host.close(); });
  await host.createRoom({ name: 'Two-device test', difficulty: 8 });
  const invite = await host.room.enableNetwork('127.0.0.1');
  await guest.joinRoom({ invite, deviceName: 'Second device' });
  await until(() => host.room.pending.size === 1, 10_000);
  assert.equal(guest.client.approved, false); assert.equal(guest.miner.worker, null); assert.throws(() => guest.startMining());
  host.room.approve([...host.room.pending.keys()][0], true);
  await until(() => guest.client.approved, 10_000);
  const hostJob = host.room.job(host.profile.id), guestJob = host.room.job(guest.profile.id);
  assert.equal(hostJob.round, guestJob.round); assert.equal(hostJob.template, guestJob.template); assert.ok(hostJob.end < guestJob.start);
  host.room.setActive(host.profile.id, true);
  const bad = await host.room.submit(host.profile.id, { round: hostJob.round, nonce: guestJob.start, proof: '0'.repeat(64) }); assert.equal(bad.accepted, false); assert.match(bad.reason, /nonce partition/);
  host.room.setActive(host.profile.id, false);
  host.miner.setDuty(100); guest.miner.setDuty(100); host.startMining(); guest.startMining();
  await until(() => host.room.blocks.length >= 2);
  await host.command('stop'); await guest.command('stop');
  await until(() => guest.client.state.height === host.room.blocks.length, 10_000);
  assert.equal(guest.client.state.tip, host.room.tip);
  assert.ok(host.miner.hashes > 0); assert.ok(guest.miner.hashes > 0);
  const b = host.room.blocks[0];
  host.room.setActive(host.profile.id, true);
  const replay = await host.room.submit(host.profile.id, { round: b.round, nonce: b.nonce, proof: b.proof }); assert.equal(replay.accepted, false); assert.match(replay.reason, /Stale/);
  host.room.setActive(host.profile.id, false);
  const corrupt = structuredClone(host.room.data); corrupt.blocks[0].reward = 100; assert.throws(() => validateLedger(corrupt));
  const invalidTarget = structuredClone(host.room.data); invalidTarget.blocks[0].proof = 'f'.repeat(64); invalidTarget.blocks[0].hash = blockDigest(invalidTarget.blocks[0]); assert.throws(() => validateLedger(invalidTarget));
  const badState = structuredClone(guest.client.state); badState.devices[0].name = {}; assert.throws(() => guest.client.validateState(badState));
  guest.startMining(); await until(() => guest.miner.worker !== null, 10_000);
  await host.leave(); await until(() => guest.miner.running === false, 15_000);
  assert.equal(guest.miner.worker, null); assert.equal(guest.role, 'disconnected');
});

test('wrong certificate pin cannot reveal identity, request approval or start mining', async t => {
  const host = await Application.create(await directory()), guest = await Application.create(await directory());
  t.after(async () => { await guest.close(); await host.close(); });
  await host.createRoom({ difficulty: 8 }); const invite = parseInvite(await host.room.enableNetwork('127.0.0.1'));
  invite.pin = '0'.repeat(64);
  await guest.joinRoom({ invite: `MEEP-LAB1:${Buffer.from(JSON.stringify(invite)).toString('base64url')}` });
  await until(() => guest.role === 'disconnected', 10_000);
  assert.match(guest.connectionStatus, /certificate/); assert.equal(host.room.pending.size, 0); assert.equal(guest.miner.worker, null);
});

test('Stop during verification and close during LAN setup leave no fatal room or listener', async t => {
  const app = await Application.create(await directory()); t.after(() => app.close());
  await app.createRoom({ difficulty: 8 });
  const room = app.room; room.setActive(app.profile.id, true);
  const job = room.job(app.profile.id);
  const verification = room.submit(app.profile.id, { round: job.round, nonce: job.start, proof: '0'.repeat(64) });
  room.setActive(app.profile.id, false);
  const result = await verification;
  assert.equal(result.accepted, false); assert.equal(room.fatal, null); assert.equal(room.blocks.length, 0);
  room.setActive(app.profile.id, true); room.setActive(app.profile.id, false);
  const sharing = room.enableNetwork('127.0.0.1');
  await assert.rejects(room.enableNetwork('127.0.0.1'), /already enabled/);
  const closing = room.close();
  await assert.rejects(sharing, /closed/); await closing;
  assert.equal(room.network, null); assert.equal(room.heartbeat, undefined);
  assert.equal(room.inviteSecret, null); assert.equal(room.verifier.worker, null);
});

test('dashboard rejects cross-origin mutation, missing capability and DNS rebinding host', async t => {
  const app = await Application.create(await directory()), web = await dashboard(app);
  t.after(async () => { await app.close(); await web.close(); });
  const html = await (await fetch(web.url)).text();
  const key = /name="lab-key" content="([a-f0-9]+)"/.exec(html)[1];
  assert.equal((await fetch(`${web.url}/api/state`)).status, 403);
  assert.equal((await fetch(`${web.url}/api/state`, { headers: { 'X-Lab-Key': key, Origin: 'https://evil.example' } })).status, 403);
  // Node fetch normalizes Host; use an actual HTTP request with the hostile Host header.
  const hostileHost = await new Promise((resolve, reject) => { const req = httpRequest(web.url, { headers: { Host: 'evil.example' } }, res => { res.resume(); resolve(res.statusCode); }); req.on('error', reject); req.end(); });
  assert.equal(hostileHost, 403);
  assert.equal((await fetch(`${web.url}/api/state`, { headers: { 'X-Lab-Key': key } })).status, 200);
  const response = await fetch(`${web.url}/api/command`, { method: 'POST', headers: { 'X-Lab-Key': key, 'Content-Type': 'application/json', Origin: web.url }, body: JSON.stringify({ action: 'create', payload: { name: 'API room', difficulty: 8 } }) });
  assert.equal(response.status, 200); assert.equal(app.miner.worker, null);
});

test('browser/app controls share state, require the local capability and quit only after stop', async t => {
  const app = await Application.create(await directory());
  const desktop = { mode: 'app', switches: [], quitCalled: false,
    async setMode(mode) { this.mode = mode; this.switches.push(mode); },
    quit() { this.quitCalled = true; assert.equal(app.miner.running, false); },
  };
  const web = await dashboard(app, { desktop });
  t.after(async () => { await app.close(); await web.close(); });
  const html = await (await fetch(web.url)).text();
  const moreOptions = html.indexOf('<details id="more-options">');
  assert.ok(moreOptions > html.indexOf('id="display-button"'), 'View switch belongs on the main screen.');
  assert.ok(html.indexOf('id="quit-button"') > moreOptions, 'Quit remains in More options.');
  assert.equal((html.match(/id="display-button"/g) || []).length, 1);
  const key = /name="lab-key" content="([a-f0-9]+)"/.exec(html)[1];
  const send = (action, payload, headers = {}) => fetch(`${web.url}/api/command`, { method: 'POST', headers: { 'X-Lab-Key': key, 'Content-Type': 'application/json', ...headers }, body: JSON.stringify({ action, payload }) });
  assert.equal((await send('display', { mode: 'browser' }, { Origin: 'https://evil.example' })).status, 403);
  assert.equal((await send('display', { mode: 'browser' }, { 'X-Lab-Key': '' })).status, 403);
  assert.deepEqual(desktop.switches, []);
  assert.equal((await send('display', { mode: 'remote' })).status, 400);
  const browser = await (await send('display', { mode: 'browser' })).json();
  assert.equal(browser.desktop.mode, 'browser'); assert.equal(browser.desktop.url, web.url);
  assert.equal(browser.miner.running, false); assert.equal(browser.role, 'idle');
  const window = await (await send('display', { mode: 'app' })).json();
  assert.equal(window.profile.id, browser.profile.id); assert.equal(window.desktop.mode, 'app');
  await send('create', { difficulty: 8 }); await send('start');
  assert.equal(app.miner.running, true);
  assert.equal((await send('quit', {}, { Origin: 'https://evil.example' })).status, 403);
  assert.equal(desktop.quitCalled, false); assert.equal(app.miner.running, true);
  const quit = await (await send('quit')).json(); assert.equal(quit.quitting, true);
  await until(() => desktop.quitCalled); assert.equal(app.miner.worker, null);
});
