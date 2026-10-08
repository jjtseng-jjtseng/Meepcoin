import { EventEmitter } from 'node:events';
import { createServer } from 'node:https';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';
import selfsigned from 'selfsigned';
import { Verifier } from './workers.mjs';
import { saveRoom, readRoom } from './storage.mjs';
import { VERSION, REWARD, MAX_DEVICES, MAX_BLOCKS, MAX_MESSAGE, randomId, sha256, cleanName, privateIPv4, newJob, isHex, blockDigest, difficultyTarget } from './protocol.mjs';

const safeSecret = (a, b) => isHex(a, 64) && timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
const send = (ws, value) => { if (ws.readyState === WebSocket.OPEN) { if (ws.bufferedAmount > 1024 * 1024) ws.terminate(); else ws.send(JSON.stringify(value)); } };

export class Room extends EventEmitter {
  static async create(options) {
    const room = new Room(options);
    room.data = options.resumeId ? await readRoom(options.directory, options.resumeId) : {
      version: VERSION, id: randomId(), name: cleanName(options.name || 'My mining room'), difficulty: options.difficulty ?? 32,
      created: new Date().toISOString(), blocks: [],
    };
    difficultyTarget(room.data.difficulty);
    if (!options.resumeId) await saveRoom(options.directory, room.data);
    room.nextRound();
    return room;
  }
  constructor({ directory, profile }) {
    super(); this.directory = directory; this.profile = profile; this.closed = false; this.busy = false; this.fatal = null;
    this.devices = new Map([[profile.id, { id: profile.id, name: profile.name, slot: 0, active: false, rate: 0, host: true }]]);
    this.pending = new Map(); this.verifier = new Verifier(); this.network = null;
  }
  get id() { return this.data.id; }
  get blocks() { return this.data.blocks; }
  get difficulty() { return this.data.difficulty; }
  get tip() { return this.blocks.at(-1)?.hash ?? '0'.repeat(64); }
  nextRound() { this.round = { id: randomId(), seed: randomBytes(32).toString('hex'), started: Date.now() }; }
  job(id) { const d = this.devices.get(id); if (!d) throw new Error('Device is not approved.'); return newJob(this, d.slot); }
  snapshot() {
    const balances = {};
    for (const b of this.blocks) balances[b.winnerId] = (balances[b.winnerId] ?? 0) + b.reward;
    return { version: VERSION, id: this.id, name: this.data.name, difficulty: this.difficulty, reward: REWARD, round: this.round.id, seed: this.round.seed,
      roundStarted: this.round.started, height: this.blocks.length, tip: this.tip, totalMinted: this.blocks.length * REWARD, balances,
      devices: [...this.devices.values()].map(({ id, name, active, rate, host }) => ({ id, name, active, rate, host })),
      // Bounded live view. The host's full ledger is separately exportable.
      blocks: this.blocks.slice(-100), fatal: this.fatal };
  }
  publish(jobs = false) {
    if (this.closed) return;
    const state = this.snapshot();
    this.emit('state', state);
    for (const d of this.devices.values()) if (d.ws) { send(d.ws, { type: 'state', state }); if (jobs && d.active) send(d.ws, { type: 'job', job: this.job(d.id) }); }
    if (jobs && this.devices.get(this.profile.id).active) this.emit('job', this.job(this.profile.id));
  }
  setActive(id, active) {
    if (this.closed || this.fatal) { if (!active) return; throw new Error(this.fatal || 'Room is closed.'); }
    if (active && this.blocks.length >= MAX_BLOCKS) throw new Error('This demo room reached its 5,000-block limit. Create a new room.');
    const device = this.devices.get(id); if (!device) throw new Error('Unknown device.');
    device.active = active; if (!active) device.rate = 0;
    this.publish();
    if (active) { const job = this.job(id); if (device.ws) send(device.ws, { type: 'job', job }); else this.emit('job', job); }
    if (!this.busy && ![...this.devices.values()].some(d => d.active)) void this.verifier.close();
  }
  setRate(id, rate) {
    const d = this.devices.get(id);
    if (d && d.active && Number.isFinite(rate) && rate >= 0 && rate <= 1e9) { d.rate = rate; }
  }
  async submit(id, proof) {
    const device = this.devices.get(id);
    if (this.closed || this.fatal || !device?.active) return { accepted: false, reason: 'Mining is stopped.' };
    if (proof.round !== this.round.id) return { accepted: false, reason: 'Stale round.' };
    const job = this.job(id);
    if (!Number.isInteger(proof.nonce) || proof.nonce < job.start || proof.nonce > job.end || !isHex(proof.proof, 64)) return { accepted: false, reason: 'Invalid proof or nonce partition.' };
    if (this.busy) return { accepted: false, reason: 'Another proof is being verified. Retry shortly.', retry: true };
    this.busy = true;
    try {
      const result = await this.verifier.verify(job, proof.nonce);
      if (this.closed || this.fatal || !this.devices.get(id)?.active || proof.round !== this.round.id) return { accepted: false, reason: 'Round or device changed during verification.' };
      if (!result.valid || result.proof !== proof.proof) return { accepted: false, reason: 'Host recomputation rejected this proof.' };
      const block = { roomId: this.id, height: this.blocks.length + 1, previous: this.tip, round: job.round, seed: job.seed,
        template: job.template, target: job.target, nonce: proof.nonce, proof: result.proof, winnerId: id, winnerName: device.name,
        reward: REWARD, timestamp: new Date().toISOString() };
      block.hash = blockDigest(block);
      const next = { ...this.data, blocks: [...this.blocks, block] };
      this.saving = saveRoom(this.directory, next);
      await this.saving;
      if (this.closed) return { accepted: false, reason: 'Room closed while saving; saved block retained.' };
      this.data = next; this.nextRound(); this.publish(true);
      if (this.blocks.length >= MAX_BLOCKS) this.fail('This room reached its 5,000-block limit. Create a new room.');
      return { accepted: true, block };
    } catch (e) {
      if (!this.closed && !String(e.message).includes('Room closed')) this.fail(`Room stopped: ${e.message}`);
      return { accepted: false, reason: e.message };
    } finally { this.busy = false; this.saving = null; if (![...this.devices.values()].some(d => d.active)) void this.verifier.close(); }
  }
  fail(message) {
    this.fatal = message;
    for (const d of this.devices.values()) { d.active = false; d.rate = 0; if (d.ws) send(d.ws, { type: 'halt', reason: message }); }
    this.emit('halt', message); this.publish(); void this.verifier.close();
  }
  async enableNetwork(host) {
    if (!privateIPv4(host, true)) throw new Error('Select a private IPv4 network adapter.');
    if (this.closed || this.fatal) throw new Error('Room is closed or halted.');
    if (this.network || this.enabling) throw new Error('Room sharing is already enabled or being prepared.');
    this.enabling = this.openNetwork(host);
    try { return await this.enabling; } finally { this.enabling = null; }
  }
  async openNetwork(host) {
    const pems = await selfsigned.generate([{ name: 'commonName', value: 'MeepCoin Local Lab' }], { keySize: 2048, algorithm: 'sha256' });
    if (this.closed) throw new Error('Room closed during LAN setup.');
    const certDer = Buffer.from(pems.cert.split('-----')[2].replace(/\s/g, ''), 'base64');
    const pin = sha256(certDer);
    const server = createServer({ key: pems.private, cert: pems.cert, minVersion: 'TLSv1.2', requestTimeout: 5000, headersTimeout: 5000 }, (_req, res) => { res.writeHead(404); res.end('MeepCoin Local Lab pairing endpoint.'); });
    const wss = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024, perMessageDeflate: false });
    server.on('upgrade', (req, socket, head) => {
      const address = socket.remoteAddress?.replace(/^::ffff:/, '');
      if (this.closed || !privateIPv4(address, true) || req.url !== '/lab' || req.headers.origin || wss.clients.size >= MAX_DEVICES + 4) { socket.destroy(); return; }
      wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws));
    });
    server.maxConnections = 16;
    server.on('connection', socket => { socket.setTimeout(15_000); socket.on('timeout', () => socket.destroy()); });
    wss.on('connection', ws => this.attachPeer(ws));
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, host, resolve); });
    if (this.closed) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); wss.close(); throw new Error('Room closed during LAN setup.'); }
    server.on('error', e => this.fail(`LAN listener failed: ${e.message}`));
    this.network = { host, port: server.address().port, pin, server, wss };
    this.heartbeat = setInterval(() => {
      for (const ws of wss.clients) { if (!ws.alive) { ws.terminate(); continue; } ws.alive = false; ws.ping(); }
      this.publish();
    }, 3000);
    return this.refreshInvite();
  }
  refreshInvite() {
    if (!this.network) throw new Error('Enable LAN sharing first.');
    this.inviteSecret = randomBytes(32).toString('hex'); this.inviteExpires = Date.now() + 10 * 60_000;
    const { host, port, pin } = this.network;
    return `MEEP-LAB1:${Buffer.from(JSON.stringify({ v: VERSION, host, port, pin, secret: this.inviteSecret, expires: this.inviteExpires })).toString('base64url')}`;
  }
  attachPeer(ws) {
    ws.alive = true; ws.on('pong', () => { ws.alive = true; });
    let id = null, awaiting = null, rateWindow = Date.now(), messages = 0;
    const helloTimer = setTimeout(() => ws.terminate(), 5000);
    ws.on('error', () => {});
    ws.on('message', raw => {
      if (Date.now() - rateWindow > 1000) { rateWindow = Date.now(); messages = 0; }
      if (++messages > 20) { ws.terminate(); return; }
      try {
        const m = JSON.parse(raw.toString());
        if (!id) {
          if (awaiting || m.type !== 'hello' || !isHex(m.id, 32) || this.devices.has(m.id) || [...this.pending.values()].some(p => p.id === m.id) ||
            !this.inviteSecret || Date.now() > this.inviteExpires || !safeSecret(m.secret, this.inviteSecret)) { ws.close(1008, 'Invalid or expired invite'); return; }
          clearTimeout(helloTimer);
          awaiting = randomId();
          const request = { requestId: awaiting, id: m.id, name: cleanName(m.name), ws, timer: setTimeout(() => this.approve(awaiting, false), 60_000), assign: value => { id = value; } };
          this.pending.set(awaiting, request); this.emit('pending'); send(ws, { type: 'pending' }); return;
        }
        const d = this.devices.get(id);
        if (!d || m.token !== d.token) { ws.close(1008, 'Invalid session'); return; }
        if (m.type === 'active' && typeof m.active === 'boolean') this.setActive(id, m.active);
        else if (m.type === 'stats') this.setRate(id, m.rate);
        else if (m.type === 'proof') {
          if (d.submitting) return;
          d.submitting = true;
          void this.submit(id, m).then(result => { send(ws, { type: 'result', ...result, round: m.round }); }).finally(() => { d.submitting = false; });
        } else { ws.close(1008, 'Unknown message'); }
      } catch { ws.close(1008, 'Malformed request'); }
    });
    ws.on('close', () => {
      clearTimeout(helloTimer);
      if (awaiting) { const p = this.pending.get(awaiting); clearTimeout(p?.timer); this.pending.delete(awaiting); this.emit('pending'); }
      if (id) { this.devices.delete(id); this.publish(); if (!this.busy && ![...this.devices.values()].some(d => d.active)) void this.verifier.close(); }
    });
  }
  approve(requestId, allow) {
    const p = this.pending.get(requestId); if (!p) return;
    this.pending.delete(requestId); clearTimeout(p.timer); this.emit('pending');
    if (!allow || this.closed || this.fatal || this.devices.size >= MAX_DEVICES || p.ws.readyState !== WebSocket.OPEN) { p.ws.close(1008, 'Host declined, halted, or room full'); return; }
    const used = new Set([...this.devices.values()].map(d => d.slot));
    const slot = Array.from({ length: MAX_DEVICES }, (_, n) => n).find(n => !used.has(n));
    const token = randomId();
    this.devices.set(p.id, { id: p.id, name: p.name, slot, active: false, rate: 0, host: false, token, ws: p.ws });
    p.assign(p.id); send(p.ws, { type: 'approved', token, state: this.snapshot() }); this.publish();
  }
  async close() {
    if (this.closed) return; this.closed = true;
    this.inviteSecret = null; this.inviteExpires = 0;
    await this.enabling?.catch(() => {});
    clearInterval(this.heartbeat);
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.ws.terminate(); } this.pending.clear();
    if (this.network) {
      for (const ws of this.network.wss.clients) ws.terminate();
      await new Promise(resolve => this.network.wss.close(resolve));
      this.network.server.closeAllConnections();
      await new Promise(resolve => this.network.server.close(resolve));
    }
    await this.verifier.close();
    await this.saving?.catch(() => {});
  }
}
