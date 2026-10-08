import { hostname, networkInterfaces } from 'node:os';
import { join } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { Miner, checkHashIdentity } from './workers.mjs';
import { Room } from './room.mjs';
import { Client } from './client.mjs';
import { loadProfile, writeAtomic, listRooms } from './storage.mjs';
import { cleanName, privateIPv4, randomId } from './protocol.mjs';

export function adapters() {
  return Object.entries(networkInterfaces()).flatMap(([name, entries]) => entries.filter(e => e.family === 'IPv4' && !e.internal && privateIPv4(e.address)).map(e => ({ name, address: e.address })))
    .sort((a, b) => Number(/virtual|vethernet|wsl|docker|vmware/i.test(a.name)) - Number(/virtual|vethernet|wsl|docker|vmware/i.test(b.name)));
}

export class Application {
  static async create(directory) {
    await checkHashIdentity();
    const app = new Application(directory);
    app.profile = await loadProfile(directory, hostname());
    return app;
  }
  constructor(directory) {
    this.directory = directory; this.miner = new Miner(); this.room = null; this.client = null; this.invite = null;
    this.role = 'idle'; this.connectionStatus = ''; this.events = []; this.lastProof = null; this.closed = false;
    this.miner.on('stats', () => {
      if (this.room) this.room.setRate(this.profile.id, this.miner.rate);
      else if (this.client?.approved) this.client.send({ type: 'stats', rate: this.miner.rate });
    });
    this.miner.on('proof', proof => { this.lastProof = proof; void this.submitProof(proof); });
    this.miner.on('failure', error => { this.stopMining(); this.note(error, 'error'); });
  }
  note(text, level = 'info') { this.events.unshift({ id: randomId(), timestamp: new Date().toISOString(), text: String(text).slice(0, 240), level }); this.events.length = Math.min(this.events.length, 30); }
  async snapshot() {
    this.miner.sampleRate();
    const state = this.room?.snapshot() ?? this.client?.state ?? null;
    const own = state?.devices.find(d => d.id === this.profile.id);
    return { appVersion: '0.1.3', role: this.role, profile: this.profile, room: state, invite: this.invite,
      connectionStatus: this.connectionStatus, adapters: adapters(), savedRooms: await listRooms(this.directory), dataDirectory: this.directory,
      pending: this.room ? [...this.room.pending.values()].map(({ requestId, name }) => ({ requestId, name })) : [],
      miner: { running: this.miner.running, status: this.miner.status, hashrate: this.miner.rate, hashes: this.miner.hashes, duty: this.miner.duty },
      ownBalance: state?.balances[this.profile.id] ?? 0, events: this.events,
      canMine: Boolean(this.room && !this.room.fatal || this.client?.approved && own && !state.fatal) };
  }
  async createRoom(options) {
    await this.leave();
    await this.setName(options.deviceName || this.profile.name);
    this.room = await Room.create({ directory: this.directory, profile: this.profile, name: options.name, difficulty: Number(options.difficulty ?? 32), resumeId: options.resumeId });
    this.role = 'host';
    this.room.on('job', job => { this.lastProof = null; this.miner.mine(job); });
    this.room.on('halt', error => { this.miner.stop(); this.note(error, 'error'); });
    if (options.lan) {
      if (!adapters().some(a => a.address === options.address)) { await this.leave(); throw new Error('That private adapter is no longer available.'); }
      try { this.invite = await this.room.enableNetwork(options.address); }
      catch (e) { await this.leave(); throw e; }
    }
    this.note(options.resumeId ? 'Saved room restored. Mining is stopped until you press Start.' : 'Room created. Press Start mining when ready.');
    return this.snapshot();
  }
  async setName(name) {
    this.profile = { ...this.profile, name: cleanName(name) };
    await writeAtomic(join(this.directory, 'profile.json'), this.profile);
  }
  async joinRoom({ invite, deviceName }) {
    await this.leave(); await this.setName(deviceName || this.profile.name);
    const client = this.client = new Client(this.profile);
    this.role = 'joining'; this.connectionStatus = 'Connecting to the private host';
    client.on('status', status => { this.connectionStatus = status; });
    client.on('approved', () => { this.role = 'client'; this.connectionStatus = 'Paired over certificate-pinned TLS'; this.note('Host approved this device. Press Start mining when ready.'); });
    client.on('job', job => { this.lastProof = null; this.miner.mine(job); });
    client.on('result', result => this.proofResult(result, this.lastProof));
    client.on('failure', error => { this.miner.stop(); this.role = 'disconnected'; this.connectionStatus = error; this.note(error, 'error'); });
    try { client.connect(invite); } catch (e) { this.client = null; this.role = 'idle'; throw e; }
    return this.snapshot();
  }
  startMining() {
    if (this.miner.running) return;
    if (this.room?.fatal) throw new Error(this.room.fatal);
    if (!this.room && !this.client?.approved) throw new Error('Create a room or wait for host approval first.');
    this.miner.running = true; this.miner.status = 'Waiting for work';
    try { if (this.room) this.room.setActive(this.profile.id, true); else this.client.send({ type: 'active', active: true }); }
    catch (e) { this.miner.stop(); throw e; }
    this.note('Mining started by you. One worker, no automatic restart.');
  }
  stopMining() {
    const wasRunning = this.miner.running;
    this.miner.stop(); this.lastProof = null;
    if (this.room && !this.room.closed && !this.room.fatal) this.room.setActive(this.profile.id, false);
    else if (this.client?.approved) this.client.send({ type: 'active', active: false });
    if (wasRunning) this.note('Mining stopped. The worker was terminated.');
  }
  async submitProof(proof) {
    if (!proof || !this.miner.running || proof !== this.lastProof) return;
    if (this.room) this.proofResult({ ...await this.room.submit(this.profile.id, proof), round: proof.round }, proof);
    else if (this.client?.approved) this.client.send({ type: 'proof', ...proof });
  }
  proofResult(result, proof) {
    if (result.accepted) { this.note(`Verified demo block #${result.block.height}: +${result.block.reward} demo MEEP for ${result.block.winnerName}.`); return; }
    if (!proof || result.round !== proof.round || this.lastProof !== proof || !this.miner.running) return;
    if (result.retry) { setTimeout(() => { void this.submitProof(proof); }, 250); return; }
    this.note(result.reason || 'Proof rejected.', 'warning');
    if (!String(result.reason).includes('Stale')) this.stopMining();
  }
  async exportLedger() {
    const data = this.room?.data;
    if (!data) throw new Error('Only the host owns the complete ledger.');
    const path = join(this.directory, `demo-ledger-${data.id}-${Date.now()}.json`);
    await writeFile(path, JSON.stringify({ ...data, notice: 'Non-spendable demo credits. Host-authoritative ledger, not native MeepCoin consensus.' }, null, 2), { flag: 'wx' });
    this.note(`Exported ${data.blocks.length} demo blocks to ${path}`); return { path };
  }
  async leave() {
    this.stopMining(); this.client?.close(); this.client = null;
    const room = this.room; this.room = null; if (room) await room.close();
    await this.miner.close(); this.invite = null; this.role = 'idle'; this.connectionStatus = '';
  }
  async command(action, payload = {}) {
    if (this.closed) throw new Error('App is closing.');
    switch (action) {
      case 'create': return this.createRoom(payload);
      case 'join': return this.joinRoom(payload);
      case 'start': this.startMining(); break;
      case 'stop': this.stopMining(); await this.miner.retiring; break;
      case 'duty': this.miner.setDuty(Number(payload.duty)); break;
      case 'leave': await this.leave(); break;
      case 'approve': if (!this.room) throw new Error('Only the host approves devices.'); this.room.approve(payload.requestId, payload.allow === true); break;
      case 'invite': if (!this.room) throw new Error('Only the host creates invites.'); this.invite = this.room.refreshInvite(); break;
      case 'export': return this.exportLedger();
      default: throw new Error('Unknown action.');
    }
    return this.snapshot();
  }
  async close() { this.closed = true; await this.leave(); }
}
