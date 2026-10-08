import { EventEmitter } from 'node:events';
import { WebSocket } from 'ws';
import { parseInvite, sha256, VERSION, MAX_MESSAGE, MAX_DEVICES, MAX_BLOCKS, REWARD, isHex, validJob, cleanName, difficultyTarget, blockDigest, proofMeetsTarget } from './protocol.mjs';

export class Client extends EventEmitter {
  constructor(profile) { super(); this.profile = profile; this.ws = null; this.approved = false; this.closed = false; this.token = null; this.state = null; this.lastHeard = Date.now(); }
  connect(text) {
    const invite = parseInvite(text);
    const ws = this.ws = new WebSocket(`wss://${invite.host}:${invite.port}/lab`, { rejectUnauthorized: false, handshakeTimeout: 5000, maxPayload: MAX_MESSAGE, perMessageDeflate: false });
    this.deadline = setTimeout(() => this.fail('No host approval within 65 seconds. Ask the host to approve you.'), 65_000);
    ws.on('open', () => {
      // Self-signed is permitted ONLY with an exact out-of-band SHA-256 certificate pin.
      // No invite secret or device identity is sent before this check.
      const cert = ws._socket.getPeerCertificate();
      if (!cert.raw || sha256(cert.raw) !== invite.pin) { this.fail('Host certificate does not match the invite. Connection refused.'); return; }
      this.lastHeard = Date.now();
      this.liveness = setInterval(() => { if (Date.now() - this.lastHeard > 10_000) this.fail('Host connection lost. Mining stopped.'); }, 1000);
      this.send({ type: 'hello', id: this.profile.id, name: this.profile.name, secret: invite.secret });
    });
    ws.on('ping', () => { this.lastHeard = Date.now(); });
    ws.on('message', raw => {
      this.lastHeard = Date.now();
      try {
        const m = JSON.parse(raw.toString());
        if (m.type === 'pending' && !this.approved) { this.emit('status', 'Waiting for host approval'); return; }
        if (m.type === 'approved' && !this.approved && isHex(m.token, 32)) { this.validateState(m.state); this.token = m.token; this.approved = true; clearTimeout(this.deadline); this.emit('approved'); this.update(m.state); return; }
        if (!this.approved) throw new Error('Host sent work before approval.');
        if (m.type === 'state') { this.validateState(m.state); this.update(m.state); }
        else if (m.type === 'job') {
          if (!validJob(m.job) || m.job.round !== this.state.round || m.job.seed !== this.state.seed || m.job.height !== this.state.height + 1 ||
            m.job.target !== difficultyTarget(this.state.difficulty) || m.job.template !== Buffer.from(`MeepCoin Local Lab DEMO v1|${this.state.id}|${m.job.height}|${this.state.tip}|${this.state.round}`).toString('hex') ||
            m.job.start % 0x20000000 !== 0 || m.job.end !== m.job.start + 0x20000000 - 1) throw new Error('Host sent an invalid work assignment.');
          this.emit('job', m.job);
        } else if (m.type === 'result') this.emit('result', m);
        else if (m.type === 'halt') this.fail(String(m.reason || 'Host stopped the room.'));
        else throw new Error('Unknown host message.');
      } catch (e) { this.fail(`Invalid host response: ${e.message}`); }
    });
    ws.on('error', e => this.fail(`Cannot connect: ${e.message}. Check the host, same LAN, and Windows private-network firewall permission.`));
    ws.on('close', (_code, reason) => { if (!this.closed) this.fail(reason.length ? `Room disconnected: ${reason}` : 'Host disconnected. Mining stopped.'); });
  }
  validateState(s) {
    if (!s || s.version !== VERSION || !isHex(s.id, 32) || !isHex(s.round, 32) || !isHex(s.seed, 64) || !isHex(s.tip, 64) || typeof s.name !== 'string' || s.name !== cleanName(s.name) ||
      !Number.isInteger(s.height) || s.height < 0 || s.height > MAX_BLOCKS || ![8, 32, 128, 512].includes(s.difficulty) || s.reward !== REWARD ||
      !Array.isArray(s.devices) || s.devices.length > MAX_DEVICES || !Array.isArray(s.blocks) || s.blocks.length > 100 ||
      !s.balances || typeof s.balances !== 'object' || Array.isArray(s.balances) || Object.keys(s.balances).length > MAX_BLOCKS ||
      !Object.keys(s.balances).every(id => isHex(id, 32)) || !Object.values(s.balances).every(n => Number.isSafeInteger(n) && n >= 0 && n <= MAX_BLOCKS * REWARD && n % REWARD === 0) ||
      s.totalMinted !== s.height * REWARD || Object.values(s.balances).reduce((sum, n) => sum + n, 0) !== s.totalMinted ||
      !s.devices.every(d => d && isHex(d.id, 32) && typeof d.name === 'string' && d.name === cleanName(d.name) && typeof d.active === 'boolean' && typeof d.host === 'boolean' && Number.isFinite(d.rate) && d.rate >= 0 && d.rate <= 1e9) ||
      new Set(s.devices.map(d => d.id)).size !== s.devices.length || s.devices.filter(d => d.host).length !== 1 || !s.devices.some(d => d.id === this.profile.id)) throw new Error('Invalid room state.');
    if (s.blocks.length !== Math.min(s.height, 100)) throw new Error('Invalid live history length.');
    for (const [index, b] of s.blocks.entries()) {
      if (!b || b.roomId !== s.id || b.height !== s.height - s.blocks.length + index + 1 || !isHex(b.hash, 64) || !isHex(b.previous, 64) || !isHex(b.round, 32) || !isHex(b.seed, 64) || !isHex(b.winnerId, 32) ||
        typeof b.winnerName !== 'string' || b.winnerName !== cleanName(b.winnerName) || b.reward !== REWARD || !Number.isFinite(Date.parse(b.timestamp)) ||
        !Number.isInteger(b.nonce) || b.nonce < 0 || b.nonce > 0xffffffff || b.target !== difficultyTarget(s.difficulty) || !proofMeetsTarget(b.proof, b.target) || blockDigest(b) !== b.hash ||
        b.template !== Buffer.from(`MeepCoin Local Lab DEMO v1|${s.id}|${b.height}|${b.previous}|${b.round}`).toString('hex') || (index > 0 && b.previous !== s.blocks[index - 1].hash)) throw new Error('Invalid live block history.');
    }
    if (s.tip !== (s.blocks.at(-1)?.hash ?? '0'.repeat(64)) || s.height > 0 && s.blocks[0].height === 1 && s.blocks[0].previous !== '0'.repeat(64)) throw new Error('Invalid live chain tip.');
    if (this.state && (s.id !== this.state.id || s.height < this.state.height || s.difficulty !== this.state.difficulty)) throw new Error('Host changed or rolled back the room.');
    if (this.state && s.height === this.state.height && s.tip !== this.state.tip) throw new Error('Host changed the accepted history.');
  }
  update(state) { this.state = state; this.emit('state', state); }
  send(message) { if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify({ ...message, ...(this.token ? { token: this.token } : {}) })); }
  fail(message) { if (this.closed) return; this.emit('failure', message); this.close(); }
  close() { this.closed = true; this.approved = false; clearTimeout(this.deadline); clearInterval(this.liveness); this.ws?.terminate(); }
}
