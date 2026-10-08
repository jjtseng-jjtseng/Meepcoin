import { createHash, randomBytes } from 'node:crypto';

export const VERSION = 1;
export const REWARD = 10;
export const MAX_DEVICES = 8;
export const MAX_BLOCKS = 5000;
export const MAX_MESSAGE = 512 * 1024;
export const HASH_IDENTITY = Object.freeze({
  'meepow.mjs': '5a61038d0d40aaaf4f33d779dfa9e0b4ee7e68817eabdf8de57465711ef49e31',
  'meepow.wasm': 'a039b57ed7d874792eced9044054764c6c3d10c316581efe64721ff52b3988a7',
});
export const sha256 = value => createHash('sha256').update(value).digest('hex');
export const randomId = () => randomBytes(16).toString('hex');
export const cleanName = value => String(value ?? '').replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 32) || 'Unnamed device';
export const isHex = (v, length) => typeof v === 'string' && new RegExp(`^[0-9a-f]{${length}}$`).test(v);

export function privateIPv4(ip, allowLoopback = false) {
  if (typeof ip !== 'string' || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false;
  const parts = ip.split('.').map(Number);
  if (parts.some(p => p < 0 || p > 255) || parts.join('.') !== ip) return false;
  return (allowLoopback && parts[0] === 127) || parts[0] === 10 ||
    (parts[0] === 192 && parts[1] === 168) || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31);
}

export function difficultyTarget(difficulty) {
  if (![8, 32, 128, 512].includes(difficulty)) throw new Error('Choose one of the lab difficulties.');
  let n = ((1n << 256n) - 1n) / BigInt(difficulty);
  const bytes = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) { bytes[i] = Number(n & 255n); n >>= 8n; }
  return bytes.toString('hex');
}

export function newJob(room, slot) {
  // Same round/template for everybody; disjoint 1/8 uint32 nonce partitions.
  return { version: VERSION, round: room.round.id, seed: room.round.seed, height: room.blocks.length + 1,
    template: Buffer.from(`MeepCoin Local Lab DEMO v1|${room.id}|${room.blocks.length + 1}|${room.tip}|${room.round.id}`).toString('hex'),
    target: difficultyTarget(room.difficulty), start: slot * 0x20000000, end: (slot + 1) * 0x20000000 - 1 };
}

export function validJob(j) {
  return j && j.version === VERSION && isHex(j.round, 32) && isHex(j.seed, 64) &&
    Number.isSafeInteger(j.height) && j.height >= 1 && j.height <= MAX_BLOCKS &&
    typeof j.template === 'string' && j.template.length <= 1024 && j.template.length > 0 && j.template.length % 2 === 0 && /^[0-9a-f]+$/.test(j.template) &&
    isHex(j.target, 64) && Number.isInteger(j.start) && Number.isInteger(j.end) && j.start >= 0 && j.end <= 0xffffffff && j.end >= j.start;
}

export function blockDigest(b) {
  return sha256(JSON.stringify([VERSION, b.roomId, b.height, b.previous, b.round, b.seed, b.template,
    b.target, b.nonce, b.proof, b.winnerId, b.winnerName, b.reward, b.timestamp]));
}

export function proofMeetsTarget(proof, target) {
  if (!isHex(proof, 64) || !isHex(target, 64)) return false;
  for (let i = 62; i >= 0; i -= 2) {
    const a = parseInt(proof.slice(i, i + 2), 16), b = parseInt(target.slice(i, i + 2), 16);
    if (a !== b) return a < b;
  }
  return true;
}

export function validateLedger(data) {
  if (!data || data.version !== VERSION || !isHex(data.id, 32) || typeof data.name !== 'string' || data.name !== cleanName(data.name) || !Array.isArray(data.blocks) || data.blocks.length > MAX_BLOCKS) throw new Error('Invalid demo ledger.');
  difficultyTarget(data.difficulty);
  let previous = '0'.repeat(64);
  for (const [i, b] of data.blocks.entries()) {
    if (!b || b.roomId !== data.id || b.height !== i + 1 || b.previous !== previous || b.reward !== REWARD || !isHex(b.proof, 64) || !isHex(b.winnerId, 32) ||
      !isHex(b.round, 32) || !isHex(b.seed, 64) || !isHex(b.target, 64) || !Number.isInteger(b.nonce) || b.nonce < 0 || b.nonce > 0xffffffff ||
      typeof b.winnerName !== 'string' || b.winnerName !== cleanName(b.winnerName) || !Number.isFinite(Date.parse(b.timestamp)) || blockDigest(b) !== b.hash ||
      b.template !== Buffer.from(`MeepCoin Local Lab DEMO v1|${data.id}|${b.height}|${previous}|${b.round}`).toString('hex') || b.target !== difficultyTarget(data.difficulty) || !proofMeetsTarget(b.proof, b.target)) throw new Error(`Demo ledger damaged at block ${i + 1}. Nothing was overwritten.`);
    previous = b.hash;
  }
  return data;
}

export function parseInvite(text) {
  if (typeof text !== 'string' || text.length > 1500 || !text.trim().startsWith('MEEP-LAB1:')) throw new Error('Paste a complete MEEP-LAB1 invite from the host.');
  let d;
  try { d = JSON.parse(Buffer.from(text.trim().slice(10), 'base64url').toString('utf8')); } catch { throw new Error('That invite is damaged.'); }
  if (!d || d.v !== VERSION || !privateIPv4(d.host, true) || !Number.isInteger(d.port) || d.port < 1 || d.port > 65535 || !isHex(d.pin, 64) || !isHex(d.secret, 64) ||
    !Number.isSafeInteger(d.expires) || d.expires < Date.now() || d.expires > Date.now() + 11 * 60_000) throw new Error('Invite expired or not a supported private-network address. Ask the host for a new invite.');
  return d;
}
