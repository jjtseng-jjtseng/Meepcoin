import { mkdir, readFile, readdir, open, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { randomId, cleanName, validateLedger } from './protocol.mjs';

export async function writeAtomic(path, value) {
  const temp = `${path}.${randomId()}.tmp`;
  const file = await open(temp, 'wx');
  try { await file.writeFile(JSON.stringify(value, null, 2)); await file.sync(); } finally { await file.close(); }
  await rename(temp, path);
}
export async function loadProfile(directory, defaultName) {
  await mkdir(join(directory, 'rooms'), { recursive: true });
  const path = join(directory, 'profile.json');
  try {
    const profile = JSON.parse(await readFile(path, 'utf8'));
    if (!/^[0-9a-f]{32}$/.test(profile.id) || profile.name !== cleanName(profile.name)) throw new Error('Invalid local device profile.');
    return profile;
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    const profile = { id: randomId(), name: cleanName(defaultName) };
    await writeAtomic(path, profile); return profile;
  }
}
export async function listRooms(directory) {
  const rooms = [];
  for (const filename of await readdir(join(directory, 'rooms'))) {
    if (!/^[0-9a-f]{32}\.json$/.test(filename)) continue;
    try {
      const room = validateLedger(JSON.parse(await readFile(join(directory, 'rooms', filename), 'utf8')));
      rooms.push({ id: room.id, name: room.name, blocks: room.blocks.length, created: room.created, difficulty: room.difficulty });
    } catch { rooms.push({ id: filename.slice(0, -5), name: 'Damaged ledger (not overwritten)', damaged: true, blocks: 0 }); }
  }
  return rooms.sort((a, b) => String(b.created).localeCompare(String(a.created)));
}
export async function readRoom(directory, id) {
  if (!/^[0-9a-f]{32}$/.test(id)) throw new Error('Invalid saved room.');
  return validateLedger(JSON.parse(await readFile(join(directory, 'rooms', `${id}.json`), 'utf8')));
}
export const saveRoom = (directory, data) => writeAtomic(join(directory, 'rooms', `${data.id}.json`), data);
