// Publication preflight: imports and pinned assets only. Starts no service and performs no mining.
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve, dirname} from 'node:path';
import {createHash} from 'node:crypto';
import {createPrivateGateway} from '../../pool/private/server.mjs';
import {verifyWasmIdentity, loadSyntheticFixture} from '../../pool/dev/identity.mjs';
import {ROUTES} from '../../pool/dev/static.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
if (typeof createPrivateGateway !== 'function') throw new Error('Gateway export missing');
verifyWasmIdentity();
loadSyntheticFixture();
const files = new Set([
  'web-miner/private/index.html', 'web-miner/private/app.js', 'web-miner/private/style.css',
  ...Object.entries(ROUTES).filter(([route]) => route === '/worker.js'
    || route.startsWith('/lib/') || route.startsWith('/wasm/'))
    .map(([, entry]) => entry.file),
]);
const hashes = {};
for (const file of files) {
  const absolute = resolve(root, file);
  const bytes = await readFile(absolute);
  if (!bytes.length) throw new Error('Empty participant asset: ' + file);
  hashes[absolute.slice(root.length + 1).replaceAll('\\', '/')] =
    createHash('sha256').update(bytes).digest('hex');
}
console.log(JSON.stringify({status: 'PARTICIPANT_PUBLICATION_ASSETS_PASS',
  serviceStarted: false, miningPerformed: false, files: hashes}, null, 2));
