import { join } from 'node:path';
import { homedir } from 'node:os';
import { Application } from './application.mjs';
import { dashboard } from './dashboard.mjs';
const application = await Application.create(process.env.MEEP_LAB_DATA_DIR || join(homedir(), '.meepcoin-local-lab'));
const web = await dashboard(application);
console.log(`MeepCoin Local Lab dashboard: ${web.url}\nMining is OFF. Press Start explicitly. Ctrl+C stops all app workers.`);
let closing = false;
async function close() { if (closing) return; closing = true; await application.close(); await web.close(); }
process.on('SIGINT', () => { void close(); }); process.on('SIGTERM', () => { void close(); });
