// Finite private participant rehearsal. Never a public service or invitation issuer.
import {readFile, writeFile} from 'node:fs/promises';
import {createPrivateGateway} from '../pool/private/server.mjs';
const config = JSON.parse(await readFile(process.argv[2], 'utf8'));
const gateway = await createPrivateGateway(config);
await writeFile(config.readyFile, JSON.stringify({url: gateway.url, origin: gateway.origin}), {flag: 'wx', mode: 0o600});
let closing = false;
const close = async () => {
  if (closing) return;
  closing = true;
  clearInterval(observer); clearTimeout(deadline);
  await gateway.close();
};
const observer = setInterval(async () => {
  const state = gateway.snapshot();
  if (state.events.some(event => event.type === 'block_accepted')) {
    clearInterval(observer);
    await writeFile(config.blockFile, JSON.stringify(state), {flag: 'wx', mode: 0o600});
  }
}, 250);
const deadline = setTimeout(close, 900000);
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, close);
