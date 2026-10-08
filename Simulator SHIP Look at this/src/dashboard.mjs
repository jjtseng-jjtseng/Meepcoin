import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const assets = { '/': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'], '/style.css': ['style.css', 'text/css; charset=utf-8'], '/logo.svg': ['logo.svg', 'image/svg+xml'] };
export async function dashboard(application, { desktop = null } = {}) {
  const key = randomBytes(32).toString('hex');
  let origin, queue = Promise.resolve();
  const decorate = state => state?.profile ? { ...state, desktop: desktop ? { mode: desktop.mode, url: origin } : null } : state;
  const server = createServer(async (req, res) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Cache-Control', 'no-store'); res.setHeader('Referrer-Policy', 'no-referrer');
    const json = (status, value) => { if (!res.headersSent) res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
    try {
      if (req.headers.host !== new URL(origin).host || req.headers.origin && req.headers.origin !== origin) { json(403, { error: 'Only this local dashboard is allowed.' }); return; }
      if (req.method === 'GET' && assets[req.url]) {
        const [file, mime] = assets[req.url];
        let content = await readFile(new URL(`../ui/${file}`, import.meta.url));
        if (file === 'index.html') content = Buffer.from(content.toString().replace('__LAB_API_KEY__', key));
        res.writeHead(200, { 'Content-Type': mime }); res.end(content); return;
      }
      const supplied = req.headers['x-lab-key'];
      if (typeof supplied !== 'string' || supplied.length !== key.length || !timingSafeEqual(Buffer.from(supplied), Buffer.from(key))) { json(403, { error: 'Invalid dashboard session.' }); return; }
      if (req.method === 'GET' && req.url === '/api/state') { json(200, decorate(await application.snapshot())); return; }
      if (req.method !== 'POST' || req.url !== '/api/command' || !String(req.headers['content-type']).startsWith('application/json')) { json(404, { error: 'Not found.' }); return; }
      let size = 0, chunks = [];
      for await (const chunk of req) { size += chunk.length; if (size > 16 * 1024) { json(413, { error: 'Request too large.' }); req.destroy(); return; } chunks.push(chunk); }
      const { action, payload } = JSON.parse(Buffer.concat(chunks));
      const task = queue.then(async () => {
        if (action === 'display') {
          if (!desktop) throw new Error('Display switching is available in the Windows executable.');
          if (!['app', 'browser'].includes(payload?.mode)) throw new Error('Choose app or browser mode.');
          await desktop.setMode(payload.mode);
          return decorate(await application.snapshot());
        }
        if (action === 'quit') {
          if (!desktop) throw new Error('Stop this development server with Ctrl+C.');
          await application.command('stop');
          res.once('finish', () => setImmediate(() => desktop.quit()));
          return { ...decorate(await application.snapshot()), quitting: true };
        }
        return decorate(await application.command(action, payload));
      });
      queue = task.catch(() => {});
      json(200, await task);
    } catch (e) { json(400, { error: e.message }); }
  });
  server.requestTimeout = 5000; server.headersTimeout = 5000; server.maxConnections = 32;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  origin = `http://127.0.0.1:${server.address().port}`;
  return { url: origin, close: async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await queue; } };
}
