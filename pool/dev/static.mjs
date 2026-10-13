// Static file serving for the local development pool.
//
// There is no document root and no path resolution: an explicit, closed route table maps a fixed
// set of URL paths to a fixed set of absolute file paths. Nothing else can be served, so path
// traversal, symlink escape, dotfile leaks and directory listings are not defended against --
// they are simply not expressible. Unknown paths are 404 with no body detail.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(__dirname, '../..');

const WEB = (p) => resolve(REPO_ROOT, 'web-miner', p);
const WASM = (p) => resolve(REPO_ROOT, 'meepow/wasm', p);

const JS = 'text/javascript; charset=utf-8';

/** The complete set of files this server will ever serve. */
export const ROUTES = Object.freeze({
  '/': { file: WEB('index.html'), type: 'text/html; charset=utf-8' },
  '/index.html': { file: WEB('index.html'), type: 'text/html; charset=utf-8' },
  '/styles.css': { file: WEB('styles.css'), type: 'text/css; charset=utf-8' },
  '/app.js': { file: WEB('app.js'), type: JS },
  '/worker.js': { file: WEB('worker.js'), type: JS },
  '/lib/controller.js': { file: WEB('lib/controller.js'), type: JS },
  '/lib/shared/target.js': { file: WEB('lib/shared/target.js'), type: JS },
  '/lib/shared/protocol.js': { file: WEB('lib/shared/protocol.js'), type: JS },
  '/lib/shared/search.js': { file: WEB('lib/shared/search.js'), type: JS },
  '/lib/shared/wasm_hasher.js': { file: WEB('lib/shared/wasm_hasher.js'), type: JS },
  // The Worker's command dispatcher and its one-hash permit. worker.js imports both; a module a
  // Worker imports but this table does not serve makes the Worker fail to load in EVERY mode.
  '/lib/worker_core.js': { file: WEB('lib/worker_core.js'), type: JS },
  '/lib/shared/one_shot.js': { file: WEB('lib/shared/one_shot.js'), type: JS },
  // The MeepHash-W build outputs. These are gitignored BUILD ARTIFACTS of the committed frozen
  // source, not committed files, and they are served ONLY from identity-verified snapshots (see
  // `artifacts` below). meepow.mjs resolves meepow.wasm relative to its own URL, which is why the
  // pair must sit under the same path prefix.
  '/wasm/meepow.mjs': { file: WASM('meepow.mjs'), type: JS, verified: true },
  '/wasm/meepow.wasm': { file: WASM('meepow.wasm'), type: 'application/wasm', verified: true },
});

// Requests carrying a body are not part of this protocol at all.
export const MAX_REQUEST_BODY_BYTES = 1024;

/**
 * Content-Security-Policy for the miner page.
 *
 * `'wasm-unsafe-eval'` is required: without it the browser refuses to compile the MeepHash-W
 * module. The WebSocket origin is named explicitly rather than relying on `connect-src 'self'`
 * covering ws: on the same authority. Everything else is denied, so the page cannot reach any
 * network destination but the loopback server that served it.
 */
export function contentSecurityPolicy(wsOrigin) {
  return [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "worker-src 'self'",
    "style-src 'self'",
    `connect-src 'self' ${wsOrigin}`,
    "img-src 'self' data:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
  ].join('; ');
}

export function securityHeaders(wsOrigin) {
  return {
    'Content-Security-Policy': contentSecurityPolicy(wsOrigin),
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'geolocation=(), camera=(), microphone=(), payment=(), usb=()',
    'Cache-Control': 'no-store',
  };
}

/**
 * The exact route-table key a request maps to, or null. Query strings are ignored and fragments
 * never arrive. Separated from lookupRoute() so the handler can key the verified-snapshot map by
 * the same canonical path it used for the table lookup.
 */
export function routePath(rawUrl) {
  let pathname;
  try {
    pathname = new URL(rawUrl, 'http://localhost').pathname;
  } catch {
    return null;
  }
  // A decoded path is never used to build a filename; it is only compared against the table.
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  return Object.prototype.hasOwnProperty.call(ROUTES, decoded) ? decoded : null;
}

/** Resolve a request path to its route entry, or null. */
export function lookupRoute(rawUrl) {
  const p = routePath(rawUrl);
  return p === null ? null : ROUTES[p];
}

/**
 * @param {object} o
 * @param {string} o.wsOrigin
 * @param {Map<string, Buffer>} [o.artifacts]  identity-verified Wasm snapshots, keyed by route
 * @param {(entry:{method:string,url:string,status:number,atMs:number}) => void} [o.onRequest]
 */
export function createStaticHandler({ wsOrigin, artifacts = null, beforeRead = null, onRequest = () => {} }) {
  const headers = securityHeaders(wsOrigin);

  return async function handle(req, res) {
    const finish = (status, body, extra = {}) => {
      res.writeHead(status, { ...headers, 'Content-Length': body ? Buffer.byteLength(body) : 0, ...extra });
      res.end(req.method === 'HEAD' ? undefined : body);
      onRequest({ method: req.method, url: req.url, status, atMs: Date.now() });
    };

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return finish(405, 'method not allowed', { 'Content-Type': 'text/plain; charset=utf-8', Allow: 'GET, HEAD' });
    }
    const declared = Number(req.headers['content-length'] ?? 0);
    if (Number.isFinite(declared) && declared > MAX_REQUEST_BODY_BYTES) {
      return finish(413, 'request body too large', { 'Content-Type': 'text/plain; charset=utf-8' });
    }

    // Test seam only: lets a test hold this async handler open so shutdown can be shown to drain
    // it. Production passes nothing, so this is a no-op there.
    if (beforeRead) await beforeRead(req);

    const pathname = routePath(req.url ?? '/');
    const route = pathname === null ? null : ROUTES[pathname];
    if (!route) return finish(404, 'not found', { 'Content-Type': 'text/plain; charset=utf-8' });

    // The algorithm routes are served ONLY from the identity-verified snapshot taken at startup.
    // Re-reading the file here would mean shipping bytes nobody hashed -- a file mutated after the
    // startup check would go straight out to the browser. No later read of these paths happens.
    if (route.verified) {
      const snapshot = artifacts?.get(pathname);
      if (!snapshot) {
        return finish(503, 'algorithm build not identity-verified; see docs/LOCAL_BROWSER_MINER_SLICE.md', {
          'Content-Type': 'text/plain; charset=utf-8',
        });
      }
      return finish(200, snapshot, { 'Content-Type': route.type });
    }

    let body;
    try {
      body = await readFile(route.file);
    } catch {
      // A route whose file is missing is a build problem, not a client problem.
      return finish(503, 'file not built; see docs/LOCAL_BROWSER_MINER_SLICE.md', {
        'Content-Type': 'text/plain; charset=utf-8',
      });
    }
    return finish(200, body, { 'Content-Type': route.type });
  };
}
