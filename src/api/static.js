// Serves the built React dashboard (web/dist) from the same origin as the API, so the HttpOnly SameSite=Strict session cookie and the
// Origin check work with no CORS. This module is deliberately small and strict:
//   * GET/HEAD only; anything else falls through to the API router (404/405 JSON as before).
//   * Path traversal is refused three ways: decoded once, dot-segments / dotfiles / NUL / backslash rejected, and the resolved real path
//     (symlinks followed) must stay inside the real web root.
//   * Its CSP is a separate, strict policy for the app (self only, no inline script/style, no third parties). API responses keep their own
//     `default-src 'none'` policy (see http.js); nothing here touches API headers, authentication or authorisation.
//   * Static requests never reach the router, rate limiter, session store or access log (so serving assets cannot touch PostgreSQL).
import { createReadStream, existsSync } from 'node:fs';
import { realpath, stat } from 'node:fs/promises';
import path from 'node:path';

export const STATIC_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp',
  '.ico': 'image/x-icon', '.woff': 'font/woff', '.woff2': 'font/woff2', '.txt': 'text/plain; charset=utf-8', '.map': 'application/json; charset=utf-8',
};

/** Static handling applies to everything except the API namespace. */
export const isStaticPath = (pathname) => !(pathname === '/api' || pathname.startsWith('/api/'));

/** Fail fast at startup if the configured directory is not a built dashboard. */
export function assertWebDist(dir) {
  if (!existsSync(path.join(dir, 'index.html'))) {
    throw new Error(`WEB_DIST_DIR "${dir}" has no index.html. Build the dashboard first: cd web && npm ci && npm run build`);
  }
}

function headers(type, { hsts, cache, length }) {
  return {
    'Content-Type': type,
    'Content-Length': length,
    'Cache-Control': cache,
    'Content-Security-Policy': STATIC_CSP,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    ...(hsts ? { 'Strict-Transport-Security': 'max-age=31536000' } : {}),
  };
}

/**
 * @param {{dir: string, hsts?: boolean}} opts
 * @returns {(req, res, pathname: string) => Promise<void>} always ends the response
 */
export function createStaticHandler({ dir, hsts = false }) {
  const rootReal = realpath(path.resolve(dir)); // promise, resolved once
  rootReal.catch(() => {}); // surfaced on first request instead of as an unhandled rejection

  const within = (root, p) => p === root || p.startsWith(root.endsWith(path.sep) ? root : root + path.sep);

  const text = (res, req, status, body) => {
    const buf = Buffer.from(body);
    res.writeHead(status, headers('text/plain; charset=utf-8', { hsts, cache: 'no-store', length: buf.length }));
    res.end(req.method === 'HEAD' ? undefined : buf);
  };

  async function sendFile(req, res, file, urlPath) {
    const s = await stat(file);
    const type = TYPES[path.extname(file).toLowerCase()] ?? 'application/octet-stream';
    // Vite emits content-hashed files under /assets/: safe to cache forever. Everything else (index.html) must revalidate.
    const cache = urlPath.startsWith('/assets/') ? 'public, max-age=31536000, immutable' : 'no-cache';
    res.writeHead(200, headers(type, { hsts, cache, length: s.size }));
    if (req.method === 'HEAD') return res.end();
    const stream = createReadStream(file);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
    return undefined;
  }

  return async function handleStatic(req, res, pathname) {
    try {
      let decoded;
      try { decoded = decodeURIComponent(pathname); } catch { return text(res, req, 400, 'Bad request'); }
      if (decoded.includes('\0') || decoded.includes('\\')) return text(res, req, 400, 'Bad request');
      const segments = decoded.split('/').filter((s) => s !== '');
      // dot-segments and dotfiles (".env", ".git", "..") are never served
      if (segments.some((s) => s.startsWith('.'))) return text(res, req, 404, 'Not found');

      const root = await rootReal;
      const candidate = path.join(root, ...segments);
      if (!within(root, candidate)) return text(res, req, 404, 'Not found');

      let file = null;
      try {
        const real = await realpath(candidate); // follow symlinks, then re-check containment
        if (within(root, real) && (await stat(real)).isFile()) file = real;
      } catch { /* not found */ }

      if (file) return await sendFile(req, res, file, `/${segments.join('/')}`);
      // A missing file that looks like an asset (has an extension) is a real 404; a route-like path is a client-side route -> index.html
      if (/\.[A-Za-z0-9]{1,8}$/.test(segments.at(-1) ?? '')) return text(res, req, 404, 'Not found');
      return await sendFile(req, res, path.join(root, 'index.html'), '/index.html');
    } catch {
      if (!res.headersSent) return text(res, req, 500, 'Internal error');
      res.destroy();
      return undefined;
    }
  };
}
