import http from 'node:http';
import { FailureLimiter, RateLimiter, SESSION_COOKIE, hashToken, parseCookies } from './auth.js';
import { ApiError, newRequestId, readJsonBody, sendJson } from './http.js';
import { buildRouter } from './routes.js';
import { clientIpFrom } from './clientIp.js';
import { createStaticHandler, isStaticPath } from './static.js';

const defaultLogger = (line) => process.stderr.write(JSON.stringify(line) + '\n');

/**
 * Build the REST API HTTP server (not listening yet).
 * @param {{deps: object, config: object, clock?: ()=>number, logger?: (o:object)=>void}} opts
 *   deps: { users (user/session/access-log store), ping(), health(), audit:{verify()} }
 */
export function createApiServer({ deps, config, clock = Date.now, logger = defaultLogger }) {
  const router = buildRouter();
  const limiters = {
    login: new FailureLimiter({ max: 5, windowMs: 15 * 60_000, now: clock }), // failed sign-ins per (ip, username)
    loginIp: new FailureLimiter({ max: 20, windowMs: 15 * 60_000, now: clock }), // failed sign-ins per ip, any username
    api: new RateLimiter({ max: 600, windowMs: 60_000, now: clock }),
  };
  const stats = { requests: 0, accessLogFailures: 0 };
  const idleMs = config.sessionIdleMinutes * 60_000;

  const clientIp = (req) => clientIpFrom({
    xff: req.headers['x-forwarded-for'], remoteAddress: req.socket.remoteAddress, hops: config.trustProxyHops ?? 0, legacyTrustFirst: config.trustProxy,
  });
  // The built dashboard, served from this same origin (only when WEB_DIST_DIR is configured).
  const staticHandler = config.webDistDir ? createStaticHandler({ dir: config.webDistDir, hsts: config.cookieSecure }) : null;

  function checkOrigin(req) {
    const origin = req.headers.origin;
    if (!origin) return; // non-browser client; SameSite=Strict cookies protect browsers
    let host;
    try { host = new URL(origin).host; } catch { throw new ApiError(403, 'bad_origin', 'origin not allowed'); }
    if (config.allowedOrigins.includes(origin) || host === req.headers.host) return;
    throw new ApiError(403, 'bad_origin', 'origin not allowed');
  }

  async function authenticate(req) {
    const header = String(req.headers.authorization ?? '');
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (!token || token.length > 200) throw new ApiError(401, 'unauthenticated', 'authentication required');
    const tokenHash = hashToken(token);
    const found = await deps.users.getSessionByTokenHash(tokenHash);
    if (!found) throw new ApiError(401, 'unauthenticated', 'authentication required');
    const now = clock();
    const expired = new Date(found.session.expiresAt).getTime() <= now;
    const idle = new Date(found.session.lastSeenAt).getTime() + idleMs <= now;
    if (expired || idle) {
      await deps.users.deleteSessionByTokenHash(tokenHash).catch(() => {});
      throw new ApiError(401, 'session_expired', 'session expired; sign in again');
    }
    if (now - new Date(found.session.lastSeenAt).getTime() > 60_000) deps.users.touchSession(found.session.id).catch(() => {});
    return { ...found, token };
  }

  async function handle(req, res) {
    const t0 = performance.now();
    const requestId = newRequestId();
    const ip = clientIp(req);
    let url;
    try { url = new URL(req.url ?? '/', 'http://localhost'); } catch { url = new URL('/', 'http://localhost'); }
    // Dashboard files (GET/HEAD outside /api): no router, no rate limiter, no session, no database, no access-log row.
    if (staticHandler && (req.method === 'GET' || req.method === 'HEAD') && isStaticPath(url.pathname)) {
      await staticHandler(req, res, url.pathname);
      if (res.statusCode >= 400) logger({ level: 'info', requestId, method: req.method, static: true, status: res.statusCode, ms: Math.round((performance.now() - t0) * 10) / 10 });
      return;
    }
    let status = 500;
    let who = null;
    let route = null;
    let extraAudit = null;
    stats.requests++;
    const send = (s, body, headers = {}) => { status = s; sendJson(res, s, body, { 'X-Request-Id': requestId, ...headers }); };
    try {
      const m = router.match(req.method ?? 'GET', url.pathname);
      if (!m.route) {
        if (m.methodNotAllowed) throw new ApiError(405, 'method_not_allowed', 'method not allowed', { headers: { Allow: m.methodNotAllowed.join(', ') } });
        throw new ApiError(404, 'not_found', 'no such endpoint');
      }
      route = m.route;
      const rate = limiters.api.hit(ip);
      if (!rate.allowed) throw new ApiError(429, 'rate_limited', 'too many requests', { headers: { 'Retry-After': String(rate.retryAfterSec) } });
      if (req.method !== 'GET' && req.method !== 'HEAD') checkOrigin(req);

      let auth = null;
      if (route.options.auth !== 'none') {
        auth = await authenticate(req);
        who = auth.user;
        if (route.options.roles && !route.options.roles.includes(auth.user.role)) throw new ApiError(403, 'forbidden', 'your role may not use this endpoint');
      }
      const body = route.options.body ? (req.headers['content-length'] === '0' && !req.headers['content-type'] ? {} : await readJsonBody(req, config.maxBodyBytes)) : undefined;

      const out = await route.handler({
        req, url, params: m.params, body, deps, config, clock, ip, requestId, limiters,
        user: auth?.user, session: auth?.session, token: auth?.token,
      });
      extraAudit = out.audit ?? null;
      if (extraAudit?.userId) who = { id: extraAudit.userId, username: extraAudit.username };
      send(out.status ?? 200, out.body ?? out, out.headers ?? {});
    } catch (err) {
      if (err instanceof ApiError) {
        send(err.status, { error: { code: err.code, message: err.message, requestId } }, err.headers ?? {});
      } else {
        logger({ level: 'error', requestId, method: req.method, path: url.pathname, error: String(err?.message ?? err).replace(/postgres(?:ql)?:\/\/\S+/g, '<redacted>') });
        send(500, { error: { code: 'internal_error', message: 'internal error', requestId } });
      }
    } finally {
      const durationMs = Math.round((performance.now() - t0) * 10) / 10;
      logger({ level: 'info', requestId, method: req.method, path: url.pathname, status, ms: durationMs });
      if (!route?.options.noAccessLog) {
        const detail = extraAudit?.detail ?? (status === 401 && url.pathname === '/api/auth/login' ? { event: 'login_failed' } : status === 429 && url.pathname === '/api/auth/login' ? { event: 'login_blocked' } : undefined);
        Promise.resolve(deps.users.recordAccess({ userId: who?.id, username: who?.username, method: req.method, path: url.pathname, status, durationMs, ip, requestId, detail }))
          .catch(() => { stats.accessLogFailures++; });
      }
    }
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      // handle() already converts every error to a response; this is a last-resort guard
      logger({ level: 'error', fatal: true, error: String(err?.message ?? err) });
      if (!res.headersSent) { res.writeHead(500); res.end(); } else res.destroy();
    });
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.stats = stats;
  return server;
}

export function listen(server, { host, port }) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => { server.off('error', reject); resolve(server.address()); });
  });
}
