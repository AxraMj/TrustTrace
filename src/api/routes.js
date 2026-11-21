import { burnPasswordCheck, clearedCookie, hashToken, newSessionToken, sessionCookie, verifyPassword } from './auth.js';
import { ApiError, Router } from './http.js';
import { registerInvestigationRoutes } from './investigationRoutes.js';

const ROLES = ['analyst', 'supervisor', 'admin'];
const ANY = { auth: 'user' };
const ADMIN = { auth: 'user', roles: ['admin'] };

/**
 * Phase 1 routes: health, authentication, audit-chain verification. Phase 2 adds the investigation endpoints.
 * Every route is declared with its auth requirement; anything not declared is a 404.
 */
export function buildRouter() {
  const r = new Router();

  // Liveness/readiness: public and minimal (no versions, counts or latencies).
  r.add('GET', '/api/health', { auth: 'none', noAccessLog: true }, async ({ deps, clock }) => {
    const db = await deps.ping();
    return { status: db.ok ? 200 : 503, body: { status: db.ok ? 'ok' : 'degraded', time: new Date(clock()).toISOString(), db: db.ok ? 'up' : 'down' } };
  });

  // Process liveness only: answers 200 if the Node process is running and able to respond. It deliberately does NOT query PostgreSQL
  // or Meko (use it for platform liveness checks; use /api/health for real dependency health). Public, minimal, never access-logged.
  r.add('GET', '/api/live', { auth: 'none', noAccessLog: true }, async ({ clock }) => ({ body: { status: 'ok', time: new Date(clock()).toISOString() } }));

  r.add('GET', '/api/health/details', ADMIN, async ({ deps }) => ({ body: await deps.health() }));

  r.add('POST', '/api/auth/login', { auth: 'none', body: true }, async ({ body, deps, config, clock, ip, req, limiters }) => {
    const { username, password } = body;
    if (typeof username !== 'string' || typeof password !== 'string' || username.length < 1 || username.length > 64 || password.length < 1 || password.length > 256) {
      throw new ApiError(400, 'invalid_request', 'username and password are required');
    }
    const keyUser = `${ip}|${username.toLowerCase()}`;
    const keyIp = `ip|${ip}`;
    for (const c of [limiters.login.check(keyUser), limiters.loginIp.check(keyIp)]) {
      if (!c.allowed) throw new ApiError(429, 'too_many_attempts', 'too many failed sign-in attempts; try again later', { headers: { 'Retry-After': String(c.retryAfterSec) } });
    }
    const user = await deps.users.findUserByUsername(username);
    const ok = user && user.active ? await verifyPassword(password, user.password_hash) : (await burnPasswordCheck(password), false);
    if (!ok) {
      limiters.login.fail(keyUser);
      limiters.loginIp.fail(keyIp);
      // identical response for unknown user, wrong password and disabled account: no account enumeration
      throw new ApiError(401, 'invalid_credentials', 'invalid username or password');
    }
    limiters.login.reset(keyUser);
    const token = newSessionToken();
    const expiresAt = new Date(clock() + config.sessionTtlMinutes * 60_000);
    await deps.users.createSession({ userId: user.id, tokenHash: hashToken(token), expiresAt, ip, userAgent: req.headers['user-agent'] });
    await deps.users.setLastLogin(user.id);
    return {
      body: { user: { id: user.id, username: user.username, role: user.role }, expiresAt: expiresAt.toISOString() },
      headers: { 'Set-Cookie': sessionCookie(token, { maxAgeSec: config.sessionTtlMinutes * 60, secure: config.cookieSecure }) },
      audit: { userId: user.id, username: user.username, detail: { event: 'login_success' } },
    };
  });

  r.add('POST', '/api/auth/logout', ANY, async ({ deps, config, token }) => {
    await deps.users.deleteSessionByTokenHash(hashToken(token));
    return { body: { ok: true }, headers: { 'Set-Cookie': clearedCookie({ secure: config.cookieSecure }) } };
  });

  r.add('GET', '/api/auth/me', ANY, async ({ user, session }) => ({ body: { user: { id: user.id, username: user.username, role: user.role }, session: { expiresAt: new Date(session.expiresAt).toISOString() } } }));

  r.add('GET', '/api/audit/verify', ADMIN, async ({ deps }) => ({ body: await deps.audit.verify() }));

  registerInvestigationRoutes(r); // Phase 2: read-only investigation endpoints over the PostgreSQL decision log

  return r;
}

export { ROLES };
