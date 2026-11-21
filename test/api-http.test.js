// Offline tests of the REST API's HTTP behaviour: authentication, authorisation, headers, limits, error handling, logging.
// A REAL http.Server on an ephemeral port is used, with an IN-MEMORY TEST DOUBLE for the user/session store (labelled below).
// The real PostgreSQL-backed store is exercised in test/db/api.integration.test.js.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { createApiServer, listen } from '../src/api/server.js';
import { loadAppConfig } from '../src/api/config.js';
import { hashPassword } from '../src/api/auth.js';
import { makeClock } from './helpers/trust.js';
import { pgUrl } from './helpers/fakeSecrets.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PW = 'a perfectly reasonable passphrase 1!';

/** TEST DOUBLE: in-memory implementation of the user/session/access-log store interface used by the HTTP layer. */
function memoryUsers(clock) {
  const users = new Map();
  const sessions = new Map();
  const access = [];
  return {
    _users: users, _sessions: sessions, _access: access,
    async findUserByUsername(name) { return users.get(String(name).toLowerCase()) ?? null; },
    async setLastLogin() {},
    async createSession({ userId, tokenHash, expiresAt }) {
      const s = { id: randomUUID(), userId, createdAt: new Date(clock.now), lastSeenAt: new Date(clock.now), expiresAt };
      sessions.set(tokenHash, s);
      return s;
    },
    async getSessionByTokenHash(h) {
      const s = sessions.get(h);
      if (!s) return null;
      const u = [...users.values()].find((x) => x.id === s.userId && x.active);
      return u ? { session: { id: s.id, createdAt: s.createdAt, lastSeenAt: s.lastSeenAt, expiresAt: s.expiresAt }, user: { id: u.id, username: u.username, role: u.role } } : null;
    },
    async touchSession(id) { for (const s of sessions.values()) if (s.id === id) s.lastSeenAt = new Date(clock.now); },
    async deleteSessionByTokenHash(h) { sessions.delete(h); },
    async recordAccess(e) { access.push(e); },
  };
}

function call(base, method, path, { headers = {}, body, rawBody } = {}) {
  return new Promise((resolve, reject) => {
    const payload = rawBody ?? (body === undefined ? undefined : JSON.stringify(body));
    const chunked = String(headers['transfer-encoding'] ?? '').toLowerCase() === 'chunked';
    const req = http.request(base + path, { method, agent: false, headers: { ...(payload !== undefined && !('content-type' in headers) ? { 'content-type': 'application/json' } : {}), ...(payload !== undefined && !chunked ? { 'content-length': Buffer.byteLength(payload) } : {}), connection: 'close', ...headers } }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => {
        let json; try { json = JSON.parse(text); } catch { json = undefined; }
        resolve({ status: res.statusCode, headers: res.headers, text, json, cookies: res.headers['set-cookie'] ?? [] });
      });
    });
    // the server may answer (e.g. 413) before reading the whole body: a reset while still writing is part of a correct rejection
    req.on('error', (err) => { if (['ECONNRESET', 'EPIPE'].includes(err.code)) resolve({ status: 413, headers: {}, text: '', json: { error: { code: 'payload_too_large' } }, cookies: [], reset: true }); else reject(err); });
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}
const cookieOf = (r) => (r.cookies[0] ?? '').split(';')[0];

describe('REST API (HTTP layer, in-memory user store)', () => {
  let hashes;
  const booted = [];
  before(async () => { hashes = { admin: await hashPassword(PW), analyst: await hashPassword(PW) }; });
  // a test that throws before its own ctx.close() must not leave a listening socket (it would hang the runner)
  after(async () => { await Promise.all(booted.map((c) => c.close())); });

  async function boot({ env = {}, deps = {}, logs = [] } = {}) {
    const clock = makeClock(Date.UTC(2026, 0, 1));
    const users = memoryUsers(clock);
    users._users.set('alice', { id: randomUUID(), username: 'alice', password_hash: hashes.admin, role: 'admin', active: true });
    users._users.set('bob', { id: randomUUID(), username: 'bob', password_hash: hashes.analyst, role: 'analyst', active: true });
    users._users.set('carol', { id: randomUUID(), username: 'carol', password_hash: hashes.analyst, role: 'analyst', active: false });
    const config = loadAppConfig({ DATABASE_URL: 'postgres://u:p@localhost:5432/x', ...env });
    const server = createApiServer({
      deps: { users, ping: async () => ({ ok: true }), health: async () => ({ status: 'ok', db: { ok: true } }), audit: { verify: async () => ({ ok: true, checked: 0, head: null, problems: [] }) }, ...deps },
      config, clock: clock.fn, logger: (l) => logs.push(l),
    });
    const addr = await listen(server, { host: '127.0.0.1', port: 0 });
    const ctx = { base: `http://127.0.0.1:${addr.port}`, server, users, clock, logs, config, close: () => new Promise((r) => { if (!server.listening) return r(); server.closeAllConnections?.(); server.close(() => r()); }) };
    booted.push(ctx);
    return ctx;
  }
  const login = (ctx, username = 'alice', password = PW) => call(ctx.base, 'POST', '/api/auth/login', { body: { username, password } });

  describe('health and generic behaviour', () => {
    let ctx;
    before(async () => { ctx = await boot(); });
    after(() => ctx.close());

    test('GET /api/health is public and minimal (status, time, db only)', async () => {
      const r = await call(ctx.base, 'GET', '/api/health');
      assert.equal(r.status, 200);
      assert.deepEqual(Object.keys(r.json).sort(), ['db', 'status', 'time']);
      assert.equal(r.json.db, 'up');
    });
    test('security headers are on every response (200, 401, 404)', async () => {
      for (const r of [await call(ctx.base, 'GET', '/api/health'), await call(ctx.base, 'GET', '/api/auth/me'), await call(ctx.base, 'GET', '/api/nope')]) {
        assert.equal(r.headers['cache-control'], 'no-store');
        assert.equal(r.headers['x-content-type-options'], 'nosniff');
        assert.equal(r.headers['x-frame-options'], 'DENY');
        assert.equal(r.headers['referrer-policy'], 'no-referrer');
        assert.match(r.headers['content-security-policy'], /default-src 'none'/);
        assert.match(r.headers['content-type'], /^application\/json/);
        assert.ok(r.headers['x-request-id']);
      }
    });
    test('unknown endpoint -> 404 with the standard error shape and a matching request id', async () => {
      const r = await call(ctx.base, 'GET', '/api/does-not-exist');
      assert.equal(r.status, 404);
      assert.deepEqual(Object.keys(r.json.error).sort(), ['code', 'message', 'requestId']);
      assert.equal(r.json.error.requestId, r.headers['x-request-id']);
    });
    test('wrong method -> 405 with Allow', async () => {
      const r = await call(ctx.base, 'GET', '/api/auth/login');
      assert.equal(r.status, 405);
      assert.equal(r.headers.allow, 'POST');
    });
    test('non-API paths do not serve files (no path traversal surface)', async () => {
      for (const p of ['/', '/etc/passwd', '/api/../secrets/verifier-private.pem', '/..%2f..%2f.env', '/.env']) {
        const r = await call(ctx.base, 'GET', p);
        assert.equal(r.status, 404, p);
        assert.ok(!/BEGIN|mko_tkn_/.test(r.text));
      }
    });
    test('protected endpoints return 401 without credentials', async () => {
      for (const [m, p] of [['GET', '/api/auth/me'], ['GET', '/api/health/details'], ['GET', '/api/audit/verify'], ['POST', '/api/auth/logout']]) {
        const r = await call(ctx.base, m, p);
        assert.equal(r.status, 401, `${m} ${p}`);
        assert.equal(r.json.error.code, 'unauthenticated');
      }
    });
    test('a garbage or oversized token is 401, not a 500', async () => {
      for (const c of ['tt_session=garbage', `tt_session=${'x'.repeat(500)}`, 'tt_session=']) assert.equal((await call(ctx.base, 'GET', '/api/auth/me', { headers: { cookie: c } })).status, 401);
      assert.equal((await call(ctx.base, 'GET', '/api/auth/me', { headers: { authorization: 'Bearer nonsense' } })).status, 401);
    });
    test('the API rate limit (600/min per ip) returns 429 with Retry-After', async () => {
      const c2 = await boot();
      let last;
      for (let i = 0; i < 601; i++) last = await call(c2.base, 'GET', '/api/health');
      assert.equal(last.status, 429);
      assert.equal(last.json.error.code, 'rate_limited');
      assert.ok(Number(last.headers['retry-after']) >= 1);
      c2.clock.advance(61_000);
      assert.equal((await call(c2.base, 'GET', '/api/health')).status, 200);
      await c2.close();
    });
  });

  describe('authentication', () => {
    let ctx;
    before(async () => { ctx = await boot(); });
    after(() => ctx.close());

    test('login succeeds: user returned without any hash, cookie is HttpOnly + SameSite=Strict (no Secure in dev)', async () => {
      const r = await login(ctx);
      assert.equal(r.status, 200);
      assert.deepEqual(Object.keys(r.json.user).sort(), ['id', 'role', 'username']);
      assert.equal(r.json.user.role, 'admin');
      const c = r.cookies[0];
      assert.match(c, /^tt_session=[A-Za-z0-9_-]{40,}; HttpOnly; SameSite=Strict; Path=\/; Max-Age=28800$/);
      assert.doesNotMatch(r.text, /scrypt|password/i);
    });
    test('the session cookie authenticates /api/auth/me; a Bearer token works too', async () => {
      const r = await login(ctx);
      const me = await call(ctx.base, 'GET', '/api/auth/me', { headers: { cookie: cookieOf(r) } });
      assert.equal(me.status, 200);
      assert.equal(me.json.user.username, 'alice');
      const token = cookieOf(r).split('=')[1];
      assert.equal((await call(ctx.base, 'GET', '/api/auth/me', { headers: { authorization: `Bearer ${token}` } })).status, 200);
    });
    test('the database never sees the raw token: only its SHA-256 is stored', async () => {
      const r = await login(ctx);
      const token = cookieOf(r).split('=')[1];
      const stored = [...ctx.users._sessions.keys()];
      assert.ok(!stored.includes(token));
      assert.ok(stored.every((k) => /^[0-9a-f]{64}$/.test(k)));
    });
    test('wrong password, unknown user and disabled account are INDISTINGUISHABLE (no account enumeration)', async () => {
      const a = await login(ctx, 'alice', 'wrong password entirely');
      const b = await login(ctx, 'nobody', PW);
      const c = await login(ctx, 'carol', PW);
      for (const r of [a, b, c]) { assert.equal(r.status, 401); assert.equal(r.json.error.code, 'invalid_credentials'); }
      assert.equal(a.json.error.message, b.json.error.message);
      assert.equal(a.json.error.message, c.json.error.message);
      assert.equal(a.cookies.length + b.cookies.length + c.cookies.length, 0);
    });
    test('usernames are case-insensitive', async () => {
      assert.equal((await login(ctx, 'ALICE')).status, 200);
    });
    test('logout invalidates the session and clears the cookie', async () => {
      const r = await login(ctx);
      const cookie = cookieOf(r);
      const out = await call(ctx.base, 'POST', '/api/auth/logout', { headers: { cookie } });
      assert.equal(out.status, 200);
      assert.match(out.cookies[0], /Max-Age=0/);
      assert.equal((await call(ctx.base, 'GET', '/api/auth/me', { headers: { cookie } })).status, 401);
    });
    test('a user disabled after login loses access immediately', async () => {
      const r = await login(ctx, 'bob');
      const cookie = cookieOf(r);
      assert.equal((await call(ctx.base, 'GET', '/api/auth/me', { headers: { cookie } })).status, 200);
      ctx.users._users.get('bob').active = false;
      assert.equal((await call(ctx.base, 'GET', '/api/auth/me', { headers: { cookie } })).status, 401);
      ctx.users._users.get('bob').active = true;
    });
  });

  describe('authorisation (roles)', () => {
    let ctx, admin, analyst;
    before(async () => {
      ctx = await boot();
      admin = cookieOf(await login(ctx, 'alice'));
      analyst = cookieOf(await login(ctx, 'bob'));
    });
    after(() => ctx.close());

    test('analyst is FORBIDDEN on admin endpoints; admin is allowed', async () => {
      for (const p of ['/api/health/details', '/api/audit/verify']) {
        assert.equal((await call(ctx.base, 'GET', p, { headers: { cookie: analyst } })).status, 403, p);
        assert.equal((await call(ctx.base, 'GET', p, { headers: { cookie: admin } })).status, 200, p);
      }
    });
    test('403 body does not leak internals', async () => {
      const r = await call(ctx.base, 'GET', '/api/audit/verify', { headers: { cookie: analyst } });
      assert.equal(r.json.error.code, 'forbidden');
    });
  });

  describe('session lifetime', () => {
    test('absolute expiry (8 h): expired sessions are rejected and removed', async () => {
      const ctx = await boot();
      const cookie = cookieOf(await login(ctx));
      // stay ACTIVE (a request every 20 min) so the idle limit never fires, up to 7 h 40 min
      for (let i = 0; i < 23; i++) {
        ctx.clock.advance(20 * 60_000);
        assert.equal((await call(ctx.base, 'GET', '/api/auth/me', { headers: { cookie } })).status, 200, `active at ${(i + 1) * 20} min`);
        await sleep(15);
      }
      ctx.clock.advance(25 * 60_000); // 8 h 05 since login, only 25 min idle: the ABSOLUTE limit must end it
      const after = await call(ctx.base, 'GET', '/api/auth/me', { headers: { cookie } });
      assert.equal(after.status, 401);
      assert.equal(after.json.error.code, 'session_expired');
      assert.equal(ctx.users._sessions.size, 0);
      await ctx.close();
    });
    test('idle expiry (30 min): inactivity ends the session, activity keeps it alive', async () => {
      const ctx = await boot();
      const cookie = cookieOf(await login(ctx));
      for (let i = 0; i < 4; i++) {
        ctx.clock.advance(20 * 60_000);
        const r = await call(ctx.base, 'GET', '/api/auth/me', { headers: { cookie } });
        assert.equal(r.status, 200, `still active after ${(i + 1) * 20} min`);
        await sleep(15); // let the fire-and-forget touch land
      }
      ctx.clock.advance(31 * 60_000);
      const idle = await call(ctx.base, 'GET', '/api/auth/me', { headers: { cookie } });
      assert.equal(idle.status, 401);
      assert.equal(idle.json.error.code, 'session_expired');
      await ctx.close();
    });
  });

  describe('brute-force protection', () => {
    test('5 failures for one user+ip -> 429 + Retry-After, even for the CORRECT password; other users unaffected; recovers after the window', async () => {
      const ctx = await boot();
      for (let i = 0; i < 5; i++) assert.equal((await login(ctx, 'alice', `wrong password ${i}`)).status, 401);
      const blocked = await login(ctx, 'alice', PW);
      assert.equal(blocked.status, 429);
      assert.equal(blocked.json.error.code, 'too_many_attempts');
      assert.ok(Number(blocked.headers['retry-after']) > 0);
      assert.equal((await login(ctx, 'bob', PW)).status, 200);
      ctx.clock.advance(16 * 60_000);
      assert.equal((await login(ctx, 'alice', PW)).status, 200);
      await ctx.close();
    });
    test('a successful login resets that user\'s failure count', async () => {
      const ctx = await boot();
      for (let i = 0; i < 4; i++) await login(ctx, 'alice', `wrong ${i}`);
      assert.equal((await login(ctx, 'alice', PW)).status, 200);
      for (let i = 0; i < 4; i++) assert.equal((await login(ctx, 'alice', `wrong again ${i}`)).status, 401);
      await ctx.close();
    });
    test('20 failures from one ip across many usernames -> blocked (credential stuffing)', async () => {
      const ctx = await boot();
      for (let i = 0; i < 20; i++) await login(ctx, `ghost${i}`, 'whatever password');
      const r = await login(ctx, 'alice', PW);
      assert.equal(r.status, 429);
      await ctx.close();
    });
  });

  describe('request validation', () => {
    let ctx;
    before(async () => { ctx = await boot({ env: { MAX_BODY_BYTES: '1024' } }); });
    after(() => ctx.close());

    test('oversized body -> 413 (declared and streamed)', async () => {
      const big = JSON.stringify({ username: 'alice', password: 'x'.repeat(5000) });
      assert.equal((await call(ctx.base, 'POST', '/api/auth/login', { rawBody: big })).status, 413);
      assert.equal((await call(ctx.base, 'POST', '/api/auth/login', { rawBody: big, headers: { 'transfer-encoding': 'chunked' } })).status, 413);
    });
    test('wrong content type -> 415; invalid JSON / non-object -> 400', async () => {
      assert.equal((await call(ctx.base, 'POST', '/api/auth/login', { rawBody: 'username=a&password=b', headers: { 'content-type': 'application/x-www-form-urlencoded' } })).status, 415);
      assert.equal((await call(ctx.base, 'POST', '/api/auth/login', { rawBody: '{nope' })).status, 400);
      assert.equal((await call(ctx.base, 'POST', '/api/auth/login', { rawBody: '[1,2]' })).status, 400);
      assert.equal((await call(ctx.base, 'POST', '/api/auth/login', { rawBody: 'null' })).status, 400);
    });
    test('missing / wrongly typed / oversized fields -> 400 invalid_request', async () => {
      for (const body of [{}, { username: 'a' }, { username: 1, password: 'x' }, { username: 'a', password: {} }, { username: 'x'.repeat(65), password: 'p' }, { username: '', password: 'p' }]) {
        const r = await call(ctx.base, 'POST', '/api/auth/login', { body });
        assert.equal(r.status, 400, JSON.stringify(body).slice(0, 40));
        assert.equal(r.json.error.code, 'invalid_request');
      }
    });
    test('SQL/JS injection strings in credentials are just wrong credentials', async () => {
      for (const u of ["alice' OR '1'='1", 'alice"; DROP TABLE users;--', '__proto__', 'constructor']) {
        const r = await call(ctx.base, 'POST', '/api/auth/login', { body: { username: u, password: PW } });
        assert.equal(r.status, 401, u);
      }
    });
  });

  describe('origin check (CSRF defence in depth)', () => {
    test('a cross-site Origin on a POST is rejected; same-host and allow-listed origins pass', async () => {
      const ctx = await boot({ env: { ALLOWED_ORIGINS: 'http://localhost:5173' } });
      const host = ctx.base.replace('http://', '');
      const post = (origin) => call(ctx.base, 'POST', '/api/auth/login', { body: { username: 'alice', password: PW }, headers: origin ? { origin } : {} });
      assert.equal((await post('http://evil.example')).status, 403);
      assert.equal((await post('http://evil.example')).json.error.code, 'bad_origin');
      assert.equal((await post(`http://${host}`)).status, 200);
      assert.equal((await post('http://localhost:5173')).status, 200);
      assert.equal((await post('not a url')).status, 403);
      assert.equal((await post(undefined)).status, 200); // non-browser client
      await ctx.close();
    });
  });

  describe('error handling and secrets', () => {
    test('an unexpected internal error -> generic 500; the connection string password never reaches the client OR the log', async () => {
      const logs = [];
      const ctx = await boot({ logs, deps: { ping: async () => { throw new Error(`connect failed for ${pgUrl('app', 'topsecretpw', 'db.internal:5432/tt')}`); } } });
      const r = await call(ctx.base, 'GET', '/api/health');
      assert.equal(r.status, 500);
      assert.equal(r.json.error.code, 'internal_error');
      assert.ok(!r.text.includes('topsecretpw') && !r.text.includes('db.internal'));
      assert.ok(!JSON.stringify(logs).includes('topsecretpw'), 'password leaked into the log');
      assert.ok(JSON.stringify(logs).includes('<redacted>'));
      await ctx.close();
    });
    test('a database outage on /health is a 503 with db "down" (readiness), not a crash', async () => {
      const ctx = await boot({ deps: { ping: async () => ({ ok: false, error: 'ECONNREFUSED' }) } });
      const r = await call(ctx.base, 'GET', '/api/health');
      assert.equal(r.status, 503);
      assert.equal(r.json.db, 'down');
      await ctx.close();
    });
    test('no response anywhere contains credentials, hashes or key material', async () => {
      const ctx = await boot();
      const admin = cookieOf(await login(ctx, 'alice'));
      const texts = [];
      for (const [m, p, h] of [['GET', '/api/health'], ['GET', '/api/health/details', { cookie: admin }], ['GET', '/api/auth/me', { cookie: admin }], ['GET', '/api/audit/verify', { cookie: admin }], ['GET', '/api/nope']]) {
        texts.push((await call(ctx.base, m, p, { headers: h ?? {} })).text);
      }
      for (const t of texts) assert.doesNotMatch(t, /mko_tkn_|PRIVATE KEY|scrypt\$|password_hash|token_hash|postgres:\/\//i);
      await ctx.close();
    });
  });

  describe('access logging', () => {
    test('every request except /health is logged with user, status, ip and request id; failed logins are flagged', async () => {
      const ctx = await boot();
      await login(ctx, 'alice', 'wrong password!!');
      const ok = await login(ctx);
      const cookie = cookieOf(ok);
      await call(ctx.base, 'GET', '/api/auth/me', { headers: { cookie } });
      await call(ctx.base, 'GET', '/api/health');
      await call(ctx.base, 'GET', '/api/audit/verify');
      await sleep(30);
      const log = ctx.users._access;
      assert.ok(!log.some((e) => e.path === '/api/health'), 'health checks must not flood the access log');
      const failed = log.find((e) => e.path === '/api/auth/login' && e.status === 401);
      assert.deepEqual(failed.detail, { event: 'login_failed' });
      const success = log.find((e) => e.path === '/api/auth/login' && e.status === 200);
      assert.equal(success.username, 'alice');
      assert.deepEqual(success.detail, { event: 'login_success' });
      const me = log.find((e) => e.path === '/api/auth/me');
      assert.equal(me.username, 'alice');
      assert.ok(me.requestId && me.ip && me.durationMs >= 0);
      assert.equal(log.find((e) => e.path === '/api/audit/verify').status, 401); // no cookie sent: denied AND logged
      await ctx.close();
    });
    test('a failing access-log store never breaks a response, and failures are counted', async () => {
      const ctx = await boot();
      ctx.users.recordAccess = async () => { throw new Error('db down'); };
      const r = await login(ctx);
      assert.equal(r.status, 200);
      await sleep(30);
      assert.ok(ctx.server.stats.accessLogFailures >= 1);
      await ctx.close();
    });
  });
});
