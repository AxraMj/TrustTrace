// Offline: the dashboard is served from the same origin as the API (src/api/static.js) without weakening the API.
// A REAL http.Server serves a temporary web root. Raw requests are used so that paths are NOT normalised client-side (fetch would
// collapse "/../" before sending); a secret file sits OUTSIDE the web root and a sibling "dist-evil" directory checks prefix confusion.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bootApi, PW } from './helpers/apiHarness.js';
import { call, cookieOf } from './helpers/httpClient.js';
import { STATIC_CSP, assertWebDist } from '../src/api/static.js';
import { SECURITY_HEADERS } from '../src/api/http.js';

const raw = (base, path, { method = 'GET', headers = {} } = {}) => new Promise((resolve, reject) => {
  const u = new URL(base);
  const req = http.request({ host: u.hostname, port: u.port, method, path, headers }, (res) => {
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
  });
  req.on('error', reject);
  req.end();
});

const INDEX = '<!doctype html><html><head><title>TT</title></head><body><div id="root"></div><script type="module" src="/assets/app-abc123.js"></script></body></html>';
const SECRET = 'TOPSECRET-OUTSIDE-THE-WEB-ROOT';

describe('dashboard served from the Node server (same origin)', () => {
  let tmp, dist, ctx, symlinkOk = false, dirLinkOk = false;
  before(async () => {
    tmp = mkdtempSync(join(tmpdir(), 'tt-static-'));
    dist = join(tmp, 'dist');
    mkdirSync(join(dist, 'assets'), { recursive: true });
    mkdirSync(join(tmp, 'dist-evil'));
    writeFileSync(join(dist, 'index.html'), INDEX);
    writeFileSync(join(dist, 'assets', 'app-abc123.js'), 'console.log("app")');
    writeFileSync(join(dist, 'assets', 'app-abc123.css'), 'body{margin:0}');
    writeFileSync(join(dist, 'favicon.svg'), '<svg xmlns="http://www.w3.org/2000/svg"/>');
    writeFileSync(join(dist, '.env'), `DATABASE_URL=${SECRET}`);
    writeFileSync(join(dist, 'assets', '.hidden'), SECRET);
    writeFileSync(join(tmp, 'secret.txt'), SECRET);
    writeFileSync(join(tmp, 'dist-evil', 'index.html'), `EVIL ${SECRET}`);
    try { symlinkSync(join(tmp, 'secret.txt'), join(dist, 'linked.txt')); symlinkOk = true; } catch { /* file symlinks need privileges on Windows */ }
    // a directory link (a junction on Windows, which needs no privileges) pointing OUTSIDE the web root
    mkdirSync(join(tmp, 'outside'));
    writeFileSync(join(tmp, 'outside', 'secret.txt'), SECRET);
    try { symlinkSync(join(tmp, 'outside'), join(dist, 'linkdir'), 'junction'); dirLinkOk = true; } catch { /* not permitted */ }
    ctx = await bootApi({ env: { WEB_DIST_DIR: dist } });
  });
  after(async () => { await ctx.close(); rmSync(tmp, { recursive: true, force: true }); });

  describe('serving', () => {
    test('GET / returns the app with its own strict CSP and hardening headers', async () => {
      const r = await raw(ctx.base, '/');
      assert.equal(r.status, 200);
      assert.equal(r.body, INDEX);
      assert.match(r.headers['content-type'], /^text\/html/);
      assert.equal(r.headers['content-security-policy'], STATIC_CSP);
      assert.doesNotMatch(r.headers['content-security-policy'], /unsafe-|\*|https?:/);
      assert.equal(r.headers['x-content-type-options'], 'nosniff');
      assert.equal(r.headers['x-frame-options'], 'DENY');
      assert.equal(r.headers['referrer-policy'], 'no-referrer');
      assert.equal(r.headers['cache-control'], 'no-cache');
      assert.equal(r.headers['strict-transport-security'], undefined, 'no HSTS unless COOKIE_SECURE');
    });
    test('hashed assets: correct types, immutable caching', async () => {
      const js = await raw(ctx.base, '/assets/app-abc123.js');
      assert.equal(js.status, 200); assert.match(js.headers['content-type'], /^text\/javascript/); assert.equal(js.headers['cache-control'], 'public, max-age=31536000, immutable');
      const css = await raw(ctx.base, '/assets/app-abc123.css');
      assert.match(css.headers['content-type'], /^text\/css/);
      assert.equal((await raw(ctx.base, '/favicon.svg')).headers['content-type'], 'image/svg+xml');
      assert.equal((await raw(ctx.base, '/favicon.svg')).headers['cache-control'], 'no-cache', 'only /assets/ is immutable');
    });
    test('client-side routes fall back to index.html (SPA), including percent-encoded ids', async () => {
      for (const p of ['/alerts', '/alerts?window=24h&flag=degraded', '/cases', '/cases/acct%2Fodd/case%20%231', '/decisions/11111111-1111-4111-8111-111111111111', '/login', '/assets']) {
        const r = await raw(ctx.base, p);
        assert.equal(r.status, 200, p); assert.equal(r.body, INDEX, p);
      }
    });
    test('a missing file that looks like an asset is a real 404, not index.html', async () => {
      for (const p of ['/assets/missing.js', '/favicon.ico', '/robots.txt', '/assets/app-abc123.js.map']) {
        const r = await raw(ctx.base, p);
        assert.equal(r.status, 404, p); assert.doesNotMatch(r.body, /<div id="root">/, p);
        assert.equal(r.headers['content-security-policy'], STATIC_CSP);
      }
    });
    test('HEAD returns headers and length but no body; query strings are ignored', async () => {
      const h = await raw(ctx.base, '/assets/app-abc123.js?v=1', { method: 'HEAD' });
      assert.equal(h.status, 200); assert.equal(h.body, ''); assert.equal(Number(h.headers['content-length']), 'console.log("app")'.length);
    });
    test('static requests never touch the session store, the access log or the database', async () => {
      const before = ctx.users._access.length;
      const sessionsBefore = ctx.users._sessions.size;
      for (const p of ['/', '/alerts', '/assets/app-abc123.js', '/assets/nope.js']) await raw(ctx.base, p);
      assert.equal(ctx.users._access.length, before);
      assert.equal(ctx.users._sessions.size, sessionsBefore);
    });
  });

  describe('path traversal and sensitive files are refused', () => {
    const ATTACKS = [
      '/../secret.txt', '/..%2fsecret.txt', '/%2e%2e/secret.txt', '/%2e%2e%2fsecret.txt', '/assets/../../secret.txt', '/assets/..%2f..%2fsecret.txt',
      '/assets/%2e%2e/%2e%2e/secret.txt', '/%252e%252e/secret.txt', '/..%5csecret.txt', '/..%5C..%5Csecret.txt', '/assets/..%5c..%5csecret.txt',
      '/..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd', '/../dist-evil/index.html', '/..%2fdist-evil%2findex.html', '/%2e%2e%2fdist-evil%2findex.html',
      '/.env', '/%2eenv', '/assets/.hidden', '/.git/config', '/.git%2fconfig', '/assets/%00.js', '/%00', '/index.html%00.png',
      '/C:/Windows/win.ini', '/C%3A%5CWindows%5Cwin.ini', '//etc/passwd', '///secret.txt', '/\\..\\secret.txt',
    ];
    for (const p of ATTACKS) {
      test(`refuses ${p}`, async () => {
        const r = await raw(ctx.base, p);
        assert.ok(r.body !== undefined);
        assert.doesNotMatch(r.body, new RegExp(SECRET), `leaked the secret for ${p}`);
        assert.doesNotMatch(r.body, /EVIL/);
        assert.ok([200, 400, 404].includes(r.status), `${p} -> ${r.status}`);
        if (r.status === 200) assert.equal(r.body, INDEX, `${p}: the only acceptable 200 is the SPA shell`);
      });
    }
    test('dotfiles are never served, even though they exist in the web root', async () => {
      for (const p of ['/.env', '/assets/.hidden']) assert.equal((await raw(ctx.base, p)).status, 404);
    });
    test('a symlink inside the web root cannot escape it', async (t) => {
      if (!symlinkOk) return t.skip('file symlinks are not permitted in this environment');
      const r = await raw(ctx.base, '/linked.txt');
      assert.doesNotMatch(r.body, new RegExp(SECRET)); assert.equal(r.status, 404);
    });
    test('a directory link inside the web root pointing outside it cannot be used to read files outside', async (t) => {
      if (!dirLinkOk) return t.skip('directory links are not permitted in this environment');
      for (const p of ['/linkdir/secret.txt', '/linkdir%2fsecret.txt']) {
        const r = await raw(ctx.base, p);
        assert.doesNotMatch(r.body, new RegExp(SECRET), p); assert.equal(r.status, 404, p);
      }
    });
    test('an enormous path does not crash the server', async () => {
      const r = await raw(ctx.base, `/${'a'.repeat(8000)}`);
      assert.ok([200, 404, 414].includes(r.status));
      assert.equal((await raw(ctx.base, '/')).status, 200);
    });
  });

  describe('the API is unchanged', () => {
    test('API responses keep their own headers (default-src none, no-store); the app CSP is not applied to them', async () => {
      const r = await raw(ctx.base, '/api/nope');
      assert.equal(r.status, 404);
      assert.equal(JSON.parse(r.body).error.code, 'not_found');
      assert.equal(r.headers['content-security-policy'], SECURITY_HEADERS['Content-Security-Policy']);
      assert.equal(r.headers['cache-control'], 'no-store');
      assert.match(r.headers['content-type'], /^application\/json/);
    });
    test('/api and /api/... never fall back to index.html', async () => {
      for (const p of ['/api', '/api/', '/api/anything/else']) {
        const r = await raw(ctx.base, p);
        assert.equal(r.status, 404, p); assert.doesNotMatch(r.body, /<div id="root">/);
        assert.equal(r.headers['content-security-policy'], SECURITY_HEADERS['Content-Security-Policy']);
      }
    });
    test('authentication is still required for data, and sign-in still works on the single origin', async () => {
      assert.equal((await call(ctx.base, 'GET', '/api/alerts')).status, 401);
      assert.equal((await call(ctx.base, 'GET', '/api/summary')).status, 401);
      const login = await call(ctx.base, 'POST', '/api/auth/login', { body: { username: 'sam', password: PW }, headers: { origin: ctx.base } });
      assert.equal(login.status, 200);
      const cookie = cookieOf(login);
      assert.equal((await call(ctx.base, 'GET', '/api/auth/me', { headers: { cookie } })).json.user.role, 'supervisor');
      assert.equal((await call(ctx.base, 'GET', '/api/audit/verify', { headers: { cookie } })).status, 403, 'role checks unchanged');
    });
    test('the Origin check on writes is unchanged: a foreign origin cannot sign in', async () => {
      const r = await call(ctx.base, 'POST', '/api/auth/login', { body: { username: 'sam', password: PW }, headers: { origin: 'https://evil.example' } });
      assert.equal(r.status, 403);
      assert.equal(r.json.error.code, 'bad_origin');
    });
    test('non-GET requests on app paths are not served as files (API 404 JSON)', async () => {
      for (const m of ['POST', 'PUT', 'DELETE']) {
        const r = await raw(ctx.base, '/alerts', { method: m, headers: { 'content-length': '0' } });
        assert.equal(r.status, 404, m);
        assert.equal(JSON.parse(r.body).error.code, 'not_found');
        assert.equal(r.headers['content-security-policy'], SECURITY_HEADERS['Content-Security-Policy']);
      }
    });
  });

  describe('/api/live (process liveness only)', () => {
    test('200 without authentication, tiny body, never touches the database, access log or sessions', async () => {
      const before = ctx.users._access.length;
      const sessionsBefore = ctx.users._sessions.size;
      for (let i = 0; i < 5; i++) {
        const r = await raw(ctx.base, '/api/live');
        assert.equal(r.status, 200);
        const j = JSON.parse(r.body);
        assert.equal(j.status, 'ok'); assert.deepEqual(Object.keys(j).sort(), ['status', 'time']);
        assert.equal(r.headers['cache-control'], 'no-store');
      }
      await new Promise((r) => setTimeout(r, 40));
      assert.equal(ctx.users._access.length, before, 'liveness probes are not access-logged');
      assert.equal(ctx.users._sessions.size, sessionsBefore, 'liveness probes create no sessions');
    });
    test('it stays 200 while the database is down; /api/health reports the failure (503)', async () => {
      let dbCalls = 0;
      const down = await bootApi({ deps: { ping: async () => { dbCalls++; return { ok: false, error: 'ECONNREFUSED' }; } } });
      try {
        const live = await raw(down.base, '/api/live');
        assert.equal(live.status, 200);
        assert.equal(dbCalls, 0, '/api/live must not query the database');
        const health = await raw(down.base, '/api/health');
        assert.equal(health.status, 503);
        assert.equal(JSON.parse(health.body).db, 'down');
        assert.equal(dbCalls, 1, '/api/health does check the database');
      } finally { await down.close(); }
    });
    test('POST /api/live is 405 (GET only)', async () => {
      const r = await raw(ctx.base, '/api/live', { method: 'POST', headers: { 'content-length': '0' } });
      assert.equal(r.status, 405);
    });
  });

  describe('configuration', () => {
    test('HSTS is added to app responses only when cookies are Secure (HTTPS deployment)', async () => {
      const s = await bootApi({ env: { WEB_DIST_DIR: dist, COOKIE_SECURE: 'true' } });
      try { assert.match((await raw(s.base, '/')).headers['strict-transport-security'], /max-age=31536000/); } finally { await s.close(); }
    });
    test('without WEB_DIST_DIR nothing is served: "/" is the API 404 exactly as before', async () => {
      const s = await bootApi({});
      try {
        const r = await raw(s.base, '/');
        assert.equal(r.status, 404); assert.equal(JSON.parse(r.body).error.code, 'not_found');
        assert.equal(r.headers['content-security-policy'], SECURITY_HEADERS['Content-Security-Policy']);
      } finally { await s.close(); }
    });
    test('a web root without index.html is rejected at startup (assertWebDist), not silently ignored', () => {
      assert.throws(() => assertWebDist(join(tmp, 'dist-evil', 'nope')), /no index\.html/);
      assert.doesNotThrow(() => assertWebDist(dist));
    });
  });
});

describe('the real production build (web/dist), when present', () => {
  test('is served: index.html references assets that are served with the right type and immutable caching', async (t) => {
    const { existsSync, readFileSync, readdirSync } = await import('node:fs');
    if (!existsSync('web/dist/index.html')) return t.skip('web/dist not built (cd web && npm run build)');
    const ctx = await bootApi({ env: { WEB_DIST_DIR: 'web/dist' } });
    try {
      const index = readFileSync('web/dist/index.html', 'utf8');
      const r = await raw(ctx.base, '/');
      assert.equal(r.body, index);
      assert.doesNotMatch(index, /<script(?![^>]*\ssrc=)[^>]*>[^<]/, 'the build has no inline script (CSP script-src self)');
      assert.doesNotMatch(index, /\sstyle="/, 'the build has no inline style attribute (CSP style-src self)');
      const js = /src="(\/assets\/[^"]+\.js)"/.exec(index)?.[1];
      assert.ok(js, 'index.html references a hashed script');
      const a = await raw(ctx.base, js);
      assert.equal(a.status, 200); assert.match(a.headers['content-type'], /javascript/); assert.match(a.headers['cache-control'], /immutable/);
      assert.ok(readdirSync('web/dist/assets').length >= 2);
      assert.doesNotMatch(a.body, /mko_tkn_|-----BEGIN [A-Z ]*PRIVATE KEY-----|postgres:\/\/[^\s'"]+:[^\s'"]+@/, 'no secrets in the shipped bundle');
    } finally { await ctx.close(); }
  });
});
