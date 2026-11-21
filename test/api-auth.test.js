// Offline tests: password hashing, session tokens, cookies, rate limiters and the API configuration.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { scrypt, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import {
  FailureLimiter, RateLimiter, SESSION_COOKIE, clearedCookie, hashPassword, hashToken, newSessionToken, parseCookies, sessionCookie,
  validatePassword, verifyPassword, burnPasswordCheck,
} from '../src/api/auth.js';
import { AppConfigError, loadAppConfig } from '../src/api/config.js';
import { PEM_HEADER, mekoKey } from './helpers/fakeSecrets.js';

const scryptP = promisify(scrypt);
const PW = 'correct horse battery staple 42';

describe('password hashing (scrypt)', () => {
  test('format is scrypt$N$r$p$salt$hash and the password is not in it', async () => {
    const h = await hashPassword(PW);
    assert.match(h, /^scrypt\$32768\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
    assert.ok(!h.includes(PW));
  });
  test('same password, different salt -> different hash; both verify', async () => {
    const a = await hashPassword(PW), b = await hashPassword(PW);
    assert.notEqual(a, b);
    assert.equal(await verifyPassword(PW, a), true);
    assert.equal(await verifyPassword(PW, b), true);
  });
  test('wrong password, empty password and different case all fail', async () => {
    const h = await hashPassword(PW);
    for (const bad of ['', 'wrong', PW + ' ', PW.toUpperCase()]) assert.equal(await verifyPassword(bad, h), false);
  });
  test('malformed / foreign / truncated hashes fail instead of throwing', async () => {
    for (const bad of [undefined, null, '', 'plaintext', 'bcrypt$10$abc$def', 'scrypt$x$y$z$a$b', 'scrypt$32768$8$1$$', 'scrypt$32768$8$1$AAAA$']) {
      assert.equal(await verifyPassword(PW, bad), false, String(bad));
    }
  });
  test('a downgraded cost parameter is refused even with the right password (no weakening via a stored hash)', async () => {
    const salt = randomBytes(16);
    const weak = await scryptP(PW, salt, 64, { N: 1024, r: 8, p: 1 });
    assert.equal(await verifyPassword(PW, `scrypt$1024$8$1$${salt.toString('base64')}$${weak.toString('base64')}`), false);
  });
  test('burnPasswordCheck costs about as much as a real check (timing equaliser) and never throws', async () => {
    const h = await hashPassword(PW);
    const t0 = performance.now(); await verifyPassword('x', h); const real = performance.now() - t0;
    await burnPasswordCheck('warm-up');
    const t1 = performance.now(); await burnPasswordCheck('x'); const burn = performance.now() - t1;
    assert.ok(burn > real * 0.25, `burn ${burn}ms vs real ${real}ms`);
  });
  test('password policy: length 12-256 and not trivially repetitive', () => {
    assert.throws(() => validatePassword('short'), /at least 12/);
    assert.throws(() => validatePassword('x'.repeat(257)), /at most 256/);
    assert.throws(() => validatePassword('aaaaaaaaaaaaaaaa'), /repetitive/);
    assert.throws(() => validatePassword(12345678901234), /string/);
    assert.doesNotThrow(() => validatePassword(PW));
  });
});

describe('session tokens and cookies', () => {
  test('tokens are long, URL-safe and unique; only their SHA-256 is stored', () => {
    const tokens = new Set(Array.from({ length: 200 }, newSessionToken));
    assert.equal(tokens.size, 200);
    const t = [...tokens][0];
    assert.ok(t.length >= 43 && /^[A-Za-z0-9_-]+$/.test(t));
    assert.match(hashToken(t), /^[0-9a-f]{64}$/);
    assert.notEqual(hashToken(t), t);
    assert.equal(hashToken(t), hashToken(t));
  });
  test('parseCookies handles several cookies, encoding, junk and duplicates (first wins)', () => {
    assert.deepEqual(parseCookies('a=1; b=hello%20world; tt_session=abc'), { a: '1', b: 'hello world', tt_session: 'abc' });
    assert.deepEqual(parseCookies('x=1; x=2'), { x: '1' });
    assert.deepEqual(parseCookies(undefined), {});
    assert.deepEqual(parseCookies('=novalue; ;;'), {});
  });
  test('session cookie is HttpOnly + SameSite=Strict; Secure only when asked', () => {
    const c = sessionCookie('tok', { maxAgeSec: 60, secure: false });
    assert.match(c, new RegExp(`^${SESSION_COOKIE}=tok; HttpOnly; SameSite=Strict; Path=/; Max-Age=60$`));
    assert.match(sessionCookie('tok', { maxAgeSec: 60, secure: true }), /; Secure$/);
  });
  test('clearing the cookie expires it immediately', () => {
    const c = clearedCookie({ secure: true });
    assert.match(c, /Max-Age=0/);
    assert.match(c, /Expires=Thu, 01 Jan 1970/);
    assert.match(c, /HttpOnly/);
  });
});

describe('rate limiters (injected clock)', () => {
  test('FailureLimiter blocks after max failures and unblocks when the window passes', () => {
    let t = 1_000_000;
    const l = new FailureLimiter({ max: 3, windowMs: 60_000, now: () => t });
    for (let i = 0; i < 3; i++) { assert.equal(l.check('k').allowed, true); l.fail('k'); }
    const blocked = l.check('k');
    assert.equal(blocked.allowed, false);
    assert.ok(blocked.retryAfterSec >= 1 && blocked.retryAfterSec <= 60);
    t += 61_000;
    assert.equal(l.check('k').allowed, true);
  });
  test('FailureLimiter keys are independent, and reset() clears one key', () => {
    const l = new FailureLimiter({ max: 1, windowMs: 60_000, now: () => 0 });
    l.fail('a');
    assert.equal(l.check('a').allowed, false);
    assert.equal(l.check('b').allowed, true);
    l.reset('a');
    assert.equal(l.check('a').allowed, true);
  });
  test('FailureLimiter memory is bounded', () => {
    const l = new FailureLimiter({ max: 1, windowMs: 60_000, now: () => 0 });
    for (let i = 0; i < 12_000; i++) l.fail(`k${i}`);
    assert.equal(l.check('k0').allowed, true); // evicted, not leaked
  });
  test('RateLimiter allows max per window then blocks with Retry-After, and resets next window', () => {
    let t = 0;
    const l = new RateLimiter({ max: 2, windowMs: 1000, now: () => t });
    assert.equal(l.hit('ip').allowed, true);
    assert.equal(l.hit('ip').allowed, true);
    const third = l.hit('ip');
    assert.equal(third.allowed, false);
    assert.ok(third.retryAfterSec >= 1);
    t += 1000;
    assert.equal(l.hit('ip').allowed, true);
  });
});

describe('API configuration', () => {
  const ok = { DATABASE_URL: 'postgres://u:p@localhost:5432/tt' };
  test('missing DATABASE_URL fails with setup guidance and no value', () => {
    assert.throws(() => loadAppConfig({}), (e) => e instanceof AppConfigError && /DATABASE_URL/.test(e.message) && /docs\/database\.md/.test(e.message));
  });
  test('wrong scheme is rejected', () => {
    assert.throws(() => loadAppConfig({ DATABASE_URL: 'mysql://x' }), AppConfigError);
  });
  test('safe defaults: loopback host, port 8787, non-secure cookie outside production, secure in production', () => {
    const c = loadAppConfig(ok);
    assert.equal(c.host, '127.0.0.1');
    assert.equal(c.port, 8787);
    assert.equal(c.cookieSecure, false);
    assert.equal(c.trustProxy, false);
    assert.deepEqual([...c.allowedOrigins], []);
    assert.equal(loadAppConfig({ ...ok, NODE_ENV: 'production' }).cookieSecure, true);
    assert.equal(loadAppConfig({ ...ok, NODE_ENV: 'production', COOKIE_SECURE: 'false' }).cookieSecure, false);
  });
  test('numeric settings are validated', () => {
    assert.throws(() => loadAppConfig({ ...ok, API_PORT: 'abc' }), AppConfigError);
    assert.throws(() => loadAppConfig({ ...ok, API_PORT: '70000' }), AppConfigError);
    assert.throws(() => loadAppConfig({ ...ok, SESSION_IDLE_MINUTES: '0' }), AppConfigError);
    assert.equal(loadAppConfig({ ...ok, API_PORT: '9000' }).port, 9000);
  });
  test('ALLOWED_ORIGINS must be origins', () => {
    assert.deepEqual([...loadAppConfig({ ...ok, ALLOWED_ORIGINS: 'http://localhost:5173, https://tt.example' }).allowedOrigins], ['http://localhost:5173', 'https://tt.example']);
    assert.throws(() => loadAppConfig({ ...ok, ALLOWED_ORIGINS: 'http://x/path' }), AppConfigError);
    assert.throws(() => loadAppConfig({ ...ok, ALLOWED_ORIGINS: '*' }), AppConfigError);
  });
  test('the Meko API key and signing material NEVER appear in the config; only a boolean', () => {
    const secret = mekoKey('super_secret_value'); // fake, assembled at runtime (see helpers/fakeSecrets.js)
    const c = loadAppConfig({ ...ok, MEKO_API_KEY: secret, TRUSTTRACE_SIGNING_KEY: PEM_HEADER });
    assert.equal(c.mekoConfigured, true);
    assert.ok(!JSON.stringify(c).includes(secret));
    assert.ok(!JSON.stringify(c).includes('PRIVATE KEY'));
    assert.equal(loadAppConfig(ok).mekoConfigured, false);
  });
  test('the config object is frozen', () => {
    assert.throws(() => { 'use strict'; loadAppConfig(ok).port = 1; }, TypeError);
  });
});
