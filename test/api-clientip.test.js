// Offline: deriving the client IP behind a reverse proxy without trusting client-forged X-Forwarded-For values.
// Platform fact (documented by Cloudflare, observed on Render): the proxy APPENDS the address it saw to any X-Forwarded-For the client
// sent. So the leftmost entries are attacker-controlled; only the rightmost entries were added by trusted infrastructure.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { clientIpFrom, normalizeIp } from '../src/api/clientIp.js';
import { AppConfigError, loadAppConfig } from '../src/api/config.js';
import { bootApi, PW } from './helpers/apiHarness.js';
import { call } from './helpers/httpClient.js';

const SOCK = '10.0.0.5'; // the proxy's address as seen by the app
const ip = (xff, hops, extra = {}) => clientIpFrom({ xff, remoteAddress: SOCK, hops, ...extra });

describe('clientIpFrom (pure)', () => {
  test('default (0 hops) ignores X-Forwarded-For completely', () => {
    assert.equal(ip('203.0.113.9', 0), SOCK);
    assert.equal(ip('1.1.1.1, 203.0.113.9', 0), SOCK);
    assert.equal(ip(undefined, 0), SOCK);
    assert.equal(clientIpFrom({ remoteAddress: undefined }), 'unknown');
  });
  test('1 hop: the entry appended by the proxy, counted from the RIGHT, is the client', () => {
    assert.equal(ip('203.0.113.9', 1), '203.0.113.9');
    assert.equal(ip('198.51.100.1, 203.0.113.9', 1), '203.0.113.9');
  });
  test('SPOOFING: whatever the client puts on the left is ignored', () => {
    for (const forged of ['1.2.3.4', '1.2.3.4, 5.6.7.8', '127.0.0.1', '10.0.0.5', 'admin', `${'9.9.9.9, '.repeat(200)}8.8.8.8`, '1.2.3.4,,,,', ' , 1.2.3.4']) {
      assert.equal(ip(`${forged}, 203.0.113.9`, 1), '203.0.113.9', `forged prefix: ${forged.slice(0, 30)}`);
    }
  });
  test('2 hops: skips the entry appended by the second trusted proxy', () => {
    assert.equal(ip('1.2.3.4, 203.0.113.9, 172.16.0.1', 2), '203.0.113.9');
    assert.equal(ip('1.2.3.4, 203.0.113.9, 172.16.0.1', 1), '172.16.0.1', 'under-counting yields a proxy-side address, never a forged one');
  });
  test('a chain shorter than the configured hops falls back to the socket address (nothing is trustworthy)', () => {
    assert.equal(ip('1.2.3.4', 2), SOCK);
    assert.equal(ip('', 1), SOCK);
    assert.equal(ip(undefined, 3), SOCK);
  });
  test('the selected entry must be a literal IP address; anything else falls back to the socket', () => {
    for (const bad of ['unknown', 'abc', '<script>alert(1)</script>', '999.1.1.1', '1.2.3', "1.2.3.4'; DROP TABLE x;--", '1.2.3.4 5.6.7.8', 'null']) {
      assert.equal(ip(`203.0.113.9, ${bad}`, 1), SOCK, bad);
    }
  });
  test('ports, brackets and IPv4-mapped IPv6 are normalised; case is folded', () => {
    assert.equal(ip('203.0.113.9:51234', 1), '203.0.113.9');
    assert.equal(ip('[2001:db8::1]:443', 1), '2001:db8::1');
    assert.equal(ip('2001:DB8::AB', 1), '2001:db8::ab');
    assert.equal(ip('::ffff:203.0.113.9', 1), '203.0.113.9');
    assert.equal(normalizeIp(''), null); assert.equal(normalizeIp(null), null);
  });
  test('distinct clients behind the same proxy get distinct addresses', () => {
    const a = ip('x, 203.0.113.1', 1), b = ip('x, 203.0.113.2', 1);
    assert.notEqual(a, b);
  });
  test('legacy first-entry mode is EXPOSED as unsafe: a client chooses its own address (kept only for compatibility)', () => {
    assert.equal(ip('6.6.6.6, 203.0.113.9', 0, { legacyTrustFirst: true }), '6.6.6.6');
  });
  test('over-counting hops is the one dangerous mistake: it reaches into client-controlled entries', () => {
    // documented limitation: pick the hop count from observation (see docs/deployment.md), never from guesswork
    assert.equal(ip('6.6.6.6, 203.0.113.9', 2), '6.6.6.6');
  });
});

describe('configuration', () => {
  const ok = { DATABASE_URL: 'postgres://u:p@localhost:5432/tt' };
  test('defaults: no proxy trust at all', () => {
    const c = loadAppConfig(ok);
    assert.equal(c.trustProxy, false); assert.equal(c.trustProxyHops, 0); assert.equal(c.webDistDir, null);
  });
  test('TRUST_PROXY_HOPS is validated (integer 0..5) and cannot be combined with the legacy flag', () => {
    assert.equal(loadAppConfig({ ...ok, TRUST_PROXY_HOPS: '2' }).trustProxyHops, 2);
    for (const bad of ['-1', '6', 'abc', '1.5']) assert.throws(() => loadAppConfig({ ...ok, TRUST_PROXY_HOPS: bad }), AppConfigError, bad);
    assert.throws(() => loadAppConfig({ ...ok, TRUST_PROXY: 'true', TRUST_PROXY_HOPS: '1' }), /not both/);
  });
  test('port: API_PORT wins, then the platform-injected PORT, then 8787; invalid values are rejected', () => {
    assert.equal(loadAppConfig(ok).port, 8787);
    assert.equal(loadAppConfig({ ...ok, PORT: '10000' }).port, 10000);
    assert.equal(loadAppConfig({ ...ok, PORT: '10000', API_PORT: '9000' }).port, 9000);
    assert.equal(loadAppConfig({ ...ok, PORT: '10000', API_PORT: '' }).port, 10000);
    for (const bad of ['0', '70000', 'abc', '80.5']) assert.throws(() => loadAppConfig({ ...ok, PORT: bad }), AppConfigError, bad);
    assert.equal(loadAppConfig(ok).host, '127.0.0.1', 'the bind address is still loopback unless API_HOST says otherwise');
  });
  test('WEB_DIST_DIR is read from the environment', () => {
    assert.equal(loadAppConfig({ ...ok, WEB_DIST_DIR: ' web/dist ' }).webDistDir, 'web/dist');
  });
});

describe('login throttling per client, end to end (real server; the "proxy" is simulated by the test client)', () => {
  const login = (base, who, password, xff) => call(base, 'POST', '/api/auth/login', { body: { username: who, password }, headers: { origin: base, ...(xff ? { 'x-forwarded-for': xff } : {}) } });
  const fail = async (base, n, mk) => { const out = []; for (let i = 0; i < n; i++) out.push((await login(base, 'sam', 'wrong password', mk(i))).status); return out; };

  test('TRUST_PROXY_HOPS=1: rotating FORGED leading entries does not evade the limiter', async () => {
    const ctx = await bootApi({ env: { TRUST_PROXY_HOPS: '1' } });
    try {
      const statuses = await fail(ctx.base, 7, (i) => `10.9.9.${i}, 198.51.100.7`); // attacker rotates forged "client" values; proxy appends the real one
      assert.deepEqual(statuses, [401, 401, 401, 401, 401, 429, 429], 'locked after 5 failures despite rotating forged entries');
    } finally { await ctx.close(); }
  });
  test('TRUST_PROXY_HOPS=1: a different client is NOT locked out by the attacker (no shared-bucket denial of service)', async () => {
    const ctx = await bootApi({ env: { TRUST_PROXY_HOPS: '1' } });
    try {
      await fail(ctx.base, 6, () => 'whatever, 198.51.100.7');
      assert.equal((await login(ctx.base, 'sam', 'wrong password', 'x, 198.51.100.7')).status, 429);
      assert.equal((await login(ctx.base, 'sam', PW, 'x, 198.51.100.8')).status, 200, 'the judge, a different client, can still sign in');
    } finally { await ctx.close(); }
  });
  test('TRUST_PROXY_HOPS=1: the access log records the proxy-appended address, not the forged one', async () => {
    const ctx = await bootApi({ env: { TRUST_PROXY_HOPS: '1' } });
    try {
      await login(ctx.base, 'sam', PW, '6.6.6.6, 203.0.113.50');
      await new Promise((r) => setTimeout(r, 50));
      const row = ctx.users._access.find((a) => a.path === '/api/auth/login');
      assert.equal(row.ip, '203.0.113.50');
    } finally { await ctx.close(); }
  });
  test('hops=0 (default): the header is ignored, so all clients share the proxy address (documented trade-off, safe but coarse)', async () => {
    const ctx = await bootApi({ env: {} });
    try {
      await fail(ctx.base, 5, (i) => `1.1.1.${i}, 203.0.113.${i}`);
      assert.equal((await login(ctx.base, 'sam', PW, '2.2.2.2, 203.0.113.99')).status, 429, 'forging cannot help, and everyone behind the proxy shares the bucket');
    } finally { await ctx.close(); }
  });
  test('legacy TRUST_PROXY=true is bypassable by forging the first entry (characterisation: this is why it must not be used on Render)', async () => {
    const ctx = await bootApi({ env: { TRUST_PROXY: 'true' } });
    try {
      const statuses = await fail(ctx.base, 8, (i) => `10.9.9.${i}, 198.51.100.7`);
      assert.ok(statuses.every((s) => s === 401), 'an attacker who rotates the first entry is never throttled');
    } finally { await ctx.close(); }
  });
  test('hops larger than the chain: forged single-entry header cannot choose the address', async () => {
    const ctx = await bootApi({ env: { TRUST_PROXY_HOPS: '2' } });
    try {
      const statuses = await fail(ctx.base, 6, (i) => `10.0.0.${i}`); // one entry only: shorter than 2 hops -> socket address -> throttled
      assert.deepEqual(statuses, [401, 401, 401, 401, 401, 429]);
    } finally { await ctx.close(); }
  });
});
