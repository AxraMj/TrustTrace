import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { ApiError, UNAUTHENTICATED_EVENT, casePath, getJson } from '../src/lib/api.js';
import { maskId, pct, relTime } from '../src/lib/format.js';
import { stubFetch } from './fixtures.js';

afterEach(() => vi.unstubAllGlobals());

describe('api client', () => {
  test('builds query strings: skips empty values, joins arrays, encodes', async () => {
    const f = stubFetch({ '/api/x': { body: {} } });
    vi.stubGlobal('fetch', f);
    await getJson('/api/x', { params: { a: 'b c', list: ['x', 'y'], none: undefined, empty: '', nul: null, noarr: [], n: 0, f: false } });
    expect(f.calls[0].url).toBe('/api/x?a=b+c&list=x%2Cy&n=0&f=false');
  });
  test('parses the standard error shape into ApiError with request id', async () => {
    vi.stubGlobal('fetch', stubFetch({ '/api/x': { status: 400, body: { error: { code: 'invalid_parameter', message: 'bad limit', requestId: 'req-1' } } } }));
    await expect(getJson('/api/x')).rejects.toMatchObject({ name: 'ApiError', status: 400, code: 'invalid_parameter', message: 'bad limit', requestId: 'req-1' });
  });
  test('a 401 signals the app to return to sign-in', async () => {
    vi.stubGlobal('fetch', stubFetch({ '/api/x': { status: 401, body: { error: { code: 'session_expired', message: 'x' } } } }));
    const seen = vi.fn(); globalThis.addEventListener(UNAUTHENTICATED_EVENT, seen);
    await expect(getJson('/api/x')).rejects.toBeInstanceOf(ApiError);
    expect(seen).toHaveBeenCalledTimes(1);
    globalThis.removeEventListener(UNAUTHENTICATED_EVENT, seen);
  });
  test('network failure becomes a clear ApiError', async () => {
    vi.stubGlobal('fetch', () => Promise.reject(new TypeError('failed')));
    await expect(getJson('/api/x')).rejects.toMatchObject({ code: 'network_error', status: 0 });
  });
  test('non-JSON error body does not crash', async () => {
    vi.stubGlobal('fetch', () => Promise.resolve(new Response('<html>502</html>', { status: 502 })));
    await expect(getJson('/api/x')).rejects.toMatchObject({ status: 502, code: 'http_error' });
  });
  test('case ids with / # ? and spaces are encoded as single path segments', () => {
    expect(casePath('acct/odd one', 'case #1?x', '/timeline')).toBe('/api/cases/acct%2Fodd%20one/case%20%231%3Fx/timeline');
  });
});

describe('formatting', () => {
  test('relTime', () => {
    const now = Date.parse('2026-06-15T12:00:00Z');
    expect(relTime('2026-06-15T11:55:00Z', now)).toBe('5 min ago');
    expect(relTime('2026-06-13T12:00:00Z', now)).toBe('2 d ago');
    expect(relTime('2026-06-15T12:00:01Z', now)).toBe('just now');
    expect(relTime(null, now)).toBe('—');
  });
  test('maskId hides the middle and never throws on short/empty values', () => {
    expect(maskId('acct-A1-abc123')).toBe('acct-••••123');
    expect(maskId('abc')).toBe('ab••••');
    expect(maskId(null)).toBe('—');
  });
  test('pct avoids divide-by-zero', () => { expect(pct(1, 0)).toBe('—'); expect(pct(1, 4)).toBe('25%'); });
});

// ---- Static guarantees about the source (read-only v1, no HTML injection, no secrets) ----
const walk = (d) => readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? walk(p) : [p]; });
const SRC = walk('src').filter((p) => /\.(jsx?|css)$/.test(p));
const read = (p) => readFileSync(p, 'utf8');

describe('static source checks', () => {
  test('no HTML injection sinks anywhere in the app', () => {
    for (const p of SRC.filter((x) => /\.jsx?$/.test(x))) {
      const s = read(p);
      expect(s, p).not.toMatch(/dangerouslySetInnerHTML|\.innerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function\(/);
    }
  });
  test('the network is only touched in lib/api.js, and only GET plus session login/logout', () => {
    for (const p of SRC.filter((x) => /\.jsx?$/.test(x) && !x.endsWith('api.js'))) expect(read(p), p).not.toMatch(/\bfetch\(|XMLHttpRequest|sendBeacon|WebSocket|EventSource/);
    const api = read('src/lib/api.js');
    expect(api).not.toMatch(/method:\s*'(PUT|PATCH|DELETE)'/);
    const posts = [...api.matchAll(/method:\s*'POST'/g)].length;
    expect(posts).toBe(1); // sendSession only
    expect(api).toMatch(/sendSession\('\/api\/auth\/login'/);
    expect(api).toMatch(/sendSession\('\/api\/auth\/logout'/);
  });
  test('no keys, tokens or secrets are referenced by the browser code', () => {
    for (const p of SRC) expect(read(p), p).not.toMatch(/mko_tkn_|MEKO_API_KEY|-----BEGIN [A-Z ]*PRIVATE KEY-----|localStorage\.setItem\('(token|session)|document\.cookie/i);
  });
  test('the only storage use is display preferences', () => {
    const uses = SRC.filter((p) => /localStorage|sessionStorage/.test(read(p)));
    expect(uses.map((p) => p.replaceAll('\\', '/'))).toEqual(['src/lib/prefs.jsx']);
  });
  test('the verified colour class is applied in exactly one place', () => {
    const hits = SRC.filter((p) => p.endsWith('.jsx')).filter((p) => read(p).includes('trust--verified'));
    expect(hits.map((p) => p.replaceAll('\\', '/'))).toEqual(['src/components/badges.jsx']);
  });
});
