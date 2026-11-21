// Offline: authorisation, validation and wiring of the investigation endpoints against a STAND-IN data layer (a test double that
// records the arguments it receives). What the endpoints return from real data is tested in test/db/investigation.integration.test.js.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { bootApi, PW } from './helpers/apiHarness.js';
import { call, cookieOf, sleep } from './helpers/httpClient.js';
import { encodeCursor } from '../src/api/params.js';

const UUID = '11111111-1111-4111-8111-111111111111';
const NOW_ISO = '2026-06-15T12:00:00.000Z';

/** TEST DOUBLE: records calls and returns minimal, shape-correct results. */
function stubData() {
  const calls = [];
  const rec = (name, result) => async (args) => { calls.push({ name, args }); return typeof result === 'function' ? result(args) : result; };
  const emptyPage = { items: [], next: null };
  return {
    calls,
    summary: rec('summary', { totals: {}, series: { bucket: 'hour', points: [] } }),
    listAlerts: rec('listAlerts', (a) => (a.after ? emptyPage : { items: [{ id: UUID, createdAt: NOW_ISO }], next: { t: NOW_ISO, id: UUID } })),
    getDecision: rec('getDecision', (id) => (id === UUID ? { decision: { id: UUID } } : null)),
    decisionRecord: rec('decisionRecord', (id) => (id === UUID ? { id: UUID, retrieved: [], contributions: [], rejectedEvidence: [] } : null)),
    listCases: rec('listCases', emptyPage),
    getCase: rec('getCase', (a, c) => (a === 'acct-1' || a === 'acct/odd' ? { accountId: a, caseId: c } : null)),
    caseTimeline: rec('caseTimeline', { items: [], truncated: false }),
    caseDecisions: rec('caseDecisions', []),
    writersFor: rec('writersFor', []),
    listActivity: rec('listActivity', emptyPage),
    listAttestations: rec('listAttestations', emptyPage),
    caseAttestations: rec('caseAttestations', []),
    listRejections: rec('listRejections', { items: [], truncated: false }),
    verifierKeys: rec('verifierKeys', []),
    listAudit: rec('listAudit', { items: [], nextAfterSeq: null }),
    auditHead: rec('auditHead', { seq: 0, hash: null, at: null }),
  };
}
// getDecision/getCase are called positionally in the real store: adapt the stub to that signature
function adapt(d) {
  const wrap = (name) => { const f = d[name]; d[name] = async (...a) => { d.calls.push({ name, args: a.length === 1 ? a[0] : a }); return name === 'getDecision' ? (a[0] === UUID ? { decision: { id: UUID } } : null) : name === 'decisionRecord' ? (a[0] === UUID ? { id: UUID, retrieved: [], contributions: [], rejectedEvidence: [] } : null) : (a[0] === 'acct-1' || a[0] === 'acct/odd' ? { accountId: a[0], caseId: a[1] } : null); }; void f; };
  ['getDecision', 'decisionRecord', 'getCase'].forEach(wrap);
  d.caseTimeline = async (a, c, o) => { d.calls.push({ name: 'caseTimeline', args: [a, c, o] }); return { items: [], truncated: false }; };
  d.caseDecisions = async (a, c, o) => { d.calls.push({ name: 'caseDecisions', args: [a, c, o] }); return []; };
  d.caseAttestations = async (a, c) => { d.calls.push({ name: 'caseAttestations', args: [a, c] }); return []; };
  return d;
}

describe('investigation endpoints: authorisation, validation, wiring (stand-in data layer)', () => {
  let ctx, data, bob, sam, alice;
  before(async () => {
    data = adapt(stubData());
    ctx = await bootApi({ data });
    const login = async (u) => cookieOf(await call(ctx.base, 'POST', '/api/auth/login', { body: { username: u, password: PW } }));
    [bob, sam, alice] = [await login('bob'), await login('sam'), await login('alice')];
  });
  after(async () => { await ctx.close(); });
  const get = (path, cookie = bob) => call(ctx.base, 'GET', path, { headers: cookie ? { cookie } : {} });
  const last = (name) => [...data.calls].reverse().find((c) => c.name === name)?.args;

  const READ_ENDPOINTS = ['/api/meta', '/api/summary', '/api/alerts', `/api/decisions/${UUID}`, `/api/decisions/${UUID}/evidence`, '/api/cases', '/api/cases/acct-1/c1',
    '/api/cases/acct-1/c1/timeline', '/api/cases/acct-1/c1/decisions', '/api/cases/acct-1/c1/evidence', '/api/cases/acct-1/c1/verification', '/api/cases/acct-1/c1/activity',
    '/api/activity', '/api/verification/attestations', '/api/verification/rejections', '/api/verification/keys'];
  const SUPERVISION_ENDPOINTS = ['/api/audit', '/api/audit/head'];

  test('every investigation endpoint requires authentication (401) and answers 200 to an analyst', async () => {
    for (const p of [...READ_ENDPOINTS, ...SUPERVISION_ENDPOINTS]) {
      const r = await get(p, null);
      assert.equal(r.status, 401, `${p} without credentials`);
      assert.equal(r.json.error.code, 'unauthenticated');
    }
    for (const p of READ_ENDPOINTS) assert.equal((await get(p, bob)).status, 200, `${p} as analyst`);
  });
  test('audit history is for supervisors and admins only: analyst 403, supervisor 200, admin 200', async () => {
    for (const p of SUPERVISION_ENDPOINTS) {
      assert.equal((await get(p, bob)).status, 403, `${p} analyst`);
      assert.equal((await get(p, sam)).status, 200, `${p} supervisor`);
      assert.equal((await get(p, alice)).status, 200, `${p} admin`);
    }
  });
  test('the API is READ-ONLY: POST/PUT/PATCH/DELETE on any investigation path are refused', async () => {
    for (const p of [...READ_ENDPOINTS, ...SUPERVISION_ENDPOINTS]) {
      for (const m of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        const r = await call(ctx.base, m, p, { headers: { cookie: alice }, body: {} });
        assert.equal(r.status, 405, `${m} ${p}`);
        assert.equal(r.headers.allow, 'GET');
      }
    }
  });
  test('/api/meta is vocabulary only (enums, windows, versions) and says read-only', async () => {
    const r = await get('/api/meta');
    assert.equal(r.json.readOnly, true);
    assert.deepEqual(r.json.severities, ['low', 'medium', 'high', 'critical']);
    assert.ok(r.json.windows.includes('24h') && r.json.windows.includes('all'));
    assert.ok(r.json.versions.model);
  });

  describe('validation (400)', () => {
    const BAD = [
      '/api/summary?window=2h', '/api/summary?bucket=week', '/api/summary?severty=high', '/api/summary?window=1h&from=2026-06-01T00:00:00Z',
      '/api/alerts?severity=nuclear', '/api/alerts?action=maybe', '/api/alerts?flag=weird', '/api/alerts?limit=0', '/api/alerts?limit=abc', '/api/alerts?cursor=garbage',
      '/api/alerts?eventType=' + encodeURIComponent('DROP TABLE'), '/api/alerts?q=' + 'x'.repeat(101), '/api/alerts?from=2026-06-02T00:00:00Z&to=2026-06-01T00:00:00Z',
      '/api/alerts?severity=low&severity=high',
      '/api/cases?severity=bad', '/api/cases?cursor=AAAA',
      '/api/activity?ok=yes', '/api/activity?decisionId=not-a-uuid', '/api/activity?agentId=' + encodeURIComponent('a\nb'),
      '/api/verification/attestations?status=pending', '/api/verification/rejections?window=forever',
      '/api/audit?type=other', '/api/audit?afterSeq=-1', '/api/audit?limit=100000x',
      '/api/decisions/not-a-uuid', '/api/decisions/not-a-uuid/evidence', `/api/decisions/${UUID}?x=1`,
      '/api/cases/acct-1/c1/timeline?limit=0', '/api/cases/acct-1/c1/evidence?x=1',
    ];
    for (const p of BAD) {
      test(`400 for ${p.length > 90 ? p.slice(0, 90) + '…' : p}`, async () => {
        const r = await get(p, sam);
        assert.equal(r.status, 400, r.text);
        assert.equal(r.json.error.code, 'invalid_parameter');
        assert.ok(r.json.error.requestId);
      });
    }
    test('a rejected request never reaches the data layer', async () => {
      const before = data.calls.length;
      await get('/api/alerts?severity=nuclear');
      await get('/api/alerts?cursor=garbage');
      assert.equal(data.calls.length, before);
    });
  });

  describe('404', () => {
    test('unknown decision, unknown case (and every case sub-resource) -> 404 with a stable code', async () => {
      assert.equal((await get('/api/decisions/22222222-2222-4222-8222-222222222222')).json.error.code, 'decision_not_found');
      assert.equal((await get('/api/decisions/22222222-2222-4222-8222-222222222222/evidence')).json.error.code, 'decision_not_found');
      for (const sub of ['', '/timeline', '/decisions', '/evidence', '/verification', '/activity']) {
        const r = await get(`/api/cases/nope/c1${sub}`);
        assert.equal(r.status, 404, sub);
        assert.equal(r.json.error.code, 'case_not_found');
      }
    });
  });

  describe('wiring: parsed parameters reach the data layer exactly', () => {
    test('alerts: lists, search escaping, window and limit are passed through (not raw strings)', async () => {
      await get('/api/alerts?severity=high,critical&action=block&flag=degraded,rejected_evidence&eventType=mfa_change&q=50%25_x&limit=7&window=24h');
      const a = last('listAlerts');
      assert.deepEqual(a.severities, ['high', 'critical']);
      assert.deepEqual(a.actions, ['block']);
      assert.deepEqual(a.flags, ['degraded', 'rejected_evidence']);
      assert.deepEqual(a.eventTypes, ['mfa_change']);
      assert.equal(a.q, '%50\\%\\_x%');
      assert.equal(a.limit, 7);
      assert.ok(a.from instanceof Date && a.to instanceof Date && a.to - a.from === 24 * 3600e3);
      assert.equal(a.to.toISOString(), NOW_ISO, 'the window is anchored on the injected clock');
    });
    test('cursor round trip: nextCursor from page 1 decodes into the `after` of page 2, and page 2 ends the list', async () => {
      const p1 = await get('/api/alerts?limit=1');
      assert.ok(p1.json.nextCursor);
      const p2 = await get(`/api/alerts?limit=1&cursor=${encodeURIComponent(p1.json.nextCursor)}`);
      assert.deepEqual(last('listAlerts').after, { t: NOW_ISO, id: UUID });
      assert.equal(p2.json.nextCursor, null);
      assert.equal(encodeCursor({ t: NOW_ISO, id: UUID }), p1.json.nextCursor);
    });
    test('limit is clamped (alerts 200, timeline 500, audit 500) and defaults apply', async () => {
      await get('/api/alerts?limit=9999'); assert.equal(last('listAlerts').limit, 200);
      await get('/api/audit?limit=9999', sam); assert.equal(last('listAudit').limit, 500);
      await get('/api/audit', sam); assert.equal(last('listAudit').limit, 100); assert.equal(last('listAudit').afterSeq, 0);
      await get('/api/cases/acct-1/c1/timeline?limit=9999'); assert.equal(last('caseTimeline')[2].limit, 500);
      await get('/api/cases/acct-1/c1/timeline'); assert.equal(last('caseTimeline')[2].limit, 200);
    });
    test('summary: bucket defaults to hour for short windows and day for long ones; explicit bucket wins', async () => {
      await get('/api/summary?window=24h'); assert.equal(last('summary').bucket, 'hour');
      await get('/api/summary?window=7d'); assert.equal(last('summary').bucket, 'day');
      await get('/api/summary?window=all'); assert.equal(last('summary').bucket, 'day');
      await get('/api/summary?window=7d&bucket=hour'); assert.equal(last('summary').bucket, 'hour');
      const r = await get('/api/summary');
      assert.equal(r.json.meta.window, '24h');
      assert.equal(r.json.meta.source, 'postgresql');
    });
    test('percent-encoded path parameters are decoded exactly once (ids with "/" and spaces)', async () => {
      const r = await get('/api/cases/acct%2Fodd/case%20%231%3Fx');
      assert.equal(r.status, 200);
      assert.deepEqual(last('getCase'), ['acct/odd', 'case #1?x']);
      assert.equal((await get('/api/cases/acct%252Fodd/c1')).status, 404, 'double-encoded input is NOT decoded twice');
    });
    test('audit: type, refId and afterSeq are passed through', async () => {
      await get(`/api/audit?type=decision&refId=${UUID}&afterSeq=41&limit=5`, alice);
      assert.deepEqual(last('listAudit'), { type: 'decision', refId: UUID, afterSeq: 41, limit: 5 });
    });
    test('activity: ok=false is a real boolean false (not "false" the string, not dropped)', async () => {
      await get('/api/activity?ok=false&agentId=trusttrace_helpdesk_agent&kind=memory_written');
      const a = last('listActivity');
      assert.equal(a.ok, false); assert.equal(a.agentId, 'trusttrace_helpdesk_agent'); assert.equal(a.kind, 'memory_written');
      await get('/api/activity'); assert.equal(last('listActivity').ok, undefined);
    });
  });

  test('responses are plain JSON with the standard headers and never contain secrets', async () => {
    for (const p of READ_ENDPOINTS) {
      const r = await get(p);
      assert.match(r.headers['content-type'], /^application\/json/);
      assert.equal(r.headers['cache-control'], 'no-store');
      assert.doesNotMatch(r.text, /mko_tkn_|PRIVATE KEY|scrypt\$|token_hash|password_hash|postgres:\/\//i);
    }
  });
  test('reads are access-logged with the user and path (who looked at what)', async () => {
    ctx.users._access.length = 0;
    await get(`/api/decisions/${UUID}`, bob);
    await get('/api/cases/acct-1/c1', sam);
    await sleep(40);
    const rows = ctx.users._access;
    assert.deepEqual(rows.map((r) => [r.username, r.path, r.status]), [['bob', `/api/decisions/${UUID}`, 200], ['sam', '/api/cases/acct-1/c1', 200]]);
  });
});
