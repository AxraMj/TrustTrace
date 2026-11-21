// PostgreSQL integration: the investigation API over REAL persisted data (decisions produced by the real agents, the real authority,
// forged records, replays, expired evidence and a degraded decision). Every aggregate is RE-COMPUTED from the raw rows in this file
// with different code, so the tests cannot merely echo the implementation. Meko is not involved (agents use an in-memory memory store).
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { DB_SKIP, DB_CONFIG, createTestDb, makeWorld, CFO_CALL } from './helpers.js';
import { call, cookieOf, sleep } from '../helpers/httpClient.js';
import { createApiServer, listen } from '../../src/api/server.js';
import { loadAppConfig } from '../../src/api/config.js';
import { hashPassword } from '../../src/api/auth.js';
import { buildDeps } from '../../src/app/deps.js';
import { createUser } from '../../src/db/userRepo.js';
import { insertDecision, getDecision } from '../../src/db/decisionRepo.js';
import { DecisionService } from '../../src/app/decisionService.js';
import { IdentitySecurityAgent } from '../../src/agents/identityAgent.js';
import { brokenStore } from '../helpers/fakeStore.js';
import { MekoConnectionError } from '../../src/errors.js';
import { plantForgery, ATTACKER_AGENT_ID } from '../../src/adversary.js';
import { AUDIT_RESOLVERS } from '../../src/db/auditResolvers.js';
import { verifyChain } from '../../src/db/auditChain.js';

const PW = 'investigation test passphrase 7';
const HELPDESK = 'trusttrace_helpdesk_agent';
const AUTHORITY = 'trusttrace_verification_authority';
const mfa = (accountId, caseId, extra = {}) => ({ type: 'mfa_change', accountId, caseId, newDevice: true, ...extra });

async function startApi(db) {
  const config = loadAppConfig({ DATABASE_URL: DB_CONFIG.databaseUrl });
  const server = createApiServer({ deps: buildDeps({ pool: db.pool, config }), config, logger: () => {} });
  const base = `http://127.0.0.1:${(await listen(server, { host: '127.0.0.1', port: 0 })).port}`;
  const hash = await hashPassword(PW);
  for (const [u, role] of [['alice', 'admin'], ['sam', 'supervisor'], ['bob', 'analyst']]) await createUser(db.pool, { username: u, passwordHash: hash, role });
  const login = async (u) => cookieOf(await call(base, 'POST', '/api/auth/login', { body: { username: u, password: PW } }));
  const cookies = { alice: await login('alice'), sam: await login('sam'), bob: await login('bob') };
  const get = (path, who = 'bob') => call(base, 'GET', path, { headers: who ? { cookie: cookies[who] } : {} });
  const ok = async (path, who) => { const r = await get(path, who); assert.equal(r.status, 200, `${path} -> ${r.status} ${r.text.slice(0, 300)}`); return r.json; };
  return { server, base, get, ok, cookies, close: async () => { server.closeAllConnections?.(); await new Promise((r) => server.close(r)); } };
}

/** Seed a realistic spread of decisions with the REAL agents. Returns the ids needed by the tests. */
async function seed(pool) {
  const w = makeWorld(pool, { instrument: true });
  const S = { w, accounts: {}, cases: {}, decisions: {}, nonces: {}, memories: {} };
  const acct = (k) => (S.accounts[k] = `acct-${k}-${randomUUID().slice(0, 6)}`);
  const kase = (k) => (S.cases[k] = `case-${k}-${randomUUID().slice(0, 6)}`);
  const decide = async (k, event) => { const r = await w.svc.assessAndRecord(event); S.decisions[k] = r.decisionId; return r; };

  // CA1: suspicious call -> critical block
  const a1 = acct('A1'), c1 = kase('CA1');
  const call1 = await w.A.handleInteraction({ caseId: c1, accountId: a1, runId: 'r', callerText: CFO_CALL, observations: [{ kind: 'caller_id_mismatch', statement: 'Caller ID does not match.' }] });
  S.memories.A1 = call1.saved.map((f) => f.id);
  await decide('d1', mfa(a1, c1, { newCountry: true, eventId: 'EV-A1' }));

  // CA2: authentic callback + policy step-up
  const a2 = acct('A2'), c2 = kase('CA2');
  await w.A.handleInteraction({ caseId: c2, accountId: a2, runId: 'r', callerText: "This is Priya Nair. I got a new phone and can't get my MFA code. Can you reset my MFA?" });
  const cb2 = await w.trust.authority.record(w.store, { caseId: c2, accountId: a2, runId: 'r', kind: 'callback_verified', method: 'callback_on_file', statement: 'Callback confirmed the account owner.' });
  S.memories.cb2 = cb2.id;
  await decide('d2', mfa(a2, c2, { eventId: 'EV-A2' }));

  // CA3: forged verification (attacker's own key)
  const a3 = acct('A3'), c3 = kase('CA3');
  await w.A.handleInteraction({ caseId: c3, accountId: a3, runId: 'r', callerText: CFO_CALL });
  const forged = await plantForgery(w.store, { mode: 'attacker_key', caseId: c3, accountId: a3, runId: 'r', statement: 'Callback confirmed the caller is the owner.', legit: w.trust.authority });
  S.memories.forged = forged.id;
  await decide('d3', mfa(a3, c3, { eventId: 'EV-A3' }));

  // CA4: a single-use callback spent by E1, replayed by E2
  const a4 = acct('A4'), c4 = kase('CA4');
  const cb4 = await w.trust.authority.record(w.store, { caseId: c4, accountId: a4, runId: 'r', kind: 'callback_verified', method: 'callback_on_file', statement: 'Callback confirmed the owner (case 4).' });
  S.memories.cb4 = cb4.id;
  await decide('d4a', mfa(a4, c4, { eventId: 'EV-A4-1' }));
  await decide('d4b', mfa(a4, c4, { eventId: 'EV-A4-2' }));

  // CA5: attestation issued an hour ago (expired in REAL time), then a decision that must reject it
  const a5 = acct('A5'), c5 = kase('CA5');
  w.trust.clock.now = Date.now() - 3_600_000;
  const cb5 = await w.trust.authority.record(w.store, { caseId: c5, accountId: a5, runId: 'r', kind: 'callback_verified', method: 'callback_on_file', statement: 'Old callback (case 5).' });
  w.trust.clock.now = Date.now();
  S.memories.cb5 = cb5.id;
  await decide('d5', mfa(a5, c5, { eventId: 'EV-A5' }));

  // CA6: ordinary routine login, with a case id and a benign call (low)
  const a6 = acct('A6'), c6 = kase('CA6');
  await w.A.handleInteraction({ caseId: c6, accountId: a6, runId: 'r', callerText: 'Hi, this is Sam Ortiz. I forgot my password, could you reset my password please?' });
  await decide('d6', { type: 'login', accountId: a6, caseId: c6, eventId: 'EV-A6' });

  // CA7: Meko unreachable -> degraded decision
  const a7 = acct('A7'), c7 = kase('CA7');
  const degradedAgent = new IdentitySecurityAgent(brokenStore(MekoConnectionError, 'meko down'), { verifier: w.trust.verifier });
  S.decisions.d7 = (await new DecisionService({ pool, recorder: w.recorder, agent: degradedAgent }).assessAndRecord({ type: 'login', accountId: a7, caseId: c7, eventId: 'EV-A7' })).decisionId;

  // no case at all
  await decide('d8', { type: 'login', accountId: acct('A8'), eventId: 'EV-A8' });

  // 12 plain logins for pagination (some with a case)
  S.pg = [];
  for (let i = 0; i < 12; i++) S.pg.push((await w.svc.assessAndRecord({ type: 'login', accountId: `acct-pg-${i}`, caseId: i % 3 === 0 ? `case-pg-${i % 4}` : undefined, newCountry: i % 5 === 0 })).decisionId);

  // one failed activity event
  w.recorder.record({ agentId: HELPDESK, kind: 'memory_write_failed', accountId: a1, caseId: c1, ok: false, error: 'MekoToolError: boom' });
  await w.recorder.flush();
  return S;
}

const tally = (arr, f) => arr.reduce((m, x) => { const k = f(x); m[k] = (m[k] ?? 0) + 1; return m; }, {});
const tallyEntries = (arr) => Object.fromEntries(arr.map((e) => [e.reason ?? e.rule ?? e.eventType, e.count]));

describe('Investigation API on real data', { skip: DB_SKIP }, () => {
  let db, api, S, rows, events, nonces;
  before(async () => {
    db = await createTestDb();
    S = await seed(db.pool);
    api = await startApi(db);
    rows = (await db.pool.query('SELECT * FROM decisions ORDER BY created_at, id')).rows;
    events = (await db.pool.query('SELECT * FROM agent_events ORDER BY id')).rows;
    nonces = (await db.pool.query('SELECT * FROM attestation_nonces ORDER BY issued_at')).rows;
  }, { timeout: 180_000 });
  after(async () => { await api?.close(); await S?.w.recorder.close(); await db?.cleanup(); });
  const idOf = (k) => S.decisions[k];
  const acctOf = (k) => S.accounts[k];
  const caseOf = (k) => S.cases[k];
  const casePath = (a, c, sub = '') => `/api/cases/${encodeURIComponent(S.accounts[a])}/${encodeURIComponent(S.cases[c])}${sub}`;

  // ------------------------------------------------------------------------------------------------ summary
  describe('GET /api/summary reconciles exactly with the decision log', () => {
    test('totals, severity, action, flags, event types, reasons and policy rules match a recomputation from the raw rows', async () => {
      const s = await api.ok('/api/summary?window=24h');
      assert.equal(s.totals.decisions, rows.length);
      assert.ok(rows.length >= 20, 'seed produced a realistic number of decisions');
      const sev = { low: 0, medium: 0, high: 0, critical: 0, ...tally(rows, (r) => r.severity) };
      const act = { allow: 0, step_up: 0, block: 0, ...tally(rows, (r) => r.recommended_action) };
      assert.deepEqual(s.bySeverity, sev);
      assert.deepEqual(s.byAction, act);
      assert.equal(s.totals.blocked, act.block); assert.equal(s.totals.stepUp, act.step_up); assert.equal(s.totals.allowed, act.allow);
      assert.deepEqual(s.flags, {
        degraded: rows.filter((r) => r.degraded).length,
        incompleteContext: rows.filter((r) => !r.retrieval_complete).length,
        rejectedEvidence: rows.filter((r) => r.rejected_evidence.length > 0).length,
        policyRaised: rows.filter((r) => r.policy.length > 0).length,
      });
      assert.deepEqual(tallyEntries(s.byEventType.map((e) => ({ eventType: e.eventType, count: e.count }))), tally(rows, (r) => r.event_type));
      assert.deepEqual(tallyEntries(s.rejectedReasons), tally(rows.flatMap((r) => r.rejected_evidence), (x) => x.reason));
      assert.deepEqual(tallyEntries(s.policyRules), tally(rows.flatMap((r) => r.policy), (x) => x.rule));
      assert.equal(s.totals.accounts, new Set(rows.map((r) => r.account_id)).size);
      assert.equal(s.totals.cases, new Set(rows.filter((r) => r.case_id).map((r) => r.case_id)).size);
      assert.equal(s.totals.lastDecisionAt, rows.at(-1).created_at.toISOString());
    });
    test('the severity x action cross-tab sums to the total and matches the rows', async () => {
      const s = await api.ok('/api/summary?window=24h');
      assert.equal(s.bySeverityAndAction.reduce((a, x) => a + x.count, 0), rows.length);
      const oracle = tally(rows, (r) => `${r.severity}|${r.recommended_action}`);
      for (const x of s.bySeverityAndAction) assert.equal(x.count, oracle[`${x.severity}|${x.action}`], `${x.severity}/${x.action}`);
    });
    test('the time series covers every decision exactly once, per severity', async () => {
      const s = await api.ok('/api/summary?window=24h&bucket=hour');
      assert.equal(s.series.bucket, 'hour');
      assert.equal(s.series.points.reduce((a, p) => a + p.total, 0), rows.length);
      for (const p of s.series.points) assert.equal(p.total, p.low + p.medium + p.high + p.critical);
      for (const sv of ['low', 'medium', 'high', 'critical']) assert.equal(s.series.points.reduce((a, p) => a + p[sv], 0), rows.filter((r) => r.severity === sv).length);
      assert.deepEqual((await api.ok('/api/summary?window=24h&bucket=day')).series.bucket, 'day');
    });
    test('top risk drivers: counts and points match the stored contributions; sorted by count', async () => {
      const s = await api.ok('/api/summary?window=24h');
      const oracle = {};
      for (const c of rows.flatMap((r) => r.contributions)) {
        if (c.source === 'event' || c.effectivePoints === 0) continue;
        const k = `${c.source}|${c.label}|${c.kind}`;
        oracle[k] ??= { n: 0, pts: 0 }; oracle[k].n++; oracle[k].pts += c.effectivePoints;
      }
      assert.ok(s.topDrivers.length > 0 && s.topDrivers.length <= 10);
      for (const d of s.topDrivers) { const o = oracle[`${d.source}|${d.label}|${d.kind}`]; assert.equal(d.count, o.n); assert.ok(Math.abs(d.totalPoints - o.pts) < 0.11); }
      assert.deepEqual(s.topDrivers.map((d) => d.count), [...s.topDrivers.map((d) => d.count)].sort((a, b) => b - a));
      assert.equal(s.topDrivers[0].count, Math.max(...Object.values(oracle).map((o) => o.n)), 'the most frequent driver is first');
    });
    test('latency block equals the stored timings (averages recomputed from the rows)', async () => {
      const s = await api.ok('/api/summary?window=24h');
      const avg = (f) => rows.reduce((a, r) => a + f(r), 0) / rows.length;
      assert.ok(Math.abs(s.latencyMs.retrieval.avg - avg((r) => r.timings.retrievalMs)) < 0.2);
      assert.ok(s.latencyMs.retrieval.p95 >= s.latencyMs.retrieval.p50);
    });
    test('agents and attestations blocks match agent_events and attestation_nonces', async () => {
      const s = await api.ok('/api/summary?window=24h');
      const byAgent = tally(events, (e) => e.agent_id);
      assert.deepEqual(Object.fromEntries(s.agents.map((a) => [a.agentId, a.events])), byAgent);
      assert.equal(s.agents.find((a) => a.agentId === HELPDESK).failures, events.filter((e) => e.agent_id === HELPDESK && !e.ok).length);
      const status = (n) => (n.consumed_event_id ? 'spent' : n.expires_at < new Date() ? 'expired' : 'valid');
      assert.deepEqual(tally(s.attestations.flatMap((a) => Array(a.count).fill(`${a.kind}|${a.status}`)), (x) => x), tally(nonces, (n) => `${n.kind}|${status(n)}`));
      assert.ok(s.attestations.find((a) => a.kind === 'callback_verified').singleUse);
    });
    test('a window with no data is all zeros / empty (nothing is invented)', async () => {
      const s = await api.ok('/api/summary?from=2000-01-01T00:00:00Z&to=2000-01-02T00:00:00Z');
      assert.equal(s.totals.decisions, 0);
      assert.deepEqual(s.bySeverity, { low: 0, medium: 0, high: 0, critical: 0 });
      assert.deepEqual(s.series.points, []);
      assert.deepEqual(s.topDrivers, []);
      assert.equal(s.latencyMs.retrieval.avg, null);
      assert.equal(s.totals.lastDecisionAt, null);
    });
    test('window=all includes everything; a recent window is a subset; meta echoes the range', async () => {
      const all = await api.ok('/api/summary?window=all');
      assert.equal(all.totals.decisions, rows.length);
      assert.equal(all.meta.from, null);
      const r = await api.ok('/api/summary?window=15m');
      assert.equal(r.meta.window, '15m');
      assert.ok(r.totals.decisions <= all.totals.decisions);
    });
  });

  // ------------------------------------------------------------------------------------------------ alerts
  describe('GET /api/alerts', () => {
    const page = async (qs, who) => { const out = []; let cursor = null; let pages = 0; do { const j = await api.ok(`/api/alerts?${qs}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, who); out.push(...j.items); cursor = j.nextCursor; pages++; } while (cursor && pages < 50); return { items: out, pages }; };

    test('paging through the whole list yields every decision exactly once, newest first', async () => {
      const { items, pages } = await page('limit=5&window=24h');
      assert.ok(pages >= 4);
      const oracle = [...rows].sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? 1 : -1)).map((r) => r.id);
      assert.deepEqual(items.map((i) => i.id), oracle);
      assert.equal(new Set(items.map((i) => i.id)).size, rows.length);
      for (let i = 1; i < items.length; i++) assert.ok(items[i - 1].createdAt >= items[i].createdAt);
    });
    test('the last page has nextCursor null; an exact-fit page does not invent another', async () => {
      assert.equal((await api.ok(`/api/alerts?limit=200&window=24h`)).nextCursor, null);
      assert.equal((await api.ok(`/api/alerts?limit=${rows.length}&window=24h`)).nextCursor, null);
      assert.ok((await api.ok(`/api/alerts?limit=${rows.length - 1}&window=24h`)).nextCursor);
    });
    test('severity / action / event type filters return exactly the matching rows', async () => {
      const ids = async (qs) => (await page(`${qs}&limit=50&window=24h`)).items.map((i) => i.id).sort();
      const want = (f) => rows.filter(f).map((r) => r.id).sort();
      assert.deepEqual(await ids('severity=critical'), want((r) => r.severity === 'critical'));
      assert.deepEqual(await ids('severity=high,critical'), want((r) => ['high', 'critical'].includes(r.severity)));
      assert.deepEqual(await ids('action=block'), want((r) => r.recommended_action === 'block'));
      assert.deepEqual(await ids('action=step_up,allow'), want((r) => r.recommended_action !== 'block'));
      assert.deepEqual(await ids('eventType=mfa_change'), want((r) => r.event_type === 'mfa_change'));
      assert.deepEqual(await ids('severity=critical&action=block&eventType=mfa_change'), want((r) => r.severity === 'critical' && r.recommended_action === 'block' && r.event_type === 'mfa_change'));
    });
    test('flag filters: rejected_evidence, degraded, incomplete_context, policy_raised (any-of)', async () => {
      const ids = async (qs) => (await page(`${qs}&limit=50&window=24h`)).items.map((i) => i.id).sort();
      const want = (f) => rows.filter(f).map((r) => r.id).sort();
      assert.deepEqual(await ids('flag=rejected_evidence'), want((r) => r.rejected_evidence.length > 0));
      assert.deepEqual(await ids('flag=degraded'), [idOf('d7')]);
      assert.deepEqual(await ids('flag=policy_raised'), want((r) => r.policy.length > 0));
      assert.deepEqual(await ids('flag=incomplete_context'), want((r) => !r.retrieval_complete));
      assert.deepEqual(await ids('flag=degraded,rejected_evidence'), want((r) => r.degraded || r.rejected_evidence.length > 0));
      assert.ok((await ids('flag=rejected_evidence')).includes(idOf('d3')), 'the forged-verification decision is flagged');
      assert.ok((await ids('flag=rejected_evidence')).includes(idOf('d4b')), 'the replay is flagged');
      assert.ok(!(await ids('flag=rejected_evidence')).includes(idOf('d2')), 'authentic evidence is NOT flagged');
    });
    test('search: matches account, case and event ids; "%" and "_" are literal, injection strings are inert', async () => {
      const ids = async (q) => (await page(`q=${encodeURIComponent(q)}&limit=50&window=24h`)).items.map((i) => i.id).sort();
      assert.deepEqual(await ids(S.accounts.A3), [idOf('d3')]);
      assert.deepEqual(await ids(S.cases.CA4), [idOf('d4a'), idOf('d4b')].sort());
      assert.deepEqual(await ids('EV-A5'), [idOf('d5')]);
      assert.equal((await ids('acct-pg')).length, 12);
      assert.deepEqual(await ids('acct_pg'), [], '"_" must not act as a wildcard');
      assert.deepEqual(await ids('%'), [], '"%" must not act as a wildcard');
      assert.deepEqual(await ids("'; DROP TABLE decisions; --"), []);
      assert.equal((await db.pool.query('SELECT count(*) FROM decisions')).rows[0].count, rows.length);
    });
    test('each item carries what a triage queue needs, and agrees with the stored row', async () => {
      const { items } = await page('limit=50&window=24h');
      const byId = Object.fromEntries(rows.map((r) => [r.id, r]));
      for (const it of items) {
        const r = byId[it.id];
        assert.equal(it.severity, r.severity); assert.equal(it.recommendedAction, r.recommended_action); assert.equal(it.baseAction, r.base_action);
        assert.equal(it.rawScore, r.raw_score); assert.equal(it.accountId, r.account_id); assert.equal(it.caseId, r.case_id); assert.equal(it.eventType, r.event_type);
        assert.equal(it.rejectedCount, r.rejected_evidence.length);
        assert.deepEqual(it.flags, [...(r.rejected_evidence.length ? ['rejected_evidence'] : []), ...(r.degraded ? ['degraded'] : []), ...(!r.retrieval_complete ? ['incomplete_context'] : []), ...(r.policy.length ? ['policy_raised'] : [])]);
        assert.ok(it.topReasons.length <= 2);
        const nonZero = r.contributions.filter((c) => c.effectivePoints !== 0).map((c) => Math.abs(c.effectivePoints)).sort((a, b) => b - a);
        assert.deepEqual(it.topReasons.map((t) => Math.abs(t.effect)).sort((a, b) => b - a), nonZero.slice(0, 2));
      }
      const d1 = items.find((i) => i.id === idOf('d1'));
      assert.equal(d1.severity, 'critical'); assert.equal(d1.recommendedAction, 'block');
      const d2 = items.find((i) => i.id === idOf('d2'));
      assert.equal(d2.baseAction, 'allow'); assert.equal(d2.recommendedAction, 'step_up'); assert.ok(d2.flags.includes('policy_raised'), 'the UI can show "score says ALLOW, policy requires STEP-UP"');
      assert.ok(items.find((i) => i.id === idOf('d7')).flags.includes('degraded'));
    });
    test('time range filter works and an empty result is an empty list, not an error', async () => {
      const j = await api.ok('/api/alerts?from=2000-01-01T00:00:00Z&to=2000-01-02T00:00:00Z');
      assert.deepEqual(j.items, []); assert.equal(j.nextCursor, null);
    });
    test('a forged-but-well-formed cursor cannot expose anything outside the filter', async () => {
      const cursor = Buffer.from(JSON.stringify({ t: '2000-01-01T00:00:00.000Z', id: randomUUID() })).toString('base64url');
      assert.deepEqual((await api.ok(`/api/alerts?cursor=${cursor}&window=all`)).items, [], 'everything is newer than that cursor');
    });
  });

  // ------------------------------------------------------------------------------------------------ decision detail
  describe('GET /api/decisions/:id (explanation + audit)', () => {
    test('returns the stored decision with every explanation field, and it equals the database row', async () => {
      const j = await api.ok(`/api/decisions/${idOf('d1')}`);
      const row = rows.find((r) => r.id === idOf('d1'));
      assert.equal(j.decision.id, row.id);
      assert.equal(j.decision.rawScore, row.raw_score); assert.equal(j.decision.severity, 'critical');
      assert.deepEqual(j.decision.contributions, row.contributions);
      assert.deepEqual(j.decision.explanation, row.explanation);
      assert.deepEqual(j.decision.retrieved, row.retrieved);
      assert.deepEqual(j.decision.policy, row.policy);
      assert.deepEqual(j.decision.stepUp, row.step_up);
      assert.equal(j.decision.modelVersion, row.model_version);
      assert.ok(j.decision.explanation.some((l) => /^\[TOTAL\]/.test(l)));
      const sum = j.decision.contributions.reduce((a, c) => a + c.effectivePoints, 0);
      assert.ok(Math.abs(sum - j.decision.rawScore) < 0.11, 'contributions add up to the raw score');
    });
    test('integrity: the audit record is found and the stored decision still hashes to it', async () => {
      const j = await api.ok(`/api/decisions/${idOf('d2')}`);
      assert.equal(j.integrity.auditRecordFound, true);
      assert.equal(j.integrity.payloadHashMatches, true);
      const rec = (await db.pool.query("SELECT * FROM audit_records WHERE record_type = 'decision' AND ref_id = $1", [idOf('d2')])).rows[0];
      assert.equal(j.audit.seq, rec.seq); assert.equal(j.audit.recordHash, rec.record_hash); assert.equal(j.audit.prevHash, rec.prev_hash); assert.equal(j.audit.payloadHash, j.integrity.recomputedPayloadHash);
    });
    test('verification story: the spent attestation is linked to its decision; the replay shows a rejection', async () => {
      const d2 = await api.ok(`/api/decisions/${idOf('d2')}`);
      assert.equal(d2.attestationsSpent.length, 1);
      assert.equal(d2.attestationsSpent[0].kind, 'callback_verified');
      assert.equal(d2.attestationsSpent[0].consumedEventId, 'EV-A2');
      assert.deepEqual(d2.decision.rejectedEvidence, []);
      const d4b = await api.ok(`/api/decisions/${idOf('d4b')}`);
      assert.deepEqual(d4b.decision.rejectedEvidence.map((r) => r.reason), ['replayed']);
      assert.deepEqual(d4b.attestationsSpent, []);
      const d3 = await api.ok(`/api/decisions/${idOf('d3')}`);
      assert.deepEqual(d3.decision.rejectedEvidence.map((r) => r.reason), ['unknown_issuer_or_key']);
      const d5 = await api.ok(`/api/decisions/${idOf('d5')}`);
      assert.deepEqual(d5.decision.rejectedEvidence.map((r) => r.reason), ['expired']);
    });
    test('agent activity of the decision and the previous/next decision in the case are included', async () => {
      const a = await api.ok(`/api/decisions/${idOf('d4a')}`);
      assert.ok(a.activity.some((e) => e.kind === 'decision_made'));
      assert.equal(a.neighbours.next.id, idOf('d4b'));
      assert.equal(a.neighbours.previous, undefined);
      const b = await api.ok(`/api/decisions/${idOf('d4b')}`);
      assert.equal(b.neighbours.previous.id, idOf('d4a'));
      assert.deepEqual((await api.ok(`/api/decisions/${idOf('d8')}`)).neighbours, {}, 'a decision without a case has no neighbours');
    });
    test('degraded decision is explained honestly', async () => {
      const j = await api.ok(`/api/decisions/${idOf('d7')}`);
      assert.equal(j.decision.degraded, true);
      assert.equal(j.decision.error.name, 'MekoConnectionError');
      assert.notEqual(j.decision.recommendedAction, 'allow');
      assert.deepEqual(j.decision.retrieved, []);
    });
    test('unknown id -> 404; non-UUID -> 400', async () => {
      assert.equal((await api.get(`/api/decisions/${randomUUID()}`)).status, 404);
      assert.equal((await api.get('/api/decisions/1;DROP TABLE decisions')).status, 400);
    });
  });

  // ------------------------------------------------------------------------------------------------ evidence
  describe('Meko memory evidence (decision-log snapshot) and trust labels', () => {
    test('decision evidence lists every retrieved memory with its label, trust class, writer and effect', async () => {
      const j = await api.ok(`/api/decisions/${idOf('d1')}/evidence`);
      const row = rows.find((r) => r.id === idOf('d1'));
      assert.equal(j.source, 'decision_log_snapshot');
      assert.match(j.note, /not a live view of Meko/);
      assert.deepEqual(j.memories.map((m) => m.memoryId).sort(), row.retrieved.map((m) => m.id).sort());
      assert.deepEqual(j.memories.map((m) => m.memoryId).sort(), [...S.memories.A1].sort(), 'exactly the memories Agent A wrote');
      for (const m of j.memories) {
        assert.equal(m.writer.agentId, HELPDESK);
        assert.ok(['unverified_claim', 'observed'].includes(m.trust));
        assert.ok(m.statement);
      }
      assert.ok(j.memories.filter((m) => m.label === 'CLAIMED').length >= 3);
      assert.ok(j.memories.filter((m) => m.label === 'CLAIMED').every((m) => m.trust === 'unverified_claim' && m.netEffectPoints >= 0), 'a CLAIMED statement is never a fact and never lowers risk');
    });
    test('authentic VERIFIED evidence vs a FORGED record claiming VERIFIED', async () => {
      const good = (await api.ok(`/api/decisions/${idOf('d2')}/evidence`)).memories.find((m) => m.memoryId === S.memories.cb2);
      assert.equal(good.trust, 'verified_authentic'); assert.equal(good.label, 'VERIFIED'); assert.equal(good.writer.agentId, AUTHORITY); assert.ok(good.netEffectPoints < 0);
      const j = await api.ok(`/api/decisions/${idOf('d3')}/evidence`);
      const bad = j.memories.find((m) => m.memoryId === S.memories.forged);
      assert.equal(bad.trust, 'rejected'); assert.equal(bad.writer.agentId, ATTACKER_AGENT_ID); assert.ok(bad.netEffectPoints > 0);
      assert.deepEqual(bad.rejectedIn.map((r) => r.reason), ['unknown_issuer_or_key']);
      assert.equal(j.rejected[0].reason, 'unknown_issuer_or_key');
      assert.ok(!j.memories.some((m) => m.trust === 'verified_authentic'), 'nothing in the forged case is trusted');
    });
    test('case evidence aggregates all its decisions: the replayed attestation shows both uses', async () => {
      const j = await api.ok(casePath('A4', 'CA4', '/evidence'));
      assert.equal(j.decisionCount, 2);
      const m = j.memories.find((x) => x.memoryId === S.memories.cb4);
      assert.equal(m.usage.filter((u) => u.source === 'verified').length, 1, 'accepted once');
      assert.deepEqual(m.rejectedIn.map((r) => r.reason), ['replayed']);
      assert.equal(j.totals.rejectedRecords, 1);
    });
    test('the writer column comes from the recorded activity (not guessed): unknown writers are null, not invented', async () => {
      const j = await api.ok(`/api/decisions/${idOf('d4a')}/evidence`);
      assert.equal(j.memories.find((m) => m.memoryId === S.memories.cb4).writer.agentId, AUTHORITY);
    });
  });

  // ------------------------------------------------------------------------------------------------ cases
  describe('cases', () => {
    test('the case list matches the case index; ordered by last activity; filters and paging work', async () => {
      const oracle = (await db.pool.query('SELECT * FROM cases ORDER BY last_seen DESC, account_id DESC, case_id DESC')).rows;
      const all = [];
      let cursor = null;
      do { const j = await api.ok(`/api/cases?limit=3&window=24h${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`); all.push(...j.items); cursor = j.nextCursor; } while (cursor);
      assert.deepEqual(all.map((c) => `${c.accountId}|${c.caseId}`), oracle.map((c) => `${c.account_id}|${c.case_id}`));
      for (const c of all) { const o = oracle.find((x) => x.account_id === c.accountId && x.case_id === c.caseId); assert.equal(c.decisionCount, o.decision_count); assert.equal(c.maxSeverity, o.max_severity); }
      const crit = (await api.ok('/api/cases?severity=critical&window=24h')).items;
      assert.deepEqual(crit.map((c) => c.caseId).sort(), oracle.filter((c) => c.max_severity === 'critical').map((c) => c.case_id).sort());
      assert.deepEqual((await api.ok(`/api/cases?q=${encodeURIComponent(S.cases.CA3)}&window=24h`)).items.map((c) => c.caseId), [S.cases.CA3]);
      assert.ok(all.find((c) => c.caseId === S.cases.CA4).latestDecision.id === idOf('d4b'), 'latest decision of the case');
    });
    test('case header: counts reconcile with the underlying tables', async () => {
      for (const k of ['CA1', 'CA2', 'CA3', 'CA4', 'CA5', 'CA7']) {
        const a = S.accounts[k.replace('CA', 'A')], c = S.cases[k];
        const j = await api.ok(`/api/cases/${encodeURIComponent(a)}/${encodeURIComponent(c)}`);
        const n = (t, extra = '') => db.pool.query(`SELECT count(*) FROM ${t} WHERE account_id = $1 AND case_id = $2 ${extra}`, [a, c]).then((r) => r.rows[0].count);
        assert.equal(j.counts.decisions, await n('decisions'));
        assert.equal(j.counts.agentEvents, await n('agent_events'));
        assert.equal(j.counts.attestations, await n('attestation_nonces'));
        assert.equal(j.counts.decisionsWithRejectedEvidence, await n('decisions', 'AND jsonb_array_length(rejected_evidence) > 0'));
        assert.equal(j.latestDecision.severity, (await db.pool.query('SELECT severity FROM decisions WHERE account_id = $1 AND case_id = $2 ORDER BY created_at DESC, id DESC LIMIT 1', [a, c])).rows[0].severity);
      }
    });
    test('the case timeline is chronological and tells the whole story (call facts, issuance, spend, decision)', async () => {
      const j = await api.ok(casePath('A2', 'CA2', '/timeline'));
      for (let i = 1; i < j.items.length; i++) assert.ok(j.items[i - 1].at <= j.items[i].at, 'out of order');
      const types = j.items.map((i) => i.type);
      assert.ok(types.includes('agent_event') && types.includes('attestation_issued') && types.includes('attestation_consumed') && types.includes('decision'));
      assert.ok(types.indexOf('attestation_issued') < types.indexOf('attestation_consumed'));
      assert.equal(j.items.filter((i) => i.type === 'decision').length, 1);
      assert.ok(!j.items.some((i) => i.kind === 'decision_made'), 'decision_made events are not duplicated next to the decision');
      assert.equal(j.items.find((i) => i.type === 'attestation_consumed').decisionId, idOf('d2'));
      assert.equal(j.truncated, false);
    });
    test('case decisions list and per-case activity are scoped to that case only', async () => {
      const d = await api.ok(casePath('A4', 'CA4', '/decisions'));
      assert.deepEqual(d.items.map((i) => i.id).sort(), [idOf('d4a'), idOf('d4b')].sort());
      const act = await api.ok(casePath('A1', 'CA1', '/activity'));
      assert.ok(act.items.length > 0 && act.items.every((e) => e.caseId === S.cases.CA1 && e.accountId === S.accounts.A1));
      assert.ok(act.items.some((e) => e.ok === false), 'the failed event is visible');
    });
    test('case verification: attestation state (valid/spent/expired) and the rejections in that case', async () => {
      const a4 = await api.ok(casePath('A4', 'CA4', '/verification'));
      assert.equal(a4.attestations.length, 1);
      assert.equal(a4.attestations[0].status, 'spent'); assert.equal(a4.attestations[0].singleUse, true); assert.equal(a4.attestations[0].consumedEventId, 'EV-A4-1');
      assert.deepEqual(a4.rejections.map((r) => r.reason), ['replayed']);
      const a5 = await api.ok(casePath('A5', 'CA5', '/verification'));
      assert.equal(a5.attestations[0].status, 'expired');
      assert.deepEqual(a5.rejections.map((r) => r.reason), ['expired']);
      const a3 = await api.ok(casePath('A3', 'CA3', '/verification'));
      assert.deepEqual(a3.attestations, [], 'a forged record has no issuance: the authority never issued it');
      assert.deepEqual(a3.rejections.map((r) => r.reason), ['unknown_issuer_or_key']);
      assert.equal((await api.ok(casePath('A2', 'CA2', '/verification'))).rejections.length, 0);
    });
    test('unknown case -> 404; ids with "/", spaces, "#" and "?" work when percent-encoded; injection in a path id is inert', async () => {
      assert.equal((await api.get('/api/cases/nope/nope')).status, 404);
      const weirdA = 'acct/odd one', weirdC = 'case #1?x';
      await S.w.svc.assessAndRecord({ type: 'login', accountId: weirdA, caseId: weirdC });
      const j = await api.ok(`/api/cases/${encodeURIComponent(weirdA)}/${encodeURIComponent(weirdC)}`);
      assert.equal(j.accountId, weirdA); assert.equal(j.caseId, weirdC);
      assert.equal((await api.get(`/api/cases/${encodeURIComponent("x' OR '1'='1")}/y`)).status, 404);
    });
  });

  // ------------------------------------------------------------------------------------------------ activity
  describe('GET /api/activity', () => {
    const all = async (qs) => { const out = []; let cursor = null; do { const j = await api.ok(`/api/activity?${qs}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`); out.push(...j.items); cursor = j.nextCursor; } while (cursor); return out; };
    test('paging returns every event exactly once, newest first, equal to the table', async () => {
      const got = await all('limit=7&window=24h');
      assert.equal(got.length, events.length);
      assert.equal(new Set(got.map((e) => e.id)).size, events.length);
      assert.deepEqual(got.map((e) => e.id), [...events].sort((a, b) => b.at - a.at || b.id - a.id).map((e) => e.id));
    });
    test('filters: agent, kind, ok, account, case, decision', async () => {
      const ids = async (qs) => (await all(`${qs}&limit=50&window=24h`)).map((e) => e.id).sort((a, b) => a - b);
      const want = (f) => events.filter(f).map((e) => e.id).sort((a, b) => a - b);
      assert.deepEqual(await ids(`agentId=${HELPDESK}`), want((e) => e.agent_id === HELPDESK));
      assert.deepEqual(await ids(`agentId=${AUTHORITY}`), want((e) => e.agent_id === AUTHORITY));
      assert.deepEqual(await ids('kind=memories_retrieved'), want((e) => e.kind === 'memories_retrieved'));
      assert.deepEqual(await ids('ok=false'), want((e) => !e.ok));
      assert.ok((await ids('ok=false')).length >= 1);
      assert.deepEqual(await ids(`accountId=${S.accounts.A3}`), want((e) => e.account_id === S.accounts.A3));
      assert.deepEqual(await ids(`decisionId=${idOf('d1')}`), want((e) => e.decision_id === idOf('d1')));
      assert.deepEqual(await ids(`agentId=${HELPDESK}&kind=memory_written&caseId=${S.cases.CA1}`), want((e) => e.agent_id === HELPDESK && e.kind === 'memory_written' && e.case_id === S.cases.CA1));
    });
    test('memory ids and timings are exposed; Agent A writes carry the label/kind and Agent B reads carry retrieval metadata', async () => {
      const w = (await all(`agentId=${HELPDESK}&kind=memory_written&limit=50`)).find((e) => e.caseId === S.cases.CA1);
      assert.equal(w.memoryIds.length, 1); assert.ok(S.memories.A1.includes(w.memoryIds[0])); assert.ok(['CLAIMED', 'OBSERVED'].includes(w.payload.label)); assert.ok(w.durationMs >= 0);
      const r = (await all('kind=memories_retrieved&limit=50')).find((e) => e.accountId === S.accounts.A1);
      assert.equal(r.payload.count, S.memories.A1.length); assert.ok(r.payload.meta.complete); assert.ok(r.payload.labels.CLAIMED > 0);
    });
    test('injection in filter values is inert; empty results are empty lists', async () => {
      assert.deepEqual((await api.ok(`/api/activity?agentId=${encodeURIComponent("x' OR 1=1 --")}`)).items, []);
      assert.deepEqual((await api.ok('/api/activity?kind=does_not_exist')).items, []);
      assert.equal((await db.pool.query('SELECT count(*) FROM agent_events')).rows[0].count, events.length);
    });
  });

  // ------------------------------------------------------------------------------------------------ verification
  describe('verification status', () => {
    test('attestations: status, kind and pagination match the ledger; statuses are computed from real expiry and consumption', async () => {
      const j = await api.ok('/api/verification/attestations?limit=50&window=24h');
      assert.equal(j.items.length, nonces.length);
      const status = (n) => (n.consumed_event_id ? 'spent' : n.expires_at < new Date() ? 'expired' : 'valid');
      for (const it of j.items) assert.equal(it.status, status(nonces.find((n) => n.nonce === it.nonce)), it.nonce);
      assert.deepEqual((await api.ok('/api/verification/attestations?status=spent&window=24h')).items.map((i) => i.nonce).sort(), nonces.filter((n) => status(n) === 'spent').map((n) => n.nonce).sort());
      assert.deepEqual((await api.ok('/api/verification/attestations?status=expired&window=24h')).items.map((i) => i.nonce), [nonces.find((n) => status(n) === 'expired').nonce]);
      assert.deepEqual((await api.ok('/api/verification/attestations?status=valid&window=24h')).items.map((i) => i.nonce).sort(), nonces.filter((n) => status(n) === 'valid').map((n) => n.nonce).sort());
      assert.equal((await api.ok('/api/verification/attestations?kind=confirmed_attack_pattern&window=24h')).items.length, 0);
      const p1 = await api.ok('/api/verification/attestations?limit=2&window=24h');
      assert.ok(p1.nextCursor);
      const p2 = await api.ok(`/api/verification/attestations?limit=50&window=24h&cursor=${encodeURIComponent(p1.nextCursor)}`);
      assert.deepEqual([...p1.items, ...p2.items].map((i) => i.nonce), j.items.map((i) => i.nonce));
    });
    test('the secret material of an attestation is never exposed (only metadata)', async () => {
      const j = await api.get('/api/verification/attestations?limit=50&window=24h');
      assert.doesNotMatch(j.text, /ATTEST:|signature|"sig"|PRIVATE/i);
    });
    test('rejections: every rejected record across decisions, filterable by reason, with the decision link', async () => {
      const oracle = rows.flatMap((r) => r.rejected_evidence.map((x) => ({ id: r.id, reason: x.reason })));
      const j = await api.ok('/api/verification/rejections?window=24h');
      assert.deepEqual(tally(j.items, (i) => i.reason), tally(oracle, (o) => o.reason));
      assert.deepEqual(new Set(j.items.map((i) => i.reason)), new Set(['unknown_issuer_or_key', 'replayed', 'expired']));
      assert.deepEqual((await api.ok('/api/verification/rejections?reason=replayed&window=24h')).items.map((i) => i.decisionId), [idOf('d4b')]);
      assert.equal(j.truncated, false);
      assert.ok(j.items.every((i) => rows.some((r) => r.id === i.decisionId)));
    });
    test('verifier key ids come from the decisions', async () => {
      const j = await api.ok('/api/verification/keys');
      const current = (await db.pool.query('SELECT verifier_key_id FROM decisions')).rows; // re-read: earlier tests may have added decisions
      const kids = [...new Set(current.map((r) => r.verifier_key_id).filter(Boolean))];
      assert.deepEqual(j.items.map((i) => i.keyId).sort(), kids.sort());
      assert.equal(j.items[0].decisions, current.filter((r) => r.verifier_key_id === j.items[0].keyId).length);
    });
  });

  // ------------------------------------------------------------------------------------------------ audit
  describe('audit history', () => {
    test('supervisors and admins can list the chain (ascending, resumable); analysts cannot', async () => {
      assert.equal((await api.get('/api/audit', 'bob')).status, 403);
      assert.equal((await api.get('/api/audit/head', 'bob')).status, 403);
      const recs = (await db.pool.query('SELECT * FROM audit_records ORDER BY seq')).rows;
      const got = [];
      let after = 0;
      for (;;) { const j = await api.ok(`/api/audit?afterSeq=${after}&limit=10`, 'sam'); got.push(...j.items); if (j.nextAfterSeq === null) break; after = j.nextAfterSeq; }
      assert.deepEqual(got.map((r) => r.seq), recs.map((r) => r.seq));
      assert.deepEqual(got.map((r) => r.recordHash), recs.map((r) => r.record_hash));
      for (let i = 1; i < got.length; i++) assert.equal(got[i].prevHash, got[i - 1].recordHash, 'the listed chain links');
    });
    test('filters by record type and by referenced id; the decision audit record matches the decision detail', async () => {
      const types = tally((await api.ok('/api/audit?limit=500', 'alice')).items, (r) => r.recordType);
      const recs = (await db.pool.query('SELECT record_type, count(*) AS n FROM audit_records GROUP BY 1')).rows;
      assert.deepEqual(types, Object.fromEntries(recs.map((r) => [r.record_type, r.n])));
      const d = (await api.ok(`/api/audit?type=decision&refId=${idOf('d3')}`, 'alice')).items;
      assert.equal(d.length, 1);
      assert.equal(d[0].recordHash, (await api.ok(`/api/decisions/${idOf('d3')}`)).audit.recordHash);
      assert.ok((await api.ok(`/api/audit?type=attestation_consumed&limit=50`, 'sam')).items.length >= 2);
    });
    test('the head equals the last record and the admin health view, and the chain verifies', async () => {
      const head = await api.ok('/api/audit/head', 'sam');
      const last = (await db.pool.query('SELECT seq, record_hash FROM audit_records ORDER BY seq DESC LIMIT 1')).rows[0];
      assert.deepEqual([head.seq, head.hash], [last.seq, last.record_hash]);
      assert.equal((await api.ok('/api/health/details', 'alice')).audit.headSeq, head.seq);
      const v = await api.ok('/api/audit/verify', 'alice');
      assert.equal(v.ok, true); assert.equal(v.checked, head.seq);
    });
  });

  // ------------------------------------------------------------------------------------------------ cross-cutting
  describe('cross-cutting', () => {
    test('every investigation endpoint rejects anonymous callers (real session store)', async () => {
      for (const p of ['/api/summary', '/api/alerts', `/api/decisions/${idOf('d1')}`, '/api/cases', '/api/activity', '/api/verification/attestations', '/api/verification/rejections', '/api/verification/keys', '/api/audit', '/api/audit/head', '/api/meta']) {
        assert.equal((await api.get(p, null)).status, 401, p);
      }
    });
    test('no endpoint response contains credentials, hashes of secrets or key material', async () => {
      for (const p of ['/api/summary?window=all', '/api/alerts?limit=200&window=all', `/api/decisions/${idOf('d3')}`, `/api/decisions/${idOf('d3')}/evidence`, '/api/verification/attestations?limit=50&window=all', '/api/activity?limit=200&window=all', '/api/audit?limit=500']) {
        const r = await api.get(p, 'alice');
        assert.doesNotMatch(r.text, /mko_tkn_|PRIVATE KEY|scrypt\$|password_hash|token_hash|postgres:\/\/|ATTEST:/i, p);
      }
    });
    test('reads are access-logged against the user (who looked at which case)', async () => {
      await api.ok(casePath('A1', 'CA1'), 'bob');
      await sleep(100);
      const row = (await db.pool.query("SELECT * FROM access_log WHERE username = 'bob' AND path = $1 ORDER BY id DESC LIMIT 1", [`/api/cases/${S.accounts.A1}/${S.cases.CA1}`])).rows[0];
      assert.ok(row && row.status === 200 && row.request_id);
    });
    test('the API is read-only: a sweep over EVERY endpoint changes no row in any data table', async () => {
      const tables = ['decisions', 'cases', 'agent_events', 'attestation_nonces', 'audit_records'];
      const snapshot = async () => Object.fromEntries(await Promise.all(tables.map(async (t) => [t, (await db.pool.query(`SELECT count(*) AS n, md5(string_agg(x::text, '' ORDER BY x::text)) AS h FROM ${t} x`)).rows[0]])));
      const before = await snapshot();
      const d = idOf('d3');
      const paths = ['/api/meta', '/api/summary?window=all', '/api/alerts?window=all&limit=200', `/api/decisions/${d}`, `/api/decisions/${d}/evidence`, '/api/cases?window=all', casePath('A1', 'CA1'),
        casePath('A1', 'CA1', '/timeline'), casePath('A1', 'CA1', '/decisions'), casePath('A1', 'CA1', '/evidence'), casePath('A1', 'CA1', '/verification'), casePath('A1', 'CA1', '/activity'),
        '/api/activity?window=all', '/api/verification/attestations?window=all', '/api/verification/rejections?window=all', '/api/verification/keys', '/api/audit', '/api/audit/head'];
      for (const p of paths) await api.ok(p, 'alice');
      assert.deepEqual(await snapshot(), before);
    });
  });
});

describe('Investigation API: empty database and tamper visibility', { skip: DB_SKIP }, () => {
  test('a fresh database returns zeros and empty lists everywhere (no demo data, no errors)', async () => {
    const db = await createTestDb();
    const api = await startApi(db);
    try {
      const s = await api.ok('/api/summary?window=all');
      assert.equal(s.totals.decisions, 0); assert.deepEqual(s.byAction, { allow: 0, step_up: 0, block: 0 }); assert.deepEqual(s.agents, []); assert.deepEqual(s.attestations, []);
      for (const p of ['/api/alerts', '/api/cases', '/api/activity', '/api/verification/attestations', '/api/verification/rejections?window=all', '/api/verification/keys']) {
        const j = await api.ok(p);
        assert.deepEqual(j.items, [], p);
      }
      assert.deepEqual(await api.ok('/api/audit/head', 'sam').then((h) => [h.seq, h.hash]), [0, null]);
      assert.deepEqual((await api.ok('/api/audit', 'sam')).items, []);
      assert.equal((await api.get(`/api/decisions/${randomUUID()}`)).status, 404);
    } finally { await api.close(); await db.cleanup(); }
  });

  test('a decision edited behind the application\'s back is flagged by the decision detail (integrity.payloadHashMatches=false) AND by /audit/verify', async () => {
    const db = await createTestDb();
    const w = makeWorld(db.pool);
    const api = await startApi(db);
    try {
      await w.A.handleInteraction({ caseId: 'case-t', accountId: 'acct-t', runId: 'r', callerText: CFO_CALL });
      const { decisionId } = await w.svc.assessAndRecord(mfa('acct-t', 'case-t'));
      assert.equal((await api.ok(`/api/decisions/${decisionId}`)).integrity.payloadHashMatches, true);
      await db.pool.query('ALTER TABLE decisions DISABLE TRIGGER decisions_append_only');
      await db.pool.query("UPDATE decisions SET recommended_action = 'allow', severity = 'low' WHERE id = $1", [decisionId]);
      await db.pool.query('ALTER TABLE decisions ENABLE TRIGGER decisions_append_only');
      const j = await api.ok(`/api/decisions/${decisionId}`);
      assert.equal(j.integrity.auditRecordFound, true);
      assert.equal(j.integrity.payloadHashMatches, false, 'the stored decision no longer matches its audit hash');
      assert.equal(j.decision.recommendedAction, 'allow', 'the API shows what is stored; the integrity flag says it cannot be trusted');
      const v = await api.ok('/api/audit/verify', 'alice');
      assert.equal(v.ok, false); assert.equal(v.problems[0].code, 'audited_row_modified');
      assert.equal((await verifyChain(db.pool, { resolvers: AUDIT_RESOLVERS })).ok, false);
    } finally { await w.recorder.close(); await api.close(); await db.cleanup(); }
  });
});

describe('Investigation API: scale sanity (synthetic bulk rows, own schema)', { skip: DB_SKIP }, () => {
  test('600 decisions: list, summary, case list and filtered search all answer quickly and page correctly', async () => {
    const db = await createTestDb();
    const w = makeWorld(db.pool);
    const api = await startApi(db);
    try {
      const { decisionId } = await w.svc.assessAndRecord(mfa('acct-bulk-0', 'case-bulk-0'));
      const tpl = await getDecision(db.pool, decisionId);
      for (let i = 1; i <= 600; i++) {
        await insertDecision(db.pool, { ...tpl, id: randomUUID(), createdAt: new Date(Date.now() - i * 60_000), accountId: `acct-bulk-${i % 40}`, caseId: `case-bulk-${i % 90}`, eventId: `bulk-${i}`, severity: ['low', 'medium', 'high', 'critical'][i % 4] });
      }
      const timed = async (p) => { const t0 = performance.now(); const j = await api.ok(p); return { j, ms: performance.now() - t0 }; };
      const a = await timed('/api/alerts?limit=50&window=all'); assert.equal(a.j.items.length, 50); assert.ok(a.ms < 1500, `alerts ${a.ms}`);
      const s = await timed('/api/summary?window=all'); assert.equal(s.j.totals.decisions, 601); assert.ok(s.ms < 2500, `summary ${s.ms}`);
      const f = await timed('/api/alerts?severity=critical&q=acct-bulk-7&limit=200&window=all'); assert.ok(f.ms < 1500, `filtered ${f.ms}`);
      assert.ok(f.j.items.every((i) => i.severity === 'critical' && /acct-bulk-7/.test(i.accountId)));
      let n = 0; let cursor = null; let pages = 0;
      do { const j = await api.ok(`/api/alerts?limit=200&window=all${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`); n += j.items.length; cursor = j.nextCursor; pages++; } while (cursor);
      assert.equal(n, 601); assert.equal(pages, 4);
      console.log(`    601 decisions: alerts(50) ${a.ms.toFixed(0)} ms, summary ${s.ms.toFixed(0)} ms, filtered ${f.ms.toFixed(0)} ms`);
    } finally { await w.recorder.close(); await api.close(); await db.cleanup(); }
  });
});
