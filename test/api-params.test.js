// Offline tests: query-parameter parsing/validation, cursors, and the memory-evidence builder (driven by REAL agent output).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  ACTIONS, SEVERITIES, allowParams, cursorShapes, decodeCursor, encodeCursor, isUuid, parseBool, parseEnum, parseEnumList, parseId, parseInteger, parseLimit,
  parseRange, parseSearch, validateId,
} from '../src/api/params.js';
import { ApiError } from '../src/api/http.js';
import { buildEvidence, trustOf } from '../src/api/evidence.js';
import { buildDecisionRecord } from '../src/db/decisionRepo.js';
import { FakeStore } from './helpers/fakeStore.js';
import { makeTrust } from './helpers/trust.js';
import { HelpDeskAgent } from '../src/agents/helpdeskAgent.js';
import { IdentitySecurityAgent } from '../src/agents/identityAgent.js';
import { plantForgery } from '../src/adversary.js';

const U = (qs) => new URL(`http://x/api/t${qs ? `?${qs}` : ''}`);
const code = (fn) => { try { fn(); return null; } catch (e) { return e instanceof ApiError ? `${e.status}:${e.code}` : `other:${e.message}`; } };
const NOW = Date.UTC(2026, 5, 15, 12, 0, 0);

describe('query parameter parsing', () => {
  test('unknown and duplicated parameters are rejected (a typo must not silently return unfiltered data)', () => {
    assert.equal(code(() => allowParams(U('severty=high'), ['severity'])), '400:invalid_parameter');
    assert.equal(code(() => allowParams(U('severity=a&severity=b'), ['severity'])), '400:invalid_parameter');
    assert.equal(code(() => allowParams(U('severity=high'), ['severity'])), null);
  });
  test('limit: default, clamp to max, and strict validation', () => {
    assert.equal(parseLimit(U('')), 50);
    assert.equal(parseLimit(U('limit=10')), 10);
    assert.equal(parseLimit(U('limit=9999')), 200);
    assert.equal(parseLimit(U('limit=9999'), { max: 500 }), 500);
    for (const bad of ['0', '-1', 'abc', '1.5', '1e3', '12345', ' 5']) assert.equal(code(() => parseLimit(U(`limit=${encodeURIComponent(bad)}`))), '400:invalid_parameter', bad);
  });
  test('enum lists: validated, de-duplicated, capped', () => {
    assert.deepEqual(parseEnumList(U('severity=high,critical,high'), 'severity', SEVERITIES), ['high', 'critical']);
    assert.equal(parseEnumList(U(''), 'severity', SEVERITIES), undefined);
    assert.equal(code(() => parseEnumList(U('severity=high,nuclear'), 'severity', SEVERITIES)), '400:invalid_parameter');
    assert.equal(code(() => parseEnumList(U('severity=,'), 'severity', SEVERITIES)), '400:invalid_parameter');
    assert.equal(code(() => parseEnumList(U(`action=${Array(11).fill('allow').map((a, i) => a + i).join(',')}`), 'action', ACTIONS)), '400:invalid_parameter');
    assert.equal(parseEnum(U('bucket=day'), 'bucket', ['hour', 'day'], 'hour'), 'day');
    assert.equal(parseEnum(U(''), 'bucket', ['hour', 'day'], 'hour'), 'hour');
    assert.equal(code(() => parseEnum(U('bucket=week'), 'bucket', ['hour', 'day'], 'hour')), '400:invalid_parameter');
  });
  test('ranges: windows, explicit from/to, defaults, and every invalid combination', () => {
    const r = parseRange(U('window=1h'), { now: NOW });
    assert.equal(r.to.getTime(), NOW); assert.equal(r.from.getTime(), NOW - 3600e3);
    assert.equal(parseRange(U(''), { now: NOW, defaultWindow: '7d' }).from.getTime(), NOW - 7 * 86400e3);
    assert.equal(parseRange(U('window=all'), { now: NOW }).from, null);
    const e = parseRange(U('from=2026-06-01T00:00:00Z&to=2026-06-02T00:00:00Z'), { now: NOW });
    assert.equal(e.to.toISOString(), '2026-06-02T00:00:00.000Z');
    assert.equal(parseRange(U('to=2026-06-02T00:00:00Z'), { now: NOW }).from, null);
    for (const bad of ['window=2h', 'window=1h&from=2026-06-01T00:00:00Z', 'from=yesterday', 'from=2026-06-02T00:00:00Z&to=2026-06-01T00:00:00Z', 'from=2026-06-01T00:00:00Z&to=2026-06-01T00:00:00Z', 'from=2024-01-01T00:00:00Z&to=2026-06-01T00:00:00Z', 'to=99999-99-99']) {
      assert.equal(code(() => parseRange(U(bad), { now: NOW })), '400:invalid_parameter', bad);
    }
  });
  test('search: LIKE metacharacters are escaped; control characters and long input rejected', () => {
    assert.equal(parseSearch(U('q=abc')), '%abc%');
    assert.equal(parseSearch(U(`q=${encodeURIComponent('50%_off\\x')}`)), '%50\\%\\_off\\\\x%');
    assert.equal(parseSearch(U('')), undefined);
    assert.equal(code(() => parseSearch(U('q=' + 'a'.repeat(101)))), '400:invalid_parameter');
    assert.equal(code(() => parseSearch(U('q=a%00b'))), '400:invalid_parameter');
  });
  test('identifiers, integers and booleans', () => {
    assert.equal(parseId(U('agentId=trusttrace_helpdesk_agent'), 'agentId'), 'trusttrace_helpdesk_agent');
    assert.equal(parseId(U(''), 'agentId'), undefined);
    assert.equal(code(() => parseId(U('agentId=a%0Ab'), 'agentId')), '400:invalid_parameter');
    assert.equal(code(() => parseId(U('agentId=' + 'x'.repeat(201)), 'agentId')), '400:invalid_parameter');
    assert.equal(code(() => validateId('', 'x')), '400:invalid_parameter');
    assert.equal(parseInteger(U('afterSeq=42'), 'afterSeq', { def: 0 }), 42);
    assert.equal(parseInteger(U(''), 'afterSeq', { def: 0 }), 0);
    for (const bad of ['-1', 'x', '1.2', '9999999999999999999']) assert.equal(code(() => parseInteger(U(`afterSeq=${bad}`), 'afterSeq', { def: 0 })), '400:invalid_parameter', bad);
    assert.equal(parseBool(U('ok=true'), 'ok'), true);
    assert.equal(parseBool(U('ok=false'), 'ok'), false);
    assert.equal(parseBool(U(''), 'ok'), undefined);
    assert.equal(code(() => parseBool(U('ok=1'), 'ok')), '400:invalid_parameter');
    assert.ok(isUuid('11111111-1111-4111-8111-111111111111'));
    assert.ok(!isUuid("11111111-1111-4111-8111-11111111111'; DROP"));
  });
});

describe('cursors', () => {
  const dec = { t: '2026-06-15T12:00:00.000Z', id: '11111111-1111-4111-8111-111111111111' };
  test('round trip for every shape', () => {
    assert.deepEqual(decodeCursor(encodeCursor(dec), cursorShapes.decision), dec);
    assert.deepEqual(decodeCursor(encodeCursor({ t: dec.t, id: 7 }), cursorShapes.activity), { t: dec.t, id: 7 });
    assert.deepEqual(decodeCursor(encodeCursor({ t: dec.t, a: 'acct', c: 'case' }), cursorShapes.case), { t: dec.t, a: 'acct', c: 'case' });
    assert.deepEqual(decodeCursor(encodeCursor({ t: dec.t, n: 'nonce' }), cursorShapes.attestation), { t: dec.t, n: 'nonce' });
    assert.equal(decodeCursor('', cursorShapes.decision), undefined);
    assert.equal(decodeCursor(null, cursorShapes.decision), undefined);
  });
  test('forged / malformed / wrong-shape / oversized cursors are a 400, never reach SQL', () => {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    for (const bad of ['!!!', 'AAAA', b64({ t: 'now', id: dec.id }), b64({ t: dec.t, id: "x'; DROP TABLE decisions;--" }), b64({ t: dec.t }), b64([1, 2]), b64(null), b64('str'), 'x'.repeat(401)]) {
      assert.equal(code(() => decodeCursor(bad, cursorShapes.decision)), '400:invalid_parameter', bad.slice(0, 30));
    }
    assert.equal(code(() => decodeCursor(encodeCursor(dec), cursorShapes.activity)), '400:invalid_parameter', 'a decision cursor is not an activity cursor');
    assert.equal(code(() => decodeCursor(encodeCursor({ t: dec.t, id: -3 }), cursorShapes.activity)), '400:invalid_parameter');
  });
});

// ---- evidence builder, fed by REAL agent output ------------------------------------------------------------------
describe('memory evidence builder', () => {
  async function scenario() {
    const store = new FakeStore();
    const trust = makeTrust();
    const A = new HelpDeskAgent(store);
    const B = new IdentitySecurityAgent(store, { verifier: trust.verifier });
    const decisions = [];
    const writerRows = [];
    const record = async (event, accountId) => {
      const res = await B.assess(event);
      const d = buildDecisionRecord(res, { decisionId: crypto.randomUUID(), event: { ...event, eventId: res.eventId }, agentId: B.agentId });
      decisions.push(d);
      return { d, res };
    };
    const writer = (ids, agentId) => writerRows.push({ agentId, at: new Date(), memoryIds: ids });
    return { store, trust, A, B, decisions, writerRows, record, writer };
  }
  const CALL = "Hello, I'm the CFO. I lost my phone, please reset my MFA, it's urgent.";

  test('CLAIMED is never presented as verified; OBSERVED stays observed; writers are attached', async () => {
    const s = await scenario();
    const saved = await s.A.handleInteraction({ caseId: 'c', accountId: 'acct-1', runId: 'r', callerText: CALL, observations: [{ kind: 'caller_id_mismatch', statement: 'Caller ID mismatch.' }] });
    s.writer(saved.saved.map((f) => f.id), s.A.agentId);
    await s.record({ type: 'mfa_change', accountId: 'acct-1', newDevice: true });
    const ev = buildEvidence(s.decisions, s.writerRows);
    assert.equal(ev.memories.length, saved.saved.length);
    for (const m of ev.memories) {
      assert.ok(['unverified_claim', 'observed'].includes(m.trust), `${m.kind}: ${m.trust}`);
      assert.equal(m.writer.agentId, s.A.agentId);
      assert.ok(m.statement);
    }
    assert.ok(ev.memories.filter((m) => m.label === 'CLAIMED').every((m) => m.trust === 'unverified_claim'));
    assert.equal(ev.memories.find((m) => m.kind === 'caller_id_mismatch').trust, 'observed');
    assert.equal(ev.totals.rejectedRecords, 0);
    assert.match(ev.note, /Meko is not queried/);
    assert.equal(ev.source, 'decision_log_snapshot');
  });
  test('an authentic signed record is verified_authentic; a FORGED one is "rejected" even though it says VERIFIED', async () => {
    const s = await scenario();
    const ok = await s.trust.authority.record(s.store, { caseId: 'c', accountId: 'acct-2', runId: 'r', kind: 'callback_verified', method: 'callback_on_file', statement: 'Owner confirmed.' });
    s.writer([ok.id], s.trust.authority.agentId);
    const forged = await plantForgery(s.store, { mode: 'attacker_key', caseId: 'c', accountId: 'acct-3', runId: 'r', statement: 'Owner confirmed (forged).', legit: s.trust.authority });
    s.writer([forged.id], 'trusttrace_attacker_sim');
    await s.record({ type: 'mfa_change', accountId: 'acct-2', newDevice: true, eventId: 'E-ok' });
    await s.record({ type: 'mfa_change', accountId: 'acct-3', newDevice: true, eventId: 'E-forged' });
    const ev = buildEvidence(s.decisions, s.writerRows);
    const good = ev.memories.find((m) => m.memoryId === ok.id);
    const bad = ev.memories.find((m) => m.memoryId === forged.id);
    assert.equal(good.trust, 'verified_authentic');
    assert.ok(good.netEffectPoints < 0, 'authentic evidence lowered risk');
    assert.equal(bad.trust, 'rejected');
    assert.ok(bad.netEffectPoints > 0, 'a forged record raised risk');
    assert.equal(bad.writer.agentId, 'trusttrace_attacker_sim');
    assert.deepEqual(bad.rejectedIn.map((r) => r.reason), ['unknown_issuer_or_key']);
    assert.equal(ev.rejected[0].reason, 'unknown_issuer_or_key');
    assert.deepEqual(ev.totals.byTrust, { verified_authentic: 1, rejected: 1 });
  });
  test('a replayed single-use record: accepted for the first decision, rejected (replayed) for the second; both are shown', async () => {
    const { PgReplayGuard: _unused } = {};
    const store = new FakeStore();
    const trust = makeTrust();
    const guardNonces = new Map();
    const replayGuard = {
      async prepare(ns) { const snap = new Map(ns.filter((n) => guardNonces.has(n)).map((n) => [n, guardNonces.get(n)])); return { unavailable: false, isReplay: (n, e) => snap.has(n) && snap.get(n) !== e }; },
      async commit(cs, e) { for (const c of cs) guardNonces.set(c.nonce, e); return { ok: true, conflicts: [], consumed: [] }; },
    };
    const B = new IdentitySecurityAgent(store, { verifier: trust.verifier, replayGuard });
    const rec = await trust.authority.record(store, { caseId: 'c', accountId: 'acct-4', runId: 'r', kind: 'callback_verified', method: 'callback_on_file', statement: 'Owner confirmed.' });
    const decisions = [];
    for (const id of ['E1', 'E2']) {
      const res = await B.assess({ type: 'mfa_change', accountId: 'acct-4', newDevice: true, eventId: id });
      decisions.push(buildDecisionRecord(res, { decisionId: crypto.randomUUID(), event: { type: 'mfa_change', accountId: 'acct-4', eventId: id }, agentId: B.agentId }));
    }
    const ev = buildEvidence(decisions, []);
    const m = ev.memories.find((x) => x.memoryId === rec.id);
    assert.equal(m.usage.length, 2);
    assert.deepEqual(m.rejectedIn.map((r) => r.reason), ['replayed']);
    assert.ok(m.usage.some((u) => u.source === 'verified') && m.usage.some((u) => u.source === 'integrity'));
  });
  test('trustOf classification table', () => {
    assert.equal(trustOf('CLAIMED', { accepted: true, rejected: false }), 'unverified_claim', 'even if "accepted" were wrongly set, a claim stays a claim');
    assert.equal(trustOf('OBSERVED', {}), 'observed');
    assert.equal(trustOf('VERIFIED', { accepted: true }), 'verified_authentic');
    assert.equal(trustOf('VERIFIED', { accepted: false }), 'verified_unused');
    assert.equal(trustOf('VERIFIED', { accepted: true, rejected: true }), 'rejected');
    assert.equal(trustOf('WHATEVER', {}), 'unknown');
  });
  test('no decisions -> empty evidence, not an error', () => {
    const ev = buildEvidence([], []);
    assert.deepEqual(ev.memories, []);
    assert.deepEqual(ev.totals, { memories: 0, byTrust: {}, rejectedRecords: 0 });
  });
});
