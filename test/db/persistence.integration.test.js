// PostgreSQL integration: decisions, case index, agent activity, the audit hash chain (incl. real tamper detection) and the
// persistent, atomic replay ledger. Real PostgreSQL; agents run over an in-memory memory store (Meko is not involved here).
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { DB_SKIP, createTestDb, makeWorld, CFO_CALL, uniq } from './helpers.js';
import { appendAudit, verifyChain } from '../../src/db/auditChain.js';
import { AUDIT_RESOLVERS } from '../../src/db/auditResolvers.js';
import { buildDecisionRecord, decisionPayload, getDecision, recordFromRow } from '../../src/db/decisionRepo.js';
import { hashOf } from '../../src/db/canonical.js';
import { ActivityRecorder } from '../../src/db/activity.js';
import { PgReplayGuard } from '../../src/db/replayGuard.js';
import { withTransaction } from '../../src/db/pool.js';
import { IdentitySecurityAgent } from '../../src/agents/identityAgent.js';
import { decodeEnvelope } from '../../src/trust/attestation.js';
import { parseMemory } from '../../src/labels.js';
import { brokenStore } from '../helpers/fakeStore.js';
import { MekoConnectionError } from '../../src/errors.js';

const chain = (pool) => verifyChain(pool, { resolvers: AUDIT_RESOLVERS });
const nonceOf = (text) => decodeEnvelope(parseMemory(text).attestation).payload.nonce;
const mfaEvent = (accountId, extra = {}) => ({ type: 'mfa_change', accountId, newDevice: true, ...extra });
async function tamper(pool, table, trigger, sql, params = []) {
  await pool.query(`ALTER TABLE ${table} DISABLE TRIGGER ${trigger}`);
  try { await pool.query(sql, params); } finally { await pool.query(`ALTER TABLE ${table} ENABLE TRIGGER ${trigger}`); }
}

describe('PostgreSQL: decisions and the audit chain', { skip: DB_SKIP }, () => {
  let db, w;
  before(async () => { db = await createTestDb(); w = makeWorld(db.pool); });
  after(async () => { await w.recorder.close(); await db.cleanup(); });

  test('a decision round-trips through jsonb/timestamptz/float8 with an IDENTICAL hash (the property the chain relies on)', async () => {
    const accountId = uniq('acct');
    await w.A.handleInteraction({ caseId: 'case-rt', accountId, runId: 'r', callerText: CFO_CALL });
    const { decisionId, record } = await w.svc.assessAndRecord(mfaEvent(accountId, { caseId: 'case-rt', newCountry: true }));
    const stored = await getDecision(db.pool, decisionId);
    assert.equal(hashOf(decisionPayload(stored)), hashOf(decisionPayload(record)));
    assert.deepEqual(stored.contributions, record.contributions);
    assert.deepEqual(stored.retrieved, record.retrieved);
    assert.equal(stored.rawScore, record.rawScore);
    assert.equal(stored.createdAt.toISOString(), record.createdAt.toISOString());
    assert.equal(stored.caseId, 'case-rt');
    assert.ok(stored.retrieved.length > 0 && stored.contributions.length > 0 && stored.explanation.length > 0);
  });

  test('the decision, its case row and its audit record commit together; a decision with an invalid value rolls ALL of them back', async () => {
    const accountId = uniq('acct');
    const before = (await db.pool.query('SELECT (SELECT count(*) FROM decisions) d, (SELECT count(*) FROM audit_records) a, (SELECT count(*) FROM cases) c')).rows[0];
    const agent = new IdentitySecurityAgent(w.store, { verifier: w.trust.verifier });
    const realAssess = agent.assess.bind(agent);
    agent.assess = async (e, o) => ({ ...(await realAssess(e, o)), severity: 'not-a-severity' }); // the DB must refuse it
    const { DecisionService } = await import('../../src/app/decisionService.js');
    await assert.rejects(new DecisionService({ pool: db.pool, recorder: null, agent }).assessAndRecord({ type: 'login', accountId, caseId: 'case-rb' }));
    const after = (await db.pool.query('SELECT (SELECT count(*) FROM decisions) d, (SELECT count(*) FROM audit_records) a, (SELECT count(*) FROM cases) c')).rows[0];
    assert.deepEqual(after, before, 'nothing may be left behind by a failed decision');
    assert.equal((await chain(db.pool)).ok, true);
  });

  test('the case index tracks count, first/last seen and the HIGHEST severity', async () => {
    const accountId = uniq('acct');
    const caseId = uniq('case');
    await w.svc.assessAndRecord({ type: 'login', accountId, caseId });                                  // low
    await w.A.handleInteraction({ caseId, accountId, runId: 'r', callerText: CFO_CALL });
    await w.svc.assessAndRecord(mfaEvent(accountId, { caseId, newCountry: true }));                     // critical-ish
    await w.svc.assessAndRecord({ type: 'login', accountId, caseId });                                  // later, lower
    const c = (await db.pool.query('SELECT * FROM cases WHERE account_id = $1 AND case_id = $2', [accountId, caseId])).rows[0];
    assert.equal(c.decision_count, 3);
    assert.ok(['high', 'critical'].includes(c.max_severity), c.max_severity);
    assert.ok(c.last_seen >= c.first_seen);
    const sevs = (await db.pool.query('SELECT severity FROM decisions WHERE case_id = $1 ORDER BY created_at', [caseId])).rows.map((r) => r.severity);
    assert.equal(c.max_severity, sevs.includes('critical') ? 'critical' : 'high');
  });

  test('events without a caseId create no case row', async () => {
    const accountId = uniq('acct');
    await w.svc.assessAndRecord({ type: 'login', accountId });
    assert.equal((await db.pool.query('SELECT count(*) FROM cases WHERE account_id = $1', [accountId])).rows[0].count, 0);
  });

  test('a DEGRADED decision (Meko unreachable) is persisted as degraded, with the error and a non-allow action', async () => {
    const { DecisionService } = await import('../../src/app/decisionService.js');
    const agent = new IdentitySecurityAgent(brokenStore(MekoConnectionError, 'meko down'), { verifier: w.trust.verifier });
    const { record } = await new DecisionService({ pool: db.pool, recorder: w.recorder, agent }).assessAndRecord({ type: 'login', accountId: uniq('acct') });
    const row = await getDecision(db.pool, record.id);
    assert.equal(row.degraded, true);
    assert.equal(row.contextAvailable, false);
    assert.equal(row.error.name, 'MekoConnectionError');
    assert.notEqual(row.recommendedAction, 'allow');
  });

  test('25 concurrent decisions produce a contiguous, valid chain (advisory lock serialises appends)', async () => {
    const own = await createTestDb();
    try {
      const w2 = makeWorld(own.pool);
      await Promise.all(Array.from({ length: 25 }, (_, i) => w2.svc.assessAndRecord({ type: 'login', accountId: `acct-conc-${i}`, caseId: `case-${i % 5}` })));
      const rows = (await own.pool.query('SELECT seq FROM audit_records ORDER BY seq')).rows.map((r) => r.seq);
      assert.deepEqual(rows, Array.from({ length: 25 }, (_, i) => i + 1));
      const v = await chain(own.pool);
      assert.equal(v.ok, true, JSON.stringify(v.problems));
      assert.equal(v.checked, 25);
      await w2.recorder.close();
    } finally { await own.cleanup(); }
  });

  test('a rolled-back transaction leaves no gap in the chain', async () => {
    const own = await createTestDb();
    try {
      await withTransaction(own.pool, (c) => appendAudit(c, { recordType: 'decision', refId: 'a', payload: { x: 1 } }));
      await assert.rejects(withTransaction(own.pool, async (c) => { await appendAudit(c, { recordType: 'decision', refId: 'b', payload: { x: 2 } }); throw new Error('abort'); }));
      await withTransaction(own.pool, (c) => appendAudit(c, { recordType: 'decision', refId: 'c', payload: { x: 3 } }));
      assert.deepEqual((await own.pool.query('SELECT seq FROM audit_records ORDER BY seq')).rows.map((r) => r.seq), [1, 2]);
    } finally { await own.cleanup(); }
  });
});

describe('PostgreSQL: REAL tamper detection (a privileged attacker bypasses the triggers; the chain still catches it)', { skip: DB_SKIP }, () => {
  async function seeded(n = 4) {
    const db = await createTestDb();
    const w = makeWorld(db.pool);
    const ids = [];
    for (let i = 0; i < n; i++) ids.push((await w.svc.assessAndRecord({ type: i % 2 ? 'mfa_change' : 'login', accountId: `acct-t-${i}`, caseId: `case-t-${i}`, newDevice: i % 2 === 1 })).decisionId);
    return { db, w, ids, close: async () => { await w.recorder.close(); await db.cleanup(); } };
  }

  test('control: an untouched chain verifies', async () => {
    const s = await seeded();
    try { const v = await chain(s.db.pool); assert.equal(v.ok, true); assert.equal(v.checked, 4); assert.equal(v.head.seq, 4); } finally { await s.close(); }
  });
  test('editing a stored DECISION (e.g. downgrading block -> allow) is detected as audited_row_modified at the right seq', async () => {
    const s = await seeded();
    try {
      await tamper(s.db.pool, 'decisions', 'decisions_append_only', "UPDATE decisions SET recommended_action = 'allow', severity = 'low' WHERE id = $1", [s.ids[1]]);
      const v = await chain(s.db.pool);
      assert.equal(v.ok, false);
      assert.equal(v.problems[0].code, 'audited_row_modified');
      assert.equal(v.problems[0].seq, 2);
    } finally { await s.close(); }
  });
  test('editing a JSON field inside a decision (the explanation) is detected too', async () => {
    const s = await seeded();
    try {
      await tamper(s.db.pool, 'decisions', 'decisions_append_only', "UPDATE decisions SET explanation = '[\"nothing to see\"]'::jsonb WHERE id = $1", [s.ids[2]]);
      assert.equal((await chain(s.db.pool)).problems[0].seq, 3);
    } finally { await s.close(); }
  });
  test('DELETING a decision is detected (audited_row_missing)', async () => {
    const s = await seeded();
    try {
      await tamper(s.db.pool, 'decisions', 'decisions_append_only', 'DELETE FROM decisions WHERE id = $1', [s.ids[0]]);
      const v = await chain(s.db.pool);
      assert.equal(v.ok, false);
      assert.equal(v.problems[0].code, 'audited_row_missing');
    } finally { await s.close(); }
  });
  test('editing an AUDIT record is detected (record_hash_mismatch)', async () => {
    const s = await seeded();
    try {
      await tamper(s.db.pool, 'audit_records', 'audit_records_append_only', "UPDATE audit_records SET payload_hash = repeat('a', 64) WHERE seq = 2");
      assert.ok((await chain(s.db.pool)).problems.some((p) => p.code === 'record_hash_mismatch' && p.seq === 2));
    } finally { await s.close(); }
  });
  test('deleting an audit record from the middle is detected (seq_gap)', async () => {
    const s = await seeded();
    try {
      await tamper(s.db.pool, 'audit_records', 'audit_records_append_only', 'DELETE FROM audit_records WHERE seq = 2');
      assert.ok((await chain(s.db.pool)).problems.some((p) => p.code === 'seq_gap'));
    } finally { await s.close(); }
  });
  test('rewriting an audit record AND its hash still breaks the next link (broken_link)', async () => {
    const s = await seeded();
    try {
      await tamper(s.db.pool, 'audit_records', 'audit_records_append_only', "UPDATE audit_records SET ref_id = 'forged' WHERE seq = 3");
      const v = await chain(s.db.pool); // must REPORT, not crash on the non-UUID ref_id
      const codes = v.problems.map((p) => p.code);
      assert.equal(v.ok, false);
      assert.ok(codes.includes('record_hash_mismatch'));
      assert.ok(codes.includes('audited_row_missing'), 'the forged ref_id points at no decision');
    } finally { await s.close(); }
  });
  test('HONEST LIMIT: truncating the TAIL of the chain (and its decisions) is not detectable from inside the database', async () => {
    const s = await seeded();
    try {
      await tamper(s.db.pool, 'audit_records', 'audit_records_append_only', 'DELETE FROM audit_records WHERE seq = 4');
      await tamper(s.db.pool, 'decisions', 'decisions_append_only', 'DELETE FROM decisions WHERE id = $1', [s.ids[3]]);
      const v = await chain(s.db.pool);
      assert.equal(v.ok, true);
      assert.equal(v.head.seq, 3); // only an externally stored head (e.g. from /api/health/details) reveals the truncation
    } finally { await s.close(); }
  });
});

describe('PostgreSQL: agent activity', { skip: DB_SKIP }, () => {
  let db;
  before(async () => { db = await createTestDb(); });
  after(async () => { await db.cleanup(); });

  test('250 events written in batches: arrays, jsonb, timestamps, booleans and nulls all round-trip', async () => {
    const r = new ActivityRecorder(db.pool, { flushDelayMs: 60_000 });
    const at = new Date('2026-03-04T05:06:07.123Z');
    for (let i = 0; i < 250; i++) {
      r.record({ at, agentId: i % 2 ? 'agent-a' : 'agent-b', kind: 'memory_written', accountId: `acct-${i % 10}`, caseId: i % 3 ? null : 'case-x', memoryIds: [`m-${i}`, `n-${i}`], payload: { i, nested: { ok: true } }, durationMs: i / 4, ok: i % 50 !== 0, error: i % 50 === 0 ? 'boom' : undefined });
    }
    await r.flush();
    assert.equal(r.stats().written, 250);
    assert.equal(r.stats().failedBatches, 0);
    const all = (await db.pool.query('SELECT * FROM agent_events ORDER BY id')).rows;
    assert.equal(all.length, 250);
    const e7 = all.find((x) => x.payload.i === 7);
    assert.deepEqual(e7.memory_ids, ['m-7', 'n-7']);
    assert.equal(e7.payload.nested.ok, true);
    assert.equal(e7.at.toISOString(), at.toISOString());
    assert.equal(e7.duration_ms, 7 / 4);
    assert.equal(e7.ok, true);
    assert.equal(e7.case_id, null, 'i=7 was recorded without a caseId: the nullable column stays NULL');
    assert.equal(all.find((x) => x.payload.i === 9).case_id, 'case-x');
    const failed = all.filter((x) => !x.ok);
    assert.equal(failed.length, 5);
    assert.ok(failed.every((x) => x.error === 'boom'));
    assert.equal((await db.pool.query("SELECT count(*) FROM agent_events WHERE agent_id = 'agent-a'")).rows[0].count, 125);
    assert.equal((await db.pool.query("SELECT count(*) FROM agent_events WHERE 'm-7' = ANY(memory_ids)")).rows[0].count, 1);
    await r.close();
  });
  test('hostile text in event fields is stored as data (parameterised SQL)', async () => {
    const r = new ActivityRecorder(db.pool, { flushDelayMs: 60_000 });
    const evil = "'); DROP TABLE agent_events; --";
    r.record({ agentId: evil, kind: evil, accountId: evil, memoryIds: [evil], payload: { evil }, error: evil });
    await r.flush();
    const row = (await db.pool.query('SELECT * FROM agent_events WHERE agent_id = $1', [evil])).rows[0];
    assert.equal(row.kind, evil);
    assert.deepEqual(row.memory_ids, [evil]);
    assert.equal((await db.pool.query('SELECT count(*) FROM agent_events')).rows[0].count >= 251, true);
    await r.close();
  });
  test('Agent B + the instrumented DecisionService record "decision_made" with the retrieved memory ids', async () => {
    const w = makeWorld(db.pool);
    const accountId = uniq('acct');
    const res = await w.A.handleInteraction({ caseId: 'case-act', accountId, runId: 'r', callerText: CFO_CALL });
    const { decisionId } = await w.svc.assessAndRecord(mfaEvent(accountId, { caseId: 'case-act' }));
    await w.recorder.flush();
    const ev = (await db.pool.query("SELECT * FROM agent_events WHERE kind = 'decision_made' AND decision_id = $1", [decisionId])).rows[0];
    assert.ok(ev);
    assert.equal(ev.case_id, 'case-act');
    assert.equal(ev.memory_ids.length, res.saved.length);
    assert.equal(ev.payload.recommendedAction, 'block');
    await w.recorder.close();
  });
});

describe('PostgreSQL: persistent, atomic replay ledger', { skip: DB_SKIP }, () => {
  let db;
  before(async () => { db = await createTestDb(); });
  after(async () => { await db.cleanup(); });
  const consumable = (nonce, over = {}) => ({ nonce, kind: 'callback_verified', accountId: 'acct-r', caseId: 'case-r', issuer: 'iss', kid: 'kid', method: 'cb', statementSha256: 'h', iat: Date.now(), exp: Date.now() + 600_000, ...over });

  test('first commit wins, the same event is idempotent, a different event is a conflict (and consumes nothing)', async () => {
    const g = new PgReplayGuard(db.pool);
    const n = uniq('nonce');
    assert.deepEqual(await g.commit([consumable(n)], 'E1', { decisionId: randomUUID() }), { ok: true, conflicts: [], consumed: [n] });
    assert.equal((await g.commit([consumable(n)], 'E1')).ok, true, 'idempotent for the same event');
    const lost = await g.commit([consumable(n)], 'E2');
    assert.deepEqual([lost.ok, lost.conflicts], [false, [n]]);
    const row = (await db.pool.query('SELECT * FROM attestation_nonces WHERE nonce = $1', [n])).rows[0];
    assert.equal(row.consumed_event_id, 'E1');
    assert.equal(row.source, 'first_seen');
  });
  test('RACE: 12 different events try to spend the same nonce at once -> exactly ONE succeeds', async () => {
    const n = uniq('nonce');
    const results = await Promise.all(Array.from({ length: 12 }, (_, i) => new PgReplayGuard(db.newPool()).commit([consumable(n)], `RACE-${i}`)));
    assert.equal(results.filter((r) => r.ok).length, 1);
    assert.equal(results.filter((r) => !r.ok).length, 11);
    const row = (await db.pool.query('SELECT consumed_event_id FROM attestation_nonces WHERE nonce = $1', [n])).rows[0];
    assert.match(row.consumed_event_id, /^RACE-\d+$/);
    assert.equal((await db.pool.query("SELECT count(*) FROM audit_records WHERE record_type = 'attestation_consumed' AND ref_id = $1", [n])).rows[0].count, 1, 'exactly one consumption audit record');
  });
  test('ALL-OR-NOTHING: a batch containing one already-spent nonce consumes none of them', async () => {
    const g = new PgReplayGuard(db.pool);
    const free = uniq('free'), spent = uniq('spent');
    await g.commit([consumable(spent)], 'OTHER');
    const r = await g.commit([consumable(free), consumable(spent)], 'E9');
    assert.deepEqual([r.ok, r.conflicts], [false, [spent]]);
    assert.equal((await db.pool.query('SELECT count(*) FROM attestation_nonces WHERE nonce = $1', [free])).rows[0].count, 0, 'the free nonce must not have been consumed');
    assert.equal((await g.commit([consumable(free)], 'E9')).ok, true, 'and it is still spendable afterwards');
  });
  test('an attestation recorded as ISSUED is consumed by UPDATE (source stays issued); issuance is idempotent and audited once', async () => {
    const g = new PgReplayGuard(db.pool);
    const n = uniq('issued');
    const p = { nonce: n, kind: 'callback_verified', accountId: 'acct-r', caseId: 'case-r', iss: 'iss', kid: 'kid', method: 'cb', statementSha256: 'h', iat: Date.now(), exp: Date.now() + 600_000 };
    await g.recordIssued(p);
    await g.recordIssued(p);
    assert.equal((await db.pool.query("SELECT count(*) FROM audit_records WHERE record_type = 'attestation_issued' AND ref_id = $1", [n])).rows[0].count, 1);
    assert.equal((await g.commit([consumable(n)], 'E1')).ok, true);
    const row = (await db.pool.query('SELECT * FROM attestation_nonces WHERE nonce = $1', [n])).rows[0];
    assert.equal(row.source, 'issued');
    assert.equal(row.consumed_event_id, 'E1');
  });
  test('prepare() reports only consumed nonces, with their owner', async () => {
    const g = new PgReplayGuard(db.pool);
    const a = uniq('a'), b = uniq('b');
    await g.commit([consumable(a)], 'EV-A');
    const view = await g.prepare([a, b, 'never-seen']);
    assert.equal(view.unavailable, false);
    assert.equal(view.isReplay(a, 'EV-B'), true);
    assert.equal(view.isReplay(a, 'EV-A'), false);
    assert.equal(view.isReplay(b, 'EV-B'), false);
    assert.equal((await g.prepare([])).isReplay('x', 'y'), false);
  });
  test('the chain stays valid with issuance + consumption records, and a tampered nonce row is caught', async () => {
    assert.equal((await chain(db.pool)).ok, true);
    const g = new PgReplayGuard(db.pool);
    const n = uniq('victim');
    await g.recordIssued({ nonce: n, kind: 'callback_verified', accountId: 'acct-r', caseId: 'c', iss: 'i', kid: 'k', method: 'm', statementSha256: 'h', iat: Date.now(), exp: Date.now() + 600_000 });
    assert.equal((await chain(db.pool)).ok, true);
    await tamper(db.pool, 'attestation_nonces', 'attestation_nonces_one_way', "UPDATE attestation_nonces SET expires_at = expires_at + interval '30 days' WHERE nonce = $1", [n]);
    const v = await chain(db.pool);
    assert.equal(v.ok, false);
    assert.equal(v.problems[0].code, 'audited_row_modified');
  });
});

describe('PostgreSQL: agents + persistent replay guard end to end', { skip: DB_SKIP }, () => {
  let db;
  before(async () => { db = await createTestDb(); });
  after(async () => { await db.cleanup(); });

  test('single-use callback: spent by event 1, rejected for event 2 - even after a simulated PROCESS RESTART (new pool, new agent)', async () => {
    const w = makeWorld(db.pool);
    const accountId = uniq('acct');
    const rec = await w.trust.authority.record(w.store, { caseId: 'case-e2e', accountId, runId: 'r', kind: 'callback_verified', method: 'callback_on_file', statement: 'Callback confirmed the account owner.' });
    const first = await w.svc.assessAndRecord(mfaEvent(accountId, { caseId: 'case-e2e', eventId: 'EV1' }));
    assert.equal(first.result.verifiedFacts.length, 1);
    const ledger = (await db.pool.query('SELECT * FROM attestation_nonces WHERE nonce = $1', [nonceOf(rec.text)])).rows[0];
    assert.equal(ledger.consumed_event_id, 'EV1');
    assert.equal(ledger.decision_id, first.decisionId, 'the ledger row points at the decision that spent it');
    assert.equal(ledger.source, 'issued', 'recorded at issuance by the authority hook');

    const pool2 = db.newPool(); // "restart": nothing in memory survives
    const B2 = new IdentitySecurityAgent(w.store, { verifier: w.trust.verifier, replayGuard: new PgReplayGuard(pool2) });
    const replay = await B2.assess(mfaEvent(accountId, { eventId: 'EV2' }));
    assert.deepEqual(replay.verifiedFacts, []);
    assert.equal(replay.rejectedEvidence[0].reason, 'replayed');
    assert.ok(replay.rawScore > first.result.rawScore);
    assert.equal((await chain(db.pool)).ok, true);
    await w.recorder.close();
  });
  test('two agents racing on the same callback: exactly one decision gets the credit, the loser is rejected as replayed', async () => {
    const w = makeWorld(db.pool);
    const accountId = uniq('acct');
    await w.trust.authority.record(w.store, { caseId: 'case-race', accountId, runId: 'r', kind: 'callback_verified', method: 'callback_on_file', statement: 'Owner confirmed.' });
    const mk = () => new IdentitySecurityAgent(w.store, { verifier: w.trust.verifier, replayGuard: new PgReplayGuard(db.newPool()) });
    const [a, b] = await Promise.all([mk().assess(mfaEvent(accountId, { eventId: 'R1' })), mk().assess(mfaEvent(accountId, { eventId: 'R2' }))]);
    assert.equal([a, b].filter((r) => r.verifiedFacts.length === 1).length, 1);
    assert.equal([a, b].filter((r) => r.rejectedEvidence.some((x) => x.reason === 'replayed')).length, 1);
    await w.recorder.close();
  });
  test('authority hook fails CLOSED: if the ledger cannot record the issuance, no evidence is created', async () => {
    const w = makeWorld(db.pool);
    w.trust.authority.onIssued = async () => { throw new Error('ledger unavailable'); };
    await assert.rejects(w.trust.authority.record(w.store, { caseId: 'c', accountId: uniq('acct'), runId: 'r', kind: 'callback_verified', method: 'cb', statement: 's' }), /ledger unavailable/);
    assert.equal(w.store.rows.length, 0, 'no VERIFIED memory may exist without a ledger entry');
    await w.recorder.close();
  });
  test('the stored decision shows WHY: rejected evidence, policy and verifier key id are persisted', async () => {
    const w = makeWorld(db.pool);
    const accountId = uniq('acct');
    await w.trust.authority.record(w.store, { caseId: 'c', accountId, runId: 'r', kind: 'callback_verified', method: 'cb', statement: 'Owner confirmed.' });
    await w.svc.assessAndRecord(mfaEvent(accountId, { eventId: 'W1' }));
    const second = await w.svc.assessAndRecord(mfaEvent(accountId, { eventId: 'W2' }));
    const row = await getDecision(db.pool, second.decisionId);
    assert.equal(row.rejectedEvidence[0].reason, 'replayed');
    assert.equal(row.verifierKeyId, w.trust.verifier.keyIds[0]);
    assert.ok(Array.isArray(row.policy) && Array.isArray(row.stepUp.requirements));
    await w.recorder.close();
  });
});
