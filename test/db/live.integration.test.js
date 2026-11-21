// REAL Meko + REAL PostgreSQL together: scenarios run through Agent A, the verification authority, live Meko memory and Agent B,
// and every decision, activity event and replay-ledger entry is persisted to PostgreSQL. No mocks anywhere in this file.
// Skipped (not passed) unless BOTH MEKO_API_KEY and DATABASE_URL are configured.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { DB_SKIP, createTestDb } from './helpers.js';
import { loadConfig } from '../../src/config.js';
import { openSession } from '../../src/session.js';
import { runScenarios } from '../../src/scenarioRunner.js';
import { SCENARIOS } from '../../src/scenarios.js';
import { instrumentStore } from '../../src/app/instrumentedStore.js';
import { DecisionService } from '../../src/app/decisionService.js';
import { ActivityRecorder } from '../../src/db/activity.js';
import { PgReplayGuard } from '../../src/db/replayGuard.js';
import { verifyChain } from '../../src/db/auditChain.js';
import { AUDIT_RESOLVERS } from '../../src/db/auditResolvers.js';
import { VerificationAuthority } from '../../src/trust/authority.js';
import { deleteMemories, verifyCleanup } from '../../src/cleanup.js';

let mekoSkip = false;
try { loadConfig(); } catch { mekoSkip = 'MEKO_API_KEY not set (or malformed) in .env'; }
const SKIP = DB_SKIP || mekoSkip;

describe('live Meko + PostgreSQL: scenarios persisted end to end', { skip: SKIP }, () => {
  let db, session, recorder, run;
  const tracker = { savedIds: [], scopeIds: [], writers: {} };
  const WANT = ['S4', 'S6', 'S7'];

  before(async () => {
    db = await createTestDb();
    session = await openSession();
    recorder = new ActivityRecorder(db.pool, { flushDelayMs: 60_000 });
    const guard = new PgReplayGuard(db.pool);
    const authority = VerificationAuthority.ephemeral({ onIssued: (p) => guard.recordIssued(p) });
    run = await runScenarios({
      store: instrumentStore(session.store, recorder), tag: `lp${randomUUID().slice(0, 6)}`, authority, tracker,
      scenarios: SCENARIOS.filter((s) => WANT.includes(s.id)), replayGuard: guard,
      assess: async (agent, event) => (await new DecisionService({ pool: db.pool, recorder, agent }).assessAndRecord(event)).result,
    });
    await recorder.flush();
  }, { timeout: 400_000 });

  after(async () => {
    if (session) {
      const del = await deleteMemories(session.store, tracker.savedIds, tracker.writers);
      console.log(`    meko cleanup: deleted ${del.deleted}/${tracker.savedIds.length} (${del.failed.length} failed)`);
      await session.client.close();
    }
    await recorder?.close();
    await db?.cleanup();
  });

  test('the scenarios behaved as before AND were persisted: one decision row per scenario', async () => {
    assert.equal(run.results.length, WANT.length);
    assert.ok(run.results.every((r) => r.pass), JSON.stringify(run.results.filter((r) => !r.pass).map((r) => [r.id, r.checks])));
    assert.equal((await db.pool.query('SELECT count(*) FROM decisions')).rows[0].count, WANT.length);
  });

  test('each stored decision references the REAL Meko memory ids it retrieved, and its recorded latency is real Meko latency', async () => {
    const rows = (await db.pool.query('SELECT * FROM decisions ORDER BY created_at')).rows;
    const known = new Set(tracker.savedIds);
    for (const d of rows) {
      assert.ok(d.retrieved.length > 0, `${d.event_id} retrieved nothing`);
      assert.ok(d.retrieved.every((m) => known.has(m.id)), 'a retrieved id is not a memory written by this run');
      assert.ok(d.timings.retrievalMs > 100, `retrieval ${d.timings.retrievalMs} ms is too fast to be a Meko round trip`);
      assert.equal(d.retrieval_complete, true);
      assert.equal(d.degraded, false);
    }
  });

  test('S6: the signed callback was issued (ledger + audit), accepted, SPENT by the decision, and the ledger row points back to it', async () => {
    const d = (await db.pool.query("SELECT * FROM decisions WHERE event_id LIKE 'evt-S6-%'")).rows[0];
    assert.equal(d.verified_facts.length, 1);
    assert.deepEqual(d.rejected_evidence, []);
    assert.equal(d.base_action, 'allow');
    assert.equal(d.recommended_action, 'step_up');
    const n = (await db.pool.query("SELECT * FROM attestation_nonces WHERE kind = 'callback_verified'")).rows[0];
    assert.equal(n.source, 'issued');
    assert.equal(n.consumed_event_id, d.event_id);
    assert.equal(n.decision_id, d.id);
    const types = (await db.pool.query("SELECT record_type FROM audit_records WHERE ref_id = $1 ORDER BY seq", [n.nonce])).rows.map((r) => r.record_type);
    assert.deepEqual(types, ['attestation_issued', 'attestation_consumed']);
  });

  test('S7: the decision records the pattern contribution that escalated it', async () => {
    const d = (await db.pool.query("SELECT * FROM decisions WHERE event_id LIKE 'evt-S7-%'")).rows[0];
    assert.equal(d.recommended_action, 'block');
    assert.ok(d.contributions.some((c) => c.source === 'pattern' && c.effectivePoints > 0));
  });

  test('agent activity trail: Meko writes by Agent A and the authority, reads by Agent B, and a decision_made per scenario', async () => {
    const kinds = (await db.pool.query('SELECT kind, agent_id, count(*) AS n FROM agent_events GROUP BY kind, agent_id')).rows;
    const n = (k, agent) => kinds.filter((r) => r.kind === k && (!agent || r.agent_id === agent)).reduce((a, r) => a + r.n, 0);
    assert.equal(n('memory_written'), tracker.savedIds.length, 'every memory written to Meko is in the activity trail');
    assert.ok(n('memory_written', 'trusttrace_helpdesk_agent') > 0);
    assert.ok(n('memory_written', 'trusttrace_verification_authority') >= 2, 'S6 callback + S7 pattern');
    assert.ok(n('memories_retrieved', 'trusttrace_identity_security_agent') >= WANT.length);
    assert.equal(n('decision_made'), WANT.length);
    assert.equal((await db.pool.query('SELECT count(*) FROM agent_events WHERE ok = false')).rows[0].count, 0);
  });

  test('the audit chain over these real decisions verifies', async () => {
    const v = await verifyChain(db.pool, { resolvers: AUDIT_RESOLVERS });
    assert.equal(v.ok, true, JSON.stringify(v.problems));
    // exact composition: 3 decisions + 2 issuances (S6 callback, S7 pattern) + 1 consumption (only the S6 callback is single-use)
    const byType = Object.fromEntries((await db.pool.query('SELECT record_type, count(*) AS n FROM audit_records GROUP BY record_type')).rows.map((r) => [r.record_type, r.n]));
    assert.deepEqual(byType, { decision: 3, attestation_issued: 2, attestation_consumed: 1 });
    assert.equal(v.checked, 6);
  });

  test('cleanup: the Meko test memories are deleted and verifiably gone (PostgreSQL rows are dropped with the test schema)', { timeout: 200_000 }, async () => {
    const del = await deleteMemories(session.store, tracker.savedIds, tracker.writers);
    assert.deepEqual(del.failed, []);
    const v = await verifyCleanup({ store: session.store, savedIds: tracker.savedIds, scopeIds: tracker.scopeIds, timeoutMs: 90_000 });
    assert.equal(v.memoriesConfirmedAbsent, tracker.savedIds.length);
    assert.deepEqual(v.trusttraceMemoriesLeftInDatapack, []);
    tracker.savedIds.length = 0;
  });
});
