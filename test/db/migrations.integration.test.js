// PostgreSQL integration: migrations, constraints and append-only enforcement, against the REAL database.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { getDecision, insertDecision } from '../../src/db/decisionRepo.js';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DB_SKIP, createTestDb, makeWorld, CFO_CALL, uniq } from './helpers.js';
import { loadMigrations, migrationStatus, runMigrations } from '../../src/db/migrate.js';
import { DuplicateUserError, createUser } from '../../src/db/userRepo.js';
import { PgReplayGuard } from '../../src/db/replayGuard.js';

const FORBIDDEN = '23000'; // integrity_constraint_violation (raised by the append-only triggers)
const code = async (p) => { try { await p; return null; } catch (e) { return e.code ?? e.message; } };

describe('PostgreSQL: migrations', { skip: DB_SKIP }, () => {
  test('a fresh schema migrates from nothing; re-running is a no-op; status is up to date', async () => {
    const db = await createTestDb({ migrate: false });
    try {
      const first = await runMigrations(db.pool);
      assert.equal(first.ran.length, loadMigrations().length);
      assert.deepEqual((await runMigrations(db.pool)).ran, []);
      const s = await migrationStatus(db.pool);
      assert.equal(s.upToDate, true);
      assert.equal(s.applied.length, loadMigrations().length);
    } finally { await db.cleanup(); }
  });

  test('every table, key index and trigger exists in the real catalog', async () => {
    const db = await createTestDb();
    try {
      const tables = (await db.pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()")).rows.map((r) => r.table_name);
      for (const t of ['users', 'sessions', 'access_log', 'decisions', 'cases', 'agent_events', 'attestation_nonces', 'audit_records', 'schema_migrations']) assert.ok(tables.includes(t), `missing ${t}`);
      const triggers = (await db.pool.query("SELECT tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND NOT t.tgisinternal")).rows.map((r) => r.tgname);
      for (const t of ['decisions_append_only', 'decisions_no_truncate', 'audit_records_append_only', 'audit_records_no_truncate', 'agent_events_append_only', 'attestation_nonces_one_way']) assert.ok(triggers.includes(t), `missing trigger ${t}`);
      const cols = (await db.pool.query("SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'decisions'")).rows;
      const type = Object.fromEntries(cols.map((c) => [c.column_name, c.data_type]));
      assert.equal(type.raw_score, 'double precision');
      assert.equal(type.contributions, 'jsonb');
      assert.equal(type.created_at, 'timestamp with time zone');
    } finally { await db.cleanup(); }
  });

  test('a concurrent migration run is safe (advisory lock): both succeed and the schema exists once', async () => {
    const db = await createTestDb({ migrate: false });
    try {
      const results = await Promise.all([runMigrations(db.pool), runMigrations(db.newPool())]);
      assert.equal(results.reduce((n, r) => n + r.ran.length, 0), loadMigrations().length, 'each migration must be applied exactly once in total');
      assert.equal((await migrationStatus(db.pool)).upToDate, true);
    } finally { await db.cleanup(); }
  });

  test('a migration that was MODIFIED after being applied is refused', async () => {
    const db = await createTestDb();
    try {
      await db.pool.query("UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1");
      const s = await migrationStatus(db.pool);
      assert.equal(s.upToDate, false);
      assert.deepEqual(s.modified.map((m) => m.version), [1]);
      await assert.rejects(runMigrations(db.pool), /modified after it was applied/);
    } finally { await db.cleanup(); }
  });

  test('a failing migration is rolled back completely (no half-applied schema)', async () => {
    const db = await createTestDb({ migrate: false });
    const dir = mkdtempSync(join(tmpdir(), 'tt-mig-'));
    try {
      writeFileSync(join(dir, '001_ok.sql'), 'CREATE TABLE good (id int);');
      writeFileSync(join(dir, '002_bad.sql'), 'CREATE TABLE half (id int); SELECT * FROM table_that_does_not_exist;');
      await assert.rejects(runMigrations(db.pool, { dir }), /002_bad\.sql failed and was rolled back/);
      const t = (await db.pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()")).rows.map((r) => r.table_name);
      assert.ok(t.includes('good'));
      assert.ok(!t.includes('half'), 'the failed migration left a table behind');
      assert.deepEqual((await db.pool.query('SELECT version FROM schema_migrations')).rows.map((r) => r.version), [1]);
    } finally { rmSync(dir, { recursive: true, force: true }); await db.cleanup(); }
  });
});

describe('PostgreSQL: constraints', { skip: DB_SKIP }, () => {
  let db;
  before(async () => { db = await createTestDb(); });
  after(async () => { await db.cleanup(); });

  test('usernames are unique case-insensitively; roles are restricted', async () => {
    await createUser(db.pool, { username: 'Alice', passwordHash: 'h', role: 'admin' });
    await assert.rejects(createUser(db.pool, { username: 'ALICE', passwordHash: 'h', role: 'analyst' }), DuplicateUserError);
    assert.equal(await code(createUser(db.pool, { username: 'mallory', passwordHash: 'h', role: 'root' })), '23514');
    assert.equal(await code(createUser(db.pool, { username: 'ab', passwordHash: 'h', role: 'analyst' })), '23514'); // too short
  });
  test('deleting a user deletes their sessions (cascade)', async () => {
    const u = await createUser(db.pool, { username: 'cascade-user', passwordHash: 'h', role: 'analyst' });
    await db.pool.query("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, now() + interval '1 hour')", [u.id, `tok-${u.id}`]);
    assert.equal((await db.pool.query('SELECT count(*) FROM sessions WHERE user_id = $1', [u.id])).rows[0].count, 1, 'control: the session exists before the delete');
    await db.pool.query('DELETE FROM users WHERE id = $1', [u.id]);
    assert.equal((await db.pool.query('SELECT count(*) FROM sessions WHERE user_id = $1', [u.id])).rows[0].count, 0);
  });
  test('decisions reject invalid severity/action values at the database level', async () => {
    const w = makeWorld(db.pool);
    const { decisionId } = await w.svc.assessAndRecord({ type: 'login', accountId: uniq('acct') });
    const rec = await getDecision(db.pool, decisionId);
    assert.ok(rec);
    const bad = (patch) => code(insertDecision(db.pool, { ...rec, id: randomUUID(), ...patch }));
    assert.equal(await bad({ severity: 'catastrophic' }), '23514');
    assert.equal(await bad({ recommendedAction: 'nuke' }), '23514');
    assert.equal(await bad({ baseAction: 'maybe' }), '23514');
    assert.equal(await bad({}), null, 'control: an unmodified copy with a new id is accepted');
  });
  test('audit hashes must be 64 hex chars and seq >= 1', async () => {
    const ins = (seq, h) => db.pool.query("INSERT INTO audit_records (seq, created_at, record_type, ref_id, payload_hash, prev_hash, record_hash) VALUES ($1, now(), 'decision', 'x', $2, $2, $2)", [seq, h]);
    assert.equal(await code(ins(900, 'not-hex')), '23514');
    assert.equal(await code(ins(0, 'a'.repeat(64))), '23514');
  });
});

describe('PostgreSQL: append-only enforcement', { skip: DB_SKIP }, () => {
  let db, w, decisionId;
  before(async () => {
    db = await createTestDb();
    w = makeWorld(db.pool);
    await w.A.handleInteraction({ caseId: 'case-ao', accountId: 'acct-ao', runId: 'r', callerText: CFO_CALL });
    ({ decisionId } = await w.svc.assessAndRecord({ type: 'mfa_change', accountId: 'acct-ao', caseId: 'case-ao', newDevice: true }));
    w.recorder.record({ agentId: 'a', kind: 'k' });
    await w.recorder.flush();
  });
  after(async () => { await w.recorder.close(); await db.cleanup(); });

  for (const [table, update] of [['decisions', "UPDATE decisions SET recommended_action = 'allow'"], ['audit_records', "UPDATE audit_records SET ref_id = 'x'"], ['agent_events', "UPDATE agent_events SET kind = 'x'"]]) {
    test(`${table}: UPDATE, DELETE and TRUNCATE are all refused`, async () => {
      assert.equal(await code(db.pool.query(update)), FORBIDDEN, 'UPDATE');
      assert.equal(await code(db.pool.query(`DELETE FROM ${table}`)), FORBIDDEN, 'DELETE');
      assert.equal(await code(db.pool.query(`TRUNCATE ${table}`)), FORBIDDEN, 'TRUNCATE');
      assert.ok((await db.pool.query(`SELECT count(*) FROM ${table}`)).rows[0].count >= 1, 'rows must still be there');
    });
  }

  test('attestation_nonces: no deletes, no edits to immutable columns, consumption is one-way and happens at most once', async () => {
    const guard = new PgReplayGuard(db.pool);
    await guard.recordIssued({ nonce: 'nonce-ao', kind: 'callback_verified', accountId: 'acct-ao', caseId: 'c', iss: 'i', kid: 'k', method: 'm', statementSha256: 's', iat: Date.now(), exp: Date.now() + 60_000 });
    assert.equal(await code(db.pool.query("DELETE FROM attestation_nonces WHERE nonce = 'nonce-ao'")), FORBIDDEN);
    assert.equal(await code(db.pool.query("UPDATE attestation_nonces SET expires_at = expires_at + interval '1 day' WHERE nonce = 'nonce-ao'")), FORBIDDEN, 'expiry must not be extendable');
    assert.equal(await code(db.pool.query("UPDATE attestation_nonces SET account_id = 'other' WHERE nonce = 'nonce-ao'")), FORBIDDEN);
    assert.equal(await code(db.pool.query("UPDATE attestation_nonces SET consumed_event_id = 'e1' WHERE nonce = 'nonce-ao'")), '23514', 'consumed_event_id without consumed_at violates the pairing check');
    await db.pool.query("UPDATE attestation_nonces SET consumed_event_id = 'e1', consumed_at = now() WHERE nonce = 'nonce-ao'");
    assert.equal(await code(db.pool.query("UPDATE attestation_nonces SET consumed_event_id = 'e2', consumed_at = now() WHERE nonce = 'nonce-ao'")), FORBIDDEN, 'a second consumption (replay) must be impossible');
    assert.equal(await code(db.pool.query("UPDATE attestation_nonces SET consumed_event_id = NULL, consumed_at = NULL WHERE nonce = 'nonce-ao'")), FORBIDDEN, 'un-consuming must be impossible');
    assert.equal(await code(db.pool.query('TRUNCATE attestation_nonces')), FORBIDDEN);
  });
  test('the decision written earlier is intact after all of the above', async () => {
    const r = (await db.pool.query('SELECT recommended_action FROM decisions WHERE id = $1', [decisionId])).rows[0];
    assert.notEqual(r.recommended_action, 'allow');
  });
});
