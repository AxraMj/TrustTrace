// Offline: what happens when PostgreSQL is missing, unreachable or misconfigured. Nothing may pretend to work, nothing may leak
// the password, and every message must say what to do. Uses a real pool pointed at a closed port (connection refused) and
// real child processes for the CLIs/server.
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createPool, pingDb } from '../src/db/pool.js';
import { migrationStatus, runMigrations } from '../src/db/migrate.js';
import { PgReplayGuard } from '../src/db/replayGuard.js';
import { ActivityRecorder } from '../src/db/activity.js';
import { DecisionService } from '../src/app/decisionService.js';
import { FakeStore } from './helpers/fakeStore.js';
import { IdentitySecurityAgent } from '../src/agents/identityAgent.js';
import { makeTrust } from './helpers/trust.js';
import { pgUrl } from './helpers/fakeSecrets.js';

const DEAD = pgUrl('app', 'topsecretpw', '127.0.0.1:1/trusttrace'); // fake password; port 1: connection refused
const root = resolve('.');
const emptyCwd = mkdtempSync(join(tmpdir(), 'tt-nodotenv-')); // no .env here: the child sees only the env we pass
after(() => rmSync(emptyCwd, { recursive: true, force: true }));

const run = (script, env, args = []) => spawnSync(process.execPath, [join(root, script), ...args], {
  cwd: emptyCwd, env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, ...env }, encoding: 'utf8', timeout: 30_000,
});

describe('PostgreSQL unreachable (library level)', () => {
  const pool = createPool({ databaseUrl: DEAD }, { max: 2 });
  after(() => pool.end());

  test('pingDb reports down with an error CODE (no connection string)', async () => {
    const r = await pingDb(pool);
    assert.equal(r.ok, false);
    assert.ok(!JSON.stringify(r).includes('topsecretpw'));
  });
  test('migration status / run reject instead of pretending the schema exists', async () => {
    await assert.rejects(migrationStatus(pool));
    await assert.rejects(runMigrations(pool));
  });
  test('the replay ledger throws when the database is down (callers fail closed)', async () => {
    const g = new PgReplayGuard(pool);
    await assert.rejects(g.prepare(['n1']));
    await assert.rejects(g.commit([{ nonce: 'n1', kind: 'callback_verified', accountId: 'a', caseId: 'c', issuer: 'i', kid: 'k', iat: 1, exp: 2 }], 'e1'));
    await assert.rejects(g.recordIssued({ nonce: 'n', kind: 'callback_verified', accountId: 'a', caseId: 'c', iss: 'i', kid: 'k', iat: 1, exp: 2 }));
  });
  test('DecisionService does NOT swallow a database failure: the decision is not reported as persisted', async () => {
    const store = new FakeStore();
    const agent = new IdentitySecurityAgent(store, { verifier: makeTrust().verifier });
    const svc = new DecisionService({ pool, recorder: null, agent });
    await assert.rejects(svc.assessAndRecord({ type: 'login', accountId: 'acct-x', caseId: 'c' }));
  });
  test('an agent whose replay ledger is down fails CLOSED on single-use evidence (end to end with the real PgReplayGuard)', async () => {
    const store = new FakeStore();
    const t = makeTrust();
    await t.authority.record(store, { caseId: 'c', accountId: 'acct-1', runId: 'r', kind: 'callback_verified', method: 'callback_on_file', statement: 'Owner confirmed.' });
    const B = new IdentitySecurityAgent(store, { verifier: t.verifier, replayGuard: new PgReplayGuard(pool) });
    const r = await B.assess({ type: 'mfa_change', accountId: 'acct-1', newDevice: true, eventId: 'e1' });
    assert.deepEqual(r.verifiedFacts, []);
    assert.equal(r.rejectedEvidence[0].reason, 'replay_ledger_unavailable');
    assert.equal(r.replayLedger, 'unavailable');
  });
  test('the activity recorder keeps events and COUNTS failures when the database is down (visible, not silent)', async () => {
    const r = new ActivityRecorder(pool, { flushDelayMs: 60_000 });
    r.record({ agentId: 'a', kind: 'k' });
    await assert.rejects(r.flush());
    assert.equal(r.stats().failedBatches, 1);
    assert.equal(r.stats().queued, 1);
    assert.ok(!String(r.stats().lastError).includes('topsecretpw'));
    await r.close();
  });
});

describe('CLIs and server with missing / unreachable PostgreSQL', () => {
  test('server without DATABASE_URL: exits non-zero and explains the setup (docs/database.md)', () => {
    const r = run('src/server.js', {});
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /DATABASE_URL is not set/);
    assert.match(r.stderr, /docs\/database\.md/);
  });
  test('server with an unreachable database: exits non-zero, says it cannot connect, never prints the password', () => {
    const r = run('src/server.js', { DATABASE_URL: DEAD });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /cannot connect to PostgreSQL/);
    assert.ok(!(r.stdout + r.stderr).includes('topsecretpw'));
  });
  test('db:migrate and db:status fail clearly (and safely) when the database is unreachable', () => {
    for (const args of [[], ['--status']]) {
      const r = run('src/cli/dbMigrate.js', { DATABASE_URL: DEAD }, args);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /cannot connect to PostgreSQL/);
      assert.ok(!(r.stdout + r.stderr).includes('topsecretpw'));
    }
  });
  test('user:create validates BEFORE touching the database: weak password, bad role, missing username', () => {
    const base = { DATABASE_URL: DEAD };
    let r = run('src/cli/userCreate.js', { ...base, TRUSTTRACE_NEW_PASSWORD: 'short' }, ['--username', 'alice']);
    assert.notEqual(r.status, 0); assert.match(r.stderr, /at least 12/);
    r = run('src/cli/userCreate.js', { ...base, TRUSTTRACE_NEW_PASSWORD: 'a long enough passphrase 1' }, ['--username', 'alice', '--role', 'root']);
    assert.notEqual(r.status, 0); assert.match(r.stderr, /role must be/);
    r = run('src/cli/userCreate.js', { ...base, TRUSTTRACE_NEW_PASSWORD: 'a long enough passphrase 1' }, []);
    assert.notEqual(r.status, 0); assert.match(r.stderr, /usage/);
    r = run('src/cli/userCreate.js', base, ['--username', 'alice']);
    assert.notEqual(r.status, 0); assert.match(r.stderr, /TRUSTTRACE_NEW_PASSWORD/);
  });
  test('user:create never echoes the password, even on failure', () => {
    const pw = 'unique-password-marker-12345';
    const r = run('src/cli/userCreate.js', { DATABASE_URL: DEAD, TRUSTTRACE_NEW_PASSWORD: pw }, ['--username', 'alice']);
    assert.ok(!(r.stdout + r.stderr).includes(pw));
    assert.ok(!(r.stdout + r.stderr).includes('topsecretpw'));
  });
});
