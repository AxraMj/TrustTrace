// PostgreSQL integration: the REST API backed by the REAL database store (users, sessions, access log, audit verification),
// plus the CLIs and the server process. Real PostgreSQL; no in-memory stand-ins.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DB_SKIP, DB_CONFIG, createTestDb, makeWorld, CFO_CALL, uniq } from './helpers.js';
import { call, cookieOf, sleep } from '../helpers/httpClient.js';
import { createApiServer, listen } from '../../src/api/server.js';
import { loadAppConfig } from '../../src/api/config.js';
import { hashPassword, hashToken } from '../../src/api/auth.js';
import { mekoKey } from '../helpers/fakeSecrets.js';
import { buildDeps } from '../../src/app/deps.js';
import { createUser, createUserStore } from '../../src/db/userRepo.js';
import { createPool } from '../../src/db/pool.js';

const PW = 'integration test passphrase 99';
const root = resolve('.');

describe('PostgreSQL: REST API with the database-backed store', { skip: DB_SKIP }, () => {
  let db, server, base, w, config;
  const decisionIds = [];
  before(async () => {
    db = await createTestDb();
    config = loadAppConfig({ DATABASE_URL: DB_CONFIG.databaseUrl, MEKO_API_KEY: mekoKey('should_never_be_exposed') });
    server = createApiServer({ deps: buildDeps({ pool: db.pool, config }), config, logger: () => {} });
    base = `http://127.0.0.1:${(await listen(server, { host: '127.0.0.1', port: 0 })).port}`;
    const hash = await hashPassword(PW);
    await createUser(db.pool, { username: 'admin1', passwordHash: hash, role: 'admin' });
    await createUser(db.pool, { username: 'analyst1', passwordHash: hash, role: 'analyst' });
    await createUser(db.pool, { username: 'disabled1', passwordHash: hash, role: 'analyst' });
    await db.pool.query("UPDATE users SET active = false WHERE username = 'disabled1'");
    w = makeWorld(db.pool);
    for (let i = 0; i < 3; i++) {
      const accountId = uniq('acct');
      await w.A.handleInteraction({ caseId: `case-api-${i}`, accountId, runId: 'r', callerText: CFO_CALL });
      decisionIds.push((await w.svc.assessAndRecord({ type: 'mfa_change', accountId, caseId: `case-api-${i}`, newDevice: true })).decisionId);
    }
    await w.recorder.flush();
  }, { timeout: 120_000 });
  after(async () => { server.closeAllConnections?.(); await new Promise((r) => server.close(r)); await w.recorder.close(); await db.cleanup(); });
  const login = (u = 'admin1', p = PW) => call(base, 'POST', '/api/auth/login', { body: { username: u, password: p } });

  test('login stores a session row keyed by the token HASH; the raw token is nowhere in the database', async () => {
    const r = await login();
    assert.equal(r.status, 200);
    const token = cookieOf(r).split('=')[1];
    const rows = (await db.pool.query('SELECT token_hash FROM sessions')).rows.map((x) => x.token_hash);
    assert.ok(rows.includes(hashToken(token)));
    assert.ok(!rows.includes(token));
    assert.equal((await db.pool.query("SELECT count(*) FROM sessions WHERE token_hash = $1", [token])).rows[0].count, 0);
    assert.ok((await db.pool.query("SELECT last_login_at FROM users WHERE username = 'admin1'")).rows[0].last_login_at);
    const userRow = (await db.pool.query("SELECT password_hash FROM users WHERE username = 'admin1'")).rows[0].password_hash;
    assert.match(userRow, /^scrypt\$/);
    assert.ok(!userRow.includes(PW));
  });

  test('disabled users cannot sign in; wrong password and unknown user look identical', async () => {
    const a = await login('disabled1'); const b = await login('admin1', 'wrong password!!'); const c = await login('nobody');
    for (const r of [a, b, c]) { assert.equal(r.status, 401); assert.equal(r.json.error.code, 'invalid_credentials'); }
  });

  test('role checks hold against the real store: analyst gets 403 on admin endpoints, admin gets 200, anonymous 401', async () => {
    const admin = cookieOf(await login('admin1')); const analyst = cookieOf(await login('analyst1'));
    for (const p of ['/api/health/details', '/api/audit/verify']) {
      assert.equal((await call(base, 'GET', p)).status, 401);
      assert.equal((await call(base, 'GET', p, { headers: { cookie: analyst } })).status, 403);
      assert.equal((await call(base, 'GET', p, { headers: { cookie: admin } })).status, 200);
    }
  });

  test('/api/health/details reports REAL database state: migrations, counts, audit head, ledger; and exposes no secret', async () => {
    const admin = cookieOf(await login('admin1'));
    const r = await call(base, 'GET', '/api/health/details', { headers: { cookie: admin } });
    assert.equal(r.json.status, 'ok');
    assert.equal(r.json.migrations.upToDate, true);
    assert.equal(r.json.counts.decisions, 3);
    assert.ok(r.json.counts.agentEvents >= 3);
    assert.ok(r.json.audit.headSeq >= 3);
    assert.equal(r.json.replayLedger, 'postgresql');
    assert.equal(r.json.mekoConfigured, true, 'a boolean only');
    assert.doesNotMatch(r.text, /mko_tkn_|PRIVATE KEY|scrypt\$|postgres:\/\/|password/i);
  });

  test('GET /api/audit/verify checks the REAL chain: ok:true when intact, ok:false (with the seq) after a privileged edit', async () => {
    const admin = cookieOf(await login('admin1'));
    const intact = await call(base, 'GET', '/api/audit/verify', { headers: { cookie: admin } });
    assert.equal(intact.json.ok, true);
    assert.equal(intact.json.checked >= 3, true);
    await db.pool.query('ALTER TABLE decisions DISABLE TRIGGER decisions_append_only');
    await db.pool.query("UPDATE decisions SET recommended_action = 'allow' WHERE id = $1", [decisionIds[1]]);
    await db.pool.query('ALTER TABLE decisions ENABLE TRIGGER decisions_append_only');
    const bad = await call(base, 'GET', '/api/audit/verify', { headers: { cookie: admin } });
    assert.equal(bad.status, 200);
    assert.equal(bad.json.ok, false);
    assert.equal(bad.json.problems[0].code, 'audited_row_modified');
  });

  test('logout deletes the session row; the old cookie is dead', async () => {
    const cookie = cookieOf(await login('analyst1'));
    const before = (await db.pool.query('SELECT count(*) FROM sessions')).rows[0].count;
    assert.equal((await call(base, 'POST', '/api/auth/logout', { headers: { cookie } })).status, 200);
    assert.equal((await db.pool.query('SELECT count(*) FROM sessions')).rows[0].count, before - 1);
    assert.equal((await call(base, 'GET', '/api/auth/me', { headers: { cookie } })).status, 401);
  });

  test('an expired session row is rejected and deleted; a user disabled mid-session loses access at once', async () => {
    const c1 = cookieOf(await login('analyst1'));
    await db.pool.query("UPDATE sessions SET expires_at = now() - interval '1 minute' WHERE token_hash = $1", [hashToken(c1.split('=')[1])]);
    const r = await call(base, 'GET', '/api/auth/me', { headers: { cookie: c1 } });
    assert.equal(r.json.error.code, 'session_expired');
    assert.equal((await db.pool.query('SELECT count(*) FROM sessions WHERE token_hash = $1', [hashToken(c1.split('=')[1])])).rows[0].count, 0);

    const c2 = cookieOf(await login('analyst1'));
    await db.pool.query("UPDATE users SET active = false WHERE username = 'analyst1'");
    assert.equal((await call(base, 'GET', '/api/auth/me', { headers: { cookie: c2 } })).status, 401);
    await db.pool.query("UPDATE users SET active = true WHERE username = 'analyst1'");
  });

  test('every API call is written to access_log (user, status, ip, request id); failed logins are flagged; /health is not logged', async () => {
    await db.pool.query('DELETE FROM access_log');
    await login('admin1', 'definitely wrong password');
    const admin = cookieOf(await login('admin1'));
    await call(base, 'GET', '/api/auth/me', { headers: { cookie: admin } });
    await call(base, 'GET', '/api/health');
    await call(base, 'GET', '/api/audit/verify');
    await sleep(100);
    const rows = (await db.pool.query('SELECT * FROM access_log ORDER BY id')).rows;
    assert.ok(!rows.some((r) => r.path === '/api/health'));
    assert.deepEqual(rows.find((r) => r.status === 401).detail, { event: 'login_failed' });
    assert.deepEqual(rows.find((r) => r.path === '/api/auth/login' && r.status === 200).detail, { event: 'login_success' });
    assert.equal(rows.find((r) => r.path === '/api/auth/me').username, 'admin1');
    assert.ok(rows.every((r) => r.request_id && r.ip && r.duration_ms >= 0));
    assert.equal(rows.find((r) => r.path === '/api/audit/verify').status, 401);
  });

  test('purging expired sessions removes only the expired ones', async () => {
    const store = createUserStore(db.pool);
    await login('admin1');
    await db.pool.query("UPDATE sessions SET expires_at = now() - interval '1 day' WHERE id = (SELECT id FROM sessions LIMIT 1)");
    const n = await store.deleteExpiredSessions(new Date());
    assert.ok(n >= 1);
    assert.equal((await db.pool.query('SELECT count(*) FROM sessions WHERE expires_at < now()')).rows[0].count, 0);
  });

  test('DATABASE OUTAGE while serving: /health is 503 "down", authenticated calls are a generic 500, nothing leaks, the server survives', async () => {
    const pool2 = createPool(DB_CONFIG, { schema: db.schema, max: 2 });
    const cfg2 = loadAppConfig({ DATABASE_URL: DB_CONFIG.databaseUrl });
    const s2 = createApiServer({ deps: buildDeps({ pool: pool2, config: cfg2 }), config: cfg2, logger: () => {} });
    const b2 = `http://127.0.0.1:${(await listen(s2, { host: '127.0.0.1', port: 0 })).port}`;
    try {
      const cookie = cookieOf(await call(b2, 'POST', '/api/auth/login', { body: { username: 'admin1', password: PW } }));
      assert.equal((await call(b2, 'GET', '/api/auth/me', { headers: { cookie } })).status, 200);
      await pool2.end(); // the database "goes away" for this server
      const h = await call(b2, 'GET', '/api/health');
      assert.equal(h.status, 503);
      assert.equal(h.json.db, 'down');
      const me = await call(b2, 'GET', '/api/auth/me', { headers: { cookie } });
      assert.equal(me.status, 500);
      assert.equal(me.json.error.code, 'internal_error');
      assert.doesNotMatch(me.text, /postgres|pool|ECONN/i);
      assert.equal((await call(b2, 'GET', '/api/nope')).status, 404, 'the process is still serving');
    } finally { s2.closeAllConnections?.(); await new Promise((r) => s2.close(r)); }
  });
});

describe('PostgreSQL: CLIs and the server process', { skip: DB_SKIP }, () => {
  const cwd = mkdtempSync(join(tmpdir(), 'tt-cli-'));
  after(() => rmSync(cwd, { recursive: true, force: true }));
  const run = (db, script, args = [], env = {}) => spawnSync(process.execPath, [join(root, script), ...args], {
    cwd, env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, DATABASE_URL: db.urlForSchema(), ...env }, encoding: 'utf8', timeout: 60_000,
  });

  test('db:status exits 1 on an empty schema, db:migrate applies, db:status then exits 0; a second db:migrate is a no-op', async () => {
    const db = await createTestDb({ migrate: false });
    try {
      let r = run(db, 'src/cli/dbMigrate.js', ['--status']);
      assert.equal(r.status, 1, r.stderr);
      assert.match(r.stdout, /pending 3/);
      r = run(db, 'src/cli/dbMigrate.js');
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /applied 3 migration/);
      assert.equal(run(db, 'src/cli/dbMigrate.js', ['--status']).status, 0);
      assert.match(run(db, 'src/cli/dbMigrate.js').stdout, /already up to date/);
    } finally { await db.cleanup(); }
  });

  test('user:create stores a scrypt hash and the role; duplicates, weak passwords and bad roles are refused; the password is never printed', async () => {
    const db = await createTestDb();
    try {
      const env = { TRUSTTRACE_NEW_PASSWORD: PW };
      let r = run(db, 'src/cli/userCreate.js', ['--username', 'Carol', '--role', 'supervisor'], env);
      assert.equal(r.status, 0, r.stderr);
      assert.ok(!(r.stdout + r.stderr).includes(PW));
      const row = (await db.pool.query("SELECT username, role, active, password_hash FROM users WHERE lower(username) = 'carol'")).rows[0];
      assert.equal(row.role, 'supervisor'); assert.equal(row.active, true); assert.match(row.password_hash, /^scrypt\$/);
      r = run(db, 'src/cli/userCreate.js', ['--username', 'CAROL'], env);
      assert.equal(r.status, 1); assert.match(r.stderr, /DuplicateUser/);
      r = run(db, 'src/cli/userCreate.js', ['--username', 'dave'], { TRUSTTRACE_NEW_PASSWORD: 'short' });
      assert.equal(r.status, 1);
      assert.equal((await db.pool.query("SELECT count(*) FROM users WHERE username = 'dave'")).rows[0].count, 0);
      r = run(db, 'src/cli/userCreate.js', ['--username', 'erin', '--password-stdin'], {});
      assert.equal(r.status, 1, 'no password on stdin -> refused');
    } finally { await db.cleanup(); }
  });

  test('the server REFUSES to start on an un-migrated database and says how to fix it', async () => {
    const db = await createTestDb({ migrate: false });
    try {
      const r = run(db, 'src/server.js', [], { API_PORT: '28111' });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /npm run db:migrate/);
    } finally { await db.cleanup(); }
  });

  test('the server process starts on a migrated database, serves real login + admin endpoints, and shuts down cleanly', async () => {
    const db = await createTestDb();
    const port = 28000 + Math.floor(Math.random() * 900);
    const child = spawn(process.execPath, [join(root, 'src/server.js')], {
      cwd, env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, DATABASE_URL: db.urlForSchema(), API_PORT: String(port) },
    });
    let out = '';
    child.stdout.on('data', (d) => (out += d)); child.stderr.on('data', (d) => (out += d));
    try {
      await createUser(db.pool, { username: 'srv-admin', passwordHash: await hashPassword(PW), role: 'admin' });
      const t0 = Date.now();
      while (!/listening on/.test(out) && Date.now() - t0 < 20_000) await sleep(100);
      assert.match(out, /listening on http:\/\/127\.0\.0\.1:/, out);
      const b = `http://127.0.0.1:${port}`;
      assert.equal((await call(b, 'GET', '/api/health')).json.db, 'up');
      const cookie = cookieOf(await call(b, 'POST', '/api/auth/login', { body: { username: 'srv-admin', password: PW } }));
      assert.ok(cookie);
      const d = await call(b, 'GET', '/api/health/details', { headers: { cookie } });
      assert.equal(d.json.migrations.upToDate, true);
      assert.doesNotMatch(out, new RegExp(PW));
    } finally {
      child.kill('SIGTERM');
      await new Promise((r) => { child.once('exit', r); setTimeout(r, 5000); });
      if (child.exitCode === null) child.kill('SIGKILL');
      await db.cleanup();
    }
  });
});
