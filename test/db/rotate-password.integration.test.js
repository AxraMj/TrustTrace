// PostgreSQL integration: the password-rotation script against REAL tables, the real scrypt hasher and the real production login API.
// Runs in a throw-away schema; nothing here touches any real database. The terminal is simulated, so the generated password can be
// captured by the test (the real script shows it only on an interactive terminal).
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { DB_SKIP, DB_CONFIG, createTestDb } from './helpers.js';
import { PASSWORD_SHAPE, rotatePassword, verifyLoginViaApi } from '../../scripts/rotate-user-password.mjs';
import { hashPassword, hashToken, validatePassword, verifyPassword } from '../../src/api/auth.js';
import { createUser } from '../../src/db/userRepo.js';

const OLD = 'old judge passphrase 42!';
const imp = (p) => import(pathToFileURL(resolve(p)).href);

describe('rotate-user-password on real PostgreSQL', { skip: DB_SKIP }, () => {
  let db;
  before(async () => {
    db = await createTestDb();
    await createUser(db.pool, { username: 'judge', passwordHash: await hashPassword(OLD), role: 'supervisor' });
    await createUser(db.pool, { username: 'analyst1', passwordHash: await hashPassword('analyst passphrase 7!'), role: 'analyst' });
    await createUser(db.pool, { username: 'boss', passwordHash: await hashPassword('boss passphrase 9!'), role: 'admin' });
    const judge = (await db.pool.query(`SELECT id FROM users WHERE username = 'judge'`)).rows[0];
    await db.pool.query(`INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, now() + interval '1 hour')`, [judge.id, hashToken('existing-session-token')]);
  });
  after(async () => { await db?.cleanup(); });

  const snapshot = async () => JSON.stringify({
    users: (await db.pool.query('SELECT * FROM users ORDER BY username')).rows,
    sessions: (await db.pool.query('SELECT * FROM sessions ORDER BY id')).rows,
    access_log: (await db.pool.query('SELECT count(*)::int AS n FROM access_log')).rows,
  });
  function terminal({ confirm = true } = {}) {
    const log = []; let shown = null;
    return {
      log, shown: () => shown,
      io: {
        isTTY: true,
        print: (t) => log.push(['print', String(t)]),
        printSecret: (t) => { log.push(['secret', String(t)]); shown = String(t).match(/[A-HJ-NP-Za-km-np-z2-9]{4}(-[A-HJ-NP-Za-km-np-z2-9]{4}){5}/)?.[0]; },
        prompt: async () => (confirm ? shown : 'something else'),
        clear: () => log.push(['clear']),
      },
    };
  }
  const args = (t, extra = {}) => ({ pool: db.pool, username: 'judge', io: t.io, hashPassword, verifyPassword, validatePassword, ...extra });

  test('dry run: the whole database is byte-for-byte unchanged and no password is generated for use', async () => {
    const before = await snapshot();
    const t = terminal();
    const r = await rotatePassword(args(t));
    assert.equal(r.dryRun, true);
    assert.equal(await snapshot(), before);
    assert.equal(t.log.filter(([k]) => k === 'secret').length, 0);
  });

  test('a wrong confirmation changes nothing at all', async () => {
    const before = await snapshot();
    const t = terminal({ confirm: false });
    await assert.rejects(rotatePassword(args(t, { execute: true })), /not confirmed/);
    assert.equal(await snapshot(), before);
  });

  test('refuses to touch an admin (wrong role for this account) and leaves everything unchanged', async () => {
    const before = await snapshot();
    const t = terminal();
    await assert.rejects(rotatePassword(args(t, { execute: true, username: 'boss' })), /role "admin"/);
    assert.equal(await snapshot(), before);
    assert.equal(t.log.filter(([k]) => k === 'secret').length, 0, 'no password was shown for a refused target');
  });

  test('the script\'s own update changes ONLY judge.password_hash: every other column of every row, all sessions and the access log are identical', async () => {
    const beforeUsers = (await db.pool.query('SELECT * FROM users ORDER BY username')).rows;
    const before = await snapshot();
    const t = terminal();
    const r = await rotatePassword(args(t, { execute: true })); // no login check here, so there are no login side effects to account for
    assert.equal(r.changed, true);
    const afterUsers = (await db.pool.query('SELECT * FROM users ORDER BY username')).rows;
    assert.equal(afterUsers.length, beforeUsers.length);
    for (const b of beforeUsers) {
      const a = afterUsers.find((x) => x.id === b.id);
      if (b.username === 'judge') {
        assert.notEqual(a.password_hash, b.password_hash);
        assert.deepEqual({ ...a, password_hash: 0 }, { ...b, password_hash: 0 }, 'all other judge columns identical, including last_login_at');
      } else assert.deepEqual(a, b);
    }
    const afterSnap = JSON.parse(await snapshot()); const beforeSnap = JSON.parse(before);
    assert.deepEqual(afterSnap.sessions, beforeSnap.sessions); assert.deepEqual(afterSnap.access_log, beforeSnap.access_log);
  });

  test('real rotation with the login check: the new password signs in through the production API; the old one no longer works', async () => {
    const beforeRows = (await db.pool.query('SELECT * FROM users ORDER BY username')).rows;
    const sessionsBefore = (await db.pool.query('SELECT * FROM sessions ORDER BY id')).rows;
    const t = terminal();
    const verifyLogin = await verifyLoginViaApi({ pool: db.pool, config: DB_CONFIG, username: 'judge', expectRole: 'supervisor', imp });
    const r = await rotatePassword(args(t, { execute: true, verifyLogin }));
    assert.equal(r.ok, true, t.log.map((l) => l.join(' ')).join('\n'));
    const pw = t.shown();
    assert.match(pw, PASSWORD_SHAPE);

    const afterRows = (await db.pool.query('SELECT * FROM users ORDER BY username')).rows;
    assert.equal(afterRows.length, beforeRows.length, 'no user was created or deleted');
    for (const b of beforeRows) {
      const a = afterRows.find((x) => x.id === b.id);
      if (b.username === 'judge') {
        assert.notEqual(a.password_hash, b.password_hash, 'the judge hash changed');
        // the production login used for verification legitimately sets last_login_at; everything else must be identical
        assert.deepEqual({ ...a, password_hash: 0, last_login_at: 0 }, { ...b, password_hash: 0, last_login_at: 0 }, 'every other judge column is identical (role, username, active, created_at, ...)');
        assert.ok(a.last_login_at, 'the verification login set last_login_at (documented side effect)');
        assert.equal(await verifyPassword(pw, a.password_hash), true);
        assert.equal(await verifyPassword(OLD, a.password_hash), false, 'the old password is dead');
        assert.match(a.password_hash, /^scrypt\$/); assert.ok(!a.password_hash.includes(pw));
      } else {
        assert.deepEqual(a, b, `${b.username} is byte-identical`);
      }
    }
    assert.deepEqual((await db.pool.query('SELECT * FROM sessions ORDER BY id')).rows, sessionsBefore, 'existing sessions are untouched');
    assert.equal((await db.pool.query(`SELECT count(*)::int AS n FROM users WHERE role = 'admin'`)).rows[0].n, 1, 'still exactly the one pre-existing admin');

    // the password appears only on the one secret line; the clear happens after the confirmation
    const holders = t.log.filter((entry) => JSON.stringify(entry).includes(pw));
    assert.equal(holders.length, 1); assert.equal(holders[0][0], 'secret');
    const kinds = t.log.map(([k]) => k);
    assert.ok(kinds.indexOf('secret') < kinds.indexOf('clear'));
    const verdicts = t.log.filter(([k, text]) => k === 'print' && /^(PASS|FAIL)/.test(text)).map(([, text]) => text);
    assert.ok(verdicts.length >= 7 && verdicts.every((v) => v.startsWith('PASS')), verdicts.join('\n'));
    assert.match(t.log.at(-1)[1], /ROTATION COMPLETE/);
  });

  test('rotating twice works and each rotation invalidates the previous password', async () => {
    const t1 = terminal(); await rotatePassword(args(t1, { execute: true })); const first = t1.shown();
    const t2 = terminal(); await rotatePassword(args(t2, { execute: true })); const second = t2.shown();
    assert.notEqual(first, second);
    const hash = (await db.pool.query(`SELECT password_hash FROM users WHERE username = 'judge'`)).rows[0].password_hash;
    assert.equal(await verifyPassword(second, hash), true);
    assert.equal(await verifyPassword(first, hash), false);
  });
});
