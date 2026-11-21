// Offline: the password-rotation script. A TEST DOUBLE pool and terminal record every query and every line shown, so we can prove what the
// script does and, above all, what it never does (write in dry run, show the password anywhere but the one secret line, touch other rows).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { generatePassword, PASSWORD_SHAPE, rotatePassword } from '../scripts/rotate-user-password.mjs';
import { hashPassword, validatePassword, verifyPassword } from '../src/api/auth.js';
import { pgUrl } from './helpers/fakeSecrets.js';

const OLD_HASH = 'scrypt$old$hash$value';
const USER = () => ({ id: '11111111-1111-4111-8111-111111111111', username: 'judge', role: 'supervisor', active: true, created_at: new Date('2026-11-21T10:00:00Z'), password_hash: OLD_HASH });

/** TEST DOUBLE: a scripted pool + terminal sharing one timeline. */
function world({ user = USER(), others = [], total = 1, admins = 0, sessions = 0, updateRowCount = 1, lockRows = 1, postRole, isTTY = true, typed } = {}) {
  const timeline = []; const state = { user: { ...user } };
  const pool = {
    async query(sql, params = []) {
      const s = sql.replace(/\s+/g, ' ').trim();
      timeline.push({ kind: 'sql', sql: s, params });
      if (/^BEGIN|^COMMIT|^ROLLBACK/.test(s)) return { rows: [], rowCount: 0 };
      if (/FROM users WHERE lower\(username\)/.test(s)) return { rows: [{ ...state.user }], rowCount: 1 };
      if (/FROM users WHERE id = \$1$/.test(s)) return { rows: [{ ...state.user, ...(postRole ? { role: postRole } : {}) }], rowCount: 1 };
      if (/count\(\*\)::int AS total/.test(s)) return { rows: [{ total, admins }] };
      if (/FROM sessions/.test(s)) return { rows: [{ n: sessions }] };
      if (/FOR UPDATE/.test(s)) return { rows: Array.from({ length: lockRows }, () => ({ id: user.id })) };
      if (/^UPDATE users SET password_hash/.test(s)) { if (updateRowCount === 1) state.user.password_hash = params[0]; return { rows: [], rowCount: updateRowCount }; }
      throw new Error(`unexpected SQL in test double: ${s}`);
    },
  };
  let shown = null; let answers = 0;
  const io = {
    isTTY,
    print: (t) => timeline.push({ kind: 'print', text: String(t) }),
    printSecret: (t) => { timeline.push({ kind: 'secret', text: String(t) }); shown = String(t).match(/[A-HJ-NP-Za-km-np-z2-9]{4}(-[A-HJ-NP-Za-km-np-z2-9]{4}){5}/)?.[0] ?? null; },
    prompt: async () => { timeline.push({ kind: 'prompt' }); const a = typed ? typed(shown, answers++) : shown; return a; },
    clear: () => timeline.push({ kind: 'clear' }),
  };
  return { pool, io, timeline, state, shownPassword: () => shown };
}
const base = (w, extra = {}) => ({ pool: w.pool, username: 'judge', io: w.io, hashPassword, verifyPassword, validatePassword, ...extra });
const writes = (w) => w.timeline.filter((e) => e.kind === 'sql' && /^(BEGIN|COMMIT|ROLLBACK|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE)/.test(e.sql));
const idx = (w, pred) => w.timeline.findIndex(pred);

describe('generatePassword', () => {
  test('24 random characters in six groups of four, from an alphabet with no look-alike characters', () => {
    for (let i = 0; i < 500; i++) { const p = generatePassword(); assert.match(p, PASSWORD_SHAPE); assert.equal(p.length, 29); assert.doesNotMatch(p.replaceAll('-', ''), /[IlOo01]/); validatePassword(p); }
  });
  test('no repeats across 20000 passwords (a broken RNG would collide), and all 56 symbols of the alphabet show up', () => {
    const seen = new Set(); const symbols = new Set();
    for (let i = 0; i < 20000; i++) { const p = generatePassword(); assert.ok(!seen.has(p)); seen.add(p); for (const ch of p.replaceAll('-', '')) symbols.add(ch); }
    assert.equal(symbols.size, 56);
    assert.ok(24 * Math.log2(symbols.size) > 139, 'at least 139 bits of entropy');
  });
  test('symbols are used evenly (no modulo bias): each of the 56 symbols is within 15% of the expected count over 240k draws', () => {
    const counts = new Map(); let n = 0;
    for (let i = 0; i < 10000; i++) for (const ch of generatePassword().replaceAll('-', '')) { counts.set(ch, (counts.get(ch) ?? 0) + 1); n++; }
    const expected = n / 56;
    for (const [ch, c] of counts) assert.ok(Math.abs(c - expected) / expected < 0.15, `${ch}: ${c} vs ~${Math.round(expected)}`);
  });
});

describe('dry run (the default)', () => {
  test('only read-only queries; no BEGIN, no UPDATE; no password is shown; nothing is changed', async () => {
    const w = world();
    const r = await rotatePassword(base(w));
    assert.equal(r.dryRun, true); assert.equal(r.changed, false);
    assert.equal(writes(w).length, 0, 'a dry run must not write');
    assert.ok(w.timeline.filter((e) => e.kind === 'sql').every((e) => /^SELECT/.test(e.sql)));
    assert.equal(w.timeline.filter((e) => e.kind === 'secret' || e.kind === 'prompt' || e.kind === 'clear').length, 0);
    assert.ok(!w.timeline.some((e) => e.kind === 'print' && PASSWORD_SHAPE.test(e.text.trim())), 'no password-shaped text is printed');
    assert.equal(w.state.user.password_hash, OLD_HASH);
    const text = w.timeline.filter((e) => e.kind === 'print').map((e) => e.text).join('\n');
    assert.match(text, /DRY RUN/); assert.match(text, /self-test: password generator OK/); assert.match(text, /UPDATE users SET password_hash = \$1 WHERE id = \$2/);
  });
  test('works without a terminal (it shows nothing sensitive)', async () => { await rotatePassword(base(world({ isTTY: false }))); });
});

describe('execute', () => {
  test('refuses without an interactive terminal, before running a single query', async () => {
    const w = world({ isTTY: false });
    await assert.rejects(rotatePassword(base(w, { execute: true })), /interactive terminal/);
    assert.equal(w.timeline.filter((e) => e.kind === 'sql').length, 0);
    assert.equal(w.timeline.filter((e) => e.kind === 'secret').length, 0);
  });

  test('happy path: show once -> confirm -> clear -> ONE locked update of password_hash on the one user -> verify', async () => {
    const w = world({ sessions: 2, others: [] });
    let verifiedWith = null;
    const r = await rotatePassword(base(w, { execute: true, verifyLogin: async (pw) => { verifiedWith = pw; return [['login with the new password', true]]; } }));
    const pw = w.shownPassword();
    assert.equal(r.ok, true); assert.equal(r.changed, true);
    assert.match(pw, PASSWORD_SHAPE);
    // the password appears in exactly one call (the secret) and nowhere else, not even in later prints or SQL parameters
    const holders = w.timeline.filter((e) => JSON.stringify(e).includes(pw));
    assert.equal(holders.length, 1); assert.equal(holders[0].kind, 'secret');
    assert.equal(verifiedWith, pw, 'the login check receives the same password');
    // exactly one write statement set: BEGIN, SELECT .. FOR UPDATE, UPDATE, COMMIT
    const w2 = writes(w).map((e) => e.sql.split(' ')[0]);
    assert.deepEqual(w2, ['BEGIN', 'UPDATE', 'COMMIT']);
    const update = w.timeline.find((e) => e.kind === 'sql' && /^UPDATE/.test(e.sql));
    assert.equal(update.sql, 'UPDATE users SET password_hash = $1 WHERE id = $2');
    assert.equal(update.params[1], USER().id); assert.equal(update.params.length, 2);
    assert.ok(update.params[0].startsWith('scrypt$') && !update.params[0].includes(pw));
    assert.equal(await verifyPassword(pw, update.params[0]), true, 'the stored hash verifies the new password');
    assert.equal(await verifyPassword('nope', update.params[0]), false);
    // ordering: secret shown, then confirmation, then the screen is cleared, and only THEN the database is touched
    const iSecret = idx(w, (e) => e.kind === 'secret'); const iPrompt = idx(w, (e) => e.kind === 'prompt'); const iClear = idx(w, (e) => e.kind === 'clear'); const iBegin = idx(w, (e) => e.kind === 'sql' && e.sql === 'BEGIN');
    assert.ok(iSecret < iPrompt && iPrompt < iClear && iClear < iBegin, `order: ${[iSecret, iPrompt, iClear, iBegin]}`);
    assert.match(w.timeline.filter((e) => e.kind === 'print').map((e) => e.text).join('\n'), /sessions for this user: 2/, 'existing sessions are reported, not touched');
    assert.ok(!w.timeline.some((e) => e.kind === 'sql' && /sessions/.test(e.sql) && !/^SELECT/.test(e.sql)), 'sessions are never modified');
  });

  test('a wrong confirmation three times leaves the database untouched (a password you did not receive is never stored)', async () => {
    const w = world({ typed: () => 'not the password' });
    await assert.rejects(rotatePassword(base(w, { execute: true })), /not confirmed/);
    assert.equal(writes(w).length, 0); assert.equal(w.timeline.filter((e) => e.kind === 'prompt').length, 3);
    assert.equal(w.state.user.password_hash, OLD_HASH);
    assert.ok(!w.timeline.filter((e) => e.kind === 'print').some((e) => PASSWORD_SHAPE.test(e.text)), 'the failure messages do not echo the password');
  });
  test('a correct confirmation on the second attempt is accepted', async () => {
    const w = world({ typed: (pw, n) => (n === 0 ? 'typo' : `  ${pw}  `) });
    const r = await rotatePassword(base(w, { execute: true }));
    assert.equal(r.changed, true); assert.equal(w.timeline.filter((e) => e.kind === 'prompt').length, 2);
  });

  for (const [name, opts, pattern] of [
    ['an admin user', { user: { ...USER(), role: 'admin' } }, /role "admin"/],
    ['an analyst user', { user: { ...USER(), role: 'analyst' } }, /role "analyst"/],
    ['an inactive user', { user: { ...USER(), active: false } }, /not active/],
  ]) {
    test(`refuses ${name} before showing anything`, async () => {
      const w = world(opts);
      await assert.rejects(rotatePassword(base(w, { execute: true })), pattern);
      assert.equal(writes(w).length, 0); assert.equal(w.timeline.filter((e) => e.kind === 'secret').length, 0);
    });
  }
  test('refuses when the user does not exist (it never creates one)', async () => {
    const w = world(); w.pool.query = async (sql) => { w.timeline.push({ kind: 'sql', sql: sql.replace(/\s+/g, ' ').trim(), params: [] }); return { rows: [], rowCount: 0 }; };
    await assert.rejects(rotatePassword(base(w, { execute: true })), /exactly one user named "judge", found 0/);
    assert.equal(writes(w).length, 0);
  });

  test('if the update does not affect exactly one row it ROLLS BACK and fails (no COMMIT)', async () => {
    const w = world({ updateRowCount: 0 });
    await assert.rejects(rotatePassword(base(w, { execute: true })), /0 rows instead of 1/);
    const verbs = writes(w).map((e) => e.sql.split(' ')[0]);
    assert.deepEqual(verbs, ['BEGIN', 'UPDATE', 'ROLLBACK']);
    assert.equal(w.state.user.password_hash, OLD_HASH);
  });
  test('if the row cannot be locked (changed meanwhile) it rolls back before updating', async () => {
    const w = world({ lockRows: 0 });
    await assert.rejects(rotatePassword(base(w, { execute: true })), /changed while the script was running/);
    assert.ok(!w.timeline.some((e) => e.kind === 'sql' && /^UPDATE/.test(e.sql)));
    assert.deepEqual(writes(w).map((e) => e.sql.split(' ')[0]), ['BEGIN', 'ROLLBACK']);
  });
  test('errors raised after the password was shown never contain it', async () => {
    const w = world();
    let leaked = null;
    await assert.rejects(rotatePassword(base(w, { execute: true, verifyLogin: async (pw) => { leaked = pw; throw new Error(`boom while using ${pw}`); } })), (err) => { assert.ok(!err.message.includes(leaked), err.message); assert.match(err.message, /<redacted>/); return true; });
  });
  test('a failed post-condition or login check is reported as FAIL and not as success', async () => {
    const w = world({ postRole: 'admin' });
    const r = await rotatePassword(base(w, { execute: true, verifyLogin: async () => [['login works', false]] }));
    assert.equal(r.ok, false);
    const text = w.timeline.filter((e) => e.kind === 'print').map((e) => e.text).join('\n');
    assert.match(text, /FAIL {2}only the password hash changed/); assert.match(text, /FAIL {2}login works/); assert.match(text, /A CHECK FAILED/); assert.doesNotMatch(text, /ROTATION COMPLETE/);
  });
});

describe('command line (real child processes, no database needed)', () => {
  const script = resolve('scripts/rotate-user-password.mjs');
  const run = (args, env = {}) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', env: { ...process.env, ...env }, cwd: resolve('.'), timeout: 30_000 });
  const DEAD = pgUrl('app', 'FakeSecretPw-9x7q2', '127.0.0.1:1/trusttrace');
  test('no arguments: usage, exit 2', () => { const r = run([]); assert.equal(r.status, 2); assert.match(r.stderr, /usage/); });
  test('--username without --expect-host is refused (the target must be named explicitly)', () => { const r = run(['--username', 'judge']); assert.equal(r.status, 2); });
  test('--execute without a terminal is refused immediately (exit 3), so a pipe, a log or an assistant can never capture the password', () => {
    const r = run(['--username', 'judge', '--expect-host', '127.0.0.1', '--execute'], { DATABASE_URL: DEAD });
    assert.equal(r.status, 3); assert.match(r.stderr, /interactive terminal/); assert.equal(r.stdout.includes('NEW PASSWORD'), false);
  });
  test('a database host that does not match --expect-host is refused (exit 4) before any connection', () => {
    const r = run(['--username', 'judge', '--expect-host', 'ep-some-other-endpoint'], { DATABASE_URL: DEAD });
    assert.equal(r.status, 4); assert.match(r.stderr, /does not start with --expect-host/);
  });
  test('an unreachable database fails cleanly without leaking the connection string or password', () => {
    const r = run(['--username', 'judge', '--expect-host', '127.0.0.1'], { DATABASE_URL: DEAD });
    assert.equal(r.status, 1);
    const all = r.stdout + r.stderr;
    for (const s of ['FakeSecretPw-9x7q2', 'postgres://']) assert.ok(!all.includes(s), `leaked ${s}`);
  });
});

describe('scripts/dns-fallback.cjs (operator-only preload)', () => {
  const preload = resolve('scripts/dns-fallback.cjs');
  const probe = (host) => spawnSync(process.execPath, ['--require', preload, '-e', `require('node:dns').lookup(${JSON.stringify(host)}, (e, a) => console.log(JSON.stringify({ code: e?.code ?? null, address: a ?? null })))`], { encoding: 'utf8', timeout: 30_000 });
  test('hosts that are not *.neon.tech behave exactly as before', () => {
    assert.equal(JSON.parse(probe('localhost').stdout.trim()).code, null);
    assert.equal(JSON.parse(probe('does-not-exist.invalid').stdout.trim()).code, 'ENOTFOUND');
  });
  test('it only mentions neon.tech and the one public resolver it falls back to (no other hosts, no secrets)', async () => {
    const { readFileSync } = await import('node:fs');
    const src = readFileSync(preload, 'utf8').replace(/\/\/.*$/gm, '');
    assert.match(src, /\\\.neon\\\.tech\$/); assert.deepEqual([...src.matchAll(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g)].map((m) => m[0]), ['1.1.1.1']);
    assert.doesNotMatch(src, /process\.env|writeFile|fetch\(|https?:/);
  });
});
