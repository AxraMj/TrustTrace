// Rotate the password of ONE EXISTING user (e.g. the demo "judge" supervisor), safely and interactively.
//
//   node --env-file=.env.demo scripts/rotate-user-password.mjs --username judge --expect-host <endpoint-prefix>             DRY RUN (default)
//   node --env-file=.env.demo scripts/rotate-user-password.mjs --username judge --expect-host <endpoint-prefix> --execute   REAL RUN
//
// Run it in YOUR OWN terminal window (not through an assistant, and not with a "!" prefix): the password is shown ONLY on a real terminal.
//
// Guarantees (each one is covered by tests):
//   * Dry run by default: only read-only queries; no password is generated or shown; nothing is written.
//   * --execute refuses to run unless stdin AND stdout are interactive terminals, so the password cannot be captured by a pipe, log or tool.
//   * The password is generated with crypto.randomInt, shown once, and you must type it back (hidden prompt) before anything is changed,
//     so a password you never received can never be stored. The screen and scrollback are cleared right after the confirmation.
//   * The ONLY write is one locked `UPDATE users SET password_hash = $1 WHERE id = $2` on the existing, already-verified user
//     (it must affect exactly 1 row, else it rolls back). No user is created, no role/username/active flag changes, no other table is touched
//     (existing sessions are left alone and merely reported).
//   * The hash comes from the application's own scrypt function (src/api/auth.js); the new password is then checked through the production login API.
//   * The password is never written to a file, environment variable, command line, clipboard or log, and is redacted from every error message.
import { randomInt, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const GROUP_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'; // 56 symbols (24 + 24 + 8), no look-alikes (I l O o 0 1)
export const PASSWORD_SHAPE = /^([A-HJ-NP-Za-km-np-z2-9]{4}-){5}[A-HJ-NP-Za-km-np-z2-9]{4}$/;

/** 24 random characters in six groups of four: 24 x log2(56), about 139 bits of entropy. */
export function generatePassword() {
  return Array.from({ length: 6 }, () => Array.from({ length: 4 }, () => GROUP_ALPHABET[randomInt(GROUP_ALPHABET.length)]).join('')).join('-');
}

const sameSecret = (a, b) => { const x = Buffer.from(String(a)); const y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
const UPDATE_SQL = 'UPDATE users SET password_hash = $1 WHERE id = $2';

/**
 * @param {object} p
 * @param {{query: Function}} p.pool  a pg pool (or a test double)
 * @param {string} p.username
 * @param {string} [p.expectRole]
 * @param {boolean} [p.execute]       false (default) = dry run
 * @param {{isTTY: boolean, print: Function, printSecret: Function, prompt: Function, clear: Function}} p.io
 * @param {Function} p.hashPassword   the application's scrypt hasher
 * @param {Function} p.verifyPassword the application's scrypt verifier (used by the dry-run self-test)
 * @param {Function} p.validatePassword
 * @param {Function} [p.verifyLogin]  async (password) => [[name, ok], ...], run after the update through the production login API
 */
export async function rotatePassword({ pool, username, expectRole = 'supervisor', execute = false, io, hashPassword, verifyPassword, validatePassword, verifyLogin }) {
  let password = null;
  const redact = (s) => (password ? String(s ?? '').split(password).join('<redacted>') : String(s ?? ''));
  const fail = (msg) => { throw new Error(redact(msg)); };
  try {
    if (execute && !io.isTTY) fail('refusing to run: --execute needs an interactive terminal on both stdin and stdout (the password is shown only there). Open your own PowerShell window and run it there.');

    // ---- read-only inspection of the target ----
    const found = (await pool.query('SELECT id, username, role, active, created_at, password_hash FROM users WHERE lower(username) = lower($1)', [username])).rows;
    if (found.length !== 1) fail(`expected exactly one user named "${username}", found ${found.length}; nothing was changed`);
    const user = found[0];
    if (user.role !== expectRole) fail(`user "${username}" has role "${user.role}", expected "${expectRole}"; refusing to touch it`);
    if (user.active !== true) fail(`user "${username}" is not active; refusing to touch it`);
    const totals = (await pool.query(`SELECT count(*)::int AS total, count(*) FILTER (WHERE role = 'admin')::int AS admins FROM users`)).rows[0];
    const sessions = (await pool.query('SELECT count(*)::int AS n FROM sessions WHERE user_id = $1', [user.id])).rows[0].n;
    io.print(`target user: "${user.username}" (role ${user.role}, active, created ${new Date(user.created_at).toISOString().slice(0, 10)}); users in table: ${totals.total}, admins: ${totals.admins}; active sessions for this user: ${sessions}`);

    if (!execute) {
      // ---- dry run: prove the moving parts work WITHOUT generating or showing a real password, and without writing ----
      const samples = new Set(Array.from({ length: 200 }, () => generatePassword()));
      const generatorOk = samples.size === 200 && [...samples].every((p) => PASSWORD_SHAPE.test(p));
      const probe = generatePassword();
      validatePassword(probe);
      const probeHash = await hashPassword(probe);
      const hashOk = probeHash.startsWith('scrypt$') && !probeHash.includes(probe) && (await verifyPassword(probe, probeHash)) && !(await verifyPassword(`${probe}x`, probeHash));
      io.print(`self-test: password generator ${generatorOk ? 'OK' : 'FAILED'} (200 unique, correct shape); scrypt hash/verify round trip ${hashOk ? 'OK' : 'FAILED'} (throw-away value, discarded)`);
      if (!generatorOk || !hashOk) fail('self-test failed; nothing was changed');
      io.print('would do with --execute: show a new random password once in this terminal; require you to type it back; clear the screen; then run exactly one');
      io.print(`  ${UPDATE_SQL}   (locked, must affect exactly 1 row)`);
      io.print(`  and check the new password through the production login API. It would NOT create a user, change the role, run migrations or touch any other table.`);
      io.print('DRY RUN: no password was generated for use, and no change was made.');
      return { dryRun: true, changed: false, user: user.username, sessions };
    }

    // ---- real run ----
    password = generatePassword();
    validatePassword(password);
    io.printSecret(`\nNEW PASSWORD for "${user.username}" (shown once, only in this window):\n\n    ${password}\n\nSave it in your password manager NOW. Nothing has been changed yet.\n\n`);
    let confirmed = false;
    for (let attempt = 1; attempt <= 3 && !confirmed; attempt++) {
      const typed = await io.prompt('Type or paste the password to confirm you saved it (input is hidden): ');
      confirmed = sameSecret(typed.trim(), password);
      if (!confirmed) io.print(`That does not match (${attempt}/3).`);
    }
    if (!confirmed) fail('the password was not confirmed; the database was NOT changed');
    io.clear();
    io.print('confirmed. updating the stored hash ...');

    const newHash = await hashPassword(password);
    // ONE dedicated connection for the whole transaction (a pool may hand each pool.query() to a different connection)
    const tx = typeof pool.connect === 'function' ? await pool.connect() : pool;
    try {
      await tx.query('BEGIN');
      try {
        const locked = (await tx.query('SELECT id FROM users WHERE id = $1 AND role = $2 AND active = true FOR UPDATE', [user.id, expectRole])).rows;
        if (locked.length !== 1) fail('the user changed while the script was running; rolled back');
        const res = await tx.query(UPDATE_SQL, [newHash, user.id]);
        if (res.rowCount !== 1) fail(`the update affected ${res.rowCount} rows instead of 1; rolled back`);
        await tx.query('COMMIT');
      } catch (err) {
        try { await tx.query('ROLLBACK'); } catch { /* connection already gone */ }
        throw err;
      }
    } finally {
      if (tx !== pool) tx.release();
    }

    // ---- post-conditions ----
    const after = (await pool.query('SELECT id, username, role, active, created_at, password_hash FROM users WHERE id = $1', [user.id])).rows[0];
    const totalsAfter = (await pool.query(`SELECT count(*)::int AS total, count(*) FILTER (WHERE role = 'admin')::int AS admins FROM users`)).rows[0];
    if (verifyLogin) io.print('note: the login check signs in once as this user through the production API. That is a normal login, so it sets last_login_at, adds access_log rows and creates then deletes one session. Nothing else changes.');
    const checks = [
      ['only the password hash changed (id, username, role, active, created_at are identical)', after.id === user.id && after.username === user.username && after.role === user.role && after.active === user.active && new Date(after.created_at).getTime() === new Date(user.created_at).getTime() && after.password_hash !== user.password_hash],
      ['the stored value is a scrypt hash that does not contain the password', after.password_hash.startsWith('scrypt$') && !after.password_hash.includes(password)],
      ['the number of users and admins is unchanged (no user created, no role changed)', totalsAfter.total === totals.total && totalsAfter.admins === totals.admins],
      ...(verifyLogin ? await verifyLogin(password) : []),
    ];
    for (const [name, ok] of checks) io.print(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
    const allOk = checks.every(([, ok]) => ok);
    io.print(allOk ? 'ROTATION COMPLETE. The new password is the one you just saved.' : 'ROTATION FINISHED BUT A CHECK FAILED: do not hand out the password until this is understood.');
    return { dryRun: false, changed: true, ok: allOk, user: user.username, sessions };
  } catch (err) {
    throw new Error(redact(err.message));
  } finally {
    password = null;
  }
}

/** Production login path, in-process on loopback against the real database: proves the NEW password works and the role is intact. */
export async function verifyLoginViaApi({ pool, config, username, expectRole, imp }) {
  const { createApiServer, listen } = await imp('src/api/server.js'); const { buildDeps } = await imp('src/app/deps.js'); const { loadAppConfig } = await imp('src/api/config.js');
  const apiConfig = loadAppConfig({ ...process.env, DATABASE_URL: config.databaseUrl, NODE_ENV: 'production' });
  return async (password) => {
    const server = createApiServer({ deps: buildDeps({ pool, config: apiConfig }), config: apiConfig, logger: () => {} });
    const addr = await listen(server, { host: '127.0.0.1', port: 0 });
    const base = `http://127.0.0.1:${addr.port}`;
    const call = async (method, path, { cookie, body } = {}) => {
      const res = await fetch(base + path, { method, headers: { ...(cookie ? { cookie } : {}), ...(body ? { 'content-type': 'application/json', origin: base } : {}) }, body: body ? JSON.stringify(body) : undefined });
      const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
      return { status: res.status, json, text, headers: res.headers };
    };
    try {
      const bad = await call('POST', '/api/auth/login', { body: { username, password: `${password.slice(0, -1)}${password.endsWith('a') ? 'b' : 'a'}` } });
      const login = await call('POST', '/api/auth/login', { body: { username, password } });
      const cookie = (login.headers.getSetCookie?.()[0] ?? '').split(';')[0];
      const me = login.status === 200 ? await call('GET', '/api/auth/me', { cookie }) : { status: 0 };
      const denied = login.status === 200 ? await call('GET', '/api/audit/verify', { cookie }) : { status: 0 };
      const out = login.status === 200 ? await call('POST', '/api/auth/logout', { cookie }) : { status: 0 };
      const stale = login.status === 200 ? await call('GET', '/api/auth/me', { cookie }) : { status: 0 };
      return [
        ['production login API: a slightly wrong password is refused (401)', bad.status === 401],
        [`production login API: the NEW password signs in (200) as ${expectRole}`, login.status === 200 && login.json?.user?.role === expectRole && login.json?.user?.username === username],
        ['the login response contains neither the password nor a hash', !login.text.includes(password) && !/scrypt\$/.test(login.text)],
        ['session works (GET /api/auth/me) and the role is enforced (admin-only endpoint refused with 403)', me.status === 200 && denied.status === 403],
        ['logout ends the session (old cookie -> 401)', out.status === 200 && stale.status === 401],
      ];
    } finally { server.closeAllConnections?.(); await new Promise((r) => server.close(r)); }
  };
}

// ------------------------------------------------------------------------------------------------ real terminal I/O + CLI
function hiddenPrompt(question) {
  return new Promise((resolve, reject) => {
    const { stdin, stdout } = process;
    stdout.write(question);
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    let buf = '';
    const done = () => { stdin.off('data', onData); stdin.setRawMode(false); stdin.pause(); };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\u0003') { done(); reject(new Error('cancelled; the database was NOT changed')); return; }
        if (ch === '\r' || ch === '\n') { done(); stdout.write('\n'); resolve(buf); return; }
        if (ch === '\u007f' || ch === '\b') { buf = buf.slice(0, -1); continue; }
        buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}

async function main() {
  const args = process.argv.slice(2);
  const opt = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
  const execute = args.includes('--execute');
  const username = opt('--username'); const expectHost = opt('--expect-host'); const expectRole = opt('--expect-role') ?? 'supervisor';
  if (!username || !expectHost) { console.error('usage: node --env-file=<file> scripts/rotate-user-password.mjs --username <name> --expect-host <host prefix> [--expect-role supervisor] [--execute]\n(without --execute it is a read-only dry run)'); process.exit(2); }
  const isTTY = Boolean(process.stdout.isTTY && process.stdin.isTTY);
  if (execute && !isTTY) { console.error('refusing to run: --execute needs an interactive terminal on both stdin and stdout (the password is shown only there). Open your own PowerShell window and run it there.'); process.exit(3); }

  const root = process.cwd().replace(/\\/g, '/') + '/';
  const imp = (p) => import(pathToFileURL(root + p));
  const { loadDotEnv } = await imp('src/config.js'); const { loadAppConfig } = await imp('src/api/config.js'); const { createPool } = await imp('src/db/pool.js');
  const { hashPassword, validatePassword, verifyPassword } = await imp('src/api/auth.js');
  loadDotEnv();
  const config = loadAppConfig();
  const host = new URL(config.databaseUrl).hostname;
  if (!host.startsWith(expectHost)) { console.error('refusing to run: the database host does not start with --expect-host. Wrong .env.demo? Nothing was touched.'); process.exit(4); }
  console.log(`target host matches --expect-host (${expectHost}). Mode: ${execute ? 'EXECUTE' : 'DRY RUN (read-only)'}`);

  const pool = createPool(config, { max: 2 });
  const io = { isTTY, print: (s) => console.log(s), printSecret: (s) => process.stdout.write(s), prompt: hiddenPrompt, clear: () => process.stdout.write('\u001b[2J\u001b[3J\u001b[H') };
  try {
    const verifyLogin = execute ? await verifyLoginViaApi({ pool, config, username, expectRole, imp }) : undefined;
    const r = await rotatePassword({ pool, username, expectRole, execute, io, hashPassword, verifyPassword, validatePassword, verifyLogin });
    process.exitCode = r.dryRun || r.ok ? 0 : 1;
  } catch (err) {
    console.error(`FAILED: ${String(err.message).replace(/postgres(?:ql)?:\/\/\S+/g, '<url>')}`);
    process.exitCode = 1;
  } finally { await pool.end().catch(() => {}); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
