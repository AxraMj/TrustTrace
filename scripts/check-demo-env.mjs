// Checks the local, git-ignored demo settings file (.env.demo) WITHOUT ever printing a value.
//
//   node scripts/check-demo-env.mjs [path]        (default: .env.demo)
//
// Output is a single line, "CONFIG CHECK: PASSED" or "CONFIG CHECK: FAILED", followed on failure only by the NAMES of the failed checks.
// No credential, host name, URL fragment or file content is ever written to the output (not even in error paths).
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const EXPECTED_KEYS = ['DATABASE_URL', 'MEKO_DATAPACK'];
export const DEMO_DATAPACK = 'trusttrace-demo';

export function parseEnv(text) {
  const keys = []; const values = new Map(); const duplicates = [];
  for (const line of text.replace(/^﻿/, '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!m) { keys.push('<<unparseable line>>'); continue; }
    if (values.has(m[1])) duplicates.push(m[1]);
    keys.push(m[1]); values.set(m[1], m[2]);
  }
  return { keys, values, duplicates };
}

/**
 * Pure evaluation (testable). Returns an array of [checkName, passed]. Check names never contain values.
 * @param {{text: string|null, gitIgnored: boolean, tracked: boolean, devDatabaseUrl?: string}} input
 */
export function evaluate({ text, gitIgnored, tracked, devDatabaseUrl }) {
  const out = [];
  const add = (name, ok) => out.push([name, Boolean(ok)]);
  add('the .env.demo file exists', text !== null);
  add('the file is ignored by Git', gitIgnored);
  add('the file is not tracked by Git', !tracked);
  if (text === null) return out;
  add('the file has no byte-order mark', !text.startsWith('﻿'));
  const { keys, values, duplicates } = parseEnv(text);
  add('only DATABASE_URL and MEKO_DATAPACK are set (no other keys, no stray lines)', keys.length === EXPECTED_KEYS.length && EXPECTED_KEYS.every((k) => keys.includes(k)));
  add('no key is defined twice', duplicates.length === 0);
  const raw = values.get('DATABASE_URL') ?? '';
  add('DATABASE_URL is a bare URL (no quotes, spaces or "psql" prefix)', raw.length > 0 && raw === raw.trim() && !/^['"]/.test(raw) && !/['"]$/.test(raw) && !/^psql\b/i.test(raw) && !/\s/.test(raw));
  let u = null;
  try { u = new URL(raw); } catch { /* not a URL */ }
  add('DATABASE_URL parses as a PostgreSQL URL (postgres:// or postgresql://)', u && /^postgres(ql)?:$/.test(u.protocol));
  const host = u?.hostname ?? '';
  add('the database host ends in .neon.tech', host.endsWith('.neon.tech'));
  add('it is the DIRECT endpoint (host has no "-pooler")', Boolean(host) && !/-pooler\./.test(host));
  add('the host is not a local or private address', Boolean(host) && !/^(localhost|127\.|10\.|192\.168\.|::1)/.test(host));
  add('a user name and a password are present', Boolean(u?.username) && Boolean(u?.password));
  add('the password is not a placeholder (at least 16 characters, not "password")', (u?.password ?? '').length >= 16 && !/^<?password>?$/i.test(decodeURIComponent(u?.password ?? '')));
  add('a database name is present', (u?.pathname ?? '').length > 1);
  add('the port is the default (none or 5432)', u !== null && (u.port === '' || u.port === '5432'));
  const sslmode = u?.searchParams.get('sslmode');
  add('TLS is required with certificate verification (sslmode=require or verify-full)', sslmode === 'require' || sslmode === 'verify-full');
  add('it differs from the development database URL in .env', !devDatabaseUrl || raw !== devDatabaseUrl);
  add('MEKO_DATAPACK is exactly trusttrace-demo', values.get('MEKO_DATAPACK') === DEMO_DATAPACK);
  return out;
}

export function summarize(results) {
  const failed = results.filter(([, ok]) => !ok).map(([name]) => name);
  return failed.length === 0 ? 'CONFIG CHECK: PASSED' : `CONFIG CHECK: FAILED\n${failed.map((n) => `  - ${n}`).join('\n')}`;
}

function gitStatus(file) {
  const run = (args) => { try { execFileSync('git', args, { stdio: 'ignore' }); return true; } catch { return false; } };
  return { gitIgnored: run(['check-ignore', '-q', '--', file]), tracked: run(['ls-files', '--error-unmatch', '--', file]) };
}

function devDatabaseUrl() {
  try { const m = /^DATABASE_URL=(.*)$/m.exec(readFileSync('.env', 'utf8')); return m ? m[1].trim() : undefined; } catch { return undefined; }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const file = process.argv[2] ?? '.env.demo';
  let text = null;
  try { if (existsSync(file)) text = readFileSync(file, 'utf8'); } catch { text = null; }
  const results = evaluate({ text, ...gitStatus(file), devDatabaseUrl: devDatabaseUrl() });
  console.log(summarize(results));
  process.exit(results.every(([, ok]) => ok) ? 0 : 1);
}
