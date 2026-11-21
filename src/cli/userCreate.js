// Create a dashboard user:
//   $env:TRUSTTRACE_NEW_PASSWORD = '<at least 12 characters>'
//   npm run user:create -- --username alice --role admin
// (or pipe the password on stdin with --password-stdin). The password is never printed or stored in plain text.
import { loadDotEnv } from '../config.js';
import { loadAppConfig } from '../api/config.js';
import { hashPassword, validatePassword } from '../api/auth.js';
import { createPool } from '../db/pool.js';
import { DuplicateUserError, createUser } from '../db/userRepo.js';

const arg = (name) => (process.argv.includes(name) ? process.argv[process.argv.indexOf(name) + 1] : undefined);
async function readStdin() {
  let s = '';
  for await (const c of process.stdin) s += c;
  return s.replace(/\r?\n$/, '');
}

let pool;
try {
  const username = arg('--username');
  const role = arg('--role') ?? 'analyst';
  if (!username) throw new Error('usage: npm run user:create -- --username NAME [--role analyst|supervisor|admin]');
  if (!['analyst', 'supervisor', 'admin'].includes(role)) throw new Error('role must be analyst, supervisor or admin');
  const password = process.argv.includes('--password-stdin') ? await readStdin() : process.env.TRUSTTRACE_NEW_PASSWORD;
  if (!password) throw new Error('provide the password via the TRUSTTRACE_NEW_PASSWORD environment variable or --password-stdin');
  validatePassword(password);
  loadDotEnv();
  pool = createPool(loadAppConfig());
  const user = await createUser(pool, { username, passwordHash: await hashPassword(password), role });
  console.log(`created user "${user.username}" (${user.role}) id ${user.id}`);
} catch (err) {
  console.error(`FAIL ${err instanceof DuplicateUserError ? 'DuplicateUser' : err.name}: ${String(err.message).replace(/postgres(?:ql)?:\/\/\S+/g, '<redacted>')}`);
  process.exitCode = 1;
} finally {
  await pool?.end();
}
