// npm run db:migrate           apply pending migrations
// npm run db:status            show applied / pending / modified migrations (only creates the empty schema_migrations bookkeeping table if missing)
import { loadDotEnv } from '../config.js';
import { loadAppConfig } from '../api/config.js';
import { migrationStatus, runMigrations } from '../db/migrate.js';
import { createPool, pingDb } from '../db/pool.js';

const statusOnly = process.argv.includes('--status');
let pool;
try {
  loadDotEnv();
  pool = createPool(loadAppConfig());
  const ping = await pingDb(pool);
  if (!ping.ok) throw new Error(`cannot connect to PostgreSQL (${ping.error}). Check that the server is running and DATABASE_URL is correct (see docs/database.md).`);
  if (statusOnly) {
    const s = await migrationStatus(pool);
    console.log(`applied ${s.applied.length}: ${s.applied.map((m) => m.version).join(', ') || '-'}`);
    console.log(`pending ${s.pending.length}: ${s.pending.map((m) => `${m.version}_${m.name}`).join(', ') || '-'}`);
    if (s.modified.length) console.log(`MODIFIED after apply (error): ${s.modified.map((m) => m.version).join(', ')}`);
    if (s.unknown.length) console.log(`unknown to this checkout: ${s.unknown.map((m) => m.version).join(', ')}`);
    process.exitCode = s.upToDate ? 0 : 1;
  } else {
    const r = await runMigrations(pool, { log: (m) => console.log(m) });
    console.log(r.ran.length ? `applied ${r.ran.length} migration(s)` : 'schema already up to date');
  }
} catch (err) {
  console.error(`FAIL ${err.name}: ${String(err.message).replace(/postgres(?:ql)?:\/\/\S+/g, '<redacted>')}`);
  process.exitCode = 1;
} finally {
  await pool?.end();
}
