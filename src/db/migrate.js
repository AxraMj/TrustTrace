import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256Hex } from './canonical.js';

export const DEFAULT_MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'migrations');
const MIGRATE_LOCK_KEY = 7_424_002;
const FILE_RE = /^(\d{3,})_([a-z0-9_]+)\.sql$/;

/** Read and validate the migration files: unique, strictly increasing versions, stable checksums. */
export function loadMigrations(dir = DEFAULT_MIGRATIONS_DIR) {
  const files = readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
  const migrations = files.map((file) => {
    const m = FILE_RE.exec(file);
    if (!m) throw new Error(`migration file name must look like 001_name.sql: ${file}`);
    const sql = readFileSync(join(dir, file), 'utf8');
    return { version: Number(m[1]), name: m[2], file, sql, checksum: sha256Hex(sql.replace(/\r\n/g, '\n')) };
  });
  migrations.forEach((m, i) => {
    if (m.version !== i + 1) throw new Error(`migration versions must be 1..n without gaps; found ${m.file} at position ${i + 1}`);
  });
  return migrations;
}

async function ensureTable(client) {
  await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version    integer PRIMARY KEY,
    name       text        NOT NULL,
    checksum   text        NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
  )`);
}

/** Which migrations are applied / pending / modified-after-apply (a modified migration is an error, never re-run). */
export async function migrationStatus(pool, dir = DEFAULT_MIGRATIONS_DIR) {
  const migrations = loadMigrations(dir);
  const client = await pool.connect();
  try {
    await ensureTable(client);
    const { rows } = await client.query('SELECT version, name, checksum FROM schema_migrations ORDER BY version');
    const byVersion = new Map(rows.map((r) => [r.version, r]));
    const applied = [], pending = [], modified = [];
    for (const m of migrations) {
      const row = byVersion.get(m.version);
      if (!row) pending.push({ version: m.version, name: m.name });
      else if (row.checksum !== m.checksum) modified.push({ version: m.version, name: m.name });
      else applied.push({ version: m.version, name: m.name });
    }
    const unknown = rows.filter((r) => !migrations.some((m) => m.version === r.version)).map((r) => ({ version: r.version, name: r.name }));
    return { applied, pending, modified, unknown, upToDate: !pending.length && !modified.length && !unknown.length };
  } finally {
    client.release();
  }
}

/**
 * Apply pending migrations, each in its own transaction, under an advisory lock (safe against two processes at once).
 * Refuses to run if an already-applied migration file has changed.
 */
export async function runMigrations(pool, { dir = DEFAULT_MIGRATIONS_DIR, log = () => {} } = {}) {
  const migrations = loadMigrations(dir);
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATE_LOCK_KEY]);
    await ensureTable(client);
    const { rows } = await client.query('SELECT version, checksum FROM schema_migrations');
    const applied = new Map(rows.map((r) => [r.version, r.checksum]));
    const ran = [];
    for (const m of migrations) {
      if (applied.has(m.version)) {
        if (applied.get(m.version) !== m.checksum) {
          throw new Error(`migration ${m.file} was modified after it was applied (checksum mismatch); write a NEW migration instead`);
        }
        continue;
      }
      log(`applying ${m.file}`);
      try {
        await client.query('BEGIN');
        await client.query(m.sql);
        await client.query('INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)', [m.version, m.name, m.checksum]);
        await client.query('COMMIT');
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch { /* ignore */ }
        throw new Error(`migration ${m.file} failed and was rolled back: ${err.message}`);
      }
      ran.push(m.file);
    }
    return { ran, total: migrations.length };
  } finally {
    try { await client.query('SELECT pg_advisory_unlock($1)', [MIGRATE_LOCK_KEY]); } catch { /* ignore */ }
    client.release();
  }
}
