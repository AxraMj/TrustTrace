import pg from 'pg';

// bigint (int8) -> JS number. Safe here: sequence numbers and counts stay far below 2^53.
pg.types.setTypeParser(20, (v) => Number(v));

const SCHEMA_RE = /^[a-z_][a-z0-9_]{0,62}$/;

/** Remove the password from a connection string so it can be logged or put in an error message. */
export function redactUrl(url) {
  try {
    const u = new URL(url);
    if (u.password) u.password = '***';
    return u.toString();
  } catch {
    return '<unparseable connection string>';
  }
}

/**
 * Create a connection pool. `schema` (tests only) pins search_path so a throw-away schema can be used.
 * The connection string is never logged here; use redactUrl() if you must mention it.
 */
export function createPool(config, { schema, max } = {}) {
  if (schema !== undefined && !SCHEMA_RE.test(schema)) throw new Error(`invalid schema name: ${schema}`);
  const pool = new pg.Pool({
    connectionString: config.databaseUrl,
    max: max ?? config.dbPoolMax ?? 10,
    ssl: config.databaseSsl ? { rejectUnauthorized: true } : undefined,
    options: schema ? `-c search_path=${schema}` : undefined,
    application_name: 'trusttrace',
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 30_000,
  });
  pool.on('error', (err) => {
    // an idle client failed (e.g. the server restarted); the pool discards it. Never print connection details.
    console.error(`[db] idle client error: ${String(err.message).replace(/postgres(?:ql)?:\/\/\S+/g, '<redacted>')}`);
  });
  return pool;
}

/** Run fn inside a transaction on one client; commits on success, rolls back (and rethrows) on any error. */
export async function withTransaction(pool, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* connection already broken */ }
    throw err;
  } finally {
    client.release();
  }
}

/** Cheap liveness probe for /health. */
export async function pingDb(pool) {
  const t0 = performance.now();
  try {
    await pool.query('SELECT 1');
    return { ok: true, latencyMs: Math.round((performance.now() - t0) * 10) / 10 };
  } catch (err) {
    return { ok: false, error: err.code ?? err.name };
  }
}
