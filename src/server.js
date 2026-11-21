// REST API server: npm run api
// Requires PostgreSQL (DATABASE_URL) with migrations applied (npm run db:migrate) and at least one user (npm run user:create).
import { loadDotEnv } from './config.js';
import { loadAppConfig } from './api/config.js';
import { createApiServer, listen } from './api/server.js';
import { buildDeps } from './app/deps.js';
import { ActivityRecorder } from './db/activity.js';
import { migrationStatus } from './db/migrate.js';
import { createPool, pingDb } from './db/pool.js';
import { TrustTraceError } from './errors.js';

let pool;
let server;
try {
  loadDotEnv();
  const config = loadAppConfig();
  pool = createPool(config);
  const db = await pingDb(pool);
  if (!db.ok) throw new Error(`cannot connect to PostgreSQL (${db.error}). Is the server running and DATABASE_URL correct?`);
  const status = await migrationStatus(pool);
  if (!status.upToDate) {
    throw new Error(`database schema is not up to date (pending: ${status.pending.map((m) => m.version).join(',') || 'none'}, modified: ${status.modified.length}). Run: npm run db:migrate`);
  }
  const recorder = new ActivityRecorder(pool);
  server = createApiServer({ deps: buildDeps({ pool, config, getServerStats: () => server.stats, getActivityStats: () => recorder.stats() }), config });
  const addr = await listen(server, config);
  console.log(`TrustTrace API listening on http://${addr.address}:${addr.port} (PostgreSQL ok, schema v${status.applied.length})`);

  const shutdown = async (sig) => {
    console.log(`${sig}: shutting down`);
    server.close();
    await recorder.close();
    await pool.end();
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
} catch (err) {
  console.error(`FAIL ${err.name}: ${String(err.message).replace(/postgres(?:ql)?:\/\/\S+/g, '<redacted>')}`);
  if (!(err instanceof TrustTraceError)) console.error('(this is not a configuration error; see the message above)');
  await pool?.end().catch(() => {});
  process.exitCode = 1;
}
