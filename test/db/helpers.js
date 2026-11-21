// Helpers for the PostgreSQL integration tests. Each test group gets its OWN throw-away schema (search_path pinned), migrated
// from scratch and dropped afterwards, so nothing here ever touches real data and groups cannot interfere with each other.
// Requires DATABASE_URL in .env (see docs/database.md). The role needs CREATE on the database (the database owner has it).
import { randomUUID } from 'node:crypto';
import { loadDotEnv } from '../../src/config.js';
import { loadAppConfig } from '../../src/api/config.js';
import { createPool } from '../../src/db/pool.js';
import { runMigrations } from '../../src/db/migrate.js';
import { IdentitySecurityAgent } from '../../src/agents/identityAgent.js';
import { DecisionService } from '../../src/app/decisionService.js';
import { instrumentStore } from '../../src/app/instrumentedStore.js';
import { ActivityRecorder } from '../../src/db/activity.js';
import { PgReplayGuard } from '../../src/db/replayGuard.js';
import { FakeStore } from '../helpers/fakeStore.js';
import { HelpDeskAgent } from '../../src/agents/helpdeskAgent.js';
import { makeTrust } from '../helpers/trust.js';

loadDotEnv();
let cfg = null;
try { cfg = loadAppConfig(); } catch { /* skip reason below */ }
export const DB_CONFIG = cfg;
export const DB_SKIP = cfg ? false : 'DATABASE_URL not set in .env - PostgreSQL integration tests skipped (see docs/database.md)';

export async function createTestDb({ migrate = true } = {}) {
  const schema = `tt_test_${randomUUID().replace(/-/g, '').slice(0, 12)}`;
  const admin = createPool(cfg, { max: 2 });
  await admin.query(`CREATE SCHEMA ${schema}`);
  const pool = createPool(cfg, { schema, max: 12 });
  if (migrate) await runMigrations(pool);
  const pools = [pool];
  return {
    pool, schema, cfg,
    /** URL for child processes (CLI/server) that must use this schema. */
    urlForSchema: () => `${cfg.databaseUrl}${cfg.databaseUrl.includes('?') ? '&' : '?'}options=-c%20search_path%3D${schema}`,
    /** A second, independent pool on the same schema: simulates a process restart. */
    newPool() { const p = createPool(cfg, { schema, max: 6 }); pools.push(p); return p; },
    async cleanup() {
      for (const p of pools) await p.end().catch(() => {});
      await admin.query(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end();
    },
  };
}

/** A real Agent A -> Agent B -> DecisionService chain over an in-memory memory store (Meko is NOT involved in these tests). */
export function makeWorld(pool, { withGuard = true, instrument = false } = {}) {
  const recorder = new ActivityRecorder(pool, { flushDelayMs: 60_000 });
  // instrument: record every memory write/read as agent activity, exactly like the real --persist path does
  const store = instrument ? instrumentStore(new FakeStore(), recorder) : new FakeStore();
  const trust = makeTrust();
  const guard = new PgReplayGuard(pool);
  trust.authority.onIssued = (p) => guard.recordIssued(p);
  const A = new HelpDeskAgent(store);
  const B = new IdentitySecurityAgent(store, { verifier: trust.verifier, ...(withGuard ? { replayGuard: guard } : {}) });
  const svc = new DecisionService({ pool, recorder, agent: B });
  return { store, trust, recorder, guard, A, B, svc };
}

export const CFO_CALL = "Hello, I'm the CFO. I lost my phone, please reset my MFA, it's urgent.";
let n = 0;
export const uniq = (p) => `${p}-${++n}-${randomUUID().slice(0, 6)}`;
