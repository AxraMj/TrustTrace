// Live scenario report: npm run scenarios
// Runs the core + hardening scenarios through Agent A / verification authority -> Meko -> Agent B, prints the
// results, latency split, then deletes its memories and queries Meko to verify they are gone.
import { mkdirSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { openSession } from './session.js';
import { latencyStats } from './meko/client.js';
import { runScenarios, formatTable } from './scenarioRunner.js';
import { SCENARIOS } from './scenarios.js';
import { HARDENING_SCENARIOS } from './scenarios.hardening.js';
import { loadAuthority } from './trustSetup.js';
import { deleteMemories, verifyCleanup } from './cleanup.js';
import { TrustTraceError } from './errors.js';

let session;
let pool;
let recorder;
const persist = process.argv.includes('--persist');
const tracker = { savedIds: [], scopeIds: [], writers: {} };
try {
  session = await openSession();
  const { authority, source } = loadAuthority();
  console.log(`Verification authority key: ${source} (key id ${authority.kid})`);
  const tag = randomUUID().slice(0, 8);
  const all = [];

  // --persist: decisions, agent activity and replay protection go to PostgreSQL (real Meko + real PostgreSQL, no mocks).
  let store = session.store;
  let extra = {};
  if (persist) {
    const { loadAppConfig } = await import('./api/config.js');
    const { createPool, pingDb } = await import('./db/pool.js');
    const { migrationStatus } = await import('./db/migrate.js');
    const { ActivityRecorder } = await import('./db/activity.js');
    const { PgReplayGuard } = await import('./db/replayGuard.js');
    const { instrumentStore } = await import('./app/instrumentedStore.js');
    const { DecisionService } = await import('./app/decisionService.js');
    pool = createPool(loadAppConfig());
    if (!(await pingDb(pool)).ok) throw new Error('--persist needs PostgreSQL: cannot connect (check DATABASE_URL, see docs/database.md)');
    const st = await migrationStatus(pool);
    if (!st.upToDate) throw new Error('--persist needs the schema: run `npm run db:migrate` first');
    recorder = new ActivityRecorder(pool);
    store = instrumentStore(session.store, recorder);
    const guard = new PgReplayGuard(pool);
    authority.onIssued = (p) => guard.recordIssued(p); // issuance is recorded in the replay ledger + audit chain
    extra = {
      replayGuard: guard,
      assess: async (agent, event) => (await new DecisionService({ pool, recorder, agent }).assessAndRecord(event)).result,
    };
    console.log('Persistence: ON (PostgreSQL decisions, activity, replay ledger, audit chain)');
  }
  for (const [name, scenarios] of [['CORE', SCENARIOS], ['HARDENING', HARDENING_SCENARIOS]]) {
    const run = await runScenarios({ store, tag: `${name[0]}${tag}`, authority, scenarios, tracker, ...extra, onProgress: (m) => console.log(`  running ${m} ...`) });
    console.log(`\n=== ${name} scenarios ===\n` + formatTable(run.results));
    all.push(...run.results.map((r) => ({ suite: name, ...r })));
  }

  for (const r of all) {
    console.log(`\n${r.id} ${r.title}: ${r.pass ? 'PASS' : 'FAIL'} [${r.classification}] expected ${r.expected.actions.join('|')}, got ${r.actual.action}`);
    if (!r.pass) console.log(`   checks: ${JSON.stringify(r.checks)}`);
    r.explanation.slice(-6).forEach((l) => console.log(`   ${l}`));
  }
  const fp = all.filter((r) => r.classification === 'FALSE_POSITIVE');
  const fn = all.filter((r) => r.classification === 'FALSE_NEGATIVE');
  console.log(`\nSummary: ${all.filter((r) => r.pass).length}/${all.length} pass | false positives: ${fp.map((r) => r.id).join(',') || 'none'} | false negatives: ${fn.map((r) => r.id).join(',') || 'none'}`);

  console.log('\nMeko per-tool latency (ms):');
  console.table(latencyStats(session.client.metrics));
  mkdirSync('reports', { recursive: true });
  writeFileSync('reports/scenario-results.json', JSON.stringify({ generatedAt: new Date().toISOString(), results: all, meko: latencyStats(session.client.metrics) }, null, 2));
  console.log('Wrote reports/scenario-results.json');
} catch (err) {
  console.error(`FAIL ${err.name}: ${err.message}`);
  if (!(err instanceof TrustTraceError)) console.error(err.stack);
  process.exitCode = 1;
} finally {
  if (session) {
    const del = await deleteMemories(session.store, tracker.savedIds, tracker.writers);
    console.log(`\nCleanup: deleted ${del.deleted}/${tracker.savedIds.length} memories` + (del.failed.length ? `, FAILED: ${JSON.stringify(del.failed)}` : ''));
    const v = await verifyCleanup({ store: session.store, savedIds: tracker.savedIds, scopeIds: tracker.scopeIds });
    console.log('Cleanup verification (queried Meko after deletion):', JSON.stringify({ ...v, conversations: `${Object.keys(v.conversations).length} conversations, all reused: ${Object.values(v.conversations).every((c) => c.reusedNotRecreated)}` }, null, 2));
    if (!v.ok) process.exitCode = 1;
  }
  await recorder?.close();
  await pool?.end();
  await session?.client.close();
}
