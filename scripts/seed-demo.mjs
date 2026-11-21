// Reduced, quota-safe seeding of the demo: five of the EXISTING scenarios, run unchanged, through the real agents and the real Meko datapack
// "trusttrace-demo", persisted to the demo PostgreSQL database.
//
//   node --require ./scripts/dns-fallback.cjs --env-file=.env.demo scripts/seed-demo.mjs --expect-host <neon endpoint prefix>             DRY RUN (default)
//   node --require ./scripts/dns-fallback.cjs --env-file=.env.demo scripts/seed-demo.mjs --expect-host <neon endpoint prefix> --execute   REAL RUN
//
// Why this exists: the Meko account has a small monthly search quota, and the full 23-scenario run (src/runScenarios.js, unchanged) needs far more
// searches than are left. This script runs only S1, S4, S6, H3 and H8 (about 21 memory adds and 9 searches) and spends NO search on cleanup.
// Nothing in src/ is modified; this file only imports it.
//
// Safeguards (each covered by tests):
//   * DENY-BY-DEFAULT tool allowlist with a hard per-tool budget, enforced in code between the agents and Meko. Any tool not listed
//     (datapack_create/update/delete, memory_delete_all, conversation_delete/add_message, context_search, knowledgebase_*, artifact_*, ...) is refused
//     without being sent. A budget that is used up refuses the call (fail closed); it is never exceeded.
//   * Every memory call must carry the id of the bound "trusttrace-demo" datapack; any other datapack id is refused. The datapack is only FOUND by exact name,
//     never created here.
//   * Refuses to run unless MEKO_DATAPACK is exactly "trusttrace-demo", the demo datapack is empty, the Neon host starts with --expect-host, the schema is
//     fully migrated and the database has no decisions yet (run once).
//   * Cleanup always runs (finally): delete by id, by the agent that wrote each memory; verify with memory_get_by_id and ONE memory_get_all pass. No search.
//   * Afterwards it proves the other datapacks are unchanged and the demo datapack is empty again.
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { SCENARIOS } from '../src/scenarios.js';
import { HARDENING_SCENARIOS } from '../src/scenarios.hardening.js';
import { runScenarios } from '../src/scenarioRunner.js';
import { MemoryStore, createConversation } from '../src/meko/memory.js';
import { VERIFIER_AGENT_ID, deleteMemories } from '../src/cleanup.js';
import { MekoToolError } from '../src/errors.js';

export const DEMO_DATAPACK = 'trusttrace-demo';
export const PLAN_IDS = ['S1', 'S4', 'S6', 'H3', 'H8'];
export const POLL_MS = 5_000;          // wait between index polls
export const INDEX_TIMEOUT_MS = 30_000; // per scenario: at most about 6 polls
/** Hard per-tool budgets (calls). Typical use is far below these; they are a backstop, not a target. */
export const LIMITS = Object.freeze({
  memory_search: 40, memory_add: 30, memory_delete_by_id: 30, memory_get_by_id: 60, memory_get_all: 4,
  conversation_create: 24, datapack_search: 4, datapack_describe: 12,
});
/** Model-based estimate (offline simulation over random run tags, index lag 0 as observed in the earlier real run). */
export const ESTIMATE = Object.freeze({ memory_add: 21, memory_search: 9, memory_delete_by_id: 21, memory_get_by_id: 21, memory_get_all: 1, conversation_create: '10-11 (9-10 new containers)' });

export class QuotaExceededError extends Error {}
export class ForbiddenCallError extends Error {}

const DATAPACK_SCOPED = new Set(['memory_add', 'memory_search', 'memory_get_all', 'memory_get_by_id', 'memory_delete_by_id']);
const SETUP_SESSION = 'trusttrace-setup';

/** Wrap a Meko client: allowlist + budgets + datapack scoping. `bind(id)` fixes the only datapack memory calls may touch. */
export function guardClient(raw, { limits = LIMITS } = {}) {
  const counts = {}; const refused = []; let datapackId = null;
  return {
    counts, refused, limits,
    bind(id) { datapackId = id; },
    get metrics() { return raw.metrics; },
    async callTool(name, args = {}) {
      const deny = (Cls, why) => { refused.push(`${name}: ${why}`); throw new Cls(`${name}: ${why}`); };
      if (!(name in limits)) deny(ForbiddenCallError, 'this tool is not allowed in the demo seeding run (not sent)');
      if (DATAPACK_SCOPED.has(name)) {
        if (!datapackId) deny(ForbiddenCallError, 'no demo datapack is bound yet (not sent)');
        if (args.datapack_id !== datapackId) deny(ForbiddenCallError, 'refusing to touch any datapack other than the bound demo datapack (not sent)');
      }
      if (name === 'conversation_create') {
        const isSetup = args.session_id === SETUP_SESSION && !args.datapack_id; // the existing idempotent setup conversation
        if (!isSetup && (!datapackId || args.datapack_id !== datapackId)) deny(ForbiddenCallError, 'conversations may only be created in the bound demo datapack (not sent)');
      }
      if ((counts[name] ?? 0) + 1 > limits[name]) deny(QuotaExceededError, `budget of ${limits[name]} calls is used up; refusing the next call (not sent)`);
      counts[name] = (counts[name] ?? 0) + 1; // counted before sending: a call that errors on the server still used quota
      return raw.callTool(name, args);
    },
    close: () => raw.close?.(),
  };
}

const FIELDS = ['datapack_name', 'created_at', 'updated_at', 'grant', 'memory_count', 'knowledge_count', 'learnings_count', 'collective_memory_count', 'conversation_search_opt_out'];
const pickFields = (d) => Object.fromEntries(FIELDS.map((f) => [f, d?.[f] ?? null]));

async function snapshotAll(g, conversationId) {
  const list = await g.callTool('datapack_search', { name: '', conversation_id: conversationId, include_total: true, limit: 100 });
  const out = {};
  for (const d of list?.datapacks ?? []) out[d.datapack_name] = { id: d.datapack_id, ...pickFields(await g.callTool('datapack_describe', { datapack_id: d.datapack_id, conversation_id: conversationId })) };
  return out;
}

/** Everything except the demo datapack must be byte-identical; the demo datapack must be empty again. */
export function compareSnapshots(before, after, { demo = DEMO_DATAPACK } = {}) {
  const problems = [];
  if (!same(Object.keys(before), Object.keys(after))) problems.push('the set of datapacks changed');
  for (const [name, b] of Object.entries(before)) {
    const a = after[name];
    if (!a) continue;
    if (name === demo) { if (a.memory_count !== 0) problems.push(`${demo} still holds ${a.memory_count} memories`); continue; }
    for (const f of FIELDS) if (JSON.stringify(a[f]) !== JSON.stringify(b[f])) problems.push(`${name}.${f} changed`);
  }
  return problems;
}
const same = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());

/** Delete by id (existing helper), then verify WITHOUT any search: memory_get_by_id per id (bounded rounds) + one memory_get_all pass. */
export async function leanCleanup({ store, ids, writers, rounds = 2, pauseMs = 3000, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
  const del = await deleteMemories(store, ids, writers);
  const conv = await store.conversationFor(VERIFIER_AGENT_ID);
  let readable = [...ids];
  for (let r = 0; r < rounds && readable.length; r++) {
    if (r > 0) await sleep(pauseMs);
    const next = [];
    for (const id of readable) {
      try { await store.client.callTool('memory_get_by_id', { memory_id: id, conversation_id: conv, agent_id: VERIFIER_AGENT_ID, datapack_id: store.datapackId }); next.push(id); }
      catch (e) { if (!(e instanceof MekoToolError && e.payload?.error === 'not_found')) throw e; }
    }
    readable = next;
  }
  const leftover = [];
  let complete = true;
  for (let page = 1; page <= 2; page++) {
    const r = await store.client.callTool('memory_get_all', { conversation_id: conv, agent_id: VERIFIER_AGENT_ID, datapack_id: store.datapackId, page, page_size: 100 });
    for (const m of r.memories ?? []) if (String(m.data ?? '').startsWith('[TRUSTTRACE')) leftover.push(m.id);
    if (page >= (r.total_pages ?? 1)) break;
    if (page === 2) complete = false; // more than 200 memories: not expected in this plan
  }
  return { deleted: del.deleted, failed: del.failed, stillReadable: readable, leftoverInDatapack: leftover, complete, ok: !del.failed.length && !readable.length && !leftover.length && complete };
}

/**
 * @param {object} p
 * @param {{callTool: Function}} p.client  raw Meko client (or a test double); it is wrapped by guardClient
 * @param {object|null} p.pool             PostgreSQL pool for the demo database (null = Meko-only, used by offline tests)
 * @param {object} p.authority             verification authority (ephemeral key is fine)
 */
export async function seedDemo({
  client, pool = null, authority, execute = false, scenarioIds = PLAN_IDS, limits = LIMITS, pollMs = POLL_MS, indexTimeoutMs = INDEX_TIMEOUT_MS,
  cleanupRounds = 2, cleanupPauseMs = 3000, sleep, io = { print: (s) => console.log(s) }, configuredDatapack = DEMO_DATAPACK, allowExistingDecisions = false,
}) {
  const say = (s) => io.print(s);
  if (configuredDatapack !== DEMO_DATAPACK) throw new Error(`refusing to run: MEKO_DATAPACK is not exactly "${DEMO_DATAPACK}"`);
  const g = guardClient(client, { limits });

  // ---- plan: existing scenarios, selected by id, never modified ----
  const all = [...SCENARIOS, ...HARDENING_SCENARIOS];
  const picks = scenarioIds.map((id) => all.find((s) => s.id === id));
  if (picks.some((s) => !s)) throw new Error(`unknown scenario id in the plan: ${scenarioIds.join(',')}`);
  const orgOrPattern = picks.filter((s) => s.interactions.some((i) => i.scope === 'org' || (i.attestations ?? []).some((a) => a.kind === 'confirmed_attack_pattern')));
  if (orgOrPattern.length) throw new Error(`these scenarios use org-wide patterns and need extra searches, so they are not allowed in the reduced plan: ${orgOrPattern.map((s) => s.id).join(',')}`);

  // ---- read-only preflight ----
  const setupConv = await createConversation(g, { agentId: 'trusttrace_setup', title: 'TrustTrace setup', sessionId: SETUP_SESSION });
  const found = await g.callTool('datapack_search', { name: DEMO_DATAPACK, conversation_id: setupConv });
  const hits = (found?.datapacks ?? []).filter((d) => d.datapack_name === DEMO_DATAPACK);
  if (hits.length !== 1) throw new Error(`expected exactly one datapack named "${DEMO_DATAPACK}", found ${hits.length}; this script never creates datapacks`);
  const datapack = { id: hits[0].datapack_id, name: DEMO_DATAPACK };
  g.bind(datapack.id);
  const before = await snapshotAll(g, setupConv);
  const demo = before[DEMO_DATAPACK];
  if (!demo || demo.memory_count !== 0 || demo.knowledge_count !== 0 || demo.learnings_count !== 0) throw new Error(`the demo datapack is not empty (${demo?.memory_count} memories); refusing to run`);
  say(`target datapack: "${DEMO_DATAPACK}" (found by exact name, empty). other datapacks recorded as baseline: ${Object.keys(before).filter((n) => n !== DEMO_DATAPACK).join(', ') || '(none)'}`);
  if (pool) {
    const migrated = (await pool.query('SELECT count(*)::int AS n FROM schema_migrations')).rows[0].n;
    const { loadMigrations } = await import('../src/db/migrate.js');
    if (migrated !== loadMigrations().length) throw new Error(`the database has ${migrated} applied migrations, expected ${loadMigrations().length}; run the migrations first`);
    const decisions = (await pool.query('SELECT count(*)::int AS n FROM decisions')).rows[0].n;
    if (decisions > 0 && !allowExistingDecisions) throw new Error(`the demo database already holds ${decisions} decisions; this plan must run once (refusing to add a second copy)`);
    say(`database: schema fully migrated, ${decisions} decisions so far`);
  }
  say(`plan (${picks.length} existing scenarios, unchanged): ${picks.map((s) => `${s.id} ${s.title}`).join(' | ')}`);
  say(`budget caps: ${Object.entries(limits).map(([k, v]) => `${k} ${v}`).join(', ')}`);
  say(`estimate: ${Object.entries(ESTIMATE).map(([k, v]) => `${k} ${v}`).join(', ')}`);
  if (!execute) { say('DRY RUN: only read-only calls were made (datapack search/describe, the idempotent setup conversation). Nothing was written.'); return { dryRun: true, ok: true, counts: { ...g.counts } }; }

  // ---- real run ----
  const rawStore = new MemoryStore(g, datapack.id);
  const tracker = { savedIds: [], scopeIds: [], writers: {} };
  let store = rawStore; let extra = {}; let recorder = null;
  if (pool) {
    const { ActivityRecorder } = await import('../src/db/activity.js'); const { PgReplayGuard } = await import('../src/db/replayGuard.js');
    const { instrumentStore } = await import('../src/app/instrumentedStore.js'); const { DecisionService } = await import('../src/app/decisionService.js');
    recorder = new ActivityRecorder(pool);
    store = instrumentStore(rawStore, recorder);
    const guard = new PgReplayGuard(pool);
    authority.onIssued = (p) => guard.recordIssued(p);
    extra = { replayGuard: guard, assess: async (agent, event) => (await new DecisionService({ pool, recorder, agent }).assessAndRecord(event)).result };
  }
  let results = []; let runError = null; let cleanup = null;
  try {
    const run = await runScenarios({ store, tag: `D${randomUUID().slice(0, 8)}`, authority, scenarios: picks, tracker, pollMs, indexTimeoutMs, onProgress: (m) => say(`  running ${m} ...`), ...extra });
    results = run.results;
  } catch (err) {
    runError = err;
  } finally {
    cleanup = await leanCleanup({ store: rawStore, ids: tracker.savedIds, writers: tracker.writers, rounds: cleanupRounds, pauseMs: cleanupPauseMs, sleep }).catch((e) => ({ ok: false, error: `${e.name}: ${e.message}` }));
    await recorder?.close().catch(() => {});
  }

  // ---- verdict ----
  const checks = [];
  const add = (name, ok, detail = '') => { checks.push([name, Boolean(ok), detail]); say(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  -> ' + detail : ''}`); };
  add('the run completed without an error', !runError, runError ? `${runError.name}: ${runError.message}` : '');
  for (const r of results) add(`scenario ${r.id}: ${r.actual.action} (${r.actual.severity}) as expected [${r.classification}]`, r.pass);
  add(`all ${picks.length} scenarios ran`, results.length === picks.length, `${results.length}`);
  add(`cleanup: every memory this run wrote (${tracker.savedIds.length}) was deleted by id and confirmed gone, and no [TRUSTTRACE memory is left`, cleanup?.ok === true, cleanup?.error ?? `deleted ${cleanup?.deleted}`);
  let after = null;
  try { after = await snapshotAll(g, setupConv); } catch (e) { add('re-read the datapacks afterwards', false, `${e.name}: ${e.message}`); }
  if (after) { const problems = compareSnapshots(before, after); add(`${DEMO_DATAPACK} is empty again and every other datapack is unchanged`, problems.length === 0, problems.join('; ')); }
  if (pool) {
    const { verifyChain } = await import('../src/db/auditChain.js'); const { AUDIT_RESOLVERS } = await import('../src/db/auditResolvers.js');
    const n = (await pool.query('SELECT count(*)::int AS n FROM decisions')).rows[0].n;
    add(`PostgreSQL holds ${picks.length} decisions`, n === picks.length, `${n}`);
    const chain = await verifyChain(pool, { resolvers: AUDIT_RESOLVERS });
    add('the audit chain verifies', chain.ok === true, `${chain.checked} records`);
  }
  const used = { ...g.counts };
  add('no call was refused by the allowlist or the budgets', g.refused.length === 0, g.refused.join(' | '));
  say(`usage: ${Object.entries(used).map(([k, v]) => `${k} ${v}/${limits[k]}`).join(', ')}`);
  const ok = checks.every(([, o]) => o);
  say(ok ? 'SEEDING COMPLETE.' : 'SEEDING FINISHED WITH FAILURES: see the lines above.');
  return { dryRun: false, ok, counts: used, results, cleanup, runError, refused: g.refused };
}

// ------------------------------------------------------------------------------------------------ command line
async function main() {
  const args = process.argv.slice(2);
  const opt = (n) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
  const execute = args.includes('--execute'); const expectHost = opt('--expect-host');
  if (!expectHost) { console.error('usage: node --env-file=.env.demo scripts/seed-demo.mjs --expect-host <neon endpoint prefix> [--execute]\n(without --execute it is a read-only dry run)'); process.exit(2); }
  const root = process.cwd().replace(/\\/g, '/') + '/';
  const imp = (p) => import(pathToFileURL(root + p));
  const { loadConfig, loadDotEnv } = await imp('src/config.js'); const { loadAppConfig } = await imp('src/api/config.js'); const { createPool } = await imp('src/db/pool.js');
  loadDotEnv();
  const appConfig = loadAppConfig();
  if (!new URL(appConfig.databaseUrl).hostname.startsWith(expectHost)) { console.error('refusing to run: the database host does not start with --expect-host. Wrong .env.demo? Nothing was touched.'); process.exit(4); }
  const mekoConfig = loadConfig(process.env);
  if (mekoConfig.datapack !== DEMO_DATAPACK) { console.error(`refusing to run: MEKO_DATAPACK is "${mekoConfig.datapack}", it must be exactly "${DEMO_DATAPACK}". Nothing was touched.`); process.exit(5); }
  console.log(`database host matches --expect-host; Meko datapack is ${DEMO_DATAPACK}. Mode: ${execute ? 'EXECUTE' : 'DRY RUN (read-only)'}`);

  const { MekoClient } = await imp('src/meko/client.js'); const { loadAuthority } = await imp('src/trustSetup.js');
  const pool = createPool(appConfig, { max: 4 });
  let client;
  try {
    client = await new MekoClient(mekoConfig).connect();
    const { authority } = loadAuthority();
    const r = await seedDemo({ client, pool, authority, execute, configuredDatapack: mekoConfig.datapack });
    process.exitCode = r.ok ? 0 : 1;
  } catch (err) {
    console.error(`FAILED: ${String(err.message).replace(/postgres(?:ql)?:\/\/\S+/g, '<url>').replace(/mko_tkn_\S+/g, '<key>')}`);
    process.exitCode = 1;
  } finally { await client?.close?.(); await pool.end().catch(() => {}); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
