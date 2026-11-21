// Offline tests for scripts/seed-demo.mjs (the reduced, quota-safe Meko seeding). No network, no database, no Meko: a datapack-aware fake only.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  seedDemo, guardClient, compareSnapshots, leanCleanup, LIMITS, PLAN_IDS, DEMO_DATAPACK, ESTIMATE, QuotaExceededError, ForbiddenCallError,
} from '../scripts/seed-demo.mjs';
import { FakeDatapackMeko } from './helpers/fakeDatapackMeko.js';
import { MemoryStore } from '../src/meko/memory.js';
import { loadAuthority } from '../src/trustSetup.js';
import { SCENARIOS } from '../src/scenarios.js';

const quiet = { print() {} };
const fast = { pollMs: 5, indexTimeoutMs: 1500, cleanupPauseMs: 1, sleep: async () => {} };
const run = (fake, extra = {}) => seedDemo({ client: fake, authority: loadAuthority().authority, io: quiet, ...fast, ...extra });
const ALLOWED = new Set(Object.keys(LIMITS));
const memCount = (fake, id) => fake.memories.filter((m) => m.datapackId === id).length;
const snap = (fake) => JSON.stringify(fake.datapacks.map((d) => [d.id, fake.stamps.get(d.id), fake.memories.filter((m) => m.datapackId === d.id).length]));

describe('guardClient (deny by default)', () => {
  const mk = (limits = LIMITS) => { const fake = new FakeDatapackMeko(); const g = guardClient(fake, { limits }); return { fake, g }; };
  it('refuses tools that are not on the allowlist and never sends them', async () => {
    const { fake, g } = mk(); g.bind('dp-demo');
    for (const tool of ['datapack_create', 'datapack_delete', 'datapack_update', 'memory_delete_all', 'conversation_delete', 'conversation_add_message', 'context_search', 'knowledgebase_search']) {
      await assert.rejects(g.callTool(tool, { datapack_id: 'dp-demo' }), ForbiddenCallError, tool);
    }
    assert.equal(fake.sent.length, 0);
  });
  it('refuses memory calls before a datapack is bound and for any datapack other than the bound one', async () => {
    const { fake, g } = mk();
    await assert.rejects(g.callTool('memory_search', { datapack_id: 'dp-demo', query: 'x' }), ForbiddenCallError);
    g.bind('dp-demo');
    for (const dp of ['dp-test', 'dp-default', undefined, '']) await assert.rejects(g.callTool('memory_add', { datapack_id: dp, text: 'x', conversation_id: 'c' }), ForbiddenCallError, String(dp));
    assert.equal(fake.sent.length, 0);
    await g.callTool('memory_add', { datapack_id: 'dp-demo', text: 'ok', conversation_id: 'c', agent_id: 'a' });
    assert.equal(fake.sent.length, 1);
  });
  it('allows conversation_create only for the idempotent setup session or inside the bound datapack', async () => {
    const { fake, g } = mk();
    await g.callTool('conversation_create', { session_id: 'trusttrace-setup', agent_id: 'trusttrace_setup' });
    await assert.rejects(g.callTool('conversation_create', { session_id: 'other', agent_id: 'x' }), ForbiddenCallError);
    await assert.rejects(g.callTool('conversation_create', { session_id: 'trusttrace-setup', datapack_id: 'dp-test' }), ForbiddenCallError);
    g.bind('dp-demo');
    await assert.rejects(g.callTool('conversation_create', { session_id: 's', datapack_id: 'dp-test' }), ForbiddenCallError);
    await g.callTool('conversation_create', { session_id: 's', datapack_id: 'dp-demo' });
    assert.equal(fake.sent.length, 2);
  });
  it('fails closed when a budget is used up: the call is not sent and the budget is never exceeded', async () => {
    const { fake, g } = mk({ ...LIMITS, memory_search: 2 }); g.bind('dp-demo');
    const q = () => g.callTool('memory_search', { datapack_id: 'dp-demo', query: 'q', conversation_id: 'c', agent_id: 'a', run_id: 'c' });
    await q(); await q();
    await assert.rejects(q(), QuotaExceededError);
    await assert.rejects(q(), QuotaExceededError);
    assert.equal(fake.tally().memory_search, 2);
    assert.equal(g.counts.memory_search, 2);
  });
  it('counts a call that fails on the server (it still used quota)', async () => {
    const { g } = mk(); g.bind('dp-demo');
    await assert.rejects(g.callTool('memory_get_by_id', { datapack_id: 'dp-demo', memory_id: 'nope', conversation_id: 'c', agent_id: 'a' }));
    assert.equal(g.counts.memory_get_by_id, 1);
  });
});

describe('seedDemo: dry run', () => {
  it('makes only read-only calls and writes nothing', async () => {
    const fake = new FakeDatapackMeko(); const before = snap(fake);
    const r = await run(fake, { execute: false });
    assert.equal(r.dryRun, true); assert.equal(r.ok, true);
    assert.deepEqual(Object.keys(fake.tally()).sort(), ['conversation_create', 'datapack_describe', 'datapack_search']);
    assert.equal(fake.tally().datapack_search, 2, 'one exact-name lookup plus one listing for the baseline');
    assert.equal(fake.tally().datapack_describe, 3, 'one describe per visible datapack');
    assert.equal(fake.tally().conversation_create, 1, 'only the idempotent setup conversation');
    assert.equal(snap(fake), before);
    assert.equal(fake.memories.length, 0);
  });
});

describe('seedDemo: execute (5 existing scenarios, unchanged)', () => {
  it('passes all five, writes only to the demo datapack, cleans up without any search, leaves everything else untouched', async () => {
    const fake = new FakeDatapackMeko();
    const other = JSON.stringify([fake.stamps.get('dp-test'), fake.stamps.get('dp-default')]);
    const r = await run(fake, { execute: true });
    assert.equal(r.ok, true, JSON.stringify(r.refused));
    assert.equal(r.results.length, 5);
    assert.ok(r.results.every((x) => x.pass), JSON.stringify(r.results.filter((x) => !x.pass).map((x) => x.id)));
    assert.deepEqual(r.results.map((x) => x.id), PLAN_IDS);
    const t = fake.tally();
    assert.equal(t.memory_add, ESTIMATE.memory_add, 'adds match the published estimate');
    assert.equal(t.memory_delete_by_id, t.memory_add, 'every write is deleted');
    assert.ok(t.memory_search <= 12, `typical searches ${t.memory_search}`);
    assert.ok(t.memory_search <= LIMITS.memory_search);
    assert.equal(memCount(fake, 'dp-demo'), 0);
    assert.equal(memCount(fake, 'dp-test') + memCount(fake, 'dp-default'), 0);
    assert.equal(JSON.stringify([fake.stamps.get('dp-test'), fake.stamps.get('dp-default')]), other);
    assert.ok(fake.sent.every((c) => ALLOWED.has(c.name)), 'only allowlisted tools were ever sent');
    assert.ok(fake.sent.filter((c) => c.name.startsWith('memory_')).every((c) => c.args.datapack_id === 'dp-demo'));
    assert.ok(!fake.sent.some((c) => ['datapack_create', 'memory_delete_all', 'conversation_delete', 'datapack_delete'].includes(c.name)));
  });
  it('spends no memory_search during cleanup', async () => {
    const fake = new FakeDatapackMeko();
    const r = await run(fake, { execute: true });
    const lastAdd = fake.sent.map((c) => c.name).lastIndexOf('memory_add');
    const firstDelete = fake.sent.findIndex((c) => c.name === 'memory_delete_by_id');
    assert.ok(firstDelete > lastAdd);
    assert.equal(fake.sent.slice(firstDelete).filter((c) => c.name === 'memory_search').length, 0);
    assert.equal(r.cleanup.ok, true);
  });
  it('stays within the budgets with index lag (searches rise but stay under the cap)', async () => {
    for (const lag of [1, 2, 4]) {
      const fake = new FakeDatapackMeko({ lag });
      const r = await run(fake, { execute: true });
      assert.equal(r.ok, true, `lag ${lag}: ${JSON.stringify(r.refused)}`);
      assert.ok(fake.tally().memory_search <= LIMITS.memory_search, `lag ${lag}`);
      assert.equal(memCount(fake, 'dp-demo'), 0);
    }
  });
  it('still verifies cleanup when deletions take a moment to become visible', async () => {
    const fake = new FakeDatapackMeko({ deleteLag: 1 });
    const r = await run(fake, { execute: true });
    assert.equal(r.ok, true);
    assert.equal(r.cleanup.ok, true);
    assert.ok(fake.tally().memory_get_by_id >= ESTIMATE.memory_add, 'a second round of get_by_id was used');
    assert.ok(fake.tally().memory_get_by_id <= LIMITS.memory_get_by_id);
  });
  it('when the search budget trips mid-run it stops, still cleans up, never exceeds the cap and reports failure', async () => {
    const fake = new FakeDatapackMeko({ lag: 100000 }); // memories never become searchable: every poll is wasted
    const r = await run(fake, { execute: true, indexTimeoutMs: 400, limits: { ...LIMITS, memory_search: 6 } });
    assert.equal(r.ok, false);
    assert.ok(fake.tally().memory_search <= 6, `searches ${fake.tally().memory_search}`);
    assert.ok(r.refused.some((x) => x.startsWith('memory_search')) || r.runError || r.results.some((x) => !x.pass));
    assert.equal(memCount(fake, 'dp-demo'), 0, 'whatever was written is deleted');
    assert.equal(r.cleanup.ok, true);
  });
  it('a hard failure in the middle of the run still deletes what was written', async () => {
    const fake = new FakeDatapackMeko();
    let adds = 0; const orig = fake.callTool.bind(fake);
    fake.callTool = async (name, args) => { if (name === 'memory_add' && ++adds === 6) throw new Error('boom'); return orig(name, args); };
    const r = await run(fake, { execute: true });
    assert.equal(r.ok, false);
    assert.equal(memCount(fake, 'dp-demo'), 0);
    assert.equal(r.cleanup.ok, true);
  });
});

describe('seedDemo: refuses to start', () => {
  const refuse = async (fake, re, extra = {}) => { const before = snap(fake); await assert.rejects(run(fake, { execute: true, ...extra }), re); assert.equal(fake.tally().memory_add ?? 0, 0); assert.equal(snap(fake), before); };
  it('when MEKO_DATAPACK is not exactly trusttrace-demo', async () => {
    for (const name of ['trusttrace-test', 'meko_default_datapack', 'trusttrace-demo ', 'TrustTrace-Demo', '']) await refuse(new FakeDatapackMeko(), /not exactly/, { configuredDatapack: name });
  });
  it('when the demo datapack does not exist (it never creates one)', async () => {
    await refuse(new FakeDatapackMeko({ datapacks: [{ id: 'dp-test', name: 'trusttrace-test' }] }), /exactly one datapack/);
  });
  it('when two datapacks carry the name', async () => {
    await refuse(new FakeDatapackMeko({ datapacks: [{ id: 'a', name: 'trusttrace-demo' }, { id: 'b', name: 'trusttrace-demo' }] }), /exactly one datapack/);
  });
  it('when the demo datapack already holds memories', async () => {
    const fake = new FakeDatapackMeko();
    fake.memories.push({ id: 'pre', text: 'x', agentId: 'a', conversationId: 'c', seq: 0, datapackId: 'dp-demo' });
    await assert.rejects(run(fake, { execute: true }), /not empty/);
    assert.equal(fake.tally().memory_add ?? 0, 0);
    assert.equal(fake.memories.length, 1, 'the pre-existing memory was not touched');
  });
  it('when the plan contains an org-wide pattern scenario or an unknown id', async () => {
    const orgIds = SCENARIOS.filter((s) => s.interactions.some((i) => i.scope === 'org')).map((s) => s.id);
    assert.ok(orgIds.length > 0);
    await refuse(new FakeDatapackMeko(), /org-wide/, { scenarioIds: [orgIds[0]] });
    await refuse(new FakeDatapackMeko(), /unknown scenario/, { scenarioIds: ['S1', 'NOPE'] });
  });
});

describe('seedDemo: database checks (fake pool)', () => {
  const pool = (rows) => ({ query: async (sql) => ({ rows: [{ n: sql.includes('schema_migrations') ? rows.migrated : rows.decisions }] }) });
  it('refuses when the schema is not fully migrated', async () => {
    const fake = new FakeDatapackMeko();
    await assert.rejects(run(fake, { execute: true, pool: pool({ migrated: 1, decisions: 0 }) }), /applied migrations/);
    assert.equal(fake.tally().memory_add ?? 0, 0);
  });
  it('refuses to add a second copy when decisions already exist', async () => {
    const { loadMigrations } = await import('../src/db/migrate.js');
    const fake = new FakeDatapackMeko();
    await assert.rejects(run(fake, { execute: true, pool: pool({ migrated: loadMigrations().length, decisions: 3 }) }), /already holds 3 decisions/);
    assert.equal(fake.tally().memory_add ?? 0, 0);
  });
});

describe('compareSnapshots and leanCleanup', () => {
  const base = { 'trusttrace-demo': { memory_count: 0, updated_at: 'a' }, 'trusttrace-test': { memory_count: 0, updated_at: 'b', knowledge_count: 0 }, meko_default_datapack: { memory_count: 0, updated_at: 'c', knowledge_count: 9 } };
  const clone = (o) => JSON.parse(JSON.stringify(o));
  it('accepts identical other datapacks and an empty demo datapack (demo timestamps may change)', () => {
    const after = clone(base); after['trusttrace-demo'].updated_at = 'z';
    assert.deepEqual(compareSnapshots(base, after), []);
  });
  it('flags any change in another datapack, a non-empty demo datapack and a changed set of datapacks', () => {
    for (const [mut, re] of [
      [(a) => { a['trusttrace-test'].memory_count = 1; }, /trusttrace-test\.memory_count/],
      [(a) => { a.meko_default_datapack.updated_at = 'x'; }, /meko_default_datapack\.updated_at/],
      [(a) => { a.meko_default_datapack.knowledge_count = 10; }, /knowledge_count/],
      [(a) => { a['trusttrace-demo'].memory_count = 2; }, /still holds 2/],
      [(a) => { a.extra = { memory_count: 0 }; }, /set of datapacks/],
      [(a) => { delete a['trusttrace-test']; }, /set of datapacks/],
    ]) { const a = clone(base); mut(a); assert.match(compareSnapshots(base, a).join(';'), re); }
  });
  it('leanCleanup reports failure when a memory stays readable or a [TRUSTTRACE memory is left behind', async () => {
    const fake = new FakeDatapackMeko(); const store = new MemoryStore(fake, 'dp-demo');
    const saved = await store.saveRaw({ agentId: 'trusttrace_helpdesk', text: '[TRUSTTRACE ACCOUNT:s] hello', scopeId: 's' });
    const id = saved?.id ?? saved;
    assert.ok(id, 'a memory was written');
    // (1) written but NOT in the list of ids to delete -> must be reported as left behind in the datapack
    const left = await leanCleanup({ store, ids: [], writers: {}, rounds: 1, pauseMs: 1, sleep: async () => {} });
    assert.equal(left.ok, false);
    assert.equal(left.leftoverInDatapack.length, 1);
    // (2) deleting it by id makes the cleanup verify clean
    const clean = await leanCleanup({ store, ids: [id], writers: { [id]: 'trusttrace_helpdesk' }, rounds: 1, pauseMs: 1, sleep: async () => {} });
    assert.equal(clean.ok, true, JSON.stringify(clean));
    assert.equal(fake.memories.length, 0);
    // (3) a memory that cannot be deleted is reported, not hidden
    const saved2 = await store.saveRaw({ agentId: 'trusttrace_helpdesk', text: '[TRUSTTRACE ACCOUNT:s] stubborn', scopeId: 's' });
    const id2 = saved2?.id ?? saved2;
    const orig = fake.callTool.bind(fake);
    fake.callTool = async (n, a) => (n === 'memory_delete_by_id' ? { message: 'ok but not really' } : orig(n, a));
    const stuck = await leanCleanup({ store, ids: [id2], writers: { [id2]: 'trusttrace_helpdesk' }, rounds: 2, pauseMs: 1, sleep: async () => {} });
    assert.equal(stuck.ok, false);
    assert.deepEqual(stuck.stillReadable, [id2]);
  });
});
