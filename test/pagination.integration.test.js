// LIVE investigation: "the fallback is paginated" vs "Meko search has no pagination".
// Resolution under test: memory_search has NO pagination (its schema has no offset/page/cursor), but the fallback does not use
// it - it pages through a DIFFERENT tool, memory_get_all (page, page_size<=100, total_pages). 230 memories are seeded so that
// (a) a limit-200 search is genuinely truncated and (b) the scan spans 3 pages.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { loadConfig, loadDotEnv } from '../src/config.js';
import { openSession } from '../src/session.js';
import { deleteMemories } from '../src/cleanup.js';

loadDotEnv();
let config = null;
try { config = loadConfig(); } catch { /* skip below */ }
const SKIP = config ? false : 'MEKO_API_KEY not set (or malformed) in .env - live Meko tests skipped';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function pmap(items, fn, concurrency = 6) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => { while (i < items.length) { const k = i++; await fn(items[k], k); } }));
}

describe('live: search truncation vs paginated scan', { skip: SKIP }, () => {
  const N = 230;
  const tag = randomUUID().slice(0, 8);
  const T = `acct-pg-${tag}`;
  const ids = [];
  const writers = {};
  let s, conv, bucket;
  const call = (name, args) => s.client.callTool(name, { conversation_id: conv, agent_id: 'trusttrace_pagination_probe', datapack_id: s.datapack.id, ...args });

  before(async () => {
    s = await openSession();
    conv = await s.store.conversationFor('trusttrace_pagination_probe');
    bucket = await s.store.bucketConversation(T);
    await pmap(Array.from({ length: N }, (_, i) => i), async (i) => {
      const r = await s.store.save({ agentId: 'trusttrace_helpdesk_agent', caseId: `case-${T}`, accountId: T, runId: `run-${tag}`, label: 'CLAIMED', kind: 'role_claim', statement: `Pagination probe fact number ${i} for ${T}` });
      ids.push(r.id); writers[r.id] = 'trusttrace_helpdesk_agent';
    });
    const t0 = Date.now();
    for (;;) { // wait until Meko has indexed everything for search
      const r = await call('memory_search', { query: `TRUSTTRACE ACCOUNT:${T}`, run_id: bucket, limit: 1000 });
      if (r.results.length >= N || Date.now() - t0 > 180_000) { console.log(`    seeded ${N}; search(limit 1000) sees ${r.results.length} after ${Math.round((Date.now() - t0) / 1000)}s`); break; }
      await sleep(3000);
    }
  }, { timeout: 400_000 });

  after(async () => {
    if (!s) return;
    const del = await deleteMemories(s.store, ids, writers);
    console.log(`    cleanup: deleted ${del.deleted}/${ids.length} (${del.failed.length} failed)`);
    await s.client.close();
  });

  test('PG1 memory_search exposes NO pagination parameter (schema inspected live)', async () => {
    const tool = (await s.client.listTools()).find((t) => t.name === 'memory_search');
    const props = Object.keys(tool.inputSchema.properties);
    console.log(`    memory_search parameters: ${props.join(', ')}`);
    for (const p of ['offset', 'page', 'page_size', 'cursor', 'skip', 'next_cursor']) assert.ok(!props.includes(p), `memory_search unexpectedly has "${p}"`);
    const ga = (await s.client.listTools()).find((t) => t.name === 'memory_get_all');
    const gprops = Object.keys(ga.inputSchema.properties);
    console.log(`    memory_get_all parameters: ${gprops.join(', ')}`);
    assert.ok(gprops.includes('page') && gprops.includes('page_size'), 'memory_get_all should be the paginated tool');
  });

  test('PG2 a limit-200 search returns exactly 200 of 230 (truncated, no way to ask for the rest), limit 1000 returns all 230', async () => {
    const a = await call('memory_search', { query: `TRUSTTRACE ACCOUNT:${T}`, run_id: bucket, limit: 200 });
    const b = await call('memory_search', { query: `TRUSTTRACE ACCOUNT:${T}`, run_id: bucket, limit: 1000 });
    console.log(`    search limit 200 -> ${a.results.length}; limit 1000 -> ${b.results.length}`);
    assert.equal(a.results.length, 200);
    assert.equal(b.results.length, N);
  });

  test('PG3 documented-maximum probe: what do very large limits do? (measurement)', async () => {
    for (const limit of [5000, 100000]) {
      try {
        const r = await call('memory_search', { query: `TRUSTTRACE ACCOUNT:${T}`, run_id: bucket, limit });
        console.log(`    limit ${limit}: accepted, returned ${r.results.length}`);
      } catch (e) {
        console.log(`    limit ${limit}: REJECTED -> ${e.name}: ${String(e.message).slice(0, 140)}`);
      }
    }
  });

  test('PG4 memory_get_all IS paginated: page_size is capped, total_pages is reported, pages are disjoint and cover everything (newest first)', { timeout: 120_000 }, async () => {
    const seen = new Map();
    let totalPages = 1, reportedPageSize, total;
    const times = [];
    for (let page = 1; page <= totalPages; page++) {
      const t0 = performance.now();
      const r = await call('memory_get_all', { page, page_size: 500 }); // ask for more than the cap on purpose
      times.push(Math.round(performance.now() - t0));
      totalPages = r.total_pages; reportedPageSize = r.page_size; total = r.total;
      for (const m of r.memories) { assert.ok(!seen.has(m.id), `duplicate across pages: ${m.id}`); seen.set(m.id, m); }
      assert.ok(r.memories.length <= 100, `page ${page} returned ${r.memories.length} rows (> cap 100)`);
    }
    console.log(`    requested page_size 500 -> server page_size ${reportedPageSize}; total ${total}; total_pages ${totalPages}; per-page ms ${times}`);
    assert.ok(reportedPageSize <= 100, 'page_size must be clamped to 100');
    assert.ok(totalPages >= 3, `expected >= 3 pages for ${N}+ memories, got ${totalPages}`);
    for (const id of ids) assert.ok(seen.has(id), `memory ${id} missing from the paginated listing`);
    const created = [...seen.values()].map((m) => Date.parse(m.created_at)).filter(Number.isFinite);
    assert.ok(created.every((t, i) => i === 0 || t <= created[i - 1] + 1000), 'listing is not newest-first');
  });

  test('PG5 the implemented fallback (search limit 200 -> truncated -> memory_get_all scan) recovers ALL 230, across multiple pages', { timeout: 120_000 }, async () => {
    const t0 = performance.now();
    const r = await s.store.retrieveScope({ agentId: 'trusttrace_pagination_probe', scopeId: T, limit: 200 });
    const ms = Math.round(performance.now() - t0);
    console.log(`    meta ${JSON.stringify(r.meta)} in ${ms} ms`);
    assert.equal(r.meta.truncated, true);
    assert.equal(r.meta.usedFallback, true);
    assert.ok(r.meta.scannedPages >= 3, `scanned only ${r.meta.scannedPages} pages`);
    assert.equal(r.meta.complete, true);
    assert.deepEqual(r.memories.map((m) => m.id).sort(), [...ids].sort());
  });

  test('PG6 the scan cap is honest: with maxScanPages=1 only 100 rows are covered and completeness is reported FALSE', { timeout: 120_000 }, async () => {
    const r = await s.store.retrieveScope({ agentId: 'trusttrace_pagination_probe', scopeId: T, strategy: 'scan', maxScanPages: 1 });
    assert.equal(r.meta.complete, false);
    assert.ok(r.memories.length < ids.length);
  });

  test('PG6b memory_get_all accepts run_id but IGNORES it (no server-side scoping of the scan): a memory from another bucket still appears', { timeout: 120_000 }, async () => {
    const { bucketOf } = await import('../src/meko/memory.js');
    let other = null;
    for (let i = 0; !other; i++) { const c = `acct-pg-other-${tag}-${i}`; if (bucketOf(c) !== bucketOf(T)) other = c; }
    const r = await s.store.save({ agentId: 'trusttrace_helpdesk_agent', caseId: 'c', accountId: other, runId: 'r', label: 'CLAIMED', kind: 'role_claim', statement: `other-bucket probe ${other}` });
    ids.push(r.id); writers[r.id] = 'trusttrace_helpdesk_agent';
    await sleep(2000);
    const page = await call('memory_get_all', { page: 1, page_size: 100, run_id: bucket }); // run_id = the OTHER scope's bucket conversation
    const found = page.memories.some((m) => m.id === r.id);
    console.log(`    get_all(run_id=bucket(T)) still returned the other-bucket memory: ${found}`);
    assert.equal(found, true, 'if this fails Meko started honouring run_id on memory_get_all: the scan can now be scoped server-side - update memory.js and the docs');
  });

  test('PG7 cleanup is verifiable: after deleting, the paginated listing contains none of the seeded memories', { timeout: 300_000 }, async () => {
    const del = await deleteMemories(s.store, ids, writers);
    assert.deepEqual(del.failed, []);
    const left = [];
    let totalPages = 1;
    for (let page = 1; page <= totalPages; page++) {
      const r = await call('memory_get_all', { page, page_size: 100 });
      totalPages = r.total_pages;
      for (const m of r.memories) if (String(m.data ?? '').startsWith('[TRUSTTRACE')) left.push(m.id);
    }
    console.log(`    TrustTrace memories left in the datapack after deletion: ${left.length}`);
    assert.deepEqual(left, []);
    ids.length = 0;
  });
});
