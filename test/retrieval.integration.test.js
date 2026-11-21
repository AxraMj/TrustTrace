// LIVE retrieval tests against real Meko: account isolation, irrelevant memories, a crowded bucket, truncation
// fallback, and a measurement of the OLD unscoped top-N approach. Skipped (not passed) without MEKO_API_KEY.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { loadConfig, loadDotEnv } from '../src/config.js';
import { openSession } from '../src/session.js';
import { bucketOf } from '../src/meko/memory.js';
import { IdentitySecurityAgent } from '../src/agents/identityAgent.js';
import { deleteMemories, verifyCleanup } from '../src/cleanup.js';

loadDotEnv();
let config = null;
try { config = loadConfig(); } catch { /* skip below */ }
const SKIP = config ? false : 'MEKO_API_KEY not set (or malformed) in .env - live Meko tests skipped';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function pmap(items, fn, concurrency = 6) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
  }));
  return out;
}

describe('live retrieval at scale', { skip: SKIP }, () => {
  const tag = randomUUID().slice(0, 8);
  const T = `acct-ret-${tag}`;
  const writers = {};
  const all = [];
  const scopes = new Set([T]);
  let s, B;
  const targetKinds = [['CLAIMED', 'role_claim'], ['CLAIMED', 'lost_device_claim'], ['CLAIMED', 'request_mfa_reset'], ['OBSERVED', 'urgency_pressure'], ['OBSERVED', 'caller_id_mismatch'], ['OBSERVED', 'verification_resistance']];
  let targetIds = [];
  let lookalikeIds = [];
  let bucketTotal = 0;
  let relevantInBucket = 0;

  const save = async (accountId, i, over = {}) => {
    const r = await s.store.save({ agentId: 'trusttrace_helpdesk_agent', caseId: `case-${accountId}`, accountId, runId: `run-${tag}`, label: 'CLAIMED', kind: 'role_claim', statement: `Noise statement ${i} for ${accountId}`, ...over });
    all.push(r.id); writers[r.id] = over.agentId ?? 'trusttrace_helpdesk_agent';
    scopes.add(accountId);
    return r.id;
  };

  before(async () => {
    s = await openSession();
    B = new IdentitySecurityAgent(s.store);
    await s.store.warm(B.agentId);
    const sameBucket = [];
    for (let i = 0; sameBucket.length < 5; i++) if (bucketOf(`acct-noise-${tag}-${i}`) === bucketOf(T)) sameBucket.push(`acct-noise-${tag}-${i}`);
    const otherBucket = Array.from({ length: 5 }, (_, i) => `acct-far-${tag}-${i}`).filter((x) => bucketOf(x) !== bucketOf(T));

    targetIds = await pmap(targetKinds, ([label, kind], i) => save(T, i, { label, kind, statement: `Target fact ${kind}` }));
    await pmap(sameBucket.flatMap((sc) => Array.from({ length: 9 }, (_, i) => [sc, i])), ([sc, i]) => save(sc, i)); // 45 in T's bucket
    await pmap(otherBucket.flatMap((sc) => Array.from({ length: 3 }, (_, i) => [sc, i])), ([sc, i]) => save(sc, i)); // other buckets
    // irrelevant free text stored in T's bucket conversation, plus look-alike accounts forced into T's bucket
    await pmap(['Sprint planning notes: ship the dashboard', 'Lunch order for Friday: 12 pizzas', `mentions ${T} in passing, not a TrustTrace record`, 'Quarterly OKR draft', 'ACCOUNT:' + T + ' is only a phrase here', 'Random trivia about octopuses'], async (text) => {
      const r = await s.store.saveRaw({ agentId: 'someone_else', text, scopeId: T });
      all.push(r.id); writers[r.id] = 'someone_else';
    });
    lookalikeIds = await pmap([`${T}9`, `${T}-b`].flatMap((a) => [0, 1, 2].map((i) => [a, i])), ([a, i]) => save(a, i, { bucketScopeId: T, statement: `Look-alike ${a} fact ${i}` }));
    bucketTotal = targetIds.length + 45 + 6 + lookalikeIds.length; // everything planted under T's bucket conversation
    // Meko's memory_search applies an undocumented RELEVANCE CUTOFF (verified live): unrelated free text is never
    // returned, even with limit 500 and fewer results than the limit. Only relevant memories can crowd a search.
    relevantInBucket = targetIds.length + 45 + lookalikeIds.length;

    // wait until Meko has indexed the whole bucket (so the crowding is real)
    const t0 = Date.now();
    for (;;) {
      const r = await s.store.retrieveScope({ agentId: B.agentId, scopeId: T, limit: 500 });
      if (r.meta.searchReturned >= relevantInBucket || Date.now() - t0 > 150_000) { console.log(`    bucket indexed: ${r.meta.searchReturned} returned of ${bucketTotal} planted (${relevantInBucket} relevant) after ${Math.round((Date.now() - t0) / 1000)}s`); break; }
      await sleep(3000);
    }
  }, { timeout: 400_000 });

  after(async () => {
    if (!s) return;
    const del = await deleteMemories(s.store, all, writers);
    console.log(`    cleanup: deleted ${del.deleted}/${all.length} memories (${del.failed.length} failed)`);
    await s.client.close();
  });

  test('RL1 scoped search returns EXACTLY the target\'s 6 memories among a crowded bucket (no noise, no look-alikes)', { timeout: 60_000 }, async () => {
    const r = await s.store.retrieveScope({ agentId: B.agentId, scopeId: T });
    console.log(`    meta: ${JSON.stringify(r.meta)}`);
    assert.deepEqual(r.memories.map((m) => m.id).sort(), [...targetIds].sort());
    assert.equal(r.meta.complete, true);
    assert.equal(r.meta.truncated, false);
    assert.ok(r.memories.every((m) => m.accountId === T));
    assert.ok(r.meta.searchReturned >= relevantInBucket, `the bucket was not crowded as intended (${r.meta.searchReturned} < ${relevantInBucket})`);
  });

  test('RL8 DOCUMENTED MEKO LIMITATION: search has a relevance cutoff, so "fewer results than limit" does NOT prove completeness', { timeout: 60_000 }, async () => {
    const r = await s.store.retrieveScope({ agentId: B.agentId, scopeId: T, limit: 500 });
    console.log(`    planted ${bucketTotal} memories in the bucket, search(limit 500) returned ${r.meta.searchReturned}`);
    assert.equal(r.meta.truncated, false);
    assert.ok(r.meta.searchReturned < bucketTotal, 'if this fails Meko stopped applying a relevance cutoff: update the docs and risk register');
  });

  test('RL2 a search limit smaller than the bucket is DETECTED as truncation and the paginated scan still recovers all 6', { timeout: 120_000 }, async () => {
    const r = await s.store.retrieveScope({ agentId: B.agentId, scopeId: T, limit: 25 });
    console.log(`    meta: ${JSON.stringify(r.meta)}`);
    assert.equal(r.meta.truncated, true);
    assert.equal(r.meta.usedFallback, true);
    assert.equal(r.meta.complete, true);
    assert.deepEqual(r.memories.map((m) => m.id).sort(), [...targetIds].sort());
  });

  test('RL3 exhaustive scan strategy agrees with the scoped search', { timeout: 120_000 }, async () => {
    const t0 = performance.now();
    const r = await s.store.retrieveScope({ agentId: B.agentId, scopeId: T, strategy: 'scan' });
    console.log(`    scan: ${Math.round(performance.now() - t0)} ms, pages=${r.meta.scannedPages}`);
    assert.deepEqual(r.memories.map((m) => m.id).sort(), [...targetIds].sort());
  });

  test('RL4 look-alike accounts planted in the SAME bucket never appear in the target\'s results, and are intact under their own id', { timeout: 120_000 }, async () => {
    const mine = await s.store.retrieveScope({ agentId: B.agentId, scopeId: T });
    assert.ok(!mine.memories.some((m) => lookalikeIds.includes(m.id)));
    const theirs = await s.store.retrieveScope({ agentId: B.agentId, scopeId: `${T}9`, strategy: 'scan' });
    assert.equal(theirs.memories.length, 3);
    assert.ok(theirs.memories.every((m) => m.accountId === `${T}9`));
  });

  test('RL5 end to end: Agent B\'s decision for the target is exactly the 6-fact score, untouched by 60+ unrelated memories', { timeout: 120_000 }, async () => {
    const r = await B.assess({ type: 'mfa_change', accountId: T, newDevice: true, eventId: `ev-ret-${tag}` });
    assert.equal(r.retrieved.length, 6);
    assert.equal(r.rawScore, 100); // event 35 + role 5 + lost 10 + reset 10 + urgency 10 + caller-id 15 + resistance 15
    assert.equal(r.retrievalComplete, true);
  });

  test('RL6 MEASUREMENT (not an assertion): recall of the OLD unscoped top-N search over the whole datapack', { timeout: 120_000 }, async () => {
    const conv = await s.store.conversationFor(B.agentId);
    for (const limit of [10, 50]) {
      const res = await s.client.callTool('memory_search', { query: `TRUSTTRACE ACCOUNT:${T}`, conversation_id: conv, agent_id: B.agentId, datapack_id: s.datapack.id, limit });
      const hits = res.results.filter((m) => targetIds.includes(m.id)).length;
      console.log(`    OLD approach (no run_id scoping), limit ${limit}: found ${hits}/${targetIds.length} target memories (${res.results.length} results returned)`);
    }
  });

  test('RL7 cleanup: all retrieval-test memories are gone when queried afterwards', { timeout: 400_000 }, async () => {
    const del = await deleteMemories(s.store, all, writers);
    assert.deepEqual(del.failed, []);
    const v = await verifyCleanup({ store: s.store, savedIds: all, scopeIds: [...scopes].slice(0, 6), timeoutMs: 180_000 });
    console.log(`    cleanup verification: confirmedAbsent ${v.memoriesConfirmedAbsent}/${v.memoriesChecked}, left in datapack ${v.trusttraceMemoriesLeftInDatapack.length}`);
    assert.equal(v.memoriesConfirmedAbsent, all.length);
    assert.deepEqual(v.trusttraceMemoriesLeftInDatapack, []);
    all.length = 0;
  });
});
