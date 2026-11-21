// Offline tests: the activity recorder (batching, loss accounting) and the instrumented store (records real operations,
// never changes behaviour). A fake pool captures the SQL; the real INSERT is exercised in test/db/persistence.integration.test.js.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ActivityRecorder } from '../src/db/activity.js';
import { instrumentStore } from '../src/app/instrumentedStore.js';
import { FakeStore } from './helpers/fakeStore.js';
import { HelpDeskAgent } from '../src/agents/helpdeskAgent.js';
import { IdentitySecurityAgent } from '../src/agents/identityAgent.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** TEST DOUBLE pool that records every query. */
const fakePool = () => ({
  queries: [], failNext: 0,
  async query(sql, values) {
    if (this.failNext > 0) { this.failNext--; throw Object.assign(new Error('connection reset'), { code: 'ECONNRESET' }); }
    this.queries.push({ sql, values });
    return {};
  },
});
const evt = (i, extra = {}) => ({ agentId: 'a', kind: 'memory_written', accountId: `acct-${i}`, ...extra });
const rec = (pool, o = {}) => new ActivityRecorder(pool, { flushDelayMs: 60_000, ...o }); // no auto-flush unless a test wants it

describe('ActivityRecorder', () => {
  test('batches of at most 200 rows; placeholders and casts match the value count', async () => {
    const pool = fakePool(); const r = rec(pool);
    for (let i = 0; i < 450; i++) r.record(evt(i));
    await r.flush();
    assert.deepEqual(pool.queries.map((q) => q.values.length / 12), [200, 200, 50]);
    for (const q of pool.queries) {
      const rows = q.values.length / 12;
      assert.equal((q.sql.match(/::text\[\]/g) ?? []).length, rows);
      assert.equal((q.sql.match(/::jsonb/g) ?? []).length, rows);
      assert.equal(Math.max(...[...q.sql.matchAll(/\$(\d+)/g)].map((m) => Number(m[1]))), q.values.length);
    }
    assert.deepEqual(r.stats(), { recorded: 450, written: 450, dropped: 0, failedBatches: 0, lastError: null, queued: 0 });
    await r.close();
  });
  test('column order and null handling', async () => {
    const pool = fakePool(); const r = rec(pool);
    const at = new Date('2026-01-02T03:04:05.678Z');
    r.record({ at, agentId: 'ag', kind: 'k', memoryIds: ['m1', 'm2'], payload: { x: 1 }, durationMs: 12.5, ok: false, error: 'e'.repeat(900) });
    await r.flush();
    const v = pool.queries[0].values;
    assert.equal(v[0], at); assert.equal(v[1], 'ag'); assert.equal(v[2], 'k');
    assert.deepEqual(v.slice(3, 7), [null, null, null, null]); // account, case, event, decision
    assert.deepEqual(v[7], ['m1', 'm2']);
    assert.equal(v[8], '{"x":1}');
    assert.equal(v[9], 12.5); assert.equal(v[10], false);
    assert.equal(v[11].length, 500, 'error text is truncated');
    await r.close();
  });
  test('a FAILED batch is retained and retried: nothing is lost, failures are counted', async () => {
    const pool = fakePool(); const r = rec(pool);
    for (let i = 0; i < 5; i++) r.record(evt(i));
    pool.failNext = 1;
    await assert.rejects(r.flush());
    assert.equal(r.stats().failedBatches, 1);
    assert.equal(r.stats().lastError, 'ECONNRESET');
    assert.equal(r.stats().queued, 5);
    await r.flush();
    assert.equal(r.stats().written, 5);
    assert.equal(r.stats().dropped, 0);
    await r.close();
  });
  test('buffer overflow drops the OLDEST events and counts them (loss is visible, never silent)', () => {
    const r = rec(fakePool(), { maxBuffer: 10 });
    for (let i = 0; i < 25; i++) r.record(evt(i));
    assert.equal(r.stats().dropped, 15);
    assert.equal(r.stats().queued, 10);
    assert.equal(r.buffer[0].accountId, 'acct-15');
    clearTimeout(r.timer);
  });
  test('auto-flush happens after the delay without anyone calling flush()', async () => {
    const pool = fakePool(); const r = new ActivityRecorder(pool, { flushDelayMs: 20 });
    r.record(evt(1));
    await sleep(120);
    assert.equal(pool.queries.length, 1);
    await r.close();
  });
  test('close() flushes what is queued and leaves no timer behind', async () => {
    const pool = fakePool(); const r = rec(pool);
    r.record(evt(1));
    await r.close();
    assert.equal(pool.queries.length, 1);
    assert.equal(r.timer, null);
  });
  test('a payload that cannot be serialised (circular) does not poison the batch', async () => {
    const pool = fakePool(); const r = rec(pool);
    const circ = {}; circ.self = circ;
    r.record(evt(1, { payload: circ })); r.record(evt(2));
    await r.flush();
    assert.equal(r.stats().written, 2);
    assert.equal(pool.queries[0].values[8], '{"unserializable":true}');
    await r.close();
  });
  test('record() never throws, even for odd input', () => {
    const r = rec(fakePool());
    for (const e of [{}, { agentId: undefined }, { memoryIds: null }]) assert.doesNotThrow(() => r.record(e));
    clearTimeout(r.timer);
  });
});

describe('instrumentStore (decorates the real store, behaviour unchanged)', () => {
  const captured = () => { const events = []; return { events, recorder: { record: (e) => events.push(e) } }; };

  test('Agent A writes and Agent B reads are recorded with memory ids, labels and timings', async () => {
    const { events, recorder } = captured();
    const store = instrumentStore(new FakeStore(), recorder);
    const A = new HelpDeskAgent(store);
    const B = new IdentitySecurityAgent(store);
    const res = await A.handleInteraction({ caseId: 'c1', accountId: 'acct-1', runId: 'r', callerText: "I'm the CFO. I lost my phone, reset my MFA." });
    const written = events.filter((e) => e.kind === 'memory_written');
    assert.equal(written.length, res.saved.length);
    assert.deepEqual(written.map((e) => e.memoryIds[0]).sort(), res.saved.map((f) => f.id).sort());
    assert.ok(written.every((e) => e.agentId === A.agentId && e.accountId === 'acct-1' && e.caseId === 'c1' && e.ok === true && e.durationMs >= 0));
    await B.assess({ type: 'mfa_change', accountId: 'acct-1', newDevice: true });
    const read = events.find((e) => e.kind === 'memories_retrieved');
    assert.equal(read.agentId, B.agentId);
    assert.equal(read.memoryIds.length, res.saved.length);
    assert.equal(read.payload.count, res.saved.length);
    assert.ok(read.payload.labels.CLAIMED > 0);
  });
  test('results are IDENTICAL with and without instrumentation (it is not a mock)', async () => {
    const run = async (wrap) => {
      const base = new FakeStore();
      const store = wrap ? instrumentStore(base, { record() {} }) : base;
      await new HelpDeskAgent(store).handleInteraction({ caseId: 'c', accountId: 'acct-x', runId: 'r', callerText: "I'm the CFO. I lost my phone, reset my MFA, it's urgent." });
      const out = await new IdentitySecurityAgent(store).assess({ type: 'mfa_change', accountId: 'acct-x', newDevice: true, eventId: 'e' });
      return { raw: out.rawScore, action: out.recommendedAction, n: out.retrieved.length };
    };
    assert.deepEqual(await run(true), await run(false));
  });
  test('failures are recorded (ok:false, error) and still thrown to the caller', async () => {
    const { events, recorder } = captured();
    const base = new FakeStore();
    base.save = async () => { throw new Error('meko exploded'); };
    const store = instrumentStore(base, recorder);
    await assert.rejects(store.save({ agentId: 'a', accountId: 'acct', caseId: 'c', label: 'CLAIMED', kind: 'k' }), /meko exploded/);
    assert.equal(events[0].kind, 'memory_write_failed');
    assert.equal(events[0].ok, false);
    assert.match(events[0].error, /meko exploded/);
  });
  test('activityContext tags every store call made during an assessment with its case / event / decision (reads included)', async () => {
    const { activityContext } = await import('../src/app/instrumentedStore.js');
    const { events, recorder } = captured();
    const store = instrumentStore(new FakeStore(), recorder);
    const B = new IdentitySecurityAgent(store);
    await store.save({ agentId: 'a', caseId: 'c-write', accountId: 'acct-ctx', runId: 'r', label: 'CLAIMED', kind: 'role_claim', statement: 's' });
    await activityContext.run({ caseId: 'case-X', eventId: 'ev-X', decisionId: 'dec-X' }, () => B.assess({ type: 'login', accountId: 'acct-ctx' }));
    const read = events.find((e) => e.kind === 'memories_retrieved');
    assert.deepEqual([read.caseId, read.eventId, read.decisionId], ['case-X', 'ev-X', 'dec-X']);
    const outside = events.find((e) => e.kind === 'memory_written');
    assert.equal(outside.caseId, 'c-write', 'calls outside any context keep their own fields');
    assert.equal(outside.decisionId, undefined);
  });
  test('inside a context, an event\'s own caseId wins over the context, and undefined fields never erase context values', async () => {
    const { activityContext } = await import('../src/app/instrumentedStore.js');
    const { events, recorder } = captured();
    const store = instrumentStore(new FakeStore(), recorder);
    await activityContext.run({ caseId: 'ctx-case', eventId: 'ctx-ev', decisionId: 'ctx-dec' }, async () => {
      await store.save({ agentId: 'a', caseId: 'own-case', accountId: 'acct', runId: 'r', label: 'CLAIMED', kind: 'role_claim', statement: 's' });
      await store.remove('nope', 'a');
    });
    assert.equal(events[0].caseId, 'own-case');
    assert.equal(events[0].decisionId, 'ctx-dec');
    assert.equal(events[1].caseId, 'ctx-case');
  });
  test('a broken recorder can never break an agent', async () => {
    const store = instrumentStore(new FakeStore(), { record() { throw new Error('recorder bug'); } });
    const out = await new HelpDeskAgent(store).handleInteraction({ caseId: 'c', accountId: 'acct', runId: 'r', callerText: "I'm the CFO." });
    assert.ok(out.saved.length > 0);
  });
  test('deletes are recorded; other properties and methods pass through untouched', async () => {
    const { events, recorder } = captured();
    const base = new FakeStore();
    const store = instrumentStore(base, recorder);
    const r = await store.save({ agentId: 'a', caseId: 'c', accountId: 'acct', runId: 'r', label: 'CLAIMED', kind: 'role_claim', statement: 's' });
    await store.remove(r.id, 'a');
    assert.ok(events.some((e) => e.kind === 'memory_deleted' && e.memoryIds[0] === r.id));
    assert.equal(typeof store.warm, 'function');
    assert.equal(store.rows.length, 0);
  });
});
