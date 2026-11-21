// LIVE: core + hardening scenarios through Agent A / verification authority -> real Meko -> Agent B, plus
// post-deletion verification and latency measurement. No mocks. Skipped (not passed) without MEKO_API_KEY.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { loadConfig, loadDotEnv } from '../src/config.js';
import { openSession } from '../src/session.js';
import { latencyStats } from '../src/meko/client.js';
import { runScenarios, formatTable } from '../src/scenarioRunner.js';
import { SCENARIOS } from '../src/scenarios.js';
import { HARDENING_SCENARIOS, KNOWN_GAPS } from '../src/scenarios.hardening.js';
import { VerificationAuthority } from '../src/trust/authority.js';
import { deleteMemories, verifyCleanup } from '../src/cleanup.js';

loadDotEnv();
let config = null;
try { config = loadConfig(); } catch { /* skip below */ }
const SKIP = config ? false : 'MEKO_API_KEY not set (or malformed) in .env - live Meko tests skipped';

describe('fraud scenarios on live Meko', { skip: SKIP }, () => {
  let s, core, hard, cleaned = false;
  const tracker = { savedIds: [], scopeIds: [], writers: {} };

  before(async () => {
    s = await openSession();
    const authority = VerificationAuthority.ephemeral();
    const tag = randomUUID().slice(0, 8);
    core = await runScenarios({ store: s.store, tag: `c${tag}`, authority, scenarios: SCENARIOS, tracker });
    hard = await runScenarios({ store: s.store, tag: `h${tag}`, authority, scenarios: HARDENING_SCENARIOS, tracker });
    console.log('\n=== CORE ===\n' + formatTable(core.results) + '\n\n=== HARDENING ===\n' + formatTable(hard.results) + '\n');
  }, { timeout: 900_000 });

  after(async () => {
    if (s && !cleaned) {
      const del = await deleteMemories(s.store, tracker.savedIds, tracker.writers);
      console.log(`    safety cleanup in after(): deleted ${del.deleted}/${tracker.savedIds.length}`);
    }
    await s?.client.close();
  });

  const detail = (r) => `${r.classification}: expected ${r.expected.actions.join('|')}, got ${r.actual.action} (base ${r.actual.baseAction}, raw ${r.actual.rawScore}); rejected=[${r.rejected.map((x) => x.reason)}]; checks ${JSON.stringify(r.checks)}`;

  for (const sc of SCENARIOS) {
    test(`CORE ${sc.id}: ${sc.title}`, { timeout: 30_000 }, () => {
      const r = core.results.find((x) => x.id === sc.id);
      assert.ok(r, 'scenario did not run');
      assert.ok(r.checks.indexed, `Meko did not index the saved memories in time. ${detail(r)}`);
      assert.ok(r.checks.retrievedOk, `memory retrieval expectation failed (retrieved ${r.memoriesRetrieved}). ${detail(r)}`);
      assert.ok(r.checks.actionCorrect, `wrong action. ${detail(r)}`);
      assert.ok(r.checks.severityOk, `wrong severity. ${detail(r)}`);
      assert.ok(r.checks.influenceOk, `influence expectation failed [${r.influencing.map((i) => i.source)}]. ${detail(r)}`);
      assert.ok(r.checks.policyOk, `policy expectation failed [${r.policy.map((p) => p.rule)}]. ${detail(r)}`);
    });
  }

  for (const sc of HARDENING_SCENARIOS) {
    const opts = { timeout: 30_000, ...(KNOWN_GAPS[sc.id] ? { todo: KNOWN_GAPS[sc.id] } : {}) };
    test(`HARDENING ${sc.id}: ${sc.title}`, opts, () => {
      const r = hard.results.find((x) => x.id === sc.id);
      assert.ok(r, 'scenario did not run');
      assert.ok(r.checks.indexed, `Meko did not index in time. ${detail(r)}`);
      assert.equal(r.classification, 'correct', detail(r));
      assert.ok(r.pass, detail(r));
    });
  }

  test('S6 (reviewed): the signed callback lowers the score yet a sensitive MFA change from a new device still needs step-up', () => {
    const r = core.results.find((x) => x.id === 'S6');
    assert.ok(r.influencing.some((i) => i.source === 'verified' && i.effect < 0));
    assert.equal(r.actual.baseAction, 'allow');
    assert.equal(r.actual.action, 'step_up');
    assert.ok(r.stepUp.required && r.stepUp.requirements.length >= 2);
  });

  test('S7: the signed VERIFIED pattern retrieved from Meko is what escalates the decision', () => {
    const r = core.results.find((x) => x.id === 'S7');
    assert.ok(r.influencing.some((i) => i.source === 'pattern'));
    assert.equal(r.counterfactual.withoutPattern.action, 'step_up');
    assert.equal(r.actual.action, 'block');
  });

  test('every forged-verification scenario: forged record fetched from Meko, REJECTED with the right reason, never trusted, never lowered risk', () => {
    for (const sc of HARDENING_SCENARIOS.filter((x) => x.expected.rejected)) {
      const r = hard.results.find((x) => x.id === sc.id);
      assert.ok(r.checks.rejectedOk, `${sc.id}: expected rejections ${sc.expected.rejected}, got ${r.rejected.map((x) => x.reason)}`);
      assert.ok(r.checks.noTrustFromRejected, sc.id);
      assert.ok(!r.influencing.some((i) => i.source === 'verified' && i.effect < 0), `${sc.id}: forged evidence reduced risk`);
      assert.equal(r.actual.action, 'block', `${sc.id}: ${detail(r)}`);
    }
  });

  test('latency: Meko retrieval and agent processing are measured separately', () => {
    const all = [...core.results, ...hard.results];
    const agg = (k) => all.reduce((a, r) => a + r.timings[k], 0);
    const stats = latencyStats(s.client.metrics);
    console.log('    totals (ms): ' + JSON.stringify({ mekoWrite: Math.round(agg('mekoWriteMs')), indexWait: Math.round(agg('indexWaitMs')), mekoRetrieval: Math.round(agg('retrievalMs')), agentExtract: +agg('agentExtractMs').toFixed(2), agentScoring: +agg('scoringMs').toFixed(2) }));
    console.log('    memory_search latency: ' + JSON.stringify(stats.memory_search));
    console.log('    memory_add latency: ' + JSON.stringify(stats.memory_add));
    for (const r of all) for (const v of Object.values(r.timings)) assert.ok(Number.isFinite(v) && v >= 0);
    assert.ok(agg('scoringMs') < agg('retrievalMs'), 'agent scoring should be far cheaper than a Meko round-trip');
  });

  test('cleanup: after deletion, querying Meko shows ALL test memories (incl. forged ones) are gone', { timeout: 300_000 }, async () => {
    const n = tracker.savedIds.length;
    assert.ok(n > 0);
    const del = await deleteMemories(s.store, tracker.savedIds, tracker.writers);
    assert.deepEqual(del.failed, [], 'some deletes failed');
    const v = await verifyCleanup({ store: s.store, savedIds: tracker.savedIds, scopeIds: tracker.scopeIds, timeoutMs: 120_000 });
    cleaned = true;
    console.log('    cleanup verification: ' + JSON.stringify({ memoriesChecked: v.memoriesChecked, confirmedAbsent: v.memoriesConfirmedAbsent, leftInDatapack: v.trusttraceMemoriesLeftInDatapack.length, scopesWithResults: v.scopesWithResults.length, conversations: Object.keys(v.conversations).length, allReused: Object.values(v.conversations).every((c) => c.reusedNotRecreated), ms: v.ms }));
    assert.equal(v.memoriesConfirmedAbsent, n, `still readable: ${v.memoriesStillReadable}`);
    assert.deepEqual(v.trusttraceMemoriesLeftInDatapack, []);
    assert.deepEqual(v.scopesWithResults, []);
    assert.ok(Object.values(v.conversations).every((c) => c.reusedNotRecreated), 'conversations are being re-created per run');
  });
});
