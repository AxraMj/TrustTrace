// Offline replay of the independently-worded HARDENING scenarios through the real agents + authority + an
// in-memory test double. Expected outcomes (src/scenarios.hardening.js) were fixed before running; tests that
// reveal a genuine detection gap are marked `todo` WITH the reason - they still run and are reported, they do not
// hide the gap. Nothing here claims real-world detection accuracy: these are synthetic, self-authored cases.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { FakeStore } from './helpers/fakeStore.js';
import { makeTrust } from './helpers/trust.js';
import { runScenarios, classify } from '../src/scenarioRunner.js';
import { HARDENING_SCENARIOS, KNOWN_GAPS } from '../src/scenarios.hardening.js';

describe('hardening scenarios (offline, independent wording)', () => {
  let results;
  before(async () => {
    ({ results } = await runScenarios({ store: new FakeStore(), tag: 'hard', pollMs: 1, authority: makeTrust().authority, scenarios: HARDENING_SCENARIOS }));
  });

  for (const sc of HARDENING_SCENARIOS) {
    const opts = KNOWN_GAPS[sc.id] ? { todo: KNOWN_GAPS[sc.id] } : {};
    test(`${sc.id}: ${sc.title}`, opts, () => {
      const r = results.find((x) => x.id === sc.id);
      const msg = `${r.classification}: expected ${sc.expected.actions.join('|')}, got ${r.actual.action} (base ${r.actual.baseAction}, raw ${r.actual.rawScore}); rejected=[${r.rejected.map((x) => x.reason)}]; checks=${JSON.stringify(r.checks)}`;
      assert.equal(r.classification, 'correct', msg);
      assert.ok(r.pass, msg);
    });
  }

  test('classification: false positive = more severe than acceptable, false negative = more lenient', () => {
    assert.equal(classify('block', ['allow', 'step_up']), 'FALSE_POSITIVE');
    assert.equal(classify('allow', ['block']), 'FALSE_NEGATIVE');
    assert.equal(classify('allow', ['step_up', 'block']), 'FALSE_NEGATIVE');
    assert.equal(classify('step_up', ['allow', 'step_up']), 'correct');
  });

  test('INVARIANT: in every scenario, rejected records never also count as accepted verified evidence', () => {
    for (const r of results) assert.ok(r.checks.noTrustFromRejected, r.id);
  });

  test('INVARIANT: no forged-verification scenario ever lowered risk (rejected evidence contributes only >= 0)', () => {
    for (const r of results.filter((x) => x.rejected.length)) {
      assert.ok(r.rejected.every((x) => x.points >= 0), r.id);
      assert.ok(!r.influencing.some((i) => i.source === 'verified' && i.effect < 0), `${r.id}: a forged record reduced risk`);
    }
  });
});
