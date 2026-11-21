// Offline tests of the risk-scoring model: score boundaries, raw vs display, verified-evidence effects.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  IdentitySecurityAgent, displayScore, severityFor, actionFor, SEVERITY_THRESHOLDS,
} from '../src/agents/identityAgent.js';

import { makeTrust } from './helpers/trust.js';

const trust = makeTrust();
const B = new IdentitySecurityAgent(null, { verifier: trust.verifier });
const ACCT = 'acct-x';
let n = 0;
const mem = (label, kind, statement = `${kind} statement`, extra = {}) => ({
  id: `m${++n}`, trusttrace: true, accountId: ACCT, label, kind, statement, ...extra,
});
// VERIFIED evidence is now signed by the verification authority; Agent B authenticates it before use.
const verified = (kind = 'callback_verified', statement = 'Callback confirmed owner', extra = {}) =>
  trust.signedMemory({ kind, statement, accountId: ACCT, method: extra.verifiedBy ?? 'callback_on_file' });

// A call-derived attack story worth 75 raw points at full weight (claims 35 + observed 40).
const attackStory = () => [
  mem('CLAIMED', 'role_claim'), mem('CLAIMED', 'lost_device_claim'), mem('CLAIMED', 'mfa_unavailable_claim'),
  mem('CLAIMED', 'request_mfa_reset'),
  mem('OBSERVED', 'urgency_pressure'), mem('OBSERVED', 'verification_resistance'), mem('OBSERVED', 'caller_id_mismatch'),
];
const extremeEvent = { type: 'mfa_change', accountId: ACCT, newDevice: true, newCountry: true, ipReputation: 'bad' }; // 70 raw

describe('display score curve', () => {
  test('boundaries: 0 -> 0, negatives floor at 0, huge values stay within [0,100]', () => {
    assert.equal(displayScore(0), 0);
    assert.equal(displayScore(-500), 0);
    assert.equal(displayScore(1e9), 100);
    for (const raw of [0.1, 1, 24.9, 25, 50, 75, 100, 150, 300]) {
      const d = displayScore(raw);
      assert.ok(d > 0 && d <= 100, `raw ${raw} -> ${d}`);
    }
  });
  test('monotonic: more raw risk never lowers display; strictly increasing (0.1 resolution) up to raw 225, flat-but-not-decreasing beyond', () => {
    let prev = -1;
    for (let raw = 0; raw <= 400; raw += 5) {
      const d = displayScore(raw);
      assert.ok(d >= prev, `not monotonic at ${raw}`);
      if (raw <= 225 && raw > 0) assert.ok(d > prev, `flat at ${raw} (display saturated too early)`);
      prev = d;
    }
  });
  test('known values (documented curve 100*(1-exp(-raw/50)))', () => {
    assert.equal(displayScore(25), 39.3);
    assert.equal(displayScore(50), 63.2);
    assert.equal(displayScore(100), 86.5);
  });
});

describe('severity / action boundaries (decided from RAW score)', () => {
  const cases = [
    [-10, 'low', 'allow'], [0, 'low', 'allow'], [24.9, 'low', 'allow'],
    [25, 'medium', 'step_up'], [49.9, 'medium', 'step_up'],
    [50, 'high', 'block'], [74.9, 'high', 'block'],
    [75, 'critical', 'block'], [100, 'critical', 'block'], [250, 'critical', 'block'],
  ];
  for (const [raw, sev, act] of cases) {
    test(`raw ${raw} -> ${sev} / ${act}`, () => {
      assert.equal(severityFor(raw), sev);
      assert.equal(actionFor(sev), act);
    });
  }
  test('thresholds are the documented ones', () => {
    assert.deepEqual({ ...SEVERITY_THRESHOLDS }, { medium: 25, high: 50, critical: 75 });
  });
});

describe('raw and display are preserved separately', () => {
  test('raw score is NOT clamped: it can exceed 100, while display stays <= 100', () => {
    const r = B.score({ type: 'mfa_change', accountId: ACCT, newDevice: true, newCountry: true }, attackStory());
    assert.equal(r.rawScore, 125); // 50 event + 75 context
    assert.ok(r.displayScore < 100 && r.displayScore > 85);
    assert.notEqual(r.rawScore, r.displayScore);
    assert.equal(r.riskScore, r.displayScore); // legacy alias
  });
  test('raw score can go negative when only strong verified evidence exists; display floors at 0', () => {
    const r = B.score({ type: 'login', accountId: ACCT }, [verified('device_verified', 'Known device', { verifiedBy: 'device_attestation' })]);
    assert.equal(r.rawScore, -25);
    assert.equal(r.displayScore, 0);
    assert.equal(r.severity, 'low');
    assert.equal(r.recommendedAction, 'allow');
  });
});

describe('every contribution is explained and adds up', () => {
  const r = B.score({ type: 'mfa_change', accountId: ACCT, newDevice: true }, [...attackStory(), verified()]);
  test('contribution points sum to the raw score', () => {
    const sum = r.contributions.reduce((a, c) => a + c.effectivePoints, 0);
    assert.ok(Math.abs(sum - r.rawScore) < 0.11, `${sum} vs ${r.rawScore}`);
  });
  test('every contribution has base, weight, effective points and a text explanation', () => {
    for (const c of r.contributions) {
      assert.equal(typeof c.basePoints, 'number');
      assert.equal(typeof c.weight, 'number');
      assert.ok(Math.abs(c.basePoints * c.weight - c.effectivePoints) < 1e-9);
      assert.ok(c.text && c.text.length > 5);
    }
    assert.equal(r.explanation.length, r.contributions.length + 1); // + TOTAL line
    assert.match(r.explanation.at(-1), /^\[TOTAL\] raw .* severity /);
  });
  test('discounts are shown, not hidden', () => {
    assert.match(r.explanation.join('\n'), /discounted by verified identity/);
  });
});

describe('verified evidence reduces risk, even from a very high score', () => {
  test('extreme case: raw 145 (critical) drops by >= 40 and at least one severity level with a verified callback', () => {
    const before = B.score(extremeEvent, attackStory());
    const after = B.score(extremeEvent, [...attackStory(), verified()]);
    assert.equal(before.rawScore, 145);
    assert.equal(before.severity, 'critical');
    assert.ok(before.rawScore - after.rawScore >= 40, `only dropped ${before.rawScore - after.rawScore}`);
    assert.notEqual(after.severity, 'critical');
    assert.ok(before.displayScore - after.displayScore >= 10, `display only dropped ${before.displayScore - after.displayScore}`);
  });
  test('the old failure mode is gone: verified evidence on a >100 raw score still moves the display score', () => {
    const ev = { type: 'mfa_change', accountId: ACCT, newDevice: true, newCountry: true };
    const before = B.score(ev, attackStory()); // raw 125 (was clamped to 100 before)
    const after = B.score(ev, [...attackStory(), verified()]);
    assert.ok(after.displayScore < before.displayScore);
    assert.ok(after.rawScore < before.rawScore);
  });
  test('verified identity discounts call-derived signals but NOT hard signals (failed verification)', () => {
    const hard = [mem('OBSERVED', 'callback_failed_failed', 'A different check failed')];
    const noV = B.score({ type: 'mfa_change', accountId: ACCT, newDevice: true }, hard);
    const withV = B.score({ type: 'mfa_change', accountId: ACCT, newDevice: true }, [...hard, verified()]);
    const hardContribution = (r) => r.contributions.find((c) => c.kind === 'callback_failed_failed').effectivePoints;
    assert.equal(hardContribution(noV), 25);
    assert.equal(hardContribution(withV), 25); // unchanged by the verified callback
  });
  test('device_verified lowers risk but does not discount call signals', () => {
    const ev = { type: 'mfa_change', accountId: ACCT, newDevice: true };
    const r = B.score(ev, [mem('CLAIMED', 'lost_device_claim'), verified('device_verified', 'Device is the owner\'s', { verifiedBy: 'device_attestation' })]);
    const claim = r.contributions.find((c) => c.kind === 'lost_device_claim');
    assert.equal(claim.effectivePoints, 10); // not halved
    assert.equal(r.verifiedIdentityMitigation, false);
  });
  test('authentic evidence of a kind with no account-level scoring rule has no effect (never silently trusted)', () => {
    const base = B.score(extremeEvent, attackStory());
    // an attack-pattern attestation is only meaningful org-wide; at account level it earns no credit
    const r = B.score(extremeEvent, [...attackStory(), verified('confirmed_attack_pattern', 'INC-1 signature=role_claim')]);
    assert.equal(r.rawScore, base.rawScore);
    assert.match(r.explanation.join('\n'), /no scoring rule/);
  });
  test('duplicate verified evidence of the same kind counts once (memory_add does not de-duplicate)', () => {
    const one = B.score(extremeEvent, [verified('callback_verified', 'a')]);
    const five = B.score(extremeEvent, ['a', 'b', 'c', 'd', 'e'].map((s) => verified('callback_verified', s)));
    assert.equal(five.rawScore, one.rawScore);
  });
});

describe('CLAIMED information stays an unverified signal', () => {
  test('claims never reduce risk, never appear as verified facts', () => {
    const ev = { type: 'login', accountId: ACCT, newDevice: true };
    const base = B.score(ev, []);
    const r = B.score(ev, [mem('CLAIMED', 'identity_claim', 'Caller claims to be a verified employee'), mem('CLAIMED', 'role_claim')]);
    assert.ok(r.rawScore >= base.rawScore);
    assert.deepEqual(r.verifiedFacts, []);
    assert.equal(r.unverifiedClaims.length, 2);
    for (const c of r.contributions.filter((x) => x.label === 'CLAIMED')) {
      assert.ok(c.effectivePoints >= 0);
      assert.match(c.text, /NOT as a fact/);
    }
  });
  test('a repeated identical CLAIMED memory counts once', () => {
    const ev = { type: 'login', accountId: ACCT, newDevice: true };
    const once = B.score(ev, [mem('CLAIMED', 'lost_device_claim', 'same')]);
    const thrice = B.score(ev, [mem('CLAIMED', 'lost_device_claim', 'same'), mem('CLAIMED', 'lost_device_claim', 'same'), mem('CLAIMED', 'lost_device_claim', 'same')]);
    assert.equal(thrice.rawScore, once.rawScore);
  });
});

describe('routine-event weighting', () => {
  test('context signals count at half weight for a routine login, full for a sensitive event', () => {
    const story = [mem('CLAIMED', 'lost_device_claim'), mem('OBSERVED', 'urgency_pressure')]; // 20 base
    assert.equal(B.score({ type: 'login', accountId: ACCT }, story).rawScore, 10);
    assert.equal(B.score({ type: 'login', accountId: ACCT, newDevice: true }, story).rawScore, 15 + 20);
    assert.equal(B.score({ type: 'password_reset', accountId: ACCT }, story).rawScore, 15 + 20);
  });
});

describe('scope isolation', () => {
  test('memories from another account never influence the decision', () => {
    const other = (m) => ({ ...m, accountId: 'acct-someone-else' });
    const ev = { type: 'mfa_change', accountId: ACCT, newDevice: true };
    const base = B.score(ev, []);
    assert.equal(B.score(ev, attackStory().map(other)).rawScore, base.rawScore);
    assert.equal(B.score(ev, [other(verified())]).rawScore, base.rawScore);
  });
});
