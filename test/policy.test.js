// Pins decision 001 (docs/decisions/001-overseas-login-policy.md): how a sign-in from a new country is treated.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { FakeStore } from './helpers/fakeStore.js';
import { makeTrust } from './helpers/trust.js';
import { HelpDeskAgent } from '../src/agents/helpdeskAgent.js';
import { IdentitySecurityAgent } from '../src/agents/identityAgent.js';

async function world() {
  const store = new FakeStore();
  const t = makeTrust();
  const A = new HelpDeskAgent(store);
  const B = new IdentitySecurityAgent(store, { verifier: t.verifier });
  let n = 0;
  const acct = () => `acct-pol-${++n}`;
  return { store, t, A, B, acct };
}

describe('decision 001: new-country sign-in', () => {
  test('known device, new country, nothing else -> allow WITH a notification advisory (H1)', async () => {
    const w = await world();
    const r = await w.B.assess({ type: 'login', accountId: w.acct(), newCountry: true });
    assert.equal(r.recommendedAction, 'allow');
    assert.equal(r.rawScore, 15);
    assert.deepEqual(r.advisories.map((a) => a.code), ['notify_user_new_country']);
    assert.match(r.explanation.join('\n'), /\[ADVISORY\] notify_user_new_country/);
  });
  test('no advisory when nothing unusual happened', async () => {
    const w = await world();
    const r = await w.B.assess({ type: 'login', accountId: w.acct() });
    assert.deepEqual(r.advisories, []);
  });
  test('new country + new device -> step_up (no advisory: it is not an allow)', async () => {
    const w = await world();
    const r = await w.B.assess({ type: 'login', accountId: w.acct(), newCountry: true, newDevice: true });
    assert.equal(r.recommendedAction, 'step_up');
    assert.deepEqual(r.advisories, []);
  });
  test('new country + poor IP reputation -> step_up', async () => {
    const w = await world();
    const r = await w.B.assess({ type: 'login', accountId: w.acct(), newCountry: true, ipReputation: 'bad' });
    assert.equal(r.recommendedAction, 'step_up');
  });
  test('new country AFTER a suspicious help-desk call escalates: the context now counts at full weight', async () => {
    const w = await world();
    const accountId = w.acct();
    await w.A.handleInteraction({ caseId: 'c', accountId, runId: 'r', callerText: "Hello, I'm the CFO. I lost my phone, please reset my MFA." });
    const r = await w.B.assess({ type: 'login', accountId, newCountry: true });
    assert.notEqual(r.recommendedAction, 'allow', `raw ${r.rawScore}`);
    assert.equal(r.contextWeight, 1);
  });
  test('the SAME call followed by a login from the usual country is only a half-weight signal (unchanged Phase 3 behaviour)', async () => {
    const w = await world();
    const accountId = w.acct();
    await w.A.handleInteraction({ caseId: 'c', accountId, runId: 'r', callerText: "Hello, I'm the CFO. I lost my phone, please reset my MFA." });
    const r = await w.B.assess({ type: 'login', accountId });
    assert.equal(r.contextWeight, 0.5);
  });
  test('an attested new device makes a new-country login allowed again, with the advisory', async () => {
    const w = await world();
    const accountId = w.acct();
    await w.t.authority.record(w.store, { caseId: 'c', accountId, runId: 'r', kind: 'device_verified', method: 'device_attestation', statement: 'Device approved from an existing trusted device.' });
    const r = await w.B.assess({ type: 'login', accountId, newCountry: true, newDevice: true });
    assert.equal(r.recommendedAction, 'allow');
    assert.ok(r.advisories.some((a) => a.code === 'notify_user_new_country'));
  });
  test('sensitive actions from a new country are NEVER allowed, whatever the score (see H2)', async () => {
    const w = await world();
    for (const type of ['mfa_change', 'bank_detail_change', 'password_reset']) {
      const accountId = w.acct();
      await w.t.authority.record(w.store, { caseId: 'c', accountId, runId: 'r', kind: 'callback_verified', method: 'callback_on_file', statement: `Owner confirmed for ${type}.` });
      const r = await w.B.assess({ type, accountId, newCountry: true, eventId: `e-${type}` });
      assert.notEqual(r.recommendedAction, 'allow', type);
    }
  });
  test('the severity thresholds and the new-country weight are unchanged by this decision', async () => {
    const { SEVERITY_THRESHOLDS } = await import('../src/agents/identityAgent.js');
    assert.deepEqual({ ...SEVERITY_THRESHOLDS }, { medium: 25, high: 50, critical: 75 });
    const w = await world();
    assert.equal((await w.B.assess({ type: 'login', accountId: w.acct(), newCountry: true })).rawScore, 15);
  });
});
