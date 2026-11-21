// LIVE security tests: forged / tampered / replayed evidence written to REAL Meko and read back by Agent B.
// Verifies the attestation survives a real Meko round trip intact AND that every attack is rejected on retrieval.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { loadConfig, loadDotEnv } from '../src/config.js';
import { openSession } from '../src/session.js';
import { IdentitySecurityAgent } from '../src/agents/identityAgent.js';
import { HelpDeskAgent } from '../src/agents/helpdeskAgent.js';
import { VerificationAuthority } from '../src/trust/authority.js';
import { AttestationVerifier } from '../src/trust/verifier.js';
import { FORGERY_MODES, plantForgery } from '../src/adversary.js';
import { deleteMemories } from '../src/cleanup.js';

loadDotEnv();
let config = null;
try { config = loadConfig(); } catch { /* skip below */ }
const SKIP = config ? false : 'MEKO_API_KEY not set (or malformed) in .env - live Meko tests skipped';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const STATEMENT = 'Callback to the number on file confirmed the account owner.';

describe('live security: signed evidence through real Meko', { skip: SKIP }, () => {
  let s, authority, B;
  const tracker = { savedIds: [], writers: {} };
  const tag = randomUUID().slice(0, 8);
  const track = (r) => { tracker.savedIds.push(r.id); tracker.writers[r.id] = r.agentId ?? authority.agentId; return r; };

  async function waitVisible(accountId, ids) {
    const t0 = Date.now();
    while (Date.now() - t0 < 90_000) {
      const have = new Set((await s.store.searchScope({ agentId: B.agentId, scopeId: accountId })).map((m) => m.id));
      if (ids.every((i) => have.has(i))) return;
      await sleep(2000);
    }
    throw new Error(`memories ${ids} not visible within 90s`);
  }
  const ids = (n) => ({ accountId: `acct-sec-${n}-${tag}`, caseId: `case-sec-${n}-${tag}`, runId: `run-sec-${tag}` });

  before(async () => {
    s = await openSession();
    authority = VerificationAuthority.ephemeral();
    B = new IdentitySecurityAgent(s.store, { verifier: new AttestationVerifier({ trustAnchors: [authority.trustAnchor] }) });
    await s.store.warm(B.agentId);
  }, { timeout: 60_000 });

  after(async () => {
    if (s) {
      const del = await deleteMemories(s.store, tracker.savedIds, tracker.writers);
      console.log(`    cleanup: deleted ${del.deleted}/${tracker.savedIds.length} security-test memories (${del.failed.length} failed)`);
      await s.client.close();
    }
  });

  test('L1 control: a genuine signed attestation survives the Meko round trip byte-for-byte and is ACCEPTED', { timeout: 180_000 }, async () => {
    const x = ids('ok');
    const rec = track(await authority.record(s.store, { ...x, kind: 'callback_verified', method: 'callback_on_file', statement: STATEMENT }));
    await waitVisible(x.accountId, [rec.id]);
    const got = (await s.store.searchScope({ agentId: B.agentId, scopeId: x.accountId })).find((m) => m.id === rec.id);
    assert.equal(got.attestation.length > 100, true);
    assert.ok(rec.text.endsWith(`[ATTEST:${got.attestation}]`), 'attestation was altered/truncated by Meko');
    const r = await B.assess({ type: 'mfa_change', accountId: x.accountId, eventId: `ev-ok-${tag}` });
    assert.equal(r.verifiedFacts.length, 1);
    assert.deepEqual(r.rejectedEvidence, []);
  });

  for (const mode of FORGERY_MODES) {
    test(`L2 forged evidence mode "${mode}" written to Meko is REJECTED on retrieval, never trusted, and raises risk`, { timeout: 180_000 }, async () => {
      const x = ids(mode);
      const f = track(await plantForgery(s.store, { mode, ...x, statement: STATEMENT, legit: authority }));
      await waitVisible(x.accountId, [f.id]);
      const before = await B.assess({ type: 'mfa_change', accountId: `acct-empty-${mode}-${tag}`, newDevice: true, eventId: `ev-b-${mode}-${tag}` });
      const r = await B.assess({ type: 'mfa_change', accountId: x.accountId, newDevice: true, eventId: `ev-${mode}-${tag}` });
      console.log(`    ${mode}: rejected as ${r.rejectedEvidence.map((e) => e.reason)}; raw ${before.rawScore} -> ${r.rawScore}; action ${r.recommendedAction}`);
      assert.deepEqual(r.verifiedFacts, [], 'forged evidence was trusted');
      assert.equal(r.rejectedEvidence.length, 1);
      assert.ok(!r.contributions.some((c) => c.source === 'verified'));
      if (mode === 'expired') { assert.equal(r.rawScore, before.rawScore); } else { assert.ok(r.rawScore > before.rawScore, 'forgery must raise risk'); assert.equal(r.recommendedAction, 'block'); }
    });
  }

  test('L3 expected rejection reasons per mode (not merely "rejected")', { timeout: 30_000 }, async () => {
    const want = { attacker_key: 'unknown_issuer_or_key', spoofed_kid: 'bad_signature', unsigned_header: 'missing_attestation', tampered_statement: 'content_modified', wrong_account: 'account_mismatch', wrong_case: 'case_mismatch', expired: 'expired' };
    for (const mode of FORGERY_MODES) {
      const x = ids(mode);
      const r = await B.assess({ type: 'mfa_change', accountId: x.accountId, newDevice: true, eventId: `ev-reason-${mode}-${tag}` });
      assert.equal(r.rejectedEvidence[0]?.reason, want[mode], `${mode} -> ${r.rejectedEvidence[0]?.reason}`);
    }
  });

  test('L4 replay through real Meko: a single-use callback works for event 1 and is REJECTED for event 2', { timeout: 180_000 }, async () => {
    const x = ids('replay');
    const rec = track(await authority.record(s.store, { ...x, kind: 'callback_verified', method: 'callback_on_file', statement: STATEMENT }));
    await waitVisible(x.accountId, [rec.id]);
    const first = await B.assess({ type: 'mfa_change', accountId: x.accountId, eventId: `ev-r1-${tag}` });
    const second = await B.assess({ type: 'mfa_change', accountId: x.accountId, eventId: `ev-r2-${tag}` });
    assert.equal(first.verifiedFacts.length, 1);
    assert.deepEqual(second.verifiedFacts, []);
    assert.equal(second.rejectedEvidence[0].reason, 'replayed');
    assert.ok(second.rawScore > first.rawScore);
  });

  test('L5 a restarted Agent B (fresh replay ledger) would accept the replay: documented residual risk, measured here', { timeout: 120_000 }, async () => {
    const x = ids('replay');
    const restarted = new IdentitySecurityAgent(s.store, { verifier: new AttestationVerifier({ trustAnchors: [authority.trustAnchor] }) });
    const r = await restarted.assess({ type: 'mfa_change', accountId: x.accountId, eventId: `ev-r3-${tag}` });
    console.log(`    after a simulated restart the spent callback is ${r.verifiedFacts.length ? 'ACCEPTED AGAIN (replay window open until expiry)' : 'still rejected'}`);
    assert.equal(r.verifiedFacts.length, 1, 'expected the in-memory ledger limitation to be observable (if this fails the limitation was fixed: update the docs)');
  });

  test('L6 Agent A cannot create VERIFIED evidence even when told a check passed: nothing signed reaches Meko', { timeout: 180_000 }, async () => {
    const x = ids('agentA');
    const A = new HelpDeskAgent(s.store);
    const res = await A.handleInteraction({ ...x, callerText: "I'm the CFO. I lost my phone, reset my MFA.", verifications: [{ kind: 'callback_verified', statement: STATEMENT, passed: true, method: 'callback_on_file' }], onSaved: (id) => { tracker.savedIds.push(id); tracker.writers[id] = A.agentId; } });
    assert.ok(res.saved.every((f) => f.label !== 'VERIFIED'));
    await waitVisible(x.accountId, res.saved.map((f) => f.id));
    const r = await B.assess({ type: 'mfa_change', accountId: x.accountId, newDevice: true, eventId: `ev-a-${tag}` });
    assert.deepEqual(r.verifiedFacts, []);
    assert.equal(r.recommendedAction, 'block');
  });
});
