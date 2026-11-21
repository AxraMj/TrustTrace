// Offline tests of Agent B's PERSISTENT replay-guard path (prepare / atomic commit / race retry / fail closed), using an
// in-memory atomic ledger TEST DOUBLE that has the same contract as PgReplayGuard. The SQL implementation of that contract
// is tested against real PostgreSQL in test/db/persistence.integration.test.js.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { FakeStore } from './helpers/fakeStore.js';
import { makeTrust } from './helpers/trust.js';
import { IdentitySecurityAgent } from '../src/agents/identityAgent.js';
import { decodeEnvelope } from '../src/trust/attestation.js';
import { parseMemory } from '../src/labels.js';

/** TEST DOUBLE with the PgReplayGuard contract: atomic all-or-nothing commit, snapshot prepare. */
class MemoryLedger {
  constructor({ interleave = false } = {}) {
    this.spent = new Map(); this.down = false; this.commitDown = false; this.interleave = interleave;
    this.staleFirstPrepare = false; this.prepares = 0; this.commits = [];
  }
  async prepare(nonces) {
    this.prepares++;
    if (this.down) throw new Error('ledger down');
    if (this.interleave) await new Promise((r) => setImmediate(r));
    const snap = new Map();
    if (!(this.staleFirstPrepare && this.prepares === 1)) for (const n of nonces) if (this.spent.has(n)) snap.set(n, this.spent.get(n));
    return { unavailable: false, isReplay: (n, e) => snap.has(n) && snap.get(n) !== e };
  }
  async commit(consumables, eventId, ctx) {
    if (this.commitDown) throw new Error('write failed');
    if (this.interleave) await new Promise((r) => setImmediate(r));
    this.commits.push({ nonces: consumables.map((c) => c.nonce), eventId, ctx });
    const conflicts = consumables.filter((c) => this.spent.has(c.nonce) && this.spent.get(c.nonce) !== eventId).map((c) => c.nonce);
    if (conflicts.length) return { ok: false, conflicts, consumed: [] };
    for (const c of consumables) this.spent.set(c.nonce, eventId);
    return { ok: true, conflicts: [], consumed: consumables.map((c) => c.nonce) };
  }
}

const ACCT = 'acct-async';
const CASE = 'case-async';
const nonceOf = (text) => decodeEnvelope(parseMemory(text).attestation).payload.nonce;

async function world({ ledger = new MemoryLedger() } = {}) {
  const store = new FakeStore();
  const t = makeTrust();
  const mk = () => new IdentitySecurityAgent(store, { verifier: t.verifier, replayGuard: ledger });
  const attest = async (kind, statement = `${kind} ok`, method = 'callback_on_file') =>
    t.authority.record(store, { caseId: CASE, accountId: ACCT, runId: 'r', kind, method, statement });
  return { store, t, ledger, B: mk(), mk, attest };
}
const ev = (id, extra = {}) => ({ type: 'mfa_change', accountId: ACCT, newDevice: true, eventId: id, ...extra });

describe('persistent replay guard: normal operation', () => {
  test('first sensitive event spends the callback; the SAME event again is idempotent; a different event is a replay', async () => {
    const w = await world();
    const rec = await w.attest('callback_verified');
    const first = await w.B.assess(ev('E1'), { decisionId: 'dec-1' });
    assert.equal(first.verifiedFacts.length, 1);
    assert.equal(first.replayLedger, 'ok');
    assert.equal(w.ledger.spent.get(nonceOf(rec.text)), 'E1');
    assert.equal(w.ledger.commits[0].ctx.decisionId, 'dec-1', 'the decision id is recorded with the spend');
    const again = await w.B.assess(ev('E1'));
    assert.equal(again.verifiedFacts.length, 1, 'a retry of the same event is not a replay');
    const other = await w.B.assess(ev('E2'));
    assert.deepEqual(other.verifiedFacts, []);
    assert.equal(other.rejectedEvidence[0].reason, 'replayed');
    assert.ok(other.rawScore > first.rawScore, 'a replay must not be cheaper than the first use');
  });
  test('a routine LOGIN does not spend the callback (only sensitive actions do)', async () => {
    const w = await world();
    await w.attest('callback_verified');
    await w.B.assess({ type: 'login', accountId: ACCT, eventId: 'L1' });
    assert.equal(w.ledger.spent.size, 0);
    assert.equal(w.ledger.commits.length, 0);
    assert.equal((await w.B.assess(ev('E1'))).verifiedFacts.length, 1);
  });
  test('PERSISTENCE: a brand-new Agent B instance (a process restart) still rejects the replay, unlike the in-process guard', async () => {
    const w = await world();
    await w.attest('callback_verified');
    await w.B.assess(ev('E1'));
    const restarted = w.mk(); // fresh agent, SAME ledger
    const r = await restarted.assess(ev('E2'));
    assert.deepEqual(r.verifiedFacts, []);
    assert.equal(r.rejectedEvidence[0].reason, 'replayed');
  });
  test('reusable evidence (device attestation) is not spent and still works repeatedly', async () => {
    const w = await world();
    await w.attest('device_verified', 'Device approved.', 'device_attestation');
    assert.equal((await w.B.assess(ev('E1'))).verifiedFacts.length, 1);
    assert.equal((await w.B.assess(ev('E2'))).verifiedFacts.length, 1);
    assert.equal(w.ledger.spent.size, 0);
  });
});

describe('persistent replay guard: races', () => {
  test('RACE: two different events presenting the same callback at the same time -> exactly ONE wins', async () => {
    const w = await world({ ledger: new MemoryLedger({ interleave: true }) });
    const rec = await w.attest('callback_verified');
    const [a, b] = await Promise.all([w.B.assess(ev('E1')), w.mk().assess(ev('E2'))]);
    const winners = [a, b].filter((r) => r.verifiedFacts.length === 1);
    const losers = [a, b].filter((r) => r.verifiedFacts.length === 0);
    assert.equal(winners.length, 1, 'exactly one event may use a single-use verification');
    assert.equal(losers.length, 1);
    assert.equal(losers[0].rejectedEvidence[0].reason, 'replayed');
    assert.ok(['E1', 'E2'].includes(w.ledger.spent.get(nonceOf(rec.text))));
    assert.equal(w.ledger.spent.size, 1);
  });
  test('commit-time conflict (stale snapshot) is retried: the conflicting evidence is rejected, the rest is still spent atomically', async () => {
    const w = await world();
    const cb = await w.attest('callback_verified');
    const id = await w.attest('identity_verified', 'Identity confirmed.', 'authenticator_push');
    w.ledger.spent.set(nonceOf(id.text), 'SOMEONE-ELSE'); // already spent by another event
    w.ledger.staleFirstPrepare = true; // the first read misses it (a race): only the commit reveals the conflict
    const r = await w.B.assess(ev('E1'));
    assert.equal(r.replayAttempts, 2);
    assert.deepEqual(r.rejectedEvidence.map((x) => x.reason), ['replayed']);
    assert.equal(r.verifiedFacts.length, 1, 'the callback is still honoured');
    assert.equal(w.ledger.spent.get(nonceOf(cb.text)), 'E1');
    assert.equal(w.ledger.spent.get(nonceOf(id.text)), 'SOMEONE-ELSE');
  });
});

describe('persistent replay guard: fails closed', () => {
  test('ledger UNREADABLE: single-use evidence is rejected with replay_ledger_unavailable (0 points), never trusted', async () => {
    const w = await world();
    await w.attest('callback_verified');
    w.ledger.down = true;
    const r = await w.B.assess(ev('E1'));
    assert.equal(r.replayLedger, 'unavailable');
    assert.deepEqual(r.verifiedFacts, []);
    assert.equal(r.rejectedEvidence[0].reason, 'replay_ledger_unavailable');
    assert.equal(r.rejectedEvidence[0].points, 0, 'an outage is not an attack: no risk added');
    assert.equal(r.rawScore, w.B.score(ev('X'), []).rawScore);
    assert.notEqual(r.recommendedAction, 'allow');
  });
  test('ledger UNWRITABLE: the spend cannot be recorded, so the evidence is NOT trusted (it could be reused later)', async () => {
    const w = await world();
    await w.attest('callback_verified');
    w.ledger.commitDown = true;
    const r = await w.B.assess(ev('E1'));
    assert.deepEqual(r.verifiedFacts, []);
    assert.equal(r.rejectedEvidence[0].reason, 'replay_ledger_unavailable');
    assert.equal(w.ledger.spent.size, 0);
  });
  test('ledger down: non-single-use evidence (device attestation) is still honoured, the outage does not over-block', async () => {
    const w = await world();
    await w.attest('device_verified', 'Device approved.', 'device_attestation');
    w.ledger.down = true;
    const r = await w.B.assess(ev('E1'));
    assert.equal(r.verifiedFacts.length, 1);
  });
  test('persistent losing streak (3 attempts) ends fail-closed instead of looping', async () => {
    const w = await world();
    await w.attest('callback_verified');
    const real = w.ledger.commit.bind(w.ledger);
    w.ledger.commit = async (c, e, ctx) => ({ ...(await real([], 'x', ctx)), ok: false, conflicts: c.map((x) => x.nonce) });
    const r = await w.B.assess(ev('E1'));
    assert.deepEqual(r.verifiedFacts, []);
    assert.equal(r.replayLedger, 'unavailable');
  });
  test('the in-process ReplayGuard path is unchanged (no prepare/commit): same results as Phase 3', async () => {
    const store = new FakeStore();
    const t = makeTrust();
    const B = new IdentitySecurityAgent(store, { verifier: t.verifier });
    await t.authority.record(store, { caseId: CASE, accountId: ACCT, runId: 'r', kind: 'callback_verified', method: 'callback_on_file', statement: 'ok' });
    assert.equal((await B.assess(ev('E1'))).verifiedFacts.length, 1);
    assert.equal((await B.assess(ev('E2'))).rejectedEvidence[0].reason, 'replayed');
  });
});
