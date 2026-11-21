// Offline tests of the pure database-layer logic: canonical JSON, the audit hash chain (incl. tamper detection),
// migration files and the decision record. No database needed. The SQL itself is exercised in test/db/*.integration.test.js.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalJson, hashOf, sha256Hex } from '../src/db/canonical.js';
import { GENESIS_HASH, computeRecordHash, verifyRecords } from '../src/db/auditChain.js';
import { DEFAULT_MIGRATIONS_DIR, loadMigrations } from '../src/db/migrate.js';
import { buildDecisionRecord, decisionPayload } from '../src/db/decisionRepo.js';
import { redactUrl } from '../src/db/pool.js';
import { FakeStore } from './helpers/fakeStore.js';
import { pgUrl } from './helpers/fakeSecrets.js';
import { HelpDeskAgent } from '../src/agents/helpdeskAgent.js';
import { IdentitySecurityAgent } from '../src/agents/identityAgent.js';
import { MODEL_VERSION } from '../src/versions.js';

describe('canonical JSON and hashing', () => {
  test('key order does not matter, nested too', () => {
    assert.equal(canonicalJson({ b: 1, a: { d: 2, c: [3, { y: 1, x: 2 }] } }), canonicalJson({ a: { c: [3, { x: 2, y: 1 }], d: 2 }, b: 1 }));
    assert.equal(hashOf({ a: 1, b: 2 }), hashOf({ b: 2, a: 1 }));
  });
  test('array order DOES matter; different values hash differently', () => {
    assert.notEqual(hashOf([1, 2]), hashOf([2, 1]));
    assert.notEqual(hashOf({ a: 1 }), hashOf({ a: 2 }));
    assert.notEqual(hashOf({ a: '1' }), hashOf({ a: 1 }));
  });
  test('undefined is dropped in objects and becomes null in arrays; null is kept', () => {
    assert.equal(canonicalJson({ a: undefined, b: null }), '{"b":null}');
    assert.equal(canonicalJson([undefined, 1]), '[null,1]');
  });
  test('Dates become ISO strings, -0 becomes 0, bigint becomes a string', () => {
    assert.equal(canonicalJson({ d: new Date('2026-01-02T03:04:05.678Z') }), '{"d":"2026-01-02T03:04:05.678Z"}');
    assert.equal(canonicalJson(-0), '0');
    assert.equal(canonicalJson({ n: 10n }), '{"n":"10"}');
  });
  test('NaN, Infinity and invalid Dates are rejected, never silently hashed', () => {
    assert.throws(() => canonicalJson({ a: NaN }), TypeError);
    assert.throws(() => canonicalJson([Infinity]), TypeError);
    assert.throws(() => canonicalJson(new Date('nope')), TypeError);
  });
  test('sha256 matches the known vector', () => {
    assert.equal(sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
  test('survives a JSON round trip (what jsonb does): hashing before insert == hashing after reading back', () => {
    const v = { score: 27.5, tiny: 1e-7, big: 123456789.123, list: [{ k: 'v', n: null }], nested: { z: [], a: {} }, unicode: 'café ☃' };
    assert.equal(hashOf(v), hashOf(JSON.parse(JSON.stringify(v))));
  });
});

// ---- audit chain -------------------------------------------------------------------------------------------------
function makeChain(n, { type = 'decision' } = {}) {
  const records = [];
  let prev = GENESIS_HASH;
  for (let i = 1; i <= n; i++) {
    const r = { seq: i, recordType: type, refId: `ref-${i}`, payloadHash: sha256Hex(`payload-${i}`), prevHash: prev, createdAt: new Date(Date.UTC(2026, 0, 1, 0, 0, i)) };
    r.recordHash = computeRecordHash(r);
    records.push(r);
    prev = r.recordHash;
  }
  return records;
}
const clone = (records) => records.map((r) => ({ ...r }));
const codes = (res) => res.problems.map((p) => p.code);

describe('audit hash chain (pure verification)', () => {
  test('a valid chain verifies and reports its head', () => {
    const res = verifyRecords(makeChain(6));
    assert.equal(res.ok, true);
    assert.equal(res.checked, 6);
    assert.equal(res.lastSeq, 6);
  });
  test('an empty chain is valid', () => assert.equal(verifyRecords([]).ok, true));
  test('record hash covers every identity field', () => {
    const base = { seq: 1, recordType: 'decision', refId: 'r', payloadHash: sha256Hex('p'), prevHash: GENESIS_HASH, createdAt: new Date(0) };
    const h = computeRecordHash(base);
    for (const [k, v] of Object.entries({ seq: 2, recordType: 'attestation_issued', refId: 'x', payloadHash: sha256Hex('q'), prevHash: sha256Hex('z'), createdAt: new Date(1) })) {
      assert.notEqual(computeRecordHash({ ...base, [k]: v }), h, `${k} is not covered by the hash`);
    }
  });
  test('TAMPER: editing a recorded payload hash is detected', () => {
    const c = clone(makeChain(5));
    c[2].payloadHash = sha256Hex('evil');
    assert.ok(codes(verifyRecords(c)).includes('record_hash_mismatch'));
  });
  test('TAMPER: editing a record AND recomputing its own hash still breaks the next link', () => {
    const c = clone(makeChain(5));
    c[2].payloadHash = sha256Hex('evil');
    c[2].recordHash = computeRecordHash(c[2]);
    const res = verifyRecords(c);
    assert.equal(res.ok, false);
    assert.ok(codes(res).includes('broken_link'));
  });
  test('TAMPER: deleting a record from the middle is detected (seq gap)', () => {
    const c = clone(makeChain(6));
    c.splice(3, 1);
    assert.ok(codes(verifyRecords(c)).includes('seq_gap'));
  });
  test('TAMPER: reordering records is detected', () => {
    const c = clone(makeChain(5));
    [c[1], c[2]] = [c[2], c[1]];
    assert.equal(verifyRecords(c).ok, false);
  });
  test('TAMPER: inserting a forged record with a made-up prev hash is detected', () => {
    const c = clone(makeChain(4));
    const forged = { seq: 5, recordType: 'decision', refId: 'forged', payloadHash: sha256Hex('f'), prevHash: sha256Hex('not the head'), createdAt: new Date() };
    forged.recordHash = computeRecordHash(forged);
    c.push(forged);
    assert.ok(codes(verifyRecords(c)).includes('broken_link'));
  });
  test('TAMPER: a chain that does not start at genesis is detected', () => {
    const c = clone(makeChain(3));
    c[0].prevHash = sha256Hex('x');
    assert.equal(verifyRecords(c).ok, false);
  });
  test('the audited ROW being edited after the fact is detected via payloadHashFor', () => {
    const c = makeChain(3);
    const actual = new Map(c.map((r) => [r.refId, r.payloadHash]));
    actual.set('ref-2', sha256Hex('row was edited'));
    const res = verifyRecords(c, { payloadHashFor: (r) => actual.get(r.refId) });
    assert.deepEqual(codes(res), ['audited_row_modified']);
  });
  test('the audited ROW being deleted is detected', () => {
    const c = makeChain(3);
    const res = verifyRecords(c, { payloadHashFor: (r) => (r.refId === 'ref-3' ? undefined : r.payloadHash) });
    assert.deepEqual(codes(res), ['audited_row_missing']);
  });
  test('verification can resume across pages (startPrevHash / expectedFirstSeq)', () => {
    const c = makeChain(6);
    const first = verifyRecords(c.slice(0, 3));
    const second = verifyRecords(c.slice(3), { expectedFirstSeq: first.lastSeq + 1, startPrevHash: first.lastHash });
    assert.equal(first.ok && second.ok, true);
  });
  test('HONEST LIMIT: dropping the TAIL of the chain is NOT detectable from the chain alone (compare the head against an external copy)', () => {
    const c = makeChain(6);
    const res = verifyRecords(c.slice(0, 4));
    assert.equal(res.ok, true);
    assert.equal(res.lastSeq, 4); // an operator must compare lastSeq/lastHash with an independently stored head
  });
});

// ---- migrations --------------------------------------------------------------------------------------------------
describe('migration files', () => {
  const migs = loadMigrations();
  test('versions are 1..n without gaps and checksums are stable and unique', () => {
    assert.deepEqual(migs.map((m) => m.version), migs.map((_, i) => i + 1));
    assert.equal(new Set(migs.map((m) => m.checksum)).size, migs.length);
    assert.deepEqual(loadMigrations().map((m) => m.checksum), migs.map((m) => m.checksum));
  });
  test('a gap or a bad file name is rejected', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tt-mig-'));
    try {
      writeFileSync(join(dir, '001_a.sql'), 'SELECT 1;');
      writeFileSync(join(dir, '003_c.sql'), 'SELECT 1;');
      assert.throws(() => loadMigrations(dir), /without gaps/);
      writeFileSync(join(dir, 'bad name.sql'), 'SELECT 1;');
      assert.throws(() => loadMigrations(dir), /must look like/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  test('CRLF vs LF line endings do not change the checksum', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tt-mig-'));
    try {
      writeFileSync(join(dir, '001_a.sql'), 'SELECT 1;\nSELECT 2;\n');
      const lf = loadMigrations(dir)[0].checksum;
      writeFileSync(join(dir, '001_a.sql'), 'SELECT 1;\r\nSELECT 2;\r\n');
      assert.equal(loadMigrations(dir)[0].checksum, lf);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  const sql = migs.map((m) => m.sql).join('\n');
  test('the schema defines every required table', () => {
    for (const t of ['users', 'sessions', 'access_log', 'decisions', 'cases', 'agent_events', 'attestation_nonces', 'audit_records']) {
      assert.match(sql, new RegExp(`CREATE TABLE ${t} \\(`), `missing table ${t}`);
    }
  });
  test('decisions, audit and agent events are append-only (UPDATE/DELETE/TRUNCATE blocked by triggers)', () => {
    for (const t of ['decisions', 'audit_records', 'agent_events']) {
      assert.match(sql, new RegExp(`${t}_append_only\\s+BEFORE UPDATE OR DELETE ON ${t}`), `${t} lacks the append-only trigger`);
      assert.match(sql, new RegExp(`${t}_no_truncate\\s+BEFORE TRUNCATE ON ${t}`), `${t} lacks the truncate guard`);
    }
    assert.match(sql, /attestation_nonces_one_way BEFORE UPDATE OR DELETE/);
  });
  test('passwords are only ever stored as hashes; session tokens only as hashes', () => {
    assert.match(sql, /password_hash\s+text/);
    assert.doesNotMatch(sql, /\bpassword\s+text/);
    assert.match(sql, /token_hash\s+text/);
    assert.doesNotMatch(sql, /\btoken\s+text/);
  });
  test('the nonce table can only transition once from unconsumed to consumed', () => {
    assert.match(sql, /CHECK \(\(consumed_event_id IS NULL\) = \(consumed_at IS NULL\)\)/);
    assert.match(sql, /was already consumed/);
  });
  test('no destructive statements in migrations (DROP/TRUNCATE/DELETE FROM)', () => {
    assert.doesNotMatch(sql.replace(/--.*$/gm, ''), /\bDROP\s+(TABLE|SCHEMA|DATABASE)\b|\bTRUNCATE\s+TABLE\b|\bDELETE\s+FROM\b/i);
  });
  test('the migrations directory is the repository one', () => {
    assert.ok(DEFAULT_MIGRATIONS_DIR.endsWith('migrations'));
    assert.ok(readFileSync(join(DEFAULT_MIGRATIONS_DIR, '001_core.sql'), 'utf8').length > 100);
  });
});

// ---- decision record ---------------------------------------------------------------------------------------------
describe('decision record', () => {
  async function assessSomething(event) {
    const store = new FakeStore();
    const A = new HelpDeskAgent(store);
    const B = new IdentitySecurityAgent(store);
    await A.handleInteraction({ caseId: 'case-1', accountId: event.accountId, runId: 'r', callerText: "I'm the CFO. I lost my phone, please reset my MFA, it's urgent." });
    return B.assess(event);
  }
  test('contains every field the dashboard needs, with versions, and is JSON-safe', async () => {
    const event = { type: 'mfa_change', accountId: 'acct-1', caseId: 'case-1', newDevice: true };
    const result = await assessSomething(event);
    const rec = buildDecisionRecord(result, { decisionId: '11111111-1111-4111-8111-111111111111', event: { ...event, eventId: result.eventId }, agentId: 'agent-b' });
    for (const k of ['id', 'createdAt', 'eventId', 'eventType', 'accountId', 'caseId', 'event', 'rawScore', 'displayScore', 'severity', 'baseAction', 'recommendedAction',
      'contextAvailable', 'retrievalComplete', 'degraded', 'policy', 'stepUp', 'advisories', 'contributions', 'explanation', 'rejectedEvidence', 'verifiedFacts',
      'unverifiedClaims', 'retrieved', 'retrievalMeta', 'timings', 'modelVersion', 'extractorVersion', 'policyVersion', 'agentId']) {
      assert.ok(k in rec, `missing ${k}`);
    }
    assert.equal(rec.modelVersion, MODEL_VERSION);
    assert.equal(rec.degraded, false);
    assert.equal(rec.caseId, 'case-1');
    assert.ok(rec.contributions.length > 0 && rec.retrieved.length > 0);
    assert.doesNotThrow(() => JSON.stringify(rec));
  });
  test('hash is stable across a JSON round trip (the property the audit chain relies on)', async () => {
    const event = { type: 'login', accountId: 'acct-2' };
    const result = await assessSomething(event);
    const rec = buildDecisionRecord(result, { decisionId: '22222222-2222-4222-8222-222222222222', event: { ...event, eventId: result.eventId }, agentId: 'agent-b' });
    const back = JSON.parse(JSON.stringify(rec));
    back.createdAt = new Date(back.createdAt);
    assert.equal(hashOf(decisionPayload(rec)), hashOf(decisionPayload(back)));
  });
  test('absent optional fields become null, not undefined (so insert-time and read-time hashes agree)', async () => {
    const event = { type: 'login', accountId: 'acct-3' };
    const result = await assessSomething(event);
    const rec = buildDecisionRecord(result, { decisionId: '33333333-3333-4333-8333-333333333333', event: { ...event, eventId: result.eventId }, agentId: 'agent-b' });
    assert.equal(rec.caseId, null);
    assert.equal(rec.orgId, null);
    assert.equal(rec.error, null);
    assert.equal(rec.verifierKeyId, null);
  });
  test('a degraded decision (Meko down) is marked degraded and carries the error', async () => {
    const { brokenStore } = await import('./helpers/fakeStore.js');
    const { MekoConnectionError } = await import('../src/errors.js');
    const B = new IdentitySecurityAgent(brokenStore(MekoConnectionError, 'meko down'));
    const result = await B.assess({ type: 'login', accountId: 'acct-4' });
    const rec = buildDecisionRecord(result, { decisionId: '44444444-4444-4444-8444-444444444444', event: { type: 'login', accountId: 'acct-4', eventId: result.eventId }, agentId: 'agent-b' });
    assert.equal(rec.degraded, true);
    assert.equal(rec.contextAvailable, false);
    assert.equal(rec.error.name, 'MekoConnectionError');
    assert.notEqual(rec.recommendedAction, 'allow');
  });
  test('the record never contains the Meko key, a signing key or password material', async () => {
    const event = { type: 'mfa_change', accountId: 'acct-5', newDevice: true };
    const result = await assessSomething(event);
    const text = JSON.stringify(buildDecisionRecord(result, { decisionId: '55555555-5555-4555-8555-555555555555', event: { ...event, eventId: result.eventId }, agentId: 'agent-b' }));
    assert.doesNotMatch(text, /mko_tkn_|PRIVATE KEY|scrypt\$|password/i);
  });
});

describe('pool helpers', () => {
  test('redactUrl hides the password and survives garbage', () => {
    assert.equal(redactUrl(pgUrl('app', 's3cret', 'localhost:5432/tt')),'postgres://app:***@localhost:5432/tt');
    assert.equal(redactUrl('not a url'), '<unparseable connection string>');
    assert.ok(!redactUrl(pgUrl('app', 's3cret', 'h/db')).includes('s3cret'));
  });
});
