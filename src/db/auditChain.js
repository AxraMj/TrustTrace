import { canonicalJson, hashOf, sha256Hex } from './canonical.js';

export const GENESIS_HASH = '0'.repeat(64);
const AUDIT_LOCK_KEY = 7_424_001; // pg advisory lock id: serialises appends so seq/prev_hash are consistent

/** record_hash = SHA-256(canonical JSON of the record's identity fields). Pure. */
export function computeRecordHash({ seq, recordType, refId, payloadHash, prevHash, createdAt }) {
  return sha256Hex(canonicalJson({ seq, recordType, refId, payloadHash, prevHash, createdAt: new Date(createdAt).toISOString() }));
}

/**
 * Append one record to the chain. MUST run inside a transaction (the advisory lock is transaction-scoped), so the
 * audited row and its audit record commit or roll back together.
 */
export async function appendAudit(client, { recordType, refId, payload, createdAt = new Date() }) {
  await client.query('SELECT pg_advisory_xact_lock($1)', [AUDIT_LOCK_KEY]);
  const { rows } = await client.query('SELECT seq, record_hash FROM audit_records ORDER BY seq DESC LIMIT 1');
  const seq = rows.length ? rows[0].seq + 1 : 1;
  const prevHash = rows.length ? rows[0].record_hash : GENESIS_HASH;
  const payloadHash = hashOf(payload);
  const created = new Date(createdAt);
  const recordHash = computeRecordHash({ seq, recordType, refId, payloadHash, prevHash, createdAt: created });
  await client.query(
    'INSERT INTO audit_records (seq, created_at, record_type, ref_id, payload_hash, prev_hash, record_hash) VALUES ($1,$2,$3,$4,$5,$6,$7)',
    [seq, created, recordType, refId, payloadHash, prevHash, recordHash],
  );
  return { seq, recordHash, payloadHash };
}

/**
 * Verify a run of consecutive records. Pure (no I/O) so tampering cases are unit-testable.
 * Checks: contiguous seq, prev_hash links, record_hash recomputation, and (when `payloadHashFor` is supplied) that the
 * audited row still hashes to the recorded payload_hash.
 * @returns {{ok:boolean, checked:number, problems:{seq:number, code:string, detail:string}[], lastSeq:number|null, lastHash:string|null}}
 */
export function verifyRecords(records, { expectedFirstSeq = 1, startPrevHash = GENESIS_HASH, payloadHashFor } = {}) {
  const problems = [];
  let expectSeq = expectedFirstSeq;
  let prev = startPrevHash;
  let lastSeq = null;
  let lastHash = null;
  for (const r of records) {
    const bad = (code, detail) => problems.push({ seq: r.seq, code, detail });
    if (r.seq !== expectSeq) bad('seq_gap', `expected seq ${expectSeq}, found ${r.seq} (a record was removed, reordered or inserted)`);
    if (r.prevHash !== prev) bad('broken_link', 'prev_hash does not match the previous record');
    const recomputed = computeRecordHash(r);
    if (recomputed !== r.recordHash) bad('record_hash_mismatch', 'record fields were modified after being written');
    if (payloadHashFor) {
      const actual = payloadHashFor(r);
      if (actual === undefined) bad('audited_row_missing', `${r.recordType} ${r.refId} no longer exists`);
      else if (actual !== r.payloadHash) bad('audited_row_modified', `${r.recordType} ${r.refId} no longer matches its audit hash`);
    }
    expectSeq = r.seq + 1;
    prev = r.recordHash; // follow the CLAIMED chain so one tampered record is reported once, not on every later record
    lastSeq = r.seq;
    lastHash = r.recordHash;
  }
  return { ok: problems.length === 0, checked: records.length, problems, lastSeq, lastHash };
}

const toRecord = (row) => ({
  seq: row.seq, recordType: row.record_type, refId: row.ref_id, payloadHash: row.payload_hash,
  prevHash: row.prev_hash, recordHash: row.record_hash, createdAt: row.created_at,
});

/**
 * Verify the whole chain in the database, page by page. `resolvers` maps record_type -> async (pool, refIds) => Map(refId -> payloadHash),
 * so each audited row is re-read and re-hashed. Returns the first problems found (capped) and the chain head.
 */
export async function verifyChain(pool, { resolvers = {}, pageSize = 2000, maxProblems = 20 } = {}) {
  let after = 0;
  let prev = GENESIS_HASH;
  let expectedFirstSeq = 1;
  let checked = 0;
  const problems = [];
  let head = null;
  for (;;) {
    const { rows } = await pool.query(
      'SELECT seq, created_at, record_type, ref_id, payload_hash, prev_hash, record_hash FROM audit_records WHERE seq > $1 ORDER BY seq LIMIT $2',
      [after, pageSize],
    );
    if (!rows.length) break;
    const records = rows.map(toRecord);
    const hashes = new Map();
    const byType = new Map();
    for (const r of records) (byType.get(r.recordType) ?? byType.set(r.recordType, []).get(r.recordType)).push(r.refId);
    const resolverFailures = [];
    for (const [type, ids] of byType) {
      const resolver = resolvers[type];
      try {
        hashes.set(type, resolver ? await resolver(pool, ids) : null);
      } catch (err) {
        // never let a failing re-read abort verification: report it, and treat those rows as unverifiable (missing)
        hashes.set(type, new Map());
        resolverFailures.push({ seq: records.find((r) => r.recordType === type).seq, code: 'resolver_failed', detail: `${type}: ${err.code ?? err.name}` });
      }
    }
    for (const f of resolverFailures) if (problems.length < maxProblems) problems.push(f);
    const res = verifyRecords(records, {
      expectedFirstSeq, startPrevHash: prev,
      payloadHashFor: (r) => { const m = hashes.get(r.recordType); return m === null || m === undefined ? r.payloadHash : m.get(r.refId); },
    });
    checked += res.checked;
    for (const p of res.problems) if (problems.length < maxProblems) problems.push(p);
    prev = res.lastHash;
    expectedFirstSeq = res.lastSeq + 1;
    after = res.lastSeq;
    head = { seq: res.lastSeq, hash: res.lastHash };
    if (rows.length < pageSize) break;
  }
  return { ok: problems.length === 0, checked, head, problems };
}
// NOTE: resolver failures are pushed into `problems` above, so ok is false whenever any re-read failed.
