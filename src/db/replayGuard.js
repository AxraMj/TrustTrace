import { appendAudit } from './auditChain.js';
import { hashOf } from './canonical.js';
import { withTransaction } from './pool.js';

// ---- audit payloads (also used by the audit resolvers, so insert-time and verify-time hashing cannot drift) ----
export const issuedPayload = (r) => ({
  nonce: r.nonce, source: r.source, kind: r.kind, accountId: r.account_id ?? r.accountId, caseId: r.case_id ?? r.caseId, issuer: r.issuer, kid: r.kid,
  method: r.method ?? null, statementSha256: r.statement_sha256 ?? r.statementSha256 ?? null,
  issuedAt: new Date(r.issued_at ?? r.issuedAt).toISOString(), expiresAt: new Date(r.expires_at ?? r.expiresAt).toISOString(),
});
export const consumedPayload = (r) => ({
  nonce: r.nonce, consumedEventId: r.consumed_event_id ?? r.consumedEventId,
  consumedAt: new Date(r.consumed_at ?? r.consumedAt).toISOString(), decisionId: r.decision_id ?? r.decisionId ?? null,
});

/** Audit resolvers for the nonce-related record types (re-read the row, re-hash it). */
export async function issuedHashes(pool, nonces) {
  const { rows } = await pool.query('SELECT * FROM attestation_nonces WHERE nonce = ANY($1::text[])', [nonces]);
  // an 'issued' audit record covers the issuance facts only (source was 'issued' when it was written)
  return new Map(rows.filter((r) => r.source === 'issued').map((r) => [r.nonce, hashOf(issuedPayload(r))]));
}
export async function consumedHashes(pool, nonces) {
  const { rows } = await pool.query('SELECT * FROM attestation_nonces WHERE nonce = ANY($1::text[]) AND consumed_event_id IS NOT NULL', [nonces]);
  return new Map(rows.map((r) => [r.nonce, hashOf(consumedPayload(r))]));
}

/**
 * Persistent, atomic replay ledger for single-use verification attestations (PostgreSQL is authoritative).
 * Agent B uses it through two calls: prepare() before scoring (read what is already spent) and commit() after (spend atomically).
 */
export class PgReplayGuard {
  constructor(pool) {
    this.pool = pool;
  }

  /** Snapshot of which of these nonces are already consumed, and by which event. Throws if the database is unavailable. */
  async prepare(nonces) {
    const spent = new Map();
    if (nonces.length) {
      const { rows } = await this.pool.query(
        'SELECT nonce, consumed_event_id FROM attestation_nonces WHERE nonce = ANY($1::text[]) AND consumed_event_id IS NOT NULL', [nonces]);
      for (const r of rows) spent.set(r.nonce, r.consumed_event_id);
    }
    return { unavailable: false, isReplay: (nonce, eventId) => spent.has(nonce) && spent.get(nonce) !== eventId };
  }

  /** Called by the verification authority when it issues an attestation (non-secret metadata only). Idempotent. */
  async recordIssued(p) {
    await withTransaction(this.pool, async (c) => {
      const issuedAt = new Date(p.iat);
      const expiresAt = new Date(p.exp);
      const { rows } = await c.query(
        `INSERT INTO attestation_nonces (nonce, source, kind, account_id, case_id, issuer, kid, method, statement_sha256, issued_at, expires_at)
         VALUES ($1,'issued',$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (nonce) DO NOTHING RETURNING nonce`,
        [p.nonce, p.kind, p.accountId, p.caseId, p.iss, p.kid, p.method ?? null, p.statementSha256 ?? null, issuedAt, expiresAt]);
      if (rows.length) {
        await appendAudit(c, {
          recordType: 'attestation_issued', refId: p.nonce,
          payload: issuedPayload({ nonce: p.nonce, source: 'issued', kind: p.kind, accountId: p.accountId, caseId: p.caseId, issuer: p.iss, kid: p.kid,
            method: p.method ?? null, statementSha256: p.statementSha256 ?? null, issuedAt, expiresAt }),
        });
      }
    });
  }

  /**
   * Spend single-use attestations for `eventId`, ALL-OR-NOTHING in one transaction. A nonce already consumed by a DIFFERENT
   * event is a replay/race loser: nothing is consumed and the conflicting nonces are returned.
   * Re-committing the same (nonce, eventId) is idempotent.
   * @returns {{ok:boolean, conflicts:string[], consumed:string[]}}
   */
  async commit(consumables, eventId, { decisionId = null } = {}) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const conflicts = [];
      const consumed = [];
      const consumedAt = new Date();
      for (const c of consumables) {
        const { rows } = await client.query(
          `INSERT INTO attestation_nonces (nonce, source, kind, account_id, case_id, issuer, kid, method, statement_sha256, issued_at, expires_at,
             consumed_event_id, consumed_at, decision_id)
           VALUES ($1,'first_seen',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
           ON CONFLICT (nonce) DO UPDATE SET consumed_event_id = EXCLUDED.consumed_event_id, consumed_at = EXCLUDED.consumed_at, decision_id = EXCLUDED.decision_id
             WHERE attestation_nonces.consumed_event_id IS NULL
           RETURNING nonce`,
          [c.nonce, c.kind, c.accountId, c.caseId, c.issuer, c.kid, c.method ?? null, c.statementSha256 ?? null, new Date(c.iat), new Date(c.exp), eventId, consumedAt, decisionId]);
        if (rows.length) {
          consumed.push(c.nonce);
          await appendAudit(client, { recordType: 'attestation_consumed', refId: c.nonce, payload: consumedPayload({ nonce: c.nonce, consumedEventId: eventId, consumedAt, decisionId }) });
          continue;
        }
        const owner = (await client.query('SELECT consumed_event_id FROM attestation_nonces WHERE nonce = $1', [c.nonce])).rows[0]?.consumed_event_id;
        if (owner !== eventId) conflicts.push(c.nonce); // consumed by another event -> replay / lost race
      }
      if (conflicts.length) {
        await client.query('ROLLBACK');
        return { ok: false, conflicts, consumed: [] };
      }
      await client.query('COMMIT');
      return { ok: true, conflicts: [], consumed };
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* ignore */ }
      throw err;
    } finally {
      client.release();
    }
  }
}
