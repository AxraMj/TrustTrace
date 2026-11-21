import { hashOf } from './canonical.js';
import { MODEL_VERSION, EXTRACTOR_VERSION, POLICY_VERSION } from '../versions.js';

const SEVERITY_RANK_SQL = (col) => `(CASE ${col} WHEN 'low' THEN 0 WHEN 'medium' THEN 1 WHEN 'high' THEN 2 WHEN 'critical' THEN 3 END)`;
const plain = (v, fallback) => (v === undefined || v === null ? fallback : JSON.parse(JSON.stringify(v)));

/**
 * Pure: turn an Agent B assessment (IdentitySecurityAgent.assess result) into the record that is persisted and audited.
 * Everything is made JSON-safe, absent values become null, so hashing the record before insert and after reading it back
 * from the database gives the same hash.
 */
export function buildDecisionRecord(result, { decisionId, event, agentId, verifierKeyId = null, createdAt = new Date() }) {
  const created = new Date(Math.floor(createdAt.getTime())); // ms precision: what timestamptz round-trips through JS exactly
  return {
    id: decisionId,
    createdAt: created,
    eventId: String(result.eventId ?? event.eventId),
    eventType: String(event.type),
    accountId: String(event.accountId),
    caseId: event.caseId ?? null,
    orgId: event.orgId ?? null,
    event: plain(event, {}),
    rawScore: result.rawScore,
    displayScore: result.displayScore,
    severity: result.severity,
    baseAction: result.baseAction,
    recommendedAction: result.recommendedAction,
    contextAvailable: Boolean(result.contextAvailable),
    retrievalComplete: Boolean(result.retrievalComplete),
    degraded: result.contextAvailable === false,
    error: plain(result.error, null),
    policy: plain(result.policy, []),
    stepUp: plain(result.stepUp, { required: false, requirements: [] }),
    advisories: plain(result.advisories, []),
    contributions: plain(result.contributions, []),
    explanation: plain(result.explanation, []),
    rejectedEvidence: plain(result.rejectedEvidence, []),
    verifiedFacts: plain(result.verifiedFacts, []),
    unverifiedClaims: plain(result.unverifiedClaims, []),
    retrieved: plain(result.retrieved, []),
    retrievalMeta: plain(result.retrievalMeta, []),
    timings: plain(result.timings, {}),
    modelVersion: MODEL_VERSION,
    extractorVersion: EXTRACTOR_VERSION,
    policyVersion: POLICY_VERSION,
    verifierKeyId,
    agentId,
  };
}

/** The exact object that is hashed into the audit chain: the decision record itself. */
export const decisionPayload = (record) => record;

export function recordFromRow(r) {
  return {
    id: r.id, createdAt: r.created_at, eventId: r.event_id, eventType: r.event_type, accountId: r.account_id,
    caseId: r.case_id, orgId: r.org_id, event: r.event, rawScore: r.raw_score, displayScore: r.display_score,
    severity: r.severity, baseAction: r.base_action, recommendedAction: r.recommended_action,
    contextAvailable: r.context_available, retrievalComplete: r.retrieval_complete, degraded: r.degraded, error: r.error,
    policy: r.policy, stepUp: r.step_up, advisories: r.advisories, contributions: r.contributions, explanation: r.explanation,
    rejectedEvidence: r.rejected_evidence, verifiedFacts: r.verified_facts, unverifiedClaims: r.unverified_claims,
    retrieved: r.retrieved, retrievalMeta: r.retrieval_meta, timings: r.timings, modelVersion: r.model_version,
    extractorVersion: r.extractor_version, policyVersion: r.policy_version, verifierKeyId: r.verifier_key_id, agentId: r.agent_id,
  };
}

const j = JSON.stringify;

export async function insertDecision(client, d) {
  await client.query(
    `INSERT INTO decisions (id, created_at, event_id, event_type, account_id, case_id, org_id, event, raw_score, display_score, severity,
       base_action, recommended_action, context_available, retrieval_complete, degraded, error, policy, step_up, advisories, contributions,
       explanation, rejected_evidence, verified_facts, unverified_claims, retrieved, retrieval_meta, timings, model_version,
       extractor_version, policy_version, verifier_key_id, agent_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb,$18::jsonb,$19::jsonb,$20::jsonb,$21::jsonb,
       $22::jsonb,$23::jsonb,$24::jsonb,$25::jsonb,$26::jsonb,$27::jsonb,$28::jsonb,$29,$30,$31,$32,$33)`,
    [d.id, d.createdAt, d.eventId, d.eventType, d.accountId, d.caseId, d.orgId, j(d.event), d.rawScore, d.displayScore, d.severity,
      d.baseAction, d.recommendedAction, d.contextAvailable, d.retrievalComplete, d.degraded, d.error === null ? null : j(d.error),
      j(d.policy), j(d.stepUp), j(d.advisories), j(d.contributions), j(d.explanation), j(d.rejectedEvidence), j(d.verifiedFacts),
      j(d.unverifiedClaims), j(d.retrieved), j(d.retrievalMeta), j(d.timings), d.modelVersion, d.extractorVersion, d.policyVersion,
      d.verifierKeyId, d.agentId],
  );
}

/** Maintain the case index in the same transaction as the decision. No-op when the event carries no caseId. */
export async function upsertCase(client, d) {
  if (!d.caseId) return;
  await client.query(
    `INSERT INTO cases (account_id, case_id, first_seen, last_seen, decision_count, max_severity)
     VALUES ($1, $2, $3, $3, 1, $4)
     ON CONFLICT (account_id, case_id) DO UPDATE SET
       last_seen = GREATEST(cases.last_seen, EXCLUDED.last_seen),
       decision_count = cases.decision_count + 1,
       max_severity = CASE WHEN ${SEVERITY_RANK_SQL('EXCLUDED.max_severity')} > ${SEVERITY_RANK_SQL('cases.max_severity')}
                           THEN EXCLUDED.max_severity ELSE cases.max_severity END`,
    [d.accountId, d.caseId, d.createdAt, d.severity],
  );
}

export async function getDecision(pool, id) {
  const { rows } = await pool.query('SELECT * FROM decisions WHERE id = $1', [id]);
  return rows.length ? recordFromRow(rows[0]) : null;
}

/** Audit resolver: re-read decisions and re-hash them (detects a decision edited after the fact). */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function decisionHashes(pool, ids) {
  // A tampered audit record may carry a ref_id that is not even a UUID: it must be REPORTED as "audited row missing",
  // not crash the verifier with a cast error. Invalid ids are simply never found.
  const valid = [...new Set(ids.filter((id) => UUID_RE.test(String(id))))];
  if (!valid.length) return new Map();
  const { rows } = await pool.query('SELECT * FROM decisions WHERE id = ANY($1::uuid[])', [valid]);
  return new Map(rows.map((r) => [r.id, hashOf(decisionPayload(recordFromRow(r)))]));
}
