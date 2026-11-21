// Read-only SQL behind the investigation API. Every statement is parameterised; the only values interpolated into SQL text
// come from fixed whitelists (date_trunc unit, sort order). Nothing here writes.
import { hashOf } from './canonical.js';
import { decisionPayload, recordFromRow } from './decisionRepo.js';

const STATUS_SQL = `(CASE WHEN n.consumed_event_id IS NOT NULL THEN 'spent' WHEN n.expires_at < now() THEN 'expired' ELSE 'valid' END)`;
const SINGLE_USE = ['callback_verified', 'identity_verified'];
const rnd = (x, d = 1) => (x === null || x === undefined ? null : Math.round(x * 10 ** d) / 10 ** d);
const ISO = (d) => (d ? new Date(d).toISOString() : null);

const FLAG_SQL = {
  rejected_evidence: 'jsonb_array_length(d.rejected_evidence) > 0',
  degraded: 'd.degraded',
  incomplete_context: 'NOT d.retrieval_complete',
  policy_raised: 'jsonb_array_length(d.policy) > 0',
};

const TOP_REASONS_SQL = `(SELECT COALESCE(jsonb_agg(x), '[]'::jsonb) FROM (
    SELECT jsonb_build_object('source', c->>'source', 'label', c->>'label', 'kind', c->>'kind', 'effect', (c->>'effectivePoints')::float8) AS x
      FROM jsonb_array_elements(d.contributions) c
     WHERE (c->>'effectivePoints')::float8 <> 0
     ORDER BY abs((c->>'effectivePoints')::float8) DESC, c->>'kind' LIMIT 2) s) AS top_reasons`;

const flagsOf = (r) => [
  ...(r.rejected_count > 0 ? ['rejected_evidence'] : []),
  ...(r.degraded ? ['degraded'] : []),
  ...(!r.retrieval_complete ? ['incomplete_context'] : []),
  ...(r.policy_count > 0 ? ['policy_raised'] : []),
];

const alertItem = (r) => ({
  id: r.id, createdAt: ISO(r.created_at), eventId: r.event_id, eventType: r.event_type, accountId: r.account_id, caseId: r.case_id,
  severity: r.severity, rawScore: r.raw_score, displayScore: r.display_score, baseAction: r.base_action, recommendedAction: r.recommended_action,
  flags: flagsOf(r), topReasons: r.top_reasons ?? [], rejectedCount: r.rejected_count, degraded: r.degraded, retrievalComplete: r.retrieval_complete,
});

export function createInvestigationStore(pool) {
  const q = async (sql, params) => (await pool.query(sql, params)).rows;

  /** Collects positional parameters and returns the placeholder: add(value) -> "$n". */
  const builder = () => {
    const params = [];
    return { params, add: (v) => { params.push(v); return `$${params.length}`; } };
  };

  async function summary({ from, to, bucket }) {
    const w = `d.created_at >= COALESCE($1::timestamptz, '-infinity'::timestamptz) AND d.created_at < $2::timestamptz`;
    const p = [from, to];
    const [tot, sa, et, rej, pol, drv, ser, ag, att] = await Promise.all([
      q(`SELECT count(*) AS decisions,
                count(*) FILTER (WHERE d.recommended_action = 'block') AS blocked,
                count(*) FILTER (WHERE d.recommended_action = 'step_up') AS step_up,
                count(*) FILTER (WHERE d.recommended_action = 'allow') AS allowed,
                count(*) FILTER (WHERE d.degraded) AS degraded,
                count(*) FILTER (WHERE NOT d.retrieval_complete) AS incomplete_context,
                count(*) FILTER (WHERE jsonb_array_length(d.rejected_evidence) > 0) AS rejected_evidence,
                count(*) FILTER (WHERE jsonb_array_length(d.policy) > 0) AS policy_raised,
                count(DISTINCT d.account_id) AS accounts, count(DISTINCT d.case_id) AS cases, max(d.created_at) AS last_decision_at,
                avg((d.timings->>'retrievalMs')::float8) AS retr_avg,
                percentile_cont(0.5) WITHIN GROUP (ORDER BY (d.timings->>'retrievalMs')::float8) AS retr_p50,
                percentile_cont(0.95) WITHIN GROUP (ORDER BY (d.timings->>'retrievalMs')::float8) AS retr_p95,
                avg((d.timings->>'scoringMs')::float8) AS score_avg,
                percentile_cont(0.95) WITHIN GROUP (ORDER BY (d.timings->>'scoringMs')::float8) AS score_p95
           FROM decisions d WHERE ${w}`, p),
      q(`SELECT d.severity, d.recommended_action AS action, count(*) AS n FROM decisions d WHERE ${w} GROUP BY 1, 2`, p),
      q(`SELECT d.event_type, count(*) AS n FROM decisions d WHERE ${w} GROUP BY 1 ORDER BY n DESC, 1`, p),
      q(`SELECT r->>'reason' AS reason, count(*) AS n FROM decisions d, jsonb_array_elements(d.rejected_evidence) r WHERE ${w} GROUP BY 1 ORDER BY n DESC, 1`, p),
      q(`SELECT x->>'rule' AS rule, count(*) AS n FROM decisions d, jsonb_array_elements(d.policy) x WHERE ${w} GROUP BY 1 ORDER BY n DESC, 1`, p),
      q(`SELECT c->>'source' AS source, c->>'label' AS label, c->>'kind' AS kind, count(*) AS n, sum((c->>'effectivePoints')::float8) AS pts
           FROM decisions d, jsonb_array_elements(d.contributions) c
          WHERE ${w} AND c->>'source' <> 'event' AND (c->>'effectivePoints')::float8 <> 0
          GROUP BY 1, 2, 3 ORDER BY n DESC, 1, 2, 3 LIMIT 10`, p),
      q(`SELECT date_trunc('${bucket}', d.created_at) AS t, d.severity, count(*) AS n FROM decisions d WHERE ${w} GROUP BY 1, 2 ORDER BY 1`, p),
      q(`SELECT e.agent_id, count(*) AS events, count(*) FILTER (WHERE NOT e.ok) AS failures, max(e.at) AS last_at
           FROM agent_events e WHERE e.at >= COALESCE($1::timestamptz, '-infinity'::timestamptz) AND e.at < $2::timestamptz GROUP BY 1 ORDER BY 1`, p),
      q(`SELECT n.kind, ${STATUS_SQL} AS status, count(*) AS n FROM attestation_nonces n
          WHERE n.issued_at >= COALESCE($1::timestamptz, '-infinity'::timestamptz) AND n.issued_at < $2::timestamptz GROUP BY 1, 2 ORDER BY 1, 2`, p),
    ]);
    const t = tot[0];
    const bySeverity = Object.fromEntries(['low', 'medium', 'high', 'critical'].map((s) => [s, 0]));
    const byAction = Object.fromEntries(['allow', 'step_up', 'block'].map((a) => [a, 0]));
    for (const r of sa) { bySeverity[r.severity] += r.n; byAction[r.action] += r.n; }
    const points = new Map();
    for (const r of ser) {
      const k = ISO(r.t);
      if (!points.has(k)) points.set(k, { t: k, low: 0, medium: 0, high: 0, critical: 0, total: 0 });
      const pt = points.get(k); pt[r.severity] += r.n; pt.total += r.n;
    }
    return {
      totals: {
        decisions: t.decisions, accounts: t.accounts, cases: t.cases, lastDecisionAt: ISO(t.last_decision_at),
        blocked: t.blocked, stepUp: t.step_up, allowed: t.allowed,
      },
      bySeverity, byAction,
      bySeverityAndAction: sa.map((r) => ({ severity: r.severity, action: r.action, count: r.n })),
      byEventType: et.map((r) => ({ eventType: r.event_type, count: r.n })),
      flags: { degraded: t.degraded, incompleteContext: t.incomplete_context, rejectedEvidence: t.rejected_evidence, policyRaised: t.policy_raised },
      rejectedReasons: rej.map((r) => ({ reason: r.reason, count: r.n })),
      policyRules: pol.map((r) => ({ rule: r.rule, count: r.n })),
      topDrivers: drv.map((r) => ({ source: r.source, label: r.label, kind: r.kind, count: r.n, totalPoints: rnd(r.pts) })),
      series: { bucket, points: [...points.values()] },
      agents: ag.map((r) => ({ agentId: r.agent_id, events: r.events, failures: r.failures, lastAt: ISO(r.last_at) })),
      attestations: att.map((r) => ({ kind: r.kind, status: r.status, count: r.n, singleUse: SINGLE_USE.includes(r.kind) })),
      latencyMs: {
        retrieval: { avg: rnd(t.retr_avg), p50: rnd(t.retr_p50), p95: rnd(t.retr_p95) },
        scoring: { avg: rnd(t.score_avg, 2), p95: rnd(t.score_p95, 2) },
      },
    };
  }

  async function listAlerts({ q: search, severities, actions, eventTypes, flags, accountId, caseId, from, to, limit, after }) {
    const b = builder();
    const where = [`d.created_at >= COALESCE(${b.add(from)}::timestamptz, '-infinity'::timestamptz)`, `d.created_at < ${b.add(to)}::timestamptz`];
    if (accountId) where.push(`d.account_id = ${b.add(accountId)}`);
    if (caseId) where.push(`d.case_id = ${b.add(caseId)}`);
    if (severities) where.push(`d.severity = ANY(${b.add(severities)}::text[])`);
    if (actions) where.push(`d.recommended_action = ANY(${b.add(actions)}::text[])`);
    if (eventTypes) where.push(`d.event_type = ANY(${b.add(eventTypes)}::text[])`);
    if (flags) where.push(`(${flags.map((f) => FLAG_SQL[f]).join(' OR ')})`);
    if (search) { const p = b.add(search); where.push(`(d.account_id ILIKE ${p} ESCAPE '\\' OR d.case_id ILIKE ${p} ESCAPE '\\' OR d.event_id ILIKE ${p} ESCAPE '\\')`); }
    if (after) where.push(`(d.created_at, d.id) < (${b.add(new Date(after.t))}::timestamptz, ${b.add(after.id)}::uuid)`);
    const rows = await q(
      `SELECT d.id, d.created_at, d.event_id, d.event_type, d.account_id, d.case_id, d.severity, d.raw_score, d.display_score, d.base_action,
              d.recommended_action, d.degraded, d.retrieval_complete, jsonb_array_length(d.rejected_evidence) AS rejected_count,
              jsonb_array_length(d.policy) AS policy_count, ${TOP_REASONS_SQL}
         FROM decisions d WHERE ${where.join(' AND ')} ORDER BY d.created_at DESC, d.id DESC LIMIT ${b.add(limit + 1)}`, b.params);
    const page = rows.slice(0, limit).map(alertItem);
    return { items: page, next: rows.length > limit ? { t: page.at(-1).createdAt, id: page.at(-1).id } : null };
  }

  async function getDecision(id) {
    const rows = await q('SELECT * FROM decisions WHERE id = $1', [id]);
    if (!rows.length) return null;
    const record = recordFromRow(rows[0]);
    const [audit, spent, events, neighbours] = await Promise.all([
      q(`SELECT seq, payload_hash, prev_hash, record_hash, created_at FROM audit_records WHERE record_type = 'decision' AND ref_id = $1`, [id]),
      q('SELECT nonce, kind, issuer, kid, method, issued_at, expires_at, consumed_event_id, consumed_at, source FROM attestation_nonces WHERE decision_id = $1 ORDER BY consumed_at', [id]),
      q('SELECT id, at, agent_id, kind, memory_ids, duration_ms, ok, error, payload FROM agent_events WHERE decision_id = $1 ORDER BY at, id', [id]),
      record.caseId
        ? q(`SELECT id, created_at, 'previous' AS rel FROM (SELECT id, created_at FROM decisions WHERE account_id = $1 AND case_id = $2 AND (created_at, id) < ($3::timestamptz, $4::uuid) ORDER BY created_at DESC, id DESC LIMIT 1) a
             UNION ALL
             SELECT id, created_at, 'next' AS rel FROM (SELECT id, created_at FROM decisions WHERE account_id = $1 AND case_id = $2 AND (created_at, id) > ($3::timestamptz, $4::uuid) ORDER BY created_at, id LIMIT 1) b`,
          [record.accountId, record.caseId, record.createdAt, record.id])
        : Promise.resolve([]),
    ]);
    const a = audit[0];
    const actualHash = hashOf(decisionPayload(record));
    return {
      decision: { ...record, createdAt: ISO(record.createdAt) },
      integrity: {
        auditRecordFound: Boolean(a),
        payloadHashMatches: a ? a.payload_hash === actualHash : false, // recomputed from the stored row right now
        recomputedPayloadHash: actualHash,
      },
      audit: a ? { seq: a.seq, payloadHash: a.payload_hash, prevHash: a.prev_hash, recordHash: a.record_hash, createdAt: ISO(a.created_at) } : null,
      attestationsSpent: spent.map((r) => ({ nonce: r.nonce, kind: r.kind, issuer: r.issuer, kid: r.kid, method: r.method, source: r.source, issuedAt: ISO(r.issued_at), expiresAt: ISO(r.expires_at), consumedEventId: r.consumed_event_id, consumedAt: ISO(r.consumed_at) })),
      activity: events.map((r) => ({ id: r.id, at: ISO(r.at), agentId: r.agent_id, kind: r.kind, memoryIds: r.memory_ids, durationMs: r.duration_ms, ok: r.ok, error: r.error, payload: r.payload })),
      neighbours: Object.fromEntries(neighbours.map((r) => [r.rel, { id: r.id, createdAt: ISO(r.created_at) }])),
    };
  }

  async function listCases({ q: search, severities, from, to, limit, after }) {
    const b = builder();
    const where = [`c.last_seen >= COALESCE(${b.add(from)}::timestamptz, '-infinity'::timestamptz)`, `c.last_seen < ${b.add(to)}::timestamptz`];
    if (severities) where.push(`c.max_severity = ANY(${b.add(severities)}::text[])`);
    if (search) { const p = b.add(search); where.push(`(c.account_id ILIKE ${p} ESCAPE '\\' OR c.case_id ILIKE ${p} ESCAPE '\\')`); }
    if (after) where.push(`(c.last_seen, c.account_id, c.case_id) < (${b.add(new Date(after.t))}::timestamptz, ${b.add(after.a)}, ${b.add(after.c)})`);
    const rows = await q(
      `SELECT c.*, l.id AS latest_id, l.recommended_action AS latest_action, l.severity AS latest_severity
         FROM cases c
         LEFT JOIN LATERAL (SELECT id, recommended_action, severity FROM decisions d WHERE d.account_id = c.account_id AND d.case_id = c.case_id ORDER BY created_at DESC, id DESC LIMIT 1) l ON true
        WHERE ${where.join(' AND ')} ORDER BY c.last_seen DESC, c.account_id DESC, c.case_id DESC LIMIT ${b.add(limit + 1)}`, b.params);
    const items = rows.slice(0, limit).map((r) => ({
      accountId: r.account_id, caseId: r.case_id, firstSeen: ISO(r.first_seen), lastSeen: ISO(r.last_seen), decisionCount: r.decision_count,
      maxSeverity: r.max_severity, latestDecision: r.latest_id ? { id: r.latest_id, recommendedAction: r.latest_action, severity: r.latest_severity } : null,
    }));
    return { items, next: rows.length > limit ? { t: items.at(-1).lastSeen, a: items.at(-1).accountId, c: items.at(-1).caseId } : null };
  }

  async function getCase(accountId, caseId) {
    const rows = await q('SELECT * FROM cases WHERE account_id = $1 AND case_id = $2', [accountId, caseId]);
    if (!rows.length) return null;
    const c = rows[0];
    const [counts, latest] = await Promise.all([
      q(`SELECT (SELECT count(*) FROM agent_events WHERE account_id = $1 AND case_id = $2) AS events,
                (SELECT count(*) FROM attestation_nonces WHERE account_id = $1 AND case_id = $2) AS attestations,
                (SELECT count(*) FROM decisions WHERE account_id = $1 AND case_id = $2 AND jsonb_array_length(rejected_evidence) > 0) AS with_rejected,
                (SELECT count(*) FROM decisions WHERE account_id = $1 AND case_id = $2 AND degraded) AS degraded`, [accountId, caseId]),
      q(`SELECT d.id, d.created_at, d.event_type, d.severity, d.recommended_action, d.base_action, d.raw_score, d.display_score FROM decisions d
          WHERE d.account_id = $1 AND d.case_id = $2 ORDER BY d.created_at DESC, d.id DESC LIMIT 1`, [accountId, caseId]),
    ]);
    const l = latest[0];
    return {
      accountId: c.account_id, caseId: c.case_id, firstSeen: ISO(c.first_seen), lastSeen: ISO(c.last_seen), decisionCount: c.decision_count, maxSeverity: c.max_severity,
      counts: { decisions: c.decision_count, agentEvents: counts[0].events, attestations: counts[0].attestations, decisionsWithRejectedEvidence: counts[0].with_rejected, degradedDecisions: counts[0].degraded },
      latestDecision: l ? { id: l.id, createdAt: ISO(l.created_at), eventType: l.event_type, severity: l.severity, baseAction: l.base_action, recommendedAction: l.recommended_action, rawScore: l.raw_score, displayScore: l.display_score } : null,
    };
  }

  /** Merged, chronological case timeline: decisions, agent events (except the decision_made duplicates) and attestation issue/spend. */
  async function caseTimeline(accountId, caseId, { limit }) {
    const [dec, ev, att] = await Promise.all([
      q(`SELECT id, created_at, event_type, severity, base_action, recommended_action, raw_score FROM decisions WHERE account_id = $1 AND case_id = $2 ORDER BY created_at, id LIMIT $3`, [accountId, caseId, limit]),
      q(`SELECT id, at, agent_id, kind, memory_ids, duration_ms, ok, error FROM agent_events WHERE account_id = $1 AND case_id = $2 AND kind <> 'decision_made' ORDER BY at, id LIMIT $3`, [accountId, caseId, limit]),
      q(`SELECT nonce, kind, method, issued_at, expires_at, consumed_event_id, consumed_at, decision_id FROM attestation_nonces WHERE account_id = $1 AND case_id = $2 ORDER BY issued_at LIMIT $3`, [accountId, caseId, limit]),
    ]);
    const items = [
      ...dec.map((r) => ({ at: ISO(r.created_at), type: 'decision', ref: r.id, severity: r.severity, baseAction: r.base_action, recommendedAction: r.recommended_action, eventType: r.event_type, rawScore: r.raw_score })),
      ...ev.map((r) => ({ at: ISO(r.at), type: 'agent_event', ref: String(r.id), agentId: r.agent_id, kind: r.kind, memoryIds: r.memory_ids, durationMs: r.duration_ms, ok: r.ok, error: r.error })),
      ...att.flatMap((r) => [
        { at: ISO(r.issued_at), type: 'attestation_issued', ref: r.nonce, kind: r.kind, method: r.method, expiresAt: ISO(r.expires_at) },
        ...(r.consumed_at ? [{ at: ISO(r.consumed_at), type: 'attestation_consumed', ref: r.nonce, kind: r.kind, consumedEventId: r.consumed_event_id, decisionId: r.decision_id }] : []),
      ]),
    ].sort((a, b) => a.at.localeCompare(b.at) || a.type.localeCompare(b.type) || String(a.ref).localeCompare(String(b.ref)));
    const truncated = dec.length === limit || ev.length === limit || att.length === limit;
    return { items: items.slice(0, limit * 3), truncated };
  }

  async function caseDecisions(accountId, caseId, { limit = 200 } = {}) {
    return (await q('SELECT * FROM decisions WHERE account_id = $1 AND case_id = $2 ORDER BY created_at, id LIMIT $3', [accountId, caseId, limit])).map(recordFromRow);
  }
  async function decisionRecord(id) {
    const r = await q('SELECT * FROM decisions WHERE id = $1', [id]);
    return r.length ? recordFromRow(r[0]) : null;
  }
  async function writersFor(memoryIds) {
    if (!memoryIds.length) return [];
    return (await q(
      `SELECT agent_id, at, memory_ids FROM agent_events WHERE kind IN ('memory_written', 'memory_written_raw') AND memory_ids && $1::text[] ORDER BY at, id`, [memoryIds],
    )).map((r) => ({ agentId: r.agent_id, at: ISO(r.at), memoryIds: r.memory_ids }));
  }

  async function listActivity({ agentId, kind, accountId, caseId, decisionId, ok, from, to, limit, after }) {
    const b = builder();
    const where = [`e.at >= COALESCE(${b.add(from)}::timestamptz, '-infinity'::timestamptz)`, `e.at < ${b.add(to)}::timestamptz`];
    if (agentId) where.push(`e.agent_id = ${b.add(agentId)}`);
    if (kind) where.push(`e.kind = ${b.add(kind)}`);
    if (accountId) where.push(`e.account_id = ${b.add(accountId)}`);
    if (caseId) where.push(`e.case_id = ${b.add(caseId)}`);
    if (decisionId) where.push(`e.decision_id = ${b.add(decisionId)}::uuid`);
    if (ok !== undefined) where.push(`e.ok = ${b.add(ok)}`);
    if (after) where.push(`(e.at, e.id) < (${b.add(new Date(after.t))}::timestamptz, ${b.add(after.id)}::bigint)`);
    const rows = await q(
      `SELECT e.* FROM agent_events e WHERE ${where.join(' AND ')} ORDER BY e.at DESC, e.id DESC LIMIT ${b.add(limit + 1)}`, b.params);
    const items = rows.slice(0, limit).map((r) => ({
      id: r.id, at: ISO(r.at), agentId: r.agent_id, kind: r.kind, accountId: r.account_id, caseId: r.case_id, eventId: r.event_id, decisionId: r.decision_id,
      memoryIds: r.memory_ids, payload: r.payload, durationMs: r.duration_ms, ok: r.ok, error: r.error,
    }));
    return { items, next: rows.length > limit ? { t: items.at(-1).at, id: items.at(-1).id } : null };
  }

  const attestationItem = (r) => ({
    nonce: r.nonce, kind: r.kind, status: r.status, singleUse: SINGLE_USE.includes(r.kind), accountId: r.account_id, caseId: r.case_id, issuer: r.issuer, kid: r.kid,
    method: r.method, source: r.source, issuedAt: ISO(r.issued_at), expiresAt: ISO(r.expires_at), consumedEventId: r.consumed_event_id, consumedAt: ISO(r.consumed_at), decisionId: r.decision_id,
  });

  async function listAttestations({ status, kind, accountId, caseId, from, to, limit, after }) {
    const b = builder();
    const where = [`n.issued_at >= COALESCE(${b.add(from)}::timestamptz, '-infinity'::timestamptz)`, `n.issued_at < ${b.add(to)}::timestamptz`];
    if (kind) where.push(`n.kind = ${b.add(kind)}`);
    if (accountId) where.push(`n.account_id = ${b.add(accountId)}`);
    if (caseId) where.push(`n.case_id = ${b.add(caseId)}`);
    if (status) where.push(`${STATUS_SQL} = ANY(${b.add(status)}::text[])`);
    if (after) where.push(`(n.issued_at, n.nonce) < (${b.add(new Date(after.t))}::timestamptz, ${b.add(after.n)})`);
    const rows = await q(
      `SELECT n.*, ${STATUS_SQL} AS status FROM attestation_nonces n WHERE ${where.join(' AND ')} ORDER BY n.issued_at DESC, n.nonce DESC LIMIT ${b.add(limit + 1)}`, b.params);
    const items = rows.slice(0, limit).map(attestationItem);
    return { items, next: rows.length > limit ? { t: items.at(-1).issuedAt, n: items.at(-1).nonce } : null };
  }

  async function caseAttestations(accountId, caseId) {
    return (await q(`SELECT n.*, ${STATUS_SQL} AS status FROM attestation_nonces n WHERE n.account_id = $1 AND n.case_id = $2 ORDER BY n.issued_at, n.nonce`, [accountId, caseId])).map(attestationItem);
  }

  /** Records that CLAIMED to be verified but failed authentication, flattened out of the decisions. */
  async function listRejections({ reason, accountId, caseId, from, to, limit }) {
    const b = builder();
    const where = [`d.created_at >= COALESCE(${b.add(from)}::timestamptz, '-infinity'::timestamptz)`, `d.created_at < ${b.add(to)}::timestamptz`];
    if (reason) where.push(`r.value->>'reason' = ${b.add(reason)}`);
    if (accountId) where.push(`d.account_id = ${b.add(accountId)}`);
    if (caseId) where.push(`d.case_id = ${b.add(caseId)}`);
    const rows = await q(
      `SELECT d.id AS decision_id, d.created_at, d.account_id, d.case_id, d.event_type, d.recommended_action, r.value AS rej
         FROM decisions d CROSS JOIN LATERAL jsonb_array_elements(d.rejected_evidence) AS r(value)
        WHERE ${where.join(' AND ')} ORDER BY d.created_at DESC, d.id DESC, r.value->>'memoryId' LIMIT ${b.add(limit + 1)}`, b.params);
    return {
      items: rows.slice(0, limit).map((r) => ({
        decisionId: r.decision_id, at: ISO(r.created_at), accountId: r.account_id, caseId: r.case_id, eventType: r.event_type, recommendedAction: r.recommended_action,
        memoryId: r.rej.memoryId ?? null, kind: r.rej.kind ?? null, reason: r.rej.reason, detail: r.rej.detail ?? null, points: r.rej.points ?? 0, statement: r.rej.statement ?? null,
      })),
      truncated: rows.length > limit,
    };
  }
  async function verifierKeys() {
    return (await q('SELECT verifier_key_id AS kid, count(*) AS decisions, max(created_at) AS last_used FROM decisions WHERE verifier_key_id IS NOT NULL GROUP BY 1 ORDER BY 3 DESC')).map((r) => ({ keyId: r.kid, decisions: r.decisions, lastUsedAt: ISO(r.last_used) }));
  }

  async function listAudit({ type, refId, afterSeq, limit }) {
    const b = builder();
    const where = [`a.seq > ${b.add(afterSeq)}`];
    if (type) where.push(`a.record_type = ${b.add(type)}`);
    if (refId) where.push(`a.ref_id = ${b.add(refId)}`);
    const rows = await q(`SELECT a.* FROM audit_records a WHERE ${where.join(' AND ')} ORDER BY a.seq LIMIT ${b.add(limit + 1)}`, b.params);
    const items = rows.slice(0, limit).map((r) => ({ seq: r.seq, createdAt: ISO(r.created_at), recordType: r.record_type, refId: r.ref_id, payloadHash: r.payload_hash, prevHash: r.prev_hash, recordHash: r.record_hash }));
    return { items, nextAfterSeq: rows.length > limit ? items.at(-1).seq : null };
  }
  async function auditHead() {
    const r = (await q('SELECT seq, record_hash, created_at FROM audit_records ORDER BY seq DESC LIMIT 1'))[0];
    return r ? { seq: r.seq, hash: r.record_hash, at: ISO(r.created_at) } : { seq: 0, hash: null, at: null };
  }

  return {
    summary, listAlerts, getDecision, listCases, getCase, caseTimeline, caseDecisions, decisionRecord, writersFor, listActivity,
    listAttestations, caseAttestations, listRejections, verifierKeys, listAudit, auditHead,
  };
}
