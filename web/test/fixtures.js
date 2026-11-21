// TEST FIXTURES shaped exactly like the API's responses (see docs/api.md). They are inputs to component tests only; the app itself
// never contains demo data. The real API is exercised by the real-browser run (web/scripts/e2e.mjs).
export const UUID = '11111111-1111-4111-8111-111111111111';
export const UUID2 = '22222222-2222-4222-8222-222222222222';
const T = '2026-06-15T12:00:00.000Z';

export const alertItem = (o = {}) => ({
  id: UUID, createdAt: T, eventId: 'EV-1', eventType: 'mfa_change', accountId: 'acct-A1-abc123', caseId: 'case-CA1-abc123',
  severity: 'critical', rawScore: 85, displayScore: 82, baseAction: 'block', recommendedAction: 'block', flags: [],
  topReasons: [{ source: 'event', label: 'EVENT', kind: 'MFA method was changed', effect: 35 }, { source: 'context', label: 'CLAIMED', kind: 'urgency_pressure', effect: 10 }],
  rejectedCount: 0, degraded: false, retrievalComplete: true, ...o,
});

export const contribution = (o = {}) => ({ source: 'context', label: 'CLAIMED', kind: 'role_claim', basePoints: 10, weight: 1, effectivePoints: 10, text: 'Caller claims to be the CFO.', memoryId: 'mem-claim-1', statement: 'I am the CFO', ...o });

export const decisionBody = (o = {}) => ({
  meta: { generatedAt: T },
  decision: {
    id: UUID, createdAt: T, eventId: 'EV-1', eventType: 'mfa_change', accountId: 'acct-A1-abc123', caseId: 'case-CA1-abc123', orgId: null, event: { type: 'mfa_change', newDevice: true },
    rawScore: 60, displayScore: 70, severity: 'high', baseAction: 'allow', recommendedAction: 'step_up', contextAvailable: true, retrievalComplete: true, degraded: false, error: null,
    policy: [{ rule: 'sensitive_action_from_unfamiliar_context', from: 'allow', to: 'step_up', why: 'identity evidence proves who is calling, not that the device is theirs' }],
    stepUp: { required: true, requirements: ['Verify via callback on file', 'Require hardware key'] }, advisories: [{ code: 'notify_user_new_country', text: 'Notify the account holder out-of-band.' }],
    contributions: [contribution(), contribution({ source: 'event', label: 'EVENT', kind: 'MFA changed', text: 'MFA method was changed', memoryId: undefined, basePoints: 35, effectivePoints: 35 })],
    explanation: ['[CLAIMED +10] "Caller claims…" - unverified', '[TOTAL] raw 60 -> severity high'], rejectedEvidence: [], verifiedFacts: [], unverifiedClaims: [], retrieved: [], retrievalMeta: [{ scope: 'acct', strategy: 'run_id', complete: true, truncated: false, usedFallback: false, scannedPages: 1 }],
    timings: { retrievalMs: 640, scoringMs: 3 }, modelVersion: 'm1', extractorVersion: 'e1', policyVersion: 'p1', verifierKeyId: 'kid-1234', agentId: 'trusttrace_identity_security_agent', ...o.decision,
  },
  integrity: { auditRecordFound: true, payloadHashMatches: true, recomputedPayloadHash: 'abc', ...o.integrity },
  audit: { seq: 4, payloadHash: 'p'.repeat(64), prevHash: 'q'.repeat(64), recordHash: 'r'.repeat(64), createdAt: T },
  attestationsSpent: [], activity: [], neighbours: {}, ...o.rest,
});

export const memory = (o = {}) => ({
  memoryId: 'mem-1', label: 'CLAIMED', kind: 'role_claim', scope: 'acct', statement: 'I am the CFO', trust: 'unverified_claim', writer: { agentId: 'trusttrace_helpdesk_agent', at: T },
  usage: [{ decisionId: UUID, source: 'context', effectivePoints: 10 }], rejectedIn: [], netEffectPoints: 10, ...o,
});

export const summaryBody = (o = {}) => ({
  meta: { generatedAt: T, window: '24h' },
  totals: { decisions: 10, accounts: 8, cases: 6, lastDecisionAt: T, blocked: 4, stepUp: 3, allowed: 3 },
  bySeverity: { low: 3, medium: 1, high: 2, critical: 4 }, byAction: { allow: 3, step_up: 3, block: 4 }, bySeverityAndAction: [],
  byEventType: [{ eventType: 'mfa_change', count: 6 }, { eventType: 'login', count: 4 }],
  flags: { degraded: 1, incompleteContext: 2, rejectedEvidence: 3, policyRaised: 2 },
  rejectedReasons: [{ reason: 'expired', count: 1 }, { reason: 'bad_signature', count: 2 }], policyRules: [{ rule: 'bank_detail_change_requires_step_up', count: 2 }],
  topDrivers: [{ source: 'context', label: 'CLAIMED', kind: 'urgency_pressure', count: 5, totalPoints: 50 }],
  series: { bucket: 'hour', points: [{ t: T, low: 1, medium: 0, high: 1, critical: 2, total: 4 }] },
  agents: [{ agentId: 'trusttrace_helpdesk_agent', events: 12, failures: 1, lastAt: T }], attestations: [{ kind: 'callback_verified', status: 'spent', count: 2, singleUse: true }],
  latencyMs: { retrieval: { avg: 800, p50: 700, p95: 1200 }, scoring: { avg: 4, p95: 9 } }, ...o,
});

/** fetch stub: routes by path prefix. Unknown paths fail loudly so a test cannot pass by accident. */
export function stubFetch(routes) {
  const calls = [];
  const fn = async (url, init = {}) => {
    const u = String(url);
    calls.push({ url: u, method: init.method ?? 'GET' });
    const path = u.split('?')[0];
    const hit = Object.entries(routes).find(([k]) => (k.endsWith('*') ? path.startsWith(k.slice(0, -1)) : path === k));
    if (!hit) return new Response(JSON.stringify({ error: { code: 'not_found', message: `no stub for ${u}` } }), { status: 404 });
    const r = typeof hit[1] === 'function' ? hit[1](u, init) : hit[1];
    if (r instanceof Response) return r;
    return new Response(JSON.stringify(r.body ?? r), { status: r.status ?? 200, headers: { 'content-type': 'application/json' } });
  };
  fn.calls = calls;
  return fn;
}
