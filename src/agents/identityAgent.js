import { randomUUID } from 'node:crypto';
import { LABELS } from '../labels.js';
import { MekoError } from '../errors.js';
import { SINGLE_USE_KINDS, decodeEnvelope } from '../trust/attestation.js';
import { FORGERY_REASONS, ReplayGuard } from '../trust/verifier.js';

// Replay view used when the persistent ledger cannot be read or written: single-use evidence is then NOT trusted (fail closed).
const LEDGER_UNAVAILABLE = Object.freeze({ unavailable: true, isReplay: () => false });
const MAX_COMMIT_ATTEMPTS = 3;

/** Nonces of the VERIFIED claims among the memories (decoded WITHOUT trusting them), so the ledger can be read up front. */
function nonceCandidates(memories) {
  const out = new Set();
  for (const m of memories) {
    if (!m?.attestation) continue;
    try { out.add(decodeEnvelope(m.attestation).payload.nonce); } catch { /* malformed: the verifier will reject it */ }
  }
  return [...out];
}

export const IDENTITY_AGENT_ID = 'trusttrace_identity_security_agent';

// ---------------------------------------------------------------------------------------------
// Scoring model
//   rawScore     = sum of signed, weighted contributions. Unclamped: can exceed 100 or go < 0.
//                  Severity (and the BASE action) are decided from rawScore.
//   displayScore = 100 * (1 - exp(-max(raw,0)/50)), 1 decimal. A smooth, bounded 0-100 curve for UIs.
//                  Increasing in raw: distinguishable at 0.1 resolution for raw up to ~225, then it
//                  flattens (rounds to the same value) toward 100. Decisions never use displayScore.
//   recommendedAction = baseAction raised by the sensitive-action POLICY below (never lowered by it).
// ---------------------------------------------------------------------------------------------
export const SEVERITY_THRESHOLDS = Object.freeze({ medium: 25, high: 50, critical: 75 });
export const DISPLAY_SCALE = 50;
const ACTION = { critical: 'block', high: 'block', medium: 'step_up', low: 'allow' };
export const ACTION_RANK = Object.freeze({ allow: 0, step_up: 1, block: 2 });

export function displayScore(raw) {
  const r = Math.max(0, raw);
  return Math.round(1000 * (1 - Math.exp(-r / DISPLAY_SCALE))) / 10;
}
export function severityFor(raw) {
  const t = SEVERITY_THRESHOLDS;
  return raw >= t.critical ? 'critical' : raw >= t.high ? 'high' : raw >= t.medium ? 'medium' : 'low';
}
export function actionFor(severity) {
  return ACTION[severity];
}

// Points from the NEW EVENT itself (telemetry the identity system observes directly).
const EVENT_RULES = [
  { when: (e) => e.type === 'mfa_change', points: 20, why: 'MFA method was changed (high-value account-takeover step).' },
  { when: (e) => e.type === 'bank_detail_change', points: 25, why: 'Payroll/bank details were changed (direct financial-fraud step).' },
  { when: (e) => e.type === 'password_reset', points: 15, why: 'Password was reset.' },
  { when: (e) => e.newDevice === true, points: 15, why: 'Event comes from a device not seen before on this account.' },
  { when: (e) => e.newCountry === true, points: 15, why: 'Event comes from a country not previously used by this account.' },
  { when: (e) => e.ipReputation === 'bad', points: 20, why: 'Source IP has a poor reputation.' },
];
export const SENSITIVE_ACTIONS = new Set(['mfa_change', 'bank_detail_change', 'password_reset']);

/** Help-desk context counts at half weight for a routine event (known device+country, ordinary login). */
export const ROUTINE_EVENT_WEIGHT = 0.5;
export function isUnfamiliarContext(e) {
  return e.newDevice === true || e.newCountry === true || e.ipReputation === 'bad';
}
export function isSensitiveEvent(e) {
  return SENSITIVE_ACTIONS.has(e.type) || isUnfamiliarContext(e);
}

const CONTEXT_POINTS = {
  CLAIMED: { lost_device_claim: 10, mfa_unavailable_claim: 10, request_mfa_reset: 10, request_password_reset: 10, request_contact_change: 5, request_bank_detail_change: 10, role_claim: 5 },
  OBSERVED: { urgency_pressure: 10, authority_pressure: 10, verification_resistance: 15, caller_id_mismatch: 15, identity_compromise_indicator: 30 },
};
const FAILED_VERIFICATION_POINTS = 25;
const CALL_DERIVED = new Set([
  'lost_device_claim', 'mfa_unavailable_claim', 'request_mfa_reset', 'request_password_reset', 'request_contact_change', 'request_bank_detail_change', 'role_claim',
  'urgency_pressure', 'authority_pressure', 'verification_resistance', 'caller_id_mismatch',
]);
export const VERIFIED_CALL_SIGNAL_WEIGHT = 0.5;

// What ACCEPTED (signature-verified) evidence is worth, by kind. Unknown kinds score 0.
const VERIFIED_EFFECTS = {
  callback_verified: { points: -40, mitigatesCall: true, why: 'independent callback confirmed the account owner' },
  identity_verified: { points: -40, mitigatesCall: true, why: 'identity independently verified' },
  device_verified: { points: -25, mitigatesCall: false, why: 'device independently confirmed as the owner\'s' },
};
export const ATTACK_PATTERN_KIND = 'confirmed_attack_pattern';
export const ATTACK_PATTERN_POINTS = 40;

// Risk added when a record CLAIMS to be verified but fails authentication. Rejected evidence is never
// trusted, never turned into an observation, and is itself a tamper signal.
export const FORGERY_POINTS = 40;
export const REPLAY_POINTS = 25;
const REJECTION_POINTS = (reason) => (FORGERY_REASONS.has(reason) ? FORGERY_POINTS : reason === 'replayed' ? REPLAY_POINTS : 0);

// ---- Sensitive-action policy: independent of the score, it can only RAISE the action. ----
const STEP_UP_REQUIREMENTS = {
  mfa_change: [
    'Confirm the change through an ALREADY-registered factor or trusted device (never through the help-desk caller).',
    'Prove possession of the NEW factor/device with a one-time challenge.',
    'Notify every existing contact point and hold the new factor in a limited-privilege state for a cooling-off period.',
  ],
  bank_detail_change: [
    'Confirm through an already-registered factor or trusted device.',
    'Hold the payroll change for a review window and notify the previous bank details/contacts.',
    'Obtain out-of-band approval from payroll/manager.',
  ],
  password_reset: [
    'Confirm through an already-registered factor or trusted device.',
    'Force re-authentication on all sessions and notify existing contact points.',
  ],
  default: ['Re-authenticate with an existing, already-registered MFA factor.'],
};

const round1 = (x) => Math.round(x * 10) / 10;
const fmt = (x) => (x >= 0 ? `+${round1(x)}` : `${round1(x)}`);

function signatureOf(statement) {
  const m = /signature=([a-z_,]+)/.exec(statement);
  return m ? m[1].split(',').filter(Boolean) : [];
}

/**
 * Agent B. Evaluates a login / MFA-change / payroll-change event using ONLY context it retrieves from Meko.
 * VERIFIED evidence is accepted only after its signature and bindings are verified with `verifier`
 * (public keys only). Without a verifier, every VERIFIED record is rejected (secure default).
 */
export class IdentitySecurityAgent {
  constructor(store, { agentId = IDENTITY_AGENT_ID, verifier = null, replayGuard = new ReplayGuard() } = {}) {
    this.store = store;
    this.agentId = agentId;
    this.verifier = verifier;
    this.replay = replayGuard;
  }

  /** Authenticate one VERIFIED memory. Rejections are explicit, never silently downgraded. */
  #authenticate(m, eventId, replay) {
    if (!this.verifier) return { ok: false, reason: 'no_trust_anchor', detail: 'no verifier configured; VERIFIED evidence cannot be trusted' };
    return this.verifier.verify(m, { replay, eventId });
  }

  /** Pure scoring from an event + retrieved memories (reads, never writes, the replay ledger). `replay` may inject a ledger snapshot. */
  score(event, memories = [], { retrievalComplete = true, replay = this.replay } = {}) {
    const contributions = [];
    const sensitive = isSensitiveEvent(event);
    const contextWeight = sensitive ? 1 : ROUTINE_EVENT_WEIGHT;

    // 1. Scope filter. Only this account (or this org's attack patterns) may influence the decision.
    const inScope = memories.filter(
      (m) => m && m.trusttrace && LABELS[m.label] && (m.accountId === event.accountId || (event.orgId && m.accountId === event.orgId)),
    );

    // 2. Authenticate VERIFIED claims BEFORE any de-duplication (a forged copy must not shadow a real one).
    const acceptedVerified = [];
    const rejectedEvidence = [];
    const seenNonces = new Set();
    for (const m of inScope.filter((x) => x.label === LABELS.VERIFIED)) {
      const res = this.#authenticate(m, event.eventId, replay);
      if (!res.ok) {
        rejectedEvidence.push({ memoryId: m.id, kind: m.kind, reason: res.reason, detail: res.detail, points: REJECTION_POINTS(res.reason), statement: m.statement });
        continue;
      }
      if (seenNonces.has(res.payload.nonce)) continue; // same authentic record stored twice: counted once, harmless
      seenNonces.add(res.payload.nonce);
      acceptedVerified.push({ ...m, payload: res.payload });
    }

    // 3. De-duplicate CLAIMED/OBSERVED (memory_add does not de-dupe).
    const seen = new Set();
    const plain = [];
    for (const m of inScope.filter((x) => x.label !== LABELS.VERIFIED)) {
      const key = `${m.accountId}|${m.label}|${m.kind}|${m.statement}`;
      if (seen.has(key)) continue;
      seen.add(key);
      plain.push(m);
    }
    const accountMems = plain.filter((m) => m.accountId === event.accountId);
    const accountVerified = [];
    const verifiedKinds = new Set();
    for (const m of acceptedVerified.filter((x) => x.accountId === event.accountId)) {
      if (verifiedKinds.has(m.kind)) continue; // first of each kind only (no stacking)
      verifiedKinds.add(m.kind);
      accountVerified.push(m);
    }
    const patternMems = acceptedVerified.filter((m) => event.orgId && m.accountId === event.orgId && m.kind === ATTACK_PATTERN_KIND);

    const callMitigated = accountVerified.some((m) => VERIFIED_EFFECTS[m.kind]?.mitigatesCall);
    const callWeight = callMitigated ? VERIFIED_CALL_SIGNAL_WEIGHT : 1;

    // 4. Event contributions
    for (const r of EVENT_RULES) {
      if (r.when(event)) contributions.push({ source: 'event', label: 'EVENT', kind: r.why, basePoints: r.points, weight: 1, effectivePoints: r.points, text: r.why });
    }

    // 5. Context contributions
    for (const m of accountMems) {
      const failed = m.label === LABELS.OBSERVED && m.kind.endsWith('_failed');
      const base = failed ? FAILED_VERIFICATION_POINTS : CONTEXT_POINTS[m.label]?.[m.kind] ?? 0;
      let weight = contextWeight;
      const notes = [];
      if (contextWeight !== 1) notes.push(`x${contextWeight} routine event`);
      if (CALL_DERIVED.has(m.kind) && callMitigated) {
        weight *= callWeight;
        notes.push(`x${callWeight} discounted by verified identity`);
      }
      const text = m.label === LABELS.CLAIMED
        ? `"${m.statement}" - unverified caller statement; treated as a risk signal, NOT as a fact.`
        : `${m.statement}`;
      contributions.push({
        source: 'context', label: m.label, kind: m.kind, memoryId: m.id, statement: m.statement,
        basePoints: base, weight, effectivePoints: base * weight, text: text + (notes.length ? ` (base ${base}, ${notes.join(', ')})` : ''),
      });
    }

    // 6. Authenticated attack patterns (org-wide, previous confirmed incidents)
    const presentKinds = new Set(accountMems.map((m) => m.kind));
    for (const p of patternMems) {
      const sig = signatureOf(p.statement);
      const matched = sig.length > 0 && sig.every((k) => presentKinds.has(k));
      const weight = contextWeight * (matched && callMitigated ? callWeight : 1);
      const base = matched ? ATTACK_PATTERN_POINTS : 0;
      contributions.push({
        source: 'pattern', label: LABELS.VERIFIED, kind: p.kind, memoryId: p.id, statement: p.statement, verifiedBy: p.verifiedBy,
        matchedMemoryIds: matched ? accountMems.filter((m) => sig.includes(m.kind)).map((m) => m.id) : [],
        basePoints: base, weight, effectivePoints: base * weight,
        text: matched
          ? `Matches previously VERIFIED attack pattern (${sig.join(' + ')}): ${p.statement}`
          : `Verified attack pattern on file did not match this case (needs ${sig.join(' + ') || 'unknown signature'}).`,
      });
    }

    // 7. Authenticated reductions
    for (const m of accountVerified) {
      const eff = VERIFIED_EFFECTS[m.kind];
      contributions.push({
        source: 'verified', label: LABELS.VERIFIED, kind: m.kind, memoryId: m.id, statement: m.statement, verifiedBy: m.verifiedBy, nonce: m.payload.nonce, exp: m.payload.exp,
        basePoints: eff?.points ?? 0, weight: 1, effectivePoints: eff?.points ?? 0,
        text: eff ? `${m.statement} (signature verified; ${m.verifiedBy}: ${eff.why}).` : `${m.statement} (VERIFIED kind "${m.kind}" has no scoring rule; no effect).`,
      });
    }

    // 8. Rejected evidence is a tamper/replay signal. It never reduces risk and is never an observation.
    for (const r of rejectedEvidence) {
      contributions.push({
        source: 'integrity', label: 'REJECTED_VERIFIED', kind: r.kind, memoryId: r.memoryId, statement: r.statement, reason: r.reason,
        basePoints: r.points, weight: 1, effectivePoints: r.points,
        text: `REJECTED record claiming VERIFIED (${r.reason}: ${r.detail}). Not trusted, not an observation.`,
      });
    }

    const rawScore = round1(contributions.reduce((a, c) => a + c.effectivePoints, 0));
    const severity = severityFor(rawScore);
    const display = displayScore(rawScore);

    // 9. Sensitive-action policy (can only raise the action).
    const baseAction = ACTION[severity];
    let action = baseAction;
    const policy = [];
    const raise = (to, rule, why) => {
      if (ACTION_RANK[to] > ACTION_RANK[action]) {
        action = to;
        policy.push({ rule, from: baseAction, to, why });
      }
    };
    const isSensitiveAction = SENSITIVE_ACTIONS.has(event.type);
    const deviceAttested = accountVerified.some((m) => m.kind === 'device_verified');
    if (isSensitiveAction && rejectedEvidence.some((r) => FORGERY_REASONS.has(r.reason))) {
      raise('block', 'forged_verification_on_sensitive_action', 'a record claiming VERIFIED failed authentication on a sensitive action');
    }
    if (event.type === 'bank_detail_change') {
      raise('step_up', 'bank_detail_change_requires_step_up', 'payroll/bank changes always need step-up, even with strong identity evidence');
    }
    if (isSensitiveAction && isUnfamiliarContext(event) && !deviceAttested) {
      raise('step_up', 'sensitive_action_from_unfamiliar_context',
        'identity evidence (e.g. a verified callback) proves who is calling, not that the unfamiliar device/location is theirs');
    }
    if (isSensitiveAction && !retrievalComplete) {
      raise('step_up', 'incomplete_context_on_sensitive_action', 'Meko context could not be retrieved completely, so absence of evidence is not trusted');
    }
    const stepUp = action === 'step_up'
      ? { required: true, requirements: STEP_UP_REQUIREMENTS[event.type] ?? STEP_UP_REQUIREMENTS.default }
      : { required: false, requirements: [] };

    // Advisories: non-blocking follow-ups attached to an ALLOW. Decision record: docs/decisions/001-overseas-login-policy.md
    // (a sign-in from a new country on a KNOWN device is allowed, but the account holder must be told out-of-band).
    const advisories = [];
    if (action === 'allow' && event.newCountry === true) {
      advisories.push({
        code: 'notify_user_new_country',
        text: 'Sign-in from a country not used before on a known device: allowed, but notify the account holder out-of-band so a stolen session can be revoked.',
      });
    }

    const explanation = contributions.map((c) => `[${c.source === 'event' ? 'event' : c.label} ${fmt(c.effectivePoints)}] ${c.text}`);
    explanation.push(`[TOTAL] raw ${rawScore} -> severity ${severity} (display ${display}/100) -> base action ${baseAction}`);
    for (const p of policy) explanation.push(`[POLICY] ${p.rule}: ${p.from} -> ${p.to} (${p.why})`);
    for (const a of advisories) explanation.push(`[ADVISORY] ${a.code}: ${a.text}`);

    return {
      rawScore, displayScore: display, severity, baseAction,
      recommendedAction: action,
      riskScore: display, // legacy alias of displayScore
      riskLevel: severity, // legacy alias of severity
      policy, stepUp, advisories, contributions, explanation,
      evidence: contributions.filter((c) => c.source !== 'event')
        .map((c) => ({ memoryId: c.memoryId, label: c.label, kind: c.kind, statement: c.statement, effect: c.effectivePoints, verifiedBy: c.verifiedBy, source: c.source, reason: c.reason })),
      rejectedEvidence,
      verifiedFacts: [...accountVerified, ...patternMems].map((m) => m.statement),
      unverifiedClaims: accountMems.filter((m) => m.label === LABELS.CLAIMED).map((m) => m.statement),
      consumable: accountVerified.filter((m) => SINGLE_USE_KINDS.has(m.kind)).map((m) => ({
        nonce: m.payload.nonce, exp: m.payload.exp, iat: m.payload.iat, kind: m.payload.kind, accountId: m.payload.accountId, caseId: m.payload.caseId,
        issuer: m.payload.iss, kid: m.payload.kid, method: m.payload.method, statementSha256: m.payload.statementSha256,
      })),
      contextAvailable: true, retrievalComplete,
      contextItemsUsed: inScope.length, contextWeight, verifiedIdentityMitigation: callMitigated,
    };
  }

  /**
   * Retrieve context from Meko, then score. If Meko is unreachable we fail SAFE: no context, never
   * "allow". Returns timings: retrievalMs (Meko) and scoringMs (pure agent computation), kept separate.
   * Single-use verifications that backed a sensitive action are consumed here (replay protection).
   */
  async assess(event, { decisionId = null } = {}) {
    const ev = { ...event, eventId: event.eventId ?? randomUUID() };
    const scopes = [ev.accountId, ...(ev.orgId ? [ev.orgId] : [])];
    const t0 = performance.now();
    let memories;
    let retrievalComplete = true;
    let retrievalMeta = [];
    try {
      const lists = await Promise.all(scopes.map((scopeId) => this.store.retrieveScope({ agentId: this.agentId, scopeId })));
      memories = lists.flatMap((l) => l.memories);
      retrievalComplete = lists.every((l) => l.meta.complete);
      retrievalMeta = lists.map((l) => l.meta);
    } catch (err) {
      if (!(err instanceof MekoError)) throw err;
      const retrievalMs = performance.now() - t0;
      const s0 = performance.now();
      const base = this.score(ev, []);
      const scoringMs = performance.now() - s0;
      const floored = base.recommendedAction === 'allow' ? 'step_up' : base.recommendedAction;
      return {
        ...base,
        contextAvailable: false, retrievalComplete: false,
        recommendedAction: floored,
        stepUp: floored === 'step_up' ? { required: true, requirements: STEP_UP_REQUIREMENTS[ev.type] ?? STEP_UP_REQUIREMENTS.default } : base.stepUp,
        explanation: [`[DEGRADED] Could not retrieve context from Meko (${err.name}: ${err.message}). Decision uses the event alone and is floored at step_up.`, ...base.explanation],
        error: { name: err.name, message: err.message },
        retrieved: [], eventId: ev.eventId, timings: { retrievalMs, scoringMs },
      };
    }
    const retrievalMs = performance.now() - t0;
    const s0 = performance.now();
    const result = await this.#decide(ev, memories, retrievalComplete, decisionId);
    const scoringMs = performance.now() - s0;
    return {
      ...result,
      retrieved: memories.map((m) => ({ id: m.id, label: m.label, kind: m.kind, scope: m.accountId })),
      retrievalMeta, eventId: ev.eventId, timings: { retrievalMs, scoringMs },
    };
  }

  /**
   * Score and spend single-use evidence. Two replay-guard flavours:
   *  - in-process ReplayGuard (sync): the original behaviour;
   *  - persistent guard (has prepare/commit, e.g. PgReplayGuard): read the ledger, score, then spend ATOMICALLY. If another
   *    event won the race the decision is recomputed with that evidence rejected as replayed; if the ledger cannot be read or
   *    written the single-use evidence is rejected (fail closed) and the result says so (replayLedger: 'unavailable').
   */
  async #decide(ev, memories, retrievalComplete, decisionId) {
    const spend = SENSITIVE_ACTIONS.has(ev.type);
    if (typeof this.replay.prepare !== 'function') {
      const result = this.score(ev, memories, { retrievalComplete });
      if (spend) for (const c of result.consumable) this.replay.consume(c.nonce, ev.eventId, c.exp);
      return result;
    }
    const nonces = nonceCandidates(memories);
    for (let attempt = 1; ; attempt++) {
      let view;
      try { view = await this.replay.prepare(nonces); } catch { view = LEDGER_UNAVAILABLE; }
      const result = this.score(ev, memories, { retrievalComplete, replay: view });
      result.replayLedger = view.unavailable ? 'unavailable' : 'ok';
      if (view.unavailable || !spend || !result.consumable.length) return result;
      try {
        const spent = await this.replay.commit(result.consumable, ev.eventId, { decisionId });
        if (spent.ok) return { ...result, replayAttempts: attempt };
        if (attempt >= MAX_COMMIT_ATTEMPTS) break; // still losing races: fail closed below
      } catch {
        break; // could not write the ledger: fail closed below
      }
    }
    const failed = this.score(ev, memories, { retrievalComplete, replay: LEDGER_UNAVAILABLE });
    failed.replayLedger = 'unavailable';
    return failed;
  }
}
