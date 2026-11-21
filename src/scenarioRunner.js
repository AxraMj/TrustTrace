import { HelpDeskAgent } from './agents/helpdeskAgent.js';
import { ACTION_RANK, IdentitySecurityAgent } from './agents/identityAgent.js';
import { plantForgery } from './adversary.js';
import { SCENARIOS } from './scenarios.js';
import { AttestationVerifier } from './trust/verifier.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const r1 = (x) => Math.round(x * 10) / 10;

/** correct | FALSE_POSITIVE (system more severe than any acceptable outcome) | FALSE_NEGATIVE (more lenient). */
export function classify(actual, acceptable) {
  if (acceptable.includes(actual)) return 'correct';
  const max = Math.max(...acceptable.map((a) => ACTION_RANK[a]));
  return ACTION_RANK[actual] > max ? 'FALSE_POSITIVE' : 'FALSE_NEGATIVE';
}

/**
 * Run scenarios through Agent A / verification authority -> store -> Agent B.
 * `store` is the real Meko MemoryStore for live runs (or a test double for offline logic tests).
 * `authority` plays the trusted verification component; Agent B only gets its PUBLIC trust anchor.
 * Cleanup is the caller's job: `tracker.savedIds` / `tracker.writers` (id -> writer agent) are filled incrementally.
 */
export async function runScenarios({
  store, tag, authority, scenarios = SCENARIOS, indexTimeoutMs = 90_000, pollMs = 2_000, onProgress = () => {},
  tracker = { savedIds: [], scopeIds: [], writers: {} },
  // Phase "app": a persistent replay guard and a persisting assess function (DecisionService) can be injected.
  replayGuard, assess = (agent, event) => agent.assess(event),
}) {
  tracker.writers ??= {};
  const verifier = authority ? new AttestationVerifier({ trustAnchors: [authority.trustAnchor] }) : null;
  const A = new HelpDeskAgent(store);
  const B = new IdentitySecurityAgent(store, { verifier, ...(replayGuard ? { replayGuard } : {}) });
  await store.warm?.(A.agentId);
  await store.warm?.(B.agentId); // so conversation setup is not counted as retrieval latency
  const { savedIds, scopeIds } = tracker;
  const track = (id, agentId) => { savedIds.push(id); tracker.writers[id] = agentId; };

  const results = [];
  for (const sc of scenarios) {
    onProgress(`${sc.id} ${sc.title}`);
    const accountId = `acct-${sc.id}-${tag}`;
    const orgId = `org-${sc.id}-${tag}`;
    const caseId = `case-${sc.id}-${tag}`;
    const runId = `run-${tag}`;
    const timings = { agentExtractMs: 0, mekoWriteMs: 0, indexWaitMs: 0, retrievalMs: 0, scoringMs: 0 };
    const saved = [];

    for (const it of sc.interactions) {
      const scope = it.scope === 'org' ? orgId : accountId;
      if (!scopeIds.includes(scope)) scopeIds.push(scope);
      const res = await A.handleInteraction({
        caseId, accountId: scope, runId, callerText: it.callerText ?? '', observations: it.observations, verifications: it.verifications,
        onSaved: (id) => track(id, A.agentId),
      });
      timings.agentExtractMs += res.timings.extractMs;
      timings.mekoWriteMs += res.timings.saveMs;
      for (const f of res.saved) saved.push({ ...f, scope });

      const w0 = performance.now();
      for (const att of it.attestations ?? []) {
        if (!authority) throw new Error(`${sc.id}: scenario needs a verification authority`);
        const r = await authority.record(store, { caseId, accountId: scope, runId, ...att });
        track(r.id, authority.agentId);
        saved.push({ id: r.id, scope, label: 'VERIFIED', kind: att.kind });
      }
      for (const fg of it.forgeries ?? []) {
        const r = await plantForgery(store, { caseId, accountId: scope, runId, legit: authority, ...fg });
        track(r.id, r.agentId);
        saved.push({ id: r.id, scope, label: 'VERIFIED(forged)', kind: fg.kind });
      }
      timings.mekoWriteMs += performance.now() - w0;
    }

    // Meko indexes asynchronously: wait until every saved memory is visible (measured separately).
    const w0 = performance.now();
    let indexed = true;
    for (const scope of new Set(saved.map((f) => f.scope))) {
      const want = saved.filter((f) => f.scope === scope).map((f) => f.id);
      let ok = false;
      while (performance.now() - w0 < indexTimeoutMs) {
        const have = new Set((await store.searchScope({ agentId: B.agentId, scopeId: scope })).map((m) => m.id));
        if (want.every((id) => have.has(id))) { ok = true; break; }
        await sleep(pollMs);
      }
      indexed = indexed && ok;
    }
    timings.indexWaitMs = performance.now() - w0;

    const event = { ...sc.event, accountId, caseId, eventId: `evt-${sc.id}-${tag}`, ...(sc.interactions.some((i) => i.scope === 'org') ? { orgId } : {}) };
    const out = await assess(B, event);
    timings.retrievalMs = out.timings.retrievalMs;
    timings.scoringMs = out.timings.scoringMs;

    const noContext = B.score(event, []);
    const withoutPattern = out.contributions.some((c) => c.source === 'pattern')
      ? B.score(event, await store.searchScope({ agentId: B.agentId, scopeId: accountId }))
      : null;

    const influencing = out.contributions
      .filter((c) => c.source !== 'event' && c.memoryId && c.effectivePoints !== 0)
      .map((c) => ({ memoryId: c.memoryId, source: c.source, label: c.label, kind: c.kind, effect: r1(c.effectivePoints), statement: c.statement }));
    const sources = new Set(influencing.map((i) => i.source));
    const rejectedReasons = out.rejectedEvidence.map((r) => r.reason);

    const exp = sc.expected;
    const classification = classify(out.recommendedAction, exp.actions);
    const checks = {
      actionCorrect: classification === 'correct',
      severityOk: exp.severities ? exp.severities.includes(out.severity) : true,
      retrievedOk: exp.memoriesRetrieved === undefined ? true : exp.memoriesRetrieved ? out.retrieved.length > 0 && indexed : out.retrieved.length === 0,
      influenceOk: exp.influences ? exp.influences.every((s) => sources.has(s)) && (exp.memoriesRetrieved !== false || influencing.length === 0) : true,
      rejectedOk: exp.rejected ? exp.rejected.every((reason) => rejectedReasons.includes(reason)) : true,
      policyOk: exp.policyRules ? exp.policyRules.every((p) => out.policy.some((x) => x.rule === p)) : true,
      // The decision must be backed by EVIDENCE Agent A extracted (not merely by a policy floor): these kinds must be
      // among the memories that actually moved the score.
      evidenceOk: exp.evidenceKinds ? exp.evidenceKinds.every((k) => influencing.some((i) => i.kind === k)) : true,
      // A record that failed authentication must never also appear as accepted verified evidence.
      noTrustFromRejected: !out.contributions.some(
        (c) => (c.source === 'verified' || c.source === 'pattern') && out.rejectedEvidence.some((r) => r.memoryId === c.memoryId),
      ),
      indexed,
    };

    results.push({
      id: sc.id, title: sc.title, expected: exp, classification,
      actual: { action: out.recommendedAction, baseAction: out.baseAction, severity: out.severity, rawScore: out.rawScore, displayScore: out.displayScore },
      memoriesRetrieved: out.retrieved.length,
      influencing, rejected: out.rejectedEvidence.map((r) => ({ reason: r.reason, kind: r.kind, points: r.points })),
      policy: out.policy, stepUp: out.stepUp, retrievalComplete: out.retrievalComplete,
      counterfactual: {
        withoutMeko: { rawScore: noContext.rawScore, severity: noContext.severity, action: noContext.recommendedAction },
        withoutPattern: withoutPattern ? { rawScore: withoutPattern.rawScore, severity: withoutPattern.severity, action: withoutPattern.recommendedAction } : null,
      },
      explanation: out.explanation, checks,
      pass: Object.values(checks).every(Boolean),
      timings: Object.fromEntries(Object.entries(timings).map(([k, v]) => [k, r1(v)])),
    });
  }
  return { results, savedIds, scopeIds, writers: tracker.writers, agentIds: [A.agentId, B.agentId] };
}

/** Plain-text scenario results table. */
export function formatTable(results) {
  const rows = results.map((r) => {
    const infl = r.influencing.length ? r.influencing.map((i) => `${i.label}:${i.kind}(${i.effect > 0 ? '+' : ''}${i.effect})`).join(', ') : '-';
    const rej = r.rejected.length ? r.rejected.map((x) => x.reason).join(',') : '-';
    return [
      r.id, r.title,
      r.expected.actions.join('|'),
      r.actual.action + (r.actual.baseAction !== r.actual.action ? ` (base ${r.actual.baseAction})` : ''),
      `${r.actual.rawScore} / ${r.actual.displayScore}`,
      String(r.memoriesRetrieved), infl, rej, r.classification,
      `${r.counterfactual.withoutMeko.rawScore} (${r.counterfactual.withoutMeko.action})`,
      r.pass ? 'PASS' : 'FAIL',
    ];
  });
  const head = ['ID', 'Scenario', 'Expected action', 'Actual action', 'Raw / Display', 'Retrieved', 'Influencing memories', 'Rejected evidence', 'vs expected', 'Without Meko (raw)', 'Result'];
  const widths = head.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
  const line = (cells) => cells.map((c, i) => c.padEnd(widths[i])).join(' | ');
  return [line(head), widths.map((w) => '-'.repeat(w)).join('-+-'), ...rows.map(line)].join('\n');
}
