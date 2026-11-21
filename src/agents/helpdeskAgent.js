import { LABELS } from '../labels.js';
import { extractFacts } from './extraction.js';

export const HELPDESK_AGENT_ID = 'trusttrace_helpdesk_agent';
// Language extraction lives in ./extraction.js (concept matcher: stemming, windows, negation, typo tolerance).

/**
 * Agent A. Turns a help-desk interaction into labelled facts and saves them in Meko.
 *
 * Trust rules (enforced here AND in labels.js):
 *  - What the caller says            -> CLAIMED
 *  - What the system/agent saw       -> OBSERVED (call behaviour, telemetry in `observations`)
 *  - Agent A can NEVER produce VERIFIED. Only the verification authority (src/trust/authority.js), which
 *    holds the signing key, can attest evidence. A "passed check" reported to this agent is an unsigned
 *    OBSERVED note worth zero risk points.
 */
export class HelpDeskAgent {
  constructor(store, { agentId = HELPDESK_AGENT_ID } = {}) {
    this.store = store;
    this.agentId = agentId;
  }

  /** Pure extraction, no I/O. Exposed for testing. */
  extract({ callerText = '', observations = [], verifications = [] }) {
    // Caller speech -> CLAIMED (what they said) or OBSERVED (how they behaved on the call). Never VERIFIED.
    const facts = extractFacts(callerText).map((f) => ({ label: f.label === 'CLAIMED' ? LABELS.CLAIMED : LABELS.OBSERVED, kind: f.kind, statement: f.statement }));
    for (const o of observations) {
      facts.push({ label: LABELS.OBSERVED, kind: o.kind, statement: o.statement });
    }
    for (const v of verifications) {
      if (v.passed === true && v.method) {
        // Agent A can NEVER create VERIFIED evidence: that needs a signature from the verification
        // authority (src/trust/authority.js), which this agent cannot reach. A reported pass is kept as
        // an unsigned observation worth 0 risk points - useful context, never trusted.
        facts.push({ label: LABELS.OBSERVED, kind: `${v.kind}_reported_passed`, statement: `Unsigned report (not verified evidence): ${v.statement}` });
      } else {
        // A failed or method-less check is itself an observation, never a verified fact.
        facts.push({
          label: LABELS.OBSERVED,
          kind: `${v.kind}_failed`,
          statement: `Verification did not pass: ${v.statement}`,
        });
      }
    }
    return facts;
  }

  /** Extract + persist to Meko. Returns the saved memories with their Meko ids. */
  async handleInteraction({ caseId, accountId, runId, callerText, observations, verifications, onSaved }) {
    const e0 = performance.now();
    const facts = this.extract({ callerText, observations, verifications });
    const extractMs = performance.now() - e0;
    const s0 = performance.now();
    const saved = [];
    for (const f of facts) {
      const res = await this.store.save({ agentId: this.agentId, caseId, accountId, runId, ...f });
      saved.push({ ...f, id: res.id });
      onSaved?.(res.id); // lets callers track ids for cleanup even if a later save throws
    }
    // extractMs = pure agent computation; saveMs = Meko write round-trips (reported separately).
    return { caseId, accountId, runId, saved, timings: { extractMs, saveMs: performance.now() - s0 } };
  }
}
