import { randomUUID } from 'node:crypto';
import { appendAudit } from '../db/auditChain.js';
import { buildDecisionRecord, decisionPayload, insertDecision, upsertCase } from '../db/decisionRepo.js';
import { withTransaction } from '../db/pool.js';
import { activityContext } from './instrumentedStore.js';

/**
 * Runs Agent B and PERSISTS the decision: the decision row, the case index and the audit-chain record commit in ONE
 * transaction, and the decision is also noted in the agent activity trail. The decision log in PostgreSQL is authoritative;
 * if the database write fails the error propagates (nothing is silently dropped).
 */
export class DecisionService {
  constructor({ pool, recorder, agent }) {
    this.pool = pool;
    this.recorder = recorder;
    this.agent = agent;
  }

  /** @returns {{decisionId:string, record:object, result:object}} */
  async assessAndRecord(event) {
    const decisionId = randomUUID();
    const t0 = performance.now();
    let result;
    try {
      // everything Agent B does against Meko during this assessment is tagged with this case/event/decision
      result = await activityContext.run({ caseId: event.caseId, eventId: event.eventId, decisionId }, () => this.agent.assess(event, { decisionId }));
    } catch (err) {
      this.recorder?.record({ agentId: this.agent.agentId, kind: 'decision_failed', accountId: event.accountId, caseId: event.caseId, eventId: event.eventId, decisionId, ok: false, error: `${err.name}: ${err.message}` });
      throw err;
    }
    const record = buildDecisionRecord(result, {
      decisionId, event: { ...event, eventId: result.eventId }, agentId: this.agent.agentId,
      verifierKeyId: this.agent.verifier?.keyIds?.[0] ?? null,
    });
    await withTransaction(this.pool, async (c) => {
      await insertDecision(c, record);
      await upsertCase(c, record);
      await appendAudit(c, { recordType: 'decision', refId: record.id, payload: decisionPayload(record), createdAt: record.createdAt });
    });
    this.recorder?.record({
      agentId: this.agent.agentId, kind: 'decision_made', accountId: record.accountId, caseId: record.caseId, eventId: record.eventId, decisionId,
      memoryIds: record.retrieved.map((m) => m.id), durationMs: Math.round((performance.now() - t0) * 10) / 10, ok: true,
      payload: {
        severity: record.severity, recommendedAction: record.recommendedAction, rawScore: record.rawScore, degraded: record.degraded,
        rejected: record.rejectedEvidence.map((r) => r.reason), replayLedger: result.replayLedger ?? 'in_process',
      },
    });
    return { decisionId, record, result };
  }
}
