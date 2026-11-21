// Pure assembly of "Meko memory evidence" from persisted decisions (no I/O, unit-testable).
//
// IMPORTANT (what this is and is not): this is the SNAPSHOT recorded in the decision log at decision time - which memories Agent B
// retrieved from Meko, how each one was labelled, what it contributed, and which records claiming VERIFIED were rejected. The API server
// never holds the Meko key and does not query Meko, so this is not a live view of Meko's current contents.

/**
 * Trust classification shown to analysts. A CLAIMED statement is never presented as a fact:
 *   unverified_claim    - a caller said it (CLAIMED)
 *   observed            - a system saw it (OBSERVED)
 *   verified_authentic  - VERIFIED and its signature/bindings were accepted for that decision
 *   rejected            - the record claimed to be VERIFIED but FAILED authentication (forged, tampered, expired, replayed, ...)
 */
export function trustOf(label, { accepted, rejected }) {
  if (rejected) return 'rejected';
  if (label === 'CLAIMED') return 'unverified_claim';
  if (label === 'OBSERVED') return 'observed';
  if (label === 'VERIFIED') return accepted ? 'verified_authentic' : 'verified_unused';
  return 'unknown';
}

/**
 * @param {object[]} decisions persisted decision records (camelCase, as from recordFromRow)
 * @param {{memory_id?:string, agent_id:string, at:Date, memoryIds?:string[]}[]} writerRows memory_written agent events
 */
export function buildEvidence(decisions, writerRows = []) {
  const writers = new Map();
  for (const w of writerRows) for (const id of w.memoryIds ?? w.memory_ids ?? []) if (!writers.has(id)) writers.set(id, { agentId: w.agentId ?? w.agent_id, at: w.at });

  const memories = new Map();
  const rejected = [];
  const touch = (id, base) => {
    if (!memories.has(id)) memories.set(id, { memoryId: id, label: base.label ?? null, kind: base.kind ?? null, scope: base.scope ?? null, statement: null, usage: [], rejectedIn: [], acceptedIn: [] });
    return memories.get(id);
  };

  for (const d of decisions) {
    const rejectedIds = new Set(d.rejectedEvidence.map((r) => r.memoryId).filter(Boolean));
    for (const m of d.retrieved) touch(m.id, m);
    for (const c of d.contributions) {
      if (!c.memoryId) continue;
      const m = touch(c.memoryId, { label: c.label === 'REJECTED_VERIFIED' ? 'VERIFIED' : c.label, kind: c.kind });
      m.statement ??= c.statement ?? null;
      m.usage.push({ decisionId: d.id, source: c.source, basePoints: c.basePoints, weight: c.weight, effectivePoints: c.effectivePoints });
      if (c.source === 'verified' || c.source === 'pattern') m.acceptedIn.push(d.id);
    }
    for (const r of d.rejectedEvidence) {
      rejected.push({ decisionId: d.id, memoryId: r.memoryId ?? null, kind: r.kind ?? null, reason: r.reason, detail: r.detail ?? null, points: r.points ?? 0, statement: r.statement ?? null });
      if (r.memoryId) {
        const m = touch(r.memoryId, { label: 'VERIFIED', kind: r.kind });
        m.statement ??= r.statement ?? null;
        m.rejectedIn.push({ decisionId: d.id, reason: r.reason });
      }
    }
    void rejectedIds;
  }

  const items = [...memories.values()].map((m) => ({
    memoryId: m.memoryId, label: m.label, kind: m.kind, scope: m.scope, statement: m.statement,
    trust: trustOf(m.label, { accepted: m.acceptedIn.length > 0, rejected: m.rejectedIn.length > 0 && m.acceptedIn.length === 0 }),
    writer: writers.get(m.memoryId) ?? null,
    usage: m.usage, rejectedIn: m.rejectedIn,
    netEffectPoints: Math.round(m.usage.reduce((a, u) => a + (u.effectivePoints ?? 0), 0) * 10) / 10,
  }));
  items.sort((a, b) => Math.abs(b.netEffectPoints) - Math.abs(a.netEffectPoints) || String(a.memoryId).localeCompare(String(b.memoryId)));

  return {
    source: 'decision_log_snapshot',
    note: 'Recorded when each decision was made. Meko is not queried by the API server, so this is not a live view of Meko.',
    memories: items,
    rejected,
    totals: {
      memories: items.length,
      byTrust: items.reduce((o, m) => ((o[m.trust] = (o[m.trust] ?? 0) + 1), o), {}),
      rejectedRecords: rejected.length,
    },
  };
}
