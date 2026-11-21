/**
 * Wrap a MemoryStore so every Meko memory operation is recorded as agent activity (agent_events).
 * Behaviour is unchanged: results and errors pass straight through. Recording is write-behind and never throws.
 * Not a mock: it decorates the real store.
 */
import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * Context for everything an agent does while handling one decision: { caseId, eventId, decisionId }. DecisionService runs Agent B
 * inside it, so Meko reads made during the assessment are tagged with the case/event/decision they belong to (otherwise a case's
 * activity trail would show Agent A's writes but none of Agent B's reads).
 */
export const activityContext = new AsyncLocalStorage();

export function instrumentStore(store, recorder) {
  const record = (e) => {
    try {
      const ctx = activityContext.getStore();
      recorder.record(ctx ? { caseId: ctx.caseId, eventId: ctx.eventId, decisionId: ctx.decisionId, ...stripUndefined(e) } : e);
    } catch { /* recording must never break an agent */ }
  };
  const stripUndefined = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null));
  const timed = async (fn, onOk, onErr) => {
    const t0 = performance.now();
    try {
      const out = await fn();
      record({ ...onOk(out), durationMs: Math.round((performance.now() - t0) * 10) / 10, ok: true });
      return out;
    } catch (err) {
      record({ ...onErr, durationMs: Math.round((performance.now() - t0) * 10) / 10, ok: false, error: `${err.name}: ${err.message}` });
      throw err;
    }
  };

  const overrides = {
    save: (a) => timed(
      () => store.save(a),
      (r) => ({ agentId: a.agentId, kind: 'memory_written', accountId: a.accountId, caseId: a.caseId, memoryIds: [r.id], payload: { label: a.label, kind: a.kind } }),
      { agentId: a.agentId, kind: 'memory_write_failed', accountId: a.accountId, caseId: a.caseId, payload: { label: a.label, kind: a.kind } },
    ),
    saveRaw: (a) => timed(
      () => store.saveRaw(a),
      (r) => ({ agentId: a.agentId, kind: 'memory_written_raw', accountId: a.scopeId, memoryIds: [r.id], payload: {} }),
      { agentId: a.agentId, kind: 'memory_write_failed', accountId: a.scopeId, payload: {} },
    ),
    retrieveScope: (a) => timed(
      () => store.retrieveScope(a),
      (r) => ({
        agentId: a.agentId, kind: 'memories_retrieved', accountId: a.scopeId, memoryIds: r.memories.map((m) => m.id),
        payload: { meta: r.meta, count: r.memories.length, labels: Object.fromEntries(['CLAIMED', 'OBSERVED', 'VERIFIED'].map((l) => [l, r.memories.filter((m) => m.label === l).length])) },
      }),
      { agentId: a.agentId, kind: 'memory_retrieval_failed', accountId: a.scopeId, payload: {} },
    ),
    remove: (id, agentId) => timed(
      () => store.remove(id, agentId),
      () => ({ agentId, kind: 'memory_deleted', memoryIds: [id], payload: {} }),
      { agentId, kind: 'memory_delete_failed', memoryIds: [id], payload: {} },
    ),
  };
  return new Proxy(store, {
    get(target, prop, receiver) {
      if (prop in overrides) return overrides[prop];
      const v = Reflect.get(target, prop, target);
      return typeof v === 'function' ? v.bind(target) : v;
    },
  });
}
