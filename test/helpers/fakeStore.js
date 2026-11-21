// TEST DOUBLE ONLY. An in-memory stand-in for MemoryStore used to test Agent A/B *logic* offline and
// deterministically. It is NOT Meko and proves nothing about the Meko integration - the live
// integration tests do that. It mimics Meko semantics that matter: text stored as written, search is
// cross-agent, results come back through the same parseMemory().
import { formatMemory, parseMemory } from '../../src/labels.js';

export class FakeStore {
  constructor() {
    this.rows = [];
    this.n = 0;
  }
  async warm() {}
  async save({ agentId, caseId, accountId, runId, label, kind, statement, verifiedBy, attestation }) {
    const text = formatMemory({ caseId, accountId, runId, label, kind, statement, verifiedBy, attestation });
    return this.addRaw(text, agentId, label);
  }
  /** Insert arbitrary raw text (e.g. a forged memory an attacker managed to get stored). */
  addRaw(text, agentId = 'someone', label) {
    const id = `fake-${++this.n}`;
    this.rows.push({ id, text, agentId });
    return { id, text, label };
  }
  async saveRaw({ agentId, text }) {
    return this.addRaw(text, agentId);
  }
  async retrieveScope({ scopeId, accountId }) {
    const scope = scopeId ?? accountId;
    const memories = this.rows
      .map((r) => ({ id: r.id, writerAgentId: r.agentId, ...parseMemory(r.text) }))
      .filter((m) => m.trusttrace && m.accountId === scope);
    return { memories, meta: { strategy: 'fake', complete: true, truncated: false, usedFallback: false, scannedPages: 0, searchReturned: memories.length } };
  }
  async searchScope(args) {
    return (await this.retrieveScope(args)).memories;
  }
  async remove(id) {
    this.rows = this.rows.filter((r) => r.id !== id);
  }
}

/** A store that always fails like an unreachable Meko. */
export function brokenStore(ErrorClass, message = 'Meko unreachable') {
  return {
    async warm() {},
    async retrieveScope() {
      throw new ErrorClass(message);
    },
    async searchScope() {
      throw new ErrorClass(message);
    },
  };
}
