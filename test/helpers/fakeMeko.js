// TEST DOUBLE ONLY: a fake Meko tool API with the response shapes and the behaviours that were verified
// against the live server (see src/meko/memory.js header). Used to test MemoryStore's retrieval logic -
// truncation, bucket scoping, pagination - offline and at scale. It is NOT Meko.
import { MekoToolError } from '../../src/errors.js';

const dashed = (hex) => (hex.includes('-') ? hex : `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`);

export class FakeMeko {
  /**
   * @param {{rank?: 'relevant_first'|'noise_first'}} [opts] ranking used by memory_search. 'noise_first'
   *        models the crowding failure: unrelated memories outrank the ones we need.
   */
  constructor({ rank = 'relevant_first' } = {}) {
    this.rank = rank;
    this.conversationsBySession = new Map();
    this.memories = []; // { id, text, agentId, conversationId, seq }
    this.calls = [];
    this.seq = 0;
  }

  async callTool(name, args = {}) {
    this.calls.push({ name, args });
    switch (name) {
      case 'conversation_create': {
        const key = args.session_id ?? `anon-${this.conversationsBySession.size}-${Math.random()}`;
        if (!this.conversationsBySession.has(key)) this.conversationsBySession.set(key, `c${String(this.conversationsBySession.size + 1).padStart(31, '0')}`);
        return { id: this.conversationsBySession.get(key), agent_id: args.agent_id };
      }
      case 'memory_add': {
        const id = `m-${++this.seq}`;
        this.memories.push({ id, text: args.text, agentId: args.agent_id, conversationId: args.conversation_id, seq: this.seq });
        return { results: [{ id, memory: args.text, event: 'ADD' }] };
      }
      case 'memory_search': {
        const q = String(args.query ?? '');
        const limit = args.limit ?? 10;
        let rows = this.memories.filter((m) => !args.run_id || m.conversationId === args.run_id);
        const rel = (m) => (m.text.includes(q.replace('TRUSTTRACE ACCOUNT:', 'ACCOUNT:')) ? 1 : 0);
        rows = [...rows].sort((a, b) => (this.rank === 'noise_first' ? rel(a) - rel(b) : rel(b) - rel(a)) || b.seq - a.seq);
        return { results: rows.slice(0, limit).map((m) => ({ id: m.id, memory: m.text, score: rel(m), agent_id: m.agentId, run_id: m.conversationId })) };
      }
      case 'memory_get_all': {
        const pageSize = Math.min(args.page_size ?? 20, 100);
        const page = args.page ?? 1;
        const rows = [...this.memories].sort((a, b) => b.seq - a.seq); // newest first
        const slice = rows.slice((page - 1) * pageSize, page * pageSize);
        return {
          memories: slice.map((m) => ({ id: m.id, data: m.text, agent_id: m.agentId, conversation_id: dashed(m.conversationId) })),
          total: rows.length, page, page_size: pageSize, total_pages: Math.max(1, Math.ceil(rows.length / pageSize)),
        };
      }
      case 'memory_get_by_id': {
        const m = this.memories.find((x) => x.id === args.memory_id);
        if (!m) throw new MekoToolError('memory_get_by_id returned an error: not_found', { tool: name, payload: { error: 'not_found' } });
        return { id: m.id, memory: m.text };
      }
      case 'memory_delete_by_id':
        this.memories = this.memories.filter((x) => x.id !== args.memory_id);
        return { message: 'Memory deleted successfully!' };
      default:
        throw new Error(`FakeMeko: unsupported tool ${name}`);
    }
  }
}
