// TEST DOUBLE ONLY: FakeMeko extended with datapacks (scoped memories, datapack_search / datapack_describe), a model of Meko's indexing lag and of
// delayed deletion visibility, and a log of every call. It is NOT Meko.
import { FakeMeko } from './fakeMeko.js';
import { MekoToolError } from '../../src/errors.js';

export class FakeDatapackMeko extends FakeMeko {
  /** @param {{lag?: number, deleteLag?: number, datapacks?: {id:string,name:string}[]}} opts */
  constructor({ lag = 0, deleteLag = 0, datapacks } = {}) {
    super();
    this.lag = lag; this.deleteLag = deleteLag;
    this.datapacks = datapacks ?? [
      { id: 'dp-demo', name: 'trusttrace-demo' }, { id: 'dp-test', name: 'trusttrace-test' }, { id: 'dp-default', name: 'meko_default_datapack' },
    ];
    this.stamps = new Map(this.datapacks.map((d) => [d.id, { created_at: '2026-11-19T10:00:00Z', updated_at: '2026-11-19T10:00:00Z', knowledge_count: d.id === 'dp-default' ? 9 : 0 }]));
    this.hidden = new Map(); this.zombies = new Map(); this.sent = [];
  }

  #view(dp) { return this.memories.filter((m) => m.datapackId === dp); }

  async callTool(name, args = {}) {
    this.sent.push({ name, args });
    if (name === 'datapack_search') {
      const rows = this.datapacks.filter((d) => !args.name || d.name === args.name);
      return { datapacks: rows.map((d) => ({ datapack_id: d.id, datapack_name: d.name, grant: 'owner' })), has_more: false, total: rows.length };
    }
    if (name === 'datapack_describe') {
      const d = this.datapacks.find((x) => x.id === args.datapack_id);
      if (!d) throw new MekoToolError('datapack_describe: not found', { tool: name, payload: { error: 'not_found' } });
      const s = this.stamps.get(d.id);
      return { datapack_name: d.name, grant: 'owner', created_at: s.created_at, updated_at: s.updated_at, memory_count: this.#view(d.id).length, knowledge_count: s.knowledge_count, learnings_count: 0, collective_memory_count: 0, conversation_search_opt_out: false };
    }
    if (name === 'conversation_create') return super.callTool(name, args);
    if (!name.startsWith('memory_')) throw new Error(`FakeDatapackMeko: unsupported tool ${name}`);

    const dp = args.datapack_id;
    const others = this.memories.filter((m) => m.datapackId !== dp);
    this.memories = this.#view(dp);
    let result;
    try {
      if (name === 'memory_get_by_id' && this.zombies.has(args.memory_id)) {
        const left = this.zombies.get(args.memory_id);
        if (left > 0) { this.zombies.set(args.memory_id, left - 1); return { id: args.memory_id, memory: 'being deleted' }; }
        this.zombies.delete(args.memory_id);
      }
      if (name === 'memory_delete_by_id' && this.deleteLag > 0) { this.zombies.set(args.memory_id, this.deleteLag); }
      result = await super.callTool(name, args);
      if (name === 'memory_add') { const id = result.results[0].id; this.memories.find((m) => m.id === id).datapackId = dp; this.hidden.set(id, this.lag); }
      if (name === 'memory_search') {
        result = { results: result.results.filter((r) => (this.hidden.get(r.id) ?? 0) === 0) };
        for (const [id, n] of this.hidden) if (n > 0) this.hidden.set(id, n - 1);
      }
    } finally {
      this.memories = [...others, ...this.memories];
    }
    return result;
  }

  tally(names) { const t = {}; for (const c of this.sent) if (!names || names.includes(c.name)) t[c.name] = (t[c.name] ?? 0) + 1; return t; }
}
