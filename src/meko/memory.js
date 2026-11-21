import { createHash } from 'node:crypto';
import { MekoToolError } from '../errors.js';
import { formatMemory, parseMemory } from '../labels.js';

// Response shapes below were confirmed against the live Meko Cloud server (2026-11-21):
//   conversation_create -> { id, ... }   (session_id makes it idempotent: same id back)
//   datapack_search     -> { datapacks: [{ datapack_id, datapack_name, ... }], has_more }
//   datapack_create     -> { datapack_id, name }
//   memory_add          -> { results: [{ id, memory, event }] }
//   memory_search       -> { results: [{ id, memory, metadata, score, agent_id, run_id }] }
//   memory_get_all      -> { memories: [{ id, data, agent_id, conversation_id }], total, page, page_size, total_pages }
// Facts verified live and relied on here (see README "Meko behaviours"):
//   * every tool call needs a conversation_id, even where the docs say optional
//   * memory_add's conversation_id TAGS the memory row; memory_search's `run_id` filters EXACTLY on that tag
//   * any agent may write into / search a conversation that a different agent id created
//   * memory_search has NO pagination/offset parameter; `limit` (documented default 10) was accepted up to 100000 with no cap observed
//     (the 200 we used before Phase 4 was OUR choice, not a Meko limit). Results are cut by a relevance cutoff, not just by limit.
//   * memory_get_all IS paginated (page_size clamped to 100, total_pages reported) and lists every memory the user has in the datapack;
//     its run_id parameter is accepted but IGNORED (verified live), so the scan cannot be scoped server-side: it costs O(datapack) pages
//   * conversation_delete is not verifiable, so conversations are reused (session_id), never deleted
const pickId = (o) => o?.id ?? o?.datapack_id ?? o?.memory_id;
const pickText = (o) => o?.memory ?? o?.text ?? o?.content ?? o?.data ?? '';

function asArray(payload, ...keys) {
  if (Array.isArray(payload)) return payload;
  for (const k of keys) if (Array.isArray(payload?.[k])) return payload[k];
  return null;
}

export const BUCKET_COUNT = 32;
/** Our default limit for memory_search. Meko accepted 100000 in tests; 1000 keeps responses reasonable and still detects truncation. */
export const DEFAULT_SEARCH_LIMIT = 1000;
export const BUCKET_AGENT_ID = 'trusttrace_bucket';

/** Deterministic bucket for a scope id (an account id or an org id). */
export function bucketOf(scopeId, buckets = BUCKET_COUNT) {
  return createHash('sha256').update(String(scopeId)).digest().readUInt32BE(0) % buckets;
}

/** Create-or-reuse a conversation (the trace container every other Meko call needs). */
export async function createConversation(client, { agentId, title, datapackId, sessionId }) {
  const args = { agent_id: agentId, title };
  if (datapackId) args.datapack_id = datapackId;
  if (sessionId) args.session_id = sessionId; // dedup key: same session_id -> same conversation
  const conv = await client.callTool('conversation_create', args);
  if (!conv?.id) throw new MekoToolError('conversation_create returned no id', { tool: 'conversation_create', payload: conv });
  return conv.id;
}

/** Find a datapack by exact name, or create it (documented tools: datapack_search / datapack_create). */
export async function ensureDatapack(client, name, conversationId) {
  const found = await client.callTool('datapack_search', { name, conversation_id: conversationId });
  const hit = (asArray(found, 'datapacks', 'results') ?? []).find((d) => (d?.datapack_name ?? d?.name) === name);
  if (hit) return { id: pickId(hit), name, created: false };

  const created = await client.callTool('datapack_create', { name, conversation_id: conversationId });
  const id = pickId(created) ?? pickId(created?.datapack);
  if (!id) throw new MekoToolError('datapack_create returned no datapack id', { tool: 'datapack_create', payload: created });
  return { id, name, created: true };
}

export class MemoryStore {
  /**
   * @param {{callTool:Function}} client
   * @param {string} datapackId
   * @param {{buckets?:number}} [opts]
   */
  constructor(client, datapackId, { buckets = BUCKET_COUNT } = {}) {
    this.client = client;
    this.datapackId = datapackId;
    this.buckets = buckets;
    this.registry = new Map(); // key -> { spec, promise }   (every conversation we use, for reuse checks)
  }

  #conversation(key, spec) {
    if (!this.registry.has(key)) {
      const promise = createConversation(this.client, { ...spec, datapackId: this.datapackId });
      promise.catch(() => this.registry.delete(key)); // never cache failures
      this.registry.set(key, { spec, promise });
    }
    return this.registry.get(key).promise;
  }

  /** The agent's own stable conversation: used only as the Meko trace container for its calls. */
  conversationFor(agentId) {
    return this.#conversation(`agent:${agentId}`, { agentId, title: `TrustTrace ${agentId}`, sessionId: `trusttrace-${agentId}` });
  }

  /** Shared conversation for a scope's bucket: it tags rows on write and scopes search server-side. */
  bucketConversation(scopeId) {
    const n = bucketOf(scopeId, this.buckets);
    return this.#conversation(`bucket:${n}`, { agentId: BUCKET_AGENT_ID, title: `TrustTrace bucket ${n}`, sessionId: `trusttrace-bucket-${n}` });
  }

  /** Every conversation this store has used, with its spec, for reuse verification. */
  async conversations() {
    const out = [];
    for (const [key, { spec, promise }] of this.registry) out.push({ key, spec, id: await promise });
    return out;
  }

  /** Pre-create the agent's conversation so it is not counted as retrieval latency. */
  async warm(agentId) {
    await this.conversationFor(agentId);
  }

  /** Save one labelled fact. Returns { id, text, label }. `bucketScopeId` is for adversary simulations only. */
  async save({ agentId, caseId, accountId, runId, label, kind, statement, verifiedBy, attestation, bucketScopeId }) {
    const text = formatMemory({ caseId, accountId, runId, label, kind, statement, verifiedBy, attestation });
    return this.saveRaw({ agentId, text, scopeId: bucketScopeId ?? accountId, metadata: { trusttrace: true, label, kind, case_id: caseId, account_id: accountId, run_id: runId } });
  }

  /** Store arbitrary text as Meko would (an attacker with write access can do exactly this). */
  async saveRaw({ agentId, text, scopeId, metadata = {} }) {
    const payload = await this.client.callTool('memory_add', {
      text,
      conversation_id: await this.bucketConversation(scopeId),
      agent_id: agentId,
      datapack_id: this.datapackId,
      metadata: JSON.stringify(metadata),
    });
    const id = asArray(payload, 'results', 'memories')?.[0]?.id;
    if (!id) throw new MekoToolError('memory_add returned no memory id', { tool: 'memory_add', payload });
    return { id, text, label: metadata.label };
  }

  /**
   * Retrieve every TrustTrace memory for one scope (account id or org id), with explicit completeness info.
   *
   * 1. Server-side scoped search: memory_search restricted (run_id) to the scope's bucket conversation, so
   *    unrelated accounts/noise in other buckets cannot crowd out results. Not exact: the bucket is shared by
   *    ~1/32 of scopes, so results are still post-filtered by the exact scope in the memory header.
   * 2. memory_search has no pagination. If it returns `limit` rows the result may be truncated, so we fall back
   *    to an exhaustive paginated scan (memory_get_all, 100/page) filtered by exact scope.
   * 3. If even the scan exceeds `maxScanPages`, we say so: meta.complete === false (callers must fail safe).
   *
   * @returns {{memories: object[], meta: {strategy:string, bucket:number, searchReturned:number, truncated:boolean,
   *            usedFallback:boolean, scannedPages:number, complete:boolean}}}
   */
  async retrieveScope({ agentId, scopeId, limit = DEFAULT_SEARCH_LIMIT, strategy = 'search', maxScanPages = 30 }) {
    const accept = (id, text, extra = {}) => {
      const p = parseMemory(text);
      return p.trusttrace && p.accountId === scopeId ? { id, ...extra, ...p } : null; // exact match only
    };
    const found = new Map();
    const meta = { strategy, bucket: bucketOf(scopeId, this.buckets), searchReturned: 0, truncated: false, usedFallback: false, scannedPages: 0, complete: true };
    const traceConv = await this.conversationFor(agentId);

    if (strategy === 'search') {
      const payload = await this.client.callTool('memory_search', {
        query: `TRUSTTRACE ACCOUNT:${scopeId}`,
        conversation_id: traceConv,
        run_id: await this.bucketConversation(scopeId),
        agent_id: agentId,
        datapack_id: this.datapackId,
        limit,
      });
      const items = asArray(payload, 'results', 'memories');
      if (!items) throw new MekoToolError('memory_search returned an unrecognised response shape', { tool: 'memory_search', payload });
      meta.searchReturned = items.length;
      for (const r of items) {
        const m = accept(pickId(r), pickText(r), { score: r.score, writerAgentId: r.agent_id });
        if (m) found.set(m.id, m);
      }
      meta.truncated = items.length >= limit;
    }

    if (strategy === 'scan' || meta.truncated) {
      meta.usedFallback = strategy === 'search';
      let totalPages = 1;
      for (let page = 1; page <= totalPages; page++) {
        if (page > maxScanPages) { meta.complete = false; break; }
        const r = await this.client.callTool('memory_get_all', { conversation_id: traceConv, agent_id: agentId, datapack_id: this.datapackId, page, page_size: 100 });
        totalPages = r?.total_pages ?? 1;
        meta.scannedPages = page;
        for (const row of r?.memories ?? []) {
          const m = accept(row.id, pickText(row), { writerAgentId: row.agent_id });
          if (m) found.set(m.id, m);
        }
      }
    }
    return { memories: [...found.values()], meta };
  }

  async searchScope({ agentId, scopeId, accountId, limit, strategy }) {
    return (await this.retrieveScope({ agentId, scopeId: scopeId ?? accountId, limit, strategy })).memories;
  }

  /** Backwards-compatible alias. */
  searchAccount({ agentId, accountId, limit }) {
    return this.searchScope({ agentId, scopeId: accountId, limit });
  }

  async remove(memoryId, agentId) {
    return this.client.callTool('memory_delete_by_id', {
      memory_id: memoryId,
      conversation_id: await this.conversationFor(agentId),
      agent_id: agentId,
      datapack_id: this.datapackId,
    });
  }
}

