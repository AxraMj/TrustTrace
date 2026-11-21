import { MekoToolError } from './errors.js';
import { createConversation } from './meko/memory.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const VERIFIER_AGENT_ID = 'trusttrace_verifier';
const DEFAULT_WRITER = 'trusttrace_helpdesk_agent';

/**
 * Delete memories by id (concurrently, in small batches). Meko requires the DELETING agent_id to match the
 * writer, so `writers` maps id -> writer agent id (ids not in the map fall back to the help-desk agent).
 * Returns { deleted, failed: [{id, error}] }.
 */
export async function deleteMemories(store, ids, writers = {}, { concurrency = 6 } = {}) {
  const asMap = typeof writers === 'string' ? Object.fromEntries(ids.map((i) => [i, writers])) : writers;
  let deleted = 0;
  const failed = [];
  const queue = [...ids];
  await Promise.all(
    Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
      while (queue.length) {
        const id = queue.shift();
        try {
          await store.remove(id, asMap[id] ?? DEFAULT_WRITER);
          deleted++;
        } catch (err) {
          failed.push({ id, error: `${err.name}: ${err.message}` });
        }
      }
    }),
  );
  return { deleted, failed };
}

async function isAbsent(store, id, conversationId) {
  try {
    await store.client.callTool('memory_get_by_id', { memory_id: id, conversation_id: conversationId, agent_id: VERIFIER_AGENT_ID, datapack_id: store.datapackId });
    return false; // still readable
  } catch (err) {
    if (err instanceof MekoToolError && err.payload?.error === 'not_found') return true;
    throw err; // any other failure is NOT proof of absence
  }
}

async function trusttraceMemoriesInDatapack(store, conversationId) {
  const found = [];
  for (let page = 1; page <= 100; page++) {
    const r = await store.client.callTool('memory_get_all', {
      conversation_id: conversationId, agent_id: VERIFIER_AGENT_ID, datapack_id: store.datapackId, page, page_size: 100,
    });
    for (const m of r.memories ?? []) if (String(m.data ?? '').startsWith('[TRUSTTRACE')) found.push(m.id);
    if (page >= (r.total_pages ?? 1)) break;
  }
  return found;
}

/**
 * Query Meko AFTER deletion and report what is still there.
 *  1. every deleted memory id: memory_get_by_id must return not_found
 *  2. the whole datapack: no memory whose text starts with [TRUSTTRACE may remain (memory_get_all)
 *  3. semantic search for each test scope returns nothing
 *  4. conversations: NOT deletable in a verifiable way (conversation_delete is accepted but conversation_get
 *     still returns the conversation), so we only check that every conversation we use is REUSED (session_id),
 *     i.e. a repeat run creates no new one.
 */
export async function verifyCleanup({ store, savedIds, scopeIds = [], timeoutMs = 60_000, pollMs = 3_000 }) {
  const t0 = performance.now();
  const convId = await store.conversationFor(VERIFIER_AGENT_ID);
  const deadline = Date.now() + timeoutMs;

  let stillReadable = [...savedIds];
  let leftoverInDatapack = [];
  let scopesWithResults = [];
  for (;;) {
    const next = [];
    for (const id of stillReadable) if (!(await isAbsent(store, id, convId))) next.push(id);
    stillReadable = next;
    leftoverInDatapack = await trusttraceMemoriesInDatapack(store, convId);
    scopesWithResults = [];
    for (const scopeId of scopeIds) {
      const hits = await store.searchScope({ agentId: VERIFIER_AGENT_ID, scopeId });
      if (hits.length) scopesWithResults.push({ scopeId, count: hits.length });
    }
    if ((!stillReadable.length && !leftoverInDatapack.length && !scopesWithResults.length) || Date.now() > deadline) break;
    await sleep(pollMs);
  }

  const conversations = {};
  for (const { key, spec, id } of await store.conversations()) {
    const again = await createConversation(store.client, { ...spec, datapackId: store.datapackId });
    conversations[key] = { id, reusedNotRecreated: id === again };
  }

  return {
    ok: !stillReadable.length && !leftoverInDatapack.length && !scopesWithResults.length && Object.values(conversations).every((c) => c.reusedNotRecreated),
    memoriesChecked: savedIds.length,
    memoriesConfirmedAbsent: savedIds.length - stillReadable.length,
    memoriesStillReadable: stillReadable,
    trusttraceMemoriesLeftInDatapack: leftoverInDatapack,
    scopesWithResults,
    conversations,
    conversationDeletionVerifiable: false,
    ms: Math.round(performance.now() - t0),
  };
}
