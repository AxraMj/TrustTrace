# Retrieval and pagination: what is actually implemented

Phase 3 said both "the fallback is paginated" and "Meko search has no pagination". Both are true, because they are
**two different Meko tools**. This page records what was verified live (2026-11, `test/pagination.integration.test.js`)
and what that means for the code in `src/meko/memory.js` (`MemoryStore.retrieveScope`).

## Verified facts about the Meko tools

| Tool | Pagination? | Verified behaviour |
|---|---|---|
| `memory_search` | **No.** Parameters: `query, conversation_id, agent_id, limit, datapack_id, run_id`. No offset/page/cursor. | `limit` (documented default 10) was accepted at 1000, 5000 and **100000** with no cap observed. With 230 matching memories: `limit 200` -> 200 results, `limit 1000/5000/100000` -> 230. `run_id` is an **exact** server-side filter on the memory's conversation tag. Results are also cut by an undocumented **relevance cutoff** (unrelated free text was never returned, even far below `limit`; the boundary varied between runs). |
| `memory_get_all` | **Yes.** `page`, `page_size`, response has `total`, `total_pages`. | Asked for `page_size 500`, server used **100**. 230 memories -> `total_pages 3`; pages disjoint, newest first, union = everything. Page latency ~0.3-0.4 s (one outlier 2.3 s). It lists **every memory of the user in the datapack** (any agent, any conversation, any app). Its `run_id` parameter is **accepted but ignored**: a call with a bogus `run_id` returned the same rows as one with none, and a memory from another bucket was still returned. |

## How `retrieveScope` uses them
1. **Scoped search (normal path).** `memory_search` with `run_id = <the scope's bucket conversation>` and `limit = 1000`.
   Each scope (account id or org id) lives under one of 32 shared "bucket" conversations (`sha256(scope) mod 32`), so unrelated
   accounts in the other 31 buckets cannot crowd the results. The bucket is shared by roughly 1/32 of all scopes, so the results are
   post-filtered by the **exact** scope in the memory header (look-alike ids, prefixes and other accounts are discarded).
2. **Truncation detection.** If the search returns exactly `limit` rows it may have been cut off, because search cannot be
   paged. (`limit 1000` is our choice, not a Meko cap; the earlier 200 was too.)
3. **Paginated fallback (`memory_get_all`).** On truncation (or when `strategy: 'scan'`) we page through `memory_get_all`
   (`page_size 100`) and keep rows whose header scope matches exactly. Cost is **O(all memories in the datapack)**: there is no
   server-side way to narrow it (`run_id` is ignored).
4. **Honest completeness.** The scan stops after `maxScanPages` (30 pages = 3000 memories). If more pages exist the result carries
   `meta.complete = false`; Agent B then requires step-up for sensitive actions instead of trusting an empty/partial context.

## Limitations (all still open)
* **The relevance cutoff means "fewer results than `limit`" does not prove the search was complete.** Our memories share a header
  prefix and the query contains the scope id, which has matched every time in tests (1,000s of memories, several runs), but
  completeness is **not guaranteed** by Meko. Only a full scan proves completeness.
* **The scan is O(datapack)** and shares the Meko free-tier retrieval quota; above ~3000 memories in the datapack it can never be
  complete with the current cap.
* **Wrong-bucket writes are invisible to the scoped search** (only a scan finds them). All writers in this repo use the store, so
  they are placed correctly; an outside writer using another conversation would be missed on the fast path.
* **No atomicity:** memories written while a scan is paging can be missed or duplicated across pages (duplicates are de-duplicated
  by id).
* **Each Meko round trip is ~0.5-1 s** (search p50 ~0.7 s, add p50 ~0.5 s measured), which dominates agent latency.
* **Conversation containers cannot be deleted verifiably**, so the 32 bucket conversations, one conversation per agent and a setup
  conversation are reused forever (bounded: ~40 containers).
* `run_id` ignoring on `memory_get_all` is monitored by test `PG6b`: if Meko starts honouring it, the scan can be scoped
  server-side and this document and `memory.js` should be updated.
