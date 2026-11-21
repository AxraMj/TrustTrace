/**
 * Records what the agents did (memories written/read/deleted, attestations issued, decisions made, errors) into agent_events.
 * Write-behind and batched so it never slows an agent down, but NOT silent: failures and drops are counted and exposed
 * (stats() -> /api/health/details). Decisions and the replay ledger are NOT written through this class: they are synchronous
 * and authoritative; activity events are a best-effort trail with explicit loss accounting.
 */
export class ActivityRecorder {
  constructor(pool, { maxBuffer = 10_000, flushDelayMs = 250, batchSize = 200 } = {}) {
    this.pool = pool;
    this.maxBuffer = maxBuffer;
    this.flushDelayMs = flushDelayMs;
    this.batchSize = batchSize;
    this.buffer = [];
    this.timer = null;
    this.flushing = null;
    this.counters = { recorded: 0, written: 0, dropped: 0, failedBatches: 0, lastError: null };
  }

  /** Queue one event (synchronous, never throws). */
  record(evt) {
    this.counters.recorded++;
    this.buffer.push({ at: evt.at ?? new Date(), ...evt });
    if (this.buffer.length > this.maxBuffer) {
      this.buffer.shift();
      this.counters.dropped++;
    }
    if (!this.timer) {
      this.timer = setTimeout(() => { this.timer = null; this.flush().catch(() => {}); }, this.flushDelayMs);
      this.timer.unref?.();
    }
  }

  /** Write everything queued so far. Safe to call concurrently. */
  async flush() {
    if (this.flushing) await this.flushing.catch(() => {});
    this.flushing = this.#drain();
    try { await this.flushing; } finally { this.flushing = null; }
  }

  async #drain() {
    while (this.buffer.length) {
      const batch = this.buffer.splice(0, this.batchSize);
      try {
        await this.#insert(batch);
        this.counters.written += batch.length;
      } catch (err) {
        this.counters.failedBatches++;
        this.counters.lastError = String(err.code ?? err.message).slice(0, 200);
        // keep the batch for one more attempt unless the buffer is full; otherwise it is counted as dropped
        const room = this.maxBuffer - this.buffer.length;
        const keep = batch.slice(0, Math.max(0, room));
        this.counters.dropped += batch.length - keep.length;
        this.buffer.unshift(...keep);
        throw err;
      }
    }
  }

  async #insert(batch) {
    const values = [];
    // a payload that cannot be serialised (circular, BigInt, ...) must not poison the whole batch on every retry
    const safeJson = (v) => { try { return JSON.stringify(v ?? {}); } catch { return JSON.stringify({ unserializable: true }); } };
    const tuples = batch.map((e, i) => {
      const o = i * 12;
      values.push(e.at, e.agentId, e.kind, e.accountId ?? null, e.caseId ?? null, e.eventId ?? null, e.decisionId ?? null,
        e.memoryIds ?? [], safeJson(e.payload), e.durationMs ?? null, e.ok ?? true, e.error ? String(e.error).slice(0, 500) : null);
      const p = (k) => `$${o + k}`;
      return `(${p(1)},${p(2)},${p(3)},${p(4)},${p(5)},${p(6)},${p(7)},${p(8)}::text[],${p(9)}::jsonb,${p(10)},${p(11)},${p(12)})`;
    });
    await this.pool.query(
      `INSERT INTO agent_events (at, agent_id, kind, account_id, case_id, event_id, decision_id, memory_ids, payload, duration_ms, ok, error)
       VALUES ${tuples.join(',')}`,
      values,
    );
  }

  stats() {
    return { ...this.counters, queued: this.buffer.length };
  }

  /** Flush and stop the timer (call on shutdown and at the end of tests). */
  async close() {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    await this.flush().catch(() => {});
  }
}
