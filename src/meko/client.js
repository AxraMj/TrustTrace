import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { MekoAuthError, MekoConnectionError, MekoToolError } from '../errors.js';

// Meko rejects requests without a Bearer Authorization header AND a User-Agent header.
// Source: https://docs.mekodata.ai/use-meko/connect/ ("Send the key as a Bearer token")
const USER_AGENT = 'meko-mcp-installer/1.0';

const AUTH_STATUS = new Set([401, 403]);

function looksLikeAuthFailure(text) {
  return /unauthori[sz]ed|forbidden|invalid (api )?(key|token)|no meko account/i.test(text);
}

/** Pull a usable payload out of an MCP tool result (JSON text, or raw text). */
function tryParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

export function extractPayload(result) {
  let payload = result?.structuredContent;
  if (payload === undefined) {
    const text = (result?.content ?? [])
      .filter((c) => c.type === 'text')
      .map((c) => c.text)
      .join('\n');
    payload = tryParse(text) ?? { text };
  }
  // Live Meko wraps tool output as {"result": "<JSON string>"}; unwrap it so error and data
  // payloads look the same however the server delivers them.
  if (payload && typeof payload === 'object' && typeof payload.result === 'string' && Object.keys(payload).length === 1) {
    const inner = tryParse(payload.result);
    if (inner !== undefined) return inner;
  }
  return payload;
}

/** Summarise recorded call latencies per tool: { tool: {n, minMs, p50Ms, p95Ms, maxMs, meanMs} }. */
export function latencyStats(metrics) {
  const byTool = new Map();
  for (const m of metrics) {
    if (!byTool.has(m.tool)) byTool.set(m.tool, []);
    byTool.get(m.tool).push(m.ms);
  }
  const pct = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
  const r1 = (x) => Math.round(x * 10) / 10;
  const out = {};
  for (const [tool, arr] of byTool) {
    const s = [...arr].sort((a, b) => a - b);
    out[tool] = {
      n: s.length,
      minMs: r1(s[0]),
      p50Ms: r1(pct(s, 50)),
      p95Ms: r1(pct(s, 95)),
      maxMs: r1(s[s.length - 1]),
      meanMs: r1(s.reduce((a, b) => a + b, 0) / s.length),
    };
  }
  return out;
}

export class MekoClient {
  /**
   * @param {{apiKey:string, mcpUrl:string}} config
   * @param {{sdkClient?: object}} [deps] inject a fake SDK client for offline tests
   */
  constructor(config, deps = {}) {
    this.config = config;
    this.sdk = deps.sdkClient ?? null;
    this.connected = Boolean(deps.sdkClient);
    /** Wall-clock latency of every Meko tool call (network + server), in call order. */
    this.metrics = [];
  }

  async connect() {
    if (this.connected) return this;
    const transport = new StreamableHTTPClientTransport(new URL(this.config.mcpUrl), {
      requestInit: {
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
          'User-Agent': USER_AGENT,
        },
      },
    });
    const sdk = new Client({ name: 'trusttrace', version: '0.1.0' });
    try {
      await sdk.connect(transport);
    } catch (err) {
      throw this.#mapError(err, 'connect');
    }
    this.sdk = sdk;
    this.connected = true;
    return this;
  }

  async listTools() {
    this.#requireConnected();
    try {
      const { tools } = await this.sdk.listTools();
      return tools;
    } catch (err) {
      throw this.#mapError(err, 'listTools');
    }
  }

  /**
   * Call a Meko tool and return its parsed payload.
   * @throws {MekoAuthError|MekoConnectionError|MekoToolError}
   */
  async callTool(name, args = {}) {
    this.#requireConnected();
    let result;
    const t0 = performance.now();
    try {
      result = await this.sdk.callTool({ name, arguments: args });
    } catch (err) {
      this.metrics.push({ tool: name, ms: performance.now() - t0, ok: false });
      throw this.#mapError(err, name);
    }
    this.metrics.push({ tool: name, ms: performance.now() - t0, ok: !result?.isError });
    const payload = extractPayload(result);
    if (result?.isError) {
      const msg = payload?.text ?? payload?.error ?? JSON.stringify(payload);
      if (looksLikeAuthFailure(String(msg))) throw new MekoAuthError(`${name}: ${msg}`);
      throw new MekoToolError(`${name} failed: ${msg}`, { tool: name, payload });
    }
    // Meko documents error-shaped payloads (an `error` or error-like `detail`) on search tools.
    if (payload && typeof payload === 'object' && (payload.error || payload.detail)) {
      const msg = payload.error ?? payload.detail;
      if (looksLikeAuthFailure(String(msg))) throw new MekoAuthError(`${name}: ${msg}`);
      throw new MekoToolError(`${name} returned an error: ${typeof msg === 'string' ? msg : JSON.stringify(msg)}`, {
        tool: name,
        payload,
      });
    }
    return payload;
  }

  async close() {
    try {
      await this.sdk?.close?.();
    } finally {
      this.connected = false;
    }
  }

  #requireConnected() {
    if (!this.connected) throw new MekoConnectionError('MekoClient is not connected; call connect() first.');
  }

  #mapError(err, where) {
    const status = err?.code;
    const message = String(err?.message ?? err);
    if (AUTH_STATUS.has(status) || looksLikeAuthFailure(message)) {
      return new MekoAuthError(`Meko rejected the credentials during ${where} (HTTP ${status ?? '?'}). Check MEKO_API_KEY.`, {
        cause: err,
      });
    }
    return new MekoConnectionError(`Could not talk to Meko during ${where}: ${message}`, { cause: err });
  }
}
