import { randomUUID } from 'node:crypto';

/** An error the client may see: status + stable code + safe message. Anything else becomes a generic 500. */
export class ApiError extends Error {
  constructor(status, code, message, { headers } = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

export const SECURITY_HEADERS = Object.freeze({
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Resource-Policy': 'same-origin',
});

export function sendJson(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Length': Buffer.byteLength(payload), ...extraHeaders });
  res.end(payload);
}

export const newRequestId = () => randomUUID();

/** Read a JSON body with a hard size cap. Rejects non-JSON content types (415), oversized (413) and malformed JSON (400). */
export async function readJsonBody(req, maxBytes) {
  const type = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  const declared = Number(req.headers['content-length'] ?? 0);
  if (declared > maxBytes) throw new ApiError(413, 'payload_too_large', 'request body is too large');
  if (type !== 'application/json') throw new ApiError(415, 'unsupported_media_type', 'Content-Type must be application/json');
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new ApiError(413, 'payload_too_large', 'request body is too large');
    chunks.push(chunk);
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8') || 'null');
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
    return parsed;
  } catch {
    throw new ApiError(400, 'invalid_json', 'request body must be a JSON object');
  }
}

/** Tiny router: exact segments plus :params. */
export class Router {
  #routes = [];
  add(method, pattern, options, handler) {
    const segs = pattern.split('/').filter(Boolean);
    this.#routes.push({ method, segs, options, handler });
    return this;
  }
  /** @returns {{route?:object, params?:object, methodNotAllowed?:string[]}} */
  match(method, pathname) {
    const parts = pathname.split('/').filter(Boolean);
    const allowed = new Set();
    for (const r of this.#routes) {
      if (r.segs.length !== parts.length) continue;
      const params = {};
      let ok = true;
      for (let i = 0; i < parts.length && ok; i++) {
        if (r.segs[i].startsWith(':')) {
          try { params[r.segs[i].slice(1)] = decodeURIComponent(parts[i]); } catch { ok = false; }
        } else ok = r.segs[i] === parts[i];
      }
      if (!ok) continue;
      if (r.method === method) return { route: r, params };
      allowed.add(r.method);
    }
    return allowed.size ? { methodNotAllowed: [...allowed] } : {};
  }
}
