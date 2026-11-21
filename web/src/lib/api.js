// The ONLY place the app talks to the network. v1 is read-only: every call is a GET except sign-in/sign-out of the session itself.
// There is deliberately no generic "post/put/delete" helper (a test enforces this), and no key, token or secret in the browser:
// authentication is an HttpOnly cookie the page JavaScript cannot read.

export class ApiError extends Error {
  constructor(status, code, message, requestId) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId ?? null;
  }
}

export const UNAUTHENTICATED_EVENT = 'trusttrace:unauthenticated';

async function parse(res) {
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON error page */ }
  if (!res.ok) {
    const e = json?.error;
    const err = new ApiError(res.status, e?.code ?? 'http_error', e?.message ?? `Request failed (${res.status})`, e?.requestId ?? res.headers.get('x-request-id'));
    if (res.status === 401 && err.code !== 'invalid_credentials') globalThis.dispatchEvent?.(new Event(UNAUTHENTICATED_EVENT));
    throw err;
  }
  return json;
}

/** GET a JSON resource. `params` (object) are added as a query string; undefined/null/'' and empty arrays are skipped. */
export async function getJson(path, { params, signal } = {}) {
  let url = path;
  if (params) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null || v === '' || (Array.isArray(v) && v.length === 0)) continue;
      qs.set(k, Array.isArray(v) ? v.join(',') : String(v));
    }
    const s = qs.toString();
    if (s) url += (path.includes('?') ? '&' : '?') + s;
  }
  let res;
  try { res = await fetch(url, { method: 'GET', headers: { accept: 'application/json' }, credentials: 'same-origin', signal }); }
  catch (e) {
    if (e?.name === 'AbortError') throw e;
    throw new ApiError(0, 'network_error', 'Cannot reach the TrustTrace API. Is the server running?');
  }
  return parse(res);
}

export const login = (username, password) => sendSession('/api/auth/login', { username, password });
export const logout = () => sendSession('/api/auth/logout', {});

async function sendSession(path, body) {
  let res;
  try { res = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, credentials: 'same-origin', body: JSON.stringify(body) }); }
  catch { throw new ApiError(0, 'network_error', 'Cannot reach the TrustTrace API. Is the server running?'); }
  return parse(res);
}

/** Path segments for case URLs: ids are opaque and may contain "/", spaces, "#" or "?". */
export const casePath = (accountId, caseId, sub = '') => `/api/cases/${encodeURIComponent(accountId)}/${encodeURIComponent(caseId)}${sub}`;
