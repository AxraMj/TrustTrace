import { ApiError } from './http.js';

export const SEVERITIES = Object.freeze(['low', 'medium', 'high', 'critical']);
export const ACTIONS = Object.freeze(['allow', 'step_up', 'block']);
export const FLAGS = Object.freeze(['rejected_evidence', 'degraded', 'incomplete_context', 'policy_raised']);
export const ATTESTATION_STATUSES = Object.freeze(['valid', 'spent', 'expired']);
export const AUDIT_TYPES = Object.freeze(['decision', 'attestation_issued', 'attestation_consumed']);
export const WINDOWS = Object.freeze({ '15m': 15 * 60e3, '1h': 3600e3, '6h': 6 * 3600e3, '24h': 24 * 3600e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3, '90d': 90 * 86400e3, all: null });
export const BUCKETS = Object.freeze(['hour', 'day']);

const bad = (message) => new ApiError(400, 'invalid_parameter', message);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONTROL_RE = /[\u0000-\u001f\u007f]/;
const MAX_SPAN_MS = 400 * 86400e3;

export const isUuid = (s) => UUID_RE.test(String(s));

/** Unknown query parameters are rejected: a typo like "?severty=high" must not silently return unfiltered data. */
export function allowParams(url, allowed) {
  for (const k of url.searchParams.keys()) if (!allowed.includes(k)) throw bad(`unknown query parameter "${k}"`);
  for (const k of allowed) if (url.searchParams.getAll(k).length > 1) throw bad(`query parameter "${k}" may only appear once`);
}

export function parseEnumList(url, name, allowed, { max = 10 } = {}) {
  const raw = url.searchParams.get(name);
  if (raw === null || raw === '') return undefined;
  const parts = [...new Set(raw.split(',').map((s) => s.trim()).filter(Boolean))];
  if (!parts.length || parts.length > max) throw bad(`${name} must list 1-${max} values`);
  for (const p of parts) if (!allowed.includes(p)) throw bad(`${name}: "${String(p).slice(0, 40)}" is not one of ${allowed.join(', ')}`);
  return parts;
}

export function parseEnum(url, name, allowed, fallback) {
  const raw = url.searchParams.get(name);
  if (raw === null || raw === '') return fallback;
  if (!allowed.includes(raw)) throw bad(`${name} must be one of ${allowed.join(', ')}`);
  return raw;
}

export function parseLimit(url, { def = 50, max = 200 } = {}) {
  const raw = url.searchParams.get('limit');
  if (raw === null || raw === '') return def;
  if (!/^\d{1,4}$/.test(raw)) throw bad('limit must be a positive integer');
  const n = Number(raw);
  if (n < 1) throw bad('limit must be at least 1');
  return Math.min(n, max);
}

export function parseInteger(url, name, { min = 0, max = Number.MAX_SAFE_INTEGER, def } = {}) {
  const raw = url.searchParams.get(name);
  if (raw === null || raw === '') return def;
  if (!/^\d{1,15}$/.test(raw)) throw bad(`${name} must be a non-negative integer`);
  const n = Number(raw);
  if (n < min || n > max) throw bad(`${name} must be between ${min} and ${max}`);
  return n;
}

/** A short, printable identifier (account id, case id, agent id, ...). */
export function parseId(url, name, { max = 200 } = {}) {
  const raw = url.searchParams.get(name);
  if (raw === null || raw === '') return undefined;
  return validateId(raw, name, max);
}
export function validateId(raw, name, max = 200) {
  if (typeof raw !== 'string' || !raw.length || raw.length > max || CONTROL_RE.test(raw)) throw bad(`${name} is not a valid identifier`);
  return raw;
}

export function parseBool(url, name) {
  const raw = url.searchParams.get(name);
  if (raw === null || raw === '') return undefined;
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  throw bad(`${name} must be true or false`);
}

/** Free-text search: at most 100 printable chars, returned as an ILIKE pattern with LIKE metacharacters escaped. */
export function parseSearch(url, name = 'q') {
  const raw = url.searchParams.get(name);
  if (raw === null || raw === '') return undefined;
  if (raw.length > 100 || CONTROL_RE.test(raw)) throw bad(`${name} must be at most 100 printable characters`);
  return `%${raw.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
}

const isoDate = (raw, name) => {
  const d = new Date(raw);
  if (!/^\d{4}-\d{2}-\d{2}/.test(raw) || Number.isNaN(d.getTime())) throw bad(`${name} must be an ISO-8601 date-time`);
  return d;
};

/**
 * Time range: either window=15m|1h|6h|24h|7d|30d|90d|all, or from/to (ISO-8601). `from` may be null (= everything up to `to`).
 * `now` is injected so behaviour is deterministic in tests.
 */
export function parseRange(url, { defaultWindow = '24h', now = Date.now() } = {}) {
  const win = url.searchParams.get('window');
  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');
  if (win && (from || to)) throw bad('use either window or from/to, not both');
  if (win) {
    if (!(win in WINDOWS)) throw bad(`window must be one of ${Object.keys(WINDOWS).join(', ')}`);
    return { from: WINDOWS[win] === null ? null : new Date(now - WINDOWS[win]), to: new Date(now), window: win };
  }
  if (from || to) {
    const t = to ? isoDate(to, 'to') : new Date(now);
    const f = from ? isoDate(from, 'from') : null;
    if (f && f >= t) throw bad('from must be before to');
    if (f && t - f > MAX_SPAN_MS) throw bad('the requested range is longer than 400 days');
    return { from: f, to: t, window: null };
  }
  return { from: WINDOWS[defaultWindow] === null ? null : new Date(now - WINDOWS[defaultWindow]), to: new Date(now), window: defaultWindow };
}

/** Opaque keyset cursor. Shape is validated on the way back in, so a forged cursor is a 400, never SQL. */
export const encodeCursor = (obj) => Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
export function decodeCursor(raw, validate) {
  if (raw === null || raw === undefined || raw === '') return undefined;
  try {
    if (raw.length > 400) throw new Error('too long');
    const obj = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
    if (!obj || typeof obj !== 'object' || !validate(obj)) throw new Error('shape');
    return obj;
  } catch {
    throw bad('cursor is not valid');
  }
}
const iso = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(s) && !Number.isNaN(Date.parse(s));
export const cursorShapes = {
  decision: (o) => iso(o.t) && isUuid(o.id),
  activity: (o) => iso(o.t) && Number.isSafeInteger(o.id) && o.id > 0,
  case: (o) => iso(o.t) && typeof o.a === 'string' && o.a.length <= 200 && typeof o.c === 'string' && o.c.length <= 200,
  attestation: (o) => iso(o.t) && typeof o.n === 'string' && o.n.length <= 100,
};
