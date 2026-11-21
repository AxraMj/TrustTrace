import { createHash } from 'node:crypto';

/**
 * Canonical JSON: object keys sorted recursively, undefined/functions dropped (null kept), Dates as ISO strings,
 * -0 as 0, NaN/Infinity rejected. The same logical value always yields the same string, so it can be hashed.
 */
export function canonicalJson(value) {
  return JSON.stringify(normalise(value));
}

function normalise(v) {
  if (v === null) return null;
  if (v instanceof Date) {
    if (Number.isNaN(v.getTime())) throw new TypeError('canonicalJson: invalid Date');
    return v.toISOString();
  }
  switch (typeof v) {
    case 'string':
    case 'boolean':
      return v;
    case 'number':
      if (!Number.isFinite(v)) throw new TypeError('canonicalJson: non-finite number');
      return Object.is(v, -0) ? 0 : v;
    case 'bigint':
      return v.toString();
    case 'object': {
      if (Array.isArray(v)) return v.map((x) => { const n = normalise(x); return n === undefined ? null : n; });
      const out = {};
      for (const k of Object.keys(v).sort()) {
        const n = normalise(v[k]);
        if (n !== undefined) out[k] = n;
      }
      return out;
    }
    default:
      return undefined; // undefined, function, symbol
  }
}

export const sha256Hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
export const hashOf = (value) => sha256Hex(canonicalJson(value));
