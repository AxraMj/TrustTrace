// Deriving the client IP behind a reverse proxy WITHOUT trusting values the client can forge.
//
// Why this exists: a proxy such as Render's edge APPENDS the address it saw to any X-Forwarded-For the client sent, so the LEFTMOST
// entries are attacker-controlled and only the entries to the RIGHT were added by infrastructure we trust. Reading the first entry
// (the old TRUST_PROXY=true behaviour) lets anyone pick their own "IP" and walk around the per-IP login limiter.
//
// TRUST_PROXY_HOPS=N says "the last N entries were appended by proxies I trust"; the client is the N-th entry counted from the RIGHT.
//   * N = 0 (default): the header is ignored completely; the socket address is used.
//   * chain shorter than N: more hops were configured than exist, so nothing in the header can be trusted -> socket address.
//   * under-counting N is always safe (you get a proxy-side address shared by many clients, never a forged one);
//     over-counting N is the dangerous mistake, so choose N from observation, not from hope.
// Only valid when the app is reachable ONLY through those proxies (otherwise a direct caller could write the whole header).
import { isIP } from 'node:net';

/** Strip an optional port / IPv6 brackets and the IPv4-mapped prefix; return null unless the result is a literal IP address. */
export function normalizeIp(value) {
  let v = String(value ?? '').trim();
  if (!v) return null;
  const bracket = /^\[([^\]]+)\](?::\d+)?$/.exec(v);
  if (bracket) v = bracket[1];
  else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(v)) v = v.slice(0, v.lastIndexOf(':'));
  v = v.replace(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i, '$1');
  return isIP(v) ? v.toLowerCase() : null;
}

/**
 * @param {{xff?: string, remoteAddress?: string, hops?: number, legacyTrustFirst?: boolean}} p
 * @returns {string}
 */
export function clientIpFrom({ xff, remoteAddress, hops = 0, legacyTrustFirst = false }) {
  const socketIp = remoteAddress ?? 'unknown';
  if (hops > 0) {
    const parts = String(xff ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length < hops) return socketIp;
    return normalizeIp(parts[parts.length - hops]) ?? socketIp;
  }
  if (legacyTrustFirst) { // old behaviour, kept for compatibility; NOT safe behind proxies that append (see above)
    const first = String(xff ?? '').split(',')[0].trim();
    if (first) return first;
  }
  return socketIp;
}
