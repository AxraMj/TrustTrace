import { createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);
const N = 2 ** 15;
const R = 8;
const P = 1;
const KEYLEN = 64;
const MAXMEM = 128 * N * R * 2; // scrypt needs ~128*N*r bytes; allow headroom

export const SESSION_COOKIE = 'tt_session';

/** scrypt$N$r$p$salt$hash (base64). The password itself is never stored or logged. */
export async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scryptAsync(password, salt, KEYLEN, { N, r: R, p: P, maxmem: MAXMEM });
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64')}$${derived.toString('base64')}`;
}

/** Constant-time verification. Malformed hashes simply fail (never throw). */
export async function verifyPassword(password, stored) {
  try {
    const [scheme, n, r, p, saltB64, hashB64] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    if (!salt.length || !expected.length) return false;
    const params = { N: Number(n), r: Number(r), p: Number(p), maxmem: MAXMEM };
    if (!Number.isInteger(params.N) || params.N < 2 ** 14 || params.N > 2 ** 20) return false; // refuse downgraded or absurd costs
    const actual = await scryptAsync(String(password), salt, expected.length, params);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

let dummy;
/** Verify against a throw-away hash so "unknown user" costs the same as "wrong password" (no user enumeration by timing). */
export async function burnPasswordCheck(password) {
  dummy ??= await hashPassword('timing-equaliser-not-a-real-password');
  await verifyPassword(password, dummy);
}

export function validatePassword(pw) {
  if (typeof pw !== 'string') throw new Error('password must be a string');
  if (pw.length < 12) throw new Error('password must be at least 12 characters');
  if (pw.length > 256) throw new Error('password must be at most 256 characters');
  if (new Set(pw).size < 5) throw new Error('password is too repetitive');
}

export const newSessionToken = () => randomBytes(32).toString('base64url');
/** Only this hash is stored in the database. */
export const hashToken = (token) => createHash('sha256').update(String(token)).digest('hex');

export function parseCookies(header) {
  const out = {};
  for (const part of String(header ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (!(k in out)) out[k] = decodeURIComponent(v);
  }
  return out;
}

export function sessionCookie(token, { maxAgeSec, secure }) {
  return [`${SESSION_COOKIE}=${token}`, 'HttpOnly', 'SameSite=Strict', 'Path=/', `Max-Age=${maxAgeSec}`, ...(secure ? ['Secure'] : [])].join('; ');
}
export const clearedCookie = ({ secure }) =>
  [`${SESSION_COOKIE}=`, 'HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=0', 'Expires=Thu, 01 Jan 1970 00:00:00 GMT', ...(secure ? ['Secure'] : [])].join('; ');

/** In-memory failure limiter (per process): blocks a key after `max` failures inside `windowMs`. See docs/database.md for limits. */
export class FailureLimiter {
  #hits = new Map();
  constructor({ max, windowMs, now = Date.now }) {
    this.max = max;
    this.windowMs = windowMs;
    this.now = now;
  }
  #live(key) {
    const cutoff = this.now() - this.windowMs;
    const arr = (this.#hits.get(key) ?? []).filter((t) => t > cutoff);
    if (arr.length) this.#hits.set(key, arr); else this.#hits.delete(key);
    return arr;
  }
  /** { allowed, retryAfterSec } */
  check(key) {
    const arr = this.#live(key);
    if (arr.length < this.max) return { allowed: true, retryAfterSec: 0 };
    return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((arr[0] + this.windowMs - this.now()) / 1000)) };
  }
  fail(key) {
    const arr = this.#live(key);
    arr.push(this.now());
    this.#hits.set(key, arr);
    if (this.#hits.size > 10_000) this.#hits.delete(this.#hits.keys().next().value); // bound memory
  }
  reset(key) {
    this.#hits.delete(key);
  }
}

/** Fixed-window request counter per key (generic API rate limit). */
export class RateLimiter {
  #w = new Map();
  constructor({ max, windowMs, now = Date.now }) {
    this.max = max;
    this.windowMs = windowMs;
    this.now = now;
  }
  hit(key) {
    const t = this.now();
    let w = this.#w.get(key);
    if (!w || t - w.start >= this.windowMs) { w = { start: t, n: 0 }; this.#w.set(key, w); }
    w.n++;
    if (this.#w.size > 10_000) this.#w.delete(this.#w.keys().next().value);
    return w.n <= this.max ? { allowed: true, retryAfterSec: 0 } : { allowed: false, retryAfterSec: Math.max(1, Math.ceil((w.start + this.windowMs - t) / 1000)) };
  }
}
