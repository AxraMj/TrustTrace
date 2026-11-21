import { TrustTraceError } from '../errors.js';

export class AppConfigError extends TrustTraceError {}

const int = (v, d, { min = 1, max = Number.MAX_SAFE_INTEGER, name } = {}) => {
  if (v === undefined || v === '') return d;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new AppConfigError(`${name} must be an integer between ${min} and ${max}`);
  return n;
};
const bool = (v, d) => (v === undefined || v === '' ? d : ['1', 'true', 'yes'].includes(String(v).toLowerCase()));

/**
 * Configuration for the REST API + PostgreSQL. Read from the environment only; no secrets have defaults.
 * The Meko API key and the signing key are NEVER part of this object (the API server does not need them to serve reads);
 * `mekoConfigured` is just a boolean for the admin health view.
 * @throws {AppConfigError}
 */
export function loadAppConfig(env = process.env) {
  const databaseUrl = (env.DATABASE_URL ?? '').trim();
  if (!databaseUrl) {
    throw new AppConfigError(
      'DATABASE_URL is not set. TrustTrace stores decisions, activity and replay protection in PostgreSQL. ' +
        'Create a database and role (see docs/database.md), then put DATABASE_URL=postgres://USER:PASSWORD@localhost:5432/trusttrace in .env.',
    );
  }
  if (!/^postgres(?:ql)?:\/\//.test(databaseUrl)) throw new AppConfigError('DATABASE_URL must start with postgres:// or postgresql://');
  const production = env.NODE_ENV === 'production';
  const origins = (env.ALLOWED_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  for (const o of origins) if (!/^https?:\/\/[^/\s]+$/.test(o)) throw new AppConfigError(`ALLOWED_ORIGINS entry is not an origin: ${o}`);
  const trustProxy = bool(env.TRUST_PROXY, false);
  const trustProxyHops = int(env.TRUST_PROXY_HOPS, 0, { min: 0, max: 5, name: 'TRUST_PROXY_HOPS' });
  if (trustProxy && trustProxyHops > 0) {
    throw new AppConfigError('Set either TRUST_PROXY (legacy: trusts the client-controlled FIRST X-Forwarded-For entry) or TRUST_PROXY_HOPS, not both. Prefer TRUST_PROXY_HOPS.');
  }
  return Object.freeze({
    databaseUrl,
    databaseSsl: bool(env.DATABASE_SSL, false),
    dbPoolMax: int(env.DB_POOL_MAX, 10, { max: 100, name: 'DB_POOL_MAX' }),
    host: (env.API_HOST ?? '').trim() || '127.0.0.1', // loopback by default: expose it deliberately
    port: int(env.API_PORT || env.PORT, 8787, { max: 65535, name: 'API_PORT (or PORT)' }), // platforms such as Render inject PORT; API_PORT wins if both are set
    sessionTtlMinutes: int(env.SESSION_TTL_MINUTES, 480, { max: 60 * 24 * 14, name: 'SESSION_TTL_MINUTES' }),
    sessionIdleMinutes: int(env.SESSION_IDLE_MINUTES, 30, { max: 60 * 24, name: 'SESSION_IDLE_MINUTES' }),
    cookieSecure: bool(env.COOKIE_SECURE, production),
    allowedOrigins: Object.freeze(origins),
    trustProxy, // legacy and unsafe behind proxies that append to X-Forwarded-For; see src/api/clientIp.js
    trustProxyHops, // number of trusted proxies that APPENDED to X-Forwarded-For (0 = ignore the header)
    webDistDir: (env.WEB_DIST_DIR ?? '').trim() || null, // set to serve the built dashboard (web/dist) from this process; unset = API only
    maxBodyBytes: int(env.MAX_BODY_BYTES, 64 * 1024, { max: 1024 * 1024, name: 'MAX_BODY_BYTES' }),
    mekoConfigured: Boolean((env.MEKO_API_KEY ?? '').trim()),
  });
}
