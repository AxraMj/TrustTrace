// Shared harness for offline HTTP tests: an in-memory TEST DOUBLE of the user/session store (the real PostgreSQL store is covered
// in test/db/*), plus a booted real http.Server. The data layer (deps.data) is supplied by each test.
import { randomUUID } from 'node:crypto';
import { createApiServer, listen } from '../../src/api/server.js';
import { loadAppConfig } from '../../src/api/config.js';
import { hashPassword } from '../../src/api/auth.js';
import { makeClock } from './trust.js';

export const PW = 'a perfectly reasonable passphrase 1!';

export function memoryUsers(clock) {
  const users = new Map(); const sessions = new Map(); const access = [];
  return {
    _users: users, _sessions: sessions, _access: access,
    async findUserByUsername(name) { return users.get(String(name).toLowerCase()) ?? null; },
    async setLastLogin() {},
    async createSession({ userId, tokenHash, expiresAt }) { const s = { id: randomUUID(), userId, createdAt: new Date(clock.now), lastSeenAt: new Date(clock.now), expiresAt }; sessions.set(tokenHash, s); return s; },
    async getSessionByTokenHash(h) {
      const s = sessions.get(h); if (!s) return null;
      const u = [...users.values()].find((x) => x.id === s.userId && x.active);
      return u ? { session: { id: s.id, createdAt: s.createdAt, lastSeenAt: s.lastSeenAt, expiresAt: s.expiresAt }, user: { id: u.id, username: u.username, role: u.role } } : null;
    },
    async touchSession(id) { for (const s of sessions.values()) if (s.id === id) s.lastSeenAt = new Date(clock.now); },
    async deleteSessionByTokenHash(h) { sessions.delete(h); },
    async recordAccess(e) { access.push(e); },
  };
}

let hash;
/** Boot a server with users alice(admin), sam(supervisor), bob(analyst). */
export async function bootApi({ data = {}, env = {}, deps = {} } = {}) {
  hash ??= await hashPassword(PW);
  const clock = makeClock(Date.UTC(2026, 5, 15, 12, 0, 0));
  const users = memoryUsers(clock);
  for (const [name, role] of [['alice', 'admin'], ['sam', 'supervisor'], ['bob', 'analyst']]) users._users.set(name, { id: randomUUID(), username: name, password_hash: hash, role, active: true });
  const config = loadAppConfig({ DATABASE_URL: 'postgres://u:p@localhost:5432/x', ...env });
  const server = createApiServer({
    deps: { users, data, ping: async () => ({ ok: true }), health: async () => ({ status: 'ok' }), audit: { verify: async () => ({ ok: true, checked: 0, head: null, problems: [] }) }, ...deps },
    config, clock: clock.fn, logger: () => {},
  });
  const addr = await listen(server, { host: '127.0.0.1', port: 0 });
  return { base: `http://127.0.0.1:${addr.port}`, server, users, clock, close: () => new Promise((r) => { if (!server.listening) return r(); server.closeAllConnections?.(); server.close(() => r()); }) };
}
