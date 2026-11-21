// Users, sessions and the access log. Plain SQL, parameterised everywhere.
export class DuplicateUserError extends Error {}

export async function createUser(pool, { username, passwordHash, role }) {
  try {
    const { rows } = await pool.query(
      'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role, active, created_at',
      [username, passwordHash, role]);
    return rows[0];
  } catch (err) {
    if (err.code === '23505') throw new DuplicateUserError(`user "${username}" already exists`);
    throw err;
  }
}

export async function findUserByUsername(pool, username) {
  const { rows } = await pool.query('SELECT id, username, password_hash, role, active FROM users WHERE lower(username) = lower($1)', [username]);
  return rows[0] ?? null;
}

export async function setLastLogin(pool, userId) {
  await pool.query('UPDATE users SET last_login_at = now() WHERE id = $1', [userId]);
}

export async function createSession(pool, { userId, tokenHash, expiresAt, ip, userAgent }) {
  const { rows } = await pool.query(
    'INSERT INTO sessions (user_id, token_hash, expires_at, ip, user_agent) VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at, expires_at',
    [userId, tokenHash, expiresAt, ip ?? null, (userAgent ?? '').slice(0, 300) || null]);
  return rows[0];
}

/** Session + user for a token hash. Inactive users never get a session back. Expiry/idle checks are the caller's (they need the clock). */
export async function getSessionByTokenHash(pool, tokenHash) {
  const { rows } = await pool.query(
    `SELECT s.id AS session_id, s.created_at, s.last_seen_at, s.expires_at, u.id AS user_id, u.username, u.role
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND u.active`, [tokenHash]);
  const r = rows[0];
  return r ? { session: { id: r.session_id, createdAt: r.created_at, lastSeenAt: r.last_seen_at, expiresAt: r.expires_at }, user: { id: r.user_id, username: r.username, role: r.role } } : null;
}

export async function touchSession(pool, sessionId) {
  await pool.query('UPDATE sessions SET last_seen_at = now() WHERE id = $1', [sessionId]);
}
export async function deleteSessionByTokenHash(pool, tokenHash) {
  await pool.query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash]);
}
export async function deleteExpiredSessions(pool, now = new Date()) {
  const { rowCount } = await pool.query('DELETE FROM sessions WHERE expires_at < $1', [now]);
  return rowCount;
}

export async function recordAccess(pool, e) {
  await pool.query(
    'INSERT INTO access_log (user_id, username, method, path, status, duration_ms, ip, request_id, detail) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)',
    [e.userId ?? null, e.username ?? null, e.method, String(e.path).slice(0, 500), e.status, e.durationMs ?? null, e.ip ?? null, e.requestId ?? null, e.detail ? JSON.stringify(e.detail) : null]);
}

/** The repository bound to a pool: what the HTTP layer depends on (tests can substitute an in-memory double). */
export function createUserStore(pool) {
  return {
    createUser: (u) => createUser(pool, u),
    findUserByUsername: (n) => findUserByUsername(pool, n),
    setLastLogin: (id) => setLastLogin(pool, id),
    createSession: (s) => createSession(pool, s),
    getSessionByTokenHash: (h) => getSessionByTokenHash(pool, h),
    touchSession: (id) => touchSession(pool, id),
    deleteSessionByTokenHash: (h) => deleteSessionByTokenHash(pool, h),
    deleteExpiredSessions: (now) => deleteExpiredSessions(pool, now),
    recordAccess: (e) => recordAccess(pool, e),
  };
}
