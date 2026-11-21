-- 001_core: authentication and access logging.
-- Every object is created in the CURRENT schema (search_path), so tests can run in a throw-away schema.

CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username      text        NOT NULL CHECK (length(username) BETWEEN 3 AND 64),
  password_hash text        NOT NULL,                       -- scrypt$N$r$p$salt$hash, never the password
  role          text        NOT NULL CHECK (role IN ('analyst', 'supervisor', 'admin')),
  active        boolean     NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);
CREATE UNIQUE INDEX users_username_lower_key ON users (lower(username));

-- Opaque server-side sessions. Only a SHA-256 of the token is stored, so a database leak does not leak live sessions.
CREATE TABLE sessions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  token_hash   text        NOT NULL UNIQUE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  ip           text,
  user_agent   text
);
CREATE INDEX sessions_user_idx    ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

-- Who looked at what (analyst data contains personal data): one row per API request, plus login attempts.
CREATE TABLE access_log (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  user_id     uuid,
  username    text,
  method      text        NOT NULL,
  path        text        NOT NULL,
  status      integer     NOT NULL,
  duration_ms double precision,
  ip          text,
  request_id  text,
  detail      jsonb
);
CREATE INDEX access_log_at_idx   ON access_log (at DESC);
CREATE INDEX access_log_user_idx ON access_log (user_id, at DESC);
