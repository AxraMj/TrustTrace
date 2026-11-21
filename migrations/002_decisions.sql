-- 002_decisions: authoritative decision log, case index, agent activity, attestation nonces (replay protection).

-- One row per security decision made by Agent B. Everything the dashboard needs to explain the decision is stored here,
-- including which memories were retrieved and which verification records were rejected and why.
CREATE TABLE decisions (
  id                 uuid PRIMARY KEY,
  created_at         timestamptz      NOT NULL,
  event_id           text             NOT NULL,
  event_type         text             NOT NULL,
  account_id         text             NOT NULL,
  case_id            text,
  org_id             text,
  event              jsonb            NOT NULL,           -- the event Agent B evaluated
  raw_score          double precision NOT NULL,           -- unclamped; severity and base action come from this
  display_score      double precision NOT NULL,           -- 0-100 UI curve only
  severity           text             NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  base_action        text             NOT NULL CHECK (base_action IN ('allow', 'step_up', 'block')),
  recommended_action text             NOT NULL CHECK (recommended_action IN ('allow', 'step_up', 'block')),
  context_available  boolean          NOT NULL,
  retrieval_complete boolean          NOT NULL,
  degraded           boolean          NOT NULL,           -- true = Meko was unreachable, decided on the event alone
  error              jsonb,
  policy             jsonb            NOT NULL,
  step_up            jsonb            NOT NULL,
  advisories         jsonb            NOT NULL,
  contributions      jsonb            NOT NULL,
  explanation        jsonb            NOT NULL,
  rejected_evidence  jsonb            NOT NULL,
  verified_facts     jsonb            NOT NULL,
  unverified_claims  jsonb            NOT NULL,
  retrieved          jsonb            NOT NULL,           -- [{id,label,kind,scope}] memories Agent B read from Meko
  retrieval_meta     jsonb            NOT NULL,
  timings            jsonb            NOT NULL,
  model_version      text             NOT NULL,
  extractor_version  text             NOT NULL,
  policy_version     text             NOT NULL,
  verifier_key_id    text,
  agent_id           text             NOT NULL
);
CREATE INDEX decisions_created_idx  ON decisions (created_at DESC);
CREATE INDEX decisions_severity_idx ON decisions (severity, created_at DESC);
CREATE INDEX decisions_action_idx   ON decisions (recommended_action, created_at DESC);
CREATE INDEX decisions_account_idx  ON decisions (account_id, created_at DESC);
CREATE INDEX decisions_case_idx     ON decisions (case_id, created_at DESC) WHERE case_id IS NOT NULL;
CREATE INDEX decisions_event_idx    ON decisions (event_id);

-- Case index: derived from decisions, maintained in the same transaction.
CREATE TABLE cases (
  account_id     text        NOT NULL,
  case_id        text        NOT NULL,
  first_seen     timestamptz NOT NULL,
  last_seen      timestamptz NOT NULL,
  decision_count integer     NOT NULL DEFAULT 0,
  max_severity   text        NOT NULL CHECK (max_severity IN ('low', 'medium', 'high', 'critical')),
  PRIMARY KEY (account_id, case_id)
);
CREATE INDEX cases_last_seen_idx ON cases (last_seen DESC);

-- What each agent did: memories written/read/deleted, attestations issued, decisions made, errors.
CREATE TABLE agent_events (
  id          bigserial PRIMARY KEY,
  at          timestamptz      NOT NULL,
  agent_id    text             NOT NULL,
  kind        text             NOT NULL,
  account_id  text,
  case_id     text,
  event_id    text,
  decision_id uuid,
  memory_ids  text[]           NOT NULL DEFAULT '{}',
  payload     jsonb            NOT NULL DEFAULT '{}',
  duration_ms double precision,
  ok          boolean          NOT NULL DEFAULT true,
  error       text
);
CREATE INDEX agent_events_at_idx       ON agent_events (at DESC);
CREATE INDEX agent_events_agent_idx    ON agent_events (agent_id, at DESC);
CREATE INDEX agent_events_case_idx     ON agent_events (case_id, at DESC) WHERE case_id IS NOT NULL;
CREATE INDEX agent_events_decision_idx ON agent_events (decision_id) WHERE decision_id IS NOT NULL;

-- Verification attestation nonces: the authoritative replay ledger. A row is created when the verification authority issues
-- an attestation (source 'issued') or when an attestation unknown to this database is first consumed ('first_seen').
-- A single-use attestation can be consumed exactly ONCE: the consumption is a one-way, atomic UPDATE/INSERT.
CREATE TABLE attestation_nonces (
  nonce             text        PRIMARY KEY,
  source            text        NOT NULL CHECK (source IN ('issued', 'first_seen')),
  kind              text        NOT NULL,
  account_id        text        NOT NULL,
  case_id           text        NOT NULL,
  issuer            text        NOT NULL,
  kid               text        NOT NULL,
  method            text,
  statement_sha256  text,
  issued_at         timestamptz NOT NULL,
  expires_at        timestamptz NOT NULL,
  recorded_at       timestamptz NOT NULL DEFAULT now(),
  consumed_event_id text,
  consumed_at       timestamptz,
  decision_id       uuid,
  CHECK ((consumed_event_id IS NULL) = (consumed_at IS NULL))
);
CREATE INDEX attestation_nonces_account_idx ON attestation_nonces (account_id, case_id);
CREATE INDEX attestation_nonces_expires_idx ON attestation_nonces (expires_at);
