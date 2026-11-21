-- 003_audit: tamper-evident audit chain + append-only enforcement.

-- Hash chain: record_hash = SHA-256(canonical JSON of seq, record_type, ref_id, payload_hash, prev_hash, created_at).
-- payload_hash covers the audited row itself (decision, attestation issuance/consumption), so editing a decision after the
-- fact breaks the chain even if the audit table is untouched. Records are appended under an advisory lock (see auditChain.js).
CREATE TABLE audit_records (
  seq          bigint      PRIMARY KEY CHECK (seq >= 1),
  created_at   timestamptz NOT NULL,
  record_type  text        NOT NULL CHECK (record_type IN ('decision', 'attestation_issued', 'attestation_consumed')),
  ref_id       text        NOT NULL,
  payload_hash text        NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  prev_hash    text        NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
  record_hash  text        NOT NULL UNIQUE CHECK (record_hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX audit_records_ref_idx ON audit_records (record_type, ref_id);

-- Append-only enforcement. NOTE (honest limit): a database superuser or the table owner can DISABLE these triggers;
-- the hash chain is what makes such tampering DETECTABLE. These triggers stop accidental and application-level mutation.
CREATE FUNCTION tt_forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'table % is append-only (% not allowed)', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER audit_records_append_only BEFORE UPDATE OR DELETE ON audit_records FOR EACH ROW EXECUTE FUNCTION tt_forbid_mutation();
CREATE TRIGGER audit_records_no_truncate BEFORE TRUNCATE ON audit_records FOR EACH STATEMENT EXECUTE FUNCTION tt_forbid_mutation();
CREATE TRIGGER decisions_append_only     BEFORE UPDATE OR DELETE ON decisions     FOR EACH ROW EXECUTE FUNCTION tt_forbid_mutation();
CREATE TRIGGER decisions_no_truncate     BEFORE TRUNCATE ON decisions             FOR EACH STATEMENT EXECUTE FUNCTION tt_forbid_mutation();
CREATE TRIGGER agent_events_append_only  BEFORE UPDATE OR DELETE ON agent_events  FOR EACH ROW EXECUTE FUNCTION tt_forbid_mutation();
CREATE TRIGGER agent_events_no_truncate  BEFORE TRUNCATE ON agent_events          FOR EACH STATEMENT EXECUTE FUNCTION tt_forbid_mutation();

-- Nonces: rows may never be deleted; the only permitted UPDATE is the one-way transition "unconsumed -> consumed".
CREATE FUNCTION tt_nonce_one_way() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'attestation_nonces rows cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.consumed_event_id IS NOT NULL THEN
    RAISE EXCEPTION 'attestation % was already consumed (replay)', OLD.nonce USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.nonce IS DISTINCT FROM OLD.nonce OR NEW.source IS DISTINCT FROM OLD.source OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.account_id IS DISTINCT FROM OLD.account_id OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.issuer IS DISTINCT FROM OLD.issuer OR NEW.kid IS DISTINCT FROM OLD.kid
     OR NEW.method IS DISTINCT FROM OLD.method OR NEW.statement_sha256 IS DISTINCT FROM OLD.statement_sha256
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'only the consumption columns of attestation_nonces may change' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER attestation_nonces_one_way BEFORE UPDATE OR DELETE ON attestation_nonces FOR EACH ROW EXECUTE FUNCTION tt_nonce_one_way();
CREATE TRIGGER attestation_nonces_no_truncate BEFORE TRUNCATE ON attestation_nonces FOR EACH STATEMENT EXECUTE FUNCTION tt_forbid_mutation();
