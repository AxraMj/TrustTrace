# PostgreSQL setup, schema and operations

PostgreSQL is the **authoritative** store for decisions, agent activity, attestation replay protection and the audit chain.
Meko remains the shared memory/context layer for agents; nothing here replaces it.

## 1. One-time setup (Windows, PostgreSQL 18)
`psql` is not on the PATH by default. Use the full path (adjust the version if needed) and enter the `postgres` superuser
password you chose at install time:

```powershell
& 'C:\Program Files\PostgreSQL\18\bin\psql.exe' -U postgres -h localhost
```
then, inside psql (choose your own password; do not reuse another one):
```sql
CREATE ROLE trusttrace_app LOGIN PASSWORD 'choose-a-long-random-password';
CREATE DATABASE trusttrace OWNER trusttrace_app;
\q
```
The application role owns only this database; it needs no superuser rights. (The integration tests create and drop throw-away
schemas inside this database, which the owner is allowed to do.)

Put the connection string in **`.env`** (never commit it; it is gitignored):
```
DATABASE_URL=postgres://trusttrace_app:<your-password>@localhost:5432/trusttrace
```
If the password contains special characters, URL-encode them (`@` -> `%40`, `/` -> `%2F`, `:` -> `%3A`).

Then:
```powershell
npm run db:migrate                      # create/upgrade the schema
$env:TRUSTTRACE_NEW_PASSWORD = '<12+ characters>'
npm run user:create -- --username alice --role admin   # roles: analyst | supervisor | admin (all read-only in v1)
npm run api                             # REST API on http://127.0.0.1:8787
```
`npm run db:status` shows applied/pending migrations without changing anything. The API refuses to start if migrations are pending.

## 2. Configuration (environment variables)
| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | *(required)* | PostgreSQL connection string. Never logged; passwords are redacted from every error. |
| `DATABASE_SSL` | `false` | `true` enables TLS with certificate verification. |
| `DB_POOL_MAX` | `10` | Connection pool size. |
| `API_HOST` / `API_PORT` | `127.0.0.1` / `8787` | The API binds to loopback by default; expose it deliberately. |
| `SESSION_TTL_MINUTES` | `480` | Absolute session lifetime. |
| `SESSION_IDLE_MINUTES` | `30` | Idle timeout. |
| `COOKIE_SECURE` | `true` when `NODE_ENV=production` | Adds the `Secure` flag to the session cookie. |
| `ALLOWED_ORIGINS` | *(none)* | Comma-separated browser origins allowed to POST cross-origin (e.g. the Vite dev server). |
| `TRUST_PROXY_HOPS` | `0` | Number of trusted proxies that **appended** to `X-Forwarded-For`; the client is the N-th entry from the right. `0` ignores the header. Too small is safe, too large is not: see [`deployment.md`](deployment.md). |
| `TRUST_PROXY` | `false` | **Legacy, unsafe behind proxies that append:** trusts the client-controlled *first* `X-Forwarded-For` entry. Cannot be combined with `TRUST_PROXY_HOPS`. |
| `WEB_DIST_DIR` | *(unset)* | Serve the built dashboard (`web/dist`) from the same process and origin as `/api`. Unset = API only. The process refuses to start if the directory has no `index.html`. |
| `MAX_BODY_BYTES` | `65536` | Request body limit. |

The Meko API key and the verification authority's private key are **not** read by the API server and are never part of any
response; `/api/health/details` reports only the boolean `mekoConfigured`.

## 3. Schema (migrations in `migrations/`)
| Migration | Tables |
|---|---|
| `001_core.sql` | `users` (scrypt hashes, role), `sessions` (token **hash** only), `access_log` |
| `002_decisions.sql` | `decisions`, `cases`, `agent_events`, `attestation_nonces` |
| `003_audit.sql` | `audit_records` (hash chain) and the append-only triggers |

* **`decisions`**: one row per Agent B decision: event, raw/display score, severity, base and recommended action, policy steps, step-up
  requirements, advisories, every score contribution, explanation, rejected evidence (with reason codes), retrieved memories
  (`[{id,label,kind,scope}]` = what was read from Meko), retrieval metadata, timings, model/extractor/policy versions, verifier key id,
  `degraded` (Meko was unreachable).
* **`cases`**: case index derived from decisions in the same transaction (`decision_count`, `first_seen`, `last_seen`, `max_severity`).
* **`agent_events`**: what each agent did (memory written/read/deleted, decision made, errors) with memory ids and durations.
* **`attestation_nonces`**: the replay ledger. A row exists from issuance (or first sight); consumption is a one-way, atomic transition
  that can happen **once**; rows can never be deleted.
* **`audit_records`**: `record_hash = SHA-256(canonical JSON of seq, record_type, ref_id, payload_hash, prev_hash, created_at)`;
  `payload_hash` covers the audited row itself (decision, attestation issuance/consumption). Appends are serialised by an advisory lock and
  committed in the same transaction as the audited row.

## 4. Integrity model, honestly
* `decisions`, `agent_events` and `audit_records` reject UPDATE/DELETE/TRUNCATE through triggers; the nonce table allows only the
  one-way consume. **A database superuser or the table owner can disable these triggers.** That is why the chain exists: editing a
  decision, an audit record, a nonce row, or deleting/reordering records is detected by `GET /api/audit/verify` (tested against real
  PostgreSQL with the triggers deliberately bypassed).
* **Not detectable from inside the database:** truncating the *tail* of the chain together with its rows. Record the chain head
  (`/api/health/details` -> `audit.headSeq/headHash`) somewhere independent and compare.
* The chain proves the log was not edited **after** it was written; it does not prove the decision was *correct*.
* Passwords are stored as scrypt hashes; session tokens only as SHA-256 hashes; neither appears in any response or log.
* Login brute-force limits (5 failures per user+IP and 20 per IP per 15 minutes) and the 600 requests/minute API limit are
  **in-process memory**: they reset on restart and are per process. A shared limiter (e.g. at a reverse proxy) is needed for multiple instances.
* **Not done yet:** retention/redaction of caller-derived text (names, claims appear in `decisions`), database encryption at rest,
  backups/restore drills, row-level security, TLS to the database by default, and key management for the verification authority.

## 5. Tests that touch PostgreSQL
`npm run test:db` creates a throw-away schema per test group (so real data is never touched) and drops it afterwards. Without
`DATABASE_URL` these tests are **skipped**, never counted as passing. `npm run test:live-db` additionally needs `MEKO_API_KEY` and
runs scenarios against real Meko with persistence.
