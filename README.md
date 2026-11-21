# TrustTrace

**Account-takeover and help-desk social-engineering detection, built on [Meko](https://docs.mekodata.ai/) shared memory.**

> **Status: synthetic proof of concept, not production-ready.** All data is synthetic, thresholds and weights are hand-set, and nothing
> here has been measured on real help-desk traffic. The dashboard is **read-only**: it never blocks an account or changes payroll.
> See [Known limitations](#known-limitations).

## Live demo
* **Live demo:** <https://trusttrace-demo.onrender.com>
* **Source code:** <https://github.com/AxraMj/TrustTrace>

### Demo login
| | |
|---|---|
| **Username** | `judge` |
| **Password** | *Not published here.* Judges can obtain it securely from the project owner (it is shared privately, never committed to this repository). |
| **Role** | `supervisor`: read-only access to decisions, evidence and the audit trail. |

Things to know before you open it:
* **Synthetic data only.** Every account, caller, decision and attestation in the demo is synthetic; no real people or customer data are involved.
* **The first load can be slow.** The demo runs on Render's free tier, which puts the service to sleep after about 15 minutes without traffic. Waking it
  can take **50 seconds or more**, so the first page load may look stuck; please wait and refresh once.
* The demo database holds a small, pre-seeded set of five decisions (allow, step-up and block outcomes, including forged and expired
  verifications that were rejected). The dashboard is read-only, so nothing you click changes an account.

## Problem
Attackers rarely break the login page; they phone the help desk, claim to be the CFO who "lost their phone", and get MFA reset or
payroll details changed. Two systems each see half of it: the help desk hears the call, the identity system sees the new-device
login. Neither can safely trust what the other *says*, and a caller's claim ("I'm the CFO, it's urgent") must never be treated as fact.

## Solution
TrustTrace is a small multi-agent system whose agents share one memory (Meko) and trust it **by provenance, not by wording**:

* **Agent A (help desk)** listens to a call, extracts claims and signals, and writes them to Meko labelled `CLAIMED` (a person said it)
  or `OBSERVED` (a system saw it). Agent A **cannot** create `VERIFIED` evidence.
* **Verification authority** is the only component that can mint `VERIFIED` evidence. It holds an Ed25519 private key and signs an
  attestation each time an independent check (e.g. a callback to the number on file) succeeds.
* **Agent B (identity security)** receives a login / MFA-change / payroll-change event, retrieves the account's context from Meko,
  **cryptographically authenticates** any `VERIFIED` record with the authority's *public* key, scores the risk, applies a
  sensitive-action policy and returns an explained recommendation (`allow` / `step_up` / `block`). A record that merely *says*
  "VERIFIED" but fails authentication is rejected and **raises** risk.
* **PostgreSQL** is the authoritative record of every decision, agent action, single-use attestation and a hash-chained audit log.
* A **read-only React dashboard** lets analysts see why each decision was made, which evidence was authentic, rejected or merely claimed,
  and whether the audit trail is intact.

## Architecture
```
 caller ──► Agent A (help desk) ──writes CLAIMED / OBSERVED──┐
                                                              ▼
 Verification authority ──signs VERIFIED attestations──►  MEKO  (shared memory, MCP over HTTPS)
   (only holder of the private key)                           │ retrieves context
                                                              ▼
 login / MFA / payroll event ─────────────────────────►  Agent B (identity security)
                                                          verify signatures (public key) → score → policy
                                                              │ DecisionService (one DB transaction)
                                                              ▼
                       PostgreSQL: decisions · cases · agent_events · attestation_nonces · audit_records (hash chain)
                                                              │
                                              REST API (Node `http`, auth, roles, read-only)
                                                              │  same-origin /api
                                              React + Vite dashboard (web/, read-only v1)
```
The browser never receives the Meko key or any signing key; the API server holds neither the signing key nor queries Meko.

## Meko integration
Meko is the agents' shared memory (MCP over streamable HTTP to `https://mcp.mekodata.ai/mcp`, headers `Authorization: Bearer <key>` and
`User-Agent`). TrustTrace uses `memory_add`, `memory_search`, `memory_get_all`, `memory_get_by_id`, `memory_delete_by_id`, `conversation_create`
and `datapack_search` / `datapack_create`. Limits we measured against the live service, and how the design copes:

* Every tool call needs a `conversation_id`; `metadata` must be a JSON string; responses arrive as `{"result":"<json>"}`.
* `memory_search` has **no pagination parameter** (`limit` was accepted up to 100000) and ranks semantically with an undocumented relevance
  cut-off, so "fewer than `limit` rows" does not prove completeness.
* `memory_search`'s `run_id` filters **exactly** on the memory's conversation tag. TrustTrace stores each account/org scope under one of
  32 shared "bucket" conversations and searches with `run_id=<bucket>`, then post-filters by the exact scope in the memory header.
* If a search returns `limit` rows it may be truncated, so Agent B falls back to an exhaustive scan via `memory_get_all` (paginated,
  `page_size` clamped to 100; its `run_id` is ignored, so it costs O(datapack)). If even that cannot cover the datapack the result says
  `complete: false` and sensitive actions **fail safe** (step-up).
* `conversation_delete` cannot be verified (the conversation stays readable), so conversations are never deleted and are reused via
  `session_id`. Memory deletion **is** verifiable (`memory_get_by_id` → `not_found`), and only the writing `agent_id` may delete.

Details: [`docs/retrieval-and-pagination.md`](docs/retrieval-and-pagination.md).

## Agent responsibilities
| Component | May write | May read | Must never |
|---|---|---|---|
| **Agent A** (`src/agents/helpdeskAgent.js`) | `CLAIMED`, `OBSERVED` memories | – | create `VERIFIED` evidence |
| **Verification authority** (`src/trust/authority.js`) | signed `VERIFIED` attestations | – | be imported by agents or the Meko layer (a test enforces this statically) |
| **Agent B** (`src/agents/identityAgent.js`) | – (decisions go to PostgreSQL) | Meko context | trust a record because it says `VERIFIED`; hold the private key |
| **DecisionService** (`src/app/decisionService.js`) | decision + case + audit record, atomically | – | – |

### Trust model
* `CLAIMED` = a person said it. `OBSERVED` = a system saw it. `VERIFIED` = independently confirmed **and signed**.
* Agent B verifies an Ed25519 signature (Node `crypto`, domain-separated) over issuer, key id, case id, account id, evidence kind,
  method, SHA-256 of the canonical statement, issued-at, expiry and nonce. Rejection reasons: unknown issuer/key, bad signature,
  missing attestation, modified content, wrong account, wrong case, expired, replayed, replay ledger unavailable (and malformed /
  future-dated / excessive validity). A rejected record is **never** downgraded to an observation; tampering raises risk.
* Ed25519 rather than HMAC because with HMAC every verifier could also forge; Agent B holds only a public key.
* Single-use evidence (`callback_verified`, `identity_verified`) is spent by the first sensitive action; a replay is rejected.
  In the application layer the replay ledger lives in PostgreSQL (`attestation_nonces`, one-way updates); a bare library use without
  a guard falls back to in-process memory.
* The signing key never enters `process.env`. This is an architectural boundary, **not** a process/OS boundary.

### Scoring and policy
`rawScore` is the sum of signed, weighted contributions (unclamped). Severity comes from the raw score: <25 low, 25–49 medium,
50–74 high, ≥75 critical. `displayScore = 100·(1−exp(−raw/50))` is for display only. `CLAIMED` data can only raise risk; only
authenticated `VERIFIED` data lowers it. The **sensitive-action policy** can only raise the action: payroll/bank changes always need
step-up; MFA change / password reset from an unfamiliar device, country or IP need step-up unless the new device itself is attested
(a verified callback proves who is calling, not that the new device is theirs); forged verification on a sensitive action blocks;
incomplete Meko context on a sensitive action requires step-up. A sign-in from a new country on a known device is allowed with a
"notify the account holder" advisory ([decision record](docs/decisions/001-overseas-login-policy.md)).

### Agent A language extraction
`src/agents/extraction.js` is a deterministic concept matcher (no LLM). It is **English-only, keyword-lexicon based and brittle**.
Measured on frozen, hash-checked synthetic sets written by the same author as the rules: sets A and B were used to develop the rules
(72/73 and 57/60 exact match); **set C, written after all fixes and scored once, is the honest estimate: 23/35 exact (66%), precision
0.90, recall 0.61** (the earlier regex baseline scored 13/35, precision 0.33, recall 0.07). Every remaining miss is a visible `TODO` test.

## PostgreSQL and audit architecture
PostgreSQL is authoritative for decisions, agent activity, replay protection and the audit trail (Meko stays the agents' memory).
Eight tables (`users`, `sessions`, `access_log`, `decisions`, `cases`, `agent_events`, `attestation_nonces`, `audit_records`) plus
`schema_migrations`, created by three migrations in [`migrations/`](migrations/).

* **Append-only:** `decisions`, `agent_events` and `audit_records` reject `UPDATE`, `DELETE` and `TRUNCATE` via triggers;
  `attestation_nonces` may only move from "unspent" to "spent" (one-way).
* **Hash chain:** every decision and attestation event appends an `audit_records` row whose hash covers the previous record's hash and a
  SHA-256 of the canonical JSON of the audited row. Appends are serialised with an advisory lock. `GET /api/audit/verify` (admin)
  re-hashes the chain, and each decision page re-computes the stored decision's hash and compares it to its audit record.
* **Atomic:** the decision, its case and its audit record are written in one transaction.
* **Honest limit:** the chain detects edits, but someone who rewrites the whole chain is only caught against a chain head recorded
  elsewhere (`GET /api/audit/head`). Full integrity model: [`docs/database.md`](docs/database.md).
* **API and auth:** Node `http`, scrypt password hashing, opaque server-side sessions in an `HttpOnly; SameSite=Strict` cookie, roles
  `analyst` / `supervisor` / `admin`, origin check on non-GET, login and API rate limits (in-memory), access log. Endpoint reference:
  [`docs/api.md`](docs/api.md).

## Setup
Prerequisites: **Node.js ≥ 20.18.1**, **PostgreSQL**, and a **Meko Cloud account** (<https://cloud.mekodata.ai/> → Settings → API Keys).

0. `git clone https://github.com/AxraMj/TrustTrace.git` and `cd TrustTrace`.
1. `npm install` (backend) and `cd web; npm install` (frontend).
2. `copy .env.example .env` and set `MEKO_API_KEY` (starts with `mko_tkn_`) and `DATABASE_URL`. **Never commit `.env`.**
3. Create the PostgreSQL role and database once: [`docs/database.md`](docs/database.md) §1. URL-encode special characters in the password.
4. Optional: `npm run keygen` writes `secrets/verifier-private.pem` (authority only, git-ignored) and `config/trust-anchor.pem`
   (public). Without it, CLIs and tests use an ephemeral in-memory key.

## Run it
```powershell
# Backend (repo root)
npm run db:migrate                      # apply migrations; `npm run db:status` to inspect
$env:TRUSTTRACE_NEW_PASSWORD = '<a long passphrase>'
npm run user:create -- --username me --role admin     # or analyst / supervisor
npm run api                             # REST API on http://127.0.0.1:8787

# Optional: put real decisions in the database (live Meko, ~3.5 min, ADDS ROWS to the configured database)
npm run scenarios -- --persist

# Frontend (second terminal)
cd web
npm run dev                             # http://localhost:5173, proxies /api to the API
# or: npm run build; npm run preview    # production build on http://localhost:4173 with a strict CSP
```
Dashboard details (screens, UI rules, limits): [`web/README.md`](web/README.md).

**Single-process mode (same origin, for hosting):** `cd web; npm run build`, then `WEB_DIST_DIR=web/dist npm run api` serves the dashboard and `/api`
from one process. `GET /api/live` is a database-free liveness probe, `GET /api/health` checks PostgreSQL. Hosting notes, proxy/client-IP handling
and database connection guidance: [`docs/deployment.md`](docs/deployment.md).

### All commands
| Command | What it does |
|---|---|
| `npm test` | offline tests (no network, no database); run serially because one extraction test has a wall-clock limit |
| `npm run test:db` | PostgreSQL integration tests in throw-away schemas (**skipped** without `DATABASE_URL`) |
| `npm run test:live-db` | real Meko + real PostgreSQL scenarios persisted end to end |
| `npm run test:integration` | live Meko suites (serialised) |
| `npm run check` | live: Meko auth, tools, create/find the datapack |
| `npm run scenarios [-- --persist]` | live scenario tables, FP/FN summary, latency; writes `reports/scenario-results.json` |
| `npm run demo` | live end-to-end demo (verifies its own cleanup) |
| `npm run eval:extraction [-- --set heldout\|validation\|validation2]` / `npm run eval:compare` | score Agent A extraction on frozen sets (offline) |
| `cd web; npm test` | frontend component, XSS, accessibility and static-source tests |
| `npm run reports:sanitize` | publish sanitized copies of the raw reports to `reports/evidence/` (memory ids pseudonymised) |

## Test results
Measured on 2026-11-21 in the development environment (Windows, PostgreSQL, live Meko).

| Check | Result |
|---|---|
| Backend offline (`npm test`) | 455 tests: **439 pass, 0 fail, 16 todo** (each todo is a documented extraction miss) |
| PostgreSQL integration (`npm run test:db`) | **106/106** pass (including API, authorisation, injection safety, tamper detection) |
| Live Meko + PostgreSQL (`npm run test:live-db`) | **7/7** pass |
| Live scenarios (`npm run scenarios`) | **23/23** pass, no false positives, no false negatives; 83 test memories deleted and confirmed absent |
| Frontend (`cd web; npm test`) | **60/60** pass |
| Real-browser run (headless Edge, real API, real persisted data; driver script not included in this repo) | **83/83** checks: every screen at 1280 px and 390 px, login/logout, session expiry (absolute and idle), role permissions enforced by the server, strict CSP with no violations, no console errors |
| Accessibility (axe, WCAG 2.1 AA, contrast on) | no violations on 9 screens in light and dark |
| Extraction, clean set C | 23/35 exact, precision 0.90, recall 0.61 |

Not re-run in the final verification: the live Meko integration suites (`npm run test:integration`). The scenario run measured Meko
retrieval at roughly 0.8 s per decision on average (p95 about 1.2 s), scoring at a few milliseconds. Sanitized evidence files:
[`reports/evidence/`](reports/README.md). One extraction test enforces a 4 s wall-clock limit (about 2.3 s here), so under heavy CPU
load the parallel runner can fail it spuriously; `npm test` therefore runs serially.

## Known limitations
* **Synthetic only.** No real help-desk data was used; thresholds and weights are hand-set; accuracy figures are not real-world.
* **Extraction is brittle:** English keyword lexicons, 66% exact match on the clean set. A claim that is missed does not appear in the UI.
* **Advisory only.** `stepUp` and `advisories` are displayed; nothing enforces them. There is no integration with a real MFA or payroll system.
* **Evidence is a snapshot.** The dashboard shows what each decision recorded at the time, not live Meko contents.
* **Meko limits** (above): no pagination on search, an undocumented relevance cut-off, conversations cannot be deleted.
* **Security boundaries are architectural, not OS-level:** the authority key is protected by code structure, not a separate process or HSM.
* **Hash chain** detects edits but not a wholesale rewrite without an externally stored chain head.
* **Privacy:** masked ids in the UI are a display convenience, not access control; "show full ids" is not audit-logged; there is no
  retention or redaction policy for caller-derived text.
* **Operations:** rate limits and login throttling are per process and in memory; the dashboard polls every 30 s; no TLS termination
  is included (serve behind HTTPS and set `COOKIE_SECURE=true`).
* Production-readiness has **not** been assessed or claimed.

## Repository map
`src/agents/` agents and extraction · `src/trust/` attestations and authority · `src/meko/` Meko client and retrieval ·
`src/db/` repositories, audit chain · `src/api/` REST API · `src/app/` decision service · `migrations/` schema · `web/` dashboard ·
`test/` tests and frozen evaluation sets · `docs/` setup, API, retrieval, decision records · `reports/evidence/` sanitized evidence ·
`scripts/` tooling. [`docs/frontend-plan.md`](docs/frontend-plan.md) holds the original frontend plan plus what was actually built and
what is still missing; the dashboard in [`web/`](web/README.md) implements it as a read-only v1.

## License
[ISC](LICENSE). Copyright (c) 2026 AxraMj.
