# Deployment runbook (single service, same origin)

Status: **preparation only.** Nothing has been deployed, no hosting account has been created, no database has been migrated and no Meko
datapack has been created from this document. Every step marked **APPROVAL GATE** must be explicitly approved by the owner before it is run.
Provider limits below were read from the providers' own pages on 2026-11-21 and change often: re-check them before relying on them.

## Architecture
```
browser ──HTTPS──► one Node process (node src/server.js) ── serves the built dashboard (WEB_DIST_DIR) and /api on ONE origin
                          │  DATABASE_URL (platform secret)
                          ▼
                   managed PostgreSQL (a separate demo database, never the development one)

owner's own machine (the Meko API key never leaves it):
   db:migrate · user:create · check · scenarios --persist   → run against the demo database / demo datapack
```
Same origin is required: the session cookie is `SameSite=Strict`, the API sends no CORS headers and writes check `Origin`.
The web process needs only `DATABASE_URL`. It does **not** need `MEKO_API_KEY` or any signing key, because it only reads stored decisions.

## Chosen hosting (all free tiers; no card required for either as of the date above)
| Part | Choice | Limits that matter |
|---|---|---|
| Web service | **Render** free web service (`render.yaml` is an optional Blueprint) | sleeps after 15 min without traffic (about a minute to wake); 750 free instance hours a month; may restart at any time; no shell and no one-off jobs; HTTPS and an `onrender.com` URL included. Without a payment method, exceeding bandwidth suspends the service instead of billing. |
| PostgreSQL | **Neon** free plan | permanent, no card; 1 GB storage; 100 compute-hours a month; 5 GB egress; compute suspends after 5 min idle and wakes in a few hundred ms; exceeding limits suspends compute, it does not delete data. |
Rejected: Render's own free Postgres (expires after 30 days, deleted after a 14-day grace), Railway (about $1 a month of credit), Koyeb (no free compute on its pricing page), Fly.io (no free tier for new organisations).

## Environment variables (names only; never commit values)
| Variable | Value on the web service | Notes |
|---|---|---|
| `DATABASE_URL` | the demo database's **direct** string | secret; prompted for by `render.yaml` (`sync: false`) |
| `DATABASE_SSL` | `true` | and keep `sslmode=require` in the URL |
| `NODE_ENV` | `production` | cookies become `Secure`; HSTS on app responses |
| `API_HOST` | `0.0.0.0` | default is loopback |
| `PORT` | injected by Render | read automatically; `API_PORT` overrides it if set |
| `WEB_DIST_DIR` | `web/dist` | serve the dashboard from this process |
| `DB_POOL_MAX` | `5` | small instance |
| `NODE_VERSION` | `24.22.1` (Render's current default) | any Node ≥ 22.12 satisfies the build tool; CI covers 22.22.2, 22, 24 and 26 |
| `TRUST_PROXY_HOPS` | **leave unset** | see "Client IP" |
Never set `TRUST_PROXY=true` and never put `MEKO_API_KEY` or any signing key on the web service.

Manual (dashboard) settings if the Blueprint is not used: runtime Node; build command
`npm ci && npm --prefix web ci --include=dev && npm --prefix web run build` (`NODE_ENV=production` applies to the build and would otherwise skip
the devDependencies Vite needs); start command `node src/server.js`; health check path `/api/live`; auto-deploy off.

## Database: direct connection, TLS
* Use the **direct** (non-pooled) string everywhere. Migrations take a session-level advisory lock, which Neon's transaction-mode pooler
  (the `-pooler` hostname) does not support. The app itself only uses a transaction-scoped lock, which works either way.
* node-postgres treats `sslmode=require` in the URL as `verify-full` (the certificate is verified) and that setting overrides `DATABASE_SSL`.
  A URL **without** `sslmode` and with `DATABASE_SSL` unset connects **without TLS**. Keep both. Never use `sslmode=no-verify` or `disable`.
* A scale-to-zero database wakes on the first query (the first connection took about 3 s). Do not point frequent probes at `/api/health` (it queries
  the database); use `/api/live`.
* node-postgres 8.x prints a deprecation warning for `sslmode=require`: it is currently an alias of `verify-full`, but in the next major version
  (pg 9) `require` will adopt libpq semantics, which do **not** verify the certificate. Use **`sslmode=verify-full`** explicitly (in `.env.demo` and in
  the Render `DATABASE_URL`) so an upgrade can never silently weaken TLS. The pinned lockfile keeps pg 8.23.1 until then.
* Neon terminates TLS at its proxy, so the database server's own `pg_stat_ssl` does not describe the client's connection; verify encryption on the
  client socket instead (the preflight does).
* Verified on 2026-11-21 against the real Neon endpoint (read-only): PostgreSQL 18.7, empty database, TLS 1.3 with a verified certificate, session
  advisory locks work on the direct endpoint, the role can create objects (it is not a superuser).
* **Local DNS caveat (this development machine):** the router's DNS (192.168.31.1) answers `REFUSED` for Neon endpoint names while 1.1.1.1 resolves
  them, so Node's system lookup fails with `ENOTFOUND` on this machine (the deployed Render service is not affected). Fix it on the machine (use 1.1.1.1
  as the adapter's DNS, or another network), or run local operator commands with a scoped preload that falls back to 1.1.1.1 only for `*.neon.tech`
  names when the system lookup fails. It changes no system settings and does not affect TLS verification.
* The connected role owns the tables it creates, so it can disable the append-only triggers (as the migration's own comment says; the hash chain is
  what makes that detectable). A separate least-privilege runtime role would be stronger; it is not part of the current plan.

## Client IP behind a proxy
Login throttling and the access log are keyed by client IP. With `TRUST_PROXY_HOPS` unset the header is ignored and everyone behind the proxy
shares one bucket (safe, but one visitor's failed logins could lock the judge account).
* Cloudflare documents that it **appends** the connecting address to an existing `X-Forwarded-For`; a Render user tested the same on Render
  (2021 thread). A Render staff reply there says the first entry is the real client IP, which conflicts with that test and is not in Render's
  docs, so it cannot be relied on. If the user's test is right, the leftmost entries are client-controlled, so the old `TRUST_PROXY=true` lets an
  attacker choose their own address (a characterisation test shows the limiter bypass).
* `TRUST_PROXY_HOPS=N` takes the N-th entry **from the right**; a shorter chain, a non-IP value or `N=0` falls back to the socket address.
  Under-counting is safe, over-counting is the dangerous mistake. **Measure after deployment**: send a request with a forged
  `X-Forwarded-For`, read the `ip` recorded in `access_log`, and raise `N` only while the recorded value is your real address and the forged
  value is never used. Only valid when the app port is reachable solely through the proxy.

## Node versions and CI
`.github/workflows/ci.yml` runs on every push to `main` and every pull request, with read-only permissions, no secrets and actions pinned to
commit SHAs: backend tests on Node 22.22.2, 22 (latest), 24 and 26; frontend tests, production build and the "serve the real build" test on the
same versions; the PostgreSQL integration suite (a throw-away container with a random masked password) on 22.22.2 and 26; and an informational
`npm audit`. It does **not** run the live-Meko suites (no secrets in CI). The workflow was validated locally with a structural checker only
(no `actionlint` available): the first run on GitHub is the real validation. **Do not deploy until it is green.**
Findings from static analysis: backend runtime packages accept Node 20.18.1 and up; the frontend build needs Node 22.12+ (or 20.19+); only the
`jsdom` test tooling needs 22.22.2+.

## The Meko demo datapack
`npm run check` and `npm run scenarios` call `ensureDatapack()`, which searches for the configured name **exactly** and **creates it if absent**.
Inspected (read-only) on 2026-11-21: `datapack_create` provisions a new "isolated database environment with its own agent namespace"; `name` is
required and **must be unique across the whole platform**; `datapack_delete` (never called by TrustTrace) drops the database irreversibly.
**Done on 2026-11-21 (owner-approved, conditional on it being free):** `datapack_create { name: "trusttrace-demo", conversation_id: <the existing stable
"trusttrace-setup" conversation> }` — no folder, no other fields. Result: the account went from 2 to 3 datapacks; `trusttrace-demo` is owned by the
account and is empty (0 memories, 0 knowledge, 0 learnings); `trusttrace-test` and `meko_default_datapack` were snapshotted before and after
(name, timestamps, counts, access) and are **unchanged**. No memory was written.
Cost evidence read from Meko's own pages that day: Free is $0 with no card and caps the account at 10 datapacks, 1,000 conversations and 10,000 memory
adds; Standard is a flat $25 a month (50 datapacks, 10,000 conversations, 30,000 memory adds); Pro is custom. There is no per-datapack fee and no
usage-based overage on Free or Standard. Reaching a cap blocks the action and shows an upgrade banner; it does not charge. The API does not expose
which plan the account is on, so the plan itself was not read directly. A seeding run adds roughly 83 memories and about 20–35 conversations (bucket
conversations are created per datapack and are never deleted), so check the plan's conversation and memory-add headroom in the Meko console first.
To remove the datapack later use the Meko console (owner only); TrustTrace never deletes datapacks.

## Runbook (owner steps and approval gates)
0. **Commit and push** the prepared changes, then confirm the CI run on GitHub is green (all matrix jobs). Render deploys from the repository.
1. **Neon account** *(you; approval needed before I proceed)*: sign up at neon.com (the Free plan needs no card), create a project, pick the region
   nearest your Render region (Render defaults to Oregon; Neon offers an AWS US West 2 Oregon region), open **Connect**, turn **Connection pooling
   off**, and copy the connection string. Treat it as a secret: do not paste it into chat, issues, commits or screenshots.
2. **Local, git-ignored demo settings** *(you)*: `.env.demo` in the project root (the `.env.*` rule keeps it out of git) contains only
   `DATABASE_URL=<the Neon direct string>` and `MEKO_DATAPACK=trusttrace-demo`. Create it in **your own terminal window** (not through the
   assistant, and never paste the string into chat) with a hidden prompt, so the string is never displayed, logged or stored in shell history:
   ```powershell
   cd <project root>
   $sec = Read-Host -AsSecureString 'Paste the Neon DIRECT connection string (nothing is shown)'
   $p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
   try { $url = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($p) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) }
   $url = ($url.Trim() -replace '^psql\s+', '').Trim().Trim("'").Trim('"').Trim()   # Neon's "copy" can add a psql prefix and quotes
   [IO.File]::WriteAllText((Join-Path (Get-Location) '.env.demo'), "DATABASE_URL=$url`nMEKO_DATAPACK=trusttrace-demo`n", (New-Object Text.UTF8Encoding $false))
   Remove-Variable url, sec, p; Set-Clipboard -Value ' '
   ```
   (The file is written without a byte-order mark, which would corrupt the first key.) Then verify it; the output is only PASSED or FAILED, plus the
   names of failed checks, and never a value: `node scripts/check-demo-env.mjs`. The checks: file exists, Git-ignored and untracked; exactly the two
   keys; a bare URL; PostgreSQL scheme; host ends in `.neon.tech`; direct (no `-pooler`) and not local; user and a non-placeholder password present;
   database name; default port; `sslmode=require`; differs from the development URL in `.env`; datapack is exactly `trusttrace-demo`.
   Commands below use `node --env-file=.env.demo`, so these values win over your development `.env`, the Meko key still comes from `.env`, and a
   missing `.env.demo` is an error (exit code 9) rather than a silent fallback to your development database.
3. **APPROVAL GATE (database migration).** First a read-only preflight (it runs the same startup sequence as the CLI, executes only `SELECT`/`SHOW`
   in a read-only transaction plus a session-lock test on a spare key, and creates nothing): it confirms the effective host comes from `.env.demo`
   and not from the development `.env`, the host is a direct `*.neon.tech` endpoint, the database is empty, the role may create objects, the socket is
   TLS-encrypted with a verified certificate, `gen_random_uuid()` and `plpgsql` exist, and session advisory locks work. Then
   `node --env-file=.env.demo src/cli/dbMigrate.js`. Run `... --status` only **after** that: `--status` is not read-only, it creates the empty
   `schema_migrations` bookkeeping table if it is missing.
   What it creates (all in the `public` schema, nothing else, no data except 3 bookkeeping rows): tables `users`, `sessions`, `access_log`, `decisions`,
   `cases`, `agent_events`, `attestation_nonces`, `audit_records` and `schema_migrations`; 19 explicit indexes (plus 11 primary-key/unique indexes);
   2 sequences; the functions `tt_forbid_mutation` and `tt_nonce_one_way`; and 8 triggers that make `decisions`, `agent_events`, `audit_records` and
   `attestation_nonces` append-only. There is no `DROP`, `ALTER`, `GRANT`, extension, role or cross-database statement. Each migration runs in its
   own transaction under a session advisory lock and is rolled back on error; a migration file edited after it was applied is refused.
   **Done on 2026-11-21 (owner-approved)** against the confirmed demo endpoint: `001_core`, `002_decisions` and `003_audit` applied (exit 0). Verified
   afterwards with read-only queries inside a READ ONLY transaction (39 checks, all passing): 9 tables with exact column lists, 30 indexes (including the
   3 partial ones and the case-insensitive unique username index), 2 sequences, 2 plpgsql functions whose stored bodies match `003_audit.sql` byte for
   byte, 8 enabled triggers of the right type on the right tables, 9 primary keys / 2 unique / 1 foreign key (ON DELETE CASCADE) / 13 CHECK
   constraints, migration records with checksums equal to the files, all domain tables empty, one owner, no extensions, no extra schemas, views or
   enum types. The `DATABASE_URL` SSL parameter was changed to `sslmode=verify-full`. `db:migrate --status` has not been run (it is only safe now that
   `schema_migrations` exists).
4. **APPROVAL GATE (create an account):** a single supervisor for the judges, with a long random password that is never written to a file:
   `$env:TRUSTTRACE_NEW_PASSWORD = '<generated>'; node --env-file=.env.demo src/cli/userCreate.js --username judge --role supervisor`
   Never create an admin account unless that is decided separately.
   **Done on 2026-11-21 (owner-approved)** in the demo database: one account, username `judge`, role `supervisor`; no admin exists. The password is 24
   random characters (about 139 bits: a 56-symbol alphabet without look-alike characters, shown as six groups of four) generated in memory and passed to the real `userCreate` CLI
   over stdin. It was never printed, never written to a file and never put in an environment variable or command line. It was placed on the clipboard
   for the owner and read back correctly at that moment, but a later read found the clipboard empty, so **delivery to the owner is unconfirmed**: if the
   owner does not have the password, rotate it (see below) rather than assume it was received.
   Verified against the real database through the production API code on loopback (23 checks): wrong password and unknown user give the identical 401;
   login returns a `Secure; HttpOnly; SameSite=Strict` cookie; the supervisor can read all investigation and audit endpoints, is refused
   `/api/audit/verify` and `/api/health/details` (403) and every write (405); logout kills the session; the stored value is a scrypt hash.
   **Rotating the password** (`scripts/rotate-user-password.mjs`, run by the owner in their own terminal window, never through an assistant or a
   `!` prefix): `node --require ./scripts/dns-fallback.cjs --env-file=.env.demo scripts/rotate-user-password.mjs --username judge --expect-host <endpoint prefix>`
   is a read-only **dry run** (the default); add `--execute` for the real run. `--execute` refuses to run unless stdin and stdout are interactive terminals,
   shows a new random password once (on that terminal only), requires you to type it back into a hidden prompt (so a password you did not receive is never
   stored), clears the screen and scrollback, and then runs exactly one locked `UPDATE users SET password_hash = $1 WHERE id = $2` on the existing
   user (it must affect exactly 1 row, else it rolls back). It creates no user, changes no role or other column, and leaves existing sessions alone
   (it only reports how many exist). It then checks the new password through the production login API; that is a normal login, so it sets `last_login_at`,
   adds `access_log` rows and creates then deletes one session. `scripts/dns-fallback.cjs` is the operator-only preload for networks whose DNS refuses
   Neon names (see "Database").
5. *Datapack: already created and verified empty (see above).* `node --env-file=.env.demo src/check.js` now only confirms that `trusttrace-demo` exists
   and is usable; it would create it again only if it had been deleted.
6. **DONE (Meko seeding, approved and completed):** the reduced five-scenario seeding (S1, S4, S6, H3, H8) was run once with
   `scripts/seed-demo.mjs --execute` (see "Reduced seeding" below). Result: all five decisions are persisted in the Neon demo database
   (S1 allow, S4 block, S6 step-up, H3 block, H8 block) and the audit chain verifies (7 records, 0 problems). All 21 temporary Meko memories were deleted
   and confirmed gone, `trusttrace-demo` is empty again (0 memories), and `trusttrace-test` and `meko_default_datapack` are unchanged. **Do not run the
   seeding again** (the script refuses when decisions already exist) **and do not run the retired 23-scenario, 83-memory plan** (`npm run scenarios` /
   `src/runScenarios.js --persist`): it needs far more Meko searches than the account has left. The retired plan's arithmetic is kept below for reference only.

   **Seeding plan (measured offline with the fake client over 25 random run tags; no Meko call was made to measure it).** The run executes 23
   scenarios (7 core S1–S7, 16 hardening H1–H16) through the real agents and the verification authority: legitimate users that must not be blocked
   (normal and overseas logins, a stolen-laptop traveller with a verified callback, a payroll change after a verified callback, a stressed but verified
   user); suspicious help-desk calls (CFO and director impersonation, MFA and password-reset requests, urgency and authority pressure, compromise
   indicators); eight forged or tampered verifications that must be rejected (unknown issuer, spoofed key id, unsigned, altered text, other account's
   attestation, expired); repeat attacks matched to a stored VERIFIED attack pattern, including a reworded one; and compromised payroll changes.
   Per run: **83 `memory_add`**, 83 `memory_delete_by_id`, 83 `memory_get_by_id`, **51 `memory_search` before cleanup plus 22 per cleanup poll**
   (22 distinct accounts or orgs; cleanup polls until the deleted memories stop being searchable, bounded by a 60 s deadline, and the old live logs show
   70–83 s, so expect 2–4 polls: about 73–140 searches, never more than about 490), 1 `memory_get_all` page per poll, **20–26 new conversation
   containers** (bucket and agent conversations, reused via `session_id`, never deleted) and 40–52 `conversation_create` calls (most are idempotent
   re-uses). Nothing calls `conversation_add_message`, `context_search` or `knowledgebase_search`. On the Neon side the run writes about 23 decisions,
   about 130 agent events, 7 attestation nonces and about 33 audit records. Cleanup deletes only the memory ids this run created (each by id, by the agent
   that wrote it), then checks every id is `not_found`, that no `[TRUSTTRACE` memory remains in the datapack, and that every conversation was re-used
   rather than re-created. It never calls `memory_delete_all`, `conversation_delete` or `datapack_delete`. If the process is killed hard the `finally`
   block cannot run: the leftover ids are then recoverable from the `memory_written` rows in `agent_events` and are deleted by id only.
   Free-tier quotas are metered **per month per account** (Retrievals 10,000: `memory_search`, `context_search`, `knowledgebase_search`; Conversations
   1,000: `conversation_add_message`; memory adds 10,000 per the pricing page). One run is 83 adds (0.8%) and at most about 1.4% (typically) to 4.9%
   (worst case) of the retrieval quota. The account's remaining quota cannot be read through the API (no tool exposes usage) and `conversation_list`
   does not list the earlier bucket conversations, so confirm the remaining quota in the Meko portal before approving. The quota is shared with any
   other use of the account (for example an agent client attached to `meko_default_datapack`). When a quota is exceeded further calls are blocked, not
   billed.

   **Update, same day: the Meko usage dashboard shows 894 of 1,000 memory searches used (106 left), so the 10,000 figure above does not apply to this
   account and the 23-scenario plan above MUST NOT be run now** (it needs about 73–140 searches). Use the reduced seeding script instead. Do not run
   `npm run scenarios`, `npm run test:integration` or `npm run test:live-db` until the monthly quota resets: they spend Meko searches.

   **Reduced seeding: `scripts/seed-demo.mjs` (`npm run seed:demo -- --expect-host <neon endpoint prefix> [--execute]`).** It runs five of the existing
   scenarios, selected by id and unchanged (S1 allow; S4 CLAIMED/OBSERVED context from Agent A used by Agent B to block; S6 an authentic VERIFIED
   callback that lowers risk but still requires step-up; H3 a forged verification rejected as unknown issuer; H8 an expired verification rejected), through
   the real agents, verification authority and PostgreSQL persistence. Without `--execute` it is a read-only dry run (datapack search and describe plus
   the idempotent setup conversation).
   Expected usage per execution (modelled offline with index lag 0, as seen in earlier real runs): `memory_add` 21, `memory_search` 9 (about 25 if the index
   lagged by 4 polls), `memory_delete_by_id` 21, `memory_get_by_id` 21, `memory_get_all` 1, `datapack_search` 2, `datapack_describe` 3, and 10 or 11
   `conversation_create` calls (9–10 new containers). It spends **no search on cleanup**. `conversation_add_message` is never called.
   Hard caps enforced in code (a call over the cap is refused and never sent): `memory_search` 40, `memory_add` 30, `memory_delete_by_id` 30,
   `memory_get_by_id` 60, `memory_get_all` 4, `conversation_create` 24, `datapack_search` 4, `datapack_describe` 12. Every tool not in that list
   (`datapack_create/update/delete`, `memory_delete_all`, `conversation_delete`, `conversation_add_message`, `context_search`, `knowledgebase_*`) is refused
   outright, and every memory call must carry the id of the datapack found by the exact name `trusttrace-demo`.
   Refuses to start unless: `MEKO_DATAPACK` is exactly `trusttrace-demo`; exactly one such datapack exists and it is empty; the Neon host starts with
   `--expect-host`; all migrations are applied; and the database holds no decisions yet (run once). Cleanup always runs, deletes only the ids this run
   wrote (by the agent that wrote each), and checks each is gone with `memory_get_by_id` plus one `memory_get_all` pass. Afterwards it re-reads every
   datapack and fails if anything other than `trusttrace-demo` changed or `trusttrace-demo` is not empty again. Tests:
   `test/seed-demo.test.js` (offline, 22 tests, 15 mutation checks all caught) and `test/db/seed-demo.integration.test.js` (local throw-away schema).
7. **Render account** *(you; approval needed before I proceed)*: sign up at dashboard.render.com (no card needed for a free web service), then
   **New → Blueprint** pointing at this repository (reads `render.yaml`; Render prompts for `DATABASE_URL`) or **New → Web Service** with the manual
   settings above and the plan set to **Free**. Paste `DATABASE_URL` only into Render's secret field. Do not add a payment method.
8. **APPROVAL GATE (deploy):** trigger the first deploy manually (auto-deploy is off), then I verify the live site end to end: `/api/live`,
   `/api/health`, sign-in and sign-out, roles, dashboard data, evidence styling, audit integrity, console/CSP, no secrets in responses or logs,
   desktop and 390 px.
9. **Measure `TRUST_PROXY_HOPS`** as described above, set it only if the measurement is unambiguous, and redeploy.

## Judge access
One `supervisor` account: sees everything including the audit chain and the per-decision integrity check, but cannot run the whole-chain
verification or see health details. Share its password only privately, never in a file or the repository. Rotate or delete it, and the database,
after the event.

## Shut down or redeploy
* Pause without losing anything: in the Render service's settings, suspend it (the Neon database stays; compute sleeps on its own).
* Redeploy: push a commit (CI must be green), then use Render's manual deploy for that commit; roll back from the service's deploy history.
* Rotate the judge password: re-run `user:create` flow with a new account and delete the old one, or delete the database and re-migrate.
* Tear down completely: delete the Render service, delete the Neon project, and (only if you decide to) the `trusttrace-demo` datapack in Meko
  using the Meko console. TrustTrace never deletes datapacks or conversations by itself.
(Provider menu labels can change; check the provider's current documentation.)

## Known limits
Free web services sleep, so the first request after idle is slow; in-memory rate limits reset on every restart; per-process throttling means one
instance only; the dashboard shows a decision-time snapshot of Meko evidence, not live Meko state; this is a synthetic proof of concept.
