# TrustTrace dashboard (v1, read-only)

React + Vite single-page app over the TrustTrace REST API (`docs/api.md`). It shows real decisions from PostgreSQL; there is no demo
data anywhere in `src/`. **It cannot change anything**: the only non-GET requests are sign-in and sign-out of the session itself
(a test enforces this). It is a proof-of-concept investigation view, not a production system.

## Run it
```
# 1. backend (repo root): migrate once, create a user, start the API (default http://127.0.0.1:8787)
npm run db:migrate
$env:TRUSTTRACE_NEW_PASSWORD = '<a long passphrase>'; npm run user:create -- --username me --role analyst   # or supervisor / admin
npm run api

# 2. frontend (this folder)
cd web
npm install
npm run dev        # http://localhost:5173  (Vite proxies /api to the API; set TRUSTTRACE_API_URL to change the target)
# or a production build served with a strict CSP:
npm run build; npm run preview     # http://localhost:4173
```
The browser only ever talks to its own origin; `/api` is proxied, so the `HttpOnly; SameSite=Strict` session cookie works with no CORS.
Meko credentials and signing keys never reach the browser (the API server doesn't hold the signing key either).

For a real deployment serve `dist/` from the same origin as the API behind TLS (set `COOKIE_SECURE=true`) and send the CSP from
`vite.config.js` (`securityHeaders`) from your web server.

## Screens
Overview (counts, flags, severity over time, top drivers, health) · Alerts queue (filters live in the URL) · Decision detail (raw score
first, score-vs-policy, contribution waterfall, recommended actions, memory evidence, rejected evidence, retrieval health, audit
integrity) · Cases (timeline, claims & evidence, verification, decisions, agent activity) · Agent activity · Verification (attestation
ledger, rejected records, key ids) · Audit (supervisor/admin; admin can re-verify the whole chain) · About (limits).

## Rules the UI enforces (and tests)
* The green "verified" style exists in exactly one place and only `verified_authentic` evidence gets it. CLAIMED is dashed purple
  "unverified"; a record that claimed VERIFIED but failed authentication is red "REJECTED". Expired is shown differently from forged.
* Severity is shown from the raw score; the 0–100 display score is secondary. Score-only and post-policy actions are both shown.
* Degraded, incomplete-context and integrity-mismatch states are loud banners, never hidden.
* All caller-derived text is rendered as text (no `innerHTML` anywhere; tested with hostile transcripts).
* Colour is never the only signal (icon + text). Light/dark themes, keyboard operable, phone width.

## Tests
`npm test` (vitest + Testing Library + axe): trust-style invariants, XSS, waterfall maths, API client, page states, static source rules.
During development the real stack (real API, real PostgreSQL, scenario data persisted through live Meko) was also driven with a headless
Edge/Chrome (83 checks: every screen at 1280 px and 390 px, login/logout, session expiry, role permissions, CSP, console errors, axe
WCAG 2.1 AA in light and dark). That driver script is not part of this repository, so those results are a record, not something you can
re-run from here.

## Known limits
Masked ids are a display convenience, not access control (and "show full ids" is not audit-logged). No retention/redaction policy for
caller text. Polling every 30 s on the overview (no push). No saved views beyond bookmarkable URLs.
