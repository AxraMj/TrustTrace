# TrustTrace frontend: plan and implementation status

> **Status: implemented as a read-only v1 in [`web/`](../web/README.md)** (React + Vite). The original plan is kept below for
> reference; this section records what was actually built, where it differs, and what is still missing. The system remains a synthetic
> proof of concept and is **not production-ready**; a UI makes it look more finished than it is, so v1 is read-only and labels
> everything honestly.

## Implementation status (what was built)

### Backend prerequisites (section 2)
| # | Prerequisite | Status |
|---|---|---|
| B1 | Read-only HTTP API; no secrets in the browser | **Done.** Node `http` API (`src/api/`), no framework. The browser holds neither the Meko key nor any signing key; the API server holds no signing key and does not query Meko. Reference: [`api.md`](api.md). |
| B2 | Append-only decision log with hash chain and versions | **Done.** PostgreSQL `decisions` + `audit_records` (SHA-256 hash chain, append-only triggers); model/extractor/policy versions on every record. [`database.md`](database.md). |
| B3 | Agent activity log | **Done.** `agent_events` (memory ids, timings, errors) via an instrumented memory store. |
| B4 | Persisted replay ledger | **Done** in the application layer (`attestation_nonces`, one-way spend). A bare library use without a guard still falls back to in-process memory. |
| B5 | Case concept | **Done.** `cases` index derived from `(accountId, caseId)`. |
| B6 | Authentication, roles, access logging | **Done.** Login, opaque server-side sessions in an `HttpOnly; SameSite=Strict` cookie, roles `analyst` / `supervisor` / `admin` (all read-only), `access_log`. Idle and absolute session expiry. |
| B7 | Caller text treated as untrusted | **Done.** API returns plain text; the UI renders it as text only (no `innerHTML`; tested with hostile transcripts). |
| B8 | Retention / redaction policy | **Not done.** Caller-derived text is stored and shown unredacted to every signed-in role. |

### Screens (section 4)
| Plan | Delivered | Differences |
|---|---|---|
| 4.1 Dashboard | **Overview**: counts by action and severity, integrity/health flags, severity over time (SVG + table alternative), needs-review queue, top risk drivers, rejected-evidence reasons, policy rules, health strip, agents, attestations. | The health strip shows API/database state and retrieval completeness from decision records; it does **not** probe Meko reachability. No separate Settings/Health screen. |
| 4.2 Alerts | **Alerts** queue with severity/action/flag/time/search filters kept in the URL, score-vs-policy action pair, top-2 reasons, flags. | "Saved views" are bookmarkable URLs only. |
| 4.3 Case detail | **Case** page: header, merged timeline, claims & evidence (CLAIMED / OBSERVED / VERIFIED / REJECTED never share a style), verification, decisions, agent activity. | Ids are masked by default, but "show full ids" is a display toggle and is **not** audit-logged. |
| 4.3b Activity & evidence | **Agent activity** page, memory-evidence table (label, trust class, writer, statement, effect, memory id), per-decision retrieval health. | Evidence is a decision-time snapshot, not live Meko. The Meko limits are explained in text, not a popover. |
| 4.4 Verification | **Verification** page: attestation ledger (valid / spent / expired, single-use), rejected records with plain-language reason codes (expired shown differently from forged), key ids. | Replay-ledger size / persistence status is not shown. |
| 4.5 Recommended actions | On the decision page: ordered step-up checklist, advisories, explicit "advisory only; this dashboard enforces nothing". | – |
| 4.6 Explanation & audit | **Decision** page: raw score first (display score secondary), contribution waterfall with running total and band markers, policy override spelled out, audit trail with integrity re-check. **Audit** page (supervisor/admin) with chain head; admins can re-verify the whole chain. | Counterfactuals ("without Meko context / without pattern") exist in scenario reports but are **not** shown in the UI. |

### Technology (section 6)
React + Vite + react-router, plain CSS tokens (light/dark), inline-SVG charts, no UI kit and no state library; same-origin `/api`
via a dev/preview proxy. A strict CSP is configured for `vite preview`; a real deployment must send it from its own web server.

### Test plan (section 9): status
Done: component tests per screen state (loading / empty / error / degraded), API-client tests, hostile-transcript XSS tests,
"no fake verified" test (the verified style exists in one place, applied only to authentic verified evidence; also verified once by deliberately breaking the rule and confirming the tests fail),
axe accessibility (jsdom and a real browser, light and dark), keyboard tab navigation, and a real-browser run against the real API and
persisted data (login/logout, session expiry, role permissions enforced by the server, every screen at 1280 px and 390 px, CSP, console).
Not done: visual-regression snapshots, formal contract tests against recorded fixtures (fixtures are used in component tests; the API's
own numbers are checked against independent recomputations in the PostgreSQL integration tests), a usability review with real analysts,
and any load test of the dashboard.

### Remaining limitations
No retention/redaction policy (B8); masked ids are not access control and reveals are not logged; no counterfactual view; no Meko health
probe; polling every 30 s (no push); per-process in-memory rate limits; no TLS termination shipped; Agent A extraction is English
keyword-based (66% exact match on the clean set), so a missed claim is simply absent from the UI; all data is synthetic and the
thresholds are hand-set. Production-readiness has not been assessed.

---

## Original plan (kept for reference)
The sections below are the plan as written before implementation. Where they say "nothing exists" or describe the sketch API in
section 5, the status section above and [`api.md`](api.md) are authoritative.

## 1. Users and goals
| User | Needs |
|---|---|
| Fraud analyst | Triage alerts fast; understand *why* the system decided; see which evidence is authentic vs rejected; know what to do next. |
| Help-desk supervisor | See suspicious calls and what Agent A extracted; confirm that no caller claim was treated as fact. |
| Security admin | Verification authority/key status, replay and retrieval health, audit trail integrity. |

Non-goals for v1: approving/blocking actions from the UI, editing scores or rules, case management workflow, any write path to Meko.

## 2. Backend prerequisites (must exist before UI work starts)
The current repo is a library plus CLIs. A UI needs the following, in this order:

| # | Gap today | Required work | Why it blocks the UI |
|---|---|---|---|
| B1 | No API server | Thin **read-only HTTP API** (Node `http`, no framework) between browser and backend. The browser must never hold the Meko API key or any signing material. | Secrets must stay server-side. |
| B2 | Decisions are **ephemeral**: `assess()` returns an object and nothing persists it | An **append-only decision log** (e.g. `node:sqlite` or JSONL) with a hash chain (`prevHash`) and `modelVersion` / `extractorVersion` / `policyVersion` per record | Audit trail, history and the alert list cannot exist without it. |
| B3 | Agent A/B/authority activity is not recorded | An **activity/event log** (who wrote/read which memory ids, timings, errors) | "Agent activity" screen. |
| B4 | **Replay ledger is in-process memory** (lost on restart) | Persist consumed attestation nonces (in the decision log store) | Verification screen must show "spent/valid/expired" truthfully. |
| B5 | No case concept beyond a free-form `caseId` string | Derive a case from `(accountId, caseId)` in the log; add a case index | Case list/search. |
| B6 | No authentication/authorisation | Login + roles (`analyst`, `supervisor`, `admin`, all read-only in v1); access logging | Results contain personal data (names, roles, claims). |
| B7 | Caller-derived text appears in evidence strings | Contract: the API returns plain text; the UI must escape it (never `innerHTML`) | XSS from attacker-controlled call transcripts. |
| B8 | No data-retention/redaction policy | Define retention and redaction of caller text before storing | Privacy. |

Fields the UI can already use from `IdentitySecurityAgent.assess()`: `rawScore`, `displayScore`, `severity`, `baseAction`,
`recommendedAction`, `policy[]`, `stepUp.requirements[]`, `advisories[]`, `contributions[]` (source/label/kind/basePoints/weight/effectivePoints/text/memoryId),
`explanation[]`, `evidence[]`, `rejectedEvidence[]` (reason/detail/points), `verifiedFacts[]`, `unverifiedClaims[]`, `retrieved[]`,
`retrievalMeta[]` (strategy/truncated/usedFallback/scannedPages/complete), `retrievalComplete`, `contextAvailable` (false = degraded), `error`,
`timings.{retrievalMs,scoringMs}`, `eventId`.

## 3. Information architecture
```
Dashboard  ->  Alerts (queue)  ->  Case detail  ->  Decision detail (explanation + audit trail)
                                      |-> Agent activity & memory evidence
                                      |-> Verification status
Settings/Health (admin): authority key id, trust anchor, replay ledger, retrieval/Meko health
```

## 4. Screens
For every screen: **states** = loading, empty, error, degraded (`contextAvailable:false`), partial (`retrievalComplete:false`).

### 4.1 Fraud monitoring dashboard
* **Purpose:** situational awareness in under 10 seconds.
* **Content:** counts by action (`allow / step_up / block`) and severity over a selectable window; open alerts needing review;
  top risk drivers (most frequent contribution kinds); rejected-evidence count (tamper signal) with reasons; system health strip
  (Meko reachable, retrieval completeness rate, degraded decisions, verification-authority key id).
* **Notes:** show **severity from raw score**, never the 0-100 display score alone (the display curve flattens near the top).
  Charts need a text/table alternative.
* **Acceptance:** numbers reconcile exactly with the decision log; a degraded or incomplete decision is visibly counted, not hidden.

### 4.2 Risk alerts and severity
* **Queue** sorted by severity then recency. Row: severity badge (colour **and** text **and** icon), recommended action, event type, account (masked), time, key reason (top 2 contributions), flags: `REJECTED EVIDENCE`, `DEGRADED`, `INCOMPLETE CONTEXT`, `POLICY RAISED`.
* **Filters:** severity, action, event type, flag, time range, account; saved views.
* **Distinguish clearly:** `baseAction` (from score) vs `recommendedAction` (after policy). Example label: "Score says ALLOW - policy requires STEP-UP (sensitive action from unfamiliar device)".
* **Acceptance:** a forged-verification alert is unmistakable (red flag + reason code, e.g. `bad_signature`).

### 4.3 Case investigation details
* **Header:** case id, account (masked, reveal with logged action), events in the case, current recommended action.
* **Timeline** (merged): help-desk call facts -> verification issuances -> login/MFA/payroll events -> decisions.
* **Claims panel:** every caller claim as **CLAIMED - unverified**, never styled like a fact. Observed behaviours as **OBSERVED**.
* **Acceptance:** nothing labelled CLAIMED can appear in a "verified" visual style anywhere in the app.

### 4.3b Agent activity and memory evidence
* **Agent activity:** per agent (help-desk, identity, verification authority): memories written (ids, kinds, labels), retrievals (scope, bucket, results, truncated/fallback, pages, completeness), latency split (Meko vs agent).
* **Memory evidence table:** memory id, label badge, kind, statement (escaped plain text), writer agent, effect on score (+/-), whether it influenced the decision, link to the contribution.
* **Retrieval health:** show `truncated`, `usedFallback`, `scannedPages`, `complete` and the known Meko limits in a help popover.
* **Acceptance:** an analyst can trace any score point to a memory id.

### 4.4 Verification status
* **Per case:** each VERIFIED attestation: kind, method, issuer + key id, issued/expires, **authenticity result** (accepted / rejected + reason), single-use state (unspent / spent by event X / replayed).
* **Rejected records:** reason codes with plain-language meaning (`unknown_issuer_or_key`, `bad_signature`, `content_modified`, `account_mismatch`, `case_mismatch`, `expired`, `replayed`, ...) and the risk points they added.
* **Admin view:** trust anchor key id, last issuance, replay ledger size and persistence status.
* **Acceptance:** a record that failed verification is never shown with a green "verified" style; expired is distinguished from forged.

### 4.5 Recommended security actions
* Shows `stepUp.requirements[]` as an ordered checklist, `advisories[]` (e.g. `notify_user_new_country`), and what each action protects against.
* **v1 is advisory and read-only.** State explicitly that the UI does not enforce anything; enforcement lives in the (not yet existing) integration with real MFA/payroll systems.

### 4.6 Decision explanation and audit trail
* **Explanation:** waterfall of `contributions[]` (event, context, pattern, verified, integrity) with base x weight = effective points and the running total to raw score, severity band markers (25/50/75), then the policy step(s) that raised the action.
* **Audit trail:** the persisted decision record: inputs (event), retrieved memory ids and labels, authentication outcomes, versions, timings, `prevHash`; a "verify chain" action that recomputes hashes client-side or server-side and reports tampering.
* **Counterfactuals** (already computed in scenario runs): "without Meko context" and "without stored pattern" - helpful for analysts, labelled as simulations.
* **Acceptance:** two analysts reading the same decision reach the same understanding; the raw score and severity are shown first, the 0-100 display second.

## 5. API contract (read-only, v1)
```
GET /api/summary?from&to                 -> counts by action/severity, flags, health
GET /api/alerts?severity&action&flag&q   -> paged list of decision summaries
GET /api/cases/:caseId                   -> case header + timeline
GET /api/decisions/:id                   -> full decision record (fields in section 2) + hash-chain status
GET /api/cases/:caseId/evidence          -> memories with labels, effects, writers
GET /api/cases/:caseId/verification      -> attestations, authenticity, single-use state
GET /api/health                          -> Meko reachability, key id, ledger status, retrieval completeness rate
```
Contract rules: stable error shape, pagination, every record carries `modelVersion`, strings are plain text, ids are opaque, PII is
masked by default with an auditable reveal. Contract tests run against recorded fixtures (`reports/scenario-results.json` is the first fixture).

## 6. Technology approach (decision needed from you)
* **Recommended:** a single-page app with a small stack (Vite + a lightweight view library + plain CSS/tokens), no UI kit, no state library, charts as inline SVG. Rationale: matches the "no unnecessary dependencies" rule and keeps the security surface small.
* **Alternative:** server-rendered pages from the same Node process (fewest moving parts, weaker interactivity).
* **Not recommended for v1:** a heavy component library or a real-time stack. Polling every 10-30 s is enough; add SSE only if needed.
* Must-haves: responsive down to phone width, light/dark themes, keyboard navigation, WCAG 2.1 AA contrast, colour never the only severity signal, `prefers-reduced-motion`.

## 7. Security requirements for the UI
No secrets or keys in the browser; all caller-derived text rendered as text (never HTML); strict CSP; session cookies `HttpOnly` + `SameSite`; role checks on every API call; all views and reveals audit-logged; no write endpoints in v1; rate limiting; dependency pinning and review.

## 8. Delivery plan
| Phase | Deliverable | Exit criteria |
|---|---|---|
| F0 | Backend prerequisites B1-B8 (decision log, activity log, API, auth) | Contract tests green; replay ledger persisted; decision records reconstruct every field in section 2 |
| F1 | App shell, auth, Alerts queue, Decision detail (explanation waterfall) | Seven core + eleven hardening scenarios render correctly from fixtures; a11y checks pass |
| F2 | Case detail, evidence table, verification status | CLAIMED is never styled as verified (automated visual/DOM test); rejected evidence is unmistakable |
| F3 | Dashboard, Health, audit-chain verification | Dashboard totals reconcile with the log; tampered log is detected |
| F4 | Hardening: CSP, XSS tests with hostile transcripts, load test, usability review with analysts | No XSS in hostile-transcript suite; analyst task success measured |

## 9. Test plan
Component tests per screen state (loading/empty/error/degraded/partial); API contract tests on fixtures; XSS tests using attack
transcripts (brackets, `<script>`, `[ATTEST:...]`); visual regression in light/dark; automated a11y (axe) plus keyboard-only walk-through;
end-to-end against a stubbed backend replaying the scenario results; a "no fake verified" test asserting that only records with
`authenticity: accepted` receive the verified style.

## 10. Risks and open questions
* Where should the decision log live (local store vs also mirrored to Meko)? Mirroring raises tamper-evidence but also quota and privacy questions.
* Who consumes `advisories` / `stepUp` - there is no integration with a real MFA or payroll system yet; the UI can only display them.
* Analysts may over-trust the score. Show raw score, uncertainty flags and the synthetic-data/accuracy caveat in the UI itself.
* Extraction is brittle (English keyword lexicons): the UI must show *what was extracted*, so missed claims are visible by omission.
* Real help-desk data has not been used anywhere; thresholds and weights are hand-set.
