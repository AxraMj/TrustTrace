# TrustTrace REST API (v1, read-only)

Base: `http://127.0.0.1:8787` (see `docs/database.md`). All responses are JSON with `Cache-Control: no-store`; every response carries
`X-Request-Id`. Strings that come from callers (statements, names) are **plain text and must be escaped/rendered as text, never as HTML**.

**Data source.** Everything comes from PostgreSQL (the decision log, agent events, attestation ledger, audit chain). Nothing is
hardcoded; an empty database returns zeros and empty lists. The API server never holds the Meko key or any signing key and does
**not** query Meko: "memory evidence" is the snapshot recorded when each decision was made.

## Authentication and roles
`POST /api/auth/login {username,password}` sets an `HttpOnly; SameSite=Strict` cookie `tt_session` (a `Bearer` token also works for
non-browser clients). `POST /api/auth/logout`, `GET /api/auth/me`. Roles (all read-only in v1):

| Role | Access |
|---|---|
| analyst | every investigation endpoint below |
| supervisor | analyst + `/api/audit`, `/api/audit/head` |
| admin | supervisor + `/api/health/details`, `/api/audit/verify` |

Every authenticated request is written to `access_log` (user, path, status, ip, request id). Any write method returns **405**.

## Conventions
* **Time range** (`window=15m|1h|6h|24h|7d|30d|90d|all` or `from`/`to` ISO-8601; not both). Defaults: summary/activity 24h, alerts 7d, cases/verification 30d.
* **Pagination** (lists): `limit` (default 50, max 200) and opaque `cursor`; response has `nextCursor` (null on the last page). Keyset-based,
  stable under concurrent inserts. Audit uses `afterSeq` / `nextAfterSeq`.
* **Validation:** unknown or repeated query parameters, bad enums, bad limits, bad cursors and bad dates are **400** `invalid_parameter`.
* **Errors:** `{ "error": { "code", "message", "requestId" } }`. 401 `unauthenticated`/`session_expired`, 403 `forbidden`, 404 `*_not_found`, 429 `rate_limited`.
* **Filters** are whitelists; `q` is a literal substring search (LIKE metacharacters are escaped).
* Every body has `meta: { generatedAt, source: "postgresql", window, from, to }`.

## Endpoints
| Endpoint | Purpose | Key fields |
|---|---|---|
| `GET /api/meta` | vocabulary for filters | `severities, actions, flags, windows, attestationStatuses, auditTypes, versions` |
| `GET /api/summary` | dashboard | `totals, bySeverity, byAction, bySeverityAndAction, byEventType, flags{degraded,incompleteContext,rejectedEvidence,policyRaised}, rejectedReasons, policyRules, topDrivers, series{bucket,points}, agents, attestations, latencyMs` |
| `GET /api/alerts?severity&action&eventType&flag&q` | risk alert queue | item: `id, createdAt, eventType, accountId, caseId, severity, rawScore, displayScore, baseAction, recommendedAction, flags[], topReasons[2], rejectedCount` |
| `GET /api/decisions/:id` | decision explanation | `decision` (all contributions, explanation, policy, stepUp, advisories, rejectedEvidence, retrieved, retrievalMeta, timings, versions), `integrity{auditRecordFound,payloadHashMatches}`, `audit{seq,hashes}`, `attestationsSpent`, `activity`, `neighbours{previous,next}` |
| `GET /api/decisions/:id/evidence` | memory evidence of one decision | see below |
| `GET /api/cases?q&severity` | case list | `accountId, caseId, firstSeen, lastSeen, decisionCount, maxSeverity, latestDecision` |
| `GET /api/cases/:accountId/:caseId` | case header | `counts{decisions,agentEvents,attestations,decisionsWithRejectedEvidence,degradedDecisions}, latestDecision` |
| `.../timeline` | merged chronological story | items typed `decision`, `agent_event`, `attestation_issued`, `attestation_consumed`; `truncated` |
| `.../decisions` | the case's decisions (alert items) | paged |
| `.../evidence` | memory evidence across the case | see below |
| `.../verification` | attestations + rejections of the case | `attestations[{status,singleUse,...}], rejections[{reason,detail,points,...}]` |
| `.../activity` | agent events of the case | paged |
| `GET /api/activity?agentId&kind&accountId&caseId&decisionId&ok` | agent activity | `agentId, kind, memoryIds, durationMs, ok, error, payload` |
| `GET /api/verification/attestations?status&kind&accountId&caseId` | attestation ledger | `status: valid|spent|expired`, `singleUse`, `consumedEventId`, `decisionId` (never the signature) |
| `GET /api/verification/rejections?reason` | records that claimed VERIFIED but failed authentication | `reason, detail, points, decisionId` |
| `GET /api/verification/keys` | trust-anchor key ids seen in decisions | `keyId, decisions, lastUsedAt` |
| `GET /api/audit?type&refId&afterSeq` (supervisor+) | audit chain history | `seq, recordType, refId, payloadHash, prevHash, recordHash` |
| `GET /api/audit/head` (supervisor+) | chain head, for external anchoring | `seq, hash` |
| `GET /api/audit/verify` (admin) | re-verify the whole chain | `ok, checked, head, problems[]` |

Path ids must be percent-encoded (`encodeURIComponent`); they are decoded exactly once.

### Memory evidence (`.../evidence`)
`memories[]`: `memoryId, label (CLAIMED|OBSERVED|VERIFIED), kind, statement, trust, writer{agentId,at}|null, usage[], rejectedIn[], netEffectPoints`.
`trust` is the classification the UI must use: `unverified_claim` (CLAIMED: never a fact, never lowers risk), `observed`,
`verified_authentic` (signature and bindings accepted), `rejected` (claimed VERIFIED but failed authentication), `verified_unused`.
`rejected[]` lists each failed record with its reason code. `writer` comes from the recorded activity and is `null` when unknown (never guessed).

### Flags on an alert
`rejected_evidence`, `degraded` (Meko unreachable: decided on the event alone), `incomplete_context` (retrieval not provably complete),
`policy_raised` (the sensitive-action policy raised the action above what the score alone said; compare `baseAction` and `recommendedAction`).

## Honest limits
* Evidence is a decision-time snapshot, not live Meko state. Writers are known only for memories written through the instrumented path
  (`npm run scenarios -- --persist`); events recorded outside it have no activity rows.
* Account/case ids and caller-derived statements are returned unmasked to every authenticated role (no redaction/retention policy yet).
* `integrity.payloadHashMatches` re-hashes the stored decision against its audit record; a database superuser who rewrites both the
  decision and the entire later chain is only detectable against an externally stored chain head (`/api/audit/head`).
* Rate limits are per process and in memory.
