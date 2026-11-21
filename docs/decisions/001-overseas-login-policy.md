# Decision 001 - sign-in from a new country (review of scenario H1)

Status: **decided, Phase 4** - keep `allow`, add a mandatory out-of-band notification (`advisories`).
Scope: ordinary sign-ins (`login`). Sensitive actions (MFA change, payroll change, password reset) are governed by
the sensitive-action policy, not by this decision.

## The question
H1 ("legitimate overseas traveller: known laptop, plain login") was `allow` at raw 15. Phase 3 flagged this as possibly
too lenient: should a login from a country the account has never used require step-up?

## Options considered
| Option | Effect | Why / why not |
|---|---|---|
| A. Always step up on a new country | every business trip triggers an extra challenge | high friction for legitimate travellers (the common case); alert fatigue; pushes users to weaker bypasses. Rejected. |
| **B. Allow when the device is known and nothing else is wrong, but notify the holder out-of-band (chosen)** | no friction; the holder can revoke if the login was not theirs | keeps the signal visible and actionable without punishing the common case. |
| C. Allow silently (Phase 3 behaviour) | no friction, no visibility | a stolen session replayed from abroad would go unnoticed. Rejected. |

## What the system does now
* New country + known device + no other risk -> `allow`, raw 15, **advisory `notify_user_new_country`**.
* New country combined with anything else escalates on its own, with no extra rules:
  * + new device -> raw 30 -> `step_up` (scenario S3)
  * + poor IP reputation -> raw 35 -> `step_up`
  * + a suspicious help-desk call in Meko -> context counts at full weight (a new country makes the event "sensitive"), e.g. the CFO story gives raw 40 -> `step_up`, and a heavier story blocks
  * + attested new device (`device_verified`) -> `allow` (the owner vouched for it)
* Sensitive actions from a new country are never `allow`: the sensitive-action policy requires step-up (scenario H2).
* Thresholds, weights and the severity bands are unchanged by this decision.

## Residual risk (accepted, not solved)
* "Known device" is a claim made by the event producer. If an attacker replays a stolen session cookie, the device may look
  known; the only mitigation here is the notification. Token binding / continuous session risk is out of scope.
* The notification is only an advisory string in the result: nothing in this repository delivers it. A real deployment must
  wire `advisories` to an actual notification channel, and monitor that channel's own integrity.
* A traveller whose phone is also abroad will see notifications on the same device: the advisory helps only if the holder has
  a second channel.

## Review triggers
Revisit if: false-negative reports show takeovers that began with a new-country login on a "known" device; the alert
volume from the advisory is unmanageable; or session/device binding becomes available (then step up when binding is absent).

## Tests
`test/policy.test.js` pins each row above (including the escalation combinations).
