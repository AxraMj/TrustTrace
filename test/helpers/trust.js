// Test helper: a verification authority with an EPHEMERAL key, the matching verifier (public key only),
// and a builder for signed, already-parsed memories (what Agent B sees after retrieval).
import { formatMemory, parseMemory } from '../../src/labels.js';
import { VerificationAuthority } from '../../src/trust/authority.js';
import { AttestationVerifier } from '../../src/trust/verifier.js';

/** A controllable clock: `t.now` can be moved to test expiry / future-dated records. */
export function makeClock(start = Date.now()) {
  const c = { now: start, fn: () => c.now, advance(ms) { c.now += ms; } };
  return c;
}

export function makeTrust({ clock = makeClock() } = {}) {
  const authority = VerificationAuthority.ephemeral({ clock: clock.fn });
  const verifier = new AttestationVerifier({ trustAnchors: [authority.trustAnchor], clock: clock.fn });
  let n = 0;
  /** A parsed VERIFIED memory exactly as Agent B would retrieve it from Meko. */
  function signedMemory({ kind = 'callback_verified', statement = 'Callback confirmed owner', accountId, caseId = 'case-t', method = 'callback_on_file', ttlMs, runId = 'run-t' }) {
    const { attestation } = authority.issue({ caseId, accountId, kind, method, statement, ttlMs });
    const text = formatMemory({ caseId, accountId, runId, label: 'VERIFIED', kind, statement, verifiedBy: method, attestation });
    return { id: `signed-${++n}`, ...parseMemory(text), text };
  }
  return { clock, authority, verifier, signedMemory };
}
