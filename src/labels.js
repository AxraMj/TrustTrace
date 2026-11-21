import { TrustViolationError } from './errors.js';

export const LABELS = Object.freeze({
  CLAIMED: 'CLAIMED', //   asserted by a person; unproven
  OBSERVED: 'OBSERVED', //  seen directly by a system/agent (behaviour, telemetry)
  VERIFIED: 'VERIFIED', //  independently confirmed AND cryptographically attested by the verification authority
});

const SAFE_ID = /^[A-Za-z0-9_.:-]+$/;
const B64URL = /^[A-Za-z0-9_-]+$/;

function safeId(name, value) {
  if (typeof value !== 'string' || !SAFE_ID.test(value)) {
    throw new TypeError(`${name} must match ${SAFE_ID} (got ${JSON.stringify(value)})`);
  }
  return value;
}

/** Canonical form of a statement: the exact string stored in Meko AND hashed into attestations. */
export function canonicalStatement(statement) {
  return String(statement).replace(/\s+/g, ' ').trim();
}

/**
 * Serialize a fact to the text stored in Meko. Meko stores memory_add text as written, so the trust
 * label is part of the stored text itself (and mirrored in metadata).
 *
 * VERIFIED is only formattable together with an `attestation` (a signed envelope produced by the
 * verification authority, see src/trust/). The header alone never makes anything trusted: Agent B
 * verifies the signature and its bindings before accepting VERIFIED evidence.
 */
export function formatMemory({ caseId, accountId, runId, label, kind, statement, verifiedBy, attestation }) {
  if (!Object.values(LABELS).includes(label)) {
    throw new TrustViolationError(`Unknown trust label: ${String(label)}`);
  }
  if (label === LABELS.VERIFIED) {
    if (!verifiedBy) throw new TrustViolationError('VERIFIED requires verifiedBy (the independent verification method).');
    if (typeof attestation !== 'string' || !B64URL.test(attestation)) {
      throw new TrustViolationError('VERIFIED requires a signed attestation from the verification authority.');
    }
  } else if (verifiedBy || attestation) {
    throw new TrustViolationError(`verifiedBy/attestation are only valid with VERIFIED, not ${label}.`);
  }
  if (typeof statement !== 'string' || !statement.trim()) {
    throw new TypeError('statement must be a non-empty string');
  }
  const header =
    `[TRUSTTRACE v1][CASE:${safeId('caseId', caseId)}][ACCOUNT:${safeId('accountId', accountId)}]` +
    `[RUN:${safeId('runId', runId)}][LABEL:${label}][KIND:${safeId('kind', kind)}]` +
    (verifiedBy ? `[VERIFIED_BY:${safeId('verifiedBy', verifiedBy)}]` : '');
  return `${header} ${canonicalStatement(statement)}` + (attestation ? ` [ATTEST:${attestation}]` : '');
}

const HEADER =
  /^\[TRUSTTRACE v1\]\[CASE:([^\]]+)\]\[ACCOUNT:([^\]]+)\]\[RUN:([^\]]+)\]\[LABEL:(CLAIMED|OBSERVED|VERIFIED)\]\[KIND:([^\]]+)\](?:\[VERIFIED_BY:([^\]]+)\])? (.*)$/s;
const ATTEST_TAIL = /^(.*) \[ATTEST:([A-Za-z0-9_-]+)\]$/s;

/**
 * Parse a stored memory. The header is anchored at the very start, so label-like text inside a
 * caller's statement cannot change the label or the account. Parsing does NOT establish trust:
 * a memory that says LABEL:VERIFIED is only a *claim* of verification until Agent B has checked its
 * signature. Text that is not a TrustTrace memory gets label UNTRUSTED and is never used.
 */
export function parseMemory(text) {
  const m = typeof text === 'string' ? HEADER.exec(text) : null;
  if (!m) return { label: 'UNTRUSTED', trusttrace: false, statement: String(text ?? '') };
  const [, caseId, accountId, runId, label, kind, verifiedBy, rest] = m;
  let statement = rest;
  let attestation = null;
  if (label === LABELS.VERIFIED) {
    const t = ATTEST_TAIL.exec(rest);
    if (t) [, statement, attestation] = t;
  }
  return { trusttrace: true, caseId, accountId, runId, label, kind, verifiedBy: verifiedBy ?? null, attestation, statement };
}
