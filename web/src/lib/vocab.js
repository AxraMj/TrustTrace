// Plain-language meaning of the backend's codes. Unknown codes fall back to the raw code (never hidden, never invented).

export { humanize } from './format.js';

export const SEVERITIES =['critical', 'high', 'medium', 'low'];
export const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
export const SEVERITY_BANDS = { low: '< 25', medium: '25 – 49', high: '50 – 74', critical: '≥ 75' };
export const ACTION_RANK = { allow: 0, step_up: 1, block: 2 };
export const ACTION_LABEL = { allow: 'Allow', step_up: 'Step-up', block: 'Block' };

export const FLAG_INFO = {
  rejected_evidence: { label: 'Rejected evidence', short: 'REJECTED EVIDENCE', help: 'A record claimed to be VERIFIED but failed authentication (forged, tampered, expired, replayed…). It was not trusted.' },
  degraded: { label: 'Degraded', short: 'DEGRADED', help: 'Shared memory (Meko) could not be read, so this decision used the event alone. Treat "no risk found" with suspicion.' },
  incomplete_context: { label: 'Incomplete context', short: 'INCOMPLETE CONTEXT', help: 'Retrieval could not prove it saw every relevant memory, so absence of evidence is not trusted.' },
  policy_raised: { label: 'Policy raised', short: 'POLICY RAISED', help: 'The sensitive-action policy raised the action above what the score alone said.' },
};

// category: forged = authenticity failed; stale = was genuine but out of date; replay = genuine but already used; system = infrastructure
export const REJECTION_INFO = {
  unknown_issuer_or_key: { category: 'forged', title: 'Unknown issuer or key', text: 'Signed by a key the system does not trust — the signature is not from the verification authority.' },
  bad_signature: { category: 'forged', title: 'Bad signature', text: 'The signature does not match the content. The record was forged or damaged.' },
  missing_attestation: { category: 'forged', title: 'No attestation', text: 'The record says VERIFIED but carries no signed attestation at all.' },
  content_modified: { category: 'forged', title: 'Content modified', text: 'The statement was changed after it was signed.' },
  account_mismatch: { category: 'forged', title: 'Wrong account', text: 'A genuine attestation, but issued for a different account. It cannot vouch for this one.' },
  case_mismatch: { category: 'forged', title: 'Wrong case', text: 'A genuine attestation, but issued for a different case.' },
  expired: { category: 'stale', title: 'Expired', text: 'Genuine, but past its validity window. Not forged — just too old to rely on.' },
  replayed: { category: 'replay', title: 'Already used (replay)', text: 'A genuine single-use attestation that was already spent on an earlier event. Re-using it is not allowed.' },
  replay_ledger_unavailable: { category: 'system', title: 'Replay ledger unavailable', text: 'The single-use check could not be completed, so the attestation was not trusted.' },
};
export const rejectionInfo = (code) => REJECTION_INFO[code] ?? { category: 'forged', title: code, text: 'Rejected by the verifier.' };

export const TRUST_INFO = {
  unverified_claim: { label: 'CLAIMED', sub: 'unverified', help: 'Something a caller said. Never a fact, and it never lowers risk.' },
  observed: { label: 'OBSERVED', sub: 'system saw it', help: 'A behaviour observed by a system or agent (not self-reported).' },
  verified_authentic: { label: 'VERIFIED', sub: 'authentic', help: 'Signature and bindings were checked and accepted for this decision.' },
  verified_unused: { label: 'VERIFIED', sub: 'not used', help: 'Labelled VERIFIED but not used in the score of the decisions shown.' },
  rejected: { label: 'REJECTED', sub: 'failed verification', help: 'Claimed to be VERIFIED but failed authentication. Not trusted; not an observation.' },
  unknown: { label: 'UNKNOWN', sub: '', help: 'Trust class could not be determined.' },
};

export const SOURCE_INFO = {
  event: 'Event', context: 'Context (Meko)', pattern: 'Stored pattern', verified: 'Verified evidence', integrity: 'Integrity',
};

export const ATTESTATION_STATUS = {
  valid: { label: 'Valid', help: 'Issued, not expired, not yet used.' },
  spent: { label: 'Spent', help: 'Single-use attestation already consumed by an event.' },
  expired: { label: 'Expired', help: 'Past its validity window without being used.' },
};

export const ACTIVITY_KIND = {
  memory_written: 'Memory written', memory_write_failed: 'Memory write failed', memories_retrieved: 'Memories retrieved', memory_deleted: 'Memory deleted',
  decision_made: 'Decision made', decision_failed: 'Decision failed', memory_written_raw: 'Memory written (raw)',
};
export const AGENT_NAME = {
  trusttrace_helpdesk_agent: 'Help-desk agent (A)', trusttrace_identity_security_agent: 'Identity-security agent (B)',
  trusttrace_verification_authority: 'Verification authority', trusttrace_attacker_sim: 'Attacker simulation',
};
export const agentName = (id) => AGENT_NAME[id] ?? id ?? '—';

export const EVENT_TYPE = {
  login: 'Login', mfa_change: 'MFA change', bank_detail_change: 'Bank / payroll change', password_reset: 'Password reset', privilege_change: 'Privilege change',
};
export const eventType = (t) => EVENT_TYPE[t] ?? (t ? t.replace(/_/g, ' ') : '—');

export const WINDOW_LABEL = { '15m': 'Last 15 min', '1h': 'Last hour', '6h': 'Last 6 h', '24h': 'Last 24 h', '7d': 'Last 7 days', '30d': 'Last 30 days', '90d': 'Last 90 days', all: 'All time' };
