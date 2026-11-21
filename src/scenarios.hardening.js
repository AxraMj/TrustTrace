// Phase 3 HARDENING scenarios: different wording, event combinations, forgeries.
//
// Expected outcomes were written BEFORE running them, from what a fraud analyst would want - not from
// the scorer's behaviour. The scorer and extraction rules are NOT tuned to make these pass: where they
// disagree, the result is reported as a FALSE_POSITIVE (system too severe) or FALSE_NEGATIVE (too lenient).
// Action severity order: allow < step_up < block.
//
// interaction fields: scope ('account'|'org'), callerText, observations, verifications (reported checks, never trusted),
// attestations (signed by the verification authority), forgeries (attacker-planted records, see src/adversary.js).

/**
 * Genuine detection gaps found by these scenarios. They are NOT fixed by tuning (that would defeat the point of
 * independent testing); they are listed so the corresponding tests stay visible as TODOs with the reason.
 */
export const KNOWN_GAPS = {
  // Phase 4: H10 (reworded repeat attack) is FIXED by the concept-matcher extraction; it is no longer a known gap.
};

const PATTERN_ATTESTATION = {
  kind: 'confirmed_attack_pattern',
  statement: 'Confirmed incident INC-3310: executive impersonation takeover. signature=role_claim,lost_device_claim,request_mfa_reset',
  method: 'incident_review',
};
const CFO_STORY = "Hi, I'm the CFO. I lost my phone, please reset my MFA.";

export const HARDENING_SCENARIOS = [
  // ---------- legitimate (false-positive checks): must NOT be blocked ----------
  {
    id: 'H1', title: 'Legitimate overseas traveller: known laptop, plain login',
    interactions: [], event: { type: 'login', newCountry: true },
    expected: { actions: ['allow', 'step_up'] },
  },
  {
    id: 'H2', title: 'Legitimate traveller, laptop stolen abroad: verified callback, MFA change on new device in new country',
    interactions: [{
      scope: 'account',
      callerText: "Hello, this is Elena Petrov. I'm travelling for work and my laptop was stolen at the airport, so I'm on a borrowed device. I'd like to move my authenticator over to a new handset.",
      attestations: [{ kind: 'callback_verified', statement: 'Callback to the registered number confirmed the account owner.', method: 'callback_on_file' }],
    }],
    event: { type: 'mfa_change', newDevice: true, newCountry: true },
    expected: { actions: ['step_up'], policyRules: ['sensitive_action_from_unfamiliar_context'] },
  },
  {
    id: 'H13', title: 'Legitimate payroll change from known device right after a verified callback',
    interactions: [{
      scope: 'account',
      callerText: "Hi, it's Tomas Reyes. I've switched banks, can you help me change my direct deposit account?",
      attestations: [{ kind: 'callback_verified', statement: 'Callback to the registered number confirmed the account owner.', method: 'callback_on_file' }],
    }],
    event: { type: 'bank_detail_change' },
    expected: { actions: ['step_up'], policyRules: ['bank_detail_change_requires_step_up'] },
  },
  {
    id: 'H15', title: 'Legitimate but stressed user (urgent tone) with verified callback, then routine login',
    interactions: [{
      scope: 'account',
      callerText: "This is Anika Rao and it's urgent, I'm presenting in ten minutes and I can't log in. I need my password reset right now please.",
      attestations: [{ kind: 'identity_verified', statement: 'Identity confirmed via registered authenticator push.', method: 'authenticator_push' }],
    }],
    event: { type: 'login' },
    expected: { actions: ['allow', 'step_up'] },
  },

  // ---------- forged / tampered verification (false-negative checks): must be rejected, attacks blocked ----------
  ...[
    ['H3', 'attacker_key', 'signed with the attacker\'s own key', ['unknown_issuer_or_key']],
    ['H4', 'spoofed_kid', 'claims the real authority\'s key id', ['bad_signature']],
    ['H5', 'unsigned_header', 'legacy unsigned VERIFIED_BY header', ['missing_attestation']],
    ['H6', 'tampered_statement', 'real attestation re-used with altered text', ['content_modified']],
    ['H7', 'wrong_account', 'real attestation copied from another account', ['account_mismatch']],
    ['H8', 'expired', 'expired real attestation re-stored', ['expired']],
  ].map(([id, mode, what, rejected]) => ({
    id, title: `CFO takeover backed by a forged verification (${what})`,
    interactions: [{
      scope: 'account', callerText: CFO_STORY,
      forgeries: [{ mode, kind: 'callback_verified', method: 'callback_on_file', statement: 'Callback confirmed the caller is the account owner.' }],
    }],
    event: { type: 'mfa_change', newDevice: true },
    expected: { actions: ['block'], rejected },
  })),

  // ---------- repeat attacks ----------
  {
    id: 'H9', title: 'Repeat attack, SAME wording as the stored verified pattern (control)',
    interactions: [{ scope: 'org', callerText: '', attestations: [PATTERN_ATTESTATION] }, { scope: 'account', callerText: CFO_STORY }],
    event: { type: 'mfa_change', newDevice: true },
    expected: { actions: ['block'], influences: ['pattern'] },
  },
  {
    id: 'H10', title: 'Repeat attack, REWORDED so the stored pattern keywords do not appear',
    interactions: [
      { scope: 'org', callerText: '', attestations: [PATTERN_ATTESTATION] },
      { scope: 'account', callerText: "Good morning, I'm one of the directors. My handset got stolen last night. Could you wipe my second factor and attach it to a new number?" },
    ],
    event: { type: 'mfa_change', newDevice: true },
    // Phase 4: the reworded call must still match the stored VERIFIED pattern, via evidence extracted from the language.
    expected: { actions: ['block'], influences: ['pattern'], evidenceKinds: ['role_claim', 'lost_device_claim', 'request_mfa_reset'] },
  },

  // ---------- compromised payroll ----------
  {
    id: 'H11', title: 'Compromised payroll change: stolen credentials, new device AND country, no call at all',
    interactions: [], event: { type: 'bank_detail_change', newDevice: true, newCountry: true },
    expected: { actions: ['block'] },
  },
  {
    id: 'H12', title: 'Compromised payroll change from the usual device after a compromise indicator (malware)',
    interactions: [{
      scope: 'account', callerText: '',
      observations: [{ kind: 'identity_compromise_indicator', statement: 'Password reset by an unfamiliar actor 40 minutes earlier.' }],
    }],
    event: { type: 'bank_detail_change' },
    expected: { actions: ['block'] },
  },

  // ---------- polished social engineering / combinations ----------
  {
    id: 'H14', title: 'Urgent, reworded reset + second-factor swap request from a new device',
    interactions: [{
      scope: 'account',
      callerText: "Good afternoon, Marcus here from finance, I'm locked out of everything and need back in urgently, the boss is waiting. Can you send me a reset and switch my second factor to my new number?",
    }],
    event: { type: 'mfa_change', newDevice: true },
    // Phase 4: previously passed only because of the policy floor (Agent A extracted almost nothing). The acceptance
    // criterion is now that the language-derived evidence itself moves the score.
    expected: { actions: ['step_up', 'block'], evidenceKinds: ['request_password_reset', 'request_mfa_reset', 'urgency_pressure', 'authority_pressure'] },
  },
  {
    id: 'H16', title: 'Calm, polished pretext (no pressure, caller ID fine) asking for a deposit-account update, from a new device',
    interactions: [{
      scope: 'account',
      callerText: "Hello, it's Jordan Pike in accounts. For the new financial year please update the direct-deposit account on my profile to the details I'll read out.",
    }],
    event: { type: 'bank_detail_change', newDevice: true },
    expected: { actions: ['step_up', 'block'], evidenceKinds: ['request_bank_detail_change'] },
  },
];

