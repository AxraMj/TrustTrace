// Deterministic fraud scenarios. Expected outcomes are decided from fraud logic (what a security
// analyst would want), NOT tuned to whatever the scorer outputs. If the scorer disagrees, the
// scenario fails and that is reported as a defect.
//
// interaction.scope: 'account' -> saved under the scenario's account; 'org' -> saved under the org id
// (org-wide, e.g. a previously VERIFIED attack pattern from another incident).

const CFO_CALL =
  "Hi, this is Dana Whitfield, I'm the CFO. I lost my phone and can't get my MFA code. Please reset my MFA immediately, skip the verification, it's urgent.";

export const SCENARIOS = [
  {
    id: 'S1',
    title: 'Normal login from a known device',
    interactions: [],
    event: { type: 'login' },
    expected: { actions: ['allow'], severities: ['low'], memoriesRetrieved: false, influences: [] },
  },
  {
    id: 'S2',
    title: 'Suspicious help-desk call, then a routine login',
    interactions: [
      {
        scope: 'account',
        callerText: "This is Marcus Lee, I'm the director. I need my password reset right now, it's urgent, skip the security questions.",
        observations: [{ kind: 'caller_id_mismatch', statement: 'Inbound caller ID does not match the number on file.' }],
      },
    ],
    event: { type: 'login' },
    // Suspicious call raises concern, but a known-device login must not be hard-blocked.
    expected: { actions: ['step_up'], severities: ['medium'], memoriesRetrieved: true, influences: ['context'] },
  },
  {
    id: 'S3',
    title: 'Login from an unrecognized device and country',
    interactions: [],
    event: { type: 'login', newDevice: true, newCountry: true },
    expected: { actions: ['step_up'], severities: ['medium'], memoriesRetrieved: false, influences: [] },
  },
  {
    id: 'S4',
    title: 'MFA reset after a suspicious help-desk interaction',
    interactions: [
      {
        scope: 'account',
        callerText: CFO_CALL,
        observations: [{ kind: 'caller_id_mismatch', statement: 'Inbound caller ID does not match the number on file.' }],
      },
    ],
    event: { type: 'mfa_change', newDevice: true, newCountry: true },
    expected: { actions: ['block'], severities: ['critical'], memoriesRetrieved: true, influences: ['context'] },
  },
  {
    id: 'S5',
    title: 'Payroll bank-detail change after identity compromise',
    interactions: [
      {
        scope: 'account',
        callerText: "I'm an administrator. I lost my phone, please change my phone number and email, it's urgent.",
        observations: [
          { kind: 'identity_compromise_indicator', statement: 'MFA on this account was reset within the last hour after a help-desk call that failed verification.' },
        ],
      },
    ],
    event: { type: 'bank_detail_change', newDevice: true },
    expected: { actions: ['block'], severities: ['critical', 'high'], memoriesRetrieved: true, influences: ['context'] },
  },
  {
    id: 'S6',
    title: 'Verified callback confirming the legitimate user',
    interactions: [
      {
        scope: 'account',
        callerText: "This is Priya Nair. I got a new phone and can't get my MFA code. Can you reset my MFA?",
        // Signed by the verification authority (the only component able to create VERIFIED evidence).
        attestations: [
          { kind: 'callback_verified', statement: 'Callback to the number on file confirmed the caller is the account owner.', method: 'callback_on_file' },
        ],
      },
    ],
    event: { type: 'mfa_change', newDevice: true },
    // Phase 3 review: a verified callback proves WHO is calling, not that the unfamiliar device is theirs.
    // It lowers the risk score (so no block) but must NOT authorise a sensitive MFA change by itself: step-up.
    expected: { actions: ['step_up'], severities: ['low', 'medium'], memoriesRetrieved: true, influences: ['verified'], policyRules: ['sensitive_action_from_unfamiliar_context'] },
  },
  {
    id: 'S7',
    title: 'Repeat attack matching a previously stored VERIFIED attack pattern',
    interactions: [
      {
        scope: 'org',
        callerText: '',
        attestations: [
          {
            kind: 'confirmed_attack_pattern',
            statement: 'Confirmed incident INC-2291: executive impersonation takeover. signature=role_claim,lost_device_claim,request_mfa_reset',
            method: 'incident_review',
          },
        ],
      },
      { scope: 'account', callerText: "Hello, I'm the CFO. I lost my phone, please reset my MFA." },
    ],
    event: { type: 'mfa_change' },
    // Without the stored pattern this case is only medium (step_up); the pattern must escalate it.
    expected: { actions: ['block'], severities: ['critical', 'high'], memoriesRetrieved: true, influences: ['pattern'] },
  },
];
