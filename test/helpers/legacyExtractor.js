// BASELINE ONLY: the Phase 1-3 regex extraction rules, reproduced verbatim so Phase-4 improvements can be measured
// against them on the same utterances. Not used by the product.
const CLAIM_RULES = [
  { kind: 'identity_claim', re: /\b(?:[Ii](?: am|'m)|[Tt]his is|[Mm]y name is)\s+([A-Z][\w'-]*(?:\s+[A-Z][\w'-]*){0,2})/ },
  { kind: 'role_claim', re: /\b(?:i am|i'm)\s+(?:the\s+|a\s+|an\s+)?(cfo|ceo|cto|executive|director|vp|manager|administrator|it admin|contractor)\b/i },
  { kind: 'lost_device_claim', re: /\b(?:lost|broke|broken|stolen|replaced|new)\s+(?:my\s+)?(?:phone|device|laptop)\b|\bphone\s+(?:was\s+)?(?:lost|stolen|broken)\b/i },
  { kind: 'mfa_unavailable_claim', re: /\b(?:can't|cannot|can not|unable to|don't have|do not have)\s+(?:get|receive|access|use)?\s*(?:the\s+|my\s+)?(?:mfa|2fa|verification|authenticator|one[- ]time|otp|code)/i },
  { kind: 'request_mfa_reset', re: /\b(?:reset|remove|disable|change|bypass)\s+(?:my\s+|the\s+)?(?:mfa|2fa|two[- ]factor|authenticator)|\b(?:mfa|2fa|two[- ]factor|authenticator)\s+(?:reset|removal|bypass)\b/i },
  { kind: 'request_password_reset', re: /\b(?:reset|change)\s+(?:my\s+|the\s+)?password\b|\bpassword\s+(?:reset|change)\b/i },
  { kind: 'request_contact_change', re: /\b(?:change|update|add)\s+(?:my\s+|the\s+)?(?:phone number|email|recovery)/i },
  { kind: 'urgency_pressure', re: /\b(?:urgent|urgently|immediately|right now|asap|emergency|hurry)\b/i },
  { kind: 'authority_pressure', re: /\b(?:my boss|the ceo|executive|will be (?:very )?upset|get you fired|escalate)\b/i },
  { kind: 'verification_resistance', re: /\b(?:skip|without|no need for|don't need)\s+(?:the\s+)?(?:verification|security questions|callback)|\brefuse[sd]?\s+(?:to\s+)?(?:verify|answer)/i },
];
export function legacyKinds(text) {
  return CLAIM_RULES.filter((r) => r.re.test(text)).map((r) => r.kind);
}
