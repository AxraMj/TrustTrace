// Scores an extractor against labelled utterances. Pure function; no I/O.
// An extractor is `(text) => string[]` returning the claim/observation kinds it found.
export const EVALUATED_KINDS = Object.freeze([
  'role_claim', 'identity_claim', 'lost_device_claim', 'mfa_unavailable_claim', 'request_mfa_reset', 'request_password_reset',
  'request_contact_change', 'request_bank_detail_change', 'urgency_pressure', 'authority_pressure', 'verification_resistance',
]);

const r3 = (x) => Math.round(x * 1000) / 1000;

export function evaluateExtraction(extractKinds, cases) {
  const perKind = Object.fromEntries(EVALUATED_KINDS.map((k) => [k, { tp: 0, fp: 0, fn: 0 }]));
  const perGroup = {};
  const misses = [];
  let exact = 0;
  for (const c of cases) {
    const got = new Set(extractKinds(c.text).filter((k) => EVALUATED_KINDS.includes(k)));
    const want = new Set(c.expected);
    const missing = [...want].filter((k) => !got.has(k));
    const extra = [...got].filter((k) => !want.has(k));
    for (const k of EVALUATED_KINDS) {
      if (want.has(k) && got.has(k)) perKind[k].tp++;
      else if (got.has(k)) perKind[k].fp++;
      else if (want.has(k)) perKind[k].fn++;
    }
    const ok = !missing.length && !extra.length;
    if (ok) exact++;
    else misses.push({ id: c.id, group: c.group, text: c.text, missing, extra });
    const g = (perGroup[c.group] ??= { n: 0, exact: 0 });
    g.n++;
    if (ok) g.exact++;
  }
  const sum = (f) => EVALUATED_KINDS.reduce((a, k) => a + perKind[k][f], 0);
  const tp = sum('tp'), fp = sum('fp'), fn = sum('fn');
  return {
    cases: cases.length,
    exactMatch: exact,
    exactMatchRate: r3(exact / cases.length),
    precision: r3(tp / Math.max(1, tp + fp)),
    recall: r3(tp / Math.max(1, tp + fn)),
    tp, fp, fn,
    perGroup,
    perKind: Object.fromEntries(Object.entries(perKind).map(([k, v]) => [k, { ...v, precision: r3(v.tp / Math.max(1, v.tp + v.fp)), recall: r3(v.tp / Math.max(1, v.tp + v.fn)) }])),
    misses,
  };
}
