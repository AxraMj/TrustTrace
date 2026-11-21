import { Card, PageHeader } from '../components/ui.jsx';
import { TrustBadge } from '../components/badges.jsx';
import { TRUST_INFO } from '../lib/vocab.js';

export function About() {
  return (
    <div className="page">
      <PageHeader title="About this view" subtitle="How to read TrustTrace, and what it cannot tell you." />
      <Card title="Trust labels">
        <ul className="plain">{['unverified_claim', 'observed', 'verified_authentic', 'rejected'].map((t) => <li key={t}><TrustBadge trust={t} /> {TRUST_INFO[t].help}</li>)}</ul>
      </Card>
      <Card title="Limits you should know about">
        <ul>
          <li><strong>Read-only.</strong> This dashboard issues no blocks, step-ups or payroll changes. Recommended actions are advisory; nothing enforces them yet.</li>
          <li><strong>Synthetic proof of concept.</strong> Thresholds and weights are hand-set and were never tested on real help-desk data. It is not production-ready.</li>
          <li><strong>Evidence is a snapshot.</strong> Memory evidence is what the decision recorded at the time, not a live view of Meko.</li>
          <li><strong>Extraction is brittle.</strong> Claims are found by English keyword rules. A claim that was missed does not appear — so absence here is not proof the caller said nothing.</li>
          <li><strong>Raw score first.</strong> Severity comes from the raw score (low &lt; 25, medium 25–49, high 50–74, critical ≥ 75). The 0–100 display score flattens near the top.</li>
          <li><strong>Masked ids are a convenience,</strong> not access control. Every signed-in role can use "Show full ids", and that choice is not audit-logged. Page views are logged by the server.</li>
          <li><strong>No retention or redaction policy yet</strong> for caller-derived text.</li>
          <li><strong>Hash chain.</strong> It detects edits, but someone who rewrites the whole chain is only caught against a head hash stored elsewhere.</li>
        </ul>
      </Card>
    </div>
  );
}
