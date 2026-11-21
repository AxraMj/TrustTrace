import { Link, useParams } from 'react-router-dom';
import { ActionBadge, ActionPair, FlagChips, SeverityBadge } from '../components/badges.jsx';
import { Waterfall } from '../components/charts.jsx';
import { ActivityTable, EvidenceTable, RejectionTable, caseLink } from '../components/tables.jsx';
import { Card, Ident, Mono, Notice, PageHeader, Resource, Time } from '../components/ui.jsx';
import { useApi } from '../lib/hooks.js';
import { fmtDateTime, fmtMs } from '../lib/format.js';
import { ACTION_LABEL, eventType, humanize } from '../lib/vocab.js';

export function DecisionDetail() {
  const { id } = useParams();
  const res = useApi(`/api/decisions/${encodeURIComponent(id)}`);
  const evidence = useApi(`/api/decisions/${encodeURIComponent(id)}/evidence`);
  return (
    <div className="page">
      <p className="crumbs"><Link to="/alerts">Alerts</Link> / Decision <Mono value={id} /></p>
      <Resource res={res} label="Loading decision…">{(d) => <Body d={d} evidence={evidence} />}</Resource>
    </div>
  );
}

function Body({ d, evidence }) {
  const x = d.decision;
  const flags = [
    ...(x.rejectedEvidence.length ? ['rejected_evidence'] : []), ...(x.degraded ? ['degraded'] : []),
    ...(!x.retrievalComplete ? ['incomplete_context'] : []), ...(x.policy.length ? ['policy_raised'] : []),
  ];
  const integrityBad = d.integrity.auditRecordFound && !d.integrity.payloadHashMatches;
  return (
    <>
      <PageHeader title={`${eventType(x.eventType)} decision`} subtitle={`Assessed ${fmtDateTime(x.createdAt)} · event ${x.eventId ?? '—'}`}
        actions={<div className="stack-h">{d.neighbours.previous ? <Link className="btn" to={`/decisions/${d.neighbours.previous.id}`}>← Previous in case</Link> : null}{d.neighbours.next ? <Link className="btn" to={`/decisions/${d.neighbours.next.id}`}>Next in case →</Link> : null}</div>}>
        <div className="headline">
          <SeverityBadge severity={x.severity} />
          <span className="score" title="Raw score. Severity comes from this, not from the display score."><span className="score__label">Raw score</span><strong>{x.rawScore}</strong></span>
          <span className="muted" title="0–100 curve that flattens near the top; shown for orientation only">display {x.displayScore}/100</span>
          <ActionPair baseAction={x.baseAction} recommendedAction={x.recommendedAction} />
          <FlagChips flags={flags} />
        </div>
        <p className="small">Account <Ident value={x.accountId} kind="account" /> · Case {x.caseId ? <Ident value={x.caseId} kind="case" to={caseLink(x.accountId, x.caseId)} /> : <span className="muted">none</span>}</p>
      </PageHeader>

      {integrityBad ? <Notice kind="danger" title="Integrity check FAILED">This stored decision no longer matches the hash recorded in the audit chain. It may have been altered after it was made. Do not rely on it; tell a security administrator.</Notice> : null}
      {!d.integrity.auditRecordFound ? <Notice kind="warn" title="No audit record found">This decision has no entry in the audit chain, so its integrity cannot be confirmed.</Notice> : null}
      {x.degraded ? <Notice kind="warn" title="Degraded: Meko context was not available">The decision used the event alone{x.error ? ` (${x.error.name}: ${x.error.message})` : ''}. A low score here does not mean "no risk found".</Notice> : null}
      {!x.degraded && !x.retrievalComplete ? <Notice kind="warn" title="Incomplete context">Retrieval could not prove it saw every relevant memory. Missing evidence is not treated as clean.</Notice> : null}

      {x.policy.length ? (
        <Card title="Why the action is not just the score" subtitle="The sensitive-action policy overrides a score-only result">
          <ul className="policy">
            {x.policy.map((p, i) => (
              <li key={i}><strong>Score says {ACTION_LABEL[p.from]?.toUpperCase()} — policy requires {ACTION_LABEL[p.to]?.toUpperCase()}.</strong> <span>{p.why}</span> <code className="muted small">{p.rule}</code></li>
            ))}
          </ul>
        </Card>
      ) : null}

      <div className="grid grid--2">
        <Card title="Recommended security actions" subtitle="Advisory only — this dashboard enforces nothing">
          <p><ActionBadge action={x.recommendedAction} /></p>
          {x.stepUp?.required ? (
            <>
              <h3>Step-up checklist (in order)</h3>
              <ol className="checklist">{x.stepUp.requirements.map((r, i) => <li key={i}>{r}</li>)}</ol>
            </>
          ) : x.recommendedAction === 'block' ? <p>Block the action and escalate to a security analyst. No step-up path is offered for a block.</p> : <p className="muted">No step-up required.</p>}
          {x.advisories.length ? <><h3>Advisories</h3><ul className="advisories">{x.advisories.map((a) => <li key={a.code}><code>{a.code}</code> {a.text}</li>)}</ul></> : null}
        </Card>
        <Card title="Event inputs" subtitle="What was assessed (as recorded)">
          <dl className="kv kv--tight">{Object.entries(x.event ?? {}).filter(([, v]) => v !== undefined && v !== null && typeof v !== 'object').map(([k, v]) => <div key={k}><dt>{humanize(k)}</dt><dd>{String(v)}</dd></div>)}</dl>
        </Card>
      </div>

      <Card title="How the score was built" subtitle="Each contribution: base points × weight = effective points, with the running total">
        <Waterfall contributions={x.contributions} rawScore={x.rawScore} />
      </Card>

      <Card title="Memory evidence" subtitle="What Agent B retrieved from Meko at decision time (snapshot, not live Meko)">
        <Resource res={evidence} empty={Object.assign((e) => !e.memories.length, { title: 'No memories were retrieved', text: x.degraded ? 'Meko was not available.' : 'Nothing relevant was stored for this account.' })}>
          {(e) => (
            <>
              <p className="muted small">{e.note}</p>
              <EvidenceTable memories={e.memories} />
            </>
          )}
        </Resource>
      </Card>

      {x.rejectedEvidence.length ? (
        <Card title="Rejected evidence" subtitle="Claimed VERIFIED, failed authentication — not trusted, not an observation">
          <RejectionTable withContext={false} items={x.rejectedEvidence.map((r) => ({ ...r, decisionId: x.id }))} />
        </Card>
      ) : null}

      <div className="grid grid--2">
        <Card title="Retrieval health" subtitle="How completely Meko was read">
          {x.retrievalMeta?.length ? (
            <div className="table-wrap"><table className="table table--tight">
              <caption className="sr-only">Retrieval metadata per scope</caption>
              <thead><tr><th scope="col">Scope</th><th scope="col">Strategy</th><th scope="col">Complete</th><th scope="col">Truncated</th><th scope="col">Fallback</th><th scope="col">Pages</th></tr></thead>
              <tbody>{x.retrievalMeta.map((m, i) => <tr key={i}><td>{m.scope ?? m.bucket ?? `#${i + 1}`}</td><td>{m.strategy ?? '—'}</td><td>{m.complete ? 'yes' : <strong className="bad-text">NO</strong>}</td><td>{m.truncated ? <strong className="bad-text">yes</strong> : 'no'}</td><td>{m.usedFallback ? 'yes' : 'no'}</td><td>{m.scannedPages ?? '—'}</td></tr>)}</tbody>
            </table></div>
          ) : <p className="muted">No retrieval was performed{x.degraded ? ' (Meko unavailable)' : ''}.</p>}
          <p className="muted small">Retrieval time {fmtMs(x.timings?.retrievalMs)} · scoring {fmtMs(x.timings?.scoringMs)}. Meko search has no pagination and an undocumented relevance cut-off; completeness is proven per scope, not assumed.</p>
        </Card>
        <Card title="Audit trail & integrity" subtitle="Hash-chained decision record">
          <dl className="kv kv--tight">
            <div><dt>Integrity</dt><dd>{d.integrity.auditRecordFound ? (d.integrity.payloadHashMatches ? <span className="ok-text">stored decision matches its audit hash</span> : <strong className="bad-text">MISMATCH — possible tampering</strong>) : <span className="muted">no audit record</span>}</dd></div>
            <div><dt>Audit sequence</dt><dd>{d.audit ? `#${d.audit.seq}` : '—'}</dd></div>
            <div><dt>Payload hash</dt><dd><Mono value={d.audit?.payloadHash} n={16} /></dd></div>
            <div><dt>Previous record hash</dt><dd><Mono value={d.audit?.prevHash} n={16} /></dd></div>
            <div><dt>Record hash</dt><dd><Mono value={d.audit?.recordHash} n={16} /></dd></div>
            <div><dt>Model / extractor / policy</dt><dd>{x.modelVersion} · {x.extractorVersion} · {x.policyVersion}</dd></div>
            <div><dt>Verifier key id</dt><dd><Mono value={x.verifierKeyId} n={16} /></dd></div>
            <div><dt>Decision id</dt><dd><Mono value={x.id} n={36} /></dd></div>
          </dl>
          {d.attestationsSpent.length ? <><h3>Attestations spent by this decision</h3><ul>{d.attestationsSpent.map((a) => <li key={a.nonce}>{humanize(a.kind)} via {humanize(a.method)} — consumed by event <code>{a.consumedEventId}</code> <Time iso={a.consumedAt} /></li>)}</ul></> : null}
        </Card>
      </div>

      <Card title="Full explanation (as recorded)" subtitle="Plain text, one line per contribution">
        <ol className="explain">{x.explanation.map((l, i) => <li key={i}>{l}</li>)}</ol>
      </Card>

      {d.activity.length ? <Card title="Agent activity during this decision"><ActivityTable items={d.activity} /></Card> : null}
    </>
  );
}
