import { Link } from 'react-router-dom';
import { ActionPair, FlagChips, ReasonChip, SeverityBadge, TrustBadge } from './badges.jsx';
import { Ident, Mono, Time } from './ui.jsx';
import { agentName, eventType, humanize } from '../lib/vocab.js';
import { fmtPoints } from '../lib/format.js';

export const caseLink = (a, c) => `/cases/${encodeURIComponent(a)}/${encodeURIComponent(c)}`;

/** Triage queue rows. Everything caller-derived is rendered as React text (escaped); nothing is ever injected as HTML. */
export function AlertTable({ items, showCase = true }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Risk alerts, newest first</caption>
        <thead>
          <tr><th scope="col">Severity</th><th scope="col">Action</th><th scope="col">Event</th><th scope="col">Account</th>{showCase ? <th scope="col">Case</th> : null}<th scope="col">Why (top reasons)</th><th scope="col">Flags</th><th scope="col">When</th></tr>
        </thead>
        <tbody>
          {items.map((a) => (
            <tr key={a.id} className={`row row--${a.severity}`}>
              <td><Link to={`/decisions/${a.id}`} className="rowlink" aria-label={`Open ${a.severity} ${eventType(a.eventType)} decision`}><SeverityBadge severity={a.severity} /></Link><div className="muted small">raw {a.rawScore}</div></td>
              <td><ActionPair baseAction={a.baseAction} recommendedAction={a.recommendedAction} /></td>
              <td>{eventType(a.eventType)}</td>
              <td><Ident value={a.accountId} kind="account" /></td>
              {showCase ? <td>{a.caseId ? <Ident value={a.caseId} kind="case" to={caseLink(a.accountId, a.caseId)} /> : <span className="muted">no case</span>}</td> : null}
              <td>
                <ul className="reasons">{a.topReasons?.length ? a.topReasons.map((r, i) => <li key={i}><span className={r.effect > 0 ? 'pts pts--pos' : 'pts pts--neg'}>{fmtPoints(r.effect)}</span> {humanize(r.kind)}</li>) : <li className="muted">no contributions</li>}</ul>
              </td>
              <td><FlagChips flags={a.flags} /></td>
              <td><Time iso={a.createdAt} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Memory evidence: label, trust class, writer, statement (plain text), effect on score. Styling is decided by `trust` only. */
export function EvidenceTable({ memories }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Memory evidence recorded for the decision(s)</caption>
        <thead><tr><th scope="col">Trust</th><th scope="col">Kind</th><th scope="col">Statement (as recorded)</th><th scope="col">Written by</th><th scope="col">Effect on score</th><th scope="col">Memory</th></tr></thead>
        <tbody>
          {memories.map((m) => (
            <tr key={m.memoryId} className={`row row--trust-${m.trust}`}>
              <td><TrustBadge trust={m.trust} />{m.rejectedIn?.length ? <div className="stack">{[...new Set(m.rejectedIn.map((r) => r.reason))].map((r) => <ReasonChip key={r} reason={r} />)}</div> : null}</td>
              <td>{humanize(m.kind)}</td>
              <td className={`statement statement--${m.trust}`}>{m.statement ? <q className="quote">{m.statement}</q> : <span className="muted">statement not recorded</span>}</td>
              <td>{m.writer ? <>{agentName(m.writer.agentId)}<div className="muted small"><Time iso={m.writer.at} /></div></> : <span className="muted" title="No write event was recorded for this memory">unknown</span>}</td>
              <td><strong className={m.netEffectPoints > 0 ? 'pts pts--pos' : m.netEffectPoints < 0 ? 'pts pts--neg' : 'pts'}>{fmtPoints(m.netEffectPoints)}</strong>{m.usage?.length ? <div className="muted small">{m.usage.length} use{m.usage.length === 1 ? '' : 's'}</div> : <div className="muted small">no effect</div>}</td>
              <td><Mono value={m.memoryId} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function RejectionTable({ items, withContext = true }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Records that claimed to be VERIFIED but failed authentication</caption>
        <thead><tr><th scope="col">Why rejected</th><th scope="col">Record</th><th scope="col">Risk added</th>{withContext ? <><th scope="col">Account / case</th><th scope="col">Decision</th></> : null}<th scope="col">When</th></tr></thead>
        <tbody>
          {items.map((r, i) => (
            <tr key={`${r.decisionId}-${r.memoryId}-${i}`} className="row row--trust-rejected">
              <td><ReasonChip reason={r.reason} />{r.detail ? <div className="small muted">{r.detail}</div> : null}</td>
              <td>{r.statement ? <q className="quote">{r.statement}</q> : <span className="muted">no statement</span>}<div className="small muted">{humanize(r.kind)} · <Mono value={r.memoryId} /></div></td>
              <td><strong className="pts pts--pos">{fmtPoints(r.points)}</strong></td>
              {withContext ? <><td><Ident value={r.accountId} kind="account" />{r.caseId ? <div><Ident value={r.caseId} kind="case" to={caseLink(r.accountId, r.caseId)} /></div> : null}</td>
                <td><Link to={`/decisions/${r.decisionId}`}><Mono value={r.decisionId} /></Link><div className="small muted">{eventType(r.eventType)}</div></td></> : null}
              <td><Time iso={r.at} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ActivityTable({ items }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Agent activity, newest first</caption>
        <thead><tr><th scope="col">When</th><th scope="col">Agent</th><th scope="col">Activity</th><th scope="col">Details</th><th scope="col">Duration</th><th scope="col">Result</th></tr></thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.id} className={e.ok === false ? 'row row--fail' : 'row'}>
              <td><Time iso={e.at} /></td>
              <td>{agentName(e.agentId)}</td>
              <td>{humanize(e.kind)}</td>
              <td className="small">
                {e.memoryIds?.length ? <span>{e.memoryIds.length} memor{e.memoryIds.length === 1 ? 'y' : 'ies'}: {e.memoryIds.slice(0, 3).map((m) => <Mono key={m} value={m} n={6} />).reduce((a, x) => (a ? [a, ', ', x] : x), null)}{e.memoryIds.length > 3 ? ' …' : ''}</span> : null}
                {e.payload?.labels ? <div className="muted">labels {Object.entries(e.payload.labels).map(([k, v]) => `${k}:${v}`).join(' ')}</div> : null}
                {e.payload?.meta ? <div className="muted">retrieval {e.payload.meta.complete ? 'complete' : 'INCOMPLETE'}{e.payload.meta.truncated ? ' · truncated' : ''}{e.payload.meta.usedFallback ? ' · fallback' : ''}{e.payload.meta.scannedPages != null ? ` · ${e.payload.meta.scannedPages} pages` : ''}</div> : null}
                {e.decisionId ? <div><Link to={`/decisions/${e.decisionId}`}>decision <Mono value={e.decisionId} n={6} /></Link></div> : null}
                {e.accountId && e.caseId ? <div><Ident value={e.caseId} kind="case" to={caseLink(e.accountId, e.caseId)} /></div> : null}
              </td>
              <td>{e.durationMs != null ? `${Math.round(e.durationMs)} ms` : '—'}</td>
              <td>{e.ok === false ? <span className="badge sev sev--high">FAILED</span> : <span className="muted">ok</span>}{e.error ? <div className="small">{e.error}</div> : null}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
