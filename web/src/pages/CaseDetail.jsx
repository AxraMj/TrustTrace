import { Link, useParams, useSearchParams } from 'react-router-dom';
import { ActionPair, AttestationStatus, SeverityBadge, TrustBadge } from '../components/badges.jsx';
import { ActivityTable, AlertTable, EvidenceTable, RejectionTable } from '../components/tables.jsx';
import { Card, EmptyState, Ident, LoadMore, Loading, Mono, Notice, PageHeader, Resource, Stat, Tabs, Time } from '../components/ui.jsx';
import { casePath } from '../lib/api.js';
import { usePaged, useApi } from '../lib/hooks.js';
import { agentName, eventType, humanize } from '../lib/vocab.js';
import { fmtDateTime } from '../lib/format.js';

const TABS = ['timeline', 'evidence', 'verification', 'decisions', 'activity'];

export function CaseDetail() {
  const { accountId, caseId } = useParams();
  const [sp, setSp] = useSearchParams();
  const tab = TABS.includes(sp.get('tab')) ? sp.get('tab') : 'timeline';
  const header = useApi(casePath(accountId, caseId));
  return (
    <div className="page">
      <p className="crumbs"><Link to="/cases">Cases</Link> / <Ident value={caseId} kind="case" /></p>
      <Resource res={header} label="Loading case…">
        {(c) => (
          <>
            <PageHeader title="Case investigation" subtitle={`First seen ${fmtDateTime(c.firstSeen)} · last activity ${fmtDateTime(c.lastSeen)}`}>
              <p className="small">Account <Ident value={c.accountId} kind="account" /> · Case <Ident value={c.caseId} kind="case" /></p>
              {c.latestDecision ? (
                <div className="headline"><span className="muted">Latest decision</span> <SeverityBadge severity={c.latestDecision.severity} /> <ActionPair baseAction={c.latestDecision.baseAction} recommendedAction={c.latestDecision.recommendedAction} /> <Link to={`/decisions/${c.latestDecision.id}`}>open</Link></div>
              ) : null}
            </PageHeader>
            <section className="stats" aria-label="Case counts">
              <Stat label="Decisions" value={c.counts.decisions} />
              <Stat label="Agent events" value={c.counts.agentEvents} />
              <Stat label="Attestations" value={c.counts.attestations} />
              <Stat label="With rejected evidence" value={c.counts.decisionsWithRejectedEvidence} tone={c.counts.decisionsWithRejectedEvidence ? 'danger' : undefined} />
            </section>
            {c.counts.degradedDecisions ? <Notice kind="warn" title={`${c.counts.degradedDecisions} decision(s) in this case were degraded`}>Meko context was unavailable for them.</Notice> : null}
            <Tabs label="Case sections" current={tab} onChange={(t) => setSp({ tab: t }, { replace: true })}
              tabs={[{ id: 'timeline', label: 'Timeline' }, { id: 'evidence', label: 'Claims & evidence' }, { id: 'verification', label: 'Verification', count: c.counts.attestations }, { id: 'decisions', label: 'Decisions', count: c.counts.decisions }, { id: 'activity', label: 'Agent activity', count: c.counts.agentEvents }]} />
            <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} className="tabpanel">
              {tab === 'timeline' ? <Timeline a={accountId} c={caseId} /> : null}
              {tab === 'evidence' ? <CaseEvidence a={accountId} c={caseId} /> : null}
              {tab === 'verification' ? <CaseVerification a={accountId} c={caseId} /> : null}
              {tab === 'decisions' ? <CaseDecisions a={accountId} c={caseId} /> : null}
              {tab === 'activity' ? <CaseActivity a={accountId} c={caseId} /> : null}
            </div>
          </>
        )}
      </Resource>
    </div>
  );
}

function TimelineItem({ it }) {
  switch (it.type) {
    case 'decision':
      return <><span className="tl__title">Decision</span> <SeverityBadge severity={it.severity} /> <ActionPair baseAction={it.baseAction} recommendedAction={it.recommendedAction} /> for {eventType(it.eventType)} (raw {it.rawScore}) <Link to={`/decisions/${it.ref}`}>open</Link></>;
    case 'attestation_issued':
      return <><span className="tl__title">Verification issued</span> {humanize(it.kind)} via {humanize(it.method)} <span className="muted">· expires <Time iso={it.expiresAt} /></span></>;
    case 'attestation_consumed':
      return <><span className="tl__title">Verification spent</span> {humanize(it.kind)} used for event <code>{it.consumedEventId}</code>{it.decisionId ? <> in <Link to={`/decisions/${it.decisionId}`}>decision</Link></> : null}</>;
    default:
      return <><span className="tl__title">{agentName(it.agentId)}</span> {humanize(it.kind)}{it.memoryIds?.length ? ` (${it.memoryIds.length} memor${it.memoryIds.length === 1 ? 'y' : 'ies'})` : ''}{it.ok === false ? <strong className="bad-text"> FAILED {it.error}</strong> : null}</>;
  }
}

function Timeline({ a, c }) {
  const res = useApi(casePath(a, c, '/timeline'));
  return (
    <Card title="Timeline" subtitle="Help-desk call facts → verification → decisions, oldest first">
      <Resource res={res} empty={Object.assign((d) => !d.items.length, { title: 'No events recorded for this case' })}>
        {(d) => (
          <>
            {d.truncated ? <Notice kind="warn" title="Timeline truncated">More events exist than are shown here.</Notice> : null}
            <ol className="timeline">{d.items.map((it, i) => <li key={`${it.type}-${it.ref}-${i}`} className={`tl tl--${it.type}`}><Time iso={it.at} relative={false} /> <div className="tl__body"><TimelineItem it={it} /></div></li>)}</ol>
          </>
        )}
      </Resource>
    </Card>
  );
}

/** Claims panel: CLAIMED / OBSERVED / VERIFIED / REJECTED never share a visual style. */
function CaseEvidence({ a, c }) {
  const res = useApi(casePath(a, c, '/evidence'));
  return (
    <Resource res={res} empty={Object.assign((d) => !d.memories.length, { title: 'No memory evidence', text: 'No memories were retrieved by any decision in this case.' })}>
      {(d) => {
        const by = (t) => d.memories.filter((m) => m.trust === t);
        const groups = [
          ['unverified_claim', 'Caller claims — unverified', 'Things the caller said. Treated as risk signals, never as facts.'],
          ['observed', 'Observed behaviour', 'Seen by a system or agent.'],
          ['verified_authentic', 'Verified evidence (authentic)', 'Signature and bindings checked and accepted.'],
          ['rejected', 'Rejected: claimed VERIFIED, failed authentication', 'Not trusted. See the reason on each row.'],
          ['verified_unused', 'Verified but not used', 'Labelled VERIFIED, not used by any decision shown.'],
        ];
        return (
          <>
            <p className="muted small">{d.note} Across {d.decisionCount} decision(s).</p>
            {groups.map(([t, title, text]) => by(t).length ? (
              <Card key={t} title={<span className="inline-title"><TrustBadge trust={t} compact /> {title} ({by(t).length})</span>} subtitle={text}><EvidenceTable memories={by(t)} /></Card>
            ) : null)}
          </>
        );
      }}
    </Resource>
  );
}

function CaseVerification({ a, c }) {
  const res = useApi(casePath(a, c, '/verification'));
  return (
    <Resource res={res}>
      {(d) => (
        <>
          <Card title="Attestations issued for this case" subtitle="Signed identity checks from the verification authority">
            {d.attestations.length ? (
              <div className="table-wrap"><table className="table">
                <caption className="sr-only">Attestations issued for this case</caption>
                <thead><tr><th scope="col">State</th><th scope="col">Kind</th><th scope="col">Method</th><th scope="col">Issuer / key</th><th scope="col">Issued</th><th scope="col">Expires</th><th scope="col">Used by</th></tr></thead>
                <tbody>{d.attestations.map((x) => (
                  <tr key={x.nonce}><td><AttestationStatus status={x.status} /></td><td>{humanize(x.kind)}{x.singleUse ? <div className="muted small">single-use</div> : null}</td><td>{humanize(x.method)}</td><td>{x.issuer}<div className="muted small"><Mono value={x.kid} n={12} /></div></td><td><Time iso={x.issuedAt} /></td><td><Time iso={x.expiresAt} /></td>
                    <td>{x.consumedEventId ? <><code>{x.consumedEventId}</code>{x.decisionId ? <> · <Link to={`/decisions/${x.decisionId}`}>decision</Link></> : null}</> : <span className="muted">unused</span>}</td></tr>
                ))}</tbody>
              </table></div>
            ) : <p className="muted">No attestation was ever issued for this case. A record that claims VERIFIED here was not issued by the authority.</p>}
          </Card>
          <Card title="Rejected records in this case" subtitle="Claimed VERIFIED, failed authentication">
            {d.rejections.length ? <RejectionTable withContext={false} items={d.rejections} /> : <p className="muted">None.</p>}
            {d.rejectionsTruncated ? <Notice kind="warn" title="Truncated">More rejected records exist.</Notice> : null}
          </Card>
        </>
      )}
    </Resource>
  );
}

function CaseDecisions({ a, c }) {
  const res = usePaged(casePath(a, c, '/decisions'), { limit: 50 });
  if (res.loading) return <Loading />;
  if (!res.items.length) return <EmptyState title="No decisions" />;
  return <Card title="Decisions in this case"><AlertTable items={res.items} showCase={false} /><LoadMore list={res} /></Card>;
}

function CaseActivity({ a, c }) {
  const res = usePaged(casePath(a, c, '/activity'), { limit: 50 }, { idOf: (e) => e.id });
  if (res.loading) return <Loading />;
  if (!res.items.length) return <EmptyState title="No agent activity recorded">Activity is recorded for events that went through the instrumented path.</EmptyState>;
  return <Card title="Agent activity"><ActivityTable items={res.items} /><LoadMore list={res} /></Card>;
}
