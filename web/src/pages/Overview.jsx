import { useSearchParams } from 'react-router-dom';
import { Link } from 'react-router-dom';
import { BarList, SeriesChart } from '../components/charts.jsx';
import { AlertTable } from '../components/tables.jsx';
import { Card, EmptyState, Notice, PageHeader, Resource, Stat, Time, WindowSelect } from '../components/ui.jsx';
import { useApi } from '../lib/hooks.js';
import { fmtMs, fmtNum, pct } from '../lib/format.js';
import { ATTESTATION_STATUS, FLAG_INFO, SEVERITIES, agentName, eventType, humanize, rejectionInfo } from '../lib/vocab.js';

const WINDOWS = ['1h', '6h', '24h', '7d', '30d', 'all'];

export function Overview() {
  const [sp, setSp] = useSearchParams();
  const window = WINDOWS.includes(sp.get('window')) ? sp.get('window') : '24h';
  const summary = useApi('/api/summary', { params: { window }, pollMs: 30_000 });
  const review = useApi('/api/alerts', { params: { window, severity: ['critical', 'high'], limit: 8 }, pollMs: 30_000 });
  const health = useApi('/api/health', { pollMs: 30_000 });
  const meta = useApi('/api/meta');

  return (
    <div className="page">
      <PageHeader title="Fraud monitoring overview" subtitle="Every number below is counted from the persisted decision log in PostgreSQL."
        actions={<WindowSelect value={window} onChange={(w) => setSp({ window: w })} options={WINDOWS} />} />
      <Resource res={summary} label="Loading summary…">
        {(s) => <Body s={s} window={window} review={review} health={health} meta={meta} />}
      </Resource>
    </div>
  );
}

function Body({ s, window, review, health, meta }) {
  const t = s.totals;
  if (!t.decisions) {
    return <EmptyState title="No decisions in this window">Nothing has been assessed in this time range. Try a longer range — no demo data is shown.</EmptyState>;
  }
  const f = s.flags;
  const q = (extra) => `/alerts?window=${window}${extra}`;
  return (
    <>
      <section aria-label="Decisions by recommended action" className="stats">
        <Stat label="Decisions" value={fmtNum(t.decisions)} hint={`${fmtNum(t.accounts)} accounts · ${fmtNum(t.cases)} cases`} to={q('')} />
        <Stat label="Block" value={fmtNum(t.blocked)} tone="block" hint={pct(t.blocked, t.decisions)} to={q('&action=block')} />
        <Stat label="Step-up" value={fmtNum(t.stepUp)} tone="step_up" hint={pct(t.stepUp, t.decisions)} to={q('&action=step_up')} />
        <Stat label="Allow" value={fmtNum(t.allowed)} tone="allow" hint={pct(t.allowed, t.decisions)} to={q('&action=allow')} />
      </section>

      <section aria-label="Integrity and health flags" className="stats stats--flags">
        <Stat label={FLAG_INFO.rejected_evidence.label} value={fmtNum(f.rejectedEvidence)} tone={f.rejectedEvidence ? 'danger' : undefined} hint="possible tampering / forgery" to={q('&flag=rejected_evidence')} />
        <Stat label={FLAG_INFO.degraded.label} value={fmtNum(f.degraded)} tone={f.degraded ? 'warn' : undefined} hint="Meko unreadable" to={q('&flag=degraded')} />
        <Stat label={FLAG_INFO.incomplete_context.label} value={fmtNum(f.incompleteContext)} tone={f.incompleteContext ? 'warn' : undefined} hint={`${pct(t.decisions - f.incompleteContext, t.decisions)} fully retrieved`} to={q('&flag=incomplete_context')} />
        <Stat label={FLAG_INFO.policy_raised.label} value={fmtNum(f.policyRaised)} hint="policy overrode the score" to={q('&flag=policy_raised')} />
      </section>

      <div className="grid grid--2">
        <Card title="Decisions over time" subtitle="By severity (from the raw score)"><SeriesChart series={s.series} /></Card>
        <Card title="By severity" subtitle="Severity bands: low < 25 · medium 25–49 · high 50–74 · critical ≥ 75">
          <BarList total={t.decisions} items={SEVERITIES.map((sv) => ({ key: sv, label: sv[0].toUpperCase() + sv.slice(1), count: s.bySeverity[sv], tone: sv }))} />
        </Card>
      </div>

      <Card title="Needs review" subtitle="Newest critical and high alerts in this window" actions={<Link to={q('&severity=critical,high')}>All critical + high</Link>}>
        <Resource res={review} empty={Object.assign((d) => !d.items.length, { title: 'Nothing critical or high', text: 'No critical or high alerts in this window.' })}>
          {(d) => <AlertTable items={d.items} />}
        </Resource>
      </Card>

      <div className="grid grid--2">
        <Card title="Top risk drivers" subtitle="Most frequent non-event score contributions">
          <BarList items={s.topDrivers.map((d) => ({ key: `${d.source}${d.kind}`, label: humanize(d.kind), sub: `${d.label} · ${d.totalPoints > 0 ? '+' : ''}${d.totalPoints} pts`, count: d.count, tone: d.totalPoints < 0 ? 'allow' : 'high' }))} />
        </Card>
        <Card title="Rejected evidence" subtitle="Records that claimed VERIFIED but failed authentication">
          <BarList empty="No rejected evidence in this window." items={s.rejectedReasons.map((r) => ({ key: r.reason, label: rejectionInfo(r.reason).title, sub: r.reason, count: r.count, tone: rejectionInfo(r.reason).category === 'stale' ? 'medium' : 'critical' }))} />
          {s.rejectedReasons.length ? <p className="small"><Link to="/verification">See every rejected record</Link></p> : null}
        </Card>
        <Card title="By event type"><BarList total={t.decisions} items={s.byEventType.map((e) => ({ key: e.eventType, label: eventType(e.eventType), count: e.count }))} /></Card>
        <Card title="Policy rules that raised the action" subtitle="Score said one thing; policy required more">
          <BarList empty="Policy did not raise any action in this window." items={s.policyRules.map((p) => ({ key: p.rule, label: humanize(p.rule), count: p.count, tone: 'medium' }))} />
        </Card>
      </div>

      <Card title="System health" subtitle="From this window's records and the API — the dashboard does not query Meko directly">
        <dl className="kv">
          <div><dt>API / database</dt><dd>{health.data ? (health.data.db === 'up' ? <span className="ok-text">up</span> : <strong className="bad-text">DOWN</strong>) : health.error ? <strong className="bad-text">unreachable</strong> : '…'}</dd></div>
          <div><dt>Context retrieval completeness</dt><dd>{pct(t.decisions - f.incompleteContext, t.decisions)} of decisions · {f.degraded} degraded</dd></div>
          <div><dt>Meko retrieval latency</dt><dd>avg {fmtMs(s.latencyMs.retrieval.avg)} · p95 {fmtMs(s.latencyMs.retrieval.p95)}</dd></div>
          <div><dt>Scoring latency</dt><dd>avg {fmtMs(s.latencyMs.scoring.avg)} · p95 {fmtMs(s.latencyMs.scoring.p95)}</dd></div>
          <div><dt>Last decision</dt><dd><Time iso={t.lastDecisionAt} /></dd></div>
          <div><dt>Versions</dt><dd>{meta.data ? `model ${meta.data.versions.model} · extractor ${meta.data.versions.extractor} · policy ${meta.data.versions.policy}` : '…'}</dd></div>
        </dl>
        {f.degraded ? <Notice kind="warn" title={`${f.degraded} decision(s) were made without Meko context`}>These decisions saw the event only. Do not read their score as "no risk found".</Notice> : null}
      </Card>

      <div className="grid grid--2">
        <Card title="Agent activity" actions={<Link to="/activity">Open</Link>}>
          <BarList empty="No agent activity recorded." items={s.agents.map((a) => ({ key: a.agentId, label: agentName(a.agentId), sub: a.failures ? `${a.failures} failed` : undefined, count: a.events, tone: a.failures ? 'high' : 'neutral' }))} />
        </Card>
        <Card title="Attestations" subtitle="Signed identity checks issued in this window" actions={<Link to="/verification">Open</Link>}>
          <BarList empty="No attestations issued in this window." items={s.attestations.map((a) => ({ key: `${a.kind}${a.status}`, label: humanize(a.kind), sub: `${ATTESTATION_STATUS[a.status]?.label ?? a.status}${a.singleUse ? ' · single-use' : ''}`, count: a.count }))} />
        </Card>
      </div>
      <p className="muted small">Generated <Time iso={s.meta.generatedAt} relative={false} />. Severity is shown from the raw score; the 0–100 display score flattens near the top and is secondary.</p>
    </>
  );
}
