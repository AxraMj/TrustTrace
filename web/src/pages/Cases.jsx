import { Link, useSearchParams } from 'react-router-dom';
import { ActionBadge, SeverityBadge } from '../components/badges.jsx';
import { caseLink } from '../components/tables.jsx';
import { EmptyState, ErrorState, Ident, Loading, LoadMore, PageHeader, SearchBox, SeverityToggle, Time, WindowSelect } from '../components/ui.jsx';
import { usePaged } from '../lib/hooks.js';

const WINDOWS = ['24h', '7d', '30d', '90d', 'all'];

export function Cases() {
  const [sp, setSp] = useSearchParams();
  const window = WINDOWS.includes(sp.get('window')) ? sp.get('window') : '30d';
  const severity = sp.get('severity') ? sp.get('severity').split(',') : [];
  const q = sp.get('q') ?? '';
  const set = (patch) => {
    const n = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(patch)) { if (!v || (Array.isArray(v) && !v.length)) n.delete(k); else n.set(k, Array.isArray(v) ? v.join(',') : v); }
    setSp(n);
  };
  const res = usePaged('/api/cases', { window, severity, q: q || undefined, limit: 50 }, { idOf: (c) => `${c.accountId}|${c.caseId}` });
  return (
    <div className="page">
      <PageHeader title="Cases" subtitle="A case is an (account, case id) pair seen in help-desk calls and decisions. Ordered by latest activity." />
      <div className="filters" role="group" aria-label="Case filters">
        <SeverityToggle value={severity} onChange={(v) => set({ severity: v })} />
        <WindowSelect value={window} onChange={(w) => set({ window: w })} options={WINDOWS} />
        <SearchBox key={q} value={q} onSubmit={(v) => set({ q: v })} label="Account or case id" placeholder="contains…" />
      </div>
      <div aria-live="polite">
        {res.loading ? <Loading /> : res.error && !res.items.length ? <ErrorState error={res.error} onRetry={res.reload} />
          : !res.items.length ? <EmptyState title="No cases match">Only decisions that carry a case id create a case.</EmptyState>
            : (
              <>
                <div className="table-wrap"><table className="table">
                  <caption className="sr-only">Cases, most recently active first</caption>
                  <thead><tr><th scope="col">Highest severity</th><th scope="col">Latest action</th><th scope="col">Case</th><th scope="col">Account</th><th scope="col">Decisions</th><th scope="col">Last activity</th></tr></thead>
                  <tbody>{res.items.map((c) => (
                    <tr key={`${c.accountId}|${c.caseId}`} className={`row row--${c.maxSeverity}`}>
                      <td><SeverityBadge severity={c.maxSeverity} /></td>
                      <td><ActionBadge action={c.latestDecision?.recommendedAction} /></td>
                      <td><Ident value={c.caseId} kind="case" to={caseLink(c.accountId, c.caseId)} /></td>
                      <td><Ident value={c.accountId} kind="account" /></td>
                      <td>{c.decisionCount}{c.latestDecision ? <> · <Link to={`/decisions/${c.latestDecision.id}`}>latest</Link></> : null}</td>
                      <td><Time iso={c.lastSeen} /></td>
                    </tr>))}</tbody>
                </table></div>
                <LoadMore list={res} />
              </>
            )}
      </div>
    </div>
  );
}
