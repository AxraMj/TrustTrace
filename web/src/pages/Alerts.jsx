import { useSearchParams } from 'react-router-dom';
import { AlertTable } from '../components/tables.jsx';
import { EmptyState, ErrorState, Loading, LoadMore, PageHeader, SearchBox, SeverityToggle, ToggleGroup, WindowSelect } from '../components/ui.jsx';
import { usePaged } from '../lib/hooks.js';
import { ACTION_LABEL, FLAG_INFO } from '../lib/vocab.js';

const WINDOWS = ['1h', '6h', '24h', '7d', '30d', '90d', 'all'];
const list = (sp, k) => (sp.get(k) ? sp.get(k).split(',').filter(Boolean) : []);

/** Filters live in the URL so a view can be shared / bookmarked ("saved views" = bookmarks in v1). */
export function Alerts() {
  const [sp, setSp] = useSearchParams();
  const window = WINDOWS.includes(sp.get('window')) ? sp.get('window') : '7d';
  const severity = list(sp, 'severity'), action = list(sp, 'action'), flag = list(sp, 'flag');
  const q = sp.get('q') ?? '';
  const set = (patch) => {
    const n = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(patch)) { if (!v || (Array.isArray(v) && !v.length)) n.delete(k); else n.set(k, Array.isArray(v) ? v.join(',') : v); }
    setSp(n);
  };
  const res = usePaged('/api/alerts', { window, severity, action, flag, q: q || undefined, limit: 50 });
  const filtered = severity.length || action.length || flag.length || q;

  return (
    <div className="page">
      <PageHeader title="Risk alerts" subtitle="Every assessed event, newest first. Open a row to see exactly why." />
      <div className="filters" role="group" aria-label="Alert filters">
        <SeverityToggle value={severity} onChange={(v) => set({ severity: v })} />
        <ToggleGroup legend="Recommended action" options={Object.entries(ACTION_LABEL).map(([value, label]) => ({ value, label }))} value={action} onChange={(v) => set({ action: v })} />
        <ToggleGroup legend="Flags" options={Object.entries(FLAG_INFO).map(([value, i]) => ({ value, label: i.label }))} value={flag} onChange={(v) => set({ flag: v })} />
        <WindowSelect value={window} onChange={(w) => set({ window: w })} options={WINDOWS} />
        <SearchBox key={q} value={q} onSubmit={(v) => set({ q: v })} label="Account, case or event id" placeholder="contains…" />
        {filtered ? <button type="button" className="btn btn--ghost" onClick={() => setSp({ window })}>Clear filters</button> : null}
      </div>
      <div aria-live="polite">
        {res.loading ? <Loading /> : res.error && !res.items.length ? <ErrorState error={res.error} onRetry={res.reload} />
          : !res.items.length ? <EmptyState title="No alerts match">{filtered ? 'Loosen the filters or widen the time range.' : 'No decisions in this time range.'}</EmptyState>
            : <><AlertTable items={res.items} /><LoadMore list={res} /></>}
      </div>
    </div>
  );
}
