import { useSearchParams } from 'react-router-dom';
import { ActivityTable } from '../components/tables.jsx';
import { EmptyState, ErrorState, Loading, LoadMore, PageHeader, ToggleGroup, WindowSelect } from '../components/ui.jsx';
import { usePaged } from '../lib/hooks.js';
import { ACTIVITY_KIND, AGENT_NAME } from '../lib/vocab.js';

const WINDOWS = ['1h', '6h', '24h', '7d', '30d', 'all'];

export function Activity() {
  const [sp, setSp] = useSearchParams();
  const window = WINDOWS.includes(sp.get('window')) ? sp.get('window') : '24h';
  const agentId = sp.get('agentId') ?? '';
  const kind = sp.get('kind') ?? '';
  const failed = sp.get('ok') === 'false';
  const set = (patch) => { const n = new URLSearchParams(sp); for (const [k, v] of Object.entries(patch)) { if (!v) n.delete(k); else n.set(k, v); } setSp(n); };
  const res = usePaged('/api/activity', { window, agentId: agentId || undefined, kind: kind || undefined, ok: failed ? 'false' : undefined, limit: 50 });
  const one = (legend, options, value, key) => <ToggleGroup legend={legend} options={options} value={value ? [value] : []} onChange={(v) => set({ [key]: v.find((x) => x !== value) ?? '' })} />;
  return (
    <div className="page">
      <PageHeader title="Agent activity" subtitle="What the help-desk agent, identity-security agent and verification authority wrote and read — with Meko memory ids and timings." />
      <div className="filters" role="group" aria-label="Activity filters">
        {one('Agent', Object.entries(AGENT_NAME).map(([value, label]) => ({ value, label })), agentId, 'agentId')}
        {one('Activity', Object.entries(ACTIVITY_KIND).slice(0, 6).map(([value, label]) => ({ value, label })), kind, 'kind')}
        <ToggleGroup legend="Result" options={[{ value: 'failed', label: 'Failures only' }]} value={failed ? ['failed'] : []} onChange={(v) => set({ ok: v.length ? 'false' : '' })} />
        <WindowSelect value={window} onChange={(w) => set({ window: w })} options={WINDOWS} />
      </div>
      <div aria-live="polite">
        {res.loading ? <Loading /> : res.error && !res.items.length ? <ErrorState error={res.error} onRetry={res.reload} />
          : !res.items.length ? <EmptyState title="No activity in this range" />
            : <><ActivityTable items={res.items} /><LoadMore list={res} /></>}
      </div>
    </div>
  );
}
