import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Card, EmptyState, ErrorState, Loading, LoadMore, Mono, Notice, PageHeader, Resource, Time, ToggleGroup } from '../components/ui.jsx';
import { getJson } from '../lib/api.js';
import { useAuth } from '../lib/auth.jsx';
import { useApi } from '../lib/hooks.js';
import { humanize } from '../lib/vocab.js';
import { useCallback, useEffect } from 'react';

const TYPES = ['decision', 'attestation_issued', 'attestation_consumed'];

/** Audit history (supervisors and admins). Pages with afterSeq; "Verify chain" is a READ that recomputes every hash on the server (admin). */
export function Audit() {
  const { user } = useAuth();
  const [sp, setSp] = useSearchParams();
  const type = sp.get('type') ?? '';
  const head = useApi('/api/audit/head');
  const [state, setState] = useState({ items: [], next: null, loading: true, error: null, more: false });

  const load = useCallback(async (after, reset) => {
    setState((s) => ({ ...s, ...(reset ? { loading: true, items: [] } : { more: true }), error: null }));
    try {
      const d = await getJson('/api/audit', { params: { type: type || undefined, afterSeq: after || undefined, limit: 100 } });
      setState((s) => ({ items: reset ? d.items : [...s.items, ...d.items], next: d.nextAfterSeq, loading: false, error: null, more: false }));
    } catch (error) { setState((s) => ({ ...s, loading: false, more: false, error })); }
  }, [type]);
  useEffect(() => { load(0, true); }, [load]);

  const [verify, setVerify] = useState(null);
  async function runVerify() {
    setVerify({ busy: true });
    try { setVerify({ result: await getJson('/api/audit/verify') }); } catch (error) { setVerify({ error }); }
  }

  return (
    <div className="page">
      <PageHeader title="Audit history" subtitle="Append-only, hash-chained record of every decision and attestation. Each record includes the hash of the one before it." />
      <Card title="Chain head" subtitle="Record this value somewhere outside this system to detect a rewrite of the whole chain">
        <Resource res={head}>{(h) => <dl className="kv kv--tight"><div><dt>Records</dt><dd>{h.seq}</dd></div><div><dt>Head hash</dt><dd><Mono value={h.hash} n={32} /></dd></div><div><dt>Latest</dt><dd><Time iso={h.at} /></dd></div></dl>}</Resource>
        {user?.role === 'admin' ? (
          <div className="verify">
            <button type="button" className="btn" onClick={runVerify} disabled={verify?.busy}>{verify?.busy ? 'Verifying…' : 'Verify whole chain'}</button>
            {verify?.result ? (verify.result.ok
              ? <Notice kind="info" title="Chain verified">{verify.result.checked} records re-hashed; every link and every audited row matches.</Notice>
              : <Notice kind="danger" title="CHAIN PROBLEMS FOUND">{verify.result.problems.slice(0, 10).map((p, i) => <div key={i}><code>{p.code}</code> at record {p.seq}{p.detail ? ` — ${p.detail}` : ''}</div>)}</Notice>) : null}
            {verify?.error ? <ErrorState error={verify.error} /> : null}
          </div>
        ) : <p className="muted small">Only administrators can run the full chain verification.</p>}
      </Card>
      <ToggleGroup legend="Record type" options={TYPES.map((t) => ({ value: t, label: humanize(t) }))} value={type ? [type] : []} onChange={(v) => { const n = v.find((x) => x !== type); n ? setSp({ type: n }) : setSp({}); }} />
      {state.loading ? <Loading /> : state.error && !state.items.length ? <ErrorState error={state.error} onRetry={() => load(0, true)} />
        : !state.items.length ? <EmptyState title="No audit records" />
          : (
            <>
              <div className="table-wrap"><table className="table">
                <caption className="sr-only">Audit chain records in order</caption>
                <thead><tr><th scope="col">#</th><th scope="col">Type</th><th scope="col">Reference</th><th scope="col">When</th><th scope="col">Payload hash</th><th scope="col">Previous</th><th scope="col">Record hash</th></tr></thead>
                <tbody>{state.items.map((r) => (
                  <tr key={r.seq}><th scope="row">{r.seq}</th><td>{humanize(r.recordType)}</td><td>{r.recordType === 'decision' ? <Link to={`/decisions/${r.refId}`}><Mono value={r.refId} /></Link> : <Mono value={r.refId} />}</td><td><Time iso={r.createdAt} /></td><td><Mono value={r.payloadHash} n={12} /></td><td><Mono value={r.prevHash} n={12} /></td><td><Mono value={r.recordHash} n={12} /></td></tr>))}</tbody>
              </table></div>
              <div className="center">{state.next ? <button type="button" className="btn" disabled={state.more} onClick={() => load(state.next, false)}>{state.more ? 'Loading…' : 'Load more'}</button> : <p className="muted small">End of chain · {state.items.length} shown</p>}</div>
            </>
          )}
    </div>
  );
}
