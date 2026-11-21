import { Link, useSearchParams } from 'react-router-dom';
import { AttestationStatus } from '../components/badges.jsx';
import { RejectionTable, caseLink } from '../components/tables.jsx';
import { Card, EmptyState, ErrorState, Ident, Loading, LoadMore, Mono, Notice, PageHeader, Resource, Time, ToggleGroup, WindowSelect } from '../components/ui.jsx';
import { useApi, usePaged } from '../lib/hooks.js';
import { ATTESTATION_STATUS, REJECTION_INFO, humanize } from '../lib/vocab.js';

const WINDOWS = ['24h', '7d', '30d', '90d', 'all'];

export function Verification() {
  const [sp, setSp] = useSearchParams();
  const window = WINDOWS.includes(sp.get('window')) ? sp.get('window') : '30d';
  const status = sp.get('status') ? sp.get('status').split(',') : [];
  const set = (patch) => { const n = new URLSearchParams(sp); for (const [k, v] of Object.entries(patch)) { if (!v || (Array.isArray(v) && !v.length)) n.delete(k); else n.set(k, Array.isArray(v) ? v.join(',') : v); } setSp(n); };
  const list = usePaged('/api/verification/attestations', { window, status, limit: 50 }, { idOf: (a) => a.nonce });
  const rej = useApi('/api/verification/rejections', { params: { window, limit: 100 } });
  const keys = useApi('/api/verification/keys');
  return (
    <div className="page">
      <PageHeader title="Verification status" subtitle="Signed identity checks, whether each was accepted, spent or expired — and every record that falsely claimed to be VERIFIED."
        actions={<WindowSelect value={window} onChange={(w) => set({ window: w })} options={WINDOWS} />} />

      <Card title="Rejected records" subtitle="Claimed VERIFIED but failed authentication. Expired is not the same as forged.">
        <Resource res={rej} empty={Object.assign((d) => !d.items.length, { title: 'No rejected records', text: 'No record failed verification in this range.' })}>
          {(d) => <>{d.truncated ? <Notice kind="warn" title="Showing the newest 100">More rejected records exist in this range.</Notice> : null}<RejectionTable items={d.items} /></>}
        </Resource>
        <details className="legend-details"><summary>What do the reason codes mean?</summary>
          <dl className="kv kv--tight">{Object.entries(REJECTION_INFO).map(([code, i]) => <div key={code}><dt><code>{code}</code></dt><dd><strong>{i.title}.</strong> {i.text}</dd></div>)}</dl>
        </details>
      </Card>

      <Card title="Attestation ledger" subtitle="Issued by the verification authority; single-use kinds can be spent only once">
        <ToggleGroup legend="State" options={Object.entries(ATTESTATION_STATUS).map(([value, i]) => ({ value, label: i.label }))} value={status} onChange={(v) => set({ status: v })} />
        <div aria-live="polite">
          {list.loading ? <Loading /> : list.error && !list.items.length ? <ErrorState error={list.error} onRetry={list.reload} />
            : !list.items.length ? <EmptyState title="No attestations in this range" />
              : (
                <>
                  <div className="table-wrap"><table className="table">
                    <caption className="sr-only">Attestation ledger</caption>
                    <thead><tr><th scope="col">State</th><th scope="col">Kind</th><th scope="col">Method</th><th scope="col">Case</th><th scope="col">Issuer / key</th><th scope="col">Issued</th><th scope="col">Expires</th><th scope="col">Used by</th></tr></thead>
                    <tbody>{list.items.map((a) => (
                      <tr key={a.nonce}>
                        <td><AttestationStatus status={a.status} /></td>
                        <td>{humanize(a.kind)}{a.singleUse ? <div className="muted small">single-use</div> : null}</td>
                        <td>{humanize(a.method)}</td>
                        <td>{a.caseId ? <Ident value={a.caseId} kind="case" to={caseLink(a.accountId, a.caseId)} /> : '—'}</td>
                        <td>{a.issuer}<div className="muted small"><Mono value={a.kid} n={12} /></div></td>
                        <td><Time iso={a.issuedAt} /></td><td><Time iso={a.expiresAt} /></td>
                        <td>{a.consumedEventId ? <><code>{a.consumedEventId}</code>{a.decisionId ? <> · <Link to={`/decisions/${a.decisionId}`}>decision</Link></> : null}</> : <span className="muted">unused</span>}</td>
                      </tr>))}</tbody>
                  </table></div>
                  <LoadMore list={list} />
                </>
              )}
        </div>
      </Card>

      <Card title="Verifier trust-anchor keys" subtitle="Key ids Agent B used to check signatures (public keys only; private keys never leave the authority)">
        <Resource res={keys} empty={Object.assign((d) => !d.items.length, { title: 'No decisions recorded a key id yet' })}>
          {(d) => <ul>{d.items.map((k) => <li key={k.keyId}><code>{k.keyId}</code> — used by {k.decisions} decision(s), last <Time iso={k.lastUsedAt} /></li>)}</ul>}
        </Resource>
      </Card>
    </div>
  );
}
