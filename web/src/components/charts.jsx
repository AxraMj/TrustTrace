import { fmtDay, fmtHour, fmtNum, fmtPoints } from '../lib/format.js';
import { SEVERITIES, SEVERITY_BANDS, SOURCE_INFO } from '../lib/vocab.js';
import { TrustBadge, trustOfContribution } from './badges.jsx';
import { Icon } from './Icon.jsx';

/** Stacked bars of decisions per time bucket by severity. Inline SVG + a data table alternative (charts never stand alone). */
export function SeriesChart({ series }) {
  const pts = series?.points ?? [];
  if (!pts.length) return <p className="muted">No decisions in this window.</p>;
  const W = 640, H = 180, padL = 34, padB = 22, padT = 8;
  const max = Math.max(...pts.map((p) => p.total), 1);
  const bw = (W - padL) / pts.length;
  const label = series.bucket === 'day' ? fmtDay : fmtHour;
  const order = ['low', 'medium', 'high', 'critical'];
  const step = Math.ceil(pts.length / 8);
  return (
    <div className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Decisions per ${series.bucket} by severity. ${pts.length} buckets, peak ${max}.`} className="chart__svg">
        <line x1={padL} y1={H - padB} x2={W} y2={H - padB} className="axis" />
        <text x={padL - 6} y={padT + 8} textAnchor="end" className="tick">{max}</text>
        <text x={padL - 6} y={H - padB} textAnchor="end" className="tick">0</text>
        {pts.map((p, i) => {
          let y = H - padB;
          const x = padL + i * bw + bw * 0.12;
          const w = Math.max(bw * 0.76, 2);
          return (
            <g key={p.t}>
              {order.map((s) => {
                const h = ((H - padB - padT) * p[s]) / max;
                y -= h;
                return h > 0 ? <rect key={s} x={x} y={y} width={w} height={h} className={`bar bar--${s}`}><title>{`${label(p.t)} · ${s}: ${p[s]}`}</title></rect> : null;
              })}
              {i % step === 0 ? <text x={x + w / 2} y={H - 6} textAnchor="middle" className="tick">{label(p.t)}</text> : null}
            </g>
          );
        })}
      </svg>
      <Legend />
      <details className="chart__table">
        <summary>Show as table</summary>
        <table>
          <caption className="sr-only">Decisions per {series.bucket} by severity</caption>
          <thead><tr><th scope="col">{series.bucket === 'day' ? 'Day' : 'Hour'}</th>{SEVERITIES.slice().reverse().map((s) => <th key={s} scope="col">{s}</th>)}<th scope="col">Total</th></tr></thead>
          <tbody>{pts.map((p) => <tr key={p.t}><th scope="row">{label(p.t)}</th>{SEVERITIES.slice().reverse().map((s) => <td key={s}>{p[s]}</td>)}<td>{p.total}</td></tr>)}</tbody>
        </table>
      </details>
    </div>
  );
}

export function Legend() {
  return (
    <ul className="legend" aria-label="Severity legend">
      {SEVERITIES.slice().reverse().map((s) => <li key={s}><span className={`swatch swatch--${s}`} aria-hidden="true" />{s}</li>)}
    </ul>
  );
}

/** Horizontal bar list: label, bar, count. Counts are always printed (colour/length is never the only signal). */
export function BarList({ items, total, tone = 'neutral', empty = 'None in this window.' }) {
  if (!items?.length) return <p className="muted">{empty}</p>;
  const max = Math.max(...items.map((i) => i.count), 1);
  return (
    <ul className="barlist">
      {items.map((i) => (
        <li key={i.key ?? i.label}>
          <span className="barlist__label">{i.label}{i.sub ? <span className="muted small"> {i.sub}</span> : null}</span>
          <span className="barlist__track" aria-hidden="true"><span className={`barlist__fill barlist__fill--${i.tone ?? tone}`} style={{ width: `${Math.max((i.count / max) * 100, 2)}%` }} /></span>
          <span className="barlist__count">{fmtNum(i.count)}{total ? <span className="muted small"> ({Math.round((i.count / total) * 100)}%)</span> : null}</span>
        </li>
      ))}
    </ul>
  );
}

/**
 * Score waterfall for one decision: every contribution (base × weight = effective points) with the running total, and the
 * severity band markers (25 / 50 / 75). The RAW score is the headline; the 0-100 display score is secondary.
 */
export function Waterfall({ contributions, rawScore }) {
  const rows = (contributions ?? []).filter((c) => c.effectivePoints !== 0 || c.label === 'REJECTED_VERIFIED');
  if (!rows.length) return <p className="muted">No score contributions were recorded.</p>;
  let run = 0;
  const lines = rows.map((c) => { run += c.effectivePoints; return { c, run: Math.round(run * 10) / 10 }; });
  const peak = Math.max(100, ...lines.map((l) => Math.abs(l.run)), Math.abs(rawScore ?? 0));
  const pctOf = (v) => `${Math.min(Math.max(v, 0), peak) / peak * 100}%`;
  return (
    <div className="waterfall">
      <div className="waterfall__scale" aria-hidden="true">
        {[25, 50, 75].map((b) => <span key={b} style={{ left: pctOf(b) }}>{b}</span>)}
      </div>
      <ol className="waterfall__rows">
        {lines.map(({ c, run: r }, i) => {
          const trust = trustOfContribution(c);
          const neg = c.effectivePoints < 0;
          return (
            <li key={`${c.memoryId ?? c.kind}-${i}`} className="wf-row">
              <div className="wf-row__what">
                <span className="wf-row__source">{SOURCE_INFO[c.source] ?? c.source}</span>
                {trust ? <TrustBadge trust={trust} compact /> : <span className="badge trust trust--event">EVENT</span>}
                <span className="wf-row__text">{c.text}</span>
                {c.memoryId ? <code className="mono muted small" title={`Meko memory ${c.memoryId}`}>mem {c.memoryId.slice(0, 8)}</code> : null}
              </div>
              <div className="wf-row__calc"><span className="muted small">{c.basePoints} × {c.weight}</span> <strong className={neg ? 'pts pts--neg' : 'pts pts--pos'}>{fmtPoints(c.effectivePoints)}</strong></div>
              <div className="wf-row__bar" aria-hidden="true">
                <span className="wf-row__bands" />
                <span className={`wf-row__fill ${neg ? 'is-neg' : ''}`} style={{ width: pctOf(Math.abs(r)) }} />
              </div>
              <div className="wf-row__run"><span className="sr-only">Running total </span>{r}</div>
            </li>
          );
        })}
      </ol>
      <p className="waterfall__total"><Icon name="info" /> Raw score <strong>{rawScore}</strong> · band markers: low &lt; 25, medium {SEVERITY_BANDS.medium}, high {SEVERITY_BANDS.high}, critical {SEVERITY_BANDS.critical}. Raw score is not capped at 100.</p>
    </div>
  );
}
