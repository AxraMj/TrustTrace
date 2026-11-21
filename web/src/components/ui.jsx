import { useId, useState } from 'react';
import { Link } from 'react-router-dom';
import { Icon } from './Icon.jsx';
import { fmtDateTime, maskId, relTime, shortId } from '../lib/format.js';
import { usePrefs } from '../lib/prefs.jsx';
import { SEVERITIES, WINDOW_LABEL } from '../lib/vocab.js';

export function PageHeader({ title, subtitle, actions, children }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle ? <p className="muted">{subtitle}</p> : null}
        {children}
      </div>
      {actions ? <div className="page-header__actions">{actions}</div> : null}
    </header>
  );
}

export function Card({ title, subtitle, actions, children, className = '', id, as: Tag = 'section' }) {
  const hid = useId();
  return (
    <Tag className={`card ${className}`} id={id} aria-labelledby={title ? hid : undefined}>
      {title || actions ? (
        <div className="card__head">
          <div>{title ? <h2 id={hid}>{title}</h2> : null}{subtitle ? <p className="muted small">{subtitle}</p> : null}</div>
          {actions ? <div className="card__actions">{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </Tag>
  );
}

export function Loading({ label = 'Loading…' }) {
  return <div className="state state--loading" role="status" aria-live="polite"><span className="spinner" aria-hidden="true" />{label}</div>;
}

export function EmptyState({ title = 'Nothing to show', children }) {
  return <div className="state state--empty"><strong>{title}</strong>{children ? <p className="muted">{children}</p> : null}</div>;
}

export function ErrorState({ error, onRetry }) {
  const forbidden = error?.status === 403;
  return (
    <div className="state state--error" role="alert">
      <strong>{forbidden ? 'You do not have access to this view' : error?.status === 404 ? 'Not found' : 'Could not load this data'}</strong>
      <p>{error?.message ?? 'Unknown error'}</p>
      {error?.requestId ? <p className="muted small">Request id <code>{error.requestId}</code></p> : null}
      {onRetry && !forbidden ? <button type="button" className="btn" onClick={onRetry}><Icon name="refresh" /> Retry</button> : null}
    </div>
  );
}

/** Wraps a resource: loading / error / empty / content, so every screen handles every state the same way. */
export function Resource({ res, empty, children, label }) {
  if (res.error && !res.data) return <ErrorState error={res.error} onRetry={res.reload} />;
  if (!res.data) return <Loading label={label} />;
  if (empty?.(res.data)) return <EmptyState title={empty.title}>{empty.text}</EmptyState>;
  return (
    <>
      {res.error ? <Notice kind="warn" title="Showing the last data received">Refresh failed: {res.error.message}</Notice> : null}
      {children(res.data)}
    </>
  );
}

export function Notice({ kind = 'info', title, children }) {
  return (
    <div className={`notice notice--${kind}`} role={kind === 'danger' ? 'alert' : 'note'}>
      <Icon name={kind === 'danger' || kind === 'warn' ? 'high' : 'info'} size={18} />
      <div>{title ? <strong>{title}</strong> : null}{children ? <div>{children}</div> : null}</div>
    </div>
  );
}

/** Account / case identifier. Masked by default (a convenience against shoulder-surfing, NOT access control); full value in the link target. */
export function Ident({ value, to, kind = 'id' }) {
  const { mask } = usePrefs();
  if (!value) return <span className="muted">—</span>;
  const text = mask ? maskId(value) : value;
  const inner = <code className={`ident ident--${kind}`} title={mask ? 'Masked — use "Show full ids" in the header' : value}>{text}</code>;
  return to ? <Link to={to} aria-label={`${kind} ${text}`}>{inner}</Link> : inner;
}

/** A UUID / hash with a short form and the full value on hover/focus. */
export function Mono({ value, n = 8 }) {
  if (!value) return <span className="muted">—</span>;
  return <code className="mono" title={value}>{shortId(value, n)}</code>;
}

export function Time({ iso, relative = true }) {
  if (!iso) return <span className="muted">—</span>;
  return <time dateTime={iso} title={fmtDateTime(iso)}>{relative ? relTime(iso) : fmtDateTime(iso)}</time>;
}

export function Stat({ label, value, hint, tone, to }) {
  const body = (
    <>
      <span className="stat__value">{value}</span>
      <span className="stat__label">{label}</span>
      {hint ? <span className="stat__hint muted small">{hint}</span> : null}
    </>
  );
  return to ? <Link to={to} className={`stat stat--link ${tone ? `stat--${tone}` : ''}`}>{body}</Link> : <div className={`stat ${tone ? `stat--${tone}` : ''}`}>{body}</div>;
}

/** Multi-select filter as a group of toggle buttons (keyboard + screen-reader friendly; state exposed via aria-pressed). */
export function ToggleGroup({ legend, options, value, onChange }) {
  const set = new Set(value);
  const toggle = (o) => { const n = new Set(set); n.has(o) ? n.delete(o) : n.add(o); onChange([...n]); };
  return (
    <fieldset className="toggle-group">
      <legend>{legend}</legend>
      <div className="toggle-group__row">
        {options.map((o) => {
          const key = typeof o === 'string' ? o : o.value;
          const label = typeof o === 'string' ? o : o.label;
          return <button key={key} type="button" className="toggle" aria-pressed={set.has(key)} onClick={() => toggle(key)}>{label}</button>;
        })}
      </div>
    </fieldset>
  );
}

export function SeverityToggle({ value, onChange }) {
  return <ToggleGroup legend="Severity" options={SEVERITIES.map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) }))} value={value} onChange={onChange} />;
}

export function WindowSelect({ value, onChange, options = ['1h', '6h', '24h', '7d', '30d', 'all'], label = 'Time range' }) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((w) => <option key={w} value={w}>{WINDOW_LABEL[w] ?? w}</option>)}
      </select>
    </div>
  );
}

export function SearchBox({ value, onSubmit, label = 'Search', placeholder }) {
  const id = useId();
  const [draft, setDraft] = useState(value ?? '');
  return (
    <form className="field field--search" role="search" onSubmit={(e) => { e.preventDefault(); onSubmit(draft.trim()); }}>
      <label htmlFor={id}>{label}</label>
      <div className="search">
        <input id={id} type="search" value={draft} placeholder={placeholder} maxLength={100} onChange={(e) => setDraft(e.target.value)} autoComplete="off" spellCheck="false" />
        <button type="submit" className="btn">Search</button>
      </div>
    </form>
  );
}

export function LoadMore({ list }) {
  if (list.error && list.items.length) return <ErrorState error={list.error} onRetry={list.loadMore} />;
  if (!list.hasMore) return list.items.length ? <p className="muted small center">End of list · {list.items.length} shown</p> : null;
  return (
    <div className="center">
      <button type="button" className="btn" onClick={list.loadMore} disabled={list.loadingMore}>{list.loadingMore ? 'Loading…' : 'Load more'}</button>
    </div>
  );
}

export function Tabs({ tabs, current, onChange, label }) {
  const onKey = (e) => {
    const i = tabs.findIndex((t) => t.id === current);
    const next = e.key === 'ArrowRight' ? (i + 1) % tabs.length : e.key === 'ArrowLeft' ? (i - 1 + tabs.length) % tabs.length : e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length - 1 : -1;
    if (next >= 0) { e.preventDefault(); onChange(tabs[next].id); document.getElementById(`tab-${tabs[next].id}`)?.focus(); }
  };
  return (
    <div className="tabs" role="tablist" aria-label={label} onKeyDown={onKey}>
      {tabs.map((t) => (
        <button key={t.id} id={`tab-${t.id}`} role="tab" type="button" aria-selected={t.id === current} aria-controls={`panel-${t.id}`} tabIndex={t.id === current ? 0 : -1} className="tab" onClick={() => onChange(t.id)}>
          {t.label}{t.count !== undefined ? <span className="tab__count">{t.count}</span> : null}
        </button>
      ))}
    </div>
  );
}
