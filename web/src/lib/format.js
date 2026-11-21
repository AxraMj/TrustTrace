const dtf = new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
const dayf = new Intl.DateTimeFormat(undefined, { month: 'short', day: '2-digit' });
const hourf = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });

export const fmtDateTime = (iso) => (iso ? dtf.format(new Date(iso)) : '—');
export const fmtDay = (iso) => dayf.format(new Date(iso));
export const fmtHour = (iso) => hourf.format(new Date(iso));

/** "5 min ago" / "in 2 h" / "3 d ago". Pure given `now` so it is testable. */
export function relTime(iso, now = Date.now()) {
  if (!iso) return '—';
  const diff = new Date(iso).getTime() - now;
  const abs = Math.abs(diff);
  const units = [['d', 86400e3], ['h', 3600e3], ['min', 60e3], ['s', 1e3]];
  for (const [u, ms] of units) {
    if (abs >= ms || u === 's') {
      const n = Math.round(abs / ms);
      if (u === 's' && abs < 5e3) return 'just now';
      return diff < 0 ? `${n} ${u} ago` : `in ${n} ${u}`;
    }
  }
  return '—';
}

export const fmtNum = (n) => (n === null || n === undefined ? '—' : new Intl.NumberFormat().format(n));
export const fmtPoints = (n) => (n === null || n === undefined ? '—' : `${n > 0 ? '+' : n < 0 ? '−' : ''}${Math.abs(Math.round(n * 10) / 10)}`);
export const fmtMs = (n) => (n === null || n === undefined ? '—' : n >= 1000 ? `${(n / 1000).toFixed(2)} s` : `${Math.round(n)} ms`);
export const humanize = (s) => (s ? String(s).replace(/_/g, ' ') : '—');
export const pct = (a, b) => (b ? `${Math.round((a / b) * 100)}%` : '—');

/** Shorten an opaque id for display only (the full value stays in the title/aria and in links). */
export const shortId = (id, n = 8) => (id && id.length > n + 1 ? `${id.slice(0, n)}…` : id ?? '—');

/** Mask the middle of an account/case identifier ("acct-7f3a…c91") for shoulder-surfing protection. Not a security boundary. */
export function maskId(id) {
  if (!id) return '—';
  const s = String(id);
  if (s.length <= 8) return `${s.slice(0, 2)}••••`;
  return `${s.slice(0, 5)}••••${s.slice(-3)}`;
}
