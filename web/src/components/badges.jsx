import { Icon } from './Icon.jsx';
import { ACTION_LABEL, ATTESTATION_STATUS, FLAG_INFO, TRUST_INFO, rejectionInfo } from '../lib/vocab.js';

/** Severity: colour + icon + TEXT. Severity always comes from the raw score band, never from the 0-100 display score. */
export function SeverityBadge({ severity }) {
  if (!severity) return <span className="badge badge--none">—</span>;
  return <span className={`badge sev sev--${severity}`}><Icon name={severity} /><span>{severity.toUpperCase()}</span></span>;
}

export function ActionBadge({ action }) {
  if (!action) return <span className="badge badge--none">—</span>;
  return <span className={`badge act act--${action}`}><Icon name={action} /><span>{(ACTION_LABEL[action] ?? action).toUpperCase()}</span></span>;
}

/**
 * Score vs policy: shows the action the SCORE alone gave and the action after POLICY, so an analyst never reads a raised action as a
 * pure score result.
 */
export function ActionPair({ baseAction, recommendedAction }) {
  if (!baseAction || baseAction === recommendedAction) return <ActionBadge action={recommendedAction} />;
  return (
    <span className="action-pair" title={`Score alone said ${baseAction}; policy raised it to ${recommendedAction}`}>
      <span className="action-pair__base"><span className="sr-only">Score said </span><s>{ACTION_LABEL[baseAction]}</s></span>
      <span aria-hidden="true">→</span><span className="sr-only"> policy raised to </span>
      <ActionBadge action={recommendedAction} />
    </span>
  );
}

export function FlagChip({ flag }) {
  const info = FLAG_INFO[flag];
  return <span className={`chip flag flag--${flag}`} title={info?.help}><Icon name="flag" size={12} />{info?.short ?? flag}</span>;
}
export const FlagChips = ({ flags }) => (flags?.length ? <span className="chips">{flags.map((f) => <FlagChip key={f} flag={f} />)}</span> : null);

/**
 * THE one place trust styling is decided. The "verified" look (green + shield-check) is applied ONLY to trust === 'verified_authentic'.
 * A CLAIMED statement can never get it; a rejected record gets the red "rejected" look (with its own icon and text).
 */
const TRUST_ICON = { unverified_claim: 'claimed', observed: 'observed', verified_authentic: 'verified', verified_unused: 'verified', rejected: 'rejected', unknown: 'info' };
export function TrustBadge({ trust, compact = false }) {
  const t = TRUST_INFO[trust] ?? TRUST_INFO.unknown;
  const cls = trust === 'verified_authentic' ? 'trust--verified' : trust === 'verified_unused' ? 'trust--neutral' : `trust--${trust ?? 'unknown'}`;
  return (
    <span className={`badge trust ${cls}`} data-trust={trust} title={t.help}>
      <Icon name={TRUST_ICON[trust] ?? 'info'} />
      <span>{t.label}</span>
      {!compact && t.sub ? <span className="trust__sub">{t.sub}</span> : null}
    </span>
  );
}

/** Map a score contribution to a trust class. VERIFIED styling only when the contribution came from accepted verified evidence. */
export function trustOfContribution(c) {
  if (c.source === 'event') return null;
  if (c.label === 'REJECTED_VERIFIED') return 'rejected';
  if (c.label === 'CLAIMED') return 'unverified_claim';
  if (c.label === 'OBSERVED') return 'observed';
  if (c.label === 'VERIFIED') return c.source === 'verified' || c.source === 'pattern' ? 'verified_authentic' : 'verified_unused';
  return 'unknown';
}

/** Rejection reason: forged/tampered vs expired vs replayed are visually distinct (an expired record is not a forgery). */
export function ReasonChip({ reason }) {
  const info = rejectionInfo(reason);
  return (
    <span className={`badge reason reason--${info.category}`} title={info.text}>
      <Icon name={info.category === 'stale' ? 'clock' : info.category === 'replay' ? 'refresh' : info.category === 'system' ? 'info' : 'rejected'} />
      <span>{info.title}</span>
      <code className="reason__code">{reason}</code>
    </span>
  );
}

export function AttestationStatus({ status }) {
  const info = ATTESTATION_STATUS[status] ?? { label: status, help: '' };
  const icon = status === 'valid' ? 'verified' : status === 'spent' ? 'lock' : 'clock';
  return <span className={`badge att att--${status}`} title={info.help}><Icon name={icon} /><span>{info.label.toUpperCase()}</span></span>;
}
