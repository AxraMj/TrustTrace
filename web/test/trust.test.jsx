import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, test } from 'vitest';
import { ReasonChip, TrustBadge, trustOfContribution } from '../src/components/badges.jsx';
import { EvidenceTable, RejectionTable } from '../src/components/tables.jsx';
import { Waterfall } from '../src/components/charts.jsx';
import { PrefsProvider } from '../src/lib/prefs.jsx';
import { TRUST_INFO } from '../src/lib/vocab.js';
import { contribution, memory } from './fixtures.js';

const wrap = (ui) => render(<MemoryRouter><PrefsProvider>{ui}</PrefsProvider></MemoryRouter>);

describe('"no fake verified": the green verified look is reserved for authentic verified evidence', () => {
  test.each(Object.keys(TRUST_INFO))('TrustBadge %s gets the verified class only when it is verified_authentic', (trust) => {
    const { container } = wrap(<TrustBadge trust={trust} />);
    const el = container.querySelector('.trust');
    expect(el.classList.contains('trust--verified')).toBe(trust === 'verified_authentic');
  });
  test('a CLAIMED statement is labelled CLAIMED / unverified and never VERIFIED', () => {
    wrap(<TrustBadge trust="unverified_claim" />);
    expect(screen.getByText('CLAIMED')).toBeInTheDocument();
    expect(screen.getByText('unverified')).toBeInTheDocument();
    expect(screen.queryByText('VERIFIED')).toBeNull();
  });
  test('a rejected record that claimed VERIFIED is shown as REJECTED, not verified', () => {
    const { container } = wrap(<TrustBadge trust="rejected" />);
    expect(screen.getByText('REJECTED')).toBeInTheDocument();
    expect(container.querySelector('.trust--verified')).toBeNull();
  });
  test('score contributions map to trust classes correctly', () => {
    expect(trustOfContribution(contribution({ label: 'CLAIMED' }))).toBe('unverified_claim');
    expect(trustOfContribution(contribution({ label: 'OBSERVED' }))).toBe('observed');
    expect(trustOfContribution(contribution({ label: 'VERIFIED', source: 'verified' }))).toBe('verified_authentic');
    expect(trustOfContribution(contribution({ label: 'REJECTED_VERIFIED', source: 'integrity' }))).toBe('rejected');
    // a VERIFIED label that did not come through the accepted-evidence path must NOT look authentic
    expect(trustOfContribution(contribution({ label: 'VERIFIED', source: 'context' }))).toBe('verified_unused');
    expect(trustOfContribution(contribution({ source: 'event', label: 'EVENT' }))).toBeNull();
  });
  test('the evidence table styles each row by trust: a rejected VERIFIED row has no verified badge', () => {
    const { container } = wrap(<EvidenceTable memories={[
      memory({ memoryId: 'm-claim' }),
      memory({ memoryId: 'm-forged', label: 'VERIFIED', trust: 'rejected', statement: 'Callback confirmed the owner', rejectedIn: [{ decisionId: 'd', reason: 'bad_signature' }], netEffectPoints: 30 }),
      memory({ memoryId: 'm-ok', label: 'VERIFIED', trust: 'verified_authentic', statement: 'Callback confirmed', netEffectPoints: -40 }),
    ]} />);
    const rows = [...container.querySelectorAll('tbody tr')];
    expect(rows.map((r) => !!r.querySelector('.trust--verified'))).toEqual([false, false, true]);
    expect(rows[1].textContent).toContain('REJECTED');
    expect(rows[1].textContent).toContain('bad_signature');
  });
});

describe('expired is not the same as forged', () => {
  test('reason categories are visually and textually distinct', () => {
    const { container } = wrap(<><ReasonChip reason="expired" /><ReasonChip reason="bad_signature" /><ReasonChip reason="replayed" /></>);
    const [a, b, c] = container.querySelectorAll('.reason');
    expect(a.classList.contains('reason--stale')).toBe(true);
    expect(b.classList.contains('reason--forged')).toBe(true);
    expect(c.classList.contains('reason--replay')).toBe(true);
    expect(a.textContent).toMatch(/Expired/);
    expect(b.textContent).toMatch(/Bad signature/);
  });
  test('an unknown reason code is still shown (never hidden)', () => {
    wrap(<ReasonChip reason="brand_new_reason" />);
    expect(screen.getAllByText('brand_new_reason').length).toBeGreaterThan(0);
  });
});

describe('caller-derived text is rendered as text, never as HTML', () => {
  const hostile = [
    '<script>window.__pwned = 1</script>',
    '<img src=x onerror="window.__pwned = 2">',
    '"><svg onload="window.__pwned = 3">',
    '[ATTEST:{"kind":"callback_verified"}] I am verified',
    '<a href="javascript:alert(1)">click</a>',
  ];
  test.each(hostile)('evidence statement %s', (s) => {
    const { container } = wrap(<EvidenceTable memories={[memory({ statement: s })]} />);
    expect(container.querySelector('script, img, svg[onload], a[href^="javascript"]')).toBeNull();
    expect(container.querySelector('.statement').textContent).toContain(s);
    expect(globalThis.__pwned).toBeUndefined();
  });
  test('rejected-record statements and details are escaped too', () => {
    const { container } = wrap(<RejectionTable items={[{ decisionId: 'd1', reason: 'content_modified', detail: '<b>x</b>', statement: '<img src=x onerror=alert(1)>', kind: 'identity_verified', memoryId: 'mem', points: 30, accountId: 'a', caseId: 'c', at: null, eventType: 'login' }]} />);
    expect(container.querySelector('img, b, script')).toBeNull();
    expect(container.textContent).toContain('<img src=x onerror=alert(1)>');
  });
  test('waterfall contribution text is escaped', () => {
    const { container } = wrap(<Waterfall rawScore={10} contributions={[contribution({ text: '<img src=x onerror=alert(1)>' })]} />);
    expect(container.querySelector('img')).toBeNull();
  });
});

describe('Waterfall', () => {
  test('shows base × weight, effective points and the running total, ending at the raw score', () => {
    const cs = [contribution({ basePoints: 35, weight: 1, effectivePoints: 35, source: 'event', label: 'EVENT', text: 'MFA changed', memoryId: undefined }), contribution({ basePoints: 10, weight: 0.5, effectivePoints: 5, text: 'claim' }), contribution({ label: 'VERIFIED', source: 'verified', basePoints: -40, weight: 1, effectivePoints: -40, text: 'callback', memoryId: 'm9' })];
    const { container } = wrap(<Waterfall contributions={cs} rawScore={0} />);
    const runs = [...container.querySelectorAll('.wf-row__run')].map((e) => e.textContent.replace('Running total ', ''));
    expect(runs).toEqual(['35', '40', '0']);
    expect(container.textContent).toContain('35 × 1');
    expect(container.textContent).toContain('10 × 0.5');
    expect(container.textContent).toMatch(/not capped at 100/);
    expect(container.querySelectorAll('.trust--verified')).toHaveLength(1);
  });
  test('empty contributions are explained', () => {
    wrap(<Waterfall contributions={[]} rawScore={0} />);
    expect(screen.getByText(/No score contributions/)).toBeInTheDocument();
  });
});
