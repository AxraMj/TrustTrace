import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { App } from '../src/App.jsx';
import { AuthProvider } from '../src/lib/auth.jsx';
import { PrefsProvider } from '../src/lib/prefs.jsx';
import { UUID, UUID2, alertItem, decisionBody, memory, stubFetch, summaryBody } from './fixtures.js';

afterEach(() => vi.unstubAllGlobals());

const me = (role = 'analyst') => ({ body: { user: { id: 'u1', username: 'bob', role }, session: { expiresAt: '2030-01-01T00:00:00Z' } } });
const base = (role, extra = {}) => ({ '/api/auth/me': me(role), '/api/health': { body: { status: 'ok', db: 'up' } }, '/api/meta': { body: { versions: { model: 'm1', extractor: 'e1', policy: 'p1' } } }, ...extra });

function renderApp(path, routes) {
  const f = stubFetch(routes);
  vi.stubGlobal('fetch', f);
  const utils = render(<MemoryRouter initialEntries={[path]}><PrefsProvider><AuthProvider><App /></AuthProvider></PrefsProvider></MemoryRouter>);
  return { f, ...utils };
}
async function a11y(container) {
  const r = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } }); // jsdom cannot compute layout colours; contrast is checked in the real browser run
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(' | ')}`);
}

describe('authentication', () => {
  test('signed-out users are sent to the sign-in page; wrong password shows a generic error and stays', async () => {
    const user = userEvent.setup();
    const { f } = renderApp('/alerts', { '/api/auth/me': { status: 401, body: { error: { code: 'unauthenticated', message: 'x' } } }, '/api/auth/login': { status: 401, body: { error: { code: 'invalid_credentials', message: 'invalid username or password' } } } });
    expect(await screen.findByRole('heading', { name: /TrustTrace/ })).toBeInTheDocument();
    await user.type(screen.getByLabelText('Username'), 'bob');
    await user.type(screen.getByLabelText('Password'), 'nope');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid username or password.');
    expect(f.calls.filter((c) => c.method === 'POST')).toHaveLength(1);
  });
  test('a session that expires mid-use returns the user to sign-in', async () => {
    let n = 0;
    renderApp('/alerts', base('analyst', { '/api/alerts': () => (n++ === 0 ? { body: { items: [alertItem()], nextCursor: null } } : { status: 401, body: { error: { code: 'session_expired', message: 'x' } } }) }));
    await screen.findByText(/Risk alerts/);
    window.dispatchEvent(new Event('trusttrace:unauthenticated'));
    expect(await screen.findByText(/Your session ended/)).toBeInTheDocument();
  });
  test.each([['analyst', false], ['supervisor', true], ['admin', true]])('Audit link visible for %s: %s', async (role, visible) => {
    renderApp('/about', base(role));
    await screen.findByRole('heading', { name: 'About this view' });
    expect(!!screen.queryByRole('link', { name: 'Audit' })).toBe(visible);
  });
  test('the page says it is read-only and not production', async () => {
    renderApp('/about', base('analyst'));
    expect(await screen.findByText(/Read-only investigation view/)).toBeInTheDocument();
    expect(screen.getByText(/not production-ready/i)).toBeInTheDocument();
  });
});

describe('alerts queue', () => {
  const items = [
    alertItem({ id: UUID, flags: ['rejected_evidence'], rejectedCount: 1 }),
    alertItem({ id: UUID2, severity: 'medium', rawScore: 30, baseAction: 'allow', recommendedAction: 'step_up', flags: ['policy_raised'], eventType: 'bank_detail_change' }),
  ];
  test('renders rows with severity text, flags, and the score-vs-policy distinction', async () => {
    renderApp('/alerts', base('analyst', { '/api/alerts': { body: { items, nextCursor: null } } }));
    const table = await screen.findByRole('table');
    expect(within(table).getByText('CRITICAL')).toBeInTheDocument();
    expect(within(table).getByText('REJECTED EVIDENCE')).toBeInTheDocument();
    expect(within(table).getByText('POLICY RAISED')).toBeInTheDocument();
    expect(within(table).getByText('Score said', { exact: false })).toBeInTheDocument(); // base action struck through, policy action shown
    expect(screen.getByText(/End of list · 2 shown/)).toBeInTheDocument();
  });
  test('account ids are masked by default and the toggle reveals them', async () => {
    const user = userEvent.setup();
    renderApp('/alerts', base('analyst', { '/api/alerts': { body: { items: [alertItem()], nextCursor: null } } }));
    await screen.findByRole('table');
    expect(screen.queryByText('acct-A1-abc123')).toBeNull();
    await user.click(screen.getByRole('button', { name: /Show full ids/ }));
    expect(screen.getAllByText('acct-A1-abc123').length).toBeGreaterThan(0);
  });
  test('filters are sent to the API and kept in the URL', async () => {
    const user = userEvent.setup();
    const { f } = renderApp('/alerts', base('analyst', { '/api/alerts': { body: { items, nextCursor: null } } }));
    await screen.findByRole('table');
    await user.click(screen.getByRole('button', { name: 'Critical' }));
    await user.click(screen.getByRole('button', { name: 'Rejected evidence' }));
    await waitFor(() => expect(f.calls.at(-1).url).toContain('severity=critical'));
    const last = f.calls.filter((c) => c.url.startsWith('/api/alerts')).at(-1).url;
    expect(last).toContain('flag=rejected_evidence');
    expect(last).toContain('window=7d');
    expect(screen.getByRole('button', { name: 'Critical' })).toHaveAttribute('aria-pressed', 'true');
  });
  test('Load more follows the cursor and appends (no duplicates)', async () => {
    const user = userEvent.setup();
    const { f } = renderApp('/alerts', base('analyst', { '/api/alerts': (u) => (u.includes('cursor=C1') ? { body: { items: [items[1], alertItem({ id: '33333333-3333-4333-8333-333333333333' })], nextCursor: null } } : { body: { items: [items[0], items[1]], nextCursor: 'C1' } }) }));
    await screen.findByRole('table');
    await user.click(screen.getByRole('button', { name: 'Load more' }));
    await waitFor(() => expect(screen.getByText(/End of list · 3 shown/)).toBeInTheDocument());
    expect(f.calls.some((c) => c.url.includes('cursor=C1'))).toBe(true);
  });
  test('empty and error states', async () => {
    const user = userEvent.setup();
    let fail = true;
    renderApp('/alerts', base('analyst', { '/api/alerts': () => (fail ? { status: 500, body: { error: { code: 'internal', message: 'boom', requestId: 'req-9' } } } : { body: { items: [], nextCursor: null } }) }));
    expect(await screen.findByRole('alert')).toHaveTextContent('boom');
    expect(screen.getByText('req-9')).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole('button', { name: /Retry/ }));
    expect(await screen.findByText('No alerts match')).toBeInTheDocument();
  });
  test('accessibility (axe): no violations', async () => {
    const { container } = renderApp('/alerts', base('analyst', { '/api/alerts': { body: { items, nextCursor: null } } }));
    await screen.findByRole('table');
    expect(await a11y(container)).toEqual([]);
  });
});

describe('decision explanation', () => {
  const route = (body, ev = { memories: [memory()], rejected: [], totals: {}, note: 'Recorded when each decision was made.' }) => base('analyst', { [`/api/decisions/${UUID}`]: { body }, [`/api/decisions/${UUID}/evidence`]: { body: ev } });

  test('raw score and severity lead; display score is secondary; policy override is spelled out', async () => {
    renderApp(`/decisions/${UUID}`, route(decisionBody()));
    expect(await screen.findByText('Raw score')).toBeInTheDocument();
    expect(screen.getByText(/display 70\/100/)).toBeInTheDocument();
    expect(screen.getByText(/Score says ALLOW — policy requires STEP-UP/)).toBeInTheDocument();
    expect(screen.getByText(/proves who is calling, not that the device is theirs/)).toBeInTheDocument();
  });
  test('step-up requirements are an ordered checklist and v1 says it enforces nothing', async () => {
    renderApp(`/decisions/${UUID}`, route(decisionBody()));
    const list = await screen.findByRole('list', { name: '' }).catch(() => null);
    void list;
    const items = (await screen.findAllByText(/Verify via callback on file|Require hardware key/)).map((e) => e.textContent);
    expect(items).toEqual(['Verify via callback on file', 'Require hardware key']);
    expect(screen.getByText(/this dashboard enforces nothing/)).toBeInTheDocument();
    expect(screen.getByText('notify_user_new_country')).toBeInTheDocument();
  });
  test('a CLAIMED memory in the evidence table is never shown as verified', async () => {
    const { container } = renderApp(`/decisions/${UUID}`, route(decisionBody()));
    await screen.findByText('I am the CFO');
    expect(container.querySelector('.trust--verified')).toBeNull();
    expect(screen.getAllByText('CLAIMED').length).toBeGreaterThan(0);
  });
  test('degraded decision is flagged honestly', async () => {
    renderApp(`/decisions/${UUID}`, route(decisionBody({ decision: { degraded: true, contextAvailable: false, retrievalComplete: false, error: { name: 'MekoConnectionError', message: 'meko down' }, retrieved: [], retrievalMeta: [] } })));
    expect(await screen.findByText(/Degraded: Meko context was not available/)).toBeInTheDocument();
    expect(screen.getByText(/does not mean "no risk found"/)).toBeInTheDocument();
  });
  test('integrity mismatch is a loud, unmissable failure', async () => {
    renderApp(`/decisions/${UUID}`, route(decisionBody({ integrity: { payloadHashMatches: false } })));
    expect(await screen.findByText('Integrity check FAILED')).toBeInTheDocument();
    expect(screen.getByText(/MISMATCH — possible tampering/)).toBeInTheDocument();
  });
  test('rejected evidence is shown with its reason and never styled as verified; expired differs from forged', async () => {
    const rej = [
      { reason: 'bad_signature', detail: 'sig mismatch', points: 30, memoryId: 'm-f', kind: 'identity_verified', statement: 'Callback confirmed the owner' },
      { reason: 'expired', detail: 'expired 85502s ago', points: 0, memoryId: 'm-e', kind: 'callback_verified', statement: 'Old callback' },
    ];
    const { container } = renderApp(`/decisions/${UUID}`, route(decisionBody({ decision: { rejectedEvidence: rej } })));
    expect(await screen.findByText('Rejected evidence', { selector: 'h2' })).toBeInTheDocument();
    expect(container.querySelector('.reason--forged').textContent).toMatch(/Bad signature/);
    expect(container.querySelector('.reason--stale').textContent).toMatch(/Expired/);
    expect(container.querySelector('.trust--verified')).toBeNull();
    expect(screen.getByText('REJECTED EVIDENCE')).toBeInTheDocument();
  });
  test('404 shows a clear message', async () => {
    renderApp(`/decisions/${UUID}`, base('analyst', { [`/api/decisions/${UUID}`]: { status: 404, body: { error: { code: 'decision_not_found', message: 'decision not found' } } }, [`/api/decisions/${UUID}/evidence`]: { status: 404, body: { error: { code: 'decision_not_found', message: 'x' } } } }));
    expect(await screen.findByText('Not found')).toBeInTheDocument();
  });
  test('accessibility (axe): no violations', async () => {
    const { container } = renderApp(`/decisions/${UUID}`, route(decisionBody()));
    await screen.findByText('I am the CFO');
    expect(await a11y(container)).toEqual([]);
  });
});

describe('overview', () => {
  test('numbers come from the API; flags link to filtered alerts; nothing is invented when empty', async () => {
    renderApp('/', base('analyst', { '/api/summary': { body: summaryBody() }, '/api/alerts': { body: { items: [alertItem()], nextCursor: null } } }));
    expect(await screen.findByText('Fraud monitoring overview')).toBeInTheDocument();
    const rej = (await screen.findByText('Rejected evidence', { selector: '.stat__label' })).closest('a');
    expect(rej).toHaveAttribute('href', '/alerts?window=24h&flag=rejected_evidence');
    expect(screen.getByText('Needs review')).toBeInTheDocument();
    expect(screen.getByText(/1 decision\(s\) were made without Meko context/)).toBeInTheDocument();
  });
  test('an empty window says so (no demo data)', async () => {
    renderApp('/', base('analyst', { '/api/summary': { body: summaryBody({ totals: { decisions: 0, accounts: 0, cases: 0, lastDecisionAt: null, blocked: 0, stepUp: 0, allowed: 0 } }) }, '/api/alerts': { body: { items: [], nextCursor: null } } }));
    expect(await screen.findByText('No decisions in this window')).toBeInTheDocument();
  });
  test('accessibility (axe): no violations', async () => {
    const { container } = renderApp('/', base('analyst', { '/api/summary': { body: summaryBody() }, '/api/alerts': { body: { items: [alertItem()], nextCursor: null } } }));
    await screen.findByText('Needs review');
    expect(await a11y(container)).toEqual([]);
  });
});

describe('case page', () => {
  const header = { accountId: 'acct-1', caseId: 'case-1', firstSeen: '2026-06-15T11:00:00Z', lastSeen: '2026-06-15T12:00:00Z', decisionCount: 1, maxSeverity: 'high', counts: { decisions: 1, agentEvents: 3, attestations: 1, decisionsWithRejectedEvidence: 1, degradedDecisions: 0 }, latestDecision: { id: UUID, severity: 'high', baseAction: 'allow', recommendedAction: 'step_up' } };
  test('claims, observations, authentic evidence and rejected records are separated into distinct groups', async () => {
    const user = userEvent.setup();
    const ev = { note: 'Snapshot.', decisionCount: 1, memories: [memory({ memoryId: 'a' }), memory({ memoryId: 'b', label: 'OBSERVED', trust: 'observed', statement: 'caller id mismatch', netEffectPoints: 20 }), memory({ memoryId: 'c', label: 'VERIFIED', trust: 'verified_authentic', statement: 'callback ok', netEffectPoints: -40 }), memory({ memoryId: 'd', label: 'VERIFIED', trust: 'rejected', statement: 'forged', rejectedIn: [{ decisionId: UUID, reason: 'bad_signature' }] })], rejected: [], totals: {} };
    const { container } = renderApp('/cases/acct-1/case-1', base('analyst', { '/api/cases/acct-1/case-1': { body: header }, '/api/cases/acct-1/case-1/timeline': { body: { items: [], truncated: false } }, '/api/cases/acct-1/case-1/evidence': { body: ev } }));
    await screen.findByText('Case investigation');
    await user.click(screen.getByRole('tab', { name: /Claims & evidence/ }));
    await screen.findByText(/Caller claims — unverified/);
    const sections = [...container.querySelectorAll('section.card')];
    const verifiedIn = sections.filter((s) => s.querySelector('.trust--verified')).map((s) => s.querySelector('h2').textContent);
    expect(verifiedIn).toHaveLength(1);
    expect(verifiedIn[0]).toMatch(/Verified evidence \(authentic\)/);
    expect(screen.getByText(/Rejected: claimed VERIFIED, failed authentication/)).toBeInTheDocument();
  });
  test('tabs are keyboard operable (arrow keys)', async () => {
    const user = userEvent.setup();
    renderApp('/cases/acct-1/case-1', base('analyst', { '/api/cases/acct-1/case-1': { body: header }, '/api/cases/acct-1/case-1/timeline': { body: { items: [], truncated: false } }, '/api/cases/acct-1/case-1/evidence': { body: { memories: [], rejected: [], totals: {}, note: '', decisionCount: 0 } } }));
    await screen.findByText('Case investigation');
    screen.getByRole('tab', { name: 'Timeline' }).focus();
    await user.keyboard('{ArrowRight}');
    expect(screen.getByRole('tab', { name: /Claims & evidence/ })).toHaveAttribute('aria-selected', 'true');
  });
});
