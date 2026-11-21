import { NavLink, Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom';
import { Icon } from './components/Icon.jsx';
import { Loading } from './components/ui.jsx';
import { canSeeAudit, useAuth } from './lib/auth.jsx';
import { usePrefs } from './lib/prefs.jsx';
import { About } from './pages/About.jsx';
import { Activity } from './pages/Activity.jsx';
import { Alerts } from './pages/Alerts.jsx';
import { Audit } from './pages/Audit.jsx';
import { CaseDetail } from './pages/CaseDetail.jsx';
import { Cases } from './pages/Cases.jsx';
import { DecisionDetail } from './pages/DecisionDetail.jsx';
import { Login } from './pages/Login.jsx';
import { Overview } from './pages/Overview.jsx';
import { Verification } from './pages/Verification.jsx';

function Shell() {
  const { user, signOut } = useAuth();
  const { mask, setMask, theme, setTheme } = usePrefs();
  const next = theme === 'dark' ? 'light' : 'dark';
  return (
    <>
      <a className="skip" href="#main">Skip to content</a>
      <div className="banner" role="note"><Icon name="info" /> <strong>Read-only investigation view.</strong> Nothing here blocks accounts or changes payroll. Synthetic-data proof of concept — not a production system.</div>
      <header className="topbar">
        <NavLink to="/" className="brand" aria-label="TrustTrace home"><span className="brand__mark" aria-hidden="true" />TrustTrace</NavLink>
        <nav aria-label="Main">
          <NavLink to="/" end>Overview</NavLink>
          <NavLink to="/alerts">Alerts</NavLink>
          <NavLink to="/cases">Cases</NavLink>
          <NavLink to="/activity">Agent activity</NavLink>
          <NavLink to="/verification">Verification</NavLink>
          {canSeeAudit(user) ? <NavLink to="/audit">Audit</NavLink> : null}
          <NavLink to="/about">About</NavLink>
        </nav>
        <div className="topbar__tools">
          <button type="button" className="btn btn--ghost" aria-pressed={!mask} onClick={() => setMask(!mask)} title="Account and case ids are masked by default. This is a display convenience, not access control.">
            <Icon name={mask ? 'eyeoff' : 'eye'} /> {mask ? 'Show full ids' : 'Hide ids'}
          </button>
          <button type="button" className="btn btn--ghost" onClick={() => setTheme(next)} aria-label={`Switch to ${next} theme`}><Icon name={next === 'dark' ? 'moon' : 'sun'} /></button>
          <span className="who" title={`Signed in as ${user?.username}`}>{user?.username} <span className="badge badge--role">{user?.role}</span></span>
          <button type="button" className="btn" onClick={signOut}>Sign out</button>
        </div>
      </header>
      <main id="main" tabIndex={-1}><Outlet /></main>
    </>
  );
}

function RequireAuth() {
  const { status } = useAuth();
  const loc = useLocation();
  if (status === 'loading') return <main><Loading label="Checking your session…" /></main>;
  if (status === 'out') return <Navigate to="/login" replace state={{ from: loc.pathname + loc.search }} />;
  return <Shell />;
}

function NotFound() {
  return <div className="page"><h1>Page not found</h1><p><NavLink to="/">Back to the overview</NavLink></p></div>;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<RequireAuth />}>
        <Route index element={<Overview />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="decisions/:id" element={<DecisionDetail />} />
        <Route path="cases" element={<Cases />} />
        <Route path="cases/:accountId/:caseId" element={<CaseDetail />} />
        <Route path="activity" element={<Activity />} />
        <Route path="verification" element={<Verification />} />
        <Route path="audit" element={<Audit />} />
        <Route path="about" element={<About />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
