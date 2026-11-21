import { useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/auth.jsx';

export function Login() {
  const { status, signIn, expired } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  if (status === 'in') return <Navigate to={loc.state?.from ?? '/'} replace />;

  async function submit(e) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true); setError(null);
    try { await signIn(String(f.get('username')), String(f.get('password'))); nav(loc.state?.from ?? '/', { replace: true }); }
    catch (err) { setError(err); } finally { setBusy(false); }
  }
  const msg = error ? (error.status === 429 ? 'Too many failed attempts. Wait a few minutes and try again.' : error.code === 'invalid_credentials' ? 'Invalid username or password.' : error.message) : null;

  return (
    <main className="login">
      <form className="card login__card" onSubmit={submit} aria-labelledby="login-h">
        <h1 id="login-h"><span className="brand__mark" aria-hidden="true" /> TrustTrace</h1>
        <p className="muted">Sign in to the read-only investigation dashboard.</p>
        {expired ? <div className="notice notice--warn" role="status"><strong>Your session ended.</strong> Sign in again.</div> : null}
        {msg ? <div className="notice notice--danger" role="alert"><strong>{msg}</strong></div> : null}
        <div className="field"><label htmlFor="u">Username</label><input id="u" name="username" autoComplete="username" required maxLength={64} autoFocus /></div>
        <div className="field"><label htmlFor="p">Password</label><input id="p" name="password" type="password" autoComplete="current-password" required maxLength={256} /></div>
        <button className="btn btn--primary" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        <p className="muted small">Accounts are created by an administrator. This view cannot change anything.</p>
      </form>
    </main>
  );
}
