import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { UNAUTHENTICATED_EVENT, getJson, login as apiLogin, logout as apiLogout } from './api.js';

const Ctx = createContext(null);
export const useAuth = () => useContext(Ctx);

export const canSeeAudit = (user) => user?.role === 'supervisor' || user?.role === 'admin';

/** Session state comes from the server (GET /api/auth/me); the cookie itself is HttpOnly and invisible to this code. */
export function AuthProvider({ children }) {
  const [state, setState] = useState({ status: 'loading', user: null, error: null });

  const refresh = useCallback(async () => {
    try {
      const me = await getJson('/api/auth/me');
      setState({ status: 'in', user: me.user, error: null, expiresAt: me.session?.expiresAt });
    } catch (e) {
      setState({ status: 'out', user: null, error: e.status === 401 ? null : e });
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    const onOut = () => setState((s) => (s.status === 'in' ? { status: 'out', user: null, error: null, expired: true } : s));
    globalThis.addEventListener(UNAUTHENTICATED_EVENT, onOut);
    return () => globalThis.removeEventListener(UNAUTHENTICATED_EVENT, onOut);
  }, []);

  const value = useMemo(() => ({
    ...state,
    async signIn(username, password) { const r = await apiLogin(username, password); setState({ status: 'in', user: r.user, error: null, expiresAt: r.expiresAt }); },
    async signOut() { try { await apiLogout(); } finally { setState({ status: 'out', user: null, error: null }); } },
  }), [state]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
