import { createContext, useContext, useEffect, useMemo, useState } from 'react';

const Ctx = createContext({ mask: true, setMask() {}, theme: 'system', setTheme() {} });
export const usePrefs = () => useContext(Ctx);

const read = (k, d) => { try { return sessionStorage.getItem(k) ?? localStorage.getItem(k) ?? d; } catch { return d; } };
const write = (store, k, v) => { try { window[store].setItem(k, v); } catch { /* storage may be blocked: preferences just won't persist */ } };

/** Display preferences only. Nothing sensitive is stored: ids are masked by default and the "show" choice lasts for the browser session. */
export function PrefsProvider({ children }) {
  const [mask, setMaskState] = useState(() => read('tt.mask', '1') !== '0');
  const [theme, setThemeState] = useState(() => read('tt.theme', 'system'));

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', theme);
  }, [theme]);

  const value = useMemo(() => ({
    mask, theme,
    setMask: (m) => { setMaskState(m); write('sessionStorage', 'tt.mask', m ? '1' : '0'); },
    setTheme: (t) => { setThemeState(t); write('localStorage', 'tt.theme', t); },
  }), [mask, theme]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
