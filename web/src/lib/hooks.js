import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { getJson } from './api.js';

/**
 * Load a resource. Re-fetches when path/params change; optional polling (paused while the tab is hidden).
 * Stale responses are discarded (AbortController), so a slow earlier request can never overwrite a newer one.
 * Returns { data, error, loading, reload, updatedAt }. `data` keeps the previous value while reloading (no flicker).
 */
export function useApi(path, { params, pollMs = 0, enabled = true } = {}) {
  const key = JSON.stringify([path, params ?? null]);
  const [state, setState] = useState({ data: null, error: null, loading: Boolean(enabled), updatedAt: null, key });
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    if (!enabled || !path) return undefined;
    const ctl = new AbortController();
    setState((s) => ({ ...s, loading: true, ...(s.key !== key ? { data: null, error: null } : {}), key }));
    getJson(path, { params, signal: ctl.signal }).then(
      (data) => setState({ data, error: null, loading: false, updatedAt: new Date(), key }),
      (error) => { if (error?.name !== 'AbortError') setState((s) => ({ ...s, error, loading: false, key })); },
    );
    return () => ctl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, tick, enabled]);

  useEffect(() => {
    if (!pollMs || !enabled) return undefined;
    const id = setInterval(() => { if (document.visibilityState !== 'hidden') setTick((n) => n + 1); }, pollMs);
    return () => clearInterval(id);
  }, [pollMs, enabled]);

  return { data: state.data, error: state.error, loading: state.loading, reload, updatedAt: state.updatedAt };
}

/**
 * Cursor-paged list. `params` identify the query (filters); changing them starts over. loadMore() appends the next page.
 * Items are de-duplicated by `idOf` so a poll/reload cannot show a row twice.
 */
export function usePaged(path, params, { idOf = (x) => x.id, enabled = true } = {}) {
  const key = JSON.stringify([path, params]);
  const [st, setSt] = useState({ items: [], next: null, loading: true, loadingMore: false, error: null, key, meta: null });
  const nextRef = useRef(null);
  const ctlRef = useRef(null);

  const fetchPage = useCallback((cursor, reset) => {
    ctlRef.current?.abort();
    const ctl = new AbortController();
    ctlRef.current = ctl;
    setSt((s) => ({ ...s, ...(reset ? { loading: true, items: [], next: null } : { loadingMore: true }), error: null }));
    getJson(path, { params: { ...params, cursor }, signal: ctl.signal }).then(
      (res) => {
        nextRef.current = res.nextCursor ?? null;
        setSt((s) => {
          const seen = new Set(reset ? [] : s.items.map(idOf));
          const add = res.items.filter((x) => !seen.has(idOf(x)));
          return { ...s, items: reset ? res.items : [...s.items, ...add], next: res.nextCursor ?? null, loading: false, loadingMore: false, error: null, meta: res.meta ?? null };
        });
      },
      (error) => { if (error?.name !== 'AbortError') setSt((s) => ({ ...s, loading: false, loadingMore: false, error })); },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  useEffect(() => {
    if (!enabled) return undefined;
    fetchPage(undefined, true);
    return () => ctlRef.current?.abort();
  }, [fetchPage, enabled]);

  return useMemo(() => ({
    items: st.items, loading: st.loading, loadingMore: st.loadingMore, error: st.error, hasMore: Boolean(st.next), meta: st.meta,
    loadMore: () => { if (nextRef.current) fetchPage(nextRef.current, false); },
    reload: () => fetchPage(undefined, true),
  }), [st, fetchPage]);
}
