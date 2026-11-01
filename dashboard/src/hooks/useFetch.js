import { useState, useEffect, useCallback } from 'react';

/**
 * Generic async data fetcher hook.
 * Usage: const { data, loading, error, refresh } = useFetch(fn, deps)
 */
export function useFetch(fetchFn, deps = []) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchFn();
      setData(res.data);
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || 'Request failed');
    } finally {
      setLoading(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => { load(); }, [load]);

  return { data, loading, error, refresh: load };
}

