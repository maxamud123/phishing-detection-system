import { useState, useEffect, useCallback } from 'react';

export interface SystemHealth {
  api: boolean;
  db: boolean;
  websocket: boolean;
  status: 'ok' | 'degraded' | 'unknown';
}

const POLL_MS = 30_000;

export function useSystemHealth(enabled: boolean) {
  const [health, setHealth] = useState<SystemHealth>({
    api: false,
    db: false,
    websocket: false,
    status: 'unknown',
  });

  const fetchHealth = useCallback(async () => {
    try {
      const res = await fetch('/api/health');
      const data = await res.json();
      if (data.success) {
        setHealth({
          api: true,
          db: !!data.db,
          websocket: !!data.websocket,
          status: data.status === 'ok' ? 'ok' : 'degraded',
        });
      } else {
        setHealth({ api: false, db: false, websocket: false, status: 'unknown' });
      }
    } catch {
      setHealth({ api: false, db: false, websocket: false, status: 'unknown' });
    }
  }, []);

  useEffect(() => {
    if (!enabled) return;
    fetchHealth();
    const id = setInterval(fetchHealth, POLL_MS);
    return () => clearInterval(id);
  }, [enabled, fetchHealth]);

  return { health, refresh: fetchHealth };
}
