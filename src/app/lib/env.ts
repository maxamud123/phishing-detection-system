/**
 * Runtime URLs — override via .env (see .env.example)
 */
function wsUrl(): string {
  const fromEnv = import.meta.env.VITE_WS_URL as string | undefined;
  if (fromEnv) return fromEnv;
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = import.meta.env.DEV ? 'localhost:3001' : window.location.host;
  return `${proto}//${host}`;
}

export const WS_URL = typeof window !== 'undefined' ? wsUrl() : 'ws://localhost:3001';
