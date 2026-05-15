import { useEffect, useRef } from 'react';
import { WS_URL } from '../lib/env';

export interface AppNotification {
  id: string;
  type: 'threat' | 'report' | 'system' | 'info';
  title: string;
  body: string;
  time: string;
  read: boolean;
}

type NotifHandler = (n: AppNotification) => void;
type ThreatHandler = (scan: { id: string; target: string; riskScore: number }) => void;

function formatTime(iso?: string) {
  const d = iso ? new Date(iso) : new Date();
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function useAppWebSocket(
  enabled: boolean,
  onNotification: NotifHandler,
  onThreatAlert?: ThreatHandler,
) {
  const onNotifRef = useRef(onNotification);
  const onThreatRef = useRef(onThreatAlert);
  onNotifRef.current = onNotification;
  onThreatRef.current = onThreatAlert;

  useEffect(() => {
    if (!enabled) return;
    let ws: WebSocket | null = null;
    let closed = false;

    try {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => {
        onNotifRef.current({
          id: `sys-${Date.now()}`,
          type: 'system',
          title: 'Live alerts connected',
          body: 'Real-time threat notifications are active.',
          time: formatTime(),
          read: false,
        });
      };
      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data as string);
          if (msg.type === 'THREAT_DETECTED' && msg.scan) {
            const { id, target, riskScore } = msg.scan;
            onThreatRef.current?.({ id, target, riskScore });
            onNotifRef.current({
              id: `threat-${id}-${Date.now()}`,
              type: 'threat',
              title: 'Threat detected',
              body: `${target} — risk score ${riskScore}`,
              time: formatTime(msg.scan.timestamp),
              read: false,
            });
          }
        } catch { /* ignore malformed */ }
      };
      ws.onerror = () => { /* backend may be down */ };
    } catch { /* WebSocket unsupported */ }

    return () => {
      closed = true;
      ws?.close();
    };
  }, [enabled]);
}
