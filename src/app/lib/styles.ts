/**
 * Shared style constants and helpers used across components.
 * Import from here instead of repeating inline.
 */

export const cardStyle = {
  backgroundColor: '#2A0010',
  border: '1px solid #4A001A',
  borderRadius: '16px',
} as const;

export const inputStyle: React.CSSProperties = {
  backgroundColor: '#1E000A',
  border: '1px solid #4A001A',
  borderRadius: '10px',
  color: '#F0D0D5',
  fontSize: '13px',
  outline: 'none',
  padding: '9px 14px',
};

/** Badge style for Safe / Suspicious / Dangerous threat levels */
export function getRiskStyle(level: string): React.CSSProperties {
  switch (level) {
    case 'Safe':       return { color: '#22c55e', backgroundColor: 'rgba(34, 197, 94, 0.12)',  border: '1px solid rgba(34, 197, 94, 0.3)'  };
    case 'Suspicious': return { color: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.12)', border: '1px solid rgba(251, 191, 36, 0.3)' };
    case 'Dangerous':  return { color: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.12)',  border: '1px solid rgba(239, 68, 68, 0.3)'  };
    default:           return { color: '#94a3b8', backgroundColor: 'rgba(148, 163, 184, 0.1)', border: '1px solid rgba(148, 163, 184, 0.2)' };
  }
}

/** Color string for a numeric risk score (used for text/bar coloring) */
export function getScoreColor(score: number): string {
  if (score >= 40) return '#ef4444';
  if (score >= 15) return '#fbbf24';
  return '#22c55e';
}
