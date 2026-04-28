/**
 * Phishing Detection System — API Client
 * Talks to the Node.js backend (proxied via Vite → localhost:3001)
 */

// ── Auth token helpers ────────────────────────────────────────────────────────
export function getToken(): string | null {
  return sessionStorage.getItem('pg_token');
}
export function setToken(token: string) {
  sessionStorage.setItem('pg_token', token);
}
export function getUser(): User | null {
  try { return JSON.parse(sessionStorage.getItem('pg_user') || 'null'); }
  catch { return null; }
}
export function setUser(user: User) {
  sessionStorage.setItem('pg_user', JSON.stringify(user));
}
export function clearSession() {
  sessionStorage.removeItem('pg_token');
  sessionStorage.removeItem('pg_user');
}
export function isLoggedIn(): boolean {
  return !!getToken() && !!getUser();
}

// ── Types ─────────────────────────────────────────────────────────────────────
export interface User {
  userId:     string;
  name:       string;
  email:      string;
  role:       'Admin' | 'User';
  disabled?:  boolean;
  createdAt?: string;
  lastLogin?: string;
  loginCount?: number;
}

export interface ActiveSession {
  _id:       string;
  userId:    string;
  name:      string;
  email:     string;
  role:      string;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
  expiresAt: string;
}

export interface Report {
  _id?:        string;
  id:          string;
  reporter:    string;
  type:        'Email' | 'URL' | 'SMS' | 'Social Media';
  target:      string;
  riskScore:   number;
  status:      'Confirmed Threat' | 'Pending' | 'False Positive';
  description: string;
  timestamp:   string;
  createdAt?:  string;
}

export interface Scan {
  _id?:       string;
  id:         string;
  target:     string;
  type:       'URL' | 'Email';
  result:     'Safe' | 'Suspicious' | 'Dangerous' | 'Unknown';
  riskScore:  number;
  aiPowered?: boolean;
  timestamp:  string;
  createdAt?: string;
}

export interface AuditLog {
  _id?:      string;
  action:    string;
  userId:    string;
  userName:  string;
  details:   string;
  ip?:       string | null;
  resource?: string | null;
  timestamp: string;
}

export interface PagedResponse<T> {
  data:  T[];
  total: number;
  page:  number;
  pages: number;
}

// ── Core fetch wrapper ────────────────────────────────────────────────────────
async function apiFetch<T = any>(
  url: string,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET',
  body?: object
): Promise<{ success: boolean; error?: string } & T> {
  const token = getToken();
  const opts: RequestInit = {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  };
  const res  = await fetch(url, opts);
  const data = await res.json();
  if (!res.ok && data.success === undefined) {
    return { success: false, error: data.error || data.message || `HTTP ${res.status}` } as { success: boolean; error?: string } & T;
  }
  return data;
}

// ── Auth API ──────────────────────────────────────────────────────────────────
export const AuthAPI = {
  async login(email: string, password: string) {
    const data = await apiFetch<{ token: string; user: User }>('/api/auth/login', 'POST', { email, password });
    if (data.success && data.token && data.user) {
      setToken(data.token);
      setUser(data.user);
    }
    return data;
  },

  async signup(payload: { name: string; email: string; password: string; confirmPassword: string }) {
    return apiFetch<{ user: User; message: string }>('/api/auth/signup', 'POST', payload);
  },

  async logout() {
    try { await apiFetch('/api/auth/logout', 'POST'); } catch { /* ignore */ }
    clearSession();
  },

  me:            () => apiFetch<{ user: User }>('/api/auth/me'),
  checkSetup:    () => apiFetch<{ needsSetup: boolean; dbConnected: boolean }>('/api/auth/check-setup'),
  changePassword:(currentPassword: string, newPassword: string) =>
    apiFetch('/api/auth/password', 'PUT', { currentPassword, newPassword }),
  updateProfile: (payload: { name?: string; email?: string }) =>
    apiFetch<{ user: User }>('/api/auth/profile', 'PUT', payload),
};

// ── Users API ─────────────────────────────────────────────────────────────────
export const UsersAPI = {
  getAll:       () => apiFetch<{ data: User[] }>('/api/users'),
  create:       (u: Partial<User> & { password: string }) => apiFetch<{ user: User }>('/api/users', 'POST', u),
  update:       (id: string, u: Partial<User> & { password?: string }) => apiFetch<{ user: User }>(`/api/users/${id}`, 'PUT', u),
  delete:       (id: string) => apiFetch(`/api/users/${id}`, 'DELETE'),
  toggleStatus: (id: string, disabled: boolean) => apiFetch<{ user: User }>(`/api/users/${id}/status`, 'PUT', { disabled }),
  resetPassword:(id: string, password: string) => apiFetch(`/api/users/${id}/reset-password`, 'PUT', { password }),
};

// ── Reports API ───────────────────────────────────────────────────────────────
export const ReportsAPI = {
  getAll:  (page = 1, limit = 50) =>
    apiFetch<PagedResponse<Report>>(`/api/reports?page=${page}&limit=${limit}`),
  create:  (r: Partial<Report>) => apiFetch<{ report: Report }>('/api/reports', 'POST', r),
  update:  (id: string, r: Partial<Report>) => apiFetch<{ report: Report }>(`/api/reports/${id}`, 'PUT', r),
  delete:  (id: string) => apiFetch(`/api/reports/${id}`, 'DELETE'),
};

// ── Analysis types ────────────────────────────────────────────────────────────
export interface ThreatFactor {
  layer:       string;
  label:       string;
  impact:      number;
  severity:    'safe' | 'warning' | 'danger';
  description: string;
}

export interface ExternalCheck {
  source: string;
  result: 'CLEAN' | 'THREAT' | 'WARNING' | 'N/A';
  detail: string;
  link?:  string | null;
}

export interface AnalysisResult {
  threatLevel:    'Safe' | 'Suspicious' | 'Dangerous';
  score:          number;
  factors:        ThreatFactor[];
  externalChecks: ExternalCheck[];
  domain:         string | null;
}

// ── Scans API ─────────────────────────────────────────────────────────────────
export const ScansAPI = {
  getAll:  (page = 1, limit = 50) =>
    apiFetch<PagedResponse<Scan>>(`/api/scans?page=${page}&limit=${limit}`),
  create:  (s: Partial<Scan>) => apiFetch<{ scan: Scan }>('/api/scans', 'POST', s),
  delete:  (id: string) => apiFetch(`/api/scans/${id}`, 'DELETE'),
  analyze: (target: string, type: 'URL' | 'Email') =>
    apiFetch<{ scan: Scan; analysis: AnalysisResult }>('/api/scan/analyze', 'POST', { target, type }),
  bulk:    (targets: string[], type: 'URL' | 'Email') =>
    apiFetch<{ results: (AnalysisResult & { target: string; scanId: string; error?: string })[]; total: number }>('/api/scan/bulk', 'POST', { targets, type }),
};

// ── Admin API ─────────────────────────────────────────────────────────────────
export const AdminAPI = {
  auditLogs: () => apiFetch<{ data: AuditLog[] }>('/api/audit-logs'),
  dbStats:   () => apiFetch<{ connected: boolean; dbName: string; collections: Record<string, number> }>('/api/db-stats'),
};

// ── Sessions API ──────────────────────────────────────────────────────────────
export const SessionsAPI = {
  getAll: () => apiFetch<{ data: ActiveSession[] }>('/api/sessions'),
  kill:   (id: string) => apiFetch(`/api/sessions/${id}`, 'DELETE'),
};

// ── Chat API ──────────────────────────────────────────────────────────────────
export const ChatAPI = {
  send: (messages: { role: 'user' | 'assistant'; content: string }[]) =>
    apiFetch<{ reply: string }>('/api/chat', 'POST', { messages }),
};

// ── CSV export helper ─────────────────────────────────────────────────────────
export function exportCSV(filename: string, rows: object[]) {
  if (!rows.length) return;
  const keys   = Object.keys(rows[0]);
  const header = keys.join(',');
  const body   = rows.map(r =>
    keys.map(k => {
      const v = String((r as any)[k] ?? '').replace(/"/g, '""');
      return v.includes(',') || v.includes('"') || v.includes('\n') ? `"${v}"` : v;
    }).join(',')
  ).join('\n');
  const blob = new Blob([header + '\n' + body], { type: 'text/csv' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
