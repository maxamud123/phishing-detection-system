import { useState, useEffect } from 'react';
import { Users, FileText, Activity, Shield, Plus, Trash2, X, Check, Database, Cpu, Clock, HardDrive, ScrollText, RefreshCw, Lock, PowerOff, Power, WifiOff, Monitor } from 'lucide-react';
import { UsersAPI, AdminAPI, SessionsAPI, User, AuditLog, ActiveSession } from '../lib/api';
import { cardStyle, inputStyle } from '../lib/styles';

const permissions = [
  { label: 'View Dashboard',     admin: true,  user: true  },
  { label: 'Run Scans',          admin: true,  user: true  },
  { label: 'Submit Reports',     admin: true,  user: true  },
  { label: 'Manage Reports',     admin: true,  user: true  },
  { label: 'View Analytics',     admin: true,  user: true  },
  { label: 'Manage Users',       admin: true,  user: false },
  { label: 'System Config',      admin: true,  user: false },
  { label: 'Access Admin Panel', admin: true,  user: false },
];

interface DbStats {
  connected: boolean;
  collections: { users: number; reports: number; scans: number; audit_logs: number };
}

type AdminSection = 'users' | 'audit' | 'monitoring' | 'sessions';

export function Admin() {
  const [activeSection, setActiveSection] = useState<AdminSection>('users');
  const [users, setUsers] = useState<User[]>([]);
  const [dbStats, setDbStats] = useState<DbStats | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showUserForm, setShowUserForm] = useState(false);

  // Sessions state
  const [sessions,        setSessions]        = useState<ActiveSession[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [killingSess,     setKillingSess]     = useState<string | null>(null);

  // Reset password modal state
  const [resetTarget, setResetTarget]   = useState<User | null>(null);
  const [resetPwd,    setResetPwd]      = useState('');
  const [resetSaving, setResetSaving]   = useState(false);
  const [resetErr,    setResetErr]      = useState('');

  const fetchSessions = async () => {
    setSessionsLoading(true);
    try {
      const res = await SessionsAPI.getAll();
      if (res.success) setSessions(res.data);
    } catch { /* ignore */ }
    finally { setSessionsLoading(false); }
  };

  const handleKillSession = async (id: string) => {
    setKillingSess(id);
    try {
      const res = await SessionsAPI.kill(id);
      if (res.success) setSessions(prev => prev.filter(s => s._id !== id));
    } catch { /* ignore */ }
    finally { setKillingSess(null); }
  };

  const handleToggleStatus = async (user: User) => {
    const next = !user.disabled;
    const res  = await UsersAPI.toggleStatus(user.userId, next);
    if (res.success) setUsers(prev => prev.map(u => u.userId === user.userId ? { ...u, disabled: next } : u));
    else setError(res.error || 'Failed to update status.');
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetTarget) return;
    setResetErr('');
    if (resetPwd.length < 6) { setResetErr('Password must be at least 6 characters.'); return; }
    setResetSaving(true);
    try {
      const res = await UsersAPI.resetPassword(resetTarget.userId, resetPwd);
      if (res.success) { setResetTarget(null); setResetPwd(''); }
      else setResetErr(res.error || 'Failed to reset password.');
    } catch { setResetErr('Server error.'); }
    finally { setResetSaving(false); }
  };

  // Add user form state
  const [formName, setFormName]       = useState('');
  const [formEmail, setFormEmail]     = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [submitting, setSubmitting]   = useState(false);
  const [formError, setFormError]     = useState('');

  useEffect(() => { fetchData(); }, []);

  const fetchAuditLogs = async () => {
    setAuditLoading(true);
    try {
      const res = await AdminAPI.auditLogs();
      if (res.success) setAuditLogs(res.data);
    } catch { /* ignore */ }
    finally { setAuditLoading(false); }
  };

  useEffect(() => {
    if (activeSection === 'audit'    && auditLogs.length === 0) fetchAuditLogs();
    if (activeSection === 'sessions' && sessions.length === 0)  fetchSessions();
  }, [activeSection]);

  const fetchData = async () => {
    setLoading(true);
    setError('');
    try {
      const [usersRes, statsRes] = await Promise.all([
        UsersAPI.getAll(),
        AdminAPI.dbStats(),
      ]);
      if (usersRes.success) setUsers(usersRes.data);
      else setError(usersRes.error || 'Failed to load users.');
      if (statsRes.success) setDbStats(statsRes as DbStats);
    } catch {
      setError('Cannot connect to server. Is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteUser = async (userId: string) => {
    try {
      await UsersAPI.delete(userId);
      setUsers(prev => prev.filter(u => u.userId !== userId));
    } catch {
      setError('Failed to delete user.');
    }
  };

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');
    setSubmitting(true);
    try {
      const data = await UsersAPI.create({
        name: formName, email: formEmail,
        password: formPassword,
      });
      if (data.success && data.user) {
        setUsers(prev => [...prev, data.user]);
        setShowUserForm(false);
        setFormName(''); setFormEmail(''); setFormPassword('');
      } else {
        setFormError(data.error || 'Failed to create user.');
      }
    } catch {
      setFormError('Server error. Try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const getRoleStyle = (role: string) => {
    switch (role) {
      case 'Admin': return { color: '#C8909A', backgroundColor: 'rgba(200, 144, 154, 0.12)', border: '1px solid rgba(200, 144, 154, 0.3)' };
      default:      return { color: '#F0C0C8', backgroundColor: 'rgba(240, 192, 200, 0.12)', border: '1px solid rgba(240, 192, 200, 0.3)' };
    }
  };

  // Build stat cards from real db data
  const systemStats = [
    {
      label: 'Total Users',      value: dbStats ? String(dbStats.collections.users)          : '—',
      icon: Users,    color: '#F0C0C8', bg: 'rgba(240, 192, 200, 0.1)',    border: 'rgba(240, 192, 200, 0.25)',
    },
    {
      label: 'Active Sessions',  value: dbStats ? String(dbStats.collections.activeSessions) : '—',
      icon: Monitor,  color: '#22c55e', bg: 'rgba(34, 197, 94, 0.1)',    border: 'rgba(34, 197, 94, 0.25)',
    },
    {
      label: 'Total Scans',      value: dbStats ? String(dbStats.collections.scans)          : '—',
      icon: Activity, color: '#C8909A', bg: 'rgba(200, 144, 154, 0.1)', border: 'rgba(200, 144, 154, 0.25)',
    },
    {
      label: 'Audit Logs',       value: dbStats ? String(dbStats.collections.audit_logs)     : '—',
      icon: Shield,   color: '#ef4444', bg: 'rgba(239, 68, 68, 0.1)',   border: 'rgba(239, 68, 68, 0.25)',
    },
  ];

  const monitoring = [
    { label: 'Database Status',   value: dbStats?.connected ? 'Healthy' : 'Offline', icon: Database, color: dbStats?.connected ? '#22c55e' : '#ef4444', bg: dbStats?.connected ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239,68,68,0.1)', border: dbStats?.connected ? 'rgba(34, 197, 94, 0.25)' : 'rgba(239,68,68,0.25)', barPct: dbStats?.connected ? 100 : 0 },
    { label: 'API Response Time', value: '< 200ms',  icon: Cpu,       color: '#22c55e', bg: 'rgba(34, 197, 94, 0.1)',   border: 'rgba(34, 197, 94, 0.25)',   barPct: 95 },
    { label: 'Active Sessions',   value: 'Live',     icon: Clock,     color: '#F0C0C8', bg: 'rgba(240, 192, 200, 0.1)',  border: 'rgba(240, 192, 200, 0.25)',   barPct: 75 },
    { label: 'Storage Used',      value: 'MongoDB',  icon: HardDrive, color: '#fbbf24', bg: 'rgba(251, 191, 36, 0.1)', border: 'rgba(251, 191, 36, 0.25)',  barPct: 60 },
  ];

  const actionColor = (action: string) => {
    if (action.includes('DELETE')) return { color: '#ef4444', bg: 'rgba(239,68,68,0.1)' };
    if (action.includes('CREATE') || action.includes('SIGNUP')) return { color: '#22c55e', bg: 'rgba(34,197,94,0.1)' };
    if (action.includes('LOGIN')) return { color: '#F0C0C8', bg: 'rgba(240, 192, 200,0.1)' };
    return { color: '#C8909A', bg: 'rgba(200, 144, 154,0.1)' };
  };

  return (
    <div className="space-y-6">
      {error && (
        <div className="px-4 py-3 rounded-xl flex items-center gap-2"
          style={{ backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)' }}>
          <span style={{ fontSize: '13px', color: '#ef4444' }}>{error}</span>
        </div>
      )}

      {/* Section tabs */}
      <div className="flex p-1 rounded-xl gap-1 w-fit" style={{ backgroundColor: '#1E000A', border: '1px solid #4A001A' }}>
        {([
          { id: 'users'      as AdminSection, icon: Users,      label: 'User Management' },
          { id: 'sessions'   as AdminSection, icon: Monitor,    label: 'Active Sessions' },
          { id: 'audit'      as AdminSection, icon: ScrollText, label: 'Audit Logs' },
          { id: 'monitoring' as AdminSection, icon: Activity,   label: 'Monitoring' },
        ]).map(({ id, icon: Icon, label }) => (
          <button key={id} type="button" onClick={() => setActiveSection(id)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg transition-all"
            style={activeSection === id
              ? { backgroundColor: 'rgba(240, 192, 200,0.12)', color: '#F0C0C8', border: '1px solid rgba(240, 192, 200,0.3)', fontWeight: 600, fontSize: '13px' }
              : { color: '#C8909A', border: '1px solid transparent', fontSize: '13px' }}>
            <Icon className="w-4 h-4" />{label}
          </button>
        ))}
      </div>

      {/* System Stat Cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        {systemStats.map(s => {
          const Icon = s.icon;
          return (
            <div key={s.label} className="p-4 rounded-2xl transition-all hover:-translate-y-0.5 duration-200"
              style={{ ...cardStyle, border: `1px solid ${s.border}` }}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl" style={{ backgroundColor: s.bg }}>
                  <Icon className="w-5 h-5" style={{ color: s.color }} />
                </div>
                <div>
                  <div style={{ fontSize: '22px', fontWeight: 800, color: 'white', lineHeight: 1 }}>
                    {loading ? '…' : s.value}
                  </div>
                  <div style={{ fontSize: '11px', color: '#C8909A', marginTop: '3px' }}>{s.label}</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* ── AUDIT LOG SECTION ── */}
      {activeSection === 'audit' && (
        <div className="p-5" style={cardStyle}>
          <div className="flex items-center justify-between mb-5">
            <div>
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'white' }}>Audit Log</h3>
              <p style={{ fontSize: '12px', color: '#8B4555', marginTop: '2px' }}>All system actions — logins, scans, user changes, report updates</p>
            </div>
            <button type="button" onClick={fetchAuditLogs} disabled={auditLoading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all"
              style={{ color: '#F0C0C8', backgroundColor: 'rgba(240, 192, 200,0.08)', border: '1px solid rgba(240, 192, 200,0.2)', fontSize: '12px' }}>
              <RefreshCw className={`w-3.5 h-3.5 ${auditLoading ? 'animate-spin' : ''}`} />Refresh
            </button>
          </div>

          {auditLoading ? (
            <div className="py-10 text-center" style={{ color: '#8B4555', fontSize: '14px' }}>Loading audit logs…</div>
          ) : auditLogs.length === 0 ? (
            <div className="py-10 text-center" style={{ color: '#8B4555', fontSize: '14px' }}>No audit logs found.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full" style={{ borderCollapse: 'collapse', minWidth: '620px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #4A001A' }}>
                    {['Action', 'User', 'Details', 'Timestamp'].map(h => (
                      <th key={h} className="text-left py-3 px-3"
                        style={{ fontSize: '11px', color: '#8B4555', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((log, i) => {
                    const ac = actionColor(log.action);
                    return (
                      <tr key={i}
                        style={{ borderBottom: '1px solid rgba(26,32,64,0.6)', transition: 'background-color 0.15s' }}
                        onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
                        onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
                        <td className="py-3 px-3">
                          <span className="px-2 py-0.5 rounded text-xs font-bold" style={{ color: ac.color, backgroundColor: ac.bg }}>
                            {log.action}
                          </span>
                        </td>
                        <td className="py-3 px-3" style={{ fontSize: '12px', color: '#94a3b8' }}>{log.userName}</td>
                        <td className="py-3 px-3 max-w-xs">
                          <span className="truncate block" style={{ fontSize: '12px', color: '#C8909A' }}>{log.details}</span>
                        </td>
                        <td className="py-3 px-3" style={{ fontSize: '11px', color: '#8B4555', whiteSpace: 'nowrap' }}>
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── USER MANAGEMENT SECTION ── */}
      {activeSection === 'users' && <div className="p-5" style={cardStyle}>
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'white' }}>User Management</h3>
            <p style={{ fontSize: '12px', color: '#8B4555', marginTop: '2px' }}>
              {loading ? 'Loading…' : `${users.length} total users`}
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowUserForm(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl transition-all hover:opacity-90"
            style={{ background: 'linear-gradient(135deg, #F0C0C8, #0099bb)', color: '#3A0015', fontWeight: 700, fontSize: '13px', boxShadow: '0 0 20px rgba(240, 192, 200, 0.2)' }}
          >
            <Plus className="w-4 h-4" />
            Add User
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full" style={{ borderCollapse: 'collapse', minWidth: '600px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #4A001A' }}>
                {['Name', 'Email', 'Role', 'Logins', 'Last Login', 'Status', ''].map(h => (
                  <th key={h} className="text-left py-3 px-3" style={{ fontSize: '11px', color: '#8B4555', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={5} className="py-10 text-center" style={{ color: '#8B4555', fontSize: '14px' }}>Loading users…</td>
                </tr>
              ) : users.map(user => (
                <tr key={user.userId}
                  style={{ borderBottom: '1px solid rgba(26, 32, 64, 0.6)', transition: 'background-color 0.15s', opacity: user.disabled ? 0.5 : 1 }}
                  onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
                  onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-lg flex items-center justify-center text-xs shrink-0"
                        style={{ background: 'linear-gradient(135deg, #F0C0C822, #F0C0C844)', color: '#F0C0C8', fontWeight: 700 }}>
                        {user.name.split(' ').map((n: string) => n[0]).join('').slice(0, 2)}
                      </div>
                      <span style={{ fontSize: '13px', color: 'white', fontWeight: 500 }}>{user.name}</span>
                    </div>
                  </td>
                  <td className="py-3 px-3" style={{ fontSize: '12px', color: '#C8909A' }}>{user.email}</td>
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded-lg text-xs" style={{ ...getRoleStyle(user.role), fontWeight: 600 }}>
                      {user.role}
                    </span>
                  </td>
                  <td className="py-3 px-3" style={{ fontSize: '12px', color: '#C8909A', textAlign: 'center' }}>
                    {user.loginCount ?? 0}
                  </td>
                  <td className="py-3 px-3" style={{ fontSize: '11px', color: '#8B4555' }}>
                    {user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'Never'}
                  </td>
                  <td className="py-3 px-3">
                    <span className={`px-2 py-0.5 rounded-lg text-xs font-semibold ${user.disabled ? 'user-status-disabled' : 'user-status-active'}`}>
                      {user.disabled ? 'Disabled' : 'Active'}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    <div className="flex gap-1">
                      <button type="button" onClick={() => { setResetTarget(user); setResetPwd(''); setResetErr(''); }}
                        className="p-1.5 rounded-lg transition-colors hover:bg-white/5"
                        style={{ color: '#8B4555' }} title="Reset password" aria-label={`Reset password for ${user.name}`}>
                        <Lock className="w-3.5 h-3.5" />
                      </button>
                      {user.role !== 'Admin' && (
                        <button type="button" onClick={() => handleToggleStatus(user)}
                          className="p-1.5 rounded-lg transition-colors hover:bg-white/5"
                          style={{ color: user.disabled ? '#22c55e' : '#f59e0b' }}
                          title={user.disabled ? 'Enable user' : 'Disable user'}
                          aria-label={user.disabled ? `Enable ${user.name}` : `Disable ${user.name}`}>
                          {user.disabled ? <Power className="w-3.5 h-3.5" /> : <PowerOff className="w-3.5 h-3.5" />}
                        </button>
                      )}
                      <button type="button" onClick={() => handleDeleteUser(user.userId)}
                        className="p-1.5 rounded-lg transition-colors"
                        style={{ color: '#8B4555' }}
                        onMouseEnter={e => (e.currentTarget.style.color = '#ef4444')}
                        onMouseLeave={e => (e.currentTarget.style.color = '#8B4555')}
                        title="Delete user" aria-label={`Delete user ${user.name}`}>
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>}

      {/* ── ACTIVE SESSIONS SECTION ── */}
      {activeSection === 'sessions' && (
        <div className="p-5" style={cardStyle}>
          <div className="flex items-center justify-between mb-5">
            <div>
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'white' }}>Active Sessions</h3>
              <p style={{ fontSize: '12px', color: '#8B4555', marginTop: '2px' }}>
                All currently logged-in sessions — click Terminate to force logout
              </p>
            </div>
            <button type="button" onClick={fetchSessions} disabled={sessionsLoading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all"
              style={{ color: '#F0C0C8', backgroundColor: 'rgba(240, 192, 200,0.08)', border: '1px solid rgba(240, 192, 200,0.2)', fontSize: '12px' }}>
              <RefreshCw className={`w-3.5 h-3.5 ${sessionsLoading ? 'animate-spin' : ''}`} />Refresh
            </button>
          </div>

          {sessionsLoading ? (
            <div className="py-10 text-center" style={{ color: '#8B4555', fontSize: '14px' }}>Loading sessions…</div>
          ) : sessions.length === 0 ? (
            <div className="py-10 text-center" style={{ color: '#8B4555', fontSize: '14px' }}>No active sessions.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full" style={{ borderCollapse: 'collapse', minWidth: '700px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #4A001A' }}>
                    {['User', 'Role', 'IP Address', 'Browser / Client', 'Logged In', 'Expires', ''].map(h => (
                      <th key={h} className="text-left py-3 px-3"
                        style={{ fontSize: '11px', color: '#8B4555', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {sessions.map(s => {
                    const ua = s.userAgent || '';
                    const browser = ua.includes('Firefox') ? 'Firefox'
                      : ua.includes('Edg') ? 'Edge'
                      : ua.includes('Chrome') ? 'Chrome'
                      : ua.includes('Safari') ? 'Safari'
                      : ua.includes('curl') ? 'curl'
                      : 'Unknown';
                    const os = ua.includes('Windows') ? 'Windows'
                      : ua.includes('Mac') ? 'macOS'
                      : ua.includes('Linux') ? 'Linux'
                      : ua.includes('Android') ? 'Android'
                      : ua.includes('iPhone') ? 'iOS'
                      : '';
                    const isExpired = new Date(s.expiresAt) < new Date();
                    return (
                      <tr key={s._id}
                        style={{ borderBottom: '1px solid rgba(26,32,64,0.6)', transition: 'background-color 0.15s' }}
                        onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
                        onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
                        <td className="py-3 px-3">
                          <div style={{ fontSize: '13px', color: 'white', fontWeight: 500 }}>{s.name}</div>
                          <div style={{ fontSize: '11px', color: '#8B4555' }}>{s.email}</div>
                        </td>
                        <td className="py-3 px-3">
                          <span className="px-2 py-0.5 rounded-lg text-xs font-semibold"
                            style={s.role === 'Admin'
                              ? { color: '#C8909A', backgroundColor: 'rgba(200, 144, 154,0.12)', border: '1px solid rgba(200, 144, 154,0.3)' }
                              : { color: '#F0C0C8', backgroundColor: 'rgba(240, 192, 200,0.12)', border: '1px solid rgba(240, 192, 200,0.3)' }}>
                            {s.role}
                          </span>
                        </td>
                        <td className="py-3 px-3" style={{ fontSize: '12px', color: '#C8909A', fontFamily: 'monospace' }}>
                          {s.ipAddress || '—'}
                        </td>
                        <td className="py-3 px-3" style={{ fontSize: '12px', color: '#C8909A' }}>
                          {browser}{os ? ` / ${os}` : ''}
                        </td>
                        <td className="py-3 px-3" style={{ fontSize: '11px', color: '#8B4555', whiteSpace: 'nowrap' }}>
                          {new Date(s.createdAt).toLocaleString()}
                        </td>
                        <td className="py-3 px-3" style={{ fontSize: '11px', whiteSpace: 'nowrap', color: isExpired ? '#ef4444' : '#22c55e' }}>
                          {isExpired ? 'Expired' : new Date(s.expiresAt).toLocaleString()}
                        </td>
                        <td className="py-3 px-3">
                          <button type="button"
                            onClick={() => handleKillSession(s._id)}
                            disabled={killingSess === s._id}
                            className="flex items-center gap-1 px-2.5 py-1 rounded-lg transition-colors hover:bg-red-500/10"
                            style={{ color: '#ef4444', border: '1px solid rgba(239,68,68,0.25)', fontSize: '11px', fontWeight: 600, opacity: killingSess === s._id ? 0.5 : 1 }}>
                            <WifiOff className="w-3 h-3" />
                            {killingSess === s._id ? '…' : 'Terminate'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── MONITORING SECTION ── */}
      {activeSection === 'monitoring' && <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* System Monitoring */}
        <div className="p-5" style={cardStyle}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'white', marginBottom: '16px' }}>System Monitoring</h3>
          <div className="space-y-3">
            {monitoring.map(item => {
              const Icon = item.icon;
              return (
                <div key={item.label} className="p-3 rounded-xl" style={{ backgroundColor: '#1E000A', border: '1px solid #4A001A' }}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Icon className="w-4 h-4" style={{ color: item.color }} />
                      <span style={{ fontSize: '13px', color: '#94a3b8' }}>{item.label}</span>
                    </div>
                    <span className="px-2.5 py-0.5 rounded-lg text-xs"
                      style={{ color: item.color, backgroundColor: item.bg, border: `1px solid ${item.border}`, fontWeight: 600 }}>
                      {item.value}
                    </span>
                  </div>
                  <div className="w-full h-1 rounded-full overflow-hidden" style={{ backgroundColor: '#4A001A' }}>
                    <div className="h-1 rounded-full transition-all duration-700"
                      style={{ width: `${item.barPct}%`, backgroundColor: item.color, boxShadow: `0 0 6px ${item.color}` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Permissions Matrix */}
        <div className="p-5" style={cardStyle}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'white', marginBottom: '16px' }}>Permissions Matrix</h3>
          <div className="overflow-x-auto">
            <table className="w-full" style={{ borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #4A001A' }}>
                  <th className="text-left py-2 px-2" style={{ fontSize: '11px', color: '#8B4555', fontWeight: 600, width: '50%' }}>Permission</th>
                  {[{ label: 'Admin', color: '#C8909A' }, { label: 'User', color: '#F0C0C8' }].map(({ label, color }) => (
                    <th key={label} className="text-center py-2 px-2" style={{ fontSize: '11px', color, fontWeight: 600 }}>{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {permissions.map((p, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid rgba(26, 32, 64, 0.5)', transition: 'background-color 0.15s' }}
                    onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
                    onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}>
                    <td className="py-2 px-2" style={{ fontSize: '12px', color: '#94a3b8' }}>{p.label}</td>
                    {[p.admin, p.user].map((allowed, j) => (
                      <td key={j} className="py-2 px-2 text-center">
                        {allowed ? (
                          <div className="inline-flex items-center justify-center w-5 h-5 rounded-full" style={{ backgroundColor: 'rgba(34, 197, 94, 0.15)' }}>
                            <Check className="w-3 h-3" style={{ color: '#22c55e' }} />
                          </div>
                        ) : (
                          <div className="inline-flex items-center justify-center w-5 h-5 rounded-full" style={{ backgroundColor: 'rgba(74, 96, 128, 0.15)' }}>
                            <span style={{ fontSize: '10px', color: '#4A001A' }}>—</span>
                          </div>
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>}

      {/* Add User Modal */}
      {showUserForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 admin-modal-overlay">
          <div className="w-full max-w-md admin-modal-card">
            <div className="flex items-center justify-between mb-6">
              <h3 className="admin-modal-title">Add New User</h3>
              <button type="button" aria-label="Close" onClick={() => setShowUserForm(false)} className="p-2 rounded-lg hover:bg-white/5 transition-colors" style={{ color: '#C8909A' }}>
                <X className="w-5 h-5" />
              </button>
            </div>
            {formError && (
              <div className="mb-4 px-4 py-3 rounded-xl" style={{ backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)' }}>
                <span style={{ fontSize: '13px', color: '#ef4444' }}>{formError}</span>
              </div>
            )}
            <form className="space-y-4" onSubmit={handleAddUser}>
              <div>
                <label style={{ fontSize: '12px', color: '#C8909A', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Full Name</label>
                <input type="text" value={formName} onChange={e => setFormName(e.target.value)} placeholder="Enter full name" style={{ ...inputStyle, width: '100%' }} required />
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#C8909A', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Email Address</label>
                <input type="email" value={formEmail} onChange={e => setFormEmail(e.target.value)} placeholder="Enter email" style={{ ...inputStyle, width: '100%' }} required />
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#C8909A', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Password</label>
                <input type="password" value={formPassword} onChange={e => setFormPassword(e.target.value)} placeholder="Min 6 characters" style={{ ...inputStyle, width: '100%' }} required minLength={6} />
              </div>
              <div className="flex gap-3 pt-2">
                <button type="submit" disabled={submitting} className="flex-1 py-3 rounded-xl hover:opacity-90 transition-all admin-modal-btn-primary"
                  style={{ opacity: submitting ? 0.6 : 1 }}>
                  {submitting ? 'Creating…' : 'Add User'}
                </button>
                <button type="button" onClick={() => setShowUserForm(false)} className="flex-1 py-3 rounded-xl hover:bg-white/5 transition-colors admin-modal-btn-cancel">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Reset Password Modal */}
      {resetTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 admin-modal-overlay">
          <div className="w-full max-w-sm admin-modal-card">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="admin-modal-title">Reset Password</h3>
                <p className="admin-modal-sub">{resetTarget.name}</p>
              </div>
              <button type="button" onClick={() => setResetTarget(null)} className="p-2 rounded-lg hover:bg-white/5" style={{ color: '#C8909A' }} aria-label="Close">
                <X className="w-4 h-4" />
              </button>
            </div>
            <form onSubmit={handleResetPassword} className="space-y-4">
              <div>
                <label style={{ fontSize: '12px', color: '#C8909A', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>New Password</label>
                <input type="password" value={resetPwd} onChange={e => setResetPwd(e.target.value)}
                  placeholder="Min 6 characters" style={{ ...inputStyle, width: '100%' }} required minLength={6} autoFocus />
              </div>
              {resetErr && <p className="admin-modal-error">{resetErr}</p>}
              <div className="flex gap-3 pt-1">
                <button type="submit" disabled={resetSaving} className="flex-1 py-2.5 rounded-xl hover:opacity-90 transition-all admin-modal-btn-primary"
                  style={{ opacity: resetSaving ? 0.6 : 1 }}>
                  {resetSaving ? 'Saving…' : 'Set Password'}
                </button>
                <button type="button" onClick={() => setResetTarget(null)} className="flex-1 py-2.5 rounded-xl hover:bg-white/5 transition-colors admin-modal-btn-cancel">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
