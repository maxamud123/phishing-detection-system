import { useState, useEffect } from 'react';
import { Users, FileText, Activity, Shield, Plus, Trash2, X, Check, Database, Cpu, Clock, HardDrive, ScrollText, RefreshCw } from 'lucide-react';
import { UsersAPI, AdminAPI, User, AuditLog } from '../lib/api';

const cardStyle = {
  backgroundColor: '#0d1225',
  border: '1px solid #1a2040',
  borderRadius: '16px',
};

const inputStyle: React.CSSProperties = {
  backgroundColor: '#060b18',
  border: '1px solid #1a2040',
  borderRadius: '10px',
  color: 'white',
  fontSize: '13px',
  outline: 'none',
  padding: '9px 14px',
};

const permissions = [
  { label: 'View Dashboard',   admin: true,  analyst: true,  viewer: true  },
  { label: 'Run Scans',        admin: true,  analyst: true,  viewer: true  },
  { label: 'Submit Reports',   admin: true,  analyst: true,  viewer: false },
  { label: 'Manage Reports',   admin: true,  analyst: true,  viewer: false },
  { label: 'View Analytics',   admin: true,  analyst: true,  viewer: false },
  { label: 'Manage Users',     admin: true,  analyst: false, viewer: false },
  { label: 'System Config',    admin: true,  analyst: false, viewer: false },
  { label: 'Access Admin Panel', admin: true, analyst: false, viewer: false },
];

interface DbStats {
  connected: boolean;
  collections: { users: number; reports: number; scans: number; audit_logs: number };
}

type AdminSection = 'users' | 'audit' | 'monitoring';

export function Admin() {
  const [activeSection, setActiveSection] = useState<AdminSection>('users');
  const [users, setUsers] = useState<User[]>([]);
  const [dbStats, setDbStats] = useState<DbStats | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showUserForm, setShowUserForm] = useState(false);

  // Add user form state
  const [formName, setFormName]       = useState('');
  const [formEmail, setFormEmail]     = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [formRole, setFormRole]       = useState<User['role']>('Viewer');
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
    if (activeSection === 'audit' && auditLogs.length === 0) fetchAuditLogs();
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
        password: formPassword, role: formRole,
      });
      if (data.success && data.user) {
        setUsers(prev => [...prev, data.user]);
        setShowUserForm(false);
        setFormName(''); setFormEmail(''); setFormPassword(''); setFormRole('Viewer');
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
      case 'Admin':   return { color: '#a78bfa', backgroundColor: 'rgba(167, 139, 250, 0.12)', border: '1px solid rgba(167, 139, 250, 0.3)' };
      case 'Analyst': return { color: '#00d4ff', backgroundColor: 'rgba(0, 212, 255, 0.12)', border: '1px solid rgba(0, 212, 255, 0.3)' };
      default:        return { color: '#94a3b8', backgroundColor: 'rgba(148, 163, 184, 0.1)', border: '1px solid rgba(148, 163, 184, 0.2)' };
    }
  };

  // Build stat cards from real db data
  const systemStats = [
    {
      label: 'Total Users',    value: dbStats ? String(dbStats.collections.users)   : '—',
      icon: Users,   color: '#00d4ff', bg: 'rgba(0, 212, 255, 0.1)',   border: 'rgba(0, 212, 255, 0.25)',
    },
    {
      label: 'Active Reports', value: dbStats ? String(dbStats.collections.reports) : '—',
      icon: FileText, color: '#22c55e', bg: 'rgba(34, 197, 94, 0.1)',  border: 'rgba(34, 197, 94, 0.25)',
    },
    {
      label: 'Total Scans',    value: dbStats ? String(dbStats.collections.scans)   : '—',
      icon: Activity, color: '#a78bfa', bg: 'rgba(167, 139, 250, 0.1)', border: 'rgba(167, 139, 250, 0.25)',
    },
    {
      label: 'Audit Logs',     value: dbStats ? String(dbStats.collections.audit_logs) : '—',
      icon: Shield,  color: '#ef4444', bg: 'rgba(239, 68, 68, 0.1)',   border: 'rgba(239, 68, 68, 0.25)',
    },
  ];

  const monitoring = [
    { label: 'Database Status',   value: dbStats?.connected ? 'Healthy' : 'Offline', icon: Database, color: dbStats?.connected ? '#22c55e' : '#ef4444', bg: dbStats?.connected ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239,68,68,0.1)', border: dbStats?.connected ? 'rgba(34, 197, 94, 0.25)' : 'rgba(239,68,68,0.25)', barPct: dbStats?.connected ? 100 : 0 },
    { label: 'API Response Time', value: '< 200ms',  icon: Cpu,       color: '#22c55e', bg: 'rgba(34, 197, 94, 0.1)',   border: 'rgba(34, 197, 94, 0.25)',   barPct: 95 },
    { label: 'Active Sessions',   value: 'Live',     icon: Clock,     color: '#00d4ff', bg: 'rgba(0, 212, 255, 0.1)',  border: 'rgba(0, 212, 255, 0.25)',   barPct: 75 },
    { label: 'Storage Used',      value: 'MongoDB',  icon: HardDrive, color: '#fbbf24', bg: 'rgba(251, 191, 36, 0.1)', border: 'rgba(251, 191, 36, 0.25)',  barPct: 60 },
  ];

  const actionColor = (action: string) => {
    if (action.includes('DELETE')) return { color: '#ef4444', bg: 'rgba(239,68,68,0.1)' };
    if (action.includes('CREATE') || action.includes('SIGNUP')) return { color: '#22c55e', bg: 'rgba(34,197,94,0.1)' };
    if (action.includes('LOGIN')) return { color: '#00d4ff', bg: 'rgba(0,212,255,0.1)' };
    return { color: '#a78bfa', bg: 'rgba(167,139,250,0.1)' };
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
      <div className="flex p-1 rounded-xl gap-1 w-fit" style={{ backgroundColor: '#060b18', border: '1px solid #1a2040' }}>
        {([
          { id: 'users'      as AdminSection, icon: Users,      label: 'User Management' },
          { id: 'audit'      as AdminSection, icon: ScrollText, label: 'Audit Logs' },
          { id: 'monitoring' as AdminSection, icon: Activity,   label: 'Monitoring' },
        ]).map(({ id, icon: Icon, label }) => (
          <button key={id} type="button" onClick={() => setActiveSection(id)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg transition-all"
            style={activeSection === id
              ? { backgroundColor: 'rgba(0,212,255,0.12)', color: '#00d4ff', border: '1px solid rgba(0,212,255,0.3)', fontWeight: 600, fontSize: '13px' }
              : { color: '#6b7f9e', border: '1px solid transparent', fontSize: '13px' }}>
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
                  <div style={{ fontSize: '11px', color: '#6b7f9e', marginTop: '3px' }}>{s.label}</div>
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
              <p style={{ fontSize: '12px', color: '#4a6080', marginTop: '2px' }}>All system actions — logins, scans, user changes, report updates</p>
            </div>
            <button type="button" onClick={fetchAuditLogs} disabled={auditLoading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all"
              style={{ color: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)', fontSize: '12px' }}>
              <RefreshCw className={`w-3.5 h-3.5 ${auditLoading ? 'animate-spin' : ''}`} />Refresh
            </button>
          </div>

          {auditLoading ? (
            <div className="py-10 text-center" style={{ color: '#4a6080', fontSize: '14px' }}>Loading audit logs…</div>
          ) : auditLogs.length === 0 ? (
            <div className="py-10 text-center" style={{ color: '#4a6080', fontSize: '14px' }}>No audit logs found.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full" style={{ borderCollapse: 'collapse', minWidth: '620px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #1a2040' }}>
                    {['Action', 'User', 'Details', 'Timestamp'].map(h => (
                      <th key={h} className="text-left py-3 px-3"
                        style={{ fontSize: '11px', color: '#4a6080', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
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
                          <span className="truncate block" style={{ fontSize: '12px', color: '#6b7f9e' }}>{log.details}</span>
                        </td>
                        <td className="py-3 px-3" style={{ fontSize: '11px', color: '#4a6080', whiteSpace: 'nowrap' }}>
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
            <p style={{ fontSize: '12px', color: '#4a6080', marginTop: '2px' }}>
              {loading ? 'Loading…' : `${users.length} total users`}
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowUserForm(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl transition-all hover:opacity-90"
            style={{ background: 'linear-gradient(135deg, #00d4ff, #0099bb)', color: '#0a0e1a', fontWeight: 700, fontSize: '13px', boxShadow: '0 0 20px rgba(0, 212, 255, 0.2)' }}
          >
            <Plus className="w-4 h-4" />
            Add User
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full" style={{ borderCollapse: 'collapse', minWidth: '600px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1a2040' }}>
                {['Name', 'Email', 'Role', 'Last Login', ''].map(h => (
                  <th key={h} className="text-left py-3 px-3" style={{ fontSize: '11px', color: '#4a6080', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={5} className="py-10 text-center" style={{ color: '#4a6080', fontSize: '14px' }}>Loading users…</td>
                </tr>
              ) : users.map(user => (
                <tr key={user.userId}
                  style={{ borderBottom: '1px solid rgba(26, 32, 64, 0.6)', transition: 'background-color 0.15s' }}
                  onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
                  onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-lg flex items-center justify-center text-xs shrink-0"
                        style={{ background: 'linear-gradient(135deg, #00d4ff22, #00d4ff44)', color: '#00d4ff', fontWeight: 700 }}>
                        {user.name.split(' ').map(n => n[0]).join('').slice(0, 2)}
                      </div>
                      <span style={{ fontSize: '13px', color: 'white', fontWeight: 500 }}>{user.name}</span>
                    </div>
                  </td>
                  <td className="py-3 px-3" style={{ fontSize: '12px', color: '#6b7f9e' }}>{user.email}</td>
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded-lg text-xs" style={{ ...getRoleStyle(user.role), fontWeight: 600 }}>
                      {user.role}
                    </span>
                  </td>
                  <td className="py-3 px-3" style={{ fontSize: '11px', color: '#4a6080' }}>
                    {user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'Never'}
                  </td>
                  <td className="py-3 px-3">
                    <div className="flex gap-1">
                      <button
                        type="button"
                        onClick={() => handleDeleteUser(user.userId)}
                        className="p-1.5 rounded-lg transition-colors"
                        style={{ color: '#4a6080' }}
                        onMouseEnter={e => (e.currentTarget.style.color = '#ef4444')}
                        onMouseLeave={e => (e.currentTarget.style.color = '#4a6080')}
                        title="Delete user"
                        aria-label={`Delete user ${user.name}`}
                      >
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

      {/* ── MONITORING SECTION ── */}
      {activeSection === 'monitoring' && <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* System Monitoring */}
        <div className="p-5" style={cardStyle}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'white', marginBottom: '16px' }}>System Monitoring</h3>
          <div className="space-y-3">
            {monitoring.map(item => {
              const Icon = item.icon;
              return (
                <div key={item.label} className="p-3 rounded-xl" style={{ backgroundColor: '#060b18', border: '1px solid #1a2040' }}>
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
                  <div className="w-full h-1 rounded-full overflow-hidden" style={{ backgroundColor: '#1a2040' }}>
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
                <tr style={{ borderBottom: '1px solid #1a2040' }}>
                  <th className="text-left py-2 px-2" style={{ fontSize: '11px', color: '#4a6080', fontWeight: 600, width: '50%' }}>Permission</th>
                  {[{ label: 'Admin', color: '#a78bfa' }, { label: 'Analyst', color: '#00d4ff' }, { label: 'Viewer', color: '#94a3b8' }].map(({ label, color }) => (
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
                    {[p.admin, p.analyst, p.viewer].map((allowed, j) => (
                      <td key={j} className="py-2 px-2 text-center">
                        {allowed ? (
                          <div className="inline-flex items-center justify-center w-5 h-5 rounded-full" style={{ backgroundColor: 'rgba(34, 197, 94, 0.15)' }}>
                            <Check className="w-3 h-3" style={{ color: '#22c55e' }} />
                          </div>
                        ) : (
                          <div className="inline-flex items-center justify-center w-5 h-5 rounded-full" style={{ backgroundColor: 'rgba(74, 96, 128, 0.15)' }}>
                            <span style={{ fontSize: '10px', color: '#1a2040' }}>—</span>
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
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(4px)' }}>
          <div className="w-full max-w-md p-6 rounded-2xl" style={{ backgroundColor: '#0d1225', border: '1px solid #1a2040' }}>
            <div className="flex items-center justify-between mb-6">
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'white' }}>Add New User</h3>
              <button type="button" aria-label="Close" onClick={() => setShowUserForm(false)} className="p-2 rounded-lg hover:bg-white/5 transition-colors" style={{ color: '#6b7f9e' }}>
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
                <label style={{ fontSize: '12px', color: '#6b7f9e', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Full Name</label>
                <input type="text" value={formName} onChange={e => setFormName(e.target.value)} placeholder="Enter full name" style={{ ...inputStyle, width: '100%' }} required />
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7f9e', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Email Address</label>
                <input type="email" value={formEmail} onChange={e => setFormEmail(e.target.value)} placeholder="Enter email" style={{ ...inputStyle, width: '100%' }} required />
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7f9e', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Password</label>
                <input type="password" value={formPassword} onChange={e => setFormPassword(e.target.value)} placeholder="Min 6 characters" style={{ ...inputStyle, width: '100%' }} required minLength={6} />
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#6b7f9e', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Role</label>
                <select aria-label="Role" value={formRole} onChange={e => setFormRole(e.target.value as User['role'])} style={{ ...inputStyle, width: '100%', cursor: 'pointer' }}>
                  <option>Admin</option>
                  <option>Analyst</option>
                  <option>Viewer</option>
                </select>
              </div>
              <div className="flex gap-3 pt-2">
                <button type="submit" disabled={submitting} className="flex-1 py-3 rounded-xl hover:opacity-90 transition-all"
                  style={{ background: 'linear-gradient(135deg, #00d4ff, #0099bb)', color: '#0a0e1a', fontWeight: 700, fontSize: '13px', opacity: submitting ? 0.6 : 1 }}>
                  {submitting ? 'Creating…' : 'Add User'}
                </button>
                <button type="button" onClick={() => setShowUserForm(false)} className="flex-1 py-3 rounded-xl hover:bg-white/5 transition-colors"
                  style={{ color: '#6b7f9e', border: '1px solid #1a2040', fontSize: '13px' }}>
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
