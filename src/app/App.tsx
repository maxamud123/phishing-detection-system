import { useState, useRef, useEffect, useCallback } from 'react';
import {
  Shield, LayoutDashboard, ScanLine, FileText, History, BarChart2,
  Settings, Menu, Bell, ChevronRight, Wifi, LogOut, BookOpen,
  Search, Sun, Moon, X, AlertTriangle, CheckCircle, Info,
  AlertCircle, Zap, Clock, ArrowRight,
} from 'lucide-react';
import { Dashboard } from './components/Dashboard';
import { Scanner } from './components/Scanner';
import { Reports } from './components/Reports';
import { Admin } from './components/Admin';
import { ScanHistory } from './components/ScanHistory';
import { Analytics } from './components/Analytics';
import { KnowledgeBase } from './components/KnowledgeBase';
import { Profile } from './components/Profile';
import { Login } from './components/Login';
import { Signup } from './components/Signup';
import { ErrorBoundary } from './components/ErrorBoundary';
import { ChatBox } from './components/ChatBox';
import { AuthAPI, getUser, getToken, clearSession } from './lib/api';

// ── Types ──────────────────────────────────────────────────────────────────

type Tab = 'dashboard' | 'scanner' | 'reports' | 'scanhistory' | 'analytics' | 'knowledgebase' | 'admin' | 'profile';
type Theme = 'dark' | 'light';

interface AppNotification {
  id: string;
  type: 'threat' | 'report' | 'system' | 'info';
  title: string;
  body: string;
  time: string;
  read: boolean;
}

interface SearchResult {
  type: 'page' | 'scan' | 'report';
  label: string;
  sub: string;
  icon: any;
  action: () => void;
  badge?: { text: string; color: string; bg: string };
}

// ── Static data ────────────────────────────────────────────────────────────

const allNavItems = [
  { id: 'dashboard'     as Tab, label: 'Dashboard',      icon: LayoutDashboard, roles: ['Admin','User'] },
  { id: 'scanner'       as Tab, label: 'Threat Scanner',  icon: ScanLine,        roles: ['Admin','User'] },
  { id: 'reports'       as Tab, label: 'Reports',         icon: FileText,        roles: ['Admin','User'] },
  { id: 'scanhistory'   as Tab, label: 'Scan History',    icon: History,         roles: ['Admin','User'] },
  { id: 'analytics'     as Tab, label: 'Analytics',       icon: BarChart2,       roles: ['Admin','User'] },
  { id: 'knowledgebase' as Tab, label: 'Knowledge Base',  icon: BookOpen,        roles: ['Admin','User'] },
  { id: 'admin'         as Tab, label: 'Admin',           icon: Settings,        roles: ['Admin'] },
  { id: 'profile'       as Tab, label: 'My Profile',      icon: Shield,          roles: ['Admin','User'] },
];

const pageTitles: Record<Tab, string> = {
  dashboard:     'Dashboard Overview',
  scanner:       'Threat Scanner',
  reports:       'Reports Management',
  scanhistory:   'Scan History',
  analytics:     'Analytics',
  knowledgebase: 'Knowledge Base',
  admin:         'Admin Panel',
  profile:       'My Profile',
};

const INITIAL_NOTIFICATIONS: AppNotification[] = [];

function AccessDenied() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <p className="access-denied-title">Access Denied</p>
        <p className="access-denied-sub">Admin panel requires Admin role.</p>
      </div>
    </div>
  );
}

// ── Theme colour tokens ────────────────────────────────────────────────────

const tokens = {
  dark: {
    bg:            '#0a0e1a',
    sidebar:       '#2A0010',
    sidebarBorder: '#4A001A',
    header:        'rgba(13,18,37,0.95)',
    headerBorder:  '#4A001A',
    title:         'white',
    titleSub:      '#4a6080',
    navActive:     'rgba(0,212,255,0.1)',
    navActiveBorder: 'rgba(0,212,255,0.3)',
    navActiveColor:  '#00d4ff',
    navInactive:     '#6b7f9e',
    statusBg:      'rgba(0,255,128,0.06)',
    statusBorder:  'rgba(0,255,128,0.15)',
    dropBg:        '#2A0010',
    dropBorder:    '#4A001A',
    dropHover:     'rgba(255,255,255,0.03)',
    inputBg:       '#1E000A',
    accent:        '#00d4ff',
  },
  light: {
    bg:            '#f0f4f8',
    sidebar:       '#ffffff',
    sidebarBorder: '#e2e8f0',
    header:        'rgba(255,255,255,0.95)',
    headerBorder:  '#e2e8f0',
    title:         '#0f172a',
    titleSub:      '#64748b',
    navActive:     'rgba(0,153,187,0.1)',
    navActiveBorder: 'rgba(0,153,187,0.35)',
    navActiveColor:  '#0077aa',
    navInactive:     '#475569',
    statusBg:      'rgba(34,197,94,0.07)',
    statusBorder:  'rgba(34,197,94,0.2)',
    dropBg:        '#ffffff',
    dropBorder:    '#e2e8f0',
    dropHover:     'rgba(0,0,0,0.03)',
    inputBg:       '#f8fafc',
    accent:        '#0077aa',
  },
};

// ── Notification icon helper ───────────────────────────────────────────────

const notifMeta = {
  threat: { icon: AlertTriangle, color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.3)' },
  report: { icon: FileText,      color: '#a78bfa', bg: 'rgba(167,139,250,0.12)', border: 'rgba(167,139,250,0.3)' },
  system: { icon: Zap,           color: '#00d4ff', bg: 'rgba(0,212,255,0.12)',  border: 'rgba(0,212,255,0.3)' },
  info:   { icon: Info,          color: '#fbbf24', bg: 'rgba(251,191,36,0.12)', border: 'rgba(251,191,36,0.3)' },
};

// ── useClickOutside ────────────────────────────────────────────────────────

function useClickOutside(ref: React.RefObject<HTMLElement | null>, cb: () => void) {
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) cb();
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [ref, cb]);
}

// ══════════════════════════════════════════════════════════════════════════
export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(() => !!getToken() && !!getUser());
  const [showSignup, setShowSignup]   = useState(false);
  const [currentUser, setCurrentUser] = useState<{ email: string; role: string; name: string } | null>(() => {
    const u = getUser();
    return u ? { email: u.email, role: u.role, name: u.name } : null;
  });
  const [activeTab, setActiveTab] = useState<Tab>('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [theme, setTheme] = useState<Theme>('dark');

  // Notifications
  const [notifications, setNotifications] = useState<AppNotification[]>(INITIAL_NOTIFICATIONS);
  const [notifOpen, setNotifOpen] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);
  useClickOutside(notifRef, () => setNotifOpen(false));
  const unread = notifications.filter(n => !n.read).length;

  const markAllRead = () => setNotifications(ns => ns.map(n => ({ ...n, read: true })));
  const dismiss = (id: string) => setNotifications(ns => ns.filter(n => n.id !== id));

  // Search
  const [searchQuery, setSearchQuery] = useState('');
  const [searchOpen, setSearchOpen] = useState(false);
  const searchRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  useClickOutside(searchRef, () => setSearchOpen(false));

  const navigate = useCallback((tab: Tab) => {
    setActiveTab(tab);
    setSearchQuery('');
    setSearchOpen(false);
    setSidebarOpen(false);
  }, []);

  // Build search results
  const searchResults: SearchResult[] = (() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return [];
    const results: SearchResult[] = [];

    // Pages
    navItems.forEach(item => {
      if (item.label.toLowerCase().includes(q)) {
        results.push({
          type: 'page', label: item.label, sub: 'Navigate to page',
          icon: item.icon, action: () => navigate(item.id),
        });
      }
    });

    return results.slice(0, 8);
  })();

  // Keyboard shortcut: Ctrl+K / Cmd+K to open search
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setSearchOpen(true);
        setTimeout(() => searchInputRef.current?.focus(), 50);
      }
      if (e.key === 'Escape') { setSearchOpen(false); setNotifOpen(false); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const t = tokens[theme];
  const navItems = allNavItems.filter(item => item.roles.includes(currentUser?.role || ''));

  if (!isLoggedIn) {
    if (showSignup) {
      return (
        <Signup
          onSuccess={() => { setShowSignup(false); }}
          onBackToLogin={() => setShowSignup(false)}
        />
      );
    }
    return (
      <Login
        onLogin={(email, role, name) => {
          setCurrentUser({ email, role, name: name || email.split('@')[0] });
          setIsLoggedIn(true);
        }}
        onSignup={() => setShowSignup(true)}
      />
    );
  }


  return (
    <div
      className={`min-h-screen flex ${theme === 'light' ? 'light-theme' : ''}`}
      style={{ fontFamily: "'Inter', sans-serif", backgroundColor: t.bg, color: t.title }}
    >
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div className="fixed inset-0 z-40 bg-black/70 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      {/* ── Sidebar ────────────────────────────────────────────────────── */}
      <aside
        className={`sidebar-shell fixed top-0 left-0 h-full z-50 flex flex-col transition-transform duration-300 lg:translate-x-0 lg:static lg:z-auto ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
        style={{ width: '256px', backgroundColor: t.sidebar, borderRight: `1px solid ${t.sidebarBorder}`, flexShrink: 0 }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-6 py-5" style={{ borderBottom: `1px solid ${t.sidebarBorder}` }}>
          <div
            className="flex items-center justify-center w-10 h-10 rounded-xl"
            style={{ background: 'linear-gradient(135deg, #00d4ff22, #00d4ff44)', border: '1px solid #00d4ff55', boxShadow: '0 0 20px rgba(0,212,255,0.25)' }}
          >
            <Shield className="w-5 h-5" style={{ color: '#00d4ff' }} />
          </div>
          <div>
            <div style={{ fontSize: '15px', fontWeight: 700, letterSpacing: '0.02em', color: t.title }}>Phish Guard</div>
            <div style={{ fontSize: '11px', color: t.titleSub, fontWeight: 500 }}>SOC Platform</div>
          </div>
        </div>

        {/* Nav section label */}
        <div className="px-5 pt-4 pb-1">
          <span style={{ fontSize: '10px', fontWeight: 700, color: t.titleSub, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            Navigation
          </span>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 pb-4 space-y-0.5 overflow-y-auto">
          {navItems.map(item => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => navigate(item.id)}
                className="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl group"
                style={isActive
                  ? { backgroundColor: t.navActive, border: `1px solid ${t.navActiveBorder}`, color: t.navActiveColor,
                      boxShadow: `0 0 16px ${t.navActive}, inset 0 0 16px ${t.navActive}` }
                  : { backgroundColor: 'transparent', border: '1px solid transparent', color: t.navInactive }}
              >
                <Icon className="w-4 h-4 shrink-0" style={{ color: isActive ? t.navActiveColor : t.navInactive }} />
                <span style={{ fontSize: '13.5px', fontWeight: isActive ? 600 : 500 }}>{item.label}</span>
                {isActive && <ChevronRight className="w-3.5 h-3.5 ml-auto" style={{ color: t.navActiveColor }} />}
              </button>
            );
          })}
        </nav>

        {/* System status */}
        <div className="px-4 py-4" style={{ borderTop: `1px solid ${t.sidebarBorder}` }}>
          <div className="flex items-center gap-3 px-3 py-3 rounded-xl"
            style={{ backgroundColor: t.statusBg, border: `1px solid ${t.statusBorder}` }}>
            <div className="relative">
              <Wifi className="w-4 h-4" style={{ color: '#00ff80' }} />
              <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full"
                style={{ backgroundColor: '#00ff80', boxShadow: '0 0 6px #00ff80' }} />
            </div>
            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: '#00c060' }}>System Online</div>
              <div style={{ fontSize: '10px', color: t.titleSub }}>All services active</div>
            </div>
            <div className="ml-auto flex flex-col items-end gap-0.5">
              <div className="flex items-center gap-1">
                <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: '#22c55e' }} />
                <span style={{ fontSize: '9px', color: t.titleSub }}>API</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: '#22c55e' }} />
                <span style={{ fontSize: '9px', color: t.titleSub }}>DB</span>
              </div>
            </div>
          </div>
        </div>
      </aside>

      {/* ── Main area ──────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* ── Topbar ───────────────────────────────────────────────────── */}
        <header
          className="topbar sticky top-0 z-30 flex items-center gap-3 px-5 py-3"
          style={{ backgroundColor: t.header, borderBottom: `1px solid ${t.headerBorder}`, backdropFilter: 'blur(16px)' }}
        >
          {/* Mobile menu */}
          <button className="lg:hidden p-2 rounded-xl" style={{ color: t.navInactive }}
            onClick={() => setSidebarOpen(true)}>
            <Menu className="w-5 h-5" />
          </button>

          {/* Page title */}
          <div className="hidden sm:block mr-2">
            <h1 style={{ fontSize: '16px', fontWeight: 700, color: t.title, lineHeight: 1.2 }}>
              {pageTitles[activeTab]}
            </h1>
            <p style={{ fontSize: '11px', color: t.titleSub }}>{new Date().toLocaleDateString('en-US', { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' })}</p>
          </div>

          {/* ── Global search ── */}
          <div ref={searchRef} className="relative flex-1 max-w-xl">
            <div
              className="flex items-center gap-2 px-3 py-2 rounded-xl cursor-text"
              style={{ backgroundColor: t.inputBg, border: `1px solid ${t.sidebarBorder}` }}
              onClick={() => { setSearchOpen(true); setTimeout(() => searchInputRef.current?.focus(), 30); }}
            >
              <Search className="w-4 h-4 shrink-0" style={{ color: t.titleSub }} />
              <input
                ref={searchInputRef}
                type="text"
                value={searchQuery}
                onChange={e => { setSearchQuery(e.target.value); setSearchOpen(true); }}
                onFocus={() => setSearchOpen(true)}
                placeholder="Search pages, scans, reports…"
                className="flex-1 bg-transparent outline-none"
                style={{ fontSize: '13px', color: t.title, caretColor: '#00d4ff' }}
              />
              <kbd style={{ fontSize: '10px', color: t.titleSub, backgroundColor: t.dropBg,
                border: `1px solid ${t.sidebarBorder}`, borderRadius: '4px', padding: '1px 5px' }}>
                ⌘K
              </kbd>
            </div>

            {/* Search dropdown */}
            {searchOpen && (
              <div
                className="absolute top-full left-0 right-0 mt-1.5 rounded-2xl overflow-hidden z-50 dropdown-shadow"
                style={{ backgroundColor: t.dropBg, border: `1px solid ${t.dropBorder}` }}
              >
                {searchQuery.trim() === '' ? (
                  <div className="p-4">
                    <p style={{ fontSize: '11px', color: t.titleSub, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '8px' }}>
                      Quick Navigate
                    </p>
                    <div className="grid grid-cols-2 gap-1.5">
                      {navItems.map(item => {
                        const Icon = item.icon;
                        return (
                          <button
                            key={item.id}
                            onClick={() => navigate(item.id)}
                            className="flex items-center gap-2 px-3 py-2 rounded-xl text-left"
                            style={{ color: t.navInactive, backgroundColor: t.dropHover }}
                          >
                            <Icon className="w-3.5 h-3.5" style={{ color: t.accent }} />
                            <span style={{ fontSize: '12px' }}>{item.label}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ) : searchResults.length === 0 ? (
                  <div className="px-4 py-8 text-center">
                    <AlertCircle className="w-8 h-8 mx-auto mb-2 opacity-20" style={{ color: t.titleSub }} />
                    <p style={{ fontSize: '13px', color: t.titleSub }}>No results for "{searchQuery}"</p>
                  </div>
                ) : (
                  <div className="py-1.5">
                    {(['page', 'scan', 'report'] as const).map(type => {
                      const group = searchResults.filter(r => r.type === type);
                      if (!group.length) return null;
                      const labels = { page: 'Pages', scan: 'Recent Scans', report: 'Reports' };
                      return (
                        <div key={type}>
                          <p className="px-4 py-1.5" style={{ fontSize: '10px', color: t.titleSub, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                            {labels[type]}
                          </p>
                          {group.map((r, i) => {
                            const Icon = r.icon;
                            return (
                              <button
                                key={i}
                                onClick={r.action}
                                className="w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors"
                                style={{ color: t.title }}
                                onMouseEnter={e => (e.currentTarget.style.backgroundColor = t.dropHover)}
                                onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
                              >
                                <div className="p-1.5 rounded-lg shrink-0" style={{ backgroundColor: 'rgba(0,212,255,0.1)' }}>
                                  <Icon className="w-3.5 h-3.5" style={{ color: '#00d4ff' }} />
                                </div>
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2">
                                    <span style={{ fontSize: '13px', fontWeight: 600 }}>{r.label}</span>
                                    {r.badge && (
                                      <span className="px-1.5 py-0.5 rounded text-xs font-semibold"
                                        style={{ color: r.badge.color, backgroundColor: r.badge.bg }}>
                                        {r.badge.text}
                                      </span>
                                    )}
                                  </div>
                                  <p className="truncate" style={{ fontSize: '11px', color: t.titleSub }}>{r.sub}</p>
                                </div>
                                <ArrowRight className="w-3.5 h-3.5 shrink-0" style={{ color: t.titleSub }} />
                              </button>
                            );
                          })}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* ── Right controls ── */}
          <div className="flex items-center gap-1.5 ml-auto">

            {/* Theme toggle */}
            <button
              onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
              className="p-2 rounded-xl"
              style={{ color: t.navInactive, backgroundColor: t.inputBg, border: `1px solid ${t.sidebarBorder}` }}
              title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            >
              {theme === 'dark'
                ? <Sun className="w-4 h-4" style={{ color: '#fbbf24' }} />
                : <Moon className="w-4 h-4" style={{ color: '#6366f1' }} />}
            </button>

            {/* ── Notification bell ── */}
            <div ref={notifRef} className="relative">
              <button
                onClick={() => setNotifOpen(o => !o)}
                className="relative p-2 rounded-xl"
                style={{ color: t.navInactive, backgroundColor: notifOpen ? 'rgba(0,212,255,0.1)' : t.inputBg,
                  border: `1px solid ${notifOpen ? 'rgba(0,212,255,0.3)' : t.sidebarBorder}` }}
                title="Notifications"
              >
                <Bell className="w-4 h-4" style={{ color: notifOpen ? '#00d4ff' : t.navInactive }} />
                {unread > 0 && (
                  <span
                    className="absolute -top-1 -right-1 min-w-[18px] h-[18px] rounded-full flex items-center justify-center text-white"
                    style={{ fontSize: '9px', fontWeight: 800, backgroundColor: '#ef4444',
                      boxShadow: '0 0 8px rgba(239,68,68,0.6)' }}
                  >
                    {unread}
                  </span>
                )}
              </button>

              {/* Notification dropdown */}
              {notifOpen && (
                <div
                  className="absolute top-full right-0 mt-1.5 w-96 rounded-2xl overflow-hidden z-50 dropdown-shadow"
                  style={{ backgroundColor: t.dropBg, border: `1px solid ${t.dropBorder}` }}
                >
                  {/* Header */}
                  <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: `1px solid ${t.dropBorder}` }}>
                    <div className="flex items-center gap-2">
                      <span style={{ fontSize: '14px', fontWeight: 700, color: t.title }}>Notifications</span>
                      {unread > 0 && (
                        <span className="px-2 py-0.5 rounded-full text-xs font-bold"
                          style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)' }}>
                          {unread} new
                        </span>
                      )}
                    </div>
                    <button
                      onClick={markAllRead}
                      className="text-xs px-2.5 py-1 rounded-lg"
                      style={{ color: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)' }}
                    >
                      Mark all read
                    </button>
                  </div>

                  {/* List */}
                  <div className="max-h-80 overflow-y-auto">
                    {notifications.map(n => {
                      const meta = notifMeta[n.type];
                      const Icon = meta.icon;
                      return (
                        <div
                          key={n.id}
                          className="flex items-start gap-3 px-4 py-3 relative transition-colors"
                          style={{
                            borderBottom: `1px solid ${t.dropBorder}`,
                            backgroundColor: !n.read ? (theme === 'dark' ? 'rgba(0,212,255,0.03)' : 'rgba(0,150,200,0.04)') : 'transparent',
                          }}
                          onMouseEnter={e => (e.currentTarget.style.backgroundColor = t.dropHover)}
                          onMouseLeave={e => (e.currentTarget.style.backgroundColor = !n.read ? (theme === 'dark' ? 'rgba(0,212,255,0.03)' : 'rgba(0,150,200,0.04)') : 'transparent')}
                        >
                          {/* Unread dot */}
                          {!n.read && (
                            <span className="absolute left-2 top-4 w-1.5 h-1.5 rounded-full"
                              style={{ backgroundColor: '#00d4ff', boxShadow: '0 0 4px #00d4ff' }} />
                          )}
                          <div className="p-2 rounded-xl shrink-0" style={{ backgroundColor: meta.bg, border: `1px solid ${meta.border}` }}>
                            <Icon className="w-3.5 h-3.5" style={{ color: meta.color }} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-start justify-between gap-2">
                              <p style={{ fontSize: '12px', fontWeight: n.read ? 500 : 700, color: t.title }}>{n.title}</p>
                              <button
                                onClick={e => { e.stopPropagation(); dismiss(n.id); }}
                                className="shrink-0 p-0.5 rounded opacity-0 group-hover:opacity-100 transition-opacity"
                                style={{ color: t.titleSub }}
                                title="Dismiss"
                              >
                                <X className="w-3 h-3" />
                              </button>
                            </div>
                            <p style={{ fontSize: '12px', color: t.titleSub, lineHeight: 1.5, marginTop: '2px' }}>{n.body}</p>
                            <div className="flex items-center gap-2 mt-1.5">
                              <Clock className="w-3 h-3" style={{ color: t.titleSub }} />
                              <span style={{ fontSize: '10px', color: t.titleSub }}>{n.time}</span>
                              <span
                                className="px-1.5 py-0.5 rounded text-xs font-semibold capitalize"
                                style={{ color: meta.color, backgroundColor: meta.bg }}>
                                {n.type}
                              </span>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Footer */}
                  <div className="px-4 py-2.5" style={{ borderTop: `1px solid ${t.dropBorder}` }}>
                    <button
                      className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded-xl text-xs"
                      style={{ color: t.titleSub }}
                      onClick={() => setNotifOpen(false)}
                    >
                      View all notifications
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Divider */}
            <div className="w-px h-6 mx-1" style={{ backgroundColor: t.sidebarBorder }} />

            {/* User chip — click to open profile */}
            <button
              type="button"
              onClick={() => navigate('profile')}
              className="user-chip flex items-center gap-2 px-3 py-1.5 rounded-xl transition-all hover:opacity-80"
              title="My Profile"
            >
              <div className="w-6 h-6 rounded-lg flex items-center justify-center text-xs font-bold"
                style={{ background: 'linear-gradient(135deg, #00d4ff33, #00d4ff55)', color: '#00d4ff' }}>
                {(currentUser?.name || currentUser?.email || 'U').slice(0, 2).toUpperCase()}
              </div>
              <span className="hidden md:block" style={{ fontSize: '12px', color: t.title, fontWeight: 600 }}>
                {currentUser?.name || currentUser?.email?.split('@')[0]}
              </span>
              <span
                className="hidden md:block px-1.5 py-0.5 rounded text-xs font-semibold"
                style={{
                  color: currentUser?.role === 'Admin' ? '#a78bfa' : '#00d4ff',
                  backgroundColor: currentUser?.role === 'Admin' ? 'rgba(167,139,250,0.1)' : 'rgba(0,212,255,0.1)',
                }}>
                {currentUser?.role}
              </span>
            </button>

            {/* Sign out */}
            <button
              onClick={async () => { await AuthAPI.logout(); clearSession(); setIsLoggedIn(false); setCurrentUser(null); setActiveTab('dashboard'); }}
              className="p-2 rounded-xl"
              style={{ color: t.titleSub, border: `1px solid ${t.sidebarBorder}`, backgroundColor: t.inputBg }}
              title="Sign Out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </header>

        {/* ── Page content ─────────────────────────────────────────────── */}
        <main
          className="main-grid-bg flex-1 p-6"
          style={{
            backgroundImage:
              'linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px)',
            backgroundSize: '40px 40px',
          }}
        >
          <ErrorBoundary>
            {activeTab === 'dashboard'     && <Dashboard />}
            {activeTab === 'scanner'       && <Scanner />}
            {activeTab === 'reports'       && <Reports />}
            {activeTab === 'scanhistory'   && <ScanHistory />}
            {activeTab === 'analytics'     && <Analytics />}
            {activeTab === 'knowledgebase' && <KnowledgeBase />}
            {activeTab === 'profile'       && <Profile />}
            {activeTab === 'admin' && (
              currentUser?.role === 'Admin' ? <Admin /> : <AccessDenied />
            )}
          </ErrorBoundary>
        </main>
      </div>

      {/* ── AI Chatbox (floating, always visible when logged in) ───────── */}
      <ChatBox />
    </div>
  );
}
