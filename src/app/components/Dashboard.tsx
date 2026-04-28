import { useState, useEffect } from 'react';
import { ScanLine, AlertTriangle, FileText, ShieldCheck } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  PieChart, Pie, Cell,
} from 'recharts';
import { ScansAPI, ReportsAPI, Scan, Report } from '../lib/api';
import { cardStyle, getRiskStyle } from '../lib/styles';

const tooltipStyle = {
  backgroundColor: '#2A0010',
  border: '1px solid #4A001A',
  borderRadius: '10px',
  color: 'white',
  fontSize: '13px',
};

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: { name: string; fill?: string; color?: string; value: number }[]; label?: string }) => {
  if (active && payload && payload.length) {
    return (
      <div style={tooltipStyle} className="px-3 py-2">
        <p style={{ color: '#94a3b8', fontSize: '12px', marginBottom: '4px' }}>{label}</p>
        {payload.map(p => (
          <p key={p.name} style={{ color: p.fill || p.color }}>
            {p.name}: <strong style={{ color: 'white' }}>{p.value}</strong>
          </p>
        ))}
      </div>
    );
  }
  return null;
};

const DonutTooltip = ({ active, payload }: { active?: boolean; payload?: { name: string; value: number; payload: { color: string } }[] }) => {
  if (active && payload && payload.length) {
    return (
      <div style={tooltipStyle} className="px-3 py-2">
        <p style={{ color: payload[0].payload.color }}>{payload[0].name}</p>
        <p style={{ color: 'white' }}><strong>{payload[0].value}%</strong></p>
      </div>
    );
  }
  return null;
};

const RADIAN = Math.PI / 180;
const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }: { cx: number; cy: number; midAngle: number; innerRadius: number; outerRadius: number; percent: number }) => {
  if (percent < 0.05) return null;
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" style={{ fontSize: '12px', fontWeight: 600 }}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

// Group scans by day-of-week for last 7 days
function buildWeeklyData(scans: Scan[]) {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const now = new Date();
  const buckets: Record<string, { scans: number; threats: number }> = {};
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now); d.setDate(d.getDate() - i);
    buckets[days[d.getDay()]] = { scans: 0, threats: 0 };
  }
  scans.forEach(s => {
    const ts = new Date(s.createdAt || s.timestamp);
    const diffDays = Math.floor((now.getTime() - ts.getTime()) / 86400000);
    if (diffDays > 6) return;
    const key = days[ts.getDay()];
    if (!buckets[key]) return;
    buckets[key].scans++;
    if (s.result === 'Dangerous' || s.result === 'Suspicious') buckets[key].threats++;
  });
  return Object.entries(buckets).map(([name, v]) => ({ name, ...v }));
}

export function Dashboard() {
  const [scans, setScans]     = useState<Scan[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([ScansAPI.getAll(1, 1000), ReportsAPI.getAll(1, 1000)])
      .then(([s, r]) => {
        if (s.success) setScans(s.data);
        if (r.success) setReports(r.data);
      })
      .finally(() => setLoading(false));
  }, []);

  // Derived stats
  const totalScans    = scans.length;
  const dangerous     = scans.filter(s => s.result === 'Dangerous').length;
  const suspicious    = scans.filter(s => s.result === 'Suspicious').length;
  const safe          = scans.filter(s => s.result === 'Safe').length;
  const totalThreats  = dangerous + suspicious;
  const totalReports  = reports.length;

  const statCards = [
    { label: 'Total Scans',      value: loading ? '…' : totalScans.toLocaleString(),   icon: ScanLine,      color: '#7A9AB8', bg: 'rgba(122, 154, 184, 0.08)',  border: 'rgba(122, 154, 184, 0.3)',  glow: 'rgba(122, 154, 184, 0.15)'  },
    { label: 'Threats Detected', value: loading ? '…' : totalThreats.toLocaleString(), icon: AlertTriangle, color: '#ef4444', bg: 'rgba(239, 68, 68, 0.08)',  border: 'rgba(239, 68, 68, 0.3)',  glow: 'rgba(239, 68, 68, 0.15)'  },
    { label: 'Reports Filed',    value: loading ? '…' : totalReports.toLocaleString(), icon: FileText,      color: '#fbbf24', bg: 'rgba(251, 191, 36, 0.08)', border: 'rgba(251, 191, 36, 0.3)', glow: 'rgba(251, 191, 36, 0.15)' },
    { label: 'Safe URLs',        value: loading ? '…' : safe.toLocaleString(),         icon: ShieldCheck,   color: '#22c55e', bg: 'rgba(34, 197, 94, 0.08)',  border: 'rgba(34, 197, 94, 0.3)',  glow: 'rgba(34, 197, 94, 0.15)'  },
  ];

  const weeklyData = buildWeeklyData(scans);

  const total = dangerous + suspicious + safe || 1;
  const donutData = [
    { name: 'Safe',       value: Math.round(safe       / total * 100), color: '#7A9AB8' },
    { name: 'Suspicious', value: Math.round(suspicious / total * 100), color: '#fbbf24' },
    { name: 'Dangerous',  value: Math.round(dangerous  / total * 100), color: '#ef4444' },
  ].filter(d => d.value > 0);

  // Recent activity: latest 5 from combined scans + reports
  const recentActivity = [
    ...scans.slice(0, 10).map(s => ({
      id: s.id, type: 'scan' as const,
      target: s.target,
      riskLevel: (s.result === 'Unknown' ? 'Suspicious' : s.result) as 'Safe' | 'Suspicious' | 'Dangerous',
      timestamp: s.timestamp,
    })),
    ...reports.slice(0, 5).map(r => ({
      id: r.id, type: 'report' as const,
      target: r.target,
      riskLevel: (r.riskScore >= 70 ? 'Dangerous' : r.riskScore >= 40 ? 'Suspicious' : 'Safe') as 'Safe' | 'Suspicious' | 'Dangerous',
      timestamp: r.timestamp,
    })),
  ]
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    .slice(0, 5);

  if (loading) return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {[1,2,3,4].map(i => (
          <div key={i} className="skeleton-card">
            <div className="skeleton h-4 w-24 mb-3" />
            <div className="skeleton h-8 w-16 mb-2" />
            <div className="skeleton h-3 w-32" />
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {[1,2].map(i => (
          <div key={i} className="skeleton-card-tall">
            <div className="skeleton h-4 w-32 mb-4" />
            <div className="skeleton h-40 w-full" />
          </div>
        ))}
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {statCards.map(card => {
          const Icon = card.icon;
          return (
            <div key={card.label} className="relative rounded-2xl p-5 overflow-hidden transition-all duration-300 hover:-translate-y-0.5"
              style={{ backgroundColor: '#2A0010', border: `1px solid ${card.border}`, boxShadow: `0 0 30px ${card.glow}, 0 4px 24px rgba(0,0,0,0.3)` }}>
              <div className="absolute top-0 left-0 right-0 h-0.5 rounded-t-2xl"
                style={{ background: `linear-gradient(90deg, transparent, ${card.color}, transparent)` }} />
              <div className="mb-4">
                <div className="p-2.5 rounded-xl w-fit" style={{ backgroundColor: card.bg, border: `1px solid ${card.border}` }}>
                  <Icon className="w-5 h-5" style={{ color: card.color }} />
                </div>
              </div>
              <div style={{ fontSize: '28px', fontWeight: 700, color: 'white', lineHeight: 1 }}>{card.value}</div>
              <div style={{ fontSize: '13px', color: '#5A80A8', marginTop: '6px', fontWeight: 500 }}>{card.label}</div>
            </div>
          );
        })}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Bar Chart */}
        <div className="lg:col-span-2 rounded-2xl p-5" style={cardStyle}>
          <div className="flex items-center justify-between mb-5">
            <div>
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'white' }}>Weekly Scan Activity</h3>
              <p style={{ fontSize: '12px', color: '#3A5A7A', marginTop: '2px' }}>Scans vs Threats detected</p>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: '#7A9AB8' }} /><span style={{ fontSize: '12px', color: '#5A80A8' }}>Scans</span></div>
              <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: '#ef4444' }} /><span style={{ fontSize: '12px', color: '#5A80A8' }}>Threats</span></div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={weeklyData} barGap={4}>
              <CartesianGrid strokeDasharray="3 3" stroke="#4A001A" vertical={false} />
              <XAxis dataKey="name" tick={{ fill: '#5A80A8', fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#5A80A8', fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(122, 154, 184, 0.04)' }} />
              <Bar dataKey="scans"   fill="#7A9AB8" radius={[6, 6, 0, 0]} fillOpacity={0.85} />
              <Bar dataKey="threats" fill="#ef4444" radius={[6, 6, 0, 0]} fillOpacity={0.85} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Donut Chart */}
        <div className="rounded-2xl p-5" style={cardStyle}>
          <div className="mb-3">
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'white' }}>Threat Distribution</h3>
            <p style={{ fontSize: '12px', color: '#3A5A7A', marginTop: '2px' }}>All-time classification</p>
          </div>
          {donutData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={donutData} cx="50%" cy="50%" innerRadius={50} outerRadius={80}
                    dataKey="value" labelLine={false} label={renderCustomLabel} strokeWidth={0}>
                    {donutData.map(entry => <Cell key={entry.name} fill={entry.color} opacity={0.9} />)}
                  </Pie>
                  <Tooltip content={<DonutTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2 mt-2">
                {donutData.map(item => (
                  <div key={item.name} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                      <span style={{ fontSize: '12px', color: '#94a3b8' }}>{item.name}</span>
                    </div>
                    <span style={{ fontSize: '12px', fontWeight: 600, color: 'white' }}>{item.value}%</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-40" style={{ color: '#3A5A7A', fontSize: '13px' }}>
              {loading ? 'Loading…' : 'No scan data yet'}
            </div>
          )}
        </div>
      </div>

      {/* Recent Activity */}
      <div className="rounded-2xl p-5" style={cardStyle}>
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'white' }}>Recent Activity</h3>
            <p style={{ fontSize: '12px', color: '#3A5A7A', marginTop: '2px' }}>Latest scans and reports</p>
          </div>
        </div>
        <div className="space-y-2">
          {loading ? (
            <p style={{ fontSize: '13px', color: '#3A5A7A', textAlign: 'center', padding: '24px 0' }}>Loading…</p>
          ) : recentActivity.length === 0 ? (
            <p style={{ fontSize: '13px', color: '#3A5A7A', textAlign: 'center', padding: '24px 0' }}>No activity yet. Run a scan to get started.</p>
          ) : recentActivity.map(activity => {
            const riskStyle = getRiskStyle(activity.riskLevel);
            return (
              <div key={activity.id} className="flex items-center justify-between p-3 rounded-xl transition-all duration-200 hover:bg-white/[0.03]"
                style={{ border: '1px solid #4A001A' }}>
                <div className="flex items-center gap-3 min-w-0">
                  <span className="px-2.5 py-1 rounded-full text-xs shrink-0" style={{ ...riskStyle, fontWeight: 600 }}>
                    {activity.riskLevel}
                  </span>
                  <div className="min-w-0">
                    <p className="truncate" style={{ fontSize: '13px', color: '#e2e8f0', maxWidth: '300px' }}>
                      {activity.target}
                    </p>
                    <p style={{ fontSize: '11px', color: '#3A5A7A', marginTop: '1px' }}>{activity.timestamp}</p>
                  </div>
                </div>
                <span className="shrink-0 ml-4 px-2.5 py-1 rounded-lg text-xs capitalize"
                  style={{ color: activity.type === 'scan' ? '#7A9AB8' : '#5A80A8', backgroundColor: activity.type === 'scan' ? 'rgba(122, 154, 184, 0.08)' : 'rgba(90, 128, 168, 0.08)', fontWeight: 500 }}>
                  {activity.type}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
