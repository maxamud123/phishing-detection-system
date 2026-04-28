import { useState, useMemo, useEffect } from 'react';
import {
  Search, Globe, Mail, Eye, Trash2, Download, ChevronUp, ChevronDown,
  ChevronsUpDown, ChevronLeft, ChevronRight, X, Clock, Target, Zap, AlertTriangle,
} from 'lucide-react';
import { ScansAPI, Scan, exportCSV } from '../lib/api';
import { cardStyle, inputStyle, getRiskStyle, getScoreColor } from '../lib/styles';

interface HistoryEntry {
  id: string;
  type: 'url' | 'email';
  target: string;
  threatLevel: 'Safe' | 'Suspicious' | 'Dangerous';
  score: number;
  timestamp: string;
  duration: string;
  redFlags: number;
}

// Map API Scan → local HistoryEntry
function scanToEntry(s: Scan): HistoryEntry {
  return {
    id: s.id,
    type: s.type === 'URL' ? 'url' : 'email',
    target: s.target,
    threatLevel: (s.result === 'Unknown' ? 'Suspicious' : s.result) as HistoryEntry['threatLevel'],
    score: s.riskScore,
    timestamp: s.timestamp,
    duration: '—',
    redFlags: 0,
  };
}

type SortKey = keyof HistoryEntry;

const PAGE_SIZE = 8;

export function ScanHistory() {
  const [search, setSearch]         = useState('');
  const [riskFilter, setRiskFilter] = useState<'All' | 'Safe' | 'Suspicious' | 'Dangerous'>('All');
  const [typeFilter, setTypeFilter] = useState<'All' | 'url' | 'email'>('All');
  const [dateFrom, setDateFrom]     = useState('');
  const [dateTo, setDateTo]         = useState('');
  const [sortKey, setSortKey]       = useState<SortKey>('timestamp');
  const [sortDir, setSortDir]       = useState<'asc' | 'desc'>('desc');
  const [page, setPage]             = useState(1);
  const [selected, setSelected]     = useState<HistoryEntry | null>(null);
  const [history, setHistory]       = useState<HistoryEntry[]>([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState('');

  useEffect(() => {
    ScansAPI.getAll(1, 1000).then(data => {
      if (data.success) setHistory(data.data.map(scanToEntry));
      else setError(data.error || 'Failed to load scan history.');
    }).catch(() => setError('Cannot connect to server.')).finally(() => setLoading(false));
  }, []);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('asc'); }
    setPage(1);
  };

  const SortIcon = ({ k }: { k: SortKey }) =>
    sortKey === k
      ? sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />
      : <ChevronsUpDown className="w-3 h-3 opacity-25" />;

  const filtered = useMemo(() => {
    return history
      .filter(h => {
        const q = search.toLowerCase();
        const matchSearch = h.target.toLowerCase().includes(q) || h.id.toLowerCase().includes(q);
        const matchRisk = riskFilter === 'All' || h.threatLevel === riskFilter;
        const matchType = typeFilter === 'All' || h.type === typeFilter;
        const matchFrom = !dateFrom || h.timestamp >= dateFrom;
        const matchTo   = !dateTo   || h.timestamp <= dateTo + ' 23:59';
        return matchSearch && matchRisk && matchType && matchFrom && matchTo;
      })
      .sort((a, b) => {
        const av = a[sortKey], bv = b[sortKey];
        if (typeof av === 'number' && typeof bv === 'number')
          return sortDir === 'asc' ? av - bv : bv - av;
        return sortDir === 'asc'
          ? String(av).localeCompare(String(bv))
          : String(bv).localeCompare(String(av));
      });
  }, [history, search, riskFilter, typeFilter, dateFrom, dateTo, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated  = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const stats = {
    total: history.length,
    safe: history.filter(h => h.threatLevel === 'Safe').length,
    suspicious: history.filter(h => h.threatLevel === 'Suspicious').length,
    dangerous: history.filter(h => h.threatLevel === 'Dangerous').length,
  };


  const handleExportCSV = () => {
    exportCSV('scan-history.csv', filtered.map(h => ({
      ID: h.id, Type: h.type.toUpperCase(), Target: h.target,
      Score: h.score, ThreatLevel: h.threatLevel, Timestamp: h.timestamp,
    })));
  };

  const clearFilters = () => {
    setSearch(''); setRiskFilter('All'); setTypeFilter('All');
    setDateFrom(''); setDateTo(''); setPage(1);
  };

  const hasFilters = search || riskFilter !== 'All' || typeFilter !== 'All' || dateFrom || dateTo;

  return (
    <div className="space-y-5">
      {error && (
        <div className="px-4 py-3 rounded-xl flex items-center gap-2"
          style={{ backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)' }}>
          <AlertTriangle className="w-4 h-4 shrink-0" style={{ color: '#ef4444' }} />
          <span style={{ fontSize: '13px', color: '#ef4444' }}>{error}</span>
        </div>
      )}
      {/* Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Total Scans',  value: stats.total,     color: '#F0C0C8', bg: 'rgba(240, 192, 200,0.08)',  border: 'rgba(240, 192, 200,0.2)',  icon: Target },
          { label: 'Safe',         value: stats.safe,       color: '#22c55e', bg: 'rgba(34,197,94,0.08)', border: 'rgba(34,197,94,0.2)',  icon: Zap },
          { label: 'Suspicious',   value: stats.suspicious, color: '#fbbf24', bg: 'rgba(251,191,36,0.08)',border: 'rgba(251,191,36,0.2)', icon: Clock },
          { label: 'Dangerous',    value: stats.dangerous,  color: '#ef4444', bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.2)',  icon: X },
        ].map(({ label, value, color, bg, border, icon: Icon }) => (
          <div
            key={label}
            className="p-4 rounded-2xl flex items-center gap-3 transition-all hover:-translate-y-0.5 duration-200"
            style={{ backgroundColor: bg, border: `1px solid ${border}` }}
          >
            <div className="p-2 rounded-xl" style={{ backgroundColor: `${bg}` }}>
              <Icon className="w-4 h-4" style={{ color }} />
            </div>
            <div>
              <div style={{ fontSize: '24px', fontWeight: 800, color, lineHeight: 1 }}>{value}</div>
              <div style={{ fontSize: '11px', color: '#C8909A', marginTop: '3px' }}>{label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Table Card */}
      <div className="p-5" style={cardStyle}>
        {/* Filter Bar */}
        <div className="flex flex-col gap-3 mb-5">
          <div className="flex flex-col sm:flex-row gap-3">
            {/* Search */}
            <div className="flex-1 relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#8B4555' }} />
              <input
                type="text"
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(1); }}
                placeholder="Search scan ID or target..."
                style={{ ...inputStyle, paddingLeft: '36px', width: '100%' }}
              />
            </div>
            {/* Selects */}
            <select aria-label="Filter by risk level" value={riskFilter} onChange={e => { setRiskFilter(e.target.value as typeof riskFilter); setPage(1); }} style={{ ...inputStyle, cursor: 'pointer' }}>
              <option value="All">All Risk</option>
              <option value="Safe">Safe</option>
              <option value="Suspicious">Suspicious</option>
              <option value="Dangerous">Dangerous</option>
            </select>
            <select aria-label="Filter by type" value={typeFilter} onChange={e => { setTypeFilter(e.target.value as typeof typeFilter); setPage(1); }} style={{ ...inputStyle, cursor: 'pointer' }}>
              <option value="All">All Types</option>
              <option value="url">URL</option>
              <option value="email">Email</option>
            </select>
          </div>
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
            {/* Date Range */}
            <div className="flex items-center gap-2 flex-1">
              <span style={{ fontSize: '12px', color: '#8B4555', whiteSpace: 'nowrap' }}>From</span>
              <input type="date" value={dateFrom} onChange={e => { setDateFrom(e.target.value); setPage(1); }}
                style={{ ...inputStyle, colorScheme: 'dark', cursor: 'pointer', flex: 1 }} />
              <span style={{ fontSize: '12px', color: '#8B4555' }}>To</span>
              <input type="date" value={dateTo} onChange={e => { setDateTo(e.target.value); setPage(1); }}
                style={{ ...inputStyle, colorScheme: 'dark', cursor: 'pointer', flex: 1 }} />
            </div>
            <div className="flex gap-2 ml-auto">
              {hasFilters && (
                <button
                  type="button"
                  onClick={clearFilters}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs transition-all hover:bg-white/5"
                  style={{ color: '#8B4555', border: '1px solid #4A001A' }}
                >
                  <X className="w-3.5 h-3.5" /> Clear
                </button>
              )}
              <button
                type="button"
                onClick={handleExportCSV}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs transition-all hover:opacity-90"
                style={{ color: '#F0C0C8', border: '1px solid rgba(240, 192, 200,0.3)', backgroundColor: 'rgba(240, 192, 200,0.06)' }}
              >
                <Download className="w-3.5 h-3.5" /> Export CSV
              </button>
            </div>
          </div>
        </div>

        {/* Result count */}
        <p style={{ fontSize: '12px', color: '#8B4555', marginBottom: '12px' }}>
          {filtered.length} result{filtered.length !== 1 ? 's' : ''} found
        </p>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full" style={{ borderCollapse: 'collapse', minWidth: '700px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #4A001A' }}>
                {(
                  [
                    { label: 'Scan ID',      key: 'id'          },
                    { label: 'Type',         key: 'type'        },
                    { label: 'Target',       key: 'target'      },
                    { label: 'Score',        key: 'score'       },
                    { label: 'Threat',       key: 'threatLevel' },
                    { label: 'Red Flags',    key: 'redFlags'    },
                    { label: 'Duration',     key: 'duration'    },
                    { label: 'Timestamp',    key: 'timestamp'   },
                    { label: '',             key: null          },
                  ] as { label: string; key: SortKey | null }[]
                ).map(({ label, key }) => (
                  <th
                    key={label || '_'}
                    onClick={() => key && handleSort(key)}
                    className="text-left py-3 px-3"
                    style={{
                      fontSize: '11px',
                      color: key && sortKey === key ? '#F0C0C8' : '#8B4555',
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                      cursor: key ? 'pointer' : 'default',
                      userSelect: 'none',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {label ? (
                      <span className="inline-flex items-center gap-1">
                        {label}
                        {key && <SortIcon k={key as SortKey} />}
                      </span>
                    ) : null}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-14 text-center" style={{ color: '#8B4555', fontSize: '14px' }}>
                    Loading scan history…
                  </td>
                </tr>
              ) : paginated.map(entry => (
                <tr
                  key={entry.id}
                  style={{ borderBottom: '1px solid rgba(26,32,64,0.6)', transition: 'background-color 0.15s' }}
                  onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
                  onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  <td className="py-3 px-3">
                    <span style={{ fontSize: '12px', fontWeight: 600, color: '#F0C0C8', fontFamily: 'monospace' }}>
                      {entry.id}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    <span
                      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg text-xs font-semibold"
                      style={entry.type === 'url'
                        ? { color: '#F0C0C8', backgroundColor: 'rgba(240, 192, 200,0.1)' }
                        : { color: '#C8909A', backgroundColor: 'rgba(200, 144, 154,0.1)' }}
                    >
                      {entry.type === 'url' ? <Globe className="w-3 h-3" /> : <Mail className="w-3 h-3" />}
                      {entry.type.toUpperCase()}
                    </span>
                  </td>
                  <td className="py-3 px-3" style={{ maxWidth: '220px' }}>
                    <div className="truncate" style={{ fontSize: '12px', color: '#e2e8f0' }}>{entry.target}</div>
                  </td>
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      <span style={{ fontSize: '13px', fontWeight: 700, color: getScoreColor(entry.score) }}>
                        {entry.score}
                      </span>
                      <div className="w-12 h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: '#4A001A' }}>
                        <div
                          className="h-full rounded-full"
                          style={{ width: `${entry.score}%`, backgroundColor: getScoreColor(entry.score) }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-2.5 py-1 rounded-lg text-xs font-semibold" style={getRiskStyle(entry.threatLevel)}>
                      {entry.threatLevel}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    <span style={{ fontSize: '12px', fontWeight: 600, color: entry.redFlags > 0 ? '#fbbf24' : '#22c55e' }}>
                      {entry.redFlags}
                    </span>
                  </td>
                  <td className="py-3 px-3" style={{ fontSize: '12px', color: '#C8909A' }}>{entry.duration}</td>
                  <td className="py-3 px-3" style={{ fontSize: '11px', color: '#8B4555', whiteSpace: 'nowrap' }}>{entry.timestamp}</td>
                  <td className="py-3 px-3">
                    <div className="flex gap-1">
                      <button
                        type="button"
                        onClick={() => setSelected(entry)}
                        className="p-1.5 rounded-lg hover:bg-white/5 transition-colors"
                        style={{ color: '#C8909A' }}
                        title="View details"
                        aria-label="View details"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          const res = await ScansAPI.delete(entry.id);
                          if (res.success) setHistory(h => h.filter(x => x.id !== entry.id));
                          else setError(res.error || 'Failed to delete scan.');
                        }}
                        className="p-1.5 rounded-lg transition-colors"
                        style={{ color: '#8B4555' }}
                        title="Delete"
                        aria-label="Delete scan"
                        onMouseEnter={e => (e.currentTarget.style.color = '#ef4444')}
                        onMouseLeave={e => (e.currentTarget.style.color = '#8B4555')}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {paginated.length === 0 && (
                <tr>
                  <td colSpan={9} className="py-14 text-center" style={{ color: '#8B4555', fontSize: '14px' }}>
                    No scans match your filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-4 pt-4" style={{ borderTop: '1px solid #4A001A' }}>
            <span style={{ fontSize: '12px', color: '#8B4555' }}>
              Page {page} of {totalPages} · {filtered.length} records
            </span>
            <div className="flex gap-1">
              <button
                type="button"
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-1.5 rounded-lg transition-colors hover:bg-white/5 disabled:opacity-30"
                style={{ color: '#C8909A' }}
                aria-label="Previous page"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              {Array.from({ length: totalPages }, (_, i) => i + 1).map(n => (
                <button
                  key={n}
                  type="button"
                  onClick={() => setPage(n)}
                  className="w-7 h-7 rounded-lg text-xs transition-all"
                  aria-label={`Page ${n}`}
                  aria-current={n === page ? 'page' : undefined}
                  style={n === page
                    ? { backgroundColor: 'rgba(240, 192, 200,0.15)', color: '#F0C0C8', border: '1px solid rgba(240, 192, 200,0.3)', fontWeight: 700 }
                    : { color: '#C8909A' }}
                >
                  {n}
                </button>
              ))}
              <button
                type="button"
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="p-1.5 rounded-lg transition-colors hover:bg-white/5 disabled:opacity-30"
                style={{ color: '#C8909A' }}
                aria-label="Next page"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selected && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ backgroundColor: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(4px)' }}
          onClick={() => setSelected(null)}
        >
          <div
            className="w-full max-w-lg rounded-2xl overflow-hidden"
            style={{ backgroundColor: '#2A0010', border: '1px solid #4A001A' }}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: '1px solid #4A001A' }}>
              <div className="flex items-center gap-3">
                {selected.type === 'url'
                  ? <Globe className="w-5 h-5" style={{ color: '#F0C0C8' }} />
                  : <Mail className="w-5 h-5" style={{ color: '#C8909A' }} />}
                <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'white' }}>{selected.id}</h3>
                <span className="px-2 py-0.5 rounded-lg text-xs font-semibold" style={getRiskStyle(selected.threatLevel)}>
                  {selected.threatLevel}
                </span>
              </div>
              <button type="button" onClick={() => setSelected(null)} className="p-2 rounded-lg hover:bg-white/5 transition-colors" style={{ color: '#C8909A' }} title="Close" aria-label="Close">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-3">
              <div className="p-3 rounded-xl" style={{ backgroundColor: '#1E000A', border: '1px solid #4A001A' }}>
                <p style={{ fontSize: '11px', color: '#8B4555', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Target</p>
                <p style={{ fontSize: '13px', color: '#e2e8f0', marginTop: '4px', wordBreak: 'break-all' }}>{selected.target}</p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Risk Score', value: String(selected.score), highlight: getScoreColor(selected.score) },
                  { label: 'Red Flags', value: String(selected.redFlags), highlight: selected.redFlags > 0 ? '#fbbf24' : '#22c55e' },
                  { label: 'Scan Duration', value: selected.duration, highlight: '#94a3b8' },
                  { label: 'Timestamp', value: selected.timestamp, highlight: '#94a3b8' },
                ].map(({ label, value, highlight }) => (
                  <div key={label} className="p-3 rounded-xl" style={{ backgroundColor: '#1E000A', border: '1px solid #4A001A' }}>
                    <p style={{ fontSize: '11px', color: '#8B4555', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</p>
                    <p style={{ fontSize: '14px', fontWeight: 700, color: highlight, marginTop: '4px' }}>{value}</p>
                  </div>
                ))}
              </div>
              {/* Score bar */}
              <div className="p-3 rounded-xl" style={{ backgroundColor: '#1E000A', border: '1px solid #4A001A' }}>
                <div className="flex justify-between mb-2">
                  <span style={{ fontSize: '11px', color: '#8B4555', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Risk Score</span>
                  <span style={{ fontSize: '12px', fontWeight: 700, color: getScoreColor(selected.score) }}>{selected.score}/100</span>
                </div>
                <div className="w-full h-2 rounded-full overflow-hidden" style={{ backgroundColor: '#4A001A' }}>
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${selected.score}%`, backgroundColor: getScoreColor(selected.score), boxShadow: `0 0 8px ${getScoreColor(selected.score)}` }}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
