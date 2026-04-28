import { useState, useEffect } from 'react';
import { Search, Filter, Trash2, Eye, Plus, X, AlertTriangle, ChevronUp, ChevronDown, ChevronsUpDown, Download } from 'lucide-react';
import { ReportsAPI, Report, getUser, exportCSV } from '../lib/api';
import { cardStyle, inputStyle } from '../lib/styles';

export function Reports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showSubmitForm, setShowSubmitForm] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState<'All' | 'Confirmed Threat' | 'Pending' | 'False Positive'>('All');
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const [sortKey, setSortKey] = useState<keyof Report | null>(null);
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  // Submit form state
  const [formTarget, setFormTarget] = useState('');
  const [formType, setFormType] = useState<Report['type']>('URL');
  const [formDesc, setFormDesc] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const currentUser = getUser();

  useEffect(() => { fetchReports(); }, []);

  const fetchReports = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await ReportsAPI.getAll(1, 1000);
      if (data.success) setReports(data.data);
      else setError(data.error || 'Failed to load reports.');
    } catch {
      setError('Cannot connect to server. Is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  const exportPDF = () => {
    const filtered = reports.filter(r => {
      const q = searchQuery.toLowerCase();
      const matchQ = !q || r.id.toLowerCase().includes(q) || r.target.toLowerCase().includes(q) || r.reporter.toLowerCase().includes(q);
      const matchS = filterStatus === 'All' || r.status === filterStatus;
      return matchQ && matchS;
    });

    const statusColor = (s: string) => s === 'Confirmed Threat' ? '#ef4444' : s === 'False Positive' ? '#22c55e' : '#fbbf24';

    const rows = filtered.map(r => `
      <tr style="border-bottom:1px solid #e2e8f0">
        <td style="padding:8px 10px;font-size:12px;font-weight:600;color:#0f172a">${r.id}</td>
        <td style="padding:8px 10px;font-size:12px;color:#475569">${r.reporter}</td>
        <td style="padding:8px 10px;font-size:12px;color:#475569">${r.type}</td>
        <td style="padding:8px 10px;font-size:11px;color:#64748b;max-width:200px;word-break:break-all">${r.target}</td>
        <td style="padding:8px 10px;font-size:12px;font-weight:700;color:${statusColor(r.status)}">${r.status}</td>
        <td style="padding:8px 10px;font-size:12px;font-weight:800;color:${r.riskScore >= 50 ? '#ef4444' : r.riskScore >= 20 ? '#f59e0b' : '#22c55e'}">${r.riskScore}/100</td>
        <td style="padding:8px 10px;font-size:11px;color:#94a3b8">${r.timestamp}</td>
      </tr>`).join('');

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"/>
    <title>PhishGuard — Reports Export</title>
    <style>body{font-family:Arial,sans-serif;margin:0;padding:24px;color:#0f172a}
    h1{font-size:22px;margin:0 0 4px}p{font-size:13px;color:#64748b;margin:0 0 20px}
    table{width:100%;border-collapse:collapse}th{background:#f8fafc;padding:10px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:#64748b;border-bottom:2px solid #e2e8f0}
    tr:hover{background:#f8fafc}
    .footer{margin-top:24px;font-size:11px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:12px}
    @media print{body{padding:0}}</style></head>
    <body>
      <h1>PhishGuard — Threat Reports</h1>
      <p>Generated: ${new Date().toLocaleString()} &nbsp;|&nbsp; Total: ${filtered.length} reports ${filterStatus !== 'All' ? `(filtered: ${filterStatus})` : ''}</p>
      <table><thead><tr>
        <th>Report ID</th><th>Reporter</th><th>Type</th><th>Target</th><th>Status</th><th>Risk</th><th>Date</th>
      </tr></thead><tbody>${rows}</tbody></table>
      <div class="footer">Exported from PhishGuard Threat Detection Platform &nbsp;|&nbsp; Confidential</div>
    </body></html>`;

    const win = window.open('', '_blank');
    if (!win) return;
    win.document.write(html);
    win.document.close();
    win.focus();
    setTimeout(() => { win.print(); }, 400);
  };

  const handleExportCSV = () => {
    const filtered = reports.filter(r => {
      const q = searchQuery.toLowerCase();
      return (!q || r.id.toLowerCase().includes(q) || r.target.toLowerCase().includes(q)) &&
             (filterStatus === 'All' || r.status === filterStatus);
    });
    exportCSV(`phishguard_reports_${Date.now()}.csv`, filtered.map(r => ({
      ID: r.id, Reporter: r.reporter, Type: r.type, Target: r.target,
      Status: r.status, RiskScore: r.riskScore, Timestamp: r.timestamp,
      Description: r.description || '',
    })));
  };

  const handleSort = (key: keyof Report) => {
    if (sortKey === key) setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('asc'); }
  };

  const handleDelete = async (id: string) => {
    try {
      await ReportsAPI.delete(id);
      setReports(prev => prev.filter(r => r.id !== id));
      setSelectedReport(null);
    } catch {
      setError('Failed to delete report.');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const now = new Date().toISOString().slice(0, 16).replace('T', ' ');
      const data = await ReportsAPI.create({
        target: formTarget,
        type: formType,
        description: formDesc,
        reporter: currentUser?.email || 'unknown',
        riskScore: 0,
        status: 'Pending',
        timestamp: now,
      });
      if (data.success && data.report) {
        setReports(prev => [data.report, ...prev]);
        setShowSubmitForm(false);
        setFormTarget(''); setFormType('URL'); setFormDesc('');
      } else {
        setError(data.error || 'Failed to submit report.');
      }
    } catch {
      setError('Failed to submit report.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleUpdateStatus = async (id: string, status: Report['status']) => {
    try {
      const data = await ReportsAPI.update(id, { status });
      if (data.success && data.report) {
        setReports(prev => prev.map(r => r.id === id ? data.report : r));
        setSelectedReport(data.report);
      }
    } catch {
      setError('Failed to update report.');
    }
  };

  const getStatusStyle = (status: string) => {
    switch (status) {
      case 'Confirmed Threat':
        return { color: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)' };
      case 'Pending':
        return { color: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.12)', border: '1px solid rgba(251, 191, 36, 0.3)' };
      case 'False Positive':
        return { color: '#22c55e', backgroundColor: 'rgba(34, 197, 94, 0.12)', border: '1px solid rgba(34, 197, 94, 0.3)' };
      default:
        return { color: '#94a3b8', backgroundColor: 'rgba(148, 163, 184, 0.08)', border: '1px solid rgba(148, 163, 184, 0.15)' };
    }
  };

  const getRiskStyle = (score: number) => {
    if (score >= 70) return { color: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.25)' };
    if (score >= 40) return { color: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.12)', border: '1px solid rgba(251, 191, 36, 0.25)' };
    return { color: '#22c55e', backgroundColor: 'rgba(34, 197, 94, 0.12)', border: '1px solid rgba(34, 197, 94, 0.25)' };
  };

  const getTypeStyle = (type: string) => {
    switch (type) {
      case 'Email': return { color: '#5A80A8', backgroundColor: 'rgba(90, 128, 168, 0.1)' };
      case 'URL': return { color: '#7A9AB8', backgroundColor: 'rgba(122, 154, 184, 0.1)' };
      case 'SMS': return { color: '#fb923c', backgroundColor: 'rgba(251, 146, 60, 0.1)' };
      default: return { color: '#94a3b8', backgroundColor: 'rgba(148, 163, 184, 0.1)' };
    }
  };

  const filteredReports = reports
    .filter(r => {
      const matchSearch =
        r.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
        r.reporter.toLowerCase().includes(searchQuery.toLowerCase()) ||
        r.id.toLowerCase().includes(searchQuery.toLowerCase());
      const matchFilter = filterStatus === 'All' || r.status === filterStatus;
      return matchSearch && matchFilter;
    })
    .sort((a, b) => {
      if (!sortKey) return 0;
      const av = a[sortKey as keyof Report];
      const bv = b[sortKey as keyof Report];
      if (typeof av === 'number' && typeof bv === 'number') return sortDir === 'asc' ? av - bv : bv - av;
      return sortDir === 'asc' ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
    });

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <p style={{ fontSize: '13px', color: '#5A80A8', marginTop: '2px' }}>
            {loading ? 'Loading…' : `${filteredReports.length} reports found`}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Export buttons */}
          <button type="button" onClick={handleExportCSV}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl transition-all hover:opacity-90"
            style={{ color: '#5A80A8', backgroundColor: '#2A0010', border: '1px solid #4A001A', fontSize: '12px', fontWeight: 600 }}
            title="Export as CSV">
            <Download className="w-3.5 h-3.5" />CSV
          </button>
          <button type="button" onClick={exportPDF}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl transition-all hover:opacity-90"
            style={{ color: '#5A80A8', backgroundColor: 'rgba(90, 128, 168,0.08)', border: '1px solid rgba(90, 128, 168,0.25)', fontSize: '12px', fontWeight: 600 }}
            title="Export as PDF (opens print dialog)">
            <Download className="w-3.5 h-3.5" />PDF
          </button>
          <button
            type="button"
            onClick={() => setShowSubmitForm(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl transition-all hover:opacity-90"
            style={{ background: 'linear-gradient(135deg, #7A9AB8, #0099bb)', color: '#3A0015', fontWeight: 700, fontSize: '13px', boxShadow: '0 0 20px rgba(122, 154, 184, 0.25)' }}
          >
            <Plus className="w-4 h-4" />Submit Report
          </button>
        </div>
      </div>

      {error && (
        <div className="px-4 py-3 rounded-xl flex items-center gap-2"
          style={{ backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)' }}>
          <AlertTriangle className="w-4 h-4 shrink-0" style={{ color: '#ef4444' }} />
          <span style={{ fontSize: '13px', color: '#ef4444' }}>{error}</span>
        </div>
      )}

      {/* Table Card */}
      <div className="p-5" style={cardStyle}>
        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-3 mb-5">
          <div className="flex-1 relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#3A5A7A' }} />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search by ID, reporter, or target..."
              style={{ ...inputStyle, paddingLeft: '36px', width: '100%' }}
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 shrink-0" style={{ color: '#3A5A7A' }} />
            <select
              aria-label="Filter by status"
              value={filterStatus}
              onChange={e => setFilterStatus(e.target.value as typeof filterStatus)}
              style={{ ...inputStyle, cursor: 'pointer' }}
            >
              <option value="All">All Status</option>
              <option value="Confirmed Threat">Confirmed Threat</option>
              <option value="Pending">Pending</option>
              <option value="False Positive">False Positive</option>
            </select>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full" style={{ borderCollapse: 'collapse', minWidth: '700px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #4A001A' }}>
                {(
                  [
                    { label: 'ID', key: 'id' },
                    { label: 'Reporter', key: 'reporter' },
                    { label: 'Type', key: 'type' },
                    { label: 'Target', key: 'target' },
                    { label: 'Risk', key: 'riskScore' },
                    { label: 'Status', key: 'status' },
                    { label: 'Date', key: 'timestamp' },
                    { label: '', key: null },
                  ] as { label: string; key: keyof Report | null }[]
                ).map(({ label, key }) => (
                  <th
                    key={label || '_actions'}
                    className="text-left py-3 px-3"
                    style={{
                      fontSize: '11px',
                      color: key && sortKey === key ? '#7A9AB8' : '#3A5A7A',
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                      cursor: key ? 'pointer' : 'default',
                      userSelect: 'none',
                      whiteSpace: 'nowrap',
                    }}
                    onClick={() => key && handleSort(key)}
                  >
                    {label ? (
                      <span className="inline-flex items-center gap-1">
                        {label}
                        {key ? (
                          sortKey === key ? (
                            sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />
                          ) : (
                            <ChevronsUpDown className="w-3 h-3 opacity-30" />
                          )
                        ) : null}
                      </span>
                    ) : null}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center" style={{ color: '#3A5A7A', fontSize: '14px' }}>
                    Loading reports…
                  </td>
                </tr>
              ) : filteredReports.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center" style={{ color: '#3A5A7A', fontSize: '14px' }}>
                    No reports match your search criteria.
                  </td>
                </tr>
              ) : filteredReports.map(report => (
                <tr
                  key={report.id}
                  className="transition-colors"
                  style={{ borderBottom: '1px solid rgba(26, 32, 64, 0.6)' }}
                  onMouseEnter={e => (e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)')}
                  onMouseLeave={e => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  <td className="py-3 px-3">
                    <span style={{ fontSize: '12px', fontWeight: 600, color: '#7A9AB8', fontFamily: 'monospace' }}>{report.id}</span>
                  </td>
                  <td className="py-3 px-3" style={{ fontSize: '12px', color: '#94a3b8', maxWidth: '160px' }}>
                    <div className="truncate">{report.reporter}</div>
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded-md text-xs" style={{ ...getTypeStyle(report.type), fontWeight: 600 }}>
                      {report.type}
                    </span>
                  </td>
                  <td className="py-3 px-3" style={{ maxWidth: '200px' }}>
                    <div className="truncate" style={{ fontSize: '12px', color: '#e2e8f0' }}>{report.target}</div>
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded-md text-xs" style={{ ...getRiskStyle(report.riskScore), fontWeight: 700 }}>
                      {report.riskScore}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-2.5 py-1 rounded-lg text-xs whitespace-nowrap" style={{ ...getStatusStyle(report.status), fontWeight: 600 }}>
                      {report.status}
                    </span>
                  </td>
                  <td className="py-3 px-3" style={{ fontSize: '11px', color: '#3A5A7A', whiteSpace: 'nowrap' }}>
                    {report.timestamp}
                  </td>
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-1">
                      <button onClick={() => setSelectedReport(report)} className="p-1.5 rounded-lg transition-colors hover:bg-white/5" title="View" style={{ color: '#5A80A8' }}>
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDelete(report.id)}
                        className="p-1.5 rounded-lg transition-colors"
                        title="Delete"
                        style={{ color: '#3A5A7A' }}
                        onMouseEnter={e => (e.currentTarget.style.color = '#ef4444')}
                        onMouseLeave={e => (e.currentTarget.style.color = '#3A5A7A')}
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
      </div>

      {/* Submit Modal */}
      {showSubmitForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0, 0, 0, 0.8)', backdropFilter: 'blur(4px)' }}>
          <div className="w-full max-w-lg p-6 rounded-2xl" style={{ backgroundColor: '#2A0010', border: '1px solid #4A001A' }}>
            <div className="flex items-center justify-between mb-6">
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'white' }}>Submit New Report</h3>
              <button onClick={() => setShowSubmitForm(false)} className="p-2 rounded-lg transition-colors hover:bg-white/5" style={{ color: '#5A80A8' }} title="Close">
                <X className="w-5 h-5" />
              </button>
            </div>
            <form className="space-y-4" onSubmit={handleSubmit}>
              <div>
                <label style={{ fontSize: '12px', color: '#5A80A8', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Suspicious Target (Email / URL / Phone)
                </label>
                <input
                  type="text"
                  value={formTarget}
                  onChange={e => setFormTarget(e.target.value)}
                  placeholder="Enter suspicious source"
                  style={{ ...inputStyle, width: '100%' }}
                  required
                />
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#5A80A8', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Type</label>
                <select
                  aria-label="Report type"
                  value={formType}
                  onChange={e => setFormType(e.target.value as Report['type'])}
                  style={{ ...inputStyle, width: '100%', cursor: 'pointer' }}
                >
                  <option>Email</option>
                  <option>URL</option>
                  <option>SMS</option>
                  <option>Social Media</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: '12px', color: '#5A80A8', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Description</label>
                <textarea
                  value={formDesc}
                  onChange={e => setFormDesc(e.target.value)}
                  placeholder="Describe the suspicious activity..."
                  rows={4}
                  style={{ ...inputStyle, width: '100%', resize: 'none', lineHeight: 1.6 }}
                  required
                />
              </div>
              <div className="flex gap-3 pt-2">
                <button
                  type="submit"
                  disabled={submitting}
                  className="flex-1 py-3 rounded-xl transition-all hover:opacity-90"
                  style={{ background: 'linear-gradient(135deg, #7A9AB8, #0099bb)', color: '#3A0015', fontWeight: 700, fontSize: '13px', opacity: submitting ? 0.6 : 1 }}
                >
                  {submitting ? 'Submitting…' : 'Submit Report'}
                </button>
                <button type="button" onClick={() => setShowSubmitForm(false)} className="flex-1 py-3 rounded-xl transition-colors hover:bg-white/5" style={{ color: '#5A80A8', border: '1px solid #4A001A', fontSize: '13px' }}>
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* View Detail Modal */}
      {selectedReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0, 0, 0, 0.8)', backdropFilter: 'blur(4px)' }}>
          <div className="w-full max-w-xl rounded-2xl overflow-hidden" style={{ backgroundColor: '#2A0010', border: '1px solid #4A001A' }}>
            <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: '1px solid #4A001A' }}>
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5" style={{ color: '#fbbf24' }} />
                <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'white' }}>Report {selectedReport.id}</h3>
              </div>
              <button onClick={() => setSelectedReport(null)} className="p-2 rounded-lg transition-colors hover:bg-white/5" style={{ color: '#5A80A8' }} title="Close">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Reporter', value: selectedReport.reporter },
                  { label: 'Date', value: selectedReport.timestamp },
                  { label: 'Type', value: selectedReport.type },
                  { label: 'Risk Score', value: String(selectedReport.riskScore), isRisk: true },
                ].map(({ label, value, isRisk }) => (
                  <div key={label} className="p-3 rounded-xl" style={{ backgroundColor: '#1E000A', border: '1px solid #4A001A' }}>
                    <p style={{ fontSize: '11px', color: '#3A5A7A', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</p>
                    <p style={{ fontSize: '13px', color: isRisk ? getStatusStyle(selectedReport.status).color : '#e2e8f0', marginTop: '4px', fontWeight: isRisk ? 700 : 400 }}>
                      {value}
                    </p>
                  </div>
                ))}
              </div>
              <div className="p-3 rounded-xl" style={{ backgroundColor: '#1E000A', border: '1px solid #4A001A' }}>
                <p style={{ fontSize: '11px', color: '#3A5A7A', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Target</p>
                <p style={{ fontSize: '13px', color: '#e2e8f0', marginTop: '4px', wordBreak: 'break-all' }}>{selectedReport.target}</p>
              </div>
              <div className="p-3 rounded-xl" style={{ backgroundColor: '#1E000A', border: '1px solid #4A001A' }}>
                <p style={{ fontSize: '11px', color: '#3A5A7A', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Status</p>
                <span className="inline-block mt-2 px-3 py-1 rounded-lg text-xs" style={{ ...getStatusStyle(selectedReport.status), fontWeight: 600 }}>
                  {selectedReport.status}
                </span>
              </div>
              <div className="p-3 rounded-xl" style={{ backgroundColor: '#1E000A', border: '1px solid #4A001A' }}>
                <p style={{ fontSize: '11px', color: '#3A5A7A', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Description</p>
                <p style={{ fontSize: '13px', color: '#94a3b8', marginTop: '4px', lineHeight: 1.6 }}>{selectedReport.description}</p>
              </div>
              <div className="flex gap-3">
                <button
                  onClick={() => handleUpdateStatus(selectedReport.id, 'Confirmed Threat')}
                  className="flex-1 py-2.5 rounded-xl text-xs transition-all hover:opacity-80"
                  style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.3)', fontWeight: 600 }}
                >
                  Mark as Threat
                </button>
                <button
                  onClick={() => handleUpdateStatus(selectedReport.id, 'False Positive')}
                  className="flex-1 py-2.5 rounded-xl text-xs transition-all hover:opacity-80"
                  style={{ backgroundColor: 'rgba(34, 197, 94, 0.1)', color: '#22c55e', border: '1px solid rgba(34, 197, 94, 0.3)', fontWeight: 600 }}
                >
                  Mark as False Positive
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
