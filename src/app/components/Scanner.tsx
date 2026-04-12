import { useState, useEffect, useRef } from 'react';
import { ScansAPI, AnalysisResult, ThreatFactor, ExternalCheck } from '../lib/api';
import { Link, Mail, Search, AlertCircle, CheckCircle, AlertTriangle, Shield, Globe, Lock, FileWarning, Eye, Layers, Upload, Download, Zap, ExternalLink } from 'lucide-react';

interface ScanDetail {
  label: string;
  value: string;
  severity: 'safe' | 'warning' | 'danger' | 'info';
}

interface ScanResult {
  threatLevel: 'Safe' | 'Suspicious' | 'Dangerous';
  score: number;
  redFlags: string[];
  positives: string[];
  recommendations: string[];
  details: ScanDetail[];
  scanType: 'url' | 'email';
  scannedInput: string;
}

// ---- URL Analysis Engine ----

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.club', '.work', '.buzz', '.icu', '.tk', '.ml', '.ga', '.cf', '.gq',
  '.pw', '.cc', '.su', '.info', '.biz', '.click', '.link', '.site', '.online', '.live',
  '.store', '.stream', '.download', '.racing', '.win', '.bid', '.loan', '.trade',
];

const LEGITIMATE_DOMAINS = [
  'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'apple.com', 'microsoft.com',
  'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com', 'twitter.com', 'x.com',
  'linkedin.com', 'instagram.com', 'netflix.com', 'paypal.com', 'dropbox.com', 'figma.com',
  'notion.so', 'slack.com', 'zoom.us', 'stripe.com', 'shopify.com', 'twitch.tv',
  'whatsapp.com', 'telegram.org', 'discord.com', 'spotify.com', 'adobe.com',
];

const BRAND_KEYWORDS = [
  'google', 'apple', 'microsoft', 'amazon', 'paypal', 'netflix', 'facebook', 'instagram',
  'bank', 'chase', 'wellsfargo', 'citibank', 'amex', 'visa', 'mastercard', 'venmo',
  'coinbase', 'binance', 'crypto', 'wallet', 'dropbox', 'icloud', 'outlook', 'yahoo',
];

const PHISHING_PATH_KEYWORDS = [
  'login', 'signin', 'sign-in', 'verify', 'verification', 'confirm', 'account', 'secure',
  'update', 'password', 'credential', 'authenticate', 'billing', 'suspend', 'restore',
  'unlock', 'recover', 'reset', 'validate', 'identity', 'ssn', 'social-security',
];

function extractDomain(url: string): string {
  try {
    let cleaned = url.trim();
    if (!cleaned.match(/^https?:\/\//i)) cleaned = 'http://' + cleaned;
    const u = new URL(cleaned);
    return u.hostname.toLowerCase();
  } catch {
    const match = url.match(/(?:https?:\/\/)?([^\/\s:?#]+)/i);
    return match ? match[1].toLowerCase() : url.toLowerCase();
  }
}

function analyzeUrl(input: string): ScanResult {
  const redFlags: string[] = [];
  const positives: string[] = [];
  const details: ScanDetail[] = [];
  let score = 0;

  const trimmed = input.trim();
  let url = trimmed;
  if (!url.match(/^https?:\/\//i)) url = 'http://' + url;

  let parsedUrl: URL | null = null;
  try {
    parsedUrl = new URL(url);
  } catch {
    redFlags.push('URL is malformed and cannot be properly parsed');
    score += 30;
  }

  const domain = extractDomain(trimmed);

  if (parsedUrl) {
    if (parsedUrl.protocol === 'https:') {
      positives.push('Uses HTTPS encryption');
      details.push({ label: 'Protocol', value: 'HTTPS (Encrypted)', severity: 'safe' });
    } else {
      redFlags.push('Does not use HTTPS — data sent to this site is not encrypted');
      details.push({ label: 'Protocol', value: 'HTTP (Unencrypted)', severity: 'danger' });
      score += 15;
    }
  }

  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
    redFlags.push('Uses an IP address instead of a domain name — common phishing tactic');
    details.push({ label: 'Domain Type', value: 'Raw IP Address', severity: 'danger' });
    score += 25;
  }

  const hasSuspiciousTld = SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld));
  if (hasSuspiciousTld) {
    const tld = SUSPICIOUS_TLDS.find(t => domain.endsWith(t)) || '';
    redFlags.push(`Uses suspicious top-level domain "${tld}" often associated with phishing`);
    details.push({ label: 'TLD Risk', value: `${tld} — High risk TLD`, severity: 'danger' });
    score += 15;
  } else {
    const tld = '.' + domain.split('.').pop();
    details.push({ label: 'TLD', value: tld, severity: 'info' });
  }

  const isLegitimate = LEGITIMATE_DOMAINS.some(d => domain === d || domain === 'www.' + d);
  if (isLegitimate) {
    positives.push(`"${domain}" is a recognized legitimate domain`);
    details.push({ label: 'Domain Reputation', value: 'Known legitimate', severity: 'safe' });
    score = Math.max(0, score - 30);
  }

  if (!isLegitimate) {
    const impersonatedBrand = BRAND_KEYWORDS.find(brand => domain.includes(brand));
    if (impersonatedBrand) {
      redFlags.push(`Domain contains brand name "${impersonatedBrand}" but is not the official domain — possible impersonation`);
      details.push({ label: 'Brand Impersonation', value: `Contains "${impersonatedBrand}"`, severity: 'danger' });
      score += 25;
    }
  }

  const subdomainParts = domain.split('.');
  if (subdomainParts.length > 3) {
    redFlags.push(`Excessive subdomains (${subdomainParts.length - 2} levels) — used to obscure the real domain`);
    score += 10;
  }

  const domainWithoutTld = subdomainParts.slice(0, -1).join('.');
  const hyphenCount = (domainWithoutTld.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    redFlags.push(`Domain contains ${hyphenCount} hyphens — frequently seen in phishing URLs`);
    score += 10;
  }

  if (domain.length > 40) {
    redFlags.push('Unusually long domain name — may be attempting to hide the real destination');
    score += 10;
  }

  if (parsedUrl) {
    const path = parsedUrl.pathname.toLowerCase() + parsedUrl.search.toLowerCase();
    const foundKeywords = PHISHING_PATH_KEYWORDS.filter(kw => path.includes(kw));
    if (foundKeywords.length > 0) {
      redFlags.push(`URL path contains sensitive keywords: ${foundKeywords.map(k => `"${k}"`).join(', ')}`);
      details.push({ label: 'Path Keywords', value: foundKeywords.join(', '), severity: 'warning' });
      score += foundKeywords.length * 5;
    }
  }

  if (trimmed.includes('@')) {
    redFlags.push('Contains "@" symbol — can be used to redirect to a different domain than displayed');
    score += 20;
  }

  if (/%[0-9a-fA-F]{2}/.test(trimmed)) {
    redFlags.push('Contains URL-encoded characters that may be hiding the true destination');
    score += 10;
  }

  if (parsedUrl && parsedUrl.port && !['80', '443', ''].includes(parsedUrl.port)) {
    redFlags.push(`Uses non-standard port :${parsedUrl.port} — legitimate sites rarely do this`);
    details.push({ label: 'Port', value: parsedUrl.port, severity: 'warning' });
    score += 10;
  }

  if (/[а-яА-Я]|[\u0400-\u04FF]|[\u0250-\u02AF]/.test(domain)) {
    redFlags.push('Domain contains characters from non-Latin scripts — possible homoglyph attack');
    score += 30;
  }

  details.push({ label: 'Domain', value: domain, severity: isLegitimate ? 'safe' : 'info' });
  details.push({ label: 'Domain Length', value: `${domain.length} characters`, severity: domain.length > 40 ? 'warning' : 'info' });

  if (redFlags.length === 0) {
    positives.push('No obvious phishing indicators detected');
  }

  score = Math.max(0, Math.min(100, score));

  const threatLevel: ScanResult['threatLevel'] = score >= 40 ? 'Dangerous' : score >= 15 ? 'Suspicious' : 'Safe';
  const recommendations = generateRecommendations(threatLevel, 'url');

  return { threatLevel, score, redFlags, positives, recommendations, details, scanType: 'url', scannedInput: trimmed };
}

// ---- Email Analysis Engine ----

const URGENCY_PHRASES = [
  'act now', 'immediate action', 'urgent', 'expires today', 'last chance', 'limited time',
  'within 24 hours', 'within 48 hours', 'account will be closed', 'account suspended',
  'account disabled', 'unauthorized access', 'unusual activity', 'verify immediately',
  'confirm your identity', 'failure to respond', 'your account has been compromised',
  'action required', 'respond immediately', 'do not ignore',
];

const THREAT_PHRASES = [
  'click here to verify', 'click the link below', 'update your payment', 'confirm your password',
  'enter your credentials', 'provide your ssn', 'social security number', 'bank account details',
  'credit card number', 'wire transfer', 'send money', 'gift card', 'bitcoin payment',
  'cryptocurrency', 'inheritance', 'lottery winner', 'you have won', 'congratulations you won',
  'unclaimed funds', 'claim your prize', 'million dollars',
];

const IMPERSONATION_PHRASES = [
  'dear customer', 'dear valued customer', 'dear account holder', 'dear user',
  'we have detected', 'our records indicate', 'your account has been', 'as a security measure',
  'for your protection', 'security department', 'fraud department', 'technical support',
];

const SUSPICIOUS_SENDER_PATTERNS = [
  /no-?reply@(?!google|microsoft|apple|amazon|github|linkedin)/i,
  /support@(?!google|microsoft|apple|amazon|github)/i,
  /admin@(?!google|microsoft|apple)/i,
  /@[a-z]{2,}\d{3,}\./i,
  /@.*\.(xyz|top|club|buzz|icu|tk|ml|ga|cf|gq)/i,
];

function analyzeEmail(input: string): ScanResult {
  const redFlags: string[] = [];
  const positives: string[] = [];
  const details: ScanDetail[] = [];
  let score = 0;

  const text = input.toLowerCase();
  const lines = input.split('\n');

  const foundUrgency = URGENCY_PHRASES.filter(phrase => text.includes(phrase));
  if (foundUrgency.length > 0) {
    redFlags.push(`Contains urgency/pressure tactics: "${foundUrgency[0]}"${foundUrgency.length > 1 ? ` and ${foundUrgency.length - 1} more` : ''}`);
    details.push({ label: 'Urgency Tactics', value: `${foundUrgency.length} found`, severity: 'danger' });
    score += Math.min(30, foundUrgency.length * 8);
  } else {
    positives.push('No urgency or pressure tactics detected');
  }

  const foundThreats = THREAT_PHRASES.filter(phrase => text.includes(phrase));
  if (foundThreats.length > 0) {
    redFlags.push(`Contains suspicious phrases: "${foundThreats[0]}"${foundThreats.length > 1 ? ` and ${foundThreats.length - 1} more` : ''}`);
    details.push({ label: 'Suspicious Phrases', value: `${foundThreats.length} found`, severity: 'danger' });
    score += Math.min(35, foundThreats.length * 10);
  }

  const foundImpersonation = IMPERSONATION_PHRASES.filter(phrase => text.includes(phrase));
  if (foundImpersonation.length > 0) {
    redFlags.push(`Uses generic impersonation language: "${foundImpersonation[0]}"`);
    details.push({ label: 'Impersonation Language', value: `${foundImpersonation.length} patterns`, severity: 'warning' });
    score += Math.min(20, foundImpersonation.length * 5);
  }

  const urlPattern = /https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi;
  const urls = text.match(urlPattern) || [];
  details.push({ label: 'Embedded URLs', value: `${urls.length} found`, severity: urls.length > 3 ? 'warning' : 'info' });

  if (urls.length > 0) {
    const suspiciousUrls = urls.filter(u => {
      const d = extractDomain(u);
      return SUSPICIOUS_TLDS.some(tld => d.endsWith(tld)) || /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(d);
    });
    if (suspiciousUrls.length > 0) {
      redFlags.push(`Contains ${suspiciousUrls.length} suspicious URL(s) with risky domains`);
      score += suspiciousUrls.length * 10;
    }

    const shortenedDomains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rb.gy'];
    const shortened = urls.filter(u => shortenedDomains.some(d => u.toLowerCase().includes(d)));
    if (shortened.length > 0) {
      redFlags.push('Contains shortened URLs that hide the true destination');
      score += 10;
    }
  }

  const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = text.match(emailPattern) || [];
  if (emails.length > 0) {
    const suspiciousEmails = emails.filter(e => SUSPICIOUS_SENDER_PATTERNS.some(p => p.test(e)));
    if (suspiciousEmails.length > 0) {
      redFlags.push(`Contains suspicious email address: ${suspiciousEmails[0]}`);
      score += 10;
    }
    details.push({ label: 'Email Addresses', value: emails.slice(0, 3).join(', '), severity: suspiciousEmails.length > 0 ? 'warning' : 'info' });
  }

  const personalInfoKeywords = ['password', 'ssn', 'social security', 'credit card', 'bank account', 'routing number', 'pin number', 'date of birth', "mother's maiden"];
  const foundPersonal = personalInfoKeywords.filter(kw => text.includes(kw));
  if (foundPersonal.length > 0) {
    redFlags.push(`Requests sensitive personal information: ${foundPersonal.join(', ')}`);
    details.push({ label: 'Personal Info Request', value: foundPersonal.join(', '), severity: 'danger' });
    score += foundPersonal.length * 12;
  }

  const grammarIssues = [
    /\b(kindly|do the needful|revert back|humbly request)\b/i,
    /dear\s+(sir|madam|friend|beneficiary)/i,
    /\b(plese|recieve|transfere|informations|datas)\b/i,
  ];
  const grammarMatches = grammarIssues.filter(p => p.test(input));
  if (grammarMatches.length > 0) {
    redFlags.push('Contains grammar patterns commonly associated with phishing/scam emails');
    score += 10;
  }

  const capsPattern = /[A-Z\s]{20,}/;
  if (capsPattern.test(input)) {
    redFlags.push('Contains excessive capitalization — common in scam/phishing emails');
    score += 5;
  }

  if (/\b(attached|attachment|see attached|open the attached|download)\b/i.test(input)) {
    details.push({ label: 'Attachment Reference', value: 'Mentions attachments', severity: 'warning' });
    if (score > 10) {
      redFlags.push('References attachments in a suspicious context — may contain malware');
      score += 5;
    }
  }

  details.push({ label: 'Content Length', value: `${input.length} characters, ${lines.length} lines`, severity: 'info' });

  if (redFlags.length === 0) {
    positives.push('No obvious phishing indicators detected in the email content');
  }

  score = Math.max(0, Math.min(100, score));
  const threatLevel: ScanResult['threatLevel'] = score >= 40 ? 'Dangerous' : score >= 15 ? 'Suspicious' : 'Safe';
  const recommendations = generateRecommendations(threatLevel, 'email');

  return { threatLevel, score, redFlags, positives, recommendations, details, scanType: 'email', scannedInput: input.slice(0, 100) + (input.length > 100 ? '...' : '') };
}

function generateRecommendations(level: ScanResult['threatLevel'], type: 'url' | 'email'): string[] {
  const recs: string[] = [];
  if (level === 'Dangerous') {
    if (type === 'url') {
      recs.push('Do NOT visit this URL — it shows strong phishing indicators');
      recs.push('If you already visited, do not enter any personal information');
      recs.push('Run a full antivirus scan on your device');
    } else {
      recs.push('Do NOT click any links or download attachments from this email');
      recs.push('Report this email as phishing to your email provider');
      recs.push('Delete the email immediately');
    }
    recs.push('If you shared any credentials, change your passwords immediately');
    recs.push('Enable two-factor authentication on all important accounts');
  } else if (level === 'Suspicious') {
    if (type === 'url') {
      recs.push('Exercise caution — verify the URL independently before proceeding');
      recs.push('Look for the padlock icon in your browser before entering data');
    } else {
      recs.push('Verify the sender through a separate communication channel');
      recs.push('Do not click links — navigate to the service directly via your browser');
    }
    recs.push('When in doubt, contact the organization directly using their official website');
  } else {
    if (type === 'url') {
      recs.push('This URL appears safe, but always stay vigilant');
      recs.push('Ensure the padlock icon is present before entering sensitive data');
    } else {
      recs.push('This email appears safe, but always verify unexpected requests');
    }
    recs.push('Keep your browser and antivirus software up to date');
  }
  return recs;
}

// ---- UI ----

const cardStyle = {
  backgroundColor: '#0d1225',
  border: '1px solid #1a2040',
  borderRadius: '16px',
};

const inputStyle: React.CSSProperties = {
  backgroundColor: '#060b18',
  border: '1px solid #1a2040',
  borderRadius: '12px',
  color: 'white',
  fontSize: '14px',
  outline: 'none',
  width: '100%',
  padding: '12px 16px',
  transition: 'border-color 0.2s',
};

// ─── Bulk scan types ──────────────────────────────────────────────────────────
interface BulkResult {
  target: string;
  threatLevel: 'Safe' | 'Suspicious' | 'Dangerous';
  score: number;
  scanId?: string;
  error?: string;
}

export function Scanner() {
  const [mode, setMode] = useState<'single' | 'bulk'>('single');
  const [scanType, setScanType] = useState<'url' | 'email'>('url');
  const [inputValue, setInputValue] = useState('');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [externalResult, setExternalResult] = useState<AnalysisResult | null>(null);
  const [externalLoading, setExternalLoading] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [focusedInput, setFocusedInput] = useState(false);

  // Bulk scan state
  const [bulkText, setBulkText] = useState('');
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkResults, setBulkResults] = useState<BulkResult[]>([]);
  const [bulkProgress, setBulkProgress] = useState(0);

  // WebSocket — live threat alerts
  const wsRef = useRef<WebSocket | null>(null);
  const [liveAlert, setLiveAlert] = useState<{ id: string; target: string; riskScore: number } | null>(null);

  useEffect(() => {
    try {
      const ws = new WebSocket(`ws://localhost:3001`);
      wsRef.current = ws;
      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type === 'THREAT_DETECTED') {
            setLiveAlert(msg.scan);
            setTimeout(() => setLiveAlert(null), 8000);
          }
        } catch { /* ignore */ }
      };
      ws.onerror = () => { /* backend may not have ws installed yet */ };
      return () => ws.close();
    } catch { /* ws not available */ }
  }, []);

  const handleScan = () => {
    if (!inputValue.trim()) return;
    setIsScanning(true);
    setScanResult(null);
    setExternalResult(null);
    setScanProgress(0);
    const steps = [10, 25, 45, 65, 80, 95, 100];
    let i = 0;
    const interval = setInterval(() => {
      if (i < steps.length) {
        setScanProgress(steps[i]);
        i++;
      } else {
        clearInterval(interval);
        const result = scanType === 'url' ? analyzeUrl(inputValue) : analyzeEmail(inputValue);
        setScanResult(result);
        setIsScanning(false);

        // Layer 2–5: call backend for external intelligence
        setExternalLoading(true);
        ScansAPI.analyze(inputValue.trim(), scanType === 'url' ? 'URL' : 'Email')
          .then(res => { if (res.success) setExternalResult(res.analysis); })
          .catch(() => { /* non-critical */ })
          .finally(() => setExternalLoading(false));
      }
    }, 200);
  };

  const handleBulkScan = async () => {
    const lines = bulkText.split('\n').map(l => l.trim()).filter(Boolean);
    if (lines.length === 0) return;
    if (lines.length > 50) { alert('Maximum 50 targets per bulk scan'); return; }
    setBulkLoading(true);
    setBulkResults([]);
    setBulkProgress(0);
    try {
      const res = await ScansAPI.bulk(lines, scanType === 'url' ? 'URL' : 'Email');
      if (res.success) {
        setBulkResults(res.results.map(r => ({
          target: r.target,
          threatLevel: r.error ? 'Suspicious' : r.threatLevel,
          score: r.score || 0,
          scanId: r.scanId,
          error: r.error,
        })));
      }
    } catch (err) {
      console.error('Bulk scan failed:', err);
    } finally {
      setBulkLoading(false);
      setBulkProgress(100);
    }
  };

  const exportBulkCSV = () => {
    const header = 'Target,Threat Level,Risk Score,Scan ID\n';
    const rows = bulkResults.map(r => `"${r.target}","${r.threatLevel}",${r.score},"${r.scanId || ''}"`).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'bulk_scan_results.csv'; a.click();
    URL.revokeObjectURL(url);
  };

  const getThreatConfig = (level: string) => {
    switch (level) {
      case 'Safe':
        return {
          icon: <CheckCircle className="w-8 h-8" style={{ color: '#22c55e' }} />,
          color: '#22c55e',
          bg: 'rgba(34, 197, 94, 0.08)',
          border: 'rgba(34, 197, 94, 0.3)',
          glow: 'rgba(34, 197, 94, 0.15)',
        };
      case 'Suspicious':
        return {
          icon: <AlertTriangle className="w-8 h-8" style={{ color: '#fbbf24' }} />,
          color: '#fbbf24',
          bg: 'rgba(251, 191, 36, 0.08)',
          border: 'rgba(251, 191, 36, 0.3)',
          glow: 'rgba(251, 191, 36, 0.15)',
        };
      case 'Dangerous':
        return {
          icon: <AlertCircle className="w-8 h-8" style={{ color: '#ef4444' }} />,
          color: '#ef4444',
          bg: 'rgba(239, 68, 68, 0.08)',
          border: 'rgba(239, 68, 68, 0.3)',
          glow: 'rgba(239, 68, 68, 0.15)',
        };
      default:
        return { icon: null, color: '#94a3b8', bg: 'transparent', border: '#1a2040', glow: 'transparent' };
    }
  };

  const getScoreBarColor = (score: number) => {
    if (score >= 40) return '#ef4444';
    if (score >= 15) return '#fbbf24';
    return '#22c55e';
  };

  const getSeverityStyle = (severity: ScanDetail['severity']) => {
    switch (severity) {
      case 'safe': return { color: '#22c55e', backgroundColor: 'rgba(34, 197, 94, 0.1)', border: '1px solid rgba(34, 197, 94, 0.2)' };
      case 'warning': return { color: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.1)', border: '1px solid rgba(251, 191, 36, 0.2)' };
      case 'danger': return { color: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)' };
      default: return { color: '#94a3b8', backgroundColor: 'rgba(148, 163, 184, 0.08)', border: '1px solid rgba(148, 163, 184, 0.15)' };
    }
  };

  const scanSteps = [
    { threshold: 10, text: 'Parsing input...' },
    { threshold: 25, text: `Checking ${scanType === 'url' ? 'domain reputation' : 'content patterns'}...` },
    { threshold: 45, text: `Analyzing ${scanType === 'url' ? 'URL structure' : 'urgency indicators'}...` },
    { threshold: 65, text: `Detecting ${scanType === 'url' ? 'brand impersonation' : 'social engineering'}...` },
    { threshold: 80, text: 'Evaluating threat indicators...' },
    { threshold: 95, text: 'Generating report...' },
  ];

  return (
    <div className="space-y-5 max-w-3xl mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'white' }}>Threat Scanner</h2>
          <p style={{ fontSize: '13px', color: '#6b7f9e', marginTop: '4px' }}>
            Multi-layer detection: heuristics + RDAP + VirusTotal + Google Safe Browsing
          </p>
        </div>
        {/* Mode toggle */}
        <div className="flex p-1 rounded-xl gap-1" style={{ backgroundColor: '#060b18', border: '1px solid #1a2040' }}>
          {[{ id: 'single' as const, icon: Search, label: 'Single' }, { id: 'bulk' as const, icon: Layers, label: 'Bulk' }].map(({ id, icon: Icon, label }) => (
            <button key={id} type="button" onClick={() => setMode(id)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all"
              style={mode === id
                ? { backgroundColor: 'rgba(0,212,255,0.12)', color: '#00d4ff', border: '1px solid rgba(0,212,255,0.3)', fontWeight: 600, fontSize: '12px' }
                : { color: '#6b7f9e', border: '1px solid transparent', fontSize: '12px' }}>
              <Icon className="w-3.5 h-3.5" />{label}
            </button>
          ))}
        </div>
      </div>

      {/* Live threat alert banner */}
      {liveAlert && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl animate-pulse"
          style={{ backgroundColor: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.4)' }}>
          <Zap className="w-4 h-4 shrink-0" style={{ color: '#ef4444' }} />
          <div className="flex-1 min-w-0">
            <span style={{ fontSize: '12px', fontWeight: 700, color: '#ef4444' }}>LIVE ALERT </span>
            <span style={{ fontSize: '12px', color: '#e2e8f0' }}>Dangerous threat detected: </span>
            <span className="truncate block" style={{ fontSize: '12px', color: '#94a3b8' }}>{liveAlert.target}</span>
          </div>
          <span style={{ fontSize: '13px', fontWeight: 800, color: '#ef4444' }}>{liveAlert.riskScore}/100</span>
        </div>
      )}

      {/* ── BULK MODE ── */}
      {mode === 'bulk' && (
        <div className="p-6 space-y-5" style={cardStyle}>
          <div>
            <label style={{ fontSize: '12px', color: '#6b7f9e', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Scan Type
            </label>
            <div className="flex mt-2 p-1 rounded-xl gap-2" style={{ backgroundColor: '#060b18', border: '1px solid #1a2040' }}>
              {[{ type: 'url' as const, icon: Globe, label: 'URL' }, { type: 'email' as const, icon: Mail, label: 'Email' }].map(({ type, icon: Icon, label }) => (
                <button key={type} type="button" onClick={() => setScanType(type)}
                  className="flex-1 flex items-center justify-center gap-2 py-2 rounded-lg transition-all"
                  style={scanType === type ? { backgroundColor: 'rgba(0,212,255,0.12)', color: '#00d4ff', border: '1px solid rgba(0,212,255,0.3)', fontWeight: 600 } : { color: '#6b7f9e', border: '1px solid transparent' }}>
                  <Icon className="w-4 h-4" /><span style={{ fontSize: '13px' }}>{label}</span>
                </button>
              ))}
            </div>
          </div>
          <div>
            <label style={{ fontSize: '12px', color: '#6b7f9e', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Targets — one per line (max 50)
            </label>
            <textarea value={bulkText} onChange={e => setBulkText(e.target.value)} rows={8}
              placeholder={"https://example.com\nhttps://suspicious-site.xyz\nhttp://192.168.1.1/login\n..."}
              style={{ ...inputStyle, marginTop: '8px', resize: 'none', lineHeight: 1.6, width: '100%' }} />
          </div>
          <button type="button" onClick={handleBulkScan} disabled={bulkLoading || !bulkText.trim()}
            className="w-full flex items-center justify-center gap-2 py-3 rounded-xl transition-all"
            style={bulkLoading || !bulkText.trim()
              ? { backgroundColor: '#1a2040', color: '#4a6080', cursor: 'not-allowed' }
              : { background: 'linear-gradient(135deg, #00d4ff, #0099bb)', color: '#0a0e1a', fontWeight: 700, fontSize: '14px', boxShadow: '0 0 30px rgba(0,212,255,0.3)' }}>
            {bulkLoading ? <><div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />Scanning...</> : <><Layers className="w-4 h-4" />Run Bulk Scan</>}
          </button>

          {bulkResults.length > 0 && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'white' }}>Results ({bulkResults.length} targets)</span>
                <button type="button" onClick={exportBulkCSV}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs"
                  style={{ color: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)' }}>
                  <Download className="w-3.5 h-3.5" />Export CSV
                </button>
              </div>
              {/* Summary */}
              <div className="grid grid-cols-3 gap-3">
                {(['Dangerous', 'Suspicious', 'Safe'] as const).map(level => {
                  const count = bulkResults.filter(r => r.threatLevel === level).length;
                  const color = level === 'Dangerous' ? '#ef4444' : level === 'Suspicious' ? '#fbbf24' : '#22c55e';
                  return (
                    <div key={level} className="p-3 rounded-xl text-center" style={{ backgroundColor: '#060b18', border: `1px solid ${color}30` }}>
                      <div style={{ fontSize: '22px', fontWeight: 800, color }}>{count}</div>
                      <div style={{ fontSize: '11px', color: '#6b7f9e' }}>{level}</div>
                    </div>
                  );
                })}
              </div>
              {/* Rows */}
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {bulkResults.map((r, i) => {
                  const color = r.threatLevel === 'Dangerous' ? '#ef4444' : r.threatLevel === 'Suspicious' ? '#fbbf24' : '#22c55e';
                  return (
                    <div key={i} className="flex items-center gap-3 px-4 py-2.5 rounded-xl" style={{ backgroundColor: '#060b18', border: '1px solid #1a2040' }}>
                      <span className="flex-1 truncate" style={{ fontSize: '12px', color: '#94a3b8' }}>{r.target}</span>
                      <span style={{ fontSize: '11px', color, fontWeight: 700, whiteSpace: 'nowrap' }}>{r.threatLevel}</span>
                      <span style={{ fontSize: '13px', fontWeight: 800, color, minWidth: '36px', textAlign: 'right' }}>{r.score}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── SINGLE SCAN MODE ── */}
      {mode === 'single' && <>

      {/* Input Card */}
      <div className="p-6 space-y-5" style={cardStyle}>
        {/* Toggle */}
        <div>
          <label style={{ fontSize: '12px', color: '#6b7f9e', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Scan Type
          </label>
          <div
            className="flex mt-2 p-1 rounded-xl gap-2"
            style={{ backgroundColor: '#060b18', border: '1px solid #1a2040' }}
          >
            {[
              { type: 'url' as const, icon: Globe, label: 'URL Analysis' },
              { type: 'email' as const, icon: Mail, label: 'Email Analysis' },
            ].map(({ type, icon: Icon, label }) => (
              <button
                key={type}
                type="button"
                onClick={() => { setScanType(type); setInputValue(''); setScanResult(null); setExternalResult(null); }}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg transition-all duration-200"
                style={
                  scanType === type
                    ? {
                        backgroundColor: 'rgba(0, 212, 255, 0.12)',
                        color: '#00d4ff',
                        border: '1px solid rgba(0, 212, 255, 0.3)',
                        boxShadow: '0 0 15px rgba(0, 212, 255, 0.1)',
                        fontWeight: 600,
                      }
                    : { color: '#6b7f9e', border: '1px solid transparent', fontWeight: 500 }
                }
              >
                <Icon className="w-4 h-4" />
                <span style={{ fontSize: '13px' }}>{label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Input */}
        <div>
          <label style={{ fontSize: '12px', color: '#6b7f9e', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            {scanType === 'url' ? 'Target URL' : 'Email Content'}
          </label>
          <div className="mt-2">
            {scanType === 'url' ? (
              <input
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                onFocus={() => setFocusedInput(true)}
                onBlur={() => setFocusedInput(false)}
                placeholder="e.g. https://secure-login-paypal.xyz/verify-account"
                style={{
                  ...inputStyle,
                  borderColor: focusedInput ? 'rgba(0, 212, 255, 0.5)' : '#1a2040',
                  boxShadow: focusedInput ? '0 0 0 3px rgba(0, 212, 255, 0.08)' : 'none',
                }}
              />
            ) : (
              <textarea
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onFocus={() => setFocusedInput(true)}
                onBlur={() => setFocusedInput(false)}
                placeholder={"Paste the full email content here...\n\nExample:\nDear Customer,\nYour account has been suspended. Click here to verify your identity immediately: http://secure-banking.xyz/login"}
                rows={7}
                style={{
                  ...inputStyle,
                  resize: 'none',
                  borderColor: focusedInput ? 'rgba(0, 212, 255, 0.5)' : '#1a2040',
                  boxShadow: focusedInput ? '0 0 0 3px rgba(0, 212, 255, 0.08)' : 'none',
                  lineHeight: 1.6,
                }}
              />
            )}
          </div>
        </div>

        {/* Quick examples */}
        <div>
          <p style={{ fontSize: '11px', color: '#4a6080', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Quick examples
          </p>
          <div className="flex flex-wrap gap-2">
            {scanType === 'url' ? (
              <>
                <button type="button" onClick={() => setInputValue('https://google.com')} className="px-3 py-1 rounded-lg text-xs transition-all hover:opacity-80" style={{ color: '#22c55e', backgroundColor: 'rgba(34, 197, 94, 0.08)', border: '1px solid rgba(34, 197, 94, 0.2)' }}>google.com (safe)</button>
                <button type="button" onClick={() => setInputValue('http://secure-paypal-login.xyz/verify-account?id=12345')} className="px-3 py-1 rounded-lg text-xs transition-all hover:opacity-80" style={{ color: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)' }}>fake paypal (dangerous)</button>
                <button type="button" onClick={() => setInputValue('http://192.168.1.1:8080/admin/login')} className="px-3 py-1 rounded-lg text-xs transition-all hover:opacity-80" style={{ color: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.08)', border: '1px solid rgba(251, 191, 36, 0.2)' }}>IP address URL</button>
                <button type="button" onClick={() => setInputValue('https://my-secure-banking-app.club/account/verify')} className="px-3 py-1 rounded-lg text-xs transition-all hover:opacity-80" style={{ color: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)' }}>suspicious .club</button>
              </>
            ) : (
              <>
                <button type="button" onClick={() => setInputValue('Dear Customer,\n\nYour account has been suspended due to unusual activity. You must verify your identity immediately or your account will be permanently closed within 24 hours.\n\nClick here to verify: http://secure-banking-login.xyz/verify\n\nPlease provide your password and social security number to confirm your identity.\n\nSecurity Department')} className="px-3 py-1 rounded-lg text-xs transition-all hover:opacity-80" style={{ color: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)' }}>Phishing email</button>
                <button type="button" onClick={() => setInputValue("Hi Team,\n\nJust a reminder that our weekly standup meeting is at 10am tomorrow. Please review the project updates in the shared folder before the meeting.\n\nThanks,\nSarah")} className="px-3 py-1 rounded-lg text-xs transition-all hover:opacity-80" style={{ color: '#22c55e', backgroundColor: 'rgba(34, 197, 94, 0.08)', border: '1px solid rgba(34, 197, 94, 0.2)' }}>Safe email</button>
                <button type="button" onClick={() => setInputValue('CONGRATULATIONS! You have won $5,000,000 in the International Lottery. To claim your prize, kindly send your bank account details and a processing fee of $500 via gift card to claim@winner-lottery.tk')} className="px-3 py-1 rounded-lg text-xs transition-all hover:opacity-80" style={{ color: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.08)', border: '1px solid rgba(251, 191, 36, 0.2)' }}>Lottery scam</button>
              </>
            )}
          </div>
        </div>

        {/* Scan Button */}
        <button
          type="button"
          onClick={handleScan}
          disabled={isScanning || !inputValue.trim()}
          className="w-full flex items-center justify-center gap-2 py-3.5 rounded-xl transition-all duration-200"
          style={
            isScanning || !inputValue.trim()
              ? { backgroundColor: '#1a2040', color: '#4a6080', cursor: 'not-allowed' }
              : {
                  background: 'linear-gradient(135deg, #00d4ff, #0099bb)',
                  color: '#0a0e1a',
                  fontWeight: 700,
                  fontSize: '14px',
                  boxShadow: '0 0 30px rgba(0, 212, 255, 0.3)',
                  cursor: 'pointer',
                }
          }
        >
          {isScanning ? (
            <>
              <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
              Analyzing...
            </>
          ) : (
            <>
              <Search className="w-4 h-4" />
              Scan for Threats
            </>
          )}
        </button>
      </div>

      {/* Scanning Progress */}
      {isScanning && (
        <div className="p-5" style={cardStyle}>
          <div className="flex items-center gap-3 mb-4">
            <div
              className="p-2 rounded-lg animate-pulse"
              style={{ backgroundColor: 'rgba(0, 212, 255, 0.1)' }}
            >
              <Shield className="w-5 h-5" style={{ color: '#00d4ff' }} />
            </div>
            <span style={{ fontSize: '14px', color: '#94a3b8' }}>Running heuristic analysis...</span>
            <span style={{ marginLeft: 'auto', fontSize: '14px', fontWeight: 700, color: '#00d4ff' }}>{scanProgress}%</span>
          </div>
          <div className="w-full rounded-full h-1.5 overflow-hidden" style={{ backgroundColor: '#1a2040' }}>
            <div
              className="h-1.5 rounded-full transition-all duration-300"
              style={{
                width: `${scanProgress}%`,
                background: 'linear-gradient(90deg, #00d4ff, #0099bb)',
                boxShadow: '0 0 10px rgba(0, 212, 255, 0.5)',
              }}
            />
          </div>
          <div className="mt-3 space-y-1">
            {scanSteps.filter(s => scanProgress >= s.threshold).map((s, i) => (
              <p key={i} style={{ fontSize: '12px', color: '#4a6080' }}>
                <span style={{ color: '#00d4ff' }}>✓</span> {s.text}
              </p>
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      {scanResult && (() => {
        const config = getThreatConfig(scanResult.threatLevel);
        return (
          <div className="space-y-4">
            {/* Threat Level */}
            <div
              className="relative p-5 rounded-2xl overflow-hidden"
              style={{
                backgroundColor: config.bg,
                border: `1px solid ${config.border}`,
                boxShadow: `0 0 40px ${config.glow}`,
              }}
            >
              <div
                className="absolute top-0 left-0 right-0 h-0.5"
                style={{ background: `linear-gradient(90deg, transparent, ${config.color}, transparent)` }}
              />
              <div className="flex items-center justify-between flex-wrap gap-4 mb-5">
                <div className="flex items-center gap-4">
                  {config.icon}
                  <div>
                    <h3 style={{ fontSize: '20px', fontWeight: 700, color: 'white' }}>
                      Threat Level:{' '}
                      <span style={{ color: config.color }}>{scanResult.threatLevel}</span>
                    </h3>
                    <p style={{ fontSize: '12px', color: '#6b7f9e', marginTop: '2px' }}>
                      {scanResult.scanType === 'url' ? 'URL' : 'Email'} scan completed on {new Date().toLocaleString()}
                    </p>
                  </div>
                </div>
                <div className="text-center">
                  <div style={{ fontSize: '36px', fontWeight: 800, color: config.color, lineHeight: 1 }}>
                    {scanResult.score}
                  </div>
                  <div style={{ fontSize: '11px', color: '#6b7f9e', marginTop: '2px' }}>Risk Score</div>
                </div>
              </div>
              <div>
                <div className="flex justify-between mb-1.5" style={{ fontSize: '11px', color: '#4a6080' }}>
                  <span>Safe (0)</span>
                  <span>Dangerous (100)</span>
                </div>
                <div className="w-full rounded-full h-2.5 overflow-hidden" style={{ backgroundColor: 'rgba(255,255,255,0.08)' }}>
                  <div
                    className="h-2.5 rounded-full transition-all duration-700"
                    style={{
                      width: `${Math.max(3, scanResult.score)}%`,
                      backgroundColor: getScoreBarColor(scanResult.score),
                      boxShadow: `0 0 8px ${getScoreBarColor(scanResult.score)}`,
                    }}
                  />
                </div>
              </div>
            </div>

            {/* Red Flags */}
            {scanResult.redFlags.length > 0 && (
              <div className="p-5 rounded-2xl" style={cardStyle}>
                <div className="flex items-center gap-2 mb-4">
                  <AlertCircle className="w-5 h-5" style={{ color: '#ef4444' }} />
                  <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'white' }}>
                    Red Flags ({scanResult.redFlags.length})
                  </h4>
                </div>
                <div className="space-y-2">
                  {scanResult.redFlags.map((flag, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-3 p-3 rounded-xl"
                      style={{ backgroundColor: 'rgba(239, 68, 68, 0.06)', border: '1px solid rgba(239, 68, 68, 0.15)' }}
                    >
                      <span style={{ color: '#ef4444', flexShrink: 0, fontSize: '14px' }}>⚠</span>
                      <span style={{ fontSize: '13px', color: '#e2e8f0', lineHeight: 1.5 }}>{flag}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Positives */}
            {scanResult.positives.length > 0 && (
              <div className="p-5 rounded-2xl" style={cardStyle}>
                <div className="flex items-center gap-2 mb-4">
                  <CheckCircle className="w-5 h-5" style={{ color: '#22c55e' }} />
                  <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'white' }}>
                    Positive Indicators ({scanResult.positives.length})
                  </h4>
                </div>
                <div className="space-y-2">
                  {scanResult.positives.map((pos, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-3 p-3 rounded-xl"
                      style={{ backgroundColor: 'rgba(34, 197, 94, 0.06)', border: '1px solid rgba(34, 197, 94, 0.15)' }}
                    >
                      <span style={{ color: '#22c55e', flexShrink: 0 }}>✓</span>
                      <span style={{ fontSize: '13px', color: '#e2e8f0', lineHeight: 1.5 }}>{pos}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Technical Details */}
            <div className="p-5 rounded-2xl" style={cardStyle}>
              <div className="flex items-center gap-2 mb-4">
                <Eye className="w-5 h-5" style={{ color: '#00d4ff' }} />
                <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'white' }}>Technical Details</h4>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {scanResult.details.map((detail, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between p-3 rounded-xl"
                    style={{ backgroundColor: '#060b18', border: '1px solid #1a2040' }}
                  >
                    <span style={{ fontSize: '12px', color: '#6b7f9e' }}>{detail.label}</span>
                    <span
                      className="px-2 py-0.5 rounded-lg text-xs"
                      style={getSeverityStyle(detail.severity)}
                    >
                      {detail.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommendations */}
            <div className="p-5 rounded-2xl" style={cardStyle}>
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-5 h-5" style={{ color: '#00d4ff' }} />
                <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'white' }}>Recommendations</h4>
              </div>
              <div className="space-y-2">
                {scanResult.recommendations.map((rec, i) => (
                  <div key={i} className="flex items-start gap-3 p-3 rounded-xl" style={{ backgroundColor: 'rgba(0, 212, 255, 0.04)', border: '1px solid rgba(0, 212, 255, 0.1)' }}>
                    <span style={{ color: '#00d4ff', flexShrink: 0, fontSize: '14px' }}>→</span>
                    <span style={{ fontSize: '13px', color: '#94a3b8', lineHeight: 1.5 }}>{rec}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* ── Threat Intelligence (external checks) ── */}
            <div className="p-5 rounded-2xl" style={cardStyle}>
              <div className="flex items-center gap-2 mb-4">
                <Layers className="w-5 h-5" style={{ color: '#a78bfa' }} />
                <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'white' }}>Threat Intelligence</h4>
                {externalLoading && (
                  <div className="flex items-center gap-1.5 ml-auto">
                    <div className="w-3 h-3 border-2 border-purple-400 border-t-transparent rounded-full animate-spin" />
                    <span style={{ fontSize: '11px', color: '#a78bfa' }}>Querying external sources…</span>
                  </div>
                )}
              </div>

              {externalLoading && !externalResult && (
                <div className="space-y-2">
                  {['RDAP Domain Registry', 'Google Safe Browsing', 'VirusTotal'].map(src => (
                    <div key={src} className="flex items-center justify-between px-4 py-3 rounded-xl" style={{ backgroundColor: '#060b18', border: '1px solid #1a2040' }}>
                      <span style={{ fontSize: '13px', color: '#6b7f9e' }}>{src}</span>
                      <div className="w-3 h-3 border-2 border-gray-600 border-t-transparent rounded-full animate-spin" />
                    </div>
                  ))}
                </div>
              )}

              {externalResult && (
                <div className="space-y-3">
                  {/* Updated combined score */}
                  <div className="flex items-center justify-between px-4 py-3 rounded-xl"
                    style={{ backgroundColor: externalResult.score >= 50 ? 'rgba(239,68,68,0.08)' : externalResult.score >= 20 ? 'rgba(251,191,36,0.08)' : 'rgba(34,197,94,0.08)',
                      border: `1px solid ${externalResult.score >= 50 ? 'rgba(239,68,68,0.3)' : externalResult.score >= 20 ? 'rgba(251,191,36,0.3)' : 'rgba(34,197,94,0.3)'}` }}>
                    <div>
                      <span style={{ fontSize: '13px', fontWeight: 600, color: 'white' }}>Combined Score (all layers)</span>
                      <p style={{ fontSize: '11px', color: '#6b7f9e', marginTop: '2px' }}>Local heuristics + external intelligence</p>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontSize: '22px', fontWeight: 800, color: externalResult.score >= 50 ? '#ef4444' : externalResult.score >= 20 ? '#fbbf24' : '#22c55e' }}>
                        {externalResult.score}
                      </span>
                      <span style={{ fontSize: '12px', color: '#6b7f9e' }}>/100</span>
                    </div>
                  </div>

                  {/* External check rows */}
                  {externalResult.externalChecks.map((check, i) => {
                    const resultColor = check.result === 'THREAT' ? '#ef4444' : check.result === 'WARNING' ? '#fbbf24' : check.result === 'CLEAN' ? '#22c55e' : '#6b7f9e';
                    const resultBg    = check.result === 'THREAT' ? 'rgba(239,68,68,0.1)' : check.result === 'WARNING' ? 'rgba(251,191,36,0.1)' : check.result === 'CLEAN' ? 'rgba(34,197,94,0.1)' : 'rgba(148,163,184,0.08)';
                    return (
                      <div key={i} className="p-3 rounded-xl" style={{ backgroundColor: '#060b18', border: '1px solid #1a2040' }}>
                        <div className="flex items-center justify-between mb-1">
                          <span style={{ fontSize: '12px', fontWeight: 600, color: '#94a3b8' }}>{check.source}</span>
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-xs font-bold" style={{ color: resultColor, backgroundColor: resultBg }}>{check.result}</span>
                            {check.link && (
                              <a href={check.link} target="_blank" rel="noopener noreferrer">
                                <ExternalLink className="w-3.5 h-3.5" style={{ color: '#6b7f9e' }} />
                              </a>
                            )}
                          </div>
                        </div>
                        <p style={{ fontSize: '11px', color: '#4a6080' }}>{check.detail}</p>
                      </div>
                    );
                  })}

                  {/* Risk factor breakdown */}
                  <div className="pt-2">
                    <p style={{ fontSize: '11px', color: '#4a6080', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '8px' }}>
                      Risk Factor Breakdown
                    </p>
                    <div className="space-y-1.5">
                      {externalResult.factors.filter(f => f.impact !== 0).map((f: ThreatFactor, i) => {
                        const color = f.severity === 'danger' ? '#ef4444' : f.severity === 'warning' ? '#fbbf24' : '#22c55e';
                        return (
                          <div key={i} className="flex items-center gap-3 px-3 py-2 rounded-lg" style={{ backgroundColor: '#060b18', border: '1px solid #1a2040' }}>
                            <span className="shrink-0 px-1.5 py-0.5 rounded text-xs font-semibold" style={{ color: '#6b7f9e', backgroundColor: '#0d1225', border: '1px solid #1a2040', fontSize: '10px' }}>
                              {f.layer}
                            </span>
                            <span className="flex-1" style={{ fontSize: '12px', color: '#94a3b8' }}>{f.label}</span>
                            <span style={{ fontSize: '12px', fontWeight: 700, color, whiteSpace: 'nowrap' }}>
                              {f.impact > 0 ? `+${f.impact}` : f.impact}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}

              {!externalLoading && !externalResult && (
                <p style={{ fontSize: '13px', color: '#4a6080' }}>Run a scan to see threat intelligence results.</p>
              )}
            </div>
          </div>
        );
      })()}
      </> /* end single mode */}
    </div>
  );
}
