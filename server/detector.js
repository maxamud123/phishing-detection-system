'use strict';

/**
 * PhishGuard — Multi-Layer Threat Detection Engine
 *
 * Layer 1 : Local heuristics       (URL features, email content analysis)
 * Layer 2 : Typosquatting check     (Levenshtein distance vs. popular brands)
 * Layer 3 : RDAP domain-age lookup  (free, no API key required)
 * Layer 4 : Google Safe Browsing    (requires GOOGLE_SAFE_BROWSING_KEY in .env)
 * Layer 5 : VirusTotal              (requires VIRUSTOTAL_API_KEY in .env)
 */

const https = require('https');

// ─── HTTPS helper ─────────────────────────────────────────────────────────────

function httpsRequest(options, body = null) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('Request timeout')); });
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

// ─── Domain helpers ───────────────────────────────────────────────────────────

function extractDomain(url) {
  try {
    let u = url.trim();
    if (!u.match(/^https?:\/\//i)) u = 'http://' + u;
    return new URL(u).hostname.toLowerCase();
  } catch {
    const m = url.match(/(?:https?:\/\/)?([^/\s:?#]+)/i);
    return m ? m[1].toLowerCase() : url.toLowerCase();
  }
}

// Levenshtein distance — used for typosquatting detection
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
  return dp[m][n];
}

// ─── Static lookup tables ─────────────────────────────────────────────────────

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.club', '.work', '.buzz', '.icu', '.tk', '.ml', '.ga', '.cf', '.gq',
  '.pw', '.cc', '.su', '.info', '.biz', '.click', '.link', '.site', '.online', '.live',
  '.store', '.stream', '.download', '.racing', '.win', '.bid', '.loan', '.trade',
];

const BRAND_KEYWORDS = [
  'google', 'apple', 'microsoft', 'amazon', 'paypal', 'netflix', 'facebook', 'instagram',
  'bank', 'chase', 'wellsfargo', 'citibank', 'amex', 'visa', 'mastercard', 'venmo',
  'coinbase', 'binance', 'crypto', 'wallet', 'icloud', 'outlook', 'yahoo', 'ebay',
  'dropbox', 'linkedin', 'twitter', 'whatsapp', 'telegram',
];

const PHISHING_PATHS = [
  'login', 'signin', 'sign-in', 'verify', 'verification', 'confirm', 'account',
  'secure', 'update', 'password', 'credential', 'authenticate', 'billing',
  'suspend', 'restore', 'unlock', 'recover', 'reset', 'validate', 'identity', 'ssn',
];

const LEGIT_DOMAINS = new Set([
  'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'apple.com',
  'microsoft.com', 'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com',
  'twitter.com', 'x.com', 'linkedin.com', 'instagram.com', 'netflix.com',
  'paypal.com', 'dropbox.com', 'slack.com', 'zoom.us', 'stripe.com',
]);

const POPULAR_DOMAINS_FOR_TYPO = [
  'paypal.com', 'amazon.com', 'google.com', 'apple.com', 'microsoft.com',
  'facebook.com', 'netflix.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
  'instagram.com', 'linkedin.com', 'twitter.com', 'dropbox.com', 'icloud.com',
];

// ─── Layer 1: Local URL heuristics ────────────────────────────────────────────

function analyzeUrlLocal(urlStr) {
  const factors = [];
  let score = 0;

  let parsed = null;
  let url = urlStr.trim();
  if (!url.match(/^https?:\/\//i)) url = 'http://' + url;
  try { parsed = new URL(url); }
  catch {
    factors.push({ layer: 'Heuristic', label: 'Malformed URL', impact: +30, severity: 'danger', description: 'URL cannot be parsed — likely obfuscated' });
    score += 30;
  }

  const domain = extractDomain(urlStr);

  // Protocol
  if (parsed?.protocol === 'https:') {
    factors.push({ layer: 'Heuristic', label: 'HTTPS Encryption', impact: -5, severity: 'safe', description: 'Connection is encrypted' });
    score = Math.max(0, score - 5);
  } else {
    factors.push({ layer: 'Heuristic', label: 'No HTTPS', impact: +15, severity: 'danger', description: 'Unencrypted HTTP — data can be intercepted' });
    score += 15;
  }

  // Raw IP address
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
    factors.push({ layer: 'Heuristic', label: 'Raw IP Address', impact: +25, severity: 'danger', description: 'IP used instead of domain name — common phishing tactic' });
    score += 25;
  }

  // Suspicious TLD
  const suspTld = SUSPICIOUS_TLDS.find(t => domain.endsWith(t));
  if (suspTld) {
    factors.push({ layer: 'Heuristic', label: `Suspicious TLD (${suspTld})`, impact: +15, severity: 'danger', description: `"${suspTld}" is frequently abused in phishing campaigns` });
    score += 15;
  }

  // Legitimate domain whitelist — short-circuit
  const isLegit = LEGIT_DOMAINS.has(domain) || LEGIT_DOMAINS.has(domain.replace(/^www\./, ''));
  if (isLegit) {
    factors.push({ layer: 'Heuristic', label: 'Trusted Domain', impact: -30, severity: 'safe', description: 'Domain is in the trusted whitelist' });
    score = Math.max(0, score - 30);
    return { score: Math.max(0, Math.min(100, score)), factors };
  }

  // Brand impersonation
  const brand = BRAND_KEYWORDS.find(b => domain.includes(b));
  if (brand) {
    factors.push({ layer: 'Heuristic', label: `Brand Impersonation (${brand})`, impact: +25, severity: 'danger', description: `Domain contains "${brand}" but is not the official domain` });
    score += 25;
  }

  // Typosquatting
  const baseDomain = domain.replace(/^www\./, '').replace(/\.[^.]+$/, '');
  for (const legit of POPULAR_DOMAINS_FOR_TYPO) {
    const legitBase = legit.replace(/\.[^.]+$/, '');
    if (baseDomain !== legitBase && levenshtein(baseDomain, legitBase) <= 2) {
      factors.push({ layer: 'Heuristic', label: `Typosquatting (≈${legit})`, impact: +30, severity: 'danger', description: `Domain is 1–2 characters away from "${legit}" — lookalike attack` });
      score += 30;
      break;
    }
  }

  // Subdomain depth
  const parts = domain.split('.');
  if (parts.length > 3) {
    factors.push({ layer: 'Heuristic', label: `Excessive Subdomains (${parts.length - 2} levels)`, impact: +10, severity: 'warning', description: 'Deep subdomain structure used to obscure the real domain' });
    score += 10;
  }

  // Hyphen count
  const hyphens = (domain.match(/-/g) || []).length;
  if (hyphens >= 3) {
    factors.push({ layer: 'Heuristic', label: `Excessive Hyphens (${hyphens})`, impact: +10, severity: 'warning', description: 'High hyphen count is common in phishing domains' });
    score += 10;
  }

  // Long domain
  if (domain.length > 40) {
    factors.push({ layer: 'Heuristic', label: `Long Domain (${domain.length} chars)`, impact: +10, severity: 'warning', description: 'Unusually long domain may be hiding the real destination' });
    score += 10;
  }

  // Phishing path keywords
  if (parsed) {
    const path = parsed.pathname.toLowerCase() + parsed.search.toLowerCase();
    const kws = PHISHING_PATHS.filter(k => path.includes(k));
    if (kws.length > 0) {
      factors.push({ layer: 'Heuristic', label: `Phishing Path Keywords (${kws.length})`, impact: kws.length * 5, severity: 'warning', description: `Path contains: ${kws.slice(0, 4).join(', ')}` });
      score += kws.length * 5;
    }
    if (parsed.port && !['80', '443', ''].includes(parsed.port)) {
      factors.push({ layer: 'Heuristic', label: `Non-Standard Port (:${parsed.port})`, impact: +10, severity: 'warning', description: 'Legitimate sites rarely use non-standard ports' });
      score += 10;
    }
  }

  // @ symbol
  if (urlStr.includes('@')) {
    factors.push({ layer: 'Heuristic', label: '"@" Symbol in URL', impact: +20, severity: 'danger', description: '"@" can redirect browser to a different domain than displayed' });
    score += 20;
  }

  // URL encoding abuse
  if (/%[0-9a-fA-F]{2}/.test(urlStr)) {
    factors.push({ layer: 'Heuristic', label: 'URL Encoding', impact: +10, severity: 'warning', description: 'Encoded characters may be hiding the true destination' });
    score += 10;
  }

  // Homoglyph / non-Latin characters
  if (/[\u0400-\u04FF\u0250-\u02AF]/.test(domain)) {
    factors.push({ layer: 'Heuristic', label: 'Non-Latin Characters', impact: +30, severity: 'danger', description: 'Cyrillic or other non-Latin scripts used for homoglyph attack' });
    score += 30;
  }

  return { score: Math.max(0, Math.min(100, score)), factors };
}

// ─── Layer 2: RDAP domain-age lookup (free, no key needed) ───────────────────

async function checkDomainAge(domain) {
  try {
    const cleanDomain = domain.replace(/^www\./, '').split(':')[0];
    // Skip IP addresses
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(cleanDomain)) return null;
    const result = await httpsRequest({
      hostname: 'rdap.org',
      path: `/domain/${cleanDomain}`,
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (result.status === 200 && result.data?.events) {
      const reg = result.data.events.find(e => e.eventAction === 'registration');
      if (reg) {
        const regDate   = new Date(reg.eventDate);
        const ageInDays = Math.round((Date.now() - regDate.getTime()) / 86400000);
        return { registered: regDate.toISOString().split('T')[0], ageInDays };
      }
    }
    return null;
  } catch { return null; }
}

// ─── Layer 3: Google Safe Browsing ───────────────────────────────────────────

async function checkGoogleSafeBrowsing(url, apiKey) {
  if (!apiKey) return null;
  try {
    const body = JSON.stringify({
      client: { clientId: 'phishguard', clientVersion: '2.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    });
    const result = await httpsRequest({
      hostname: 'safebrowsing.googleapis.com',
      path: `/v4/threatMatches:find?key=${apiKey}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, body);
    if (result.status === 200) {
      const threats = result.data?.matches || [];
      return {
        source: 'Google Safe Browsing',
        safe: threats.length === 0,
        threats: threats.map(t => t.threatType),
        detail: threats.length === 0
          ? 'Not found in Google threat database'
          : `Flagged: ${threats.map(t => t.threatType).join(', ')}`,
      };
    }
    return null;
  } catch { return null; }
}

// ─── Layer 4: VirusTotal ──────────────────────────────────────────────────────

async function checkVirusTotal(url, apiKey) {
  if (!apiKey) return null;
  try {
    // VirusTotal v3 — URL ID is base64url of the URL
    const urlId = Buffer.from(url).toString('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

    const result = await httpsRequest({
      hostname: 'www.virustotal.com',
      path: `/api/v3/urls/${urlId}`,
      method: 'GET',
      headers: { 'x-apikey': apiKey, Accept: 'application/json' },
    });

    if (result.status === 200 && result.data?.data?.attributes?.last_analysis_stats) {
      const stats = result.data.data.attributes.last_analysis_stats;
      const total = Object.values(stats).reduce((a, b) => a + b, 0);
      return {
        source: 'VirusTotal',
        malicious:  stats.malicious  || 0,
        suspicious: stats.suspicious || 0,
        harmless:   stats.harmless   || 0,
        undetected: stats.undetected || 0,
        totalEngines: total,
        permalink: `https://www.virustotal.com/gui/url/${urlId}`,
        detail: `${stats.malicious}/${total} engines flagged as malicious`,
      };
    }
    return null;
  } catch { return null; }
}

// ─── Email analysis (backend version) ────────────────────────────────────────

function analyzeEmailBackend(content) {
  const factors = [];
  let score = 0;
  const text = content.toLowerCase();

  const urgency = [
    'urgent', 'act now', 'immediate action', 'expires today', 'last chance',
    'account suspended', 'account will be closed', 'unauthorized access',
    'verify immediately', 'action required', 'respond immediately', 'within 24 hours',
  ];
  const foundUrgency = urgency.filter(u => text.includes(u));
  if (foundUrgency.length > 0) {
    const pts = Math.min(30, foundUrgency.length * 8);
    factors.push({ layer: 'Content Analysis', label: `Urgency Tactics (${foundUrgency.length})`, impact: pts, severity: 'danger', description: `"${foundUrgency[0]}"${foundUrgency.length > 1 ? ` +${foundUrgency.length - 1} more` : ''}` });
    score += pts;
  } else {
    factors.push({ layer: 'Content Analysis', label: 'No Urgency Tactics', impact: 0, severity: 'safe', description: 'No pressure language detected' });
  }

  const threatPhrases = [
    'click here to verify', 'update your payment', 'confirm your password',
    'enter your credentials', 'credit card number', 'bitcoin payment',
    'gift card', 'wire transfer', 'you have won', 'claim your prize', 'million dollars',
  ];
  const foundThreats = threatPhrases.filter(p => text.includes(p));
  if (foundThreats.length > 0) {
    const pts = Math.min(35, foundThreats.length * 10);
    factors.push({ layer: 'Content Analysis', label: `Threat Phrases (${foundThreats.length})`, impact: pts, severity: 'danger', description: `"${foundThreats[0]}"` });
    score += pts;
  }

  const personalInfo = ['password', 'ssn', 'social security', 'credit card', 'bank account', 'pin number', 'routing number'];
  const foundPI = personalInfo.filter(k => text.includes(k));
  if (foundPI.length > 0) {
    const pts = Math.min(40, foundPI.length * 12);
    factors.push({ layer: 'Content Analysis', label: 'Requests Personal Info', impact: pts, severity: 'danger', description: `Asks for: ${foundPI.join(', ')}` });
    score += pts;
  }

  const urlPattern = /https?:\/\/[^\s<>"']+/gi;
  const urls = (text.match(urlPattern) || []);
  if (urls.length > 3) {
    factors.push({ layer: 'Content Analysis', label: `Many Embedded URLs (${urls.length})`, impact: +10, severity: 'warning', description: 'Excessive links increase phishing risk' });
    score += 10;
  }

  const suspiciousUrls = urls.filter(u => SUSPICIOUS_TLDS.some(tld => extractDomain(u).endsWith(tld)));
  if (suspiciousUrls.length > 0) {
    factors.push({ layer: 'Content Analysis', label: `Suspicious URLs (${suspiciousUrls.length})`, impact: suspiciousUrls.length * 10, severity: 'danger', description: 'URLs with high-risk TLDs embedded in content' });
    score += suspiciousUrls.length * 10;
  }

  const grammarPatterns = [/\b(kindly|do the needful|revert back)\b/i, /dear\s+(sir|madam|friend|beneficiary)/i, /\b(plese|recieve|transfere)\b/i];
  if (grammarPatterns.some(p => p.test(content))) {
    factors.push({ layer: 'Content Analysis', label: 'Grammar Anomalies', impact: +10, severity: 'warning', description: 'Patterns associated with non-native phishing emails' });
    score += 10;
  }

  const finalScore = Math.max(0, Math.min(100, score));
  return {
    threatLevel: finalScore >= 40 ? 'Dangerous' : finalScore >= 15 ? 'Suspicious' : 'Safe',
    score: finalScore,
    factors,
    externalChecks: [],
    domain: null,
  };
}

// ─── Master analysis function ─────────────────────────────────────────────────

async function analyzeTarget(target, type, apiKeys = {}) {
  if (type === 'Email') return analyzeEmailBackend(target);

  // URL analysis — run local + all external checks in parallel
  const layer1 = analyzeUrlLocal(target);
  const domain = extractDomain(target);

  const [domainAge, gsbResult, vtResult] = await Promise.allSettled([
    checkDomainAge(domain),
    checkGoogleSafeBrowsing(target, apiKeys.safeBrowsing),
    checkVirusTotal(target, apiKeys.virusTotal),
  ]);

  const externalChecks = [];
  let externalAdjustment = 0;
  const factors = [...layer1.factors];

  // Domain age
  const age = domainAge.status === 'fulfilled' ? domainAge.value : null;
  if (age) {
    if (age.ageInDays < 30) {
      factors.push({ layer: 'RDAP Registry', label: `Very New Domain (${age.ageInDays} days old)`, impact: +25, severity: 'danger', description: `Registered ${age.registered} — brand new domains are high-risk` });
      externalAdjustment += 25;
      externalChecks.push({ source: 'RDAP Domain Registry', result: 'THREAT', detail: `Registered ${age.registered} (${age.ageInDays} days ago)` });
    } else if (age.ageInDays < 180) {
      factors.push({ layer: 'RDAP Registry', label: `Young Domain (${age.ageInDays} days old)`, impact: +10, severity: 'warning', description: `Registered ${age.registered}` });
      externalAdjustment += 10;
      externalChecks.push({ source: 'RDAP Domain Registry', result: 'WARNING', detail: `Registered ${age.registered} (${age.ageInDays} days ago)` });
    } else {
      const years = (age.ageInDays / 365).toFixed(1);
      factors.push({ layer: 'RDAP Registry', label: `Established Domain (${years} years old)`, impact: -5, severity: 'safe', description: `Registered ${age.registered}` });
      externalAdjustment -= 5;
      externalChecks.push({ source: 'RDAP Domain Registry', result: 'CLEAN', detail: `Registered ${age.registered} (${age.ageInDays} days ago)` });
    }
  } else {
    externalChecks.push({ source: 'RDAP Domain Registry', result: 'N/A', detail: 'Domain age data unavailable' });
  }

  // Google Safe Browsing
  const gsb = gsbResult.status === 'fulfilled' ? gsbResult.value : null;
  if (gsb) {
    externalChecks.push({ source: 'Google Safe Browsing', result: gsb.safe ? 'CLEAN' : 'THREAT', detail: gsb.detail, link: null });
    if (!gsb.safe) externalAdjustment += 35;
    else externalAdjustment -= 5;
    if (!gsb.safe) {
      factors.push({ layer: 'Google Safe Browsing', label: `GSB Threat Match`, impact: +35, severity: 'danger', description: gsb.detail });
    } else {
      factors.push({ layer: 'Google Safe Browsing', label: 'Not in GSB Blocklist', impact: -5, severity: 'safe', description: 'Google has not flagged this URL' });
    }
  } else {
    externalChecks.push({ source: 'Google Safe Browsing', result: 'N/A', detail: apiKeys.safeBrowsing ? 'API error' : 'No API key configured — add GOOGLE_SAFE_BROWSING_KEY to .env' });
  }

  // VirusTotal
  const vt = vtResult.status === 'fulfilled' ? vtResult.value : null;
  if (vt) {
    externalChecks.push({ source: 'VirusTotal', result: vt.malicious > 0 ? 'THREAT' : 'CLEAN', detail: vt.detail, link: vt.permalink });
    if (vt.malicious >= 5)      externalAdjustment += 40;
    else if (vt.malicious >= 2) externalAdjustment += 25;
    else if (vt.malicious > 0)  externalAdjustment += 15;
    else externalAdjustment -= 5;
    if (vt.malicious > 0) {
      factors.push({ layer: 'VirusTotal', label: `VT Malicious (${vt.malicious}/${vt.totalEngines} engines)`, impact: Math.min(40, vt.malicious * 8), severity: 'danger', description: vt.detail });
    } else {
      factors.push({ layer: 'VirusTotal', label: `VT Clean (0/${vt.totalEngines} engines)`, impact: -5, severity: 'safe', description: 'No AV engine flagged this URL' });
    }
  } else {
    externalChecks.push({ source: 'VirusTotal', result: 'N/A', detail: apiKeys.virusTotal ? 'API error' : 'No API key configured — add VIRUSTOTAL_API_KEY to .env' });
  }

  const finalScore = Math.max(0, Math.min(100, layer1.score + externalAdjustment));
  const threatLevel = finalScore >= 50 ? 'Dangerous' : finalScore >= 20 ? 'Suspicious' : 'Safe';

  return { threatLevel, score: finalScore, factors, externalChecks, domain };
}

module.exports = { analyzeTarget, analyzeUrlLocal, extractDomain };
