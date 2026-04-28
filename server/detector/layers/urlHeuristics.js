'use strict';

const { extractDomain, levenshtein } = require('../domainUtils');
const { SUSPICIOUS_TLDS, BRAND_KEYWORDS, PHISHING_PATHS, LEGIT_DOMAINS, POPULAR_DOMAINS_FOR_TYPO } = require('../lookupTables');

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
    const kws  = PHISHING_PATHS.filter(k => path.includes(k));
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
  if (/[Ѐ-ӿɐ-ʯ]/.test(domain)) {
    factors.push({ layer: 'Heuristic', label: 'Non-Latin Characters', impact: +30, severity: 'danger', description: 'Cyrillic or other non-Latin scripts used for homoglyph attack' });
    score += 30;
  }

  return { score: Math.max(0, Math.min(100, score)), factors };
}

module.exports = { analyzeUrlLocal };
