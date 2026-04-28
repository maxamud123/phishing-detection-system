'use strict';

const { extractDomain } = require('../domainUtils');
const { SUSPICIOUS_TLDS } = require('../lookupTables');

function analyzeEmailBackend(content) {
  const factors = [];
  let score = 0;
  const text = content.toLowerCase();

  // Urgency tactics
  const urgencyPhrases = [
    'urgent', 'act now', 'immediate action', 'expires today', 'last chance',
    'account suspended', 'account will be closed', 'unauthorized access',
    'verify immediately', 'action required', 'respond immediately', 'within 24 hours',
  ];
  const foundUrgency = urgencyPhrases.filter(u => text.includes(u));
  if (foundUrgency.length > 0) {
    const pts = Math.min(30, foundUrgency.length * 8);
    factors.push({ layer: 'Content Analysis', label: `Urgency Tactics (${foundUrgency.length})`, impact: pts, severity: 'danger', description: `"${foundUrgency[0]}"${foundUrgency.length > 1 ? ` +${foundUrgency.length - 1} more` : ''}` });
    score += pts;
  } else {
    factors.push({ layer: 'Content Analysis', label: 'No Urgency Tactics', impact: 0, severity: 'safe', description: 'No pressure language detected' });
  }

  // Threat phrases
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

  // Personal info requests
  const personalInfo = ['password', 'ssn', 'social security', 'credit card', 'bank account', 'pin number', 'routing number'];
  const foundPI = personalInfo.filter(k => text.includes(k));
  if (foundPI.length > 0) {
    const pts = Math.min(40, foundPI.length * 12);
    factors.push({ layer: 'Content Analysis', label: 'Requests Personal Info', impact: pts, severity: 'danger', description: `Asks for: ${foundPI.join(', ')}` });
    score += pts;
  }

  // Embedded URLs
  const urls = (text.match(/https?:\/\/[^\s<>"']+/gi) || []);
  if (urls.length > 3) {
    factors.push({ layer: 'Content Analysis', label: `Many Embedded URLs (${urls.length})`, impact: +10, severity: 'warning', description: 'Excessive links increase phishing risk' });
    score += 10;
  }

  // Suspicious URLs in content
  const suspiciousUrls = urls.filter(u => SUSPICIOUS_TLDS.some(tld => extractDomain(u).endsWith(tld)));
  if (suspiciousUrls.length > 0) {
    factors.push({ layer: 'Content Analysis', label: `Suspicious URLs (${suspiciousUrls.length})`, impact: suspiciousUrls.length * 10, severity: 'danger', description: 'URLs with high-risk TLDs embedded in content' });
    score += suspiciousUrls.length * 10;
  }

  // Grammar anomalies
  const grammarPatterns = [
    /\b(kindly|do the needful|revert back)\b/i,
    /dear\s+(sir|madam|friend|beneficiary)/i,
    /\b(plese|recieve|transfere)\b/i,
  ];
  if (grammarPatterns.some(p => p.test(content))) {
    factors.push({ layer: 'Content Analysis', label: 'Grammar Anomalies', impact: +10, severity: 'warning', description: 'Patterns associated with non-native phishing emails' });
    score += 10;
  }

  const finalScore = Math.max(0, Math.min(100, score));
  return {
    threatLevel:    finalScore >= 40 ? 'Dangerous' : finalScore >= 15 ? 'Suspicious' : 'Safe',
    score:          finalScore,
    factors,
    externalChecks: [],
    domain:         null,
  };
}

module.exports = { analyzeEmailBackend };
