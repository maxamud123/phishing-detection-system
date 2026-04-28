'use strict';

const { extractDomain }           = require('./domainUtils');
const { analyzeUrlLocal }         = require('./layers/urlHeuristics');
const { checkDomainAge }          = require('./layers/domainAge');
const { checkGoogleSafeBrowsing } = require('./layers/safeBrowsing');
const { checkVirusTotal }         = require('./layers/virusTotal');
const { analyzeEmailBackend }     = require('./layers/emailAnalyzer');

async function analyzeTarget(target, type, apiKeys = {}) {
  if (type === 'Email') return analyzeEmailBackend(target);

  const layer1 = analyzeUrlLocal(target);
  const domain = extractDomain(target);

  const [domainAge, gsbResult, vtResult] = await Promise.allSettled([
    checkDomainAge(domain),
    checkGoogleSafeBrowsing(target, apiKeys.safeBrowsing),
    checkVirusTotal(target, apiKeys.virusTotal),
  ]);

  const externalChecks     = [];
  let   externalAdjustment = 0;
  const factors            = [...layer1.factors];

  // Domain age (RDAP)
  const age = domainAge.status === 'fulfilled' ? domainAge.value : null;
  if (age) {
    if (age.ageInDays < 30) {
      factors.push({ layer: 'RDAP Registry', label: `Very New Domain (${age.ageInDays} days old)`, impact: +25, severity: 'danger', description: `Registered ${age.registered} — brand new domains are high-risk` });
      externalAdjustment += 25;
      externalChecks.push({ source: 'RDAP Domain Registry', result: 'THREAT',  detail: `Registered ${age.registered} (${age.ageInDays} days ago)` });
    } else if (age.ageInDays < 180) {
      factors.push({ layer: 'RDAP Registry', label: `Young Domain (${age.ageInDays} days old)`, impact: +10, severity: 'warning', description: `Registered ${age.registered}` });
      externalAdjustment += 10;
      externalChecks.push({ source: 'RDAP Domain Registry', result: 'WARNING', detail: `Registered ${age.registered} (${age.ageInDays} days ago)` });
    } else {
      const years = (age.ageInDays / 365).toFixed(1);
      factors.push({ layer: 'RDAP Registry', label: `Established Domain (${years} years old)`, impact: -5, severity: 'safe', description: `Registered ${age.registered}` });
      externalAdjustment -= 5;
      externalChecks.push({ source: 'RDAP Domain Registry', result: 'CLEAN',   detail: `Registered ${age.registered} (${age.ageInDays} days ago)` });
    }
  } else {
    externalChecks.push({ source: 'RDAP Domain Registry', result: 'N/A', detail: 'Domain age data unavailable' });
  }

  // Google Safe Browsing
  const gsb = gsbResult.status === 'fulfilled' ? gsbResult.value : null;
  if (gsb) {
    externalChecks.push({ source: 'Google Safe Browsing', result: gsb.safe ? 'CLEAN' : 'THREAT', detail: gsb.detail, link: null });
    if (!gsb.safe) {
      externalAdjustment += 35;
      factors.push({ layer: 'Google Safe Browsing', label: 'GSB Threat Match',       impact: +35, severity: 'danger', description: gsb.detail });
    } else {
      externalAdjustment -= 5;
      factors.push({ layer: 'Google Safe Browsing', label: 'Not in GSB Blocklist',   impact:  -5, severity: 'safe',   description: 'Google has not flagged this URL' });
    }
  } else {
    externalChecks.push({ source: 'Google Safe Browsing', result: 'N/A', detail: apiKeys.safeBrowsing ? 'API error' : 'No API key configured — add GOOGLE_SAFE_BROWSING_KEY to .env' });
  }

  // VirusTotal
  const vt = vtResult.status === 'fulfilled' ? vtResult.value : null;
  if (vt) {
    externalChecks.push({ source: 'VirusTotal', result: vt.malicious > 0 ? 'THREAT' : 'CLEAN', detail: vt.detail, link: vt.permalink });
    if      (vt.malicious >= 5) externalAdjustment += 40;
    else if (vt.malicious >= 2) externalAdjustment += 25;
    else if (vt.malicious >  0) externalAdjustment += 15;
    else                        externalAdjustment -= 5;
    if (vt.malicious > 0) {
      factors.push({ layer: 'VirusTotal', label: `VT Malicious (${vt.malicious}/${vt.totalEngines} engines)`, impact: Math.min(40, vt.malicious * 8), severity: 'danger', description: vt.detail });
    } else {
      factors.push({ layer: 'VirusTotal', label: `VT Clean (0/${vt.totalEngines} engines)`, impact: -5, severity: 'safe', description: 'No AV engine flagged this URL' });
    }
  } else {
    externalChecks.push({ source: 'VirusTotal', result: 'N/A', detail: apiKeys.virusTotal ? 'API error' : 'No API key configured — add VIRUSTOTAL_API_KEY to .env' });
  }

  const finalScore  = Math.max(0, Math.min(100, layer1.score + externalAdjustment));
  const threatLevel = finalScore >= 50 ? 'Dangerous' : finalScore >= 20 ? 'Suspicious' : 'Safe';

  return { threatLevel, score: finalScore, factors, externalChecks, domain };
}

module.exports = { analyzeTarget, analyzeUrlLocal, extractDomain };
