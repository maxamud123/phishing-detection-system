'use strict';

const { httpsRequest } = require('../httpHelper');

async function checkGoogleSafeBrowsing(url, apiKey) {
  if (!apiKey) return null;
  try {
    const body = JSON.stringify({
      client: { clientId: 'phishguard', clientVersion: '2.0' },
      threatInfo: {
        threatTypes:      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes:    ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries:    [{ url }],
      },
    });
    const result = await httpsRequest({
      hostname: 'safebrowsing.googleapis.com',
      path:     `/v4/threatMatches:find?key=${apiKey}`,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, body);

    if (result.status === 200) {
      const threats = result.data?.matches || [];
      return {
        source:  'Google Safe Browsing',
        safe:    threats.length === 0,
        threats: threats.map(t => t.threatType),
        detail:  threats.length === 0
          ? 'Not found in Google threat database'
          : `Flagged: ${threats.map(t => t.threatType).join(', ')}`,
      };
    }
    return null;
  } catch { return null; }
}

module.exports = { checkGoogleSafeBrowsing };
