'use strict';

const { httpsRequest } = require('../httpHelper');

async function checkVirusTotal(url, apiKey) {
  if (!apiKey) return null;
  try {
    const urlId = Buffer.from(url).toString('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

    const result = await httpsRequest({
      hostname: 'www.virustotal.com',
      path:     `/api/v3/urls/${urlId}`,
      method:   'GET',
      headers:  { 'x-apikey': apiKey, Accept: 'application/json' },
    });

    if (result.status === 200 && result.data?.data?.attributes?.last_analysis_stats) {
      const stats = result.data.data.attributes.last_analysis_stats;
      const total = Object.values(stats).reduce((a, b) => a + b, 0);
      return {
        source:       'VirusTotal',
        malicious:    stats.malicious  || 0,
        suspicious:   stats.suspicious || 0,
        harmless:     stats.harmless   || 0,
        undetected:   stats.undetected || 0,
        totalEngines: total,
        permalink:    `https://www.virustotal.com/gui/url/${urlId}`,
        detail:       `${stats.malicious}/${total} engines flagged as malicious`,
      };
    }
    return null;
  } catch { return null; }
}

module.exports = { checkVirusTotal };
