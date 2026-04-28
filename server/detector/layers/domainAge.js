'use strict';

const { httpsRequest } = require('../httpHelper');

async function checkDomainAge(domain) {
  try {
    const cleanDomain = domain.replace(/^www\./, '').split(':')[0];
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(cleanDomain)) return null; // skip raw IPs
    const result = await httpsRequest({
      hostname: 'rdap.org',
      path:     `/domain/${cleanDomain}`,
      method:   'GET',
      headers:  { Accept: 'application/json' },
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

module.exports = { checkDomainAge };
