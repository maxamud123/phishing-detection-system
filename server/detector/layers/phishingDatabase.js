'use strict';

const { checkPhishingDatabase, getStatus } = require('../../services/phishingDatabaseService');

function checkPhishingDatabaseLayer(target, domain) {
  const result = checkPhishingDatabase(target, domain);
  const st     = getStatus();
  return { ...result, enabled: st.enabled, counts: { domains: st.domainCount, links: st.linkCount } };
}

module.exports = { checkPhishingDatabaseLayer };
