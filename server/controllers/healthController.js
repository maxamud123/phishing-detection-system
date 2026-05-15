'use strict';

const { getDb } = require('../db/connection');
const { jsonOk } = require('../middleware/http');
const { isWebSocketActive } = require('../services/websocketService');
const { isEmailConfigured } = require('../services/emailService');
const { VIRUSTOTAL_KEY, SAFE_BROWSING_KEY, GROQ_API_KEY, DB_NAME } = require('../config');
const { getStatus: getPhishingDbStatus } = require('../services/phishingDatabaseService');

async function health(_req, res) {
  const db = getDb();
  jsonOk(res, {
    status:    db ? 'ok' : 'degraded',
    api:       true,
    db:        !!db,
    dbName:    DB_NAME,
    websocket: isWebSocketActive(),
    email:     isEmailConfigured(),
    virusTotal:     !!VIRUSTOTAL_KEY,
    safeBrowsing:   !!SAFE_BROWSING_KEY,
    chat:           !!GROQ_API_KEY,
    phishingDatabase: (() => {
      const pdb = getPhishingDbStatus();
      return {
        enabled: pdb.enabled,
        loaded:  pdb.loaded,
        domains: pdb.domainCount,
        links:   pdb.linkCount,
        lastRefresh: pdb.lastRefresh,
      };
    })(),
    timestamp: new Date().toISOString(),
  });
}

module.exports = { health };
