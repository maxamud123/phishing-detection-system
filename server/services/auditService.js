'use strict';

const { getDb } = require('../db/connection');

async function audit(action, actor, details, ip = null, resource = null) {
  const db = getDb();
  if (!db) return;
  try {
    await db.collection('audit_logs').insertOne({
      action,
      userId:   actor?.userId || 'SYSTEM',
      userName: actor?.name   || 'System',
      details, ip, resource,
      timestamp: new Date(),
    });
  } catch { /* non-critical */ }
}

module.exports = { audit };
