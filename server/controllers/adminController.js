'use strict';

const { getDb, getObjectId } = require('../db/connection');
const { DB_NAME, MONGODB_URI } = require('../config');
const { jsonOk, jsonError, noDb } = require('../middleware/http');
const { requireAuth } = require('../middleware/auth');
const { audit } = require('../services/auditService');

async function getAuditLogs(req, res) {
  const db = getDb();
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;
  if (user.role !== 'Admin') return jsonError(res, 403, 'Admin only.');

  const logs = await db.collection('audit_logs')
    .find({}).sort({ timestamp: -1 }).limit(200).toArray();
  jsonOk(res, { data: logs });
}

async function getDbStats(req, res) {
  const db = getDb();
  if (!db) return jsonOk(res, { connected: false });
  const user = await requireAuth(req, res);
  if (!user) return;
  if (user.role !== 'Admin') return jsonError(res, 403, 'Admin only.');

  const now = new Date();
  const [users, reports, scans, logs, activeSessions] = await Promise.all([
    db.collection('users').countDocuments(),
    db.collection('reports').countDocuments(),
    db.collection('scans').countDocuments(),
    db.collection('audit_logs').countDocuments(),
    db.collection('sessions').countDocuments({ expiresAt: { $gt: now } }),
  ]);
  jsonOk(res, {
    connected: true,
    dbName: DB_NAME,
    uri: MONGODB_URI.replace(/:\/\/[^@]+@/, '://***@'),
    collections: { users, reports, scans, audit_logs: logs, activeSessions },
  });
}

async function getActiveSessions(req, res) {
  const db = getDb();
  if (!db) return noDb(res);
  const actor = await requireAuth(req, res);
  if (!actor) return;
  if (actor.role !== 'Admin') return jsonError(res, 403, 'Admin only.');

  const sessions = await db.collection('sessions')
    .find({ expiresAt: { $gt: new Date() } })
    .sort({ createdAt: -1 })
    .project({ token: 0 })
    .toArray();
  jsonOk(res, { data: sessions });
}

async function killSession(req, res, sessionId) {
  const db       = getDb();
  const ObjectId = getObjectId();
  if (!db) return noDb(res);
  const actor = await requireAuth(req, res);
  if (!actor) return;
  if (actor.role !== 'Admin') return jsonError(res, 403, 'Admin only.');

  let oid;
  try { oid = new ObjectId(sessionId); } catch { return jsonError(res, 400, 'Invalid session ID.'); }
  const result = await db.collection('sessions').deleteOne({ _id: oid });
  if (result.deletedCount === 0) return jsonError(res, 404, 'Session not found or already expired.');
  await audit('KILL_SESSION', actor, `Killed session ${sessionId}`, null, 'session');
  jsonOk(res, { message: 'Session terminated.' });
}

module.exports = { getAuditLogs, getDbStats, getActiveSessions, killSession };
