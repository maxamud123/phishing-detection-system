'use strict';

const { getDb } = require('../db/connection');
const { jsonError } = require('./http');

const loginAttempts    = new Map();
const MAX_ATTEMPTS     = 10;
const RATE_WINDOW_MS   = 15 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of loginAttempts) if (e.resetAt <= now) loginAttempts.delete(ip);
}, 30 * 60 * 1000);

function checkRateLimit(ip) {
  const now = Date.now();
  let entry = loginAttempts.get(ip);
  if (!entry || entry.resetAt <= now) {
    entry = { count: 1, resetAt: now + RATE_WINDOW_MS };
    loginAttempts.set(ip, entry);
    return true;
  }
  if (entry.count >= MAX_ATTEMPTS) return false;
  entry.count++;
  return true;
}

async function requireAuth(req, res) {
  const db = getDb();
  if (!db) { jsonError(res, 503, 'Database not connected.'); return null; }
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) { jsonError(res, 401, 'Authentication required.'); return null; }
  const session = await db.collection('sessions').findOne({ token, expiresAt: { $gt: new Date() } });
  if (!session) { jsonError(res, 401, 'Session expired. Please log in again.'); return null; }
  const user = await db.collection('users').findOne({ userId: session.userId }, { projection: { disabled: 1 } });
  if (user?.disabled) { jsonError(res, 403, 'Account disabled.'); return null; }
  return { userId: session.userId, name: session.name, email: session.email, role: session.role };
}

module.exports = { requireAuth, checkRateLimit };
