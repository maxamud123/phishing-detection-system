/**
 * Phishing Detection System — Backend Server
 * Node.js + MongoDB REST API
 * Port: 3001  (Vite dev server proxies /api → http://localhost:3001)
 *
 * Run:  cd server && npm install && node index.js
 */

'use strict';

const http   = require('http');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// ─── Optional deps (graceful degrade if not installed) ───────────────────────
let WebSocketServer = null;
let nodemailer      = null;
try { WebSocketServer = require('ws').WebSocketServer; } catch { /* ws not installed */ }
try { nodemailer = require('nodemailer'); }              catch { /* nodemailer not installed */ }

// ─── Detector engine ─────────────────────────────────────────────────────────
const { analyzeTarget } = require('./detector');

// ─── Rate-limit store (login) ─────────────────────────────────────────────────
const loginAttempts = new Map(); // ip → { count, resetAt }
const MAX_LOGIN_ATTEMPTS = 10;
const RATE_WINDOW_MS     = 15 * 60 * 1000; // 15 min
const BODY_SIZE_LIMIT    = 50_000; // bytes

function checkRateLimit(ip) {
  const now = Date.now();
  let entry = loginAttempts.get(ip);
  if (!entry || entry.resetAt <= now) {
    entry = { count: 1, resetAt: now + RATE_WINDOW_MS };
    loginAttempts.set(ip, entry);
    return true;
  }
  if (entry.count >= MAX_LOGIN_ATTEMPTS) return false;
  entry.count++;
  return true;
}
// Prune old entries every 30 min to avoid memory leak
setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of loginAttempts) if (e.resetAt <= now) loginAttempts.delete(ip);
}, 30 * 60 * 1000);

// ─── Load .env ────────────────────────────────────────────────────────────────
(function loadEnv() {
  try {
    const lines = fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n');
    for (const line of lines) {
      const t = line.trim();
      if (!t || t.startsWith('#')) continue;
      const eq = t.indexOf('=');
      if (eq < 0) continue;
      const k = t.slice(0, eq).trim();
      const v = t.slice(eq + 1).trim();
      if (k && !process.env[k]) process.env[k] = v;
    }
  } catch { /* no .env */ }
})();

const PORT        = parseInt(process.env.PORT  || '3001', 10);
const MONGODB_URI = process.env.MONGODB_URI    || 'mongodb://localhost:27017';
const DB_NAME     = process.env.DB_NAME        || 'phishguard_pds';
const CORS_ORIGIN = process.env.CORS_ORIGIN    || 'http://localhost:5173';

// ─── Admin credentials (set in server/.env) ───────────────────────────────────
const ADMIN_EMAIL    = process.env.ADMIN_EMAIL    || 'admin@phishguard.local';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin@1234';

// ─── Threat Intelligence API keys (optional) ─────────────────────────────────
const VIRUSTOTAL_KEY    = process.env.VIRUSTOTAL_API_KEY        || '';
const SAFE_BROWSING_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY  || '';

// ─── Email alert config (optional — requires nodemailer) ─────────────────────
const SMTP_FROM  = process.env.SMTP_FROM  || '';
const SMTP_TO    = process.env.SMTP_ALERT_TO  || '';
const SMTP_HOST  = process.env.SMTP_HOST  || 'smtp.gmail.com';
const SMTP_PORT  = parseInt(process.env.SMTP_PORT || '587', 10);
const SMTP_USER  = process.env.SMTP_USER  || '';
const SMTP_PASS  = process.env.SMTP_PASS  || '';

// ─── MongoDB Setup ────────────────────────────────────────────────────────────
let MongoClient, ObjectId;
try {
  const m = require('mongodb');
  MongoClient = m.MongoClient;
  ObjectId    = m.ObjectId;
} catch {
  console.error('\n  ❌ mongodb not installed!\n  Run:  cd server && npm install\n');
}

let db      = null;
let mClient = null;

async function connectDB() {
  if (db) return db;
  if (!MongoClient) return null;
  try {
    mClient = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    await mClient.connect();
    db = mClient.db(DB_NAME);
    console.log(`  ✅ MongoDB connected  →  ${DB_NAME}`);
    await setupIndexes();
    await seedDefaultData();
    return db;
  } catch (err) {
    console.warn(`  ⚠️  MongoDB unavailable: ${err.message}`);
    console.warn('  Check MONGODB_URI in server/.env\n');
    return null;
  }
}

async function setupIndexes() {
  await db.collection('users').createIndex({ email: 1 }, { unique: true });
  await db.collection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  await db.collection('sessions').createIndex({ token: 1 });
}

async function seedDefaultData() {
  const col = db.collection('users');

  // Remove any Admin accounts that are not the designated admin email
  await col.deleteMany({ role: 'Admin', email: { $ne: ADMIN_EMAIL.toLowerCase() } });

  // Create the admin account if it doesn't exist yet
  const exists = await col.findOne({ email: ADMIN_EMAIL.toLowerCase() });
  if (!exists) {
    const salt         = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPwd(ADMIN_PASSWORD, salt);
    await col.insertOne({
      userId: 'USR-001', name: 'Admin', email: ADMIN_EMAIL.toLowerCase(),
      passwordHash, salt, role: 'Admin', createdAt: new Date(),
    });
  }

  // Ensure the admin email always has Admin role (in case it was changed)
  await col.updateOne({ email: ADMIN_EMAIL.toLowerCase() }, { $set: { role: 'Admin' } });

  console.log(`  ✅ Admin account ready  →  ${ADMIN_EMAIL}`);
}

// ─── Crypto Helpers ───────────────────────────────────────────────────────────
function hashPwd(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100_000, 64, 'sha512').toString('hex');
}
function genToken()    { return crypto.randomBytes(32).toString('hex'); }
function genUserId()   { return 'USR-' + crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase(); }
function genReportId() { return 'RPT-' + crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase(); }

// ─── HTTP Helpers ─────────────────────────────────────────────────────────────
function jsonOk(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ success: true, ...data }));
}
function jsonError(res, status, message) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ success: false, error: message }));
}
function parseBody(req) {
  return new Promise((resolve, reject) => {
    const contentLen = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLen > BODY_SIZE_LIMIT) { resolve({ __tooLarge: true }); return; }
    let body = '';
    let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > BODY_SIZE_LIMIT) { resolve({ __tooLarge: true }); return; }
      body += c;
    });
    req.on('end',  () => { try { resolve(JSON.parse(body || '{}')); } catch { resolve({}); } });
    req.on('error', reject);
  });
}
async function requireAuth(req, res) {
  if (!db) { jsonError(res, 503, 'Database not connected.'); return null; }
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) { jsonError(res, 401, 'Authentication required.'); return null; }
  const session = await db.collection('sessions').findOne({ token, expiresAt: { $gt: new Date() } });
  if (!session) { jsonError(res, 401, 'Session expired. Please log in again.'); return null; }
  return { userId: session.userId, name: session.name, email: session.email, role: session.role };
}
function noDb(res) {
  jsonError(res, 503, 'Database not connected. Check server/.env MONGODB_URI.');
}

// ─── Audit Helper ─────────────────────────────────────────────────────────────
async function audit(action, actor, details) {
  if (!db) return;
  try {
    await db.collection('audit_logs').insertOne({
      action, userId: actor?.userId || 'SYSTEM', userName: actor?.name || 'System',
      details, timestamp: new Date(),
    });
  } catch { /* non-critical */ }
}

// ─── WebSocket broadcast helper ───────────────────────────────────────────────
let wss = null;
function broadcastAlert(payload) {
  if (!wss) return;
  const msg = JSON.stringify(payload);
  wss.clients.forEach(client => {
    if (client.readyState === 1) client.send(msg); // 1 = OPEN
  });
}

// ─── Email alert helper ───────────────────────────────────────────────────────
async function sendThreatAlert(scan) {
  if (!nodemailer || !SMTP_USER || !SMTP_PASS || !SMTP_TO) return;
  try {
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST, port: SMTP_PORT, secure: false,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
    await transporter.sendMail({
      from: SMTP_FROM || SMTP_USER,
      to:   SMTP_TO,
      subject: `🚨 PhishGuard Alert: Dangerous threat detected — ${scan.target.slice(0, 60)}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0e1a;color:#e2e8f0;padding:24px;border-radius:12px">
          <h2 style="color:#ef4444;margin-top:0">⚠️ High-Risk Threat Detected</h2>
          <table style="width:100%;border-collapse:collapse;font-size:14px">
            <tr><td style="padding:8px;color:#6b7f9e">Scan ID</td><td style="padding:8px">${scan.id}</td></tr>
            <tr><td style="padding:8px;color:#6b7f9e">Target</td><td style="padding:8px;word-break:break-all">${scan.target}</td></tr>
            <tr><td style="padding:8px;color:#6b7f9e">Type</td><td style="padding:8px">${scan.type}</td></tr>
            <tr><td style="padding:8px;color:#6b7f9e">Risk Score</td><td style="padding:8px;color:#ef4444;font-weight:bold">${scan.riskScore}/100</td></tr>
            <tr><td style="padding:8px;color:#6b7f9e">Timestamp</td><td style="padding:8px">${scan.timestamp}</td></tr>
          </table>
          <p style="color:#6b7f9e;font-size:12px;margin-top:16px">
            This alert was generated automatically by PhishGuard Threat Detection Platform.
          </p>
        </div>`,
    });
  } catch (err) {
    console.warn('  ⚠️  Email alert failed:', err.message);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// POST /api/auth/login
async function authLogin(req, res) {
  if (!db) return noDb(res);
  const ip = req.socket.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) return jsonError(res, 429, 'Too many login attempts. Try again in 15 minutes.');
  const body = await parseBody(req);
  if (body.__tooLarge) return jsonError(res, 413, 'Request too large.');
  const { email, password } = body;
  if (!email || !password) return jsonError(res, 400, 'Email and password required.');

  const user = await db.collection('users').findOne({ email: email.toLowerCase().trim() });
  if (!user) return jsonError(res, 401, 'No account found with that email.');
  if (hashPwd(password, user.salt) !== user.passwordHash)
    return jsonError(res, 401, 'Incorrect password.');

  const token = genToken();
  await db.collection('sessions').insertOne({
    token, userId: user.userId, name: user.name, email: user.email, role: user.role,
    createdAt: new Date(), expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
  });
  await db.collection('users').updateOne({ _id: user._id }, { $set: { lastLogin: new Date() } });
  await audit('LOGIN', { userId: user.userId, name: user.name }, `Logged in`);

  const { passwordHash, salt, _id, ...safe } = user;
  jsonOk(res, { token, user: safe });
}

// POST /api/auth/signup
async function authSignup(req, res) {
  if (!db) return noDb(res);
  const body = await parseBody(req);
  if (body.__tooLarge) return jsonError(res, 413, 'Request too large.');
  const { name, email, password, confirmPassword } = body;

  if (!name || !email || !password) return jsonError(res, 400, 'Name, email, and password are required.');
  if (password !== confirmPassword)  return jsonError(res, 400, 'Passwords do not match.');
  if (password.length < 6)           return jsonError(res, 400, 'Password must be at least 6 characters.');

  const col = db.collection('users');

  const exists = await col.findOne({ email: email.toLowerCase().trim() });
  if (exists) return jsonError(res, 400, 'An account with this email already exists.');

  const salt         = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPwd(password, salt);
  const userId       = genUserId();

  const newUser = { userId, name: name.trim(), email: email.toLowerCase().trim(),
    passwordHash, salt, role: 'User', createdAt: new Date() };
  await col.insertOne(newUser);
  await audit('SIGNUP', { userId, name: name.trim() }, `New user signed up: "${name}"`);

  const { passwordHash: ph, salt: s, _id, ...safe } = newUser;
  jsonOk(res, { user: safe, message: 'Account created successfully.' }, 201);
}

// POST /api/auth/logout
async function authLogout(req, res) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '');
  if (db && token) await db.collection('sessions').deleteOne({ token });
  jsonOk(res, { message: 'Logged out.' });
}

// GET /api/auth/me
async function authMe(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  jsonOk(res, { user });
}

// GET /api/auth/check-setup
async function authCheckSetup(req, res) {
  if (!db) return jsonOk(res, { needsSetup: false, dbConnected: false });
  const count = await db.collection('users').countDocuments();
  jsonOk(res, { needsSetup: count === 0, dbConnected: true });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  USERS ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/users
async function getUsers(req, res) {
  if (!db) return noDb(res);
  const actor = await requireAuth(req, res);
  if (!actor) return;
  if (actor.role !== 'Admin') return jsonError(res, 403, 'Admin only.');
  const users = await db.collection('users').find({}, { projection: { passwordHash: 0, salt: 0 } }).sort({ createdAt: 1 }).toArray();
  jsonOk(res, { data: users });
}

// POST /api/users (admin create user)
async function createUser(req, res) {
  if (!db) return noDb(res);
  const actor = await requireAuth(req, res);
  if (!actor) return;
  if (actor.role !== 'Admin') return jsonError(res, 403, 'Admin only.');

  const { name, email, password } = await parseBody(req);
  if (!name || !email || !password) return jsonError(res, 400, 'Name, email, and password required.');

  const exists = await db.collection('users').findOne({ email: email.toLowerCase() });
  if (exists) return jsonError(res, 400, 'Email already in use.');

  const salt         = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPwd(password, salt);
  const userId       = genUserId();
  const assignedRole = 'User'; // only one Admin (the first account) — all new accounts are User

  const newUser = { userId, name: name.trim(), email: email.toLowerCase(),
    passwordHash, salt, role: assignedRole, createdAt: new Date() };
  await db.collection('users').insertOne(newUser);
  await audit('CREATE_USER', actor, `Created "${name}" (${assignedRole})`);

  const { passwordHash: ph, salt: s, _id, ...safe } = newUser;
  jsonOk(res, { user: safe }, 201);
}

// PUT /api/users/:id
async function updateUser(req, res, userId) {
  if (!db) return noDb(res);
  const actor = await requireAuth(req, res);
  if (!actor) return;
  if (actor.role !== 'Admin') return jsonError(res, 403, 'Admin only.');

  const body   = await parseBody(req);
  const update = { updatedAt: new Date() };
  if (body.name)  update.name  = body.name.trim();
  if (body.email) update.email = body.email.toLowerCase().trim();
  // role is not updatable — only the original Admin account holds that role
  if (body.password) {
    update.salt         = crypto.randomBytes(16).toString('hex');
    update.passwordHash = hashPwd(body.password, update.salt);
  }

  const result = await db.collection('users').findOneAndUpdate(
    { userId }, { $set: update }, { returnDocument: 'after', projection: { passwordHash: 0, salt: 0 } }
  );
  if (!result) return jsonError(res, 404, 'User not found.');
  await audit('UPDATE_USER', actor, `Updated user "${userId}"`);
  jsonOk(res, { user: result });
}

// DELETE /api/users/:id
async function deleteUser(req, res, userId) {
  if (!db) return noDb(res);
  const actor = await requireAuth(req, res);
  if (!actor) return;
  if (actor.role !== 'Admin') return jsonError(res, 403, 'Admin only.');
  if (userId === actor.userId) return jsonError(res, 400, 'Cannot delete your own account.');

  const result = await db.collection('users').deleteOne({ userId });
  if (result.deletedCount === 0) return jsonError(res, 404, 'User not found.');
  await db.collection('sessions').deleteMany({ userId });
  await audit('DELETE_USER', actor, `Deleted user "${userId}"`);
  jsonOk(res, { message: 'User deleted.' });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  REPORTS ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/reports
async function getReports(req, res) {
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;
  const reports = await db.collection('reports').find({}).sort({ createdAt: -1 }).toArray();
  jsonOk(res, { data: reports });
}

// POST /api/reports
async function createReport(req, res) {
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;

  const body   = await parseBody(req);
  const report = {
    id:          body.id          || genReportId(),
    reporter:    body.reporter    || user.name,
    type:        body.type        || 'URL',
    target:      body.target      || '',
    riskScore:   Number(body.riskScore) || 0,
    status:      body.status      || 'Pending',
    description: body.description || body.desc || '',
    timestamp:   body.timestamp   || new Date().toISOString().slice(0, 16).replace('T', ' '),
    createdBy:   user.userId,
    createdAt:   new Date(),
  };
  await db.collection('reports').insertOne(report);
  await audit('CREATE_REPORT', user, `Filed report ${report.id}`);
  jsonOk(res, { report }, 201);
}

// PUT /api/reports/:id
async function updateReport(req, res, reportId) {
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;

  const body   = await parseBody(req);
  const update = { updatedAt: new Date(), updatedBy: user.userId };
  if (body.status)      update.status      = body.status;
  if (body.description) update.description = body.description;
  if (body.riskScore !== undefined) update.riskScore = Number(body.riskScore);

  const result = await db.collection('reports').findOneAndUpdate(
    { id: reportId }, { $set: update }, { returnDocument: 'after' }
  );
  if (!result) return jsonError(res, 404, 'Report not found.');
  await audit('UPDATE_REPORT', user, `Updated ${reportId} → ${body.status || 'edited'}`);
  jsonOk(res, { report: result });
}

// DELETE /api/reports/:id
async function deleteReport(req, res, reportId) {
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;
  const result = await db.collection('reports').deleteOne({ id: reportId });
  if (result.deletedCount === 0) return jsonError(res, 404, 'Report not found.');
  await audit('DELETE_REPORT', user, `Deleted ${reportId}`);
  jsonOk(res, { message: 'Report deleted.' });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SCANS ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// DELETE /api/scans/:id
async function deleteScan(req, res, scanId) {
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;
  const result = await db.collection('scans').deleteOne({ id: scanId });
  if (result.deletedCount === 0) return jsonError(res, 404, 'Scan not found.');
  await audit('DELETE_SCAN', user, `Deleted scan ${scanId}`);
  jsonOk(res, { message: 'Scan deleted.' });
}

// GET /api/scans
async function getScans(req, res) {
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;
  const scans = await db.collection('scans').find({}).sort({ createdAt: -1 }).limit(500).toArray();
  jsonOk(res, { data: scans });
}

// POST /api/scans
async function createScan(req, res) {
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;

  const body = await parseBody(req);
  const scan = {
    id:         body.id     || 'SCN-' + Date.now().toString(36).toUpperCase(),
    target:     body.target || '',
    type:       body.type   || 'URL',
    result:     body.result || 'Unknown',
    riskScore:  Number(body.riskScore || body.score) || 0,
    aiPowered:  body.aiPowered || false,
    scannedBy:  user.userId,
    timestamp:  body.timestamp || new Date().toISOString().slice(0, 16).replace('T', ' '),
    createdAt:  new Date(),
  };
  await db.collection('scans').insertOne(scan);
  jsonOk(res, { scan }, 201);
}

// POST /api/scan/analyze — multi-layer intelligent scan
async function scanAnalyze(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const body = await parseBody(req);
  if (body.__tooLarge) return jsonError(res, 413, 'Request too large.');

  const { target, type = 'URL' } = body;
  if (!target || !target.trim()) return jsonError(res, 400, 'Target is required.');

  const analysis = await analyzeTarget(target.trim(), type, {
    virusTotal:  VIRUSTOTAL_KEY,
    safeBrowsing: SAFE_BROWSING_KEY,
  });

  const scanId = 'SCN-' + Date.now().toString(36).toUpperCase();
  const scan = {
    id:         scanId,
    target:     target.trim(),
    type,
    result:     analysis.threatLevel,
    riskScore:  analysis.score,
    factors:    analysis.factors,
    externalChecks: analysis.externalChecks,
    aiPowered:  true,
    scannedBy:  user.userId,
    timestamp:  new Date().toISOString().slice(0, 16).replace('T', ' '),
    createdAt:  new Date(),
  };

  if (db) await db.collection('scans').insertOne(scan);

  // Real-time broadcast
  if (analysis.threatLevel === 'Dangerous') {
    broadcastAlert({ type: 'THREAT_DETECTED', scan: { id: scan.id, target: scan.target, riskScore: scan.riskScore, timestamp: scan.timestamp } });
    await sendThreatAlert(scan);
  }

  jsonOk(res, { scan, analysis });
}

// POST /api/scan/bulk — scan multiple targets
async function scanBulk(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const body = await parseBody(req);
  if (body.__tooLarge) return jsonError(res, 413, 'Request too large.');

  const { targets, type = 'URL' } = body;
  if (!Array.isArray(targets) || targets.length === 0)
    return jsonError(res, 400, 'targets must be a non-empty array.');
  if (targets.length > 50)
    return jsonError(res, 400, 'Maximum 50 targets per bulk scan.');

  const results = [];
  for (const target of targets) {
    if (!target || typeof target !== 'string') continue;
    try {
      const analysis = await analyzeTarget(target.trim(), type, {
        virusTotal:  VIRUSTOTAL_KEY,
        safeBrowsing: SAFE_BROWSING_KEY,
      });
      const scan = {
        id:        'SCN-' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2, 5).toUpperCase(),
        target:    target.trim(), type,
        result:    analysis.threatLevel,
        riskScore: analysis.score,
        factors:   analysis.factors,
        externalChecks: analysis.externalChecks,
        aiPowered: true,
        scannedBy: user.userId,
        timestamp: new Date().toISOString().slice(0, 16).replace('T', ' '),
        createdAt: new Date(),
      };
      if (db) await db.collection('scans').insertOne(scan);
      if (analysis.threatLevel === 'Dangerous') {
        broadcastAlert({ type: 'THREAT_DETECTED', scan: { id: scan.id, target: scan.target, riskScore: scan.riskScore, timestamp: scan.timestamp } });
      }
      results.push({ target: target.trim(), ...analysis, scanId: scan.id });
    } catch (err) {
      results.push({ target: target.trim(), error: err.message });
    }
  }

  jsonOk(res, { results, total: results.length });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AUDIT + STATS
// ═══════════════════════════════════════════════════════════════════════════════

async function getAuditLogs(req, res) {
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;
  if (user.role !== 'Admin') return jsonError(res, 403, 'Admin only.');
  const logs = await db.collection('audit_logs').find({}).sort({ timestamp: -1 }).limit(200).toArray();
  jsonOk(res, { data: logs });
}

async function getDbStats(req, res) {
  if (!db) return jsonOk(res, { connected: false });
  const user = await requireAuth(req, res);
  if (!user) return;
  if (user.role !== 'Admin') return jsonError(res, 403, 'Admin only.');

  const [users, reports, scans, logs] = await Promise.all([
    db.collection('users').countDocuments(),
    db.collection('reports').countDocuments(),
    db.collection('scans').countDocuments(),
    db.collection('audit_logs').countDocuments(),
  ]);
  jsonOk(res, {
    connected: true,
    dbName: DB_NAME,
    uri: MONGODB_URI.replace(/:\/\/[^@]+@/, '://***@'),
    collections: { users, reports, scans, audit_logs: logs },
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ROUTER
// ═══════════════════════════════════════════════════════════════════════════════

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  CORS_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url    = req.url.split('?')[0];
  const method = req.method;

  // ── Auth ──
  if (url === '/api/auth/login'       && method === 'POST') return authLogin(req, res);
  if (url === '/api/auth/signup'      && method === 'POST') return authSignup(req, res);
  if (url === '/api/auth/logout'      && method === 'POST') return authLogout(req, res);
  if (url === '/api/auth/me'          && method === 'GET')  return authMe(req, res);
  if (url === '/api/auth/check-setup' && method === 'GET')  return authCheckSetup(req, res);

  // ── Users ──
  if (url === '/api/users' && method === 'GET')  return getUsers(req, res);
  if (url === '/api/users' && method === 'POST') return createUser(req, res);
  const uMatch = url.match(/^\/api\/users\/([^/]+)$/);
  if (uMatch && method === 'PUT')    return updateUser(req, res, uMatch[1]);
  if (uMatch && method === 'DELETE') return deleteUser(req, res, uMatch[1]);

  // ── Reports ──
  if (url === '/api/reports' && method === 'GET')  return getReports(req, res);
  if (url === '/api/reports' && method === 'POST') return createReport(req, res);
  const rMatch = url.match(/^\/api\/reports\/([^/]+)$/);
  if (rMatch && method === 'PUT')    return updateReport(req, res, rMatch[1]);
  if (rMatch && method === 'DELETE') return deleteReport(req, res, rMatch[1]);

  // ── Scans ──
  if (url === '/api/scans'          && method === 'GET')  return getScans(req, res);
  if (url === '/api/scans'          && method === 'POST') return createScan(req, res);
  const sMatch = url.match(/^\/api\/scans\/([^/]+)$/);
  if (sMatch && method === 'DELETE') return deleteScan(req, res, sMatch[1]);
  if (url === '/api/scan/analyze'   && method === 'POST') return scanAnalyze(req, res);
  if (url === '/api/scan/bulk'      && method === 'POST') return scanBulk(req, res);

  // ── Audit & Stats ──
  if (url === '/api/audit-logs' && method === 'GET') return getAuditLogs(req, res);
  if (url === '/api/db-stats'   && method === 'GET') return getDbStats(req, res);

  // ── Unknown ──
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ success: false, error: 'Not found.' }));
});

// ─── Start ────────────────────────────────────────────────────────────────────
(async () => {
  await connectDB();
  server.listen(PORT, () => {
    // WebSocket server — attach to same HTTP server
    if (WebSocketServer) {
      wss = new WebSocketServer({ server });
      wss.on('connection', ws => {
        ws.on('error', () => { /* ignore */ });
      });
      console.log(`  ✅ WebSocket server active  (ws://localhost:${PORT})`);
    } else {
      console.log(`  ⚠️  WebSocket disabled — run: cd server && npm install ws`);
    }

    if (!nodemailer) {
      console.log(`  ⚠️  Email alerts disabled — run: cd server && npm install nodemailer`);
    } else if (!SMTP_USER) {
      console.log(`  ⚠️  Email alerts disabled — configure SMTP_USER/SMTP_PASS in server/.env`);
    } else {
      console.log(`  ✅ Email alerts enabled  →  ${SMTP_TO}`);
    }

    console.log(`\n  ┌──────────────────────────────────────────────────────┐`);
    console.log(`  │  🛡  PhishGuard — Multi-Layer Detection Backend       │`);
    console.log(`  │  http://localhost:${PORT}  (API + WebSocket)              │`);
    console.log(`  │  MongoDB: ${db ? '✅ Connected  →  ' + DB_NAME : '❌ Not connected (check .env)'}     │`);
    console.log(`  ├──────────────────────────────────────────────────────┤`);
    console.log(`  │  POST  /api/auth/login       signup / logout         │`);
    console.log(`  │  GET   /api/users            POST / PUT / DELETE     │`);
    console.log(`  │  GET   /api/reports          POST / PUT / DELETE     │`);
    console.log(`  │  GET   /api/scans            POST                    │`);
    console.log(`  │  POST  /api/scan/analyze  ← multi-layer AI scan      │`);
    console.log(`  │  POST  /api/scan/bulk     ← bulk scan (up to 50)     │`);
    console.log(`  │  GET   /api/audit-logs       /api/db-stats           │`);
    console.log(`  │  VirusTotal:     ${VIRUSTOTAL_KEY    ? '✅ key loaded' : '⚠️  no key (optional)'}                │`);
    console.log(`  │  Safe Browsing:  ${SAFE_BROWSING_KEY ? '✅ key loaded' : '⚠️  no key (optional)'}                │`);
    console.log(`  └──────────────────────────────────────────────────────┘\n`);
    console.log(`  Frontend (Vite): run  npm run dev  in the root folder\n`);
  });
})();
