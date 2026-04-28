'use strict';

const auth    = require('../controllers/authController');
const users   = require('../controllers/usersController');
const reports = require('../controllers/reportsController');
const scans   = require('../controllers/scansController');
const admin   = require('../controllers/adminController');
const chat    = require('../controllers/chatController');

function route(req, res) {
  const url    = req.url.split('?')[0];
  const method = req.method;

  // ── Auth ──────────────────────────────────────────────────────────────────
  if (url === '/api/auth/login'       && method === 'POST') return auth.login(req, res);
  if (url === '/api/auth/signup'      && method === 'POST') return auth.signup(req, res);
  if (url === '/api/auth/logout'      && method === 'POST') return auth.logout(req, res);
  if (url === '/api/auth/me'          && method === 'GET')  return auth.me(req, res);
  if (url === '/api/auth/check-setup' && method === 'GET')  return auth.checkSetup(req, res);
  if (url === '/api/auth/password'    && method === 'PUT')  return auth.changePassword(req, res);
  if (url === '/api/auth/profile'     && method === 'PUT')  return auth.updateProfile(req, res);

  // ── Users ─────────────────────────────────────────────────────────────────
  if (url === '/api/users' && method === 'GET')  return users.getUsers(req, res);
  if (url === '/api/users' && method === 'POST') return users.createUser(req, res);
  const usMatch = url.match(/^\/api\/users\/([^/]+)\/status$/);
  const urMatch = url.match(/^\/api\/users\/([^/]+)\/reset-password$/);
  const uMatch  = url.match(/^\/api\/users\/([^/]+)$/);
  if (usMatch && method === 'PUT')    return users.toggleStatus(req, res, usMatch[1]);
  if (urMatch && method === 'PUT')    return users.resetPassword(req, res, urMatch[1]);
  if (uMatch  && method === 'PUT')    return users.updateUser(req, res, uMatch[1]);
  if (uMatch  && method === 'DELETE') return users.deleteUser(req, res, uMatch[1]);

  // ── Reports ───────────────────────────────────────────────────────────────
  if (url === '/api/reports' && method === 'GET')  return reports.getReports(req, res);
  if (url === '/api/reports' && method === 'POST') return reports.createReport(req, res);
  const rMatch = url.match(/^\/api\/reports\/([^/]+)$/);
  if (rMatch && method === 'PUT')    return reports.updateReport(req, res, rMatch[1]);
  if (rMatch && method === 'DELETE') return reports.deleteReport(req, res, rMatch[1]);

  // ── Scans ─────────────────────────────────────────────────────────────────
  if (url === '/api/scans'        && method === 'GET')  return scans.getScans(req, res);
  if (url === '/api/scans'        && method === 'POST') return scans.createScan(req, res);
  if (url === '/api/scan/analyze' && method === 'POST') return scans.analyzeScan(req, res);
  if (url === '/api/scan/bulk'    && method === 'POST') return scans.bulkScan(req, res);
  const sMatch = url.match(/^\/api\/scans\/([^/]+)$/);
  if (sMatch && method === 'DELETE') return scans.deleteScan(req, res, sMatch[1]);

  // ── Admin ─────────────────────────────────────────────────────────────────
  if (url === '/api/audit-logs' && method === 'GET') return admin.getAuditLogs(req, res);
  if (url === '/api/db-stats'   && method === 'GET') return admin.getDbStats(req, res);
  if (url === '/api/sessions'   && method === 'GET') return admin.getActiveSessions(req, res);
  const sessMatch = url.match(/^\/api\/sessions\/([^/]+)$/);
  if (sessMatch && method === 'DELETE') return admin.killSession(req, res, sessMatch[1]);

  // ── AI Chat ───────────────────────────────────────────────────────────────
  if (url === '/api/chat' && method === 'POST') return chat.chat(req, res);

  // ── 404 ───────────────────────────────────────────────────────────────────
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ success: false, error: 'Not found.' }));
}

module.exports = { route };
