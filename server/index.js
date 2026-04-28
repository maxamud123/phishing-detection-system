'use strict';

/**
 * PhishGuard — Backend Entry Point
 * Run:  cd server && npm install && node index.js
 *
 * Architecture:
 *   config.js              — environment variables
 *   db/connection.js       — MongoDB connect + seed
 *   middleware/http.js     — response helpers (jsonOk, jsonError, parseBody)
 *   middleware/auth.js     — requireAuth, checkRateLimit
 *   services/             — audit, email, websocket, crypto
 *   controllers/          — one file per resource
 *   routes/router.js      — URL → controller dispatch
 */

const http = require('http');
const { PORT, CORS_ORIGIN, VIRUSTOTAL_KEY, SAFE_BROWSING_KEY, SMTP_USER, SMTP_TO, DB_NAME } = require('./config');
const { connectDB, getDb } = require('./db/connection');
const { route } = require('./routes/router');
const { initWebSocket } = require('./services/websocketService');
const { isEmailConfigured } = require('./services/emailService');

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  CORS_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  route(req, res);
});

(async () => {
  await connectDB();

  server.listen(PORT, () => {
    const wsActive = initWebSocket(server);

    if (wsActive) {
      console.log(`  ✅ WebSocket server active  (ws://localhost:${PORT})`);
    } else {
      console.log(`  ⚠️  WebSocket disabled — run: cd server && npm install ws`);
    }

    if (!isEmailConfigured()) {
      console.log(`  ⚠️  Email alerts disabled — configure SMTP_* in server/.env`);
    } else {
      console.log(`  ✅ Email alerts enabled  →  ${SMTP_TO}`);
    }

    const db = getDb();
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
