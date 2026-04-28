'use strict';

const fs   = require('fs');
const path = require('path');

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

module.exports = {
  PORT:              parseInt(process.env.PORT || '3001', 10),
  MONGODB_URI:       process.env.MONGODB_URI             || 'mongodb://localhost:27017',
  DB_NAME:           process.env.DB_NAME                 || 'phishguard_pds',
  CORS_ORIGIN:       process.env.CORS_ORIGIN             || 'http://localhost:5173',
  ADMIN_EMAIL:       process.env.ADMIN_EMAIL             || 'admin@phishguard.local',
  ADMIN_PASSWORD:    process.env.ADMIN_PASSWORD          || 'Admin@1234',
  VIRUSTOTAL_KEY:    process.env.VIRUSTOTAL_API_KEY      || '',
  SAFE_BROWSING_KEY: process.env.GOOGLE_SAFE_BROWSING_KEY || '',
  SMTP_HOST:         process.env.SMTP_HOST               || 'smtp.gmail.com',
  SMTP_PORT:         parseInt(process.env.SMTP_PORT || '587', 10),
  SMTP_USER:         process.env.SMTP_USER               || '',
  SMTP_PASS:         process.env.SMTP_PASS               || '',
  SMTP_FROM:         process.env.SMTP_FROM               || '',
  SMTP_TO:           process.env.SMTP_ALERT_TO           || '',
  GROQ_API_KEY:      process.env.GROQ_API_KEY            || '',
  BODY_SIZE_LIMIT:   50_000,
};
