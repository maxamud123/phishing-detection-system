'use strict';

const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, SMTP_TO } = require('../config');

let nodemailer = null;
try { nodemailer = require('nodemailer'); } catch { /* nodemailer not installed */ }

async function sendThreatAlert(scan) {
  if (!nodemailer || !SMTP_USER || !SMTP_PASS || !SMTP_TO) return;
  try {
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST, port: SMTP_PORT, secure: false,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
    await transporter.sendMail({
      from:    SMTP_FROM || SMTP_USER,
      to:      SMTP_TO,
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

function isEmailConfigured() {
  return !!(nodemailer && SMTP_USER && SMTP_PASS && SMTP_TO);
}

module.exports = { sendThreatAlert, isEmailConfigured };
