'use strict';

const { BODY_SIZE_LIMIT } = require('../config');

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
    req.on('end',   () => { try { resolve(JSON.parse(body || '{}')); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

function noDb(res) {
  jsonError(res, 503, 'Database not connected. Check server/.env MONGODB_URI.');
}

module.exports = { jsonOk, jsonError, parseBody, noDb };
