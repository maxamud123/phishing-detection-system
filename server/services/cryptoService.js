'use strict';

const crypto = require('crypto');

function hashPwd(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100_000, 64, 'sha512').toString('hex');
}
function genToken()    { return crypto.randomBytes(32).toString('hex'); }
function genUserId()   { return 'USR-' + crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase(); }
function genReportId() { return 'RPT-' + crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase(); }

module.exports = { hashPwd, genToken, genUserId, genReportId };
