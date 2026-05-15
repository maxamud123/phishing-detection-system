'use strict';

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const FIXTURE = path.join(__dirname, 'fixtures', 'phishing-db');

describe('phishingDatabaseService', () => {
  before(() => {
    process.env.PHISHING_DB_CACHE_DIR = FIXTURE;
    fs.mkdirSync(FIXTURE, { recursive: true });
    fs.writeFileSync(path.join(FIXTURE, 'domains.txt'), 'evil-phish.example\n', 'utf8');
    fs.writeFileSync(path.join(FIXTURE, 'links.txt'), 'http://listed-bad.test/path\n', 'utf8');
    fs.writeFileSync(path.join(FIXTURE, 'meta.json'), JSON.stringify({ lastRefresh: new Date().toISOString() }), 'utf8');
    delete require.cache[require.resolve('../config.js')];
    delete require.cache[require.resolve('../services/phishingDatabaseService.js')];
  });

  it('matches domain and URL from local cache', () => {
    const svc = require('../services/phishingDatabaseService');
    svc.reloadCacheFromDisk();

    const domainHit = svc.checkPhishingDatabase('http://evil-phish.example', 'evil-phish.example');
    assert.equal(domainHit.listed, true);
    assert.equal(domainHit.matchType, 'domain');

    const urlHit = svc.checkPhishingDatabase('http://listed-bad.test/path', 'listed-bad.test');
    assert.equal(urlHit.listed, true);

    const miss = svc.checkPhishingDatabase('https://totally-safe-example.com', 'totally-safe-example.com');
    assert.equal(miss.listed, false);
  });
});
