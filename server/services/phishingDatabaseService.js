'use strict';

/**
 * Phishing.Database community feed integration
 * @see https://github.com/Phishing-Database
 * @see https://phish.co.za/latest/
 */

const fs   = require('fs');
const path = require('path');
const https = require('https');
const {
  PHISHING_DB_ENABLED,
  PHISHING_DB_DOMAINS_URL,
  PHISHING_DB_LINKS_URL,
  PHISHING_DB_REFRESH_HOURS,
  PHISHING_DB_CACHE_DIR,
} = require('../config');

const CACHE_DIR = PHISHING_DB_CACHE_DIR;
const META_FILE = path.join(CACHE_DIR, 'meta.json');

/** @type {Set<string>} */
let domainSet = new Set();
/** @type {Set<string>} */
let linkSet   = new Set();

let status = {
  enabled:     PHISHING_DB_ENABLED,
  loaded:      false,
  loading:     false,
  domainCount: 0,
  linkCount:    0,
  lastRefresh:  null,
  lastError:    null,
  source:       'Phishing.Database (phish.co.za)',
};

function getStatus() {
  return { ...status };
}

function ensureCacheDir() {
  fs.mkdirSync(CACHE_DIR, { recursive: true });
}

function downloadText(url, timeoutMs = 120_000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'PhishGuard/1.0 (+https://github.com/Phishing-Database)' } }, res => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        const loc = res.headers.location;
        if (loc) {
          downloadText(loc.startsWith('http') ? loc : new URL(loc, url).href, timeoutMs).then(resolve).catch(reject);
          return;
        }
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        res.resume();
        return;
      }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error(`Timeout downloading ${url}`)); });
  });
}

function parseLines(text) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    out.push(t.toLowerCase());
  }
  return out;
}

function normalizeUrlKey(raw) {
  try {
    let u = raw.trim();
    if (!/^https?:\/\//i.test(u)) u = 'http://' + u;
    const parsed = new URL(u);
    parsed.hostname = parsed.hostname.toLowerCase();
    parsed.hash = '';
    let s = parsed.href;
    if (s.endsWith('/')) s = s.slice(0, -1);
    return s;
  } catch {
    return raw.trim().toLowerCase();
  }
}

function domainListed(domain) {
  if (!domain) return false;
  const d = domain.toLowerCase();
  if (domainSet.has(d)) return { match: true, via: d };
  const parts = d.split('.');
  for (let i = 1; i < parts.length; i++) {
    const parent = parts.slice(i).join('.');
    if (domainSet.has(parent)) return { match: true, via: parent };
  }
  return { match: false };
}

function loadFromCache() {
  const domainsPath = path.join(CACHE_DIR, 'domains.txt');
  const linksPath   = path.join(CACHE_DIR, 'links.txt');
  if (!fs.existsSync(domainsPath)) return false;

  const domains = parseLines(fs.readFileSync(domainsPath, 'utf8'));
  domainSet = new Set(domains);

  linkSet = new Set();
  if (fs.existsSync(linksPath)) {
    for (const line of parseLines(fs.readFileSync(linksPath, 'utf8'))) {
      linkSet.add(normalizeUrlKey(line));
    }
  }

  let meta = {};
  if (fs.existsSync(META_FILE)) {
    try { meta = JSON.parse(fs.readFileSync(META_FILE, 'utf8')); } catch { /* ignore */ }
  }

  status.loaded      = true;
  status.domainCount = domainSet.size;
  status.linkCount   = linkSet.size;
  status.lastRefresh = meta.lastRefresh || null;
  status.lastError   = null;
  return true;
}

function cacheIsStale() {
  if (!fs.existsSync(META_FILE)) return true;
  try {
    const meta = JSON.parse(fs.readFileSync(META_FILE, 'utf8'));
    if (!meta.lastRefresh) return true;
    const ageMs = Date.now() - new Date(meta.lastRefresh).getTime();
    return ageMs > PHISHING_DB_REFRESH_HOURS * 60 * 60 * 1000;
  } catch {
    return true;
  }
}

async function fetchAndCacheFeeds() {
  ensureCacheDir();
  console.log('  ⏳ Downloading Phishing.Database feeds…');

  const [domainsText, linksText] = await Promise.all([
    downloadText(PHISHING_DB_DOMAINS_URL),
    downloadText(PHISHING_DB_LINKS_URL).catch(() => ''),
  ]);

  fs.writeFileSync(path.join(CACHE_DIR, 'domains.txt'), domainsText, 'utf8');
  if (linksText) fs.writeFileSync(path.join(CACHE_DIR, 'links.txt'), linksText, 'utf8');

  const now = new Date().toISOString();
  fs.writeFileSync(META_FILE, JSON.stringify({
    lastRefresh: now,
    domainsUrl:  PHISHING_DB_DOMAINS_URL,
    linksUrl:    PHISHING_DB_LINKS_URL,
    attribution: 'https://github.com/Phishing-Database',
  }, null, 2), 'utf8');

  loadFromCache();
  status.lastRefresh = now;
  console.log(`  ✅ Phishing.Database loaded  →  ${status.domainCount.toLocaleString()} domains, ${status.linkCount.toLocaleString()} links`);
}

async function initPhishingDatabase(force = false) {
  if (!PHISHING_DB_ENABLED) {
    status.enabled = false;
    console.log('  ℹ️  Phishing.Database feed disabled (PHISHING_DB_ENABLED=false)');
    return;
  }

  if (status.loading) return;
  status.loading = true;
  status.enabled = true;

  try {
    ensureCacheDir();
    const hasCache = fs.existsSync(path.join(CACHE_DIR, 'domains.txt'));

    if (hasCache && !force) {
      loadFromCache();
      console.log(`  ✅ Phishing.Database (cache)  →  ${status.domainCount.toLocaleString()} domains, ${status.linkCount.toLocaleString()} links`);
      if (cacheIsStale()) {
        fetchAndCacheFeeds().catch(err => {
          status.lastError = err.message;
          console.warn(`  ⚠️  Phishing.Database refresh failed: ${err.message}`);
        });
      }
      return;
    }

    await fetchAndCacheFeeds();
  } catch (err) {
    status.lastError = err.message;
    if (loadFromCache()) {
      console.warn(`  ⚠️  Phishing.Database download failed — using cache: ${err.message}`);
    } else {
      console.warn(`  ⚠️  Phishing.Database unavailable: ${err.message}`);
    }
  } finally {
    status.loading = false;
  }
}

/**
 * @param {string} target - URL or host scanned by user
 * @param {string} domain - extracted hostname
 */
function checkPhishingDatabase(target, domain) {
  if (!PHISHING_DB_ENABLED || !status.loaded) {
    return {
      listed:  false,
      loaded:  status.loaded,
      detail:  status.loaded ? null : (status.lastError || 'Feed not loaded'),
    };
  }

  const urlKey = normalizeUrlKey(target);
  if (linkSet.has(urlKey)) {
    return {
      listed:    true,
      matchType: 'url',
      detail:    'Exact URL match in Phishing.Database active links feed',
      feed:      PHISHING_DB_LINKS_URL,
    };
  }

  const dom = domainListed(domain);
  if (dom.match) {
    return {
      listed:    true,
      matchType: 'domain',
      detail:    dom.via === domain.toLowerCase()
        ? `Domain "${domain}" is in Phishing.Database active domains feed`
        : `Domain "${domain}" matches listed parent "${dom.via}" (Phishing.Database)`,
      feed: PHISHING_DB_DOMAINS_URL,
    };
  }

  return { listed: false, loaded: true };
}

/** Reload in-memory sets from disk cache (used after tests or manual cache updates). */
function reloadCacheFromDisk() {
  return loadFromCache();
}

module.exports = {
  initPhishingDatabase,
  checkPhishingDatabase,
  getStatus,
  fetchAndCacheFeeds,
  reloadCacheFromDisk,
};
