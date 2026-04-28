'use strict';

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.club', '.work', '.buzz', '.icu', '.tk', '.ml', '.ga', '.cf', '.gq',
  '.pw', '.cc', '.su', '.info', '.biz', '.click', '.link', '.site', '.online', '.live',
  '.store', '.stream', '.download', '.racing', '.win', '.bid', '.loan', '.trade',
];

const BRAND_KEYWORDS = [
  'google', 'apple', 'microsoft', 'amazon', 'paypal', 'netflix', 'facebook', 'instagram',
  'bank', 'chase', 'wellsfargo', 'citibank', 'amex', 'visa', 'mastercard', 'venmo',
  'coinbase', 'binance', 'crypto', 'wallet', 'icloud', 'outlook', 'yahoo', 'ebay',
  'dropbox', 'linkedin', 'twitter', 'whatsapp', 'telegram',
];

const PHISHING_PATHS = [
  'login', 'signin', 'sign-in', 'verify', 'verification', 'confirm', 'account',
  'secure', 'update', 'password', 'credential', 'authenticate', 'billing',
  'suspend', 'restore', 'unlock', 'recover', 'reset', 'validate', 'identity', 'ssn',
];

const LEGIT_DOMAINS = new Set([
  'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'apple.com',
  'microsoft.com', 'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com',
  'twitter.com', 'x.com', 'linkedin.com', 'instagram.com', 'netflix.com',
  'paypal.com', 'dropbox.com', 'slack.com', 'zoom.us', 'stripe.com',
]);

const POPULAR_DOMAINS_FOR_TYPO = [
  'paypal.com', 'amazon.com', 'google.com', 'apple.com', 'microsoft.com',
  'facebook.com', 'netflix.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
  'instagram.com', 'linkedin.com', 'twitter.com', 'dropbox.com', 'icloud.com',
];

module.exports = { SUSPICIOUS_TLDS, BRAND_KEYWORDS, PHISHING_PATHS, LEGIT_DOMAINS, POPULAR_DOMAINS_FOR_TYPO };
