'use strict';

const { getDb } = require('../db/connection');
const { jsonOk, jsonError, parseBody, noDb } = require('../middleware/http');
const { requireAuth } = require('../middleware/auth');
const { audit } = require('../services/auditService');
const { broadcastAlert } = require('../services/websocketService');
const { sendThreatAlert } = require('../services/emailService');
const { analyzeTarget } = require('../detector');
const { VIRUSTOTAL_KEY, SAFE_BROWSING_KEY } = require('../config');

async function getScans(req, res) {
  const db = getDb();
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;

  const qs    = Object.fromEntries(new URL('http://x' + req.url).searchParams);
  const page  = Math.max(1, parseInt(qs.page  || '1',  10));
  const limit = Math.min(100, Math.max(1, parseInt(qs.limit || '50', 10)));
  const skip  = (page - 1) * limit;
  const filter = user.role === 'Admin' ? {} : { scannedBy: user.userId };

  const [scans, total] = await Promise.all([
    db.collection('scans').find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
    db.collection('scans').countDocuments(filter),
  ]);
  jsonOk(res, { data: scans, total, page, pages: Math.ceil(total / limit) });
}

async function createScan(req, res) {
  const db = getDb();
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;

  const body = await parseBody(req);
  const scan = {
    id:        body.id     || 'SCN-' + Date.now().toString(36).toUpperCase(),
    target:    body.target || '',
    type:      body.type   || 'URL',
    result:    body.result || 'Unknown',
    riskScore: Number(body.riskScore || body.score) || 0,
    aiPowered: body.aiPowered || false,
    scannedBy: user.userId,
    timestamp: body.timestamp || new Date().toISOString().slice(0, 16).replace('T', ' '),
    createdAt: new Date(),
  };
  await db.collection('scans').insertOne(scan);
  jsonOk(res, { scan }, 201);
}

async function deleteScan(req, res, scanId) {
  const db = getDb();
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;

  const ownerFilter = user.role === 'Admin' ? { id: scanId } : { id: scanId, scannedBy: user.userId };
  const result = await db.collection('scans').deleteOne(ownerFilter);
  if (result.deletedCount === 0) return jsonError(res, 404, 'Scan not found or access denied.');
  await audit('DELETE_SCAN', user, `Deleted scan ${scanId}`);
  jsonOk(res, { message: 'Scan deleted.' });
}

async function analyzeScan(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const body = await parseBody(req);
  if (body.__tooLarge) return jsonError(res, 413, 'Request too large.');

  const { target, type = 'URL' } = body;
  if (!target || !target.trim()) return jsonError(res, 400, 'Target is required.');

  const analysis = await analyzeTarget(target.trim(), type, {
    virusTotal:   VIRUSTOTAL_KEY,
    safeBrowsing: SAFE_BROWSING_KEY,
  });

  const scan = {
    id:             'SCN-' + Date.now().toString(36).toUpperCase(),
    target:         target.trim(), type,
    result:         analysis.threatLevel,
    riskScore:      analysis.score,
    factors:        analysis.factors,
    externalChecks: analysis.externalChecks,
    aiPowered:      true,
    scannedBy:      user.userId,
    timestamp:      new Date().toISOString().slice(0, 16).replace('T', ' '),
    createdAt:      new Date(),
  };

  const db = getDb();
  if (db) await db.collection('scans').insertOne(scan);

  if (analysis.threatLevel === 'Dangerous') {
    broadcastAlert({ type: 'THREAT_DETECTED', scan: { id: scan.id, target: scan.target, riskScore: scan.riskScore, timestamp: scan.timestamp } });
    await sendThreatAlert(scan);
  }

  jsonOk(res, { scan, analysis });
}

async function bulkScan(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const body = await parseBody(req);
  if (body.__tooLarge) return jsonError(res, 413, 'Request too large.');

  const { targets, type = 'URL' } = body;
  if (!Array.isArray(targets) || targets.length === 0)
    return jsonError(res, 400, 'targets must be a non-empty array.');
  if (targets.length > 50)
    return jsonError(res, 400, 'Maximum 50 targets per bulk scan.');

  const db      = getDb();
  const results = [];

  for (const target of targets) {
    if (!target || typeof target !== 'string') continue;
    try {
      const analysis = await analyzeTarget(target.trim(), type, {
        virusTotal:   VIRUSTOTAL_KEY,
        safeBrowsing: SAFE_BROWSING_KEY,
      });
      const scan = {
        id:             'SCN-' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2, 5).toUpperCase(),
        target:         target.trim(), type,
        result:         analysis.threatLevel,
        riskScore:      analysis.score,
        factors:        analysis.factors,
        externalChecks: analysis.externalChecks,
        aiPowered:      true,
        scannedBy:      user.userId,
        timestamp:      new Date().toISOString().slice(0, 16).replace('T', ' '),
        createdAt:      new Date(),
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

module.exports = { getScans, createScan, deleteScan, analyzeScan, bulkScan };
