'use strict';

const { getDb } = require('../db/connection');
const { jsonOk, jsonError, parseBody, noDb } = require('../middleware/http');
const { requireAuth } = require('../middleware/auth');
const { genReportId } = require('../services/cryptoService');
const { audit } = require('../services/auditService');

async function getReports(req, res) {
  const db = getDb();
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;

  const qs    = Object.fromEntries(new URL('http://x' + req.url).searchParams);
  const page  = Math.max(1, parseInt(qs.page  || '1',  10));
  const limit = Math.min(100, Math.max(1, parseInt(qs.limit || '50', 10)));
  const skip  = (page - 1) * limit;
  const filter = user.role === 'Admin' ? {} : { createdBy: user.userId };

  const [reports, total] = await Promise.all([
    db.collection('reports').find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
    db.collection('reports').countDocuments(filter),
  ]);
  jsonOk(res, { data: reports, total, page, pages: Math.ceil(total / limit) });
}

async function createReport(req, res) {
  const db = getDb();
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;

  const body   = await parseBody(req);
  const report = {
    id:          body.id          || genReportId(),
    reporter:    body.reporter    || user.name,
    type:        body.type        || 'URL',
    target:      body.target      || '',
    riskScore:   Number(body.riskScore) || 0,
    status:      body.status      || 'Pending',
    description: body.description || body.desc || '',
    timestamp:   body.timestamp   || new Date().toISOString().slice(0, 16).replace('T', ' '),
    createdBy:   user.userId,
    createdAt:   new Date(),
  };
  await db.collection('reports').insertOne(report);
  await audit('CREATE_REPORT', user, `Filed report ${report.id}`);
  jsonOk(res, { report }, 201);
}

async function updateReport(req, res, reportId) {
  const db = getDb();
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;

  const ownerFilter = user.role === 'Admin' ? { id: reportId } : { id: reportId, createdBy: user.userId };
  const existing    = await db.collection('reports').findOne(ownerFilter);
  if (!existing) return jsonError(res, 404, 'Report not found or access denied.');

  const body   = await parseBody(req);
  const update = { updatedAt: new Date(), updatedBy: user.userId };
  if (body.status)                   update.status      = body.status;
  if (body.description)              update.description = body.description;
  if (body.riskScore !== undefined)  update.riskScore   = Number(body.riskScore);

  const result = await db.collection('reports').findOneAndUpdate(
    { id: reportId }, { $set: update }, { returnDocument: 'after' }
  );
  await audit('UPDATE_REPORT', user, `Updated ${reportId} → ${body.status || 'edited'}`);
  jsonOk(res, { report: result });
}

async function deleteReport(req, res, reportId) {
  const db = getDb();
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;

  const ownerFilter = user.role === 'Admin' ? { id: reportId } : { id: reportId, createdBy: user.userId };
  const result = await db.collection('reports').deleteOne(ownerFilter);
  if (result.deletedCount === 0) return jsonError(res, 404, 'Report not found or access denied.');
  await audit('DELETE_REPORT', user, `Deleted ${reportId}`);
  jsonOk(res, { message: 'Report deleted.' });
}

module.exports = { getReports, createReport, updateReport, deleteReport };
