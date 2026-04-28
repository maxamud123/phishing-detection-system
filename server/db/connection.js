'use strict';

const crypto = require('crypto');
const { MONGODB_URI, DB_NAME, ADMIN_EMAIL, ADMIN_PASSWORD } = require('../config');
const { hashPwd } = require('../services/cryptoService');

let MongoClient = null;
let ObjectId    = null;
try {
  const m  = require('mongodb');
  MongoClient = m.MongoClient;
  ObjectId    = m.ObjectId;
} catch {
  console.error('\n  ❌ mongodb not installed!  Run:  cd server && npm install\n');
}

let db      = null;
let mClient = null;

function getDb()       { return db; }
function getObjectId() { return ObjectId; }

async function connectDB() {
  if (db) return db;
  if (!MongoClient) return null;
  try {
    mClient = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    await mClient.connect();
    db = mClient.db(DB_NAME);
    console.log(`  ✅ MongoDB connected  →  ${DB_NAME}`);
    await setupIndexes();
    await seedDefaultData();
    return db;
  } catch (err) {
    console.warn(`  ⚠️  MongoDB unavailable: ${err.message}`);
    console.warn('  Check MONGODB_URI in server/.env\n');
    return null;
  }
}

async function setupIndexes() {
  await db.collection('users').createIndex({ email: 1 }, { unique: true });
  await db.collection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  await db.collection('sessions').createIndex({ token: 1 });
  await db.collection('sessions').createIndex({ userId: 1, expiresAt: 1 });
  await db.collection('scans').createIndex({ scannedBy: 1, createdAt: -1 });
  await db.collection('reports').createIndex({ createdBy: 1, createdAt: -1 });
  await db.collection('audit_logs').createIndex({ userId: 1, timestamp: -1 });
  await db.collection('audit_logs').createIndex({ timestamp: -1 });
}

async function seedDefaultData() {
  const col = db.collection('users');
  await col.deleteMany({ role: 'Admin', email: { $ne: ADMIN_EMAIL.toLowerCase() } });
  const exists = await col.findOne({ email: ADMIN_EMAIL.toLowerCase() });
  if (!exists) {
    const salt         = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPwd(ADMIN_PASSWORD, salt);
    await col.insertOne({
      userId: 'USR-001', name: 'Admin', email: ADMIN_EMAIL.toLowerCase(),
      passwordHash, salt, role: 'Admin', createdAt: new Date(),
    });
  }
  await col.updateOne({ email: ADMIN_EMAIL.toLowerCase() }, { $set: { role: 'Admin' } });
  console.log(`  ✅ Admin account ready  →  ${ADMIN_EMAIL}`);
}

module.exports = { connectDB, getDb, getObjectId };
