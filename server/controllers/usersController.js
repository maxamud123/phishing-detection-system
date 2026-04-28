'use strict';

const crypto = require('crypto');
const { getDb } = require('../db/connection');
const { jsonOk, jsonError, parseBody, noDb } = require('../middleware/http');
const { requireAuth } = require('../middleware/auth');
const { hashPwd, genUserId } = require('../services/cryptoService');
const { audit } = require('../services/auditService');

async function getUsers(req, res) {
  const db = getDb();
  if (!db) return noDb(res);
  const actor = await requireAuth(req, res);
  if (!actor) return;
  if (actor.role !== 'Admin') return jsonError(res, 403, 'Admin only.');
  const users = await db.collection('users')
    .find({}, { projection: { passwordHash: 0, salt: 0 } })
    .sort({ createdAt: 1 })
    .toArray();
  jsonOk(res, { data: users });
}

async function createUser(req, res) {
  const db = getDb();
  if (!db) return noDb(res);
  const actor = await requireAuth(req, res);
  if (!actor) return;
  if (actor.role !== 'Admin') return jsonError(res, 403, 'Admin only.');

  const { name, email, password } = await parseBody(req);
  if (!name || !email || !password) return jsonError(res, 400, 'Name, email, and password required.');

  const exists = await db.collection('users').findOne({ email: email.toLowerCase() });
  if (exists) return jsonError(res, 400, 'Email already in use.');

  const salt         = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPwd(password, salt);
  const userId       = genUserId();

  const newUser = {
    userId, name: name.trim(), email: email.toLowerCase(),
    passwordHash, salt, role: 'User', createdAt: new Date(),
  };
  await db.collection('users').insertOne(newUser);
  await audit('CREATE_USER', actor, `Created "${name}" (User)`);

  const { passwordHash: ph, salt: s, _id, ...safe } = newUser;
  jsonOk(res, { user: safe }, 201);
}

async function updateUser(req, res, userId) {
  const db = getDb();
  if (!db) return noDb(res);
  const actor = await requireAuth(req, res);
  if (!actor) return;
  if (actor.role !== 'Admin') return jsonError(res, 403, 'Admin only.');

  const body   = await parseBody(req);
  const update = { updatedAt: new Date() };
  if (body.name)     update.name  = body.name.trim();
  if (body.email)    update.email = body.email.toLowerCase().trim();
  if (body.password) {
    update.salt         = crypto.randomBytes(16).toString('hex');
    update.passwordHash = hashPwd(body.password, update.salt);
  }

  const result = await db.collection('users').findOneAndUpdate(
    { userId }, { $set: update },
    { returnDocument: 'after', projection: { passwordHash: 0, salt: 0 } }
  );
  if (!result) return jsonError(res, 404, 'User not found.');
  await audit('UPDATE_USER', actor, `Updated user "${userId}"`);
  jsonOk(res, { user: result });
}

async function deleteUser(req, res, userId) {
  const db = getDb();
  if (!db) return noDb(res);
  const actor = await requireAuth(req, res);
  if (!actor) return;
  if (actor.role !== 'Admin') return jsonError(res, 403, 'Admin only.');
  if (userId === actor.userId) return jsonError(res, 400, 'Cannot delete your own account.');

  const result = await db.collection('users').deleteOne({ userId });
  if (result.deletedCount === 0) return jsonError(res, 404, 'User not found.');
  await db.collection('sessions').deleteMany({ userId });
  await audit('DELETE_USER', actor, `Deleted user "${userId}"`);
  jsonOk(res, { message: 'User deleted.' });
}

async function resetPassword(req, res, userId) {
  const db = getDb();
  if (!db) return noDb(res);
  const actor = await requireAuth(req, res);
  if (!actor) return;
  if (actor.role !== 'Admin') return jsonError(res, 403, 'Admin only.');

  const { password } = await parseBody(req);
  if (!password || password.length < 6) return jsonError(res, 400, 'Password must be at least 6 characters.');

  const salt         = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPwd(password, salt);
  const result = await db.collection('users').findOneAndUpdate(
    { userId }, { $set: { salt, passwordHash, updatedAt: new Date() } }, { returnDocument: 'after' }
  );
  if (!result) return jsonError(res, 404, 'User not found.');
  await db.collection('sessions').deleteMany({ userId });
  await audit('RESET_PASSWORD', actor, `Reset password for user "${userId}"`, null, 'user');
  jsonOk(res, { message: 'Password reset. User sessions have been terminated.' });
}

async function toggleStatus(req, res, userId) {
  const db = getDb();
  if (!db) return noDb(res);
  const actor = await requireAuth(req, res);
  if (!actor) return;
  if (actor.role !== 'Admin') return jsonError(res, 403, 'Admin only.');
  if (userId === actor.userId) return jsonError(res, 400, 'Cannot disable your own account.');

  const { disabled } = await parseBody(req);
  const result = await db.collection('users').findOneAndUpdate(
    { userId }, { $set: { disabled: !!disabled, updatedAt: new Date() } },
    { returnDocument: 'after', projection: { passwordHash: 0, salt: 0 } }
  );
  if (!result) return jsonError(res, 404, 'User not found.');
  if (disabled) await db.collection('sessions').deleteMany({ userId });
  await audit(disabled ? 'DISABLE_USER' : 'ENABLE_USER', actor, `${disabled ? 'Disabled' : 'Enabled'} user "${userId}"`);
  jsonOk(res, { user: result });
}

module.exports = { getUsers, createUser, updateUser, deleteUser, resetPassword, toggleStatus };
