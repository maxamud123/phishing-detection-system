'use strict';

const crypto = require('crypto');
const { getDb } = require('../db/connection');
const { jsonOk, jsonError, parseBody, noDb } = require('../middleware/http');
const { requireAuth, checkRateLimit } = require('../middleware/auth');
const { hashPwd, genToken, genUserId } = require('../services/cryptoService');
const { audit } = require('../services/auditService');

async function login(req, res) {
  const db = getDb();
  if (!db) return noDb(res);
  const ip = req.socket.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) return jsonError(res, 429, 'Too many login attempts. Try again in 15 minutes.');

  const body = await parseBody(req);
  if (body.__tooLarge) return jsonError(res, 413, 'Request too large.');
  const { email, password } = body;
  if (!email || !password) return jsonError(res, 400, 'Email and password required.');

  const user = await db.collection('users').findOne({ email: email.toLowerCase().trim() });
  if (!user) return jsonError(res, 401, 'No account found with that email.');
  if (hashPwd(password, user.salt) !== user.passwordHash)
    return jsonError(res, 401, 'Incorrect password.');
  if (user.disabled) return jsonError(res, 403, 'Your account has been disabled. Contact your administrator.');

  const token     = genToken();
  const ipAddress = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  await db.collection('sessions').insertOne({
    token, userId: user.userId, name: user.name, email: user.email, role: user.role,
    ipAddress, userAgent,
    createdAt: new Date(), expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
  });
  await db.collection('users').updateOne(
    { _id: user._id },
    { $set: { lastLogin: new Date() }, $inc: { loginCount: 1 } }
  );
  await audit('LOGIN', { userId: user.userId, name: user.name }, `Logged in from ${ipAddress}`, ipAddress, 'session');

  const { passwordHash, salt, _id, ...safe } = user;
  jsonOk(res, { token, user: safe });
}

async function signup(req, res) {
  const db = getDb();
  if (!db) return noDb(res);
  const body = await parseBody(req);
  if (body.__tooLarge) return jsonError(res, 413, 'Request too large.');
  const { name, email, password, confirmPassword } = body;

  if (!name || !email || !password) return jsonError(res, 400, 'Name, email, and password are required.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return jsonError(res, 400, 'Invalid email address.');
  if (password !== confirmPassword) return jsonError(res, 400, 'Passwords do not match.');
  if (password.length < 6) return jsonError(res, 400, 'Password must be at least 6 characters.');

  const col    = db.collection('users');
  const exists = await col.findOne({ email: email.toLowerCase().trim() });
  if (exists) return jsonError(res, 400, 'An account with this email already exists.');

  const salt         = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPwd(password, salt);
  const userId       = genUserId();

  const newUser = {
    userId, name: name.trim(), email: email.toLowerCase().trim(),
    passwordHash, salt, role: 'User', createdAt: new Date(),
  };
  await col.insertOne(newUser);
  await audit('SIGNUP', { userId, name: name.trim() }, `New user signed up: "${name}"`);

  const { passwordHash: ph, salt: s, _id, ...safe } = newUser;
  jsonOk(res, { user: safe, message: 'Account created successfully.' }, 201);
}

async function logout(req, res) {
  const db    = getDb();
  const token = (req.headers['authorization'] || '').replace('Bearer ', '');
  if (db && token) await db.collection('sessions').deleteOne({ token });
  jsonOk(res, { message: 'Logged out.' });
}

async function me(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  jsonOk(res, { user });
}

async function checkSetup(req, res) {
  const db = getDb();
  if (!db) return jsonOk(res, { needsSetup: false, dbConnected: false });
  const count = await db.collection('users').countDocuments();
  jsonOk(res, { needsSetup: count === 0, dbConnected: true });
}

async function changePassword(req, res) {
  const db = getDb();
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;

  const { currentPassword, newPassword } = await parseBody(req);
  if (!currentPassword || !newPassword) return jsonError(res, 400, 'Current and new password required.');
  if (newPassword.length < 6) return jsonError(res, 400, 'New password must be at least 6 characters.');

  const dbUser = await db.collection('users').findOne({ userId: user.userId });
  if (!dbUser) return jsonError(res, 404, 'User not found.');
  if (hashPwd(currentPassword, dbUser.salt) !== dbUser.passwordHash)
    return jsonError(res, 401, 'Current password is incorrect.');

  const salt         = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPwd(newPassword, salt);
  await db.collection('users').updateOne({ userId: user.userId }, { $set: { salt, passwordHash, updatedAt: new Date() } });
  await db.collection('sessions').deleteMany({ userId: user.userId });
  await audit('CHANGE_PASSWORD', user, 'Changed own password');
  jsonOk(res, { message: 'Password changed. Please log in again.' });
}

async function updateProfile(req, res) {
  const db = getDb();
  if (!db) return noDb(res);
  const user = await requireAuth(req, res);
  if (!user) return;

  const body   = await parseBody(req);
  const update = { updatedAt: new Date() };
  if (body.name) update.name = body.name.trim();
  if (body.email) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) return jsonError(res, 400, 'Invalid email address.');
    const conflict = await db.collection('users').findOne({ email: body.email.toLowerCase(), userId: { $ne: user.userId } });
    if (conflict) return jsonError(res, 400, 'Email already in use.');
    update.email = body.email.toLowerCase().trim();
  }

  const result = await db.collection('users').findOneAndUpdate(
    { userId: user.userId }, { $set: update },
    { returnDocument: 'after', projection: { passwordHash: 0, salt: 0 } }
  );
  await audit('UPDATE_PROFILE', user, 'Updated own profile');
  jsonOk(res, { user: result });
}

module.exports = { login, signup, logout, me, checkSetup, changePassword, updateProfile };
