'use strict';

require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const AUTH_COOKIE = 'hera_auth';
const CSRF_COOKIE = 'hera_csrf';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});

class AppError extends Error {
  constructor(status, message, code = 'APP_ERROR') {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const asyncRoute = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
const today = () => new Date().toISOString().slice(0, 10);
const isId = (value) => /^\d+$/.test(String(value || ''));
const cleanText = (value, max = 500) => String(value ?? '').trim().replace(/[\u0000-\u001F\u007F]/g, '').slice(0, max);
const validDate = (value) => /^\d{4}-\d{2}-\d{2}$/.test(String(value || '')) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
const validMonth = (value) => /^\d{4}-(0[1-9]|1[0-2])$/.test(String(value || ''));

function parseMoney(value, { allowZero = false, allowNegative = false } = {}) {
  const raw = String(value ?? '').trim().replace(/[^\d-]/g, '');
  if (!/^-?\d+$/.test(raw)) throw new AppError(422, 'Nominal harus berupa rupiah utuh.', 'INVALID_AMOUNT');
  const amount = BigInt(raw);
  if (!allowNegative && amount < 0n) throw new AppError(422, 'Nominal tidak boleh negatif.', 'INVALID_AMOUNT');
  if (!allowZero && amount === 0n) throw new AppError(422, 'Nominal harus lebih dari nol.', 'INVALID_AMOUNT');
  if (amount > 9_000_000_000_000_000n || amount < -9_000_000_000_000_000n) {
    throw new AppError(422, 'Nominal berada di luar batas yang didukung.', 'INVALID_AMOUNT');
  }
  return amount;
}

function formatIDR(value) {
  const amount = typeof value === 'bigint' ? value : BigInt(String(value || 0));
  const sign = amount < 0n ? '-' : '';
  const absolute = amount < 0n ? -amount : amount;
  return `${sign}Rp${absolute.toString().replace(/\B(?=(\d{3})+(?!\d))/g, '.')}`;
}

function percentage(actual, target) {
  const a = BigInt(String(actual || 0));
  const t = BigInt(String(target || 0));
  if (t <= 0n) return 0;
  const basisPoints = (a * 10_000n) / t;
  return Math.max(0, Math.min(100, Number(basisPoints) / 100));
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function cookieOptions(httpOnly = true) {
  return {
    httpOnly,
    secure: IS_PRODUCTION,
    sameSite: 'strict',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000
  };
}

function issueSession(res, user) {
  const token = jwt.sign({ sub: String(user.id), role: user.role }, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  const csrf = crypto.randomBytes(32).toString('hex');
  res.cookie(AUTH_COOKIE, token, cookieOptions(true));
  res.cookie(CSRF_COOKIE, csrf, cookieOptions(false));
  return csrf;
}

function clearSession(res) {
  res.clearCookie(AUTH_COOKIE, { ...cookieOptions(true), maxAge: undefined });
  res.clearCookie(CSRF_COOKIE, { ...cookieOptions(false), maxAge: undefined });
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && left.length > 0 && crypto.timingSafeEqual(left, right);
}

function authenticate(req, _res, next) {
  try {
    const token = req.cookies[AUTH_COOKIE];
    if (!token) throw new Error('missing');
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (!isId(payload.sub)) throw new Error('invalid');
    req.user = { id: payload.sub, role: payload.role };
    next();
  } catch {
    next(new AppError(401, 'Sesi tidak valid atau telah berakhir.', 'UNAUTHENTICATED'));
  }
}

function requireCsrf(req, _res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (!safeEqual(req.cookies[CSRF_COOKIE], req.get('X-CSRF-Token'))) {
    return next(new AppError(403, 'Token keamanan tidak valid. Muat ulang halaman.', 'INVALID_CSRF'));
  }
  next();
}

async function withTransaction(work) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function audit(client, req, action, entityType, entityId, beforeData = null, afterData = null) {
  await client.query(
    `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, before_data, after_data, ip_address)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, NULLIF($7, '')::inet)`,
    [req.user?.id || null, action, entityType, entityId || null, beforeData ? JSON.stringify(beforeData) : null, afterData ? JSON.stringify(afterData) : null, req.ip?.replace('::ffff:', '') || null]
  );
}

const DEFAULT_CATEGORIES = [
  ['Gaji', 'income', 'salary'],
  ['Pemasukan lainnya', 'income', 'other-income'],
  ['Keluarga', 'expense', 'family'],
  ['UKT', 'expense', 'ukt'],
  ['Cicilan utang', 'expense', 'debt-payment'],
  ['Dana darurat', 'expense', 'emergency-fund'],
  ['Makan', 'expense', 'food'],
  ['Transportasi', 'expense', 'transport'],
  ['Internet dan langganan', 'expense', 'internet'],
  ['Servis motor', 'expense', 'motor-service'],
  ['Pengeluaran mendadak', 'expense', 'unexpected'],
  ['Pengeluaran lainnya', 'expense', 'other-expense']
];

async function seedCategories(client, userId) {
  for (const [name, kind, slug] of DEFAULT_CATEGORIES) {
    await client.query(
      `INSERT INTO categories (user_id, name, kind, slug, is_system)
       VALUES ($1, $2, $3, $4, TRUE) ON CONFLICT (user_id, slug) DO NOTHING`,
      [userId, name, kind, slug]
    );
  }
}

async function ownedCategory(client, userId, categoryId, expectedKind) {
  if (!isId(categoryId)) throw new AppError(422, 'Kategori tidak valid.', 'INVALID_CATEGORY');
  const { rows } = await client.query('SELECT * FROM categories WHERE id = $1 AND user_id = $2', [categoryId, userId]);
  if (!rows[0]) throw new AppError(404, 'Kategori tidak ditemukan.', 'NOT_FOUND');
  if (expectedKind && rows[0].kind !== expectedKind) throw new AppError(422, 'Kategori tidak sesuai dengan jenis transaksi.', 'CATEGORY_MISMATCH');
  return rows[0];
}

async function systemCategory(client, userId, slug) {
  const { rows } = await client.query('SELECT id FROM categories WHERE user_id = $1 AND slug = $2', [userId, slug]);
  if (!rows[0]) throw new AppError(500, 'Kategori sistem belum tersedia.', 'CATEGORY_MISSING');
  return rows[0].id;
}

async function getGoalBalance(client, userId, goalId, excludeId = null) {
  const { rows } = await client.query(
    `SELECT COALESCE(SUM(CASE WHEN entry_type = 'contribution' THEN amount ELSE -amount END), 0)::text AS balance
     FROM goal_transactions WHERE user_id = $1 AND goal_id = $2 AND ($3::bigint IS NULL OR id <> $3)`,
    [userId, goalId, excludeId]
  );
  return BigInt(rows[0].balance);
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  next();
});
app.use((req, _res, next) => {
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && process.env.APP_ORIGIN && req.get('origin') && req.get('origin') !== process.env.APP_ORIGIN) {
    return next(new AppError(403, 'Origin permintaan tidak diizinkan.', 'INVALID_ORIGIN'));
  }
  next();
});
app.use(express.static(path.join(__dirname, 'public'), { index: false, maxAge: IS_PRODUCTION ? '1h' : 0 }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { ok: false, message: 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.', code: 'RATE_LIMITED' }
});

function pageAuth(req, res, next) {
  try {
    const token = req.cookies[AUTH_COOKIE];
    if (!token) return res.redirect('/signin');
    jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    clearSession(res);
    res.redirect('/signin');
  }
}

app.get('/', pageAuth, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/statistik', pageAuth, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'statistik.html')));
app.get('/signin', (req, res) => {
  try {
    if (req.cookies[AUTH_COOKIE]) {
      jwt.verify(req.cookies[AUTH_COOKIE], process.env.JWT_SECRET);
      return res.redirect('/');
    }
  } catch { clearSession(res); }
  res.sendFile(path.join(__dirname, 'public', 'signin.html'));
});

app.post('/api/auth/register', authLimiter, asyncRoute(async (req, res) => {
  const username = cleanText(req.body.username, 40);
  const email = cleanText(req.body.email, 254).toLowerCase();
  const password = String(req.body.password || '');
  const confirmPassword = String(req.body.confirmPassword || '');
  if (!/^[A-Za-z0-9_.-]{3,40}$/.test(username)) throw new AppError(422, 'Username 3–40 karakter dan hanya boleh berisi huruf, angka, titik, garis bawah, atau tanda hubung.', 'INVALID_USERNAME');
  if (!validateEmail(email)) throw new AppError(422, 'Alamat email tidak valid.', 'INVALID_EMAIL');
  if (password.length < 10 || password.length > 72 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password)) {
    throw new AppError(422, 'Password minimal 10 karakter serta mengandung huruf besar, huruf kecil, dan angka.', 'WEAK_PASSWORD');
  }
  if (password !== confirmPassword) throw new AppError(422, 'Konfirmasi password tidak sama.', 'PASSWORD_MISMATCH');

  const user = await withTransaction(async (client) => {
    await client.query('LOCK TABLE users IN EXCLUSIVE MODE');
    const count = await client.query('SELECT COUNT(*)::int AS total FROM users');
    if (count.rows[0].total > 0) throw new AppError(403, 'Registrasi ditutup karena akun utama sudah dibuat.', 'REGISTRATION_CLOSED');
    const passwordHash = await bcrypt.hash(password, 12);
    const created = await client.query(
      `INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, 'admin')
       RETURNING id, username, email, role, created_at`,
      [username, email, passwordHash]
    );
    await seedCategories(client, created.rows[0].id);
    await audit(client, { user: { id: created.rows[0].id }, ip: req.ip }, 'REGISTER', 'user', created.rows[0].id, null, { username, email });
    return created.rows[0];
  });
  issueSession(res, user);
  res.status(201).json({ ok: true, user });
}));

app.post('/api/auth/login', authLimiter, asyncRoute(async (req, res) => {
  const identifier = cleanText(req.body.identifier, 254).toLowerCase();
  const password = String(req.body.password || '');
  if (!identifier || !password) throw new AppError(422, 'Email/username dan password wajib diisi.', 'VALIDATION_ERROR');
  const { rows } = await pool.query(
    'SELECT id, username, email, password_hash, role FROM users WHERE LOWER(email) = $1 OR LOWER(username) = $1 LIMIT 1',
    [identifier]
  );
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) throw new AppError(401, 'Email/username atau password salah.', 'INVALID_CREDENTIALS');
  issueSession(res, user);
  res.json({ ok: true, user: { id: user.id, username: user.username, email: user.email, role: user.role } });
}));

app.post('/api/auth/logout', authenticate, requireCsrf, (req, res) => {
  clearSession(res);
  res.json({ ok: true, message: 'Berhasil keluar.' });
});

app.get('/api/auth/me', authenticate, asyncRoute(async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, email, role, created_at FROM users WHERE id = $1', [req.user.id]);
  if (!rows[0]) throw new AppError(401, 'Akun tidak ditemukan.', 'UNAUTHENTICATED');
  res.json({ ok: true, user: rows[0], csrfToken: req.cookies[CSRF_COOKIE] });
}));

const api = express.Router();
api.use(authenticate, requireCsrf);

api.get('/categories', asyncRoute(async (req, res) => {
  const { rows } = await pool.query('SELECT id, name, kind, slug, is_system FROM categories WHERE user_id = $1 ORDER BY kind DESC, name', [req.user.id]);
  res.json({ ok: true, data: rows });
}));

api.post('/categories', asyncRoute(async (req, res) => {
  const name = cleanText(req.body.name, 80);
  const kind = req.body.kind;
  if (name.length < 2 || !['income', 'expense'].includes(kind)) throw new AppError(422, 'Nama dan jenis kategori tidak valid.', 'VALIDATION_ERROR');
  const { rows } = await pool.query(
    `INSERT INTO categories (user_id, name, kind, is_system) VALUES ($1, $2, $3, FALSE)
     ON CONFLICT (user_id, name, kind) DO NOTHING RETURNING id, name, kind, slug, is_system`,
    [req.user.id, name, kind]
  );
  if (!rows[0]) throw new AppError(409, 'Kategori tersebut sudah tersedia.', 'DUPLICATE_CATEGORY');
  res.status(201).json({ ok: true, data: rows[0] });
}));

api.delete('/categories/:id', asyncRoute(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError(422, 'ID kategori tidak valid.');
  const result = await pool.query('DELETE FROM categories WHERE id = $1 AND user_id = $2 AND is_system = FALSE RETURNING id', [req.params.id, req.user.id]);
  if (!result.rows[0]) throw new AppError(404, 'Kategori tidak ditemukan, kategori sistem, atau masih digunakan.', 'NOT_FOUND');
  res.json({ ok: true });
}));

api.get('/transactions', asyncRoute(async (req, res) => {
  const values = [req.user.id];
  const conditions = ['t.user_id = $1'];
  if (req.query.month) {
    if (!validMonth(req.query.month)) throw new AppError(422, 'Periode tidak valid.');
    values.push(req.query.month);
    conditions.push(`TO_CHAR(t.transaction_date, 'YYYY-MM') = $${values.length}`);
  }
  if (req.query.type) {
    if (!['income', 'expense', 'transfer'].includes(req.query.type)) throw new AppError(422, 'Jenis transaksi tidak valid.');
    values.push(req.query.type);
    conditions.push(`t.transaction_type = $${values.length}`);
  }
  const { rows } = await pool.query(
    `SELECT t.id, t.transaction_date, t.transaction_month, t.transaction_year, t.transaction_type, t.amount::text,
            t.description, t.notes, t.source_type, t.created_at, c.id AS category_id, c.name AS category_name
     FROM transactions t LEFT JOIN categories c ON c.id = t.category_id
     WHERE ${conditions.join(' AND ')} ORDER BY t.transaction_date DESC, t.id DESC LIMIT 500`, values
  );
  res.json({ ok: true, data: rows });
}));

function transactionPayload(body) {
  const transactionType = body.transactionType;
  const transactionDate = body.transactionDate;
  const description = cleanText(body.description, 180);
  const notes = cleanText(body.notes, 1000) || null;
  if (!['income', 'expense'].includes(transactionType)) throw new AppError(422, 'Jenis transaksi harus pemasukan atau pengeluaran.', 'INVALID_TYPE');
  if (!validDate(transactionDate)) throw new AppError(422, 'Tanggal transaksi tidak valid.', 'INVALID_DATE');
  if (description.length < 2) throw new AppError(422, 'Deskripsi minimal 2 karakter.', 'INVALID_DESCRIPTION');
  return { transactionType, transactionDate, description, notes, amount: parseMoney(body.amount) };
}

api.post('/transactions', asyncRoute(async (req, res) => {
  const payload = transactionPayload(req.body);
  const data = await withTransaction(async (client) => {
    await ownedCategory(client, req.user.id, req.body.categoryId, payload.transactionType);
    const { rows } = await client.query(
      `INSERT INTO transactions (user_id, category_id, transaction_date, transaction_type, amount, description, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *, amount::text`,
      [req.user.id, req.body.categoryId, payload.transactionDate, payload.transactionType, payload.amount.toString(), payload.description, payload.notes]
    );
    await audit(client, req, 'CREATE', 'transaction', rows[0].id, null, rows[0]);
    return rows[0];
  });
  res.status(201).json({ ok: true, data });
}));

api.put('/transactions/:id', asyncRoute(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError(422, 'ID transaksi tidak valid.');
  const payload = transactionPayload(req.body);
  const data = await withTransaction(async (client) => {
    const before = await client.query('SELECT * FROM transactions WHERE id = $1 AND user_id = $2 FOR UPDATE', [req.params.id, req.user.id]);
    if (!before.rows[0]) throw new AppError(404, 'Transaksi tidak ditemukan.', 'NOT_FOUND');
    if (before.rows[0].source_type !== 'manual') throw new AppError(409, 'Transaksi terhubung harus diubah dari modul asalnya.', 'LINKED_TRANSACTION');
    await ownedCategory(client, req.user.id, req.body.categoryId, payload.transactionType);
    const { rows } = await client.query(
      `UPDATE transactions SET category_id = $1, transaction_date = $2, transaction_type = $3, amount = $4,
       description = $5, notes = $6, updated_at = NOW() WHERE id = $7 AND user_id = $8 RETURNING *, amount::text`,
      [req.body.categoryId, payload.transactionDate, payload.transactionType, payload.amount.toString(), payload.description, payload.notes, req.params.id, req.user.id]
    );
    await audit(client, req, 'UPDATE', 'transaction', req.params.id, before.rows[0], rows[0]);
    return rows[0];
  });
  res.json({ ok: true, data });
}));

api.delete('/transactions/:id', asyncRoute(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError(422, 'ID transaksi tidak valid.');
  await withTransaction(async (client) => {
    const before = await client.query('SELECT * FROM transactions WHERE id = $1 AND user_id = $2 FOR UPDATE', [req.params.id, req.user.id]);
    if (!before.rows[0]) throw new AppError(404, 'Transaksi tidak ditemukan.', 'NOT_FOUND');
    if (before.rows[0].source_type !== 'manual') throw new AppError(409, 'Transaksi terhubung harus dihapus dari modul asalnya.', 'LINKED_TRANSACTION');
    await client.query('DELETE FROM transactions WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    await audit(client, req, 'DELETE', 'transaction', req.params.id, before.rows[0], null);
  });
  res.json({ ok: true });
}));

api.get('/debts', asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT d.*, d.original_amount::text, d.monthly_target_min::text, d.monthly_target_max::text,
      COALESCE(SUM(dp.amount), 0)::text AS paid_amount,
      GREATEST(d.original_amount - COALESCE(SUM(dp.amount), 0), 0)::text AS remaining_amount
     FROM debts d LEFT JOIN debt_payments dp ON dp.debt_id = d.id
     WHERE d.user_id = $1 GROUP BY d.id ORDER BY d.created_at DESC`, [req.user.id]
  );
  res.json({ ok: true, data: rows.map((row) => ({ ...row, progress: percentage(row.paid_amount, row.original_amount) })) });
}));

function debtPayload(body) {
  const creditorName = cleanText(body.creditorName, 120);
  const interest = String(body.interestPercent ?? '0').trim();
  if (creditorName.length < 2) throw new AppError(422, 'Nama kreditur minimal 2 karakter.');
  if (!/^\d{1,3}(\.\d{1,4})?$/.test(interest) || Number(interest) > 100) throw new AppError(422, 'Persentase bunga tidak valid.');
  const min = parseMoney(body.monthlyTargetMin ?? 0, { allowZero: true });
  const max = parseMoney(body.monthlyTargetMax ?? 0, { allowZero: true });
  if (max < min) throw new AppError(422, 'Target maksimum tidak boleh lebih kecil dari target minimum.');
  return { creditorName, originalAmount: parseMoney(body.originalAmount), interest, min, max, notes: cleanText(body.notes, 1000) || null };
}

api.post('/debts', asyncRoute(async (req, res) => {
  const p = debtPayload(req.body);
  const { rows } = await pool.query(
    `INSERT INTO debts (user_id, creditor_name, original_amount, interest_percent, monthly_target_min, monthly_target_max, notes)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *, original_amount::text, monthly_target_min::text, monthly_target_max::text`,
    [req.user.id, p.creditorName, p.originalAmount.toString(), p.interest, p.min.toString(), p.max.toString(), p.notes]
  );
  res.status(201).json({ ok: true, data: rows[0] });
}));

api.put('/debts/:id', asyncRoute(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError(422, 'ID utang tidak valid.');
  const p = debtPayload(req.body);
  const paid = await pool.query('SELECT COALESCE(SUM(amount),0)::text AS total FROM debt_payments WHERE debt_id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  if (p.originalAmount < BigInt(paid.rows[0].total)) throw new AppError(422, 'Total utang tidak boleh lebih kecil dari jumlah yang sudah dibayar.');
  const { rows } = await pool.query(
    `UPDATE debts SET creditor_name=$1, original_amount=$2, interest_percent=$3, monthly_target_min=$4,
     monthly_target_max=$5, notes=$6, updated_at=NOW() WHERE id=$7 AND user_id=$8
     RETURNING *, original_amount::text, monthly_target_min::text, monthly_target_max::text`,
    [p.creditorName, p.originalAmount.toString(), p.interest, p.min.toString(), p.max.toString(), p.notes, req.params.id, req.user.id]
  );
  if (!rows[0]) throw new AppError(404, 'Data utang tidak ditemukan.', 'NOT_FOUND');
  res.json({ ok: true, data: rows[0] });
}));

api.delete('/debts/:id', asyncRoute(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError(422, 'ID utang tidak valid.');
  await withTransaction(async (client) => {
    const debt = await client.query('SELECT * FROM debts WHERE id=$1 AND user_id=$2 FOR UPDATE', [req.params.id, req.user.id]);
    if (!debt.rows[0]) throw new AppError(404, 'Data utang tidak ditemukan.', 'NOT_FOUND');
    await client.query(`DELETE FROM transactions WHERE user_id=$1 AND source_type='debt_payment' AND source_id IN (SELECT id FROM debt_payments WHERE debt_id=$2 AND user_id=$1)`, [req.user.id, req.params.id]);
    await client.query('DELETE FROM debts WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    await audit(client, req, 'DELETE', 'debt', req.params.id, debt.rows[0], null);
  });
  res.json({ ok: true });
}));

api.get('/debts/:id/payments', asyncRoute(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError(422, 'ID utang tidak valid.');
  const { rows } = await pool.query(
    `SELECT dp.id, dp.amount::text, dp.payment_date, dp.notes, dp.created_at FROM debt_payments dp
     JOIN debts d ON d.id=dp.debt_id WHERE dp.debt_id=$1 AND dp.user_id=$2 AND d.user_id=$2 ORDER BY dp.payment_date DESC, dp.id DESC`,
    [req.params.id, req.user.id]
  );
  res.json({ ok: true, data: rows });
}));

async function validateDebtPayment(client, userId, debtId, amount, excludePaymentId = null) {
  const debt = await client.query('SELECT * FROM debts WHERE id=$1 AND user_id=$2 FOR UPDATE', [debtId, userId]);
  if (!debt.rows[0]) throw new AppError(404, 'Data utang tidak ditemukan.', 'NOT_FOUND');
  const paid = await client.query('SELECT COALESCE(SUM(amount),0)::text AS total FROM debt_payments WHERE debt_id=$1 AND user_id=$2 AND ($3::bigint IS NULL OR id<>$3)', [debtId, userId, excludePaymentId]);
  if (BigInt(paid.rows[0].total) + amount > BigInt(debt.rows[0].original_amount)) throw new AppError(422, 'Pembayaran melebihi sisa utang.', 'OVERPAYMENT');
  return debt.rows[0];
}

api.post('/debts/:id/payments', asyncRoute(async (req, res) => {
  if (!isId(req.params.id)) throw new AppError(422, 'ID utang tidak valid.');
  const amount = parseMoney(req.body.amount);
  const paymentDate = req.body.paymentDate;
  if (!validDate(paymentDate)) throw new AppError(422, 'Tanggal pembayaran tidak valid.');
  const notes = cleanText(req.body.notes, 1000) || null;
  const data = await withTransaction(async (client) => {
    const debt = await validateDebtPayment(client, req.user.id, req.params.id, amount);
    const categoryId = await systemCategory(client, req.user.id, 'debt-payment');
    const tx = await client.query(
      `INSERT INTO transactions (user_id,category_id,transaction_date,transaction_type,amount,description,notes,source_type)
       VALUES ($1,$2,$3,'expense',$4,$5,$6,'debt_payment') RETURNING id`,
      [req.user.id, categoryId, paymentDate, amount.toString(), `Cicilan utang kepada ${debt.creditor_name}`, notes]
    );
    const payment = await client.query(
      `INSERT INTO debt_payments (user_id,debt_id,transaction_id,amount,payment_date,notes)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, amount::text, payment_date, notes, created_at`,
      [req.user.id, req.params.id, tx.rows[0].id, amount.toString(), paymentDate, notes]
    );
    await client.query('UPDATE transactions SET source_id=$1 WHERE id=$2', [payment.rows[0].id, tx.rows[0].id]);
    await audit(client, req, 'CREATE', 'debt_payment', payment.rows[0].id, null, payment.rows[0]);
    return payment.rows[0];
  });
  res.status(201).json({ ok: true, data });
}));

api.put('/debts/:debtId/payments/:paymentId', asyncRoute(async (req, res) => {
  if (!isId(req.params.debtId) || !isId(req.params.paymentId)) throw new AppError(422, 'ID pembayaran tidak valid.');
  const amount = parseMoney(req.body.amount);
  if (!validDate(req.body.paymentDate)) throw new AppError(422, 'Tanggal pembayaran tidak valid.');
  const notes = cleanText(req.body.notes, 1000) || null;
  const data = await withTransaction(async (client) => {
    await validateDebtPayment(client, req.user.id, req.params.debtId, amount, req.params.paymentId);
    const before = await client.query('SELECT * FROM debt_payments WHERE id=$1 AND debt_id=$2 AND user_id=$3 FOR UPDATE', [req.params.paymentId, req.params.debtId, req.user.id]);
    if (!before.rows[0]) throw new AppError(404, 'Pembayaran tidak ditemukan.', 'NOT_FOUND');
    const debt = await client.query('SELECT creditor_name FROM debts WHERE id=$1 AND user_id=$2', [req.params.debtId, req.user.id]);
    const { rows } = await client.query('UPDATE debt_payments SET amount=$1,payment_date=$2,notes=$3,updated_at=NOW() WHERE id=$4 RETURNING id,amount::text,payment_date,notes', [amount.toString(), req.body.paymentDate, notes, req.params.paymentId]);
    await client.query('UPDATE transactions SET amount=$1,transaction_date=$2,description=$3,notes=$4,updated_at=NOW() WHERE id=$5 AND user_id=$6', [amount.toString(), req.body.paymentDate, `Cicilan utang kepada ${debt.rows[0].creditor_name}`, notes, before.rows[0].transaction_id, req.user.id]);
    await audit(client, req, 'UPDATE', 'debt_payment', req.params.paymentId, before.rows[0], rows[0]);
    return rows[0];
  });
  res.json({ ok: true, data });
}));

api.delete('/debts/:debtId/payments/:paymentId', asyncRoute(async (req, res) => {
  if (!isId(req.params.debtId) || !isId(req.params.paymentId)) throw new AppError(422, 'ID pembayaran tidak valid.');
  await withTransaction(async (client) => {
    const payment = await client.query('SELECT * FROM debt_payments WHERE id=$1 AND debt_id=$2 AND user_id=$3 FOR UPDATE', [req.params.paymentId, req.params.debtId, req.user.id]);
    if (!payment.rows[0]) throw new AppError(404, 'Pembayaran tidak ditemukan.', 'NOT_FOUND');
    await client.query('DELETE FROM transactions WHERE id=$1 AND user_id=$2', [payment.rows[0].transaction_id, req.user.id]);
    await audit(client, req, 'DELETE', 'debt_payment', req.params.paymentId, payment.rows[0], null);
  });
  res.json({ ok: true });
}));

api.get('/goals', asyncRoute(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT g.*, g.target_amount::text, g.monthly_target::text,
      COALESCE(SUM(CASE WHEN gt.entry_type='contribution' THEN gt.amount ELSE -gt.amount END),0)::text AS current_balance,
      COALESCE(SUM(CASE WHEN gt.entry_type IN ('payment','usage') THEN gt.amount ELSE 0 END),0)::text AS realized_amount
     FROM financial_goals g LEFT JOIN goal_transactions gt ON gt.goal_id=g.id
     WHERE g.user_id=$1 GROUP BY g.id ORDER BY g.is_active DESC, g.created_at DESC`, [req.user.id]
  );
  res.json({ ok: true, data: rows.map((row) => {
    const achieved = BigInt(row.current_balance) + BigInt(row.realized_amount);
    return { ...row, remaining_amount: (BigInt(row.target_amount) > achieved ? BigInt(row.target_amount) - achieved : 0n).toString(), progress: percentage(achieved, row.target_amount) };
  }) });
}));

function goalPayload(body) {
  const goalType = body.goalType;
  const name = cleanText(body.name, 120);
  if (!['ukt', 'emergency'].includes(goalType) || name.length < 2) throw new AppError(422, 'Jenis atau nama target tidak valid.');
  if (body.dueDate && !validDate(body.dueDate)) throw new AppError(422, 'Tanggal jatuh tempo tidak valid.');
  return { goalType, name, target: parseMoney(body.targetAmount), monthly: parseMoney(body.monthlyTarget ?? 0, { allowZero: true }), dueDate: body.dueDate || null, notes: cleanText(body.notes, 1000) || null };
}

api.post('/goals', asyncRoute(async (req, res) => {
  const p = goalPayload(req.body);
  const { rows } = await pool.query(
    `INSERT INTO financial_goals (user_id,goal_type,name,target_amount,monthly_target,due_date,notes)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *,target_amount::text,monthly_target::text`,
    [req.user.id,p.goalType,p.name,p.target.toString(),p.monthly.toString(),p.dueDate,p.notes]
  );
  res.status(201).json({ ok:true,data:rows[0] });
}));

api.put('/goals/:id', asyncRoute(async (req,res) => {
  if (!isId(req.params.id)) throw new AppError(422,'ID target tidak valid.');
  const p=goalPayload(req.body);
  const {rows}=await pool.query(
    `UPDATE financial_goals SET goal_type=$1,name=$2,target_amount=$3,monthly_target=$4,due_date=$5,notes=$6,is_active=$7,updated_at=NOW()
     WHERE id=$8 AND user_id=$9 RETURNING *,target_amount::text,monthly_target::text`,
    [p.goalType,p.name,p.target.toString(),p.monthly.toString(),p.dueDate,p.notes,req.body.isActive !== false,req.params.id,req.user.id]
  );
  if(!rows[0]) throw new AppError(404,'Target tidak ditemukan.','NOT_FOUND');
  res.json({ok:true,data:rows[0]});
}));

api.delete('/goals/:id', asyncRoute(async (req,res) => {
  if(!isId(req.params.id)) throw new AppError(422,'ID target tidak valid.');
  await withTransaction(async(client)=>{
    const goal=await client.query('SELECT * FROM financial_goals WHERE id=$1 AND user_id=$2 FOR UPDATE',[req.params.id,req.user.id]);
    if(!goal.rows[0]) throw new AppError(404,'Target tidak ditemukan.','NOT_FOUND');
    await client.query(`DELETE FROM transactions WHERE user_id=$1 AND source_type IN ('goal_payment','goal_usage') AND source_id IN (SELECT id FROM goal_transactions WHERE goal_id=$2 AND user_id=$1)`,[req.user.id,req.params.id]);
    await client.query('DELETE FROM financial_goals WHERE id=$1 AND user_id=$2',[req.params.id,req.user.id]);
    await audit(client,req,'DELETE','financial_goal',req.params.id,goal.rows[0],null);
  });
  res.json({ok:true});
}));

api.get('/goals/:id/entries', asyncRoute(async(req,res)=>{
  if(!isId(req.params.id)) throw new AppError(422,'ID target tidak valid.');
  const {rows}=await pool.query(`SELECT gt.id,gt.entry_type,gt.amount::text,gt.entry_date,gt.notes,gt.created_at FROM goal_transactions gt JOIN financial_goals g ON g.id=gt.goal_id WHERE gt.goal_id=$1 AND gt.user_id=$2 AND g.user_id=$2 ORDER BY gt.entry_date DESC,gt.id DESC`,[req.params.id,req.user.id]);
  res.json({ok:true,data:rows});
}));

function goalEntryPayload(body) {
  if(!['contribution','withdrawal','payment','usage'].includes(body.entryType)) throw new AppError(422,'Jenis mutasi target tidak valid.');
  if(!validDate(body.entryDate)) throw new AppError(422,'Tanggal mutasi tidak valid.');
  return {entryType:body.entryType,entryDate:body.entryDate,amount:parseMoney(body.amount),notes:cleanText(body.notes,1000)||null};
}

api.post('/goals/:id/entries', asyncRoute(async(req,res)=>{
  if(!isId(req.params.id)) throw new AppError(422,'ID target tidak valid.');
  const p=goalEntryPayload(req.body);
  const data=await withTransaction(async(client)=>{
    const goal=await client.query('SELECT * FROM financial_goals WHERE id=$1 AND user_id=$2 FOR UPDATE',[req.params.id,req.user.id]);
    if(!goal.rows[0]) throw new AppError(404,'Target tidak ditemukan.','NOT_FOUND');
    if(goal.rows[0].goal_type==='ukt' && p.entryType==='usage') throw new AppError(422,'Target UKT menggunakan jenis pembayaran, bukan penggunaan.');
    if(goal.rows[0].goal_type==='emergency' && p.entryType==='payment') throw new AppError(422,'Dana darurat menggunakan jenis penggunaan, bukan pembayaran.');
    if(p.entryType!=='contribution' && p.amount>await getGoalBalance(client,req.user.id,req.params.id)) throw new AppError(422,'Nominal melebihi saldo pos yang tersedia.','INSUFFICIENT_GOAL_BALANCE');
    let transactionId=null;
    if(['payment','usage'].includes(p.entryType)) {
      const slug=p.entryType==='payment'?'ukt':'emergency-fund';
      const categoryId=await systemCategory(client,req.user.id,slug);
      const tx=await client.query(`INSERT INTO transactions (user_id,category_id,transaction_date,transaction_type,amount,description,notes,source_type) VALUES ($1,$2,$3,'expense',$4,$5,$6,$7) RETURNING id`,[req.user.id,categoryId,p.entryDate,p.amount.toString(),p.entryType==='payment'?`Pembayaran ${goal.rows[0].name}`:`Penggunaan ${goal.rows[0].name}`,p.notes,p.entryType==='payment'?'goal_payment':'goal_usage']);
      transactionId=tx.rows[0].id;
    }
    const {rows}=await client.query(`INSERT INTO goal_transactions (user_id,goal_id,transaction_id,entry_type,amount,entry_date,notes) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,entry_type,amount::text,entry_date,notes,created_at`,[req.user.id,req.params.id,transactionId,p.entryType,p.amount.toString(),p.entryDate,p.notes]);
    if(transactionId) await client.query('UPDATE transactions SET source_id=$1 WHERE id=$2',[rows[0].id,transactionId]);
    await audit(client,req,'CREATE','goal_transaction',rows[0].id,null,rows[0]);
    return rows[0];
  });
  res.status(201).json({ok:true,data});
}));

api.put('/goals/:goalId/entries/:entryId', asyncRoute(async(req,res)=>{
  if(!isId(req.params.goalId)||!isId(req.params.entryId)) throw new AppError(422,'ID mutasi tidak valid.');
  const p=goalEntryPayload(req.body);
  const data=await withTransaction(async(client)=>{
    const goal=await client.query('SELECT * FROM financial_goals WHERE id=$1 AND user_id=$2 FOR UPDATE',[req.params.goalId,req.user.id]);
    const before=await client.query('SELECT * FROM goal_transactions WHERE id=$1 AND goal_id=$2 AND user_id=$3 FOR UPDATE',[req.params.entryId,req.params.goalId,req.user.id]);
    if(!goal.rows[0]||!before.rows[0]) throw new AppError(404,'Mutasi target tidak ditemukan.','NOT_FOUND');
    if(goal.rows[0].goal_type==='ukt'&&p.entryType==='usage'||goal.rows[0].goal_type==='emergency'&&p.entryType==='payment') throw new AppError(422,'Jenis mutasi tidak sesuai target.');
    if(p.entryType!=='contribution'&&p.amount>await getGoalBalance(client,req.user.id,req.params.goalId,req.params.entryId)) throw new AppError(422,'Nominal melebihi saldo pos yang tersedia.');
    const needsExpense=['payment','usage'].includes(p.entryType);
    let transactionId=before.rows[0].transaction_id;
    if(needsExpense){
      const categoryId=await systemCategory(client,req.user.id,p.entryType==='payment'?'ukt':'emergency-fund');
      if(transactionId){
        await client.query(`UPDATE transactions SET category_id=$1,transaction_date=$2,amount=$3,description=$4,notes=$5,source_type=$6,updated_at=NOW() WHERE id=$7 AND user_id=$8`,[categoryId,p.entryDate,p.amount.toString(),p.entryType==='payment'?`Pembayaran ${goal.rows[0].name}`:`Penggunaan ${goal.rows[0].name}`,p.notes,p.entryType==='payment'?'goal_payment':'goal_usage',transactionId,req.user.id]);
      }else{
        const tx=await client.query(`INSERT INTO transactions (user_id,category_id,transaction_date,transaction_type,amount,description,notes,source_type,source_id) VALUES ($1,$2,$3,'expense',$4,$5,$6,$7,$8) RETURNING id`,[req.user.id,categoryId,p.entryDate,p.amount.toString(),p.entryType==='payment'?`Pembayaran ${goal.rows[0].name}`:`Penggunaan ${goal.rows[0].name}`,p.notes,p.entryType==='payment'?'goal_payment':'goal_usage',req.params.entryId]);
        transactionId=tx.rows[0].id;
      }
    }else if(transactionId){
      await client.query('UPDATE goal_transactions SET transaction_id=NULL WHERE id=$1 AND user_id=$2',[req.params.entryId,req.user.id]);
      await client.query('DELETE FROM transactions WHERE id=$1 AND user_id=$2',[transactionId,req.user.id]);
      transactionId=null;
    }
    const {rows}=await client.query('UPDATE goal_transactions SET transaction_id=$1,entry_type=$2,amount=$3,entry_date=$4,notes=$5,updated_at=NOW() WHERE id=$6 RETURNING id,entry_type,amount::text,entry_date,notes',[transactionId,p.entryType,p.amount.toString(),p.entryDate,p.notes,req.params.entryId]);
    await audit(client,req,'UPDATE','goal_transaction',req.params.entryId,before.rows[0],rows[0]);
    return rows[0];
  });
  res.json({ok:true,data});
}));

api.delete('/goals/:goalId/entries/:entryId', asyncRoute(async(req,res)=>{
  if(!isId(req.params.goalId)||!isId(req.params.entryId)) throw new AppError(422,'ID mutasi tidak valid.');
  await withTransaction(async(client)=>{
    const entry=await client.query('SELECT * FROM goal_transactions WHERE id=$1 AND goal_id=$2 AND user_id=$3 FOR UPDATE',[req.params.entryId,req.params.goalId,req.user.id]);
    if(!entry.rows[0]) throw new AppError(404,'Mutasi target tidak ditemukan.','NOT_FOUND');
    if(entry.rows[0].transaction_id) await client.query('DELETE FROM transactions WHERE id=$1 AND user_id=$2',[entry.rows[0].transaction_id,req.user.id]);
    else await client.query('DELETE FROM goal_transactions WHERE id=$1 AND user_id=$2',[req.params.entryId,req.user.id]);
    await audit(client,req,'DELETE','goal_transaction',req.params.entryId,entry.rows[0],null);
  });
  res.json({ok:true});
}));

api.get('/balance-adjustments', asyncRoute(async(req,res)=>{
  const {rows}=await pool.query('SELECT id,amount::text,reason,adjustment_date,created_at FROM balance_adjustments WHERE user_id=$1 ORDER BY adjustment_date DESC,id DESC',[req.user.id]);
  res.json({ok:true,data:rows});
}));

api.post('/balance-adjustments', asyncRoute(async(req,res)=>{
  const amount=parseMoney(req.body.amount,{allowNegative:true});
  const reason=cleanText(req.body.reason,220);
  if(!validDate(req.body.adjustmentDate)||reason.length<3) throw new AppError(422,'Tanggal dan alasan penyesuaian wajib diisi.');
  const data=await withTransaction(async(client)=>{
    const {rows}=await client.query('INSERT INTO balance_adjustments (user_id,amount,reason,adjustment_date) VALUES ($1,$2,$3,$4) RETURNING id,amount::text,reason,adjustment_date,created_at',[req.user.id,amount.toString(),reason,req.body.adjustmentDate]);
    await audit(client,req,'CREATE','balance_adjustment',rows[0].id,null,rows[0]);
    return rows[0];
  });
  res.status(201).json({ok:true,data});
}));

api.delete('/balance-adjustments/:id', asyncRoute(async(req,res)=>{
  if(!isId(req.params.id)) throw new AppError(422,'ID penyesuaian tidak valid.');
  await withTransaction(async(client)=>{
    const {rows}=await client.query('DELETE FROM balance_adjustments WHERE id=$1 AND user_id=$2 RETURNING *',[req.params.id,req.user.id]);
    if(!rows[0]) throw new AppError(404,'Penyesuaian tidak ditemukan.','NOT_FOUND');
    await audit(client,req,'DELETE','balance_adjustment',req.params.id,rows[0],null);
  });
  res.json({ok:true});
}));

api.get('/dashboard', asyncRoute(async(req,res)=>{
  const month=req.query.month||today().slice(0,7);
  if(!validMonth(month)) throw new AppError(422,'Periode tidak valid.');
  const [monthly, balance, categories, goals, debts, recent] = await Promise.all([
    pool.query(`SELECT COALESCE(SUM(amount) FILTER (WHERE transaction_type='income'),0)::text income,COALESCE(SUM(amount) FILTER (WHERE transaction_type='expense'),0)::text expense FROM transactions WHERE user_id=$1 AND TO_CHAR(transaction_date,'YYYY-MM')=$2`,[req.user.id,month]),
    pool.query(`SELECT ((SELECT COALESCE(SUM(CASE WHEN transaction_type='income' THEN amount WHEN transaction_type='expense' THEN -amount ELSE 0 END),0) FROM transactions WHERE user_id=$1)+(SELECT COALESCE(SUM(amount),0) FROM balance_adjustments WHERE user_id=$1))::text balance`,[req.user.id]),
    pool.query(`SELECT c.name,COALESCE(SUM(t.amount),0)::text amount FROM categories c JOIN transactions t ON t.category_id=c.id WHERE t.user_id=$1 AND t.transaction_type='expense' AND TO_CHAR(t.transaction_date,'YYYY-MM')=$2 GROUP BY c.id,c.name ORDER BY SUM(t.amount) DESC LIMIT 6`,[req.user.id,month]),
    pool.query(`SELECT g.id,g.name,g.goal_type,g.target_amount::text,COALESCE(SUM(CASE WHEN gt.entry_type='contribution' THEN gt.amount ELSE -gt.amount END),0)::text current_balance,COALESCE(SUM(CASE WHEN gt.entry_type IN ('payment','usage') THEN gt.amount ELSE 0 END),0)::text realized FROM financial_goals g LEFT JOIN goal_transactions gt ON gt.goal_id=g.id WHERE g.user_id=$1 AND g.is_active=TRUE GROUP BY g.id ORDER BY g.created_at DESC`,[req.user.id]),
    pool.query(`SELECT COALESCE(SUM(d.original_amount),0)::text original,COALESCE(SUM(p.paid),0)::text paid FROM debts d LEFT JOIN (SELECT debt_id,SUM(amount) paid FROM debt_payments GROUP BY debt_id) p ON p.debt_id=d.id WHERE d.user_id=$1`,[req.user.id]),
    pool.query(`SELECT t.id,t.transaction_date,t.transaction_type,t.amount::text,t.description,t.source_type,c.name category_name FROM transactions t LEFT JOIN categories c ON c.id=t.category_id WHERE t.user_id=$1 ORDER BY t.transaction_date DESC,t.id DESC LIMIT 6`,[req.user.id])
  ]);
  const income=BigInt(monthly.rows[0].income), expense=BigInt(monthly.rows[0].expense);
  const emergencySaved=goals.rows.filter(g=>g.goal_type==='emergency').reduce((sum,g)=>sum+BigInt(g.current_balance),0n);
  const savingsRate=income>0n?Number(((income-expense>0n?income-expense:0n)*10000n)/income)/100:0;
  res.json({ok:true,data:{month,summary:{income:income.toString(),expense:expense.toString(),balance:balance.rows[0].balance,remaining:(income-expense).toString(),expensePercentage:income>0n?Number((expense*10000n)/income)/100:0,savingsPercentage:savingsRate,emergencyFund:emergencySaved.toString(),debtPaid:debts.rows[0].paid},categories:categories.rows,goals:goals.rows.map(g=>({...g,progress:percentage(BigInt(g.current_balance)+BigInt(g.realized),g.target_amount)})),debt:{...debts.rows[0],remaining:(BigInt(debts.rows[0].original)-BigInt(debts.rows[0].paid)).toString(),progress:percentage(debts.rows[0].paid,debts.rows[0].original)},recent:recent.rows}});
}));

api.get(
  '/statistics',
  asyncRoute(async (req, res) => {
    const end =
      req.query.end && validMonth(req.query.end)
        ? req.query.end
        : today().slice(0, 7);

    const [monthly, categories, debts, goals, opening] =
      await Promise.all([
        pool.query(
          `
          WITH month_series AS (
            SELECT
              TO_CHAR(series_date, 'YYYY-MM') AS period_month
            FROM generate_series(
              (TO_DATE($2, 'YYYY-MM') - INTERVAL '11 months')::date,
              TO_DATE($2, 'YYYY-MM'),
              INTERVAL '1 month'
            ) AS series_date
          ),

          tx AS (
            SELECT
              TO_CHAR(transaction_date, 'YYYY-MM') AS period_month,

              COALESCE(
                SUM(amount) FILTER (
                  WHERE transaction_type = 'income'
                ),
                0
              ) AS income,

              COALESCE(
                SUM(amount) FILTER (
                  WHERE transaction_type = 'expense'
                ),
                0
              ) AS expense,

              COALESCE(
                SUM(
                  CASE
                    WHEN transaction_type = 'income'
                      THEN amount
                    WHEN transaction_type = 'expense'
                      THEN -amount
                    ELSE 0
                  END
                ),
                0
              ) AS net

            FROM transactions
            WHERE user_id = $1
            GROUP BY TO_CHAR(transaction_date, 'YYYY-MM')
          ),

          adj AS (
            SELECT
              TO_CHAR(adjustment_date, 'YYYY-MM') AS period_month,
              COALESCE(SUM(amount), 0) AS net

            FROM balance_adjustments
            WHERE user_id = $1
            GROUP BY TO_CHAR(adjustment_date, 'YYYY-MM')
          )

          SELECT
            ms.period_month AS "month",
            COALESCE(tx.income, 0)::text AS income,
            COALESCE(tx.expense, 0)::text AS expense,

            (
              COALESCE(tx.net, 0) +
              COALESCE(adj.net, 0)
            )::text AS net

          FROM month_series AS ms

          LEFT JOIN tx
            ON tx.period_month = ms.period_month

          LEFT JOIN adj
            ON adj.period_month = ms.period_month

          ORDER BY ms.period_month
          `,
          [req.user.id, end]
        ),

        pool.query(
          `
          SELECT
            c.name,
            COALESCE(SUM(t.amount), 0)::text AS amount

          FROM categories AS c

          JOIN transactions AS t
            ON t.category_id = c.id

          WHERE t.user_id = $1
            AND t.transaction_type = 'expense'
            AND t.transaction_date >=
              TO_DATE($2, 'YYYY-MM') - INTERVAL '11 months'

          GROUP BY c.id, c.name
          ORDER BY SUM(t.amount) DESC
          `,
          [req.user.id, end]
        ),

        pool.query(
          `
          SELECT
            d.creditor_name,
            d.original_amount::text AS original_amount,
            COALESCE(SUM(dp.amount), 0)::text AS paid

          FROM debts AS d

          LEFT JOIN debt_payments AS dp
            ON dp.debt_id = d.id

          WHERE d.user_id = $1

          GROUP BY d.id
          ORDER BY d.created_at
          `,
          [req.user.id]
        ),

        pool.query(
          `
          SELECT
            g.name,
            g.goal_type,
            g.target_amount::text AS target_amount,

            COALESCE(
              SUM(
                CASE
                  WHEN gt.entry_type = 'contribution'
                    THEN gt.amount
                  ELSE -gt.amount
                END
              ),
              0
            )::text AS current_balance,

            COALESCE(
              SUM(
                CASE
                  WHEN gt.entry_type IN ('payment', 'usage')
                    THEN gt.amount
                  ELSE 0
                END
              ),
              0
            )::text AS realized

          FROM financial_goals AS g

          LEFT JOIN goal_transactions AS gt
            ON gt.goal_id = g.id

          WHERE g.user_id = $1

          GROUP BY g.id
          ORDER BY g.created_at
          `,
          [req.user.id]
        ),

        pool.query(
          `
          SELECT (
            COALESCE(
              (
                SELECT SUM(
                  CASE
                    WHEN transaction_type = 'income'
                      THEN amount
                    WHEN transaction_type = 'expense'
                      THEN -amount
                    ELSE 0
                  END
                )

                FROM transactions

                WHERE user_id = $1
                  AND transaction_date <
                    (
                      TO_DATE($2, 'YYYY-MM') -
                      INTERVAL '11 months'
                    )
              ),
              0
            )

            +

            COALESCE(
              (
                SELECT SUM(amount)

                FROM balance_adjustments

                WHERE user_id = $1
                  AND adjustment_date <
                    (
                      TO_DATE($2, 'YYYY-MM') -
                      INTERVAL '11 months'
                    )
              ),
              0
            )
          )::text AS balance
          `,
          [req.user.id, end]
        )
      ]);

    let runningBalance = BigInt(opening.rows[0].balance);

    const monthlyWithBalance = monthly.rows.map((row) => {
      runningBalance += BigInt(row.net);

      return {
        ...row,
        balance: runningBalance.toString()
      };
    });

    res.json({
      ok: true,
      data: {
        monthly: monthlyWithBalance,

        categories: categories.rows,

        debts: debts.rows.map((debt) => ({
          ...debt,
          progress: percentage(
            debt.paid,
            debt.original_amount
          )
        })),

        goals: goals.rows.map((goal) => ({
          ...goal,
          progress: percentage(
            BigInt(goal.current_balance) +
              BigInt(goal.realized),
            goal.target_amount
          )
        }))
      }
    });
  })
);

function csvCell(value){return `"${String(value??'').replace(/"/g,'""')}"`;}
api.get('/reports/monthly', asyncRoute(async(req,res)=>{
  const month=req.query.month;
  if(!validMonth(month)) throw new AppError(422,'Periode laporan tidak valid.');
  const [tx,adjustments]=await Promise.all([
    pool.query(`SELECT t.transaction_date,t.transaction_type,c.name category,t.description,t.amount::text,t.notes FROM transactions t LEFT JOIN categories c ON c.id=t.category_id WHERE t.user_id=$1 AND TO_CHAR(t.transaction_date,'YYYY-MM')=$2 ORDER BY t.transaction_date,t.id`,[req.user.id,month]),
    pool.query(`SELECT COALESCE(SUM(amount),0)::text total FROM balance_adjustments WHERE user_id=$1 AND adjustment_date<TO_DATE($2,'YYYY-MM')+INTERVAL '1 month'`,[req.user.id,month])
  ]);
  const income=tx.rows.filter(r=>r.transaction_type==='income').reduce((s,r)=>s+BigInt(r.amount),0n);
  const expense=tx.rows.filter(r=>r.transaction_type==='expense').reduce((s,r)=>s+BigInt(r.amount),0n);
  const before=await pool.query(`SELECT COALESCE(SUM(CASE WHEN transaction_type='income' THEN amount WHEN transaction_type='expense' THEN -amount ELSE 0 END),0)::text total FROM transactions WHERE user_id=$1 AND transaction_date<TO_DATE($2,'YYYY-MM')`,[req.user.id,month]);
  const adjBefore=await pool.query(`SELECT COALESCE(SUM(amount),0)::text total FROM balance_adjustments WHERE user_id=$1 AND adjustment_date<TO_DATE($2,'YYYY-MM')`,[req.user.id,month]);
  const opening=BigInt(before.rows[0].total)+BigInt(adjBefore.rows[0].total);
  const closing=opening+income-expense+(BigInt(adjustments.rows[0].total)-BigInt(adjBefore.rows[0].total));
  const lines=[['HERA FINANCE - LAPORAN BULANAN'],['Periode',month],[],['RINGKASAN'],['Saldo awal',formatIDR(opening)],['Total pemasukan',formatIDR(income)],['Total pengeluaran',formatIDR(expense)],['Saldo akhir',formatIDR(closing)],[],['Tanggal','Jenis','Kategori','Deskripsi','Nominal','Catatan']];
  tx.rows.forEach(r=>lines.push([r.transaction_date,r.transaction_type==='income'?'Pemasukan':r.transaction_type==='expense'?'Pengeluaran':'Transfer',r.category||'-',r.description,formatIDR(r.amount),r.notes||'']));
  const csv='\uFEFF'+lines.map(line=>line.map(csvCell).join(';')).join('\r\n');
  res.setHeader('Content-Type','text/csv; charset=utf-8');
  res.setHeader('Content-Disposition',`attachment; filename="hera-finance-${month}.csv"`);
  res.send(csv);
}));

app.use('/api',api);
app.use('/api',(_req,_res,next)=>next(new AppError(404,'Endpoint tidak ditemukan.','NOT_FOUND')));
app.use((error,req,res,_next)=>{
  if(error.code==='23505') error=new AppError(409,'Data yang sama sudah tersedia.','DUPLICATE');
  if(error.code==='23503') error=new AppError(409,'Data masih terhubung dan tidak dapat dihapus.','DATA_IN_USE');
  const status=error.status||500;
  if(status>=500) console.error(`[${new Date().toISOString()}]`,error);
  if(req.path.startsWith('/api/')) return res.status(status).json({ok:false,message:status>=500?'Terjadi gangguan pada server. Silakan coba lagi.':error.message,code:error.code||'SERVER_ERROR'});
  res.status(status).send(status===404?'Halaman tidak ditemukan.':'Terjadi gangguan pada server.');
});

async function startServer(){
  for(const key of ['DATABASE_URL','JWT_SECRET','COOKIE_SECRET']) if(!process.env[key]) throw new Error(`Environment variable ${key} wajib diisi.`);
  if(String(process.env.JWT_SECRET).length<32) throw new Error('JWT_SECRET minimal 32 karakter.');
  await pool.query('SELECT 1');
  const server=app.listen(PORT,()=>console.log(`Hera Finance berjalan di http://localhost:${PORT}`));
  const shutdown=()=>server.close(async()=>{await pool.end();process.exit(0);});
  process.on('SIGINT',shutdown);process.on('SIGTERM',shutdown);
}

if(require.main===module) startServer().catch(error=>{console.error('Gagal menjalankan aplikasi:',error.message);process.exit(1);});

module.exports={app,pool,parseMoney,formatIDR,percentage,validDate,validMonth,transactionPayload};
