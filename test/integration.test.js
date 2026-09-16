'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

if (!process.env.TEST_DATABASE_URL) {
  test('pengujian integrasi Neon PostgreSQL', { skip: 'Isi TEST_DATABASE_URL untuk menjalankan pengujian integrasi.' }, () => {});
} else {
  process.env.DATABASE_URL = process.env.TEST_DATABASE_URL;
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret-with-at-least-32-characters';
  process.env.COOKIE_SECRET = process.env.COOKIE_SECRET || 'test-cookie-secret-with-at-least-32-characters';
  process.env.DATABASE_SSL = process.env.DATABASE_SSL || 'true';
  process.env.NODE_ENV = 'test';

  const request = require('supertest');
  const bcrypt = require('bcryptjs');
  const { app, pool } = require('../server');

  let agent;
  let csrf;
  let categories;
  let familyTransactionId;
  let debtId;
  let debtPaymentId;
  let uktGoalId;
  let uktEntryId;
  let emergencyGoalId;

  test.before(async () => {
    const schema = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8');
    await pool.query(schema);
    await pool.query('TRUNCATE audit_logs, balance_adjustments, goal_transactions, debt_payments, transactions, financial_goals, debts, categories, users RESTART IDENTITY CASCADE');
    agent = request.agent(app);
  });

  test.after(async () => {
    await pool.query('TRUNCATE audit_logs, balance_adjustments, goal_transactions, debt_payments, transactions, financial_goals, debts, categories, users RESTART IDENTITY CASCADE');
    await pool.end();
  });

  test('route privat menolak pengguna tanpa sesi', async () => {
    await request(app).get('/api/transactions').expect(401);
    await request(app).get('/').expect(302).expect('Location', '/signin');
  });

  test('register membuat akun utama dan signin cookie', async () => {
    await agent.post('/api/auth/register').send({ username: 'hera', email: 'hera@example.com', password: 'Password123', confirmPassword: 'Password123' }).expect(201);
    const me = await agent.get('/api/auth/me').expect(200);
    assert.equal(me.body.user.username, 'hera');
    csrf = me.body.csrfToken;
    assert.ok(csrf);
    const categoryResponse = await agent.get('/api/categories').expect(200);
    categories = categoryResponse.body.data;
    assert.ok(categories.length >= 12);
  });

  test('registrasi kedua ditolak oleh bootstrap admin', async () => {
    await request(app).post('/api/auth/register').send({ username: 'lain', email: 'lain@example.com', password: 'Password123', confirmPassword: 'Password123' }).expect(403);
  });

  test('skenario transaksi, setoran internal, cicilan, dan saldo tidak ganda', async () => {
    const category = (slug) => categories.find((item) => item.slug === slug).id;
    await agent.post('/api/transactions').set('X-CSRF-Token', csrf).send({ transactionType: 'income', categoryId: category('salary'), amount: '3000000', transactionDate: '2026-09-01', description: 'Gaji September' }).expect(201);
    const family = await agent.post('/api/transactions').set('X-CSRF-Token', csrf).send({ transactionType: 'expense', categoryId: category('family'), amount: '500000', transactionDate: '2026-09-02', description: 'Uang keluarga' }).expect(201);
    familyTransactionId = family.body.data.id;

    const debt = await agent.post('/api/debts').set('X-CSRF-Token', csrf).send({ creditorName: 'Pia', originalAmount: '30000000', interestPercent: '0', monthlyTargetMin: '200000', monthlyTargetMax: '300000' }).expect(201);
    debtId = debt.body.data.id;
    const payment = await agent.post(`/api/debts/${debtId}/payments`).set('X-CSRF-Token', csrf).send({ amount: '200000', paymentDate: '2026-09-03', notes: 'Cicilan pertama' }).expect(201);
    debtPaymentId = payment.body.data.id;

    const ukt = await agent.post('/api/goals').set('X-CSRF-Token', csrf).send({ goalType: 'ukt', name: 'UKT Semester 7', targetAmount: '4000000', monthlyTarget: '1000000', dueDate: '2027-01-15' }).expect(201);
    uktGoalId = ukt.body.data.id;
    const uktEntry = await agent.post(`/api/goals/${uktGoalId}/entries`).set('X-CSRF-Token', csrf).send({ entryType: 'contribution', amount: '1000000', entryDate: '2026-09-04' }).expect(201);
    uktEntryId = uktEntry.body.data.id;

    const emergency = await agent.post('/api/goals').set('X-CSRF-Token', csrf).send({ goalType: 'emergency', name: 'Dana Darurat', targetAmount: '3000000', monthlyTarget: '50000' }).expect(201);
    emergencyGoalId = emergency.body.data.id;
    await agent.post(`/api/goals/${emergencyGoalId}/entries`).set('X-CSRF-Token', csrf).send({ entryType: 'contribution', amount: '50000', entryDate: '2026-09-05' }).expect(201);

    const dashboard = await agent.get('/api/dashboard?month=2026-09').expect(200);
    assert.equal(dashboard.body.data.summary.income, '3000000');
    assert.equal(dashboard.body.data.summary.expense, '700000');
    assert.equal(dashboard.body.data.summary.balance, '2300000');
    assert.equal(dashboard.body.data.summary.emergencyFund, '50000');
  });

  test('edit dan hapus transaksi menghitung ulang saldo', async () => {
    const family = categories.find((item) => item.slug === 'family');
    await agent.put(`/api/transactions/${familyTransactionId}`).set('X-CSRF-Token', csrf).send({ transactionType: 'expense', categoryId: family.id, amount: '600000', transactionDate: '2026-09-02', description: 'Uang keluarga diperbarui' }).expect(200);
    let dashboard = await agent.get('/api/dashboard?month=2026-09').expect(200);
    assert.equal(dashboard.body.data.summary.balance, '2200000');
    await agent.delete(`/api/transactions/${familyTransactionId}`).set('X-CSRF-Token', csrf).expect(200);
    dashboard = await agent.get('/api/dashboard?month=2026-09').expect(200);
    assert.equal(dashboard.body.data.summary.balance, '2800000');
  });

  test('edit dan hapus cicilan memperbarui utang serta transaksi terkait', async () => {
    await agent.put(`/api/debts/${debtId}/payments/${debtPaymentId}`).set('X-CSRF-Token', csrf).send({ amount: '300000', paymentDate: '2026-09-03', notes: 'Cicilan diubah' }).expect(200);
    let debts = await agent.get('/api/debts').expect(200);
    assert.equal(debts.body.data[0].paid_amount, '300000');
    await agent.delete(`/api/debts/${debtId}/payments/${debtPaymentId}`).set('X-CSRF-Token', csrf).expect(200);
    debts = await agent.get('/api/debts').expect(200);
    assert.equal(debts.body.data[0].paid_amount, '0');
  });

  test('edit dan hapus setoran UKT memperbarui progres tanpa mengubah saldo aktual', async () => {
    await agent.put(`/api/goals/${uktGoalId}/entries/${uktEntryId}`).set('X-CSRF-Token', csrf).send({ entryType: 'contribution', amount: '1500000', entryDate: '2026-09-04' }).expect(200);
    let goals = await agent.get('/api/goals').expect(200);
    assert.equal(goals.body.data.find((g) => g.id === uktGoalId).current_balance, '1500000');
    const dashboard = await agent.get('/api/dashboard?month=2026-09').expect(200);
    assert.equal(dashboard.body.data.summary.balance, '3000000');
    await agent.delete(`/api/goals/${uktGoalId}/entries/${uktEntryId}`).set('X-CSRF-Token', csrf).expect(200);
    goals = await agent.get('/api/goals').expect(200);
    assert.equal(goals.body.data.find((g) => g.id === uktGoalId).current_balance, '0');
  });

  test('export laporan bulanan menghasilkan CSV UTF-8 BOM', async () => {
    const response = await agent.get('/api/reports/monthly?month=2026-09').expect(200).expect('Content-Type', /text\/csv/);
    assert.ok(response.text.startsWith('\uFEFF'));
    assert.match(response.text, /HERA FINANCE - LAPORAN BULANAN/);
  });

  test('data pengguna lain tidak terlihat', async () => {
    const hash = await bcrypt.hash('Password123', 4);
    await pool.query("INSERT INTO users(username,email,password_hash,role) VALUES('kedua','kedua@example.com',$1,'user')", [hash]);
    const second = request.agent(app);
    await second.post('/api/auth/login').send({ identifier: 'kedua@example.com', password: 'Password123' }).expect(200);
    const response = await second.get('/api/transactions').expect(200);
    assert.equal(response.body.data.length, 0);
  });

  test('logout menghapus sesi', async () => {
    await agent.post('/api/auth/logout').set('X-CSRF-Token', csrf).expect(200);
    await agent.get('/api/auth/me').expect(401);
  });
}
