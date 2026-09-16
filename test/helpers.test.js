'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const { parseMoney, formatIDR, percentage, validDate, validMonth } = require('../server');

test('parseMoney memproses rupiah utuh tanpa floating point', () => {
  assert.equal(parseMoney('Rp3.000.000'), 3_000_000n);
  assert.equal(parseMoney('200000'), 200_000n);
  assert.throws(() => parseMoney('-10'));
  assert.throws(() => parseMoney('0'));
});

test('formatIDR konsisten untuk nilai positif dan negatif', () => {
  assert.equal(formatIDR(3_000_000n), 'Rp3.000.000');
  assert.equal(formatIDR(-50_000n), '-Rp50.000');
});

test('persentase dibatasi pada rentang 0 sampai 100', () => {
  assert.equal(percentage('500000', '3000000'), 16.66);
  assert.equal(percentage('4000000', '3000000'), 100);
  assert.equal(percentage('1', '0'), 0);
});

test('validator periode dan tanggal menolak format yang salah', () => {
  assert.equal(validMonth('2026-09'), true);
  assert.equal(validMonth('2026-13'), false);
  assert.equal(validDate('2026-09-16'), true);
  assert.equal(validDate('16-09-2026'), false);
});

test('tombol show/hide password bekerja pada halaman signin', async () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'signin.html'), 'utf8');
  const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'http://localhost/signin', beforeParse(window) { window.tailwind = {}; } });
  const input = dom.window.document.getElementById('password');
  const button = dom.window.document.querySelector('[data-toggle="password"]');
  assert.equal(input.type, 'password');
  button.click();
  assert.equal(input.type, 'text');
  button.click();
  assert.equal(input.type, 'password');
  dom.window.close();
});
