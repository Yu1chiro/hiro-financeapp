# Hera Finance

Hera Finance adalah aplikasi manajemen keuangan pribadi berbasis Express.js, JavaScript vanilla, Tailwind CSS CDN, ApexCharts, dan Neon PostgreSQL. Aplikasi mencatat pemasukan, pengeluaran, utang pribadi, target UKT, dana darurat, penyesuaian saldo, statistik, dan laporan CSV.

## Aturan perhitungan

Saldo aktual dihitung di backend dengan rumus `total pemasukan - total pengeluaran aktual + penyesuaian saldo`. Setoran UKT dan dana darurat adalah transfer internal sehingga tidak mengurangi saldo aktual dan tidak masuk sebagai pengeluaran konsumsi. Pembayaran UKT, pembayaran cicilan, dan penggunaan dana darurat menghasilkan satu transaksi pengeluaran terhubung. Operasi terhubung dijalankan dalam transaksi PostgreSQL agar tidak terjadi pencatatan setengah jadi atau penghitungan ganda.

Semua nominal disimpan sebagai `BIGINT` dalam satuan rupiah utuh. Backend menggunakan `BigInt` untuk validasi dan perhitungan; tipe pecahan tidak digunakan untuk nominal uang.

## Menjalankan aplikasi

1. Gunakan Node.js 20 LTS atau lebih baru.
2. Buat database Neon PostgreSQL kosong.
3. Jalankan isi `schema.sql` melalui Neon SQL Editor atau klien PostgreSQL.
4. Salin `.env.example` menjadi `.env`.
5. Isi `DATABASE_URL`, `JWT_SECRET`, dan `COOKIE_SECRET`. Gunakan secret acak minimal 32 karakter.
6. Sesuaikan `APP_ORIGIN` dengan origin aplikasi. Pada lokal gunakan `http://localhost:3000`.
7. Jalankan perintah berikut:

```bash
npm install
npm run dev
```

Buka `http://localhost:3000/signin`. Registrasi hanya dapat dilakukan saat tabel `users` masih kosong. Akun pertama otomatis menjadi admin dan registrasi berikutnya ditutup.

## Environment variable

| Nama | Keterangan |
| --- | --- |
| `PORT` | Port server, default `3000` |
| `NODE_ENV` | `development`, `test`, atau `production` |
| `DATABASE_URL` | Connection string PostgreSQL Neon |
| `JWT_SECRET` | Secret JWT minimal 32 karakter |
| `JWT_EXPIRES_IN` | Masa berlaku JWT, default `7d` |
| `COOKIE_SECRET` | Secret cookie minimal 32 karakter |
| `APP_ORIGIN` | Origin yang diizinkan mengirim mutasi data |
| `DATABASE_SSL` | Gunakan `true` untuk Neon |
| `TEST_DATABASE_URL` | Database terpisah khusus integration test |

Jangan memakai database produksi sebagai `TEST_DATABASE_URL` karena integration test mengosongkan tabel sebelum dan sesudah pengujian.

## Pengujian

Pengujian helper dan show/hide password dapat dijalankan tanpa database. Integration test otomatis dilewati jika `TEST_DATABASE_URL` belum diisi.

```bash
npm test
```

Integration test mencakup proteksi route, register, signin, pembatasan akun utama, CRUD transaksi, pencatatan utang dan cicilan atomik, target UKT, dana darurat, perubahan saldo setelah edit/hapus, export CSV, logout, serta isolasi data antar pengguna.

## Endpoint utama

- `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`
- `GET|POST /api/transactions`, `PUT|DELETE /api/transactions/:id`
- `GET|POST /api/categories`, `DELETE /api/categories/:id`
- `GET|POST /api/debts`, `PUT|DELETE /api/debts/:id`
- `GET|POST /api/debts/:id/payments`, `PUT|DELETE /api/debts/:debtId/payments/:paymentId`
- `GET|POST /api/goals`, `PUT|DELETE /api/goals/:id`
- `GET|POST /api/goals/:id/entries`, `PUT|DELETE /api/goals/:goalId/entries/:entryId`
- `GET|POST /api/balance-adjustments`, `DELETE /api/balance-adjustments/:id`
- `GET /api/dashboard`, `GET /api/statistics`, `GET /api/reports/monthly`

## Keamanan

JWT disimpan dalam cookie `HttpOnly`, `Secure` saat production, dan `SameSite=Strict`. Mutasi data memakai token CSRF double-submit. Seluruh endpoint privat memverifikasi JWT dan mengambil user ID dari token, bukan dari frontend. Query menggunakan parameter PostgreSQL. Login dibatasi dengan rate limiter, password di-hash memakai bcrypt, body request dibatasi, dan pesan error database tidak dikirim ke browser.
