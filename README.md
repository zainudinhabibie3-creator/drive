# CloudPool untuk Vercel

Gabungkan beberapa Google Drive menjadi satu penyimpanan. Upload otomatis masuk ke drive dengan ruang kosong terbesar yang cukup.

Struktur: `public/index.html` (tampilan) dan `api/index.js` (Express sebagai serverless function). Database: PostgreSQL (Neon).

## 1. Unggah ke GitHub
```
git init
git add .
git commit -m "CloudPool"
git branch -M main
git remote add origin https://github.com/USERNAME/cloudpool.git
git push -u origin main
```
Gunakan repository **private**. File `.env` sudah masuk `.gitignore`, jangan pernah di-commit.

## 2. Deploy di Vercel
1. vercel.com > Add New > Project > import repository tadi > Deploy (gagal/error karena env belum diisi itu normal).
2. Tab **Storage** > buat database **Neon (Postgres)** dan hubungkan ke project. `DATABASE_URL` terisi otomatis.
3. Settings > Environment Variables, isi: `BASE_URL`, `JWT_SECRET`, `ENC_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `ALLOW_REGISTER=true`.
   Buat secret dengan `openssl rand -hex 32`. `BASE_URL` adalah URL production, mis. `https://cloudpool.vercel.app` (tanpa garis miring akhir).
4. Deployments > Redeploy.

## 3. Google Cloud
1. Aktifkan **Google Drive API**.
2. OAuth consent screen: tambahkan semua akun Google Anda sebagai Test users. Ubah ke "In production" agar token tidak kedaluwarsa 7 hari.
3. Credentials > OAuth client ID > Web application > Authorized redirect URI: `BASE_URL/api/google/callback`.

Buka `BASE_URL`, daftar, hubungkan akun Google satu per satu, lalu set `ALLOW_REGISTER=false` dan redeploy.

## Catatan
- Upload dikirim browser langsung ke Google (lewat sesi upload yang dibuat server), jadi tidak terkena batas 4,5 MB Vercel.
- Download dialirkan lewat Vercel dan dibatasi `maxDuration` 60 detik di `vercel.json`. File yang sangat besar dan koneksi lambat bisa terputus.
- Login Google hanya berfungsi di URL production yang sama dengan `BASE_URL`, bukan di URL preview.
