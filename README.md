# CloudPool (Node.js + PostgreSQL)

Gabungkan beberapa Google Drive menjadi satu penyimpanan. Upload otomatis masuk ke drive dengan ruang kosong terbesar yang cukup.

## 1. Google Cloud (sekali saja)
1. Buat project di https://console.cloud.google.com dan aktifkan **Google Drive API**.
2. OAuth consent screen: isi nama aplikasi dan email. Selama status "Testing", tambahkan semua akun Google Anda sebagai Test users dan ketahui bahwa token kedaluwarsa tiap 7 hari. Ubah ke "In production" agar permanen.
3. Credentials > OAuth client ID > Web application. Authorized redirect URI: `https://DOMAIN-ANDA/api/google/callback`.

## 2. Deploy di VPS (Docker)
Prasyarat: VPS dengan Docker + Docker Compose, domain yang A record-nya mengarah ke IP VPS, port 80 dan 443 terbuka.
```
cp .env.example .env      # isi semua nilainya
docker compose up -d --build
docker compose logs -f app
```
Buka `https://DOMAIN-ANDA`, daftar, lalu hubungkan akun Google satu per satu. Setelah akun Anda terdaftar, set `ALLOW_REGISTER=false` dan jalankan `docker compose up -d`.

## Perawatan
- Backup database: `docker compose exec db pg_dump -U cloudpool cloudpool > backup.sql`
- Update: `git pull && docker compose up -d --build`
- Simpan `ENC_KEY` dengan aman. Jika hilang, semua akun Google harus dihubungkan ulang.

## Tanpa Docker
Butuh Node.js 18+ dan PostgreSQL 13+. Isi `.env` (termasuk `DATABASE_URL`), lalu `npm install && npm start`. Pasang reverse proxy HTTPS (Caddy/Nginx) di depannya.
