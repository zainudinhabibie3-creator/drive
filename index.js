const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');
const { OAuth2Client } = require('google-auth-library');
const { drive: gdrive } = require('@googleapis/drive');

const BASE = (process.env.BASE_URL || '').replace(/\/$/, '');
const JWT_SECRET = process.env.JWT_SECRET || '';
if (!BASE || JWT_SECRET.length < 32 || !process.env.DATABASE_URL) {
  throw new Error('Environment variable BASE_URL, JWT_SECRET (min. 32 karakter), dan DATABASE_URL wajib diisi');
}
const KEY = crypto.createHash('sha256').update(process.env.ENC_KEY || JWT_SECRET).digest();

// ---------- Database (PostgreSQL / Neon) ----------
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3, idleTimeoutMillis: 10000 });
const q = (text, params) => pool.query(text, params);
let ready;
const init = () => ready || (ready = q(`
  CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL, hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now());
  CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL, refresh_token TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (user_id, email));
  CREATE TABLE IF NOT EXISTS files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    drive_file_id TEXT NOT NULL, name TEXT NOT NULL, size BIGINT NOT NULL, mime TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (account_id, drive_file_id));
  CREATE INDEX IF NOT EXISTS files_user_idx ON files(user_id, created_at DESC);
  CREATE TABLE IF NOT EXISTS attempts (key TEXT NOT NULL, ts TIMESTAMPTZ NOT NULL DEFAULT now());
  CREATE INDEX IF NOT EXISTS attempts_idx ON attempts(key, ts);`).catch((e) => { ready = null; throw e; }));

// Pembatas percobaan login/daftar (disimpan di DB karena serverless tidak berbagi memori)
const tooMany = async (req, k) => (await q("SELECT count(*)::int AS c FROM attempts WHERE key=$1 AND ts > now() - interval '15 minutes'", [`${req.ip}|${k}`])).rows[0].c >= 10;
const note = async (req, k) => { await q("DELETE FROM attempts WHERE ts < now() - interval '1 day'"); await q('INSERT INTO attempts(key) VALUES($1)', [`${req.ip}|${k}`]); };

// ---------- Enkripsi refresh token (AES-256-GCM) ----------
const enc = (t) => {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const d = Buffer.concat([c.update(t, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), d].map((b) => b.toString('base64')).join('.');
};
const dec = (s) => {
  const [iv, tag, d] = s.split('.').map((x) => Buffer.from(x, 'base64'));
  const c = crypto.createDecipheriv('aes-256-gcm', KEY, iv); c.setAuthTag(tag);
  return Buffer.concat([c.update(d), c.final()]).toString('utf8');
};

// ---------- Google ----------
const oauth = () => new OAuth2Client(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, `${BASE}/api/google/callback`);
const clientFor = (acc) => { const o = oauth(); o.setCredentials({ refresh_token: dec(acc.refresh_token) }); return o; };
const driveFor = (acc) => gdrive({ version: 'v3', auth: clientFor(acc) });
async function quota(acc) {
  const s = (await driveFor(acc).about.get({ fields: 'storageQuota' })).data.storageQuota;
  const limit = s.limit ? Number(s.limit) : null; // null = tanpa batas (Workspace)
  const usage = Number(s.usage);
  return { limit, usage, free: limit === null ? Number.MAX_SAFE_INTEGER : limit - usage };
}

// ---------- App ----------
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(cookieParser());
const h = (fn) => (req, res, next) => fn(req, res, next).catch(next);
app.use('/api', h(async (req, res, next) => { await init(); next(); }));

const setCookie = (res, userId) => res.cookie('t', jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: '7d' }),
  { httpOnly: true, sameSite: 'lax', secure: true, maxAge: 7 * 864e5 });
const auth = (req, res, next) => {
  try { req.uid = jwt.verify(req.cookies.t, JWT_SECRET).uid; next(); }
  catch { res.status(401).json({ error: 'Belum login' }); }
};

app.post('/api/register', h(async (req, res) => {
  if (process.env.ALLOW_REGISTER === 'false') return res.status(403).json({ error: 'Pendaftaran ditutup' });
  if (await tooMany(req, 'reg')) return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi nanti.' });
  await note(req, 'reg');
  const { username, password } = req.body || {};
  if (!username || username.length > 50 || !password || password.length < 8) return res.status(400).json({ error: 'Username wajib diisi, password minimal 8 karakter' });
  try {
    const r = await q('INSERT INTO users(username, hash) VALUES($1,$2) RETURNING id', [username, await bcrypt.hash(password, 10)]);
    setCookie(res, r.rows[0].id); res.json({ username });
  } catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'Username sudah dipakai' }); throw e; }
}));
app.post('/api/login', h(async (req, res) => {
  if (await tooMany(req, 'login')) return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.' });
  const { username, password } = req.body || {};
  const u = (await q('SELECT id, hash FROM users WHERE username=$1', [username || ''])).rows[0];
  if (!u || !(await bcrypt.compare(password || '', u.hash))) { await note(req, 'login'); return res.status(401).json({ error: 'Username atau password salah' }); }
  setCookie(res, u.id); res.json({ username });
}));
app.post('/api/logout', (req, res) => { res.clearCookie('t'); res.json({ ok: true }); });
app.get('/api/me', auth, h(async (req, res) => {
  const u = (await q('SELECT username FROM users WHERE id=$1', [req.uid])).rows[0];
  if (!u) return res.status(401).json({ error: 'Belum login' });
  res.json({ username: u.username });
}));

// ---------- Hubungkan akun Google ----------
app.get('/api/google/connect', auth, (req, res) => {
  const state = jwt.sign({ uid: req.uid }, JWT_SECRET, { expiresIn: '10m' });
  res.redirect(oauth().generateAuthUrl({
    access_type: 'offline', prompt: 'consent', state,
    scope: ['https://www.googleapis.com/auth/drive.file', 'https://www.googleapis.com/auth/userinfo.email'],
  }));
});
app.get('/api/google/callback', async (req, res) => {
  try {
    await init();
    const { uid } = jwt.verify(req.query.state, JWT_SECRET);
    const { tokens } = await oauth().getToken(req.query.code);
    if (!tokens.refresh_token) throw new Error('Google tidak mengirim refresh token. Cabut akses aplikasi di akun Google lalu coba lagi.');
    const info = await (await fetch('https://www.googleapis.com/oauth2/v2/userinfo', { headers: { Authorization: `Bearer ${tokens.access_token}` } })).json();
    if (!info.email) throw new Error('Gagal membaca email akun Google');
    await q(`INSERT INTO accounts(user_id, email, refresh_token) VALUES($1,$2,$3)
             ON CONFLICT (user_id, email) DO UPDATE SET refresh_token = EXCLUDED.refresh_token`, [uid, info.email, enc(tokens.refresh_token)]);
    res.redirect('/?connected=1');
  } catch (e) { res.redirect('/?error=' + encodeURIComponent(e.message)); }
});

app.get('/api/accounts', auth, h(async (req, res) => {
  const rows = (await q('SELECT id, email, refresh_token FROM accounts WHERE user_id=$1 ORDER BY created_at', [req.uid])).rows;
  res.json(await Promise.all(rows.map(async (a) => {
    try { return { id: a.id, email: a.email, ok: true, ...(await quota(a)) }; }
    catch { return { id: a.id, email: a.email, ok: false }; }
  })));
}));
app.delete('/api/accounts/:id', auth, h(async (req, res) => {
  await q('DELETE FROM accounts WHERE id=$1 AND user_id=$2', [req.params.id, req.uid]);
  res.json({ ok: true });
}));

// ---------- File ----------
app.get('/api/files', auth, h(async (req, res) => {
  const r = await q(`SELECT f.id, f.name, f.size, f.mime, a.email AS drive, f.created_at
                     FROM files f JOIN accounts a ON a.id = f.account_id
                     WHERE f.user_id=$1 ORDER BY f.created_at DESC`, [req.uid]);
  res.json(r.rows.map((f) => ({ ...f, size: Number(f.size) })));
}));

// Langkah 1 upload: pilih drive dengan ruang kosong terbesar yang cukup, lalu buat sesi upload langsung ke Google.
// File dikirim browser langsung ke Google (tidak lewat Vercel) sehingga tidak terkena batas 4,5 MB.
app.post('/api/uploads/init', auth, h(async (req, res) => {
  const { name, size, mime } = req.body || {};
  const n = Number(size);
  if (!name || !(n >= 0)) return res.status(400).json({ error: 'Data file tidak valid' });
  const accs = (await q('SELECT id, email, refresh_token FROM accounts WHERE user_id=$1', [req.uid])).rows;
  if (!accs.length) return res.status(400).json({ error: 'Hubungkan minimal satu akun Google dulu' });
  const qs = await Promise.all(accs.map(async (a) => { try { return { a, ...(await quota(a)) }; } catch { return null; } }));
  const cand = qs.filter((x) => x && x.free >= n).sort((x, y) => y.free - x.free);
  if (!cand.length) return res.status(507).json({ error: 'Tidak ada drive dengan ruang kosong yang cukup' });
  let lastErr;
  for (const c of cand) {
    try {
      const { token } = await clientFor(c.a).getAccessToken();
      const r = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&fields=id', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json; charset=UTF-8',
          'X-Upload-Content-Type': mime || 'application/octet-stream',
          'X-Upload-Content-Length': String(n),
          Origin: new URL(BASE).origin, // agar Google mengizinkan CORS dari halaman ini
        },
        body: JSON.stringify({ name }),
      });
      if (!r.ok) throw new Error(`Google menolak (${r.status})`);
      return res.json({ uploadUrl: r.headers.get('location'), accountId: c.a.id, drive: c.a.email });
    } catch (e) { lastErr = e; }
  }
  res.status(502).json({ error: 'Gagal memulai upload: ' + lastErr.message });
}));

// Langkah 2 upload: catat file ke database setelah browser selesai mengunggah. Metadata diverifikasi ke Google.
app.post('/api/files/complete', auth, h(async (req, res) => {
  const { accountId, driveFileId } = req.body || {};
  const acc = driveFileId && (await q('SELECT id, email, refresh_token FROM accounts WHERE id=$1 AND user_id=$2', [accountId, req.uid])).rows[0];
  if (!acc) return res.status(400).json({ error: 'Data tidak valid' });
  const m = (await driveFor(acc).files.get({ fileId: driveFileId, fields: 'id,name,size,mimeType' })).data;
  const ins = await q(`INSERT INTO files(user_id, account_id, drive_file_id, name, size, mime) VALUES($1,$2,$3,$4,$5,$6)
                       ON CONFLICT (account_id, drive_file_id) DO UPDATE SET name = EXCLUDED.name RETURNING id`,
    [req.uid, acc.id, m.id, m.name, Number(m.size || 0), m.mimeType]);
  res.json({ id: ins.rows[0].id, name: m.name, size: Number(m.size || 0), drive: acc.email });
}));

const getFile = async (id, userId) => (await q(
  `SELECT f.id, f.name, f.mime, f.drive_file_id, a.refresh_token
   FROM files f JOIN accounts a ON a.id = f.account_id WHERE f.id=$1 AND f.user_id=$2`, [id, userId])).rows[0];

app.get('/api/files/:id/download', auth, h(async (req, res) => {
  const f = await getFile(req.params.id, req.uid);
  if (!f) return res.status(404).json({ error: 'File tidak ditemukan' });
  const r = await driveFor(f).files.get({ fileId: f.drive_file_id, alt: 'media' }, { responseType: 'stream' });
  res.setHeader('Content-Type', f.mime || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(f.name)}`);
  r.data.on('error', () => res.destroy()).pipe(res);
}));

app.delete('/api/files/:id', auth, h(async (req, res) => {
  const f = await getFile(req.params.id, req.uid);
  if (!f) return res.status(404).json({ error: 'File tidak ditemukan' });
  try { await driveFor(f).files.delete({ fileId: f.drive_file_id }); }
  catch (e) { if (e.code !== 404) return res.status(502).json({ error: e.message }); }
  await q('DELETE FROM files WHERE id=$1', [f.id]);
  res.json({ ok: true });
}));

app.use((e, req, res, next) => {
  if (e.code === '22P02') return res.status(404).json({ error: 'Tidak ditemukan' });
  console.error(e); res.status(500).json({ error: 'Terjadi kesalahan pada server' });
});

module.exports = app;
