require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const { google } = require('googleapis');

const PORT = process.env.PORT || 3000;
const BASE = process.env.BASE_URL || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) { console.error('JWT_SECRET wajib diisi (min. 32 karakter)'); process.exit(1); }
if (!process.env.DATABASE_URL) { console.error('DATABASE_URL wajib diisi'); process.exit(1); }
const KEY = crypto.createHash('sha256').update(process.env.ENC_KEY || JWT_SECRET).digest();
const MAX_MB = Number(process.env.MAX_UPLOAD_MB || 2048);
const TMP = path.join(__dirname, 'tmp');
fs.mkdirSync(TMP, { recursive: true });

// ---------- Database (PostgreSQL) ----------
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const q = (text, params) => pool.query(text, params);
async function initDb() {
  for (let i = 0; i < 30; i++) {
    try {
      await q(`
        CREATE TABLE IF NOT EXISTS users (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          username TEXT UNIQUE NOT NULL,
          hash TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE TABLE IF NOT EXISTS accounts (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          email TEXT NOT NULL,
          refresh_token TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          UNIQUE (user_id, email)
        );
        CREATE TABLE IF NOT EXISTS files (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
          drive_file_id TEXT NOT NULL,
          name TEXT NOT NULL,
          size BIGINT NOT NULL,
          mime TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS files_user_idx ON files(user_id, created_at DESC);`);
      return;
    } catch (e) { console.log('Menunggu database...', e.code || e.message); await new Promise((r) => setTimeout(r, 2000)); }
  }
  throw new Error('Database tidak dapat dihubungi');
}

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
const oauth = () => new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, `${BASE}/api/google/callback`);
const driveFor = (acc) => { const o = oauth(); o.setCredentials({ refresh_token: dec(acc.refresh_token) }); return google.drive({ version: 'v3', auth: o }); };
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
app.use(express.static(path.join(__dirname, 'public')));
const upload = multer({ dest: TMP, limits: { fileSize: MAX_MB * 1024 * 1024 } });
const h = (fn) => (req, res, next) => fn(req, res, next).catch(next);
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Terlalu banyak percobaan. Coba lagi beberapa menit lagi.' } });

const setCookie = (res, userId) => res.cookie('t', jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: '7d' }),
  { httpOnly: true, sameSite: 'lax', secure: BASE.startsWith('https'), maxAge: 7 * 864e5 });
const auth = (req, res, next) => {
  try { req.uid = jwt.verify(req.cookies.t, JWT_SECRET).uid; next(); }
  catch { res.status(401).json({ error: 'Belum login' }); }
};

app.get('/healthz', h(async (req, res) => { await q('SELECT 1'); res.json({ ok: true }); }));

app.post('/api/register', authLimit, h(async (req, res) => {
  if (process.env.ALLOW_REGISTER === 'false') return res.status(403).json({ error: 'Pendaftaran ditutup' });
  const { username, password } = req.body || {};
  if (!username || username.length > 50 || !password || password.length < 8) return res.status(400).json({ error: 'Username wajib diisi, password minimal 8 karakter' });
  try {
    const r = await q('INSERT INTO users(username, hash) VALUES($1,$2) RETURNING id', [username, await bcrypt.hash(password, 12)]);
    setCookie(res, r.rows[0].id); res.json({ username });
  } catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'Username sudah dipakai' }); throw e; }
}));
app.post('/api/login', authLimit, h(async (req, res) => {
  const { username, password } = req.body || {};
  const u = (await q('SELECT id, hash FROM users WHERE username=$1', [username || ''])).rows[0];
  if (!u || !(await bcrypt.compare(password || '', u.hash))) return res.status(401).json({ error: 'Username atau password salah' });
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
    const { uid } = jwt.verify(req.query.state, JWT_SECRET);
    const o = oauth();
    const { tokens } = await o.getToken(req.query.code);
    if (!tokens.refresh_token) throw new Error('Google tidak mengirim refresh token. Cabut akses aplikasi di akun Google lalu coba lagi.');
    o.setCredentials(tokens);
    const email = (await google.oauth2({ version: 'v2', auth: o }).userinfo.get()).data.email;
    await q(`INSERT INTO accounts(user_id, email, refresh_token) VALUES($1,$2,$3)
             ON CONFLICT (user_id, email) DO UPDATE SET refresh_token = EXCLUDED.refresh_token`, [uid, email, enc(tokens.refresh_token)]);
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
  await q('DELETE FROM accounts WHERE id=$1 AND user_id=$2', [req.params.id, req.uid]); // file terkait ikut terhapus dari indeks
  res.json({ ok: true });
}));

// ---------- File ----------
app.get('/api/files', auth, h(async (req, res) => {
  const r = await q(`SELECT f.id, f.name, f.size, f.mime, a.email AS drive, f.created_at
                     FROM files f JOIN accounts a ON a.id = f.account_id
                     WHERE f.user_id=$1 ORDER BY f.created_at DESC`, [req.uid]);
  res.json(r.rows.map((f) => ({ ...f, size: Number(f.size) })));
}));

// Upload: otomatis pilih drive dengan ruang kosong terbesar yang cukup untuk file
app.post('/api/files', auth, upload.single('file'), h(async (req, res) => {
  const f = req.file;
  if (!f) return res.status(400).json({ error: 'File tidak ada' });
  try {
    const accs = (await q('SELECT id, email, refresh_token FROM accounts WHERE user_id=$1', [req.uid])).rows;
    if (!accs.length) return res.status(400).json({ error: 'Hubungkan minimal satu akun Google dulu' });
    const qs = await Promise.all(accs.map(async (a) => { try { return { a, ...(await quota(a)) }; } catch { return null; } }));
    const cand = qs.filter((x) => x && x.free >= f.size).sort((x, y) => y.free - x.free);
    if (!cand.length) return res.status(507).json({ error: 'Tidak ada drive dengan ruang kosong yang cukup' });
    const name = Buffer.from(f.originalname, 'latin1').toString('utf8');
    let lastErr;
    for (const c of cand) { // jika satu drive gagal, coba drive berikutnya
      try {
        const r = await driveFor(c.a).files.create({
          requestBody: { name },
          media: { mimeType: f.mimetype, body: fs.createReadStream(f.path) },
          fields: 'id',
        });
        const ins = await q('INSERT INTO files(user_id, account_id, drive_file_id, name, size, mime) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',
          [req.uid, c.a.id, r.data.id, name, f.size, f.mimetype]);
        return res.json({ id: ins.rows[0].id, name, size: f.size, drive: c.a.email });
      } catch (e) { lastErr = e; }
    }
    res.status(502).json({ error: 'Upload gagal: ' + lastErr.message });
  } finally { fs.unlink(f.path, () => {}); }
}));

const getFile = async (id, userId) => (await q(
  `SELECT f.id, f.name, f.mime, f.drive_file_id, a.id AS account_id, a.refresh_token
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
  if (e.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: `File melebihi batas ${MAX_MB} MB` });
  if (e.code === '22P02') return res.status(404).json({ error: 'Tidak ditemukan' });
  console.error(e); res.status(500).json({ error: 'Terjadi kesalahan pada server' });
});

initDb().then(() => {
  const srv = app.listen(PORT, () => console.log(`CloudPool berjalan di ${BASE}`));
  const stop = () => srv.close(() => pool.end().then(() => process.exit(0)));
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
}).catch((e) => { console.error(e.message); process.exit(1); });
