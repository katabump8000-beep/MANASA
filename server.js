import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import rateLimit from 'express-rate-limit';
import argon2 from 'argon2';
import { z } from 'zod';
import { pool } from './db.js';

const app = express();
const port = Number(process.env.PORT || 8080);
const PgSession = connectPgSimple(session);
const production = process.env.NODE_ENV === 'production';

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters');
if (!process.env.FRONTEND_ORIGIN) throw new Error('FRONTEND_ORIGIN is required');
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_ORIGIN.split(',').map(s => s.trim()), credentials: true, methods: ['GET','POST','DELETE','PATCH','OPTIONS'], allowedHeaders: ['Content-Type','X-CSRF-Token'] }));
app.use(express.json({ limit: '32kb' }));
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'jes.sid', secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: production, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 8 }
}));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false }));

const fail = (res, status, error) => res.status(status).json({ error });
const authenticated = (req, res, next) => req.session.adminId ? next() : fail(res, 401, 'يلزم تسجيل الدخول');
const setupEnabled = () => process.env.ALLOW_ADMIN_SETUP === 'true' && Boolean(process.env.ADMIN_SETUP_KEY);

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ api: 'online', database: 'online', runtime: 'not_configured' }); }
  catch { res.status(503).json({ api: 'online', database: 'offline', runtime: 'not_configured' }); }
});

app.get('/api/auth/setup-status', async (_req, res) => {
  try {
    const q = await pool.query('SELECT EXISTS(SELECT 1 FROM admins) AS exists');
    res.json({ setupAllowed: setupEnabled() && !q.rows[0].exists, adminExists: q.rows[0].exists });
  } catch { fail(res, 503, 'قاعدة البيانات غير جاهزة'); }
});

app.post('/api/auth/setup', async (req, res) => {
  if (!setupEnabled()) return fail(res, 403, 'إعداد الإدارة معطّل في الخادم');
  const schema = z.object({ setupKey: z.string().min(20).max(256), username: z.string().trim().min(3).max(40).regex(/^[a-zA-Z0-9_-]+$/), password: z.string().min(12).max(256) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'تحقق من اسم المستخدم وكلمة المرور ومفتاح الإعداد');
  if (parsed.data.setupKey !== process.env.ADMIN_SETUP_KEY) return fail(res, 403, 'مفتاح الإعداد غير صحيح');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('LOCK TABLE admins IN EXCLUSIVE MODE');
    const existing = await client.query('SELECT id FROM admins LIMIT 1');
    if (existing.rowCount) { await client.query('ROLLBACK'); return fail(res, 409, 'تم إنشاء حساب الإدارة مسبقًا'); }
    const hash = await argon2.hash(parsed.data.password, { type: argon2.argon2id });
    const created = await client.query('INSERT INTO admins(username,password_hash) VALUES($1,$2) RETURNING id, username', [parsed.data.username, hash]);
    await client.query('COMMIT');
    req.session.adminId = created.rows[0].id;
    req.session.username = created.rows[0].username;
    res.status(201).json({ admin: { username: created.rows[0].username } });
  } catch (e) { await client.query('ROLLBACK'); if (e.code === '23505') return fail(res, 409, 'اسم المستخدم مستخدم'); fail(res, 500, 'تعذر إنشاء حساب الإدارة'); }
  finally { client.release(); }
});

app.post('/api/auth/login', async (req, res) => {
  const parsed = z.object({ username: z.string().min(1).max(40), password: z.string().min(1).max(256) }).safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'أدخل اسم المستخدم وكلمة المرور');
  try {
    const q = await pool.query('SELECT id, username, password_hash FROM admins WHERE username=$1', [parsed.data.username]);
    if (!q.rowCount || !(await argon2.verify(q.rows[0].password_hash, parsed.data.password))) return fail(res, 401, 'بيانات الدخول غير صحيحة');
    await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
    req.session.adminId = q.rows[0].id; req.session.username = q.rows[0].username;
    res.json({ admin: { username: q.rows[0].username } });
  } catch { fail(res, 500, 'تعذر تسجيل الدخول'); }
});
app.post('/api/auth/logout', (req, res) => req.session.destroy(err => { if (err) return fail(res, 500, 'تعذر إنهاء الجلسة'); res.clearCookie('jes.sid', { httpOnly: true, secure: production, sameSite: 'lax' }); res.json({ ok: true }); }));
app.get('/api/auth/me', authenticated, (req, res) => res.json({ admin: { username: req.session.username } }));

app.get('/api/projects', authenticated, async (_req, res) => {
  try { const q = await pool.query('SELECT id,name,project_type,entry_file,ram_mb,storage_mb,cpu_target_percent,runtime_status,created_at,updated_at FROM projects ORDER BY created_at DESC'); res.json({ projects: q.rows }); }
  catch { fail(res, 500, 'تعذر جلب المشاريع'); }
});
app.post('/api/projects', authenticated, async (req, res) => {
  const schema = z.object({ name: z.string().trim().min(2).max(48).regex(/^[\p{L}\p{N} _.-]+$/u), projectType: z.enum(['telegram','whatsapp','nodejs']).default('nodejs'), entryFile: z.string().trim().min(1).max(120).default('index.js'), ramMb: z.number().int().min(128).max(65536).default(1024), storageMb: z.number().int().min(128).max(1048576).default(2048), cpuTargetPercent: z.number().int().min(1).max(100).default(25) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return fail(res, 400, 'بيانات المشروع غير صالحة');
  if (parsed.data.entryFile.startsWith('/') || parsed.data.entryFile.split(/[\\/]/).includes('..')) return fail(res, 400, 'مسار ملف التشغيل غير صالح');
  const nameKey = parsed.data.name.normalize('NFKC').toLocaleLowerCase('en-US');
  try {
    const p = parsed.data;
    const q = await pool.query('INSERT INTO projects(name,name_key,project_type,entry_file,ram_mb,storage_mb,cpu_target_percent) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,name,project_type,entry_file,ram_mb,storage_mb,cpu_target_percent,runtime_status,created_at,updated_at', [p.name,nameKey,p.projectType,p.entryFile,p.ramMb,p.storageMb,p.cpuTargetPercent]);
    res.status(201).json({ project: q.rows[0], notice: 'تم إنشاء سجل المشروع. ربط محرك التشغيل مطلوب لإنشاء بيئة ملفات قابلة للتشغيل.' });
  } catch (e) { if (e.code === '23505') return fail(res, 409, 'اسم المشروع مستخدم بالفعل'); fail(res, 500, 'تعذر إنشاء المشروع'); }
});
app.delete('/api/projects/:id', authenticated, async (req, res) => {
  const valid = z.string().uuid().safeParse(req.params.id); if (!valid.success) return fail(res, 400, 'معرّف المشروع غير صالح');
  try { const q = await pool.query('DELETE FROM projects WHERE id=$1 RETURNING id', [valid.data]); if (!q.rowCount) return fail(res, 404, 'المشروع غير موجود'); res.json({ ok: true }); }
  catch { fail(res, 500, 'تعذر حذف المشروع'); }
});

app.use((err, _req, res, _next) => { if (res.headersSent) return; res.status(500).json({ error: 'حدث خطأ داخلي غير متوقع' }); });
app.listen(port, () => console.log(`J.E.S HOST API listening on ${port}`));
