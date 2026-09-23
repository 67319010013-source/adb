require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { createClient } = require('@libsql/client');
const Tesseract = require('tesseract.js'); // เพิ่มไลบรารี AI อ่านตัวอักษร

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// CONFIG
// ============================================================
const AMOUNT = 500;                            // ราคา 1 บาท
const DURATION_MS = 24 * 60 * 60 * 1000;     // 24 ชั่วโมง
const PAYMENT_TIMEOUT_MS = 30 * 60 * 1000;   // payment intent หมดอายุใน 30 นาที
const ADMIN_DEFAULT_USER = 'admin';
const ADMIN_DEFAULT_PASS = '0647748563';

// กำหนดเลขบัญชีที่ต้องการเช็คจากไฟล์ .env
const EXPECTED_ACCOUNT = process.env.RECEIVER_ACCOUNT || '';

// ตั้งค่าการอัปโหลดไฟล์เก็บไว้ในหน่วยความจำชั่วคราว
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB
  fileFilter: (req, file, cb) => {
    if (!/^image\//.test(file.mimetype)) return cb(new Error('ต้องเป็นไฟล์รูปภาพเท่านั้น'));
    cb(null, true);
  }
});

// ============================================================
// TURSO CONNECTION & DB INIT
// ============================================================
const turso = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

async function dbGet(sql, args = []) {
  const r = await turso.execute({ sql, args });
  return r.rows[0] || null;
}
async function dbAll(sql, args = []) {
  const r = await turso.execute({ sql, args });
  return r.rows;
}
async function dbRun(sql, args = []) {
  return await turso.execute({ sql, args });
}

const PUBLIC_DIR = path.join(__dirname, 'public');
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });

async function initDB() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      status TEXT NOT NULL DEFAULT 'unpaid',
      paid_at INTEGER,
      expires_at INTEGER,
      transaction_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_by TEXT
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS payment_intents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ref TEXT UNIQUE NOT NULL,
      username TEXT NOT NULL,
      amount INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at INTEGER NOT NULL,
      paid_at INTEGER,
      transaction_id TEXT,
      slip_trans_ref TEXT
    )
  `);

  try { await dbRun(`ALTER TABLE payment_intents ADD COLUMN slip_trans_ref TEXT`); } catch (e) {}

  await dbRun(`CREATE INDEX IF NOT EXISTS idx_payment_ref ON payment_intents(ref)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_payment_username ON payment_intents(username)`);

  const admin = await dbGet('SELECT 1 FROM users WHERE username=?', [ADMIN_DEFAULT_USER]);
  if (!admin) {
    const hash = bcrypt.hashSync(ADMIN_DEFAULT_PASS, 10);
    await dbRun(
      `INSERT INTO users (username,password_hash,role,status,created_by) VALUES (?,?,?,?,?)`,
      [ADMIN_DEFAULT_USER, hash, 'admin', 'paid', 'system']
    );
  }
}

// ============================================================
// MIDDLEWARE & GUARDS
// ============================================================
app.set('trust proxy', 1);

app.use(session({
  name: 'fd.sid',
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,          // ← คงไว้ false เพราะ Render proxy
    sameSite: 'lax',        // ← ✅ เพิ่มบรรทัดนี้
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ ok: false, msg: 'กรุณาเข้าสู่ระบบ' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin')
    return res.status(403).json({ ok: false, msg: 'ต้องเป็นแอดมินเท่านั้น' });
  next();
}

// ============================================================
// AUTH & BASIC API
// ============================================================
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.get('/api/me', requireLogin, async (req, res) => {
  const u = await dbGet('SELECT * FROM users WHERE username=?', [req.session.user.username]);
  if (!u) { req.session.destroy(()=>{}); return res.json({ ok: false, msg: 'บัญชีถูกลบ' }); }

  let status = u.status;
  const now = Date.now();
  if (u.role !== 'admin' && status === 'paid' && u.expires_at && u.expires_at <= now) {
    await dbRun('UPDATE users SET status=? WHERE id=?', ['expired', u.id]);
    status = 'expired';
  }
  res.json({ ok: true, user: { username: u.username, role: u.role, status, expiresAt: u.expires_at, remainingMs: u.expires_at > now ? u.expires_at - now : 0 }});
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = await dbGet('SELECT * FROM users WHERE username=?', [username]);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.json({ ok: false, msg: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
  
  req.session.user = { username: user.username, role: user.role };
  req.session.save(() => res.json({
     ok: true,
     user: {                                    
      username: user.username,
      role: user.role,
      status: user.status,
      expiresAt: user.expires_at
    } 
    }));
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || password.length < 4) return res.json({ ok: false, msg: 'ข้อมูลไม่ถูกต้อง' });
  const exists = await dbGet('SELECT 1 FROM users WHERE username=?', [username]);
  if (exists) return res.json({ ok: false, msg: 'ชื่อนี้มีอยู่แล้ว' });

  const hash = bcrypt.hashSync(password, 10);
  await dbRun(`INSERT INTO users (username,password_hash,role,status,created_by) VALUES (?,?,?,?,?)`, [username, hash, 'user', 'unpaid', 'self']);
  req.session.user = { username, role: 'user' };
  req.session.save(() => res.json({ ok: true }));
});

app.post('/api/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });

// ============================================================
// PAYMENT & OCR VERIFICATION API
// ============================================================
app.post('/api/create-payment', requireLogin, async (req, res) => {
  const username = req.session.user.username;
  const existing = await dbGet(`SELECT * FROM payment_intents WHERE username=? AND status='pending' AND created_at > ? ORDER BY id DESC LIMIT 1`, [username, Date.now() - PAYMENT_TIMEOUT_MS]);
  if (existing) return res.json({ ok: true, ref: existing.ref, amount: existing.amount });

  const ref = 'FD' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2, 6).toUpperCase();
  await dbRun(`INSERT INTO payment_intents (ref, username, amount, status, created_at) VALUES (?,?,?,?,?)`, [ref, username, AMOUNT, 'pending', Date.now()]);
  res.json({ ok: true, ref, amount: AMOUNT });
});

app.get('/api/check-payment', requireLogin, async (req, res) => {
  const { ref } = req.query;
  const intent = await dbGet('SELECT * FROM payment_intents WHERE ref=? AND username=?', [ref, req.session.user.username]);
  if (!intent) return res.json({ ok: false });

  if (intent.status === 'paid') {
    const u = await dbGet('SELECT * FROM users WHERE username=?', [req.session.user.username]);
    const now = Date.now();
    const baseTime = (u.status === 'paid' && u.expires_at > now) ? u.expires_at : now;
    await dbRun(`UPDATE users SET status=?, paid_at=?, expires_at=? WHERE id=?`, ['paid', now, baseTime + DURATION_MS, u.id]);
    return res.json({ ok: true, paid: true });
  }
  res.json({ ok: true, paid: false, status: intent.status });
});

// ---- ระบบตรวจสอบสลิปอัตโนมัติด้วย AI (Tesseract OCR) ----
// ---- ระบบตรวจสอบสลิปอัตโนมัติด้วย AI (Tesseract OCR) ปรับปรุงใหม่ ----
app.post('/api/verify-slip', requireLogin, upload.single('slip'), async (req, res) => {
  try {
    if (!req.file) return res.json({ ok: false, msg: 'กรุณาแนบรูปสลิป' });

    const username = req.session.user.username;
    const { ref } = req.body || {};
    const intent = await dbGet('SELECT * FROM payment_intents WHERE ref=? AND username=?', [ref, username]);
    if (!intent || intent.status !== 'pending') return res.json({ ok: false, msg: 'ไม่พบรายการที่รอชำระเงิน' });

    console.log(`🔍 กำลังให้ AI อ่านสลิปของ ${username}...`);
    const { data: { text } } = await Tesseract.recognize(
      req.file.buffer,
      'tha+eng'
    );
    
    // ลบช่องว่างทั้งหมดออกเพื่อให้ตรวจสอบคำง่ายขึ้น
    const cleanText = text.replace(/\s+/g, '');
    console.log("ข้อความที่ AI อ่านได้:", cleanText);

    // 1. ตรวจสอบยอดเงิน (หา 1.00)
    if (!cleanText.includes('500.00')) {
      return res.json({ ok: false, msg: 'AI ไม่พบยอดเงิน 500.00 ในสลิป' });
    }

    // 2. ตรวจสอบชื่อบัญชี (จาก .env)
    const EXPECTED_NAME = process.env.RECEIVER_NAME || '';
    if (EXPECTED_NAME && !cleanText.includes(EXPECTED_NAME.replace(/\s+/g, ''))) {
      return res.json({ ok: false, msg: 'ชื่อผู้รับเงินในสลิปไม่ตรงกัน' });
    }

    // 3. ตรวจสอบเลขบัญชี 4 ตัวท้าย (จาก .env)
    const EXPECTED_ACCOUNT_LAST4 = process.env.RECEIVER_ACCOUNT_LAST4 || '';
    if (EXPECTED_ACCOUNT_LAST4 && !cleanText.includes(EXPECTED_ACCOUNT_LAST4)) {
      return res.json({ ok: false, msg: 'เลขบัญชีผู้รับไม่ตรงกัน' });
    }

    // 4. ตรวจสอบเวลา (ไม่เกิน 10 นาที)
    // AI จะค้นหาแพทเทิร์นเวลา XX:XX หรือ XX.XX
    const timeMatch = cleanText.match(/(\d{2})[:\.](\d{2})/);
    if (timeMatch) {
       const slipHour = parseInt(timeMatch[1], 10);
       const slipMin = parseInt(timeMatch[2], 10);
       
       const now = new Date();
       const currentHour = now.getHours();
       const currentMin = now.getMinutes();

       // คำนวณความต่างของเวลาเป็นนาที
       let diffMins = (currentHour * 60 + currentMin) - (slipHour * 60 + slipMin);
       
       // จัดการกรณีโอนข้ามวัน (เช่น โอน 23:55 ตรวจตอน 00:02)
       if (diffMins < -1000) diffMins += 24 * 60;

       if (diffMins > 10) {
          return res.json({ ok: false, msg: 'สลิปนี้หมดอายุแล้ว (เกิน 10 นาที)' });
       } else if (diffMins < -5) {
          // เผื่อกรณีนาฬิกาเซิร์ฟเวอร์เดินช้ากว่านาฬิกาธนาคารเล็กน้อย
          return res.json({ ok: false, msg: 'เวลาในสลิปล่วงหน้าเกินไป' });
       }
    } else {
       console.log("⚠️ AI หาเวลาในสลิปไม่เจอ ข้ามการตรวจเวลา");
       // ถ้าระบบอ่านเวลาไม่ออกบ่อยๆ สามารถอนุโลมให้ผ่านได้ 
       // หรือถ้าอยากบังคับให้เข้มงวด เอาคอมเมนต์บรรทัดล่างออกได้เลย
       // return res.json({ ok: false, msg: 'ระบบไม่สามารถอ่านเวลาบนสลิปได้ โปรดถ่ายให้ชัดเจน' });
    }
    // 5. ตรวจสอบรหัสอ้างอิงซ้ำ (ป้องกันการใช้สลิปวนภายใน 10 นาที)
    // ค้นหาชุดตัวอักษรภาษาอังกฤษผสมตัวเลขที่ยาว 20 ตัวขึ้นไป
    const transRefMatch = cleanText.match(/[a-zA-Z0-9]{20,}/);
    let transRef = null;

    if (transRefMatch) {
      transRef = transRefMatch[0];
      const usedBefore = await dbGet('SELECT id FROM payment_intents WHERE slip_trans_ref=?', [transRef]);
      if (usedBefore) {
        return res.json({ ok: false, msg: 'สลิปใบนี้ถูกใช้ยืนยันการชำระเงินไปแล้ว' });
      }
    } else {
      console.log("⚠️ AI หารหัสอ้างอิงบนสลิปไม่เจอ");
    }

    // ผ่านเงื่อนไขทั้งหมด! ทำการอนุมัติ
    const nowStamp = Date.now();
    await dbRun(
      `UPDATE payment_intents SET status=?, paid_at=?, transaction_id=?, slip_trans_ref=? WHERE ref=?`,
      ['paid', nowStamp, transRef || 'OCR-VERIFIED-' + nowStamp, transRef || null, intent.ref]
    );

    console.log(`✅ ระบบอ่านสลิปสำเร็จ: ${username} จ่าย ${AMOUNT} บาท (ref=${intent.ref})`);
    res.json({ ok: true, msg: 'ตรวจสอบสลิปสำเร็จ กำลังเข้าสู่ระบบ...', ref: intent.ref });
  } catch (e) {
    console.error('OCR verify error:', e);
    res.status(500).json({ ok: false, msg: 'ไม่สามารถอ่านรูปภาพนี้ได้: ' + e.message });
  }
});

// ============================================================
// ADMIN API
// ============================================================
app.get('/api/admin/payment-intents', requireAdmin, async (req, res) => {
  const rows = await dbAll(`SELECT * FROM payment_intents ORDER BY created_at DESC LIMIT 100`);
  res.json({ ok: true, intents: rows });
});

app.post('/api/admin/verify-payment', requireAdmin, async (req, res) => {
  const { ref } = req.body || {};
  const intent = await dbGet('SELECT * FROM payment_intents WHERE ref=?', [ref]);
  if (!intent) return res.json({ ok: false, msg: 'ไม่พบ ref' });
  if (intent.status === 'paid') return res.json({ ok: true, msg: 'ชำระแล้ว' });

  const now = Date.now();
  await dbRun(`UPDATE payment_intents SET status=?, paid_at=?, transaction_id=? WHERE ref=?`, ['paid', now, 'ADMIN-' + now, ref]);
  res.json({ ok: true });
});

app.get('/api/users', requireAdmin, async (req, res) => {
  const rows = await dbAll(`SELECT id, username, role, status, paid_at, expires_at, transaction_id, created_at, created_by FROM users ORDER BY id`);
  const now = Date.now();
  const users = [];
  for (const u of rows) {
    let status = u.status;
    let remainingMs = 0;
    if (u.role !== 'admin' && status === 'paid' && u.expires_at) {
      if (u.expires_at <= now) {
        status = 'expired';
        await dbRun('UPDATE users SET status=? WHERE id=?', ['expired', u.id]);
      } else { remainingMs = u.expires_at - now; }
    }
    users.push({ ...u, status, remainingMs });
  }
  res.json({ ok: true, users });
});

app.post('/api/users/:username/approve', requireAdmin, async (req, res) => {
  const { username } = req.params;
  const u = await dbGet('SELECT * FROM users WHERE username=?', [username]);
  if (!u) return res.json({ ok: false, msg: 'ไม่พบผู้ใช้' });

  const now = Date.now();
  const baseTime = (u.status === 'paid' && u.expires_at && u.expires_at > now) ? u.expires_at : now;
  await dbRun(`UPDATE users SET status=?, paid_at=?, expires_at=?, transaction_id=? WHERE id=?`, ['paid', now, baseTime + DURATION_MS, 'ADMIN-' + now, u.id]);
  res.json({ ok: true, msg: 'อนุมัติสำเร็จ' });
});

app.delete('/api/users/:username', requireAdmin, async (req, res) => {
  const { username } = req.params;
  const t = await dbGet('SELECT * FROM users WHERE username=?', [username]);
  if (t.role === 'admin') return res.json({ ok: false, msg: 'ลบแอดมินไม่ได้' });
  await dbRun('DELETE FROM users WHERE username=?', [username]);
  await dbRun('DELETE FROM payment_intents WHERE username=?', [username]);
  res.json({ ok: true, msg: 'ลบสำเร็จ' });
});

app.use(express.static(PUBLIC_DIR));
app.get('*', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

initDB().then(() => app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`)));
