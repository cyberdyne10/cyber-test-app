// server.js
const express = require('express');
const bodyParser = require('body-parser');
const db = require('./db');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const BCRYPT_ROUNDS = parseInt(process.env.ADMIN_BCRYPT_ROUNDS || '12', 10);
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || 'dev-only-change-me';
const ADMIN_TOKEN_EXPIRY = process.env.ADMIN_TOKEN_EXPIRY || '2h';
const DEV_DEFAULT_ADMIN_PASSWORD = 'ChangeMe_LocalAdmin_123!';

if (IS_PROD && !process.env.ADMIN_JWT_SECRET) {
  console.error('ADMIN_JWT_SECRET is required in production.');
  process.exit(1);
}

// Setup Uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = 'public/uploads';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname.replace(/[^a-z0-9.]/gi, '_'));
  }
});
const upload = multer({ storage: storage });

app.use(helmet({
  crossOriginResourcePolicy: false,
  // Frontend currently uses inline scripts/styles in public/*.html.
  // Disable CSP for now to prevent login/register/admin button JS from being blocked.
  contentSecurityPolicy: false
}));
app.use(bodyParser.json());

const configuredOrigins = (process.env.CORS_ORIGIN || '').split(',').map(o => o.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (!IS_PROD) return callback(null, true);
    if (configuredOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.static(path.join(__dirname, 'public')));

// Helper to generate Reg Number
function generateRegNumber(id) {
  const year = new Date().getFullYear();
  const paddedId = id.toString().padStart(3, '0');
  const hex = '0x' + crypto.randomBytes(2).toString('hex').toUpperCase();
  return `CYBLN-${year}-${paddedId}-${hex}`;
}

// Helper: Shuffle array
function shuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

function dbGetAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
  });
}

function dbRunAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function isLikelyBcryptHash(value) {
  return typeof value === 'string' && /^\$2[aby]\$\d{2}\$/.test(value);
}

function isStrongAdminPassword(password) {
  if (typeof password !== 'string') return false;
  return password.length >= 12 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password) && /[^A-Za-z0-9]/.test(password);
}

function signAdminToken() {
  return jwt.sign({ role: 'admin' }, ADMIN_JWT_SECRET, { expiresIn: ADMIN_TOKEN_EXPIRY });
}

function requireAdminAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const [scheme, token] = authHeader.split(' ');
  if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'Admin auth required' });

  try {
    const payload = jwt.verify(token, ADMIN_JWT_SECRET);
    if (payload.role !== 'admin') return res.status(403).json({ error: 'Invalid admin token' });
    req.admin = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired admin token' });
  }
}

async function initializeAdminCredentials() {
  const hashRow = await dbGetAsync("SELECT value FROM admin_settings WHERE key = 'password_hash'");
  const legacyRow = await dbGetAsync("SELECT value FROM admin_settings WHERE key = 'password'");

  // Deterministic startup behavior: if ADMIN_PASSWORD is provided, ensure DB hash matches it.
  // This prevents lockouts when DB password drifts from deployment config.
  if (process.env.ADMIN_PASSWORD) {
    const envPasswordMatches = hashRow && isLikelyBcryptHash(hashRow.value)
      ? await bcrypt.compare(process.env.ADMIN_PASSWORD, hashRow.value)
      : false;

    if (!envPasswordMatches) {
      const envHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, BCRYPT_ROUNDS);
      await dbRunAsync("INSERT OR REPLACE INTO admin_settings (key, value) VALUES ('password_hash', ?)", [envHash]);
      await dbRunAsync("DELETE FROM admin_settings WHERE key = 'password'");
      console.log('[SECURITY] Admin password hash synchronized from ADMIN_PASSWORD environment variable.');
    }
    return;
  }

  if (hashRow && isLikelyBcryptHash(hashRow.value)) return;

  if (legacyRow && legacyRow.value) {
    console.warn('[SECURITY] Legacy plaintext admin password detected. It will be migrated to hash on successful admin login/update.');
    return;
  }

  const bootstrapPassword = !IS_PROD ? DEV_DEFAULT_ADMIN_PASSWORD : null;
  if (!bootstrapPassword) {
    throw new Error('ADMIN_PASSWORD is required on first production run when no admin hash exists.');
  }

  console.warn(`[SECURITY] ADMIN_PASSWORD not set. Bootstrapping local development admin password to default: ${DEV_DEFAULT_ADMIN_PASSWORD}. Change it immediately.`);

  const hash = await bcrypt.hash(bootstrapPassword, BCRYPT_ROUNDS);
  await dbRunAsync("INSERT OR REPLACE INTO admin_settings (key, value) VALUES ('password_hash', ?)", [hash]);
}

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again later.' }
});

// ADMIN AUTH ROUTES
app.post('/api/admin/login', adminLoginLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password is required' });

    const hashRow = await dbGetAsync("SELECT value FROM admin_settings WHERE key = 'password_hash'");
    const legacyRow = await dbGetAsync("SELECT value FROM admin_settings WHERE key = 'password'");

    let authenticated = false;

    if (hashRow && isLikelyBcryptHash(hashRow.value)) {
      authenticated = await bcrypt.compare(password, hashRow.value);
    } else if (legacyRow && legacyRow.value) {
      authenticated = password === legacyRow.value;
      if (authenticated) {
        const newHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        await dbRunAsync("INSERT OR REPLACE INTO admin_settings (key, value) VALUES ('password_hash', ?)", [newHash]);
        await dbRunAsync("DELETE FROM admin_settings WHERE key = 'password'");
      }
    }

    if (!authenticated) return res.status(401).json({ error: 'Incorrect password' });

    const token = signAdminToken();
    res.json({ success: true, token, expiresIn: ADMIN_TOKEN_EXPIRY });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/update-password', requireAdminAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }

    if (!isStrongAdminPassword(newPassword)) {
      return res.status(400).json({ error: 'New password must be at least 12 chars with uppercase, lowercase, number and symbol.' });
    }

    const hashRow = await dbGetAsync("SELECT value FROM admin_settings WHERE key = 'password_hash'");
    const legacyRow = await dbGetAsync("SELECT value FROM admin_settings WHERE key = 'password'");

    let currentMatches = false;
    if (hashRow && isLikelyBcryptHash(hashRow.value)) {
      currentMatches = await bcrypt.compare(currentPassword, hashRow.value);
    } else if (legacyRow && legacyRow.value) {
      currentMatches = currentPassword === legacyRow.value;
    }

    if (!currentMatches) return res.status(401).json({ error: 'Current password is incorrect' });

    const nextHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    await dbRunAsync("INSERT OR REPLACE INTO admin_settings (key, value) VALUES ('password_hash', ?)", [nextHash]);
    await dbRunAsync("DELETE FROM admin_settings WHERE key = 'password'");

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// STUDENT AUTH ROUTES
app.post('/api/auth/register', (req, res) => {
  const { name, username, password } = req.body;
  if (!name || !username || !password) return res.status(400).json({ error: 'Missing fields' });
  
  db.run('INSERT INTO students (name, username, password) VALUES (?, ?, ?)', [name, username, password], function(err) {
    if (err) return res.status(400).json({ error: 'Username likely taken' });
    
    const studentId = this.lastID;
    const regNum = generateRegNumber(studentId);
    
    db.run('UPDATE students SET reg_number = ? WHERE id = ?', [regNum, studentId], (err2) => {
      if (err2) console.error('Error setting reg number', err2);
      res.json({ success: true, id: studentId, name, username, reg_number: regNum });
    });
  });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM students WHERE username = ? AND password = ?', [username, password], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });
    
    if (!row.reg_number) {
      const newReg = generateRegNumber(row.id);
      db.run('UPDATE students SET reg_number = ? WHERE id = ?', [newReg, row.id]);
      row.reg_number = newReg;
    }
    
    res.json({ success: true, student: { id: row.id, name: row.name, username: row.username, reg_number: row.reg_number } });
  });
});

app.get('/api/student/:id/history', (req, res) => {
  db.all(
    `SELECT a.*, t.name as test_name, t.id as test_id
     FROM attempts a 
     JOIN tests t ON a.test_id = t.id 
     WHERE a.student_db_id = ? 
     ORDER BY a.created_at DESC`, 
    [req.params.id], 
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// List all students
app.get('/api/students', requireAdminAuth, (req, res) => {
  db.all('SELECT id, name, username, reg_number FROM students ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Delete Student
app.delete('/api/students/:id', requireAdminAuth, (req, res) => {
  const studentId = req.params.id;
  // Optional: Also delete their attempts? For now, we keep attempts for record but unlink them or just delete student.
  // Better to keep attempts but student gone. Or delete attempts too.
  // Let's delete student only. Attempts will remain with student_id string but student_db_id will point to nothing.
  db.run('DELETE FROM students WHERE id = ?', [studentId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

/**
 * ADMIN ROUTES
 */

// Create a test (updated for type and schedule)
app.post('/api/tests', requireAdminAuth, (req, res) => {
  const { name, description, duration_minutes, questions_per_attempt, instructions, max_attempts, access_key, type, start_time, end_time } = req.body;
  db.run(
    'INSERT INTO tests (name, description, duration_minutes, questions_per_attempt, instructions, max_attempts, access_key, type, start_time, end_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [name, description || '', duration_minutes || null, questions_per_attempt || null, instructions || '', max_attempts || null, access_key || null, type || 'exam', start_time || null, end_time || null],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, name, description });
    }
  );
});

app.get('/api/tests', (req, res) => {
  db.all('SELECT * FROM tests', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.delete('/api/tests/:testId', requireAdminAuth, (req, res) => {
  const testId = req.params.testId;
  db.run('DELETE FROM options WHERE question_id IN (SELECT id FROM questions WHERE test_id = ?)', [testId], err => {
    if (err) return res.status(500).json({ error: err.message });
    db.run('DELETE FROM questions WHERE test_id = ?', [testId], err2 => {
      if (err2) return res.status(500).json({ error: err2.message });
      db.run('DELETE FROM tests WHERE id = ?', [testId], err3 => {
        if (err3) return res.status(500).json({ error: err3.message });
        res.json({ success: true });
      });
    });
  });
});

app.post('/api/tests/:testId/duplicate', requireAdminAuth, (req, res) => {
  const testId = req.params.testId;
  db.get('SELECT * FROM tests WHERE id = ?', [testId], (err, test) => {
    if (err || !test) return res.status(404).json({ error: 'Test not found' });
    const newName = test.name + ' (Copy)';
    db.run(
      'INSERT INTO tests (name, description, duration_minutes, questions_per_attempt, instructions, max_attempts, access_key, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [newName, test.description, test.duration_minutes, test.questions_per_attempt, test.instructions, test.max_attempts, test.access_key, test.type],
      function (err2) {
        if (err2) return res.status(500).json({ error: err2.message });
        const newTestId = this.lastID;
        db.all('SELECT * FROM questions WHERE test_id = ?', [testId], (err3, questions) => {
          if (err3) return res.status(500).json({ error: err3.message });
          if (questions.length === 0) return res.json({ success: true, id: newTestId, name: newName });
          let completed = 0;
          questions.forEach(q => {
            db.run('INSERT INTO questions (test_id, text, marks, image_url) VALUES (?, ?, ?, ?)', [newTestId, q.text, q.marks, q.image_url], function(errQ) {
              const newQId = this.lastID;
              db.all('SELECT * FROM options WHERE question_id = ?', [q.id], (errO, opts) => {
                const stmt = db.prepare('INSERT INTO options (question_id, text, is_correct) VALUES (?, ?, ?)');
                opts.forEach(o => stmt.run(newQId, o.text, o.is_correct));
                stmt.finalize(() => {
                  completed++;
                  if (completed === questions.length) { res.json({ success: true, id: newTestId, name: newName }); }
                });
              });
            });
          });
        });
      }
    );
  });
});

// Analytics
app.get('/api/analytics', requireAdminAuth, (req, res) => {
  db.all(
    `SELECT t.id, t.name, 
            COUNT(a.id) as attempts, 
            AVG(a.score) as avg_score, 
            AVG(a.total) as avg_total
     FROM tests t
     LEFT JOIN attempts a ON t.id = a.test_id AND a.status = 'submitted'
     GROUP BY t.id`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// Live Monitoring
app.get('/api/live', requireAdminAuth, (req, res) => {
  db.all(
    `SELECT a.id, a.student_name, t.name as test_name, a.created_at, a.violations
     FROM attempts a
     JOIN tests t ON a.test_id = t.id
     WHERE a.status = 'in-progress' 
     AND a.created_at >= datetime('now', '-3 hours')
     ORDER BY a.created_at DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// CSV Export
app.get('/api/export/csv', requireAdminAuth, (req, res) => {
  const testId = req.query.test_id;
  let sql = `SELECT a.id, a.student_name, a.student_id, t.name as test_name, a.score, a.total, a.created_at, a.violations 
             FROM attempts a JOIN tests t ON a.test_id = t.id WHERE a.status = 'submitted'`;
  const params = [];
  if (testId) { sql += ' AND a.test_id = ?'; params.push(testId); }
  sql += ' ORDER BY a.created_at DESC';

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).send('Error');
    let csv = 'Attempt ID,Student Name,Student ID,Test Name,Score,Total,Date,Violations\n';
    rows.forEach(r => {
      csv += `${r.id},"${r.student_name}","${r.student_id || ''}","${r.test_name}",${r.score},${r.total},"${r.created_at}",${r.violations}\n`;
    });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="exam_results.csv"');
    res.send(csv);
  });
});

// Bulk Import
app.post('/api/tests/:testId/import', requireAdminAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const testId = req.params.testId;
  const content = fs.readFileSync(req.file.path, 'utf8');
  
  // Format: Text,Mark,Option1,Option2,Option3,Option4,CorrectIndex(1-4)
  const lines = content.split('\n');
  let count = 0;
  
  lines.forEach(line => {
    const parts = line.split(','); // simple split, not robust csv
    if (parts.length >= 7) {
      const text = parts[0].trim();
      const mark = parseInt(parts[1]) || 1;
      const options = [parts[2], parts[3], parts[4], parts[5]].map(s => s.trim());
      const correctIdx = parseInt(parts[6]) - 1; // 1-based csv to 0-based

      if (text) {
        db.run('INSERT INTO questions (test_id, text, marks) VALUES (?, ?, ?)', [testId, text, mark], function(e) {
          if (!e) {
            const qId = this.lastID;
            const stmt = db.prepare('INSERT INTO options (question_id, text, is_correct) VALUES (?, ?, ?)');
            options.forEach((opt, idx) => {
              stmt.run(qId, opt, idx === correctIdx ? 1 : 0);
            });
            stmt.finalize();
          }
        });
        count++;
      }
    }
  });
  
  fs.unlinkSync(req.file.path);
  res.json({ success: true, count });
});

// Questions with Images
app.post('/api/tests/:testId/questions', requireAdminAuth, upload.single('image'), (req, res) => {
  const testId = req.params.testId;
  const text = req.body.text;
  const marks = req.body.marks || 1;
  const questionType = req.body.question_type || 'single';
  let options = [];
  try { options = JSON.parse(req.body.options); } catch(e) {}

  const imageUrl = req.file ? '/uploads/' + req.file.filename : null;

  db.run('INSERT INTO questions (test_id, text, marks, image_url, question_type) VALUES (?, ?, ?, ?, ?)', [testId, text, marks, imageUrl, questionType], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    const questionId = this.lastID;
    const stmt = db.prepare('INSERT INTO options (question_id, text, is_correct) VALUES (?, ?, ?)');
    for (const opt of options) { stmt.run(questionId, opt.text, opt.is_correct ? 1 : 0); }
    stmt.finalize(err2 => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ id: questionId, test_id: testId, text });
    });
  });
});

app.get('/api/tests/:testId/questions-full', requireAdminAuth, (req, res) => {
  const testId = req.params.testId;
  db.all(
    `SELECT q.id as question_id, q.text as question_text, q.marks, q.image_url, q.question_type,
            o.id as option_id, o.text as option_text, o.is_correct
     FROM questions q
     JOIN options o ON q.id = o.question_id
     WHERE q.test_id = ?
     ORDER BY q.id ASC, o.id ASC`,
    [testId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      const questions = {};
      rows.forEach(r => {
        if (!questions[r.question_id]) {
          questions[r.question_id] = { id: r.question_id, text: r.question_text, marks: r.marks, image_url: r.image_url, question_type: r.question_type || 'single', options: [] };
        }
        questions[r.question_id].options.push({ id: r.option_id, text: r.option_text, is_correct: r.is_correct === 1 });
      });
      res.json(Object.values(questions));
    }
  );
});

app.post('/api/questions/:questionId/update', requireAdminAuth, (req, res) => {
  const questionId = req.params.questionId;
  const { text, marks, options, question_type } = req.body;
  db.run('UPDATE questions SET text = ?, marks = ?, question_type = ? WHERE id = ?', [text, marks || 1, question_type || 'single', questionId], err => {
    if (err) return res.status(500).json({ error: err.message });
    const stmt = db.prepare('UPDATE options SET text = ?, is_correct = ? WHERE id = ?');
    for (const opt of options) { if (opt.id) stmt.run(opt.text, opt.is_correct ? 1 : 0, opt.id); }
    stmt.finalize(err2 => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

app.delete('/api/questions/:questionId', requireAdminAuth, (req, res) => {
  const questionId = req.params.questionId;
  db.run('DELETE FROM options WHERE question_id = ?', [questionId], err => {
    if (err) return res.status(500).json({ error: err.message });
    db.run('DELETE FROM questions WHERE id = ?', [questionId], err2 => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

// Check eligibility (Attempts + Access Key + Schedule)
app.post('/api/tests/:testId/check', (req, res) => {
  const testId = req.params.testId;
  const { student_name, student_db_id, access_key } = req.body;

  db.get('SELECT * FROM tests WHERE id = ?', [testId], (err, test) => {
    if (err || !test) return res.status(404).json({ error: 'Test not found' });

    // Check Schedule
    const now = new Date();
    if (test.start_time && new Date(test.start_time) > now) {
      return res.status(403).json({ error: `Exam has not started yet. Opens at: ${new Date(test.start_time).toLocaleString()}` });
    }
    if (test.end_time && new Date(test.end_time) < now) {
      return res.status(403).json({ error: `Exam is closed. Ended at: ${new Date(test.end_time).toLocaleString()}` });
    }

    if (test.access_key && test.access_key.trim() !== '') {
      if (!access_key || access_key.trim() !== test.access_key) return res.status(403).json({ error: 'Invalid Access Key' });
    }

    if (test.max_attempts && test.max_attempts > 0) {
      let sql = 'SELECT COUNT(*) as count FROM attempts WHERE test_id = ? AND status = "submitted" AND ';
      let params = [testId];
      if (student_db_id) { sql += 'student_db_id = ?'; params.push(student_db_id); }
      else { sql += 'student_name = ?'; params.push(student_name); }

      db.get(sql, params, (err2, row) => {
        if (err2) return res.status(500).json({ error: err2.message });
        if (row.count >= test.max_attempts) return res.status(403).json({ error: `Maximum attempts (${test.max_attempts}) exceeded.` });
        res.json({ success: true });
      });
    } else {
      res.json({ success: true });
    }
  });
});

app.get('/api/tests/:testId/info', (req, res) => {
  db.get('SELECT id, name, description, duration_minutes, instructions, max_attempts, type, access_key, start_time, end_time, questions_per_attempt, CASE WHEN access_key IS NOT NULL AND access_key != "" THEN 1 ELSE 0 END as is_locked FROM tests WHERE id = ?', [req.params.testId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row);
  });
});

// Update a test (including schedule)
app.put('/api/tests/:testId', requireAdminAuth, (req, res) => {
  const testId = req.params.testId;
  const { name, description, duration_minutes, questions_per_attempt, instructions, max_attempts, access_key, type, start_time, end_time } = req.body;
  db.run(
    `UPDATE tests SET 
      name = ?,
      description = ?,
      duration_minutes = ?,
      questions_per_attempt = ?,
      instructions = ?,
      max_attempts = ?,
      access_key = ?,
      type = ?,
      start_time = ?,
      end_time = ?
     WHERE id = ?`,
    [
      name,
      description || '',
      duration_minutes || null,
      questions_per_attempt || null,
      instructions || '',
      max_attempts || null,
      access_key || null,
      type || 'exam',
      start_time || null,
      end_time || null,
      testId
    ],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

app.get('/api/tests/:testId/full', (req, res) => {
  const testId = req.params.testId;
  db.get('SELECT duration_minutes, questions_per_attempt, type FROM tests WHERE id = ?', [testId], (err, testRow) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!testRow) return res.status(404).json({ error: 'Test not found' });

    db.all(
      `SELECT q.id as question_id, q.text as question_text, q.marks, q.image_url, q.question_type,
              o.id as option_id, o.text as option_text
       FROM questions q
       JOIN options o ON q.id = o.question_id
       WHERE q.test_id = ?`,
      [testId],
      (err2, rows) => {
        if (err2) return res.status(500).json({ error: err2.message });
        const questionsMap = {};
        rows.forEach(r => {
          if (!questionsMap[r.question_id]) {
            questionsMap[r.question_id] = { id: r.question_id, text: r.question_text, marks: r.marks, image_url: r.image_url, question_type: r.question_type || 'single', options: [] };
          }
          questionsMap[r.question_id].options.push({ id: r.option_id, text: r.option_text });
        });

        let allQuestions = Object.values(questionsMap);
        allQuestions = shuffle(allQuestions);

        if (testRow.questions_per_attempt && testRow.questions_per_attempt > 0 && testRow.questions_per_attempt < allQuestions.length) {
          allQuestions = allQuestions.slice(0, testRow.questions_per_attempt);
        }
        allQuestions.forEach(q => { q.options = shuffle(q.options); });

        res.json({
          test_config: { 
            duration_minutes: testRow.duration_minutes || 10,
            type: testRow.type || 'exam'
          },
          questions: allQuestions
        });
      }
    );
  });
});

app.post('/api/tests/:testId/submit', (req, res) => {
  const testId = req.params.testId;
  const { student_name, student_id, student_db_id, answers, attempt_id } = req.body; 

  if (!answers || answers.length === 0) return res.status(400).json({ error: 'No answers' });

  const oIds = answers.map(a => a.option_id);
  const placeholders = oIds.map(() => '?').join(',');

  db.all(
    `SELECT id, question_id, text, is_correct FROM options WHERE id IN (${placeholders})`,
    oIds,
    (err, optRows) => {
      if (err) return res.status(500).json({ error: err.message });
      const optionMap = {}; 
      optRows.forEach(r => (optionMap[r.id] = r));
      const qIds = answers.map(a => a.question_id);
      const qPlaceholders = qIds.map(() => '?').join(',');

      db.all(
        `SELECT id, text, marks, question_type FROM questions WHERE id IN (${qPlaceholders})`,
        qIds,
        (errQ, qRows) => {
          if (errQ) return res.status(500).json({ error: errQ.message });
          const questionMap = {};
          qRows.forEach(q => (questionMap[q.id] = q));

          let score = 0;
          let totalPossible = 0;
          const detailed = [];

          const answersByQuestion = {};
          answers.forEach(a => {
            if (!answersByQuestion[a.question_id]) answersByQuestion[a.question_id] = [];
            answersByQuestion[a.question_id].push(parseInt(a.option_id));
          });

          db.all(
            `SELECT question_id, id as option_id, text FROM options WHERE question_id IN (${qPlaceholders}) AND is_correct = 1`,
            qIds,
            (errC, correctRows) => {
               const correctOptionsMap = {};
               correctRows.forEach(r => {
                 if (!correctOptionsMap[r.question_id]) correctOptionsMap[r.question_id] = [];
                 correctOptionsMap[r.question_id].push(r);
               });

               for (const qIdStr in answersByQuestion) {
                 const qId = parseInt(qIdStr);
                 const qData = questionMap[qId];
                 if (!qData) continue;

                 const userSelectedOptionIds = answersByQuestion[qId];
                 const correctOpts = correctOptionsMap[qId] || [];
                 const correctOptIds = correctOpts.map(o => o.option_id);

                 const qMarks = qData.marks || 1;
                 totalPossible += qMarks;

                 let isCorrect = false;
                 let selectedTexts = [];

                 userSelectedOptionIds.forEach(oid => {
                    const opt = optionMap[oid];
                    if(opt) selectedTexts.push(opt.text);
                 });

                 if (qData.question_type === 'multiple') {
                    const userSet = new Set(userSelectedOptionIds);
                    const correctSet = new Set(correctOptIds);
                    if (userSet.size === correctSet.size && [...userSet].every(x => correctSet.has(x))) {
                      isCorrect = true;
                      score += qMarks;
                    }
                 } else {
                    if (userSelectedOptionIds.length === 1 && correctOptIds.includes(userSelectedOptionIds[0])) {
                       isCorrect = true;
                       score += qMarks;
                    }
                 }

                 detailed.push({
                   question_id: qId,
                   question_text: qData.text,
                   marks: qMarks,
                   selected_option: { text: selectedTexts.join(', '), is_correct: isCorrect },
                   correct_option: { text: correctOpts.map(c => c.text).join(', ') }
                 });
               }

               // Check test type: practice mode should NOT create or update attempts
               db.get('SELECT type FROM tests WHERE id = ?', [testId], (errT, testRow) => {
                 if (errT || !testRow) return res.status(500).json({ error: 'Test lookup failed' });
                 if (testRow.type === 'practice') {
                   // Just return score/detailed, no DB write, no attempt id
                   return res.json({ attempt_id: null, score, total: totalPossible, detailed });
                 }

                 if (attempt_id) {
                   db.run(
                     'UPDATE attempts SET score = ?, total = ?, status = "submitted" WHERE id = ?',
                     [score, totalPossible, attempt_id],
                     function(err2) {
                       if (err2) return res.status(500).json({ error: err2.message });
                       res.json({ attempt_id, score, total: totalPossible, detailed });
                     }
                   );
                 } else {
                   db.run(
                    'INSERT INTO attempts (student_name, student_id, student_db_id, test_id, score, total, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    [student_name, student_id || '', student_db_id || null, testId, score, totalPossible, 'submitted'],
                    function (err2) {
                      if (err2) return res.status(500).json({ error: err2.message });
                      res.json({ attempt_id: this.lastID, score, total: totalPossible, detailed });
                    }
                  );
                 }
               });
            }
          );
        }
      );
    }
  );
});

// Start Attempt (for Live Monitoring)
app.post('/api/tests/:testId/start', (req, res) => {
  const testId = req.params.testId;
  const { student_name, student_id, student_db_id } = req.body;

  // Check test type first; do not record attempts for practice mode
  db.get('SELECT type FROM tests WHERE id = ?', [testId], (err, test) => {
    if (err || !test) return res.status(404).json({ error: 'Test not found' });

    if (test.type === 'practice') {
      // No DB write; just return null attempt id for practice
      return res.json({ attempt_id: null });
    }

    const cleanSql = `UPDATE attempts SET status = 'abandoned' WHERE test_id = ? AND status = 'in-progress' AND (student_db_id = ? OR (student_db_id IS NULL AND student_name = ?))`;

    db.run(cleanSql, [testId, student_db_id || -1, student_name], (err2) => {
      db.run(
        'INSERT INTO attempts (student_name, student_id, student_db_id, test_id, score, total, status) VALUES (?, ?, ?, ?, 0, 0, ?)',
        [student_name, student_id || '', student_db_id || null, testId, 'in-progress'],
        function(err3) {
          if (err3) return res.status(500).json({ error: err3.message });
          res.json({ attempt_id: this.lastID });
        }
      );
    });
  });
});

// Report Violation
app.post('/api/attempts/:attemptId/violation', (req, res) => {
  db.run('UPDATE attempts SET violations = violations + 1 WHERE id = ?', [req.params.attemptId], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.get('/api/attempts/:id', requireAdminAuth, (req, res) => {
  db.get('SELECT a.*, t.name as test_name FROM attempts a JOIN tests t ON a.test_id = t.id WHERE a.id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Attempt not found' });
    res.json(row);
  });
});

app.get('/api/attempts', requireAdminAuth, (req, res) => {
  db.all('SELECT a.*, t.name AS test_name FROM attempts a JOIN tests t ON a.test_id = t.id WHERE a.status = "submitted" ORDER BY a.created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

function initDatabase(callback) {
  const schemaPath = path.join(__dirname, 'schema.sql');
  fs.readFile(schemaPath, 'utf8', (readErr, schema) => {
    if (readErr) return callback(readErr);
    db.exec(schema, callback);
  });
}

initDatabase(async (err) => {
  if (err) {
    console.error('Failed to initialize database schema:', err.message);
    process.exit(1);
  }

  try {
    await initializeAdminCredentials();
  } catch (bootstrapErr) {
    console.error('Failed to initialize admin credentials:', bootstrapErr.message);
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`Cyber Test App running on http://localhost:${PORT}`);
  });
});
