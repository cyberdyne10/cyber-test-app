// server.js
const express = require('express');
const bodyParser = require('body-parser');
const db = require('./db');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Simple CORS for local testing
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

/**
 * ADMIN ROUTES
 */

// Create a test
app.post('/api/tests', (req, res) => {
  const { name, description } = req.body;
  db.run(
    'INSERT INTO tests (name, description) VALUES (?, ?)',
    [name, description || ''],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, name, description });
    }
  );
});

// List tests
app.get('/api/tests', (req, res) => {
  db.all('SELECT * FROM tests', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Add question with options
app.post('/api/tests/:testId/questions', (req, res) => {
  const testId = req.params.testId;
  const { text, options } = req.body; // options: [{text, is_correct}, ...]

  db.run(
    'INSERT INTO questions (test_id, text) VALUES (?, ?)',
    [testId, text],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      const questionId = this.lastID;

      const stmt = db.prepare(
        'INSERT INTO options (question_id, text, is_correct) VALUES (?, ?, ?)'
      );
      for (const opt of options) {
        stmt.run(questionId, opt.text, opt.is_correct ? 1 : 0);
      }
      stmt.finalize(err2 => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ id: questionId, test_id: testId, text });
      });
    }
  );
});

/**
 * STUDENT ROUTES
 */

// Get raw questions + options for admin editing
app.get('/api/tests/:testId/questions-full', (req, res) => {
  const testId = req.params.testId;
  db.all(
    `SELECT q.id as question_id, q.text as question_text,
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
          questions[r.question_id] = {
            id: r.question_id,
            text: r.question_text,
            options: []
          };
        }
        questions[r.question_id].options.push({
          id: r.option_id,
          text: r.option_text,
          is_correct: r.is_correct === 1
        });
      });
      res.json(Object.values(questions));
    }
  );
});

// Update question text and options
app.post('/api/questions/:questionId/update', (req, res) => {
  const questionId = req.params.questionId;
  const { text, options } = req.body; // options: [{id, text, is_correct}]

  db.run(
    'UPDATE questions SET text = ? WHERE id = ?',
    [text, questionId],
    err => {
      if (err) return res.status(500).json({ error: err.message });

      const stmt = db.prepare('UPDATE options SET text = ?, is_correct = ? WHERE id = ?');
      for (const opt of options) {
        stmt.run(opt.text, opt.is_correct ? 1 : 0, opt.id);
      }
      stmt.finalize(err2 => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ success: true });
      });
    }
  );
});

// Delete question and its options
app.delete('/api/questions/:questionId', (req, res) => {
  const questionId = req.params.questionId;
  db.run('DELETE FROM options WHERE question_id = ?', [questionId], err => {
    if (err) return res.status(500).json({ error: err.message });
    db.run('DELETE FROM questions WHERE id = ?', [questionId], err2 => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ success: true });
    });
  });
});

// Delete entire test and its questions/options
app.delete('/api/tests/:testId', (req, res) => {
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

// Get test with questions + options
app.get('/api/tests/:testId/full', (req, res) => {
  const testId = req.params.testId;

  db.all(
    `SELECT q.id as question_id, q.text as question_text,
            o.id as option_id, o.text as option_text
     FROM questions q
     JOIN options o ON q.id = o.question_id
     WHERE q.test_id = ?`,
    [testId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      const questions = {};
      rows.forEach(r => {
        if (!questions[r.question_id]) {
          questions[r.question_id] = {
            id: r.question_id,
            text: r.question_text,
            options: []
          };
        }
        questions[r.question_id].options.push({
          id: r.option_id,
          text: r.option_text
        });
      });
      res.json(Object.values(questions));
    }
  );
});

// Submit answers and auto-mark
app.post('/api/tests/:testId/submit', (req, res) => {
  const testId = req.params.testId;
  const { student_name, student_id, answers } = req.body; 
  // answers: [{question_id, option_id}]

  const oIds = answers.map(a => a.option_id);
  if (oIds.length === 0) {
    return res.status(400).json({ error: 'No answers' });
  }

  const placeholders = oIds.map(() => '?').join(',');
  db.all(
    `SELECT id, question_id, text, is_correct FROM options WHERE id IN (${placeholders})`,
    oIds,
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });

      const optionMap = {};
      rows.forEach(r => (optionMap[r.id] = r));

      let score = 0;
      const detailed = [];

      const qPlaceholders = answers.map(() => '?').join(',');
      const qIds = answers.map(a => a.question_id);

      db.all(
        `SELECT id, text FROM questions WHERE id IN (${qPlaceholders})`,
        qIds,
        (errQ, qRows) => {
          if (errQ) return res.status(500).json({ error: errQ.message });
          const questionTextMap = {};
          qRows.forEach(q => (questionTextMap[q.id] = q.text));

          answers.forEach(a => {
            const selected = optionMap[a.option_id];
            if (!selected) return;
            const correct = rows.find(o => o.question_id === selected.question_id && o.is_correct === 1);
            const isCorrect = selected.is_correct === 1;
            if (isCorrect) score++;
            detailed.push({
              question_id: selected.question_id,
              question_text: questionTextMap[selected.question_id] || '',
              selected_option: {
                id: selected.id,
                text: selected.text,
                is_correct: selected.is_correct === 1
              },
              correct_option: correct
                ? { id: correct.id, text: correct.text, is_correct: true }
                : null
            });
          });

          const total = answers.length;

          db.run(
            'INSERT INTO attempts (student_name, student_id, test_id, score, total) VALUES (?, ?, ?, ?, ?)',
            [student_name, student_id || '', testId, score, total],
            function (err2) {
              if (err2) return res.status(500).json({ error: err2.message });
              res.json({
                attempt_id: this.lastID,
                score,
                total,
                detailed
              });
            }
          );
        }
      );
    }
  );
});

// Simple route to view attempts (for teacher, no auth yet)
app.get('/api/attempts', (req, res) => {
  db.all(
    `SELECT a.*, t.name AS test_name
     FROM attempts a
     JOIN tests t ON a.test_id = t.id
     ORDER BY a.created_at DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.listen(PORT, () => {
  console.log(`Cyber Test App running on http://localhost:${PORT}`);
});
