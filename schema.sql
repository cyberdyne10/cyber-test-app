CREATE TABLE IF NOT EXISTS admin_settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  reg_number TEXT,
  must_change_password INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  duration_minutes INTEGER,
  questions_per_attempt INTEGER,
  instructions TEXT,
  max_attempts INTEGER,
  access_key TEXT,
  type TEXT DEFAULT 'exam',
  start_time DATETIME,
  end_time DATETIME
);

CREATE TABLE IF NOT EXISTS questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  test_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  marks INTEGER DEFAULT 1,
  image_url TEXT,
  question_type TEXT DEFAULT 'single',
  explanation TEXT,
  FOREIGN KEY (test_id) REFERENCES tests(id)
);

CREATE TABLE IF NOT EXISTS options (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  question_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  is_correct INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (question_id) REFERENCES questions(id)
);

CREATE TABLE IF NOT EXISTS attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_name TEXT NOT NULL,
  student_id TEXT,
  student_db_id INTEGER,
  test_id INTEGER NOT NULL,
  score INTEGER NOT NULL,
  total INTEGER NOT NULL,
  status TEXT DEFAULT 'submitted',
  violations INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (test_id) REFERENCES tests(id)
);

-- Persist in-progress attempt state for autosave/resume
CREATE TABLE IF NOT EXISTS attempt_state (
  attempt_id INTEGER PRIMARY KEY,
  remaining_seconds INTEGER,
  active_index INTEGER,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (attempt_id) REFERENCES attempts(id)
);

CREATE TABLE IF NOT EXISTS attempt_answers (
  attempt_id INTEGER NOT NULL,
  question_id INTEGER NOT NULL,
  option_id INTEGER NOT NULL,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (attempt_id, question_id, option_id),
  FOREIGN KEY (attempt_id) REFERENCES attempts(id)
);

CREATE TABLE IF NOT EXISTS attempt_flags (
  attempt_id INTEGER NOT NULL,
  question_id INTEGER NOT NULL,
  flagged INTEGER NOT NULL DEFAULT 1,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (attempt_id, question_id),
  FOREIGN KEY (attempt_id) REFERENCES attempts(id)
);
