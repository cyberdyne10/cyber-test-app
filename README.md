# Cyber Test App

A simple computer-based testing (CBT) web application for cyber security students.

- **Stack:** Node.js + Express, SQLite, vanilla JS, Bootstrap
- **Use case:** Run multiple-choice tests, auto-mark them, and store results

---

## Features

- Teacher/Admin:
  - Create tests (e.g. "Network Security 101")
  - Add multiple-choice questions with 4 options
  - Mark the correct option per question
  - View all student attempts with scores and timestamps

- Student:
  - Enter name and (optional) student ID
  - Select a test and take it in the browser
  - Auto-marked on submission
  - Immediate score display (e.g. `8 / 10`)

---

## Project Structure

```text
cyber-test-app/
  server.js          # Express server + API
  db.js              # SQLite DB connection
  schema.sql         # DB schema
  package.json
  public/
    index.html       # Student portal (choose test & start)
    test.html        # Test UI (questions & answers)
    admin.html       # Simple teacher/admin panel
```

---

## Getting Started

### 1. Install dependencies

```bash
npm install
```

### 2. Initialize the database

```bash
node -e "const fs=require('fs'); const db=require('./db'); const schema=fs.readFileSync('schema.sql','utf8'); db.exec(schema, err=>{ if(err) console.error(err); else console.log('DB initialized'); db.close(); });"
```

This creates `data.db` with the necessary tables.

### 3. Run the app

```bash
npm start
# or
node server.js
```

Then open:

```text
http://localhost:3000
```

---

## Usage

### Student Flow

1. Go to `http://localhost:3000`.
2. Enter **Student Name** and optional **Student ID**.
3. Select an available test from the dropdown.
4. Click **Start Test**.
5. Answer the questions and click **Submit**.
6. See your score immediately.

### Teacher/Admin Flow

1. Go to `http://localhost:3000/admin.html`.
2. **Create a test**:
   - Enter test name and optional description.
   - Click **Create Test**.
3. **Add questions**:
   - Select a test from the dropdown.
   - Enter the question text.
   - Enter up to 4 options.
   - Choose the correct option from the dropdown.
   - Click **Add Question**.
4. **View attempts**:
   - Scroll to **Recent Attempts** table.
   - See student name, ID, test, score, total, and timestamp.

---

## Tech Notes

- Database: SQLite (file-based, `data.db` in project root).
- API endpoints (examples):
  - `GET /api/tests` – list tests
  - `POST /api/tests` – create test
  - `POST /api/tests/:testId/questions` – add question with options
  - `GET /api/tests/:testId/full` – test with questions + options
  - `POST /api/tests/:testId/submit` – submit answers + auto-mark
  - `GET /api/attempts` – list attempts

CORS is currently open for local development.

---

## Roadmap / Ideas

- Add login/auth for teachers
- Question randomization and per-student shuffling
- Timed tests and countdowns
- More question types (true/false, multi-select, short answer)
- Export attempts to CSV/Excel
- Basic anti-cheat measures (per-question timers, navigation controls)

---

## License

MIT (or choose your own license).
