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

### 3. Configure environment (recommended)

Create a `.env`/environment variables with:

- `PORT` (optional, default `3000`)
- `NODE_ENV` (`development` or `production`)
- `ADMIN_PASSWORD` (**required for first production bootstrap** if no admin hash exists)
- `ADMIN_JWT_SECRET` (**required in production**)
- `ADMIN_TOKEN_EXPIRY` (optional, default `2h`)
- `ADMIN_BCRYPT_ROUNDS` (optional, default `12`)
- `CORS_ORIGIN` (comma-separated allowed origins in production, e.g. `https://example.com`)

> First-run bootstrap behavior:
> - If no admin password hash exists, server initializes one from `ADMIN_PASSWORD`.
> - In non-production only, if `ADMIN_PASSWORD` is missing, a local default is used and warning is logged. Change it immediately.

### 4. Run the app

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

## Seeding the 18x100 Cyber Question Bank

This project includes an idempotent seed script that creates/updates 18 dedicated exams and inserts exactly 100 MCQs per exam (1,800 questions total, 7,200 options total).

Run:

```bash
npm run seed:question-bank
```

Re-running is safe: for each managed exam, existing questions/options are replaced and re-seeded to exact counts.

## Usage

### Student Flow

1. Go to `http://localhost:3000`.
2. Enter **Student Name** and optional **Student ID**.
3. Select an available test from the dropdown.
4. Click **Start Test**.
5. Answer the questions and click **Submit**.
6. See your score immediately.

### Teacher/Admin Flow

1. Go to `http://localhost:3000/admin.html` and login with admin password.
2. A short-lived admin token is issued and used for protected admin API calls.
3. **Create/update tests and questions** as before.
4. **Change admin password** from Settings (requires current password + strong new password).
5. **View attempts/analytics/live/students/export** from admin panel.

---

## Tech Notes

- Database: SQLite (file-based, `data.db` in project root).
- Admin password storage uses bcrypt hash (`admin_settings.key='password_hash'`).
- Backward-compatible migration:
  - Existing plaintext `admin_settings.key='password'` is still recognized.
  - On successful admin login/password update, plaintext is migrated to bcrypt hash.
- Admin auth uses JWT bearer token with expiry.
- Protected admin endpoints include test create/update/delete/duplicate/import, question management, analytics/live/attempts, student listing/deletion, CSV export, and admin password update.
- Student flows (`/api/auth/*`, taking/submitting tests) remain unaffected.
- Login endpoint (`POST /api/admin/login`) has basic rate limiting.
- Security headers via Helmet; CORS is strict in production (allowlist via `CORS_ORIGIN`).

---

## License

MIT (or choose your own license).
