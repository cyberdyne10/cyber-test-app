const db = require('./db');

const topics = [
  "Network Security",
  "Web Security",
  "Application Security",
  "Information Security (InfoSec)",
  "Endpoint Security",
  "Cloud Security",
  "Mobile Security",
  "IoT Security",
  "Database Security",
  "API Security",
  "Identity and Access Management (IAM)",
  "Email Security",
  "Social Engineering Protection",
  "Threat Intelligence",
  "Penetration Testing (Ethical Hacking)",
  "Digital Forensics",
  "Governance, Risk & Compliance (GRC)",
  "Privacy & Data Protection"
];

const EXAMS_PER_TOPIC = 100;
const QUESTIONS_PER_EXAM = 5;

function runStmt(stmt, ...params) {
  return new Promise((resolve, reject) => {
    stmt.run(...params, function(err) {
      if (err) reject(err);
      else resolve(this.lastID);
    });
  });
}

function runDb(command) {
  return new Promise((resolve, reject) => {
    db.run(command, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

async function seedAll() {
  console.log("Starting bulk seed...");

  const stmtTest = db.prepare("INSERT INTO tests (name, description, duration_minutes, type) VALUES (?, ?, ?, ?)");
  const stmtQuestion = db.prepare("INSERT INTO questions (test_id, text, marks, question_type) VALUES (?, ?, ?, ?)");
  const stmtOption = db.prepare("INSERT INTO options (question_id, text, is_correct) VALUES (?, ?, ?)");

  for (let t = 0; t < topics.length; t++) {
    const topic = topics[t];
    console.log(`Seeding topic ${t + 1}/${topics.length}: ${topic}...`);

    await runDb("BEGIN TRANSACTION");

    try {
      for (let i = 1; i <= EXAMS_PER_TOPIC; i++) {
        const examName = `${topic} - Exam ${i}`;
        const description = `Auto-generated exam covering ${topic}. Set #${i}.`;

        const testId = await runStmt(stmtTest, examName, description, 30, 'exam');

        for (let q = 1; q <= QUESTIONS_PER_EXAM; q++) {
          const qText = `Sample Question ${q} for ${topic} (Exam ${i})`;
          const qType = (q % 2 === 0) ? 'multiple' : 'single';

          const qId = await runStmt(stmtQuestion, testId, qText, 1, qType);

          await runStmt(stmtOption, qId, "Option A (Incorrect)", 0);
          await runStmt(stmtOption, qId, "Option B (Correct)", 1);
          await runStmt(stmtOption, qId, "Option C (Incorrect)", 0);

          if (qType === 'multiple') {
             await runStmt(stmtOption, qId, "Option D (Correct)", 1);
          } else {
             await runStmt(stmtOption, qId, "Option D (Incorrect)", 0);
          }
        }
      }

      await runDb("COMMIT");
    } catch (e) {
      console.error("Error seeding topic " + topic, e);
      await runDb("ROLLBACK");
      process.exit(1);
    }
  }

  stmtTest.finalize();
  stmtQuestion.finalize();
  stmtOption.finalize();

  console.log("All done.");
  db.close();
}

seedAll();
