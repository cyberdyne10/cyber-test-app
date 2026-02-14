const db = require('./db');

const topics = [
  'Network Security',
  'Web Security',
  'Application Security',
  'Information Security (InfoSec)',
  'Endpoint Security',
  'Cloud Security',
  'Mobile Security',
  'IoT Security',
  'Database Security',
  'API Security',
  'Identity and Access Management (IAM)',
  'Email Security',
  'Social Engineering Protection',
  'Threat Intelligence',
  'Penetration Testing (Ethical Hacking)',
  'Digital Forensics',
  'Governance, Risk & Compliance (GRC)',
  'Privacy & Data Protection'
];

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

(async () => {
  for (const topic of topics) {
    const name = `${topic} - Mastery Exam (100 MCQs)`;
    const rows = await all(
      `SELECT
         t.id,
         COUNT(DISTINCT q.id) AS questions,
         COUNT(o.id) AS options,
         SUM(CASE WHEN x.one_correct = 1 THEN 1 ELSE 0 END) AS valid_questions
       FROM tests t
       LEFT JOIN questions q ON q.test_id = t.id
       LEFT JOIN options o ON o.question_id = q.id
       LEFT JOIN (
         SELECT question_id,
                CASE WHEN COUNT(*) = 4 AND SUM(is_correct) = 1 THEN 1 ELSE 0 END AS one_correct
         FROM options
         GROUP BY question_id
       ) x ON x.question_id = q.id
       WHERE t.name = ?
       GROUP BY t.id`,
      [name]
    );

    console.log(topic, rows[0]);
  }

  const totals = await all(
    `SELECT
       (SELECT COUNT(*) FROM tests WHERE name LIKE '% - Mastery Exam (100 MCQs)') AS tests,
       (SELECT COUNT(*)
          FROM questions q
          JOIN tests t ON t.id = q.test_id
         WHERE t.name LIKE '% - Mastery Exam (100 MCQs)') AS questions,
       (SELECT COUNT(*)
          FROM options o
         WHERE o.question_id IN (
           SELECT q.id
             FROM questions q
             JOIN tests t ON t.id = q.test_id
            WHERE t.name LIKE '% - Mastery Exam (100 MCQs)'
         )) AS options`
  );

  console.log('TOTAL', totals[0]);
  db.close();
})().catch((e) => {
  console.error(e);
  db.close();
  process.exit(1);
});
