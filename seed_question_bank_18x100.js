const db = require('./db');

const TOPICS = [
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

const TOPIC_DATA = {
  'Network Security': {
    controls: ['network segmentation', 'stateful firewall rules', 'NAC', 'secure VPN', 'microsegmentation', 'egress filtering', 'IDS/IPS tuning', 'zero-trust network access'],
    threats: ['ARP spoofing', 'DNS poisoning', 'SYN flood', 'BGP hijacking', 'lateral movement', 'man-in-the-middle attack', 'port scanning', 'ransomware propagation'],
    artifacts: ['NetFlow logs', 'firewall logs', 'packet captures', 'IDS alerts', 'routing tables', 'switch MAC tables', 'VPN logs', 'DHCP leases'],
    best: ['least privilege', 'defense in depth', 'deny by default', 'secure baseline', 'continuous monitoring', 'change management', 'incident response', 'asset inventory']
  },
  'Web Security': {
    controls: ['Content Security Policy (CSP)', 'HttpOnly cookies', 'input validation', 'output encoding', 'same-site cookies', 'WAF rules', 'CSRF tokens', 'secure headers'],
    threats: ['SQL injection', 'cross-site scripting (XSS)', 'cross-site request forgery (CSRF)', 'clickjacking', 'session fixation', 'open redirect', 'directory traversal', 'insecure deserialization'],
    artifacts: ['HTTP request logs', 'WAF alerts', 'application logs', 'session records', 'browser console traces', 'reverse proxy logs', 'error stack traces', 'access logs'],
    best: ['OWASP ASVS alignment', 'secure coding standards', 'patch management', 'threat modeling', 'code review', 'dependency scanning', 'rate limiting', 'security testing in CI/CD']
  },
  'Application Security': {
    controls: ['secure SDLC', 'SAST', 'DAST', 'software composition analysis', 'secrets management', 'code review', 'threat modeling', 'runtime protection'],
    threats: ['hardcoded credentials', 'insecure direct object references', 'broken access control', 'memory corruption', 'unsafe deserialization', 'supply chain compromise', 'business logic abuse', 'race conditions'],
    artifacts: ['build logs', 'security scan reports', 'dependency manifests', 'unit test outputs', 'code diffs', 'container image metadata', 'release notes', 'audit trails'],
    best: ['shift-left security', 'least privilege', 'secure defaults', 'defense in depth', 'security gates', 'peer review', 'signed artifacts', 'rollback readiness']
  },
  'Information Security (InfoSec)': {
    controls: ['information classification', 'security awareness training', 'data retention policy', 'access reviews', 'incident response plan', 'backup strategy', 'business continuity planning', 'risk register maintenance'],
    threats: ['data leakage', 'insider threat', 'credential theft', 'policy violations', 'unpatched systems', 'third-party compromise', 'social engineering', 'misconfiguration'],
    artifacts: ['risk assessments', 'policy documents', 'audit reports', 'incident tickets', 'training completion logs', 'asset inventories', 'control matrices', 'business impact analyses'],
    best: ['CIA triad alignment', 'need-to-know principle', 'continuous improvement', 'regulatory compliance', 'documented procedures', 'management buy-in', 'periodic testing', 'governance oversight']
  },
  'Endpoint Security': {
    controls: ['EDR deployment', 'application allowlisting', 'disk encryption', 'host firewall', 'USB control policy', 'OS hardening', 'patch management', 'tamper protection'],
    threats: ['malware infection', 'privilege escalation', 'credential dumping', 'living-off-the-land abuse', 'ransomware execution', 'unauthorized software', 'phishing payload execution', 'data exfiltration'],
    artifacts: ['EDR telemetry', 'Windows event logs', 'Sysmon logs', 'process trees', 'registry change logs', 'quarantine events', 'patch reports', 'forensic images'],
    best: ['least privilege', 'golden images', 'rapid isolation', 'continuous monitoring', 'baseline configuration', 'vulnerability remediation', 'secure remote management', 'policy enforcement']
  },
  'Cloud Security': {
    controls: ['IAM role scoping', 'security groups', 'cloud-native logging', 'KMS encryption', 'MFA enforcement', 'private networking', 'workload identity', 'infrastructure as code scanning'],
    threats: ['public storage exposure', 'excessive permissions', 'stolen API keys', 'container escape', 'metadata service abuse', 'misconfigured security groups', 'crypto-mining malware', 'shadow IT'],
    artifacts: ['CloudTrail logs', 'VPC flow logs', 'IAM policy documents', 'config snapshots', 'container runtime logs', 'KMS audit entries', 'SIEM events', 'compliance findings'],
    best: ['shared responsibility clarity', 'least privilege', 'secure-by-default templates', 'continuous posture management', 'key rotation', 'segregation of duties', 'automated remediation', 'multi-account strategy']
  },
  'Mobile Security': {
    controls: ['mobile device management (MDM)', 'application sandboxing', 'certificate pinning', 'biometric authentication', 'secure key storage', 'runtime integrity checks', 'app store vetting', 'remote wipe'],
    threats: ['malicious app sideloading', 'insecure local storage', 'SIM swap fraud', 'jailbroken/rooted device abuse', 'man-in-the-middle on public Wi-Fi', 'overlay attacks', 'SMS phishing', 'token theft'],
    artifacts: ['mobile app logs', 'MDM compliance reports', 'crash reports', 'network traces', 'device posture checks', 'auth logs', 'store review findings', 'mobile threat defense alerts'],
    best: ['secure coding for mobile', 'minimum SDK hardening', 'data minimization', 'zero trust access', 'strong session controls', 'regular app updates', 'privacy by design', 'threat-informed testing']
  },
  'IoT Security': {
    controls: ['firmware signing', 'secure boot', 'network isolation', 'device identity certificates', 'OTA update validation', 'protocol hardening', 'default password removal', 'inventory monitoring'],
    threats: ['botnet recruitment', 'weak default credentials', 'insecure firmware update', 'unencrypted telemetry', 'physical tampering', 'rogue device onboarding', 'protocol downgrade', 'command injection'],
    artifacts: ['firmware hashes', 'device logs', 'gateway logs', 'network captures', 'certificate inventories', 'update manifests', 'asset inventory records', 'alert events'],
    best: ['secure lifecycle management', 'least functionality', 'continuous patching', 'device attestation', 'supply chain validation', 'segment by trust zone', 'fail-safe defaults', 'decommissioning controls']
  },
  'Database Security': {
    controls: ['role-based access control', 'database activity monitoring', 'transparent data encryption', 'parameterized queries', 'backup encryption', 'row-level security', 'audit logging', 'tokenization'],
    threats: ['SQL injection', 'privilege abuse', 'data exfiltration', 'weak authentication', 'unpatched DB engine', 'backup theft', 'misconfigured replication', 'inference attacks'],
    artifacts: ['query logs', 'audit trails', 'backup logs', 'privilege tables', 'replication status', 'error logs', 'configuration baselines', 'integrity check outputs'],
    best: ['least privilege', 'separation of duties', 'encryption at rest and in transit', 'regular patching', 'data classification', 'secure backup lifecycle', 'continuous monitoring', 'access recertification']
  },
  'API Security': {
    controls: ['OAuth 2.0 scopes', 'rate limiting', 'schema validation', 'API gateway policies', 'mTLS', 'JWT validation', 'input sanitization', 'idempotency keys'],
    threats: ['broken object level authorization', 'mass assignment', 'token replay', 'API key leakage', 'injection attacks', 'excessive data exposure', 'resource exhaustion', 'improper asset management'],
    artifacts: ['API gateway logs', 'auth server logs', 'request traces', 'OpenAPI specs', 'WAF logs', 'error metrics', 'token audit logs', 'SIEM correlations'],
    best: ['zero trust for APIs', 'least privilege scopes', 'version governance', 'secure defaults', 'contract testing', 'observability', 'threat modeling', 'continuous testing']
  },
  'Identity and Access Management (IAM)': {
    controls: ['multi-factor authentication', 'single sign-on', 'conditional access', 'privileged access management', 'role engineering', 'access recertification', 'just-in-time access', 'federation controls'],
    threats: ['credential stuffing', 'password spraying', 'session hijacking', 'privilege escalation', 'orphaned accounts', 'MFA fatigue attacks', 'token theft', 'insider misuse'],
    artifacts: ['auth logs', 'directory records', 'access review reports', 'PAM session logs', 'identity governance tickets', 'risk signals', 'token issuance logs', 'account lifecycle events'],
    best: ['least privilege', 'segregation of duties', 'strong authentication', 'continuous verification', 'joiner-mover-leaver process', 'policy-based access', 'identity-centric monitoring', 'regular attestation']
  },
  'Email Security': {
    controls: ['SPF', 'DKIM', 'DMARC', 'secure email gateway', 'attachment sandboxing', 'URL rewriting', 'mailbox auditing', 'phishing simulation training'],
    threats: ['business email compromise', 'phishing', 'malicious attachments', 'lookalike domains', 'reply-chain hijacking', 'credential harvesting', 'invoice fraud', 'thread spoofing'],
    artifacts: ['mail headers', 'gateway logs', 'sandbox verdicts', 'user-reported phish samples', 'domain authentication reports', 'message traces', 'SOC tickets', 'blocklist events'],
    best: ['user awareness', 'sender authentication', 'least privilege mailbox access', 'rapid reporting workflows', 'continuous tuning', 'domain monitoring', 'out-of-band verification', 'incident playbooks']
  },
  'Social Engineering Protection': {
    controls: ['security awareness training', 'verification callbacks', 'role-based approval workflows', 'phishing simulations', 'visitor access controls', 'red team exercises', 'reporting hotline', 'identity verification procedures'],
    threats: ['pretexting', 'baiting', 'tailgating', 'vishing', 'smishing', 'impersonation', 'quid pro quo scams', 'deepfake-enabled fraud'],
    artifacts: ['training records', 'simulated campaign results', 'call logs', 'badge access logs', 'incident reports', 'chat transcripts', 'escalation tickets', 'awareness metrics'],
    best: ['trust but verify', 'least privilege', 'dual control approvals', 'clear escalation paths', 'human firewall culture', 'continuous reinforcement', 'scenario-based drills', 'leadership support']
  },
  'Threat Intelligence': {
    controls: ['threat intelligence platform', 'IOC enrichment', 'TTP mapping', 'feed validation', 'sharing agreements', 'threat hunting workflows', 'detection engineering', 'intelligence requirements process'],
    threats: ['APT campaigns', 'ransomware groups', 'supply chain attacks', 'credential theft operations', 'botnet activity', 'phishing campaigns', 'zero-day exploitation', 'financial fraud operations'],
    artifacts: ['IOCs', 'YARA rules', 'Sigma rules', 'STIX/TAXII feeds', 'adversary profiles', 'campaign timelines', 'detection gaps', 'hunting reports'],
    best: ['intelligence-led defense', 'context over volume', 'source reliability scoring', 'timely dissemination', 'feedback loops', 'mission alignment', 'cross-team collaboration', 'measurable outcomes']
  },
  'Penetration Testing (Ethical Hacking)': {
    controls: ['rules of engagement', 'written authorization', 'scope definition', 'evidence handling', 'safe exploit practices', 'report validation', 'remediation tracking', 'retest procedures'],
    threats: ['web application vulnerabilities', 'weak credentials', 'misconfigurations', 'unpatched services', 'wireless exposure', 'social engineering vectors', 'privilege escalation paths', 'lateral movement opportunities'],
    artifacts: ['scan outputs', 'exploit logs', 'screenshots', 'proof-of-concept payloads', 'finding severity ratings', 'attack path diagrams', 'final reports', 'retest results'],
    best: ['ethics and legality', 'minimal impact testing', 'risk-based prioritization', 'clear communication', 'reproducibility', 'evidence quality', 'actionable remediation', 'continuous improvement']
  },
  'Digital Forensics': {
    controls: ['chain of custody', 'forensic imaging', 'write blockers', 'time synchronization', 'evidence hashing', 'analysis playbooks', 'tool validation', 'secure evidence storage'],
    threats: ['log tampering', 'anti-forensics', 'data destruction', 'steganography misuse', 'insider sabotage', 'malware persistence', 'fileless attacks', 'timeline obfuscation'],
    artifacts: ['disk images', 'memory dumps', 'event logs', 'timeline analysis', 'hash reports', 'artifact parsers output', 'network captures', 'forensic notes'],
    best: ['repeatability', 'integrity preservation', 'documentation discipline', 'legal defensibility', 'least alteration', 'peer review', 'evidence correlation', 'objective reporting']
  },
  'Governance, Risk & Compliance (GRC)': {
    controls: ['policy framework', 'risk assessments', 'control testing', 'compliance audits', 'exception management', 'third-party risk reviews', 'board reporting', 'control ownership'],
    threats: ['regulatory non-compliance', 'control failures', 'unmanaged risk acceptance', 'audit findings backlog', 'vendor risk exposure', 'policy drift', 'insufficient oversight', 'fraud risk'],
    artifacts: ['risk register', 'control matrix', 'audit reports', 'compliance attestations', 'remediation plans', 'policy documents', 'KRI dashboards', 'issue logs'],
    best: ['tone at the top', 'risk-based decision making', 'continuous control monitoring', 'clear accountability', 'evidence-based assurance', 'proportionate controls', 'timely remediation', 'transparent reporting']
  },
  'Privacy & Data Protection': {
    controls: ['data minimization', 'purpose limitation', 'consent management', 'data subject rights workflow', 'privacy impact assessments', 'encryption', 'retention controls', 'cross-border transfer safeguards'],
    threats: ['unauthorized disclosure', 'over-collection of personal data', 'third-party misuse', 'insufficient consent', 're-identification risk', 'data breach', 'excessive retention', 'shadow processing'],
    artifacts: ['records of processing activities', 'consent logs', 'DPIA reports', 'breach notification records', 'data flow maps', 'deletion logs', 'access request records', 'processor agreements'],
    best: ['privacy by design', 'accountability', 'lawfulness fairness transparency', 'security safeguards', 'data lifecycle governance', 'vendor oversight', 'incident readiness', 'continuous compliance']
  }
};

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

function pick(arr, idx) {
  return arr[idx % arr.length];
}

function makeQuestion(topic, d, i, level) {
  const c = pick(d.controls, i);
  const t = pick(d.threats, i + 1);
  const a = pick(d.artifacts, i + 2);
  const b = pick(d.best, i + 3);

  const templates = [
    () => ({
      text: `[${level}] In ${topic}, which control is MOST appropriate to reduce risk from ${t}?`,
      options: [c, pick(d.controls, i + 3), pick(d.controls, i + 4), pick(d.controls, i + 5)],
      correct: 0
    }),
    () => ({
      text: `[${level}] Which artifact would be most useful first when investigating a possible ${t} event in ${topic}?`,
      options: [a, pick(d.artifacts, i + 4), pick(d.artifacts, i + 5), pick(d.artifacts, i + 6)],
      correct: 0
    }),
    () => ({
      text: `[${level}] Which principle best aligns with improving ${topic} maturity over time?`,
      options: [b, pick(d.best, i + 4), pick(d.best, i + 5), pick(d.best, i + 6)],
      correct: 0
    }),
    () => ({
      text: `[${level}] A team detects ${t}. What should be the most effective preventive focus in ${topic}?`,
      options: [c, 'disable all logging', 'accept all default settings', 'remove all authentication checks'],
      correct: 0
    }),
    () => ({
      text: `[${level}] Which option is the BEST example of defense-in-depth for ${topic}?`,
      options: [c, pick(d.controls, i + 1), pick(d.controls, i + 2), `${c} combined with ${pick(d.controls, i + 1)}`],
      correct: 3
    }),
    () => ({
      text: `[${level}] During a review of ${topic}, which statement is most accurate?`,
      options: [
        `${b} helps sustain long-term security outcomes`,
        'Security controls eliminate all risk permanently',
        'Monitoring is unnecessary after initial deployment',
        'Documentation can replace technical controls entirely'
      ],
      correct: 0
    }),
    () => ({
      text: `[${level}] Which metric would BEST show whether ${c} is improving security in ${topic}?`,
      options: [
        `Reduction in incidents linked to ${t}`,
        'Increase in unrelated UI color changes',
        'Number of meeting invitations sent',
        'Amount of unused disk space'
      ],
      correct: 0
    }),
    () => ({
      text: `[${level}] In a tabletop exercise for ${topic}, what is the strongest response to ${t}?`,
      options: [
        `Use ${a} to validate scope, then apply ${c}`,
        'Ignore evidence and continue normal operations',
        'Delete logs to reduce storage costs',
        'Disable all alerts indefinitely'
      ],
      correct: 0
    }),
    () => ({
      text: `[${level}] Which choice most directly supports compliance and audit readiness in ${topic}?`,
      options: [a, 'No records if no incident occurs', 'Only verbal approvals', 'Ad-hoc undocumented exceptions'],
      correct: 0
    }),
    () => ({
      text: `[${level}] Which of the following is the MOST suitable strategic goal for ${topic}?`,
      options: [
        `${b} with measurable control effectiveness`,
        'One-time security hardening with no follow-up',
        'Security decisions based only on assumptions',
        'Avoiding all process documentation'
      ],
      correct: 0
    })
  ];

  const q = templates[i % templates.length]();
  q.text = `${q.text} (Case ${i + 1})`;

  // Ensure exactly 4 options and one correct answer index.
  q.options = q.options.slice(0, 4);
  if (q.options.length < 4) {
    while (q.options.length < 4) q.options.push(`Distractor ${q.options.length + 1}`);
  }

  return q;
}

function uniqueQuestionsForTopic(topic, count = 100) {
  const d = TOPIC_DATA[topic];
  const levels = ['Beginner', 'Intermediate', 'Advanced'];
  const questions = [];
  const seen = new Set();

  let i = 0;
  while (questions.length < count) {
    const level = levels[i % levels.length];
    const q = makeQuestion(topic, d, i, level);

    if (!seen.has(q.text)) {
      seen.add(q.text);
      questions.push(q);
    }

    i += 1;
    if (i > 2000) throw new Error(`Failed to generate ${count} unique questions for ${topic}`);
  }

  return questions;
}

async function upsertTopicExamWithQuestions(topic) {
  const testName = `${topic} - Mastery Exam (100 MCQs)`;
  const description = `Comprehensive ${topic} question bank with 100 MCQs (beginner/intermediate/advanced).`;

  let row = await get('SELECT id FROM tests WHERE name = ?', [testName]);
  let testId;

  if (!row) {
    const insert = await run(
      'INSERT INTO tests (name, description, duration_minutes, questions_per_attempt, instructions, max_attempts, type) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [testName, description, 90, 100, `Answer all 100 questions. Topic: ${topic}`, 0, 'exam']
    );
    testId = insert.lastID;
  } else {
    testId = row.id;
    await run(
      'UPDATE tests SET description = ?, duration_minutes = ?, questions_per_attempt = ?, instructions = ?, max_attempts = ?, type = ? WHERE id = ?',
      [description, 90, 100, `Answer all 100 questions. Topic: ${topic}`, 0, 'exam', testId]
    );
  }

  await run('DELETE FROM options WHERE question_id IN (SELECT id FROM questions WHERE test_id = ?)', [testId]);
  await run('DELETE FROM questions WHERE test_id = ?', [testId]);

  const questions = uniqueQuestionsForTopic(topic, 100);

  for (const q of questions) {
    const qRes = await run(
      'INSERT INTO questions (test_id, text, marks, question_type) VALUES (?, ?, ?, ?)',
      [testId, q.text, 1, 'single']
    );

    const qId = qRes.lastID;
    for (let idx = 0; idx < 4; idx += 1) {
      await run(
        'INSERT INTO options (question_id, text, is_correct) VALUES (?, ?, ?)',
        [qId, q.options[idx], idx === q.correct ? 1 : 0]
      );
    }
  }

  const verify = await get(
    `SELECT
      (SELECT COUNT(*) FROM questions WHERE test_id = ?) AS q_count,
      (SELECT COUNT(*) FROM options WHERE question_id IN (SELECT id FROM questions WHERE test_id = ?)) AS o_count,
      (SELECT COUNT(*) FROM questions q
         WHERE q.test_id = ?
           AND (SELECT COUNT(*) FROM options o WHERE o.question_id = q.id) = 4
      ) AS q_with_4_options,
      (SELECT COUNT(*) FROM questions q
         WHERE q.test_id = ?
           AND (SELECT COUNT(*) FROM options o WHERE o.question_id = q.id AND o.is_correct = 1) = 1
      ) AS q_with_1_correct`,
    [testId, testId, testId, testId]
  );

  if (verify.q_count !== 100 || verify.o_count !== 400 || verify.q_with_4_options !== 100 || verify.q_with_1_correct !== 100) {
    throw new Error(`Validation failed for ${topic}: ${JSON.stringify(verify)}`);
  }

  return { topic, testId, ...verify };
}

async function main() {
  const summary = [];

  try {
    await run('BEGIN TRANSACTION');

    for (const topic of TOPICS) {
      const result = await upsertTopicExamWithQuestions(topic);
      summary.push(result);
      console.log(`Seeded: ${topic} -> test_id=${result.testId}, questions=${result.q_count}, options=${result.o_count}`);
    }

    await run('COMMIT');

    const totals = await get(
      `SELECT
         COUNT(*) AS test_count,
         SUM(qc) AS total_questions,
         SUM(oc) AS total_options
       FROM (
         SELECT t.id,
                (SELECT COUNT(*) FROM questions q WHERE q.test_id = t.id) AS qc,
                (SELECT COUNT(*) FROM options o WHERE o.question_id IN (SELECT q2.id FROM questions q2 WHERE q2.test_id = t.id)) AS oc
         FROM tests t
         WHERE t.name LIKE '% - Mastery Exam (100 MCQs)'
       )`
    );

    console.log('\n=== FINAL SUMMARY ===');
    summary.forEach(s => {
      console.log(`${s.topic}: questions=${s.q_count}, options=${s.o_count}`);
    });
    console.log(`TOTAL exams=${totals.test_count}, questions=${totals.total_questions}, options=${totals.total_options}`);
  } catch (err) {
    console.error('Seeding failed:', err.message);
    try { await run('ROLLBACK'); } catch (_) {}
    process.exitCode = 1;
  } finally {
    db.close();
  }
}

main();
