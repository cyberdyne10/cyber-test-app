// seed_network_set1_fixed.js
// Reset questions for test_id=2 (Network Security – Set 1) and insert 20 questions

const db = require('./db');

const TEST_ID = 2;

const questions = [
  {
    text: 'Which device is primarily used to segment a network into multiple broadcast domains?',
    options: ['Hub', 'Switch', 'Router', 'Repeater'],
    correct: 2
  },
  {
    text: 'Which protocol is commonly used to securely manage network devices via the command line?',
    options: ['Telnet', 'FTP', 'SSH', 'SNMPv1'],
    correct: 2
  },
  {
    text: 'What is the main purpose of a firewall in a network?',
    options: ['Increase bandwidth', 'Filter traffic based on rules', 'Provide DNS services', 'Assign IP addresses'],
    correct: 1
  },
  {
    text: 'Which port does HTTPS typically use?',
    options: ['80', '21', '22', '443'],
    correct: 3
  },
  {
    text: 'What does VLAN stand for?',
    options: ['Virtual Local Area Network', 'Verified Local Access Network', 'Virtual Logical Address Node', 'Variable Local Area Node'],
    correct: 0
  },
  {
    text: 'Which attack floods a target with SYN packets without completing the handshake?',
    options: ['Smurf attack', 'SYN flood', 'ARP poisoning', 'DNS poisoning'],
    correct: 1
  },
  {
    text: 'Which protocol is used to automatically assign IP addresses to hosts?',
    options: ['DNS', 'DHCP', 'ICMP', 'BGP'],
    correct: 1
  },
  {
    text: 'What type of record does DNS use to map a hostname to an IPv4 address?',
    options: ['MX record', 'AAAA record', 'CNAME record', 'A record'],
    correct: 3
  },
  {
    text: 'Which layer of the OSI model is responsible for end-to-end reliable delivery?',
    options: ['Network layer', 'Data Link layer', 'Transport layer', 'Session layer'],
    correct: 2
  },
  {
    text: 'Which tool is commonly used to capture and analyze network traffic?',
    options: ['Wireshark', 'Nmap', 'Metasploit', 'Burp Suite'],
    correct: 0
  },
  {
    text: 'Which protocol is commonly used for secure web browsing?',
    options: ['HTTP', 'HTTPS', 'FTP', 'TFTP'],
    correct: 1
  },
  {
    text: 'What is network segmentation mainly used for in security?',
    options: ['To increase Wi-Fi speed', 'To isolate and limit access between parts of a network', 'To reduce cable length', 'To provide internet access'],
    correct: 1
  },
  {
    text: 'Which wireless security protocol is currently recommended for home and enterprise Wi-Fi?',
    options: ['WEP', 'WPA', 'WPA2', 'WPA3'],
    correct: 3
  },
  {
    text: 'What does IDS stand for in network security?',
    options: ['Internal Defense System', 'Intrusion Detection System', 'Internet Defense Service', 'Information Detection Scheme'],
    correct: 1
  },
  {
    text: 'Which of the following is an example of a Layer 3 device?',
    options: ['Switch', 'Bridge', 'Router', 'Hub'],
    correct: 2
  },
  {
    text: 'Which protocol is used to securely transfer files over a network using SSH?',
    options: ['FTP', 'SFTP', 'TFTP', 'HTTP'],
    correct: 1
  },
  {
    text: 'What is the primary purpose of NAT (Network Address Translation)?',
    options: ['Encrypt data on the network', 'Translate private IP addresses to public IP addresses', 'Assign MAC addresses', 'Provide DHCP services'],
    correct: 1
  },
  {
    text: 'Which type of attack involves intercepting and altering communication between two parties?',
    options: ['Brute-force attack', 'Man-in-the-middle attack', 'Phishing attack', 'Denial-of-service attack'],
    correct: 1
  },
  {
    text: 'Which protocol is used by ping to test connectivity between hosts?',
    options: ['TCP', 'UDP', 'ICMP', 'ARP'],
    correct: 2
  },
  {
    text: 'Which device is best suited to create a DMZ (demilitarized zone) in a network?',
    options: ['Layer 2 switch', 'Router or firewall with multiple interfaces', 'Hub', 'Wireless access point'],
    correct: 1
  }
];

function resetAndSeed() {
  db.serialize(() => {
    db.run('DELETE FROM options WHERE question_id IN (SELECT id FROM questions WHERE test_id = ?)', [TEST_ID]);
    db.run('DELETE FROM questions WHERE test_id = ?', [TEST_ID], err => {
      if (err) {
        console.error('Error clearing old questions:', err.message);
        process.exit(1);
      }
      console.log('Old questions cleared for test', TEST_ID);

      const insertQuestion = db.prepare('INSERT INTO questions (test_id, text) VALUES (?, ?)');
      const insertOption = db.prepare('INSERT INTO options (question_id, text, is_correct) VALUES (?, ?, ?)');

      let index = 0;

      function next() {
        if (index >= questions.length) {
          insertQuestion.finalize();
          insertOption.finalize(() => {
            console.log('Seeding complete.');
            db.close();
          });
          return;
        }
        const q = questions[index++];
        insertQuestion.run(TEST_ID, q.text, function (err2) {
          if (err2) {
            console.error('Error inserting question:', err2.message);
            return next();
          }
          const qId = this.lastID;
          q.options.forEach((optText, optIdx) => {
            const isCorrect = optIdx === q.correct ? 1 : 0;
            insertOption.run(qId, optText, isCorrect);
          });
          next();
        });
      }

      next();
    });
  });
}

resetAndSeed();
