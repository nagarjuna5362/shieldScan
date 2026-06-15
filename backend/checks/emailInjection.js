const axios = require('axios');

const TIMEOUT = 4000;
const USER_AGENT = 'ShieldScan-SecurityBot/1.0 (security scanner)';

async function checkEmailInjection(parsedUrl) {
  const base = {
    checkId: 'email_injection',
    checkNumber: 29,
    category: 'CORS & API Security',
    name: 'Email Header Injection (CRLF)',
  };

  const testPaths = ['/contact', '/api/contact', '/sendmail', '/mail.php', '/contact.php'];
  const vulnerable = [];
  const checked = [];

  for (const path of testPaths) {
    const url = `${parsedUrl.origin}${path}`;
    try {
      // Send a test payload with CRLF injection sequence:
      // Try to inject a Bcc: header into the email parameter
      const injectPayload = {
        name: 'ShieldScan Tester',
        email: 'test@example.com\r\nBcc: spam-target@attacker.com',
        subject: 'Vulnerability Assessment Test',
        message: 'Non-destructive test request.',
      };

      const response = await axios.post(url, injectPayload, {
        headers: { 'User-Agent': USER_AGENT },
        timeout: TIMEOUT,
        validateStatus: () => true,
      });

      // If the mail script/handler exists (indicated by 200/201/204 response)
      // and it didn't throw a validation error (400 Bad Request), it might be accepting CRLF input.
      if (response.status >= 200 && response.status < 300) {
        vulnerable.push(`${path} (Accepted injection payload with status ${response.status})`);
      }
      
      if (response.status !== 404) {
        checked.push(path);
      }
    } catch {
      // Request failed or connection timed out
    }
  }

  if (vulnerable.length > 0) {
    return {
      ...base,
      severity: 'HIGH',
      status: 'FAIL',
      description: `Potential email header injection vulnerability on endpoints: ${vulnerable.join(', ')}`,
      technicalDetail: `Endpoints accepted unescaped CRLF inputs: ${vulnerable.join(' | ')}`,
      attackScenario:
        'Email Header Injection (CRLF) occurs when a contact form or mail script writes raw user input directly into outgoing SMTP headers. An attacker can insert carriage return line feed (CRLF) characters to inject additional SMTP commands, such as "Bcc:", to send anonymous spam emails to thousands of recipients from your domain.',
      fix: {
        description: 'Sanitize user inputs by stripping carriage returns (\\r) and line feeds (\\n) before writing to email templates or headers',
        code: `# PHP Sanitization Example
$email = $_POST['email'];
// Strip CRLF characters
$email = str_replace(array("\\r", "\\n", "%0a", "%0d"), "", $email);

# Node.js Express Sanitization
const cleanInput = (str) => {
  return typeof str === 'string' ? str.replace(/[\\r\\n]/g, '') : '';
};
const email = cleanInput(req.body.email);`,
      },
      points_deducted: 10,
    };
  }

  return {
    ...base,
    severity: 'INFO',
    status: 'PASS',
    description: 'No exposed or vulnerable contact/mail endpoints detected',
    technicalDetail: checked.length 
      ? `Checked active mailer endpoints: ${checked.join(', ')} — all rejected or absent.`
      : 'Probed common contact and mail form paths (contact, sendmail, mail.php) — none were exposed or vulnerable.',
    attackScenario: null,
    fix: null,
    points_deducted: 0,
  };
}

module.exports = { checkEmailInjection };
