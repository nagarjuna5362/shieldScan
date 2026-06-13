/**
 * cookies.js — Checks 15-16: Cookie & Session Security
 * CHECK 15: Cookie Security Flags
 * CHECK 16: Session Token in URL
 */

const axios = require('axios');

const TIMEOUT = 8000;
const USER_AGENT = 'ShieldScan-SecurityBot/1.0 (security scanner)';

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), ms)),
  ]);
}

// CHECK 15 — Cookie Security Flags
async function checkCookieSecurity(parsedUrl) {
  const base = {
    checkId: 'cookie_security',
    checkNumber: 15,
    category: 'Cookie & Session',
    name: 'Cookie Security Flags',
  };
  try {
    const response = await withTimeout(
      axios.get(parsedUrl.href, {
        maxRedirects: 5,
        validateStatus: () => true,
        headers: { 'User-Agent': USER_AGENT },
        timeout: TIMEOUT,
      }),
      TIMEOUT
    );

    const setCookies = response.headers['set-cookie'];

    if (!setCookies || setCookies.length === 0) {
      return {
        ...base, severity: 'INFO', status: 'PASS',
        description: 'No Set-Cookie headers found on this page (cookies may be set via API)',
        technicalDetail: 'No Set-Cookie headers in response',
        attackScenario: null, fix: null, points_deducted: 0,
      };
    }

    const issues = [];
    const cookieDetails = [];

    for (const cookie of setCookies) {
      const cookieName = cookie.split('=')[0].trim();
      const cookieLower = cookie.toLowerCase();
      const cookieIssues = [];

      if (!cookieLower.includes('httponly')) cookieIssues.push('missing HttpOnly');
      if (!cookieLower.includes('secure')) cookieIssues.push('missing Secure');
      if (!cookieLower.includes('samesite')) cookieIssues.push('missing SameSite');

      if (cookieIssues.length > 0) {
        issues.push(`${cookieName}: ${cookieIssues.join(', ')}`);
        cookieDetails.push({ name: cookieName, issues: cookieIssues });
      }
    }

    if (issues.length === 0) {
      return {
        ...base, severity: 'INFO', status: 'PASS',
        description: `All ${setCookies.length} cookie(s) have proper security flags`,
        technicalDetail: `Checked cookies: ${setCookies.map(c => c.split('=')[0]).join(', ')}`,
        attackScenario: null, fix: null, points_deducted: 0,
      };
    }

    const missingHttpOnly = cookieDetails.some(c => c.issues.includes('missing HttpOnly'));
    const severity = missingHttpOnly ? 'HIGH' : 'MEDIUM';

    return {
      ...base, severity, status: 'FAIL',
      description: `Cookie security issues found: ${issues.join(' | ')}`,
      technicalDetail: `Problematic cookies: ${issues.join('; ')}`,
      attackScenario: missingHttpOnly
        ? "A single XSS vulnerability anywhere on your site + this missing HttpOnly flag = total session theft. The attacker injects document.cookie code that runs in every visitor's browser and silently posts their session token to the attacker's server. The attacker then replays that session and is logged in as that user."
        : "Without the Secure flag, session cookies are sent over plain HTTP connections. On shared WiFi, an attacker using a tool like Wireshark can capture the cookie and replay it to log in as that user. Missing SameSite allows CSRF attacks where malicious sites make requests on behalf of logged-in users.",
      fix: {
        description: 'Set all three security flags on every cookie',
        code: `// Express.js — Set secure cookie
res.cookie('sessionId', token, {
  httpOnly: true,    // Prevents XSS access
  secure: true,      // HTTPS only
  sameSite: 'Strict', // Prevents CSRF
  maxAge: 3600000,   // 1 hour
});

// Express-session
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 3600000,
  },
}));`,
      },
      points_deducted: missingHttpOnly ? 10 : 5,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `Cookie security check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

// CHECK 16 — Session Token in URL
async function checkSessionInUrl(parsedUrl) {
  const base = {
    checkId: 'session_in_url',
    checkNumber: 16,
    category: 'Cookie & Session',
    name: 'Session Token in URL',
  };

  const sessionParams = ['sessionid', 'token', 'auth', 'session', 'sid', 'jsessionid', 'phpsessid', 'access_token', 'authtoken', 'apikey', 'api_key'];

  try {
    const searchParams = parsedUrl.searchParams;
    const foundParams = [];

    for (const param of sessionParams) {
      if (searchParams.has(param)) {
        foundParams.push(param);
      }
    }

    // Check URL string for common patterns
    const urlStr = parsedUrl.href.toLowerCase();
    for (const param of sessionParams) {
      if (urlStr.includes(`?${param}=`) || urlStr.includes(`&${param}=`)) {
        if (!foundParams.includes(param)) foundParams.push(param);
      }
    }

    if (foundParams.length > 0) {
      return {
        ...base, severity: 'HIGH', status: 'FAIL',
        description: `Session/auth token found in URL parameters: ${foundParams.join(', ')}`,
        technicalDetail: `URL contains sensitive parameter names: ${foundParams.join(', ')}`,
        attackScenario: `The token in your URL (${parsedUrl.search}) gets stored in: browser history (anyone with device access), web server access logs (any sysadmin), referrer headers (every external site you link to), and browser analytics tools. Anyone with access to these logs can steal active sessions without any hacking knowledge.`,
        fix: {
          description: 'Move tokens from URL to HTTP headers or secure cookies',
          code: `// Instead of: GET /api/data?token=abc123
// Use Authorization header:
fetch('/api/data', {
  headers: { 'Authorization': 'Bearer ' + token }
});

// Or use secure cookies (set server-side with httpOnly flag)
// Never put tokens in URL query parameters`,
        },
        points_deducted: 10,
      };
    }

    return {
      ...base, severity: 'INFO', status: 'PASS',
      description: 'No session tokens or auth parameters detected in the URL',
      technicalDetail: `URL query string checked: ${parsedUrl.search || 'none'}`,
      attackScenario: null, fix: null, points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `Session URL check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

module.exports = { checkCookieSecurity, checkSessionInUrl };
