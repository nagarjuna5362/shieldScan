
const axios = require('axios');

const TIMEOUT = 8000;
const USER_AGENT = 'ShieldScan-SecurityBot/1.0 (security scanner)';

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), ms)),
  ]);
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function checkRateLimiting(parsedUrl) {
  const base = {
    checkId: 'rate_limiting',
    checkNumber: 23,
    category: 'Rate Limiting & Abuse',
    name: 'Rate Limiting Detection',
  };

  try {
    
    let probeResponse;
    try {
      probeResponse = await withTimeout(
        axios.get(parsedUrl.href, {
          validateStatus: () => true,
          headers: { 'User-Agent': USER_AGENT },
          timeout: TIMEOUT,
        }),
        TIMEOUT
      );
    } catch {
      probeResponse = null;
    }

    if (probeResponse) {
      const h = probeResponse.headers;
      const server = (h['server'] || '').toLowerCase();
      const via = (h['via'] || '').toLowerCase();

      if (h['cf-ray'] || server.includes('cloudflare')) {
        return {
          ...base, severity: 'INFO', status: 'PASS',
          description: 'Cloudflare WAF detected — enterprise-grade rate limiting and DDoS protection active',
          technicalDetail: `CF-Ray: ${h['cf-ray'] || 'detected via Server header'} — Cloudflare handles automated rate limiting`,
          attackScenario: null, fix: null, points_deducted: 0,
        };
      }
      
      if (h['x-amz-cf-id'] || h['x-amzn-requestid'] || via.includes('cloudfront')) {
        return {
          ...base, severity: 'INFO', status: 'PASS',
          description: 'AWS CloudFront/WAF detected — automated rate limiting and DDoS protection active',
          technicalDetail: `AWS protection headers present`,
          attackScenario: null, fix: null, points_deducted: 0,
        };
      }
      
      if (h['x-served-by']?.includes('fastly') || h['x-fastly-request-id']) {
        return {
          ...base, severity: 'INFO', status: 'PASS',
          description: 'Fastly CDN detected — rate limiting and DDoS protection active',
          technicalDetail: `Fastly CDN headers detected`,
          attackScenario: null, fix: null, points_deducted: 0,
        };
      }
      
      if (h['x-akamai-transformed'] || h['x-check-cacheable'] || server.includes('akamai')) {
        return {
          ...base, severity: 'INFO', status: 'PASS',
          description: 'Akamai CDN detected — enterprise rate limiting and DDoS protection active',
          technicalDetail: `Akamai CDN headers detected`,
          attackScenario: null, fix: null, points_deducted: 0,
        };
      }
      
      if (h['ratelimit-limit'] || h['x-ratelimit-limit'] || h['retry-after'] ||
          h['x-rate-limit-limit'] || h['x-rate-limit-remaining']) {
        return {
          ...base, severity: 'INFO', status: 'PASS',
          description: 'Rate limiting headers detected — server actively limits request rates',
          technicalDetail: `Headers: ${[
            h['ratelimit-limit'] && `RateLimit-Limit: ${h['ratelimit-limit']}`,
            h['x-ratelimit-limit'] && `X-RateLimit-Limit: ${h['x-ratelimit-limit']}`,
            h['retry-after'] && `Retry-After: ${h['retry-after']}`,
          ].filter(Boolean).join(', ')}`,
          attackScenario: null, fix: null, points_deducted: 0,
        };
      }
    }

    const rapidRequests = Array.from({ length: 15 }, () =>
      withTimeout(
        axios.get(parsedUrl.href, {
          validateStatus: () => true,
          headers: { 'User-Agent': USER_AGENT },
          timeout: 5000,
        }),
        5000
      ).then(r => r.status).catch(() => null)
    );

    const statuses = await Promise.all(rapidRequests);
    const has429 = statuses.some(s => s === 429);
    const has503 = statuses.some(s => s === 503);

    if (has429 || has503) {
      return {
        ...base, severity: 'INFO', status: 'PASS',
        description: `Rate limiting confirmed — server responded with ${has429 ? '429 Too Many Requests' : '503'} under rapid requests`,
        technicalDetail: `Response codes: ${[...new Set(statuses.filter(Boolean))].join(', ')}`,
        attackScenario: null, fix: null, points_deducted: 0,
      };
    }

    return {
      ...base, severity: 'HIGH', status: 'FAIL',
      description: 'No rate limiting detected — server accepted all rapid requests without throttling',
      technicalDetail: `Sent 15 rapid requests — all returned ${[...new Set(statuses.filter(Boolean))].join('/')}. No 429/503 responses or RateLimit headers observed.`,
      attackScenario: 'An attacker can brute-force login passwords (trying millions of combinations), scrape all your data automatically, spam your contact forms, and overload your server with a simple script. Without rate limiting there is no defence against automated abuse.',
      fix: {
        description: 'Implement rate limiting on all endpoints, especially login',
        code: `// Express.js (express-rate-limit)\nconst rateLimit = require('express-rate-limit');\n\n// General API limit\napp.use('/api/', rateLimit({ windowMs: 15*60*1000, max: 100 }));\n\n// Strict login limit\napp.use('/api/login', rateLimit({ windowMs: 15*60*1000, max: 5 }));\n\n// Or use Cloudflare / Nginx:\n# Nginx rate limiting\nlimit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\nlimit_req zone=api burst=20 nodelay;`,
      },
      points_deducted: 10,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `Rate limiting check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

async function checkOpenRedirect(parsedUrl) {
  const base = {
    checkId: 'open_redirect',
    checkNumber: 24,
    category: 'Rate Limiting & Abuse',
    name: 'Open Redirect Vulnerability',
  };

  const testTarget = 'https://evil-redirect-test-12345.com';
  const redirectPaths = [
    `/redirect?url=${testTarget}`,
    `/redirect?next=${testTarget}`,
    `/out?url=${testTarget}`,
    `/?goto=${testTarget}`,
    `/login?return=${testTarget}`,
    `/go?to=${testTarget}`,
    `/r?url=${testTarget}`,
    `/exit?url=${testTarget}`,
  ];

  try {
    const vulnerable = [];

    for (const path of redirectPaths) {
      try {
        const response = await withTimeout(
          axios.get(`${parsedUrl.origin}${path}`, {
            maxRedirects: 0,
            validateStatus: () => true,
            headers: { 'User-Agent': USER_AGENT },
            timeout: TIMEOUT,
          }),
          TIMEOUT
        );

        if ((response.status === 301 || response.status === 302 || response.status === 307) &&
            response.headers['location'] &&
            response.headers['location'].includes('evil-redirect-test-12345.com')) {
          vulnerable.push({ path, location: response.headers['location'] });
        }
      } catch {  }
    }

    if (vulnerable.length > 0) {
      return {
        ...base, severity: 'HIGH', status: 'FAIL',
        description: `Open redirect vulnerability found at: ${vulnerable.map(v => v.path.split('?')[0]).join(', ')}`,
        technicalDetail: `Redirect to external domain confirmed: ${vulnerable.map(v => `${parsedUrl.origin}${v.path} → ${v.location}`).join(', ')}`,
        attackScenario: "An attacker sends your customer an email: 'Your order is ready! Track it here: yourdomain.com/redirect?url=evil.com'. The customer sees your legitimate domain in the link, clicks it, and gets silently redirected to a phishing site that looks exactly like yours. They enter their password thinking they're logging into your site.",
        fix: {
          description: 'Validate redirect destinations against an allowlist',
          code: `// Express.js — Safe redirect
const ALLOWED_REDIRECT_HOSTS = ['yourdomain.com', 'app.yourdomain.com'];

app.get('/redirect', (req, res) => {
  const url = req.query.url || req.query.next || req.query.return;
  if (!url) return res.redirect('/');
  
  try {
    const parsed = new URL(url);
    if (ALLOWED_REDIRECT_HOSTS.includes(parsed.hostname)) {
      return res.redirect(url);
    }
  } catch {}
  
  // If invalid or not in allowlist, redirect to home
  res.redirect('/');
});`,
        },
        points_deducted: 10,
      };
    }

    return {
      ...base, severity: 'INFO', status: 'PASS',
      description: 'No open redirect vulnerabilities detected at common redirect paths',
      technicalDetail: `Tested ${redirectPaths.length} redirect patterns — none redirected to external domain`,
      attackScenario: null, fix: null, points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `Open redirect check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

async function checkSecurityTxt(parsedUrl) {
  const base = {
    checkId: 'security_txt',
    checkNumber: 25,
    category: 'Rate Limiting & Abuse',
    name: 'Security.txt File',
  };

  const paths = ['/.well-known/security.txt', '/security.txt'];

  try {
    for (const path of paths) {
      try {
        const response = await withTimeout(
          axios.get(`${parsedUrl.origin}${path}`, {
            validateStatus: () => true,
            headers: { 'User-Agent': USER_AGENT },
            timeout: TIMEOUT,
          }),
          TIMEOUT
        );

        if (response.status === 200 && response.data) {
          const content = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
          if (content.includes('Contact:') || content.includes('contact:')) {
            return {
              ...base, severity: 'INFO', status: 'PASS',
              description: `security.txt found at ${path} — vulnerability disclosure contact is configured`,
              technicalDetail: `Found at ${parsedUrl.origin}${path}: ${content.substring(0, 200)}`,
              attackScenario: null, fix: null, points_deducted: 0,
            };
          }
        }
      } catch {  }
    }

    return {
      ...base, severity: 'LOW', status: 'FAIL',
      description: 'security.txt file is missing — no vulnerability disclosure contact configured',
      technicalDetail: `Checked /.well-known/security.txt and /security.txt — not found`,
      attackScenario: "When security researchers find real vulnerabilities in your site, they have no way to contact you responsibly. So they either do nothing (bug stays unfixed), sell the vulnerability to malicious actors, or publicly disclose it before you can patch it. Meanwhile, real attackers are exploiting that same bug.",
      fix: {
        description: 'Create a security.txt file to enable responsible disclosure',
        code: `# Create /.well-known/security.txt with:
Contact: mailto:security@yourdomain.com
Expires: 2025-12-31T23:59:59Z
Preferred-Languages: en
Policy: https://yourdomain.com/security-policy

# Generator: https://securitytxt.org/`,
      },
      points_deducted: 2,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `Security.txt check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

module.exports = { checkRateLimiting, checkOpenRedirect, checkSecurityTxt };
