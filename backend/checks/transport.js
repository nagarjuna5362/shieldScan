/**
 * transport.js — Checks 1-4: Transport Security
 * CHECK 1: HTTPS Enforcement
 * CHECK 2: SSL/TLS Certificate Validity
 * CHECK 3: HSTS Header
 * CHECK 4: TLS Version
 */

const axios = require('axios');
const tls = require('tls');

const TIMEOUT = 8000;
const USER_AGENT = 'ShieldScan-SecurityBot/1.0 (security scanner)';

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), ms)),
  ]);
}

// CHECK 1 — HTTPS Enforcement
async function checkHttpsEnforcement(parsedUrl) {
  const base = {
    checkId: 'https_enforcement',
    checkNumber: 1,
    category: 'Transport Security',
    name: 'HTTPS Enforcement',
  };

  // If the scanned URL is already HTTPS, also verify HTTP redirects to it
  const httpUrl = `http://${parsedUrl.hostname}${parsedUrl.pathname || '/'}`;

  try {
    // Follow up to 5 redirects to find the final destination
    const response = await withTimeout(
      axios.get(httpUrl, {
        maxRedirects: 5,           // follow the chain
        validateStatus: () => true,
        headers: { 'User-Agent': USER_AGENT },
        timeout: TIMEOUT,
      }),
      TIMEOUT
    );

    // Check the final URL we landed on
    const finalUrl = response.request?.res?.responseUrl || response.config?.url || '';
    const finalIsHttps = finalUrl.startsWith('https://');

    // Also check the first-hop redirect header
    const loc = response.headers['location'] || '';
    const firstHopIsHttps = loc.startsWith('https://');

    // If status is 2xx AND the final URL is https — properly redirected
    if ((response.status >= 200 && response.status < 300) && finalIsHttps) {
      return {
        ...base,
        severity: 'INFO',
        status: 'PASS',
        description: `Site redirects HTTP to HTTPS correctly (final URL: ${finalUrl.substring(0, 60)})`,
        technicalDetail: `HTTP request followed redirects and landed on HTTPS`,
        attackScenario: null,
        fix: null,
        points_deducted: 0,
      };
    }

    // If we ended up on HTTP still — no redirect
    if (response.status >= 200 && response.status < 300 && !finalIsHttps) {
      return {
        ...base,
        severity: 'CRITICAL',
        status: 'FAIL',
        description: 'Site serves content over plain HTTP — no HTTPS redirect detected',
        technicalDetail: `HTTP ${response.status} response at ${httpUrl} — final URL is not HTTPS`,
        attackScenario:
          'Anyone on the same network (coffee shop Wi-Fi, hotel, airport) can read and modify ALL traffic between the user and your site — passwords, form data, session tokens. This is a classic Man-in-the-Middle attack.',
        fix: {
          description: 'Configure your server to redirect all HTTP traffic to HTTPS',
          code: `# Nginx\nserver {\n  listen 80;\n  return 301 https://$host$request_uri;\n}\n\n# Apache .htaccess\nRewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n\n# Express.js\napp.use((req,res,next) => {\n  if (req.headers['x-forwarded-proto'] !== 'https') {\n    return res.redirect(301, 'https://' + req.headers.host + req.url);\n  }\n  next();\n});`,
        },
        points_deducted: 15,
      };
    }

    // Non-2xx but has https location redirect — good
    if (firstHopIsHttps || (response.status >= 300 && response.status < 400 && loc.startsWith('https'))) {
      return {
        ...base,
        severity: 'INFO',
        status: 'PASS',
        description: `HTTP properly redirects to HTTPS (${response.status} → ${loc.substring(0, 60)})`,
        technicalDetail: `HTTP ${response.status} redirect to: ${loc}`,
        attackScenario: null,
        fix: null,
        points_deducted: 0,
      };
    }

    // Anything else (4xx, 5xx on HTTP) is treated as PASS — server likely refuses plain HTTP
    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: `HTTP port returns status ${response.status} — likely not serving plain HTTP`,
      technicalDetail: `HTTP ${response.status} at ${httpUrl}`,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };

  } catch (err) {
    // ECONNREFUSED = port 80 not open = server only runs HTTPS = PASS
    const isRefused = err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' ||
      (err.message && (err.message.includes('ECONNREFUSED') || err.message.includes('ENOTFOUND')));
    if (isRefused) {
      return {
        ...base,
        severity: 'INFO',
        status: 'PASS',
        description: 'Server does not accept plain HTTP connections (port 80 refused) — HTTPS only',
        technicalDetail: `HTTP connection refused: ${err.message}`,
        attackScenario: null,
        fix: null,
        points_deducted: 0,
      };
    }
    // Timeout or other network error
    return {
      ...base,
      severity: 'INFO',
      status: 'ERROR',
      description: `Could not test HTTP redirect: ${err.message}`,
      technicalDetail: err.message,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }
}

// CHECK 2 — SSL/TLS Certificate Validity
async function checkSslCertificate(parsedUrl) {
  const base = {
    checkId: 'ssl_certificate',
    checkNumber: 2,
    category: 'Transport Security',
    name: 'SSL/TLS Certificate Validity',
  };

  if (parsedUrl.protocol === 'http:') {
    return {
      ...base,
      severity: 'CRITICAL',
      status: 'FAIL',
      description: 'Site uses HTTP — no SSL/TLS certificate present',
      technicalDetail: 'Protocol is HTTP, no TLS connection possible',
      attackScenario: 'Without SSL/TLS, all traffic is unencrypted. Attackers can intercept and read all data.',
      fix: {
        description: 'Install an SSL certificate. Use Let\'s Encrypt for free certificates.',
        code: `# Install certbot and get free certificate
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com`,
      },
      points_deducted: 20,
    };
  }

  return new Promise((resolve) => {
    const hostname = parsedUrl.hostname;
    const timeout = setTimeout(() => {
      resolve({
        ...base,
        severity: 'INFO',
        status: 'ERROR',
        description: 'TLS certificate check timed out',
        technicalDetail: 'Connection timed out after 8 seconds',
        attackScenario: null,
        fix: null,
        points_deducted: 0,
      });
    }, TIMEOUT);

    try {
      const socket = tls.connect(
        { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false },
        () => {
          clearTimeout(timeout);
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          const authError = socket.authorizationError;
          socket.destroy();

          if (!cert || !cert.subject) {
            return resolve({
              ...base,
              severity: 'HIGH',
              status: 'FAIL',
              description: 'No valid certificate found on port 443',
              technicalDetail: 'No peer certificate returned',
              attackScenario: 'Without a valid certificate, browsers will warn users. Attackers can intercept traffic using fake certificates.',
              fix: { description: 'Install a valid SSL certificate from a trusted CA', code: 'sudo certbot --nginx -d yourdomain.com' },
              points_deducted: 10,
            });
          }

          const now = new Date();
          const expiry = new Date(cert.valid_to);
          const isExpired = expiry < now;
          const daysLeft = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
          const isExpiringSoon = daysLeft < 30 && daysLeft > 0;

          const isSelfSigned =
            cert.issuer && cert.subject &&
            JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);

          const issues = [];
          let severity = 'INFO';
          let status = 'PASS';

          if (isExpired) { issues.push('Certificate is EXPIRED'); severity = 'HIGH'; status = 'FAIL'; }
          if (isSelfSigned) { issues.push('Certificate is self-signed'); if (severity !== 'HIGH') { severity = 'HIGH'; status = 'FAIL'; } }
          if (!authorized && authError) { issues.push(`Auth error: ${authError}`); if (severity !== 'HIGH') { severity = 'HIGH'; status = 'FAIL'; } }
          if (isExpiringSoon) { issues.push(`Certificate expires in ${daysLeft} days`); if (status === 'PASS') { severity = 'MEDIUM'; status = 'WARNING'; } }

          if (status === 'PASS') {
            return resolve({
              ...base,
              severity: 'INFO',
              status: 'PASS',
              description: `Valid SSL certificate — expires ${expiry.toDateString()} (${daysLeft} days)`,
              technicalDetail: `Issuer: ${cert.issuer?.O || 'Unknown'}, Valid until: ${cert.valid_to}`,
              attackScenario: null,
              fix: null,
              points_deducted: 0,
            });
          }

          return resolve({
            ...base,
            severity,
            status,
            description: `SSL Certificate issues: ${issues.join(', ')}`,
            technicalDetail: `Expires: ${cert.valid_to}, Issuer: ${JSON.stringify(cert.issuer)}, Authorized: ${authorized}`,
            attackScenario: 'Browsers show security warnings for invalid certificates. Users who click through are vulnerable to MITM attacks where an attacker presents their own fake certificate and decrypts all traffic.',
            fix: {
              description: 'Renew or replace your SSL certificate',
              code: `# Renew Let's Encrypt certificate
sudo certbot renew
# Or force renewal
sudo certbot renew --force-renewal`,
            },
            points_deducted: severity === 'HIGH' ? 10 : 5,
          });
        }
      );

      socket.on('error', (err) => {
        clearTimeout(timeout);
        resolve({
          ...base,
          severity: 'HIGH',
          status: 'FAIL',
          description: `SSL/TLS connection failed: ${err.message}`,
          technicalDetail: err.message,
          attackScenario: 'SSL connection errors prevent secure communication, forcing users to use insecure connections.',
          fix: { description: 'Check your SSL certificate configuration', code: 'openssl s_client -connect yourdomain.com:443' },
          points_deducted: 10,
        });
      });
    } catch (err) {
      clearTimeout(timeout);
      resolve({
        ...base,
        severity: 'INFO',
        status: 'ERROR',
        description: `SSL check error: ${err.message}`,
        technicalDetail: err.message,
        attackScenario: null,
        fix: null,
        points_deducted: 0,
      });
    }
  });
}

// CHECK 3 — HSTS
async function checkHsts(parsedUrl) {
  const base = {
    checkId: 'hsts',
    checkNumber: 3,
    category: 'Transport Security',
    name: 'HSTS (HTTP Strict Transport Security)',
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

    const hsts = response.headers['strict-transport-security'];

    if (!hsts) {
      return {
        ...base,
        severity: 'HIGH',
        status: 'FAIL',
        description: 'Strict-Transport-Security (HSTS) header is completely missing',
        technicalDetail: 'No Strict-Transport-Security header in response',
        attackScenario: 'An attacker performs an SSL stripping attack on a user\'s first visit. They intercept the initial HTTP request before it can redirect to HTTPS, downgrading the connection. The user sees no warning, and all data flows in plaintext through the attacker.',
        fix: {
          description: 'Add HSTS header with at least 1 year max-age',
          code: `# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Express.js
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  next();
});`,
        },
        points_deducted: 10,
      };
    }

    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
    const hasIncludeSubDomains = hsts.toLowerCase().includes('includesubdomains');
    const hasPreload = hsts.toLowerCase().includes('preload');

    if (maxAge < 31536000) {
      return {
        ...base,
        severity: 'MEDIUM',
        status: 'WARNING',
        description: `HSTS max-age is too short: ${maxAge}s (minimum recommended: 31536000s = 1 year)`,
        technicalDetail: `Strict-Transport-Security: ${hsts}`,
        attackScenario: 'Short HSTS duration means users lose HTTPS protection frequently, making them vulnerable to SSL stripping attacks more often.',
        fix: {
          description: 'Increase HSTS max-age to at least 1 year',
          code: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        },
        points_deducted: 5,
      };
    }

    const notes = [];
    if (!hasIncludeSubDomains) notes.push('includeSubDomains missing');
    if (!hasPreload) notes.push('preload missing');

    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: `HSTS properly configured — max-age: ${maxAge}s${hasIncludeSubDomains ? ', includeSubDomains' : ''}${hasPreload ? ', preload' : ''}${notes.length ? ' (Note: ' + notes.join(', ') + ')' : ''}`,
      technicalDetail: `Strict-Transport-Security: ${hsts}`,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  } catch (err) {
    return {
      ...base,
      severity: 'INFO',
      status: 'ERROR',
      description: `HSTS check failed: ${err.message}`,
      technicalDetail: err.message,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }
}

// CHECK 4 — TLS Version
async function checkTlsVersion(parsedUrl) {
  const base = {
    checkId: 'tls_version',
    checkNumber: 4,
    category: 'Transport Security',
    name: 'TLS Version Check',
  };

  if (parsedUrl.protocol === 'http:') {
    return {
      ...base,
      severity: 'INFO',
      status: 'ERROR',
      description: 'Site uses HTTP — TLS version check not applicable',
      technicalDetail: 'No TLS connection',
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }

  return new Promise((resolve) => {
    const hostname = parsedUrl.hostname;
    let resolved = false;
    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        resolve({
          ...base,
          severity: 'INFO',
          status: 'ERROR',
          description: 'TLS version check timed out',
          technicalDetail: 'Connection timed out',
          attackScenario: null,
          fix: null,
          points_deducted: 0,
        });
      }
    }, TIMEOUT);

    try {
      const socket = tls.connect(
        { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false },
        () => {
          if (resolved) return;
          clearTimeout(timeout);
          resolved = true;
          const version = socket.getProtocol();
          socket.destroy();

          // IMPORTANT: must check for exact deprecated version strings.
          // 'TLSv1' substring check accidentally matches 'TLSv1.3' which is MODERN.
          const deprecated = ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2', 'TLSv1.0'];
          const isOld = deprecated.some(v => version === v || version === v.replace('v', ' '));

          if (isOld) {
            return resolve({
              ...base,
              severity: 'HIGH',
              status: 'FAIL',
              description: `Server supports deprecated TLS version: ${version}`,
              technicalDetail: `Negotiated protocol: ${version}`,
              attackScenario: 'POODLE and BEAST attacks can decrypt traffic encrypted with TLS 1.0/1.1. An attacker forces the connection to downgrade to these old protocols and then decrypts the encrypted data using known cryptographic weaknesses.',
              fix: {
                description: 'Disable TLS 1.0 and 1.1, only allow TLS 1.2 and 1.3',
                code: `# Nginx
ssl_protocols TLSv1.2 TLSv1.3;

# Apache
SSLProtocol -all +TLSv1.2 +TLSv1.3`,
              },
              points_deducted: 10,
            });
          }

          return resolve({
            ...base,
            severity: 'INFO',
            status: 'PASS',
            description: `Modern TLS version in use: ${version}`,
            technicalDetail: `Negotiated protocol: ${version}`,
            attackScenario: null,
            fix: null,
            points_deducted: 0,
          });
        }
      );

      socket.on('error', (err) => {
        if (resolved) return;
        clearTimeout(timeout);
        resolved = true;
        resolve({
          ...base,
          severity: 'INFO',
          status: 'ERROR',
          description: `TLS version check error: ${err.message}`,
          technicalDetail: err.message,
          attackScenario: null,
          fix: null,
          points_deducted: 0,
        });
      });
    } catch (err) {
      clearTimeout(timeout);
      if (!resolved) {
        resolved = true;
        resolve({
          ...base,
          severity: 'INFO',
          status: 'ERROR',
          description: `TLS check error: ${err.message}`,
          technicalDetail: err.message,
          attackScenario: null,
          fix: null,
          points_deducted: 0,
        });
      }
    }
  });
}

module.exports = { checkHttpsEnforcement, checkSslCertificate, checkHsts, checkTlsVersion };
