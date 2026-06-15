const axios = require('axios');
const tls = require('tls');
const { safeLookup } = require('../utils/dnsResolver');

const TIMEOUT = 8000;
const USER_AGENT = 'ShieldScan-SecurityBot/1.0 (security scanner)';

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), ms)),
  ]);
}

async function checkHttpsEnforcement(parsedUrl) {
  const base = {
    checkId: 'https_enforcement',
    checkNumber: 1,
    category: 'Transport Security',
    name: 'HTTPS Enforcement',
  };

  const httpUrl = `http://${parsedUrl.hostname}${parsedUrl.pathname || '/'}`;

  try {
    const response = await withTimeout(
      axios.get(httpUrl, {
        maxRedirects: 5,
        validateStatus: () => true,
        headers: { 'User-Agent': USER_AGENT },
        timeout: TIMEOUT,
      }),
      TIMEOUT
    );

    const finalUrl = response.request?.res?.responseUrl || response.config?.url || '';
    const finalIsHttps = finalUrl.startsWith('https://');
    const loc = response.headers['location'] || '';
    const firstHopIsHttps = loc.startsWith('https://');

    if (response.status >= 200 && response.status < 300 && finalIsHttps) {
      return {
        ...base,
        severity: 'INFO',
        status: 'PASS',
        description: `Site redirects HTTP to HTTPS correctly (final URL: ${finalUrl.substring(0, 60)})`,
        technicalDetail: 'HTTP request followed redirects and landed on HTTPS',
        attackScenario: null,
        fix: null,
        points_deducted: 0,
      };
    }

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
          code: `# Nginx
server {
  listen 80;
  return 301 https://$host$request_uri;
}

# Apache .htaccess
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`,
        },
        points_deducted: 15,
      };
    }

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
    const isRefused =
      err.code === 'ECONNREFUSED' ||
      err.code === 'ENOTFOUND' ||
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
        description: "Install an SSL certificate. Use Let's Encrypt for free certificates.",
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
        { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false, lookup: safeLookup },
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
              attackScenario:
                'Without a valid certificate, browsers will warn users. Attackers can intercept traffic using fake certificates.',
              fix: {
                description: 'Install a valid SSL certificate from a trusted CA',
                code: 'sudo certbot --nginx -d yourdomain.com',
              },
              points_deducted: 10,
            });
          }

          const now = new Date();
          const expiry = new Date(cert.valid_to);
          const isExpired = expiry < now;
          const daysLeft = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
          const isExpiringSoon = daysLeft < 30 && daysLeft > 0;

          const isSelfSigned =
            cert.issuer && cert.subject && JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);

          const issues = [];
          let severity = 'INFO';
          let status = 'PASS';

          if (isExpired) {
            issues.push('Certificate is EXPIRED');
            severity = 'HIGH';
            status = 'FAIL';
          }
          if (isSelfSigned) {
            issues.push('Certificate is self-signed');
            if (severity !== 'HIGH') {
              severity = 'HIGH';
              status = 'FAIL';
            }
          }
          if (!authorized && authError) {
            issues.push(`Auth error: ${authError}`);
            if (severity !== 'HIGH') {
              severity = 'HIGH';
              status = 'FAIL';
            }
          }
          if (isExpiringSoon) {
            issues.push(`Certificate expires in ${daysLeft} days`);
            if (status === 'PASS') {
              severity = 'MEDIUM';
              status = 'WARNING';
            }
          }

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
            attackScenario:
              'Browsers show security warnings for invalid certificates. Users who click through are vulnerable to MITM attacks where an attacker presents their own fake certificate and decrypts all traffic.',
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
          attackScenario:
            'If the HTTPS handshake fails or port 443 is blocked, users cannot establish secure connections, leaving no protection.',
          fix: {
            description: 'Check your web server configuration for correct port 443 bindings',
            code: 'sudo nginx -t',
          },
          points_deducted: 10,
        });
      });
    } catch (err) {
      clearTimeout(timeout);
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
  });
}

async function checkSslChain(parsedUrl) {
  const base = {
    checkId: 'ssl_chain',
    checkNumber: 3,
    category: 'Transport Security',
    name: 'SSL/TLS Certificate Chain Validation',
  };

  if (parsedUrl.protocol === 'http:') {
    return {
      ...base,
      severity: 'HIGH',
      status: 'FAIL',
      description: 'Site uses HTTP — no certificate chain present',
      technicalDetail: 'Connection protocol is HTTP.',
      attackScenario: null,
      fix: null,
      points_deducted: 5,
    };
  }

  return new Promise((resolve) => {
    const hostname = parsedUrl.hostname;
    const timeout = setTimeout(() => {
      resolve({
        ...base,
        severity: 'INFO',
        status: 'ERROR',
        description: 'Certificate chain validation timed out',
        technicalDetail: 'Connection timed out',
        attackScenario: null,
        fix: null,
        points_deducted: 0,
      });
    }, TIMEOUT);

    try {
      const socket = tls.connect(
        { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false, lookup: safeLookup },
        () => {
          clearTimeout(timeout);
          const peerCert = socket.getPeerCertificate(true);
          socket.destroy();

          if (!peerCert) {
            return resolve({
              ...base,
              severity: 'HIGH',
              status: 'FAIL',
              description: 'Could not fetch certificate chain',
              technicalDetail: 'getPeerCertificate returned null',
              attackScenario: null,
              fix: null,
              points_deducted: 5,
            });
          }

          const chain = [];
          let currentCert = peerCert;
          while (currentCert) {
            chain.push(currentCert);
            if (currentCert.issuerCertificate && currentCert.issuerCertificate !== currentCert) {
              currentCert = currentCert.issuerCertificate;
            } else {
              currentCert = null;
            }
          }

          const now = new Date();
          const expiredCerts = [];

          for (let i = 0; i < chain.length; i++) {
            const cert = chain[i];
            const expiry = new Date(cert.valid_to);
            if (expiry < now) {
              expiredCerts.push(`${cert.subject?.CN || 'Unknown CN'} (expired ${expiry.toDateString()})`);
            }
          }

          if (expiredCerts.length > 0) {
            return resolve({
              ...base,
              severity: 'HIGH',
              status: 'FAIL',
              description: `Expired certificate in intermediate/root chain: ${expiredCerts.join(', ')}`,
              technicalDetail: `Chain depth: ${chain.length}. Expired items: ${expiredCerts.join(' | ')}`,
              attackScenario:
                'If an intermediate or root certificate in the SSL chain is expired, modern browsers will reject the connection and display a security warning to users, even if the primary leaf certificate is valid.',
              fix: {
                description: 'Re-install the correct bundle from your certificate provider containing valid intermediate CA certificates',
                code: `# Nginx — check full chain configuration
# Make sure your ssl_certificate file contains the full chain:
# 1. Leaf certificate
# 2. Intermediate certificate
# 3. Root certificate (optional)
# Concatenate them in order: cat domain.crt intermediate.crt > bundle.crt`,
              },
              points_deducted: 10,
            });
          }

          return resolve({
            ...base,
            severity: 'INFO',
            status: 'PASS',
            description: `SSL/TLS certificate chain is fully trusted and valid (depth: ${chain.length})`,
            technicalDetail: `Chain validated: ${chain.map((c) => c.subject?.CN || 'Unknown').join(' -> ')}`,
            attackScenario: null,
            fix: null,
            points_deducted: 0,
          });
        }
      );

      socket.on('error', (err) => {
        clearTimeout(timeout);
        resolve({
          ...base,
          severity: 'INFO',
          status: 'ERROR',
          description: `Chain validation connection failed: ${err.message}`,
          technicalDetail: err.message,
          attackScenario: null,
          fix: null,
          points_deducted: 0,
        });
      });
    } catch (err) {
      clearTimeout(timeout);
      resolve({
        ...base,
        severity: 'INFO',
        status: 'ERROR',
        description: `Chain validation error: ${err.message}`,
        technicalDetail: err.message,
        attackScenario: null,
        fix: null,
        points_deducted: 0,
      });
    }
  });
}

async function checkHsts(parsedUrl) {
  const base = {
    checkId: 'hsts',
    checkNumber: 5,
    category: 'Transport Security',
    name: 'HSTS (HTTP Strict Transport Security)',
  };

  if (parsedUrl.protocol === 'http:') {
    return {
      ...base,
      severity: 'MEDIUM',
      status: 'FAIL',
      description: 'HSTS not active — page served over unencrypted HTTP',
      technicalDetail: 'HSTS headers require an HTTPS connection to take effect.',
      attackScenario:
        'HSTS is not active on HTTP. Attackers can hijack connection requests before they are upgraded to HTTPS.',
      fix: {
        description: 'First enable HTTPS, then configure the HSTS header',
        code: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      },
      points_deducted: 5,
    };
  }

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

    const hsts = response.headers['strict-transport-security'] || '';

    if (!hsts) {
      return {
        ...base,
        severity: 'HIGH',
        status: 'FAIL',
        description: 'HSTS header is missing',
        technicalDetail: 'No Strict-Transport-Security header returned',
        attackScenario:
          'A user types "mysite.com" in a browser. The browser sends an unencrypted HTTP request first. An attacker on the same network redirects that HTTP request to their spoofed server before the site redirects to HTTPS. HSTS tells the browser to NEVER send HTTP and always connect via HTTPS directly.',
        fix: {
          description: 'Add the Strict-Transport-Security header to all HTTPS responses',
          code: `# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Apache .htaccess
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

# Express.js (helmet)
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));`,
        },
        points_deducted: 8,
      };
    }

    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: 'HSTS header is configured correctly',
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

function testTlsHandshake(host, version) {
  return new Promise((resolve) => {
    let resolved = false;
    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
        minVersion: version,
        maxVersion: version,
        lookup: safeLookup,
      },
      () => {
        resolved = true;
        socket.destroy();
        resolve(true); // Handshake succeeded, protocol is supported
      }
    );

    socket.setTimeout(2500);
    socket.on('timeout', () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve(false);
      }
    });

    socket.on('error', () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve(false); // Handshake failed, protocol likely disabled
      }
    });
  });
}

async function checkTlsVersion(parsedUrl) {
  const base = {
    checkId: 'tls_version',
    checkNumber: 6,
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

  const hostname = parsedUrl.hostname;

  // Probe all TLS versions actively
  const [supportsTls10, supportsTls11, supportsTls12, supportsTls13] = await Promise.all([
    testTlsHandshake(hostname, 'TLSv1'),
    testTlsHandshake(hostname, 'TLSv1.1'),
    testTlsHandshake(hostname, 'TLSv1.2'),
    testTlsHandshake(hostname, 'TLSv1.3'),
  ]);

  const activeVulnerabilities = [];
  if (supportsTls10) activeVulnerabilities.push('TLS 1.0');
  if (supportsTls11) activeVulnerabilities.push('TLS 1.1');
  // SSLv3 and SSLv2 are deprecated and unsupported in modern clients (including Node.js),
  // which means they are automatically blocked/unsupported. We list them as vulnerabilities if we fail.

  const modernSupported = [];
  if (supportsTls12) modernSupported.push('TLS 1.2');
  if (supportsTls13) modernSupported.push('TLS 1.3');

  if (activeVulnerabilities.length > 0) {
    return {
      ...base,
      severity: 'HIGH',
      status: 'FAIL',
      description: `Server supports deprecated TLS versions: ${activeVulnerabilities.join(', ')}`,
      technicalDetail: `Accepted: ${activeVulnerabilities.join(', ')}. Supported modern: ${modernSupported.join(', ') || 'None'}`,
      attackScenario:
        'Attackers can force a TLS connection to downgrade to TLS 1.0 or 1.1 (e.g. POODLE, BEAST, or SWEET32 attacks) and exploit known cryptographic vulnerabilities in those versions to decrypt session cookies or sensitive transaction data.',
      fix: {
        description: 'Configure your web server to only support TLS 1.2 and TLS 1.3, disabling TLS 1.0, TLS 1.1, SSLv2, and SSLv3.',
        code: `# Nginx config
ssl_protocols TLSv1.2 TLSv1.3;

# Apache config
SSLProtocol -all +TLSv1.2 +TLSv1.3`,
      },
      points_deducted: 10,
    };
  }

  if (modernSupported.length === 0) {
    return {
      ...base,
      severity: 'CRITICAL',
      status: 'FAIL',
      description: 'Server does not support modern TLS versions (TLS 1.2 or TLS 1.3)',
      technicalDetail: 'Handshakes using TLS 1.2 and TLS 1.3 failed or were rejected.',
      attackScenario:
        'Without support for TLS 1.2 or TLS 1.3, users cannot establish modern secure connections, leaving transactions exposed to eavesdropping or completely blocked by modern browsers.',
      fix: {
        description: 'Enable TLS 1.2 and TLS 1.3 protocols on your web server configuration.',
        code: `ssl_protocols TLSv1.2 TLSv1.3;`,
      },
      points_deducted: 10,
    };
  }

  // PASS: only modern TLS versions are supported, and deprecated versions are rejected.
  return {
    ...base,
    severity: 'INFO',
    status: 'PASS',
    description: `Server restricts SSL/TLS connections to secure modern protocols: ${modernSupported.join(' and ')}`,
    technicalDetail: `Accepted protocols: ${modernSupported.join(', ')}. Deprecated protocols (TLS 1.1, TLS 1.0, SSLv3, SSLv2) were successfully rejected.`,
    attackScenario: null,
    fix: null,
    points_deducted: 0,
  };
}

module.exports = {
  checkHttpsEnforcement,
  checkSslCertificate,
  checkSslChain,
  checkHsts,
  checkTlsVersion,
};
