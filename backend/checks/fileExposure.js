const axios = require('axios');

const TIMEOUT = 7000;
const USER_AGENT = 'ShieldScan-SecurityBot/1.0 (security scanner)';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function checkSensitiveFiles(parsedUrl) {
  const base = {
    checkId: 'sensitive_files',
    checkNumber: 17,
    category: 'File & Info Exposure',
    name: 'Sensitive File Exposure',
  };

  const sensitiveFiles = [
    '/.env',
    '/.env.local',
    '/.env.production',
    '/.env.backup',
    '/config.json',
    '/config.yml',
    '/config.yaml',
    '/.git/config',
    '/.git/HEAD',
    '/wp-config.php',
    '/database.sql',
    '/backup.sql',
    '/backup.zip',
    '/dump.sql',
    '/.htaccess',
    '/phpinfo.php',
    '/server-status',
    '/server-info',
    '/web.config',
    '/package.json',
    '/composer.json',
    '/docker-compose.yml',
  ];

  const adminPaths = ['/admin', '/admin/login', '/administrator', '/phpmyadmin'];

  try {
    const fileResults = [];
    const adminResults = [];

    // Run probes sequentially with WAF-friendly delays
    for (const file of sensitiveFiles) {
      await sleep(150);
      try {
        const r = await axios.get(`${parsedUrl.origin}${file}`, {
          validateStatus: () => true,
          headers: { 'User-Agent': USER_AGENT },
          timeout: TIMEOUT,
          maxRedirects: 0,
        });
        fileResults.push({ file, status: r.status });
      } catch {
        fileResults.push({ file, status: null });
      }
    }

    for (const path of adminPaths) {
      await sleep(150);
      try {
        const r = await axios.get(`${parsedUrl.origin}${path}`, {
          validateStatus: () => true,
          headers: { 'User-Agent': USER_AGENT },
          timeout: TIMEOUT,
          maxRedirects: 0,
        });
        adminResults.push({ file: path, status: r.status });
      } catch {
        adminResults.push({ file: path, status: null });
      }
    }

    const critical = fileResults.filter((r) => r.status === 200).map((r) => r.file);
    const blocked = fileResults.filter((r) => r.status === 403).map((r) => r.file);
    const adminExposed = adminResults.filter((r) => r.status === 200).map((r) => r.file);

    if (critical.length > 0) {
      return {
        ...base,
        severity: 'CRITICAL',
        status: 'FAIL',
        description: `${critical.length} sensitive file(s) publicly accessible: ${critical.join(', ')}`,
        technicalDetail: `HTTP 200 responses: ${critical.join(', ')}${blocked.length ? ` | HTTP 403 (blocked): ${blocked.join(', ')}` : ''}`,
        attackScenario: `An attacker visits ${parsedUrl.origin}${critical[0]} and downloads it directly in their browser. If it's a .env file, they now have your database password, payment API keys (Stripe, PayPal), JWT secret, and any other credentials — complete system takeover in seconds. No skills required.`,
        fix: {
          description: 'Block access to sensitive files and remove them from public directories',
          code: `# Nginx — block sensitive files
location ~* \\.env|config\\.json|\\.git|phpinfo\\.php|wp-config\\.php|docker-compose\\.yml {
    deny all;
    return 404;
}

# Never put .env files in web root
# Move config files above the webroot directory
# Add to .gitignore: .env, config.yml, *.sql, *.zip

# Apache .htaccess
<FilesMatch "(\\.env|\\.git|config\\.json|phpinfo\\.php|docker-compose\\.yml)">
    Order allow,deny
    Deny from all
</FilesMatch>`,
        },
        points_deducted: 20,
      };
    }

    if (adminExposed.length > 0) {
      return {
        ...base,
        severity: 'HIGH',
        status: 'WARNING',
        description: `${adminExposed.length} admin panel path(s) publicly reachable (may just be login page): ${adminExposed.join(', ')}`,
        technicalDetail: `Paths returning HTTP 200: ${adminExposed.join(', ')}`,
        attackScenario: `Admin panels visible to the public internet are prime targets for brute-force login attacks. Tools like Hydra can try thousands of password combinations against /admin. Even if protected by login, exposed admin URLs help attackers map your attack surface.`,
        fix: {
          description: 'Restrict admin panel access by IP or move it to a non-standard path',
          code: `# Nginx — restrict /admin to office IP only
location /admin {
    allow 203.0.113.10;  # your office IP
    deny all;
}

# Or rename the admin path to something unpredictable
# /admin → /manage-x7k2p (security through obscurity + IP restriction)`,
        },
        points_deducted: 10,
      };
    }

    if (blocked.length > 0) {
      return {
        ...base,
        severity: 'MEDIUM',
        status: 'WARNING',
        description: `${blocked.length} sensitive file path(s) exist but are blocked (403): ${blocked.join(', ')}`,
        technicalDetail: `HTTP 403 responses indicate files exist: ${blocked.join(', ')}`,
        attackScenario:
          'The files are blocked now, but they exist at predictable paths. A misconfiguration or server update could expose them. Server path information revealed by 403 vs 404 responses also helps attackers map your infrastructure.',
        fix: {
          description: 'Remove sensitive files from the web directory entirely, not just block them',
          code: `# Return 404 instead of 403 to not reveal file existence
location ~ /\\.env {
    return 404;
}
# Best practice: move .env files above webroot
/var/www/         <- webroot (public)
/var/             <- store .env here instead`,
        },
        points_deducted: 5,
      };
    }

    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: 'No sensitive files found at common paths',
      technicalDetail: `Checked ${sensitiveFiles.length} paths — all returned 404 or non-200`,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  } catch (err) {
    return {
      ...base,
      severity: 'INFO',
      status: 'ERROR',
      description: `Sensitive file check failed: ${err.message}`,
      technicalDetail: err.message,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }
}

async function checkServerDisclosure(parsedUrl) {
  const base = {
    checkId: 'server_disclosure',
    checkNumber: 18,
    category: 'File & Info Exposure',
    name: 'Server & Technology Disclosure',
  };
  try {
    const response = await axios.get(parsedUrl.href, {
      maxRedirects: 5,
      validateStatus: () => true,
      headers: { 'User-Agent': USER_AGENT },
      timeout: TIMEOUT,
    });

    const headers = response.headers;
    const disclosures = [];

    const checkHeader = (name, value) => {
      if (!value) return;
      const versionPattern = /[\d]+\.[\d]+/;
      if (versionPattern.test(value)) {
        disclosures.push({ header: name, value, hasVersion: true });
      } else {
        disclosures.push({ header: name, value, hasVersion: false });
      }
    };

    checkHeader('Server', headers['server']);
    checkHeader('X-Powered-By', headers['x-powered-by']);
    checkHeader('X-AspNet-Version', headers['x-aspnet-version']);
    checkHeader('X-AspNetMvc-Version', headers['x-aspnetmvc-version']);
    checkHeader('X-Generator', headers['x-generator']);
    checkHeader('X-Drupal-Cache', headers['x-drupal-cache']);
    checkHeader('X-Joomla-Version', headers['x-joomla-version']);

    const withVersion = disclosures.filter((d) => d.hasVersion);
    const withoutVersion = disclosures.filter((d) => !d.hasVersion);

    if (withVersion.length > 0) {
      return {
        ...base,
        severity: 'MEDIUM',
        status: 'FAIL',
        description: `Server version information exposed: ${withVersion.map((d) => `${d.header}: ${d.value}`).join(', ')}`,
        technicalDetail: disclosures.map((d) => `${d.header}: ${d.value}`).join(' | '),
        attackScenario: `Your server responds with "${withVersion[0].header}: ${withVersion[0].value}". An attacker searches CVE databases for known exploits for this exact version. They find a public exploit, download it, and run it against your server. This is an entirely automated attack — tools like Metasploit do this in one command.`,
        fix: {
          description: 'Remove or generic-ize server version headers',
          code: `# Nginx — remove Server version
server_tokens off;

# Apache — remove version info
ServerTokens Prod
ServerSignature Off

# Express.js — remove X-Powered-By
app.disable('x-powered-by');
# OR use helmet:
const helmet = require('helmet');
app.use(helmet());`,
        },
        points_deducted: 5,
      };
    }

    if (withoutVersion.length > 0) {
      return {
        ...base,
        severity: 'LOW',
        status: 'WARNING',
        description: `Server technology disclosed (no version): ${withoutVersion.map((d) => `${d.header}: ${d.value}`).join(', ')}`,
        technicalDetail: disclosures.map((d) => `${d.header}: ${d.value}`).join(' | '),
        attackScenario:
          'Knowing your tech stack (PHP, Node.js, Apache) helps attackers choose the right exploit toolkit and search for vulnerabilities specific to that technology.',
        fix: {
          description: 'Remove technology identification headers',
          code: "app.disable('x-powered-by'); // Express.js\nserver_tokens off; // Nginx",
        },
        points_deducted: 2,
      };
    }

    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: 'No sensitive server or technology version headers detected',
      technicalDetail: 'Server, X-Powered-By, and version headers are absent or generic',
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  } catch (err) {
    return {
      ...base,
      severity: 'INFO',
      status: 'ERROR',
      description: `Server disclosure check failed: ${err.message}`,
      technicalDetail: err.message,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }
}

async function checkDirectoryListing(parsedUrl) {
  const base = {
    checkId: 'directory_listing',
    checkNumber: 19,
    category: 'File & Info Exposure',
    name: 'Directory Listing Enabled',
  };

  const directories = [
    '/images/',
    '/uploads/',
    '/assets/',
    '/static/',
    '/files/',
    '/backup/',
    '/media/',
    '/data/',
    '/admin/',
  ];

  try {
    const results = [];

    // Run probes sequentially with WAF-friendly delays
    for (const dir of directories) {
      await sleep(150);
      try {
        const r = await axios.get(`${parsedUrl.origin}${dir}`, {
          validateStatus: () => true,
          headers: { 'User-Agent': USER_AGENT },
          timeout: TIMEOUT,
        });
        const hasListing =
          r.status === 200 &&
          (r.data?.includes('Index of /') ||
            r.data?.includes('Directory listing') ||
            r.data?.includes('<title>Index of') ||
            r.data?.includes('Parent Directory'));

        results.push({ dir, status: r.status, hasListing });
      } catch {
        results.push({ dir, status: null, hasListing: false });
      }
    }

    const exposed = results.filter((r) => r.hasListing).map((r) => r.dir);

    if (exposed.length > 0) {
      return {
        ...base,
        severity: 'HIGH',
        status: 'FAIL',
        description: `Directory listing is enabled at: ${exposed.join(', ')}`,
        technicalDetail: `Directories showing file listings: ${exposed.join(', ')}`,
        attackScenario: `Visiting ${parsedUrl.origin}${exposed[0]} shows a complete file browser of your server. An attacker can see and download every file — user uploaded profile pictures (with embedded GPS data), database backup files, source code archives, configuration files. It's like leaving your office filing cabinet open in a public park.`,
        fix: {
          description: 'Disable directory listing on your web server',
          code: `# Nginx — disable directory listing
autoindex off;

# Apache .htaccess
Options -Indexes

# Make sure uploads directory has no .php execution either
location /uploads/ {
    autoindex off;
    location ~ \\.php$ { deny all; }
}`,
        },
        points_deducted: 10,
      };
    }

    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: 'Directory listing is disabled at all tested paths',
      technicalDetail: `Checked ${directories.length} directories — none showed "Index of /" listing`,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  } catch (err) {
    return {
      ...base,
      severity: 'INFO',
      status: 'ERROR',
      description: `Directory listing check failed: ${err.message}`,
      technicalDetail: err.message,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }
}

async function checkStackTrace(parsedUrl) {
  const base = {
    checkId: 'stack_trace',
    checkNumber: 20,
    category: 'File & Info Exposure',
    name: 'Source Code / Stack Trace Exposure',
  };

  const errorPatterns = [
    'stack trace',
    'at Object.',
    'at Module.',
    'SyntaxError:',
    'TypeError:',
    'ReferenceError:',
    'mysqli_',
    'ORA-',
    'Warning: mysql',
    'Fatal error:',
    'parse error:',
    'Traceback (most recent call last)',
    'Exception in thread',
    'NullPointerException',
    'StackOverflowError',
    'SQLSTATE[',
    'You have an error in your SQL syntax',
    'Microsoft OLE DB Provider',
    'ODBC SQL Server Driver',
    'vendor/laravel',
    'app/Http/Controllers',
    'at /home/',
  ];

  try {
    const response = await axios.get(parsedUrl.href, {
      maxRedirects: 5,
      validateStatus: () => true,
      headers: { 'User-Agent': USER_AGENT },
      timeout: TIMEOUT,
    });

    const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    const bodyLower = body.toLowerCase();
    const found = errorPatterns.filter((p) => bodyLower.includes(p.toLowerCase()));

    if (found.length > 0) {
      return {
        ...base,
        severity: 'HIGH',
        status: 'FAIL',
        description: `Stack trace or error information exposed in page body: "${found[0]}"`,
        technicalDetail: `Error patterns found: ${found.slice(0, 3).join(', ')}`,
        attackScenario:
          'Stack traces reveal your internal file paths (/home/user/myapp/models/User.js), framework versions, database schema, and sometimes even database credentials in error messages. An attacker collects this information to precisely target your specific setup.',
        fix: {
          description: 'Never expose stack traces or technical errors to users',
          code: `// Express.js — production error handler
app.use((err, req, res, next) => {
  // Log internally
  console.error(err.stack);
  // Show generic message to user
  res.status(500).json({ 
    error: 'Internal server error',
    // NEVER include: err.message, err.stack
  });
});

// Set NODE_ENV=production to disable stack traces
// in Express and most frameworks`,
        },
        points_deducted: 10,
      };
    }

    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: 'No stack traces or error information detected in page response',
      technicalDetail: 'Scanned response body — no error pattern indicators found',
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  } catch (err) {
    return {
      ...base,
      severity: 'INFO',
      status: 'ERROR',
      description: `Stack trace check failed: ${err.message}`,
      technicalDetail: err.message,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }
}

module.exports = {
  checkSensitiveFiles,
  checkServerDisclosure,
  checkDirectoryListing,
  checkStackTrace,
};
