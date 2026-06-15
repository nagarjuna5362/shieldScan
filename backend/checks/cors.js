
const axios = require('axios');

const TIMEOUT = 8000;
const USER_AGENT = 'ShieldScan-SecurityBot/1.0 (security scanner)';

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), ms)),
  ]);
}

async function checkCors(parsedUrl) {
  const base = {
    checkId: 'cors_misconfiguration',
    checkNumber: 11,
    category: 'CORS & API Security',
    name: 'CORS Misconfiguration',
  };
  try {
    const response = await withTimeout(
      axios.get(parsedUrl.href, {
        maxRedirects: 5,
        validateStatus: () => true,
        headers: {
          'User-Agent': USER_AGENT,
          'Origin': 'https://evil-attacker.com',
        },
        timeout: TIMEOUT,
      }),
      TIMEOUT
    );

    const acao = response.headers['access-control-allow-origin'];
    const acac = response.headers['access-control-allow-credentials'];

    if (!acao) {
      return {
        ...base, severity: 'INFO', status: 'PASS',
        description: 'No permissive CORS headers detected',
        technicalDetail: 'No Access-Control-Allow-Origin header returned for cross-origin request',
        attackScenario: null, fix: null, points_deducted: 0,
      };
    }

    if (acao === '*' && acac === 'true') {
      return {
        ...base, severity: 'CRITICAL', status: 'FAIL',
        description: 'CRITICAL: CORS allows all origins AND credentials — attackers can make authenticated cross-origin requests',
        technicalDetail: `Access-Control-Allow-Origin: ${acao}, Access-Control-Allow-Credentials: ${acac}`,
        attackScenario: "An attacker hosts a page at evil.com. When your logged-in customer visits that page, it silently calls your /api/orders endpoint with the user's session cookie. Because CORS allows wildcard + credentials, the browser sends the cookie and your API returns all of the user's order history, addresses, and payment info — the attacker reads it all without the user knowing.",
        fix: {
          description: 'Never use wildcard CORS with credentials. Restrict to specific origins.',
          code: `// Express.js
const cors = require('cors');
app.use(cors({
  origin: 'https://yourdomain.com', // exact origin
  credentials: true,
}));

// Nginx
add_header Access-Control-Allow-Origin "https://yourdomain.com";
add_header Access-Control-Allow-Credentials "true";`,
        },
        points_deducted: 20,
      };
    }

    if (acao === '*') {
      return {
        ...base, severity: 'CRITICAL', status: 'FAIL',
        description: 'CORS allows requests from any origin (wildcard *)',
        technicalDetail: `Access-Control-Allow-Origin: *`,
        attackScenario: "Any website can make API calls to your backend and read the responses. An attacker's site can call your /api/products, /api/prices, or any public endpoint and scrape all your data. If any endpoint returns user data without proper auth checks, it's fully exposed.",
        fix: {
          description: 'Restrict CORS to specific allowed origins',
          code: `// Express.js
app.use(cors({ origin: ['https://yourdomain.com', 'https://app.yourdomain.com'] }));`,
        },
        points_deducted: 20,
      };
    }

    if (acao === 'https://evil-attacker.com') {
      return {
        ...base, severity: 'HIGH', status: 'FAIL',
        description: 'CORS reflects arbitrary origins — server blindly mirrors Origin header',
        technicalDetail: `Access-Control-Allow-Origin: ${acao} (reflected from request)`,
        attackScenario: "The server blindly copies whatever Origin header the request sends into the CORS response. This means any attacker can send requests from their domain and the server will authorize them. This completely bypasses CORS protection.",
        fix: {
          description: 'Validate Origin against a whitelist instead of reflecting it',
          code: `// Express.js — SAFE approach
const allowedOrigins = ['https://yourdomain.com', 'https://app.yourdomain.com'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) callback(null, true);
    else callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));`,
        },
        points_deducted: 10,
      };
    }

    return {
      ...base, severity: 'INFO', status: 'PASS',
      description: `CORS is restricted — Origin header is properly validated`,
      technicalDetail: `Access-Control-Allow-Origin: ${acao}`,
      attackScenario: null, fix: null, points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `CORS check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

async function checkApiEnumeration(parsedUrl) {
  const base = {
    checkId: 'api_enumeration',
    checkNumber: 12,
    category: 'CORS & API Security',
    name: 'API Endpoint Enumeration',
  };

  const endpoints = [
    '/api/users', '/api/v1/users', '/api/orders', '/api/v1/orders',
    '/api/payments', '/api/admin', '/api/config', '/api/v1/admin',
    '/api/customers', '/api/products', '/graphql', '/api/v2/users',
  ];

  try {
    const results = await Promise.allSettled(
      endpoints.map(ep =>
        withTimeout(
          axios.get(`${parsedUrl.origin}${ep}`, {
            validateStatus: () => true,
            headers: { 'User-Agent': USER_AGENT },
            timeout: TIMEOUT,
          }),
          TIMEOUT
        ).then(r => ({ endpoint: ep, status: r.status })).catch(() => ({ endpoint: ep, status: null }))
      )
    );

    const exposed = results
      .filter(r => r.status === 'fulfilled' && r.value.status === 200)
      .map(r => r.value.endpoint);

    if (exposed.length > 0) {
      return {
        ...base, severity: 'HIGH', status: 'FAIL',
        description: `${exposed.length} unauthenticated API endpoint(s) publicly accessible: ${exposed.join(', ')}`,
        technicalDetail: `Endpoints returning HTTP 200 without auth: ${exposed.join(', ')}`,
        attackScenario: `An attacker simply visits ${parsedUrl.origin}${exposed[0]} in a browser and reads all the data. No login, no hacking — just an HTTP request. They can download all customers, orders, or payment records automatically with a simple script.`,
        fix: {
          description: 'Require authentication on all API endpoints',
          code: `// Express.js — Auth middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};
app.use('/api', authenticate);`,
        },
        points_deducted: 10,
      };
    }

    return {
      ...base, severity: 'INFO', status: 'PASS',
      description: 'No unauthenticated API endpoints found at common paths',
      technicalDetail: `Checked ${endpoints.length} common API paths — none returned HTTP 200`,
      attackScenario: null, fix: null, points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `API enumeration check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

async function checkIdor(parsedUrl) {
  const base = {
    checkId: 'idor',
    checkNumber: 13,
    category: 'CORS & API Security',
    name: 'IDOR Detection (Insecure Direct Object Reference)',
  };

  const idorPaths = [
    ['/api/orders/1', '/api/orders/2'],
    ['/api/users/1', '/api/users/2'],
    ['/api/payments/1', '/api/payments/2'],
  ];

  try {
    const vulnerablePaths = [];

    for (const [path1, path2] of idorPaths) {
      const [r1, r2] = await Promise.allSettled([
        withTimeout(axios.get(`${parsedUrl.origin}${path1}`, { validateStatus: () => true, headers: { 'User-Agent': USER_AGENT }, timeout: TIMEOUT }), TIMEOUT),
        withTimeout(axios.get(`${parsedUrl.origin}${path2}`, { validateStatus: () => true, headers: { 'User-Agent': USER_AGENT }, timeout: TIMEOUT }), TIMEOUT),
      ]);

      if (r1.status === 'fulfilled' && r2.status === 'fulfilled' &&
          r1.value.status === 200 && r2.value.status === 200) {
        vulnerablePaths.push(path1.replace('/1', '/{id}'));
      }
    }

    if (vulnerablePaths.length > 0) {
      return {
        ...base, severity: 'CRITICAL', status: 'FAIL',
        description: `IDOR vulnerability detected — sequential IDs return data without authorization: ${vulnerablePaths.join(', ')}`,
        technicalDetail: `Both /1 and /2 return HTTP 200 without any auth headers — ${vulnerablePaths.join(', ')}`,
        attackScenario: "An attacker creates an account and makes an order (order ID 1001). They change the URL to /api/orders/1002 and can see another customer's order. Then 1003, 1004... They write a script to loop through all IDs and download every single order in your system — including addresses, items, and payment details.",
        fix: {
          description: 'Always verify the authenticated user owns the requested resource',
          code: `// Express.js — IDOR prevention
app.get('/api/orders/:id', authenticate, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  // CRITICAL: Check ownership!
  if (order.userId !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(order);
});`,
        },
        points_deducted: 20,
      };
    }

    return {
      ...base, severity: 'INFO', status: 'PASS',
      description: 'No obvious IDOR vulnerabilities found at common API paths',
      technicalDetail: 'Sequential ID requests at /api/orders, /api/users, /api/payments returned non-200 responses',
      attackScenario: null, fix: null, points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `IDOR check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

async function checkHttpMethods(parsedUrl) {
  const base = {
    checkId: 'http_methods',
    checkNumber: 14,
    category: 'CORS & API Security',
    name: 'HTTP Methods Allowed',
  };
  try {
    const [traceRes, putRes, deleteRes] = await Promise.allSettled([
      withTimeout(
        axios.request({
          url: parsedUrl.href,
          method: 'TRACE',
          validateStatus: () => true,
          headers: { 'User-Agent': USER_AGENT, 'X-ShieldScan-Probe': 'true' },
          timeout: 3000,
        }),
        3000
      ),
      withTimeout(
        axios.request({
          url: `${parsedUrl.origin}/shieldscan-http-probe-test`,
          method: 'PUT',
          data: { test: true },
          validateStatus: () => true,
          headers: { 'User-Agent': USER_AGENT },
          timeout: 3000,
        }),
        3000
      ),
      withTimeout(
        axios.request({
          url: `${parsedUrl.origin}/shieldscan-http-probe-test`,
          method: 'DELETE',
          validateStatus: () => true,
          headers: { 'User-Agent': USER_AGENT },
          timeout: 3000,
        }),
        3000
      ),
    ]);

    const activeViolations = [];

    // Check TRACE
    if (traceRes.status === 'fulfilled' && traceRes.value.status === 200) {
      const body = typeof traceRes.value.data === 'string' ? traceRes.value.data : '';
      if (body.includes('X-ShieldScan-Probe') || traceRes.value.headers['content-type']?.includes('message/http')) {
        activeViolations.push('TRACE (enabled and echoed test header)');
      }
    }

    // Check unauthenticated PUT/DELETE
    if (putRes.status === 'fulfilled' && [200, 201, 204].includes(putRes.value.status)) {
      activeViolations.push('PUT (returned HTTP ' + putRes.value.status + ' on unauthenticated path)');
    }
    if (deleteRes.status === 'fulfilled' && [200, 201, 202, 204].includes(deleteRes.value.status)) {
      activeViolations.push('DELETE (returned HTTP ' + deleteRes.value.status + ' on unauthenticated path)');
    }

    if (activeViolations.length > 0) {
      const isTraceFailed = activeViolations.some(v => v.startsWith('TRACE'));
      return {
        ...base,
        severity: isTraceFailed ? 'MEDIUM' : 'HIGH',
        status: 'FAIL',
        description: `Dangerous HTTP methods enabled/accepted: ${activeViolations.join(', ')}`,
        technicalDetail: `Active method probes accepted: ${activeViolations.join(' | ')}`,
        attackScenario: isTraceFailed
          ? 'The TRACE method echoes request headers back to the client. Attackers can execute Cross-Site Tracing (XST) to bypass HttpOnly flags on session cookies by retrieving them from the reflected HTTP headers.'
          : 'Allowing unauthenticated PUT or DELETE requests on arbitrary paths could allow attackers to upload web shells, override existing files, or delete critical application assets directly.',
        fix: {
          description: 'Disable TRACE, PUT, and DELETE methods globally on your reverse proxy or web server unless explicitly authenticated',
          code: `# Nginx config
# Disable TRACE and block unauthorized PUT/DELETE
if ($request_method = TRACE) { return 405; }
if ($request_method ~ ^(PUT|DELETE)$ ) {
  # require authentication or block globally:
  return 405;
}

# Express.js Middleware
app.use((req, res, next) => {
  const blocked = ['TRACE'];
  if (blocked.includes(req.method)) {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }
  next();
});`,
        },
        points_deducted: isTraceFailed ? 5 : 10,
      };
    }

    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: 'Dangerous HTTP methods (TRACE, PUT, DELETE) are properly blocked/disabled',
      technicalDetail: 'Active probes: TRACE, PUT, and DELETE requests were rejected or did not echo credentials.',
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `HTTP methods check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

module.exports = { checkCors, checkApiEnumeration, checkIdor, checkHttpMethods };
