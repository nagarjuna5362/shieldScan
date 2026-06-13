/**
 * server.js — ShieldScan Backend
 * Express server with SSE streaming for real-time security scan results
 */

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { validateUrl } = require('./utils/validateUrl');
const { calculateScore, getGrade, getCategoryScores, getTopAttackVectors } = require('./utils/scorer');

// Check modules
const { checkHttpsEnforcement, checkSslCertificate, checkHsts, checkTlsVersion } = require('./checks/transport');
const { checkCsp, checkClickjacking, checkContentTypeOptions, checkReferrerPolicy, checkPermissionsPolicy, checkXssProtection } = require('./checks/headers');
const { checkCors, checkApiEnumeration, checkIdor, checkHttpMethods } = require('./checks/cors');
const { checkCookieSecurity, checkSessionInUrl } = require('./checks/cookies');
const { checkSensitiveFiles, checkServerDisclosure, checkDirectoryListing, checkStackTrace } = require('./checks/fileExposure');
const { checkDnsSecurity, checkSubdomainTakeover } = require('./checks/dns');
const { checkRateLimiting, checkOpenRedirect, checkSecurityTxt } = require('./checks/rateLimiting');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173'],
  credentials: true,
}));

// Rate limiting — max 60 scans per IP per 1 minute
const scanLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 60,
  message: { error: 'Too many scans from this IP. Please wait 1 minute before scanning again.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'ShieldScan backend running' });
});

// Main scan endpoint — POST body: { url: "https://example.com" }
app.post('/api/scan', scanLimiter, async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  // Validate URL
  const validation = validateUrl(url);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  const { parsed } = validation;
  const scanStart = Date.now();

  // Set up SSE
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const sendEvent = (data) => {
    if (!res.writableEnded) {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    }
  };

  // Send initial "scanning started" event
  sendEvent({
    type: 'start',
    url: parsed.href,
    hostname: parsed.hostname,
    totalChecks: 25,
  });

  const allResults = [];

  // Run a check, catch errors, stream result
  const runCheck = async (checkFn, checkArgs) => {
    try {
      const result = await Promise.race([
        checkFn(...checkArgs),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Check timed out')), 12000)),
      ]);
      allResults.push(result);
      sendEvent({ type: 'check', ...result });
      return result;
    } catch (err) {
      const errorResult = {
        checkId: checkFn.name,
        checkNumber: 0,
        category: 'Unknown',
        name: checkFn.name,
        severity: 'INFO',
        status: 'ERROR',
        description: `Check failed: ${err.message}`,
        technicalDetail: err.message,
        attackScenario: null,
        fix: null,
        points_deducted: 0,
      };
      allResults.push(errorResult);
      sendEvent({ type: 'check', ...errorResult });
      return errorResult;
    }
  };

  // ── BATCH 1: Transport Security (parallel) ──────────────────
  await Promise.all([
    runCheck(checkHttpsEnforcement, [parsed]),
    runCheck(checkSslCertificate, [parsed]),
    runCheck(checkHsts, [parsed]),
    runCheck(checkTlsVersion, [parsed]),
  ]);

  // ── BATCH 2: HTTP Headers (parallel) ────────────────────────
  await Promise.all([
    runCheck(checkCsp, [parsed]),
    runCheck(checkClickjacking, [parsed]),
    runCheck(checkContentTypeOptions, [parsed]),
    runCheck(checkReferrerPolicy, [parsed]),
    runCheck(checkPermissionsPolicy, [parsed]),
    runCheck(checkXssProtection, [parsed]),
  ]);

  // ── BATCH 3: CORS & API (parallel, but IDOR after enumeration) ──
  await Promise.all([
    runCheck(checkCors, [parsed]),
    runCheck(checkHttpMethods, [parsed]),
  ]);
  await Promise.all([
    runCheck(checkApiEnumeration, [parsed]),
    runCheck(checkIdor, [parsed]),
  ]);

  // ── BATCH 4: Cookies (parallel) ─────────────────────────────
  await Promise.all([
    runCheck(checkCookieSecurity, [parsed]),
    runCheck(checkSessionInUrl, [parsed]),
  ]);

  // ── BATCH 5: File Exposure (parallel) ───────────────────────
  await Promise.all([
    runCheck(checkSensitiveFiles, [parsed]),
    runCheck(checkServerDisclosure, [parsed]),
    runCheck(checkDirectoryListing, [parsed]),
    runCheck(checkStackTrace, [parsed]),
  ]);

  // ── BATCH 6: DNS (parallel) ──────────────────────────────────
  await Promise.all([
    runCheck(checkDnsSecurity, [parsed]),
    runCheck(checkSubdomainTakeover, [parsed]),
  ]);

  // ── BATCH 7: Rate Limiting & Abuse (sequential — rate test last) ──
  await runCheck(checkRateLimiting, [parsed]);
  await Promise.all([
    runCheck(checkOpenRedirect, [parsed]),
    runCheck(checkSecurityTxt, [parsed]),
  ]);

  // ── Calculate final score ────────────────────────────────────
  const { score, summary } = calculateScore(allResults);
  const { grade, label, emoji } = getGrade(score);
  const categoryScores = getCategoryScores(allResults);
  const topAttackVectors = getTopAttackVectors(allResults);
  const scanDuration = ((Date.now() - scanStart) / 1000).toFixed(1) + 's';

  // Send completion event
  sendEvent({
    type: 'complete',
    score,
    grade,
    label,
    emoji,
    summary,
    categoryScores,
    topAttackVectors,
    scanDuration,
    hostname: parsed.hostname,
    url: parsed.href,
    timestamp: new Date().toISOString(),
  });

  res.end();
});

app.listen(PORT, () => {
  console.log(`\n🛡️  ShieldScan Backend running on http://localhost:${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/api/health`);
  console.log(`   Scan:   POST http://localhost:${PORT}/api/scan\n`);
});
