const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const http = require('http');
const https = require('https');
const axios = require('axios');
const { safeLookup } = require('./utils/dnsResolver');
const { validateUrl } = require('./utils/validateUrl');
const { calculateScore, getGrade, getCategoryScores, getTopAttackVectors, getFixPriorities } = require('./utils/scorer');
const { saveReport, getReport } = require('./utils/shareStore');
const { generatePdfReport } = require('./utils/pdfGenerator');

const { checkHttpsEnforcement, checkSslCertificate, checkSslChain, checkHsts, checkTlsVersion } = require('./checks/transport');
const { checkCsp, checkClickjacking, checkContentTypeOptions, checkReferrerPolicy, checkPermissionsPolicy, checkXssProtection } = require('./checks/headers');
const { checkCors, checkApiEnumeration, checkIdor, checkHttpMethods } = require('./checks/cors');
const { checkCookieSecurity, checkSessionInUrl } = require('./checks/cookies');
const { checkSensitiveFiles, checkServerDisclosure, checkDirectoryListing, checkStackTrace } = require('./checks/fileExposure');
const { checkDnsSecurity, checkDkimRecord, checkCaaRecord, checkSubdomainTakeover } = require('./checks/dns');
const { checkRateLimiting, checkOpenRedirect, checkSecurityTxt } = require('./checks/rateLimiting');
const { checkSubdomains } = require('./checks/subdomains');
const { checkOpenPorts } = require('./checks/ports');
const { checkMixedContent } = require('./checks/mixedContent');
const { checkEmailInjection } = require('./checks/emailInjection');

const safeHttpAgent = new http.Agent({ lookup: safeLookup, keepAlive: false });
const safeHttpsAgent = new https.Agent({ lookup: safeLookup, keepAlive: false });
axios.defaults.httpAgent = safeHttpAgent;
axios.defaults.httpsAgent = safeHttpsAgent;

const app = express();
app.set('trust proxy', true);
const PORT = process.env.PORT || 3001;

app.disable('x-powered-by');

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginEmbedderPolicy: false,
}));

app.use(compression());
app.use(express.json({ limit: '2kb' }));

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));

const scanLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 5,                  // limit each IP to 5 scans per hour
  message: { error: 'Too many scans from this IP. Please wait 1 hour before scanning again.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req, res) => {
    if (process.env.NODE_ENV === 'development') {
      return true;
    }
    const ip = req.ip || req.connection.remoteAddress || '';
    if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || ip.includes('localhost')) {
      return true;
    }
    return false;
  },
  handler: (req, res, next, options) => {
    console.warn(`[RATE LIMIT HIT] IP: ${req.ip} tried to access ${req.originalUrl}`);
    res.status(options.statusCode).json(options.message);
  }
});

const generalLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 120,
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/health', generalLimiter);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'ShieldScan backend running' });
});

app.post('/api/reports', generalLimiter, async (req, res) => {
  const { report } = req.body;
  if (!report) {
    return res.status(400).json({ error: 'Report data is required' });
  }
  const uuid = await saveReport(report);
  res.json({ uuid });
});

app.get('/api/reports/:uuid', generalLimiter, async (req, res) => {
  const report = await getReport(req.params.uuid);
  if (!report) {
    return res.status(404).json({ error: 'Report not found or expired' });
  }
  res.json(report);
});

app.get('/api/reports/:uuid/pdf', generalLimiter, async (req, res) => {
  const report = await getReport(req.params.uuid);
  if (!report) {
    return res.status(404).json({ error: 'Report not found or expired' });
  }

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename=shieldscan-${report.hostname}.pdf`);

  generatePdfReport(report, res);
});

app.get('/api/badge/:hostname', (req, res) => {
  const score = parseInt(req.query.score) || 100;
  let color = '#2e7d32'; // green
  if (score < 40) color = '#d32f2f'; // red
  else if (score < 60) color = '#f57c00'; // orange
  else if (score < 80) color = '#fbc02d'; // yellow

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="130" height="20">
    <linearGradient id="b" x2="0" y2="100%">
      <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
      <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <mask id="a">
      <rect width="130" height="20" rx="3" fill="#fff"/>
    </mask>
    <g mask="url(#a)">
      <path fill="#555" d="M0 0h85v20H0z"/>
      <path fill="${color}" d="M85 0h45v20H85z"/>
      <path fill="url(#b)" d="M0 0h130v20H0z"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
      <text x="42.5" y="15" fill="#010101" fill-opacity=".3">shieldscan</text>
      <text x="42.5" y="14">shieldscan</text>
      <text x="107.5" y="15" fill="#010101" fill-opacity=".3">${score}/100</text>
      <text x="107.5" y="14">${score}/100</text>
    </g>
  </svg>`;

  res.setHeader('Content-Type', 'image/svg+xml');
  res.send(svg);
});

app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send("User-agent: *\nAllow: /\nDisallow: /api/");
});

app.get('/.well-known/security.txt', (req, res) => {
  res.type('text/plain');
  res.send("Contact: mailto:security@shieldscan.dev\nExpires: 2027-06-13T22:00:00.000Z\nAcknowledgements: https://shieldscan.dev/acknowledgements\nPreferred-Languages: en");
});

app.get('/security.txt', (req, res) => {
  res.redirect(301, '/.well-known/security.txt');
});

app.post('/api/scan', scanLimiter, async (req, res, next) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'URL must be a valid string' });
    }

    if (url.length > 2048) {
      return res.status(400).json({ error: 'URL is too long (maximum 2048 characters)' });
    }

    const validation = validateUrl(url);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const { parsed } = validation;
    const scanStart = Date.now();

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

    sendEvent({
      type: 'start',
      url: parsed.href,
      hostname: parsed.hostname,
      totalChecks: 32,
    });

    const allResults = [];

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

    await Promise.all([
      runCheck(checkHttpsEnforcement, [parsed]),
      runCheck(checkSslCertificate, [parsed]),
      runCheck(checkSslChain, [parsed]),
      runCheck(checkHsts, [parsed]),
      runCheck(checkTlsVersion, [parsed]),
    ]);

    await Promise.all([
      runCheck(checkCsp, [parsed]),
      runCheck(checkClickjacking, [parsed]),
      runCheck(checkContentTypeOptions, [parsed]),
      runCheck(checkReferrerPolicy, [parsed]),
      runCheck(checkPermissionsPolicy, [parsed]),
      runCheck(checkXssProtection, [parsed]),
    ]);

    await Promise.all([
      runCheck(checkCors, [parsed]),
      runCheck(checkHttpMethods, [parsed]),
    ]);

    await Promise.all([
      runCheck(checkApiEnumeration, [parsed]),
      runCheck(checkIdor, [parsed]),
      runCheck(checkEmailInjection, [parsed]),
    ]);

    await Promise.all([
      runCheck(checkCookieSecurity, [parsed]),
      runCheck(checkSessionInUrl, [parsed]),
    ]);

    await Promise.all([
      runCheck(checkSensitiveFiles, [parsed]),
      runCheck(checkServerDisclosure, [parsed]),
      runCheck(checkDirectoryListing, [parsed]),
      runCheck(checkStackTrace, [parsed]),
    ]);

    await Promise.all([
      runCheck(checkDnsSecurity, [parsed]),
      runCheck(checkDkimRecord, [parsed]),
      runCheck(checkCaaRecord, [parsed]),
      runCheck(checkSubdomainTakeover, [parsed]),
      runCheck(checkSubdomains, [parsed]),
      runCheck(checkOpenPorts, [parsed]),
    ]);

    await runCheck(checkRateLimiting, [parsed]);

    await Promise.all([
      runCheck(checkOpenRedirect, [parsed]),
      runCheck(checkSecurityTxt, [parsed]),
      runCheck(checkMixedContent, [parsed]),
    ]);

    const { score, summary } = calculateScore(allResults);
    const { grade, label, emoji } = getGrade(score);
    const categoryScores = getCategoryScores(allResults);
    const topAttackVectors = getTopAttackVectors(allResults);
    const fixPriorities = getFixPriorities(allResults);
    const scanDuration = ((Date.now() - scanStart) / 1000).toFixed(1) + 's';

    sendEvent({
      type: 'complete',
      score,
      grade,
      label,
      emoji,
      summary,
      categoryScores,
      topAttackVectors,
      fixPriorities,
      scanDuration,
      hostname: parsed.hostname,
      url: parsed.href,
      timestamp: new Date().toISOString(),
    });

    res.end();
  } catch (err) {
    next(err);
  }
});

app.post('/api/contact', generalLimiter, async (req, res) => {
  const { name, email, issue } = req.body;

  if (!name || !email || !issue) {
    return res.status(400).json({ error: 'All fields (name, email, issue) are required' });
  }

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.SMTP_USER || '',
      pass: process.env.SMTP_PASS || '',
    },
  });

  const mailOptions = {
    from: `"ShieldScan Contact Form" <${process.env.SMTP_USER || 'shieldscan.mailer@gmail.com'}>`,
    replyTo: email,
    to: 'nagarjuna2005reddy@gmail.com',
    subject: `🛡️ ShieldScan Issue Report from ${name}`,
    text: `Name: ${name}\nEmail: ${email}\n\nIssue Details:\n${issue}\n\n---\nSent via ShieldScan Contact Support Portal`,
    html: `
      <div style="font-family: sans-serif; padding: 20px; color: #333; max-width: 600px; border: 1px solid #ddd; border-radius: 8px;">
        <h2 style="color: #e02929; border-bottom: 2px solid #e02929; padding-bottom: 8px; margin-top: 0;">🛡️ ShieldScan Issue Report</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> <a href="mailto:${email}">${email}</a></p>
        <div style="background: #f9f9f9; padding: 15px; border-radius: 6px; border-left: 4px solid #e02929; margin-top: 15px;">
          <h3 style="margin-top: 0; font-size: 14px; color: #111;">Issue Details:</h3>
          <p style="white-space: pre-wrap; line-height: 1.6; margin: 0; font-size: 13px;">${issue}</p>
        </div>
        <hr style="border: 0; border-top: 1px solid #eee; margin-top: 24px; margin-bottom: 12px;" />
        <p style="font-size: 11px; color: #888; margin: 0;">Sent via ShieldScan Contact Support Portal</p>
      </div>
    `
  };

  try {
    if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
      console.log('\n--- [MOCK MAIL LOGGED] ---');
      console.log(`To: nagarjuna2005reddy@gmail.com`);
      console.log(`From (ReplyTo): ${email}`);
      console.log(`Subject: ${mailOptions.subject}`);
      console.log(`Content:\n${mailOptions.text}`);
      console.log('--------------------------\n');
      
      await new Promise(resolve => setTimeout(resolve, 800));
      return res.json({ success: true, message: 'Message logged to server console (SMTP credentials not set)' });
    }

    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: 'Your message has been sent successfully!' });
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ error: 'Failed to send message. Please try again later.' });
  }
});

app.use((err, req, res, next) => {
  console.error('[Error Handler]', err.message);

  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS policy blocked this request' });
  }

  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload size limit exceeded (maximum 2KB)' });
  }

  res.status(err.status || 500).json({
    error: 'An internal server error occurred',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined,
  });
});

process.on('uncaughtException', (err) => {
  console.error('CRITICAL UNCAUGHT EXCEPTION:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('CRITICAL UNHANDLED REJECTION:', reason);
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n🛡️  ShieldScan Backend running on http://localhost:${PORT}`);
    console.log(`   Health: http://localhost:${PORT}/api/health`);
    console.log(`   Scan:   POST http://localhost:${PORT}/api/scan\n`);
  });
}
