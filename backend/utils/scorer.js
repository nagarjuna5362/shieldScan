/**
 * scorer.js — Weight-based security scoring engine
 *
 * HOW IT WORKS:
 *   Every check has a fixed "weight" (points it can earn).
 *   PASS    → earns 100% of its weight
 *   WARNING → earns 50% of its weight
 *   FAIL    → earns 0% of its weight
 *   ERROR   → excluded from both numerator AND denominator
 *
 *   Overall Score   = sum(earned) / sum(possible) × 100
 *   Category Score  = same formula, but only within that category
 *
 *   This guarantees category scores are ALWAYS consistent with the
 *   overall score — no more "categories show 90% but overall is 30%".
 */

// ─── Check weights (higher = more important) ─────────────────────────────────
const CHECK_WEIGHTS = {
  // Transport Security (total: 45)
  https_enforcement:    15,
  ssl_certificate:      15,
  hsts:                  8,
  tls_version:           7,

  // HTTP Headers (total: 29)
  csp:                   8,
  clickjacking:          8,
  content_type_options:  4,
  referrer_policy:       3,
  permissions_policy:    3,
  xss_protection:        3,

  // CORS & API Security (total: 26)
  cors_misconfiguration: 10,
  api_enumeration:        5,
  idor:                   8,
  http_methods:           3,

  // Cookie & Session (total: 11)
  cookie_security:        8,
  session_in_url:         3,

  // File & Info Exposure (total: 21)
  sensitive_files:       10,
  server_disclosure:      3,
  directory_listing:      5,
  stack_trace:            3,

  // DNS & Network (total: 7)
  dns_security:           4,
  subdomain_takeover:     3,

  // Rate Limiting & Abuse (total: 10)
  rate_limiting:          5,
  open_redirect:          4,
  security_txt:           1,
};

// ─── How many points a result earns ──────────────────────────────────────────
function earnedPoints(result) {
  const weight = CHECK_WEIGHTS[result.checkId] || 0;
  if (!weight) return null;          // unknown check — skip

  switch (result.status) {
    case 'ERROR':   return null;     // cannot determine — exclude from score
    case 'PASS':    return weight;   // full credit
    case 'WARNING': return weight * 0.5; // half credit
    case 'FAIL':    return 0;        // zero credit
    default:        return null;
  }
}

// ─── Overall score ────────────────────────────────────────────────────────────
function calculateScore(results) {
  let earned   = 0;
  let possible = 0;
  const summary = { critical: 0, high: 0, medium: 0, low: 0, pass: 0, error: 0 };

  for (const r of results) {
    // Tally summary counts
    if      (r.status === 'PASS')                                  summary.pass++;
    else if (r.status === 'ERROR')                                 summary.error++;
    else if ((r.status === 'FAIL' || r.status === 'WARNING')) {
      if      (r.severity === 'CRITICAL') summary.critical++;
      else if (r.severity === 'HIGH')     summary.high++;
      else if (r.severity === 'MEDIUM')   summary.medium++;
      else                                summary.low++;
    }

    // Tally score points
    const pts    = earnedPoints(r);
    const weight = CHECK_WEIGHTS[r.checkId] || 0;
    if (pts !== null && weight > 0) {
      earned   += pts;
      possible += weight;
    }
  }

  const score = possible > 0
    ? Math.max(0, Math.min(100, Math.round((earned / possible) * 100)))
    : 0;

  return { score, summary };
}

// ─── Grade lookup ─────────────────────────────────────────────────────────────
function getGrade(score) {
  if (score >= 90) return { grade: 'A', label: 'Excellent — Well secured',         emoji: '🟢' };
  if (score >= 75) return { grade: 'B', label: 'Good — Minor issues present',       emoji: '🟡' };
  if (score >= 55) return { grade: 'C', label: 'Needs Work — Fix issues soon',      emoji: '🟠' };
  if (score >= 35) return { grade: 'D', label: 'Dangerous — Fix immediately',       emoji: '🔴' };
  return              { grade: 'F', label: 'Critical — Do not use this site',       emoji: '💀' };
}

// ─── Per-category scores (same math, scoped to category) ─────────────────────
function getCategoryScores(results) {
  const cats = {
    'Transport Security':    { earned: 0, possible: 0 },
    'HTTP Headers':          { earned: 0, possible: 0 },
    'CORS & API Security':   { earned: 0, possible: 0 },
    'Cookie & Session':      { earned: 0, possible: 0 },
    'File & Info Exposure':  { earned: 0, possible: 0 },
    'DNS & Network':         { earned: 0, possible: 0 },
    'Rate Limiting & Abuse': { earned: 0, possible: 0 },
  };

  for (const r of results) {
    const cat    = cats[r.category];
    if (!cat) continue;

    const pts    = earnedPoints(r);
    const weight = CHECK_WEIGHTS[r.checkId] || 0;
    if (pts !== null && weight > 0) {
      cat.earned   += pts;
      cat.possible += weight;
    }
  }

  const scores = {};
  for (const [name, data] of Object.entries(cats)) {
    scores[name] = data.possible > 0
      ? Math.max(0, Math.min(100, Math.round((data.earned / data.possible) * 100)))
      : 100; // no checks ran in category → assume fine
  }
  return scores;
}

// ─── Top attack vectors (worst findings for the summary warning) ──────────────
function getTopAttackVectors(results) {
  const fails = results
    .filter(r => (r.status === 'FAIL' || r.status === 'WARNING') && r.attackScenario)
    .sort((a, b) => {
      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
    });
  return fails.slice(0, 3).map(r => r.attackScenario.split('.')[0]);
}

module.exports = { calculateScore, getGrade, getCategoryScores, getTopAttackVectors };
