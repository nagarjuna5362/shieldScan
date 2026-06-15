const CHECK_WEIGHTS = {
  // Transport — Core security foundation (high weight)
  https_enforcement: 12,
  ssl_certificate:   12,
  ssl_chain:          6,
  hsts:               8,
  tls_version:        7,

  // Headers — Critical for web security (higher weight)
  csp:                10,
  clickjacking:        8,
  content_type_options: 5,
  referrer_policy:     4,
  permissions_policy:  4,
  xss_protection:      4,

  // CORS & API — Critical for data exposure
  cors_misconfiguration: 12,
  api_enumeration:        5,
  idor:                   8,
  http_methods:           4,
  email_injection:        5,   // reduced: often errors on sites without contact forms

  // Cookies & Session — Important
  cookie_security:    8,
  session_in_url:     3,

  // Exposure — Very important for real security
  sensitive_files:   10,
  server_disclosure:  3,
  directory_listing:  5,
  stack_trace:        3,

  // DNS & Network — Informational, lower weight (these often PASS trivially for simple sites)
  dns_security:          4,
  subdomain_takeover:    3,
  dkim_record:           3,
  caa_record:            2,
  subdomains:            4,   // reduced: simple sites trivially pass with no subdomains
  open_ports:            4,   // reduced: simple sites trivially pass with no open ports

  // Abuse Protection — Important
  rate_limiting:     5,
  open_redirect:     4,
  security_txt:      1,
  mixed_content:     8,
};

const CHECK_METRICS = {
  https_enforcement: { severity: 'CRITICAL', cvss: 8.1, exploitability: 'Easy' },
  ssl_certificate: { severity: 'CRITICAL', cvss: 8.1, exploitability: 'Easy' },
  ssl_chain: { severity: 'HIGH', cvss: 7.5, exploitability: 'Easy' },
  hsts: { severity: 'HIGH', cvss: 7.5, exploitability: 'Moderate' },
  tls_version: { severity: 'HIGH', cvss: 7.5, exploitability: 'Hard' },
  csp: { severity: 'HIGH', cvss: 7.2, exploitability: 'Moderate' },
  clickjacking: { severity: 'HIGH', cvss: 7.2, exploitability: 'Easy' },
  content_type_options: { severity: 'MEDIUM', cvss: 4.8, exploitability: 'Moderate' },
  referrer_policy: { severity: 'LOW', cvss: 3.1, exploitability: 'Hard' },
  permissions_policy: { severity: 'LOW', cvss: 3.1, exploitability: 'Hard' },
  xss_protection: { severity: 'LOW', cvss: 3.1, exploitability: 'Moderate' },
  cors_misconfiguration: { severity: 'CRITICAL', cvss: 9.3, exploitability: 'Easy' },
  api_enumeration: { severity: 'HIGH', cvss: 7.5, exploitability: 'Easy' },
  idor: { severity: 'CRITICAL', cvss: 9.3, exploitability: 'Easy' },
  http_methods: { severity: 'HIGH', cvss: 7.5, exploitability: 'Moderate' },
  email_injection: { severity: 'HIGH', cvss: 7.5, exploitability: 'Easy' },
  cookie_security: { severity: 'HIGH', cvss: 7.5, exploitability: 'Moderate' },
  session_in_url: { severity: 'HIGH', cvss: 7.5, exploitability: 'Easy' },
  sensitive_files: { severity: 'CRITICAL', cvss: 9.8, exploitability: 'Easy' },
  server_disclosure: { severity: 'LOW', cvss: 2.1, exploitability: 'Hard' },
  directory_listing: { severity: 'HIGH', cvss: 7.5, exploitability: 'Easy' },
  stack_trace: { severity: 'HIGH', cvss: 7.5, exploitability: 'Easy' },
  dns_security: { severity: 'MEDIUM', cvss: 5.3, exploitability: 'Hard' },
  subdomain_takeover: { severity: 'HIGH', cvss: 8.5, exploitability: 'Moderate' },
  dkim_record: { severity: 'LOW', cvss: 3.5, exploitability: 'Hard' },
  caa_record: { severity: 'LOW', cvss: 3.5, exploitability: 'Hard' },
  subdomains: { severity: 'HIGH', cvss: 7.5, exploitability: 'Moderate' },
  open_ports: { severity: 'CRITICAL', cvss: 9.8, exploitability: 'Easy' },
  rate_limiting: { severity: 'MEDIUM', cvss: 5.3, exploitability: 'Easy' },
  open_redirect: { severity: 'HIGH', cvss: 7.4, exploitability: 'Easy' },
  security_txt: { severity: 'LOW', cvss: 1.5, exploitability: 'Hard' },
  mixed_content: { severity: 'HIGH', cvss: 7.4, exploitability: 'Easy' },
};

function earnedPoints(result) {
  const weight = CHECK_WEIGHTS[result.checkId] || 0;
  if (!weight) return null;

  switch (result.status) {
    case 'ERROR':
      // Partial penalty: we can't confirm safety, so only award 30% of points.
      // This prevents ERROR results from being silently excluded (which inflates scores).
      return { pts: weight * 0.3, possible: weight };
    case 'PASS':
      return { pts: weight, possible: weight };
    case 'WARNING':
      return { pts: weight * 0.5, possible: weight };
    case 'FAIL':
      return { pts: 0, possible: weight };
    default:
      return null;
  }
}

function enrichResults(results) {
  for (const r of results) {
    const metrics = CHECK_METRICS[r.checkId] || { severity: 'INFO', cvss: 0.0, exploitability: 'Hard' };
    if (r.status === 'PASS') {
      r.severity = 'INFO';
      r.cvss = 0.0;
      r.exploitability = 'N/A';
    } else {
      r.severity = metrics.severity;
      r.cvss = r.status === 'WARNING' ? Math.round(metrics.cvss * 0.5 * 10) / 10 : metrics.cvss;
      r.exploitability = metrics.exploitability;
    }
  }
  return results;
}

function calculateScore(results) {
  let earned = 0;
  let possible = 0;
  const summary = { critical: 0, high: 0, medium: 0, low: 0, pass: 0, error: 0 };

  enrichResults(results);

  for (const r of results) {
    if (r.status === 'PASS') summary.pass++;
    else if (r.status === 'ERROR') summary.error++;
    else if (r.status === 'FAIL' || r.status === 'WARNING') {
      if (r.severity === 'CRITICAL') summary.critical++;
      else if (r.severity === 'HIGH') summary.high++;
      else if (r.severity === 'MEDIUM') summary.medium++;
      else summary.low++;
    }

    const result = earnedPoints(r);
    if (result !== null) {
      earned += result.pts;
      possible += result.possible;
    }
  }

  const score = possible > 0 ? Math.max(0, Math.min(100, Math.round((earned / possible) * 100))) : 0;

  return { score, summary };
}


function getGrade(score) {
  if (score >= 90) return { grade: 'A', label: 'Excellent — Well secured', emoji: '🟢' };
  if (score >= 75) return { grade: 'B', label: 'Good — Minor issues present', emoji: '🟡' };
  if (score >= 55) return { grade: 'C', label: 'Needs Work — Fix issues soon', emoji: '🟠' };
  if (score >= 35) return { grade: 'D', label: 'Dangerous — Fix immediately', emoji: '🔴' };
  return { grade: 'F', label: 'Critical — Do not use this site', emoji: '💀' };
}

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
    const cat = cats[r.category];
    if (!cat) continue;

    const result = earnedPoints(r);
    if (result !== null) {
      cat.earned   += result.pts;
      cat.possible += result.possible;
    }
  }

  const scores = {};
  for (const [name, data] of Object.entries(cats)) {
    scores[name] = data.possible > 0
      ? Math.max(0, Math.min(100, Math.round((data.earned / data.possible) * 100)))
      : 100;
  }
  return scores;
}

function getTopAttackVectors(results) {
  const fails = results
    .filter((r) => (r.status === 'FAIL' || r.status === 'WARNING') && r.attackScenario)
    .sort((a, b) => {
      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
    });
  return fails.slice(0, 3).map((r) => r.attackScenario.split('.')[0]);
}

function getFixPriorities(results) {
  const sortedIssues = results
    .filter((r) => (r.status === 'FAIL' || r.status === 'WARNING') && r.fix)
    .sort((a, b) => {
      const metricsA = CHECK_METRICS[a.checkId] || { cvss: 0 };
      const metricsB = CHECK_METRICS[b.checkId] || { cvss: 0 };
      return metricsB.cvss - metricsA.cvss;
    });

  return sortedIssues.slice(0, 3).map((r) => {
    const metrics = CHECK_METRICS[r.checkId] || { cvss: 0, exploitability: 'Easy' };
    return {
      checkId: r.checkId,
      name: r.name,
      severity: r.severity,
      cvss: metrics.cvss,
      exploitability: metrics.exploitability,
      recommendation: r.fix.description,
      code: r.fix.code,
    };
  });
}

module.exports = {
  calculateScore,
  getGrade,
  getCategoryScores,
  getTopAttackVectors,
  getFixPriorities,
  enrichResults,
};
