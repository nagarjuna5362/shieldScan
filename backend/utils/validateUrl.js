/**
 * validateUrl.js — URL validation + SSRF protection
 */

const PRIVATE_IP_RANGES = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i,
];

function validateUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, error: 'Invalid URL format. Please include http:// or https://' };
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { valid: false, error: 'Only http:// and https:// URLs are supported' };
  }

  const hostname = parsed.hostname.toLowerCase();

  if (hostname === 'localhost' || hostname === '0.0.0.0') {
    return { valid: false, error: 'Scanning localhost is not permitted' };
  }

  for (const pattern of PRIVATE_IP_RANGES) {
    if (pattern.test(hostname)) {
      return { valid: false, error: 'Scanning private/internal IP ranges is not permitted' };
    }
  }

  // Block file:// and other non-web schemes embedded in hostname tricks
  if (hostname.includes('..') || hostname.length > 253) {
    return { valid: false, error: 'Invalid hostname' };
  }

  return { valid: true, parsed, hostname, origin: parsed.origin };
}

module.exports = { validateUrl };
