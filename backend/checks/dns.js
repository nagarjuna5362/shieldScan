/**
 * dns.js — Checks 21-22: DNS & Network Security
 * CHECK 21: DNS Security (SPF, DMARC, DNSSEC)
 * CHECK 22: Subdomain Takeover Risk
 */

const dns = require('dns').promises;

const TIMEOUT = 8000;

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), ms)),
  ]);
}

// CHECK 21 — DNS Security (SPF, DMARC, DNSSEC)
async function checkDnsSecurity(parsedUrl) {
  const base = {
    checkId: 'dns_security',
    checkNumber: 21,
    category: 'DNS & Network',
    name: 'DNS Security (SPF, DMARC, DNSSEC)',
  };

  const hostname = parsedUrl.hostname;
  const issues = [];
  const details = [];

  try {
    // Check SPF
    try {
      const txtRecords = await withTimeout(dns.resolveTxt(hostname), TIMEOUT);
      const spfRecord = txtRecords.flat().find(r => r.startsWith('v=spf1'));
      if (spfRecord) {
        details.push(`SPF: ${spfRecord.substring(0, 80)}`);
      } else {
        issues.push({ type: 'SPF', severity: 'MEDIUM', message: 'No SPF record found' });
      }
    } catch {
      issues.push({ type: 'SPF', severity: 'MEDIUM', message: 'SPF record lookup failed' });
    }

    // Check DMARC
    try {
      const dmarcRecords = await withTimeout(dns.resolveTxt(`_dmarc.${hostname}`), TIMEOUT);
      const dmarcRecord = dmarcRecords.flat().find(r => r.startsWith('v=DMARC1'));
      if (dmarcRecord) {
        details.push(`DMARC: ${dmarcRecord.substring(0, 80)}`);
      } else {
        issues.push({ type: 'DMARC', severity: 'MEDIUM', message: 'No DMARC record found' });
      }
    } catch {
      issues.push({ type: 'DMARC', severity: 'MEDIUM', message: 'DMARC record not found' });
    }

    // Check DNSSEC
    try {
      await withTimeout(dns.resolve(hostname, 'DNSKEY'), TIMEOUT);
      details.push('DNSSEC: Enabled');
    } catch {
      issues.push({ type: 'DNSSEC', severity: 'LOW', message: 'DNSSEC not configured' });
    }

    if (issues.length === 0) {
      return {
        ...base, severity: 'INFO', status: 'PASS',
        description: 'All DNS security records configured correctly (SPF, DMARC, DNSSEC)',
        technicalDetail: details.join(' | '),
        attackScenario: null, fix: null, points_deducted: 0,
      };
    }

    const highestSeverity = issues.some(i => i.severity === 'MEDIUM') ? 'MEDIUM' : 'LOW';
    const missingTypes = issues.map(i => i.type).join(', ');

    return {
      ...base,
      severity: highestSeverity,
      status: 'FAIL',
      description: `Missing DNS security records: ${missingTypes}`,
      technicalDetail: `Issues: ${issues.map(i => `${i.type}: ${i.message}`).join(' | ')}${details.length ? ' | Found: ' + details.join(', ') : ''}`,
      attackScenario: "Without SPF and DMARC, an attacker can send emails that appear to come exactly from your domain — support@yourdomain.com, noreply@yourdomain.com, billing@yourdomain.com. Your customers receive these phishing emails, trust them because they're from your real domain, click malicious links, and enter their login credentials on a fake site. This is email spoofing.",
      fix: {
        description: 'Add SPF and DMARC TXT records to your DNS',
        code: `# Add these TXT records in your DNS provider:

# SPF Record (replace with your mail servers)
TXT @ "v=spf1 include:_spf.google.com include:sendgrid.net ~all"

# DMARC Record
TXT _dmarc "v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; pct=100"

# Verify with:
# dig TXT yourdomain.com
# dig TXT _dmarc.yourdomain.com`,
      },
      points_deducted: highestSeverity === 'MEDIUM' ? 5 : 2,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `DNS security check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

// CHECK 22 — Subdomain Takeover Risk
async function checkSubdomainTakeover(parsedUrl) {
  const base = {
    checkId: 'subdomain_takeover',
    checkNumber: 22,
    category: 'DNS & Network',
    name: 'Subdomain Takeover Risk',
  };

  const hostname = parsedUrl.hostname;
  // Extract base domain (last two parts)
  const parts = hostname.split('.');
  const baseDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;

  const subdomains = ['www', 'mail', 'api', 'dev', 'staging', 'test', 'admin', 'shop', 'blog', 'app', 'cdn', 'static'];

  // Cloud services that indicate potential takeover if unclaimed
  const vulnerableFingerprints = [
    'github.io', 'herokuapp.com', 'netlify.app', 's3.amazonaws.com',
    'azurewebsites.net', 'cloudfront.net', 'surge.sh', 'vercel.app',
    'ghost.io', 'helpscoutdocs.com', 'zendesk.com',
  ];

  try {
    const atRisk = [];

    for (const sub of subdomains) {
      const fqdn = `${sub}.${baseDomain}`;
      if (fqdn === hostname) continue; // skip the target itself

      try {
        const cnames = await withTimeout(dns.resolveCname(fqdn), TIMEOUT);
        if (cnames && cnames.length > 0) {
          const cname = cnames[0].toLowerCase();
          const isVulnerable = vulnerableFingerprints.some(fp => cname.includes(fp));
          if (isVulnerable) {
            atRisk.push({ subdomain: fqdn, cname });
          }
        }
      } catch {
        // Subdomain doesn't exist or no CNAME — that's fine
      }
    }

    if (atRisk.length > 0) {
      return {
        ...base, severity: 'HIGH', status: 'FAIL',
        description: `${atRisk.length} subdomain(s) may be vulnerable to takeover: ${atRisk.map(r => r.subdomain).join(', ')}`,
        technicalDetail: atRisk.map(r => `${r.subdomain} → CNAME: ${r.cname}`).join(' | '),
        attackScenario: `${atRisk[0].subdomain} has a CNAME pointing to ${atRisk[0].cname}, which appears to be an unclaimed cloud service. An attacker registers that service name, and now they control ${atRisk[0].subdomain}. They serve a phishing page or malware from your legitimate subdomain, and users trust it because it's your domain.`,
        fix: {
          description: 'Remove DNS records for unused subdomains or claim the cloud service',
          code: `# Option 1: Remove the CNAME record if the subdomain isn't used
# Delete CNAME record for: ${atRisk.map(r => r.subdomain).join(', ')}

# Option 2: Claim the cloud resource (GitHub Pages, Heroku, etc.)
# Make sure the service account/project still exists

# Audit regularly:
# dig CNAME staging.yourdomain.com
# Check if the pointed service is still active`,
        },
        points_deducted: 10,
      };
    }

    return {
      ...base, severity: 'INFO', status: 'PASS',
      description: 'No obvious subdomain takeover risks detected',
      technicalDetail: `Checked ${subdomains.length} common subdomains for unclaimed CNAME targets`,
      attackScenario: null, fix: null, points_deducted: 0,
    };
  } catch (err) {
    return { ...base, severity: 'INFO', status: 'ERROR', description: `Subdomain takeover check failed: ${err.message}`, technicalDetail: err.message, attackScenario: null, fix: null, points_deducted: 0 };
  }
}

module.exports = { checkDnsSecurity, checkSubdomainTakeover };
