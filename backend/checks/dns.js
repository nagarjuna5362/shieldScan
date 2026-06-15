const dns = require('dns').promises;

const TIMEOUT = 8000;

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), ms)),
  ]);
}

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

    try {
      await withTimeout(dns.resolve(hostname, 'DNSKEY'), TIMEOUT);
      details.push('DNSSEC: Enabled');
    } catch {
      issues.push({ type: 'DNSSEC', severity: 'LOW', message: 'DNSSEC not configured' });
    }

    if (issues.length === 0) {
      return {
        ...base,
        severity: 'INFO',
        status: 'PASS',
        description: 'All DNS security records configured correctly (SPF, DMARC, DNSSEC)',
        technicalDetail: details.join(' | '),
        attackScenario: null,
        fix: null,
        points_deducted: 0,
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
      attackScenario:
        "Without SPF and DMARC, an attacker can send emails that appear to come exactly from your domain — support@yourdomain.com, noreply@yourdomain.com, billing@yourdomain.com. Your customers receive these phishing emails, trust them because they're from your real domain, click malicious links, and enter their login credentials on a fake site. This is email spoofing.",
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
    return {
      ...base,
      severity: 'INFO',
      status: 'ERROR',
      description: `DNS security check failed: ${err.message}`,
      technicalDetail: err.message,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }
}

async function checkDkimRecord(parsedUrl) {
  const base = {
    checkId: 'dkim_record',
    checkNumber: 22,
    category: 'DNS & Network',
    name: 'DKIM DNS Verification',
  };

  const hostname = parsedUrl.hostname;
  const commonSelectors = ['default', 'google', 'k1', 'sig1', 'mail'];
  let foundDkim = null;
  let triedSelectors = [];

  for (const selector of commonSelectors) {
    const dkimHost = `${selector}._domainkey.${hostname}`;
    triedSelectors.push(selector);
    try {
      const records = await withTimeout(dns.resolveTxt(dkimHost), 3000);
      const dkim = records.flat().find(r => r.startsWith('v=DKIM1') || r.includes('p='));
      if (dkim) {
        foundDkim = { selector, record: dkim };
        break;
      }
    } catch {
      // Selector not found
    }
  }

  if (foundDkim) {
    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: `DKIM record found for selector "${foundDkim.selector}"`,
      technicalDetail: `DKIM Record: ${foundDkim.record.substring(0, 100)}...`,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }

  return {
    ...base,
    severity: 'LOW',
    status: 'WARNING',
    description: 'No DKIM record detected at common selectors',
    technicalDetail: `Checked selectors: ${triedSelectors.join(', ')}._domainkey.${hostname}`,
    attackScenario:
      'DomainKeys Identified Mail (DKIM) adds a cryptographic signature to your emails. Without DKIM, receiving mail servers (like Gmail or Yahoo) cannot cryptographically verify that the email was sent by you, increasing spam scores or causing mail to be rejected.',
    fix: {
      description: 'Generate a DKIM public/private key pair from your mail host and add the public key as a DNS TXT record',
      code: `# TXT record in your DNS provider:
# Name: default._domainkey
# Value: v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...`,
    },
    points_deducted: 2,
  };
}

async function checkCaaRecord(parsedUrl) {
  const base = {
    checkId: 'caa_record',
    checkNumber: 23,
    category: 'DNS & Network',
    name: 'CAA DNS Record Audit',
  };

  const hostname = parsedUrl.hostname;
  const parts = hostname.split('.');
  const baseDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;

  try {
    let caaRecords = [];
    try {
      caaRecords = await withTimeout(dns.resolve(hostname, 'CAA'), TIMEOUT);
    } catch {
      // Try resolving on base domain if subdomain failed
      if (baseDomain !== hostname) {
        try {
          caaRecords = await withTimeout(dns.resolve(baseDomain, 'CAA'), TIMEOUT);
        } catch {
          // No CAA records
        }
      }
    }

    if (caaRecords && caaRecords.length > 0) {
      const formatted = caaRecords.map(r => `${r.issue ? 'issue: ' + r.issue : JSON.stringify(r)}`).join(' | ');
      return {
        ...base,
        severity: 'INFO',
        status: 'PASS',
        description: 'CAA DNS records configured correctly',
        technicalDetail: `CAA configuration: ${formatted}`,
        attackScenario: null,
        fix: null,
        points_deducted: 0,
      };
    }

    return {
      ...base,
      severity: 'LOW',
      status: 'WARNING',
      description: 'Missing CAA DNS record',
      technicalDetail: 'No CAA (Certification Authority Authorization) records found',
      attackScenario:
        'Without a CAA DNS record, any certificate authority (CA) in the world is allowed to issue SSL certificates for your domain. If an attacker compromises a weaker CA, they can obtain a rogue certificate for your site to execute MITM intercept attacks.',
      fix: {
        description: 'Add a CAA record in your DNS provider to whitelist authorized certificate issuers (e.g. Let\'s Encrypt)',
        code: `# Add CAA records in your DNS provider:
# Name: @
# Value: 0 issue "letsencrypt.org"
# Value: 0 issue "digicert.com"`,
      },
      points_deducted: 2,
    };
  } catch (err) {
    return {
      ...base,
      severity: 'INFO',
      status: 'ERROR',
      description: `CAA check failed: ${err.message}`,
      technicalDetail: err.message,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }
}

async function checkSubdomainTakeover(parsedUrl) {
  const base = {
    checkId: 'subdomain_takeover',
    checkNumber: 24,
    category: 'DNS & Network',
    name: 'Subdomain Takeover Risk',
  };

  const hostname = parsedUrl.hostname;
  const parts = hostname.split('.');
  const baseDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  const subdomains = ['www', 'mail', 'api', 'dev', 'staging', 'test', 'admin', 'shop', 'blog', 'app', 'cdn', 'static'];
  const vulnerableFingerprints = [
    'github.io', 'herokuapp.com', 'netlify.app', 's3.amazonaws.com',
    'azurewebsites.net', 'cloudfront.net', 'surge.sh', 'vercel.app',
    'ghost.io', 'helpscoutdocs.com', 'zendesk.com',
  ];

  try {
    const atRisk = [];

    for (const sub of subdomains) {
      const fqdn = `${sub}.${baseDomain}`;
      if (fqdn === hostname) continue;

      try {
        const cnames = await withTimeout(dns.resolveCname(fqdn), 3000);
        if (cnames && cnames.length > 0) {
          const cname = cnames[0].toLowerCase();
          const isVulnerable = vulnerableFingerprints.some(fp => cname.includes(fp));
          if (isVulnerable) {
            atRisk.push({ subdomain: fqdn, cname });
          }
        }
      } catch {
        // CNAME lookup failed
      }
    }

    if (atRisk.length > 0) {
      return {
        ...base,
        severity: 'HIGH',
        status: 'FAIL',
        description: `${atRisk.length} subdomain(s) may be vulnerable to takeover: ${atRisk.map(r => r.subdomain).join(', ')}`,
        technicalDetail: atRisk.map(r => `${r.subdomain} → CNAME: ${r.cname}`).join(' | '),
        attackScenario: `${atRisk[0].subdomain} has a CNAME pointing to ${atRisk[0].cname}, which appears to be an unclaimed cloud service. An attacker registers that service name, and now they control ${atRisk[0].subdomain}. They serve a phishing page or malware from your legitimate subdomain, and users trust it because it's your domain.`,
        fix: {
          description: 'Remove DNS records for unused subdomains or claim the cloud service',
          code: `# Option 1: Remove the CNAME record if the subdomain isn't used
# Delete CNAME record for: ${atRisk.map(r => r.subdomain).join(', ')}

# Option 2: Claim the cloud resource (GitHub Pages, Heroku, etc.)
# Make sure the service account/project still exists`,
        },
        points_deducted: 10,
      };
    }

    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: 'No obvious subdomain takeover risks detected',
      technicalDetail: `Checked ${subdomains.length} common subdomains for unclaimed CNAME targets`,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  } catch (err) {
    return {
      ...base,
      severity: 'INFO',
      status: 'ERROR',
      description: `Subdomain takeover check failed: ${err.message}`,
      technicalDetail: err.message,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }
}

module.exports = { checkDnsSecurity, checkDkimRecord, checkCaaRecord, checkSubdomainTakeover };
