const dns = require('dns').promises;
const { isPrivateIp } = require('../utils/dnsResolver');

async function checkSubdomains(parsedUrl) {
  const base = {
    checkId: 'subdomains',
    checkNumber: 26,
    category: 'DNS & Network',
    name: 'Subdomain Exposure Probe',
  };

  const hostname = parsedUrl.hostname;
  const parts = hostname.split('.');
  
  // If IP address, do not brute-force subdomains
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: 'Host is an IP address; subdomain enumeration skipped',
      technicalDetail: 'No subdomains to check for raw IP address.',
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }

  // Only scan subdomains if we have a proper domain (at least two parts: example.com)
  const baseDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  const subdomainsToTest = ['admin', 'api', 'dev', 'staging', 'mail'];
  const exposed = [];

  for (const sub of subdomainsToTest) {
    const targetHost = `${sub}.${baseDomain}`;
    if (targetHost === hostname) continue; // Skip scanning self

    try {
      // Resolve the IPv4 address
      const ips = await Promise.race([
        dns.resolve4(targetHost),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 2000)),
      ]);

      if (ips && ips.length > 0) {
        const publicIps = ips.filter(ip => !isPrivateIp(ip));
        if (publicIps.length > 0) {
          exposed.push(`${targetHost} (${publicIps.join(', ')})`);
        }
      }
    } catch {
      // Host resolution failed or timed out; subdomain is likely not active
    }
  }

  if (exposed.length > 0) {
    return {
      ...base,
      severity: 'HIGH',
      status: 'FAIL',
      description: `Active subdomains exposed publicly: ${exposed.join(', ')}`,
      technicalDetail: `Exposed hosts: ${exposed.join(' | ')}`,
      attackScenario:
        'Development, staging, or admin subdomains exposed on the public DNS are prime targets. Attackers probe these environments for debug logs, unauthenticated APIs, configuration files, and outdated server software, bypassing production security boundaries.',
      fix: {
        description: 'Remove public DNS entries for internal/staging environments, or restrict access behind a VPN/IP whitelist',
        code: `# DNS Management
# Delete public A/CNAME records for internal subdomains:
# - dev.${baseDomain}
# - staging.${baseDomain}

# Access restriction example for Nginx:
# allow 192.168.1.0/24; # Whitelist corporate subnet
# deny all;            # Restrict everyone else`,
      },
      points_deducted: 10,
    };
  }

  return {
    ...base,
    severity: 'INFO',
    status: 'PASS',
    description: 'No common development or administrative subdomains exposed',
    technicalDetail: `Checked common subdomains (admin, api, dev, staging, mail) for ${baseDomain}`,
    attackScenario: null,
    fix: null,
    points_deducted: 0,
  };
}

module.exports = { checkSubdomains };
