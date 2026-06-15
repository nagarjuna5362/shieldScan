const net = require('net');
const { safeLookup } = require('../utils/dnsResolver');

function testPort(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = 'closed';

    socket.setTimeout(1500);

    socket.connect({ host, port, lookup: safeLookup }, () => {
      status = 'open';
      socket.destroy();
    });

    socket.on('error', () => {
      status = 'closed';
      socket.destroy();
    });

    socket.on('timeout', () => {
      status = 'closed';
      socket.destroy();
    });

    socket.on('close', () => {
      resolve({ port, status });
    });
  });
}

async function checkOpenPorts(parsedUrl) {
  const base = {
    checkId: 'open_ports',
    checkNumber: 27,
    category: 'DNS & Network',
    name: 'Exposed Port Scanner',
  };

  const hostname = parsedUrl.hostname;
  const portsToTest = [21, 23, 3306, 27017, 6379, 8080, 8443];
  const openPorts = [];

  const promises = portsToTest.map(port => testPort(hostname, port));
  const results = await Promise.all(promises);

  for (const res of results) {
    if (res.status === 'open') {
      openPorts.push(res.port);
    }
  }

  if (openPorts.length > 0) {
    const portDesc = {
      21: 'FTP (File Transfer Protocol) - insecure file exchange',
      23: 'Telnet - unencrypted terminal access',
      3306: 'MySQL Database Server',
      27017: 'MongoDB Database',
      6379: 'Redis Cache Server',
      8080: 'HTTP Alternate Web Port',
      8443: 'HTTPS Alternate Web Port',
    };

    const exposedDetails = openPorts.map(p => `${p} (${portDesc[p] || 'Unknown Service'})`).join(', ');

    return {
      ...base,
      severity: openPorts.some(p => [21, 23, 3306, 27017, 6379].includes(p)) ? 'CRITICAL' : 'HIGH',
      status: 'FAIL',
      description: `Dangerous open ports detected publicly: ${exposedDetails}`,
      technicalDetail: `Open TCP ports: ${openPorts.join(', ')}`,
      attackScenario:
        'Exposing database ports (MySQL/MongoDB/Redis) or legacy admin services (Telnet/FTP) directly to the public web allows attackers to brute-force authentication, exploit remote code execution (RCE) flaws, or access databases directly to exfiltrate database records.',
      fix: {
        description: 'Close database and admin ports in your cloud firewall (security groups) or restrict them to secure VPN subnets',
        code: `# Linux Firewall (UFW) configuration
# Block MySQL port from public access:
sudo ufw deny 3306/tcp

# Block Redis port from public access:
sudo ufw deny 6379/tcp

# AWS / Cloud Provider Security Groups:
# Edit Inbound Rules:
# - Remove rules allowing "0.0.0.0/0" on ports 3306, 27017, 6379, 21, 23.`,
      },
      points_deducted: 15,
    };
  }

  return {
    ...base,
    severity: 'INFO',
    status: 'PASS',
    description: 'No dangerous database or admin ports detected publicly',
    technicalDetail: `Checked ports: ${portsToTest.join(', ')}`,
    attackScenario: null,
    fix: null,
    points_deducted: 0,
  };
}

module.exports = { checkOpenPorts };
