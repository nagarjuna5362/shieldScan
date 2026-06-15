const dns = require('dns');

function isPrivateIp(ipAddress) {
  if (!ipAddress) return true;

  const ipv4Match = ipAddress.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4Match) {
    const [, octet1, octet2] = ipv4Match.map(Number);
    if (octet1 === 127) return true;
    if (octet1 === 10) return true;
    if (octet1 === 192 && octet2 === 168) return true;
    if (octet1 === 172 && octet2 >= 16 && octet2 <= 31) return true;
    if (octet1 === 169 && octet2 === 254) return true;
    if (octet1 === 0) return true;
    return false;
  }

  const cleanIp = ipAddress.toLowerCase().trim();
  if (cleanIp === '::1' || cleanIp === '::' || cleanIp === '0:0:0:0:0:0:0:1') {
    return true;
  }

  if (
    cleanIp.startsWith('fc') ||
    cleanIp.startsWith('fd') ||
    cleanIp.startsWith('fe8') ||
    cleanIp.startsWith('fe9') ||
    cleanIp.startsWith('fea') ||
    cleanIp.startsWith('feb')
  ) {
    return true;
  }

  if (cleanIp.startsWith('::ffff:')) {
    const part = cleanIp.substring(7);
    if (part.includes('.')) {
      return isPrivateIp(part);
    }
    const hex = part.replace(/:/g, '');
    if (hex.length === 8 && /^[0-9a-f]{8}$/.test(hex)) {
      const o1 = parseInt(hex.substring(0, 2), 16);
      const o2 = parseInt(hex.substring(2, 4), 16);
      const o3 = parseInt(hex.substring(4, 6), 16);
      const o4 = parseInt(hex.substring(6, 8), 16);
      return isPrivateIp(`${o1}.${o2}.${o3}.${o4}`);
    }
  }

  return false;
}

function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);

    if (Array.isArray(address)) {
      const hasPrivate = address.some(addr => isPrivateIp(addr.address));
      if (hasPrivate) {
        return callback(new Error('Access to private IP addresses is blocked'));
      }
    } else {
      if (isPrivateIp(address)) {
        return callback(new Error('Access to private IP addresses is blocked'));
      }
    }

    callback(null, address, family);
  });
}

module.exports = {
  isPrivateIp,
  safeLookup,
};
