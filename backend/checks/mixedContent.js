const axios = require('axios');

const TIMEOUT = 8000;
const USER_AGENT = 'ShieldScan-SecurityBot/1.0 (security scanner)';

async function checkMixedContent(parsedUrl) {
  const base = {
    checkId: 'mixed_content',
    checkNumber: 28,
    category: 'Transport Security',
    name: 'Mixed Content Detection',
  };

  // If the scanned URL is HTTP, mixed content is not applicable (since the main page is already unencrypted)
  if (parsedUrl.protocol !== 'https:') {
    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: 'Site is served over HTTP; mixed content checks not applicable',
      technicalDetail: 'Active and passive mixed content audits require an HTTPS origin.',
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }

  try {
    const response = await axios.get(parsedUrl.href, {
      maxRedirects: 3,
      validateStatus: () => true,
      headers: { 'User-Agent': USER_AGENT },
      timeout: TIMEOUT,
    });

    const html = response.data;
    if (typeof html !== 'string') {
      return {
        ...base,
        severity: 'INFO',
        status: 'PASS',
        description: 'No mixed content detected (response was not HTML)',
        technicalDetail: 'Non-HTML homepage body returned.',
        attackScenario: null,
        fix: null,
        points_deducted: 0,
      };
    }

    // Search for assets loaded over unencrypted http://
    // Regex matches src="http://..." and href="http://..." for scripts, stylesheets, images, audio, video, frames, etc.
    const mixedUrls = [];
    const mixedRegex = /(?:src|href)=["'](http:\/\/[^"'\s>]+)/gi;
    let match;

    while ((match = mixedRegex.exec(html)) !== null) {
      const url = match[1];
      // Exclude generic schemas, empty values, or standard schemas
      if (url && !url.includes('w3.org') && !url.includes('schema.org') && !mixedUrls.includes(url)) {
        mixedUrls.push(url);
      }
    }

    if (mixedUrls.length > 0) {
      const list = mixedUrls.slice(0, 5).join(', ');
      const overflow = mixedUrls.length > 5 ? ` (+${mixedUrls.length - 5} more)` : '';

      return {
        ...base,
        severity: 'HIGH',
        status: 'FAIL',
        description: `Unencrypted resources (Mixed Content) loaded over HTTP: ${list}${overflow}`,
        technicalDetail: `Found ${mixedUrls.length} HTTP resources inside HTTPS source.`,
        attackScenario:
          'Mixed Content occurs when an HTTPS site loads scripts, stylesheets, or images over unencrypted HTTP. Attackers can inject malicious Javascript or CSS into these HTTP resource payloads on public networks to hijack sessions, execute client-side scripts, or alter site aesthetics.',
        fix: {
          description: 'Update all asset URLs to use https:// or relative paths (//), and enable HSTS with Upgrade-Insecure-Requests',
          code: `# Content Security Policy Header
# Enforce upgrading all passive and active mixed content automatically:
Content-Security-Policy: upgrade-insecure-requests;

# HTML code updates:
# Change: <script src="http://example.com/js/app.js"></script>
# To:     <script src="https://example.com/js/app.js"></script>`,
        },
        points_deducted: 10,
      };
    }

    return {
      ...base,
      severity: 'INFO',
      status: 'PASS',
      description: 'All embedded links and assets load securely over HTTPS',
      technicalDetail: 'HTML source parsed: zero unencrypted http:// asset references identified.',
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  } catch (err) {
    return {
      ...base,
      severity: 'INFO',
      status: 'ERROR',
      description: `Mixed content check failed: ${err.message}`,
      technicalDetail: err.message,
      attackScenario: null,
      fix: null,
      points_deducted: 0,
    };
  }
}

module.exports = { checkMixedContent };
