import React, { useState } from 'react';

// ─────────────────────────────────────────────
// Plain-English explainers for each check ID
// ─────────────────────────────────────────────
const PLAIN_EXPLANATIONS = {
  https_enforcement: {
    what: "Your website can be opened without a padlock (using http:// instead of https://).",
    why: "When someone visits without HTTPS, their connection is not encrypted. Anyone on the same Wi-Fi can read or change what they see.",
    example: "Imagine sending a postcard instead of a sealed envelope — anyone who handles it can read it.",
    fix: "Set up your web server to automatically send visitors to the https:// version of your site.",
  },
  ssl_certificate: {
    what: "Your website's security certificate has a problem (expired, wrong domain, or not trusted).",
    why: "Browsers show a scary 'Not Secure' warning to visitors. Users may leave your site immediately.",
    example: "It's like showing an ID card that's expired — security won't let you through.",
    fix: "Renew your SSL certificate. Free certificates from Let's Encrypt are available at certbot.eff.org.",
  },
  hsts: {
    what: "Your site doesn't tell browsers to always use the secure (https://) version.",
    why: "Attackers can trick users into visiting the insecure version and intercept their data.",
    example: "It's like a door that locks only sometimes — an attacker can catch you when it's unlocked.",
    fix: "Add a header called 'Strict-Transport-Security' to all your server responses.",
  },
  tls_version: {
    what: "Your site is using an old, insecure version of encryption.",
    why: "Old encryption versions (TLS 1.0 or 1.1) have known weaknesses hackers can exploit.",
    example: "Like using a combination lock from the 1980s — today's tools can crack it quickly.",
    fix: "Update your server to only use TLS 1.2 or TLS 1.3.",
  },
  csp: {
    what: "Your site is missing a rule that controls what code can run on your pages.",
    why: "Without this, attackers can inject malicious scripts into your pages and steal user data.",
    example: "Like an office with no visitor badge policy — anyone can walk in and access sensitive areas.",
    fix: "Add a Content-Security-Policy header to restrict which sources can run scripts on your site.",
  },
  clickjacking: {
    what: "Your website can be hidden inside another website and trick users into clicking invisible buttons.",
    why: "Attackers embed your page in their site with fake buttons — users think they're clicking on yours.",
    example: "Imagine someone putting a transparent sheet over a voting ballot and redirecting your click.",
    fix: "Add the header 'X-Frame-Options: DENY' or use Content-Security-Policy frame-ancestors.",
  },
  content_type_options: {
    what: "Your server is missing a header that prevents browsers from misreading file types.",
    why: "Browsers might execute a text file as a script if they guess its type, allowing code injection.",
    example: "Like a package with no label — the receiver might open it the wrong way and trigger something dangerous.",
    fix: "Add the header 'X-Content-Type-Options: nosniff' to all responses.",
  },
  referrer_policy: {
    what: "Your site shares too much information when users click links to other websites.",
    why: "Private page URLs (like password-reset links) could be sent to third-party sites automatically.",
    example: "Like whispering a secret address, but everyone in the room hears you before you leave.",
    fix: "Add the header 'Referrer-Policy: strict-origin-when-cross-origin' to control what gets shared.",
  },
  permissions_policy: {
    what: "Your site doesn't control which browser features (camera, microphone, location) can be used.",
    why: "Embedded ads or third-party code could secretly use the user's camera or location.",
    example: "Like renting a room and not specifying whether the renter can sublet — they might misuse the space.",
    fix: "Add a 'Permissions-Policy' header to disable features you don't need.",
  },
  xss_protection: {
    what: "Your site is missing an old protection header against script-injection attacks.",
    why: "Some older browsers may run malicious scripts injected into your pages.",
    example: "Like leaving the door unlocked for a type of burglar that only affects older homes.",
    fix: "Add the header 'X-XSS-Protection: 1; mode=block'.",
  },
  cors_misconfiguration: {
    what: "Your website allows any other website to make requests to it on behalf of users.",
    why: "A malicious site could silently read your users' private data or perform actions as them.",
    example: "Like your bank letting any stranger walk in and check your balance just because they ask nicely.",
    fix: "Set the 'Access-Control-Allow-Origin' header to only allow specific trusted domains.",
  },
  api_enumeration: {
    what: "Common hidden pages (like /admin, /api/users) were found or accessible on your site.",
    why: "Attackers discover these endpoints and try to exploit them for unauthorized access.",
    example: "Like having a 'Staff Only' door clearly labeled in the middle of a shopping mall.",
    fix: "Remove unused endpoints, add authentication to all sensitive routes, and use security monitoring.",
  },
  idor: {
    what: "Your site may let users access other users' data by changing a number in the URL.",
    why: "Changing /user/123 to /user/124 might expose another person's private data.",
    example: "Like having numbered hotel rooms where any guest can open any room without a key check.",
    fix: "Always verify server-side that the logged-in user has permission to access the requested data.",
  },
  http_methods: {
    what: "Your server accepts dangerous HTTP methods like DELETE or PUT that should not be open.",
    why: "Attackers can use these methods to modify or delete data on your server.",
    example: "Like having an 'Employees Only' button that any visitor can press.",
    fix: "Disable HTTP methods you don't use. Only allow GET and POST for most websites.",
  },
  cookie_security: {
    what: "Your site's login cookies (which keep users signed in) are not properly protected.",
    why: "Attackers can steal cookies to take over user accounts without needing a password.",
    example: "Like leaving your house key on the front doorstep — anyone can grab it and get in.",
    fix: "Add 'HttpOnly' and 'Secure' flags to all cookies. Use 'SameSite=Strict' when possible.",
  },
  session_in_url: {
    what: "Login session tokens are being included in the website URL.",
    why: "URLs get saved in browser history and server logs, exposing session tokens to anyone with access.",
    example: "Like printing your ATM PIN on the receipt that the machine spits out.",
    fix: "Store session tokens in cookies, not in the URL.",
  },
  sensitive_files: {
    what: "Private files (like .env, config files, or backup files) are accessible from the internet.",
    why: "These files often contain passwords, API keys, and database credentials.",
    example: "Like leaving your filing cabinet with all passwords outside your office door.",
    fix: "Block access to sensitive files in your web server config. Never put secret files in your public folder.",
  },
  server_disclosure: {
    what: "Your server tells visitors which software and version it's running.",
    why: "Attackers can look up known vulnerabilities for that specific software version.",
    example: "Like wearing a shirt that says 'I use Brand X alarm system — easily bypassed'.",
    fix: "Configure your server to hide or remove the 'Server' and 'X-Powered-By' headers.",
  },
  directory_listing: {
    what: "Visiting a folder URL on your site shows a list of all files inside.",
    why: "Attackers can browse your server's file structure and find sensitive documents.",
    example: "Like leaving your file cabinet open and alphabetically organized for anyone to browse.",
    fix: "Disable directory listing in your web server configuration (Apache/Nginx/etc.).",
  },
  stack_trace: {
    what: "Your site shows detailed error messages and code details when something goes wrong.",
    why: "These messages reveal how your code works internally, giving attackers a roadmap.",
    example: "Like handing someone your source code and internal documents after they trip on your doorstep.",
    fix: "Turn off debug error messages in production. Show users a simple 'Something went wrong' message.",
  },
  dns_security: {
    what: "Your domain is missing email security records (SPF and DMARC).",
    why: "Anyone can send emails pretending to be from your domain (email spoofing / phishing attacks).",
    example: "Like anyone being able to write letters using your return address — your contacts can't tell it's fake.",
    fix: "Add SPF and DMARC DNS records to your domain. Many domain registrars have guides for this.",
  },
  subdomain_takeover: {
    what: "One or more of your subdomains point to a service that no longer exists.",
    why: "An attacker can register that service and then control traffic to your subdomain.",
    example: "Like keeping a forwarding address at a house you no longer rent — the new tenant gets your mail.",
    fix: "Audit your DNS records. Remove or update any CNAME records pointing to unused external services.",
  },
  rate_limiting: {
    what: "Your site doesn't limit how many requests someone can make in a short time.",
    why: "Attackers can make millions of automated requests to brute-force passwords or overload your server.",
    example: "Like a bank that lets you try your PIN unlimited times — someone will eventually guess it.",
    fix: "Set up rate limiting on your server (e.g. Nginx rate_limit, Cloudflare rules, or express-rate-limit).",
  },
  open_redirect: {
    what: "Your site can be used to automatically redirect users to any other website.",
    why: "Attackers send phishing links like yoursite.com/go?to=evil.com — users trust your domain but end up on a fake site.",
    example: "Like a trusted bus that passengers board, then drops them off at a different (unsafe) location.",
    fix: "Validate all redirect destinations server-side. Only allow redirects to your own domain.",
  },
  security_txt: {
    what: "Your site doesn't have a security contact file so researchers know how to report vulnerabilities.",
    why: "Security researchers who find bugs in your site won't know who to contact, so problems go unreported.",
    example: "Like having no contact number on your business front door — people can't report a problem.",
    fix: "Create a file at /.well-known/security.txt listing your security contact email.",
  },
};

const SEVERITY_CONFIG = {
  CRITICAL: { label: 'CRITICAL', cls: 'badge-critical', cardCls: 'card-critical', emoji: 'X', color: '#991b1b', bg: '#fee2e2' },
  HIGH:     { label: 'HIGH',     cls: 'badge-high',     cardCls: 'card-high',     emoji: '!', color: '#dc2626', bg: '#fee2e2' },
  MEDIUM:   { label: 'MEDIUM',   cls: 'badge-medium',   cardCls: 'card-medium',   emoji: '~', color: '#d97706', bg: '#fef3c7' },
  LOW:      { label: 'LOW',      cls: 'badge-low',      cardCls: 'card-low',      emoji: 'i', color: '#2563eb', bg: '#dbeafe' },
  INFO:     { label: 'PASS',     cls: 'badge-pass',     cardCls: 'card-pass',     emoji: 'ok', color: '#059669', bg: '#d1fae5' },
};

const STATUS_ICON = { PASS: '✅', FAIL: '❌', WARNING: '⚠️', ERROR: '⚙️' };
const STATUS_LABEL = {
  PASS: 'All good — no issue found',
  FAIL: 'Problem found — action needed',
  WARNING: 'Potential risk — worth reviewing',
  ERROR: 'Could not check this item',
};
const SEVERITY_SIMPLE = {
  CRITICAL: 'Very Dangerous',
  HIGH: 'Serious Risk',
  MEDIUM: 'Moderate Risk',
  LOW: 'Minor Issue',
};

// ─── Explain Popup ────────────────────────────────────────────────
function ExplainPopup({ checkId, name, onClose }) {
  const info = PLAIN_EXPLANATIONS[checkId];
  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 9999, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px' }}
      onClick={onClose}
    >
      <div
        style={{ background: '#ffffff', borderRadius: '8px', padding: '32px', maxWidth: '560px', width: '100%', boxShadow: '0 20px 60px rgba(0,0,0,0.2)', maxHeight: '90vh', overflowY: 'auto' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '24px' }}>
          <div>
            <div style={{ fontSize: '11px', color: '#64748b', fontFamily: "'Space Mono', monospace", fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '6px' }}>Plain-English Explanation</div>
            <div style={{ fontSize: '18px', fontWeight: 800, color: '#0f172a', fontFamily: "'Outfit', sans-serif" }}>{name}</div>
          </div>
          <button onClick={onClose} style={{ background: '#f1f5f9', border: 'none', borderRadius: '4px', width: '30px', height: '30px', fontSize: '16px', cursor: 'pointer', color: '#475569', flexShrink: 0, marginLeft: '12px' }}>x</button>
        </div>
        {info ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '6px', padding: '16px' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: '#475569', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>What is this problem?</div>
              <div style={{ fontSize: '14px', color: '#0f172a', lineHeight: 1.6 }}>{info.what}</div>
            </div>
            <div style={{ background: '#fff7ed', border: '1px solid #fed7aa', borderRadius: '6px', padding: '16px' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: '#c2410c', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Why does it matter?</div>
              <div style={{ fontSize: '14px', color: '#7c2d12', lineHeight: 1.6 }}>{info.why}</div>
            </div>
            <div style={{ background: '#fffbeb', border: '1px solid #fde68a', borderRadius: '6px', padding: '16px' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: '#92400e', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Simple Real-World Example</div>
              <div style={{ fontSize: '14px', color: '#78350f', lineHeight: 1.6, fontStyle: 'italic' }}>{info.example}</div>
            </div>
            <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '6px', padding: '16px' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: '#166534', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>How to fix it</div>
              <div style={{ fontSize: '14px', color: '#14532d', lineHeight: 1.6 }}>{info.fix}</div>
            </div>
          </div>
        ) : (
          <p style={{ color: '#475569', fontSize: '14px', lineHeight: 1.6 }}>Review the technical finding below and consult your developer about the fix instructions.</p>
        )}
        <button
          onClick={onClose}
          style={{ marginTop: '24px', width: '100%', background: '#0f172a', color: '#ffffff', border: 'none', borderRadius: '6px', padding: '12px', fontSize: '14px', fontWeight: 700, cursor: 'pointer', fontFamily: "'Inter', sans-serif" }}
        >
          Got it, close this
        </button>
      </div>
    </div>
  );
}

// ─── Main VulnCard ─────────────────────────────────────────────────
export default function VulnCard({ result, index }) {
  const [expanded, setExpanded] = useState(result.status === 'FAIL' || result.status === 'WARNING');
  const [showExplain, setShowExplain] = useState(false);

  const isPass = result.status === 'PASS';
  const isError = result.status === 'ERROR';
  const sevKey = isPass || isError ? 'INFO' : result.severity;
  const sevConfig = SEVERITY_CONFIG[sevKey] || SEVERITY_CONFIG.INFO;
  const cardClass = isPass ? 'card-pass' : isError ? 'card-error' : sevConfig.cardCls;
  const simpleStatus = STATUS_LABEL[result.status] || result.status;

  return (
    <>
      {showExplain && (
        <ExplainPopup checkId={result.checkId} name={result.name} onClose={() => setShowExplain(false)} />
      )}

      <div
        className={`animate-slide-in ${cardClass}`}
        style={{ background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '6px', overflow: 'hidden', animationDelay: `${index * 0.05}s`, opacity: 0, animationFillMode: 'forwards', marginBottom: '10px', boxShadow: '0 1px 3px rgba(0,0,0,0.05)', transition: 'border-color 0.2s ease, box-shadow 0.2s ease' }}
        onMouseEnter={(e) => { e.currentTarget.style.borderColor = '#cbd5e1'; e.currentTarget.style.boxShadow = '0 4px 6px -1px rgba(0,0,0,0.06)'; }}
        onMouseLeave={(e) => { e.currentTarget.style.borderColor = '#e2e8f0'; e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.05)'; }}
      >
        {/* Header */}
        <button
          onClick={() => setExpanded(!expanded)}
          style={{ width: '100%', display: 'flex', alignItems: 'center', gap: '12px', padding: '14px 18px', background: 'transparent', border: 'none', cursor: 'pointer', textAlign: 'left' }}
        >
          <span style={{ fontSize: '20px', flexShrink: 0 }}>{STATUS_ICON[result.status] || 'o'}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span style={{ color: '#0f172a', fontWeight: 700, fontSize: '14px', fontFamily: "'Outfit', sans-serif" }}>{result.name}</span>
              {!isPass && !isError && (
                <span style={{ background: sevConfig.bg, color: sevConfig.color, border: `1px solid ${sevConfig.color}40`, fontSize: '10px', fontWeight: 700, padding: '2px 8px', borderRadius: '3px', fontFamily: "'Space Mono', monospace", whiteSpace: 'nowrap' }}>
                  {SEVERITY_SIMPLE[result.severity] || result.severity}
                </span>
              )}
              {isPass && <span style={{ background: '#d1fae5', color: '#059669', border: '1px solid #6ee7b780', fontSize: '10px', fontWeight: 700, padding: '2px 8px', borderRadius: '3px', fontFamily: "'Space Mono', monospace" }}>All Good</span>}
              {isError && <span style={{ background: '#f1f5f9', color: '#475569', border: '1px solid #cbd5e1', fontSize: '10px', fontWeight: 700, padding: '2px 8px', borderRadius: '3px', fontFamily: "'Space Mono', monospace" }}>Could Not Check</span>}
            </div>
            <div style={{ color: '#64748b', fontSize: '12px', marginTop: '3px' }}>{simpleStatus}</div>
          </div>
          {result.points_deducted > 0 && (
            <span style={{ fontFamily: "'Space Mono', monospace", fontSize: '11px', fontWeight: 700, color: '#b91c1c', background: '#fee2e2', padding: '2px 8px', borderRadius: '4px', border: '1px solid #fca5a5', flexShrink: 0 }}>-{result.points_deducted} pts</span>
          )}
          <span style={{ color: '#94a3b8', fontSize: '14px', transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s', flexShrink: 0 }}>v</span>
        </button>

        {/* Expanded */}
        {expanded && (
          <div style={{ borderTop: '1px solid #f1f5f9', background: '#f8fafc' }}>
            {/* Action bar */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 18px', borderBottom: '1px solid #f1f5f9', background: '#ffffff', flexWrap: 'wrap', gap: '8px' }}>
              <span style={{ fontSize: '12px', color: '#475569' }}>Category: <strong>{result.category}</strong></span>
              <button
                onClick={(e) => { e.stopPropagation(); setShowExplain(true); }}
                style={{ background: '#0f172a', color: '#ffffff', border: 'none', borderRadius: '4px', padding: '6px 16px', fontSize: '12px', fontWeight: 700, cursor: 'pointer', fontFamily: "'Inter', sans-serif", transition: 'background-color 0.15s' }}
                onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = '#dc2626'; }}
                onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = '#0f172a'; }}
              >
                Explain this to me
              </button>
            </div>

            <div style={{ padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {result.technicalDetail && (
                <div>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '5px' }}>What was found</div>
                  <div style={{ background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '4px', padding: '10px 14px', fontFamily: "'Space Mono', monospace", fontSize: '12px', color: '#334155', wordBreak: 'break-all' }}>{result.technicalDetail}</div>
                </div>
              )}
              {result.attackScenario && (
                <div>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: '#b91c1c', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '5px' }}>What can happen if not fixed</div>
                  <div style={{ background: '#fff1f2', border: '1px solid #fecdd3', borderRadius: '4px', padding: '12px 14px', fontSize: '13px', color: '#991b1b', lineHeight: 1.6 }}>{result.attackScenario}</div>
                </div>
              )}
              {result.fix && (
                <div>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: '#166534', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '5px' }}>How to fix it</div>
                  <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '4px', padding: '12px 14px', fontSize: '13px', color: '#14532d', lineHeight: 1.6, marginBottom: result.fix.code ? '8px' : 0 }}>{result.fix.description}</div>
                  {result.fix.code && <div className="code-block">{result.fix.code}</div>}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
