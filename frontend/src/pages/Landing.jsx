import React, { useState } from 'react';
import FlipCard from '../components/FlipCard';

const SAMPLES = ['github.com', 'wikipedia.org', 'bbc.co.uk', 'gov.in'];

const CHECKS_DATA = [
  {
    icon: '🔒',
    label: 'HTTPS & SSL/TLS',
    description: 'Verifies SSL certificates, HTTPS enforcement, and encryption strength.',
    disaster: 'Hackers on public Wi-Fi can easily hijack sessions and steal passwords in plain text!'
  },
  {
    icon: '📋',
    label: 'Security Headers',
    description: 'Checks CSP, HSTS, X-Frame-Options, and other security headers.',
    disaster: 'Missing headers expose users to clickjacking and malicious script injections!'
  },
  {
    icon: '🍪',
    label: 'Cookie Security',
    description: 'Analyzes cookie flags such as Secure, HttpOnly, and SameSite.',
    disaster: 'Insecure cookies let attackers steal login sessions via cross-site scripts (XSS)!'
  },
  {
    icon: '🌐',
    label: 'CORS & API risks',
    description: 'Inspects CORS origins, allowed HTTP methods, and API exposure.',
    disaster: 'Permissive CORS policies let malicious sites steal your private database data!'
  },
  {
    icon: '📁',
    label: 'Exposed Files',
    description: 'Probes for public access to sensitive files like .env, config, and .git.',
    disaster: 'Exposing .env credentials gives attackers full database and server control!'
  },
  {
    icon: '🌍',
    label: 'DNS Records',
    description: 'Verifies SPF, DKIM, DMARC, and checks for subdomain takeover risks.',
    disaster: 'Weak DNS settings let scammers spoof your emails to phish your clients!'
  },
  {
    icon: '⚡',
    label: 'Rate Limiting',
    description: 'Tests endpoint vulnerability to brute-force and Denial-of-Service attacks.',
    disaster: 'No rate limits allow bots to spam forms, crash servers, and inflate costs!'
  },
  {
    icon: '🔍',
    label: '25 checks total',
    description: 'A complete non-intrusive scan covering server disclosures and DNS flaws.',
    disaster: 'Ignoring security checks leaves quiet backdoors open for massive data breaches!'
  }
];


export default function Landing({ onStart }) {
  const [url, setUrl]       = useState('');
  const [error, setError]   = useState('');
  const [focused, setFocused] = useState(false);
  const [activeTab, setActiveTab] = useState('scanner'); // 'scanner' | 'about'

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    let input = url.trim().replace(/\s+/g, '');
    if (!input) { setError('Enter a website URL first'); return; }
    if (!/^https?:\/\//i.test(input)) input = 'https://' + input;

    let parsed;
    try { parsed = new URL(input); }
    catch { setError("That doesn't look right — try something like example.in or mysite.dev"); return; }

    const h = parsed.hostname.toLowerCase();
    if (!h.includes('.')) { setError('Need a full domain — e.g. example.com or site.in'); return; }
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h)) {
      setError('Cannot scan local/private addresses'); return;
    }
    onStart(input);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '40px 20px', position: 'relative', zIndex: 2 }}>
      <div style={{ width: '100%', maxWidth: '580px' }}>

        {/* Header */}
        <div style={{ marginBottom: '24px', textAlign: 'center' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
            <span style={{ fontSize: '22px' }}>🛡️</span>
            <span style={{ fontSize: '18px', fontWeight: 700, color: '#1c1c1c', letterSpacing: '-0.01em' }}>ShieldScan</span>
            <span style={{ fontSize: '11px', background: '#e02929', color: '#fff', padding: '1px 6px', borderRadius: '3px', fontWeight: 600 }}>free</span>
          </div>

          {/* Tab Navigation switcher */}
          <div style={{
            display: 'flex',
            justifyContent: 'center',
            gap: '8px',
            marginTop: '8px',
            borderBottom: '2px solid #eaeaea',
            paddingBottom: '8px'
          }}>
            <button
              onClick={() => setActiveTab('scanner')}
              style={{
                background: activeTab === 'scanner' ? '#111' : 'transparent',
                color: activeTab === 'scanner' ? '#fff' : '#666',
                border: 'none',
                borderRadius: '4px',
                padding: '6px 14px',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
                fontFamily: "'Space Mono', monospace",
                transition: 'all 0.1s',
              }}
            >
              [ SCANNER ]
            </button>
            <button
              onClick={() => setActiveTab('about')}
              style={{
                background: activeTab === 'about' ? '#111' : 'transparent',
                color: activeTab === 'about' ? '#fff' : '#666',
                border: 'none',
                borderRadius: '4px',
                padding: '6px 14px',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
                fontFamily: "'Space Mono', monospace",
                transition: 'all 0.1s',
              }}
            >
              [ ABOUT & INFO ]
            </button>
          </div>
        </div>

        {/* Scanner Tab View */}
        {activeTab === 'scanner' && (
          <div style={{ animation: 'slideIn 0.2s ease forwards' }}>
            <div style={{ textAlign: 'center', marginBottom: '24px' }}>
              <h1 style={{ fontSize: 'clamp(22px, 5vw, 30px)', fontWeight: 700, color: '#111', lineHeight: 1.3, marginBottom: '10px' }}>
                Check if your website has security problems
              </h1>
              <p style={{ color: '#666', fontSize: '15px', lineHeight: 1.6 }}>
                Paste any URL — .com, .in, .dev, .me, .co.uk, .io, anything — and get a plain-English security report in about 60 seconds.
              </p>
            </div>

            {/* Search box */}
            <form onSubmit={handleSubmit}>
              <div style={{
                display: 'flex',
                gap: '8px',
                background: '#fff',
                border: `2px solid ${focused ? '#e02929' : '#ccc'}`,
                borderRadius: '8px',
                padding: '6px 6px 6px 14px',
                alignItems: 'center',
                transition: 'border-color 0.15s',
              }}>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => { setUrl(e.target.value); setError(''); }}
                  onFocus={() => setFocused(true)}
                  onBlur={() => setFocused(false)}
                  placeholder="yoursite.com  or  example.in  or  app.dev"
                  autoComplete="off"
                  style={{
                    flex: 1,
                    border: 'none',
                    outline: 'none',
                    background: 'transparent',
                    fontSize: '15px',
                    color: '#1c1c1c',
                    fontFamily: "'Space Mono', monospace",
                    minWidth: 0,
                  }}
                />
                <button
                  type="submit"
                  style={{
                    background: '#e02929',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '6px',
                    padding: '9px 20px',
                    fontWeight: 600,
                    fontSize: '14px',
                    cursor: 'pointer',
                    whiteSpace: 'nowrap',
                    flexShrink: 0,
                  }}
                >
                  Scan →
                </button>
              </div>

              {error && (
                <p style={{ color: '#c00', fontSize: '13px', marginTop: '7px', paddingLeft: '2px' }}>
                  ⚠ {error}
                </p>
              )}
            </form>

            {/* Quick examples */}
            <div style={{ marginTop: '14px', display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '12px', color: '#999' }}>Try:</span>
              {SAMPLES.map(s => (
                <button
                  key={s}
                  onClick={() => setUrl('https://' + s)}
                  style={{ background: '#fff', border: '1px solid #ddd', borderRadius: '4px', padding: '2px 10px', fontSize: '12px', color: '#555', cursor: 'pointer', fontFamily: "'Space Mono', monospace" }}
                >
                  {s}
                </button>
              ))}
            </div>

            {/* Works with row */}
            <div style={{ marginTop: '10px', display: 'flex', gap: '5px', flexWrap: 'wrap', alignItems: 'center' }}>
              <span style={{ fontSize: '12px', color: '#bbb' }}>Works with:</span>
              {['.com','.in','.dev','.me','.io','.co.uk','.gov','.org','.net','.app','.us','+ more'].map(t => (
                <span key={t} style={{ fontSize: '11px', color: '#aaa', background: '#efefef', borderRadius: '3px', padding: '1px 6px', fontFamily: "'Space Mono', monospace" }}>{t}</span>
              ))}
            </div>

            {/* Divider */}
            <div style={{ height: '1px', background: '#e5e5e5', margin: '28px 0' }} />

            {/* What it checks */}
            <div>
              <p style={{ fontSize: '13px', color: '#888', marginBottom: '12px', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>What gets checked</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {CHECKS_DATA.map((card, idx) => (
                  <FlipCard
                    key={card.label}
                    icon={card.icon}
                    label={card.label}
                    description={card.description}
                    disaster={card.disaster}
                    delayIndex={idx}
                  />
                ))}
              </div>
            </div>

            {/* Disclaimer */}
            <div style={{ marginTop: '24px', padding: '10px 14px', background: '#fff8f8', border: '1px solid #ffd5d5', borderRadius: '5px', fontSize: '12px', color: '#b00', lineHeight: 1.5 }}>
              <strong>Heads up:</strong> Only scan websites you own or have permission to test. Unauthorized scanning may be illegal.
            </div>
          </div>
        )}

        {/* About Tab View */}
        {activeTab === 'about' && (
          <div style={{ animation: 'slideIn 0.2s ease forwards', display: 'flex', flexDirection: 'column', gap: '20px' }}>
            
            {/* Chill Poster */}
            <div style={{ border: '2px solid #222', borderRadius: '8px', overflow: 'hidden', background: '#fff', boxShadow: '4px 4px 0px #222' }}>
              <img
                src="/shieldscan_chill_poster.png"
                alt="ShieldScan Chill Poster"
                style={{ width: '100%', height: 'auto', display: 'block' }}
              />
              <div style={{ padding: '10px', background: '#fff', borderTop: '2px solid #222', fontSize: '11px', color: '#666', fontStyle: 'italic', textAlign: 'center', fontFamily: "'Space Mono', monospace" }}>
                "Securing the web, one chill scan at a time."
              </div>
            </div>

            {/* What is ShieldScan */}
            <div style={{ background: '#fff', border: '1px solid #ddd', borderRadius: '6px', padding: '18px' }}>
              <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#e02929', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '-0.01em' }}>
                What is ShieldScan?
              </h2>
              <p style={{ fontSize: '14px', color: '#333', lineHeight: 1.6 }}>
                ShieldScan is a simple and free security auditor tool built for developers, webmasters, and team leads to test their server setup. It runs external checks to see if standard security configuration practices are active.
              </p>
              <p style={{ fontSize: '14px', color: '#333', lineHeight: 1.6, marginTop: '8px' }}>
                No database, no user accounts, and no complex setups. Just paste your website address and see what configuration issues you might have.
              </p>
            </div>

            {/* What you can get */}
            <div style={{ background: '#fff', border: '1px solid #ddd', borderRadius: '6px', padding: '18px' }}>
              <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#111', marginBottom: '10px', textTransform: 'uppercase', letterSpacing: '-0.01em' }}>
                What you can get by using this website
              </h2>
              <ul style={{ paddingLeft: '20px', margin: 0, display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <li style={{ fontSize: '13px', color: '#333', lineHeight: 1.5 }}>
                  <strong>Security Score (0-100):</strong> An overall rating that shows how robust your current server security headers and TLS configuration are.
                </li>
                <li style={{ fontSize: '13px', color: '#333', lineHeight: 1.5 }}>
                  <strong>25 Core Checks:</strong> Scans checking for secure cookies, open CORS paths, exposed files (.git, .env, etc.), SSL protocols, HSTS, clickjacking, and rate limit protections.
                </li>
                <li style={{ fontSize: '13px', color: '#333', lineHeight: 1.5 }}>
                  <strong>Plain English Explanations:</strong> Click "Explain this to me" on any fail to understand the risk, how an attacker could exploit it, and copy-pasteable fix steps.
                </li>
                <li style={{ fontSize: '13px', color: '#333', lineHeight: 1.5 }}>
                  <strong>Zero Footprint:</strong> Completely stateless audit. We run external checks and stream the answers back to you, without storing your data.
                </li>
              </ul>
            </div>

            {/* How it works */}
            <div style={{ background: '#fff', border: '1px solid #ddd', borderRadius: '6px', padding: '18px' }}>
              <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#111', marginBottom: '12px', textTransform: 'uppercase', letterSpacing: '-0.01em' }}>
                How this website works
              </h2>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>
                  <span style={{ background: '#e02929', color: '#fff', width: '20px', height: '20px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold', fontSize: '11px', flexShrink: 0, fontFamily: "'Space Mono', monospace" }}>1</span>
                  <div>
                    <h4 style={{ fontSize: '13px', fontWeight: 700, margin: 0 }}>Input your website URL</h4>
                    <p style={{ fontSize: '12px', color: '#666', marginTop: '2px' }}>Provide any public domain name (e.g., example.in, startup.dev, test.me).</p>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>
                  <span style={{ background: '#e02929', color: '#fff', width: '20px', height: '20px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold', fontSize: '11px', flexShrink: 0, fontFamily: "'Space Mono', monospace" }}>2</span>
                  <div>
                    <h4 style={{ fontSize: '13px', fontWeight: 700, margin: 0 }}>Automated External Checks</h4>
                    <p style={{ fontSize: '12px', color: '#666', marginTop: '2px' }}>The scanner triggers server checks, checks SSL handshakes, probes common headers, checks for exposed files, and validates DNS records.</p>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>
                  <span style={{ background: '#e02929', color: '#fff', width: '20px', height: '20px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold', fontSize: '11px', flexShrink: 0, fontFamily: "'Space Mono', monospace" }}>3</span>
                  <div>
                    <h4 style={{ fontSize: '13px', fontWeight: 700, margin: 0 }}>Live-streamed results and score</h4>
                    <p style={{ fontSize: '12px', color: '#666', marginTop: '2px' }}>Each check updates on your screen in real time. Once finished, you get an overall grade and direct tips to secure your site.</p>
                  </div>
                </div>
              </div>
            </div>

          </div>
        )}

        {/* Footer Credit */}
        <div style={{ marginTop: '40px', textAlign: 'center', padding: '20px 0 10px 0', borderTop: '1px solid #e5e5e5' }}>
          <p style={{ fontSize: '12px', color: '#888', fontFamily: "'Space Mono', monospace" }}>
            made by <span style={{ color: '#e02929', fontWeight: 700 }}>nagarjuna's team</span>
          </p>
        </div>

      </div>
    </div>
  );
}

