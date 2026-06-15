import React, { useState } from 'react';
import FlipCard from '../components/FlipCard';

const API_URL = import.meta.env.VITE_API_URL || '';
const SAMPLES = ['github.com', 'wikipedia.org', 'bbc.co.uk', 'gov.in'];

const CHECKS_DATA = [
  { icon: '🔒', label: 'HTTPS & SSL/TLS', description: 'Verifies SSL certificates, HTTPS enforcement, and encryption strength.', disaster: 'Hackers on public Wi-Fi can easily hijack sessions and steal passwords in plain text!' },
  { icon: '📋', label: 'Security Headers', description: 'Checks CSP, HSTS, X-Frame-Options, and other security headers.', disaster: 'Missing headers expose users to clickjacking and malicious script injections!' },
  { icon: '🍪', label: 'Cookie Security', description: 'Analyzes cookie flags such as Secure, HttpOnly, and SameSite.', disaster: 'Insecure cookies let attackers steal login sessions via cross-site scripts (XSS)!' },
  { icon: '🌐', label: 'CORS & API risks', description: 'Inspects CORS origins, allowed HTTP methods, and API exposure.', disaster: 'Permissive CORS policies let malicious sites steal your private database data!' },
  { icon: '📁', label: 'Exposed Files', description: 'Probes for public access to sensitive files like .env, config, and .git.', disaster: 'Exposing .env credentials gives attackers full database and server control!' },
  { icon: '🌍', label: 'DNS Records', description: 'Verifies SPF, DKIM, DMARC, and checks for subdomain takeover risks.', disaster: 'Weak DNS settings let scammers spoof your emails to phish your clients!' },
  { icon: '⚡', label: 'Rate Limiting', description: 'Tests endpoint vulnerability to brute-force and Denial-of-Service attacks.', disaster: 'No rate limits allow bots to spam forms, crash servers, and inflate costs!' },
  { icon: '🔍', label: '25 checks total', description: 'A complete non-intrusive scan covering server disclosures and DNS flaws.', disaster: 'Ignoring security checks leaves quiet backdoors open for massive data breaches!' }
];

const STATS = [
  { icon: '🔍', value: '25', label: 'security checks' },
  { icon: '⚡', value: '~60s', label: 'scan time' },
  { icon: '🆓', value: '100%', label: 'free forever' },
  { icon: '🔒', value: 'Zero', label: 'data stored' },
];

const TESTIMONIALS = [
  { name: 'Ravi K.', role: 'Full-stack Developer', text: 'Found 3 critical issues on my startup\'s site in under a minute. Fixed all of them the same day.', avatar: 'RK' },
  { name: 'Priya M.', role: 'DevOps Engineer', text: 'The plain-English explanations are brilliant. I shared the report with my non-technical CEO and he actually understood it.', avatar: 'PM' },
  { name: 'Alex T.', role: 'Freelance Web Dev', text: 'I run this on every client site before handoff. It\'s become part of my standard checklist.', avatar: 'AT' },
];

export default function Landing({ onStart, dark, onToggleDark, onNavigate, onContactClick }) {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [focused, setFocused] = useState(false);
  const [activeTab, setActiveTab] = useState('scanner');

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    let input = url.trim().replace(/\s+/g, '');
    if (!input) { setError('Enter a website URL first'); return; }
    if (input.length > 2048) { setError('URL is too long (maximum 2048 characters)'); return; }
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

  const tab = (id, label) => (
    <button
      onClick={() => setActiveTab(id)}
      className="interactive-element"
      style={{
        background: activeTab === id ? 'var(--red)' : 'transparent',
        color: activeTab === id ? '#fff' : 'var(--text-muted)',
        border: 'none',
        borderRadius: '6px',
        padding: '7px 16px',
        fontSize: '12px',
        fontWeight: 700,
        cursor: 'pointer',
        fontFamily: "'Space Mono', monospace",
        letterSpacing: '0.03em',
      }}
    >{label}</button>
  );

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>

      <nav style={{
        background: 'var(--nav-bg)',
        padding: '0 24px',
        height: '52px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'sticky',
        top: 0,
        zIndex: 50,
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <img src="/logo.png" alt="ShieldScan" style={{ height: '28px', width: 'auto', background: '#ffffff', padding: '2px 6px', borderRadius: '4px' }} />
          <span style={{ background: 'var(--red)', color: '#fff', fontSize: '9px', fontWeight: 700, padding: '1px 6px', borderRadius: '3px', letterSpacing: '0.05em', fontFamily: "'Space Mono', monospace" }}>FREE</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className="mobile-hide" style={{ color: 'rgba(255,255,255,0.4)', fontSize: '12px', fontFamily: "'Space Mono', monospace" }}>No login • No data stored</span>
          <button
            onClick={onContactClick}
            className="interactive-element"
            style={{
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.15)',
              borderRadius: '4px',
              color: 'rgba(255,255,255,0.85)',
              padding: '4px 10px',
              fontSize: '11px',
              fontWeight: 700,
              fontFamily: "'Space Mono', monospace",
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              letterSpacing: '0.02em'
            }}
            onMouseEnter={(e) => {
              e.target.style.borderColor = 'var(--red)';
              e.target.style.color = '#ffffff';
            }}
            onMouseLeave={(e) => {
              e.target.style.borderColor = 'rgba(255,255,255,0.15)';
              e.target.style.color = 'rgba(255,255,255,0.85)';
            }}
          >
            CONTACT
          </button>
          <button
            className="dark-toggle"
            onClick={onToggleDark}
            title={dark ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-label="Toggle dark mode"
          />
        </div>
      </nav>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '48px 20px 60px', position: 'relative', zIndex: 2 }}>
        <div style={{ width: '100%', maxWidth: '600px' }}>

          <div style={{ animation: 'fadeUp 0.6s cubic-bezier(0.16,1,0.3,1) forwards', textAlign: 'center', marginBottom: '32px' }}>
            <div style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: '20px',
              padding: '4px 12px',
              marginBottom: '20px',
              fontSize: '11px',
              color: 'var(--red)',
              fontWeight: 700,
              fontFamily: "'Space Mono', monospace",
              letterSpacing: '0.04em',
              boxShadow: 'var(--shadow-sm)',
            }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--red)', display: 'inline-block', animation: 'pulseRed 2s ease infinite' }} />
              FREE SECURITY SCANNER
            </div>

            <h1 style={{
              fontSize: 'clamp(28px, 7vw, 44px)',
              fontWeight: 900,
              color: 'var(--text-primary)',
              lineHeight: 1.15,
              letterSpacing: '-0.03em',
              marginBottom: '14px',
              fontFamily: "'Outfit', sans-serif",
            }}>
              Is your website
              <span style={{ color: 'var(--red)', display: 'block' }}>actually secure?</span>
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: '16px', lineHeight: 1.65, maxWidth: '480px', margin: '0 auto' }}>
              Run 32 professional security checks on any domain — .com, .in, .dev, .io, anything. Get a plain-English report in ~60 seconds.
            </p>

            <div className="trust-bar">
              {STATS.map(s => (
                <div key={s.label} className="stat-badge">
                  <span>{s.icon}</span>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 800 }}>{s.label === 'security checks' ? '32' : s.value}</span>
                  <span style={{ color: 'var(--text-muted)', fontWeight: 400, fontSize: '11px' }}>{s.label}</span>
                </div>
              ))}
            </div>
          </div>

          <div style={{ animation: 'fadeUp 0.7s 0.1s cubic-bezier(0.16,1,0.3,1) both' }}>
            <div style={{
              display: 'flex',
              gap: '4px',
              background: 'var(--bg-card-2)',
              borderRadius: '10px',
              padding: '4px',
              marginBottom: '20px',
              border: '1px solid var(--border)',
            }}>
              {tab('scanner', '[ AUDIT SCANNER ]')}
              {tab('about', '[ ABOUT & INFO ]')}
            </div>
          </div>

          {activeTab === 'scanner' && (
            <div style={{ animation: 'slideIn 0.25s cubic-bezier(0.16,1,0.3,1) forwards', display: 'flex', flexDirection: 'column', gap: '20px' }}>

              <form onSubmit={handleSubmit}>
                <div style={{
                  display: 'flex',
                  gap: '8px',
                  background: 'var(--input-bg)',
                  border: `2px solid ${focused ? 'var(--red)' : 'var(--border)'}`,
                  borderRadius: '10px',
                  padding: '6px 6px 6px 16px',
                  alignItems: 'center',
                  transition: 'all var(--transition)',
                  boxShadow: focused ? '0 0 0 4px var(--red-glow)' : 'var(--shadow-sm)',
                }}>
                  <span style={{ fontSize: '16px', flexShrink: 0 }}>🔗</span>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => { setUrl(e.target.value); setError(''); }}
                    onFocus={() => setFocused(true)}
                    onBlur={() => setFocused(false)}
                    placeholder="yoursite.com  ·  example.in  ·  app.dev"
                    autoComplete="off"
                    autoCorrect="off"
                    spellCheck={false}
                    style={{
                      flex: 1,
                      border: 'none',
                      outline: 'none',
                      background: 'transparent',
                      fontSize: '15px',
                      color: 'var(--text-primary)',
                      fontFamily: "'Space Mono', monospace",
                      minWidth: 0,
                    }}
                  />
                  <button type="submit" className="btn-primary" style={{ borderRadius: '7px', padding: '9px 22px', flexShrink: 0 }}>
                    Scan →
                  </button>
                </div>
                {error && (
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    marginTop: '8px',
                    padding: '8px 12px',
                    background: '#fff8f8',
                    border: '1px solid #fecdd3',
                    borderRadius: '6px',
                    fontSize: '13px',
                    color: '#b91c1c',
                  }}>
                    <span>⚠️</span> {error}
                  </div>
                )}
              </form>

              <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '6px' }}>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Try:</span>
                {SAMPLES.map(s => (
                  <button
                    key={s}
                    onClick={() => setUrl('https://' + s)}
                    className="interactive-element"
                    style={{
                      background: 'var(--bg-card)',
                      border: '1px solid var(--border)',
                      borderRadius: '5px',
                      padding: '3px 10px',
                      fontSize: '12px',
                      color: 'var(--text-secondary)',
                      cursor: 'pointer',
                      fontFamily: "'Space Mono', monospace",
                    }}
                  >{s}</button>
                ))}
              </div>

              <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap', alignItems: 'center', marginBottom: '28px' }}>
                <span style={{ fontSize: '11px', color: 'var(--text-faint)' }}>Works with:</span>
                {['.com', '.in', '.dev', '.me', '.io', '.co.uk', '.gov', '.org', '.net', '.app', '.us', '+ more'].map(t => (
                  <span key={t} style={{
                    fontSize: '11px',
                    color: 'var(--text-muted)',
                    background: 'var(--bg-card-2)',
                    borderRadius: '4px',
                    padding: '1px 6px',
                    fontFamily: "'Space Mono', monospace",
                    border: '1px solid var(--border)',
                  }}>{t}</span>
                ))}
              </div>

              <div style={{ height: '1px', background: 'var(--border)', marginBottom: '20px' }} />

              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <p style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                    What gets checked
                  </p>
                  <span style={{ fontSize: '11px', color: 'var(--text-faint)', fontFamily: "'Space Mono', monospace" }}>hover to flip</span>
                </div>
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

              <div style={{
                background: 'rgba(217, 119, 6, 0.05)',
                border: '1px solid var(--border)',
                borderLeft: '3px solid #d97706',
                borderRadius: '6px',
                padding: '10px 14px',
                fontSize: '12px',
                color: 'var(--text-secondary)',
                lineHeight: 1.5,
              }}>
                <strong style={{ color: '#d97706' }}>⚠ Responsible use:</strong> Only scan websites you own or have explicit permission to test. Unauthorized scanning may be illegal.
              </div>
            </div>
          )}

          {activeTab === 'about' && (
            <div style={{ animation: 'slideIn 0.25s cubic-bezier(0.16,1,0.3,1) forwards', display: 'flex', flexDirection: 'column', gap: '16px' }}>

              <div style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                padding: '24px',
                background: 'var(--bg-card)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                boxShadow: 'var(--shadow-sm)',
              }}>
                <img
                  src="/logo.png"
                  alt="ShieldScan Logo"
                  style={{ height: '72px', width: 'auto', background: '#ffffff', padding: '6px 18px', borderRadius: '6px', border: '1px solid var(--border)' }}
                />
              </div>

              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', padding: '20px', boxShadow: 'var(--shadow-sm)' }}>
                <h2 style={{ fontSize: '15px', fontWeight: 800, color: 'var(--red)', marginBottom: '10px', textTransform: 'uppercase', letterSpacing: '0.04em', fontFamily: "'Outfit', sans-serif" }}>
                  What is ShieldScan?
                </h2>
                <p style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                  ShieldScan is a free, stateless security auditor for web developers, webmasters, and team leads. It runs 32 non-intrusive external checks on any public domain — no login, no tracking, no data stored.
                </p>
                <p style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: 1.7, marginTop: '8px' }}>
                  Results are streamed live to your browser and explained in plain English, so you know exactly what to fix and why it matters.
                </p>
              </div>

              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', padding: '20px', boxShadow: 'var(--shadow-sm)' }}>
                <h2 style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', marginBottom: '14px', textTransform: 'uppercase', letterSpacing: '0.04em', fontFamily: "'Outfit', sans-serif" }}>
                  What you get
                </h2>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {[
                    { title: 'Security Score (0–100)', desc: 'An overall letter grade that shows how robust your server security configuration is.' },
                    { title: '32 Core Checks', desc: 'Cookies, CORS, exposed files (.git, .env), SSL, HSTS, clickjacking, rate limiting, DNS, and more.' },
                    { title: 'Plain English Explanations', desc: 'Click "Explain this to me" on any issue to see the risk, a real-world example, and fix steps.' },
                    { title: 'Zero Footprint', desc: 'No accounts, no database, no logs. We run checks and stream results directly to you.' },
                  ].map(item => (
                    <div key={item.title} style={{ display: 'flex', gap: '12px', alignItems: 'flex-start', padding: '12px 14px', background: 'var(--bg-card-2)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                      <div>
                        <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '2px' }}>{item.title}</div>
                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{item.desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', padding: '20px', boxShadow: 'var(--shadow-sm)' }}>
                <h2 style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', marginBottom: '14px', textTransform: 'uppercase', letterSpacing: '0.04em', fontFamily: "'Outfit', sans-serif" }}>
                  Recommended Usage Guidelines
                </h2>
                <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                  To get the most out of ShieldScan audits, we recommend integrating these practices into your deployment workflow:
                </p>
                <ul style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6, marginTop: '8px', paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <li>
                    <strong>Pre-Deployment Audits:</strong> Run a scan on your staging or pre-production environment (provided it is publicly resolvable) to catch configuration leaks or CORS issues before they go live.
                  </li>
                  <li>
                    <strong>Regular Audits:</strong> Certificate details and DNS headers can drift or expire. Schedule a scan once a month or after major server infrastructure upgrades.
                  </li>
                  <li>
                    <strong>Remediation Strategy:</strong> Focus first on <em>Critical</em> and <em>High</em> severity findings, which represent immediate vectors for attack or data exposure, before styling security parameters like secondary headers.
                  </li>
                  <li>
                    <strong>Third-Party Vendor Checks:</strong> Validate SaaS providers, API gateways, and external partner endpoints that handle your user data to verify their transport security compliance.
                  </li>
                </ul>
              </div>

              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', padding: '20px', boxShadow: 'var(--shadow-sm)' }}>
                <h2 style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', marginBottom: '16px', textTransform: 'uppercase', letterSpacing: '0.04em', fontFamily: "'Outfit', sans-serif" }}>
                  How it works
                </h2>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
                  {[
                    { n: 1, title: 'Enter any URL', desc: 'Any public domain — .com, .in, .dev, .me, .co.uk, .io — anything with a dot.' },
                    { n: 2, title: 'Automated external checks', desc: 'Our scanner runs 32 real HTTP/TLS/DNS checks from outside your server, just like a real attacker would.' },
                    { n: 3, title: 'Live-streamed results', desc: 'Watch each check complete in real time. When finished, get an overall grade and tailored fix instructions.' },
                  ].map((step, i) => (
                    <div key={step.n} style={{ display: 'flex', gap: '14px', alignItems: 'flex-start', position: 'relative', paddingBottom: i < 2 ? '20px' : 0 }}>
                      {i < 2 && <div style={{ position: 'absolute', left: '14px', top: '28px', width: '2px', height: 'calc(100% - 10px)', background: 'var(--border)' }} />}
                      <div style={{
                        width: '28px', height: '28px',
                        borderRadius: '50%',
                        background: 'var(--red)',
                        color: '#fff',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontWeight: 800, fontSize: '12px',
                        flexShrink: 0,
                        fontFamily: "'Space Mono', monospace",
                        position: 'relative', zIndex: 1,
                        boxShadow: '0 0 0 4px var(--bg-card)',
                      }}>{step.n}</div>
                      <div style={{ paddingTop: '4px' }}>
                        <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '2px' }}>{step.title}</div>
                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{step.desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', padding: '20px', boxShadow: 'var(--shadow-sm)' }}>
                <h2 style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', marginBottom: '16px', textTransform: 'uppercase', letterSpacing: '0.04em', fontFamily: "'Outfit', sans-serif" }}>
                  What developers say
                </h2>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {TESTIMONIALS.map(t => (
                    <div key={t.name} style={{ display: 'flex', gap: '12px', alignItems: 'flex-start', padding: '14px', background: 'var(--bg-card-2)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                      <div style={{
                        width: '36px', height: '36px',
                        borderRadius: '50%',
                        background: 'var(--red)',
                        color: '#fff',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontWeight: 800, fontSize: '12px',
                        flexShrink: 0,
                        fontFamily: "'Space Mono', monospace",
                      }}>{t.avatar}</div>
                      <div>
                        <div style={{ display: 'flex', gap: '8px', alignItems: 'baseline', marginBottom: '5px' }}>
                          <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>{t.name}</span>
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{t.role}</span>
                        </div>
                        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.55, fontStyle: 'italic' }}>"{t.text}"</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          )}

        </div>
      </div>

      <footer style={{
        borderTop: '1px solid var(--border)',
        padding: '16px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px',
        position: 'relative',
        zIndex: 2,
      }}>
        <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
          <button onClick={() => onNavigate('privacy')} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '11px', cursor: 'pointer', fontFamily: "'Space Mono', monospace", textDecoration: 'underline', padding: 0 }}>Privacy Policy</button>
          <button onClick={() => onNavigate('terms')} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '11px', cursor: 'pointer', fontFamily: "'Space Mono', monospace", textDecoration: 'underline', padding: 0 }}>Terms of Service</button>
          <a href={`${API_URL}/security.txt`} target="_blank" rel="noreferrer" style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: "'Space Mono', monospace" }}>security.txt</a>
          <a href={`${API_URL}/robots.txt`} target="_blank" rel="noreferrer" style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: "'Space Mono', monospace" }}>robots.txt</a>
        </div>
        <p style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: "'Space Mono', monospace" }}>
          made by <span style={{ color: 'var(--red)', fontWeight: 700 }}>nagarjuna's team</span>
        </p>
      </footer>

    </div>
  );
}