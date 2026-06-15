import React, { useEffect, useRef, useState } from 'react';

const ALL_CHECKS = [
  { id: 'https_enforcement',    name: 'HTTPS Enforcement',         category: 'Transport' },
  { id: 'ssl_certificate',      name: 'SSL/TLS Certificate',        category: 'Transport' },
  { id: 'hsts',                 name: 'HSTS Header',                category: 'Transport' },
  { id: 'tls_version',          name: 'TLS Version',                category: 'Transport' },
  { id: 'csp',                  name: 'Content Security Policy',    category: 'Headers' },
  { id: 'clickjacking',         name: 'Clickjacking Protection',    category: 'Headers' },
  { id: 'content_type_options', name: 'Content-Type Sniffing',      category: 'Headers' },
  { id: 'referrer_policy',      name: 'Referrer Policy',            category: 'Headers' },
  { id: 'permissions_policy',   name: 'Permissions Policy',         category: 'Headers' },
  { id: 'xss_protection',       name: 'XSS Protection',             category: 'Headers' },
  { id: 'cors_misconfiguration',name: 'CORS Policy',                category: 'CORS & API' },
  { id: 'api_enumeration',      name: 'API Enumeration',            category: 'CORS & API' },
  { id: 'idor',                 name: 'IDOR Detection',             category: 'CORS & API' },
  { id: 'http_methods',         name: 'HTTP Methods',               category: 'CORS & API' },
  { id: 'cookie_security',      name: 'Cookie Flags',               category: 'Cookies' },
  { id: 'session_in_url',       name: 'Session in URL',             category: 'Cookies' },
  { id: 'sensitive_files',      name: 'Sensitive Files',            category: 'Exposure' },
  { id: 'server_disclosure',    name: 'Server Info Leak',           category: 'Exposure' },
  { id: 'directory_listing',    name: 'Directory Listing',          category: 'Exposure' },
  { id: 'stack_trace',          name: 'Error Message Leak',         category: 'Exposure' },
  { id: 'dns_security',         name: 'DNS Records (SPF/DMARC)',    category: 'DNS' },
  { id: 'subdomain_takeover',   name: 'Subdomain Takeover',         category: 'DNS' },
  { id: 'rate_limiting',        name: 'Rate Limiting',              category: 'Abuse' },
  { id: 'open_redirect',        name: 'Open Redirect',              category: 'Abuse' },
  { id: 'security_txt',         name: 'Security.txt',               category: 'Abuse' },
];

const CATEGORIES = ['Transport','Headers','CORS & API','Cookies','Exposure','DNS','Abuse'];

const CAT_ICONS = {
  Transport: '🔒', Headers: '📋', 'CORS & API': '🌐',
  Cookies: '🍪', Exposure: '📁', DNS: '🌍', Abuse: '⚡',
};

function StatusIcon({ s }) {
  if (s === 'running') return (
    <span style={{
      display: 'inline-block', width: 12, height: 12,
      border: '2px solid var(--red)', borderTopColor: 'transparent',
      borderRadius: '50%', animation: 'spin 0.7s linear infinite',
    }} />
  );
  if (s === 'pass')  return <span style={{ color: '#16a34a', fontWeight: 700, fontSize: '14px' }}>✓</span>;
  if (s === 'fail')  return <span style={{ color: 'var(--red)', fontWeight: 700, fontSize: '14px' }}>✗</span>;
  if (s === 'error') return <span style={{ color: 'var(--text-faint)' }}>?</span>;
  return <span className="skeleton" style={{ display: 'inline-block', width: 10, height: 10, borderRadius: '50%' }} />;
}

export default function Scanning({ url, onComplete, onCancel, dark, onToggleDark, onContactClick }) {
  const [statuses, setStatuses] = useState({});
  const [done, setDone]         = useState(0);
  const [elapsed, setElapsed]   = useState(0);
  const [err, setErr]           = useState('');
  const results = useRef([]);
  const t0 = useRef(Date.now());

  useEffect(() => {
    const tick = setInterval(() => setElapsed(Math.floor((Date.now()-t0.current)/1000)), 1000);
    const init = {};
    ALL_CHECKS.forEach(c => { init[c.id] = 'pending'; });
    setStatuses(init);

    const ctrl = new AbortController();

    const runAnim = setInterval(() => {
      setStatuses(prev => {
        const next = { ...prev };
        ALL_CHECKS.filter(c => prev[c.id] === 'pending').slice(0,2).forEach(c => { next[c.id] = 'running'; });
        return next;
      });
    }, 1100);

    (async () => {
      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
          signal: ctrl.signal,
        });
        if (!res.ok) { const d = await res.json(); setErr(d.error || 'Scan failed'); clearInterval(tick); return; }

        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = '';
        while (true) {
          const { done: d, value } = await reader.read();
          if (d) break;
          buf += dec.decode(value, { stream: true });
          const lines = buf.split('\n'); buf = lines.pop();
          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            try {
              const data = JSON.parse(line.slice(6));
              if (data.type === 'check') {
                const st = data.status === 'PASS' ? 'pass' : data.status === 'ERROR' ? 'error' : 'fail';
                setStatuses(p => ({ ...p, [data.checkId]: st }));
                results.current.push(data);
                setDone(n => n+1);
              } else if (data.type === 'complete') {
                clearInterval(tick);
                onComplete(results.current, data);
              }
            } catch {}
          }
        }
      } catch (e) {
        if (e.name !== 'AbortError') { setErr('Cannot reach backend. Is it running on port 3001?'); clearInterval(tick); }
      }
    })();

    return () => { ctrl.abort(); clearInterval(tick); clearInterval(runAnim); };
  }, []);

  const pct = Math.round((done/25)*100);

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
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
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
          <button
            onClick={onCancel}
            className="btn-ghost"
            style={{ color: 'rgba(255,255,255,0.7)', borderColor: 'rgba(255,255,255,0.15)', fontSize: '12px', padding: '5px 14px' }}
          >
            ✕ Cancel
          </button>
        </div>
      </nav>

      <div style={{ flex: 1, display: 'flex', alignItems: 'flex-start', justifyContent: 'center', padding: '32px 16px 60px', position: 'relative', zIndex: 2 }}>
        <div style={{ width: '100%', maxWidth: '660px' }}>

          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '20px 22px', marginBottom: '14px', boxShadow: 'var(--shadow-md)' }}>
            <div style={{ fontFamily: "'Space Mono', monospace", fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px', wordBreak: 'break-all' }}>
              <span style={{ color: 'var(--red)' }}>$ </span>
              scanning <strong style={{ color: 'var(--text-primary)' }}>{url}</strong>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px', fontFamily: "'Space Mono', monospace" }}>
              <span>{done} / 25 checks done</span>
              <span>{elapsed}s elapsed</span>
            </div>

            <div style={{ height: '7px', background: 'var(--border)', borderRadius: '4px', overflow: 'hidden', marginBottom: '6px' }}>
              <div
                className="shimmer-bar"
                style={{ height: '100%', width: `${pct}%`, borderRadius: '4px', transition: 'width 0.5s cubic-bezier(0.16,1,0.3,1)' }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-faint)', fontFamily: "'Space Mono', monospace" }}>
                {pct < 100 ? 'Running checks...' : 'Processing results...'}
              </span>
              <span style={{ fontSize: '13px', color: 'var(--red)', fontWeight: 700, fontFamily: "'Space Mono', monospace" }}>{pct}%</span>
            </div>

            {err && (
              <div style={{ marginTop: '14px', padding: '12px 14px', background: '#fff0f0', border: '1px solid #fdd', borderLeft: '3px solid var(--red)', borderRadius: '6px', fontSize: '13px', color: '#c00' }}>
                ⚠ {err}
              </div>
            )}
          </div>

          {CATEGORIES.map(cat => {
            const checks = ALL_CHECKS.filter(c => c.category === cat);
            const catStatuses = checks.map(c => statuses[c.id] || 'pending');
            const catDone = catStatuses.filter(s => s === 'pass' || s === 'fail' || s === 'error').length;
            const catRunning = catStatuses.some(s => s === 'running');
            return (
              <div
                key={cat}
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  padding: '14px 18px',
                  marginBottom: '8px',
                  boxShadow: 'var(--shadow-sm)',
                  transition: 'border-color var(--transition)',
                  borderLeft: catRunning ? '3px solid var(--red)' : '3px solid var(--border)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                  <span style={{ fontSize: '14px' }}>{CAT_ICONS[cat]}</span>
                  <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em', flex: 1 }}>{cat}</span>
                  <span style={{ fontSize: '11px', color: 'var(--text-faint)', fontFamily: "'Space Mono', monospace" }}>{catDone}/{checks.length}</span>
                </div>
                <div>
                  {checks.map(c => (
                    <div
                      key={c.id}
                      className="row-stagger"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px',
                        padding: '5px 0',
                        borderBottom: '1px solid var(--border)',
                        animationDelay: `${ALL_CHECKS.findIndex(x => x.id === c.id) * 30}ms`,
                      }}
                    >
                      <span style={{ width: '16px', textAlign: 'center', flexShrink: 0 }}>
                        <StatusIcon s={statuses[c.id] || 'pending'} />
                      </span>
                      <span style={{
                        fontSize: '13px',
                        fontFamily: "'Space Mono', monospace",
                        color: statuses[c.id] === 'running' ? 'var(--red)'
                          : statuses[c.id] === 'pass' ? 'var(--text-secondary)'
                          : statuses[c.id] === 'fail' ? 'var(--text-primary)'
                          : 'var(--text-faint)',
                        flex: 1,
                        transition: 'color 0.3s ease',
                      }}>
                        {c.name}
                      </span>
                      {statuses[c.id] === 'running' && (
                        <span style={{ fontSize: '11px', color: 'var(--red)', fontFamily: "'Space Mono', monospace", opacity: 0.8 }}>checking…</span>
                      )}
                      {statuses[c.id] === 'pending' && (
                        <span className="skeleton" style={{ width: '55px', height: '8px', borderRadius: '4px' }} />
                      )}
                      {statuses[c.id] === 'fail' && (() => {
                        const r = results.current.find(x => x.checkId === c.id);
                        if (!r) return null;
                        const colors = { CRITICAL: '#b91c1c', HIGH: '#e02929', MEDIUM: '#b45309', LOW: '#1d4ed8' };
                        const bgs = { CRITICAL: '#fee2e2', HIGH: '#fee2e2', MEDIUM: '#fef3c7', LOW: '#dbeafe' };
                        return (
                          <span style={{ fontSize: '10px', fontWeight: 700, color: colors[r.severity] || 'var(--red)', background: bgs[r.severity] || '#fee2e2', padding: '1px 6px', borderRadius: '3px', fontFamily: "'Space Mono', monospace" }}>
                            {r.severity}
                          </span>
                        );
                      })()}
                    </div>
                  ))}
                </div>
              </div>
            );
          })}

          <p style={{ textAlign: 'center', fontSize: '12px', color: 'var(--text-faint)', marginTop: '16px', fontFamily: "'Space Mono', monospace" }}>
            🔒 Results are not stored anywhere.
          </p>
        </div>
      </div>
    </div>
  );
}
