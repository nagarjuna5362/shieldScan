import React, { useEffect, useRef, useState } from 'react';
import { API_BASE } from '../config';

const ALL_CHECKS = [
  { id: 'https_enforcement',     name: 'HTTPS Enforcement',          category: 'Transport' },
  { id: 'ssl_certificate',       name: 'SSL/TLS Certificate',         category: 'Transport' },
  { id: 'ssl_chain',             name: 'SSL Certificate Chain',         category: 'Transport' },
  { id: 'hsts',                  name: 'HSTS Header',                 category: 'Transport' },
  { id: 'tls_version',           name: 'TLS Version',                   category: 'Transport' },
  { id: 'mixed_content',         name: 'Mixed Content',               category: 'Transport' },
  { id: 'csp',                   name: 'Content Security Policy',     category: 'Headers' },
  { id: 'clickjacking',          name: 'Clickjacking Protection',     category: 'Headers' },
  { id: 'content_type_options',  name: 'Content-Type Sniffing',       category: 'Headers' },
  { id: 'referrer_policy',       name: 'Referrer Policy',             category: 'Headers' },
  { id: 'permissions_policy',    name: 'Permissions Policy',          category: 'Headers' },
  { id: 'xss_protection',        name: 'XSS Protection',              category: 'Headers' },
  { id: 'cors_misconfiguration', name: 'CORS Policy',                 category: 'CORS & API' },
  { id: 'api_enumeration',       name: 'API Enumeration',             category: 'CORS & API' },
  { id: 'idor',                  name: 'IDOR Detection',              category: 'CORS & API' },
  { id: 'http_methods',          name: 'HTTP Methods',                category: 'CORS & API' },
  { id: 'email_injection',       name: 'Email Injection',             category: 'CORS & API' },
  { id: 'cookie_security',       name: 'Cookie Flags',                category: 'Cookies' },
  { id: 'session_in_url',        name: 'Session in URL',              category: 'Cookies' },
  { id: 'sensitive_files',       name: 'Sensitive Files',             category: 'Exposure' },
  { id: 'server_disclosure',     name: 'Server Info Leak',            category: 'Exposure' },
  { id: 'directory_listing',     name: 'Directory Listing',           category: 'Exposure' },
  { id: 'stack_trace',           name: 'Error Message Leak',          category: 'Exposure' },
  { id: 'dns_security',          name: 'DNS Records (SPF/DMARC)',     category: 'DNS' },
  { id: 'dkim_record',           name: 'DKIM Record',                 category: 'DNS' },
  { id: 'caa_record',            name: 'CAA Record',                  category: 'DNS' },
  { id: 'subdomain_takeover',    name: 'Subdomain Takeover',          category: 'DNS' },
  { id: 'subdomains',            name: 'Subdomain Exposure',          category: 'DNS' },
  { id: 'open_ports',            name: 'Exposed Ports',               category: 'DNS' },
  { id: 'rate_limiting',         name: 'Rate Limiting',               category: 'Abuse' },
  { id: 'open_redirect',         name: 'Open Redirect',                 category: 'Abuse' },
  { id: 'security_txt',          name: 'Security.txt',                category: 'Abuse' },
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
  const [statuses, setStatuses]     = useState({});
  const [done, setDone]             = useState(0);
  const [elapsed, setElapsed]       = useState(0);
  const [err, setErr]               = useState('');
  const [isComplete, setIsComplete] = useState(false);
  const finalElapsed = useRef(0);
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
      // #region agent log
      fetch('http://127.0.0.1:7785/ingest/2de4b017-3375-4a31-8b3b-6cef6255f665',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'59f1b2'},body:JSON.stringify({sessionId:'59f1b2',location:'Scanning.jsx:scan-start',message:'Scan initiated',data:{url,apiBase:API_BASE,expectedChecks:ALL_CHECKS.length},timestamp:Date.now(),hypothesisId:'B'})}).catch(()=>{});
      // #endregion
      try {
        const res = await fetch(`${API_BASE}/scan`, {
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
                // #region agent log
                fetch('http://127.0.0.1:7785/ingest/2de4b017-3375-4a31-8b3b-6cef6255f665',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'59f1b2'},body:JSON.stringify({sessionId:'59f1b2',location:'Scanning.jsx:scan-complete',message:'Scan SSE complete',data:{checksReceived:results.current.length,expectedChecks:ALL_CHECKS.length,score:data.score},timestamp:Date.now(),hypothesisId:'B'})}).catch(()=>{});
                // #endregion
                clearInterval(tick);
                clearInterval(runAnim);
                // Mark all remaining pending/running checks as done
                setStatuses(prev => {
                  const next = { ...prev };
                  ALL_CHECKS.forEach(c => {
                    if (next[c.id] === 'pending' || next[c.id] === 'running') {
                      next[c.id] = 'pass';
                    }
                  });
                  return next;
                });
                setDone(ALL_CHECKS.length);
                finalElapsed.current = Math.floor((Date.now() - t0.current) / 1000);
                setElapsed(finalElapsed.current);
                setIsComplete(true);
                // Wait 2.5s so user can see the scan time and results before navigating
                setTimeout(() => onComplete(results.current, data), 2500);
              }
            } catch {}
          }
        }
      } catch (e) {
        if (e.name !== 'AbortError') {
          // #region agent log
          fetch('http://127.0.0.1:7785/ingest/2de4b017-3375-4a31-8b3b-6cef6255f665',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'59f1b2'},body:JSON.stringify({sessionId:'59f1b2',location:'Scanning.jsx:scan-error',message:'Scan fetch failed',data:{error:e.message,apiBase:API_BASE},timestamp:Date.now(),hypothesisId:'E'})}).catch(()=>{});
          // #endregion
          const apiTarget = API_BASE || 'local server';
          setErr(`Cannot reach backend (${apiTarget}). Please verify it is running.`);
          clearInterval(tick);
        }
      }
    })();

    return () => { ctrl.abort(); clearInterval(tick); clearInterval(runAnim); };
  }, []);

  const pct = isComplete ? 100 : Math.round((done / ALL_CHECKS.length) * 100);

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
              <span>{done} / {ALL_CHECKS.length} checks done</span>
              <span>{elapsed}s elapsed</span>
            </div>

            <div style={{ height: '7px', background: 'var(--border)', borderRadius: '4px', overflow: 'hidden', marginBottom: '6px' }}>
              <div
                className="shimmer-bar"
                style={{
                  height: '100%',
                  width: `${pct}%`,
                  borderRadius: '4px',
                  transition: 'width 0.5s cubic-bezier(0.16,1,0.3,1)',
                  background: isComplete ? 'linear-gradient(90deg,#16a34a,#22c55e)' : undefined,
                }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontFamily: "'Space Mono', monospace",
                color: isComplete ? '#16a34a' : 'var(--text-faint)',
                fontWeight: isComplete ? 700 : 400,
              }}>
                {isComplete ? `✓ Scan complete — ${finalElapsed.current}s` : pct < 100 ? 'Running checks...' : 'Finalizing...'}
              </span>
              <span style={{ fontSize: '13px', color: isComplete ? '#16a34a' : 'var(--red)', fontWeight: 700, fontFamily: "'Space Mono', monospace",
                transition: 'color 0.4s ease' }}>{pct}%</span>
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
