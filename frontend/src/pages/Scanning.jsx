import React, { useEffect, useRef, useState } from 'react';

const ALL_CHECKS = [
  { id: 'https_enforcement',   name: 'HTTPS Enforcement',          category: 'Transport' },
  { id: 'ssl_certificate',     name: 'SSL/TLS Certificate',         category: 'Transport' },
  { id: 'hsts',                name: 'HSTS Header',                 category: 'Transport' },
  { id: 'tls_version',         name: 'TLS Version',                 category: 'Transport' },
  { id: 'csp',                 name: 'Content Security Policy',     category: 'Headers' },
  { id: 'clickjacking',        name: 'Clickjacking Protection',     category: 'Headers' },
  { id: 'content_type_options',name: 'Content-Type Sniffing',       category: 'Headers' },
  { id: 'referrer_policy',     name: 'Referrer Policy',             category: 'Headers' },
  { id: 'permissions_policy',  name: 'Permissions Policy',          category: 'Headers' },
  { id: 'xss_protection',      name: 'XSS Protection',              category: 'Headers' },
  { id: 'cors_misconfiguration',name: 'CORS Policy',                category: 'CORS & API' },
  { id: 'api_enumeration',     name: 'API Enumeration',             category: 'CORS & API' },
  { id: 'idor',                name: 'IDOR Detection',              category: 'CORS & API' },
  { id: 'http_methods',        name: 'HTTP Methods',                category: 'CORS & API' },
  { id: 'cookie_security',     name: 'Cookie Flags',                category: 'Cookies' },
  { id: 'session_in_url',      name: 'Session in URL',              category: 'Cookies' },
  { id: 'sensitive_files',     name: 'Sensitive Files',             category: 'Exposure' },
  { id: 'server_disclosure',   name: 'Server Info Leak',            category: 'Exposure' },
  { id: 'directory_listing',   name: 'Directory Listing',           category: 'Exposure' },
  { id: 'stack_trace',         name: 'Error Message Leak',          category: 'Exposure' },
  { id: 'dns_security',        name: 'DNS Records (SPF/DMARC)',     category: 'DNS' },
  { id: 'subdomain_takeover',  name: 'Subdomain Takeover',          category: 'DNS' },
  { id: 'rate_limiting',       name: 'Rate Limiting',               category: 'Abuse' },
  { id: 'open_redirect',       name: 'Open Redirect',               category: 'Abuse' },
  { id: 'security_txt',        name: 'Security.txt',                category: 'Abuse' },
];

const CATEGORIES = ['Transport','Headers','CORS & API','Cookies','Exposure','DNS','Abuse'];

function statusIcon(s) {
  if (s === 'running') return <span style={{ display: 'inline-block', width: 12, height: 12, border: '2px solid #e02929', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 0.7s linear infinite', verticalAlign: 'middle' }} />;
  if (s === 'pass')    return <span style={{ color: '#16a34a', fontWeight: 700 }}>✓</span>;
  if (s === 'fail')    return <span style={{ color: '#e02929', fontWeight: 700 }}>✗</span>;
  if (s === 'error')   return <span style={{ color: '#aaa' }}>?</span>;
  return <span style={{ color: '#ccc' }}>·</span>;
}

export default function Scanning({ url, onComplete, onCancel }) {
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

    // Animate "running" markers
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
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'flex-start', justifyContent: 'center', padding: '32px 16px', position: 'relative', zIndex: 2 }}>
      <div style={{ width: '100%', maxWidth: '660px' }}>

        {/* Top bar */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '16px' }}>🛡️</span>
            <span style={{ fontWeight: 700, fontSize: '15px', color: '#111' }}>ShieldScan</span>
          </div>
          <button
            onClick={onCancel}
            style={{ background: 'none', border: '1px solid #ccc', borderRadius: '5px', padding: '4px 12px', fontSize: '13px', color: '#666', cursor: 'pointer' }}
          >
            Cancel
          </button>
        </div>

        {/* Target + progress */}
        <div style={{ background: '#fff', border: '1px solid #ddd', borderRadius: '7px', padding: '18px 20px', marginBottom: '12px' }}>
          <div style={{ fontFamily: "'Space Mono', monospace", fontSize: '13px', color: '#555', marginBottom: '14px', wordBreak: 'break-all' }}>
            <span style={{ color: '#e02929' }}>$</span> scanning <strong style={{ color: '#111' }}>{url}</strong>
          </div>

          {/* Progress bar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: '#888', marginBottom: '6px', fontFamily: "'Space Mono', monospace" }}>
            <span>{done} / 25 checks done</span>
            <span>{elapsed}s elapsed</span>
          </div>
          <div style={{ height: '6px', background: '#eee', borderRadius: '4px', overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${pct}%`, background: '#e02929', borderRadius: '4px', transition: 'width 0.4s ease' }} />
          </div>
          <div style={{ fontSize: '12px', color: '#e02929', textAlign: 'right', marginTop: '4px', fontFamily: "'Space Mono', monospace" }}>{pct}%</div>

          {err && (
            <div style={{ marginTop: '12px', padding: '10px 12px', background: '#fff0f0', border: '1px solid #fdd', borderRadius: '5px', fontSize: '13px', color: '#c00' }}>
              Error: {err}
            </div>
          )}
        </div>

        {/* Check list grouped by category */}
        {CATEGORIES.map(cat => {
          const checks = ALL_CHECKS.filter(c => c.category === cat);
          return (
            <div key={cat} style={{ background: '#fff', border: '1px solid #ddd', borderRadius: '7px', padding: '14px 18px', marginBottom: '10px' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: '#999', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '10px' }}>
                {cat}
              </div>
              <div>
                {checks.map(c => (
                  <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '5px 0', borderBottom: '1px solid #f5f5f5' }}>
                    <span style={{ width: '16px', textAlign: 'center', flexShrink: 0, fontSize: '13px' }}>
                      {statusIcon(statuses[c.id] || 'pending')}
                    </span>
                    <span style={{
                      fontSize: '13px',
                      fontFamily: "'Space Mono', monospace",
                      color: statuses[c.id] === 'running' ? '#e02929' : statuses[c.id] === 'pass' ? '#555' : statuses[c.id] === 'fail' ? '#111' : '#bbb',
                      flex: 1,
                    }}>
                      {c.name}
                    </span>
                    {statuses[c.id] === 'running' && (
                      <span style={{ fontSize: '11px', color: '#e02929', fontFamily: "'Space Mono', monospace" }}>checking...</span>
                    )}
                    {statuses[c.id] === 'fail' && (() => {
                      const r = results.current.find(x => x.checkId === c.id);
                      if (!r) return null;
                      const colors = { CRITICAL: '#b91c1c', HIGH: '#e02929', MEDIUM: '#b45309', LOW: '#1d4ed8' };
                      return (
                        <span style={{ fontSize: '10px', fontWeight: 700, color: colors[r.severity] || '#e02929', background: r.severity === 'MEDIUM' ? '#fef3c7' : r.severity === 'LOW' ? '#dbeafe' : '#fee2e2', padding: '1px 6px', borderRadius: '3px', fontFamily: "'Space Mono', monospace" }}>
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

        <p style={{ textAlign: 'center', fontSize: '12px', color: '#bbb', marginTop: '12px' }}>
          Results are not stored anywhere.
        </p>
      </div>
    </div>
  );
}
