import React from 'react';

export default function Privacy({ onBack, onContactClick }) {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <nav style={{
        background: 'var(--nav-bg)',
        padding: '0 24px',
        height: '52px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <img src="/logo.png" alt="ShieldScan" style={{ height: '28px', width: 'auto', background: '#ffffff', padding: '2px 6px', borderRadius: '4px' }} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
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
              letterSpacing: '0.02em',
              marginRight: '8px'
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
            onClick={onBack}
            className="interactive-element"
            style={{
              background: 'var(--red)',
              color: '#fff',
              border: 'none',
              borderRadius: '4px',
              padding: '6px 14px',
              fontSize: '11px',
              fontWeight: 700,
              cursor: 'pointer',
              fontFamily: "'Space Mono', monospace",
            }}
          >BACK TO SCANNER</button>
        </div>
      </nav>

      <div style={{ flex: 1, maxWidth: '800px', margin: '48px auto', padding: '0 24px', color: 'var(--text-primary)' }}>
        <h1 style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 900, marginBottom: '24px', color: 'var(--red)' }}>Privacy Policy</h1>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '16px' }}>
          Last updated: June 13, 2026
        </p>

        <p style={{ lineHeight: 1.6, marginBottom: '20px' }}>
          ShieldScan is built with privacy as our core design principle. We perform non-destructive, remote checks on web hosts.
        </p>

        <h2 style={{ fontFamily: "'Outfit', sans-serif", marginTop: '32px', marginBottom: '12px' }}>1. Zero Data Retention</h2>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '20px' }}>
          We do not maintain any database or persistent storage for scan logs or target domains. When you run a scan, the results are streamed directly to your browser and discarded from the server's transient memory as soon as the HTTP stream completes.
        </p>

        <h2 style={{ fontFamily: "'Outfit', sans-serif", marginTop: '32px', marginBottom: '12px' }}>2. Temporary Report Sharing</h2>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '20px' }}>
          If you explicitly choose to generate a "Shareable Report URL," the scan metadata is saved temporarily in the server's volatile memory. This data is assigned a random UUID and is automatically garbage-collected and permanently destroyed after 24 hours.
        </p>

        <h2 style={{ fontFamily: "'Outfit', sans-serif", marginTop: '32px', marginBottom: '12px' }}>3. Non-Destructive Scanning</h2>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '20px' }}>
          All scans performed by ShieldScan are strictly passive or non-destructive audits (verifying public headers, checking certificate configurations, validating DNS records, and checking exposed configuration files). We do not perform injection attacks or exploit attempts on targets.
        </p>

        <h2 style={{ fontFamily: "'Outfit', sans-serif", marginTop: '32px', marginBottom: '12px' }}>4. Third-Party Integrations</h2>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '20px' }}>
          We do not share any scanning records or IP telemetry with third-party advertising companies or data brokers.
        </p>
      </div>
    </div>
  );
}
