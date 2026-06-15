import React from 'react';

export default function Terms({ onBack, onContactClick }) {
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
        <h1 style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 900, marginBottom: '24px', color: 'var(--red)' }}>Terms of Service</h1>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '16px' }}>
          Last updated: June 13, 2026
        </p>

        <h2 style={{ fontFamily: "'Outfit', sans-serif", marginTop: '32px', marginBottom: '12px' }}>1. Scope of Use</h2>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '20px' }}>
          ShieldScan is provided as a web resource audit tool. You must only scan websites that you own, operate, or have explicit legal authorization to scan. Unauthorized auditing of third-party domains may violate local computer misuse regulations.
        </p>

        <h2 style={{ fontFamily: "'Outfit', sans-serif", marginTop: '32px', marginBottom: '12px' }}>2. Rate Limits & Abuse</h2>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '20px' }}>
          To maintain server resource stability, scans are rate-limited to 5 requests per hour per IP address. Scripts, bots, or actions attempting to bypass our API rate limit controls are strictly prohibited.
        </p>

        <h2 style={{ fontFamily: "'Outfit', sans-serif", marginTop: '32px', marginBottom: '12px' }}>3. Disclaimer of Warranties</h2>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '20px' }}>
          ShieldScan is provided "as is" without warranties of any kind. While our audits help identify common configuration mistakes, they do not guarantee complete defense against advanced cyber attacks. We assume no liability for errors, site downtime, or security breaches.
        </p>

        <h2 style={{ fontFamily: "'Outfit', sans-serif", marginTop: '32px', marginBottom: '12px' }}>4. Content Modifications</h2>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '20px' }}>
          We reserve the right to modify check modules, adjust scoring weights, and clean in-memory shared report databases at any time.
        </p>
      </div>
    </div>
  );
}
