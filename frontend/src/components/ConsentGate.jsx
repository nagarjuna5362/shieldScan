import React, { useState } from 'react';

export default function ConsentGate({ onAccept, dark }) {
  const [checked, setChecked] = useState(false);
  const [activeTab, setActiveTab] = useState('summary'); // 'summary' | 'terms' | 'privacy'

  const handleSubmit = (e) => {
    e.preventDefault();
    if (checked) {
      onAccept();
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '24px',
      position: 'relative',
      zIndex: 10,
      fontFamily: "'Outfit', sans-serif"
    }}>
      <div style={{
        width: '100%',
        maxWidth: '580px',
        background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: '12px',
        padding: '32px',
        boxShadow: 'var(--shadow-lg)',
        boxSizing: 'border-box',
        backdropFilter: 'blur(10px)',
        display: 'flex',
        flexDirection: 'column',
        gap: '20px'
      }}>
        {/* Header */}
        <div style={{ textAlign: 'center' }}>
          <div style={{ marginBottom: '16px', display: 'flex', justifyContent: 'center' }}>
            <img src="/logo.png" alt="ShieldScan Logo" style={{ height: '52px', width: 'auto', background: '#ffffff', padding: '4px 12px', borderRadius: '6px', border: '1px solid var(--border)' }} />
          </div>
          <div style={{
            color: 'var(--red)',
            fontSize: '11px',
            fontWeight: 700,
            fontFamily: "'Space Mono', monospace",
            letterSpacing: '0.05em',
            textTransform: 'uppercase'
          }}>Security Scanner Access Gate</div>
        </div>

        {/* Info Text */}
        <p style={{
          color: 'var(--text-secondary)',
          fontSize: '13.5px',
          lineHeight: 1.55,
          margin: 0,
          textAlign: 'center'
        }}>
          To access our professional web security auditing suite, you must review and agree to our Terms of Service and Privacy Policy.
        </p>

        {/* Tabs Selection */}
        <div style={{
          display: 'flex',
          borderBottom: '1px solid var(--border)',
          gap: '4px',
          marginTop: '8px'
        }}>
          {['summary', 'terms', 'privacy'].map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveTab(tab)}
              className="interactive-element"
              style={{
                background: 'none',
                border: 'none',
                padding: '8px 14px',
                color: activeTab === tab ? 'var(--text-primary)' : 'var(--text-muted)',
                fontWeight: activeTab === tab ? 700 : 500,
                fontSize: '11px',
                fontFamily: "'Space Mono', monospace",
                cursor: 'pointer',
                borderBottom: activeTab === tab ? '2px solid var(--red)' : '2px solid transparent',
                transition: 'all 0.2s ease',
                textTransform: 'uppercase',
                outline: 'none'
              }}
            >
              {tab === 'summary' ? 'Summary' : tab === 'terms' ? 'Terms of Service' : 'Privacy Policy'}
            </button>
          ))}
        </div>

        {/* Scrollable Terms Box */}
        <div style={{
          height: '200px',
          overflowY: 'auto',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          padding: '16px',
          background: 'rgba(0,0,0,0.18)',
          boxSizing: 'border-box',
          fontSize: '12px',
          color: 'var(--text-secondary)',
          lineHeight: 1.6,
          fontFamily: "'Space Mono', monospace"
        }} className="custom-scrollbar">
          {activeTab === 'summary' && (
            <>
              <h3 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '13px', fontFamily: "'Outfit', sans-serif" }}>1. SCOPE OF SERVICES</h3>
              <p style={{ margin: '0 0 16px 0' }}>
                ShieldScan provides non-destructive security vulnerability scanning services. We perform remote connection audits, header validations, DNS records queries, SSL certificate analysis, and public configuration file checks.
              </p>

              <h3 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '13px', fontFamily: "'Outfit', sans-serif" }}>2. AUTHORIZATION & OWNERSHIP</h3>
              <p style={{ margin: '0 0 16px 0' }}>
                You represent and warrant that you are the legal owner of the domain name entered for scanning, or that you have received explicit, written permission from the owner to perform automated security checks on this target.
              </p>

              <h3 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '13px', fontFamily: "'Outfit', sans-serif" }}>3. NO MALICIOUS EXPLOITATION</h3>
              <p style={{ margin: '0 0 16px 0' }}>
                ShieldScan audits are strictly passive and non-destructive. You agree not to attempt to reverse engineer, disrupt, bypass, or abuse the scanner's infrastructure or rate limits.
              </p>

              <h3 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '13px', fontFamily: "'Outfit', sans-serif" }}>4. PRIVACY & DATA POLICY</h3>
              <p style={{ margin: '0 0 16px 0' }}>
                We store zero scan records in databases. If you generate a shareable URL, the metadata is saved in volatile in-memory storage and permanently destroyed after 24 hours. No personally identifiable details are tracked.
              </p>

              <h3 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '13px', fontFamily: "'Outfit', sans-serif" }}>5. LIMITATION OF LIABILITY</h3>
              <p style={{ margin: '0' }}>
                Audits are provided "as-is". We assume no liability for website downtime, security breaches, data loss, or server damage resulting from your audit actions or dependency on these reports.
              </p>
            </>
          )}

          {activeTab === 'terms' && (
            <>
              <h3 style={{ color: 'var(--text-primary)', margin: '0 0 4px 0', fontSize: '14px', fontFamily: "'Outfit', sans-serif", fontWeight: 800 }}>Terms of Service</h3>
              <p style={{ fontSize: '10px', color: 'var(--text-muted)', margin: '0 0 12px 0' }}>Last updated: June 13, 2026</p>
              
              <h4 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '12px', fontWeight: 700 }}>1. Scope of Use</h4>
              <p style={{ margin: '0 0 14px 0' }}>
                ShieldScan is provided as a web resource audit tool. You must only scan websites that you own, operate, or have explicit legal authorization to scan. Unauthorized auditing of third-party domains may violate local computer misuse regulations.
              </p>

              <h4 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '12px', fontWeight: 700 }}>2. Rate Limits & Abuse</h4>
              <p style={{ margin: '0 0 14px 0' }}>
                To maintain server resource stability, scans are rate-limited to 5 requests per hour per IP address. Scripts, bots, or actions attempting to bypass our API rate limit controls are strictly prohibited.
              </p>

              <h4 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '12px', fontWeight: 700 }}>3. Disclaimer of Warranties</h4>
              <p style={{ margin: '0 0 14px 0' }}>
                ShieldScan is provided "as is" without warranties of any kind. While our audits help identify common configuration mistakes, they do not guarantee complete defense against advanced cyber attacks. We assume no liability for errors, site downtime, or security breaches.
              </p>

              <h4 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '12px', fontWeight: 700 }}>4. Content Modifications</h4>
              <p style={{ margin: '0' }}>
                We reserve the right to modify check modules, adjust scoring weights, and clean in-memory shared report databases at any time.
              </p>
            </>
          )}

          {activeTab === 'privacy' && (
            <>
              <h3 style={{ color: 'var(--text-primary)', margin: '0 0 4px 0', fontSize: '14px', fontFamily: "'Outfit', sans-serif", fontWeight: 800 }}>Privacy Policy</h3>
              <p style={{ fontSize: '10px', color: 'var(--text-muted)', margin: '0 0 12px 0' }}>Last updated: June 13, 2026</p>
              
              <p style={{ margin: '0 0 14px 0' }}>
                ShieldScan is built with privacy as our core design principle. We perform non-destructive, remote checks on web hosts.
              </p>

              <h4 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '12px', fontWeight: 700 }}>1. Zero Data Retention</h4>
              <p style={{ margin: '0 0 14px 0' }}>
                We do not maintain any database or persistent storage for scan logs or target domains. When you run a scan, the results are streamed directly to your browser and discarded from the server's transient memory as soon as the HTTP stream completes.
              </p>

              <h4 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '12px', fontWeight: 700 }}>2. Temporary Report Sharing</h4>
              <p style={{ margin: '0 0 14px 0' }}>
                If you explicitly choose to generate a "Shareable Report URL," the scan metadata is saved temporarily in the server's volatile memory. This data is assigned a random UUID and is automatically garbage-collected and permanently destroyed after 24 hours.
              </p>

              <h4 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '12px', fontWeight: 700 }}>3. Non-Destructive Scanning</h4>
              <p style={{ margin: '0 0 14px 0' }}>
                All scans performed by ShieldScan are strictly passive or non-destructive audits (verifying public headers, checking certificate configurations, validating DNS records, and checking exposed configuration files). We do not perform injection attacks or exploit attempts on targets.
              </p>

              <h4 style={{ color: 'var(--text-primary)', margin: '0 0 6px 0', fontSize: '12px', fontWeight: 700 }}>4. Third-Party Integrations</h4>
              <p style={{ margin: '0' }}>
                We do not share any scanning records or IP telemetry with third-party advertising companies or data brokers.
              </p>
            </>
          )}
        </div>

        {/* Form Consent */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <label style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '12px',
            cursor: 'pointer',
            userSelect: 'none'
          }}>
            <input
              type="checkbox"
              checked={checked}
              onChange={(e) => setChecked(e.target.checked)}
              style={{
                marginTop: '3px',
                accentColor: 'var(--red)',
                cursor: 'pointer',
                width: '16px',
                height: '16px',
                flexShrink: 0
              }}
            />
            <span style={{
              fontSize: '12px',
              color: 'var(--text-secondary)',
              lineHeight: 1.5
            }}>
              I agree to the{' '}
              <button
                type="button"
                onClick={() => setActiveTab('terms')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--red)',
                  textDecoration: 'underline',
                  cursor: 'pointer',
                  padding: 0,
                  font: 'inherit',
                  display: 'inline'
                }}
              >
                Terms of Service
              </button>{' '}
              and{' '}
              <button
                type="button"
                onClick={() => setActiveTab('privacy')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--red)',
                  textDecoration: 'underline',
                  cursor: 'pointer',
                  padding: 0,
                  font: 'inherit',
                  display: 'inline'
                }}
              >
                Privacy Policy
              </button>
              . I certify that I have full authorization and ownership to run audits on the domains I submit.
            </span>
          </label>

          <button
            type="submit"
            disabled={!checked}
            className={checked ? "btn-primary interactive-element" : ""}
            style={{
              padding: '12px 24px',
              border: 'none',
              borderRadius: '8px',
              background: checked ? 'var(--red)' : 'var(--border)',
              color: checked ? '#ffffff' : 'var(--text-muted)',
              fontSize: '14px',
              fontWeight: 700,
              cursor: checked ? 'pointer' : 'not-allowed',
              fontFamily: "'Space Mono', monospace",
              transition: 'all 0.2s ease',
              textAlign: 'center',
              boxShadow: checked ? '0 4px 12px rgba(224, 41, 41, 0.2)' : 'none'
            }}
          >
            ACCEPT & ENTER SCANNER
          </button>
        </form>
      </div>
    </div>
  );
}
