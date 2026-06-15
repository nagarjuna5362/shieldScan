import React, { useState, useMemo, useEffect } from 'react';
import ScoreRing from '../components/ScoreRing';
import VulnCard from '../components/VulnCard';

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

const CAT_ICONS = {
  'Transport Security': '🔒',
  'HTTP Headers': '📋',
  'CORS & API Security': '🌐',
  'Cookie & Session': '🍪',
  'File & Info Exposure': '📁',
  'DNS & Network': '🌍',
  'Rate Limiting & Abuse': '⚡',
};

const CAT_WEIGHTS = {
  'Transport Security': 45,
  'HTTP Headers': 29,
  'CORS & API Security': 26,
  'Cookie & Session': 11,
  'File & Info Exposure': 21,
  'DNS & Network': 7,
  'Rate Limiting & Abuse': 10,
};

function RadarChart({ categoryScores }) {
  const cats = Object.keys(categoryScores);
  const n = cats.length;
  if (n < 3) return null;

  const cx = 140,
    cy = 140,
    r = 110;
  const angleStep = (2 * Math.PI) / n;

  const levels = [20, 40, 60, 80, 100];

  const polarToXY = (angle, radius) => ({
    x: cx + radius * Math.sin(angle),
    y: cy - radius * Math.cos(angle),
  });

  const gridPolygons = levels.map((level) => {
    const pts = cats.map((_, i) => {
      const p = polarToXY(i * angleStep, (level / 100) * r);
      return `${p.x},${p.y}`;
    });
    return pts.join(' ');
  });

  const dataPoints = cats.map((cat, i) => {
    const val = categoryScores[cat] || 0;
    const p = polarToXY(i * angleStep, (val / 100) * r);
    return p;
  });

  const dataPath = dataPoints.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x},${p.y}`).join(' ') + 'Z';

  const axes = cats.map((cat, i) => {
    const end = polarToXY(i * angleStep, r);
    const labelPt = polarToXY(i * angleStep, r + 22);
    return { end, labelPt, cat, score: categoryScores[cat] || 0 };
  });

  return (
    <svg viewBox="0 0 280 280" style={{ width: '100%', maxWidth: '280px', display: 'block', margin: '0 auto' }}>
      {gridPolygons.map((pts, i) => (
        <polygon
          key={i}
          points={pts}
          fill="none"
          stroke="var(--border)"
          strokeWidth={i === gridPolygons.length - 1 ? 1.5 : 0.8}
          opacity={0.8}
        />
      ))}
      {axes.map((ax, i) => (
        <line
          key={i}
          x1={cx}
          y1={cy}
          x2={ax.end.x}
          y2={ax.end.y}
          stroke="var(--border)"
          strokeWidth={0.8}
          opacity={0.6}
        />
      ))}
      <defs>
        <linearGradient id="radarGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#e02929" stopOpacity="0.75" />
          <stop offset="100%" stopColor="#e02929" stopOpacity="0.35" />
        </linearGradient>
      </defs>
      <path d={dataPath} fill="url(#radarGrad)" stroke="#e02929" strokeWidth={2} strokeLinejoin="round" />
      {dataPoints.map((p, i) => {
        const score = categoryScores[cats[i]] || 0;
        const color = score >= 75 ? '#16a34a' : score >= 55 ? '#d97706' : '#e02929';
        return <circle key={i} cx={p.x} cy={p.y} r={4} fill={color} stroke="var(--bg-card)" strokeWidth={2} />;
      })}
      {axes.map((ax, i) => {
        const score = ax.score;
        const color = score >= 75 ? '#16a34a' : score >= 55 ? '#d97706' : '#e02929';
        const shortCat = ax.cat
          .replace(' Security', '')
          .replace(' & Session', '')
          .replace(' & Info', '')
          .replace(' & Abuse', '')
          .replace('Rate Limiting', 'Rate Limit')
          .replace('Transport', 'Transport');
        return (
          <text
            key={i}
            x={ax.labelPt.x}
            y={ax.labelPt.y}
            textAnchor="middle"
            dominantBaseline="middle"
            fontSize="8.5"
            fill={color}
            fontWeight="700"
            fontFamily="'Space Mono', monospace"
          >
            {shortCat.length > 14 ? shortCat.slice(0, 13) + '…' : shortCat}
          </text>
        );
      })}
    </svg>
  );
}

export default function Results({ results, finalData, url, onRescan, dark, onToggleDark, prevScore, onContactClick }) {
  const [filter, setFilter] = useState('all');
  const [reportUuid, setReportUuid] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    fetch('/api/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report: finalData }),
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.uuid) setReportUuid(data.uuid);
      })
      .catch((err) => console.error('Error saving report:', err));
  }, [finalData]);

  const sorted = useMemo(() => {
    if (!results) return [];
    return [...results].sort((a, b) => {
      const ao = a.status === 'PASS' || a.status === 'ERROR' ? 5 : SEV_ORDER[a.severity] ?? 4;
      const bo = b.status === 'PASS' || b.status === 'ERROR' ? 5 : SEV_ORDER[b.severity] ?? 4;
      return ao - bo;
    });
  }, [results]);

  const filtered = useMemo(() => {
    if (filter === 'issues') return sorted.filter((r) => r.status === 'FAIL' || r.status === 'WARNING');
    if (filter === 'pass') return sorted.filter((r) => r.status === 'PASS');
    if (filter === 'critical') return sorted.filter((r) => r.severity === 'CRITICAL' && r.status === 'FAIL');
    return sorted;
  }, [sorted, filter]);

  if (!finalData) return null;

  const { score, grade, label, summary, categoryScores, topAttackVectors, scanDuration, hostname, fixPriorities, timestamp } =
    finalData;
  const scoreColor = score >= 75 ? '#16a34a' : score >= 55 ? '#d97706' : '#e02929';

  const downloadPdf = () => {
    if (reportUuid) {
      window.open(`/api/reports/${reportUuid}/pdf`, '_blank');
    }
  };

  const handleCopyLink = () => {
    if (reportUuid) {
      const shareUrl = `${window.location.origin}/report/${reportUuid}`;
      navigator.clipboard.writeText(shareUrl).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      });
    }
  };

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(finalData, null, 2)], { type: 'application/json' });
    const urlStr = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = urlStr;
    a.download = `shieldscan-${hostname}.json`;
    a.click();
    URL.revokeObjectURL(urlStr);
  };

  const generateReport = () => {
    const lines = [
      '=== ShieldScan Security Report ===',
      `Target: ${url}`,
      `Date:   ${new Date(timestamp).toLocaleString()}`,
      `Score:  ${score}/100  Grade: ${grade}  (${label})`,
      '',
      '--- Summary ---',
      `Critical: ${summary.critical}  High: ${summary.high}  Medium: ${summary.medium}  Low: ${summary.low}  Pass: ${summary.pass}`,
      '',
      '--- Category Scores ---',
      ...Object.entries(categoryScores).map(([cat, sc]) => `${cat}: ${sc}%`),
      '',
      '--- Findings ---',
      '',
    ];
    results.forEach((r, i) => {
      lines.push(`[${i + 1}] ${r.name}`);
      lines.push(`  Status:   ${r.status}`);
      if (r.status !== 'PASS' && r.status !== 'ERROR') lines.push(`  Severity: ${r.severity} (-${r.points_deducted} pts)`);
      lines.push(`  Finding:  ${r.description}`);
      if (r.technicalDetail) lines.push(`  Detail:   ${r.technicalDetail}`);
      if (r.attackScenario) lines.push(`  Risk:     ${r.attackScenario}`);
      if (r.fix) lines.push(`  Fix:      ${r.fix.description}`);
      lines.push('');
    });
    lines.push('Generated by ShieldScan — for authorized testing only.');
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `shieldscan-${hostname}-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
  };

  const summaryItems = [
    { n: summary.critical || 0, l: 'Critical', c: '#b91c1c', bg: '#fee2e2', darkBg: '#3f1212' },
    { n: summary.high || 0, l: 'High', c: '#e02929', bg: '#fee2e2', darkBg: '#3f1212' },
    { n: summary.medium || 0, l: 'Medium', c: '#b45309', bg: '#fef3c7', darkBg: '#3a2800' },
    { n: summary.low || 0, l: 'Low', c: '#1d4ed8', bg: '#dbeafe', darkBg: '#0f2040' },
    { n: summary.pass || 0, l: 'Pass', c: '#15803d', bg: '#dcfce7', darkBg: '#052e16' },
  ];

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', color: 'var(--text-primary)' }}>
      <nav
        style={{
          background: 'var(--nav-bg)',
          padding: '0 20px',
          height: '52px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          position: 'sticky',
          top: 0,
          zIndex: 100,
          borderBottom: '1px solid rgba(255,255,255,0.06)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <img src="/logo.png" alt="ShieldScan" style={{ height: '28px', width: 'auto', background: '#ffffff', padding: '2px 6px', borderRadius: '4px' }} />
          <span
            className="mobile-hide"
            style={{ marginLeft: '8px', fontSize: '11px', color: 'rgba(255,255,255,0.35)', fontFamily: "'Space Mono', monospace" }}
          >
            {hostname}
          </span>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
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
          {reportUuid && (
            <button
              onClick={handleCopyLink}
              className="interactive-element"
              style={{
                background: copied ? '#15803d' : 'rgba(255,255,255,0.08)',
                color: '#fff',
                border: '1px solid rgba(255,255,255,0.15)',
                borderRadius: '6px',
                padding: '6px 12px',
                fontSize: '12px',
                cursor: 'pointer',
                fontWeight: 600,
              }}
            >
              {copied ? '✓ Copied' : '🔗 Share URL'}
            </button>
          )}
          <button
            onClick={downloadPdf}
            className="interactive-element"
            disabled={!reportUuid}
            style={{
              background: 'rgba(255,255,255,0.08)',
              color: '#fff',
              border: '1px solid rgba(255,255,255,0.15)',
              borderRadius: '6px',
              padding: '6px 12px',
              fontSize: '12px',
              cursor: 'pointer',
              fontWeight: 600,
              opacity: reportUuid ? 1 : 0.5,
            }}
          >
            PDF Report
          </button>
          <button
            onClick={exportJson}
            className="interactive-element"
            style={{
              background: 'rgba(255,255,255,0.08)',
              color: '#fff',
              border: '1px solid rgba(255,255,255,0.15)',
              borderRadius: '6px',
              padding: '6px 12px',
              fontSize: '12px',
              cursor: 'pointer',
              fontWeight: 600,
            }}
          >
            JSON Raw
          </button>
          <button
            onClick={onRescan}
            className="btn-primary"
            style={{ padding: '6px 14px', fontSize: '12px', borderRadius: '6px' }}
          >
            ← New scan
          </button>
        </div>
      </nav>

      <div
        style={{
          flex: 1,
          maxWidth: '900px',
          width: '100%',
          margin: '0 auto',
          padding: '28px 20px 60px',
          position: 'relative',
          zIndex: 2,
        }}
      >
        <div
          style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: '10px',
            padding: '24px 28px',
            marginBottom: '16px',
            boxShadow: 'var(--shadow-md)',
          }}
        >
          <div style={{ display: 'flex', gap: '32px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ flexShrink: 0, textAlign: 'center' }} className="score-ring-wrap">
              <ScoreRing score={score} grade={grade} size={140} />
              <div style={{ marginTop: '6px', fontSize: '13px', fontWeight: 700, color: scoreColor }}>{label}</div>
              {prevScore !== undefined && prevScore !== null && (
                <div
                  style={{
                    display: 'inline-block',
                    marginTop: '8px',
                    fontSize: '11px',
                    fontWeight: 700,
                    color: score > prevScore ? '#16a34a' : score < prevScore ? '#e02929' : 'var(--text-muted)',
                    background: score > prevScore ? 'rgba(22,163,74,0.08)' : score < prevScore ? 'rgba(224,41,41,0.08)' : 'rgba(255,255,255,0.05)',
                    padding: '3px 10px',
                    borderRadius: '4px',
                    fontFamily: "'Space Mono', monospace",
                  }}
                >
                  {score > prevScore ? `▲ +${score - prevScore} since last scan` : score < prevScore ? `▼ -${prevScore - score} since last scan` : 'No score change'}
                </div>
              )}
            </div>
            <div style={{ flex: 1, minWidth: '220px' }}>
              <h1
                style={{
                  fontSize: '20px',
                  fontWeight: 800,
                  marginBottom: '16px',
                  color: 'var(--text-primary)',
                  fontFamily: "'Outfit', sans-serif",
                }}
              >
                Security Report
              </h1>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '18px' }}>
                {summaryItems.map(({ n, l, c, bg, darkBg }, idx) => (
                  <div
                    key={l}
                    className="card-stagger"
                    style={{
                      background: dark ? darkBg : bg,
                      borderRadius: '6px',
                      padding: '9px 14px',
                      textAlign: 'center',
                      minWidth: '68px',
                      animationDelay: `${idx * 50}ms`,
                      border: `1px solid ${c}22`,
                    }}
                  >
                    <div
                      style={{
                        fontSize: '22px',
                        fontWeight: 800,
                        color: 'var(--text-primary)',
                        fontFamily: "'Space Mono', monospace",
                      }}
                    >
                      {n}
                    </div>
                    <div style={{ fontSize: '10px', fontWeight: 700, color: c, textTransform: 'uppercase', marginTop: '2px' }}>
                      {l}
                    </div>
                  </div>
                ))}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: "'Space Mono', monospace", lineHeight: 2 }}>
                <div>
                  Target: <span style={{ color: 'var(--text-primary)' }}>{url}</span>
                </div>
                <div>
                  Scanned: <span style={{ color: 'var(--text-primary)' }}>{new Date(timestamp).toLocaleString()}</span>
                </div>
                <div>
                  Duration: <span style={{ color: 'var(--text-primary)' }}>{scanDuration} · {results.length} checks run</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div
          style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: '10px',
            padding: '22px 26px',
            marginBottom: '16px',
            boxShadow: 'var(--shadow-sm)',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: '20px',
              flexWrap: 'wrap',
              gap: '8px',
            }}
          >
            <h2 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Category Scores
            </h2>
            <span style={{ fontSize: '11px', color: 'var(--text-faint)', fontFamily: "'Space Mono', monospace" }}>
              weighted average · higher weight = more impact
            </span>
          </div>

          <div style={{ display: 'flex', gap: '24px', alignItems: 'flex-start', flexWrap: 'wrap' }}>
            <div style={{ flex: '0 0 auto', width: '220px' }} className="mobile-hide">
              <RadarChart categoryScores={categoryScores} />
            </div>
            <div style={{ flex: 1, minWidth: '240px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {Object.entries(categoryScores).map(([cat, sc], idx) => {
                const catColor = sc >= 75 ? '#16a34a' : sc >= 55 ? '#d97706' : '#e02929';
                return (
                  <div
                    key={cat}
                    className="card-stagger interactive-element"
                    style={{
                      background: 'var(--bg-card-2)',
                      border: '1px solid var(--border)',
                      borderRadius: '6px',
                      padding: '10px 14px',
                      animationDelay: `${idx * 60}ms`,
                    }}
                  >
                    <div style={{ display: 'flex', justifycontent: 'space-between', alignItems: 'center', marginBottom: '7px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
                        <span style={{ fontSize: '14px' }}>{CAT_ICONS[cat] || '🔍'}</span>
                        <span style={{ fontSize: '12px', color: 'var(--text-primary)', fontWeight: 700 }}>{cat}</span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginLeft: 'auto' }}>
                        <span style={{ fontSize: '10px', color: 'var(--text-faint)', fontFamily: "'Space Mono', monospace" }}>
                          wt:{CAT_WEIGHTS[cat] || '?'}
                        </span>
                        <span style={{ fontSize: '16px', fontWeight: 800, color: catColor, fontFamily: "'Space Mono', monospace" }}>
                          {sc}%
                        </span>
                      </div>
                    </div>
                    <div style={{ height: '5px', background: 'var(--border)', borderRadius: '3px', overflow: 'hidden' }}>
                      <div
                        style={{
                          height: '100%',
                          width: `${sc}%`,
                          background: catColor,
                          borderRadius: '3px',
                          transition: 'width 1s cubic-bezier(0.16,1,0.3,1)',
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div
            style={{
              marginTop: '14px',
              padding: '10px 14px',
              background: 'var(--bg-card-2)',
              border: '1px solid var(--border)',
              borderRadius: '6px',
              fontSize: '11px',
              color: 'var(--text-muted)',
              fontFamily: "'Space Mono', monospace",
            }}
          >
            ℹ️ PASS = full pts · WARNING = 50% · FAIL = 0%. Overall = weighted avg. ERROR checks excluded.
          </div>
        </div>

        {fixPriorities && fixPriorities.length > 0 && (
          <div
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: '10px',
              padding: '22px 26px',
              marginBottom: '16px',
              boxShadow: 'var(--shadow-sm)',
            }}
          >
            <h2
              style={{
                fontSize: '14px',
                fontWeight: 800,
                color: 'var(--text-primary)',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                marginBottom: '16px',
              }}
            >
              Top Fix Recommendations
            </h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {fixPriorities.map((fix, idx) => (
                <div
                  key={fix.checkId}
                  style={{
                    background: 'var(--bg-card-2)',
                    border: '1px solid var(--border)',
                    borderRadius: '8px',
                    padding: '16px',
                    display: 'flex',
                    gap: '16px',
                    alignItems: 'flex-start',
                  }}
                >
                  <div
                    style={{
                      width: '28px',
                      height: '28px',
                      borderRadius: '50%',
                      background: 'var(--red)',
                      color: '#fff',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontWeight: 800,
                      fontSize: '12px',
                      flexShrink: 0,
                      fontFamily: "'Space Mono', monospace",
                    }}
                  >
                    {idx + 1}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'baseline',
                        marginBottom: '6px',
                        flexWrap: 'wrap',
                        gap: '6px',
                      }}
                    >
                      <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>{fix.name}</span>
                      <span
                        style={{
                          fontSize: '10.5px',
                          fontWeight: 700,
                          color: 'var(--red)',
                          background: 'rgba(224,41,41,0.08)',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontFamily: "'Space Mono', monospace",
                        }}
                      >
                        CVSS: {fix.cvss} ({fix.severity})
                      </span>
                    </div>
                    <p style={{ fontSize: '12.2px', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '10px' }}>
                      {fix.recommendation}
                    </p>
                    {fix.code && (
                      <pre
                        style={{
                          margin: 0,
                          padding: '10px',
                          background: 'rgba(0,0,0,0.2)',
                          color: '#a7f3d0',
                          borderRadius: '6px',
                          fontSize: '11px',
                          overflowX: 'auto',
                          fontFamily: "'Space Mono', monospace",
                        }}
                      >
                        <code>{fix.code}</code>
                      </pre>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {score < 60 && topAttackVectors && topAttackVectors.length > 0 && (
          <div
            style={{
              background: dark ? '#2d1515' : '#fff8f8',
              border: '1px solid #fecdd3',
              borderLeft: '4px solid var(--red)',
              borderRadius: '10px',
              padding: '18px 22px',
              marginBottom: '16px',
            }}
          >
            <div
              style={{
                fontWeight: 800,
                color: '#b91c1c',
                marginBottom: '12px',
                fontSize: '14px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <span>⚠</span> Likely attack paths based on these findings:
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {topAttackVectors.map((v, i) => (
                <div
                  key={i}
                  style={{
                    display: 'flex',
                    gap: '12px',
                    alignItems: 'flex-start',
                    fontSize: '13px',
                    color: dark ? '#fca5a5' : '#7f1d1d',
                    padding: '8px 10px',
                    background: dark ? 'rgba(224,41,41,0.08)' : 'rgba(255,255,255,0.6)',
                    borderRadius: '5px',
                  }}
                >
                  <span style={{ fontWeight: 800, flexShrink: 0, color: 'var(--red)', fontFamily: "'Space Mono', monospace" }}>
                    {i + 1}.
                  </span>
                  <span>{v}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div
          style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: '10px',
            padding: '20px 24px',
            boxShadow: 'var(--shadow-sm)',
            marginBottom: '16px',
          }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '16px',
              flexWrap: 'wrap',
              gap: '10px',
            }}
          >
            <h2 style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              All Findings
            </h2>
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
              {[
                { id: 'all', label: `All (${results.length})` },
                {
                  id: 'issues',
                  label: `Issues (${(summary.critical || 0) + (summary.high || 0) + (summary.medium || 0) + (summary.low || 0)})`,
                },
                { id: 'critical', label: `Critical (${summary.critical || 0})` },
                { id: 'pass', label: `Pass (${summary.pass || 0})` },
              ].map((btn) => (
                <button
                  key={btn.id}
                  onClick={() => setFilter(btn.id)}
                  className="interactive-element"
                  style={{
                    background: filter === btn.id ? 'var(--text-primary)' : 'var(--bg-card-2)',
                    color: filter === btn.id ? (dark ? '#111' : '#fff') : 'var(--text-secondary)',
                    border: `1px solid ${filter === btn.id ? 'var(--text-primary)' : 'var(--border)'}`,
                    borderRadius: '5px',
                    padding: '5px 12px',
                    fontSize: '12px',
                    cursor: 'pointer',
                    fontWeight: 700,
                  }}
                >
                  {btn.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            {filtered.map((r, i) => (
              <VulnCard key={r.checkId || i} result={r} index={i} />
            ))}
            {filtered.length === 0 && (
              <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-faint)', fontSize: '14px' }}>
                Nothing matches this filter.
              </div>
            )}
          </div>
        </div>

        {/* Dynamic Badge Embed Code Section */}
        <div
          style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: '10px',
            padding: '20px 24px',
            boxShadow: 'var(--shadow-sm)',
            marginBottom: '16px',
          }}
        >
          <h2
            style={{
              fontSize: '13px',
              fontWeight: 800,
              color: 'var(--text-primary)',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              marginBottom: '12px',
            }}
          >
            Embed ShieldScan Rating Badge
          </h2>
          <div style={{ display: 'flex', gap: '20px', alignItems: 'center', flexWrap: 'wrap' }}>
            <img src={`/api/badge/${hostname}?score=${score}`} alt="ShieldScan Score Badge" style={{ height: '20px' }} />
            <div style={{ flex: 1, minWidth: '240px' }}>
              <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                Add this SVG badge to your website footer or documentation to showcase your live security score:
              </p>
              <input
                type="text"
                readOnly
                onClick={(e) => e.target.select()}
                value={`<a href="${window.location.origin}"><img src="${window.location.origin}/api/badge/${hostname}?score=${score}" alt="ShieldScan Security Rating" /></a>`}
                style={{
                  width: '100%',
                  padding: '8px 10px',
                  background: 'rgba(0,0,0,0.15)',
                  border: '1px solid var(--border)',
                  borderRadius: '5px',
                  fontSize: '10.5px',
                  color: 'var(--text-primary)',
                  fontFamily: "'Space Mono', monospace",
                }}
              />
            </div>
          </div>
        </div>

        <div style={{ textAlign: 'center', marginTop: '28px', paddingBottom: '20px' }}>
          <button
            onClick={generateReport}
            className="btn-primary"
            style={{ padding: '12px 36px', fontSize: '14px', borderRadius: '8px' }}
          >
            ↓ Download plain text report (.txt)
          </button>
          <p style={{ marginTop: '10px', fontSize: '12px', color: 'var(--text-faint)', fontFamily: "'Space Mono', monospace" }}>
            made by <span style={{ color: 'var(--red)', fontWeight: 700 }}>nagarjuna's team</span> · for authorized security testing
            only
          </p>
        </div>
      </div>
    </div>
  );
}
