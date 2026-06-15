import React, { useEffect, useRef, useState } from 'react';

function color(s) {
  if (s >= 75) return '#16a34a';
  if (s >= 55) return '#d97706';
  if (s >= 35) return '#e02929';
  return '#b91c1c';
}

export default function ScoreRing({ score, grade, size = 160 }) {
  const [val, setVal] = useState(0);
  const ref = useRef(null);

  useEffect(() => {
    let start = null;
    const dur = 1200;
    const go = (ts) => {
      if (!start) start = ts;
      const p = Math.min((ts - start) / dur, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      setVal(Math.round(eased * score));
      if (p < 1) ref.current = requestAnimationFrame(go);
    };
    ref.current = requestAnimationFrame(go);
    return () => cancelAnimationFrame(ref.current);
  }, [score]);

  const r = 58;
  const circ = 2 * Math.PI * r;
  const stroke = color(val);

  return (
    <div style={{ position: 'relative', width: size, height: size, display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg width={size} height={size} viewBox="0 0 140 140" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={70} cy={70} r={r} fill="none" stroke="var(--border)" strokeWidth={10} />
        <circle
          cx={70} cy={70} r={r} fill="none"
          stroke={stroke} strokeWidth={10} strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={circ - (val / 100) * circ}
          style={{ transition: 'stroke-dashoffset 0.05s ease-out' }}
        />
      </svg>
      <div style={{ position: 'absolute', textAlign: 'center' }}>
        <div style={{ fontSize: size * 0.18, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1, fontFamily: "'Outfit', sans-serif" }}>{grade}</div>
        <div style={{ fontSize: size * 0.095, color: stroke, fontWeight: 700, fontFamily: "'Space Mono', monospace", lineHeight: 1.2 }}>{val}/100</div>
      </div>
    </div>
  );
}
