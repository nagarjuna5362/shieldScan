import React from 'react';

function barColor(s) {
  if (s >= 75) return '#16a34a';
  if (s >= 55) return '#d97706';
  return '#e02929';
}

export default function CategoryBar({ name, score }) {
  const c = barColor(score);
  return (
    <div>
      {name && (
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '12px' }}>
          <span style={{ color: '#444', fontWeight: 600 }}>{name}</span>
          <span style={{ color: c, fontWeight: 700, fontFamily: "'Space Mono', monospace" }}>{score}%</span>
        </div>
      )}
      {!name && (
        <div style={{ textAlign: 'right', fontSize: '11px', color: c, fontFamily: "'Space Mono', monospace", marginBottom: '4px', fontWeight: 700 }}>{score}%</div>
      )}
      <div style={{ height: '5px', background: '#eee', borderRadius: '3px', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${score}%`, background: c, borderRadius: '3px', transition: 'width 0.8s ease' }} />
      </div>
    </div>
  );
}
