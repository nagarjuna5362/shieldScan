import React from 'react';

// Simple off-white background — no fancy gradients
export default function BackgroundGrid() {
  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 0,
      backgroundColor: '#f5f5f4',
      pointerEvents: 'none',
    }}>
      {/* Very faint dot grid */}
      <div className="grid-bg" style={{ position: 'absolute', inset: 0, opacity: 0.5 }} />
    </div>
  );
}
