import React, { useEffect, useState } from 'react';

export default function BackgroundGrid({ dark }) {
  const [mousePos, setMousePos] = useState({ x: -1000, y: -1000 });

  useEffect(() => {
    const handleMouseMove = (e) => {
      setMousePos({ x: e.clientX, y: e.clientY });
    };
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 0,
      backgroundColor: 'var(--bg)',
      pointerEvents: 'none',
      transition: 'background-color 0.25s ease',
    }}>
      <div className="grid-bg" style={{ position: 'absolute', inset: 0 }} />
      <div style={{
        position: 'absolute',
        inset: 0,
        background: dark
          ? `radial-gradient(600px circle at ${mousePos.x}px ${mousePos.y}px, rgba(224, 41, 41, 0.06), rgba(120, 60, 60, 0.03), transparent 70%)`
          : `radial-gradient(600px circle at ${mousePos.x}px ${mousePos.y}px, rgba(224, 41, 41, 0.05), rgba(59, 130, 246, 0.02), transparent 70%)`,
        pointerEvents: 'none',
        transition: 'none',
      }} />
    </div>
  );
}
