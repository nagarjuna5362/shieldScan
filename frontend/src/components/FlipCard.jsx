import React, { useState, useRef } from 'react';

export default function FlipCard({ icon, label, description, disaster, delayIndex }) {
  const [isFlipped, setIsFlipped] = useState(false);
  const [isFocused, setIsFocused] = useState(false);
  const cardRef = useRef(null);
  const [tiltStyle, setTiltStyle] = useState({});

  const handleMouseMove = (e) => {
    if (!cardRef.current || isFlipped) return;
    
    if (e.pointerType === 'touch') return;

    const rect = cardRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    
    const rotateX = ((centerY - y) / centerY) * 4;
    const rotateY = ((x - centerX) / centerX) * 4;

    setTiltStyle({
      transform: `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-8px)`,
      boxShadow: '0 12px 24px rgba(59, 130, 246, 0.25)', 
    });
  };

  const handleMouseLeave = () => {
    setTiltStyle({});
  };

  const handleTap = (e) => {
    setIsFlipped(prev => !prev);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setIsFlipped(prev => !prev);
    }
  };

  const getInnerStyles = () => {
    const base = {
      width: '100%',
      height: '100%',
      position: 'relative',
      transition: 'transform 0.6s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.3s ease',
      borderRadius: '8px',
    };

    if (isFlipped) {
      return {
        ...base,
        transform: 'rotateY(180deg) translateY(-4px)',
        boxShadow: '0 12px 24px rgba(224, 41, 41, 0.25)', 
      };
    }

    if (tiltStyle.transform) {
      return {
        ...base,
        ...tiltStyle,
      };
    }

    if (isFocused) {
      return {
        ...base,
        boxShadow: '0 0 0 3px #3B82F6', 
        transform: 'translateY(-4px)',
      };
    }

    return base;
  };

  return (
    <div
      ref={cardRef}
      tabIndex={0}
      onFocus={() => setIsFocused(true)}
      onBlur={() => { setIsFocused(false); setIsFlipped(false); }}
      onKeyDown={handleKeyDown}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      onClick={handleTap}
      className="perspective-1000 card-stagger"
      style={{
        width: '100%',
        height: '142px',
        cursor: 'pointer',
        animationDelay: `${delayIndex * 70}ms`,
        outline: 'none',
      }}
    >
      <div className="preserve-3d" style={getInnerStyles()}>
        
        <div
          className="backface-hidden glass-card-front animate-border-glow"
          style={{
            position: 'absolute',
            inset: 0,
            borderRadius: '8px',
            padding: '16px',
            display: 'flex',
            alignItems: 'center',
            gap: '14px',
            borderWidth: '1px',
          }}
        >
          <span style={{ fontSize: '28px', filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.1))' }}>{icon}</span>
          <div style={{ flex: 1 }}>
            <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', margin: 0, letterSpacing: '-0.01em' }}>
              {label}
            </h3>
            <span style={{
              fontSize: '9px',
              color: '#888',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              marginTop: '4px',
              display: 'block',
              fontFamily: "'Space Mono', monospace",
              fontWeight: 600,
            }}>
              tap to flip ⚡
            </span>
          </div>
        </div>

        <div
          className="backface-hidden glass-card-back rotate-y-180"
          style={{
            position: 'absolute',
            inset: 0,
            borderRadius: '8px',
            padding: '12px 14px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            borderWidth: '1px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
            <span style={{ fontSize: '12px' }}>🛡️</span>
            <strong style={{ fontSize: '11px', color: '#60a5fa', fontFamily: "'Space Mono', monospace", letterSpacing: '0.02em' }}>
              {label}
            </strong>
          </div>
          
          <p style={{ fontSize: '10.5px', color: '#e2e8f0', margin: 0, lineHeight: 1.35, fontWeight: 500 }}>
            {description}
          </p>
          
          <div style={{
            marginTop: '6px',
            paddingTop: '5px',
            borderTop: '1px solid rgba(255, 255, 255, 0.1)',
            fontSize: '10px',
            lineHeight: 1.3,
            color: '#fca5a5',
          }}>
            <strong style={{ textTransform: 'uppercase', letterSpacing: '0.02em', fontSize: '9px' }}>⚠️ Disaster:</strong>{' '}
            {disaster}
          </div>
        </div>

      </div>
    </div>
  );
}
