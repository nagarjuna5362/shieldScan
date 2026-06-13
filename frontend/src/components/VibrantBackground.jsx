import React from 'react';

export default function VibrantBackground() {
  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 0,
      overflow: 'hidden',
      pointerEvents: 'none',
    }}>
      {/* Moving glass orbs */}
      <div style={{
        position: 'absolute',
        top: '-10%',
        left: '-10%',
        width: '50vw',
        height: '50vw',
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(208, 0, 255, 0.4) 0%, rgba(208, 0, 255, 0) 70%)',
        filter: 'blur(80px)',
        animation: 'float Orb1 25s ease-in-out infinite alternate',
      }} />

      <div style={{
        position: 'absolute',
        bottom: '-10%',
        right: '-10%',
        width: '60vw',
        height: '60vw',
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(255, 0, 127, 0.35) 0%, rgba(255, 0, 127, 0) 70%)',
        filter: 'blur(100px)',
        animation: 'float Orb2 30s ease-in-out infinite alternate-reverse',
      }} />

      <div style={{
        position: 'absolute',
        top: '30%',
        right: '15%',
        width: '40vw',
        height: '40vw',
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(0, 255, 255, 0.35) 0%, rgba(0, 255, 255, 0) 70%)',
        filter: 'blur(90px)',
        animation: 'float Orb3 28s ease-in-out infinite alternate',
      }} />

      <div style={{
        position: 'absolute',
        bottom: '20%',
        left: '10%',
        width: '35vw',
        height: '35vw',
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(255, 234, 0, 0.2) 0%, rgba(255, 234, 0, 0) 70%)',
        filter: 'blur(70px)',
        animation: 'float Orb4 22s ease-in-out infinite alternate-reverse',
      }} />

      {/* Floating hand-drawn SVG doodles */}
      <svg style={{ position: 'absolute', width: '100%', height: '100%', top: 0, left: 0, opacity: 0.15 }}>
        {/* Hand-drawn Star 1 */}
        <g style={{ transform: 'translate(10%, 15%) scale(1.5)', transformOrigin: 'center' }}>
          <path d="M 0,-15 L 4,-4 L 15,-4 L 6,3 L 10,14 L 0,8 L -10,14 L -6,3 L -15,-4 L -4,-4 Z" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" />
        </g>
        {/* Hand-drawn Star 2 */}
        <g style={{ transform: 'translate(85%, 25%) rotate(15deg) scale(1.2)' }}>
          <path d="M 0,-15 L 4,-4 L 15,-4 L 6,3 L 10,14 L 0,8 L -10,14 L -6,3 L -15,-4 L -4,-4 Z" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" />
        </g>
        {/* Hand-drawn Star 3 */}
        <g style={{ transform: 'translate(75%, 75%) rotate(-10deg) scale(1.8)' }}>
          <path d="M 0,-15 L 4,-4 L 15,-4 L 6,3 L 10,14 L 0,8 L -10,14 L -6,3 L -15,-4 L -4,-4 Z" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" />
        </g>
        {/* Hand-drawn Sparkle */}
        <g style={{ transform: 'translate(15%, 80%) scale(1.3)' }}>
          <path d="M 0,-10 C 1,-3 3,-1 10,0 C 3,1 1,3 0,10 C -1,3 -3,1 -10,0 C -3,-1 -1,-3 0,-10 Z" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" />
        </g>
        <g style={{ transform: 'translate(90%, 60%) scale(1)' }}>
          <path d="M 0,-10 C 1,-3 3,-1 10,0 C 3,1 1,3 0,10 C -1,3 -3,1 -10,0 C -3,-1 -1,-3 0,-10 Z" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" />
        </g>
        {/* Spiral scribble */}
        <path d="M 200,450 Q 210,440 220,455 T 230,470 T 240,460 T 250,480" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" style={{ transform: 'translate(15vw, 20vh) scale(1.5)' }} />
        <path d="M 200,450 Q 210,440 220,455 T 230,470 T 240,460 T 250,480" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" style={{ transform: 'translate(65vw, 55vh) rotate(110deg) scale(1.2)' }} />
      </svg>

      {/* Adding CSS keyframes for floating orbs */}
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes float {
          0% { transform: translate(0, 0) scale(1); }
          50% { transform: translate(4vw, -5vh) scale(1.05); }
          100% { transform: translate(-2vw, 3vh) scale(0.95); }
        }
      `}} />
    </div>
  );
}
