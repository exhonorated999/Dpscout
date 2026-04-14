import React from 'react';
import './HexagonBackground.css';

export const HexagonBackground: React.FC = () => {
  return (
    <div className="hexagon-background">
      <div className="hexagon-pattern"></div>
      <div className="circuit-lines">
        <svg className="circuit-svg" viewBox="0 0 1920 1080" preserveAspectRatio="none">
          <defs>
            <linearGradient id="circuit-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#4169e1" />
              <stop offset="100%" stopColor="#3057cc" />
            </linearGradient>
          </defs>
          
          {/* Top left circuits */}
          <path d="M 0,100 L 300,100" className="circuit-line" stroke="url(#circuit-gradient)" />
          <path d="M 300,100 L 300,300" className="circuit-line" stroke="url(#circuit-gradient)" />
          <path d="M 300,300 L 500,300" className="circuit-line" stroke="url(#circuit-gradient)" />
          <circle cx="300" cy="100" r="3" className="circuit-node" />
          <circle cx="300" cy="300" r="3" className="circuit-node" />
          
          {/* Bottom right circuits */}
          <path d="M 1920,980 L 1620,980" className="circuit-line" stroke="url(#circuit-gradient)" />
          <path d="M 1620,980 L 1620,780" className="circuit-line" stroke="url(#circuit-gradient)" />
          <path d="M 1620,780 L 1420,780" className="circuit-line" stroke="url(#circuit-gradient)" />
          <circle cx="1620" cy="980" r="3" className="circuit-node" />
          <circle cx="1620" cy="780" r="3" className="circuit-node" />
          
          {/* Top right diagonal */}
          <path d="M 1920,100 L 1600,100 L 1400,300" className="circuit-line" stroke="url(#circuit-gradient)" />
          <circle cx="1600" cy="100" r="3" className="circuit-node" />
          
          {/* Bottom left diagonal */}
          <path d="M 0,980 L 320,980 L 520,780" className="circuit-line" stroke="url(#circuit-gradient)" />
          <circle cx="320" cy="980" r="3" className="circuit-node" />
        </svg>
      </div>
      <div className="particles-container">
        {Array.from({ length: 20 }).map((_, i) => (
          <div 
            key={i} 
            className="particle"
            style={{
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
              animationDelay: `${Math.random() * 5}s`,
              animationDuration: `${3 + Math.random() * 4}s`
            }}
          />
        ))}
      </div>
    </div>
  );
};
