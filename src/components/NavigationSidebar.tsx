import React from 'react';
import './NavigationSidebar.css';

export interface NavItem {
  id: string;
  label: string;
  icon: string;
  count?: number;
  active: boolean;
  onClick: () => void;
}

interface NavigationSidebarProps {
  items: NavItem[];
  logo?: boolean;
}

export const NavigationSidebar: React.FC<NavigationSidebarProps> = ({ items, logo = true }) => {
  return (
    <div className="navigation-sidebar">
      {logo && (
        <div className="nav-logo">
          <div className="logo-icon">
            <div className="logo-dots">
              <div className="dot"></div>
              <div className="dot"></div>
              <div className="dot"></div>
              <div className="dot"></div>
              <div className="dot"></div>
            </div>
          </div>
          <div className="logo-text">
            <div className="logo-title">PROJECT</div>
            <div className="logo-subtitle">HINDSIGHT</div>
          </div>
        </div>
      )}
      
      <div className="nav-items">
        {items.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${item.active ? 'active' : ''}`}
            onClick={item.onClick}
          >
            <div className="nav-item-icon" dangerouslySetInnerHTML={{ __html: item.icon }} />
            <div className="nav-item-label">{item.label}</div>
            {item.count !== undefined && item.count > 0 && (
              <div className="nav-item-badge">{item.count}</div>
            )}
          </button>
        ))}
      </div>
    </div>
  );
};
