import React from 'react';
import './Layout.css';

interface LayoutProps {
  navigation: React.ReactNode;
  results: React.ReactNode;
  details: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({ navigation, results, details }) => {
  return (
    <div className="layout">
      <div className="layout-pane layout-navigation">
        {navigation}
      </div>
      <div className="layout-pane layout-results">
        {results}
      </div>
      <div className="layout-pane layout-details">
        {details}
      </div>
    </div>
  );
};
