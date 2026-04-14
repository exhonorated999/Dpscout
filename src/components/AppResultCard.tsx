import React from 'react';
import { QuestionableApp, AppCategoryLabels, AppCategoryColors } from '../types/scanner';
import './AppResultCard.css';

interface AppResultCardProps {
  app: QuestionableApp;
  isSelected: boolean;
  onClick: () => void;
  onTag?: () => void;
  isTagged?: boolean;
}

export const AppResultCard: React.FC<AppResultCardProps> = ({ 
  app, 
  isSelected, 
  onClick,
  onTag,
  isTagged = false
}) => {
  const categoryLabel = AppCategoryLabels[app.category];
  const categoryColor = AppCategoryColors[app.category];

  return (
    <div 
      className={`app-result-card ${isSelected ? 'selected' : ''} ${isTagged ? 'tagged' : ''}`}
      onClick={onClick}
    >
      <div className="app-result-card-header">
        <div className="app-icon">⚠️</div>
        <div className="app-info">
          <h3 className="app-name">{app.name}</h3>
          <span 
            className="app-category"
            style={{ color: categoryColor }}
          >
            {categoryLabel}
          </span>
        </div>
        {onTag && (
          <button 
            className={`tag-button ${isTagged ? 'tagged' : ''}`}
            onClick={(e) => {
              e.stopPropagation();
              onTag();
            }}
            title={isTagged ? "Remove from evidence" : "Tag as evidence"}
          >
            {isTagged ? '🔖' : '📌'}
          </button>
        )}
      </div>
      
      <div className="app-metadata">
        <div className="metadata-item">
          <span className="metadata-label">Version:</span>
          <span className="metadata-value">{app.version}</span>
        </div>
        {app.install_date && (
          <div className="metadata-item">
            <span className="metadata-label">Installed:</span>
            <span className="metadata-value">{formatDate(app.install_date)}</span>
          </div>
        )}
      </div>
    </div>
  );
};

function formatDate(dateStr: string): string {
  // Format: YYYYMMDD -> MM/DD/YYYY
  if (dateStr.length === 8) {
    const year = dateStr.substring(0, 4);
    const month = dateStr.substring(4, 6);
    const day = dateStr.substring(6, 8);
    return `${month}/${day}/${year}`;
  }
  return dateStr;
}
