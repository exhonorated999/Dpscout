import React from 'react';
import './ProcessingOverlay.css';

interface ProcessingOverlayProps {
  message?: string;
}

export const ProcessingOverlay: React.FC<ProcessingOverlayProps> = ({ message = "Processing..." }) => {
  return (
    <div className="processing-overlay">
      <div className="processing-content">
        <div className="processing-spinner">
          <div className="spinner-ring"></div>
          <div className="spinner-ring"></div>
          <div className="spinner-ring"></div>
        </div>
        <div className="processing-message">{message}</div>
        <div className="processing-note">
          The application is still working. Please do not close the window.
        </div>
      </div>
    </div>
  );
};
