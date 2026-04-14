import React, { useState } from 'react';
import { Button } from './Button';
import './FirstTimeSetup.css';

interface FirstTimeSetupProps {
  onComplete: (officerName: string, agencyName: string) => void;
}

export const FirstTimeSetup: React.FC<FirstTimeSetupProps> = ({ onComplete }) => {
  const [officerName, setOfficerName] = useState('');
  const [agencyName, setAgencyName] = useState('');
  const [errors, setErrors] = useState<{ officerName?: string; agencyName?: string }>({});

  const validateForm = (): boolean => {
    const newErrors: { officerName?: string; agencyName?: string } = {};
    
    if (!officerName.trim()) {
      newErrors.officerName = 'Officer name is required';
    }
    
    if (!agencyName.trim()) {
      newErrors.agencyName = 'Agency name is required';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (validateForm()) {
      onComplete(officerName.trim(), agencyName.trim());
    }
  };

  return (
    <div className="first-time-setup">
      <div className="setup-container">
        <div className="setup-header">
          <div className="logo">
            <h1 className="logo-text">HINDSIGHT</h1>
            <p className="logo-subtitle">Digital Forensic Triage Platform</p>
          </div>
        </div>

        <div className="setup-content">
          <h2>Welcome to Datapilot Scout</h2>
          <p className="setup-description">
            Before you begin, please provide your information. This will be used for report generation and case documentation.
          </p>

          <form onSubmit={handleSubmit} className="setup-form">
            <div className="form-group">
              <label htmlFor="officerName">Officer Name *</label>
              <input
                type="text"
                id="officerName"
                value={officerName}
                onChange={(e) => setOfficerName(e.target.value)}
                className={errors.officerName ? 'error' : ''}
                placeholder="Enter your full name"
                autoFocus
              />
              {errors.officerName && (
                <span className="error-message">{errors.officerName}</span>
              )}
            </div>

            <div className="form-group">
              <label htmlFor="agencyName">Agency Name *</label>
              <input
                type="text"
                id="agencyName"
                value={agencyName}
                onChange={(e) => setAgencyName(e.target.value)}
                className={errors.agencyName ? 'error' : ''}
                placeholder="Enter your agency or department name"
              />
              {errors.agencyName && (
                <span className="error-message">{errors.agencyName}</span>
              )}
            </div>

            <div className="form-info">
              <p>
                📋 This information will appear on all generated reports and can be updated later in Settings.
              </p>
            </div>

            <div className="form-actions">
              <Button 
                type="submit" 
                variant="primary" 
                size="lg"
                glow
              >
                Continue to Hindsight
              </Button>
            </div>
          </form>
        </div>

        <div className="setup-footer">
          <p>Datapilot Scout v1.0 • Law Enforcement Digital Triage Tool</p>
        </div>
      </div>
    </div>
  );
};
