import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './RegistrationScreen.css';
import { useOfflineHost, OfflineHostNotice } from './OfflineHostNotice';

interface RegistrationScreenProps {
  onRegistrationComplete: () => void;
  /**
   * Non-fatal startup error to surface above the form. When data directories
   * cannot be created, registration will very likely fail to persist too, so
   * showing the real cause here beats letting the user guess.
   */
  initError?: string | null;
  /**
   * Render just the card, without the full-screen background and wordmark,
   * so the same form can be embedded in Settings as a recovery path for
   * anyone who was never shown the first-run screen.
   */
  embedded?: boolean;
}

interface RegisterResponse {
  success: boolean;
  agency_id?: number;
  trial_expires_at?: string;
  trial_days?: number;
  message?: string;
}

export const RegistrationScreen: React.FC<RegistrationScreenProps> = ({ onRegistrationComplete, initError = null, embedded = false }) => {
  const [agencyName, setAgencyName] = useState('');
  const [contactName, setContactName] = useState('');
  const [contactEmail, setContactEmail] = useState('');
  const [agencyAddress, setAgencyAddress] = useState('');
  const [city, setCity] = useState('');
  const [stateName, setStateName] = useState('');
  const [zipCode, setZipCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const offline = useOfflineHost();

  const handleRegister = async () => {
    setError('');

    if (!agencyName.trim()) {
      setError('Agency name is required');
      return;
    }
    if (!contactName.trim()) {
      setError('Contact name is required');
      return;
    }
    if (!contactEmail.trim() || !contactEmail.includes('@')) {
      setError('Valid email address is required');
      return;
    }

    setLoading(true);

    try {
      const response = await invoke<RegisterResponse>('register_agency', {
        data: {
          agency_name: agencyName.trim(),
          contact_name: contactName.trim(),
          contact_email: contactEmail.trim(),
          agency_address: agencyAddress.trim() || null,
          city: city.trim() || null,
          state: stateName.trim() || null,
          zip_code: zipCode.trim() || null,
        }
      });

      if (response.success) {
        onRegistrationComplete();
      } else {
        setError(response.message || 'Registration failed');
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const card = (
    <div className="registration-card">
      <h2>Agency Registration</h2>
          <p className="registration-description">
            Register your agency to begin your <strong>30-day free trial</strong>.<br/>
            A license key can be entered in Settings after registration.
          </p>

          <div className="form-row">
            <div className="form-group">
              <label htmlFor="agencyName">Agency Name *</label>
              <input
                id="agencyName"
                type="text"
                value={agencyName}
                onChange={(e) => setAgencyName(e.target.value)}
                placeholder="e.g. Springfield Police Department"
                disabled={loading}
                autoFocus
              />
            </div>
          </div>

          <div className="form-row two-col">
            <div className="form-group">
              <label htmlFor="contactName">Contact Name *</label>
              <input
                id="contactName"
                type="text"
                value={contactName}
                onChange={(e) => setContactName(e.target.value)}
                placeholder="Full name"
                disabled={loading}
              />
            </div>
            <div className="form-group">
              <label htmlFor="contactEmail">Agency Email *</label>
              <input
                id="contactEmail"
                type="email"
                value={contactEmail}
                onChange={(e) => setContactEmail(e.target.value)}
                placeholder="contact@agency.gov"
                disabled={loading}
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label htmlFor="agencyAddress">Street Address</label>
              <input
                id="agencyAddress"
                type="text"
                value={agencyAddress}
                onChange={(e) => setAgencyAddress(e.target.value)}
                placeholder="123 Main St"
                disabled={loading}
              />
            </div>
          </div>

          <div className="form-row three-col">
            <div className="form-group">
              <label htmlFor="city">City</label>
              <input
                id="city"
                type="text"
                value={city}
                onChange={(e) => setCity(e.target.value)}
                placeholder="City"
                disabled={loading}
              />
            </div>
            <div className="form-group">
              <label htmlFor="stateName">State</label>
              <input
                id="stateName"
                type="text"
                value={stateName}
                onChange={(e) => setStateName(e.target.value)}
                placeholder="State"
                disabled={loading}
                maxLength={2}
              />
            </div>
            <div className="form-group">
              <label htmlFor="zipCode">Zip Code</label>
              <input
                id="zipCode"
                type="text"
                value={zipCode}
                onChange={(e) => setZipCode(e.target.value)}
                placeholder="Zip"
                disabled={loading}
                maxLength={10}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !loading) handleRegister();
                }}
              />
            </div>
          </div>

          {offline && (
            <OfflineHostNotice what="register on Windows">
              The Mac edition never connects to the internet. Plug this stick
              into a Windows computer, run Scout Portable there to register,
              then bring it back to the Mac.
            </OfflineHostNotice>
          )}

          {initError && (
            <div className="error-message">
              ⚠️ Scout could not create its data folder: {initError}
              <br />
              Registration may not save until this is resolved. Try running
              Scout as Administrator, or check that antivirus is not blocking
              it.
            </div>
          )}

          {error && (
            <div className="error-message">
              ⚠️ {error}
            </div>
          )}

          <button
            className="register-button"
            onClick={handleRegister}
            disabled={loading}
          >
            {loading ? 'Registering...' : 'Register & Start Trial'}
          </button>

          <div className="security-notice">
            <strong>ℹ️ Trial Information:</strong>
            <ul>
              <li><strong>30-Day Trial:</strong> Full access to all features for 30 days</li>
              <li><strong>License Required:</strong> Purchase a license key to continue after trial</li>
              <li><strong>Enter Key in Settings:</strong> Go to Settings → License to activate</li>
              <li><strong>Machine Bound:</strong> License is tied to this computer</li>
            </ul>
          </div>
    </div>
  );

  // Embedded in Settings — the caller supplies its own heading and chrome.
  if (embedded) {
    return card;
  }

  return (
    <div className="registration-screen">
      <div className="registration-container">
        <div className="registration-header">
          <h1>
            <span className="brand-datapilot">DATAPILOT</span>
            {' '}
            <span className="brand-scout">SCOUT</span>
          </h1>
          <p className="registration-subtitle">Digital Forensic Triage Platform</p>
        </div>

        {card}
      </div>
    </div>
  );
};
