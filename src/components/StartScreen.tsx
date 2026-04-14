import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Button } from './Button';
import './StartScreen.css';

export type DeviceType = 'windows' | 'usb' | 'android' | 'ios';

const IS_PORTABLE = import.meta.env.VITE_PORTABLE === 'true';

interface StartScreenProps {
  onBeginScan: (deviceType: DeviceType) => void;
  onOpenSettings: () => void;
}

interface TrialStatus {
  is_trial: boolean;
  is_expired: boolean;
  registered_at: string | null;
  expires_at: string | null;
  days_remaining: number;
}

// Cyberpunk-styled device icons
const WindowsIcon = () => (
  <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
    <rect x="8" y="8" width="32" height="32" stroke="#6c8aed" strokeWidth="2" rx="2"/>
    <line x1="24" y1="8" x2="24" y2="40" stroke="#6c8aed" strokeWidth="2"/>
    <line x1="8" y1="24" x2="40" y2="24" stroke="#6c8aed" strokeWidth="2"/>
    <circle cx="16" cy="16" r="2" fill="#FFA05C"/>
    <circle cx="32" cy="16" r="2" fill="#FFA05C"/>
    <circle cx="16" cy="32" r="2" fill="#FFA05C"/>
    <circle cx="32" cy="32" r="2" fill="#FFA05C"/>
  </svg>
);

const USBIcon = () => (
  <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
    <rect x="12" y="16" width="24" height="20" stroke="#6c8aed" strokeWidth="2" rx="2"/>
    <rect x="18" y="10" width="12" height="6" fill="#6c8aed" rx="1"/>
    <line x1="20" y1="22" x2="28" y2="22" stroke="#FFA05C" strokeWidth="2"/>
    <line x1="20" y1="27" x2="28" y2="27" stroke="#FFA05C" strokeWidth="2"/>
    <circle cx="24" cy="31" r="2" fill="#FFA05C"/>
  </svg>
);

const AndroidIcon = () => (
  <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
    <rect x="10" y="16" width="28" height="24" stroke="#6c8aed" strokeWidth="2" rx="3"/>
    <line x1="18" y1="12" x2="16" y2="8" stroke="#6c8aed" strokeWidth="2" strokeLinecap="round"/>
    <line x1="30" y1="12" x2="32" y2="8" stroke="#6c8aed" strokeWidth="2" strokeLinecap="round"/>
    <circle cx="20" cy="24" r="2" fill="#FFA05C"/>
    <circle cx="28" cy="24" r="2" fill="#FFA05C"/>
    <line x1="16" y1="32" x2="32" y2="32" stroke="#FFA05C" strokeWidth="2" strokeLinecap="round"/>
  </svg>
);

const AppleIcon = () => (
  <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
    {/* Apple body - rounded apple shape */}
    <path 
      d="M24 38C30 38 35 33 35 27C35 23 33 19 30 17C29 16 27 15 25 15C23 15 21 16 20 17C17 19 15 23 15 27C15 33 20 38 24 38Z" 
      stroke="#6c8aed" 
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    {/* Leaf on top */}
    <path 
      d="M26 15C26 15 27 12 29 11C30 10 31 10 32 11C33 12 33 14 32 16C31 17 29 18 28 18" 
      stroke="#6c8aed" 
      strokeWidth="2" 
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    {/* Stem */}
    <line 
      x1="25" 
      y1="15" 
      x2="25" 
      y2="11" 
      stroke="#6c8aed" 
      strokeWidth="2" 
      strokeLinecap="round"
    />
    {/* Apple bite - accent color */}
    <circle cx="30" cy="24" r="3.5" fill="#1a1f3a" stroke="#FFA05C" strokeWidth="2"/>
    {/* Inner highlight circles */}
    <circle cx="20" cy="25" r="1.5" fill="#FFA05C"/>
    <circle cx="24" cy="30" r="1" fill="#FFA05C"/>
  </svg>
);

export const StartScreen: React.FC<StartScreenProps> = ({ onBeginScan, onOpenSettings }) => {
  const [selectedDevice, setSelectedDevice] = useState<DeviceType>('windows');
  const [trialStatus, setTrialStatus] = useState<TrialStatus | null>(null);

  useEffect(() => {
    loadTrialStatus();
  }, []);

  const loadTrialStatus = async () => {
    try {
      const status = await invoke<TrialStatus>('get_trial_status');
      setTrialStatus(status);
    } catch (error) {
      console.error('Failed to load trial status:', error);
    }
  };
  
  const handleStartScan = () => {
    onBeginScan(selectedDevice);
  };

  return (
    <div className="start-screen">
      {/* Trial Badge - Top Left */}
      {trialStatus?.is_trial && (
        <div className="trial-badge">
          <div className="trial-badge-icon">🎯</div>
          <div className="trial-badge-content">
            <div className="trial-badge-title">DEMO VERSION</div>
            <div className="trial-badge-days">{trialStatus.days_remaining} days remaining</div>
            <div className="trial-badge-contact">Contact: scout@datapilot.com</div>
          </div>
        </div>
      )}

      <button className="settings-button-float" onClick={onOpenSettings} title="Settings">
        ⚙️
      </button>
      <div className="start-screen-content">
        <div className="logo-container">
          <div className="header-logo">
            <div className="logo-dots">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="dot" />
              ))}
            </div>
            <div className="logo-text">
              <div className="logo-datapilot">DATAPILOT</div>
              <div className="logo-scout">SCOUT</div>
              {IS_PORTABLE && <div className="logo-portable-badge" style={{fontSize:'0.6rem',color:'#ffb74d',letterSpacing:'0.15em',marginTop:'0.1rem'}}>PORTABLE</div>}
            </div>
          </div>
          <div className="powered-by">
            <span className="powered-text">POWERED BY</span>
            <span className="powered-project">PROJECT HINDSIGHT</span>
          </div>
        </div>
        
        <div className="device-selector-panel">
          <h2>SELECT DEVICE TYPE</h2>
          <p className="selector-description">Choose the type of device you want to scan for forensic triage</p>
          
          <div className="device-options">
            <label className={`device-option ${selectedDevice === 'windows' ? 'selected' : ''}`}>
              <input
                type="radio"
                name="deviceType"
                value="windows"
                checked={selectedDevice === 'windows'}
                onChange={(e) => setSelectedDevice(e.target.value as DeviceType)}
              />
              <div className="device-card">
                <div className="device-icon">
                  <WindowsIcon />
                </div>
                <span className="device-name">Windows Computer</span>
                <span className="device-description">Desktop or laptop running Windows OS</span>
              </div>
            </label>

            <label className={`device-option ${selectedDevice === 'usb' ? 'selected' : ''}`}>
              <input
                type="radio"
                name="deviceType"
                value="usb"
                checked={selectedDevice === 'usb'}
                onChange={(e) => setSelectedDevice(e.target.value as DeviceType)}
              />
              <div className="device-card">
                <div className="device-icon">
                  <USBIcon />
                </div>
                <span className="device-name">USB Drive</span>
                <span className="device-description">External storage device or thumb drive</span>
              </div>
            </label>

            {!IS_PORTABLE && (
            <label className={`device-option ${selectedDevice === 'android' ? 'selected' : ''}`}>
              <input
                type="radio"
                name="deviceType"
                value="android"
                checked={selectedDevice === 'android'}
                onChange={(e) => setSelectedDevice(e.target.value as DeviceType)}
              />
              <div className="device-card">
                <div className="device-icon">
                  <AndroidIcon />
                </div>
                <span className="device-name">Android Device</span>
                <span className="device-description">Smartphone or tablet with USB debugging</span>
              </div>
            </label>
            )}

            {/* iOS Device option temporarily disabled — will be re-enabled in a future update */}
          </div>
        </div>

        <Button 
          variant="primary" 
          size="lg" 
          glow 
          onClick={handleStartScan}
          className="begin-scan-button"
        >
          <span className="scan-icon">▶</span> Begin Triage Scan
        </Button>

        <div className="system-info">
          <span className="system-info-item">Forensic triage scan will analyze the selected device type</span>
        </div>
      </div>
    </div>
  );
};
