import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './LoginScreen.css';

interface User {
  username: string;
}

interface LoginScreenProps {
  onLoginSuccess: (user: User) => void;
  onReset: () => void;
}

export const LoginScreen: React.FC<LoginScreenProps> = ({ onLoginSuccess, onReset }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    setError('');

    if (!username.trim() || !password) {
      setError('Please enter username and password');
      return;
    }

    setLoading(true);

    try {
      const user = await invoke<User>('login_user', { username, password });
      onLoginSuccess(user);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };



  return (
    <div className="login-screen">
      <div className="login-container">
        <div className="login-header">
          <h1>
            <span className="brand-datapilot">DATAPILOT</span>
            {' '}
            <span className="brand-scout">SCOUT</span>
          </h1>
          <p className="login-subtitle">Digital Forensic Triage Platform</p>
        </div>

        <div className="login-card">
          <h2>🔒 USB-Secured Access</h2>
          <p className="login-description">
            Enter your credentials to access the application.<br/>
            <small>This USB drive must match your registered device.</small>
          </p>

          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              disabled={loading}
              autoFocus
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              disabled={loading}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !loading) {
                  handleLogin();
                }
              }}
            />
          </div>

          {error && (
            <div className="error-message">
              ⚠️ {error}
            </div>
          )}

          <button
            className="login-button"
            onClick={handleLogin}
            disabled={loading}
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>

          <div className="login-footer">
            <small className="recovery-hint">
              Forgot your password? Use the master recovery password to regain access,<br/>
              then change your password in Settings.
            </small>
          </div>
        </div>
      </div>
    </div>
  );
};
