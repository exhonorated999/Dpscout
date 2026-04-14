/**
 * Temporary debugging component for authentication issues
 * Add this to App.tsx to test authentication flow
 * 
 * Usage in App.tsx:
 * import { AuthDebugPanel } from './components/AuthDebugPanel';
 * 
 * // Add at the very top of the render, before any other logic:
 * return <AuthDebugPanel />;
 */

import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

export const AuthDebugPanel: React.FC = () => {
  const [result, setResult] = useState<string>('');
  const [loading, setLoading] = useState(false);

  const testRegistrationCheck = async () => {
    setLoading(true);
    setResult('');
    try {
      console.log('🔍 Testing check_is_registered command...');
      const isReg = await invoke<boolean>('check_is_registered');
      console.log('✅ Result:', isReg);
      setResult(`Is Registered: ${isReg}\n\nCheck the terminal for backend logs!`);
    } catch (error) {
      console.error('❌ Error:', error);
      setResult(`Error: ${String(error)}`);
    } finally {
      setLoading(false);
    }
  };

  const testRegistration = async () => {
    setLoading(true);
    setResult('');
    try {
      console.log('🔍 Testing register_new_user command...');
      await invoke('register_new_user', { 
        username: 'test_user', 
        password: 'test_password_123' 
      });
      console.log('✅ Registration successful');
      setResult('Registration successful! Now test login.');
    } catch (error) {
      console.error('❌ Error:', error);
      setResult(`Error: ${String(error)}`);
    } finally {
      setLoading(false);
    }
  };

  const testLogin = async () => {
    setLoading(true);
    setResult('');
    try {
      console.log('🔍 Testing login_user command...');
      const user = await invoke('login_user', { 
        username: 'test_user', 
        password: 'test_password_123' 
      });
      console.log('✅ Login successful:', user);
      setResult(`Login successful!\nUser: ${JSON.stringify(user, null, 2)}`);
    } catch (error) {
      console.error('❌ Error:', error);
      setResult(`Error: ${String(error)}`);
    } finally {
      setLoading(false);
    }
  };

  const testReset = async () => {
    if (!window.confirm('This will delete all registration data. Continue?')) {
      return;
    }
    setLoading(true);
    setResult('');
    try {
      console.log('🔍 Reset functionality disabled - use master password');
      // await invoke('reset_user_registration');
      console.log('✅ Reset disabled');
      setResult('Registration reset disabled. Use master password for recovery.');
    } catch (error) {
      console.error('❌ Error:', error);
      setResult(`Error: ${String(error)}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: '#1a1a2e',
      color: '#fff',
      padding: '40px',
      overflow: 'auto',
      zIndex: 9999
    }}>
      <div style={{ maxWidth: '800px', margin: '0 auto' }}>
        <h1 style={{ color: '#4ecca3', marginBottom: '10px' }}>
          🔍 Authentication Debug Panel
        </h1>
        <p style={{ color: '#888', marginBottom: '30px' }}>
          Temporary diagnostic tool - Remove after testing
        </p>

        <div style={{ display: 'flex', gap: '10px', marginBottom: '20px', flexWrap: 'wrap' }}>
          <button 
            onClick={testRegistrationCheck}
            disabled={loading}
            style={{
              padding: '12px 24px',
              background: '#4ecca3',
              border: 'none',
              borderRadius: '4px',
              color: '#000',
              fontWeight: 'bold',
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.5 : 1
            }}
          >
            1. Check If Registered
          </button>

          <button 
            onClick={testRegistration}
            disabled={loading}
            style={{
              padding: '12px 24px',
              background: '#3498db',
              border: 'none',
              borderRadius: '4px',
              color: '#fff',
              fontWeight: 'bold',
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.5 : 1
            }}
          >
            2. Register Test User
          </button>

          <button 
            onClick={testLogin}
            disabled={loading}
            style={{
              padding: '12px 24px',
              background: '#9b59b6',
              border: 'none',
              borderRadius: '4px',
              color: '#fff',
              fontWeight: 'bold',
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.5 : 1
            }}
          >
            3. Login Test User
          </button>

          <button 
            onClick={testReset}
            disabled={loading}
            style={{
              padding: '12px 24px',
              background: '#e74c3c',
              border: 'none',
              borderRadius: '4px',
              color: '#fff',
              fontWeight: 'bold',
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.5 : 1
            }}
          >
            Reset Registration
          </button>
        </div>

        {loading && (
          <div style={{ 
            padding: '20px', 
            background: '#2c3e50', 
            borderRadius: '4px',
            marginBottom: '20px'
          }}>
            Loading...
          </div>
        )}

        {result && (
          <div style={{ 
            padding: '20px', 
            background: '#2c3e50', 
            borderRadius: '4px',
            marginBottom: '20px',
            whiteSpace: 'pre-wrap',
            fontFamily: 'monospace'
          }}>
            {result}
          </div>
        )}

        <div style={{ 
          padding: '20px', 
          background: '#2c3e50', 
          borderRadius: '4px',
          marginTop: '30px'
        }}>
          <h3 style={{ color: '#4ecca3', marginBottom: '15px' }}>Instructions:</h3>
          <ol style={{ paddingLeft: '20px', lineHeight: '1.8' }}>
            <li>Click "Check If Registered" first</li>
            <li>Check the terminal output for backend logs</li>
            <li>Check browser console for frontend logs</li>
            <li>If it returns `true`, click "Reset Registration"</li>
            <li>Test the registration flow with "Register Test User"</li>
            <li>Test login with "Login Test User"</li>
          </ol>

          <h3 style={{ color: '#4ecca3', marginTop: '20px', marginBottom: '15px' }}>
            What to look for:
          </h3>
          <ul style={{ paddingLeft: '20px', lineHeight: '1.8' }}>
            <li><strong>Terminal output:</strong> Should show "REGISTRATION CHECK" logs</li>
            <li><strong>Database path:</strong> Note where it's looking for the .db file</li>
            <li><strong>Database exists:</strong> Should be `false` for first run</li>
            <li><strong>Result:</strong> Should be "NOT REGISTERED" if no database</li>
          </ul>

          <p style={{ 
            marginTop: '20px', 
            padding: '15px', 
            background: '#e74c3c33', 
            borderRadius: '4px',
            border: '1px solid #e74c3c'
          }}>
            <strong>⚠️ Remember:</strong> Remove this component after testing!<br/>
            This is only for debugging the authentication flow.
          </p>
        </div>
      </div>
    </div>
  );
};
