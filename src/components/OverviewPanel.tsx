import { SystemInfo, formatBytes, formatTimestamp } from "../types/system";
import "./OverviewPanel.css";

interface OverviewPanelProps {
  systemInfo: SystemInfo | null;
  isLoading?: boolean;
}

export function OverviewPanel({ systemInfo, isLoading = false }: OverviewPanelProps) {
  if (isLoading) {
    return (
      <div className="overview-panel loading">
        <div className="loading-spinner"></div>
        <p>Collecting system information...</p>
      </div>
    );
  }

  if (!systemInfo) {
    return (
      <div className="overview-panel empty">
        <p>No system information available</p>
      </div>
    );
  }

  return (
    <div className="overview-panel">
      <div className="overview-header">
        <h2>System Identification</h2>
        <div className="scan-id">Scan ID: {systemInfo.scan_id.substring(0, 8)}</div>
      </div>

      <div className="overview-grid">
        {/* System Details Card */}
        <div className="info-card">
          <h3>System Details</h3>
          <div className="info-row">
            <span className="label">Computer Name:</span>
            <span className="value">{systemInfo.computer_name}</span>
          </div>
          <div className="info-row">
            <span className="label">Operating System:</span>
            <span className="value">{systemInfo.os_version}</span>
          </div>
          {systemInfo.domain && (
            <div className="info-row">
              <span className="label">Domain:</span>
              <span className="value">{systemInfo.domain}</span>
            </div>
          )}
          <div className="info-row">
            <span className="label">Scan Time:</span>
            <span className="value">{formatTimestamp(systemInfo.scan_timestamp)}</span>
          </div>
        </div>

        {/* User Accounts Card */}
        <div className="info-card">
          <h3>User Accounts ({systemInfo.user_accounts.length})</h3>
          <div className="accounts-list">
            {systemInfo.user_accounts.map((account, index) => (
              <div key={index} className="account-item">
                <div className="account-name">
                  <strong>{account.username}</strong>
                  {account.full_name && <span className="full-name"> ({account.full_name})</span>}
                </div>
                <div className="account-details">
                  <div className="account-type">{account.account_type}</div>
                  {account.last_login && (
                    <div className="last-login">Last Login: {account.last_login}</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Hardware Info Card */}
        <div className="info-card">
          <h3>Hardware Identification</h3>
          {systemInfo.hardware.system_uuid && (
            <div className="info-row">
              <span className="label">System UUID:</span>
              <span className="value mono">{systemInfo.hardware.system_uuid}</span>
            </div>
          )}
          {systemInfo.hardware.motherboard_serial && (
            <div className="info-row">
              <span className="label">Motherboard Serial:</span>
              <span className="value mono">{systemInfo.hardware.motherboard_serial}</span>
            </div>
          )}
          {systemInfo.hardware.bios_serial && (
            <div className="info-row">
              <span className="label">BIOS Serial:</span>
              <span className="value mono">{systemInfo.hardware.bios_serial}</span>
            </div>
          )}
          
          <h4>Storage Devices</h4>
          <div className="drives-list">
            {systemInfo.hardware.drives.map((drive, index) => (
              <div key={index} className="drive-item">
                <div className="drive-header">
                  <span className="drive-letter">{drive.letter}</span>
                  <span className="drive-label">{drive.label || "Unlabeled"}</span>
                </div>
                <div className="drive-details">
                  <div className="drive-serial">S/N: {drive.serial_number}</div>
                  <div className="drive-space">
                    {formatBytes(drive.free_space)} free / {formatBytes(drive.total_space)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Network Info Card */}
        <div className="info-card">
          <h3>Network Identification</h3>
          <div className="info-row">
            <span className="label">Hostname:</span>
            <span className="value">{systemInfo.network.hostname}</span>
          </div>
          
          {systemInfo.network.mac_addresses.length > 0 && (
            <>
              <h4>MAC Addresses</h4>
              <div className="mac-list">
                {systemInfo.network.mac_addresses.map((mac, index) => (
                  <div key={index} className="mac-item mono">{mac}</div>
                ))}
              </div>
            </>
          )}
          
          {systemInfo.network.ip_addresses.length > 0 && (
            <>
              <h4>IP Addresses</h4>
              <div className="ip-list">
                {systemInfo.network.ip_addresses.map((ip, index) => (
                  <div key={index} className="ip-item mono">{ip}</div>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Email Addresses Card */}
        {systemInfo.emails.length > 0 && (
          <div className="info-card">
            <h3>Email Addresses ({systemInfo.emails.length})</h3>
            <div className="emails-list">
              {systemInfo.emails.map((email, index) => (
                <div key={index} className="email-item">
                  {email}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* USB Device History Section */}
      {systemInfo.usb_history && systemInfo.usb_history.length > 0 && (
        <div className="usb-history-section">
          <h2>USB Device History</h2>
          <div className="usb-history-table">
            <table>
              <thead>
                <tr>
                  <th>Device Name</th>
                  <th>Vendor/Product ID</th>
                  <th>Serial Number</th>
                  <th>Friendly Name</th>
                </tr>
              </thead>
              <tbody>
                {systemInfo.usb_history.map((device, index) => {
                  const vendorProduct = [device.vendor_id, device.product_id]
                    .filter(Boolean)
                    .join(' / ') || 'N/A';
                  
                  return (
                    <tr key={index}>
                      <td>{device.device_name || 'Unknown Device'}</td>
                      <td className="mono">{vendorProduct}</td>
                      <td className="mono">{device.serial_number || 'N/A'}</td>
                      <td>{device.device_name || 'USB Device'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
