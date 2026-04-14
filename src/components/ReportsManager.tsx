import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import './ReportsManager.css';

interface EncryptedReport {
  id: number;
  report_name: string;
  created_at: string;
}

interface DatapilotFile {
  filename: string;
  fullPath: string;
  caseNumber: string;
  dateGenerated: string;
  fileSize: number;
  fileSizeMb: number;
}

export const ReportsManager: React.FC = () => {
  const [reports, setReports] = useState<EncryptedReport[]>([]);
  const [datapilotFiles, setDatapilotFiles] = useState<DatapilotFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadData = async () => {
      console.log('ReportsManager: Starting to load data...');
      try {
        await loadReports();
        await loadDatapilotFiles();
      } catch (err) {
        console.error('ReportsManager: Fatal error during load:', err);
        setError(`Failed to initialize: ${err}`);
        setLoading(false);
      }
    };
    
    loadData();
  }, []);

  const loadReports = async () => {
    try {
      console.log('ReportsManager: Loading encrypted reports...');
      setLoading(true);
      setError(null);
      const reportsList = await invoke<EncryptedReport[]>('list_saved_reports');
      console.log('ReportsManager: Got reports:', reportsList);
      setReports(reportsList || []);
    } catch (err) {
      const errorMsg = `Failed to load encrypted reports: ${err}`;
      console.error('ReportsManager: Error loading reports:', err);
      setError(errorMsg);
      setReports([]); // Set empty array on error
    } finally {
      setLoading(false);
    }
  };

  const loadDatapilotFiles = async () => {
    try {
      console.log('ReportsManager: Loading Datapilot files...');
      const files = await invoke<DatapilotFile[]>('list_datapilot_files');
      console.log('ReportsManager: Got Datapilot files:', files);
      setDatapilotFiles(files || []);
    } catch (err) {
      console.error('ReportsManager: Error loading Datapilot files:', err);
      setDatapilotFiles([]); // Set empty array on error
    }
  };

  const handleOpenReport = async (report: EncryptedReport) => {
    const pwd = prompt('Enter password to decrypt and open report:');
    if (!pwd) return;

    try {
      await invoke('open_encrypted_report', { reportId: report.id, password: pwd });
    } catch (err) {
      alert(`Failed to open report: ${err}`);
      console.error('Error opening report:', err);
    }
  };

  const handleDeleteReport = async (report: EncryptedReport) => {
    if (!confirm(`Are you sure you want to delete "${report.report_name}"?\n\nThis action cannot be undone.`)) {
      return;
    }

    try {
      await invoke('delete_saved_report', { reportId: report.id });
      alert('Report deleted successfully');
      loadReports(); // Refresh list
    } catch (err) {
      alert(`Failed to delete report: ${err}`);
      console.error('Error deleting report:', err);
    }
  };

  const handleExportReport = async (report: EncryptedReport) => {
    const pwd = prompt('Enter password to decrypt report for export:');
    if (!pwd) return;

    const destination = prompt(
      `Enter destination path for ${report.report_name}:`,
      `C:\\Users\\Desktop\\${report.report_name}.pdf`
    );

    if (!destination) return;

    try {
      // Load and decrypt the PDF
      const pdfData = await invoke<number[]>('load_encrypted_pdf_report', { reportId: report.id, password: pwd });
      
      // Convert to Uint8Array
      const uint8Array = new Uint8Array(pdfData);
      
      // Create blob and download
      const blob = new Blob([uint8Array], { type: 'application/pdf' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.report_name}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      alert('Report exported successfully!');
    } catch (err) {
      alert(`Failed to export report: ${err}`);
      console.error('Error exporting report:', err);
    }
  };

  const formatFileSize = (bytes: number): string => {
    const mb = bytes / (1024 * 1024);
    return mb.toFixed(2);
  };

  const formatDate = (dateStr: string): string => {
    try {
      const date = new Date(dateStr);
      return date.toLocaleString();
    } catch {
      return dateStr;
    }
  };

  const handleOpenDatapilotFile = async (file: DatapilotFile) => {
    try {
      await invoke('open_file_location', { path: file.fullPath });
    } catch (err) {
      alert(`Failed to open file location: ${err}`);
      console.error('Error opening location:', err);
    }
  };

  const handleViewDatapilotFile = async (file: DatapilotFile) => {
    try {
      // Open the file with default text editor
      await invoke('open_pdf_file', { filePath: file.fullPath });
    } catch (err) {
      alert(`Failed to open file: ${err}`);
      console.error('Error viewing file:', err);
    }
  };

  const handleDeleteDatapilotFile = async (file: DatapilotFile) => {
    if (!confirm(`Are you sure you want to delete "${file.filename}"?\n\nThis action cannot be undone.`)) {
      return;
    }

    try {
      await invoke('delete_report', { filePath: file.fullPath });
      alert('Datapilot hash list deleted successfully');
      loadDatapilotFiles(); // Refresh list
    } catch (err) {
      alert(`Failed to delete file: ${err}`);
      console.error('Error deleting file:', err);
    }
  };

  // Wrap rendering in error boundary
  try {
    return (
      <div className="reports-manager">
        <div className="reports-header">
          <h2>📄 Encrypted Reports</h2>
          <p className="reports-description">
            View and manage encrypted reports generated during scans. All reports are stored securely 
            in an encrypted database and can only be accessed with your password after authentication.
          </p>
          <div className="security-notice">
            <span className="security-icon">🔒</span>
            <strong>Security:</strong> Reports are encrypted using AES-256 and stored in your secure database.
            They remain protected even if the USB drive is lost or stolen.
          </div>
        </div>

        {loading && (
          <div className="loading-state">
            <div className="spinner"></div>
            <p>Loading encrypted reports...</p>
          </div>
        )}

        {error && (
          <div className="error-state">
            <p>⚠️ {error}</p>
            <button onClick={loadReports}>Retry</button>
          </div>
        )}

      {!loading && !error && reports.length === 0 && (
        <div className="empty-state">
          <p>📭 No encrypted reports yet</p>
          <p className="hint">Reports will appear here after you generate them from scan results.</p>
          <p className="hint">Click "Generate Report" from the scan results screen to create your first report.</p>
        </div>
      )}

      {!loading && !error && reports.length > 0 && (
        <div className="reports-list">
          <div className="reports-count">
            {reports.length} encrypted report{reports.length !== 1 ? 's' : ''} found
          </div>

          <table className="reports-table">
            <thead>
              <tr>
                <th>Report Name</th>
                <th>Date Generated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <tr key={report.id}>
                  <td className="case-number">{report.report_name}</td>
                  <td className="date">{formatDate(report.created_at)}</td>
                  <td className="actions">
                    <button
                      onClick={() => handleOpenReport(report)}
                      className="btn-action btn-open"
                      title="Decrypt and open in PDF viewer"
                    >
                      📖 Open
                    </button>
                    <button
                      onClick={() => handleExportReport(report)}
                      className="btn-action btn-export"
                      title="Decrypt and export to file"
                    >
                      💾 Export
                    </button>
                    <button
                      onClick={() => handleDeleteReport(report)}
                      className="btn-action btn-delete"
                      title="Delete encrypted report"
                    >
                      🗑️ Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="reports-footer">
        <button onClick={loadReports} className="btn-refresh">
          🔄 Refresh Encrypted Reports
        </button>
      </div>

      {/* Datapilot Hash List Files Section */}
      <div className="datapilot-section">
        <div className="section-header">
          <h2>📊 Datapilot Hash Lists</h2>
          <p className="section-description">
            SHA-256 hash lists of flagged evidence for import into Datapilot Desktop software for data recovery.
            These files are plain text (.txt) containing one hash per line.
          </p>
        </div>

        {datapilotFiles.length === 0 ? (
          <div className="empty-state">
            <p>No Datapilot hash lists found.</p>
            <p className="hint">
              Generate a Datapilot hash list when creating a report by checking 
              "Generate Datapilot Scan File" option.
            </p>
          </div>
        ) : (
          <div className="datapilot-list">
            <table className="datapilot-table">
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Case Number</th>
                  <th>Date Generated</th>
                  <th>Size</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {datapilotFiles.map((file, idx) => (
                  <tr key={idx}>
                    <td className="filename">{file.filename || 'Unknown'}</td>
                    <td className="case-number">{file.caseNumber || 'N/A'}</td>
                    <td className="date">{file.dateGenerated ? formatDate(file.dateGenerated) : 'N/A'}</td>
                    <td className="size">{file.fileSizeMb ? file.fileSizeMb.toFixed(2) : '0.00'} MB</td>
                    <td className="actions">
                      <button
                        onClick={() => handleOpenDatapilotFile(file)}
                        className="btn-action btn-open"
                        title="Open file location"
                      >
                        📁 Open Location
                      </button>
                      <button
                        onClick={() => handleViewDatapilotFile(file)}
                        className="btn-action btn-view"
                        title="View file contents"
                      >
                        👁️ View
                      </button>
                      <button
                        onClick={() => handleDeleteDatapilotFile(file)}
                        className="btn-action btn-delete"
                        title="Delete hash list"
                      >
                        🗑️ Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="datapilot-footer">
          <button onClick={loadDatapilotFiles} className="btn-refresh">
            🔄 Refresh Hash Lists
          </button>
        </div>
      </div>
    </div>
    );
  } catch (renderError) {
    console.error('ReportsManager: Render error:', renderError);
    return (
      <div className="reports-manager">
        <div className="error-state">
          <h2>⚠️ Error Loading Reports Page</h2>
          <p>An unexpected error occurred while loading the reports page.</p>
          <p className="error-details">{String(renderError)}</p>
          <button onClick={() => window.location.reload()}>Reload Application</button>
        </div>
      </div>
    );
  }
};
