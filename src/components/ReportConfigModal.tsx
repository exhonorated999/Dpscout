import React, { useState } from 'react';
import { ReportScope, ReportFormat, ReportMetadata } from '../types/report';
import { AppSettings } from '../types/settings';
import './ReportConfigModal.css';

interface ReportConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onGenerate: (metadata: ReportMetadata, scope: ReportScope, formats: ReportFormat[]) => void;
  settings?: AppSettings;
}

export const ReportConfigModal: React.FC<ReportConfigModalProps> = ({
  isOpen,
  onClose,
  onGenerate,
  settings
}) => {
  const [caseNumber, setCaseNumber] = useState('');
  const [assignedDetective, setAssignedDetective] = useState('');
  const [scope, setScope] = useState<ReportScope>('flagged');
  const [generateDatapilot, setGenerateDatapilot] = useState(false);
  const [errors, setErrors] = useState<{ caseNumber?: string; detective?: string }>({});

  if (!isOpen) return null;

  const validateInputs = (): boolean => {
    const newErrors: { caseNumber?: string; detective?: string } = {};
    
    if (!caseNumber.trim()) {
      newErrors.caseNumber = 'Case number is required';
    }
    
    if (!assignedDetective.trim()) {
      newErrors.detective = 'Assigned detective is required';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleGenerate = () => {
    if (!validateInputs()) return;

    const metadata: ReportMetadata = {
      case_number: caseNumber.trim(),
      assigned_detective: assignedDetective.trim(),
      generated_date: new Date().toISOString(),
      officer_name: settings?.officer_name,
      agency_name: settings?.agency_name,
      generate_datapilot_file: generateDatapilot,
    };

    // Always generate PDF report
    const formats: ReportFormat[] = ['pdf'];

    onGenerate(metadata, scope, formats);
    handleClose();
  };

  const handleClose = () => {
    setCaseNumber('');
    setAssignedDetective('');
    setScope('flagged');
    setGenerateDatapilot(false);
    setErrors({});
    onClose();
  };

  return (
    <div className="report-modal-overlay" onClick={handleClose}>
      <div className="report-modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="report-modal-header">
          <h2 className="report-modal-title">GENERATE TRIAGE REPORT</h2>
          <button className="report-modal-close" onClick={handleClose}>✕</button>
        </div>

        <div className="report-modal-body">
          {/* Case Metadata */}
          <div className="report-section">
            <h3 className="report-section-title">CASE METADATA</h3>
            
            <div className="report-form-field">
              <label className="report-label">
                Case Number <span className="required">*</span>
              </label>
              <input
                type="text"
                className={`report-input ${errors.caseNumber ? 'error' : ''}`}
                placeholder="e.g., 2025-INV-12345"
                value={caseNumber}
                onChange={(e) => setCaseNumber(e.target.value)}
              />
              {errors.caseNumber && <span className="error-message">{errors.caseNumber}</span>}
            </div>

            <div className="report-form-field">
              <label className="report-label">
                Assigned Detective/Examiner <span className="required">*</span>
              </label>
              <input
                type="text"
                className={`report-input ${errors.detective ? 'error' : ''}`}
                placeholder="e.g., Det. John Smith"
                value={assignedDetective}
                onChange={(e) => setAssignedDetective(e.target.value)}
              />
              {errors.detective && <span className="error-message">{errors.detective}</span>}
            </div>
          </div>

          {/* Report Scope */}
          <div className="report-section">
            <h3 className="report-section-title">REPORT SCOPE</h3>
            
            <div className="report-radio-group">
              <label className="report-radio-option">
                <input
                  type="radio"
                  name="scope"
                  checked={scope === 'flagged'}
                  onChange={() => setScope('flagged')}
                />
                <div className="radio-content">
                  <span className="radio-label">Flagged Evidence Only</span>
                  <span className="radio-description">
                    Includes only items marked by the user across all dashboard views
                  </span>
                </div>
              </label>

              <label className="report-radio-option">
                <input
                  type="radio"
                  name="scope"
                  checked={scope === 'all'}
                  onChange={() => setScope('all')}
                />
                <div className="radio-content">
                  <span className="radio-label">Entire Triage Results</span>
                  <span className="radio-description">
                    Includes all data scanned by Datapilot Scout
                  </span>
                </div>
              </label>
            </div>
          </div>

          {/* Report Format - PDF Only */}
          <div className="report-section">
            <h3 className="report-section-title">REPORT FORMAT</h3>
            <div className="report-info-box">
              <span className="info-icon">📄</span>
              <span className="info-text">Report will be generated as a PDF document</span>
            </div>
          </div>

          {/* Datapilot Integration */}
          <div className="report-section">
            <h3 className="report-section-title">DATAPILOT INTEGRATION</h3>
            <label className="report-checkbox-option">
              <input
                type="checkbox"
                checked={generateDatapilot}
                onChange={(e) => setGenerateDatapilot(e.target.checked)}
              />
              <div className="checkbox-content">
                <span className="checkbox-label">Generate Datapilot Scan File</span>
                <span className="checkbox-description">
                  Creates a .txt file with SHA-256 hashes of all flagged evidence for import into Datapilot software
                </span>
              </div>
            </label>
          </div>
        </div>

        <div className="report-modal-footer">
          <button className="report-button cancel" onClick={handleClose}>
            CANCEL
          </button>
          <button className="report-button generate" onClick={handleGenerate}>
            GENERATE REPORT
          </button>
        </div>
      </div>
    </div>
  );
};
