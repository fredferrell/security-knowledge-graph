'use client';

import { useState } from 'react';

interface ZeroDayFormProps {
  onSimulate: (data: {
    cveId: string;
    severity: string;
    description: string;
    affectedSoftware: string;
    affectedVersion: string;
  }) => void;
  results: {
    vulnerability: Record<string, unknown>;
    affectedAssets: { name: string; ip: string; zone: string }[];
    exposurePaths: string[][];
  } | null;
  isLoading: boolean;
}

/** Form for simulating a zero-day vulnerability and displaying affected assets. */
export function ZeroDayForm({ onSimulate, results, isLoading }: ZeroDayFormProps) {
  const [cveId, setCveId] = useState('CVE-2024-99999');
  const [severity, setSeverity] = useState('critical');
  const [description, setDescription] = useState('Simulated zero-day RCE');
  const [affectedSoftware, setAffectedSoftware] = useState('apache2');
  const [affectedVersion, setAffectedVersion] = useState('2.4.x');
  const [expanded, setExpanded] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSimulate({ cveId, severity, description, affectedSoftware, affectedVersion });
  };

  return (
    <div className="zero-day-form">
      <button
        type="button"
        className="collapsible-header"
        onClick={() => setExpanded((prev) => !prev)}
      >
        Zero-Day Simulation {expanded ? '▲' : '▼'}
      </button>

      {expanded && (
        <form onSubmit={handleSubmit}>
          <div className="form-field">
            <label className="control-label">CVE ID</label>
            <input
              type="text"
              className="cve-input"
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              placeholder="CVE-YYYY-NNNNN"
            />
          </div>

          <div className="form-field">
            <label className="control-label">Severity</label>
            <select
              className="form-select"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
          </div>

          <div className="form-field">
            <label className="control-label">Description</label>
            <textarea
              className="form-textarea"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
            />
          </div>

          <div className="form-field">
            <label className="control-label">Affected Software</label>
            <input
              type="text"
              className="cve-input"
              value={affectedSoftware}
              onChange={(e) => setAffectedSoftware(e.target.value)}
            />
          </div>

          <div className="form-field">
            <label className="control-label">Affected Version</label>
            <input
              type="text"
              className="cve-input"
              value={affectedVersion}
              onChange={(e) => setAffectedVersion(e.target.value)}
            />
          </div>

          <button type="submit" className="btn btn-simulate" disabled={isLoading}>
            {isLoading ? 'Simulating...' : 'Simulate Zero-Day'}
          </button>
        </form>
      )}

      {results !== null && (
        <div className="results-section">
          <h4 className="results-title">Simulation Results</h4>

          <div className="results-block">
            <h4>Affected Assets ({results.affectedAssets.length})</h4>
            <ul className="asset-list">
              {results.affectedAssets.map((asset) => (
                <li key={asset.ip} className="asset-item">
                  <span className="asset-name">{asset.name}</span>
                  <span className="asset-meta">{asset.ip} — {asset.zone}</span>
                </li>
              ))}
            </ul>
          </div>

          {results.exposurePaths.length > 0 && (
            <div className="results-block">
              <h4>Exposure Paths</h4>
              <ul className="path-list">
                {results.exposurePaths.map((path, i) => (
                  <li key={i} className="path-item">{path.join(' → ')}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
