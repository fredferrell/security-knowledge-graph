'use client';

import { useState } from 'react';

interface ReportPanelProps {
  results: {
    generatedAt: string;
    summary: {
      overallRisk: string;
      totalAssets: number;
      totalVulnerabilities: number;
      protectionCoverage: string;
      criticalFindings: number;
    };
    vulnerabilityMatrix: {
      cveId: string;
      severity: string;
      affectedAssets: string[];
      exposedToInternet: boolean;
      firewallProtected: boolean;
    }[];
    recommendations: string[];
    credentialMap: { source: string; targets: string[]; credentialTypes: string[] }[];
  } | null;
  isLoading: boolean;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

/** Badge for CVE severity. */
function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity] ?? '#94a3b8';
  return (
    <span className="risk-badge" style={{ backgroundColor: color }}>
      {severity.toUpperCase()}
    </span>
  );
}

/** Security posture report panel. */
export function ReportPanel({ results, isLoading }: ReportPanelProps) {
  const [expandedCred, setExpandedCred] = useState<number | null>(null);

  if (isLoading) {
    return <div className="report-panel"><p className="loading-text">Generating report...</p></div>;
  }

  if (results === null) {
    return null;
  }

  const { summary, vulnerabilityMatrix, recommendations, credentialMap } = results;

  return (
    <div className="report-panel">
      <div className="report-summary">
        <div className="summary-risk">
          <span className="summary-risk-label">Overall Risk</span>
          <span className="risk-badge" style={{ backgroundColor: SEVERITY_COLORS[summary.overallRisk] ?? '#94a3b8', fontSize: '0.9rem' }}>
            {summary.overallRisk.toUpperCase()}
          </span>
        </div>
        <div className="summary-stats">
          <span>Coverage: <strong>{summary.protectionCoverage}</strong></span>
          <span>Critical Findings: <strong style={{ color: '#ef4444' }}>{summary.criticalFindings}</strong></span>
        </div>
      </div>

      {vulnerabilityMatrix.length > 0 && (
        <div className="results-block">
          <h4>Vulnerability Matrix</h4>
          <table className="vuln-matrix">
            <thead>
              <tr>
                <th>CVE</th>
                <th>Severity</th>
                <th>Assets</th>
                <th>Internet</th>
                <th>FW</th>
              </tr>
            </thead>
            <tbody>
              {vulnerabilityMatrix.map((vuln, i) => (
                <tr key={vuln.cveId} className={`vuln-row ${i % 2 === 0 ? 'vuln-row-even' : 'vuln-row-odd'}`}>
                  <td className="vuln-cve">{vuln.cveId}</td>
                  <td><SeverityBadge severity={vuln.severity} /></td>
                  <td className="vuln-assets">{vuln.affectedAssets.join(', ')}</td>
                  <td className={vuln.exposedToInternet ? 'exposed-yes' : 'exposed-no'}>
                    {vuln.exposedToInternet ? 'Yes' : 'No'}
                  </td>
                  <td className={vuln.firewallProtected ? 'exposed-no' : 'exposed-yes'}>
                    {vuln.firewallProtected ? 'Yes' : 'No'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="results-block">
        <h4>Recommendations</h4>
        <ol className="recommendations-list">
          {recommendations.map((rec, i) => (
            <li key={i}>{rec}</li>
          ))}
        </ol>
      </div>

      {credentialMap.length > 0 && (
        <div className="results-block">
          <h4>Credential Map</h4>
          <div className="credential-map">
            {credentialMap.map((entry, i) => (
              <div key={entry.source} className="cred-entry">
                <button className="collapsible-header" onClick={() => setExpandedCred(expandedCred === i ? null : i)}>
                  {expandedCred === i ? '▾' : '▸'} {entry.source} → {entry.targets.length} target(s)
                </button>
                {expandedCred === i && (
                  <div className="cred-detail">
                    <p>Targets: {entry.targets.join(', ')}</p>
                    <p>Types: {entry.credentialTypes.join(', ')}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
