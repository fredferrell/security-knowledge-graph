'use client';

import { useState } from 'react';

interface AnalyticsPanelProps {
  results: {
    assets: { name: string; zone: string; riskScore: number; riskLevel: string; metrics: Record<string, number> }[];
    topRisks: { name: string; riskScore: number; riskLevel: string; primaryReason: string }[];
    networkStats: {
      totalAssets: number;
      totalVulnerabilities: number;
      totalTrafficFlows: number;
      totalCredentials: number;
      averageRiskScore: number;
    };
  } | null;
  isLoading: boolean;
}

const RISK_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

/** Badge component for risk level display. */
function RiskBadge({ level }: { level: string }) {
  const color = RISK_COLORS[level] ?? '#94a3b8';
  return (
    <span className="risk-badge" style={{ backgroundColor: color }}>
      {level.toUpperCase()}
    </span>
  );
}

/** Analytics panel showing risk scoring results. */
export function AnalyticsPanel({ results, isLoading }: AnalyticsPanelProps) {
  const [assetListOpen, setAssetListOpen] = useState(false);

  if (isLoading) {
    return <div className="analytics-panel"><p className="loading-text">Analyzing risk...</p></div>;
  }

  if (results === null) {
    return null;
  }

  const { networkStats, topRisks, assets } = results;
  const sortedAssets = [...assets].sort((a, b) => b.riskScore - a.riskScore);

  return (
    <div className="analytics-panel">
      <div className="network-stats">
        <div className="stat-card">
          <span className="stat-value">{networkStats.totalAssets}</span>
          <span className="stat-label">Assets</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{networkStats.totalVulnerabilities}</span>
          <span className="stat-label">Vulns</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{networkStats.totalTrafficFlows}</span>
          <span className="stat-label">Flows</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{networkStats.totalCredentials}</span>
          <span className="stat-label">Creds</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{networkStats.averageRiskScore.toFixed(1)}</span>
          <span className="stat-label">Avg Risk</span>
        </div>
      </div>

      <div className="results-block">
        <h4>Top Risks</h4>
        {topRisks.map((risk, i) => (
          <div key={risk.name} className="risk-item">
            <span className="risk-rank">#{i + 1}</span>
            <span className="risk-name">{risk.name}</span>
            <RiskBadge level={risk.riskLevel} />
            <span className="risk-score">{risk.riskScore.toFixed(1)}</span>
            <span className="risk-reason">{risk.primaryReason}</span>
          </div>
        ))}
      </div>

      <div className="results-block">
        <button className="collapsible-header" onClick={() => setAssetListOpen((v) => !v)}>
          {assetListOpen ? '▾' : '▸'} All Assets ({sortedAssets.length})
        </button>
        {assetListOpen && (
          <ul className="asset-list">
            {sortedAssets.map((asset) => (
              <li key={asset.name} className="asset-item">
                <span className="asset-name">{asset.name}</span>
                <span className="asset-meta">{asset.zone}</span>
                <RiskBadge level={asset.riskLevel} />
                <span className="risk-score">{asset.riskScore.toFixed(1)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
