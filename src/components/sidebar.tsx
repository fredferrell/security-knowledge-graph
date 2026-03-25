'use client';

import { useState } from 'react';

interface AffectedAsset {
  name: string;
  ip: string;
  zone: string;
}

interface FirewallRuleResult {
  firewall: string;
  name: string;
  sourceZone: string;
  destZone: string;
  action: string;
}

interface BlastResults {
  cve: string;
  affectedAssets: AffectedAsset[];
  exposurePaths: string[][];
  firewallRules: FirewallRuleResult[];
}

interface VulnerableAsset {
  name: string;
  zone: string;
  cveId: string;
  severity: string;
  hasGap: boolean;
}

interface GapSummary {
  totalVulnerabilities: number;
  assetsWithGaps: number;
  coveredAssets: number;
}

interface GapResults {
  vulnerableAssets: VulnerableAsset[];
  summary: GapSummary;
}

interface SidebarProps {
  onBlastRadius: (cveId: string) => void;
  onGapAnalysis: () => void;
  onReset: () => void;
  blastResults: BlastResults | null;
  gapResults: GapResults | null;
}

/** Sidebar with query controls and results panels for blast radius and gap analysis. */
export function Sidebar({ onBlastRadius, onGapAnalysis, onReset, blastResults, gapResults }: SidebarProps) {
  const [cveId, setCveId] = useState('CVE-2021-41773');

  const handleBlastRadius = () => {
    onBlastRadius(cveId);
  };

  return (
    <aside className="sidebar">
      <h2 className="sidebar-title">Security Analysis</h2>

      <div className="control-group">
        <label htmlFor="cve-input" className="control-label">
          CVE ID
        </label>
        <input
          id="cve-input"
          type="text"
          className="cve-input"
          value={cveId}
          onChange={(e) => setCveId(e.target.value)}
          placeholder="CVE-YYYY-NNNNN"
        />
      </div>

      <div className="button-group">
        <button className="btn btn-primary" onClick={handleBlastRadius}>
          Blast Radius
        </button>
        <button className="btn btn-primary" onClick={onGapAnalysis}>
          Gap Analysis
        </button>
        <button className="btn btn-secondary" onClick={onReset}>
          Reset
        </button>
      </div>

      {blastResults !== null && (
        <div className="results-section">
          <h3 className="results-title">Blast Radius: {blastResults.cve}</h3>

          <div className="results-block">
            <h4>Affected Assets ({blastResults.affectedAssets.length})</h4>
            <ul className="asset-list">
              {blastResults.affectedAssets.map((asset) => (
                <li key={asset.ip} className="asset-item">
                  <span className="asset-name">{asset.name}</span>
                  <span className="asset-meta">
                    {asset.ip} — {asset.zone}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          {blastResults.exposurePaths.length > 0 && (
            <div className="results-block">
              <h4>Exposure Paths</h4>
              <ul className="path-list">
                {blastResults.exposurePaths.map((path, i) => (
                  <li key={i} className="path-item">
                    {path.join(' → ')}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {blastResults.firewallRules.length > 0 && (
            <div className="results-block">
              <h4>Firewall Rules ({blastResults.firewallRules.length})</h4>
              <ul className="rule-list">
                {blastResults.firewallRules.map((rule, i) => (
                  <li key={i} className={`rule-item rule-${rule.action}`}>
                    <span className="rule-name">{rule.name}</span>
                    <span className="rule-meta">
                      {rule.sourceZone} → {rule.destZone} ({rule.action})
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {gapResults !== null && (
        <div className="results-section">
          <h3 className="results-title">Gap Analysis</h3>

          <div className="results-block summary-block">
            <p>Total vulnerabilities: <strong>{gapResults.summary.totalVulnerabilities}</strong></p>
            <p className="gap-warning">Assets with gaps: <strong>{gapResults.summary.assetsWithGaps}</strong></p>
            <p>Covered assets: <strong>{gapResults.summary.coveredAssets}</strong></p>
          </div>

          <div className="results-block">
            <h4>Vulnerable Assets</h4>
            <ul className="asset-list">
              {gapResults.vulnerableAssets.map((asset, i) => (
                <li key={i} className={`asset-item ${asset.hasGap ? 'gap-warning' : ''}`}>
                  <span className="asset-name">{asset.name}</span>
                  <span className="asset-meta">
                    {asset.cveId} — {asset.severity}
                    {asset.hasGap ? ' ⚠ NO DENY RULE' : ''}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </aside>
  );
}
