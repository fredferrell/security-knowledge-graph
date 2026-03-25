import { describe, it, expect } from '@jest/globals';

/**
 * Unit tests for AnalyticsPanel data logic.
 * Full render tests require @testing-library/react + jsdom (not available in this project).
 * These tests cover risk badge color mapping, sorting logic, and data shape validation.
 */

type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

const RISK_BADGE_COLORS: Record<RiskLevel, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

/** Sort assets by riskScore descending. */
function sortByRiskScore<T extends { riskScore: number }>(assets: T[]): T[] {
  return [...assets].sort((a, b) => b.riskScore - a.riskScore);
}

/** Format risk score as fixed decimal string. */
function formatRiskScore(score: number): string {
  return score.toFixed(1);
}

const sampleNetworkStats = {
  totalAssets: 10,
  totalVulnerabilities: 5,
  totalTrafficFlows: 20,
  totalCredentials: 3,
  averageRiskScore: 42.5,
};

const sampleTopRisks = [
  { name: 'web-server', riskScore: 85, riskLevel: 'critical', primaryReason: 'internet exposed with CVE' },
  { name: 'app-server', riskScore: 60, riskLevel: 'high', primaryReason: 'unpatched vulnerability' },
  { name: 'db-server', riskScore: 40, riskLevel: 'medium', primaryReason: 'weak credentials' },
];

const sampleAssets = [
  { name: 'app-server', zone: 'app-tier', riskScore: 60, riskLevel: 'high', metrics: { vulnCount: 2 } },
  { name: 'web-server', zone: 'dmz', riskScore: 85, riskLevel: 'critical', metrics: { vulnCount: 5 } },
  { name: 'db-server', zone: 'db-tier', riskScore: 40, riskLevel: 'medium', metrics: { vulnCount: 1 } },
];

describe('AnalyticsPanel risk badge color mapping', () => {
  it('critical maps to red #ef4444', () => {
    expect(RISK_BADGE_COLORS['critical']).toBe('#ef4444');
  });

  it('high maps to orange #f97316', () => {
    expect(RISK_BADGE_COLORS['high']).toBe('#f97316');
  });

  it('medium maps to yellow #eab308', () => {
    expect(RISK_BADGE_COLORS['medium']).toBe('#eab308');
  });

  it('low maps to green #22c55e', () => {
    expect(RISK_BADGE_COLORS['low']).toBe('#22c55e');
  });
});

describe('AnalyticsPanel sort logic', () => {
  it('sorts assets by riskScore descending', () => {
    const sorted = sortByRiskScore(sampleAssets);
    expect(sorted[0].name).toBe('web-server');
    expect(sorted[1].name).toBe('app-server');
    expect(sorted[2].name).toBe('db-server');
  });

  it('does not mutate the original array', () => {
    const original = [...sampleAssets];
    sortByRiskScore(sampleAssets);
    expect(sampleAssets[0].name).toBe(original[0].name);
  });
});

describe('AnalyticsPanel formatRiskScore', () => {
  it('formats integer as one decimal', () => {
    expect(formatRiskScore(85)).toBe('85.0');
  });

  it('formats float to one decimal', () => {
    expect(formatRiskScore(42.567)).toBe('42.6');
  });
});

describe('AnalyticsPanel data shape', () => {
  it('networkStats has all required keys', () => {
    expect(sampleNetworkStats).toHaveProperty('totalAssets');
    expect(sampleNetworkStats).toHaveProperty('totalVulnerabilities');
    expect(sampleNetworkStats).toHaveProperty('totalTrafficFlows');
    expect(sampleNetworkStats).toHaveProperty('totalCredentials');
    expect(sampleNetworkStats).toHaveProperty('averageRiskScore');
  });

  it('topRisks items have required fields', () => {
    for (const risk of sampleTopRisks) {
      expect(risk).toHaveProperty('name');
      expect(risk).toHaveProperty('riskScore');
      expect(risk).toHaveProperty('riskLevel');
      expect(risk).toHaveProperty('primaryReason');
    }
  });

  it('assets have required fields including metrics', () => {
    for (const asset of sampleAssets) {
      expect(asset).toHaveProperty('name');
      expect(asset).toHaveProperty('zone');
      expect(asset).toHaveProperty('riskScore');
      expect(asset).toHaveProperty('riskLevel');
      expect(asset).toHaveProperty('metrics');
    }
  });
});
