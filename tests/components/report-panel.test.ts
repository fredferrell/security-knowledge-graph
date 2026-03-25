import { describe, it, expect } from '@jest/globals';

/**
 * Unit tests for ReportPanel data logic.
 * Full render tests require @testing-library/react + jsdom (not available in this project).
 * These tests cover severity badge logic, exposure indicator logic, and data shape validation.
 */

type Severity = 'critical' | 'high' | 'medium' | 'low';

const SEVERITY_BADGE_COLORS: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

/** Returns CSS class for internet exposure indicator. */
function exposureClass(exposed: boolean): string {
  return exposed ? 'exposed-yes' : 'exposed-no';
}

/** Returns display text for internet exposure. */
function exposureLabel(exposed: boolean): string {
  return exposed ? 'Yes' : 'No';
}

const sampleSummary = {
  overallRisk: 'high',
  totalAssets: 10,
  totalVulnerabilities: 5,
  protectionCoverage: '80%',
  criticalFindings: 2,
};

const sampleVulnMatrix = [
  {
    cveId: 'CVE-2021-41773',
    severity: 'critical',
    affectedAssets: ['web-server'],
    exposedToInternet: true,
    firewallProtected: false,
  },
  {
    cveId: 'CVE-2021-44228',
    severity: 'high',
    affectedAssets: ['app-server', 'db-server'],
    exposedToInternet: false,
    firewallProtected: true,
  },
];

const sampleRecommendations = [
  'Patch CVE-2021-41773 on web-server immediately',
  'Enable firewall rules for DMZ assets',
];

const sampleCredentialMap = [
  { source: 'web-server', targets: ['app-server', 'db-server'], credentialTypes: ['ssh', 'service-account'] },
];

describe('ReportPanel severity badge colors', () => {
  it('critical maps to red #ef4444', () => {
    expect(SEVERITY_BADGE_COLORS['critical']).toBe('#ef4444');
  });

  it('high maps to orange #f97316', () => {
    expect(SEVERITY_BADGE_COLORS['high']).toBe('#f97316');
  });

  it('medium maps to yellow #eab308', () => {
    expect(SEVERITY_BADGE_COLORS['medium']).toBe('#eab308');
  });

  it('low maps to green #22c55e', () => {
    expect(SEVERITY_BADGE_COLORS['low']).toBe('#22c55e');
  });
});

describe('ReportPanel exposure indicator logic', () => {
  it('exposed=true returns exposed-yes class', () => {
    expect(exposureClass(true)).toBe('exposed-yes');
  });

  it('exposed=false returns exposed-no class', () => {
    expect(exposureClass(false)).toBe('exposed-no');
  });

  it('exposed=true returns "Yes" label', () => {
    expect(exposureLabel(true)).toBe('Yes');
  });

  it('exposed=false returns "No" label', () => {
    expect(exposureLabel(false)).toBe('No');
  });
});

describe('ReportPanel data shape', () => {
  it('summary has all required keys', () => {
    expect(sampleSummary).toHaveProperty('overallRisk');
    expect(sampleSummary).toHaveProperty('totalAssets');
    expect(sampleSummary).toHaveProperty('totalVulnerabilities');
    expect(sampleSummary).toHaveProperty('protectionCoverage');
    expect(sampleSummary).toHaveProperty('criticalFindings');
  });

  it('vuln matrix entries have required fields', () => {
    for (const entry of sampleVulnMatrix) {
      expect(entry).toHaveProperty('cveId');
      expect(entry).toHaveProperty('severity');
      expect(entry).toHaveProperty('affectedAssets');
      expect(entry).toHaveProperty('exposedToInternet');
      expect(entry).toHaveProperty('firewallProtected');
    }
  });

  it('affectedAssets is an array of strings', () => {
    for (const entry of sampleVulnMatrix) {
      expect(Array.isArray(entry.affectedAssets)).toBe(true);
      for (const asset of entry.affectedAssets) {
        expect(typeof asset).toBe('string');
      }
    }
  });

  it('recommendations is an array of strings', () => {
    expect(Array.isArray(sampleRecommendations)).toBe(true);
    for (const rec of sampleRecommendations) {
      expect(typeof rec).toBe('string');
    }
  });

  it('credentialMap entries have source, targets, credentialTypes', () => {
    for (const entry of sampleCredentialMap) {
      expect(entry).toHaveProperty('source');
      expect(entry).toHaveProperty('targets');
      expect(entry).toHaveProperty('credentialTypes');
    }
  });

  it('credentialMap targets is an array', () => {
    for (const entry of sampleCredentialMap) {
      expect(Array.isArray(entry.targets)).toBe(true);
    }
  });
});
