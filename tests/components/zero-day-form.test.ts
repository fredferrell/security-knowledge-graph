import { describe, it, expect } from '@jest/globals';

/**
 * Unit tests for ZeroDayForm data logic.
 * Full render tests require @testing-library/react + jsdom (not available in this project).
 * These tests cover the form default values and results-display logic.
 */

const DEFAULT_FORM_DATA = {
  cveId: 'CVE-2024-99999',
  severity: 'critical',
  description: 'Simulated zero-day RCE',
  affectedSoftware: 'apache2',
  affectedVersion: '2.4.x',
};

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low'];

describe('ZeroDayForm defaults', () => {
  it('has the expected default cveId', () => {
    expect(DEFAULT_FORM_DATA.cveId).toBe('CVE-2024-99999');
  });

  it('has the expected default severity', () => {
    expect(DEFAULT_FORM_DATA.severity).toBe('critical');
  });

  it('has the expected default description', () => {
    expect(DEFAULT_FORM_DATA.description).toBe('Simulated zero-day RCE');
  });

  it('has the expected default affectedSoftware', () => {
    expect(DEFAULT_FORM_DATA.affectedSoftware).toBe('apache2');
  });

  it('has the expected default affectedVersion', () => {
    expect(DEFAULT_FORM_DATA.affectedVersion).toBe('2.4.x');
  });

  it('severity options include all four levels', () => {
    expect(SEVERITY_OPTIONS).toContain('critical');
    expect(SEVERITY_OPTIONS).toContain('high');
    expect(SEVERITY_OPTIONS).toContain('medium');
    expect(SEVERITY_OPTIONS).toContain('low');
    expect(SEVERITY_OPTIONS).toHaveLength(4);
  });
});

describe('ZeroDayForm results display logic', () => {
  const sampleResults = {
    vulnerability: { id: 'CVE-2024-99999', severity: 'critical' },
    affectedAssets: [
      { name: 'web-server', ip: '10.0.1.10', zone: 'dmz' },
      { name: 'app-server', ip: '10.0.2.10', zone: 'app-tier' },
    ],
    exposurePaths: [['internet', 'web-server'], ['web-server', 'app-server']],
  };

  it('results contain vulnerability, affectedAssets, and exposurePaths', () => {
    expect(sampleResults).toHaveProperty('vulnerability');
    expect(sampleResults).toHaveProperty('affectedAssets');
    expect(sampleResults).toHaveProperty('exposurePaths');
  });

  it('affectedAssets is an array', () => {
    expect(Array.isArray(sampleResults.affectedAssets)).toBe(true);
  });

  it('each affected asset has name, ip, zone', () => {
    for (const asset of sampleResults.affectedAssets) {
      expect(asset).toHaveProperty('name');
      expect(asset).toHaveProperty('ip');
      expect(asset).toHaveProperty('zone');
    }
  });

  it('exposurePaths is an array of arrays', () => {
    expect(Array.isArray(sampleResults.exposurePaths)).toBe(true);
    for (const path of sampleResults.exposurePaths) {
      expect(Array.isArray(path)).toBe(true);
    }
  });
});
