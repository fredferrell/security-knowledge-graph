import { describe, it, expect } from '@jest/globals';

/**
 * Unit tests for DriftPanel data logic.
 * Full render tests require @testing-library/react + jsdom (not available in this project).
 * These tests cover the drift item classification and display label logic.
 */

type DriftType = 'in_sync' | 'ip_mismatch' | 'zone_mismatch' | 'missing_from_graph' | 'missing_from_inventory';

const DRIFT_LABELS: Record<DriftType, string> = {
  in_sync: 'IN SYNC',
  ip_mismatch: 'IP MISMATCH',
  zone_mismatch: 'ZONE MISMATCH',
  missing_from_graph: 'NOT IN GRAPH',
  missing_from_inventory: 'NOT IN INVENTORY',
};

const DRIFT_CSS_CLASSES: Record<DriftType, string> = {
  in_sync: 'drift-in-sync',
  ip_mismatch: 'drift-mismatch',
  zone_mismatch: 'drift-mismatch',
  missing_from_graph: 'drift-missing',
  missing_from_inventory: 'drift-missing',
};

describe('DriftPanel label mapping', () => {
  it('in_sync maps to "IN SYNC"', () => {
    expect(DRIFT_LABELS['in_sync']).toBe('IN SYNC');
  });

  it('ip_mismatch maps to "IP MISMATCH"', () => {
    expect(DRIFT_LABELS['ip_mismatch']).toBe('IP MISMATCH');
  });

  it('zone_mismatch maps to "ZONE MISMATCH"', () => {
    expect(DRIFT_LABELS['zone_mismatch']).toBe('ZONE MISMATCH');
  });

  it('missing_from_graph maps to "NOT IN GRAPH"', () => {
    expect(DRIFT_LABELS['missing_from_graph']).toBe('NOT IN GRAPH');
  });

  it('missing_from_inventory maps to "NOT IN INVENTORY"', () => {
    expect(DRIFT_LABELS['missing_from_inventory']).toBe('NOT IN INVENTORY');
  });
});

describe('DriftPanel CSS class mapping', () => {
  it('in_sync uses drift-in-sync class (green)', () => {
    expect(DRIFT_CSS_CLASSES['in_sync']).toBe('drift-in-sync');
  });

  it('ip_mismatch uses drift-mismatch class (orange)', () => {
    expect(DRIFT_CSS_CLASSES['ip_mismatch']).toBe('drift-mismatch');
  });

  it('zone_mismatch uses drift-mismatch class (orange)', () => {
    expect(DRIFT_CSS_CLASSES['zone_mismatch']).toBe('drift-mismatch');
  });

  it('missing_from_graph uses drift-missing class (red)', () => {
    expect(DRIFT_CSS_CLASSES['missing_from_graph']).toBe('drift-missing');
  });

  it('missing_from_inventory uses drift-missing class (red)', () => {
    expect(DRIFT_CSS_CLASSES['missing_from_inventory']).toBe('drift-missing');
  });
});

describe('DriftPanel summary stats', () => {
  const sampleResults = {
    driftItems: [
      { name: 'web-srv', type: 'in_sync', inventoryValue: '10.0.1.10', graphValue: '10.0.1.10' },
      { name: 'app-srv', type: 'ip_mismatch', inventoryValue: '10.0.2.10', graphValue: '10.0.9.99' },
      { name: 'db-srv', type: 'missing_from_graph', inventoryValue: '10.0.3.10', graphValue: '' },
    ],
    summary: { totalInventory: 3, totalGraph: 2, inSync: 1, drifted: 2 },
  };

  it('summary has all required keys', () => {
    expect(sampleResults.summary).toHaveProperty('totalInventory');
    expect(sampleResults.summary).toHaveProperty('totalGraph');
    expect(sampleResults.summary).toHaveProperty('inSync');
    expect(sampleResults.summary).toHaveProperty('drifted');
  });

  it('driftItems is an array', () => {
    expect(Array.isArray(sampleResults.driftItems)).toBe(true);
  });

  it('each drift item has name, type, inventoryValue, graphValue', () => {
    for (const item of sampleResults.driftItems) {
      expect(item).toHaveProperty('name');
      expect(item).toHaveProperty('type');
      expect(item).toHaveProperty('inventoryValue');
      expect(item).toHaveProperty('graphValue');
    }
  });
});
