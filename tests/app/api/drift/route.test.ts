import { describe, it, expect, jest, beforeEach } from '@jest/globals';

// Mock fs before importing route
jest.mock('fs', () => ({
  readFileSync: jest.fn(),
}));

// Mock ansible-parser
jest.mock('@/lib/ansible-parser', () => ({
  parseInventory: jest.fn(),
}));

// Mock neo4j-driver
jest.mock('neo4j-driver', () => {
  const mockNeo4j = {
    driver: jest.fn(() => ({
      session: jest.fn(),
      close: jest.fn(() => Promise.resolve()),
    })),
    auth: { basic: jest.fn(() => ({ scheme: 'basic' })) },
  };
  return { __esModule: true, default: mockNeo4j, ...mockNeo4j };
});

const mockRun = jest.fn();
jest.mock('@/lib/neo4j', () => ({
  getSession: jest.fn(() => ({
    run: mockRun,
    close: jest.fn(() => Promise.resolve()),
  })),
}));

jest.mock('next/server', () => ({
  NextResponse: {
    json: jest.fn((data: unknown, init?: { status?: number }) => ({
      status: init?.status ?? 200,
      json: async () => data,
    })),
  },
}));

import { GET } from '@/app/api/drift/route';
import { readFileSync } from 'fs';
import { parseInventory } from '@/lib/ansible-parser';

const mockReadFileSync = readFileSync as jest.MockedFunction<typeof readFileSync>;
const mockParseInventory = parseInventory as jest.MockedFunction<typeof parseInventory>;

const makeAssetRecord = (name: string, ip: string, zone: string) => ({
  get: (key: string) => {
    if (key === 'name') { return name; }
    if (key === 'ip') { return ip; }
    if (key === 'zone') { return zone; }
    return null;
  },
});

const inventoryHosts = [
  { name: 'web-srv', ip: '10.10.1.10', zone: 'dmz' },
  { name: 'app-srv', ip: '10.10.2.10', zone: 'app-tier' },
  { name: 'db-srv', ip: '10.10.3.10', zone: 'db-tier' },
];

describe('GET /api/drift', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockReadFileSync.mockReturnValue('mocked-yaml-content' as unknown as Buffer);
    mockParseInventory.mockReturnValue(inventoryHosts);
  });

  describe('response shape', () => {
    it('returns driftItems array and summary object', async () => {
      mockRun.mockResolvedValueOnce({
        records: inventoryHosts.map((h) => makeAssetRecord(h.name, h.ip, h.zone)),
      });

      const response = await GET();
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data).toHaveProperty('driftItems');
      expect(data).toHaveProperty('summary');
      expect(Array.isArray(data.driftItems)).toBe(true);
    });

    it('summary has totalInventory, totalGraph, inSync, drifted', async () => {
      mockRun.mockResolvedValueOnce({
        records: inventoryHosts.map((h) => makeAssetRecord(h.name, h.ip, h.zone)),
      });

      const response = await GET();
      const data = await response.json();

      expect(data.summary).toHaveProperty('totalInventory');
      expect(data.summary).toHaveProperty('totalGraph');
      expect(data.summary).toHaveProperty('inSync');
      expect(data.summary).toHaveProperty('drifted');
      expect(typeof data.summary.totalInventory).toBe('number');
      expect(typeof data.summary.totalGraph).toBe('number');
      expect(typeof data.summary.inSync).toBe('number');
      expect(typeof data.summary.drifted).toBe('number');
    });

    it('driftItems have name, type, inventoryValue, graphValue fields', async () => {
      mockRun.mockResolvedValueOnce({
        records: inventoryHosts.map((h) => makeAssetRecord(h.name, h.ip, h.zone)),
      });

      const response = await GET();
      const data = await response.json();

      for (const item of data.driftItems) {
        expect(item).toHaveProperty('name');
        expect(item).toHaveProperty('type');
        expect(item).toHaveProperty('inventoryValue');
        expect(item).toHaveProperty('graphValue');
      }
    });
  });

  describe('in_sync detection', () => {
    it('marks all hosts as in_sync when inventory and graph match exactly', async () => {
      mockRun.mockResolvedValueOnce({
        records: inventoryHosts.map((h) => makeAssetRecord(h.name, h.ip, h.zone)),
      });

      const response = await GET();
      const data = await response.json();

      expect(data.summary.inSync).toBe(3);
      expect(data.summary.drifted).toBe(0);
      const types = data.driftItems.map((i: { type: string }) => i.type);
      expect(types.every((t: string) => t === 'in_sync')).toBe(true);
    });

    it('summary totalInventory equals number of inventory hosts', async () => {
      mockRun.mockResolvedValueOnce({
        records: inventoryHosts.map((h) => makeAssetRecord(h.name, h.ip, h.zone)),
      });

      const response = await GET();
      const data = await response.json();

      expect(data.summary.totalInventory).toBe(3);
    });

    it('summary totalGraph equals number of neo4j assets', async () => {
      mockRun.mockResolvedValueOnce({
        records: inventoryHosts.map((h) => makeAssetRecord(h.name, h.ip, h.zone)),
      });

      const response = await GET();
      const data = await response.json();

      expect(data.summary.totalGraph).toBe(3);
    });
  });

  describe('missing_from_graph detection', () => {
    it('identifies host in inventory but not in graph', async () => {
      mockRun.mockResolvedValueOnce({
        records: [
          makeAssetRecord('web-srv', '10.10.1.10', 'dmz'),
          makeAssetRecord('app-srv', '10.10.2.10', 'app-tier'),
          // db-srv is missing from graph
        ],
      });

      const response = await GET();
      const data = await response.json();

      const missing = data.driftItems.find(
        (i: { name: string; type: string }) => i.name === 'db-srv' && i.type === 'missing_from_graph',
      );
      expect(missing).toBeDefined();
    });

    it('missing_from_graph item has inventoryValue set and graphValue empty', async () => {
      mockRun.mockResolvedValueOnce({
        records: [makeAssetRecord('web-srv', '10.10.1.10', 'dmz')],
      });

      const response = await GET();
      const data = await response.json();

      const missingItems = data.driftItems.filter(
        (i: { type: string }) => i.type === 'missing_from_graph',
      );
      expect(missingItems.length).toBeGreaterThan(0);
      for (const item of missingItems) {
        expect(item.inventoryValue).toBeTruthy();
        expect(item.graphValue).toBe('');
      }
    });
  });

  describe('missing_from_inventory detection', () => {
    it('identifies asset in graph but not in inventory', async () => {
      mockRun.mockResolvedValueOnce({
        records: [
          ...inventoryHosts.map((h) => makeAssetRecord(h.name, h.ip, h.zone)),
          makeAssetRecord('ghost-srv', '10.99.0.1', 'unknown'),
        ],
      });

      const response = await GET();
      const data = await response.json();

      const ghost = data.driftItems.find(
        (i: { name: string; type: string }) =>
          i.name === 'ghost-srv' && i.type === 'missing_from_inventory',
      );
      expect(ghost).toBeDefined();
    });

    it('missing_from_inventory item has graphValue set and inventoryValue empty', async () => {
      mockRun.mockResolvedValueOnce({
        records: [
          ...inventoryHosts.map((h) => makeAssetRecord(h.name, h.ip, h.zone)),
          makeAssetRecord('ghost-srv', '10.99.0.1', 'unknown'),
        ],
      });

      const response = await GET();
      const data = await response.json();

      const ghostItem = data.driftItems.find(
        (i: { name: string }) => i.name === 'ghost-srv',
      );
      expect(ghostItem.graphValue).toBeTruthy();
      expect(ghostItem.inventoryValue).toBe('');
    });
  });

  describe('ip_mismatch detection', () => {
    it('identifies hosts with same name but different ip', async () => {
      mockRun.mockResolvedValueOnce({
        records: [
          makeAssetRecord('web-srv', '10.10.9.99', 'dmz'), // wrong ip
          makeAssetRecord('app-srv', '10.10.2.10', 'app-tier'),
          makeAssetRecord('db-srv', '10.10.3.10', 'db-tier'),
        ],
      });

      const response = await GET();
      const data = await response.json();

      const mismatch = data.driftItems.find(
        (i: { name: string; type: string }) =>
          i.name === 'web-srv' && i.type === 'ip_mismatch',
      );
      expect(mismatch).toBeDefined();
      expect(mismatch.inventoryValue).toBe('10.10.1.10');
      expect(mismatch.graphValue).toBe('10.10.9.99');
    });
  });

  describe('zone_mismatch detection', () => {
    it('identifies hosts with same name but different zone', async () => {
      mockRun.mockResolvedValueOnce({
        records: [
          makeAssetRecord('web-srv', '10.10.1.10', 'wrong-zone'), // wrong zone
          makeAssetRecord('app-srv', '10.10.2.10', 'app-tier'),
          makeAssetRecord('db-srv', '10.10.3.10', 'db-tier'),
        ],
      });

      const response = await GET();
      const data = await response.json();

      const mismatch = data.driftItems.find(
        (i: { name: string; type: string }) =>
          i.name === 'web-srv' && i.type === 'zone_mismatch',
      );
      expect(mismatch).toBeDefined();
      expect(mismatch.inventoryValue).toBe('dmz');
      expect(mismatch.graphValue).toBe('wrong-zone');
    });
  });

  describe('drifted count', () => {
    it('counts drifted correctly for mixed scenario', async () => {
      mockParseInventory.mockReturnValue([
        { name: 'web-srv', ip: '10.10.1.10', zone: 'dmz' },
        { name: 'app-srv', ip: '10.10.2.10', zone: 'app-tier' },
        { name: 'missing-host', ip: '10.99.0.5', zone: 'dmz' },
      ]);
      mockRun.mockResolvedValueOnce({
        records: [
          makeAssetRecord('web-srv', '10.10.1.10', 'dmz'), // in_sync
          makeAssetRecord('app-srv', '10.10.9.99', 'app-tier'), // ip_mismatch
          makeAssetRecord('extra-srv', '10.50.0.1', 'edge'), // missing_from_inventory
        ],
      });

      const response = await GET();
      const data = await response.json();

      // web-srv: in_sync
      // app-srv: ip_mismatch (drifted)
      // missing-host: missing_from_graph (drifted)
      // extra-srv: missing_from_inventory (drifted)
      expect(data.summary.inSync).toBe(1);
      expect(data.summary.drifted).toBe(3);
    });
  });

  describe('error handling', () => {
    it('returns 500 when hosts.yml cannot be read', async () => {
      mockReadFileSync.mockImplementation(() => {
        throw new Error('ENOENT: no such file or directory');
      });

      const response = await GET();
      expect(response.status).toBe(500);
      const data = await response.json();
      expect(data).toHaveProperty('error');
    });

    it('returns 500 when Neo4j query fails', async () => {
      mockRun.mockRejectedValueOnce(new Error('Neo4j connection refused'));

      const response = await GET();
      expect(response.status).toBe(500);
      const data = await response.json();
      expect(data).toHaveProperty('error');
    });
  });
});
