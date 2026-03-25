import { describe, it, expect, jest, beforeEach } from '@jest/globals';

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

import { GET } from '@/app/api/blast-radius/route';
import { NextRequest } from 'next/server';

const makeRequest = (cve?: string): NextRequest => {
  const url = cve
    ? `http://localhost/api/blast-radius?cve=${cve}`
    : 'http://localhost/api/blast-radius';
  return { url, nextUrl: new URL(url) } as unknown as NextRequest;
};

const makeAssetRecord = (name: string, ip: string, zone: string) => ({
  get: (key: string) => {
    if (key === 'assetName') { return name; }
    if (key === 'assetIp') { return ip; }
    if (key === 'assetZone') { return zone; }
    return null;
  },
});

const makePathRecord = (path: string[]) => ({
  get: (key: string) => {
    if (key === 'path') { return path; }
    return null;
  },
});

const makeRuleRecord = (rule: Record<string, string>) => ({
  get: (key: string) => rule[key] ?? null,
});

describe('GET /api/blast-radius', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns 400 when cve query param is missing', async () => {
    const req = makeRequest();
    const response = await GET(req);
    expect(response.status).toBe(400);
    const data = await response.json();
    expect(data).toHaveProperty('error');
  });

  it('returns correct response shape with cve, affectedAssets, exposurePaths, firewallRules', async () => {
    mockRun
      .mockResolvedValueOnce({
        records: [makeAssetRecord('web-server', '10.0.1.10', 'dmz')],
      })
      .mockResolvedValueOnce({
        records: [makePathRecord(['edge-rtr', 'web-server'])],
      })
      .mockResolvedValueOnce({
        records: [
          makeRuleRecord({
            firewall: 'fw-01',
            name: 'deny-dmz',
            sourceZone: 'internet',
            destZone: 'dmz',
            action: 'deny',
          }),
        ],
      });

    const req = makeRequest('CVE-2024-001');
    const response = await GET(req);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toHaveProperty('cve', 'CVE-2024-001');
    expect(data).toHaveProperty('affectedAssets');
    expect(data).toHaveProperty('exposurePaths');
    expect(data).toHaveProperty('firewallRules');
    expect(Array.isArray(data.affectedAssets)).toBe(true);
    expect(Array.isArray(data.exposurePaths)).toBe(true);
    expect(Array.isArray(data.firewallRules)).toBe(true);
  });

  it('affectedAssets items have name, ip, zone fields', async () => {
    mockRun
      .mockResolvedValueOnce({
        records: [makeAssetRecord('db-server', '10.0.2.10', 'internal')],
      })
      .mockResolvedValueOnce({ records: [] })
      .mockResolvedValueOnce({ records: [] });

    const req = makeRequest('CVE-2024-002');
    const response = await GET(req);
    const data = await response.json();

    expect(data.affectedAssets).toHaveLength(1);
    const asset = data.affectedAssets[0];
    expect(asset).toHaveProperty('name', 'db-server');
    expect(asset).toHaveProperty('ip', '10.0.2.10');
    expect(asset).toHaveProperty('zone', 'internal');
  });

  it('returns empty arrays when no assets are affected', async () => {
    mockRun
      .mockResolvedValueOnce({ records: [] })
      .mockResolvedValueOnce({ records: [] })
      .mockResolvedValueOnce({ records: [] });

    const req = makeRequest('CVE-2024-999');
    const response = await GET(req);
    const data = await response.json();

    expect(data.affectedAssets).toHaveLength(0);
    expect(data.exposurePaths).toHaveLength(0);
    expect(data.firewallRules).toHaveLength(0);
  });

  it('firewallRules items have expected shape', async () => {
    mockRun
      .mockResolvedValueOnce({ records: [] })
      .mockResolvedValueOnce({ records: [] })
      .mockResolvedValueOnce({
        records: [
          makeRuleRecord({
            firewall: 'fw-01',
            name: 'block-all',
            sourceZone: 'internet',
            destZone: 'dmz',
            action: 'deny',
          }),
        ],
      });

    const req = makeRequest('CVE-2024-003');
    const response = await GET(req);
    const data = await response.json();

    const rule = data.firewallRules[0];
    expect(rule).toHaveProperty('firewall');
    expect(rule).toHaveProperty('name');
    expect(rule).toHaveProperty('sourceZone');
    expect(rule).toHaveProperty('destZone');
    expect(rule).toHaveProperty('action');
  });
});
