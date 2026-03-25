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

import { POST } from '@/app/api/simulate/zero-day/route';
import { NextRequest } from 'next/server';

const makeRequest = (body: unknown): NextRequest => {
  return {
    json: async () => body,
  } as unknown as NextRequest;
};

const makeVulnRecord = (props: {
  cveId: string;
  severity: string;
  description?: string;
  affectedSoftware: string;
  affectedVersion?: string;
}) => ({
  get: (key: string) => {
    if (key === 'cveId') { return props.cveId; }
    if (key === 'severity') { return props.severity; }
    if (key === 'description') { return props.description ?? ''; }
    if (key === 'affectedSoftware') { return props.affectedSoftware; }
    if (key === 'affectedVersion') { return props.affectedVersion ?? ''; }
    return null;
  },
});

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

const validBody = {
  cveId: 'CVE-2024-99999',
  severity: 'critical',
  description: 'Simulated Apache zero-day RCE',
  affectedSoftware: 'apache2',
  affectedVersion: '2.4.x',
};

describe('POST /api/simulate/zero-day', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns 400 when cveId is missing', async () => {
    const req = makeRequest({ severity: 'critical', affectedSoftware: 'apache2' });
    const response = await POST(req);
    expect(response.status).toBe(400);
    const data = await response.json();
    expect(data).toHaveProperty('error');
  });

  it('returns 400 when severity is missing', async () => {
    const req = makeRequest({ cveId: 'CVE-2024-99999', affectedSoftware: 'apache2' });
    const response = await POST(req);
    expect(response.status).toBe(400);
    const data = await response.json();
    expect(data).toHaveProperty('error');
  });

  it('returns 400 when affectedSoftware is missing', async () => {
    const req = makeRequest({ cveId: 'CVE-2024-99999', severity: 'critical' });
    const response = await POST(req);
    expect(response.status).toBe(400);
    const data = await response.json();
    expect(data).toHaveProperty('error');
  });

  it('returns 201 with vulnerability and affected assets on valid request', async () => {
    mockRun
      .mockResolvedValueOnce({
        records: [makeVulnRecord({ cveId: 'CVE-2024-99999', severity: 'critical', affectedSoftware: 'apache2' })],
      })
      .mockResolvedValueOnce({
        records: [makeAssetRecord('web-server', '10.0.1.10', 'dmz')],
      })
      .mockResolvedValueOnce({
        records: [makePathRecord(['edge-rtr', 'web-server'])],
      });

    const req = makeRequest(validBody);
    const response = await POST(req);
    expect(response.status).toBe(201);

    const data = await response.json();
    expect(data).toHaveProperty('vulnerability');
    expect(data).toHaveProperty('affectedAssets');
    expect(data).toHaveProperty('exposurePaths');
    expect(Array.isArray(data.affectedAssets)).toBe(true);
    expect(Array.isArray(data.exposurePaths)).toBe(true);
  });

  it('vulnerability in response has expected fields', async () => {
    mockRun
      .mockResolvedValueOnce({
        records: [makeVulnRecord({
          cveId: 'CVE-2024-99999',
          severity: 'critical',
          description: 'Simulated Apache zero-day RCE',
          affectedSoftware: 'apache2',
          affectedVersion: '2.4.x',
        })],
      })
      .mockResolvedValueOnce({ records: [] })
      .mockResolvedValueOnce({ records: [] });

    const req = makeRequest(validBody);
    const response = await POST(req);
    const data = await response.json();

    expect(data.vulnerability).toHaveProperty('cveId', 'CVE-2024-99999');
    expect(data.vulnerability).toHaveProperty('severity', 'critical');
    expect(data.vulnerability).toHaveProperty('affectedSoftware', 'apache2');
  });

  it('returns empty affectedAssets when no software matches', async () => {
    mockRun
      .mockResolvedValueOnce({
        records: [makeVulnRecord({ cveId: 'CVE-2024-99999', severity: 'critical', affectedSoftware: 'apache2' })],
      })
      .mockResolvedValueOnce({ records: [] })
      .mockResolvedValueOnce({ records: [] });

    const req = makeRequest(validBody);
    const response = await POST(req);
    const data = await response.json();

    expect(response.status).toBe(201);
    expect(data.affectedAssets).toHaveLength(0);
  });

  it('affectedAssets items have name, ip, zone fields', async () => {
    mockRun
      .mockResolvedValueOnce({
        records: [makeVulnRecord({ cveId: 'CVE-2024-99999', severity: 'critical', affectedSoftware: 'apache2' })],
      })
      .mockResolvedValueOnce({
        records: [makeAssetRecord('web-server', '10.0.1.10', 'dmz')],
      })
      .mockResolvedValueOnce({ records: [] });

    const req = makeRequest(validBody);
    const response = await POST(req);
    const data = await response.json();

    expect(data.affectedAssets).toHaveLength(1);
    const asset = data.affectedAssets[0];
    expect(asset).toHaveProperty('name', 'web-server');
    expect(asset).toHaveProperty('ip', '10.0.1.10');
    expect(asset).toHaveProperty('zone', 'dmz');
  });

  it('returns exposure paths from edge-rtr', async () => {
    mockRun
      .mockResolvedValueOnce({
        records: [makeVulnRecord({ cveId: 'CVE-2024-99999', severity: 'critical', affectedSoftware: 'apache2' })],
      })
      .mockResolvedValueOnce({
        records: [makeAssetRecord('web-server', '10.0.1.10', 'dmz')],
      })
      .mockResolvedValueOnce({
        records: [makePathRecord(['edge-rtr', 'dmz-sw', 'web-server'])],
      });

    const req = makeRequest(validBody);
    const response = await POST(req);
    const data = await response.json();

    expect(data.exposurePaths).toHaveLength(1);
    expect(data.exposurePaths[0]).toEqual(['edge-rtr', 'dmz-sw', 'web-server']);
  });
});
