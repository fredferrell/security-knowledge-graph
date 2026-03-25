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

import { GET } from '@/app/api/gaps/route';

const makeGapRecord = (props: {
  assetName: string;
  assetZone: string;
  cveId: string;
  severity: string;
  hasDenyRule: boolean;
}) => ({
  get: (key: string) => {
    if (key === 'assetName') { return props.assetName; }
    if (key === 'assetZone') { return props.assetZone; }
    if (key === 'cveId') { return props.cveId; }
    if (key === 'severity') { return props.severity; }
    if (key === 'hasDenyRule') { return props.hasDenyRule; }
    return null;
  },
});

describe('GET /api/gaps', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns correct response shape with vulnerableAssets and summary', async () => {
    mockRun.mockResolvedValueOnce({
      records: [
        makeGapRecord({ assetName: 'web-server', assetZone: 'dmz', cveId: 'CVE-2024-001', severity: 'critical', hasDenyRule: false }),
        makeGapRecord({ assetName: 'db-server', assetZone: 'internal', cveId: 'CVE-2024-002', severity: 'high', hasDenyRule: true }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toHaveProperty('vulnerableAssets');
    expect(data).toHaveProperty('summary');
    expect(Array.isArray(data.vulnerableAssets)).toBe(true);
  });

  it('summary has totalVulnerabilities, assetsWithGaps, coveredAssets', async () => {
    mockRun.mockResolvedValueOnce({
      records: [
        makeGapRecord({ assetName: 'web-server', assetZone: 'dmz', cveId: 'CVE-2024-001', severity: 'critical', hasDenyRule: false }),
        makeGapRecord({ assetName: 'db-server', assetZone: 'internal', cveId: 'CVE-2024-002', severity: 'high', hasDenyRule: true }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(data.summary).toHaveProperty('totalVulnerabilities');
    expect(data.summary).toHaveProperty('assetsWithGaps');
    expect(data.summary).toHaveProperty('coveredAssets');
    expect(typeof data.summary.totalVulnerabilities).toBe('number');
    expect(typeof data.summary.assetsWithGaps).toBe('number');
    expect(typeof data.summary.coveredAssets).toBe('number');
  });

  it('correctly counts gaps vs covered assets', async () => {
    mockRun.mockResolvedValueOnce({
      records: [
        makeGapRecord({ assetName: 'web-server', assetZone: 'dmz', cveId: 'CVE-2024-001', severity: 'critical', hasDenyRule: false }),
        makeGapRecord({ assetName: 'web-server', assetZone: 'dmz', cveId: 'CVE-2024-003', severity: 'medium', hasDenyRule: false }),
        makeGapRecord({ assetName: 'db-server', assetZone: 'internal', cveId: 'CVE-2024-002', severity: 'high', hasDenyRule: true }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    // 3 total vulnerability-asset relationships
    expect(data.summary.totalVulnerabilities).toBe(3);
    // web-server has no deny rule → gap; db-server has deny rule → covered
    expect(data.summary.assetsWithGaps).toBe(1);
    expect(data.summary.coveredAssets).toBe(1);
  });

  it('vulnerableAssets items have name, zone, cveId, severity, hasGap fields', async () => {
    mockRun.mockResolvedValueOnce({
      records: [
        makeGapRecord({ assetName: 'web-server', assetZone: 'dmz', cveId: 'CVE-2024-001', severity: 'critical', hasDenyRule: false }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(data.vulnerableAssets).toHaveLength(1);
    const asset = data.vulnerableAssets[0];
    expect(asset).toHaveProperty('name');
    expect(asset).toHaveProperty('zone');
    expect(asset).toHaveProperty('cveId');
    expect(asset).toHaveProperty('severity');
    expect(asset).toHaveProperty('hasGap');
    expect(asset.hasGap).toBe(true);
  });

  it('returns empty results when no vulnerabilities exist', async () => {
    mockRun.mockResolvedValueOnce({ records: [] });

    const response = await GET();
    const data = await response.json();

    expect(data.vulnerableAssets).toHaveLength(0);
    expect(data.summary.totalVulnerabilities).toBe(0);
    expect(data.summary.assetsWithGaps).toBe(0);
    expect(data.summary.coveredAssets).toBe(0);
  });
});
