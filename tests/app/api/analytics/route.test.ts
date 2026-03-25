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

import { GET } from '@/app/api/analytics/route';

// Helper: make a neo4j-like record from a plain object
const makeRecord = (fields: Record<string, unknown>) => ({
  get: (key: string) => fields[key] ?? null,
});

// Integer helper (neo4j returns integers as objects with toNumber())
const neo4jInt = (n: number) => ({ toNumber: () => n, low: n });

// Build the 6 mock query results for a single asset scenario
// Query order: vulns, degree, credExposure, outbound, inbound, denyRules
const makeFullMockResults = (assets: Array<{
  name: string; zone: string; ip: string;
  vulnCount: number; criticalCount: number;
  degree: number; credentialExposure: number;
  outbound: number; inbound: number;
  hasDenyRule: boolean;
}>) => {
  const vulnRecords = assets.map(a =>
    makeRecord({ name: a.name, zone: a.zone, ip: a.ip, vulnCount: neo4jInt(a.vulnCount), criticalCount: neo4jInt(a.criticalCount) })
  );
  const degreeRecords = assets.map(a =>
    makeRecord({ name: a.name, degree: neo4jInt(a.degree) })
  );
  const credRecords = assets.map(a =>
    makeRecord({ name: a.name, credentialExposure: neo4jInt(a.credentialExposure) })
  );
  const outboundRecords = assets.map(a =>
    makeRecord({ name: a.name, outbound: neo4jInt(a.outbound) })
  );
  const inboundRecords = assets.map(a =>
    makeRecord({ name: a.name, inbound: neo4jInt(a.inbound) })
  );
  const denyRecords = assets
    .filter(a => a.hasDenyRule)
    .map(a => makeRecord({ name: a.name }));

  return [
    { records: vulnRecords },
    { records: degreeRecords },
    { records: credRecords },
    { records: outboundRecords },
    { records: inboundRecords },
    { records: denyRecords },
  ];
};

describe('GET /api/analytics', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns 200 with assets, topRisks, and networkStats fields', async () => {
    const mockResults = makeFullMockResults([
      { name: 'web-01', zone: 'dmz', ip: '10.0.1.10', vulnCount: 2, criticalCount: 1, degree: 4, credentialExposure: 0, outbound: 2, inbound: 1, hasDenyRule: false },
    ]);
    mockResults.forEach(r => mockRun.mockResolvedValueOnce(r));

    const response = await GET();
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data).toHaveProperty('assets');
    expect(data).toHaveProperty('topRisks');
    expect(data).toHaveProperty('networkStats');
    expect(Array.isArray(data.assets)).toBe(true);
    expect(Array.isArray(data.topRisks)).toBe(true);
  });

  it('returns all assets with correct metrics shape', async () => {
    const mockResults = makeFullMockResults([
      { name: 'vuln-vm', zone: 'corporate', ip: '10.10.4.20', vulnCount: 4, criticalCount: 2, degree: 5, credentialExposure: 1, outbound: 3, inbound: 2, hasDenyRule: false },
      { name: 'db-server', zone: 'internal', ip: '10.0.2.10', vulnCount: 0, criticalCount: 0, degree: 2, credentialExposure: 0, outbound: 0, inbound: 1, hasDenyRule: false },
    ]);
    mockResults.forEach(r => mockRun.mockResolvedValueOnce(r));

    const response = await GET();
    const data = await response.json();

    expect(data.assets).toHaveLength(2);
    const asset = data.assets.find((a: { name: string }) => a.name === 'vuln-vm');
    expect(asset).toMatchObject({
      name: 'vuln-vm',
      zone: 'corporate',
      ip: '10.10.4.20',
    });
    expect(asset.metrics).toMatchObject({
      degreeCentrality: 5,
      vulnerabilityCount: 4,
      criticalVulnCount: 2,
      credentialExposure: 1,
      inboundFlows: 2,
      outboundFlows: 3,
    });
  });

  it('computes riskScore correctly and assigns riskLevel', async () => {
    // vuln-vm: (4*1.5) + (2*2.0) + (1*0.5) + (2*0.3) = 6 + 4 + 0.5 + 0.6 = 11.1 -> capped at 10 -> critical
    // db-server: (0*1.5) + (0*2.0) + (0*0.5) + (1*0.3) = 0.3 -> low
    const mockResults = makeFullMockResults([
      { name: 'vuln-vm', zone: 'corporate', ip: '10.10.4.20', vulnCount: 4, criticalCount: 2, degree: 5, credentialExposure: 1, outbound: 3, inbound: 2, hasDenyRule: false },
      { name: 'db-server', zone: 'internal', ip: '10.0.2.10', vulnCount: 0, criticalCount: 0, degree: 2, credentialExposure: 0, outbound: 0, inbound: 1, hasDenyRule: false },
    ]);
    mockResults.forEach(r => mockRun.mockResolvedValueOnce(r));

    const response = await GET();
    const data = await response.json();

    const vulnVm = data.assets.find((a: { name: string }) => a.name === 'vuln-vm');
    expect(vulnVm.riskScore).toBe(10);
    expect(vulnVm.riskLevel).toBe('critical');

    const dbServer = data.assets.find((a: { name: string }) => a.name === 'db-server');
    expect(dbServer.riskScore).toBeCloseTo(0.3);
    expect(dbServer.riskLevel).toBe('low');
  });

  it('subtracts 1.0 from riskScore when asset has a deny rule', async () => {
    // asset with deny rule: (2*1.5) + (1*2.0) + (0*0.5) + (1*0.3) - 1.0 = 3 + 2 + 0 + 0.3 - 1 = 4.3
    const mockResults = makeFullMockResults([
      { name: 'protected-vm', zone: 'dmz', ip: '10.0.5.1', vulnCount: 2, criticalCount: 1, degree: 3, credentialExposure: 0, outbound: 0, inbound: 1, hasDenyRule: true },
    ]);
    mockResults.forEach(r => mockRun.mockResolvedValueOnce(r));

    const response = await GET();
    const data = await response.json();

    const asset = data.assets.find((a: { name: string }) => a.name === 'protected-vm');
    expect(asset.riskScore).toBeCloseTo(4.3);
    expect(asset.riskLevel).toBe('medium');
  });

  it('assigns riskLevel based on thresholds', async () => {
    // score ~7.5 -> high: (3*1.5) + (1*2.0) + (0*0.5) + (1*0.3) = 4.5+2+0+0.3 = 6.8 -> high
    // score ~3.5 -> medium: (1*1.5) + (1*2.0) + (0) + (0) = 3.5 -> medium
    const mockResults = makeFullMockResults([
      { name: 'high-risk', zone: 'dmz', ip: '10.0.3.1', vulnCount: 3, criticalCount: 1, degree: 5, credentialExposure: 0, outbound: 0, inbound: 1, hasDenyRule: false },
      { name: 'medium-risk', zone: 'internal', ip: '10.0.3.2', vulnCount: 1, criticalCount: 1, degree: 2, credentialExposure: 0, outbound: 0, inbound: 0, hasDenyRule: false },
    ]);
    mockResults.forEach(r => mockRun.mockResolvedValueOnce(r));

    const response = await GET();
    const data = await response.json();

    const highRisk = data.assets.find((a: { name: string }) => a.name === 'high-risk');
    expect(highRisk.riskLevel).toBe('high');

    const mediumRisk = data.assets.find((a: { name: string }) => a.name === 'medium-risk');
    expect(mediumRisk.riskLevel).toBe('medium');
  });

  it('topRisks is sorted descending by riskScore and limited to 5', async () => {
    const assets = [
      { name: 'a1', zone: 'z', ip: '10.0.0.1', vulnCount: 5, criticalCount: 3, degree: 5, credentialExposure: 2, outbound: 1, inbound: 2, hasDenyRule: false },
      { name: 'a2', zone: 'z', ip: '10.0.0.2', vulnCount: 4, criticalCount: 2, degree: 4, credentialExposure: 1, outbound: 1, inbound: 2, hasDenyRule: false },
      { name: 'a3', zone: 'z', ip: '10.0.0.3', vulnCount: 3, criticalCount: 1, degree: 3, credentialExposure: 0, outbound: 1, inbound: 2, hasDenyRule: false },
      { name: 'a4', zone: 'z', ip: '10.0.0.4', vulnCount: 2, criticalCount: 0, degree: 2, credentialExposure: 0, outbound: 0, inbound: 1, hasDenyRule: false },
      { name: 'a5', zone: 'z', ip: '10.0.0.5', vulnCount: 1, criticalCount: 0, degree: 1, credentialExposure: 0, outbound: 0, inbound: 0, hasDenyRule: false },
      { name: 'a6', zone: 'z', ip: '10.0.0.6', vulnCount: 0, criticalCount: 0, degree: 1, credentialExposure: 0, outbound: 0, inbound: 0, hasDenyRule: false },
    ];
    const mockResults = makeFullMockResults(assets);
    mockResults.forEach(r => mockRun.mockResolvedValueOnce(r));

    const response = await GET();
    const data = await response.json();

    expect(data.topRisks.length).toBeLessThanOrEqual(5);
    for (let i = 1; i < data.topRisks.length; i++) {
      expect(data.topRisks[i - 1].riskScore).toBeGreaterThanOrEqual(data.topRisks[i].riskScore);
    }
    expect(data.topRisks[0].name).toBe('a1');
  });

  it('topRisks items have name, riskScore, riskLevel, and primaryReason', async () => {
    const mockResults = makeFullMockResults([
      { name: 'risky-vm', zone: 'dmz', ip: '10.0.1.5', vulnCount: 3, criticalCount: 2, degree: 4, credentialExposure: 0, outbound: 0, inbound: 1, hasDenyRule: false },
    ]);
    mockResults.forEach(r => mockRun.mockResolvedValueOnce(r));

    const response = await GET();
    const data = await response.json();

    const top = data.topRisks[0];
    expect(top).toHaveProperty('name');
    expect(top).toHaveProperty('riskScore');
    expect(top).toHaveProperty('riskLevel');
    expect(top).toHaveProperty('primaryReason');
    expect(typeof top.primaryReason).toBe('string');
    expect(top.primaryReason.length).toBeGreaterThan(0);
  });

  it('networkStats has correct totals', async () => {
    const mockResults = makeFullMockResults([
      { name: 'web-01', zone: 'dmz', ip: '10.0.1.10', vulnCount: 2, criticalCount: 1, degree: 4, credentialExposure: 1, outbound: 2, inbound: 1, hasDenyRule: false },
      { name: 'db-01', zone: 'internal', ip: '10.0.2.10', vulnCount: 3, criticalCount: 0, degree: 3, credentialExposure: 2, outbound: 1, inbound: 2, hasDenyRule: false },
    ]);
    mockResults.forEach(r => mockRun.mockResolvedValueOnce(r));

    const response = await GET();
    const data = await response.json();

    expect(data.networkStats).toMatchObject({
      totalAssets: 2,
      totalVulnerabilities: 5,
      totalTrafficFlows: 6,  // (2+1) + (1+2)
      totalCredentials: 3,   // 1 + 2
    });
    expect(typeof data.networkStats.averageRiskScore).toBe('number');
  });

  it('returns empty assets and zero stats when no assets exist', async () => {
    [
      { records: [] },
      { records: [] },
      { records: [] },
      { records: [] },
      { records: [] },
      { records: [] },
    ].forEach(r => mockRun.mockResolvedValueOnce(r));

    const response = await GET();
    const data = await response.json();

    expect(data.assets).toHaveLength(0);
    expect(data.topRisks).toHaveLength(0);
    expect(data.networkStats.totalAssets).toBe(0);
    expect(data.networkStats.averageRiskScore).toBe(0);
  });

  it('riskScore is clamped between 0 and 10', async () => {
    const mockResults = makeFullMockResults([
      { name: 'mega-risk', zone: 'dmz', ip: '10.0.9.9', vulnCount: 10, criticalCount: 10, degree: 20, credentialExposure: 5, outbound: 10, inbound: 10, hasDenyRule: false },
    ]);
    mockResults.forEach(r => mockRun.mockResolvedValueOnce(r));

    const response = await GET();
    const data = await response.json();

    expect(data.assets[0].riskScore).toBe(10);
    expect(data.assets[0].riskScore).toBeGreaterThanOrEqual(0);
  });

  it('primaryReason mentions vulnerabilities when vulnCount is highest driver', async () => {
    const mockResults = makeFullMockResults([
      { name: 'vuln-heavy', zone: 'dmz', ip: '10.0.1.1', vulnCount: 5, criticalCount: 3, degree: 3, credentialExposure: 0, outbound: 0, inbound: 0, hasDenyRule: false },
    ]);
    mockResults.forEach(r => mockRun.mockResolvedValueOnce(r));

    const response = await GET();
    const data = await response.json();

    const top = data.topRisks[0];
    expect(top.primaryReason).toMatch(/vulnerabilit/i);
  });

  it('primaryReason mentions credentials when credentialExposure is high', async () => {
    const mockResults = makeFullMockResults([
      { name: 'cred-target', zone: 'dmz', ip: '10.0.1.2', vulnCount: 0, criticalCount: 0, degree: 3, credentialExposure: 6, outbound: 0, inbound: 0, hasDenyRule: false },
    ]);
    mockResults.forEach(r => mockRun.mockResolvedValueOnce(r));

    const response = await GET();
    const data = await response.json();

    const top = data.topRisks[0];
    expect(top.primaryReason).toMatch(/credential/i);
  });
});
