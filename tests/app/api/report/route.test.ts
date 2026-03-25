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

import { GET } from '@/app/api/report/route';

// ── Record factories ──────────────────────────────────────────────────────────

const makeVulnMatrixRecord = (props: {
  cveId: string;
  severity: string;
  affectedAssets: string[];
}) => ({
  get: (key: string) => {
    if (key === 'cveId') { return props.cveId; }
    if (key === 'severity') { return props.severity; }
    if (key === 'affectedAssets') { return props.affectedAssets; }
    return null;
  },
});

const makeAssetVulnRecord = (props: {
  name: string;
  zone: string;
  ip: string;
  vulnCount: number | { toNumber: () => number };
}) => ({
  get: (key: string) => {
    if (key === 'name') { return props.name; }
    if (key === 'zone') { return props.zone; }
    if (key === 'ip') { return props.ip; }
    if (key === 'vulnCount') { return props.vulnCount; }
    return null;
  },
});

const makeCredentialRecord = (props: {
  source: string;
  targets: string[];
  credentialTypes: string[];
}) => ({
  get: (key: string) => {
    if (key === 'source') { return props.source; }
    if (key === 'targets') { return props.targets; }
    if (key === 'credentialTypes') { return props.credentialTypes; }
    return null;
  },
});

const makeZoneRecord = (props: {
  zone: string;
  assets: string[];
  vulnerabilities: number | { toNumber: () => number };
  hasDenyRules: boolean;
}) => ({
  get: (key: string) => {
    if (key === 'zone') { return props.zone; }
    if (key === 'assets') { return props.assets; }
    if (key === 'vulnerabilities') { return props.vulnerabilities; }
    if (key === 'hasDenyRules') { return props.hasDenyRules; }
    return null;
  },
});

const makeInternetExposureRecord = (props: { name: string; internetExposed: boolean }) => ({
  get: (key: string) => {
    if (key === 'name') { return props.name; }
    if (key === 'internetExposed') { return props.internetExposed; }
    return null;
  },
});

// ── Shared mock setup ─────────────────────────────────────────────────────────

function setupMocks(overrides: {
  vulnMatrix?: ReturnType<typeof makeVulnMatrixRecord>[];
  assetVulns?: ReturnType<typeof makeAssetVulnRecord>[];
  credentials?: ReturnType<typeof makeCredentialRecord>[];
  zones?: ReturnType<typeof makeZoneRecord>[];
  exposure?: ReturnType<typeof makeInternetExposureRecord>[];
} = {}) {
  mockRun
    .mockResolvedValueOnce({ records: overrides.vulnMatrix ?? [] })
    .mockResolvedValueOnce({ records: overrides.assetVulns ?? [] })
    .mockResolvedValueOnce({ records: overrides.credentials ?? [] })
    .mockResolvedValueOnce({ records: overrides.zones ?? [] })
    .mockResolvedValueOnce({ records: overrides.exposure ?? [] });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('GET /api/report', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns 200 with all required top-level fields', async () => {
    setupMocks();

    const response = await GET();
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toHaveProperty('generatedAt');
    expect(data).toHaveProperty('summary');
    expect(data).toHaveProperty('vulnerabilityMatrix');
    expect(data).toHaveProperty('assetRiskRanking');
    expect(data).toHaveProperty('credentialMap');
    expect(data).toHaveProperty('zoneAnalysis');
    expect(data).toHaveProperty('recommendations');
  });

  it('generatedAt is an ISO 8601 string', async () => {
    setupMocks();

    const response = await GET();
    const data = await response.json();

    expect(typeof data.generatedAt).toBe('string');
    expect(() => new Date(data.generatedAt)).not.toThrow();
    expect(new Date(data.generatedAt).toISOString()).toBe(data.generatedAt);
  });

  it('summary has all required fields as numbers/string', async () => {
    setupMocks({
      assetVulns: [
        makeAssetVulnRecord({ name: 'web-srv', zone: 'dmz', ip: '10.0.1.1', vulnCount: 2 }),
        makeAssetVulnRecord({ name: 'db-srv', zone: 'internal', ip: '10.0.2.1', vulnCount: 0 }),
      ],
      vulnMatrix: [
        makeVulnMatrixRecord({ cveId: 'CVE-2021-41773', severity: 'critical', affectedAssets: ['web-srv'] }),
        makeVulnMatrixRecord({ cveId: 'CVE-2021-42013', severity: 'critical', affectedAssets: ['web-srv'] }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(typeof data.summary.totalAssets).toBe('number');
    expect(typeof data.summary.totalVulnerabilities).toBe('number');
    expect(typeof data.summary.assetsWithVulnerabilities).toBe('number');
    expect(typeof data.summary.protectionCoverage).toBe('string');
    expect(typeof data.summary.criticalFindings).toBe('number');
    expect(typeof data.summary.overallRisk).toBe('string');
  });

  it('summary.totalAssets equals number of distinct assets', async () => {
    setupMocks({
      assetVulns: [
        makeAssetVulnRecord({ name: 'web-srv', zone: 'dmz', ip: '10.0.1.1', vulnCount: 2 }),
        makeAssetVulnRecord({ name: 'db-srv', zone: 'internal', ip: '10.0.2.1', vulnCount: 0 }),
        makeAssetVulnRecord({ name: 'app-srv', zone: 'internal', ip: '10.0.2.2', vulnCount: 1 }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(data.summary.totalAssets).toBe(3);
  });

  it('summary.assetsWithVulnerabilities counts assets with vulnCount > 0', async () => {
    setupMocks({
      assetVulns: [
        makeAssetVulnRecord({ name: 'web-srv', zone: 'dmz', ip: '10.0.1.1', vulnCount: 2 }),
        makeAssetVulnRecord({ name: 'db-srv', zone: 'internal', ip: '10.0.2.1', vulnCount: 0 }),
        makeAssetVulnRecord({ name: 'app-srv', zone: 'internal', ip: '10.0.2.2', vulnCount: 1 }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(data.summary.assetsWithVulnerabilities).toBe(2);
  });

  it('summary.criticalFindings counts critical severity vulnerabilities', async () => {
    setupMocks({
      vulnMatrix: [
        makeVulnMatrixRecord({ cveId: 'CVE-2021-41773', severity: 'critical', affectedAssets: ['web-srv'] }),
        makeVulnMatrixRecord({ cveId: 'CVE-2021-42013', severity: 'critical', affectedAssets: ['web-srv'] }),
        makeVulnMatrixRecord({ cveId: 'CVE-2022-00001', severity: 'high', affectedAssets: ['db-srv'] }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(data.summary.criticalFindings).toBe(2);
  });

  it('vulnerabilityMatrix items have cveId, severity, affectedAssets, exposedToInternet, firewallProtected', async () => {
    setupMocks({
      vulnMatrix: [
        makeVulnMatrixRecord({ cveId: 'CVE-2021-41773', severity: 'critical', affectedAssets: ['vuln-vm', 'web-srv'] }),
      ],
      exposure: [
        makeInternetExposureRecord({ name: 'vuln-vm', internetExposed: false }),
        makeInternetExposureRecord({ name: 'web-srv', internetExposed: true }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(Array.isArray(data.vulnerabilityMatrix)).toBe(true);
    expect(data.vulnerabilityMatrix).toHaveLength(1);
    const entry = data.vulnerabilityMatrix[0];
    expect(entry).toHaveProperty('cveId', 'CVE-2021-41773');
    expect(entry).toHaveProperty('severity', 'critical');
    expect(Array.isArray(entry.affectedAssets)).toBe(true);
    expect(entry).toHaveProperty('exposedToInternet');
    expect(entry).toHaveProperty('firewallProtected');
    expect(typeof entry.exposedToInternet).toBe('boolean');
    expect(typeof entry.firewallProtected).toBe('boolean');
  });

  it('vulnerabilityMatrix exposedToInternet is true when any affected asset is internet-exposed', async () => {
    setupMocks({
      vulnMatrix: [
        makeVulnMatrixRecord({ cveId: 'CVE-2021-41773', severity: 'critical', affectedAssets: ['vuln-vm', 'web-srv'] }),
      ],
      exposure: [
        makeInternetExposureRecord({ name: 'vuln-vm', internetExposed: false }),
        makeInternetExposureRecord({ name: 'web-srv', internetExposed: true }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(data.vulnerabilityMatrix[0].exposedToInternet).toBe(true);
  });

  it('assetRiskRanking is sorted by vulnerabilities descending with rank field', async () => {
    setupMocks({
      assetVulns: [
        makeAssetVulnRecord({ name: 'vuln-vm', zone: 'corporate', ip: '10.1.1.5', vulnCount: 4 }),
        makeAssetVulnRecord({ name: 'web-srv', zone: 'dmz', ip: '10.0.1.1', vulnCount: 2 }),
        makeAssetVulnRecord({ name: 'db-srv', zone: 'internal', ip: '10.0.2.1', vulnCount: 0 }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(Array.isArray(data.assetRiskRanking)).toBe(true);
    expect(data.assetRiskRanking[0].name).toBe('vuln-vm');
    expect(data.assetRiskRanking[0].rank).toBe(1);
    expect(data.assetRiskRanking[1].rank).toBe(2);
    expect(data.assetRiskRanking[0].vulnerabilities).toBeGreaterThanOrEqual(
      data.assetRiskRanking[1].vulnerabilities
    );
  });

  it('assetRiskRanking items have name, zone, vulnerabilities, internetExposed, credentialTarget', async () => {
    setupMocks({
      assetVulns: [
        makeAssetVulnRecord({ name: 'vuln-vm', zone: 'corporate', ip: '10.1.1.5', vulnCount: 4 }),
      ],
      credentials: [
        makeCredentialRecord({ source: 'mgmt-vm', targets: ['vuln-vm'], credentialTypes: ['ssh'] }),
      ],
      exposure: [
        makeInternetExposureRecord({ name: 'vuln-vm', internetExposed: false }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    const asset = data.assetRiskRanking[0];
    expect(asset).toHaveProperty('rank');
    expect(asset).toHaveProperty('name');
    expect(asset).toHaveProperty('zone');
    expect(asset).toHaveProperty('vulnerabilities');
    expect(asset).toHaveProperty('internetExposed');
    expect(asset).toHaveProperty('credentialTarget');
    expect(typeof asset.credentialTarget).toBe('boolean');
  });

  it('credentialMap shows source → targets mapping with credentialTypes', async () => {
    setupMocks({
      credentials: [
        makeCredentialRecord({
          source: 'mgmt-vm',
          targets: ['web-srv', 'app-srv', 'db-srv'],
          credentialTypes: ['ssh-key', 'api-key'],
        }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(Array.isArray(data.credentialMap)).toBe(true);
    expect(data.credentialMap).toHaveLength(1);
    const entry = data.credentialMap[0];
    expect(entry).toHaveProperty('source', 'mgmt-vm');
    expect(Array.isArray(entry.targets)).toBe(true);
    expect(entry.targets).toContain('web-srv');
    expect(Array.isArray(entry.credentialTypes)).toBe(true);
  });

  it('zoneAnalysis has zone, assets, vulnerabilities, hasDenyRules, risk fields', async () => {
    setupMocks({
      zones: [
        makeZoneRecord({ zone: 'corporate', assets: ['dns-srv', 'vuln-vm'], vulnerabilities: 4, hasDenyRules: true }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(Array.isArray(data.zoneAnalysis)).toBe(true);
    expect(data.zoneAnalysis).toHaveLength(1);
    const zone = data.zoneAnalysis[0];
    expect(zone).toHaveProperty('zone', 'corporate');
    expect(Array.isArray(zone.assets)).toBe(true);
    expect(zone).toHaveProperty('vulnerabilities');
    expect(zone).toHaveProperty('hasDenyRules');
    expect(zone).toHaveProperty('risk');
    expect(typeof zone.risk).toBe('string');
  });

  it('zoneAnalysis risk is high when vulnerabilities > 2', async () => {
    setupMocks({
      zones: [
        makeZoneRecord({ zone: 'corporate', assets: ['vuln-vm'], vulnerabilities: 4, hasDenyRules: false }),
        makeZoneRecord({ zone: 'dmz', assets: ['web-srv'], vulnerabilities: 1, hasDenyRules: true }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    const corporate = data.zoneAnalysis.find((z: { zone: string }) => z.zone === 'corporate');
    const dmz = data.zoneAnalysis.find((z: { zone: string }) => z.zone === 'dmz');
    expect(corporate.risk).toBe('high');
    expect(dmz.risk).not.toBe('high');
  });

  it('recommendations is a non-empty string array', async () => {
    setupMocks({
      vulnMatrix: [
        makeVulnMatrixRecord({ cveId: 'CVE-2021-41773', severity: 'critical', affectedAssets: ['vuln-vm'] }),
      ],
      assetVulns: [
        makeAssetVulnRecord({ name: 'vuln-vm', zone: 'corporate', ip: '10.1.1.5', vulnCount: 2 }),
      ],
      credentials: [
        makeCredentialRecord({ source: 'mgmt-vm', targets: ['web-srv', 'app-srv', 'db-srv', 'dns-srv', 'vuln-vm', 'elk-srv', 'edge-rtr', 'edge-fw', 'internal-fw'], credentialTypes: ['ssh-key', 'api-key', 'ssh'] }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(Array.isArray(data.recommendations)).toBe(true);
    expect(data.recommendations.length).toBeGreaterThan(0);
    data.recommendations.forEach((rec: unknown) => {
      expect(typeof rec).toBe('string');
    });
  });

  it('recommendations mention critical CVE assets', async () => {
    setupMocks({
      vulnMatrix: [
        makeVulnMatrixRecord({ cveId: 'CVE-2021-41773', severity: 'critical', affectedAssets: ['vuln-vm'] }),
      ],
      assetVulns: [
        makeAssetVulnRecord({ name: 'vuln-vm', zone: 'corporate', ip: '10.1.1.5', vulnCount: 1 }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    const patchRec = data.recommendations.find((r: string) =>
      r.toLowerCase().includes('patch') && r.includes('vuln-vm')
    );
    expect(patchRec).toBeDefined();
  });

  it('recommendations mention credential concentration when source has many targets', async () => {
    setupMocks({
      credentials: [
        makeCredentialRecord({
          source: 'mgmt-vm',
          targets: ['web-srv', 'app-srv', 'db-srv', 'dns-srv', 'vuln-vm', 'elk-srv', 'edge-rtr', 'edge-fw', 'internal-fw'],
          credentialTypes: ['ssh-key'],
        }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    const credRec = data.recommendations.find((r: string) =>
      r.toLowerCase().includes('credential') && r.includes('mgmt-vm')
    );
    expect(credRec).toBeDefined();
  });

  it('recommendations mention zones without deny rules', async () => {
    setupMocks({
      zones: [
        makeZoneRecord({ zone: 'dmz', assets: ['web-srv'], vulnerabilities: 1, hasDenyRules: false }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    const denyRec = data.recommendations.find((r: string) =>
      r.toLowerCase().includes('deny')
    );
    expect(denyRec).toBeDefined();
  });

  it('handles Neo4j integer-like objects for vulnCount (toNumber method)', async () => {
    setupMocks({
      assetVulns: [
        makeAssetVulnRecord({ name: 'vuln-vm', zone: 'corporate', ip: '10.1.1.5', vulnCount: { toNumber: () => 4 } }),
      ],
    });

    const response = await GET();
    const data = await response.json();

    expect(data.summary.totalAssets).toBe(1);
    expect(data.assetRiskRanking[0].vulnerabilities).toBe(4);
  });

  it('returns empty collections gracefully when graph has no data', async () => {
    setupMocks();

    const response = await GET();
    const data = await response.json();

    expect(data.vulnerabilityMatrix).toHaveLength(0);
    expect(data.assetRiskRanking).toHaveLength(0);
    expect(data.credentialMap).toHaveLength(0);
    expect(data.zoneAnalysis).toHaveLength(0);
    expect(data.summary.totalAssets).toBe(0);
    expect(data.summary.totalVulnerabilities).toBe(0);
  });
});
