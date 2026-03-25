import { describe, it, expect, jest, beforeEach } from '@jest/globals';

// Mock neo4j-driver before any imports that use it
jest.mock('neo4j-driver', () => {
  const mockRun = jest.fn();
  const mockSession = {
    run: mockRun,
    close: jest.fn(() => Promise.resolve()),
  };
  const mockDriver = {
    session: jest.fn(() => mockSession),
    close: jest.fn(() => Promise.resolve()),
  };
  const mockNeo4j = {
    driver: jest.fn(() => mockDriver),
    auth: {
      basic: jest.fn(() => ({ scheme: 'basic' })),
    },
  };
  return { __esModule: true, default: mockNeo4j, ...mockNeo4j };
});

// Mock @/lib/neo4j
const mockRun = jest.fn();
jest.mock('@/lib/neo4j', () => ({
  getSession: jest.fn(() => ({
    run: mockRun,
    close: jest.fn(() => Promise.resolve()),
  })),
}));

// Mock next/server
jest.mock('next/server', () => ({
  NextResponse: {
    json: jest.fn((data: unknown, init?: { status?: number }) => ({
      status: init?.status ?? 200,
      json: async () => data,
    })),
  },
}));

import { GET } from '@/app/api/graph/route';

const makeNodeRecord = (props: Record<string, unknown>, labels: string[]) => ({
  get: (key: string) => {
    if (key === 'n') {
      return { labels, properties: props };
    }
    return null;
  },
});

const makeRelRecord = (
  startId: string,
  endId: string,
  type: string,
  props: Record<string, unknown>,
) => ({
  get: (key: string) => {
    if (key === 'r') { return { type, properties: props }; }
    if (key === 'startId') { return startId; }
    if (key === 'endId') { return endId; }
    return null;
  },
});

describe('GET /api/graph', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns a GraphData object with nodes and links arrays', async () => {
    mockRun
      .mockResolvedValueOnce({
        records: [
          makeNodeRecord({ name: 'web-server', type: 'server', zone: 'dmz', ip: '10.0.0.1' }, ['Asset']),
          makeNodeRecord({ cveId: 'CVE-2024-001', severity: 'critical', description: 'test' }, ['Vulnerability']),
        ],
      })
      .mockResolvedValueOnce({
        records: [
          makeRelRecord('web-server', 'CVE-2024-001', 'HAS_VULNERABILITY', { since: '2024-01-01' }),
        ],
      });

    const response = await GET();
    const data = await response.json();

    expect(data).toHaveProperty('nodes');
    expect(data).toHaveProperty('links');
    expect(Array.isArray(data.nodes)).toBe(true);
    expect(Array.isArray(data.links)).toBe(true);
  });

  it('maps Asset nodes with correct GraphNode shape', async () => {
    mockRun
      .mockResolvedValueOnce({
        records: [
          makeNodeRecord({ name: 'edge-rtr', type: 'router', zone: 'edge', ip: '10.0.0.254' }, ['Asset']),
        ],
      })
      .mockResolvedValueOnce({ records: [] });

    const response = await GET();
    const data = await response.json();

    expect(data.nodes).toHaveLength(1);
    const node = data.nodes[0];
    expect(node).toHaveProperty('id');
    expect(node).toHaveProperty('label');
    expect(node).toHaveProperty('type');
    expect(node).toHaveProperty('group');
    expect(node).toHaveProperty('properties');
    expect(node.label).toBe('Asset');
    expect(node.id).toBe('edge-rtr');
  });

  it('maps Vulnerability nodes using cveId as id', async () => {
    mockRun
      .mockResolvedValueOnce({
        records: [
          makeNodeRecord({ cveId: 'CVE-2024-999', severity: 'high', description: 'vuln' }, ['Vulnerability']),
        ],
      })
      .mockResolvedValueOnce({ records: [] });

    const response = await GET();
    const data = await response.json();

    const node = data.nodes[0];
    expect(node.id).toBe('CVE-2024-999');
    expect(node.label).toBe('Vulnerability');
  });

  it('maps relationships to links with source, target, type, properties', async () => {
    mockRun
      .mockResolvedValueOnce({ records: [] })
      .mockResolvedValueOnce({
        records: [
          makeRelRecord('web-server', 'CVE-2024-001', 'HAS_VULNERABILITY', {}),
        ],
      });

    const response = await GET();
    const data = await response.json();

    expect(data.links).toHaveLength(1);
    const link = data.links[0];
    expect(link).toHaveProperty('source', 'web-server');
    expect(link).toHaveProperty('target', 'CVE-2024-001');
    expect(link).toHaveProperty('type', 'HAS_VULNERABILITY');
    expect(link).toHaveProperty('properties');
  });

  it('returns empty nodes and links when graph is empty', async () => {
    mockRun
      .mockResolvedValueOnce({ records: [] })
      .mockResolvedValueOnce({ records: [] });

    const response = await GET();
    const data = await response.json();

    expect(data.nodes).toHaveLength(0);
    expect(data.links).toHaveLength(0);
  });

  it('returns HTTP 200 status', async () => {
    mockRun
      .mockResolvedValueOnce({ records: [] })
      .mockResolvedValueOnce({ records: [] });

    const response = await GET();
    expect(response.status).toBe(200);
  });
});
