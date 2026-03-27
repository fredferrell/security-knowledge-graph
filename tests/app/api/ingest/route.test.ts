import { describe, it, expect, jest, beforeEach } from '@jest/globals';

// Mock neo4j-driver
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

// Mock global fetch for Elasticsearch calls
const mockFetch = jest.fn() as jest.MockedFunction<typeof fetch>;
global.fetch = mockFetch;

import { GET, POST } from '@/app/api/ingest/route';

beforeEach(() => {
  jest.clearAllMocks();
});

describe('GET /api/ingest', () => {
  it('returns security event counts and traffic link count', async () => {
    mockRun
      .mockResolvedValueOnce({
        records: [
          { get: (k: string) => k === 'type' ? 'AUTH_FAILURE' : { toNumber: () => 5 } },
          { get: (k: string) => k === 'type' ? 'AUTH_SUCCESS' : { toNumber: () => 12 } },
        ],
      })
      .mockResolvedValueOnce({
        records: [{ get: () => ({ toNumber: () => 3 }) }],
      });

    const res = await GET();
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data.events).toHaveLength(2);
    expect(data.observedTrafficLinks).toBe(3);
  });

  it('handles empty graph', async () => {
    mockRun
      .mockResolvedValueOnce({ records: [] })
      .mockResolvedValueOnce({ records: [{ get: () => ({ toNumber: () => 0 }) }] });

    const res = await GET();
    const data = await res.json();

    expect(data.events).toHaveLength(0);
    expect(data.observedTrafficLinks).toBe(0);
  });
});

describe('POST /api/ingest', () => {
  it('returns ingestion summary on success', async () => {
    // Mock Elasticsearch responses
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          hits: {
            hits: [
              {
                _source: {
                  syslog_program: 'sshd',
                  syslog_message: 'Failed password for root from 10.10.5.20 port 22',
                  '@timestamp': '2026-03-27T10:00:00.000Z',
                },
              },
            ],
          },
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          aggregations: {
            messages: {
              buckets: [
                { key: 'Accepted password for cisco from 10.10.5.20 port 22', doc_count: 5 },
              ],
            },
          },
        }),
      } as Response);

    // Mock Neo4j writes
    mockRun.mockResolvedValue({ records: [] });

    const res = await POST();
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data.securityEvents).toBe(1);
    expect(data.sshEvents).toBe(1);
    expect(data.timestamp).toBeDefined();
  });

  it('handles Elasticsearch being unreachable', async () => {
    mockFetch.mockResolvedValue({ ok: false, json: async () => ({}) } as Response);

    const res = await POST();
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data.securityEvents).toBe(0);
  });
});
