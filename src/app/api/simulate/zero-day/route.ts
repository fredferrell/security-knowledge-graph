import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { getSession } from '@/lib/neo4j';

interface ZeroDayBody {
  cveId: string;
  severity: string;
  description?: string;
  affectedSoftware: string;
  affectedVersion?: string;
}

interface VulnerabilityResult {
  cveId: string;
  severity: string;
  description: string;
  affectedSoftware: string;
  affectedVersion: string;
}

interface AffectedAsset {
  name: string;
  ip: string;
  zone: string;
}

interface ZeroDayResponse {
  vulnerability: VulnerabilityResult;
  affectedAssets: AffectedAsset[];
  exposurePaths: string[][];
}

type SessionLike = { run: (q: string, p?: Record<string, unknown>) => Promise<{ records: unknown[] }>; close: () => Promise<void> };
type RecordLike = { get: (k: string) => unknown };

/** Merges a Vulnerability node and returns its properties. */
async function mergeVulnerability(session: SessionLike, body: ZeroDayBody): Promise<VulnerabilityResult> {
  const query = `
    MERGE (v:Vulnerability {cveId: $cveId})
    SET v.severity = $severity,
        v.description = $description,
        v.affectedSoftware = $affectedSoftware,
        v.affectedVersion = $affectedVersion
    RETURN v.cveId AS cveId, v.severity AS severity, v.description AS description,
           v.affectedSoftware AS affectedSoftware, v.affectedVersion AS affectedVersion
  `;
  const result = await session.run(query, {
    cveId: body.cveId,
    severity: body.severity,
    description: body.description ?? '',
    affectedSoftware: body.affectedSoftware,
    affectedVersion: body.affectedVersion ?? '',
  });
  const r = result.records[0] as RecordLike;
  return {
    cveId: String(r.get('cveId') ?? ''),
    severity: String(r.get('severity') ?? ''),
    description: String(r.get('description') ?? ''),
    affectedSoftware: String(r.get('affectedSoftware') ?? ''),
    affectedVersion: String(r.get('affectedVersion') ?? ''),
  };
}

/** Matches assets whose software list contains the affected software and creates HAS_VULNERABILITY relationships. */
async function fetchAndLinkAffectedAssets(session: SessionLike, body: ZeroDayBody): Promise<AffectedAsset[]> {
  const query = `
    MATCH (a:Asset), (v:Vulnerability {cveId: $cveId})
    WHERE any(s IN a.software WHERE toLower(s) CONTAINS toLower($affectedSoftware))
    MERGE (a)-[:HAS_VULNERABILITY]->(v)
    RETURN a.name AS assetName, a.ip AS assetIp, a.zone AS assetZone
  `;
  const result = await session.run(query, {
    cveId: body.cveId,
    affectedSoftware: body.affectedSoftware,
  });
  return result.records.map((record) => {
    const r = record as RecordLike;
    return {
      name: String(r.get('assetName') ?? ''),
      ip: String(r.get('assetIp') ?? ''),
      zone: String(r.get('assetZone') ?? ''),
    };
  });
}

/** Queries shortest exposure paths from edge-rtr to affected assets via TRAFFIC_FLOW. */
async function fetchExposurePaths(session: SessionLike, cveId: string): Promise<string[][]> {
  const query = `
    MATCH (src:Asset {name: 'edge-rtr'}),
          (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability {cveId: $cveId}),
          path = shortestPath((src)-[:TRAFFIC_FLOW*]->(a))
    RETURN [node IN nodes(path) | node.name] AS path
  `;
  const result = await session.run(query, { cveId });
  return result.records.map((record) => {
    const r = record as RecordLike;
    const path = r.get('path');
    return Array.isArray(path) ? path.map(String) : [];
  });
}

/** POST /api/simulate/zero-day — simulates a zero-day vulnerability and returns affected assets and exposure paths. */
export async function POST(request: NextRequest): Promise<NextResponse<ZeroDayResponse | { error: string }>> {
  const body = await request.json() as Partial<ZeroDayBody>;

  if (!body.cveId || !body.severity || !body.affectedSoftware) {
    return NextResponse.json(
      { error: 'Missing required fields: cveId, severity, affectedSoftware' },
      { status: 400 },
    );
  }

  const session = getSession();
  try {
    const vulnerability = await mergeVulnerability(session, body as ZeroDayBody);
    const affectedAssets = await fetchAndLinkAffectedAssets(session, body as ZeroDayBody);
    const exposurePaths = await fetchExposurePaths(session, body.cveId);

    return NextResponse.json({ vulnerability, affectedAssets, exposurePaths }, { status: 201 });
  } finally {
    await session.close();
  }
}
