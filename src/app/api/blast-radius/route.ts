import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { getSession } from '@/lib/neo4j';

interface AffectedAsset {
  name: string;
  ip: string;
  zone: string;
}

interface FirewallRuleResult {
  firewall: string;
  name: string;
  sourceZone: string;
  destZone: string;
  action: string;
}

interface BlastRadiusResponse {
  cve: string;
  affectedAssets: AffectedAsset[];
  exposurePaths: string[][];
  firewallRules: FirewallRuleResult[];
}

type SessionLike = { run: (q: string, p?: Record<string, unknown>) => Promise<{ records: unknown[] }>; close: () => Promise<void> };
type RecordLike = { get: (k: string) => unknown };

/** Queries assets affected by a given CVE via HAS_VULNERABILITY relationship. */
async function fetchAffectedAssets(session: SessionLike, cve: string): Promise<AffectedAsset[]> {
  const query = `
    MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability {cveId: $cve})
    RETURN a.name AS assetName, a.ip AS assetIp, a.zone AS assetZone
  `;
  const result = await session.run(query, { cve });
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
async function fetchExposurePaths(session: SessionLike, cve: string): Promise<string[][]> {
  const query = `
    MATCH (src:Asset {name: 'edge-rtr'}),
          (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability {cveId: $cve}),
          path = shortestPath((src)-[:TRAFFIC_FLOW*]->(a))
    RETURN [node IN nodes(path) | node.name] AS path
  `;
  const result = await session.run(query, { cve });
  return result.records.map((record) => {
    const r = record as RecordLike;
    const path = r.get('path');
    return Array.isArray(path) ? path.map(String) : [];
  });
}

/** Queries firewall rules related to zones of affected assets. */
async function fetchFirewallRules(session: SessionLike, cve: string): Promise<FirewallRuleResult[]> {
  const query = `
    MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability {cveId: $cve})
    MATCH (fw:FirewallRule)
    WHERE fw.destZone = a.zone OR fw.sourceZone = a.zone
    RETURN DISTINCT fw.firewall AS firewall, fw.name AS name,
           fw.sourceZone AS sourceZone, fw.destZone AS destZone, fw.action AS action
  `;
  const result = await session.run(query, { cve });
  return result.records.map((record) => {
    const r = record as RecordLike;
    return {
      firewall: String(r.get('firewall') ?? ''),
      name: String(r.get('name') ?? ''),
      sourceZone: String(r.get('sourceZone') ?? ''),
      destZone: String(r.get('destZone') ?? ''),
      action: String(r.get('action') ?? ''),
    };
  });
}

/** GET /api/blast-radius?cve=CVE-XXX — returns blast radius analysis for a given CVE. */
export async function GET(request: NextRequest): Promise<NextResponse<BlastRadiusResponse | { error: string }>> {
  const { searchParams } = new URL(request.url);
  const cve = searchParams.get('cve');

  if (!cve) {
    return NextResponse.json({ error: 'Missing required query param: cve' }, { status: 400 });
  }

  const sessions = [getSession(), getSession(), getSession()];
  try {
    const [affectedAssets, exposurePaths, firewallRules] = await Promise.all([
      fetchAffectedAssets(sessions[0], cve),
      fetchExposurePaths(sessions[1], cve),
      fetchFirewallRules(sessions[2], cve),
    ]);

    return NextResponse.json({ cve, affectedAssets, exposurePaths, firewallRules });
  } finally {
    await Promise.all(sessions.map((s) => s.close()));
  }
}
