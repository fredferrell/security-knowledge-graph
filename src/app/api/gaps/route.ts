import { NextResponse } from 'next/server';
import { getSession } from '@/lib/neo4j';

interface VulnerableAsset {
  name: string;
  zone: string;
  cveId: string;
  severity: string;
  hasGap: boolean;
}

interface GapSummary {
  totalVulnerabilities: number;
  assetsWithGaps: number;
  coveredAssets: number;
}

interface GapsResponse {
  vulnerableAssets: VulnerableAsset[];
  summary: GapSummary;
}

type SessionLike = { run: (q: string) => Promise<{ records: unknown[] }>; close: () => Promise<void> };
type RecordLike = { get: (k: string) => unknown };

/**
 * Queries all assets with vulnerabilities and checks whether their zone
 * has at least one deny firewall rule protecting it.
 */
async function fetchGapData(session: SessionLike): Promise<VulnerableAsset[]> {
  const query = `
    MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
    OPTIONAL MATCH (fw:FirewallRule)
      WHERE fw.destZone = a.zone AND fw.action = 'deny'
    RETURN a.name AS assetName, a.zone AS assetZone,
           v.cveId AS cveId, v.severity AS severity,
           fw IS NOT NULL AS hasDenyRule
  `;
  const result = await session.run(query);
  return result.records.map((record) => {
    const r = record as RecordLike;
    const hasDenyRule = Boolean(r.get('hasDenyRule'));
    return {
      name: String(r.get('assetName') ?? ''),
      zone: String(r.get('assetZone') ?? ''),
      cveId: String(r.get('cveId') ?? ''),
      severity: String(r.get('severity') ?? ''),
      hasGap: !hasDenyRule,
    };
  });
}

/** Computes gap summary statistics from the list of vulnerable assets. */
function computeSummary(assets: VulnerableAsset[]): GapSummary {
  const totalVulnerabilities = assets.length;
  const assetNames = new Set(assets.map((a) => a.name));
  const gapAssetNames = new Set(assets.filter((a) => a.hasGap).map((a) => a.name));
  const coveredAssetNames = new Set(assets.filter((a) => !a.hasGap).map((a) => a.name));

  // An asset counts as "with gap" only if ALL its vulnerabilities have gaps,
  // or more precisely if the asset appears in the gap set.
  // Per spec: assets with vulnerabilities but no deny rules.
  const assetsWithGaps = gapAssetNames.size;
  const coveredAssets = [...coveredAssetNames].filter((name) => !gapAssetNames.has(name)).length;

  return { totalVulnerabilities, assetsWithGaps, coveredAssets };
}

/** GET /api/gaps — returns assets with vulnerabilities and identifies protection gaps. */
export async function GET(): Promise<NextResponse<GapsResponse>> {
  const session = getSession();
  try {
    const vulnerableAssets = await fetchGapData(session);
    const summary = computeSummary(vulnerableAssets);
    return NextResponse.json({ vulnerableAssets, summary });
  } finally {
    await session.close();
  }
}
