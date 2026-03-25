import { NextResponse } from 'next/server';
import { getSession } from '@/lib/neo4j';

// ── Types ─────────────────────────────────────────────────────────────────────

interface VulnMatrixEntry { cveId: string; severity: string; affectedAssets: string[]; exposedToInternet: boolean; firewallProtected: boolean }
interface AssetRiskEntry { rank: number; name: string; zone: string; vulnerabilities: number; internetExposed: boolean; credentialTarget: boolean }
interface CredentialMapEntry { source: string; targets: string[]; credentialTypes: string[] }
interface ZoneEntry { zone: string; assets: string[]; vulnerabilities: number; hasDenyRules: boolean; risk: string }
interface ReportSummary { overallRisk: string; totalAssets: number; totalVulnerabilities: number; assetsWithVulnerabilities: number; protectionCoverage: string; criticalFindings: number }
interface ReportResponse { generatedAt: string; summary: ReportSummary; vulnerabilityMatrix: VulnMatrixEntry[]; assetRiskRanking: AssetRiskEntry[]; credentialMap: CredentialMapEntry[]; zoneAnalysis: ZoneEntry[]; recommendations: string[] }

type SessionLike = { run: (q: string) => Promise<{ records: unknown[] }>; close: () => Promise<void> };
type RecordLike = { get: (k: string) => unknown };

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Coerces Neo4j integer-like objects or plain numbers to JS number. */
function toNumber(val: unknown): number {
  if (val === null || val === undefined) { return 0; }
  if (typeof val === 'number') { return val; }
  if (typeof val === 'object' && typeof (val as { toNumber?: unknown }).toNumber === 'function') {
    return (val as { toNumber: () => number }).toNumber();
  }
  return Number(val);
}

function toStringArray(val: unknown): string[] {
  return Array.isArray(val) ? val.map(String) : [];
}

// ── Queries ───────────────────────────────────────────────────────────────────

async function fetchVulnMatrix(session: SessionLike): Promise<{ cveId: string; severity: string; affectedAssets: string[] }[]> {
  const result = await session.run(`
    MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
    RETURN v.cveId AS cveId, v.severity AS severity, collect(DISTINCT a.name) AS affectedAssets
  `);
  return result.records.map((rec) => {
    const r = rec as RecordLike;
    return { cveId: String(r.get('cveId') ?? ''), severity: String(r.get('severity') ?? ''), affectedAssets: toStringArray(r.get('affectedAssets')) };
  });
}

async function fetchAssetVulns(session: SessionLike): Promise<{ name: string; zone: string; ip: string; vulnCount: number }[]> {
  const result = await session.run(`
    MATCH (a:Asset)
    OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
    RETURN a.name AS name, a.zone AS zone, a.ip AS ip, count(v) AS vulnCount
    ORDER BY vulnCount DESC
  `);
  return result.records.map((rec) => {
    const r = rec as RecordLike;
    return { name: String(r.get('name') ?? ''), zone: String(r.get('zone') ?? ''), ip: String(r.get('ip') ?? ''), vulnCount: toNumber(r.get('vulnCount')) };
  });
}

async function fetchCredentials(session: SessionLike): Promise<CredentialMapEntry[]> {
  const result = await session.run(`
    MATCH (s:Asset)-[c:HAS_CREDENTIAL]->(t:Asset)
    RETURN s.name AS source, collect(DISTINCT t.name) AS targets, collect(DISTINCT c.credentialType) AS credentialTypes
  `);
  return result.records.map((rec) => {
    const r = rec as RecordLike;
    return { source: String(r.get('source') ?? ''), targets: toStringArray(r.get('targets')), credentialTypes: toStringArray(r.get('credentialTypes')) };
  });
}

async function fetchZones(session: SessionLike): Promise<{ zone: string; assets: string[]; vulnerabilities: number; hasDenyRules: boolean }[]> {
  const result = await session.run(`
    MATCH (a:Asset)
    OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
    OPTIONAL MATCH (fw:FirewallRule) WHERE fw.destZone = a.zone AND fw.action = 'deny'
    RETURN a.zone AS zone, collect(DISTINCT a.name) AS assets,
           count(DISTINCT v) AS vulnerabilities, count(DISTINCT fw) > 0 AS hasDenyRules
  `);
  return result.records.map((rec) => {
    const r = rec as RecordLike;
    return { zone: String(r.get('zone') ?? ''), assets: toStringArray(r.get('assets')), vulnerabilities: toNumber(r.get('vulnerabilities')), hasDenyRules: Boolean(r.get('hasDenyRules')) };
  });
}

async function fetchInternetExposure(session: SessionLike): Promise<Map<string, boolean>> {
  const result = await session.run(`
    MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
    OPTIONAL MATCH path = shortestPath((entry:Asset {name: 'edge-rtr'})-[:TRAFFIC_FLOW*..6]->(a))
    RETURN a.name AS name, path IS NOT NULL AS internetExposed
  `);
  const map = new Map<string, boolean>();
  for (const rec of result.records) {
    const r = rec as RecordLike;
    const name = String(r.get('name') ?? '');
    const exposed = Boolean(r.get('internetExposed'));
    if (!map.has(name) || exposed) { map.set(name, exposed); }
  }
  return map;
}

// ── Builders ──────────────────────────────────────────────────────────────────

function buildVulnMatrix(raw: { cveId: string; severity: string; affectedAssets: string[] }[], exposureMap: Map<string, boolean>): VulnMatrixEntry[] {
  return raw.map((v) => ({
    cveId: v.cveId, severity: v.severity, affectedAssets: v.affectedAssets,
    exposedToInternet: v.affectedAssets.some((a) => exposureMap.get(a) === true),
    firewallProtected: false,
  }));
}

function buildAssetRanking(assetVulns: { name: string; zone: string; vulnCount: number }[], exposureMap: Map<string, boolean>, credTargets: Set<string>): AssetRiskEntry[] {
  return assetVulns.map((a, idx) => ({
    rank: idx + 1, name: a.name, zone: a.zone, vulnerabilities: a.vulnCount,
    internetExposed: exposureMap.get(a.name) === true,
    credentialTarget: credTargets.has(a.name),
  }));
}

function buildZoneAnalysis(zones: { zone: string; assets: string[]; vulnerabilities: number; hasDenyRules: boolean }[]): ZoneEntry[] {
  return zones.map((z) => ({
    ...z,
    risk: z.vulnerabilities > 2 ? 'high' : z.vulnerabilities > 0 ? 'medium' : 'low',
  }));
}

function buildSummary(assetVulns: { vulnCount: number }[], vulnMatrix: { severity: string }[], zones: ZoneEntry[]): ReportSummary {
  const criticalFindings = vulnMatrix.filter((v) => v.severity === 'critical').length;
  const assetsWithVulnerabilities = assetVulns.filter((a) => a.vulnCount > 0).length;
  const zonesWithDeny = zones.filter((z) => z.hasDenyRules).length;
  const coverageRatio = zones.length > 0 ? Math.round((zonesWithDeny / zones.length) * 100) : 0;
  return {
    overallRisk: criticalFindings > 0 ? 'high' : assetsWithVulnerabilities > 0 ? 'medium' : 'low',
    totalAssets: assetVulns.length,
    totalVulnerabilities: vulnMatrix.length,
    assetsWithVulnerabilities,
    protectionCoverage: `${coverageRatio}%`,
    criticalFindings,
  };
}

function buildRecommendations(vulnMatrix: VulnMatrixEntry[], credentialMap: CredentialMapEntry[], zones: ZoneEntry[], assetVulns: { name: string; vulnCount: number }[]): string[] {
  const recs: string[] = [];

  const criticalByAsset = new Map<string, string[]>();
  for (const v of vulnMatrix) {
    if (v.severity === 'critical') {
      for (const asset of v.affectedAssets) {
        criticalByAsset.set(asset, [...(criticalByAsset.get(asset) ?? []), v.cveId]);
      }
    }
  }
  for (const [asset, cves] of criticalByAsset) {
    recs.push(`Patch ${asset}: has ${cves.length} critical CVE${cves.length > 1 ? 's' : ''} (${cves.join(', ')})`);
  }

  for (const cred of credentialMap) {
    if (cred.targets.length >= 3) {
      recs.push(`Review credential exposure: ${cred.source} holds credentials to ${cred.targets.length} devices`);
    }
  }

  if (zones.some((z) => !z.hasDenyRules)) {
    recs.push('Add deny rules for zones without firewall protection');
  }

  for (const asset of assetVulns) {
    if (asset.vulnCount > 0 && vulnMatrix.some((v) => v.exposedToInternet && v.affectedAssets.includes(asset.name))) {
      recs.push(`Priority: ${asset.name} is internet-exposed with ${asset.vulnCount} vulnerabilities`);
    }
  }

  return recs.length > 0 ? recs : ['No critical findings detected'];
}

// ── Handler ───────────────────────────────────────────────────────────────────

/** GET /api/report — returns a comprehensive security posture report. */
export async function GET(): Promise<NextResponse<ReportResponse>> {
  const session = getSession();
  try {
    const [rawMatrix, assetVulns, credentialMap, rawZones, exposureMap] = await Promise.all([
      fetchVulnMatrix(session),
      fetchAssetVulns(session),
      fetchCredentials(session),
      fetchZones(session),
      fetchInternetExposure(session),
    ]);

    const credTargets = new Set(credentialMap.flatMap((c) => c.targets));
    const vulnerabilityMatrix = buildVulnMatrix(rawMatrix, exposureMap);
    const assetRiskRanking = buildAssetRanking(assetVulns, exposureMap, credTargets);
    const zoneAnalysis = buildZoneAnalysis(rawZones);
    const summary = buildSummary(assetVulns, vulnerabilityMatrix, zoneAnalysis);
    const recommendations = buildRecommendations(vulnerabilityMatrix, credentialMap, zoneAnalysis, assetVulns);

    return NextResponse.json({ generatedAt: new Date().toISOString(), summary, vulnerabilityMatrix, assetRiskRanking, credentialMap, zoneAnalysis, recommendations });
  } finally {
    await session.close();
  }
}
