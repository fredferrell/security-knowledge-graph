import { NextResponse } from 'next/server';
import { getSession } from '@/lib/neo4j';

type SessionLike = { run: (q: string) => Promise<{ records: unknown[] }>; close: () => Promise<void> };
type RecordLike = { get: (k: string) => unknown };

interface AssetMetrics {
  degreeCentrality: number;
  vulnerabilityCount: number;
  criticalVulnCount: number;
  credentialExposure: number;
  inboundFlows: number;
  outboundFlows: number;
}

interface AssetRisk {
  name: string;
  zone: string;
  ip: string;
  metrics: AssetMetrics;
  riskScore: number;
  riskLevel: string;
}

interface TopRisk {
  name: string;
  riskScore: number;
  riskLevel: string;
  primaryReason: string;
}

interface NetworkStats {
  totalAssets: number;
  totalVulnerabilities: number;
  totalTrafficFlows: number;
  totalCredentials: number;
  averageRiskScore: number;
}

interface AnalyticsResponse {
  assets: AssetRisk[];
  topRisks: TopRisk[];
  networkStats: NetworkStats;
}

/** Extracts a numeric value from a neo4j integer-like or plain number. */
function toNum(val: unknown): number {
  if (val === null || val === undefined) { return 0; }
  if (typeof val === 'object' && val !== null && typeof (val as { toNumber?: unknown }).toNumber === 'function') {
    return (val as { toNumber: () => number }).toNumber();
  }
  return Number(val) || 0;
}

/** Determines riskLevel from a numeric score. */
function getRiskLevel(score: number): string {
  if (score >= 8.0) { return 'critical'; }
  if (score >= 6.0) { return 'high'; }
  if (score >= 3.0) { return 'medium'; }
  return 'low';
}

/** Computes risk score (0-10) from asset metrics. */
function computeRiskScore(m: AssetMetrics, hasDenyRule: boolean): number {
  const raw =
    (m.vulnerabilityCount * 1.5) +
    (m.criticalVulnCount * 2.0) +
    (m.credentialExposure * 0.5) +
    (m.inboundFlows * 0.3) -
    (hasDenyRule ? 1.0 : 0);
  return Math.min(10, Math.max(0, Math.round(raw * 100) / 100));
}

/** Generates a human-readable primary reason string for the top risk. */
function getPrimaryReason(m: AssetMetrics): string {
  const vulnScore = m.vulnerabilityCount * 1.5 + m.criticalVulnCount * 2.0;
  const credScore = m.credentialExposure * 0.5;

  if (vulnScore >= credScore && m.vulnerabilityCount > 0) {
    const critPart = m.criticalVulnCount > 0
      ? ` including ${m.criticalVulnCount} critical`
      : '';
    return `${m.vulnerabilityCount} vulnerabilities${critPart}`;
  }
  if (credScore > 0) {
    return `credential target for ${m.credentialExposure} devices`;
  }
  if (m.inboundFlows > 0) {
    return `${m.inboundFlows} inbound traffic flows`;
  }
  return 'low risk asset';
}

/** Fetches base asset info + vulnerability counts. */
async function fetchVulnData(session: SessionLike): Promise<Map<string, { zone: string; ip: string; vulnCount: number; criticalCount: number }>> {
  const result = await session.run(`
    MATCH (a:Asset)
    OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
    RETURN a.name AS name, a.zone AS zone, a.ip AS ip,
           count(v) AS vulnCount,
           count(CASE WHEN v.severity = 'critical' THEN 1 END) AS criticalCount
  `);
  const map = new Map<string, { zone: string; ip: string; vulnCount: number; criticalCount: number }>();
  for (const record of result.records) {
    const r = record as RecordLike;
    map.set(String(r.get('name') ?? ''), {
      zone: String(r.get('zone') ?? ''),
      ip: String(r.get('ip') ?? ''),
      vulnCount: toNum(r.get('vulnCount')),
      criticalCount: toNum(r.get('criticalCount')),
    });
  }
  return map;
}

/** Fetches degree centrality per asset. */
async function fetchDegrees(session: SessionLike): Promise<Map<string, number>> {
  const result = await session.run(`
    MATCH (a:Asset)
    OPTIONAL MATCH (a)-[r]-()
    RETURN a.name AS name, count(r) AS degree
  `);
  const map = new Map<string, number>();
  for (const record of result.records) {
    const r = record as RecordLike;
    map.set(String(r.get('name') ?? ''), toNum(r.get('degree')));
  }
  return map;
}

/** Fetches credential exposure count per asset. */
async function fetchCredentialExposure(session: SessionLike): Promise<Map<string, number>> {
  const result = await session.run(`
    MATCH (a:Asset)
    OPTIONAL MATCH ()-[:HAS_CREDENTIAL]->(a)
    RETURN a.name AS name, count(*) AS credentialExposure
  `);
  const map = new Map<string, number>();
  for (const record of result.records) {
    const r = record as RecordLike;
    map.set(String(r.get('name') ?? ''), toNum(r.get('credentialExposure')));
  }
  return map;
}

/** Fetches outbound traffic flow counts per asset. */
async function fetchOutboundFlows(session: SessionLike): Promise<Map<string, number>> {
  const result = await session.run(`
    MATCH (a:Asset) OPTIONAL MATCH (a)-[:TRAFFIC_FLOW]->(t)
    RETURN a.name AS name, count(t) AS outbound
  `);
  const map = new Map<string, number>();
  for (const record of result.records) {
    const r = record as RecordLike;
    map.set(String(r.get('name') ?? ''), toNum(r.get('outbound')));
  }
  return map;
}

/** Fetches inbound traffic flow counts per asset. */
async function fetchInboundFlows(session: SessionLike): Promise<Map<string, number>> {
  const result = await session.run(`
    MATCH (a:Asset) OPTIONAL MATCH (t)-[:TRAFFIC_FLOW]->(a)
    RETURN a.name AS name, count(t) AS inbound
  `);
  const map = new Map<string, number>();
  for (const record of result.records) {
    const r = record as RecordLike;
    map.set(String(r.get('name') ?? ''), toNum(r.get('inbound')));
  }
  return map;
}

/** Fetches set of asset names that have a zone-level deny rule. */
async function fetchDenyRuleAssets(session: SessionLike): Promise<Set<string>> {
  const result = await session.run(`
    MATCH (a:Asset)
    WHERE EXISTS {
      MATCH (fw:FirewallRule)
      WHERE fw.action = 'deny' AND (fw.destZone = a.zone OR fw.sourceZone = a.zone)
    }
    RETURN a.name AS name
  `);
  const set = new Set<string>();
  for (const record of result.records) {
    const r = record as RecordLike;
    set.add(String(r.get('name') ?? ''));
  }
  return set;
}

/** GET /api/analytics — returns risk analysis of every asset in the graph. */
export async function GET(): Promise<NextResponse<AnalyticsResponse>> {
  const session = getSession();
  try {
    const vulnData = await fetchVulnData(session);
    const degrees = await fetchDegrees(session);
    const credExposure = await fetchCredentialExposure(session);
    const outboundFlows = await fetchOutboundFlows(session);
    const inboundFlows = await fetchInboundFlows(session);
    const denyRuleAssets = await fetchDenyRuleAssets(session);

    const assets: AssetRisk[] = [];
    for (const [name, vd] of vulnData) {
      const metrics: AssetMetrics = {
        degreeCentrality: degrees.get(name) ?? 0,
        vulnerabilityCount: vd.vulnCount,
        criticalVulnCount: vd.criticalCount,
        credentialExposure: credExposure.get(name) ?? 0,
        inboundFlows: inboundFlows.get(name) ?? 0,
        outboundFlows: outboundFlows.get(name) ?? 0,
      };
      const hasDenyRule = denyRuleAssets.has(name);
      const riskScore = computeRiskScore(metrics, hasDenyRule);
      assets.push({
        name,
        zone: vd.zone,
        ip: vd.ip,
        metrics,
        riskScore,
        riskLevel: getRiskLevel(riskScore),
      });
    }

    const topRisks: TopRisk[] = assets
      .slice()
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 5)
      .map(a => ({
        name: a.name,
        riskScore: a.riskScore,
        riskLevel: a.riskLevel,
        primaryReason: getPrimaryReason(a.metrics),
      }));

    const totalVulnerabilities = assets.reduce((s, a) => s + a.metrics.vulnerabilityCount, 0);
    const totalTrafficFlows = assets.reduce((s, a) => s + a.metrics.inboundFlows + a.metrics.outboundFlows, 0);
    const totalCredentials = assets.reduce((s, a) => s + a.metrics.credentialExposure, 0);
    const averageRiskScore = assets.length > 0
      ? Math.round((assets.reduce((s, a) => s + a.riskScore, 0) / assets.length) * 100) / 100
      : 0;

    const networkStats: NetworkStats = {
      totalAssets: assets.length,
      totalVulnerabilities,
      totalTrafficFlows,
      totalCredentials,
      averageRiskScore,
    };

    return NextResponse.json({ assets, topRisks, networkStats });
  } finally {
    await session.close();
  }
}
