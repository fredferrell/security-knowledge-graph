import { NextResponse } from 'next/server';
import { getSession } from '@/lib/neo4j';
import type { GraphData, GraphNode, GraphLink } from '@/lib/types';

/** Returns the id for a node based on its labels and properties. */
function resolveNodeId(labels: string[], properties: Record<string, unknown>): string {
  if (labels.includes('Vulnerability')) {
    return String(properties['cveId'] ?? '');
  }
  return String(properties['name'] ?? '');
}

/** Returns the group for a node: zone for Assets, label for others. */
function resolveNodeGroup(labels: string[], properties: Record<string, unknown>): string {
  if (labels.includes('Asset') && properties['zone']) {
    return String(properties['zone']);
  }
  return labels[0] ?? 'unknown';
}

/** Queries all nodes from Neo4j and maps them to GraphNode objects. */
async function fetchNodes(
  session: { run: (q: string) => Promise<{ records: unknown[] }> },
): Promise<GraphNode[]> {
  const query = `
    MATCH (n)
    WHERE n:Asset OR n:Vulnerability OR n:Zone OR n:FirewallRule
    RETURN n
  `;
  const result = await session.run(query);
  return result.records.map((record) => {
    const r = record as { get: (k: string) => { labels: string[]; properties: Record<string, unknown> } };
    const node = r.get('n');
    const { labels, properties } = node;
    const id = resolveNodeId(labels, properties);
    const label = labels[0] ?? 'Unknown';
    return {
      id,
      label,
      type: String(properties['type'] ?? label),
      group: resolveNodeGroup(labels, properties),
      properties,
    };
  });
}

/** Queries all relationships from Neo4j and maps them to GraphLink objects. */
async function fetchLinks(
  session: { run: (q: string) => Promise<{ records: unknown[] }> },
): Promise<GraphLink[]> {
  const query = `
    MATCH (a)-[r]->(b)
    WHERE (a:Asset OR a:Vulnerability OR a:Zone OR a:FirewallRule)
      AND (b:Asset OR b:Vulnerability OR b:Zone OR b:FirewallRule)
    RETURN r, r.startId AS startId, r.endId AS endId,
           CASE WHEN a:Vulnerability THEN a.cveId ELSE a.name END AS startId,
           CASE WHEN b:Vulnerability THEN b.cveId ELSE b.name END AS endId
  `;
  const result = await session.run(query);
  return result.records.map((record) => {
    const r = record as { get: (k: string) => unknown };
    const rel = r.get('r') as { type: string; properties: Record<string, unknown> };
    const source = String(r.get('startId') ?? '');
    const target = String(r.get('endId') ?? '');
    return {
      source,
      target,
      type: rel.type,
      properties: rel.properties,
    };
  });
}

/** GET /api/graph — returns all nodes and relationships as a GraphData object. */
export async function GET(): Promise<NextResponse<GraphData>> {
  const session = getSession();
  try {
    const [nodes, links] = await Promise.all([fetchNodes(session), fetchLinks(session)]);
    return NextResponse.json({ nodes, links });
  } finally {
    await session.close();
  }
}
