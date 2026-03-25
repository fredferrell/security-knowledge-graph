import { NextResponse } from 'next/server';
import { readFileSync } from 'fs';
import { join } from 'path';
import { getSession } from '@/lib/neo4j';
import { parseInventory, type InventoryHost } from '@/lib/ansible-parser';

type DriftType =
  | 'missing_from_graph'
  | 'missing_from_inventory'
  | 'ip_mismatch'
  | 'zone_mismatch'
  | 'in_sync';

interface DriftItem {
  name: string;
  type: DriftType;
  inventoryValue: string;
  graphValue: string;
}

interface DriftSummary {
  totalInventory: number;
  totalGraph: number;
  inSync: number;
  drifted: number;
}

interface DriftResponse {
  driftItems: DriftItem[];
  summary: DriftSummary;
}

type RecordLike = { get: (k: string) => unknown };
type SessionLike = {
  run: (q: string) => Promise<{ records: unknown[] }>;
  close: () => Promise<void>;
};

/** Reads and parses the Ansible inventory from disk. */
function loadInventory(): InventoryHost[] {
  const hostsPath = join(process.cwd(), 'ansible', 'inventory', 'hosts.yml');
  const content = readFileSync(hostsPath, 'utf-8');
  return parseInventory(content);
}

/** Queries all Asset nodes from Neo4j. */
async function fetchGraphAssets(
  session: SessionLike,
): Promise<InventoryHost[]> {
  const query = 'MATCH (a:Asset) RETURN a.name AS name, a.ip AS ip, a.zone AS zone';
  const result = await session.run(query);
  return result.records.map((record) => {
    const r = record as RecordLike;
    return {
      name: String(r.get('name') ?? ''),
      ip: String(r.get('ip') ?? ''),
      zone: String(r.get('zone') ?? ''),
    };
  });
}

/** Compares inventory hosts against graph assets and returns drift items. */
function compareSets(
  inventoryHosts: InventoryHost[],
  graphAssets: InventoryHost[],
): DriftItem[] {
  const items: DriftItem[] = [];
  const graphByName = new Map(graphAssets.map((a) => [a.name, a]));
  const inventoryByName = new Map(inventoryHosts.map((h) => [h.name, h]));

  // Check every inventory host against the graph
  for (const host of inventoryHosts) {
    const graphAsset = graphByName.get(host.name);

    if (!graphAsset) {
      items.push({
        name: host.name,
        type: 'missing_from_graph',
        inventoryValue: `ip=${host.ip} zone=${host.zone}`,
        graphValue: '',
      });
      continue;
    }

    if (host.ip !== graphAsset.ip) {
      items.push({
        name: host.name,
        type: 'ip_mismatch',
        inventoryValue: host.ip,
        graphValue: graphAsset.ip,
      });
      continue;
    }

    if (host.zone !== graphAsset.zone) {
      items.push({
        name: host.name,
        type: 'zone_mismatch',
        inventoryValue: host.zone,
        graphValue: graphAsset.zone,
      });
      continue;
    }

    items.push({
      name: host.name,
      type: 'in_sync',
      inventoryValue: `ip=${host.ip} zone=${host.zone}`,
      graphValue: `ip=${graphAsset.ip} zone=${graphAsset.zone}`,
    });
  }

  // Check for graph assets not in inventory
  for (const asset of graphAssets) {
    if (!inventoryByName.has(asset.name)) {
      items.push({
        name: asset.name,
        type: 'missing_from_inventory',
        inventoryValue: '',
        graphValue: `ip=${asset.ip} zone=${asset.zone}`,
      });
    }
  }

  return items;
}

/** GET /api/drift — compares Ansible inventory against Neo4j graph and returns drift report. */
export async function GET(): Promise<NextResponse<DriftResponse | { error: string }>> {
  const session = getSession();
  try {
    const inventoryHosts = loadInventory();
    const graphAssets = await fetchGraphAssets(session);
    const driftItems = compareSets(inventoryHosts, graphAssets);

    const inSync = driftItems.filter((i) => i.type === 'in_sync').length;
    const drifted = driftItems.length - inSync;

    const summary: DriftSummary = {
      totalInventory: inventoryHosts.length,
      totalGraph: graphAssets.length,
      inSync,
      drifted,
    };

    return NextResponse.json({ driftItems, summary });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return NextResponse.json({ error: message }, { status: 500 });
  } finally {
    await session.close();
  }
}
