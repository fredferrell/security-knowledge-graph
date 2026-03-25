# SKG Application Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Security Knowledge Graph web application — Neo4j data model, seed script, API routes, and graph visualization UI — so the demo works standalone with realistic data from the CML lab topology.

**Architecture:** Next.js App Router with API routes that query Neo4j via the official JS driver. Seed script populates the graph from `cml/topology.yaml` plus synthetic CVE/traffic data. Frontend uses a force-directed graph visualization library (react-force-graph) to render nodes and relationships interactively.

**Tech Stack:** Next.js 15, TypeScript, neo4j-driver, react-force-graph-2d, js-yaml (for seed script)

---

## File Structure

```
src/
├── lib/
│   ├── neo4j.ts              # Neo4j driver singleton + session helper
│   └── types.ts              # Shared TypeScript types (Asset, CVE, Rule, etc.)
├── app/
│   ├── layout.tsx            # Already exists — add global styles
│   ├── page.tsx              # Already exists — replace with dashboard
│   ├── api/
│   │   ├── graph/
│   │   │   └── route.ts      # GET /api/graph — full graph data
│   │   ├── blast-radius/
│   │   │   └── route.ts      # GET /api/blast-radius?cve=CVE-XXX
│   │   └── gaps/
│   │       └── route.ts      # GET /api/gaps — protection gap analysis
│   └── globals.css           # Minimal dark-theme styles
├── components/
│   ├── graph-view.tsx        # Force-directed graph visualization
│   ├── sidebar.tsx           # Query panel + results display
│   └── node-detail.tsx       # Detail panel when a node is selected
scripts/
└── seed-neo4j.ts             # Populates Neo4j from topology + synthetic data
tests/
├── lib/
│   └── types.test.ts         # Type guard tests
├── api/
│   ├── graph.test.ts         # Graph API route tests
│   ├── blast-radius.test.ts  # Blast radius query tests
│   └── gaps.test.ts          # Gap analysis query tests
└── seed/
    └── seed-data.test.ts     # Seed data structure validation
```

---

### Task 1: Install Dependencies + Neo4j Driver

**Files:**
- Modify: `package.json`
- Create: `src/lib/neo4j.ts`
- Create: `src/lib/types.ts`
- Test: `tests/lib/types.test.ts`

- [ ] **Step 1: Install neo4j-driver and supporting packages**

```bash
npm install neo4j-driver
npm install -D js-yaml @types/js-yaml
```

- [ ] **Step 2: Write type definitions with type guards**

Create `src/lib/types.ts`:

```typescript
export interface Asset {
  id: string;
  name: string;
  label: string;
  type: 'router' | 'firewall' | 'server' | 'vm';
  zone: string;
  ip: string;
  software: string[];
  description: string;
}

export interface Vulnerability {
  id: string;
  cveId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  affectedSoftware: string;
  affectedVersion: string;
}

export interface FirewallRule {
  id: string;
  firewall: string;
  name: string;
  sourceZone: string;
  destZone: string;
  sourceIp: string;
  destIp: string;
  port: string;
  action: 'allow' | 'deny';
}

export interface TrafficFlow {
  sourceAsset: string;
  destAsset: string;
  port: number;
  protocol: string;
  bytesTotal: number;
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  group: string;
  properties: Record<string, unknown>;
}

export interface GraphLink {
  source: string;
  target: string;
  type: string;
  properties: Record<string, unknown>;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

export function isAsset(obj: unknown): obj is Asset {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'id' in obj &&
    'name' in obj &&
    'zone' in obj &&
    'type' in obj
  );
}

export function isVulnerability(obj: unknown): obj is Vulnerability {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'cveId' in obj &&
    'severity' in obj
  );
}
```

- [ ] **Step 3: Write failing tests for type guards**

Create `tests/lib/types.test.ts`:

```typescript
import { describe, it, expect } from '@jest/globals';
import { isAsset, isVulnerability } from '@/lib/types';

describe('isAsset', () => {
  it('returns true for valid asset', () => {
    const asset = { id: '1', name: 'web-srv', zone: 'dmz', type: 'server' };
    expect(isAsset(asset)).toBe(true);
  });

  it('returns false for missing fields', () => {
    expect(isAsset({ id: '1' })).toBe(false);
    expect(isAsset(null)).toBe(false);
    expect(isAsset(undefined)).toBe(false);
  });
});

describe('isVulnerability', () => {
  it('returns true for valid vulnerability', () => {
    const vuln = { cveId: 'CVE-2021-41773', severity: 'critical' };
    expect(isVulnerability(vuln)).toBe(true);
  });

  it('returns false for missing fields', () => {
    expect(isVulnerability({ cveId: 'CVE-2021-41773' })).toBe(false);
    expect(isVulnerability({})).toBe(false);
  });
});
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
npm test tests/lib/types.test.ts
```

Expected: PASS (types are pure functions, no async/DB dependency)

- [ ] **Step 5: Create Neo4j driver singleton**

Create `src/lib/neo4j.ts`:

```typescript
import neo4j, { Driver, Session } from 'neo4j-driver';

let driver: Driver | null = null;

export function getDriver(): Driver {
  if (!driver) {
    const uri = process.env.NEO4J_URI || 'bolt://localhost:7687';
    const user = process.env.NEO4J_USER || 'neo4j';
    const password = process.env.NEO4J_PASSWORD || 'changeme';
    driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  }
  return driver;
}

export function getSession(): Session {
  return getDriver().session();
}

export async function closeDriver(): Promise<void> {
  if (driver) {
    await driver.close();
    driver = null;
  }
}
```

- [ ] **Step 6: Commit**

```bash
git add src/lib/neo4j.ts src/lib/types.ts tests/lib/types.test.ts package.json package-lock.json
git commit -m "feat: add Neo4j driver, type definitions, and type guard tests"
```

---

### Task 2: Seed Script — Populate Neo4j from Topology

**Files:**
- Create: `scripts/seed-neo4j.ts`
- Test: `tests/seed/seed-data.test.ts`

- [ ] **Step 1: Write test validating seed data structure**

Create `tests/seed/seed-data.test.ts`:

```typescript
import { describe, it, expect } from '@jest/globals';
import { readFileSync } from 'fs';
import { load } from 'js-yaml';
import { isAsset } from '@/lib/types';

describe('seed data from topology.yaml', () => {
  const topology = load(
    readFileSync('cml/topology.yaml', 'utf-8')
  ) as Record<string, unknown>;

  it('topology has nodes array', () => {
    expect(Array.isArray((topology as any).nodes)).toBe(true);
  });

  it('topology has networks array', () => {
    expect(Array.isArray((topology as any).networks)).toBe(true);
  });

  it('topology has exactly 10 nodes', () => {
    expect((topology as any).nodes).toHaveLength(10);
  });

  it('each node has required fields for Asset conversion', () => {
    for (const node of (topology as any).nodes) {
      expect(node).toHaveProperty('name');
      expect(node).toHaveProperty('type');
      expect(node).toHaveProperty('zone');
      expect(node).toHaveProperty('description');
    }
  });
});
```

- [ ] **Step 2: Run test to verify it passes**

```bash
npm test tests/seed/seed-data.test.ts
```

Expected: PASS (reads the existing topology.yaml)

- [ ] **Step 3: Write the seed script**

Create `scripts/seed-neo4j.ts`:

```typescript
import { readFileSync } from 'fs';
import { load } from 'js-yaml';
import neo4j from 'neo4j-driver';

interface TopologyNode {
  name: string;
  type: string;
  label: string;
  zone: string;
  description: string;
  interfaces?: Array<{ name: string; network: string; description: string }>;
  software?: string[];
  telemetry?: string[];
}

interface TopologyNetwork {
  name: string;
  description: string;
  subnet: string;
}

interface FirewallPolicy {
  name: string;
  source: string;
  destination: string;
  port?: string;
  action: string;
  description: string;
}

interface Topology {
  nodes: TopologyNode[];
  networks: TopologyNetwork[];
  firewall_policies: Record<string, FirewallPolicy[]>;
}

// CVE data matching our vulnerable services
const cves = [
  {
    cveId: 'CVE-2021-41773',
    severity: 'critical',
    description: 'Apache 2.4.49 path traversal — allows reading files outside document root via crafted URI',
    affectedSoftware: 'apache',
    affectedVersion: '2.4.49',
  },
  {
    cveId: 'CVE-2021-42013',
    severity: 'critical',
    description: 'Apache 2.4.49/2.4.50 RCE via path traversal bypass when CGI is enabled',
    affectedSoftware: 'apache',
    affectedVersion: '2.4.49',
  },
  {
    cveId: 'CVE-2023-38408',
    severity: 'high',
    description: 'OpenSSH before 9.3p2 PKCS#11 remote code execution via forwarded agent socket',
    affectedSoftware: 'openssh',
    affectedVersion: '8.2',
  },
  {
    cveId: 'CVE-2023-51767',
    severity: 'medium',
    description: 'OpenSSH through 9.6 authentication bypass via row hammer attack on shared memory',
    affectedSoftware: 'openssh',
    affectedVersion: '8.2',
  },
  {
    cveId: 'CVE-2022-32081',
    severity: 'high',
    description: 'MariaDB Server use-after-poison in prepare_inplace_alter_table_dict',
    affectedSoftware: 'mariadb',
    affectedVersion: '10.x',
  },
];

// Synthetic traffic flows matching the topology
const trafficFlows = [
  { source: 'edge-rtr', dest: 'edge-fw', port: 443, protocol: 'TCP', bytes: 15_000_000 },
  { source: 'edge-fw', dest: 'web-srv', port: 443, protocol: 'TCP', bytes: 12_000_000 },
  { source: 'web-srv', dest: 'app-srv', port: 443, protocol: 'TCP', bytes: 8_000_000 },
  { source: 'app-srv', dest: 'db-srv', port: 3306, protocol: 'TCP', bytes: 3_000_000 },
  { source: 'dns-srv', dest: 'edge-rtr', port: 53, protocol: 'UDP', bytes: 500_000 },
  { source: 'web-srv', dest: 'dns-srv', port: 53, protocol: 'UDP', bytes: 200_000 },
  { source: 'app-srv', dest: 'dns-srv', port: 53, protocol: 'UDP', bytes: 150_000 },
  { source: 'db-srv', dest: 'dns-srv', port: 53, protocol: 'UDP', bytes: 100_000 },
  { source: 'mgmt-vm', dest: 'web-srv', port: 22, protocol: 'TCP', bytes: 50_000 },
  { source: 'mgmt-vm', dest: 'app-srv', port: 22, protocol: 'TCP', bytes: 50_000 },
  { source: 'mgmt-vm', dest: 'db-srv', port: 22, protocol: 'TCP', bytes: 50_000 },
  { source: 'mgmt-vm', dest: 'dns-srv', port: 22, protocol: 'TCP', bytes: 50_000 },
  { source: 'mgmt-vm', dest: 'vuln-vm', port: 22, protocol: 'TCP', bytes: 50_000 },
  { source: 'mgmt-vm', dest: 'elk-srv', port: 22, protocol: 'TCP', bytes: 50_000 },
  { source: 'vuln-vm', dest: 'dns-srv', port: 53, protocol: 'UDP', bytes: 80_000 },
  { source: 'elk-srv', dest: 'dns-srv', port: 53, protocol: 'UDP', bytes: 120_000 },
];

// Ansible credential relationships
const credentials = [
  { from: 'mgmt-vm', to: 'web-srv', type: 'ssh-key', user: 'skg-admin' },
  { from: 'mgmt-vm', to: 'app-srv', type: 'ssh-key', user: 'skg-admin' },
  { from: 'mgmt-vm', to: 'db-srv', type: 'ssh-key', user: 'skg-admin' },
  { from: 'mgmt-vm', to: 'dns-srv', type: 'ssh-key', user: 'skg-admin' },
  { from: 'mgmt-vm', to: 'vuln-vm', type: 'ssh-key', user: 'skg-admin' },
  { from: 'mgmt-vm', to: 'elk-srv', type: 'ssh-key', user: 'skg-admin' },
  { from: 'mgmt-vm', to: 'edge-fw', type: 'api-key', user: 'admin' },
  { from: 'mgmt-vm', to: 'internal-fw', type: 'api-key', user: 'admin' },
  { from: 'mgmt-vm', to: 'edge-rtr', type: 'ssh', user: 'admin' },
];

async function seed() {
  const topologyRaw = readFileSync('cml/topology.yaml', 'utf-8');
  const topology = load(topologyRaw) as Topology;

  const uri = process.env.NEO4J_URI || 'bolt://localhost:7687';
  const user = process.env.NEO4J_USER || 'neo4j';
  const password = process.env.NEO4J_PASSWORD || 'changeme';

  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  const session = driver.session();

  try {
    // Clear existing data
    await session.run('MATCH (n) DETACH DELETE n');
    console.log('Cleared existing graph data');

    // Create Zone nodes
    const zones = [...new Set(topology.nodes.map((n) => n.zone))];
    for (const zone of zones) {
      await session.run(
        'CREATE (:Zone {name: $name})',
        { name: zone }
      );
    }
    console.log(`Created ${zones.length} zones`);

    // Create Network nodes
    for (const net of topology.networks) {
      await session.run(
        'CREATE (:Network {name: $name, subnet: $subnet, description: $description})',
        net
      );
    }
    console.log(`Created ${topology.networks.length} networks`);

    // Create Asset nodes
    for (const node of topology.nodes) {
      const ipMap: Record<string, string> = {
        'edge-rtr': '10.0.0.1', 'edge-fw': '10.0.0.2',
        'web-srv': '10.10.1.10', 'internal-fw': '10.0.1.2',
        'app-srv': '10.10.2.10', 'db-srv': '10.10.3.10',
        'dns-srv': '10.10.4.10', 'vuln-vm': '10.10.4.20',
        'elk-srv': '10.10.5.10', 'mgmt-vm': '10.10.5.20',
      };

      await session.run(
        `CREATE (a:Asset {
          name: $name, label: $label, type: $type,
          zone: $zone, ip: $ip, description: $description,
          software: $software
        })`,
        {
          name: node.name,
          label: node.label,
          type: node.type,
          zone: node.zone,
          ip: ipMap[node.name] || '',
          description: node.description,
          software: node.software || [],
        }
      );

      // Link Asset to Zone
      await session.run(
        `MATCH (a:Asset {name: $name}), (z:Zone {name: $zone})
         CREATE (a)-[:IN_ZONE]->(z)`,
        { name: node.name, zone: node.zone }
      );
    }
    console.log(`Created ${topology.nodes.length} assets`);

    // Create Vulnerability nodes + link to affected assets
    for (const cve of cves) {
      await session.run(
        `CREATE (:Vulnerability {
          cveId: $cveId, severity: $severity,
          description: $description,
          affectedSoftware: $affectedSoftware,
          affectedVersion: $affectedVersion
        })`,
        cve
      );

      // Link to assets running the affected software
      await session.run(
        `MATCH (v:Vulnerability {cveId: $cveId}), (a:Asset)
         WHERE any(s IN a.software WHERE s CONTAINS $sw)
         CREATE (a)-[:HAS_VULNERABILITY]->(v)`,
        { cveId: cve.cveId, sw: cve.affectedSoftware }
      );
    }
    console.log(`Created ${cves.length} vulnerabilities`);

    // Create Firewall Rule nodes + relationships
    for (const [fwName, rules] of Object.entries(topology.firewall_policies)) {
      for (const rule of rules) {
        await session.run(
          `CREATE (:FirewallRule {
            firewall: $firewall, name: $name,
            source: $source, destination: $destination,
            port: $port, action: $action,
            description: $description
          })`,
          {
            firewall: fwName,
            name: rule.name,
            source: rule.source,
            destination: rule.destination,
            port: rule.port || 'any',
            action: rule.action,
            description: rule.description,
          }
        );

        await session.run(
          `MATCH (fw:Asset {name: $fwName}), (r:FirewallRule {name: $ruleName, firewall: $fwName})
           CREATE (fw)-[:ENFORCES]->(r)`,
          { fwName: fwName === 'edge-fw' ? 'edge-fw' : 'internal-fw', ruleName: rule.name }
        );
      }
    }
    console.log('Created firewall rules');

    // Create traffic flow relationships
    for (const flow of trafficFlows) {
      await session.run(
        `MATCH (s:Asset {name: $source}), (d:Asset {name: $dest})
         CREATE (s)-[:TRAFFIC_FLOW {port: $port, protocol: $protocol, bytesTotal: $bytes}]->(d)`,
        { source: flow.source, dest: flow.dest, port: flow.port, protocol: flow.protocol, bytes: flow.bytes }
      );
    }
    console.log(`Created ${trafficFlows.length} traffic flows`);

    // Create credential relationships
    for (const cred of credentials) {
      await session.run(
        `MATCH (s:Asset {name: $from}), (d:Asset {name: $to})
         CREATE (s)-[:HAS_CREDENTIAL {type: $type, user: $user}]->(d)`,
        cred
      );
    }
    console.log(`Created ${credentials.length} credential relationships`);

    console.log('\nSeed complete. Graph summary:');
    const result = await session.run(
      `MATCH (n) RETURN labels(n)[0] AS type, count(n) AS count ORDER BY count DESC`
    );
    for (const record of result.records) {
      console.log(`  ${record.get('type')}: ${record.get('count')}`);
    }
  } finally {
    await session.close();
    await driver.close();
  }
}

seed().catch(console.error);
```

- [ ] **Step 4: Add seed script to package.json**

Add to scripts section:

```json
"seed": "npx ts-node --esm scripts/seed-neo4j.ts"
```

Also add `ts-node` as a dev dependency:

```bash
npm install -D ts-node
```

- [ ] **Step 5: Commit**

```bash
git add scripts/seed-neo4j.ts tests/seed/seed-data.test.ts package.json package-lock.json
git commit -m "feat: add Neo4j seed script with topology, CVEs, traffic flows, and credentials"
```

---

### Task 3: API Route — Full Graph Data

**Files:**
- Create: `src/app/api/graph/route.ts`
- Test: `tests/api/graph.test.ts`

- [ ] **Step 1: Write test for graph data structure**

Create `tests/api/graph.test.ts`:

```typescript
import { describe, it, expect } from '@jest/globals';
import type { GraphData } from '@/lib/types';

describe('GraphData structure', () => {
  it('validates a well-formed graph response', () => {
    const data: GraphData = {
      nodes: [
        { id: 'web-srv', label: 'Web Server', type: 'Asset', group: 'dmz', properties: {} },
      ],
      links: [
        { source: 'web-srv', target: 'app-srv', type: 'TRAFFIC_FLOW', properties: { port: 443 } },
      ],
    };
    expect(data.nodes).toHaveLength(1);
    expect(data.links).toHaveLength(1);
    expect(data.links[0].source).toBe('web-srv');
  });
});
```

- [ ] **Step 2: Run test to verify it passes**

```bash
npm test tests/api/graph.test.ts
```

- [ ] **Step 3: Implement the API route**

Create `src/app/api/graph/route.ts`:

```typescript
import { NextResponse } from 'next/server';
import { getSession } from '@/lib/neo4j';
import type { GraphNode, GraphLink, GraphData } from '@/lib/types';

export async function GET() {
  const session = getSession();

  try {
    // Fetch all nodes
    const nodeResult = await session.run(`
      MATCH (n)
      WHERE n:Asset OR n:Vulnerability OR n:Zone OR n:FirewallRule
      RETURN n, labels(n)[0] AS type
    `);

    const nodes: GraphNode[] = nodeResult.records.map((record) => {
      const node = record.get('n');
      const type = record.get('type');
      const props = node.properties;
      return {
        id: props.name || props.cveId || props.id || `${type}-${node.identity.toString()}`,
        label: props.label || props.name || props.cveId || '',
        type,
        group: props.zone || type,
        properties: props,
      };
    });

    // Fetch all relationships
    const relResult = await session.run(`
      MATCH (a)-[r]->(b)
      WHERE (a:Asset OR a:Vulnerability OR a:Zone OR a:FirewallRule)
        AND (b:Asset OR b:Vulnerability OR b:Zone OR b:FirewallRule)
      RETURN a, r, b, type(r) AS relType
    `);

    const links: GraphLink[] = relResult.records.map((record) => {
      const source = record.get('a').properties;
      const target = record.get('b').properties;
      const relType = record.get('relType');
      const relProps = record.get('r').properties;
      return {
        source: source.name || source.cveId || '',
        target: target.name || target.cveId || '',
        type: relType,
        properties: relProps,
      };
    });

    const data: GraphData = { nodes, links };
    return NextResponse.json(data);
  } finally {
    await session.close();
  }
}
```

- [ ] **Step 4: Commit**

```bash
git add src/app/api/graph/route.ts tests/api/graph.test.ts
git commit -m "feat: add /api/graph route returning full knowledge graph data"
```

---

### Task 4: API Route — Blast Radius Query

**Files:**
- Create: `src/app/api/blast-radius/route.ts`
- Test: `tests/api/blast-radius.test.ts`

- [ ] **Step 1: Write test for blast radius response shape**

Create `tests/api/blast-radius.test.ts`:

```typescript
import { describe, it, expect } from '@jest/globals';

describe('blast radius response shape', () => {
  it('has expected fields', () => {
    const response = {
      cve: 'CVE-2021-41773',
      affectedAssets: [{ name: 'vuln-vm', zone: 'corporate' }],
      exposurePaths: [
        { path: ['edge-rtr', 'edge-fw', 'internal-fw', 'vuln-vm'], hops: 3 },
      ],
      firewallRules: [
        { name: 'default-deny', firewall: 'internal-fw', action: 'deny' },
      ],
    };
    expect(response.affectedAssets).toHaveLength(1);
    expect(response.exposurePaths[0].path[0]).toBe('edge-rtr');
  });
});
```

- [ ] **Step 2: Run test**

```bash
npm test tests/api/blast-radius.test.ts
```

- [ ] **Step 3: Implement blast radius route**

Create `src/app/api/blast-radius/route.ts`:

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/lib/neo4j';

export async function GET(request: NextRequest) {
  const cveId = request.nextUrl.searchParams.get('cve');
  if (!cveId) {
    return NextResponse.json({ error: 'Missing cve parameter' }, { status: 400 });
  }

  const session = getSession();

  try {
    // Find affected assets
    const affectedResult = await session.run(
      `MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability {cveId: $cveId})
       RETURN a.name AS name, a.zone AS zone, a.ip AS ip, a.label AS label`,
      { cveId }
    );

    const affectedAssets = affectedResult.records.map((r) => ({
      name: r.get('name'),
      zone: r.get('zone'),
      ip: r.get('ip'),
      label: r.get('label'),
    }));

    // Find exposure paths from internet edge to affected assets
    const pathResult = await session.run(
      `MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability {cveId: $cveId})
       MATCH path = shortestPath((entry:Asset {name: 'edge-rtr'})-[:TRAFFIC_FLOW*..6]->(a))
       RETURN [n IN nodes(path) | n.name] AS path, length(path) AS hops`,
      { cveId }
    );

    const exposurePaths = pathResult.records.map((r) => ({
      path: r.get('path'),
      hops: r.get('hops').toNumber(),
    }));

    // Find firewall rules along the path
    const rulesResult = await session.run(
      `MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability {cveId: $cveId})
       MATCH (fw:Asset)-[:ENFORCES]->(rule:FirewallRule)
       WHERE rule.destination CONTAINS a.zone OR rule.source CONTAINS a.zone
       RETURN rule.name AS name, rule.firewall AS firewall,
              rule.action AS action, rule.port AS port, rule.description AS description`,
      { cveId }
    );

    const firewallRules = rulesResult.records.map((r) => ({
      name: r.get('name'),
      firewall: r.get('firewall'),
      action: r.get('action'),
      port: r.get('port'),
      description: r.get('description'),
    }));

    return NextResponse.json({
      cve: cveId,
      affectedAssets,
      exposurePaths,
      firewallRules,
    });
  } finally {
    await session.close();
  }
}
```

- [ ] **Step 4: Commit**

```bash
git add src/app/api/blast-radius/route.ts tests/api/blast-radius.test.ts
git commit -m "feat: add /api/blast-radius route for CVE exposure path tracing"
```

---

### Task 5: API Route — Gap Analysis

**Files:**
- Create: `src/app/api/gaps/route.ts`
- Test: `tests/api/gaps.test.ts`

- [ ] **Step 1: Write test for gap analysis response shape**

Create `tests/api/gaps.test.ts`:

```typescript
import { describe, it, expect } from '@jest/globals';

describe('gap analysis response shape', () => {
  it('has expected fields', () => {
    const response = {
      vulnerableAssets: [
        {
          name: 'vuln-vm',
          vulnerabilities: ['CVE-2021-41773'],
          protectedBy: [],
          gaps: ['No firewall rule blocks inbound to corporate zone from DMZ'],
        },
      ],
      summary: { totalVulnerabilities: 4, assetsWithGaps: 1, coveredAssets: 2 },
    };
    expect(response.vulnerableAssets[0].gaps).toHaveLength(1);
    expect(response.summary.assetsWithGaps).toBe(1);
  });
});
```

- [ ] **Step 2: Run test**

```bash
npm test tests/api/gaps.test.ts
```

- [ ] **Step 3: Implement gap analysis route**

Create `src/app/api/gaps/route.ts`:

```typescript
import { NextResponse } from 'next/server';
import { getSession } from '@/lib/neo4j';

export async function GET() {
  const session = getSession();

  try {
    // Find all assets with vulnerabilities and their protection status
    const result = await session.run(`
      MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
      OPTIONAL MATCH (fw:Asset {type: 'paloalto'})-[:ENFORCES]->(rule:FirewallRule {action: 'deny'})
        WHERE rule.destination CONTAINS a.zone
      RETURN a.name AS name, a.zone AS zone, a.ip AS ip, a.label AS label,
             collect(DISTINCT v.cveId) AS vulnerabilities,
             collect(DISTINCT v.severity) AS severities,
             collect(DISTINCT rule.name) AS denyRules
    `);

    const vulnerableAssets = result.records.map((r) => {
      const denyRules = r.get('denyRules').filter(Boolean);
      const vulns = r.get('vulnerabilities');
      const gaps: string[] = [];

      if (denyRules.length === 0) {
        gaps.push(`No deny rules protect ${r.get('zone')} zone where ${r.get('name')} resides`);
      }

      return {
        name: r.get('name'),
        zone: r.get('zone'),
        ip: r.get('ip'),
        label: r.get('label'),
        vulnerabilities: vulns,
        severities: r.get('severities'),
        protectedBy: denyRules,
        gaps,
      };
    });

    const totalVulns = await session.run('MATCH (:Asset)-[:HAS_VULNERABILITY]->(v) RETURN count(v) AS c');
    const totalCount = totalVulns.records[0].get('c').toNumber();

    return NextResponse.json({
      vulnerableAssets,
      summary: {
        totalVulnerabilities: totalCount,
        assetsWithGaps: vulnerableAssets.filter((a) => a.gaps.length > 0).length,
        coveredAssets: vulnerableAssets.filter((a) => a.gaps.length === 0).length,
      },
    });
  } finally {
    await session.close();
  }
}
```

- [ ] **Step 4: Commit**

```bash
git add src/app/api/gaps/route.ts tests/api/gaps.test.ts
git commit -m "feat: add /api/gaps route for protection gap analysis"
```

---

### Task 6: Frontend — Graph Visualization Component

**Files:**
- Modify: `package.json` (add react-force-graph-2d)
- Create: `src/components/graph-view.tsx`
- Create: `src/components/node-detail.tsx`
- Create: `src/components/sidebar.tsx`
- Create: `src/app/globals.css`

- [ ] **Step 1: Install visualization dependency**

```bash
npm install react-force-graph-2d
```

- [ ] **Step 2: Create the graph visualization component**

Create `src/components/graph-view.tsx`:

```tsx
'use client';

import { useCallback, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import type { GraphData, GraphNode } from '@/lib/types';

const COLOR_MAP: Record<string, string> = {
  'internet-edge': '#ef4444',
  edge: '#f97316',
  dmz: '#eab308',
  'app-tier': '#22c55e',
  'db-tier': '#3b82f6',
  corporate: '#8b5cf6',
  management: '#ec4899',
  Vulnerability: '#ff0000',
  Zone: '#6b7280',
  FirewallRule: '#64748b',
};

interface GraphViewProps {
  data: GraphData;
  onNodeClick: (node: GraphNode) => void;
  highlightNodes?: Set<string>;
}

export function GraphView({ data, onNodeClick, highlightNodes }: GraphViewProps) {
  const fgRef = useRef<any>(null);

  const nodeColor = useCallback(
    (node: any) => {
      if (highlightNodes?.has(node.id)) return '#ff6b6b';
      return COLOR_MAP[node.group] || '#94a3b8';
    },
    [highlightNodes]
  );

  const nodeLabel = useCallback(
    (node: any) => `${node.label || node.id}\n[${node.type}] ${node.group}`,
    []
  );

  const linkColor = useCallback(
    (link: any) => {
      if (link.type === 'HAS_VULNERABILITY') return '#ff0000';
      if (link.type === 'TRAFFIC_FLOW') return '#22c55e';
      if (link.type === 'HAS_CREDENTIAL') return '#f97316';
      if (link.type === 'ENFORCES') return '#3b82f6';
      return '#475569';
    },
    []
  );

  return (
    <ForceGraph2D
      ref={fgRef}
      graphData={data}
      nodeId="id"
      nodeLabel={nodeLabel}
      nodeColor={nodeColor}
      nodeRelSize={6}
      linkDirectionalArrowLength={4}
      linkDirectionalArrowRelPos={1}
      linkColor={linkColor}
      linkLabel={(link: any) => link.type}
      onNodeClick={(node: any) => onNodeClick(node as GraphNode)}
      backgroundColor="#0f172a"
    />
  );
}
```

- [ ] **Step 3: Create the node detail panel**

Create `src/components/node-detail.tsx`:

```tsx
'use client';

import type { GraphNode } from '@/lib/types';

interface NodeDetailProps {
  node: GraphNode | null;
  onClose: () => void;
}

export function NodeDetail({ node, onClose }: NodeDetailProps) {
  if (!node) return null;

  return (
    <div className="node-detail">
      <div className="node-detail-header">
        <h3>{node.label || node.id}</h3>
        <button onClick={onClose}>x</button>
      </div>
      <div className="node-detail-body">
        <p><strong>Type:</strong> {node.type}</p>
        <p><strong>Group:</strong> {node.group}</p>
        {Object.entries(node.properties).map(([key, value]) => (
          <p key={key}>
            <strong>{key}:</strong> {Array.isArray(value) ? value.join(', ') : String(value)}
          </p>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Create the sidebar with query controls**

Create `src/components/sidebar.tsx`:

```tsx
'use client';

import { useState } from 'react';

interface SidebarProps {
  onBlastRadius: (cveId: string) => void;
  onGapAnalysis: () => void;
  onReset: () => void;
  gapResults: any | null;
  blastResults: any | null;
}

export function Sidebar({ onBlastRadius, onGapAnalysis, onReset, gapResults, blastResults }: SidebarProps) {
  const [cveInput, setCveInput] = useState('CVE-2021-41773');

  return (
    <div className="sidebar">
      <h2>Security Knowledge Graph</h2>

      <div className="sidebar-section">
        <h3>Blast Radius</h3>
        <input
          type="text"
          value={cveInput}
          onChange={(e) => setCveInput(e.target.value)}
          placeholder="CVE-2021-41773"
        />
        <button onClick={() => onBlastRadius(cveInput)}>Trace Blast Radius</button>
      </div>

      <div className="sidebar-section">
        <h3>Gap Analysis</h3>
        <button onClick={onGapAnalysis}>Run Gap Analysis</button>
      </div>

      <div className="sidebar-section">
        <button onClick={onReset}>Reset View</button>
      </div>

      {blastResults && (
        <div className="sidebar-results">
          <h3>Blast Radius: {blastResults.cve}</h3>
          <p><strong>Affected:</strong> {blastResults.affectedAssets?.length || 0} assets</p>
          {blastResults.exposurePaths?.map((p: any, i: number) => (
            <div key={i} className="path-display">
              <p><strong>Path ({p.hops} hops):</strong></p>
              <p>{p.path?.join(' → ')}</p>
            </div>
          ))}
          {blastResults.firewallRules?.map((r: any, i: number) => (
            <p key={i} className={r.action === 'deny' ? 'rule-deny' : 'rule-allow'}>
              {r.firewall}: {r.name} ({r.action})
            </p>
          ))}
        </div>
      )}

      {gapResults && (
        <div className="sidebar-results">
          <h3>Gap Analysis</h3>
          <p>Vulnerabilities: {gapResults.summary?.totalVulnerabilities}</p>
          <p>Assets with gaps: {gapResults.summary?.assetsWithGaps}</p>
          <p>Covered assets: {gapResults.summary?.coveredAssets}</p>
          {gapResults.vulnerableAssets?.map((a: any, i: number) => (
            <div key={i} className="gap-asset">
              <p><strong>{a.name}</strong> ({a.zone})</p>
              <p>CVEs: {a.vulnerabilities?.join(', ')}</p>
              {a.gaps?.map((g: string, j: number) => (
                <p key={j} className="gap-warning">{g}</p>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 5: Commit**

```bash
git add src/components/graph-view.tsx src/components/node-detail.tsx src/components/sidebar.tsx package.json package-lock.json
git commit -m "feat: add graph visualization, node detail, and sidebar components"
```

---

### Task 7: Frontend — Dashboard Page + Styles

**Files:**
- Modify: `src/app/page.tsx`
- Create: `src/app/globals.css`
- Modify: `src/app/layout.tsx`

- [ ] **Step 1: Create dark theme styles**

Create `src/app/globals.css`:

```css
* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  background: #0f172a;
  color: #e2e8f0;
  font-family: system-ui, -apple-system, sans-serif;
}

.dashboard {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

.sidebar {
  width: 360px;
  background: #1e293b;
  padding: 20px;
  overflow-y: auto;
  border-right: 1px solid #334155;
}

.sidebar h2 { margin-bottom: 20px; color: #f8fafc; }
.sidebar h3 { margin: 12px 0 8px; color: #94a3b8; font-size: 14px; text-transform: uppercase; }

.sidebar-section {
  margin-bottom: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid #334155;
}

.sidebar input {
  width: 100%;
  padding: 8px 12px;
  background: #0f172a;
  border: 1px solid #475569;
  color: #e2e8f0;
  border-radius: 4px;
  margin-bottom: 8px;
  font-size: 14px;
}

.sidebar button {
  width: 100%;
  padding: 8px 16px;
  background: #3b82f6;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  margin-bottom: 4px;
}

.sidebar button:hover { background: #2563eb; }

.sidebar-results { margin-top: 16px; }

.path-display {
  background: #0f172a;
  padding: 8px;
  border-radius: 4px;
  margin: 4px 0;
  font-size: 13px;
}

.rule-deny { color: #ef4444; font-size: 13px; }
.rule-allow { color: #22c55e; font-size: 13px; }
.gap-warning { color: #f97316; font-size: 13px; font-style: italic; }

.gap-asset {
  background: #0f172a;
  padding: 8px;
  border-radius: 4px;
  margin: 4px 0;
}

.graph-container { flex: 1; position: relative; }

.node-detail {
  position: absolute;
  top: 20px;
  right: 20px;
  width: 300px;
  background: #1e293b;
  border: 1px solid #475569;
  border-radius: 8px;
  padding: 16px;
  z-index: 10;
}

.node-detail-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.node-detail-header h3 { color: #f8fafc; }

.node-detail-header button {
  background: none;
  border: none;
  color: #94a3b8;
  cursor: pointer;
  font-size: 18px;
}

.node-detail-body p {
  font-size: 13px;
  margin: 4px 0;
  color: #cbd5e1;
}

.loading {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100vh;
  font-size: 18px;
}
```

- [ ] **Step 2: Update layout to import styles**

Modify `src/app/layout.tsx`:

```tsx
import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Security Knowledge Graph',
  description:
    'Connects vulnerabilities, asset context, and real-world traffic patterns',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
```

- [ ] **Step 3: Build the dashboard page**

Replace `src/app/page.tsx`:

```tsx
'use client';

import { useEffect, useState, useCallback } from 'react';
import { GraphView } from '@/components/graph-view';
import { NodeDetail } from '@/components/node-detail';
import { Sidebar } from '@/components/sidebar';
import type { GraphData, GraphNode } from '@/lib/types';

export default function Dashboard() {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [highlightNodes, setHighlightNodes] = useState<Set<string>>(new Set());
  const [blastResults, setBlastResults] = useState<any | null>(null);
  const [gapResults, setGapResults] = useState<any | null>(null);

  useEffect(() => {
    fetch('/api/graph')
      .then((res) => res.json())
      .then(setGraphData)
      .catch(console.error);
  }, []);

  const handleBlastRadius = useCallback(async (cveId: string) => {
    const res = await fetch(`/api/blast-radius?cve=${encodeURIComponent(cveId)}`);
    const data = await res.json();
    setBlastResults(data);
    setGapResults(null);

    const highlight = new Set<string>();
    for (const asset of data.affectedAssets || []) highlight.add(asset.name);
    for (const path of data.exposurePaths || []) {
      for (const node of path.path || []) highlight.add(node);
    }
    setHighlightNodes(highlight);
  }, []);

  const handleGapAnalysis = useCallback(async () => {
    const res = await fetch('/api/gaps');
    const data = await res.json();
    setGapResults(data);
    setBlastResults(null);

    const highlight = new Set<string>();
    for (const asset of data.vulnerableAssets || []) {
      if (asset.gaps?.length > 0) highlight.add(asset.name);
    }
    setHighlightNodes(highlight);
  }, []);

  const handleReset = useCallback(() => {
    setHighlightNodes(new Set());
    setBlastResults(null);
    setGapResults(null);
    setSelectedNode(null);
  }, []);

  if (!graphData) return <div className="loading">Loading graph data...</div>;

  return (
    <div className="dashboard">
      <Sidebar
        onBlastRadius={handleBlastRadius}
        onGapAnalysis={handleGapAnalysis}
        onReset={handleReset}
        blastResults={blastResults}
        gapResults={gapResults}
      />
      <div className="graph-container">
        <GraphView
          data={graphData}
          onNodeClick={setSelectedNode}
          highlightNodes={highlightNodes}
        />
        <NodeDetail node={selectedNode} onClose={() => setSelectedNode(null)} />
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Run tests to verify nothing is broken**

```bash
npm test
```

- [ ] **Step 5: Commit**

```bash
git add src/app/page.tsx src/app/layout.tsx src/app/globals.css
git commit -m "feat: add dashboard page with graph visualization, blast radius, and gap analysis"
```

---

### Task 8: Update Docker Compose + Environment + Final Integration

**Files:**
- Modify: `docker-compose.yml` (add seed service)
- Modify: `.env.example`
- Remove: `tests/placeholder.test.ts`

- [ ] **Step 1: Update .env.example with all required vars**

Modify `.env.example`:

```
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=changeme
NEXT_PUBLIC_APP_URL=http://localhost:3000
```

- [ ] **Step 2: Add seed service to docker-compose.yml**

Modify `docker-compose.yml` to add a one-shot seed container:

```yaml
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      NEO4J_URI: bolt://neo4j:7687
      NEO4J_USER: neo4j
      NEO4J_PASSWORD: changeme
    depends_on:
      seed:
        condition: service_completed_successfully

  seed:
    build:
      context: .
      dockerfile: Dockerfile.seed
    environment:
      NEO4J_URI: bolt://neo4j:7687
      NEO4J_USER: neo4j
      NEO4J_PASSWORD: changeme
    depends_on:
      neo4j:
        condition: service_healthy

  neo4j:
    image: neo4j:5-community
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      NEO4J_AUTH: neo4j/changeme
      NEO4J_PLUGINS: '["apoc"]'
    volumes:
      - neo4j_data:/data
    healthcheck:
      test: ["CMD", "neo4j", "status"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  neo4j_data:
```

- [ ] **Step 3: Create Dockerfile.seed**

Create `Dockerfile.seed`:

```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/lib/ ./src/lib/
COPY scripts/seed-neo4j.ts ./scripts/
COPY cml/topology.yaml ./cml/
CMD ["npx", "ts-node", "--esm", "scripts/seed-neo4j.ts"]
```

- [ ] **Step 4: Remove placeholder test**

```bash
rm tests/placeholder.test.ts
```

- [ ] **Step 5: Run all tests**

```bash
npm test
```

Expected: All tests pass (type guards, seed data validation, API response shape tests)

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yml Dockerfile.seed .env.example
git rm tests/placeholder.test.ts
git commit -m "feat: add seed container, update docker-compose for full stack deployment"
```

- [ ] **Step 7: Push to GitHub**

```bash
git push
```
