/**
 * Seed script: reads cml/topology.yaml and populates Neo4j with the full
 * security knowledge graph (zones, assets, networks, CVEs, firewall rules,
 * traffic flows, and credential relationships).
 *
 * Run with: npx ts-node --esm scripts/seed-neo4j.ts
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import yaml from 'js-yaml';
import neo4j, { Session } from 'neo4j-driver';
import { IP_MAP, CVES, TRAFFIC_FLOWS, CREDENTIALS, CONNECTIONS } from './seed-data.js';

// ─── Topology types ────────────────────────────────────────────────────────

interface TopologyNode {
  name: string;
  type: string;
  label: string;
  zone: string;
  description: string;
  software?: string[];
}

interface FirewallPolicy {
  name: string;
  source: string;
  destination: string;
  port?: string | number;
  action: string;
  description: string;
}

interface Topology {
  nodes: TopologyNode[];
  networks: { name: string; subnet: string; description: string }[];
  firewall_policies: Record<string, FirewallPolicy[]>;
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function loadTopology(): Topology {
  const path = join(process.cwd(), 'cml/topology.yaml');
  const raw = readFileSync(path, 'utf-8');
  return yaml.load(raw) as Topology;
}

function mapNodeType(cmlType: string): string {
  const map: Record<string, string> = {
    iosv: 'router',
    paloalto: 'firewall',
    ubuntu: 'server',
  };
  return map[cmlType] ?? 'vm';
}

async function clearGraph(session: Session): Promise<void> {
  await session.run('MATCH (n) DETACH DELETE n');
}

async function seedZones(session: Session, zones: string[]): Promise<void> {
  for (const zone of zones) {
    await session.run('MERGE (z:Zone {name: $zone})', { zone });
  }
}

async function seedNetworks(
  session: Session,
  networks: Topology['networks'],
): Promise<void> {
  for (const net of networks) {
    await session.run(
      `MERGE (n:Network {name: $name})
       ON CREATE SET n.subnet = $subnet, n.description = $description`,
      { name: net.name, subnet: net.subnet, description: net.description },
    );
  }
}

async function seedAssets(session: Session, nodes: TopologyNode[]): Promise<void> {
  for (const node of nodes) {
    const ip = IP_MAP[node.name] ?? '';
    const software = (node.software ?? []).map((s) => s.trim());
    const type = mapNodeType(node.type);

    await session.run(
      `MERGE (a:Asset {name: $name})
       ON CREATE SET a.label = $label, a.type = $type, a.zone = $zone,
                     a.ip = $ip, a.description = $description, a.software = $software`,
      {
        name: node.name,
        label: node.label,
        type,
        zone: node.zone,
        ip,
        description: node.description.trim(),
        software,
      },
    );

    await session.run(
      `MATCH (a:Asset {name: $name}), (z:Zone {name: $zone})
       MERGE (a)-[:IN_ZONE]->(z)`,
      { name: node.name, zone: node.zone },
    );
  }
}

async function seedVulnerabilities(session: Session, assetNodes: TopologyNode[]): Promise<void> {
  for (const cve of CVES) {
    await session.run(
      `MERGE (v:Vulnerability {cveId: $cveId})
       ON CREATE SET v.severity = $severity, v.description = $description,
                     v.affectedSoftware = $affectedSoftware,
                     v.affectedVersion = $affectedVersion`,
      {
        cveId: cve.cveId,
        severity: cve.severity,
        description: cve.description,
        affectedSoftware: cve.affectedSoftware,
        affectedVersion: cve.affectedVersion,
      },
    );

    for (const node of assetNodes) {
      const software = (node.software ?? []).map((s) => s.toLowerCase());
      const matches = software.some((s) => s.includes(cve.affectedSoftware.toLowerCase()));
      if (matches) {
        await session.run(
          `MATCH (a:Asset {name: $assetName}), (v:Vulnerability {cveId: $cveId})
           MERGE (a)-[:HAS_VULNERABILITY]->(v)`,
          { assetName: node.name, cveId: cve.cveId },
        );
      }
    }
  }
}

async function seedFirewallRules(
  session: Session,
  policies: Record<string, FirewallPolicy[]>,
): Promise<void> {
  for (const [firewallName, rules] of Object.entries(policies)) {
    for (const rule of rules) {
      const ruleId = `${firewallName}-${rule.name}`;
      await session.run(
        `MERGE (r:FirewallRule {id: $id})
         ON CREATE SET r.firewall = $firewall, r.name = $name,
                       r.source = $source, r.destination = $destination,
                       r.port = $port, r.action = $action,
                       r.description = $description`,
        {
          id: ruleId,
          firewall: firewallName,
          name: rule.name,
          source: rule.source,
          destination: rule.destination,
          port: rule.port != null ? String(rule.port) : '',
          action: rule.action,
          description: rule.description,
        },
      );

      await session.run(
        `MATCH (fw:Asset {name: $fw}), (r:FirewallRule {id: $id})
         MERGE (fw)-[:ENFORCES]->(r)`,
        { fw: firewallName, id: ruleId },
      );
    }
  }
}

async function seedTrafficFlows(session: Session): Promise<void> {
  for (const flow of TRAFFIC_FLOWS) {
    await session.run(
      `MATCH (src:Asset {name: $src}), (dst:Asset {name: $dst})
       MERGE (src)-[f:TRAFFIC_FLOW {port: $port, protocol: $protocol}]->(dst)
       ON CREATE SET f.bytesTotal = $bytesTotal`,
      {
        src: flow.source,
        dst: flow.dest,
        port: flow.port,
        protocol: flow.protocol,
        bytesTotal: flow.bytesTotal,
      },
    );
  }
}

async function seedConnections(session: Session): Promise<void> {
  for (const conn of CONNECTIONS) {
    await session.run(
      `MATCH (src:Asset {name: $from}), (dst:Asset {name: $to})
       MERGE (src)-[c:CONNECTS_TO {zone: $zone}]->(dst)
       ON CREATE SET c.fromInterface = $fromIf, c.toInterface = $toIf`,
      {
        from: conn.from,
        to: conn.to,
        zone: conn.zone,
        fromIf: conn.fromInterface,
        toIf: conn.toInterface,
      },
    );
  }
}

async function seedCredentials(session: Session): Promise<void> {
  for (const cred of CREDENTIALS) {
    await session.run(
      `MATCH (src:Asset {name: $from}), (dst:Asset {name: $to})
       MERGE (src)-[c:HAS_CREDENTIAL {credentialType: $type}]->(dst)`,
      { from: cred.from, to: cred.to, type: cred.credentialType },
    );
  }
}

async function printSummary(session: Session): Promise<void> {
  const labels = ['Zone', 'Network', 'Asset', 'Vulnerability', 'FirewallRule'];
  const counts: Record<string, number> = {};

  for (const label of labels) {
    const result = await session.run(`MATCH (n:${label}) RETURN count(n) AS c`);
    counts[label] = result.records[0].get('c').toNumber();
  }

  const relResult = await session.run('MATCH ()-[r]->() RETURN type(r) AS t, count(r) AS c');
  const relCounts: Record<string, number> = {};
  for (const record of relResult.records) {
    relCounts[record.get('t')] = record.get('c').toNumber();
  }

  console.log('\n=== Seed Summary ===');
  for (const [label, count] of Object.entries(counts)) {
    console.log(`  ${label}: ${count}`);
  }
  console.log('  Relationships:');
  for (const [type, count] of Object.entries(relCounts)) {
    console.log(`    ${type}: ${count}`);
  }
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const topology = loadTopology();

  const uri = process.env['NEO4J_URI'] ?? 'bolt://localhost:7687';
  const user = process.env['NEO4J_USER'] ?? 'neo4j';
  const password = process.env['NEO4J_PASSWORD'] ?? 'changeme';

  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  const session = driver.session();

  try {
    console.log('Clearing existing graph data...');
    await clearGraph(session);

    const zones = [...new Set(topology.nodes.map((n) => n.zone))];
    console.log(`Seeding ${zones.length} zones...`);
    await seedZones(session, zones);

    console.log(`Seeding ${topology.networks.length} networks...`);
    await seedNetworks(session, topology.networks);

    console.log(`Seeding ${topology.nodes.length} assets...`);
    await seedAssets(session, topology.nodes);

    console.log(`Seeding ${CVES.length} vulnerabilities...`);
    await seedVulnerabilities(session, topology.nodes);

    const policyCount = Object.values(topology.firewall_policies).flat().length;
    console.log(`Seeding ${policyCount} firewall rules...`);
    await seedFirewallRules(session, topology.firewall_policies);

    console.log(`Seeding ${TRAFFIC_FLOWS.length} traffic flows...`);
    await seedTrafficFlows(session);

    console.log(`Seeding ${CONNECTIONS.length} network connections...`);
    await seedConnections(session);

    console.log(`Seeding ${CREDENTIALS.length} credential relationships...`);
    await seedCredentials(session);

    await printSummary(session);
    console.log('\nSeed complete.\n');
  } finally {
    await session.close();
    await driver.close();
  }
}

main().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
