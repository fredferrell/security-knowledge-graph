import { readFileSync } from 'fs';
import { join } from 'path';
import yaml from 'js-yaml';

interface TopologyNode {
  name: string;
  type: string;
  label: string;
  zone: string;
  description: string;
  software?: string[];
  interfaces?: { name: string; description: string; network: string; zone?: string }[];
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
  lab: { title: string; description: string; version: string };
  nodes: TopologyNode[];
  networks: { name: string; subnet: string; description: string }[];
  firewall_policies: Record<string, FirewallPolicy[]>;
}

const TOPOLOGY_PATH = join(__dirname, '../../cml/topology.yaml');

function loadTopology(): Topology {
  const raw = readFileSync(TOPOLOGY_PATH, 'utf-8');
  return yaml.load(raw) as Topology;
}

describe('topology.yaml structure', () => {
  let topology: Topology;

  beforeAll(() => {
    topology = loadTopology();
  });

  it('loads without error', () => {
    expect(topology).toBeDefined();
    expect(typeof topology).toBe('object');
  });

  it('has exactly 10 nodes', () => {
    expect(topology.nodes).toHaveLength(10);
  });

  it('has a networks array with at least one entry', () => {
    expect(Array.isArray(topology.networks)).toBe(true);
    expect(topology.networks.length).toBeGreaterThan(0);
  });

  it('has 8 networks', () => {
    expect(topology.networks).toHaveLength(8);
  });

  it('every node has required fields: name, type, label, zone, description', () => {
    for (const node of topology.nodes) {
      expect(typeof node.name).toBe('string');
      expect(node.name.length).toBeGreaterThan(0);

      expect(typeof node.type).toBe('string');
      expect(node.type.length).toBeGreaterThan(0);

      expect(typeof node.label).toBe('string');
      expect(node.label.length).toBeGreaterThan(0);

      expect(typeof node.zone).toBe('string');
      expect(node.zone.length).toBeGreaterThan(0);

      expect(typeof node.description).toBe('string');
      expect(node.description.length).toBeGreaterThan(0);
    }
  });

  it('every network has name, subnet, and description', () => {
    for (const net of topology.networks) {
      expect(typeof net.name).toBe('string');
      expect(net.name.length).toBeGreaterThan(0);

      expect(typeof net.subnet).toBe('string');
      expect(net.subnet).toMatch(/^\d+\.\d+\.\d+\.\d+\/\d+$/);

      expect(typeof net.description).toBe('string');
      expect(net.description.length).toBeGreaterThan(0);
    }
  });

  it('contains the expected node names', () => {
    const names = topology.nodes.map((n) => n.name);
    expect(names).toContain('edge-rtr');
    expect(names).toContain('edge-fw');
    expect(names).toContain('web-srv');
    expect(names).toContain('internal-fw');
    expect(names).toContain('app-srv');
    expect(names).toContain('db-srv');
    expect(names).toContain('dns-srv');
    expect(names).toContain('vuln-vm');
    expect(names).toContain('elk-srv');
    expect(names).toContain('mgmt-vm');
  });

  it('ubuntu nodes have a software array', () => {
    const ubuntuNodes = topology.nodes.filter((n) => n.type === 'ubuntu');
    expect(ubuntuNodes.length).toBeGreaterThan(0);
    for (const node of ubuntuNodes) {
      expect(Array.isArray(node.software)).toBe(true);
    }
  });

  it('has firewall_policies for edge-fw and internal-fw', () => {
    expect(topology.firewall_policies).toBeDefined();
    expect(Array.isArray(topology.firewall_policies['edge-fw'])).toBe(true);
    expect(Array.isArray(topology.firewall_policies['internal-fw'])).toBe(true);
    expect(topology.firewall_policies['edge-fw'].length).toBeGreaterThan(0);
    expect(topology.firewall_policies['internal-fw'].length).toBeGreaterThan(0);
  });

  it('each firewall policy has required fields: name, source, destination, action', () => {
    for (const [, policies] of Object.entries(topology.firewall_policies)) {
      for (const policy of policies) {
        expect(typeof policy.name).toBe('string');
        expect(policy.name.length).toBeGreaterThan(0);
        expect(typeof policy.source).toBe('string');
        expect(typeof policy.destination).toBe('string');
        expect(['allow', 'deny']).toContain(policy.action);
      }
    }
  });

  it('has unique zones across nodes', () => {
    const zones = [...new Set(topology.nodes.map((n) => n.zone))];
    expect(zones.length).toBeGreaterThan(1);
  });
});
