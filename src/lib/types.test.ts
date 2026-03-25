import { describe, it, expect } from '@jest/globals';
import {
  isAsset,
  isVulnerability,
  type Asset,
  type Vulnerability,
  type FirewallRule,
  type TrafficFlow,
  type GraphNode,
  type GraphLink,
  type GraphData,
} from '@/lib/types';

describe('isAsset', () => {
  it('returns true for a valid Asset object', () => {
    const asset: Asset = {
      id: 'asset-1',
      name: 'web-server',
      type: 'ubuntu-vm',
      ip: '10.0.1.10',
      zone: 'dmz',
    };
    expect(isAsset(asset)).toBe(true);
  });

  it('returns true for Asset with optional os field', () => {
    const asset: Asset = {
      id: 'asset-2',
      name: 'firewall-01',
      type: 'palo-alto',
      ip: '10.0.0.1',
      zone: 'perimeter',
      os: 'PAN-OS 11.0',
    };
    expect(isAsset(asset)).toBe(true);
  });

  it('returns false when id is missing', () => {
    const obj = { name: 'web-server', type: 'ubuntu-vm', ip: '10.0.1.10', zone: 'dmz' };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false when name is missing', () => {
    const obj = { id: 'asset-1', type: 'ubuntu-vm', ip: '10.0.1.10', zone: 'dmz' };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false when type is missing', () => {
    const obj = { id: 'asset-1', name: 'web-server', ip: '10.0.1.10', zone: 'dmz' };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false when ip is missing', () => {
    const obj = { id: 'asset-1', name: 'web-server', type: 'ubuntu-vm', zone: 'dmz' };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false when zone is missing', () => {
    const obj = { id: 'asset-1', name: 'web-server', type: 'ubuntu-vm', ip: '10.0.1.10' };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false for null', () => {
    expect(isAsset(null)).toBe(false);
  });

  it('returns false for a non-object primitive', () => {
    expect(isAsset('not-an-asset')).toBe(false);
  });

  it('returns false when id is not a string', () => {
    const obj = { id: 42, name: 'web-server', type: 'ubuntu-vm', ip: '10.0.1.10', zone: 'dmz' };
    expect(isAsset(obj)).toBe(false);
  });
});

describe('isVulnerability', () => {
  it('returns true for a valid Vulnerability object', () => {
    const vuln: Vulnerability = {
      id: 'CVE-2024-1234',
      cve: 'CVE-2024-1234',
      severity: 'critical',
      cvssScore: 9.8,
      description: 'Remote code execution in OpenSSH',
    };
    expect(isVulnerability(vuln)).toBe(true);
  });

  it('returns true for Vulnerability with optional affectedVersions', () => {
    const vuln: Vulnerability = {
      id: 'CVE-2024-5678',
      cve: 'CVE-2024-5678',
      severity: 'high',
      cvssScore: 7.5,
      description: 'Privilege escalation',
      affectedVersions: ['1.0.0', '1.1.0'],
    };
    expect(isVulnerability(vuln)).toBe(true);
  });

  it('returns false when id is missing', () => {
    const obj = {
      cve: 'CVE-2024-1234',
      severity: 'critical',
      cvssScore: 9.8,
      description: 'desc',
    };
    expect(isVulnerability(obj)).toBe(false);
  });

  it('returns false when cve is missing', () => {
    const obj = { id: 'CVE-2024-1234', severity: 'critical', cvssScore: 9.8, description: 'desc' };
    expect(isVulnerability(obj)).toBe(false);
  });

  it('returns false when severity is missing', () => {
    const obj = {
      id: 'CVE-2024-1234',
      cve: 'CVE-2024-1234',
      cvssScore: 9.8,
      description: 'desc',
    };
    expect(isVulnerability(obj)).toBe(false);
  });

  it('returns false when cvssScore is missing', () => {
    const obj = {
      id: 'CVE-2024-1234',
      cve: 'CVE-2024-1234',
      severity: 'critical',
      description: 'desc',
    };
    expect(isVulnerability(obj)).toBe(false);
  });

  it('returns false when description is missing', () => {
    const obj = {
      id: 'CVE-2024-1234',
      cve: 'CVE-2024-1234',
      severity: 'critical',
      cvssScore: 9.8,
    };
    expect(isVulnerability(obj)).toBe(false);
  });

  it('returns false for null', () => {
    expect(isVulnerability(null)).toBe(false);
  });

  it('returns false when cvssScore is not a number', () => {
    const obj = {
      id: 'CVE-2024-1234',
      cve: 'CVE-2024-1234',
      severity: 'critical',
      cvssScore: '9.8',
      description: 'desc',
    };
    expect(isVulnerability(obj)).toBe(false);
  });
});

// Type-shape smoke tests — verifies the interfaces compile with correct structure
describe('FirewallRule interface shape', () => {
  it('accepts a valid FirewallRule object', () => {
    const rule: FirewallRule = {
      id: 'rule-1',
      name: 'allow-http',
      action: 'allow',
      sourceZone: 'trust',
      destZone: 'untrust',
      protocol: 'tcp',
      port: 80,
    };
    expect(rule.id).toBe('rule-1');
    expect(rule.action).toBe('allow');
  });
});

describe('TrafficFlow interface shape', () => {
  it('accepts a valid TrafficFlow object', () => {
    const flow: TrafficFlow = {
      id: 'flow-1',
      sourceIp: '10.0.1.10',
      destIp: '8.8.8.8',
      protocol: 'tcp',
      port: 443,
      timestamp: '2024-01-01T00:00:00Z',
    };
    expect(flow.id).toBe('flow-1');
  });
});

describe('GraphData interface shape', () => {
  it('accepts a valid GraphData object with nodes and links', () => {
    const node: GraphNode = { id: 'n1', label: 'Asset', properties: { name: 'web-01' } };
    const link: GraphLink = { source: 'n1', target: 'n2', type: 'CONNECTS_TO' };
    const graph: GraphData = { nodes: [node], links: [link] };
    expect(graph.nodes).toHaveLength(1);
    expect(graph.links).toHaveLength(1);
  });
});
