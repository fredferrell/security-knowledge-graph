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
      label: 'Asset',
      type: 'server',
      ip: '10.0.1.10',
      zone: 'dmz',
      software: ['nginx/1.24'],
      description: 'Web server in the DMZ',
    };
    expect(isAsset(asset)).toBe(true);
  });

  it('returns false when id is missing', () => {
    const obj = {
      name: 'web-server',
      label: 'Asset',
      type: 'server',
      ip: '10.0.1.10',
      zone: 'dmz',
      software: [],
      description: 'desc',
    };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false when name is missing', () => {
    const obj = {
      id: 'asset-1',
      label: 'Asset',
      type: 'server',
      ip: '10.0.1.10',
      zone: 'dmz',
      software: [],
      description: 'desc',
    };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false when label is missing', () => {
    const obj = {
      id: 'asset-1',
      name: 'web-server',
      type: 'server',
      ip: '10.0.1.10',
      zone: 'dmz',
      software: [],
      description: 'desc',
    };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false when type is missing', () => {
    const obj = {
      id: 'asset-1',
      name: 'web-server',
      label: 'Asset',
      ip: '10.0.1.10',
      zone: 'dmz',
      software: [],
      description: 'desc',
    };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false when ip is missing', () => {
    const obj = {
      id: 'asset-1',
      name: 'web-server',
      label: 'Asset',
      type: 'server',
      zone: 'dmz',
      software: [],
      description: 'desc',
    };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false when zone is missing', () => {
    const obj = {
      id: 'asset-1',
      name: 'web-server',
      label: 'Asset',
      type: 'server',
      ip: '10.0.1.10',
      software: [],
      description: 'desc',
    };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false when software is not an array', () => {
    const obj = {
      id: 'asset-1',
      name: 'web-server',
      label: 'Asset',
      type: 'server',
      ip: '10.0.1.10',
      zone: 'dmz',
      software: 'nginx',
      description: 'desc',
    };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false when description is missing', () => {
    const obj = {
      id: 'asset-1',
      name: 'web-server',
      label: 'Asset',
      type: 'server',
      ip: '10.0.1.10',
      zone: 'dmz',
      software: [],
    };
    expect(isAsset(obj)).toBe(false);
  });

  it('returns false for null', () => {
    expect(isAsset(null)).toBe(false);
  });

  it('returns false for a non-object primitive', () => {
    expect(isAsset('not-an-asset')).toBe(false);
  });

  it('returns false when id is not a string', () => {
    const obj = {
      id: 42,
      name: 'web-server',
      label: 'Asset',
      type: 'server',
      ip: '10.0.1.10',
      zone: 'dmz',
      software: [],
      description: 'desc',
    };
    expect(isAsset(obj)).toBe(false);
  });
});

describe('isVulnerability', () => {
  it('returns true for a valid Vulnerability object', () => {
    const vuln: Vulnerability = {
      id: 'CVE-2024-1234',
      cveId: 'CVE-2024-1234',
      severity: 'critical',
      description: 'Remote code execution in OpenSSH',
      affectedSoftware: 'openssh',
      affectedVersion: '9.3p2',
    };
    expect(isVulnerability(vuln)).toBe(true);
  });

  it('returns false when id is missing', () => {
    const obj = {
      cveId: 'CVE-2024-1234',
      severity: 'critical',
      description: 'desc',
      affectedSoftware: 'openssh',
      affectedVersion: '9.3p2',
    };
    expect(isVulnerability(obj)).toBe(false);
  });

  it('returns false when cveId is missing', () => {
    const obj = {
      id: 'CVE-2024-1234',
      severity: 'critical',
      description: 'desc',
      affectedSoftware: 'openssh',
      affectedVersion: '9.3p2',
    };
    expect(isVulnerability(obj)).toBe(false);
  });

  it('returns false when severity is missing', () => {
    const obj = {
      id: 'CVE-2024-1234',
      cveId: 'CVE-2024-1234',
      description: 'desc',
      affectedSoftware: 'openssh',
      affectedVersion: '9.3p2',
    };
    expect(isVulnerability(obj)).toBe(false);
  });

  it('returns false when description is missing', () => {
    const obj = {
      id: 'CVE-2024-1234',
      cveId: 'CVE-2024-1234',
      severity: 'critical',
      affectedSoftware: 'openssh',
      affectedVersion: '9.3p2',
    };
    expect(isVulnerability(obj)).toBe(false);
  });

  it('returns false when affectedSoftware is missing', () => {
    const obj = {
      id: 'CVE-2024-1234',
      cveId: 'CVE-2024-1234',
      severity: 'critical',
      description: 'desc',
      affectedVersion: '9.3p2',
    };
    expect(isVulnerability(obj)).toBe(false);
  });

  it('returns false when affectedVersion is missing', () => {
    const obj = {
      id: 'CVE-2024-1234',
      cveId: 'CVE-2024-1234',
      severity: 'critical',
      description: 'desc',
      affectedSoftware: 'openssh',
    };
    expect(isVulnerability(obj)).toBe(false);
  });

  it('returns false for null', () => {
    expect(isVulnerability(null)).toBe(false);
  });
});

// Type-shape smoke tests — verifies the interfaces compile with correct structure
describe('FirewallRule interface shape', () => {
  it('accepts a valid FirewallRule object', () => {
    const rule: FirewallRule = {
      id: 'rule-1',
      firewall: 'fw-01',
      name: 'allow-http',
      sourceZone: 'trust',
      destZone: 'untrust',
      sourceIp: '10.0.0.0/8',
      destIp: 'any',
      port: '80',
      action: 'allow',
    };
    expect(rule.id).toBe('rule-1');
    expect(rule.action).toBe('allow');
  });
});

describe('TrafficFlow interface shape', () => {
  it('accepts a valid TrafficFlow object', () => {
    const flow: TrafficFlow = {
      sourceAsset: 'asset-1',
      destAsset: 'asset-2',
      port: 443,
      protocol: 'tcp',
      bytesTotal: 1024,
    };
    expect(flow.sourceAsset).toBe('asset-1');
    expect(flow.port).toBe(443);
  });
});

describe('GraphData interface shape', () => {
  it('accepts a valid GraphData object with nodes and links', () => {
    const node: GraphNode = {
      id: 'n1',
      label: 'Asset',
      type: 'server',
      group: 'assets',
      properties: { name: 'web-01' },
    };
    const link: GraphLink = {
      source: 'n1',
      target: 'n2',
      type: 'CONNECTS_TO',
      properties: {},
    };
    const graph: GraphData = { nodes: [node], links: [link] };
    expect(graph.nodes).toHaveLength(1);
    expect(graph.links).toHaveLength(1);
  });
});
