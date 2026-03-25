/** Represents a network asset in the security knowledge graph. */
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

/** Represents a CVE-based vulnerability. */
export interface Vulnerability {
  id: string;
  cveId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  affectedSoftware: string;
  affectedVersion: string;
}

/** Represents a firewall policy rule. */
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

/** Represents an observed network traffic flow between two assets. */
export interface TrafficFlow {
  sourceAsset: string;
  destAsset: string;
  port: number;
  protocol: string;
  bytesTotal: number;
}

/** A node in the graph visualisation layer. */
export interface GraphNode {
  id: string;
  /** Neo4j label, e.g. 'Asset', 'Vulnerability', 'FirewallRule'. */
  label: string;
  type: string;
  group: string;
  properties: Record<string, unknown>;
}

/** A directed link between two GraphNodes. */
export interface GraphLink {
  source: string;
  target: string;
  /** Neo4j relationship type, e.g. 'CONNECTS_TO', 'HAS_VULNERABILITY'. */
  type: string;
  properties: Record<string, unknown>;
}

/** Full graph payload returned by API routes. */
export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

/**
 * Type guard for Asset.
 * Returns true if the value is a non-null object with the required Asset fields.
 */
export function isAsset(value: unknown): value is Asset {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v['id'] === 'string' &&
    typeof v['name'] === 'string' &&
    typeof v['label'] === 'string' &&
    typeof v['type'] === 'string' &&
    typeof v['zone'] === 'string' &&
    typeof v['ip'] === 'string' &&
    Array.isArray(v['software']) &&
    typeof v['description'] === 'string'
  );
}

/**
 * Type guard for Vulnerability.
 * Returns true if the value is a non-null object with the required Vulnerability fields.
 */
export function isVulnerability(value: unknown): value is Vulnerability {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v['id'] === 'string' &&
    typeof v['cveId'] === 'string' &&
    typeof v['severity'] === 'string' &&
    typeof v['description'] === 'string' &&
    typeof v['affectedSoftware'] === 'string' &&
    typeof v['affectedVersion'] === 'string'
  );
}
