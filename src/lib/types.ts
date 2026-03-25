/** Represents a network asset in the security knowledge graph. */
export interface Asset {
  id: string;
  name: string;
  /** Device category, e.g. 'ubuntu-vm', 'palo-alto', 'switch'. */
  type: string;
  ip: string;
  zone: string;
  os?: string;
}

/** Represents a CVE-based vulnerability. */
export interface Vulnerability {
  id: string;
  cve: string;
  /** CVSS severity label: 'critical' | 'high' | 'medium' | 'low'. */
  severity: string;
  cvssScore: number;
  description: string;
  affectedVersions?: string[];
}

/** Represents a firewall policy rule on a Palo Alto or similar device. */
export interface FirewallRule {
  id: string;
  name: string;
  action: 'allow' | 'deny';
  sourceZone: string;
  destZone: string;
  protocol: string;
  port: number;
}

/** Represents an observed network traffic flow between two endpoints. */
export interface TrafficFlow {
  id: string;
  sourceIp: string;
  destIp: string;
  protocol: string;
  port: number;
  timestamp: string;
  bytesTransferred?: number;
}

/** A node in the graph visualisation layer. */
export interface GraphNode {
  id: string;
  /** Neo4j label, e.g. 'Asset', 'Vulnerability', 'FirewallRule'. */
  label: string;
  properties: Record<string, unknown>;
}

/** A directed link between two GraphNodes. */
export interface GraphLink {
  source: string;
  target: string;
  /** Neo4j relationship type, e.g. 'CONNECTS_TO', 'HAS_VULNERABILITY'. */
  type: string;
  properties?: Record<string, unknown>;
}

/** Full graph payload returned by API routes. */
export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

/**
 * Type guard for Asset.
 * Returns true if the value is a non-null object with the required Asset string fields.
 */
export function isAsset(value: unknown): value is Asset {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v['id'] === 'string' &&
    typeof v['name'] === 'string' &&
    typeof v['type'] === 'string' &&
    typeof v['ip'] === 'string' &&
    typeof v['zone'] === 'string'
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
    typeof v['cve'] === 'string' &&
    typeof v['severity'] === 'string' &&
    typeof v['cvssScore'] === 'number' &&
    typeof v['description'] === 'string'
  );
}
