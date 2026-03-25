/** Static seed data: CVEs, IP map, traffic flows, and credential relationships. */

export interface CveDefinition {
  cveId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  affectedSoftware: string;
  affectedVersion: string;
}

export interface TrafficFlowDefinition {
  source: string;
  dest: string;
  port: number;
  protocol: string;
  bytesTotal: number;
}

export interface CredentialDefinition {
  from: string;
  to: string;
  credentialType: string;
}

/** IP addresses keyed by node name. */
export const IP_MAP: Record<string, string> = {
  'edge-rtr': '10.0.0.1',
  'edge-fw': '10.0.0.2',
  'web-srv': '10.10.1.10',
  'internal-fw': '10.0.1.2',
  'app-srv': '10.10.2.10',
  'db-srv': '10.10.3.10',
  'dns-srv': '10.10.4.10',
  'vuln-vm': '10.10.4.20',
  'elk-srv': '10.10.5.10',
  'mgmt-vm': '10.10.5.20',
};

/** The five CVEs to seed. */
export const CVES: CveDefinition[] = [
  {
    cveId: 'CVE-2021-41773',
    severity: 'critical',
    description: 'Apache 2.4.49 path traversal allows remote unauthenticated file read and possible RCE.',
    affectedSoftware: 'apache2',
    affectedVersion: '2.4.49',
  },
  {
    cveId: 'CVE-2021-42013',
    severity: 'critical',
    description: 'Apache 2.4.49/50 path traversal bypass leading to RCE if mod_cgi is enabled.',
    affectedSoftware: 'apache2',
    affectedVersion: '2.4.49',
  },
  {
    cveId: 'CVE-2023-38408',
    severity: 'high',
    description: 'OpenSSH ssh-agent PKCS#11 provider remote code execution via forwarded agent socket.',
    affectedSoftware: 'openssh-server',
    affectedVersion: '8.2',
  },
  {
    cveId: 'CVE-2023-51767',
    severity: 'medium',
    description: 'OpenSSH authentication bypass via row hammer attack on memory.',
    affectedSoftware: 'openssh-server',
    affectedVersion: '8.2',
  },
  {
    cveId: 'CVE-2022-32081',
    severity: 'high',
    description: 'MariaDB use-after-poison in do_command leading to server crash or potential RCE.',
    affectedSoftware: 'mariadb-server',
    affectedVersion: '10.x',
  },
];

/** 16 traffic flows covering the full topology. */
export const TRAFFIC_FLOWS: TrafficFlowDefinition[] = [
  { source: 'edge-rtr', dest: 'edge-fw', port: 443, protocol: 'TCP', bytesTotal: 5_200_000 },
  { source: 'edge-rtr', dest: 'edge-fw', port: 80, protocol: 'TCP', bytesTotal: 1_800_000 },
  { source: 'edge-fw', dest: 'web-srv', port: 443, protocol: 'TCP', bytesTotal: 4_900_000 },
  { source: 'edge-fw', dest: 'web-srv', port: 80, protocol: 'TCP', bytesTotal: 1_600_000 },
  { source: 'web-srv', dest: 'app-srv', port: 443, protocol: 'TCP', bytesTotal: 3_100_000 },
  { source: 'app-srv', dest: 'db-srv', port: 3306, protocol: 'TCP', bytesTotal: 2_400_000 },
  { source: 'edge-fw', dest: 'internal-fw', port: 443, protocol: 'TCP', bytesTotal: 900_000 },
  { source: 'internal-fw', dest: 'app-srv', port: 443, protocol: 'TCP', bytesTotal: 800_000 },
  { source: 'internal-fw', dest: 'dns-srv', port: 53, protocol: 'UDP', bytesTotal: 120_000 },
  { source: 'app-srv', dest: 'dns-srv', port: 53, protocol: 'UDP', bytesTotal: 95_000 },
  { source: 'web-srv', dest: 'elk-srv', port: 514, protocol: 'UDP', bytesTotal: 340_000 },
  { source: 'app-srv', dest: 'elk-srv', port: 514, protocol: 'UDP', bytesTotal: 290_000 },
  { source: 'db-srv', dest: 'elk-srv', port: 514, protocol: 'UDP', bytesTotal: 210_000 },
  { source: 'dns-srv', dest: 'elk-srv', port: 514, protocol: 'UDP', bytesTotal: 180_000 },
  { source: 'vuln-vm', dest: 'elk-srv', port: 514, protocol: 'UDP', bytesTotal: 155_000 },
  { source: 'mgmt-vm', dest: 'elk-srv', port: 514, protocol: 'UDP', bytesTotal: 75_000 },
];

/** 9 credential relationships. */
export const CREDENTIALS: CredentialDefinition[] = [
  { from: 'mgmt-vm', to: 'web-srv', credentialType: 'SSH key' },
  { from: 'mgmt-vm', to: 'app-srv', credentialType: 'SSH key' },
  { from: 'mgmt-vm', to: 'db-srv', credentialType: 'SSH key' },
  { from: 'mgmt-vm', to: 'dns-srv', credentialType: 'SSH key' },
  { from: 'mgmt-vm', to: 'vuln-vm', credentialType: 'SSH key' },
  { from: 'mgmt-vm', to: 'elk-srv', credentialType: 'SSH key' },
  { from: 'mgmt-vm', to: 'edge-fw', credentialType: 'API key' },
  { from: 'mgmt-vm', to: 'internal-fw', credentialType: 'API key' },
  { from: 'mgmt-vm', to: 'edge-rtr', credentialType: 'SSH key' },
];
