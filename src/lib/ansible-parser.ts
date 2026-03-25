import yaml from 'js-yaml';

/** A single host entry extracted from the Ansible inventory. */
export interface InventoryHost {
  name: string;
  ip: string;
  zone: string;
}

/** Maps Ansible group names to security zone names. */
const GROUP_ZONE_MAP: Record<string, string> = {
  routers: 'internet-edge',
  firewalls: 'edge',
  dmz: 'dmz',
  app_tier: 'app-tier',
  db_tier: 'db-tier',
  corporate: 'corporate',
  management: 'management',
};

type HostEntry = Record<string, unknown>;
type GroupEntry = {
  hosts?: Record<string, HostEntry | null>;
  children?: Record<string, GroupEntry | null>;
  vars?: unknown;
};

/**
 * Recursively walks a group's children, collecting hosts into the result array.
 * Zone is taken from an explicit `zone` property on the host, or inferred from
 * the immediate parent group name using GROUP_ZONE_MAP.
 */
function walkGroup(
  group: GroupEntry | null | undefined,
  groupName: string,
  result: InventoryHost[],
): void {
  if (!group || typeof group !== 'object') {
    return;
  }

  // Process hosts directly in this group
  if (group.hosts && typeof group.hosts === 'object') {
    const inferredZone = GROUP_ZONE_MAP[groupName] ?? groupName;
    for (const [hostName, hostProps] of Object.entries(group.hosts)) {
      const props = (hostProps ?? {}) as HostEntry;
      const ansibleHost = props['ansible_host'];
      if (typeof ansibleHost !== 'string') {
        continue;
      }
      const explicitZone = props['zone'];
      const zone = typeof explicitZone === 'string' ? explicitZone : inferredZone;
      result.push({ name: hostName, ip: ansibleHost, zone });
    }
  }

  // Recurse into child groups
  if (group.children && typeof group.children === 'object') {
    for (const [childName, childGroup] of Object.entries(group.children)) {
      walkGroup(childGroup, childName, result);
    }
  }
}

/**
 * Parses an Ansible inventory YAML string and returns a flat array of hosts.
 * Each host includes its name, IP address (from ansible_host), and security zone.
 * Zone is taken from an explicit `zone` host var, or inferred from the parent group name.
 */
export function parseInventory(yamlContent: string): InventoryHost[] {
  const raw = yaml.load(yamlContent) as Record<string, unknown> | null | undefined;
  if (!raw || typeof raw !== 'object') {
    return [];
  }

  const all = raw['all'] as GroupEntry | null | undefined;
  if (!all) {
    return [];
  }

  const result: InventoryHost[] = [];
  walkGroup(all, 'all', result);
  return result;
}
