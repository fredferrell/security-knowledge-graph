/** Zone group -> node fill color. Nodes without a matching group use the default. */
export const COLOR_MAP: Record<string, string> = {
  'internet-edge': '#ef4444',
  edge: '#f97316',
  dmz: '#f59e0b',
  internal: '#3b82f6',
  'app-tier': '#06b6d4',
  'db-tier': '#8b5cf6',
  corporate: '#a855f7',
  management: '#ec4899',
  Vulnerability: '#ef4444',
  FirewallRule: '#10b981',
  Zone: '#64748b',
  default: '#94a3b8',
};

/**
 * Returns the fill color for a graph node based on its group (zone).
 * Falls back to the default color when the group is unrecognised.
 */
export function nodeColor(group: string): string {
  return COLOR_MAP[group] ?? COLOR_MAP['default'];
}

/** Relationship type -> link color. */
export const LINK_COLOR_MAP: Record<string, string> = {
  HAS_VULNERABILITY: '#ef4444',
  TRAFFIC_FLOW: '#22c55e',
  CONNECTS_TO: '#06b6d4',
  HAS_CREDENTIAL: '#f97316',
  ENFORCES: '#3b82f6',
  default: '#64748b',
};

/**
 * Returns the color for a graph link based on its relationship type.
 * Falls back to the default color for unrecognised types.
 */
export function linkColor(type: string): string {
  return LINK_COLOR_MAP[type] ?? LINK_COLOR_MAP['default'];
}

/** Legend entries for the graph UI. */
export const NODE_LEGEND: { label: string; color: string }[] = [
  { label: 'Internet Edge', color: COLOR_MAP['internet-edge'] },
  { label: 'Edge', color: COLOR_MAP['edge'] },
  { label: 'DMZ', color: COLOR_MAP['dmz'] },
  { label: 'Internal', color: COLOR_MAP['internal'] },
  { label: 'App Tier', color: COLOR_MAP['app-tier'] },
  { label: 'DB Tier', color: COLOR_MAP['db-tier'] },
  { label: 'Corporate', color: COLOR_MAP['corporate'] },
  { label: 'Management', color: COLOR_MAP['management'] },
  { label: 'Vulnerability', color: COLOR_MAP['Vulnerability'] },
  { label: 'Firewall Rule', color: COLOR_MAP['FirewallRule'] },
  { label: 'Zone', color: COLOR_MAP['Zone'] },
];

export const LINK_LEGEND: { label: string; color: string }[] = [
  { label: 'Connects To', color: LINK_COLOR_MAP['CONNECTS_TO'] },
  { label: 'Traffic Flow', color: LINK_COLOR_MAP['TRAFFIC_FLOW'] },
  { label: 'Has Vulnerability', color: LINK_COLOR_MAP['HAS_VULNERABILITY'] },
  { label: 'Has Credential', color: LINK_COLOR_MAP['HAS_CREDENTIAL'] },
  { label: 'Enforces', color: LINK_COLOR_MAP['ENFORCES'] },
  { label: 'Other', color: LINK_COLOR_MAP['default'] },
];
