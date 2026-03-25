/** Zone group -> node fill color. Nodes without a matching group use the default. */
export const COLOR_MAP: Record<string, string> = {
  dmz: '#f59e0b',
  internal: '#3b82f6',
  external: '#ef4444',
  management: '#8b5cf6',
  Vulnerability: '#ef4444',
  FirewallRule: '#10b981',
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
