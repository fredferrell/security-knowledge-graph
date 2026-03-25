import { describe, it, expect } from '@jest/globals';
import { nodeColor, linkColor, COLOR_MAP, LINK_COLOR_MAP } from '@/lib/graph-colors';

describe('nodeColor', () => {
  it('returns the correct color for known zone groups', () => {
    expect(nodeColor('dmz')).toBe(COLOR_MAP['dmz']);
    expect(nodeColor('internal')).toBe(COLOR_MAP['internal']);
    expect(nodeColor('external')).toBe(COLOR_MAP['external']);
    expect(nodeColor('management')).toBe(COLOR_MAP['management']);
  });

  it('returns colors for graph-label groups', () => {
    expect(nodeColor('Vulnerability')).toBe(COLOR_MAP['Vulnerability']);
    expect(nodeColor('FirewallRule')).toBe(COLOR_MAP['FirewallRule']);
  });

  it('returns the default color for unknown groups', () => {
    expect(nodeColor('unknown-zone')).toBe(COLOR_MAP['default']);
    expect(nodeColor('')).toBe(COLOR_MAP['default']);
  });
});

describe('linkColor', () => {
  it('returns red for HAS_VULNERABILITY', () => {
    expect(linkColor('HAS_VULNERABILITY')).toBe(LINK_COLOR_MAP['HAS_VULNERABILITY']);
  });

  it('returns green for TRAFFIC_FLOW', () => {
    expect(linkColor('TRAFFIC_FLOW')).toBe(LINK_COLOR_MAP['TRAFFIC_FLOW']);
  });

  it('returns orange for HAS_CREDENTIAL', () => {
    expect(linkColor('HAS_CREDENTIAL')).toBe(LINK_COLOR_MAP['HAS_CREDENTIAL']);
  });

  it('returns blue for ENFORCES', () => {
    expect(linkColor('ENFORCES')).toBe(LINK_COLOR_MAP['ENFORCES']);
  });

  it('returns the default color for unknown relationship types', () => {
    expect(linkColor('CONNECTS_TO')).toBe(LINK_COLOR_MAP['default']);
    expect(linkColor('')).toBe(LINK_COLOR_MAP['default']);
  });
});
