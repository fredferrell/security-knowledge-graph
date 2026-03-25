import { describe, it, expect } from '@jest/globals';
import { parseInventory, type InventoryHost } from '@/lib/ansible-parser';
import { readFileSync } from 'fs';
import { join } from 'path';

const INLINE_YAML = `
all:
  children:
    network:
      children:
        routers:
          hosts:
            edge-rtr:
              ansible_host: 10.0.0.1
              ansible_network_os: ios
        firewalls:
          hosts:
            edge-fw:
              ansible_host: 10.0.0.2
            internal-fw:
              ansible_host: 10.0.1.2
    servers:
      children:
        dmz:
          hosts:
            web-srv:
              ansible_host: 10.10.1.10
              zone: dmz
        app_tier:
          hosts:
            app-srv:
              ansible_host: 10.10.2.10
              zone: app-tier
        db_tier:
          hosts:
            db-srv:
              ansible_host: 10.10.3.10
`;

describe('parseInventory', () => {
  describe('return type', () => {
    it('returns an array', () => {
      const result = parseInventory(INLINE_YAML);
      expect(Array.isArray(result)).toBe(true);
    });

    it('each item has name, ip, and zone properties', () => {
      const result = parseInventory(INLINE_YAML);
      for (const host of result) {
        expect(host).toHaveProperty('name');
        expect(host).toHaveProperty('ip');
        expect(host).toHaveProperty('zone');
        expect(typeof host.name).toBe('string');
        expect(typeof host.ip).toBe('string');
        expect(typeof host.zone).toBe('string');
      }
    });
  });

  describe('host extraction', () => {
    it('finds all hosts with ansible_host in the inline YAML', () => {
      const result = parseInventory(INLINE_YAML);
      expect(result).toHaveLength(6);
    });

    it('extracts correct name and ip for edge-rtr', () => {
      const result = parseInventory(INLINE_YAML);
      const host = result.find((h) => h.name === 'edge-rtr');
      expect(host).toBeDefined();
      expect(host?.ip).toBe('10.0.0.1');
    });

    it('extracts correct name and ip for web-srv', () => {
      const result = parseInventory(INLINE_YAML);
      const host = result.find((h) => h.name === 'web-srv');
      expect(host).toBeDefined();
      expect(host?.ip).toBe('10.10.1.10');
    });

    it('extracts correct name and ip for app-srv', () => {
      const result = parseInventory(INLINE_YAML);
      const host = result.find((h) => h.name === 'app-srv');
      expect(host).toBeDefined();
      expect(host?.ip).toBe('10.10.2.10');
    });
  });

  describe('zone inference', () => {
    it('uses explicit zone property when present (web-srv → dmz)', () => {
      const result = parseInventory(INLINE_YAML);
      const host = result.find((h) => h.name === 'web-srv');
      expect(host?.zone).toBe('dmz');
    });

    it('uses explicit zone property when present (app-srv → app-tier)', () => {
      const result = parseInventory(INLINE_YAML);
      const host = result.find((h) => h.name === 'app-srv');
      expect(host?.zone).toBe('app-tier');
    });

    it('infers zone from group name routers → internet-edge for edge-rtr', () => {
      const result = parseInventory(INLINE_YAML);
      const host = result.find((h) => h.name === 'edge-rtr');
      expect(host?.zone).toBe('internet-edge');
    });

    it('infers zone from group name firewalls → edge for edge-fw', () => {
      const result = parseInventory(INLINE_YAML);
      const host = result.find((h) => h.name === 'edge-fw');
      expect(host?.zone).toBe('edge');
    });

    it('infers zone from group name firewalls → edge for internal-fw', () => {
      const result = parseInventory(INLINE_YAML);
      const host = result.find((h) => h.name === 'internal-fw');
      expect(host?.zone).toBe('edge');
    });

    it('infers zone from group name db_tier → db-tier for db-srv', () => {
      const result = parseInventory(INLINE_YAML);
      const host = result.find((h) => h.name === 'db-srv');
      expect(host?.zone).toBe('db-tier');
    });
  });

  describe('zone inference from group name mapping', () => {
    it('maps corporate group to corporate zone', () => {
      const yaml = `
all:
  children:
    servers:
      children:
        corporate:
          hosts:
            dns-srv:
              ansible_host: 10.10.4.10
`;
      const result = parseInventory(yaml);
      expect(result.find((h) => h.name === 'dns-srv')?.zone).toBe('corporate');
    });

    it('maps management group to management zone', () => {
      const yaml = `
all:
  children:
    servers:
      children:
        management:
          hosts:
            elk-srv:
              ansible_host: 10.10.5.10
`;
      const result = parseInventory(yaml);
      expect(result.find((h) => h.name === 'elk-srv')?.zone).toBe('management');
    });
  });

  describe('empty and edge cases', () => {
    it('returns empty array for empty YAML', () => {
      const result = parseInventory('{}');
      expect(result).toHaveLength(0);
    });

    it('returns empty array for YAML with no hosts', () => {
      const yaml = `
all:
  children:
    servers:
      vars:
        ansible_user: admin
`;
      const result = parseInventory(yaml);
      expect(result).toHaveLength(0);
    });

    it('skips host entries without ansible_host', () => {
      const yaml = `
all:
  children:
    servers:
      children:
        dmz:
          hosts:
            no-ip-host:
              some_var: value
            real-host:
              ansible_host: 10.0.0.5
`;
      const result = parseInventory(yaml);
      expect(result).toHaveLength(1);
      expect(result[0].name).toBe('real-host');
    });
  });

  describe('against real hosts.yml (10 hosts)', () => {
    let realHosts: InventoryHost[];

    beforeAll(() => {
      const hostsPath = join(process.cwd(), 'ansible', 'inventory', 'hosts.yml');
      const content = readFileSync(hostsPath, 'utf-8');
      realHosts = parseInventory(content);
    });

    it('returns exactly 10 hosts', () => {
      expect(realHosts).toHaveLength(10);
    });

    it('includes edge-rtr with ip 10.0.0.1', () => {
      const host = realHosts.find((h) => h.name === 'edge-rtr');
      expect(host).toBeDefined();
      expect(host?.ip).toBe('10.0.0.1');
      expect(host?.zone).toBe('internet-edge');
    });

    it('includes edge-fw with ip 10.0.0.2 in edge zone', () => {
      const host = realHosts.find((h) => h.name === 'edge-fw');
      expect(host).toBeDefined();
      expect(host?.ip).toBe('10.0.0.2');
      expect(host?.zone).toBe('edge');
    });

    it('includes internal-fw in edge zone', () => {
      const host = realHosts.find((h) => h.name === 'internal-fw');
      expect(host).toBeDefined();
      expect(host?.zone).toBe('edge');
    });

    it('includes web-srv in dmz zone', () => {
      const host = realHosts.find((h) => h.name === 'web-srv');
      expect(host).toBeDefined();
      expect(host?.zone).toBe('dmz');
    });

    it('includes app-srv in app-tier zone', () => {
      const host = realHosts.find((h) => h.name === 'app-srv');
      expect(host).toBeDefined();
      expect(host?.zone).toBe('app-tier');
    });

    it('includes db-srv in db-tier zone', () => {
      const host = realHosts.find((h) => h.name === 'db-srv');
      expect(host).toBeDefined();
      expect(host?.zone).toBe('db-tier');
    });

    it('includes elk-srv and mgmt-vm in management zone', () => {
      const elk = realHosts.find((h) => h.name === 'elk-srv');
      const mgmt = realHosts.find((h) => h.name === 'mgmt-vm');
      expect(elk?.zone).toBe('management');
      expect(mgmt?.zone).toBe('management');
    });

    it('includes dns-srv and vuln-vm in corporate zone', () => {
      const dns = realHosts.find((h) => h.name === 'dns-srv');
      const vuln = realHosts.find((h) => h.name === 'vuln-vm');
      expect(dns?.zone).toBe('corporate');
      expect(vuln?.zone).toBe('corporate');
    });

    it('all hosts have non-empty name, ip, and zone', () => {
      for (const host of realHosts) {
        expect(host.name.length).toBeGreaterThan(0);
        expect(host.ip.length).toBeGreaterThan(0);
        expect(host.zone.length).toBeGreaterThan(0);
      }
    });
  });
});
