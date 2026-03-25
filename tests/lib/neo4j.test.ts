import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';

// Mock neo4j-driver to avoid real network connections in unit tests
jest.mock('neo4j-driver', () => {
  const mockSession = {};
  const mockDriver = {
    session: jest.fn(() => mockSession),
    close: jest.fn(() => Promise.resolve()),
  };
  const mockNeo4j = {
    driver: jest.fn(() => mockDriver),
    auth: {
      basic: jest.fn((user: string, password: string) => ({ scheme: 'basic', principal: user, credentials: password })),
    },
  };
  return {
    __esModule: true,
    default: mockNeo4j,
    ...mockNeo4j,
  };
});

import neo4j from 'neo4j-driver';
import { getDriver, getSession, closeDriver } from '@/lib/neo4j';

describe('Neo4j driver singleton', () => {
  beforeEach(async () => {
    // Reset the module singleton state between tests by closing any open driver
    await closeDriver();
    jest.clearAllMocks();
  });

  afterEach(async () => {
    await closeDriver();
  });

  it('exports getDriver, getSession, and closeDriver functions', () => {
    expect(typeof getDriver).toBe('function');
    expect(typeof getSession).toBe('function');
    expect(typeof closeDriver).toBe('function');
  });

  it('getDriver creates a driver with bolt URI and basic auth', () => {
    process.env['NEO4J_URI'] = 'bolt://test-host:7687';
    process.env['NEO4J_USER'] = 'testuser';
    process.env['NEO4J_PASSWORD'] = 'testpass';

    getDriver();

    expect(neo4j.driver).toHaveBeenCalledWith(
      'bolt://test-host:7687',
      expect.objectContaining({ scheme: 'basic', principal: 'testuser' })
    );

    delete process.env['NEO4J_URI'];
    delete process.env['NEO4J_USER'];
    delete process.env['NEO4J_PASSWORD'];
  });

  it('getDriver returns the same instance on repeated calls (singleton)', () => {
    const d1 = getDriver();
    const d2 = getDriver();
    expect(d1).toBe(d2);
    expect(neo4j.driver).toHaveBeenCalledTimes(1);
  });

  it('getSession returns a session from the driver', () => {
    const session = getSession();
    expect(session).toBeDefined();
  });

  it('closeDriver resolves without error when no driver is open', async () => {
    // Already closed in beforeEach, calling again should be a no-op
    await expect(closeDriver()).resolves.toBeUndefined();
  });

  it('closeDriver calls driver.close() and allows a fresh driver on next getDriver()', async () => {
    const driver = getDriver();
    await closeDriver();
    expect(driver.close).toHaveBeenCalledTimes(1);

    // Next call should create a new driver
    jest.clearAllMocks();
    getDriver();
    expect(neo4j.driver).toHaveBeenCalledTimes(1);
  });
});
