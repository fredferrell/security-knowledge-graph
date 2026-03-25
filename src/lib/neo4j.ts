import neo4j, { Driver, Session } from 'neo4j-driver';

let driver: Driver | null = null;

/**
 * Returns the singleton Neo4j driver, creating it on first call.
 * Reads NEO4J_URI, NEO4J_USER, and NEO4J_PASSWORD from environment variables.
 */
export function getDriver(): Driver {
  if (driver) {
    return driver;
  }

  const uri = process.env['NEO4J_URI'] ?? 'bolt://localhost:7687';
  const user = process.env['NEO4J_USER'] ?? 'neo4j';
  const password = process.env['NEO4J_PASSWORD'] ?? '';

  driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  return driver;
}

/**
 * Opens and returns a new Neo4j session using the singleton driver.
 * Caller is responsible for closing the session after use.
 */
export function getSession(): Session {
  return getDriver().session();
}

/**
 * Closes the singleton Neo4j driver and clears the reference.
 * Call during application shutdown to release connections cleanly.
 */
export async function closeDriver(): Promise<void> {
  if (driver) {
    await driver.close();
    driver = null;
  }
}
