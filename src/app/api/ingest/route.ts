import { NextResponse } from 'next/server';
import { getSession } from '@/lib/neo4j';

const ELK_URL = process.env['ELASTICSEARCH_URL'] ?? 'http://10.10.5.10:9200';

interface SyslogDoc {
  syslog_program?: string;
  syslog_message?: string;
  syslog_hostname?: string;
  '@timestamp'?: string;
}

interface IngestSummary {
  sshEvents: number;
  trafficLinks: number;
  securityEvents: number;
  timestamp: string;
}

/** IP-to-asset mapping for the lab network. */
const IP_TO_ASSET: Record<string, string> = {
  '10.0.0.1': 'edge-rtr',
  '10.0.0.2': 'edge-fw',
  '10.0.1.2': 'internal-fw',
  '10.10.1.10': 'web-srv',
  '10.10.2.10': 'app-srv',
  '10.10.3.10': 'db-srv',
  '10.10.4.10': 'dns-srv',
  '10.10.4.20': 'vuln-vm',
  '10.10.5.10': 'elk-srv',
  '10.10.5.20': 'mgmt-vm',
  '192.168.10.240': 'mgmt-vm',
};

/** Extract source IP from syslog message using common patterns. */
function extractSourceIp(message: string): string | null {
  const patterns = [
    /from\s+(\d+\.\d+\.\d+\.\d+)/,
    /SRC=(\d+\.\d+\.\d+\.\d+)/,
    /client\s+(\d+\.\d+\.\d+\.\d+)/,
  ];
  for (const p of patterns) {
    const m = message.match(p);
    if (m) { return m[1]; }
  }
  return null;
}

/** Classify a syslog message into a security event type. */
function classifyEvent(program: string, message: string): string | null {
  if (program === 'sshd') {
    if (message.includes('Failed password') || message.includes('Invalid user')) {
      return 'AUTH_FAILURE';
    }
    if (message.includes('Accepted password') || message.includes('Accepted publickey')) {
      return 'AUTH_SUCCESS';
    }
  }
  if (message.includes('path traversal') || message.includes('..%2f') || message.includes('%2e%2e')) {
    return 'PATH_TRAVERSAL';
  }
  if (program === 'sudo' && message.includes('COMMAND')) {
    return 'PRIVILEGE_ESCALATION';
  }
  return null;
}

/** Query Elasticsearch for recent syslog events. */
async function fetchSyslogEvents(since: string): Promise<SyslogDoc[]> {
  const query = {
    size: 500,
    sort: [{ '@timestamp': 'desc' }],
    query: {
      bool: {
        must: [
          { range: { '@timestamp': { gte: since } } },
          { terms: { 'syslog_program.keyword': ['sshd', 'sudo', 'apache2', 'named'] } },
        ],
      },
    },
  };

  const res = await fetch(`${ELK_URL}/syslog-*/_search`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(query),
  });

  if (!res.ok) { return []; }
  const data = await res.json();
  return (data.hits?.hits ?? []).map((h: { _source: SyslogDoc }) => h._source);
}

/** Query Elasticsearch for connection-level aggregation. */
async function fetchTrafficSummary(): Promise<{ sourceIp: string; count: number }[]> {
  const query = {
    size: 0,
    query: {
      bool: {
        must: [
          { term: { 'syslog_program.keyword': 'sshd' } },
          { range: { '@timestamp': { gte: 'now-24h' } } },
        ],
      },
    },
    aggs: {
      messages: {
        terms: { field: 'syslog_message.keyword', size: 200 },
      },
    },
  };

  const res = await fetch(`${ELK_URL}/syslog-*/_search`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(query),
  });

  if (!res.ok) { return []; }
  const data = await res.json();
  const buckets = data.aggregations?.messages?.buckets ?? [];
  const ipCounts: Record<string, number> = {};

  for (const b of buckets) {
    const ip = extractSourceIp(b.key);
    if (ip) {
      ipCounts[ip] = (ipCounts[ip] ?? 0) + b.doc_count;
    }
  }

  return Object.entries(ipCounts).map(([sourceIp, count]) => ({ sourceIp, count }));
}

/** Write security events and observed traffic to Neo4j. */
async function writeToNeo4j(
  events: SyslogDoc[],
  traffic: { sourceIp: string; count: number }[],
): Promise<IngestSummary> {
  const session = getSession();
  let sshEvents = 0;
  let securityEvents = 0;
  let trafficLinks = 0;

  try {
    // Create SecurityEvent nodes from classified syslog events
    for (const evt of events) {
      const program = evt.syslog_program ?? '';
      const message = evt.syslog_message ?? '';
      const eventType = classifyEvent(program, message);
      if (!eventType) { continue; }

      const sourceIp = extractSourceIp(message);
      const sourceAsset = sourceIp ? IP_TO_ASSET[sourceIp] : null;
      const timestamp = evt['@timestamp'] ?? new Date().toISOString();

      const params: Record<string, unknown> = {
        type: eventType, sourceIp: sourceIp ?? 'unknown', timestamp, message, program,
      };

      if (sourceAsset) {
        await session.run(
          `MERGE (e:SecurityEvent {type: $type, sourceIp: $sourceIp, timestamp: $timestamp})
           SET e.message = $message, e.program = $program
           WITH e
           MATCH (a:Asset {name: $sourceAsset})
           MERGE (a)-[:GENERATED]->(e)`,
          { ...params, sourceAsset },
        );
      } else {
        await session.run(
          `MERGE (e:SecurityEvent {type: $type, sourceIp: $sourceIp, timestamp: $timestamp})
           SET e.message = $message, e.program = $program`,
          params,
        );
      }
      securityEvents++;
      if (program === 'sshd') { sshEvents++; }
    }

    // Create OBSERVED_TRAFFIC relationships from IP connection data
    for (const t of traffic) {
      const sourceAsset = IP_TO_ASSET[t.sourceIp];
      if (!sourceAsset) { continue; }

      // Find all assets this IP connected to (based on SSH events)
      await session.run(
        `MATCH (src:Asset {name: $source})
         MATCH (dst:Asset)
         WHERE dst.name <> $source
         MERGE (src)-[r:OBSERVED_TRAFFIC]->(dst)
         SET r.connectionCount = $count,
             r.lastSeen = datetime(),
             r.protocol = 'ssh'`,
        { source: sourceAsset, count: t.count },
      );
      trafficLinks++;
    }

    return {
      sshEvents,
      trafficLinks,
      securityEvents,
      timestamp: new Date().toISOString(),
    };
  } finally {
    await session.close();
  }
}

/** POST /api/ingest — pull syslog data from ELK and write to Neo4j. */
export async function POST(): Promise<NextResponse<IngestSummary | { error: string }>> {
  try {
    const since = 'now-24h';
    const [events, traffic] = await Promise.all([
      fetchSyslogEvents(since),
      fetchTrafficSummary(),
    ]);

    const summary = await writeToNeo4j(events, traffic);
    return NextResponse.json(summary);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Ingestion failed';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

/** GET /api/ingest — return current ingestion status. */
export async function GET(): Promise<NextResponse> {
  const session = getSession();
  try {
    const eventResult = await session.run(
      'MATCH (e:SecurityEvent) RETURN e.type AS type, count(e) AS count ORDER BY count DESC',
    );
    const trafficResult = await session.run(
      'MATCH ()-[r:OBSERVED_TRAFFIC]->() RETURN count(r) AS count',
    );

    const events = eventResult.records.map((r) => ({
      type: r.get('type'),
      count: (r.get('count') as { toNumber?: () => number }).toNumber?.() ?? r.get('count'),
    }));
    const trafficCount = (trafficResult.records[0]?.get('count') as { toNumber?: () => number })?.toNumber?.() ?? 0;

    return NextResponse.json({ events, observedTrafficLinks: trafficCount });
  } finally {
    await session.close();
  }
}
