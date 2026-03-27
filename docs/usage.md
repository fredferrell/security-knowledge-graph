# Security Knowledge Graph — User Guide

## Accessing the Application

| Service | URL | Purpose |
|---------|-----|---------|
| **SKG Dashboard** | `http://192.168.10.240:3000` | Main application |
| **Neo4j Browser** | `http://192.168.10.240:7474` | Direct graph database queries |
| **Kibana** | `http://10.10.5.10:5601` | Raw syslog and NetFlow telemetry |

Login to Neo4j Browser with `neo4j` / `changeme`.

---

## Dashboard Overview

The dashboard has two areas:

- **Left sidebar** — Security analysis controls and results
- **Main area** — Interactive force-directed graph visualization

On load, the graph displays all assets, vulnerabilities, zones, and firewall rules as connected nodes. Nodes are color-coded by type and grouped by zone.

### Graph Interaction

- **Click a node** to see its properties in a detail panel (name, IP, zone, type, associated CVEs)
- **Drag nodes** to rearrange the layout
- **Scroll** to zoom in/out
- When an analysis is active, affected nodes are highlighted; unrelated nodes dim

---

## Security Analysis Features

### 1. Blast Radius

Shows the impact zone of a known CVE — which assets are affected and how an attacker could reach them.

**How to use:**
1. Enter a CVE ID in the text field (default: `CVE-2021-41773`)
2. Click **Blast Radius**

**Results show:**
- **Affected Assets** — servers running the vulnerable software, with IP and zone
- **Exposure Paths** — network paths from the internet edge to each affected asset (e.g., `edge-rtr → edge-fw → web-srv`)
- **Firewall Rules** — any rules that allow or deny traffic to affected assets

The graph highlights affected assets and the nodes along each exposure path.

**Known CVEs in the graph:**

| CVE | Severity | Affected Software |
|-----|----------|-------------------|
| CVE-2021-41773 | Critical | Apache 2.4.49 (path traversal) |
| CVE-2021-42013 | Critical | Apache 2.4.50 (path traversal bypass) |
| CVE-2022-32081 | High | MariaDB |
| CVE-2023-38408 | High | OpenSSH |
| CVE-2023-51767 | Medium | OpenSSH |

### 2. Gap Analysis

Identifies assets with known vulnerabilities that lack protective firewall deny rules — protection gaps.

**How to use:**
1. Click **Gap Analysis**

**Results show:**
- **Summary** — total vulnerabilities, number of assets with gaps, number of covered assets
- **Vulnerable Assets** — each asset-CVE pair, with severity and whether a deny rule exists
- Assets marked with "NO DENY RULE" are unprotected gaps

The graph highlights all assets that have protection gaps.

### 3. Zero-Day Simulation

Simulates a hypothetical zero-day vulnerability to see which assets would be at risk before a patch exists.

**How to use:**
1. Scroll to the **Zero-Day Simulation** section in the sidebar
2. Fill in:
   - **CVE ID** — any identifier (e.g., `CVE-2024-99999`)
   - **Severity** — `critical`, `high`, `medium`, or `low`
   - **Affected Software** — the software name to match against assets (e.g., `apache`, `openssh`, `mariadb`)
   - **Description** and **Affected Version** are optional
3. Click **Simulate**

**Results show:**
- **Affected Assets** — assets running the specified software
- **Exposure Paths** — how an attacker could reach those assets from the internet edge

This does not modify the graph — it's a read-only simulation.

### 4. Config Drift Detection

Compares the Ansible inventory (intended state) against the Neo4j knowledge graph (observed state) to find mismatches.

**How to use:**
1. Click **Check Drift**

**Results show:**
- Each asset with its sync status:
  - **in_sync** — inventory and graph agree
  - **zone_mismatch** — the asset's zone differs between inventory and graph
  - **ip_mismatch** — the asset's IP differs
  - **missing_from_graph** / **missing_from_inventory** — asset exists in one but not the other

### 5. Risk Analytics

Calculates risk scores for every asset based on vulnerability count, severity, credential exposure, traffic flow patterns, and network centrality.

**How to use:**
1. Click **Analyze Risk**

**Results show:**
- **Top Risks** — the 5 highest-risk assets with scores and primary risk reason
- **Network Stats** — total assets, vulnerabilities, traffic flows, credentials, and average risk score
- **Per-Asset Metrics** — degree centrality, vulnerability count, critical vulns, credential exposure, inbound/outbound flows

The graph highlights the top-risk assets.

### 6. Posture Report

Generates a comprehensive security posture report combining all analysis types.

**How to use:**
1. Click **Generate Report**

**Results show:**
- **Summary** — overall risk level, total assets/vulnerabilities, protection coverage percentage, critical findings count
- **Vulnerability Matrix** — each CVE with severity, affected assets, internet exposure, and firewall protection status
- **Zone Analysis** — risk breakdown by network zone
- **Credential Map** — which assets share credentials (lateral movement risk)
- **Recommendations** — actionable remediation steps

### Reset

Click **Reset** to clear all analysis results and return the graph to its default view.

---

## Neo4j Browser (Direct Queries)

Access `http://192.168.10.240:7474` for direct Cypher queries against the knowledge graph.

**Useful queries:**

```cypher
// View all assets and their zones
MATCH (a:Asset)-[:IN_ZONE]->(z:Zone)
RETURN a.name, a.ip, z.name AS zone

// Find assets with critical vulnerabilities
MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.severity = 'critical'
RETURN a.name, v.cveId, v.severity

// Show traffic flows between assets
MATCH (a:Asset)-[t:TRAFFIC_FLOW]->(b:Asset)
RETURN a.name AS source, b.name AS target, t.port, t.protocol

// Find exposure paths from edge to a specific asset
MATCH p = (edge:Asset {name: 'edge-rtr'})-[:TRAFFIC_FLOW*]->(target:Asset {name: 'vuln-vm'})
RETURN [n IN nodes(p) | n.name] AS path

// Show firewall rules
MATCH (r:FirewallRule)-[:ENFORCES]->(a:Asset)
RETURN r.name, r.sourceZone, r.destZone, r.action, a.name AS enforcedOn
```

---

## Kibana (Telemetry)

Access `http://10.10.5.10:5601` from within the lab network (e.g., from mgmt-vm's browser or via SSH tunnel).

### Syslog Data

Index pattern: `syslog-*`

Contains syslog messages forwarded from all lab servers via rsyslog to Logstash (port 5514). Includes authentication events, service start/stop, and application logs.

### NetFlow Data

Index pattern: `netflow-*`

Contains NetFlow v9 records exported from edge-rtr to Logstash (port 2055). Shows traffic flows with source/destination IPs, ports, protocols, and byte counts.

### Creating Index Patterns

On first use:
1. Go to **Stack Management** > **Data Views** (or **Index Patterns** in older Kibana)
2. Create a data view for `syslog-*`
3. Create a data view for `netflow-*`
4. Use **Discover** to browse events, or **Dashboard** to build visualizations

---

## Lab Network Reference

```
Internet ── edge-rtr (10.0.0.1) ── edge-fw (10.0.0.2) ─┬─ web-srv  (10.10.1.10)  DMZ
                                                         │
                                        internal-fw ─────┼─ app-srv  (10.10.2.10)  App Tier
                                        (10.0.1.2)       ├─ db-srv   (10.10.3.10)  DB Tier
                                                         ├─ dns-srv  (10.10.4.10)  Corporate
                                                         ├─ vuln-vm  (10.10.4.20)  Corporate
                                                         ├─ elk-srv  (10.10.5.10)  Management
                                                         └─ mgmt-vm (10.10.5.20)  Management
                                                                     (192.168.10.240 bridge)
```

### Three-Tier Web Application

| Tier | Server | Service | Port |
|------|--------|---------|------|
| Web | web-srv | Apache reverse proxy (HTTPS) | 443 |
| App | app-srv | Apache + PHP | 443 |
| DB | db-srv | MariaDB | 3306 |

Access the web app at `https://10.10.1.10` — it proxies through to app-srv, which queries db-srv.

### Intentionally Vulnerable VM

vuln-vm runs Apache 2.4.49 (CVE-2021-41773 path traversal) on port 80 and OpenSSH 8.2 with known CVEs. This exists to demonstrate the SKG's gap detection and blast radius analysis.
