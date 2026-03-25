# Security Knowledge Graph

A graph-based security intelligence platform that connects vulnerabilities, asset context, and real-world traffic patterns. Built as a demo for enterprise security engineering — showing how a knowledge graph can identify protection gaps, trace blast radius during zero-day events, and detect configuration drift.

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Docker Compose                      │
│                                                  │
│  ┌──────────────┐     ┌───────────────────┐     │
│  │  Next.js App  │────>│  Neo4j (graph DB)  │     │
│  │  :3000        │     │  :7474 (browser)   │     │
│  │               │     │  :7687 (bolt)      │     │
│  └──────────────┘     └───────────────────┘     │
│       │                        ▲                 │
│  ┌────┴────┐           ┌──────┴──────┐          │
│  │ API      │           │ Seed Script  │          │
│  │ Routes   │           │ (topology +  │          │
│  │          │           │  CVEs + flows │          │
│  └─────────┘           │  + creds)    │          │
│                         └─────────────┘          │
└─────────────────────────────────────────────────┘

Data sourced from:
  cml/topology.yaml     — 10-device CML enterprise lab
  ansible/inventory/    — Ansible-managed infrastructure
```

## Quick Start

```bash
docker compose up
```

Open http://localhost:3000 — the knowledge graph loads automatically.

Neo4j browser available at http://localhost:7474 (neo4j/changeme).

## Features

### Knowledge Graph Visualization
Interactive force-directed graph showing all assets, vulnerabilities, firewall rules, and their relationships. Nodes colored by network zone, links colored by relationship type (traffic=green, vulnerability=red, credential=orange, enforcement=blue). Click any node for details.

### Blast Radius Analysis
Enter a CVE ID and trace its impact: which assets are affected, what's the shortest exposure path from the internet edge, and which firewall rules apply. The graph highlights affected nodes and paths in real-time.

### Gap Analysis
Identify assets that have known vulnerabilities but no deny firewall rules protecting their zone. The summary shows total vulnerabilities, assets with gaps, and covered assets.

### Zero-Day Simulation
Simulate a new CVE dropping: enter vulnerability details, and the system inserts it into the graph, links it to affected assets, and immediately shows the blast radius. Pre-filled with an example Apache zero-day.

### Ansible Drift Detection
Compare Ansible's intended infrastructure state (from inventory) against the actual graph. Detects: missing assets, IP mismatches, zone mismatches. Shows which devices are in sync and which have drifted.

## Lab Topology

10-device CML enterprise lab across five zones:

| # | Device | Zone | Role |
|---|--------|------|------|
| 1 | Edge Router | Internet Edge | NetFlow, routing |
| 2 | Edge Palo Alto | Edge | North-south firewall, App-ID |
| 3 | Web Server | DMZ | Apache reverse proxy |
| 4 | App Server | App Tier | PHP application |
| 5 | DB Server | DB Tier | MariaDB |
| 6 | Internal Palo Alto | Internal | East-west firewall |
| 7 | DNS Server | Corporate | BIND9, query logging |
| 8 | SIEM/ELK | Management | Log aggregation |
| 9 | Management VM | Management | Ansible controller |
| 10 | Vulnerable VM | Corporate | Apache 2.4.49, OpenSSH 8.2 |

## Tech Stack

- **Frontend**: Next.js 15, TypeScript, react-force-graph-2d
- **Graph DB**: Neo4j 5 Community
- **Infrastructure**: CML topology, Ansible playbooks, Palo Alto firewalls
- **Deployment**: Docker Compose (app + neo4j + seed)

## Development

```bash
npm install          # Install dependencies
npm run dev          # Next.js dev server (needs Neo4j running)
npm test             # Run all tests (137 tests)
npm run seed         # Seed Neo4j from topology (needs Neo4j running)
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/graph | Full knowledge graph (nodes + relationships) |
| GET | /api/blast-radius?cve=CVE-XXX | Blast radius for a specific CVE |
| GET | /api/gaps | Protection gap analysis |
| POST | /api/simulate/zero-day | Simulate a new zero-day event |
| GET | /api/drift | Ansible inventory drift detection |
