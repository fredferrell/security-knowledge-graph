#!/usr/bin/env bash
# Deploy the Security Knowledge Graph lab to CML
# Usage: ./scripts/deploy-cml.sh
# Requires: CML_URL, CML_USER, CML_PASSWORD in .env

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Load .env
if [ -f "$PROJECT_DIR/.env" ]; then
  export $(grep -v '^#' "$PROJECT_DIR/.env" | grep -E '^CML_' | xargs)
fi

CML_URL="${CML_URL:?Set CML_URL in .env}"
CML_USER="${CML_USER:?Set CML_USER in .env}"
CML_PASSWORD="${CML_PASSWORD:?Set CML_PASSWORD in .env}"

echo "=== Authenticating with CML at $CML_URL ==="
TOKEN=$(curl -sk -X POST "$CML_URL/api/v0/authenticate" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$CML_USER\",\"password\":\"$CML_PASSWORD\"}" | tr -d '"')

if [[ "$TOKEN" == *"description"* ]]; then
  echo "ERROR: Authentication failed"
  exit 1
fi
echo "Authenticated."

AUTH="-H 'Authorization: Bearer $TOKEN'"

# Helper: API call
api() {
  local method=$1 path=$2
  shift 2
  curl -sk -X "$method" "$CML_URL/api/v0$path" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" "$@"
}

echo ""
echo "=== Creating Lab ==="
LAB_ID=$(api POST /labs -d '{"title":"Security Knowledge Graph Lab"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Lab created: $LAB_ID"

# ──────────────────────────────────────────
# Create nodes
# ──────────────────────────────────────────
create_node() {
  local label=$1 definition=$2 image=$3 x=$4 y=$5
  local ram=${6:-0} cpus=${7:-0}

  local data="{\"label\":\"$label\",\"node_definition\":\"$definition\",\"image_definition\":\"$image\",\"x\":$x,\"y\":$y"
  if [ "$ram" -gt 0 ]; then
    data="$data,\"ram\":$ram"
  fi
  if [ "$cpus" -gt 0 ]; then
    data="$data,\"cpus\":$cpus"
  fi
  data="$data}"

  local node_id=$(api POST "/labs/$LAB_ID/nodes" -d "$data" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
  echo "  Created node: $label ($node_id)"
  echo "$node_id"
}

echo ""
echo "=== Creating Nodes ==="

# Edge Router (IOSv)
EDGE_RTR=$(create_node "edge-rtr" "iosv" "iosv-159-3-m8" -400 0)

# Edge Palo Alto Firewall
EDGE_FW=$(create_node "edge-fw" "panos10" "PaloAltoFirewallImage" -200 0 4096 2)

# Internal Palo Alto Firewall
INTERNAL_FW=$(create_node "internal-fw" "panos10" "PaloAltoFirewallImage" 0 0 4096 2)

# Web Server (Ubuntu - DMZ)
WEB_SRV=$(create_node "web-srv" "ubuntu" "ubuntu-22-04-20240126" -100 -200)

# App Server (Ubuntu - App Tier)
APP_SRV=$(create_node "app-srv" "ubuntu" "ubuntu-22-04-20240126" 100 -200)

# DB Server (Ubuntu - DB Tier)
DB_SRV=$(create_node "db-srv" "ubuntu" "ubuntu-22-04-20240126" 300 -200)

# DNS Server (Ubuntu - Corporate)
DNS_SRV=$(create_node "dns-srv" "ubuntu" "ubuntu-22-04-20240126" 100 200)

# Vulnerable VM (Ubuntu - Corporate)
VULN_VM=$(create_node "vuln-vm" "ubuntu" "ubuntu-22-04-20240126" 300 200)

# ELK Server (Ubuntu - Management)
ELK_SRV=$(create_node "elk-srv" "ubuntu" "ubuntu-22-04-20240126" 200 400 8192 2)

# Management VM (Ubuntu - Management)
MGMT_VM=$(create_node "mgmt-vm" "ubuntu" "ubuntu-22-04-20240126" 400 400)

# External connector for internet simulation
EXT_CONN=$(create_node "internet" "external_connector" "" -600 0 0 0 2>/dev/null || true)

echo ""
echo "=== Creating Links ==="

# Helper: create link between two nodes on specific interfaces
create_link() {
  local node_a=$1 iface_a=$2 node_b=$3 iface_b=$4 label=${5:-""}

  # Get interface IDs
  local a_iface_id=$(api GET "/labs/$LAB_ID/nodes/$node_a/interfaces" | \
    python3 -c "import sys,json; ifaces=json.load(sys.stdin); print(next((k for k,v in ifaces.items() if v.get('slot')==$iface_a), list(ifaces.keys())[$iface_a] if len(ifaces)>$iface_a else 'none'))")

  local b_iface_id=$(api GET "/labs/$LAB_ID/nodes/$node_b/interfaces" | \
    python3 -c "import sys,json; ifaces=json.load(sys.stdin); print(next((k for k,v in ifaces.items() if v.get('slot')==$iface_b), list(ifaces.keys())[$iface_b] if len(ifaces)>$iface_b else 'none'))")

  api POST "/labs/$LAB_ID/links" \
    -d "{\"src_node\":\"$node_a\",\"src_iface\":\"$a_iface_id\",\"dst_node\":\"$node_b\",\"dst_iface\":\"$b_iface_id\"}" > /dev/null 2>&1
  echo "  Linked: $label"
}

# Network links matching topology
# edge-rtr Gi0/1 <-> edge-fw ethernet1/1 (edge-to-fw transit)
create_link "$EDGE_RTR" 1 "$EDGE_FW" 0 "edge-rtr <-> edge-fw"

# edge-fw ethernet1/2 <-> web-srv ens2 (DMZ)
create_link "$EDGE_FW" 1 "$WEB_SRV" 0 "edge-fw <-> web-srv (DMZ)"

# edge-fw ethernet1/3 <-> internal-fw ethernet1/1 (edge-to-internal transit)
create_link "$EDGE_FW" 2 "$INTERNAL_FW" 0 "edge-fw <-> internal-fw"

# internal-fw ethernet1/2 <-> app-srv (app tier)
create_link "$INTERNAL_FW" 1 "$APP_SRV" 0 "internal-fw <-> app-srv"

# internal-fw ethernet1/3 <-> db-srv (db tier)
create_link "$INTERNAL_FW" 2 "$DB_SRV" 0 "internal-fw <-> db-srv"

# internal-fw ethernet1/4 <-> dns-srv (corporate - needs unmanaged switch for shared segment)
create_link "$INTERNAL_FW" 3 "$DNS_SRV" 0 "internal-fw <-> dns-srv (corporate)"

# internal-fw ethernet1/5 <-> elk-srv (management - needs unmanaged switch for shared segment)
create_link "$INTERNAL_FW" 4 "$ELK_SRV" 0 "internal-fw <-> elk-srv (management)"

# For shared segments (corporate: dns-srv + vuln-vm, management: elk-srv + mgmt-vm)
# we need unmanaged switches

echo ""
echo "=== Creating Shared Segment Switches ==="

CORP_SW=$(create_node "corp-sw" "unmanaged_switch" "" 200 200 0 0 2>/dev/null || echo "skip")
MGMT_SW=$(create_node "mgmt-sw" "unmanaged_switch" "" 300 400 0 0 2>/dev/null || echo "skip")

if [ "$CORP_SW" != "skip" ]; then
  # Reconnect: internal-fw eth1/4 -> corp-sw, dns-srv -> corp-sw, vuln-vm -> corp-sw
  create_link "$DNS_SRV" 0 "$CORP_SW" 0 "dns-srv <-> corp-sw" 2>/dev/null || true
  create_link "$VULN_VM" 0 "$CORP_SW" 1 "vuln-vm <-> corp-sw" 2>/dev/null || true
fi

if [ "$MGMT_SW" != "skip" ]; then
  # mgmt-sw: elk-srv -> mgmt-sw, mgmt-vm -> mgmt-sw
  create_link "$MGMT_VM" 0 "$MGMT_SW" 0 "mgmt-vm <-> mgmt-sw" 2>/dev/null || true
fi

echo ""
echo "=== Lab Summary ==="
echo "Lab ID: $LAB_ID"
echo "Lab URL: $CML_URL/lab/$LAB_ID"

NODE_COUNT=$(api GET "/labs/$LAB_ID/nodes" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
LINK_COUNT=$(api GET "/labs/$LAB_ID/links" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
echo "Nodes: $NODE_COUNT"
echo "Links: $LINK_COUNT"

echo ""
echo "=== Starting Lab ==="
api PUT "/labs/$LAB_ID/state/start" > /dev/null 2>&1
echo "Lab start initiated. Nodes will boot over the next few minutes."
echo ""
echo "Monitor at: $CML_URL/lab/$LAB_ID"
echo "Done."
