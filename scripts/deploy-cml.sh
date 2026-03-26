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
  echo "  Created node: $label ($node_id)" >&2
  echo "$node_id"
}

echo ""
echo "=== Creating Nodes ==="

# Edge Router (IOSv)
EDGE_RTR=$(create_node "edge-rtr" "iosv" "iosv-159-3-m8" -400 0)

# Edge Firewall (IOSv router — swapped to ASAv after server testing)
EDGE_FW=$(create_node "edge-fw" "iosv" "iosv-159-3-m8" -200 0)

# Internal Firewall (IOSv router — swapped to ASAv after server testing)
INTERNAL_FW=$(create_node "internal-fw" "iosv" "iosv-159-3-m8" 0 0)

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

# Management VM (Ubuntu - Management) — runs SKG app via Docker
MGMT_VM=$(create_node "mgmt-vm" "ubuntu" "ubuntu-22-04-20240126" 400 400 4096 2)

# External connector for internet simulation
EXT_CONN=$(create_node "internet" "external_connector" "" -600 0 0 0 2>/dev/null || true)

echo ""
echo "=== Creating Links ==="

# Helper: ensure physical interfaces exist up to the given slot
ensure_interface() {
  local node=$1 slot=$2
  api POST "/labs/$LAB_ID/interfaces" \
    -d "{\"node\":\"$node\",\"slot\":$slot}" > /dev/null 2>&1
}

# Helper: get interface ID by slot number
get_iface_id() {
  local node=$1 slot=$2
  api GET "/labs/$LAB_ID/nodes/$node/interfaces?data=true" | \
    python3 -c "import sys,json; print(next(i['id'] for i in json.load(sys.stdin) if i.get('slot')==$slot))"
}

# Helper: create link between two nodes on specific interface slots
create_link() {
  local node_a=$1 slot_a=$2 node_b=$3 slot_b=$4 label=${5:-""}

  # Ensure physical interfaces exist
  ensure_interface "$node_a" "$slot_a"
  ensure_interface "$node_b" "$slot_b"

  # Get interface UUIDs
  local src_int=$(get_iface_id "$node_a" "$slot_a")
  local dst_int=$(get_iface_id "$node_b" "$slot_b")

  # Create the link
  api POST "/labs/$LAB_ID/links" \
    -d "{\"src_int\":\"$src_int\",\"dst_int\":\"$dst_int\"}" > /dev/null 2>&1
  echo "  Linked: $label"
}

# Network links matching topology (IOSv: Gi0/0=slot0, Gi0/1=slot1, ...)
# edge-rtr Gi0/1 <-> edge-fw Gi0/0 (edge-to-fw transit)
create_link "$EDGE_RTR" 1 "$EDGE_FW" 0 "edge-rtr <-> edge-fw"

# edge-fw Gi0/1 <-> web-srv ens2 (DMZ)
create_link "$EDGE_FW" 1 "$WEB_SRV" 0 "edge-fw <-> web-srv (DMZ)"

# edge-fw Gi0/2 <-> internal-fw Gi0/0 (edge-to-internal transit)
create_link "$EDGE_FW" 2 "$INTERNAL_FW" 0 "edge-fw <-> internal-fw"

# internal-fw Gi0/1 <-> app-srv ens2 (app tier)
create_link "$INTERNAL_FW" 1 "$APP_SRV" 0 "internal-fw <-> app-srv"

# internal-fw Gi0/2 <-> db-srv ens2 (db tier)
create_link "$INTERNAL_FW" 2 "$DB_SRV" 0 "internal-fw <-> db-srv"

# internal-fw Gi0/3 <-> corp-sw (corporate zone — shared segment)
create_link "$INTERNAL_FW" 3 "$DNS_SRV" 0 "internal-fw <-> dns-srv (corporate)"

# internal-fw Gi0/4 <-> mgmt-sw (management zone — shared segment)
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
