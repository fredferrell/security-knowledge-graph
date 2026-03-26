#!/usr/bin/env bash
# Swap IOSv routers (edge-fw, internal-fw) to ASAv firewalls
# Run this AFTER server testing is complete
# Usage: ./scripts/swap-to-asav.sh <lab-id>
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$PROJECT_DIR/.env" ]; then
  export $(grep -v '^#' "$PROJECT_DIR/.env" | grep -E '^CML_' | xargs)
fi

CML_URL="${CML_URL:?Set CML_URL in .env}"
CML_USER="${CML_USER:?Set CML_USER in .env}"
CML_PASSWORD="${CML_PASSWORD:?Set CML_PASSWORD in .env}"
LAB_ID="${1:?Usage: $0 <lab-id>}"

TOKEN=$(curl -sk -X POST "$CML_URL/api/v0/authenticate" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$CML_USER\",\"password\":\"$CML_PASSWORD\"}" | tr -d '"')

api() { curl -sk -X "$1" "$CML_URL/api/v0$2" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "${@:3}"; }

get_node_id() {
  api GET "/labs/$LAB_ID/nodes?data=true" | python3 -c "import sys,json; print(next(n['id'] for n in json.load(sys.stdin) if n['label']=='$1'))"
}

echo "=== Swapping IOSv routers to ASAv firewalls ==="
echo "Lab: $LAB_ID"
echo ""

# ── Stop firewall nodes ──
for fw_name in edge-fw internal-fw; do
  FW_ID=$(get_node_id "$fw_name")
  echo "Stopping $fw_name ($FW_ID)..."
  api PUT "/labs/$LAB_ID/nodes/$FW_ID/state/stop" > /dev/null 2>&1 || true
done

echo "Waiting for nodes to stop..."
sleep 15

# ── Swap to ASAv ──
for fw_name in edge-fw internal-fw; do
  FW_ID=$(get_node_id "$fw_name")
  echo "Wiping $fw_name..."
  api PUT "/labs/$LAB_ID/nodes/$FW_ID/wipe_disks" > /dev/null 2>&1 || true
  sleep 2

  echo "Changing $fw_name to ASAv..."
  api PATCH "/labs/$LAB_ID/nodes/$FW_ID" \
    -d '{"node_definition":"asav","image_definition":"asav-9-20-2","ram":2048,"cpus":1}' > /dev/null
done

# ── Apply ASAv configurations ──
echo ""
echo "Applying ASAv configurations..."

# Edge ASAv
EDGE_FW=$(get_node_id "edge-fw")
EDGE_CONFIG=$(cat <<'ASACONFIG'
hostname edge-fw
domain-name skg.lab
!
interface Management0/0
 shutdown
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 10.0.0.2 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/1
 nameif dmz
 security-level 50
 ip address 10.10.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/2
 nameif inside
 security-level 100
 ip address 10.0.1.1 255.255.255.252
 no shutdown
!
same-security-traffic permit inter-interface
same-security-traffic permit intra-interface
!
route outside 0.0.0.0 0.0.0.0 10.0.0.1 1
route inside 10.10.2.0 255.255.255.0 10.0.1.2 1
route inside 10.10.3.0 255.255.255.0 10.0.1.2 1
route inside 10.10.4.0 255.255.255.0 10.0.1.2 1
route inside 10.10.5.0 255.255.255.0 10.0.1.2 1
!
access-list PERMIT-ALL extended permit ip any any
access-group PERMIT-ALL in interface outside
access-group PERMIT-ALL in interface dmz
access-group PERMIT-ALL in interface inside
!
icmp permit any outside
icmp permit any dmz
icmp permit any inside
!
policy-map global_policy
 class inspection_default
  inspect icmp
!
service-policy global_policy global
!
dns domain-lookup outside
dns name-server 10.10.4.10
!
username cisco password cisco privilege 15
enable password cisco
aaa authentication ssh console LOCAL
ssh 0.0.0.0 0.0.0.0 outside
ssh 0.0.0.0 0.0.0.0 inside
ssh 0.0.0.0 0.0.0.0 dmz
ssh version 2
crypto key generate rsa modulus 2048 noconfirm
ASACONFIG
)
CONFIG_JSON=$(echo "$EDGE_CONFIG" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
api PATCH "/labs/$LAB_ID/nodes/$EDGE_FW" -d "{\"configuration\":$CONFIG_JSON}" > /dev/null
echo "  edge-fw configured"

# Internal ASAv
INTERNAL_FW=$(get_node_id "internal-fw")
INTERNAL_CONFIG=$(cat <<'ASACONFIG'
hostname internal-fw
domain-name skg.lab
!
interface Management0/0
 shutdown
!
interface GigabitEthernet0/0
 nameif edge-facing
 security-level 0
 ip address 10.0.1.2 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/1
 nameif app
 security-level 50
 ip address 10.10.2.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/2
 nameif db
 security-level 50
 ip address 10.10.3.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/3
 nameif corporate
 security-level 50
 ip address 10.10.4.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/4
 nameif management
 security-level 100
 ip address 10.10.5.1 255.255.255.0
 no shutdown
!
same-security-traffic permit inter-interface
same-security-traffic permit intra-interface
!
route edge-facing 0.0.0.0 0.0.0.0 10.0.1.1 1
route edge-facing 10.10.1.0 255.255.255.0 10.0.1.1 1
route management 192.168.10.0 255.255.255.0 10.10.5.20 1
!
access-list PERMIT-ALL extended permit ip any any
access-group PERMIT-ALL in interface edge-facing
access-group PERMIT-ALL in interface app
access-group PERMIT-ALL in interface db
access-group PERMIT-ALL in interface corporate
access-group PERMIT-ALL in interface management
!
icmp permit any edge-facing
icmp permit any app
icmp permit any db
icmp permit any corporate
icmp permit any management
!
policy-map global_policy
 class inspection_default
  inspect icmp
!
service-policy global_policy global
!
dns domain-lookup edge-facing
dns name-server 10.10.4.10
!
username cisco password cisco privilege 15
enable password cisco
aaa authentication ssh console LOCAL
ssh 0.0.0.0 0.0.0.0 edge-facing
ssh 0.0.0.0 0.0.0.0 app
ssh 0.0.0.0 0.0.0.0 db
ssh 0.0.0.0 0.0.0.0 corporate
ssh 0.0.0.0 0.0.0.0 management
ssh version 2
crypto key generate rsa modulus 2048 noconfirm
ASACONFIG
)
CONFIG_JSON=$(echo "$INTERNAL_CONFIG" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
api PATCH "/labs/$LAB_ID/nodes/$INTERNAL_FW" -d "{\"configuration\":$CONFIG_JSON}" > /dev/null
echo "  internal-fw configured"

# ── Start firewall nodes ──
echo ""
echo "Starting ASAv nodes..."
for fw_name in edge-fw internal-fw; do
  FW_ID=$(get_node_id "$fw_name")
  api PUT "/labs/$LAB_ID/nodes/$FW_ID/state/start" > /dev/null 2>&1
  echo "  $fw_name started"
done

echo ""
echo "=== ASAv swap complete ==="
echo "Wait 3-5 minutes for ASAv nodes to boot."
echo "Note: ASAv has 180kbps / 100 session limit."
