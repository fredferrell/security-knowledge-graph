#!/usr/bin/env bash
# Configure all SKG lab devices with IP addressing and basic connectivity
# Usage: ./scripts/configure-lab.sh
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

configure_node() {
  local nid=$1 label=$2 config=$3
  echo "Configuring $label..."
  api PUT "/labs/$LAB_ID/nodes/$nid/state/stop" > /dev/null 2>&1 || true
  sleep 8
  api PUT "/labs/$LAB_ID/nodes/$nid/wipe_disks" > /dev/null 2>&1 || true
  sleep 2
  local config_json=$(echo "$config" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")
  api PATCH "/labs/$LAB_ID/nodes/$nid" -d "{\"configuration\":$config_json}" > /dev/null
  api PUT "/labs/$LAB_ID/nodes/$nid/state/start" > /dev/null 2>&1
  echo "  $label started"
}

echo "=== Configuring SKG Lab Devices ==="
echo "Lab: $LAB_ID"
echo ""

# ── Edge Router ──
EDGE_RTR=$(get_node_id "edge-rtr")
configure_node "$EDGE_RTR" "edge-rtr" "$(cat <<'EOF'
hostname edge-rtr
!
interface GigabitEthernet0/0
 description Uplink (System Bridge - DHCP)
 ip address dhcp
 no shutdown
!
interface GigabitEthernet0/1
 description Downlink to edge-fw
 ip address 10.0.0.1 255.255.255.252
 no shutdown
!
ip route 10.10.0.0 255.255.0.0 10.0.0.2
!
ip name-server 10.10.4.10
ip domain name skg.lab
!
line con 0
 logging synchronous
line vty 0 4
 login local
 transport input ssh
!
username cisco privilege 15 secret cisco
!
ip ssh version 2
crypto key generate rsa modulus 2048
!
end
EOF
)"

# ── Edge ASAv ──
EDGE_FW=$(get_node_id "edge-fw")
configure_node "$EDGE_FW" "edge-fw" "$(cat <<'EOF'
hostname edge-fw
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
username cisco password cisco privilege 15
aaa authentication ssh console LOCAL
ssh 0.0.0.0 0.0.0.0 outside
ssh 0.0.0.0 0.0.0.0 inside
ssh 0.0.0.0 0.0.0.0 dmz
ssh version 2
crypto key generate rsa modulus 2048
!
dns domain-lookup outside
dns name-server 10.10.4.10
domain-name skg.lab
EOF
)"

# ── Internal ASAv ──
INTERNAL_FW=$(get_node_id "internal-fw")
configure_node "$INTERNAL_FW" "internal-fw" "$(cat <<'EOF'
hostname internal-fw
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
route edge-facing 0.0.0.0 0.0.0.0 10.0.1.1 1
route edge-facing 10.10.1.0 255.255.255.0 10.0.1.1 1
!
access-list PERMIT-ALL extended permit ip any any
access-group PERMIT-ALL in interface edge-facing
access-group PERMIT-ALL in interface app
access-group PERMIT-ALL in interface db
access-group PERMIT-ALL in interface corporate
access-group PERMIT-ALL in interface management
!
username cisco password cisco privilege 15
aaa authentication ssh console LOCAL
ssh 0.0.0.0 0.0.0.0 edge-facing
ssh 0.0.0.0 0.0.0.0 app
ssh 0.0.0.0 0.0.0.0 db
ssh 0.0.0.0 0.0.0.0 corporate
ssh 0.0.0.0 0.0.0.0 management
ssh version 2
crypto key generate rsa modulus 2048
!
dns domain-lookup edge-facing
dns name-server 10.10.4.10
domain-name skg.lab
EOF
)"

# ── Ubuntu VMs (cloud-init) ──
ubuntu_cloud_init() {
  local hostname=$1 ip=$2 gateway=$3
  cat <<CLOUDINIT
#cloud-config
hostname: $hostname
manage_etc_hosts: true
users:
  - name: cisco
    groups: sudo
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    plain_text_passwd: cisco
ssh_pwauth: true
write_files:
  - path: /etc/netplan/99-static.yaml
    content: |
      network:
        version: 2
        ethernets:
          ens2:
            addresses:
              - ${ip}/24
            routes:
              - to: default
                via: ${gateway}
            nameservers:
              addresses:
                - 10.10.4.10
runcmd:
  - netplan apply
CLOUDINIT
}

# mgmt-vm: dual-stack (bridge + internal)
MGMT_VM=$(get_node_id "mgmt-vm")
configure_node "$MGMT_VM" "mgmt-vm" "$(cat <<'CLOUDINIT'
#cloud-config
hostname: mgmt-vm
manage_etc_hosts: true
users:
  - name: cisco
    groups: sudo
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    plain_text_passwd: cisco
ssh_pwauth: true
write_files:
  - path: /etc/netplan/99-static.yaml
    content: |
      network:
        version: 2
        ethernets:
          ens2:
            addresses:
              - 192.168.10.240/24
              - 10.10.5.20/24
            routes:
              - to: default
                via: 192.168.10.254
              - to: 10.0.0.0/8
                via: 10.10.5.1
            nameservers:
              addresses:
                - 10.10.4.10
                - 192.168.10.254
runcmd:
  - netplan apply
CLOUDINIT
)"

# elk-srv
ELK_SRV=$(get_node_id "elk-srv")
configure_node "$ELK_SRV" "elk-srv" "$(ubuntu_cloud_init elk-srv 10.10.5.10 10.10.5.1)"

# web-srv
WEB_SRV=$(get_node_id "web-srv")
configure_node "$WEB_SRV" "web-srv" "$(ubuntu_cloud_init web-srv 10.10.1.10 10.10.1.1)"

# app-srv
APP_SRV=$(get_node_id "app-srv")
configure_node "$APP_SRV" "app-srv" "$(ubuntu_cloud_init app-srv 10.10.2.10 10.10.2.1)"

# db-srv
DB_SRV=$(get_node_id "db-srv")
configure_node "$DB_SRV" "db-srv" "$(ubuntu_cloud_init db-srv 10.10.3.10 10.10.3.1)"

# dns-srv
DNS_SRV=$(get_node_id "dns-srv")
configure_node "$DNS_SRV" "dns-srv" "$(ubuntu_cloud_init dns-srv 10.10.4.10 10.10.4.1)"

# vuln-vm
VULN_VM=$(get_node_id "vuln-vm")
configure_node "$VULN_VM" "vuln-vm" "$(ubuntu_cloud_init vuln-vm 10.10.4.20 10.10.4.1)"

echo ""
echo "=== All devices configured and starting ==="
echo "Wait 3-5 minutes for all devices to boot."
echo ""
echo "Connectivity test from mgmt-vm (192.168.10.240):"
echo "  ssh cisco@192.168.10.240  (password: cisco)"
echo "  Then from mgmt-vm:"
echo "    ping 10.10.5.1   # internal-fw management"
echo "    ping 10.10.2.10  # app-srv"
echo "    ping 10.10.1.10  # web-srv"
echo "    ping 10.0.0.1    # edge-rtr"
