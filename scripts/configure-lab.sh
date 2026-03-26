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
ip domain name skg.lab
ip name-server 10.10.4.10
!
username cisco privilege 15 secret cisco
!
interface GigabitEthernet0/0
 description Uplink (System Bridge - DHCP)
 ip address dhcp
 ip nat outside
 no shutdown
!
interface GigabitEthernet0/1
 description Downlink to edge-fw
 ip address 10.0.0.1 255.255.255.252
 ip nat inside
 no shutdown
!
ip nat inside source list NAT-ACL interface GigabitEthernet0/0 overload
!
ip access-list standard NAT-ACL
 permit 10.0.0.0 0.255.255.255
!
ip route 10.10.0.0 255.255.0.0 10.0.0.2
!
ip ssh version 2
!
line con 0
 logging synchronous
line vty 0 4
 login local
 transport input ssh
!
event manager applet GENERATE_SSH_KEYS
 event timer countdown time 90
 action 1.0 cli command "enable"
 action 1.1 cli command "configure terminal"
 action 1.2 cli command "crypto key generate rsa general-keys modulus 2048"
 action 1.3 cli command "end"
 action 2.0 cli command "configure terminal"
 action 2.1 cli command "no event manager applet GENERATE_SSH_KEYS"
 action 2.2 cli command "end"
 action 3.0 syslog msg "EEM: SSH RSA keys generated successfully"
!
end
EOF
)"

# ── Edge Firewall (IOSv router — swapped to ASAv after testing) ──
EDGE_FW=$(get_node_id "edge-fw")
configure_node "$EDGE_FW" "edge-fw" "$(cat <<'EOF'
hostname edge-fw
!
ip domain name skg.lab
ip name-server 10.10.4.10
!
username cisco privilege 15 secret cisco
!
interface GigabitEthernet0/0
 description Uplink to edge-rtr
 ip address 10.0.0.2 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/1
 description DMZ (web-srv)
 ip address 10.10.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/2
 description Downlink to internal-fw
 ip address 10.0.1.1 255.255.255.252
 no shutdown
!
ip route 0.0.0.0 0.0.0.0 10.0.0.1
ip route 10.10.2.0 255.255.255.0 10.0.1.2
ip route 10.10.3.0 255.255.255.0 10.0.1.2
ip route 10.10.4.0 255.255.255.0 10.0.1.2
ip route 10.10.5.0 255.255.255.0 10.0.1.2
!
ip ssh version 2
!
line con 0
 logging synchronous
line vty 0 4
 login local
 transport input ssh
!
event manager applet GENERATE_SSH_KEYS
 event timer countdown time 90
 action 1.0 cli command "enable"
 action 1.1 cli command "configure terminal"
 action 1.2 cli command "crypto key generate rsa general-keys modulus 2048"
 action 1.3 cli command "end"
 action 2.0 cli command "configure terminal"
 action 2.1 cli command "no event manager applet GENERATE_SSH_KEYS"
 action 2.2 cli command "end"
 action 3.0 syslog msg "EEM: SSH RSA keys generated successfully"
!
end
EOF
)"

# ── Internal Firewall (IOSv router — swapped to ASAv after testing) ──
INTERNAL_FW=$(get_node_id "internal-fw")
configure_node "$INTERNAL_FW" "internal-fw" "$(cat <<'EOF'
hostname internal-fw
!
ip domain name skg.lab
ip name-server 10.10.4.10
!
username cisco privilege 15 secret cisco
!
interface GigabitEthernet0/0
 description Uplink to edge-fw
 ip address 10.0.1.2 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/1
 description App tier (app-srv)
 ip address 10.10.2.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/2
 description DB tier (db-srv)
 ip address 10.10.3.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/3
 description Corporate (dns-srv, vuln-vm)
 ip address 10.10.4.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/4
 description Management (elk-srv, mgmt-vm)
 ip address 10.10.5.1 255.255.255.0
 no shutdown
!
ip route 0.0.0.0 0.0.0.0 10.0.1.1
ip route 10.10.1.0 255.255.255.0 10.0.1.1
ip route 192.168.10.0 255.255.255.0 10.10.5.20
!
ip ssh version 2
!
line con 0
 logging synchronous
line vty 0 4
 login local
 transport input ssh
!
event manager applet GENERATE_SSH_KEYS
 event timer countdown time 90
 action 1.0 cli command "enable"
 action 1.1 cli command "configure terminal"
 action 1.2 cli command "crypto key generate rsa general-keys modulus 2048"
 action 1.3 cli command "end"
 action 2.0 cli command "configure terminal"
 action 2.1 cli command "no event manager applet GENERATE_SSH_KEYS"
 action 2.2 cli command "end"
 action 3.0 syslog msg "EEM: SSH RSA keys generated successfully"
!
end
EOF
)"

# ── Ubuntu VMs (cloud-init) ──
ubuntu_cloud_init() {
  local hostname=$1 ip=$2 gateway=$3
  cat <<CLOUDINIT
#cloud-config
hostname: $hostname
manage_etc_hosts: true
packages:
  - openssh-server
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
  - systemctl enable ssh
  - systemctl restart ssh
CLOUDINIT
}

# mgmt-vm: dual-stack (bridge + internal)
MGMT_VM=$(get_node_id "mgmt-vm")
configure_node "$MGMT_VM" "mgmt-vm" "$(cat <<'CLOUDINIT'
#cloud-config
hostname: mgmt-vm
manage_etc_hosts: true
packages:
  - openssh-server
  - git
  - python3-pip
  - software-properties-common
  - ca-certificates
  - curl
  - gnupg
users:
  - name: cisco
    groups: sudo,docker
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
  - systemctl enable ssh
  - systemctl restart ssh
  # Set DNS to Google until lab DNS is available
  - resolvectl dns ens2 8.8.8.8 8.8.4.4
  # Install Ansible
  - add-apt-repository --yes --update ppa:ansible/ansible
  - apt-get install -y ansible
  - ansible-galaxy collection install community.mysql
  # Install Docker CE
  - install -m 0755 -d /etc/apt/keyrings
  - curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  - chmod a+r /etc/apt/keyrings/docker.asc
  - echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
  - apt-get update
  - apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  - systemctl enable docker
  - systemctl start docker
  # Deploy SKG application
  - su - cisco -c "git clone https://github.com/fredferrell/security-knowledge-graph.git /home/cisco/skg"
  - su - cisco -c "cd /home/cisco/skg && docker compose up -d"
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
