#!/usr/bin/env bash
# vivo-linkkit — Windows 11 instrumentation VM: host prerequisites (ROOT step).
#
# The ONLY step that needs root. Run once:
#     sudo bash scripts/vm/00_host_prereqs.sh
# Then LOG OUT and back in (or run `newgrp libvirt`) so the group change takes
# effect, and run scripts/vm/10_create_vm.sh as your normal user.
set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
  echo "!! Run me with sudo:  sudo bash $0" >&2
  exit 1
fi

REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo zephyr0)}"
echo ">> Target user for libvirt/kvm groups: ${REAL_USER}"

echo ">> Enabling libvirt daemons (libvirtd + virtlogd)..."
systemctl enable --now libvirtd.service
systemctl enable --now virtlogd.service

echo ">> Adding ${REAL_USER} to 'libvirt' and 'kvm' groups..."
usermod -aG libvirt,kvm "${REAL_USER}"

echo ">> Ensuring the default NAT network exists and autostarts..."
if ! virsh net-info default >/dev/null 2>&1; then
  TMPNET="$(mktemp --suffix=.xml)"
  cat >"${TMPNET}" <<'EOF'
<network>
  <name>default</name>
  <forward mode='nat'/>
  <bridge name='virbr0' stp='on' delay='0'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
    </dhcp>
  </ip>
</network>
EOF
  virsh net-define "${TMPNET}"
  rm -f "${TMPNET}"
fi
virsh net-autostart default
virsh net-start default 2>/dev/null || true

echo
echo "== Host prereqs done. =="
virsh net-info default | sed 's/^/   /'
echo
echo ">> NEXT: log out and back in (or run 'newgrp libvirt'), then:"
echo "     bash scripts/vm/10_create_vm.sh"
