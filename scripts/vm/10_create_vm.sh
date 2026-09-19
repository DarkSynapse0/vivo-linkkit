#!/usr/bin/env bash
# vivo-linkkit — Windows 11 instrumentation VM: define + start (NORMAL user).
#
# Run AFTER 00_host_prereqs.sh and a re-login (so your 'libvirt' group is live):
#     bash scripts/vm/10_create_vm.sh
#
# Boots Win11 (UEFI + Secure Boot + TPM 2.0) on q35 with SATA disk + e1000e NIC
# (both have in-box Windows drivers -> no "load driver" step during install) and
# a qemu-xhci controller ready for phone USB passthrough. NAT networking so the
# guest's cloud traffic is mitmproxy-able. See README.md for the capture workflow.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

VM_NAME="vivo-win11"
WIN_ISO="${WIN_ISO:-/home/zephyr0/Downloads/zen/Win11_25H2_EnglishInternational_x64_v2.iso}"
VIRTIO_ISO="${VIRTIO_ISO:-${REPO_ROOT}/captures/vm/virtio-win.iso}"
DISK_DIR="${REPO_ROOT}/captures/vm"
DISK="${DISK_DIR}/${VM_NAME}.qcow2"
DISK_GB="${DISK_GB:-64}"
RAM_MB="${RAM_MB:-6144}"
VCPUS="${VCPUS:-4}"
CONN="qemu:///system"

die() { echo "!! $*" >&2; exit 1; }

command -v virt-install >/dev/null || die "virt-install not found"
[ -f "${WIN_ISO}" ]    || die "Windows ISO not found: ${WIN_ISO}  (set WIN_ISO=/path)"
[ -f "${VIRTIO_ISO}" ] || die "virtio-win ISO not found: ${VIRTIO_ISO}"
virsh -c "${CONN}" version >/dev/null 2>&1 \
  || die "Cannot reach ${CONN}. Did you run 00_host_prereqs.sh and re-login (or 'newgrp libvirt')?"

if virsh -c "${CONN}" dominfo "${VM_NAME}" >/dev/null 2>&1; then
  die "Domain '${VM_NAME}' already exists. Remove it first:
     virsh -c ${CONN} destroy ${VM_NAME} 2>/dev/null; virsh -c ${CONN} undefine --nvram ${VM_NAME}"
fi

mkdir -p "${DISK_DIR}"

# System-libvirt runs qemu as 'libvirt-qemu'; it must be able to traverse the
# directory chain to the disk/ISOs (your $HOME is 0700). Grant *only* that user
# execute on the parent dirs and read on the media — no world-loosening, no sudo.
# Undo later with:  setfacl -R -x u:libvirt-qemu <path>
grant_hv_access() {
  local target="$1" p
  command -v setfacl >/dev/null || return 0
  p="$(dirname "${target}")"
  while :; do
    setfacl -m u:libvirt-qemu:x "${p}" 2>/dev/null || true
    [ "${p}" = "/" ] && break
    p="$(dirname "${p}")"
  done
  [ -f "${target}" ] && setfacl -m u:libvirt-qemu:r "${target}" 2>/dev/null || true
}
echo ">> Granting libvirt-qemu traversal to media/disk paths..."
grant_hv_access "${WIN_ISO}"
grant_hv_access "${VIRTIO_ISO}"
grant_hv_access "${DISK}"                 # parent dir; disk file created next

echo ">> Creating VM '${VM_NAME}' (${VCPUS} vCPU, ${RAM_MB}MB RAM, ${DISK_GB}GB disk)"
virt-install \
  --connect "${CONN}" \
  --name "${VM_NAME}" \
  --osinfo win11 \
  --memory "${RAM_MB}" \
  --vcpus "${VCPUS}" \
  --cpu host-passthrough \
  --machine q35 \
  --boot firmware=efi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes \
  --features smm.state=on \
  --tpm backend.type=emulator,backend.version=2.0,model=tpm-crb \
  --disk path="${DISK}",size="${DISK_GB}",bus=sata,format=qcow2 \
  --disk path="${WIN_ISO}",device=cdrom,boot.order=1 \
  --disk path="${VIRTIO_ISO}",device=cdrom \
  --network network=default,model=e1000e \
  --controller type=usb,model=qemu-xhci \
  --graphics spice \
  --video qxl \
  --sound ich9 \
  --rng /dev/urandom \
  --noautoconsole

echo
echo "== '${VM_NAME}' defined and starting. =="
echo ">> Open the console to click through Windows setup:"
echo "     virt-viewer --connect ${CONN} ${VM_NAME}    # or: virt-manager"
echo
echo ">> During Windows setup, if it demands a Microsoft account / network, use"
echo "   Shift+F10 -> 'oobe\\bypassnro' (or 'start ms-cxh:localonly') for a local account."
echo ">> The virtio-win CD is attached for later: qemu-guest-agent + spice-guest-tools."
