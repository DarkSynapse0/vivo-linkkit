# Windows 11 instrumentation VM

A throwaway Win11 guest for running the **official `pcsuite` client** and
capturing the *reference* protocol traffic — both the phone⇄client USB pipe and
the client⇄vivo-cloud login/gateway calls. We compare that reference against our
Python client (currently the P2 401-on-token-exchange problem).

> Clean-room note: the VM is for **observing** the wire protocol only. Do not
> copy vendor code into `src/`. Findings go into `protocol/PROTOCOL.md`; secrets
> and dumps stay in the gitignored `captures/`.

## Prerequisites present on this host

VT-x/AMD-V, `/dev/kvm`, QEMU, libvirt, OVMF (UEFI + Secure Boot), `swtpm`
(TPM 2.0), `virt-manager`/`virt-viewer`. The virtio-win driver ISO is at
`captures/vm/virtio-win.iso`. Windows ISO:
`~/Downloads/zen/Win11_25H2_EnglishInternational_x64_v2.iso`.

## Setup (two steps)

```bash
# 1) root, once — enables libvirt, adds you to libvirt/kvm groups, defines NAT net
sudo bash scripts/vm/00_host_prereqs.sh
#    then LOG OUT + back in (or:  newgrp libvirt)

# 2) normal user — defines and boots the VM
bash scripts/vm/10_create_vm.sh
virt-viewer --connect qemu:///system vivo-win11   # click through Windows setup
```

Tunables via env, e.g. `RAM_MB=8192 DISK_GB=80 bash scripts/vm/10_create_vm.sh`.

At the UEFI splash you may need to **press a key** for "Boot from CD/DVD".

**If setup says "This PC can't run Windows 11":** TPM 2.0 is present, but Secure
Boot is *capable* not *key-enrolled* (Arch OVMF ships no pre-enrolled keys), so
the appraiser can still balk. Press `Shift+F10` at that screen and run:

```
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f
```

then back out one screen and retry.

**Local account during OOBE:** at the network step press `Shift+F10`, run
`oobe\bypassnro` (reboots) or `start ms-cxh:localonly`.

## Hardware choices (and why)

| Part | Choice | Why |
|---|---|---|
| Firmware | OVMF UEFI + Secure Boot | Win11 install requirement |
| TPM | swtpm emulator, v2.0 | Win11 install requirement |
| Disk | **SATA** qcow2 | in-box Windows driver → no "load driver" step |
| NIC | **e1000e** | in-box Windows driver → network works on first boot |
| USB | qemu-xhci | ready for phone passthrough |
| Net | libvirt **NAT** (`default`) | phone-free, and mitmproxy-able |

Perf upgrade path (optional, later): switch disk to `bus=virtio` (viostor) and
NIC to `model=virtio` (NetKVM), loading drivers from the attached virtio-win CD.
Not worth it for pure protocol observation.

## Phone USB passthrough (for the USB-first protocol work)

Plug the phone into the host, then hand the USB device to the guest. Find it:

```bash
lsusb        # note the vivo/BBK vendor:product, e.g. 2d95:600d
```

Live attach (replace ids), or add it permanently in virt-manager
(*Add Hardware → USB Host Device*):

```bash
cat > /tmp/vivo-usb.xml <<'EOF'
<hostdev mode='subsystem' type='usb' managed='yes'>
  <source><vendor id='0xXXXX'/><product id='0xYYYY'/></source>
</hostdev>
EOF
virsh -c qemu:///system attach-device vivo-win11 /tmp/vivo-usb.xml --live
```

The phone leaves the host while attached (managed detach). Detach with
`virsh detach-device ... --live` to return it to Linux for our own captures.

## Capturing the client⇄cloud handshake (the 401 question)

The `pcsuite` login + gateway calls are HTTPS. To read them, MITM from the host:

1. Host (from the venv, since port 8080 is taken by another service here):
   `./.venv/bin/mitmweb --listen-host 0.0.0.0 --listen-port 8888 --web-port 8082
   --set save_stream_file=captures/auth/officekit-$(date +%s).mitm`.
   Guest reaches the host at the NAT gateway `192.168.122.1`; watch flows at
   `http://127.0.0.1:8082` on the host.
2. Guest: set the system proxy to `192.168.122.1:8888`, browse to
   `http://mitm.it`, install the mitmproxy CA into **Local Machine → Trusted
   Root** (Chromium/Electron apps like Office Kit use the Windows trust store).
   (Some vivo endpoints may pin certs — if a call fails only under proxy, note
   it; that itself is a finding for `PROTOCOL.md`.)
3. Drive a login in `pcsuite`; export the relevant flows to
   `captures/auth/` and diff against our request in `src/vivolinkkit`.

For the raw phone⇄client USB framing (not cloud), capture on the host with
`usbmon`/Wireshark *before* passing the device through — see
`recon/03_capture.sh`.

## Networking caveat — bridged needs Ethernet

This host is **Wi-Fi only (`wlan0`)**. 802.11 APs drop bridged frames bearing the
VM's foreign MAC, so `virbr0`-style bridging to the LAN **cannot work over
Wi-Fi**. NAT (above) is correct for USB + cloud-MITM work. When we reach the
Wi-Fi-Direct / same-L2 discovery phase (which CLAUDE.md wants on a bridge), use a
wired Ethernet uplink (or a USB-Ethernet dongle) and switch the NIC to
`type=bridge`. Not needed yet — USB comes first.

## Teardown

```bash
virsh -c qemu:///system destroy vivo-win11
virsh -c qemu:///system undefine --nvram vivo-win11   # keeps the qcow2
rm -f captures/vm/vivo-win11.qcow2                     # also drop the disk
```
