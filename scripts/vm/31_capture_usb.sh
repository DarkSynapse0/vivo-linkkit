#!/usr/bin/env bash
# Capture the phone<->PC USB pipe via usbmon — the real data path for a USB
# connect. The phone is passed through to the VM, but QEMU reaches it through the
# host USB stack, so usbmon still sees every URB. Run with sudo:
#
#   sudo bash scripts/vm/31_capture_usb.sh [bus] [seconds]
#
# Bus is auto-detected from the vivo device (vendor 2d95). To catch the CONNECT
# handshake (baseinfo + AES key/iv exchange, §3/§4 — likely the only plaintext
# part), start this FIRST, then disconnect+reconnect the phone in Office Kit,
# then browse files / send ONE small file. Keep screen-mirroring brief (video
# URBs are huge and drown the protocol).
set -euo pipefail

SECS="${2:-30}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$REPO_ROOT/captures/pipe"; mkdir -p "$OUT_DIR"

BUS="${1:-}"; DEV=""
if [ -z "$BUS" ]; then
  for d in /sys/bus/usb/devices/*/; do
    [ -f "$d/idVendor" ] || continue
    [ "$(cat "$d/idVendor")" = "2d95" ] || continue
    BUS=$(cat "$d/busnum"); DEV=$(cat "$d/devnum")
  done
fi
[ -n "$BUS" ] || { echo "!! no vivo (2d95) device found; pass the bus number explicitly"; exit 1; }

modprobe usbmon
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="$OUT_DIR/phone-usb-bus${BUS}-$STAMP.pcap"
echo ">> usbmon capture on usbmon${BUS} (vivo dev ${DEV:-?}) for ${SECS}s → $OUT"
echo ">> NOW in Office Kit: RECONNECT the phone (to catch the handshake), then"
echo "   browse the phone's files and send ONE small file. Keep mirroring short."
timeout "$SECS" tcpdump -i "usbmon${BUS}" -s 0 -w "$OUT" || true
chown "${SUDO_USER:-root}:${SUDO_USER:-root}" "$OUT" 2>/dev/null || true
echo ">> done: $(ls -lh "$OUT" 2>/dev/null)"
echo ">> analyse:  tcpdump -nr $OUT | head    (or open in Wireshark)"
