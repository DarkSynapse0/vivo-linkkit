#!/usr/bin/env bash
# 03_capture.sh [usb|net|ports] — capture traffic to captures/ (gitignored).
#
#   usb    capture the USB transport via usbmon (needs root + usbmon module)
#   net    capture the wireless transport on a chosen interface via tshark
#   ports  sweep the phone's open ports with nmap (phone must be on the LAN)
#
# Do USB before Wi-Fi — it's a clean single pipe. See CLAUDE.md.
set -euo pipefail

MODE="${1:-}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/captures/traffic"
mkdir -p "$OUT"
STAMP="$(date +%Y%m%d-%H%M%S)"

log() { printf '\033[1;34m[capture]\033[0m %s\n' "$*"; }

usage() { echo "usage: $0 [usb|net|ports]"; exit 1; }

case "$MODE" in
  usb)
    command -v tshark >/dev/null || { echo "tshark not found"; exit 1; }
    log "Loading usbmon (sudo). Find your bus with: lsusb / cat /sys/kernel/debug/usb/devices"
    sudo modprobe usbmon
    read -rp "usbmon bus number to capture (e.g. 1 for usbmon1, 0 = all): " BUS
    OUTFILE="$OUT/usb-${STAMP}.pcapng"
    log "Capturing → $OUTFILE  (Ctrl-C to stop)"
    sudo tshark -i "usbmon${BUS}" -w "$OUTFILE"
    ;;
  net)
    command -v tshark >/dev/null || { echo "tshark not found"; exit 1; }
    log "Interfaces:"; tshark -D
    read -rp "interface to capture (bridge to the phone's L2 segment): " IFACE
    OUTFILE="$OUT/net-${STAMP}.pcapng"
    log "Capturing on $IFACE → $OUTFILE  (Ctrl-C to stop)"
    log "Tip: also watch for mDNS (udp.port==5353) and broadcast discovery."
    sudo tshark -i "$IFACE" -w "$OUTFILE"
    ;;
  ports)
    command -v nmap >/dev/null || { echo "nmap not found"; exit 1; }
    read -rp "phone IP on the LAN: " IP
    OUTFILE="$OUT/ports-${IP}-${STAMP}.txt"
    log "Sweeping $IP → $OUTFILE"
    nmap -Pn -sT -sU --top-ports 200 "$IP" | tee "$OUTFILE"
    ;;
  *) usage ;;
esac

log "Saved under $OUT (gitignored)."
