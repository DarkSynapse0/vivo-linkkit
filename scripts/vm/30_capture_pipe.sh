#!/usr/bin/env bash
# Capture the phone<->PC device pipe (the direct wss to the phone's LAN IP, §2)
# from the guest's tap interface. This pipe bypasses the HTTP proxy, so we grab
# it at the packet layer. tcpdump needs raw sockets → run with sudo:
#
#   sudo bash scripts/vm/30_capture_pipe.sh <phone_ip> [seconds]
#   e.g. sudo bash scripts/vm/30_capture_pipe.sh 192.168.18.16 60
#
# While it runs, EXERCISE Office Kit in the guest (open screen mirror, browse the
# phone's files, start a transfer) so the pipe actually carries protocol data.
set -euo pipefail

PHONE_IP="${1:-}"
SECS="${2:-60}"
IFACE="${IFACE:-vnet0}"          # the guest's tap; guest→phone rides this pre-NAT
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$REPO_ROOT/captures/pipe"   # gitignored
mkdir -p "$OUT_DIR"
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="$OUT_DIR/phone-pipe-$STAMP.pcap"

FILTER="not port 8888"           # drop the mitmproxy leg; keep everything else
[ -n "$PHONE_IP" ] && FILTER="host $PHONE_IP"

echo ">> capturing on $IFACE for ${SECS}s → $OUT"
echo ">> filter: ${FILTER}"
echo ">> NOW in the guest: open the phone screen / browse files / send a file…"
timeout "$SECS" tcpdump -i "$IFACE" -n -s 0 -w "$OUT" $FILTER || true
chown "${SUDO_USER:-root}:${SUDO_USER:-root}" "$OUT" 2>/dev/null || true
echo ">> done: $(ls -lh "$OUT" 2>/dev/null)"
echo ">> analyse (no root needed):  tcpdump -nr $OUT | head"
