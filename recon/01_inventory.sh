#!/usr/bin/env bash
# 01_inventory.sh — device identity + candidate packages + open ports.
# Read-only recon. Requires: adb (USB debugging enabled + authorized on phone).
# Output is written to captures/inventory/ (gitignored).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/captures/inventory"
mkdir -p "$OUT"

log() { printf '\033[1;34m[inventory]\033[0m %s\n' "$*"; }

command -v adb >/dev/null || { echo "adb not found — run scripts/bootstrap.sh"; exit 1; }

log "Waiting for an authorized device (plug in, enable USB debugging, tap Allow)…"
adb wait-for-device

# ── Device identity ────────────────────────────────────────────────────
log "Recording device identity → $OUT/device.txt"
{
  echo "# vivo-linkkit device inventory"
  echo "## adb devices"; adb devices -l
  for p in ro.product.manufacturer ro.product.model ro.product.device \
           ro.build.version.release ro.vivo.os.version ro.vivo.os.name \
           ro.build.version.sdk ro.product.cpu.abi; do
    printf '%-32s %s\n' "$p" "$(adb shell getprop "$p" | tr -d '\r')"
  done
} > "$OUT/device.txt"

# ── Candidate packages — anything that smells like Office Kit / share ──
log "Scanning installed packages for Office-Kit candidates → $OUT/packages.txt"
adb shell pm list packages -f 2>/dev/null | tr -d '\r' > "$OUT/packages-all.txt"
grep -Ei 'office|link|kit|share|connect|easyshare|filetransfer|cast|mirror|pcshare|vivo\.easy' \
  "$OUT/packages-all.txt" | sort -u > "$OUT/packages.txt" || true
log "Candidates found:"; cat "$OUT/packages.txt" || true

# ── Open ports on the phone (best effort; may need the app running) ────
log "Enumerating listening sockets on device → $OUT/ports.txt"
{
  echo "## ss -tulpn (if available)"; adb shell 'ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null'
} | tr -d '\r' > "$OUT/ports.txt" || true

log "Done. Review $OUT/, then pick a package for recon/02_decompile.sh <pkg>"
