#!/usr/bin/env bash
# 02_decompile.sh <package> — pull & decompile the phone agent, auto-grep for
# protocol signals (ports, crypto, discovery, protobuf/JSON field names).
#
# CLEAN-ROOM NOTE: the decompiled output is a *reference for writing the spec*.
# It lands in captures/ (gitignored) and must never be committed or transliterated
# into src/. Decompiled code informs the spec; the spec informs the source.
set -euo pipefail

PKG="${1:-}"
[[ -n "$PKG" ]] || { echo "usage: $0 <package.name>   (from recon/01_inventory.sh)"; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/captures/decompiled/$PKG"
mkdir -p "$OUT"

log() { printf '\033[1;34m[decompile]\033[0m %s\n' "$*"; }

command -v adb  >/dev/null || { echo "adb not found — run scripts/bootstrap.sh"; exit 1; }

# ── Pull the APK(s) — split APKs are common ────────────────────────────
log "Locating APK path(s) for $PKG"
mapfile -t APKS < <(adb shell pm path "$PKG" 2>/dev/null | sed 's/^package://' | tr -d '\r')
[[ ${#APKS[@]} -gt 0 ]] || { echo "no APK path for $PKG — is the package name correct?"; exit 1; }

for apk in "${APKS[@]}"; do
  base="$(basename "$apk")"
  log "Pulling $apk"
  adb pull "$apk" "$OUT/$base" >/dev/null
done

BASE_APK="$OUT/base.apk"
[[ -f "$BASE_APK" ]] || BASE_APK="$OUT/$(basename "${APKS[0]}")"

# ── Decompile with jadx (Java) ─────────────────────────────────────────
if command -v jadx >/dev/null; then
  log "Running jadx → $OUT/jadx"
  jadx --no-res -d "$OUT/jadx" "$BASE_APK" >/dev/null 2>&1 || \
    log "jadx reported errors (partial output is still useful)"
else
  log "jadx not installed (AUR: yay -S jadx) — skipping Java decompile"
fi

# ── Auto-grep for protocol signals ─────────────────────────────────────
SRC="$OUT/jadx"
REPORT="$OUT/SIGNALS.txt"
if [[ -d "$SRC" ]]; then
  log "Grepping for protocol signals → $REPORT"
  {
    echo "# Protocol signals for $PKG"
    echo
    echo "## Port numbers / socket setup"
    grep -rInE 'new (Server)?Socket|InetSocketAddress|\bport\b|:[0-9]{4,5}\b|bind\(|listen\(' "$SRC" 2>/dev/null | head -80
    echo; echo "## Discovery (mDNS / broadcast / UDP)"
    grep -rInE 'mdns|_tcp|_udp|NsdManager|MulticastSocket|255\.255\.255\.255|broadcast|discover' "$SRC" 2>/dev/null | head -60
    echo; echo "## Crypto suite"
    grep -rInE 'ECDH|X25519|Curve25519|AES/|GCM|CBC|Cipher\.getInstance|KeyAgreement|SecretKey|HKDF|SHA-?256|RSA' "$SRC" 2>/dev/null | head -80
    echo; echo "## Pairing / auth / token / cert"
    grep -rInE 'pair|handshake|auth|token|credential|certificate|login|account|challenge|nonce' "$SRC" 2>/dev/null | head -80
    echo; echo "## Framing / protobuf / JSON"
    grep -rInE 'magic|header|ByteBuffer|order\(ByteOrder|LITTLE_ENDIAN|BIG_ENDIAN|protobuf|MessageLite|JSONObject|@SerializedName' "$SRC" 2>/dev/null | head -80
  } > "$REPORT"
  log "Wrote $REPORT — start turning these into protocol/PROTOCOL.md"
else
  log "No decompiled sources to grep."
fi

log "Done. Reference lives in $OUT (gitignored). Write findings into the spec, not into src/."
