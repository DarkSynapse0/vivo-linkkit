#!/usr/bin/env bash
# bootstrap.sh — install host dependencies and create the Python venv.
# Target host: Arch Linux. Safe to re-run (idempotent-ish).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

log()  { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap]\033[0m %s\n' "$*" >&2; }

# ── Host packages (Arch) ───────────────────────────────────────────────
# Grouped by role. Adjust for your distro if not on Arch.
PACMAN_PKGS=(
  python python-pip          # exploration client
  android-tools              # adb — device inventory / decompile
  jadx                       # phone-agent decompile (extra repo)
  p7zip                      # unpack the Electron installer (app.asar)
  wireshark-cli              # tshark for live capture
  nmap                       # port sweep
  ffmpeg                     # decode/verify H.264 mirroring frames
)

if command -v pacman >/dev/null 2>&1; then
  log "Installing host packages via pacman (sudo required)…"
  # --needed skips already-installed; don't fail the whole run on one missing pkg.
  sudo pacman -S --needed --noconfirm "${PACMAN_PKGS[@]}" || \
    warn "Some pacman packages failed. jadx also works portably: download the zip"
  warn "from github.com/skylot/jadx/releases and unzip to ~/.local/share/jadx"
else
  warn "pacman not found. Install these manually: ${PACMAN_PKGS[*]}"
fi

# ── Python venv ────────────────────────────────────────────────────────
if [[ ! -d .venv ]]; then
  log "Creating virtualenv at .venv"
  python -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
log "Upgrading pip and installing Python deps"
pip install --quiet --upgrade pip

if [[ -f requirements.txt ]]; then
  pip install --quiet -r requirements.txt
fi

# Install the package itself in editable mode if pyproject exists.
if [[ -f pyproject.toml ]]; then
  pip install --quiet -e . || warn "editable install failed (fine until P2)"
fi

log "Done. Activate with:  source .venv/bin/activate"
log "Next:  recon/01_inventory.sh"
