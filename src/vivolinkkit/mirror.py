"""vivolinkkit mirror — phone→PC screen mirror over USB.

INTERIM ENGINE. This drives the `app_process` capture path (scrcpy's mechanism),
NOT vivo's own Cast SDK. It's the *fallback* until vivo-native mirror is usable.

Why not vivo-native: that protocol is fully reverse-engineered (protocol/PROTOCOL.md
§6), but both PC→phone triggers (`CONTINUE_OPEN_SCREEN:` and `req_authrity`) funnel
to the same background `MediaProjectionActivity`, and Android's MediaProjection
consent self-cancels a PC-initiated (non-foreground) request in ~29 ms (verified on
Android 16; `appops PROJECT_MEDIA allow` doesn't help). The vendor client clears it
only as a *signed platform app*. So vivo-native mirror needs an on-device privileged
grant (root, or a Shizuku shell-UID helper) — until someone wires that up, we mirror
the consent-free way instead.

The `app_process` path sidesteps MediaProjection entirely: a small server runs on
the phone as the shell user, reads the display via framework APIs, and encodes
H.264/HEVC with MediaCodec — no consent dialog, works on any Android incl. vivo.
This command drives `scrcpy` (Apache-2.0), honest about the mechanism.

    vivolinkkit mirror                        # live, interactive window
    vivolinkkit mirror --view-only            # no keyboard/mouse control
    vivolinkkit mirror --record phone.mp4     # record to a file
    vivolinkkit mirror --record p.mp4 --headless --time-limit 10
    vivolinkkit mirror --max-size 1024        # downscale for speed
    vivolinkkit mirror -- --video-bit-rate 4M # pass extra args straight to scrcpy
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys


def _adb_devices() -> tuple[list[str], list[str]]:
    if shutil.which("adb") is None:
        raise SystemExit("[mirror] `adb` not found — install android-tools "
                         "(`sudo pacman -S android-tools`).")
    out = subprocess.run(["adb", "devices"], capture_output=True, text=True).stdout
    lines = [l for l in out.splitlines()[1:] if l.strip()]
    devs = [l.split()[0] for l in lines if l.split()[1:2] == ["device"]]
    unauth = [l.split()[0] for l in lines if l.split()[1:2] == ["unauthorized"]]
    return devs, unauth


def pick_device(serial: str | None) -> str:
    devs, unauth = _adb_devices()
    if serial:
        if serial in devs:
            return serial
        raise SystemExit(f"[mirror] serial {serial} not in `adb devices` ({devs or 'none'}).")
    if unauth and not devs:
        raise SystemExit("[mirror] phone is UNAUTHORIZED — accept the USB-debugging "
                         "prompt on the phone, then re-run.")
    if not devs:
        raise SystemExit("[mirror] no adb device. Plug in the phone, enable USB "
                         "debugging, authorize this host, then re-run.")
    if len(devs) > 1:
        raise SystemExit(f"[mirror] multiple devices {devs}; pass --serial.")
    return devs[0]


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="vivolinkkit mirror",
        description="Phone→PC screen mirror over USB, via the scrcpy app_process "
                    "capture path (consent-free; not vivo's OS-gated Cast SDK).")
    ap.add_argument("--serial", help="adb serial (if multiple devices)")
    ap.add_argument("--record", metavar="FILE",
                    help="record the stream to FILE (.mp4/.mkv) instead of just viewing")
    ap.add_argument("--headless", action="store_true",
                    help="don't open a window (use with --record)")
    ap.add_argument("--view-only", action="store_true",
                    help="mirror only — disable keyboard/mouse control of the phone")
    ap.add_argument("--max-size", type=int, metavar="N",
                    help="cap the longest screen dimension to N px (downscale for speed)")
    ap.add_argument("--time-limit", type=int, metavar="SECONDS",
                    help="stop after SECONDS (handy with --record/--headless)")
    ap.add_argument("extra", nargs=argparse.REMAINDER,
                    help="args after `--` are passed straight through to scrcpy")
    args = ap.parse_args()

    if shutil.which("scrcpy") is None:
        raise SystemExit(
            "[mirror] `scrcpy` not found. Install it (it's the consent-free capture "
            "engine we drive):\n"
            "    Arch:   sudo pacman -S scrcpy\n"
            "    Debian: sudo apt install scrcpy\n"
            "    (or see https://github.com/Genymobile/scrcpy)")

    serial = pick_device(args.serial)

    cmd = ["scrcpy", "-s", serial]
    if args.record:
        cmd += ["--record", args.record]
    if args.headless:
        cmd += ["--no-playback"]
    if args.view_only:
        cmd += ["--no-control"]
    if args.max_size:
        cmd += ["--max-size", str(args.max_size)]
    if args.time_limit:
        cmd += ["--time-limit", str(args.time_limit)]
    # drop a leading "--" separator argparse leaves in REMAINDER
    extra = [a for a in args.extra if a != "--"]
    cmd += extra

    if args.headless and not args.record:
        print("[mirror] note: --headless without --record just decodes and discards; "
              "add --record FILE to keep it.", file=sys.stderr)

    print(f"[mirror] {serial} → {'recording ' + args.record if args.record else 'live window'} "
          f"(scrcpy, no MediaProjection consent)")
    try:
        raise SystemExit(subprocess.call(cmd))
    except FileNotFoundError:
        raise SystemExit("[mirror] failed to launch scrcpy.")
    except KeyboardInterrupt:
        raise SystemExit(0)


if __name__ == "__main__":
    main()
