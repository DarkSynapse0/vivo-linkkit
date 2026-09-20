"""vivolinkkit mirror — phone→PC screen mirror + control over USB.

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
This command drives `scrcpy` (Apache-2.0), honest about the mechanism, and surfaces
its useful capabilities (control, audio, clipboard sync, file-drop) as first-class
flags. Anything not exposed here can still be passed through after `--`.

    vivolinkkit mirror                     # live window: control + audio + clipboard sync
    vivolinkkit mirror --view-only         # watch only, no keyboard/mouse control
    vivolinkkit mirror --stay-awake --screen-off   # keep phone awake, its own screen off
    vivolinkkit mirror --record phone.mp4  # record (also viewable unless --headless)
    vivolinkkit mirror --no-audio --bit-rate 4M --max-fps 30
    vivolinkkit mirror --push-target /sdcard/Download/   # where drag-dropped files land
    vivolinkkit mirror -- --video-codec h265             # pass extra args to scrcpy

Runtime tips (in the live window): drag a file onto it to push it to the phone; drag
an .apk to install it; clipboard syncs both ways (Ctrl+C / Ctrl+V). Over wireless
ADB (`adb tcpip` / Android "Wireless debugging") this works without a cable too.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

_INSTALL_HINT = (
    "    Arch:   sudo pacman -S scrcpy\n"
    "    Debian: sudo apt install scrcpy\n"
    "    (or see https://github.com/Genymobile/scrcpy)")


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
        raise SystemExit("[mirror] no adb device. Plug in the phone (or use wireless "
                         "ADB), enable USB debugging, authorize this host, then re-run.")
    if len(devs) > 1:
        raise SystemExit(f"[mirror] multiple devices {devs}; pass --serial.")
    return devs[0]


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="vivolinkkit mirror",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Phone→PC screen mirror + control over USB, via the scrcpy "
                    "app_process capture path (consent-free; not vivo's OS-gated "
                    "Cast SDK).",
        epilog="In the live window: drag a file onto it to push it to the phone; "
               "drag an .apk to install it; clipboard syncs both ways (Ctrl+C/Ctrl+V).")
    ap.add_argument("--serial", metavar="ID", help="adb serial (if multiple devices)")

    sess = ap.add_argument_group("session")
    sess.add_argument("--record", metavar="FILE",
                      help="record the stream to FILE (.mp4/.mkv); still viewable unless --headless")
    sess.add_argument("--headless", action="store_true",
                      help="don't open a window (use with --record)")
    sess.add_argument("--time-limit", type=int, metavar="SECONDS",
                      help="stop after SECONDS (handy with --record/--headless)")

    ctl = ap.add_argument_group("control")
    ctl.add_argument("--view-only", action="store_true",
                     help="mirror only — disable keyboard/mouse control of the phone")
    ctl.add_argument("--show-touches", action="store_true",
                     help="show a dot where the screen is touched")

    aud = ap.add_argument_group("audio (forwarded by default on Android 11+)")
    aud.add_argument("--no-audio", action="store_true", help="disable audio forwarding")
    aud.add_argument("--audio-source", choices=["output", "mic", "playback"],
                     help="audio source (default: output)")

    clip = ap.add_argument_group("clipboard (synced both ways by default)")
    clip.add_argument("--no-clipboard", action="store_true",
                      help="disable automatic clipboard sync")

    drop = ap.add_argument_group("file-drop")
    drop.add_argument("--push-target", metavar="DIR",
                      help="on-device dir for files dragged onto the window "
                           "(default: /sdcard/Download/)")

    qual = ap.add_argument_group("quality")
    qual.add_argument("--max-size", type=int, metavar="N",
                      help="cap the longest screen dimension to N px (downscale for speed)")
    qual.add_argument("--bit-rate", metavar="BR", help="video bitrate, e.g. 8M (default 8M)")
    qual.add_argument("--max-fps", type=int, metavar="N", help="cap frame rate to N fps")

    dev = ap.add_argument_group("device behaviour")
    dev.add_argument("--stay-awake", action="store_true",
                     help="keep the phone awake while plugged in")
    dev.add_argument("--screen-off", action="store_true",
                     help="turn the phone's own screen off while mirroring")

    ap.add_argument("extra", nargs=argparse.REMAINDER,
                    help="args after `--` are passed straight through to scrcpy")
    args = ap.parse_args()

    if shutil.which("scrcpy") is None:
        raise SystemExit(
            "[mirror] `scrcpy` not found. Install it (it's the consent-free capture "
            "engine we drive):\n" + _INSTALL_HINT)

    serial = pick_device(args.serial)

    cmd = ["scrcpy", "-s", serial]
    # session
    if args.record:
        cmd += ["--record", args.record]
    if args.headless:
        cmd += ["--no-playback"]
    if args.time_limit:
        cmd += ["--time-limit", str(args.time_limit)]
    # control
    if args.view_only:
        cmd += ["--no-control"]
    if args.show_touches:
        cmd += ["--show-touches"]
    # audio
    if args.no_audio:
        cmd += ["--no-audio"]
    elif args.audio_source:
        cmd += [f"--audio-source={args.audio_source}"]
    # clipboard
    if args.no_clipboard:
        cmd += ["--no-clipboard-autosync"]
    # file-drop
    if args.push_target:
        cmd += [f"--push-target={args.push_target}"]
    # quality
    if args.max_size:
        cmd += ["--max-size", str(args.max_size)]
    if args.bit_rate:
        cmd += [f"--video-bit-rate={args.bit_rate}"]
    if args.max_fps:
        cmd += [f"--max-fps={args.max_fps}"]
    # device behaviour
    if args.stay_awake:
        cmd += ["--stay-awake"]
    if args.screen_off:
        cmd += ["--turn-screen-off"]
    # passthrough (drop the leading "--" argparse leaves in REMAINDER)
    cmd += [a for a in args.extra if a != "--"]

    if args.headless and not args.record:
        print("[mirror] note: --headless without --record just decodes and discards; "
              "add --record FILE to keep it.", file=sys.stderr)

    bits = []
    if not args.view_only:
        bits.append("control")
    if not args.no_audio:
        bits.append("audio")
    if not args.no_clipboard:
        bits.append("clipboard")
    feat = "+".join(bits) or "view-only"
    dest = "recording " + args.record if args.record else "live window"
    print(f"[mirror] {serial} → {dest} [{feat}] (scrcpy, no MediaProjection consent)")
    try:
        raise SystemExit(subprocess.call(cmd))
    except FileNotFoundError:
        raise SystemExit("[mirror] failed to launch scrcpy.")
    except KeyboardInterrupt:
        raise SystemExit(0)


if __name__ == "__main__":
    main()
