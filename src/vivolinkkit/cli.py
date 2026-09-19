"""vivolinkkit — unified command-line entry point.

    vivolinkkit login   [--region in]                 # one-time: your vivo account
    vivolinkkit connect [--list images,videos] [--grab images:3]
                        [--thumbs images:5] [--watch 10]
    vivolinkkit mirror  [--record phone.mp4] [--view-only]

`login` drives your own vivo passport login to obtain the account token.
`connect` opens a cloud-free USB connection to the phone and runs file services.
`mirror` streams the phone screen to the PC over USB (consent-free, via the
scrcpy app_process path — not vivo's OS-gated Cast SDK; see PROTOCOL.md §6).
Each subcommand forwards its remaining args to the underlying module, so
`vivolinkkit connect --help` shows the full connect options.
"""
from __future__ import annotations

import sys

_SUBCOMMANDS = {
    "login": ("vivolinkkit.login", "drive your own vivo account login (one-time)"),
    "connect": ("vivolinkkit.connect_usb", "USB connect + file list/download/thumbnails"),
    "mirror": ("vivolinkkit.mirror", "phone→PC screen mirror over USB (consent-free)"),
}


def _usage() -> str:
    lines = ["vivolinkkit — clean-room vivo Office Kit client\n",
             "usage: vivolinkkit <command> [options]\n", "commands:"]
    for name, (_mod, desc) in _SUBCOMMANDS.items():
        lines.append(f"  {name:9} {desc}")
    lines.append("\nRun `vivolinkkit <command> --help` for a command's options.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_usage()); return
    if argv[0] in ("-V", "--version"):
        from . import __version__
        print(f"vivolinkkit {__version__}"); return
    cmd, rest = argv[0], argv[1:]
    if cmd not in _SUBCOMMANDS:
        print(f"vivolinkkit: unknown command {cmd!r}\n\n{_usage()}", file=sys.stderr)
        raise SystemExit(2)
    import importlib
    mod = importlib.import_module(_SUBCOMMANDS[cmd][0])
    # Present the subcommand's own argparse under a clear prog name.
    sys.argv = [f"vivolinkkit {cmd}"] + rest
    mod.main()


if __name__ == "__main__":
    main()
