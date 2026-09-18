"""explore.py — the Phase 2 exploration client.

Milestone that proves viability:  discover -> pair -> grab_one_frame,
writing a single decodable H.264 frame to disk. Verify with:

    ffmpeg -i first_frame.h264 -frames:v 1 out.png

Python on purpose: the parser gets rewritten many times, and Python makes that
minutes. Once a frame decodes, the rest is grinding, not research.

Everything below is a scaffold with the intended shape. Fill it in from
protocol/PROTOCOL.md as Phase 1 answers the open questions.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass


@dataclass
class Device:
    """A discovered vivo device."""
    name: str
    address: str
    port: int


def discover(timeout: float = 5.0) -> list[Device]:
    """Find vivo devices on the local segment.

    Mechanism (mDNS / UDP broadcast / BLE) is TBD — see PROTOCOL.md §1.
    """
    raise NotImplementedError("discovery — fill in from PROTOCOL.md §1")


def pair(device: Device) -> "Session":
    """Perform the pairing handshake and return an authenticated session.

    The auth model (local trust / account / vendor credential) is the pivotal
    unknown — see PROTOCOL.md §0. This function's shape depends on the answer.
    """
    raise NotImplementedError("pairing — fill in from PROTOCOL.md §0 and §5")


@dataclass
class Session:
    """An established, authenticated session with a device."""
    device: Device

    def grab_one_frame(self, out_path: str = "first_frame.h264") -> str:
        """Pull exactly one video frame and write it to disk.

        Success here is the whole point of Phase 2. Verify the output with
        ``ffmpeg -i <out_path> -frames:v 1 out.png``.
        """
        raise NotImplementedError("frame grab — fill in from PROTOCOL.md §6")


def main() -> None:
    ap = argparse.ArgumentParser(description="vivo-linkkit exploration client (P2)")
    ap.add_argument("--out", default="first_frame.h264", help="where to write the frame")
    ap.add_argument("--timeout", type=float, default=5.0, help="discovery timeout (s)")
    args = ap.parse_args()

    devices = discover(timeout=args.timeout)
    if not devices:
        raise SystemExit("no devices found")
    print(f"discovered: {devices[0]}")
    session = pair(devices[0])
    path = session.grab_one_frame(args.out)
    print(f"wrote {path} — verify with: ffmpeg -i {path} -frames:v 1 out.png")


if __name__ == "__main__":
    main()
