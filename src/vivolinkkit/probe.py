"""probe.py — build-and-observe connectivity probe for the vivo phone link.

Phase 2, step 0: before we can pair, we need to *see* the phone's connection
service on the wire. This probe does no pairing and sends no secrets — it only:

  1. finds the phone's IP (from `adb`, or --ip),
  2. TCP-scans a set of candidate ports (from the PC client bundle + the idle
     `ss` output in captures/inventory/ports.txt),
  3. for each open port, pokes the `CONNECT_ROUTER` HTTP(S) routes and attempts a
     WebSocket upgrade, recording exactly what comes back.

Everything is logged to captures/probe/ (gitignored). Read-only reconnaissance
of a device you own — see PROTOCOL.md §1/§2.

Usage:
    python -m vivolinkkit.probe                 # auto-detect phone via adb
    python -m vivolinkkit.probe --ip 192.168.18.16 --timeout 2
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import subprocess
from base64 import b64encode
from datetime import datetime
from pathlib import Path

# Candidate ports: literals seen in the PC client bundle (PROTOCOL.md §2) plus
# 10191 which was LISTEN on the phone at idle (captures/inventory/ports.txt).
CANDIDATE_PORTS = [
    10191, 16384, 16832, 8200, 8192, 4160, 4096,
    3600, 2880, 2080, 2048, 1882, 1800, 1080, 1024,
]

# CONNECT_ROUTER keys seen in app-connection.js, mapped to guessed URL paths.
# The probe tries several prefixes since the exact path base is unconfirmed.
CONNECT_PATHS = [
    "/", "/version", "/baseinfo", "/test",
    "/connect/version", "/connect/baseinfo",
    "/api/v1/version", "/pc_file_manager/channel",
]

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "captures" / "probe"


def detect_phone_ip() -> str | None:
    """Pull the phone's IP from `adb devices` (wireless adb shows ip:port)."""
    try:
        out = subprocess.run(
            ["adb", "devices", "-l"], capture_output=True, text=True, timeout=6
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device" and ":" in parts[0]:
            return parts[0].split(":")[0]
    return None


def scan_port(ip: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            return s.connect_ex((ip, port)) == 0
        except OSError:
            return False


def http_probe(ip: str, port: int, path: str, tls: bool, timeout: float) -> dict:
    scheme = "https" if tls else "http"
    try:
        if tls:
            conn = http.client.HTTPSConnection(
                ip, port, timeout=timeout, context=ssl._create_unverified_context()
            )
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": "vivo-linkkit-probe/0"})
        r = conn.getresponse()
        body = r.read(1024)
        conn.close()
        return {
            "scheme": scheme, "path": path, "status": r.status,
            "headers": dict(r.getheaders()),
            "body": body.decode("utf-8", "replace"),
        }
    except Exception as e:  # noqa: BLE001 — probe: record any failure verbatim
        return {"scheme": scheme, "path": path, "error": f"{type(e).__name__}: {e}"}


def ws_probe(ip: str, port: int, tls: bool, timeout: float) -> dict:
    """Attempt a raw WebSocket upgrade; report the server's response line."""
    scheme = "wss" if tls else "ws"
    key = b64encode(os.urandom(16)).decode()  # probe nonce (os.urandom is fine here)
    req = (
        f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        sock = (
            ssl._create_unverified_context().wrap_socket(raw, server_hostname=ip)
            if tls else raw
        )
        sock.sendall(req.encode())
        resp = sock.recv(1024).decode("utf-8", "replace")
        sock.close()
        first = resp.splitlines()[0] if resp else ""
        return {"scheme": scheme, "response_line": first, "raw": resp[:400]}
    except Exception as e:  # noqa: BLE001
        return {"scheme": scheme, "error": f"{type(e).__name__}: {e}"}


def banner_grab(ip: str, port: int, timeout: float) -> dict:
    """Test whether an open port speaks first (server-greeting) or after a byte.

    Two passes: (1) connect and read without sending; (2) connect, send a single
    newline, then read. Bytes are recorded as hex + printable preview.
    """
    def _read(send: bytes | None) -> dict:
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.settimeout(timeout)
            if send:
                s.sendall(send)
            data = s.recv(256)
            s.close()
            return {
                "sent": send.decode("latin-1") if send else "",
                "recv_len": len(data),
                "recv_hex": data.hex(),
                "recv_ascii": data.decode("latin-1").replace("\n", "\\n"),
            }
        except Exception as e:  # noqa: BLE001
            return {"sent": send.decode("latin-1") if send else "",
                    "error": f"{type(e).__name__}: {e}"}
    return {"listen_only": _read(None), "after_newline": _read(b"\n")}


def probe(ip: str, ports: list[int], timeout: float) -> dict:
    result: dict = {
        "ip": ip, "timestamp": datetime.now().isoformat(timespec="seconds"),
        "open_ports": [], "findings": [],
    }
    print(f"[probe] target {ip} — scanning {len(ports)} candidate ports…")
    for port in ports:
        if not scan_port(ip, port, timeout):
            continue
        result["open_ports"].append(port)
        print(f"[probe] OPEN {ip}:{port} — poking endpoints")
        entry: dict = {"port": port, "banner": banner_grab(ip, port, timeout),
                       "http": [], "ws": []}
        b = entry["banner"]["listen_only"]
        if b.get("recv_len"):
            print(f"    banner (speaks first): {b['recv_hex'][:64]}")
        for tls in (False, True):
            for path in CONNECT_PATHS:
                r = http_probe(ip, port, path, tls, timeout)
                if "error" not in r:  # only keep endpoints that actually answered
                    entry["http"].append(r)
                    print(f"    {r['scheme']} {path} -> {r['status']}")
            w = ws_probe(ip, port, tls, timeout)
            entry["ws"].append(w)
            if w.get("response_line"):
                print(f"    {w['scheme']} upgrade -> {w['response_line']}")
        result["findings"].append(entry)
    if not result["open_ports"]:
        print("[probe] no candidate ports open. The connection service may be "
              "idle — start the phone's 'connect to PC' flow, then re-run.")
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="vivo-linkkit connectivity probe")
    ap.add_argument("--ip", help="phone IP (default: auto-detect via adb)")
    ap.add_argument("--timeout", type=float, default=2.0, help="per-op timeout (s)")
    ap.add_argument("--ports", help="comma-separated ports to override the defaults")
    args = ap.parse_args()

    ip = args.ip or detect_phone_ip()
    if not ip:
        raise SystemExit("could not determine phone IP — pass --ip, or connect adb")
    ports = (
        [int(p) for p in args.ports.split(",")] if args.ports else CANDIDATE_PORTS
    )

    result = probe(ip, ports, args.timeout)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = OUT_DIR / f"probe-{ip.replace('.', '_')}-{stamp}.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"[probe] wrote {out}")
    print(f"[probe] open ports: {result['open_ports'] or 'none'}")


if __name__ == "__main__":
    main()
