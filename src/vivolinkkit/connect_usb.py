"""connect_usb.py — P3 proof-of-concept: cloud-free USB connect handshake.

Clean-room reimplementation of the vivo Office Kit USB connect (PROTOCOL.md §1
"USB" + §8), built from the *observed protocol*, not from vendor code. The whole
point of this script is to test one claim: **the connect token is PC-minted
local trust** — so we can generate our OWN token, drive adb the way the official
client does, and the phone should accept us because our account `openid` proves
same-account. No vivo cloud call is made by this script.

Flow (matches the usbmon capture, 2026-09-19):
  1. adb: verify com.vivo.pcsuite is installed on the phone.
  2. Start PC-side listeners on 5679 + 8904, then `adb reverse` them. REQUIRED:
     verified live that the phone binds its :10380 server ONLY once these
     reverse channels exist (no listener → :10380 never comes up).
  3. adb: `am start`  the PCSUITE intent, then `am startservice` the
     AdbPortalService with our minted --es token / openid / connectionId.
     Verified: no on-screen confirmation on the phone (pure USB-access trust).
  4. adb forward tcp:10380 / tcp:10381 (PC→phone); wait for :10380 to bind.
  5. HTTP POST 127.0.0.1:10380 /version then /base-info  with the `newToken`
     header.

STATUS (2026-09-19): steps 1–4 work; :10380 binds. Step 5 still blocked — the
phone accepts the TCP connection but closes /version|/base-info WITHOUT a
response. The reverse channels (8904/5679) evidently need a real handshake
(likely TLS/custom framing), not a dumb accept, before :10380 will serve. Next:
decode the 8904/5679 reverse-stream bytes from the official usbmon capture
(captures/pipe/phone-usb-bus3-*.pcap) and speak that protocol here.

Requirements:
  * adb on PATH, the phone plugged into THIS host, USB debugging authorized.
  * The phone logged into the SAME vivo account you logged into with
    `vivolinkkit.login` (captures/auth/token.json → openId).

Definitive cloud-free test: put the PHONE in airplane mode (no Wi-Fi/data) before
running. If /base-info still succeeds, the phone validates the token locally —
no cloud in the loop.
"""
from __future__ import annotations

import argparse
import json
import secrets
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AUTH_DIR = REPO_ROOT / "captures" / "auth"  # gitignored

# Observed constants (PROTOCOL.md §1/§8) ---------------------------------------
PKG = "com.vivo.pcsuite"
SERVICE = f"{PKG}/.service.AdbPortalService"
PCSUITE_INTENT = "vivo.intent.action.PCSUITE_INTENT"
PORT_HTTP = 10380          # phone's PcSuite-HTTP server (control)
PORT_TLS = 10381           # phone's TLS server (media/data)
REVERSE_PORTS = [5679, 8904]   # phone→PC channels
APP_VERSION = "6.8.2"
CONN_BASE_VERSION_CODE = 1155
PCSUITE_VERSION_CODE = 65011
UA = ("Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like "
      "Gecko) pcsuite/6.8.2 Chrome/108.0.5359.62 Electron/22.0.0 Safari/537.36")


# --- small helpers ------------------------------------------------------------
def now_ms() -> int:
    return int(time.time() * 1000)


def run(cmd: list[str], timeout: float = 15.0) -> tuple[int, str]:
    """Run a command, return (rc, combined-output). Never raises on non-zero."""
    print("   $ " + " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 1, f"{type(e).__name__}: {e}"
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode, out.strip()


def adb(serial: str | None, *args: str, timeout: float = 15.0) -> tuple[int, str]:
    base = ["adb"] + (["-s", serial] if serial else [])
    return run(base + list(args), timeout=timeout)


def pick_device(serial: str | None) -> str:
    rc, out = adb(None, "devices")
    lines = [l for l in out.splitlines()[1:] if l.strip()]
    devs = [l.split()[0] for l in lines if l.split()[1:2] == ["device"]]
    unauth = [l.split()[0] for l in lines if l.split()[1:2] == ["unauthorized"]]
    if serial:
        if serial in devs:
            return serial
        raise SystemExit(f"[connect] serial {serial} not in `adb devices`: {out}")
    if unauth and not devs:
        raise SystemExit("[connect] phone is UNAUTHORIZED — accept the USB-debug "
                         "RSA prompt on the phone, then re-run.")
    if not devs:
        raise SystemExit("[connect] no adb device. Plug in the phone, enable USB "
                         "debugging, authorize this host, then re-run.")
    if len(devs) > 1:
        raise SystemExit(f"[connect] multiple devices {devs}; pass --serial.")
    return devs[0]


# --- stable PC identity (persisted, gitignored) -------------------------------
def _persist(name: str, factory) -> str:
    p = AUTH_DIR / name
    if p.exists():
        return p.read_text().strip()
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    val = factory()
    p.write_text(val)
    return val


def pc_device_id() -> str:
    # observed shape: 64-hex + an uppercased GUID, concatenated
    return _persist("pc_device_id.txt",
                    lambda: secrets.token_hex(32) + str(uuid.uuid4()).upper())


def pc_ble_id() -> str:
    # a MAC-like id; locally-administered random
    def mk():
        b = bytearray(secrets.token_bytes(6)); b[0] = (b[0] & 0xFE) | 0x02
        return ":".join(f"{x:02x}" for x in b)
    return _persist("pc_ble_id.txt", mk)


def load_account() -> tuple[str, str]:
    """Return (openId, pcLoginAccount) from the login step's token.json."""
    tj = AUTH_DIR / "token.json"
    if not tj.exists():
        raise SystemExit("[connect] captures/auth/token.json missing — run "
                         "`python -m vivolinkkit.login --region <r>` first.")
    d = json.loads(tj.read_text())
    openid = d.get("openId") or ""
    acct = ((d.get("verify_response") or {}).get("data") or {}).get("phone") or ""
    if not openid:
        raise SystemExit("[connect] no openId in token.json — re-run login.")
    return openid, acct


# --- HTTP over the adb-forwarded port -----------------------------------------
def start_reverse_listeners(ports: list[int]) -> threading.Event:
    """Hold PC-side servers on the reverse ports. The phone binds :10380 only
    once these exist. NOTE: these currently just accept+hold — the real per-port
    handshake (8904/5679, likely TLS) is not yet implemented, which is why the
    /base-info POST still gets closed without a response."""
    stop = threading.Event()

    def serve(port: int) -> None:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port)); s.listen(8); s.settimeout(0.5)
        except OSError as e:
            print(f"   [reverse] bind :{port} failed: {e}"); return
        while not stop.is_set():
            try:
                c, _ = s.accept()
                print(f"   [reverse] phone→PC :{port} connected")
                threading.Thread(target=_hold, args=(c, stop), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break
        s.close()

    for p in ports:
        threading.Thread(target=serve, args=(p,), daemon=True).start()
    time.sleep(0.4)
    return stop


def _hold(c: socket.socket, stop: threading.Event) -> None:
    c.settimeout(1.0)
    while not stop.is_set():
        try:
            if not c.recv(65536):
                break
        except socket.timeout:
            continue
        except OSError:
            break
    c.close()


def phone_listening(serial: str, hexport: str) -> bool:
    _, out = adb(serial, "shell", "cat /proc/net/tcp6 /proc/net/tcp 2>/dev/null")
    return f":{hexport}" in out.upper()


def http_post(port: int, path: str, body: dict, token: str,
              timeout: float = 10.0) -> tuple[int, str]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=data, method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "newToken": token,
            "version": APP_VERSION,
            "X-ES-HTTP-VERSION": "1",
            "User-Agent": UA,
        })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return 0, f"{type(e).__name__}: {e}"


# --- the connect sequence -----------------------------------------------------
def connect(serial: str, hostname: str, dry_run: bool = False) -> None:
    openid, acct = load_account()
    token = secrets.token_hex(32)                 # <-- our OWN minted token
    conn_id = f"{secrets.token_hex(2)}_{now_ms()}"
    print(f"[connect] device={serial}  openId={openid}  token={token[:12]}…(minted)")
    print(f"[connect] connectionId={conn_id}  pc_name={hostname}")
    if dry_run:
        print("[connect] --dry-run: not touching the device.")
        return

    # 1) app present?
    rc, out = adb(serial, "shell", "pm", "path", PKG)
    if "package:" not in out:
        raise SystemExit(f"[connect] {PKG} not found on phone (Office Kit agent "
                         f"missing?): {out}")

    # 2) PC-side reverse listeners FIRST (required — :10380 won't bind without
    #    them), then wire the adb reverse tunnels to them.
    stop = start_reverse_listeners(REVERSE_PORTS)
    for p in REVERSE_PORTS:
        adb(serial, "reverse", f"tcp:{p}", f"tcp:{p}")

    # 3) launch the PCSUITE activity, then the AdbPortalService with our token.
    adb(serial, "shell", "am", "start", "--ei", "intent_from", "1104",
        "-a", PCSUITE_INTENT, "-f", "268435456")
    adb(serial, "shell", "am", "startservice",
        "--es", "from", "pc",
        "--ei", "foreground", "0",
        "--es", "pc_name", hostname,
        "--es", "token", token,
        "--es", "user_name", acct or "pc",
        "--es", "connectionId", conn_id,
        "--ei", "isTransferConnect", "0",
        "-n", SERVICE, "--user", "0")

    # 4) wait for the phone to bind :10380 (0x288C), then forward it.
    for _ in range(10):
        time.sleep(1)
        if phone_listening(serial, "288C"):
            print("[connect] phone :10380 is up.")
            break
    else:
        stop.set()
        raise SystemExit("[connect] phone never bound :10380 — reverse channels "
                         "may be unhealthy or the account doesn't match.")
    adb(serial, "forward", f"tcp:{PORT_HTTP}", f"tcp:{PORT_HTTP}")
    adb(serial, "forward", f"tcp:{PORT_TLS}", f"tcp:{PORT_TLS}")

    # 5) the handshake: /version then /base-info.
    print("\n[connect] POST /version …")
    st, body = http_post(PORT_HTTP, "/version", {
        "version": APP_VERSION,
        "connBaseVersionCode": CONN_BASE_VERSION_CODE,
        "pcSuiteVersionCode": PCSUITE_VERSION_CODE,
        "timestamp": now_ms(),
        "connectionId": conn_id,
    }, token)
    print(f"   → HTTP {st}: {body[:300]}")

    print("\n[connect] POST /base-info …")
    st2, body2 = http_post(PORT_HTTP, "/base-info", {
        "pc_name": hostname,
        "pcDeviceId": pc_device_id(),
        "isLogin": True,
        "openid": openid,
        "pcLoginAccount": acct or "",
        "isAutoConnect": False,
        "pcSystemType": "1",
        "isSupVdfs": True,
        "token": token,
        "isPcOsSupportExtScreen": True,
        "pcBleId": pc_ble_id(),
    }, token)
    print(f"   → HTTP {st2}: {body2[:600]}")

    # 6) verdict
    ok = False
    try:
        ok = json.loads(body2).get("code") == "0000"
    except Exception:  # noqa: BLE001
        pass
    print("\n" + "=" * 70)
    if ok:
        print("[connect] ✅ PROVEN: phone accepted our self-minted token — "
              "cloud-free USB connect works (local trust).")
        (AUTH_DIR / "connect-proof.json").write_text(json.dumps(
            {"connectionId": conn_id, "version_status": st,
             "base_info_status": st2, "base_info": body2[:4000]}, indent=2))
        print(f"[connect] saved captures/auth/connect-proof.json")
    else:
        print(f"[connect] ⚠ /base-info did not return code 0000 (HTTP {st2}). "
              "Known blocker: the reverse channels (8904/5679) need a real "
              "handshake, not a bare accept — decode them from the usbmon capture.")

    # cleanup: stop listeners, drop the adb tunnels we created.
    stop.set()
    adb(serial, "forward", "--remove-all")
    adb(serial, "reverse", "--remove-all")


def main() -> None:
    ap = argparse.ArgumentParser(description="P3: cloud-free USB /base-info PoC")
    ap.add_argument("--serial", help="adb serial (if multiple devices)")
    ap.add_argument("--pc-name", default="vivo-linkkit", help="pc_name to present")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would run without touching the device")
    args = ap.parse_args()
    serial = pick_device(args.serial) if not args.dry_run else (args.serial or "?")
    connect(serial, args.pc_name, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
