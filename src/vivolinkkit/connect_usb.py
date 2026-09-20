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

STATUS (2026-09-19): WORKS end-to-end — /base-info returns {"code":"0000",...}
with a SELF-MINTED token and a RANDOM pcDeviceId. Proven: no pairing / device
registration is needed; the trust is same-account openid + our token (PC-minted).
The one non-obvious requirement is that the PC must HOLD the reverse channels
(5679/8904) open — the phone binds :10380 only while they exist. No on-screen
confirmation, no vivo cloud call from this client → cloud-free, distributable.

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
import asyncio
import http.client
import json
import secrets
import socket
import ssl
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
WS_PATH = "/ws/heart-beat"     # control-plane websocket (plaintext, on PORT_HTTP)
WS_SUBPROTO = "v1.hc.vivo.com.cn"  # 1st WS subprotocol; the token is the 2nd

# File manager: POST /pc_file_manager/channel over TLS on PORT_HTTP (the port
# sniffs the first byte: 0x16 -> TLS). Body needs the `type` constant below.
FM_CHANNEL = "/pc_file_manager/channel"
FM_DOWNLOAD = "/download/down_files"   # GET ?path=&srctype=<mime>&newToken=
FM_THUMB = "/pc_file_manager/thumb"    # GET ?fileUri=<savePath>&width=&height=
DL_DIR = REPO_ROOT / "captures" / "downloads"   # gitignored
FM_TYPES = {  # friendly name -> vivo REQUEST_POSTS_* constant (sortCondition, groupBy)
    "home":   ("REQUEST_POSTS_HOMEDATA", 0, 0),
    "images": ("REQUEST_POSTS_IMAGELIST", 9, 1),
    "videos": ("REQUEST_POSTS_VIDEOLIST", 5, 1),
    "audio":  ("REQUEST_POSTS_AUDIOLIST", 5, 0),
    "docs":   ("REQUEST_POSTS_WEB_DOCSLIST", 5, 5),  # WEB_DOCSLIST has the real docs;
    "files":  ("REQUEST_POSTS_FILELIST", 5, 0),      #   plain DOCSLIST is empty on-device.
}
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


# --- file manager (TLS on PORT_HTTP) ------------------------------------------
def tls_post(port: int, path: str, body: dict, token: str,
             timeout: float = 12.0) -> tuple[int, str]:
    """POST JSON over TLS to the phone (self-signed cert, ignored — the official
    client uses rejectUnauthorized:false)."""
    ctx = ssl._create_unverified_context()
    try:
        c = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout,
                                        context=ctx)
        c.request("POST", path, body=json.dumps(body).encode(),
                  headers={"Content-Type": "application/json", "newToken": token})
        r = c.getresponse()
        data = r.read().decode("utf-8", "replace")
        c.close()
        return r.status, data
    except Exception as e:  # noqa: BLE001
        return 0, f"{type(e).__name__}: {e}"


# --- file UPLOAD (PC→phone), PROTOCOL.md §7 -----------------------------------
# Two-step HTTP on the same TLS-:10380 server: announce a batch, then POST bytes.
FM_UPLOAD_INFO = "/transport/upload_files_info"   # POST DropUploadFilesInfo JSON
FM_UPLOAD = "/upload/upload_files"                # POST raw bytes ?id=&type=&index=


def tls_post_raw(port: int, path: str, data: bytes, token: str,
                 timeout: float = 120.0, chunked: bool = True) -> tuple[int, str]:
    """POST raw bytes over TLS (the streamed file body for /upload/upload_files).

    Default chunked so Netty delivers the body to WebHttpUploadHandler as HttpContent
    frames (it's a SimpleChannelInboundHandler<HttpContent>, streamed to a pipe)."""
    ctx = ssl._create_unverified_context()
    try:
        c = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout, context=ctx)
        if chunked:
            c.putrequest("POST", path, skip_host=False, skip_accept_encoding=True)
            c.putheader("Content-Type", "application/octet-stream")
            c.putheader("Transfer-Encoding", "chunked")
            c.putheader("newToken", token)
            c.endheaders()
            c.send(b"%X\r\n" % len(data) + data + b"\r\n0\r\n\r\n")
        else:
            c.request("POST", path, body=data,
                      headers={"Content-Type": "application/octet-stream",
                               "Content-Length": str(len(data)), "newToken": token})
        r = c.getresponse()
        resp = r.read().decode("utf-8", "replace")
        c.close()
        return r.status, resp
    except Exception as e:  # noqa: BLE001
        return 0, f"{type(e).__name__}: {e}"


def upload_file(token: str, local: Path, save_path: str = "", ftype: str = "0") -> bool:
    """Send one file PC→phone. Announce the batch, then stream the bytes."""
    import mimetypes
    local = Path(local)
    if not local.is_file():
        print(f"[send] not a file: {local}")
        return False
    data = local.read_bytes()
    fid = secrets.token_hex(8)
    mime = mimetypes.guess_type(local.name)[0] or "application/octet-stream"
    # Each item extends BaseFileData: the phone matches the byte stream to a file by
    # `fileName` (original) then writes it as `finalFileName` — both are required.
    info = {
        "id": fid,
        "dropFileItems": [{
            "fileName": local.name,
            "fileSize": len(data),
            "finalFileName": local.name,
            "mimeType": mime,
            "isDirectory": False,
        }],
        "savePath": save_path,          # "" → phone default (Downloads/vivo办公套件)
        "totalCount": 1,
        "totalSize": len(data),
        "type": ftype,
        "screen_w": 1260, "screen_h": 2800, "x": 600, "y": 1400,
    }
    st, resp = tls_post(PORT_HTTP, FM_UPLOAD_INFO, info, token)
    print(f"[send] {local.name} ({len(data):,} B) info → HTTP {st}: {resp[:200]}")
    # the phone assigns the real transformType (+ saveDir) in its info reply; echo
    # that type back on the byte POST (a wrong type → 500 on the server side).
    upl_type = ftype
    try:
        arr = json.loads(resp)
        if isinstance(arr, list) and arr and arr[0].get("transformType") is not None:
            upl_type = str(arr[0]["transformType"])
    except Exception:  # noqa: BLE001
        pass
    # the body is chunked (no Content-Length), so the server needs the size in the
    # query: the official client appends &contentLength=<fileSize> (offline-transfer-file.ts).
    q = urllib.parse.urlencode({"id": fid, "type": upl_type, "index": "0",
                                "contentLength": len(data)})
    st2, resp2 = tls_post_raw(PORT_HTTP, f"{FM_UPLOAD}?{q}", data, token)
    print(f"[send] {local.name} bytes → HTTP {st2}: {resp2[:200]}")
    return st2 == 200


import re as _re
_FILE_RE = _re.compile(
    r'"fileName":"([^"]+)","fileSize":(\d+),"isDirectory":false,'
    r'"isLivePhoto":[^,]+,"savePath":"([^"]+)"')


def fm_list(token: str, kind: str, page_number: int = 1_000_000
            ) -> tuple[int, list[tuple[str, int, str]]]:
    """Return (http_status, [(fileName, fileSize, savePath), …]) for a category.
    `page_number` defaults high so the whole category comes back (no cap)."""
    typ, sort, group = FM_TYPES[kind]
    body = {"category": "", "data": "", "fileCount": 0, "sortCondition": sort,
            "groupBy": group, "type": typ, "pageIndex": 0, "pageNumber": page_number,
            "firstFlag": False}
    st, data = tls_post(PORT_HTTP, FM_CHANNEL, body, token)
    files = [(m.group(1), int(m.group(2)), m.group(3)) for m in _FILE_RE.finditer(data)]
    return st, files


def list_files(token: str, kind: str, limit: int = 0) -> None:
    """List a whole category. `limit`=0 prints every entry; >0 prints a preview.
    A full manifest (size + path) is always written to captures/downloads/."""
    st, files = fm_list(token, kind)
    print(f"\n[files:{kind}] type={FM_TYPES[kind][0]} → HTTP {st}  ({len(files)} files)")
    shown = files if limit <= 0 else files[:limit]
    for n, s, _ in shown:
        print(f"     {s:>12,}  {n}")
    if limit > 0 and len(files) > limit:
        print(f"     … and {len(files) - limit} more (full list in the manifest)")
    if files:
        DL_DIR.mkdir(parents=True, exist_ok=True)
        manifest = DL_DIR / f"{kind}.list.txt"
        manifest.write_text("".join(f"{s}\t{p}\t{n}\n" for n, s, p in files))
        print(f"     → full manifest ({len(files)} files): {manifest}")


def tls_get(port: int, path: str, timeout: float = 30.0) -> tuple[int, bytes]:
    ctx = ssl._create_unverified_context()
    try:
        c = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout, context=ctx)
        c.request("GET", path)
        r = c.getresponse(); data = r.read(); c.close()
        return r.status, data
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()


def grab_thumbs(token: str, kind: str, count: int) -> None:
    """Fetch thumbnails for the first `count` files of a category (previews)."""
    import urllib.parse
    st, files = fm_list(token, kind)
    if st != 200 or not files:
        print(f"\n[thumbs:{kind}] list failed (HTTP {st})"); return
    out_dir = DL_DIR / "thumbs"; out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n[thumbs:{kind}] fetching {min(count, len(files))} thumbnails → {out_dir}")
    for name, _size, save_path in files[:count]:
        q = urllib.parse.urlencode({"fileUri": save_path, "width": 160, "height": 160})
        gst, data = tls_get(PORT_HTTP, f"{FM_THUMB}?{q}")
        if gst == 200 and data[:3] in (b'\xff\xd8\xff', b'\x89PN'):
            ext = "jpg" if data[:3] == b'\xff\xd8\xff' else "png"
            (out_dir / f"{name}.thumb.{ext}").write_bytes(data)
            print(f"   {len(data):>7,}  {name}.thumb.{ext}  ✓")
        else:
            print(f"   FAILED {name}  HTTP {gst} ({len(data)}B)")


def grab_files(token: str, kind: str, count: int) -> None:
    """List a category and download the first `count` files to captures/downloads/."""
    st, files = fm_list(token, kind)
    if st != 200 or not files:
        print(f"\n[grab:{kind}] list failed (HTTP {st})"); return
    DL_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\n[grab:{kind}] downloading {min(count, len(files))} of {len(files)} files → {DL_DIR}")
    import urllib.parse
    for name, size, save_path in files[:count]:
        q = urllib.parse.urlencode({"path": save_path, "srctype": "", "newToken": token})
        gst, data = tls_get(PORT_HTTP, f"{FM_DOWNLOAD}?{q}")
        if gst == 200 and data:
            out = DL_DIR / name
            out.write_bytes(data)
            ok = "✓" if len(data) == size else f"(got {len(data)}, expected {size})"
            print(f"   {len(data):>12,}  {name}  {ok}")
        else:
            print(f"   FAILED {name}  HTTP {gst}: {data[:80]!r}")


# --- control-plane websocket --------------------------------------------------
def watch_events(token: str, seconds: float) -> None:
    """Open the plaintext control websocket and stream events. Auth is the WS
    subprotocol: `Sec-WebSocket-Protocol: v1.hc.vivo.com.cn, <token>`."""
    try:
        import websockets
    except ImportError:
        print("[watch] `websockets` not installed — `pip install websockets`.")
        return

    async def run() -> None:
        url = f"ws://127.0.0.1:{PORT_HTTP}{WS_PATH}"
        try:
            async with websockets.connect(
                url, subprotocols=[WS_SUBPROTO, token], origin="file://",
                open_timeout=6,
            ) as ws:
                print(f"[watch] ✅ control ws open — streaming {int(seconds)}s of "
                      "events (Ctrl-C to stop):")
                end = time.time() + seconds
                while time.time() < end:
                    try:
                        m = await asyncio.wait_for(ws.recv(), timeout=4)
                    except asyncio.TimeoutError:
                        continue
                    if isinstance(m, (bytes, bytearray)):
                        m = m.decode("utf-8", "replace")
                    print(f"   [event] {m[:400]}")
        except Exception as e:  # noqa: BLE001
            print(f"[watch] ws error: {type(e).__name__}: {str(e)[:160]}")

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


# --- the connect sequence -----------------------------------------------------
def connect(serial: str, hostname: str, dry_run: bool = False,
            watch_seconds: float = 0.0, list_kinds: list[str] | None = None,
            grab: list[tuple[str, int]] | None = None,
            thumbs: list[tuple[str, int]] | None = None,
            list_limit: int = 0, send: list[str] | None = None) -> None:
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

    # 3) wake pcsuite first — if it isn't already running, `am startservice` is
    #    refused ("app is in background uid null"). Launching its intent brings the
    #    app up so the service start is allowed; harmless if it's already alive.
    adb(serial, "shell", "am", "start", "--ei", "intent_from", "1104",
        "-a", PCSUITE_INTENT, "-f", "268435456")
    time.sleep(1.5)
    # …then start the AdbPortalService with our token.
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
    time.sleep(1.0)   # let the reverse channels settle before the first request

    # 5) the handshake. /base-info is the one that matters — a 200
    #    {"code":"0000",...} means we're connected. Send it FIRST (a failed
    #    /version poisons the connection); retry a couple of times for the race.
    base_body = {
        "pc_name": hostname,
        "pcDeviceId": pc_device_id(),   # any value — device identity is NOT checked
        "isLogin": True,
        "openid": openid,               # same-account openid == the trust
        "pcLoginAccount": acct or "",
        "isAutoConnect": False,
        "pcSystemType": "1",
        "isSupVdfs": True,
        "token": token,                 # our self-minted token (== am startservice)
        "isPcOsSupportExtScreen": True,
        "pcBleId": pc_ble_id(),
        "deviceAvatarUri": "",
    }
    st2, body2 = 0, ""
    for attempt in range(3):
        print(f"\n[connect] POST /base-info (attempt {attempt + 1}) …")
        st2, body2 = http_post(PORT_HTTP, "/base-info", base_body, token)
        print(f"   → HTTP {st2}: {body2[:600]}")
        if st2 == 200:
            break
        time.sleep(1.0)

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
            {"connectionId": conn_id, "base_info_status": st2,
             "base_info": body2[:4000]}, indent=2))
        print(f"[connect] saved captures/auth/connect-proof.json")
        for kind in (list_kinds or []):
            list_files(token, kind, limit=list_limit)
        for kind, n in (grab or []):
            grab_files(token, kind, n)
        for kind, n in (thumbs or []):
            grab_thumbs(token, kind, n)
        for f in (send or []):
            upload_file(token, Path(f))
        if watch_seconds:
            watch_events(token, watch_seconds)
    else:
        print(f"[connect] ⚠ /base-info did not return code 0000 (HTTP {st2}). "
              "Known blocker: the reverse channels (8904/5679) need a real "
              "handshake, not a bare accept — decode them from the usbmon capture.")

    # cleanup: stop listeners, drop the adb tunnels we created.
    stop.set()
    adb(serial, "forward", "--remove-all")
    adb(serial, "reverse", "--remove-all")


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="vivolinkkit connect",
        description="Connect to a vivo phone over USB (cloud-free, self-minted "
                    "token) and browse / download / preview its files.")
    ap.add_argument("--serial", help="adb serial (if multiple devices)")
    ap.add_argument("--pc-name", default="vivo-linkkit", help="pc_name to present")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would run without touching the device")
    ap.add_argument("--watch", type=float, default=0.0, metavar="SECONDS",
                    help="after connecting, stream control-plane ws events for N s")
    ap.add_argument("--list", default="", metavar="KINDS",
                    help=f"comma-separated file lists to fetch: {','.join(FM_TYPES)}")
    ap.add_argument("--limit", type=int, default=0, metavar="N",
                    help="print only the first N of each list (0 = all; a full "
                         "manifest is always saved to captures/downloads/)")
    ap.add_argument("--grab", default="", metavar="KIND:N",
                    help="download the first N files of a KIND to captures/downloads/ "
                         "(e.g. images:2,videos:1)")
    ap.add_argument("--thumbs", default="", metavar="KIND:N",
                    help="fetch thumbnails for the first N files of a KIND")
    ap.add_argument("--send", action="append", default=[], metavar="FILE",
                    help="upload FILE from the PC to the phone (repeatable); lands in "
                         "the phone's Downloads/vivo办公套件")
    args = ap.parse_args()
    kinds = [k.strip() for k in args.list.split(",") if k.strip()]
    bad = [k for k in kinds if k not in FM_TYPES]
    if bad:
        raise SystemExit(f"[connect] unknown --list kinds {bad}; choose from {list(FM_TYPES)}")

    def _pairs(spec, flag):
        out = []
        for s in (x.strip() for x in spec.split(",") if x.strip()):
            kind, _, n = s.partition(":")
            if kind not in FM_TYPES:
                raise SystemExit(f"[connect] unknown --{flag} kind {kind!r}; choose from {list(FM_TYPES)}")
            out.append((kind, int(n or "1")))
        return out

    grab = _pairs(args.grab, "grab")
    thumbs = _pairs(args.thumbs, "thumbs")
    serial = pick_device(args.serial) if not args.dry_run else (args.serial or "?")
    connect(serial, args.pc_name, dry_run=args.dry_run, watch_seconds=args.watch,
            list_kinds=kinds, grab=grab, thumbs=thumbs, list_limit=args.limit,
            send=args.send)


if __name__ == "__main__":
    main()
