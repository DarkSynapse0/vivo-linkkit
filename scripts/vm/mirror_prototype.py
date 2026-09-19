"""mirror_prototype.py — phone→PC screen mirror over USB (vivo Cast SDK).

Reverse-engineered from the phone's com.vivo.pcsuite APK (com.vivo.castsdk),
readable Java — NOT native/Frida. The phone→PC mirror is a WebSocket that streams
H.264/HEVC; the only real gate is Android's screen-capture consent dialog.

Full flow (see PROTOCOL.md §6):
  1. USB connect (adb reverse 5679/8904, am startservice AdbPortalService, wait
     for the phone to bind :10380, adb forward 10380).
  2. POST /version  — sets the phone-side PC version; the trigger's
     isSupportScreenCapture() needs PC version >= 3.4.9, else it silently refuses.
  3. POST /base-info.
  4. Over /ws/heart-beat send text "CONTINUE_OPEN_SCREEN:" -> the phone shows the
     "Start casting?" dialog (WebSocketController -> MediaProjectionActivity).
  5. USER taps Allow -> MediaProjectionActivity onActivityResult(RESULT_OK) ->
     CastSource.init(setPort(10381)) -> the cast server binds on :10381.
  6. adb forward 10381; ws :10381/mirror/screen (subprotocol
     "v1.hc.vivo.com.cn,<token>"); send "SCREEN_START:{SessionReq}"; read
     "DEVICE_INFO:" then H.264 BinaryWebSocketFrames -> captures/downloads/mirror.h264.

Then:  ffmpeg -i captures/downloads/mirror.h264 -frames:v 1 frame.png   (decode)

STATUS — protocol complete, consent-gated by the OS (verified on hardware
2026-09-19 via `adb logcat -b events`). Steps 1-4 all fire correctly: connect,
the /version gate (isSupportScreenCapture), CONTINUE_OPEN_SCREEN delivery, and
MediaProjectionActivity launch — and the *system* consent activity
(com.android.systemui .../MediaProjectionPermissionActivity) IS created. But it
self-cancels in ~29 ms (userLeaving=false, reproduced 3x) because a PC-initiated
(background) trigger never becomes the real foreground task, so Android's
MediaProjection foreground-gesture requirement refuses the prompt. The vendor app
gets past this only as a SIGNED PLATFORM APP. A clean-room PC client can't forge
the on-device gesture — this is the OS boundary, not a protocol gap. See
PROTOCOL.md §6. This script drives steps 1-6 for anyone who CAN satisfy the
consent (e.g. a platform-signed build or a future foreground-consent path).

Run:   PYTHONPATH=src .venv/bin/python scripts/vm/mirror_prototype.py [serial]
Requires: phone on USB (debugging authorized), captures/auth/token.json (login).
NOTE: if `phone :10380 up: False`, another process may hold the USB device (e.g.
virt-manager's USB redirect) — free it, or reboot the phone for a clean connect.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SERIAL = sys.argv[1] if len(sys.argv) > 1 else None
TOKEN = secrets.token_hex(32)
CONN = f"lk_{int(time.time() * 1000)}"
STOP = threading.Event()


def adb(*a: str) -> str:
    base = ["adb"] + (["-s", SERIAL] if SERIAL else [])
    return subprocess.run(base + list(a), capture_output=True, text=True).stdout


def _hold(c: socket.socket) -> None:
    c.settimeout(1.0)
    while not STOP.is_set():
        try:
            if not c.recv(65536):
                break
        except socket.timeout:
            continue
        except OSError:
            break


def _serve(port: int) -> None:
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port)); s.listen(8); s.settimeout(0.5)
    except OSError:
        return
    while not STOP.is_set():
        try:
            c, _ = s.accept(); threading.Thread(target=_hold, args=(c,), daemon=True).start()
        except socket.timeout:
            continue
        except OSError:
            break


def post(path: str, body: dict):
    r = urllib.request.Request(f"http://127.0.0.1:10380{path}", data=json.dumps(body).encode(),
                               method="POST", headers={"Content-Type": "application/json", "newToken": TOKEN})
    try:
        with urllib.request.urlopen(r, timeout=8) as x:
            return x.status
    except Exception as e:  # noqa: BLE001
        return str(e)[:50]


def phone_has(hexport: str) -> bool:
    return hexport in adb("shell", "cat /proc/net/tcp6 /proc/net/tcp 2>/dev/null").upper()


def connect() -> bool:
    for p in (5679, 8904):
        threading.Thread(target=_serve, args=(p,), daemon=True).start()
    time.sleep(0.4)
    for p in (5679, 8904):
        adb("reverse", f"tcp:{p}", f"tcp:{p}")
    adb("shell", "am", "start", "--ei", "intent_from", "1104",
        "-a", "vivo.intent.action.PCSUITE_INTENT", "-f", "268435456"); time.sleep(1.5)
    for _ in range(3):
        adb("shell", "am", "startservice", "--es", "from", "pc", "--ei", "foreground", "0",
            "--es", "pc_name", "vivo-linkkit", "--es", "token", TOKEN, "--es", "user_name", "pc",
            "--es", "connectionId", CONN, "--ei", "isTransferConnect", "0",
            "-n", "com.vivo.pcsuite/.service.AdbPortalService", "--user", "0")
        for _ in range(12):
            time.sleep(1)
            if phone_has(":288C"):
                adb("forward", "tcp:10380", "tcp:10380"); time.sleep(1)
                return True
    return False


SESSION_REQ = {"bit_rate": 8_000_000, "mime_type": "video/avc", "max_size": 1280,
               "video_width": 1260, "video_height": 2800, "device_type": 1, "mirror_type": 0,
               "no_audio": True, "split_frame": False, "show_touch_spot": False,
               "support_drag": False, "first_file_open": False, "need_open_file": False,
               "pc_version": "6.8.2", "msg_send_key_mode": "", "app_package_name": ""}


CAST_PORT = 10381          # CastSourceConfig.setPort(10381) in MediaProjectionActivity
CAST_HEX = ":2889"         # 10381 in /proc/net/tcp


async def _heartbeat(ws) -> None:
    """Keep the phone's IdleStateHandler(5s) from tearing the session down.

    channelRead0 treats any frame containing PCShareManager.NORMAL ("normal") as a
    heartbeat: it resets the idle counter and echoes it back. While the session
    stays 'connected', pcsuite keeps its foreground service, which is what grants
    MediaProjectionActivity the background-activity-launch privilege it needs for
    the system consent dialog to actually reach the foreground.
    """
    try:
        while True:
            await ws.send("normal")
            await asyncio.sleep(2)
    except Exception:  # noqa: BLE001
        pass


async def run() -> None:
    import websockets
    openid = json.loads((REPO / "captures/auth/token.json").read_text())["openId"]
    print("/version →", post("/version", {"version": "6.8.2", "connBaseVersionCode": 1155,
          "pcSuiteVersionCode": 65011, "timestamp": int(time.time() * 1000), "connectionId": CONN,
          "pcDeviceId": "lk-pc-001", "token": TOKEN, "isAutoConnect": False, "isOversea": True,
          "pcOsType": "win32", "pcOsVersion": "10.0.26200"}))
    print("/base-info →", post("/base-info", {"pc_name": "vivo-linkkit", "pcDeviceId": "lk-pc-001",
          "isLogin": True, "openid": openid, "token": TOKEN, "isPcOsSupportExtScreen": True,
          "pcSystemType": "1"}))
    hb = await websockets.connect("ws://127.0.0.1:10380/ws/heart-beat",
                                  subprotocols=["v1.hc.vivo.com.cn", TOKEN], origin="file://", open_timeout=8)
    # Let the session settle into a stable 'connected' state (foreground service up)
    # before asking for the screen. The consent dies with finish-imm:transit if it
    # launches DURING the connect animation ("Connecting" -> "Connection successful"),
    # so wait past that whole transition until the screen is quiescent.
    beat = asyncio.ensure_future(_heartbeat(hb))
    print("[hb] holding session alive 14s so the connect transition fully settles…")
    await asyncio.sleep(14)
    print(">>> sending CONTINUE_OPEN_SCREEN — TAP 'Start now' on the phone's dialog <<<")
    await hb.send("CONTINUE_OPEN_SCREEN:")
    loop = asyncio.get_event_loop(); port = None
    for i in range(60):
        await asyncio.sleep(1)
        if await loop.run_in_executor(None, phone_has, CAST_HEX):
            port = CAST_PORT; print(f"[cast] :{CAST_PORT} up after {i + 1}s"); break
    beat.cancel()
    if not port:
        print("[cast] no cast port — consent not granted / dialog never reached foreground"); return
    await loop.run_in_executor(None, lambda: subprocess.run(
        (["adb"] + (["-s", SERIAL] if SERIAL else []) + ["forward", f"tcp:{CAST_PORT}", f"tcp:{CAST_PORT}"]),
        capture_output=True)); await asyncio.sleep(1)
    async with websockets.connect(f"ws://127.0.0.1:{CAST_PORT}/mirror/screen",
                                  subprotocols=["v1.hc.vivo.com.cn", TOKEN], origin="file://",
                                  open_timeout=12, max_size=None) as ws:
        await ws.send("SCREEN_START:" + json.dumps(SESSION_REQ))
        out = (REPO / "captures/downloads/mirror.h264").open("wb"); n = 0; end = time.time() + 20
        while time.time() < end:
            try:
                m = await asyncio.wait_for(ws.recv(), timeout=6)
            except asyncio.TimeoutError:
                continue
            if isinstance(m, (bytes, bytearray)):
                out.write(m); n += 1
                if n <= 3 or n % 100 == 0:
                    print(f"[mirror] frame#{n} {len(m)}B head={bytes(m[:8]).hex()}")
            else:
                print("[mirror TEXT]", m[:120])
        out.close(); print(f"[mirror] {n} frames -> captures/downloads/mirror.h264")


def main() -> None:
    if not any(SERIAL or "" in l or "\tdevice" in l for l in adb("devices").splitlines()[1:]):
        raise SystemExit("no adb device")
    try:
        if not connect():
            raise SystemExit("phone :10380 didn't bind — reboot the phone / clean Office Kit "
                             "connect to reset, then retry")
        asyncio.run(run())
    finally:
        STOP.set(); adb("forward", "--remove-all"); adb("reverse", "--remove-all")


if __name__ == "__main__":
    main()
