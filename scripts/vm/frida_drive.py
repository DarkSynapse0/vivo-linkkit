#!/usr/bin/env python3
"""Attach the SSL_write hook to every Office Kit / relay process in the VM via a
remote frida-server, and print any file-upload requests it dumps (plaintext,
pre-TLS). Recovers the drop_file_to_phone body framing SSLKEYLOGFILE couldn't.

    PYTHONPATH=src .venv/bin/python scripts/vm/frida_drive.py 192.168.122.50:27042
then send ONE small file in Office Kit and watch the request print here.
"""
import sys
import time
import frida

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.122.50:27042"
WINDOW = int(sys.argv[2]) if len(sys.argv) > 2 else 120
TARGET_NAMES = {"pcsuite.exe", "vivorelay.exe", "vivo Office Kit.exe"}
HOOK = open("scripts/vm/frida_upload_hook.js", "r", encoding="utf-8").read()

dev = frida.get_device_manager().add_remote_device(HOST)
print(f"[drive] connected to frida-server @ {HOST}")

procs = [p for p in dev.enumerate_processes() if p.name in TARGET_NAMES]
print(f"[drive] targets: " + ", ".join(f"{p.name}({p.pid})" for p in procs))

sessions = []


def on_message(pid, name):
    def handler(msg, data):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("kind") == "upload":
                print("\n" + "=" * 78)
                print(f"[{name} {pid}] {p['fn']} [{p['mod']}] len={p['len']}")
                print("-" * 78)
                print(p["data"])
                print("=" * 78 + "\n", flush=True)
            elif p.get("kind") == "diag":
                print(f"[diag {name} {pid}] {p['fn']} len={p['len']}: {p['data']!r}", flush=True)
        elif msg.get("type") == "error":
            print(f"[{name} {pid}] script error: {msg.get('stack', msg)}", flush=True)
    return handler


for p in procs:
    try:
        s = dev.attach(p.pid)
        sc = s.create_script(HOOK)
        sc.on("message", on_message(p.pid, p.name))
        sc.load()
        sessions.append(s)
        print(f"[drive] hooked {p.name}({p.pid})")
    except Exception as e:  # noqa: BLE001
        print(f"[drive] could not hook {p.name}({p.pid}): {e}")

print(f"\n[drive] >>> NOW send ONE small file to the phone in Office Kit ({WINDOW}s window) <<<\n",
      flush=True)
end = time.time() + WINDOW
try:
    while time.time() < end:
        time.sleep(0.5)
except KeyboardInterrupt:
    pass
print("[drive] window closed.", flush=True)
