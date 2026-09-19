# vivo-linkkit

Clean-room interoperability client for vivo Office Kit / PC Suite on Linux —
reverse-engineering the phone↔PC protocol (pairing, mirroring, file transfer) and
reimplementing it, scrcpy-style. No vendor binaries.

<!-- GitHub "About" → use the line above. Topics: reverse-engineering,
     interoperability, vivo, linux, scrcpy, screen-mirroring, clean-room,
     android, originos -->

> We do **not** port or modify vivo's software. We observe how the phone and the
> official desktop client talk to each other, document that protocol, and
> reimplement a client that speaks it — the same approach that produced
> [scrcpy](https://github.com/Genymobile/scrcpy) and
> [libimobiledevice](https://libimobiledevice.org/).

## Status

🟢 **Phase 1 complete + Phase 2 account-auth working; into Phase 3 (device
protocol decoded).** The pivotal question is **answered**: pairing is
**vivo-account based** — no embedded secret — so the tool is **distributable** by
driving the user's *own* login.

The protocol was first read from the Electron client's plaintext JS, then
**live-verified** in a Windows 11 instrumentation VM (QEMU/KVM) with mitmproxy
(cloud/account traffic) and usbmon (the USB pipe) — **no Frida**. Live capture
also *corrected* several decompile-era guesses. What's now evidence-verified:

- **Account auth (P2 — working in our client):** passport web login → the
  `getHtml` hidden input carries the token inline (positional `&`-fields;
  field[1] = token). Authenticated gateway calls send **`openId` + `token`**
  headers (no exchange call, no signature). `getUserInfo` returns 200. See
  `src/vivolinkkit/login.py`.
- **Rendezvous:** cloud `scan/sid` → `getPhone` returns the phone's
  `ip`/`connectionId`/`bleId`.
- **USB transport = ADB:** the PC injects the connect token via
  `am startservice … com.vivo.pcsuite/.service.AdbPortalService --es token`, then
  `adb forward tcp:10380/10381` + `adb reverse tcp:5679/8904`.
- **Device control:** plaintext **HTTP** to the phone's **`PcSuite-HTTP`** server
  on `:10380`, authed with the **`newToken`** header (`POST /version` →
  `{"code":"0000",…}`).
- **Media:** **TLS 1.2** on `:10381` (self-signed `CN=vivo` cert); H.264/H.265
  video rides inside it.
- **Trust model:** the connect **token is PC-minted** (`crypto.randomBytes(32)`,
  one per connection, never seen cloud-side) — **KDE-Connect-style local trust**,
  not a cloud credential. The phone trusts it because the account `openid` proves
  *same-account*. ⇒ a **cloud-free USB connect is feasible**.

**Phase 3 — cloud-free USB connect PROVEN.** A clean-room client
([`src/vivolinkkit/connect_usb.py`](src/vivolinkkit/connect_usb.py)) drives adb
from Linux with a **self-minted** token and the phone accepts it —
`POST /base-info` → `{"code":"0000", …device info…}`. **No vivo cloud call, no
on-screen confirmation, no pairing** (a random `pcDeviceId` works; the trust is
purely the same-account `openid` + our PC-minted token). The one non-obvious
requirement: the PC must hold reverse listeners on `5679`/`8904` open, then
`adb forward 10380` and `POST /base-info` first. This confirms the whole thesis:
a distributable, secret-free, cloud-free client is possible.

The **control plane is plaintext** and already readable with our token:
`connect_usb.py --watch` opens `ws://<phone>:10380/ws/heart-beat` (auth = the WS
subprotocol `v1.hc.vivo.com.cn, <token>`) and streams events —
`UPDATE_DEVICE_INFO:{…}`, `RE_CONNECT_ALBUM:{…}`, `{"state":"normal"}`. So file
listing, input, and notifications ride this clear channel; only the video/bulk
media needs the `:10381` TLS.

Port map: `10380` control HTTP **+ TLS** + ws, `10381` screen mirror (video, TLS),
`5679`/`8904` reverse channels (**VDFS** file transfer + relay). **File browsing
works end-to-end in our client** — `connect_usb.py --list images,videos,docs`
lists real files off the phone (name/size/path), cloud-free with a self-minted
token:

```
$ python -m vivolinkkit.connect_usb --list images,videos
[files:images] … 200 files: Screenshot_2026_0918_230722.png, IMG_20260918…jpg, …
[files:videos] …  64 files: video_20260911_164804.mp4 (169 MB), …
```

The fm API is `POST /pc_file_manager/channel` over TLS (`:10380` sniffs the first
byte: `0x16`→TLS); the body's `type` field (`REQUEST_POSTS_IMAGELIST`, etc.) was
the last missing piece. Decryption used `SSLKEYLOGFILE` + a usbmon capture +
`scripts/vm/decrypt_usb_tls.py` (reorders the ADB-tunnelled TLS records so tshark
decrypts both directions). **Next:** file transfer/download + screen mirror on
`:10381` (§5). Full detail in [`protocol/PROTOCOL.md`](protocol/PROTOCOL.md).

## Quick start

```sh
scripts/bootstrap.sh          # install host deps, create the venv
recon/01_inventory.sh         # device identity + candidate packages + open ports
recon/02_decompile.sh <pkg>   # pull & decompile the phone agent, grep for signals
recon/03_capture.sh           # usbmon / network / port-sweep captures

# Account login (P2) — drive your OWN vivo login, verify the gateway token:
PYTHONPATH=src .venv/bin/python -m vivolinkkit.login --region in

# Live instrumentation VM (to observe the official client & the USB pipe):
sudo bash scripts/vm/00_host_prereqs.sh    # libvirt + NAT (once; then re-login)
bash scripts/vm/10_create_vm.sh            # Win11 guest (UEFI+TPM, USB passthrough)
sudo bash scripts/vm/31_capture_usb.sh     # capture the phone<->PC USB (ADB) pipe
```

See [`scripts/vm/README.md`](scripts/vm/README.md) for the mitmproxy + USB
capture workflow, and keep filling in `protocol/PROTOCOL.md`.

## Roadmap

| Phase | Goal | Status |
|------|------|------|
| **P0** Recon & setup | Real data on the wire, not guesses | ✅ done |
| **P1** Protocol map | Answer the pairing question; fill `PROTOCOL.md` | ✅ done |
| **P2** Exploration client | Account login (200) + cloud-free USB connect proven (`code 0000`) | 🟢 core done |
| **P3** Real client | Read `:10381` TLS → mirroring + file transfer + input | 🟡 next |
| **P4** Services | File transfer, clipboard, notifications | ⬜ |
| **P5** Packaging | PKGBUILD → AUR; broaden device support | ⬜ |

See the full [roadmap PDF](vivo-linkkit-ROADMAP.pdf) for detail.

## Interoperability statement

This project exists **solely to enable interoperability** between an independently
created program and vivo's device software. Reverse engineering strictly to obtain
information necessary for interoperability of an independently created program is
expressly permitted in several jurisdictions — e.g. India's Copyright Act
§52(1)(ab), with analogous provisions elsewhere.

We keep it clean:

- **No redistributed vendor binaries, APKs, DLLs, or extracted keys/certs.** They
  live in the gitignored `captures/` directory and never enter version control.
- **Clean-room discipline.** We implement from the *documented protocol*, not by
  transliterating decompiled code. Decompiled code informs the spec; the spec
  informs the source.
- **No shipped vendor secrets.** If pairing requires a vivo credential, we drive
  the user's own account login instead of embedding one.

*This is not legal advice.*

## License

TBD (a permissive license such as Apache-2.0 or MIT is anticipated).
