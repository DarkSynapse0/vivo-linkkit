# vivo-linkkit

Clean-room interoperability client for vivo Office Kit / PC Suite on Linux —
reverse-engineering the phone↔PC protocol (pairing, file transfer, mirroring) and
reimplementing it, scrcpy-style. No vendor binaries.

<!-- GitHub "About" → use the line above. Topics: reverse-engineering,
     interoperability, vivo, linux, scrcpy, screen-mirroring, clean-room,
     android, originos -->

> We do **not** port or modify vivo's software. We observe how the phone and the
> official desktop client talk to each other, document that protocol, and
> reimplement a client that speaks it — the same approach that produced
> [scrcpy](https://github.com/Genymobile/scrcpy) and
> [libimobiledevice](https://libimobiledevice.org/).

## Status: a working, cloud-free file client + screen mirror

From Linux, over a USB cable, `vivolinkkit` connects to the phone and **lists,
downloads, and previews files** — clean-room, no vivo cloud call, no vendor
secret, no on-screen confirmation — and **mirrors the phone screen** to the PC:

```console
$ vivolinkkit connect --list images,videos --grab images:2 --thumbs images:5
[connect] ✅ phone accepted our self-minted token — cloud-free USB connect works
[files:images]  200 files: Screenshot_2026_0918_230722.png, IMG_20260918_201539.jpg, …
[files:videos]   64 files: video_20260911_164804.mp4 (169 MB), …
[grab:images]   downloading 2 files → captures/downloads/   (byte-exact PNG/JPEG ✓)
[thumbs:images] 5 × 144×144 preview PNGs → captures/downloads/thumbs/

$ vivolinkkit mirror                    # live phone screen on Linux, consent-free
[mirror] 10BG1E183Q000Z9 → live window (scrcpy, no MediaProjection consent)
```

**The pivotal question — how is pairing authenticated? — is answered:** it's
**local trust over a user account**. The PC mints its own random session token
(`crypto.randomBytes(32)`) and hands it to the phone; the phone accepts it because
the account `openid` proves the two are the *same vivo account*. No embedded
credential, no cloud token issuance. So a fully **distributable, secret-free,
cloud-free** client is possible.

### Scope, stated honestly

`vivo-linkkit` is a **file extractor + screen mirror**, not a full Office Kit
replacement. It talks *directly* to the phone's token-authenticated file API and
pulls **genuine files** (byte-exact, openable, carrying the phone's own EXIF —
verified on real hardware). But on the phone's Office Kit "connect" screen, only
the heartbeat **link** shows ✓; file transfer, clipboard, and notifications show ✗,
because we don't establish those full feature *sessions*. So: the data you pull is
real, and the phone marks those features as not-connected — both are true.
**Mirror** works too, but deliberately *outside* Office Kit — via the consent-free
`app_process` capture path (scrcpy's mechanism), because vivo's own Cast SDK
mirror is OS-consent-gated for any non-platform-signed client (see
[`PROTOCOL.md`](protocol/PROTOCOL.md) §6). The remaining heavy features are the
[native tier](#two-tiers--whats-done-whats-native).

## How it works

The protocol was first read from the official Electron client's plaintext JS,
then **live-verified** in a Windows 11 instrumentation VM (QEMU/KVM) with
mitmproxy (account/cloud traffic), usbmon (the USB pipe), and `SSLKEYLOGFILE` TLS
decryption. Live capture corrected several decompile-era guesses. What's
evidence-verified and reimplemented:

1. **Account login** (`src/vivolinkkit/login.py`) — drive the user's *own* vivo
   passport login; the post-login `getHtml` page carries the token inline
   (positional `&`-fields). Authenticated account-gateway calls send `openId` +
   `token` headers (no exchange, no signature) → `getUserInfo` 200.
2. **USB transport = ADB.** The PC injects its self-minted token into the phone
   via `adb … am startservice … com.vivo.pcsuite/.service.AdbPortalService --es
   token`, sets up `adb forward 10380/10381` + `adb reverse 5679/8904`, and the
   phone binds its local HTTP server (only while the PC holds the reverse
   channels open).
3. **Connect handshake.** `POST /base-info` on `:10380` with the account `openid`
   + our token → `{"code":"0000", …device info…}`. No pairing, no confirm dialog
   (a *random* `pcDeviceId` works — device identity isn't checked).
4. **Control plane.** A plaintext WebSocket `ws://<phone>:10380/ws/heart-beat`
   (auth is the WS subprotocol `v1.hc.vivo.com.cn, <token>`) streams events
   (`UPDATE_DEVICE_INFO`, `RE_CONNECT_ALBUM`, heartbeats) — `vivolinkkit connect --watch`.
5. **File services** over TLS on `:10380` (the port sniffs the first byte:
   `0x16`→TLS, else plaintext): `POST /pc_file_manager/channel` (list, body `type`
   = `REQUEST_POSTS_IMAGELIST|VIDEOLIST|…`), `GET /download/down_files?path=…`
   (download), `GET /pc_file_manager/thumb?fileUri=…` (thumbnails).

**Port map:** `10380` control HTTP + TLS + ws · `10381` screen mirror (video, TLS)
· `5679`/`8904` reverse channels (VDFS file transfer + relay). Full spec:
[`protocol/PROTOCOL.md`](protocol/PROTOCOL.md).

## Two tiers — what's done, what's native

The protocol splits cleanly. Everything that was **readable JSON/HTTP** in the JS
bundle is reimplemented and working; the rest lives in **compiled native
binaries** and is a separate reverse-engineering effort (needs Frida / protobuf
reversing, not JS-grepping).

| Feature | Tier | Status |
|---|---|---|
| Account auth · cloud-free USB connect | JSON/HTTP | ✅ working |
| Control websocket | JSON/WS | ✅ working (`--watch`) |
| File **list · download · thumbnails** | JSON/HTTP | ✅ working |
| **Screen mirror + control** (phone→PC) | `app_process` capture (scrcpy path) — consent-free; control · audio · clipboard · file-drop | ✅ working (`mirror`, **interim**) |
| ↳ *via vivo's own Cast SDK* (the goal) | Cast ws `:10381/mirror/screen` — **protocol fully mapped** | 🔒 OS consent-gated; needs privileged grant (see below) |
| File **upload** (PC→phone) | VDFS (`5679`/`8904`) | ⬜ native tier |
| **Clipboard · notifications** | native `vivoSyncService` (MQTT + protobuf) | ⬜ native tier |

## Quick start

Requirements: Linux, `adb`, and a vivo phone with **USB debugging** enabled.

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e '.[login]'      # core client + playwright (for login)
playwright install chromium    # one-time, for the login browser
```

**1 — log into your own vivo account** (one-time; opens a real browser, drives
*your* login, and stores only the resulting token locally under `captures/`):

```sh
vivolinkkit login --region in           # in | asia | cn | eu | ru
```

**2 — plug the phone in (authorize the USB-debugging prompt) and use it:**

```sh
vivolinkkit connect \
    --list images,videos,docs \   # browse the phone
    --grab images:3,videos:1 \    # download → captures/downloads/
    --thumbs images:5 \           # 144×144 preview PNGs
    --watch 10                    # stream live control-plane events
```

File kinds: `images videos audio docs files home`. `--list` returns the whole
category and writes a full manifest (`size · path · name`) to
`captures/downloads/<kind>.list.txt`; add `--limit N` to trim the on-screen
preview. Downloads and thumbnails also land in `captures/downloads/` (gitignored).
Run `vivolinkkit connect --help` for all options.

**3 — mirror *and control* the phone from the PC** (live, over USB — or wireless ADB):

```sh
vivolinkkit mirror                     # live window: control + audio + clipboard sync
vivolinkkit mirror --view-only         # watch only, no keyboard/mouse control
vivolinkkit mirror --stay-awake --screen-off   # keep phone awake, its own screen off
vivolinkkit mirror --record phone.mp4  # record (also viewable unless --headless)
vivolinkkit mirror --no-audio --bit-rate 4M --max-fps 30   # tune the stream
```

By default you get keyboard/mouse **control**, **audio** forwarding (Android 11+),
and two-way **clipboard sync**; drag a file onto the window to push it to the phone,
or drop an `.apk` to install it. `--push-target DIR` sets where dropped files land.
Run `vivolinkkit mirror --help` for the full flag set.

This is an **interim engine**, consent-free: it streams via the `app_process`
display-capture path (the same mechanism as
[scrcpy](https://github.com/Genymobile/scrcpy), which it drives). The **goal** is
mirror through vivo's *own* Cast SDK — that protocol is fully reverse-engineered,
but its screen-capture consent is gated by Android's MediaProjection model for any
non-platform-signed client (both PC triggers dead-end at the same background
consent, which self-cancels in ~29 ms; see [`PROTOCOL.md`](protocol/PROTOCOL.md)
§6). Making vivo-native mirror usable needs an on-device privileged grant (root, or
a Shizuku shell-UID helper) — until then, `mirror` uses the `app_process` path.
Requires `scrcpy` (`sudo pacman -S scrcpy`).

### Instrumentation (for extending the protocol)

The Windows 11 VM + capture tooling used to observe the official client:

```sh
sudo bash scripts/vm/00_host_prereqs.sh    # libvirt + NAT (once; then re-login)
bash scripts/vm/10_create_vm.sh            # Win11 guest (UEFI+TPM, USB passthrough)
sudo bash scripts/vm/31_capture_usb.sh     # capture the phone↔PC USB (ADB) pipe
python  scripts/vm/decrypt_usb_tls.py      # reassemble + decrypt the tunnelled TLS
```

See [`scripts/vm/README.md`](scripts/vm/README.md) for the mitmproxy + usbmon +
`SSLKEYLOGFILE` capture workflow.

## Layout

```
src/vivolinkkit/cli.py           the `vivolinkkit` command (login | connect | mirror)
src/vivolinkkit/login.py         drive the user's vivo login → account token
src/vivolinkkit/connect_usb.py   cloud-free USB connect + file list/download/thumbs
src/vivolinkkit/mirror.py        phone→PC screen mirror (consent-free app_process path)
protocol/PROTOCOL.md             the living spec (the heart of the project)
scripts/vm/                      Win11 instrumentation VM + capture/decrypt tooling
recon/                           device inventory, APK decompile, capture helpers
captures/                        gitignored — raw dumps, decompiled output, secrets
```

## Roadmap

| Phase | Goal | Status |
|------|------|------|
| **P0** Recon & setup | Real data on the wire, not guesses | ✅ done |
| **P1** Protocol map | Answer the pairing question; fill `PROTOCOL.md` | ✅ done |
| **P2** Auth & connect | Account login + cloud-free USB connect (`code 0000`) | ✅ done |
| **P3** File client | List + download + thumbnails, working & clean-room | ✅ done |
| **P4** Native tier | Screen mirror ✅ (`app_process` path); next: upload (VDFS), clipboard/notifications | 🟡 started |
| **P5** Packaging | `vivolinkkit` CLI ✓; next: PKGBUILD → AUR, more devices | 🟡 started |

See the full [roadmap PDF](vivo-linkkit-ROADMAP.pdf) for detail.

## Contributing

The protocol map in [`protocol/PROTOCOL.md`](protocol/PROTOCOL.md) is the heart of
the project — published early on purpose, to recruit collaborators. **Screen
mirroring** (phone→PC) is the vivo Cast SDK (`com.vivo.castsdk`, decompiled from
the phone): a WebSocket `:10381/mirror/screen` streaming H.264, fully mapped in
§6. Every layer is reverse-engineered and coded
([`scripts/vm/mirror_prototype.py`](scripts/vm/mirror_prototype.py)) and verified
live on hardware — connect, the `/version` gate, the `CONTINUE_OPEN_SCREEN:`
trigger, `MediaProjectionActivity`, *and* the system consent activity all fire.
The one wall is **the OS itself**: Android's `MediaProjection` consent self-cancels
in ~29 ms because a PC-initiated (background) trigger isn't a genuine on-device
foreground gesture — the vendor client only clears it as a **signed platform app**.
So mirror is *protocol-complete but consent-gated*, and streaming it needs either
the vendor signature or a foreground-consent path we can't drive from the PC (open
problem — ideas welcome). Please keep the [clean-room
discipline](#interoperability-statement) — implement from the spec, never from
transliterated decompiled code.

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
- **No shipped vendor secrets.** Pairing uses the user's own account login and a
  session token the client generates itself — never an embedded vivo credential.

*This is not legal advice.*

## License

[Apache-2.0](LICENSE). This covers only this project's own source; it does **not**
grant any rights to vivo's software, which is neither included nor redistributed.
