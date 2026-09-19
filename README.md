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

**Phase 3 in progress:** a cloud-free USB connect PoC
([`src/vivolinkkit/connect_usb.py`](src/vivolinkkit/connect_usb.py)) drives adb
from Linux with a **self-minted** token. Verified: `AdbPortalService` starts with
**no on-screen confirmation** (USB-access trust), and the phone binds its
`:10380` server once the PC hosts the reverse channels (`5679`/`8904`). Remaining
blocker: `:10380` closes `/base-info` without a response until those reverse
channels speak their real handshake — next is decoding them from the usbmon
capture, then reading the `:10381` TLS. Full detail in
[`protocol/PROTOCOL.md`](protocol/PROTOCOL.md).

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
| **P2** Exploration client | Account login + token verified (200); pipe decoded | 🟡 in progress |
| **P3** Real client | Smooth mirroring + input control (Rust/Go) | ⬜ next |
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
