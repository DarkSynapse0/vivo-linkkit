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

🟢 **Phase 1 complete — protocol mapped.** The pivotal question is **answered**
(triple-confirmed by the phone APK, the PC client JS, and the phone's own UI):
pairing is **vivo-account based** — the PC and phone sign into the *same* account
and the cloud links them into "Connection center"; a per-session connect then runs
over the LAN (**QR / verify-code / handshake**). So the tool is **distributable**
by driving the user's *own* login — no embedded secrets, no bypass.

The official Windows client is **Electron**, so the protocol was read from
plaintext JS on Linux — **no VM, no Frida**. What's understood end-to-end:

- **Transport:** `wss://<host>:<port>` (TLS) carrying JSON (`MESSAGE_EVENT_TYPE` /
  `CONNECT_ROUTER`).
- **Session crypto:** **AES-256-CBC** — the PC generates the key+iv and sends them
  to the phone (nothing to derive).
- **Mirroring:** H.264/H.265 via bundled FFmpeg.
- **Discovery:** QR (cloud-mediated) + USB + Wi-Fi-Direct/LAN.

**Next (Phase 2):** drive the vivo account login to obtain the session token, then
a minimal Python client (discover → connect → first frame). Remaining unknowns are
byte-level (exact verify-code check, wire framing). Full detail in
[`protocol/PROTOCOL.md`](protocol/PROTOCOL.md). No client code yet.

## Quick start

```sh
scripts/bootstrap.sh          # install host deps, create the venv
recon/01_inventory.sh         # device identity + candidate packages + open ports
recon/02_decompile.sh <pkg>   # pull & decompile the phone agent, grep for signals
recon/03_capture.sh           # usbmon / network / port-sweep captures
```

Then start filling in `protocol/PROTOCOL.md`.

## Roadmap

| Phase | Goal | Est. |
|------|------|------|
| **P0** Recon & setup | Real data on the wire, not guesses | days |
| **P1** Protocol map | Answer the pairing question; fill `PROTOCOL.md` | 1–2 wks |
| **P2** Exploration client | Pair + write one decodable H.264 frame to disk | 2–4 wks |
| **P3** Real client | Smooth mirroring + input control (Rust/Go) | 1–2 mo |
| **P4** Services | File transfer, clipboard, notifications | ongoing |
| **P5** Packaging | PKGBUILD → AUR; broaden device support | ongoing |

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
