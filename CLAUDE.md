# CLAUDE.md — vivo-linkkit

Guidance for Claude Code (and humans) working in this repository.

## What this project is

An independent, **clean-room interoperability** client for **vivo Office Kit** on
Linux (target: Arch Linux). We observe the protocol between the phone and the
official desktop client, write it down, and reimplement a client that speaks it.
We do **not** port, modify, or redistribute any vivo software.

Lineage: same approach as `scrcpy` and `libimobiledevice`.

## The one question that decides everything

**How is pairing authenticated?** This gates whether the tool is distributable at
all. Answer it in Phase 1 before investing further.

| Auth model | Meaning | Verdict |
|---|---|---|
| **Local trust** | ECDH + on-screen confirm, pinned keys (KDE Connect / lockdownd style) | Very feasible, fully distributable |
| **User-account login** | Each user signs into their own vivo account | Feasible — drive the user's login |
| **Vendor credential** | Desktop client holds a vivo-signed cert/token | Only viable if login is account-based; otherwise not distributable |

## Non-negotiable rules (clean-room + legal)

1. **Never commit** vivo binaries, APKs, DLLs, or extracted keys/certs. They live
   in the gitignored `captures/`.
2. **Clean-room discipline**: implement from `protocol/PROTOCOL.md`, *not* by
   transliterating decompiled code. Decompiled code informs the spec; the spec
   informs the source.
3. **Never ship vendor secrets.** If pairing needs a vivo credential, drive the
   user's own account login instead of embedding one.
4. Keep the interoperability statement in `README.md` intact.

## Two ways in (use both, in this order)

1. **Phone side, first** — `jadx` on the Office Kit Android agent surfaces ports,
   JSON/protobuf field names, discovery format, crypto suite, often the whole
   state machine. ~10× the signal of x86 disassembly.
2. **Windows client, second** — first check: `strings` + DLL imports. If Electron
   → unpack `app.asar` for readable JS; if Qt/QML → extractable QML resources.
   Only fall back to a Windows VM + Frida if the client is native/compiled.
   **In this project the client is Electron** (`pcsuite` v6.8.2), so the protocol
   was read from plaintext JS on Linux — no VM, no Frida needed. See
   `protocol/PROTOCOL.md` §0b.

**Do USB before Wi-Fi** — the wireless path likely stacks BLE + Wi-Fi Direct on
top of the core protocol. USB is a clean single pipe; solve it first.

## Layout

```
scripts/bootstrap.sh      install host deps, create the venv
recon/01_inventory.sh     device identity + candidate packages + open ports
recon/02_decompile.sh     pull & decompile phone agent, auto-grep protocol signals
recon/03_capture.sh       usbmon / network / port-sweep captures
protocol/PROTOCOL.md      the living spec — the heart of the project
src/vivolinkkit/          Python exploration client (P2), later ported (P3)
captures/                 gitignored — raw dumps, decompiled output, secrets
```

## Phase discipline

- **P0** recon → **P1** protocol map (answer pairing!) → **P2** one decodable
  H.264 frame → **P3** real client → **P4** services → **P5** packaging.
- Prototype in **Python** on purpose — the parser gets rewritten many times.
- **Publish `PROTOCOL.md` early (even 30%)** — it recruits collaborators.
- **Scope to one device family first** (your exact model + OriginOS version, USB).

## Environment notes

- Host: Arch Linux. Instrumentation guest: Windows 11 under QEMU/KVM, USB
  passthrough, **bridged** networking (not NAT — discovery needs same L2 segment).
- Tools: `jadx` (phone agent — installed portably at `~/.local/share/jadx`),
  `7z` (unpack the Electron installer), Wireshark/`tshark` (live capture),
  `mitmproxy` (to drive/observe the vivo account login). Frida/VM only if a
  future native client needs it.
