# vivo Office Kit — protocol notes

> **Living document.** Publish it early (even 30% complete) — it recruits
> collaborators. Everything here is derived by clean-room observation; fill each
> section with *observed facts*, and mark guesses as `TODO`/`?`.

**Status:** 🔴 empty — Phase 1 not started.
**Scope (first target):** one device family — record your exact model + OriginOS
version + transport below.

| Field | Value |
|---|---|
| Phone model | `TODO` |
| OriginOS / FuntouchOS version | `TODO` |
| Office Kit app package | `TODO` |
| Office Kit app version | `TODO` |
| Desktop client version | `TODO` |
| Transport reversed here | USB / Wi-Fi / BLE — `TODO` |

---

## 0. The one question — pairing authentication

**Which model is it?** (decides distributability — answer this first)

- [ ] **Local trust** — ECDH + on-screen confirmation, pinned key both sides.
- [ ] **User-account login** — each user signs into their own vivo account.
- [ ] **Vendor credential** — desktop client holds a vivo-signed cert/token.

**Evidence:**

```
TODO — decompiled method names, captured handshake bytes, key exchange, etc.
```

**Verdict / implications for the project:** `TODO`

---

## 1. Discovery

- Mechanism: mDNS / UDP broadcast / BLE advertisement — `TODO`
- Service type / broadcast port: `TODO`
- Advertisement payload format: `TODO`

## 2. Transport & ports

| Role | Port | Proto | Notes |
|---|---|---|---|
| `TODO` | | | |

## 3. Framing

- Magic bytes: `TODO`
- Header layout (offsets, field sizes): `TODO`
- Endianness: `TODO`
- Length field semantics: `TODO`
- Where does encryption begin (the encryption boundary)? `TODO`

```
# annotated hex of one frame goes here
```

## 4. Crypto

- Key exchange: `TODO` (e.g. X25519 ECDH)
- Cipher / mode: `TODO` (e.g. AES-256-GCM)
- Key derivation: `TODO` (e.g. HKDF-SHA256)
- Nonce / IV construction: `TODO`

## 5. Pairing handshake (message-by-message)

```
phone → client : TODO
client → phone : TODO
...
```

## 6. Session messages

- Control channel: `TODO`
- Video stream: codec `TODO` (expected H.264), packetization `TODO`
- Input events (touch/key/mouse): `TODO`
- Audio: `TODO`

## 7. Services (later — P4)

- File transfer: `TODO`
- Clipboard sync: `TODO`
- Notification mirroring: `TODO`

---

## Open questions

- `TODO`

## References (our own captures — never commit the raw files)

- `captures/decompiled/<pkg>/SIGNALS.txt`
- `captures/traffic/*.pcapng`
