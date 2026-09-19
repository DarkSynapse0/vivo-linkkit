# vivo Office Kit — protocol notes

> **Living document.** Publish it early (even 30% complete) — it recruits
> collaborators. Everything here is derived by clean-room observation; fill each
> section with *observed facts*, and mark guesses as `TODO`/`?`.

**Status:** 🟢 Phase 1 largely done — **pairing question answered** (account login
+ QR/verify-code/handshake; distributable by driving the user's own login) and
**session crypto solved** (AES-256-CBC; PC generates key+iv and sends them, §4).
Remaining: byte-level QR/verify-code details, best confirmed with a live capture.
**Scope (first target):** one device family (below), reversed from the phone-side
agent first (jadx). Transport captures not yet taken.

| Field | Value |
|---|---|
| Phone model | **vivo V2561** (`ro.product.model=V2561`, `product:V2561i`) |
| OS | **OriginOS / vos 7.0**, Android **16** (SDK 36) |
| CPU ABI | arm64-v8a |
| Connection framework pkg | **`com.vivo.connbase.connectcenter`** (ConnectCenter, `/system/priv-app`) |
| Related pkgs | `com.vivo.smartoffice` (doc reader — *not* connectivity), `com.vivo.easyshare`, `com.vivo.share`, `com.vivo.connbase.sysui` |
| Desktop client version | `TODO` (Windows client not yet obtained) |
| Transport reversed here | none captured yet — phone-agent static analysis only |

### How this was obtained
- `recon/01_inventory.sh` → device identity + package list + idle ports.
- `recon/02_decompile.sh com.vivo.connbase.connectcenter` → jadx decompile
  (19 MB APK, ~4,435 java files). Reference lives in gitignored `captures/`.

---

## 0. The one question — pairing authentication

**Which model is it?** (decides distributability — answer this first)

- [ ] **Local trust** — ECDH + on-screen confirmation, pinned key both sides.
- [x] **User-account login** — each user signs into their own vivo account.
      *(leaning; management layer confirmed, wire layer unconfirmed)*
- [ ] **Vendor credential** — desktop client holds a vivo-signed cert/token.

**Status: 🟠 partially answered.** The *management/UI layer* requires a vivo
(BBK) account. The *wire-level pairing crypto* is in a native daemon we have not
yet extracted — so a local-trust handshake underneath the account gate is not
ruled out.

### Key architectural finding
`com.vivo.connbase.connectcenter` is a **thin AIDL/Binder client**, not the
engine. Calls like `bindDevice`, `getVivoAccountLoginState`, connect/disconnect
are Binder transactions delegated to a **remote system service** via
`CoWorkClient.checkManagerMethod(...)` → `iServiceManager` (the `v_dfs`/connbase
daemon). Evidence: `com/vivo/cowork/servicemanager/{IServiceManager,VdfsServiceManager}.java`.
**Consequence:** the real pairing handshake, transport sockets, and encryption
live in that native daemon. *(We didn't need to reverse it — the Electron PC
client, §0b, exposed the same protocol in readable JS. Kept here for context.)*

### Evidence FOR account-login being required (management layer)
- Device cache is **keyed by account openid**:
  `SharedPreferences.putString("key_device_cache", openid + "#" + deviceJson)`
  and `ConnectCenterApp` bails if `openid` is empty
  (`if (TextUtils.isEmpty(openid)) return;`). Bound devices are per-user.
- `getVivoAccountLoginState()` is a first-class Binder API
  (`IServiceManager.java`); BBK account framework (`com/bbk/account/base/`,
  `accountLogin`, `accountTrustVerify`) is integrated.
- `BindDevice` carries `userId` on every bound device.
- Bind state machine (`Constants.java`): `UNBOUND(3) → BINDING(2) → BOUND(1)`
  (failure `BIND_FAILURE(5)`; teardown `UNBINDING(4) → UNBOUND`). No numeric
  confirmation code seen at this layer — bind is backend/callback driven.

### Connection transport (from `CoworkConnInfo`)
- Connect types: **P2P** (`0x01000000`) → `CoworkP2PConnExtraInfo.mIP` (direct IP
  socket); **BR** (`0x04000000`) → `CoworkBRConnExtraInfo.mMac` (Bluetooth).
  So a session is a direct IP socket after a Bluetooth/discovery bootstrap.

### Corrected false lead ⚠️
An earlier scan flagged `AES/GCM/NoPadding` + `RSA` + an embedded
`assets/publicKey.txt` as a possible vendor credential. **That crypto is vivo's
VCode telemetry SDK** (`com/vivo/vcodeimpl/security/SecUtils.java`) — it encrypts
analytics uploads, and is **unrelated to device pairing**. Do not treat it as the
pairing key. The pairing crypto remains unseen (native daemon; `com.vivo.security`
"JVQ" SDK is not called from the connect/cowork code at all).

**Triple-confirmed by the phone's own UI.** The phone's "add my computer" screen
(vivo Office Kit → Connection center) states verbatim: *"Install vivo Office Kit
on your computer and **sign in to the same vivo account as that on your phone** to
automatically add the computer to Connection center."* Download URL shown:
**`pc.vivoglobal.com`**; the PC login offers **SMS verification code** or
**password** (or register). So device linking is **same-account association via
the cloud** — no local PIN/QR in the *add* step. Two phases:
1. **Register the PC** — sign into the same account → cloud links it (this screen).
2. **Connect a session** — QR/local + `wss` + AES-256-CBC (§1/§5).

**Verdict / implications for the project — ANSWERED ✅**
**User-account login is REQUIRED (Bucket 2), confirmed by THREE sources** (phone
APK openid-keyed cache, PC JS "not login → empty list", phone UI above), with a
**QR + verify-code + handshake** for the per-session connect on top:
- Phone side: device cache keyed by account `openid` (§ above).
- PC side (Electron JS, verified): if not logged in, the device list is force-
  emptied — `[...setPreConnectDevicesList] because not login, set empty list`;
  gated by `isLoginedVivoAccount()`. No login → no pairing.
- On top of the account gate, the actual device link uses **QR scan + a numeric
  verify code + a `/connect/handshake`** (see §5) — genuine local-trust elements.

**Distributability: FEASIBLE, and the tool stays clean-room/legal.** We **drive
the user's own vivo account login** (e.g. the real login/OAuth flow) — we do
**NOT** bypass, spoof, or embed any credential (that would break rule #3 in
CLAUDE.md and isn't necessary). The user authenticates as themselves; the tool
then performs the QR+verify-code+handshake like the official client.
**No dealbreaker.** The one remaining engineering unknown is how to drive the
vivo/BBK login headlessly enough to obtain the session (mitmproxy the login — P1
tail / P2).

---

## 0b. Windows client architecture (the "second way in" — paid off huge)

Obtained the official installer: **`pcsuite_setup_v6.8.2.0`** (447 MB NSIS).
Extracted on Linux — **no VM needed**. The client is **Electron** (`pcsuite`
v6.8.2), so the app logic is **readable JavaScript** in `resources/app.asar`
(`dist/electron/`, 397 JS files, main = `dist/electron/electron/main.js`).

The Electron UI orchestrates a fleet of **native helper processes**, talking to
them over **local WebSockets** (candidate ports seen as literals: 1800, 1080,
3600, 1882, 16384, 4096, 16832, 1024, 8192, 2880, 2080 — roles TBD):

| Helper | Tech | Role |
|---|---|---|
| `vivoExtScreen/VivoExtScreen.exe` | **FFmpeg** (avcodec/avformat-58) + `PcsuiteConnectSDK.dll` + OpenSSL (`libeay32`) | **screen mirroring** (H.264/265 decode) + core transport SDK |
| `vdfs/vdfs.exe`, `vdfsServer.exe` | native | distributed file system (file transfer) |
| `SyncService/` | **protobuf** + **MQTT** (`MQTTAdapt.dll`) + OpenSSL/TLS + iCal | calendar/contacts sync over MQTT/TLS |
| `phoneCall/phoneCall.exe` | native | call relay |
| `vivorelay/vivorelay.exe` | Qt | relay helper |
| `vivoControl/` | Electron sub-app | input/control |

**`PcsuiteConnectSDK.dll`** (310 KB, 32-bit) is the core connection SDK; it
embeds **nlohmann::json** → the transport carries **JSON messages**. Crypto
likely via the bundled OpenSSL (`libeay32.dll`). This DLL + the Electron JS are
the two authoritative sources for the wire protocol.

**Key JS files** (under `app_src/dist/electron/`): `app-connection.js`
(WebSocket manager, phone IP/port, verify code, cloudAuth, `CONNECT_ROUTER`),
`main.js` (Electron main; IPC; native-process mgmt; account init),
`app-modules.js` (file APIs / Vdfs client), `129.js` (QR UI), `125.js`
(mirroring UI).

Reference (gitignored): `captures/windows-client/app_src/` (Electron JS) and
`captures/windows-client/native/` (kept helper binaries: vivoExtScreen incl.
`PcsuiteConnectSDK.dll` + OpenSSL, SyncService, vdfs). The 447 MB installer stays
in `~/Downloads/zen/` and is re-extractable with `7z` if more is needed.

## 1. Discovery / pairing bootstrap

Multiple connect modes (from `app-connection.js` / `components-connection.js`):

- **QR scan — PC shows, phone scans (cloud-mediated).** Corrected direction: the
  **PC generates the QR** (`createQRCode()`), the **phone scans it** with
  EasyShare (`showPhoneScanModal`, `waitingScanGetPhone`). The QR is a URL:
  ```
  <baseUrl>?s=<sid>&f=pc&t=<token>&u=<account>&d=<hostName>&mac=<mac>
  (intl/export build rewrites  https://  →  pcsuite:  scheme)
  ```
  It carries a **cloud session id `sid`**, not a raw IP. Flow:
  1. PC logs into the vivo account (`passport.vivo.com.cn`).
  2. PC → **`/scan/sid`** on `pcsuite-api.vivo.com` / `pc.vivo.com` → gets `sid`
     (+ timeout); registers its `localIpArr` / `wifiDirectIp` under that `sid`.
  3. PC renders the QR; polls **`/scan/getPhone`** for the scanner (`phoneSsid`).
  4. Phone scans → resolves `sid` via cloud → learns PC IP + token → connects
     directly (§2/§5).
  → **QR pairing depends on vivo cloud + account reachability.**
- **USB — transport is ADB.** *(VERIFIED by usbmon capture, 2026-09-19;
  supersedes the "direct /connect?active=usb" guess AND an intermediate wrong
  guess that USB rode the Wi-Fi LAN — it does not, the pipe is adb-tunnelled.)*
  Office Kit's bundled **adb** talks to the phone's adb interface and:
  1. `shell:am start -a vivo.intent.action.PCSUITE_INTENT` then
     `shell:am startservice … -n com.vivo.pcsuite/.service.AdbPortalService
      --es token '<newToken>' --es connectionId '<id>' --es pc_name '<host>'
      --es user_name '<masked>' --es from 'pc'` — **the PC injects the connect
     token into the phone over adb** (USB access ⇒ trust; no on-screen confirm
     seen on this path).
  2. `adb forward tcp:10380` / `tcp:10381` (PC→phone) and `adb reverse
     tcp:5679` / `tcp:8904` (phone→PC) set up the channels.
  3. **Control:** plaintext **HTTP** to the phone's **`PcSuite-HTTP`** server at
     `127.0.0.1:10380` — `POST /version` (hdrs `newToken`, `version:6.8.2`,
     `X-ES-HTTP-VERSION:1`, UA `axios/…`; body `{version,connBaseVersionCode,
     pcSuiteVersionCode,timestamp,connectionId}`) → `{"code":"0000","data":{…}}`.
  4. **Media/data:** **TLS 1.2** on `:10381` (self-signed `CN=vivo` cert, valid
     to `99991231`) — the encrypted video (`ep4 IN`, no plaintext NALs) and data.
  The cloud `scan/sid`+`getPhone` still ran alongside, but the actual pipe is
  **local adb**; whether the `newToken` is cloud-issued or PC-minted (⇒ a
  cloud-free USB path, KDE-Connect-style) is the next thing to pin.
- **`getPhone` response (VERIFIED):** `data` is a JSON *string* →
  ```json
  {"deviceType":"phone","bleId":"<6-digit>","openId":"<64-hex device openId>",
   "ip":["<phone-LAN-ip>",""],"connectionId":"<epoch-scoped id>",
   "userName":"<masked phone>","deviceName":"vivo X200T"}
  ```
  i.e. the client learns the phone's **IP + `connectionId` + device `openId` +
  `bleId`**, then opens the direct pipe to `ip` (§2). `scan/sid` first returns
  `{sid,timeout:180000}`; the client POSTs that `sid` to `getPhone` (polls until
  the phone appears, then 200).
- **Wi-Fi Direct / local** — `startWifiDirect()`, `startLocalNetworkScan()` +
  BLE (`start_ble_scan()`), proximity `NEARBY`/`FARAWAY`/`BOTH`; `localIpArr` can
  ride in `codeInfo` — a more LAN-direct path.
- Not mDNS on the PC path. (Phone's idle `5353/udp` + `10191/tcp` are unrelated.)

## 2. Transport & ports

- **PC → phone:** `wss://<ip>:<connectionServerPort>` and
  `https://<ip>:<connectionServerPort>` (TLS), with `ws://`/`http://` fallback
  (`changeHttpsToHttp()` / `checkMobilePhoneHttpsIsOk()`).
- **`connectionServerPort` is DYNAMIC** — a variable obtained from the QR /
  `baseinfo` exchange, **not a fixed constant**. (An earlier guess of "16384" was
  unverified; many port literals appear in the bundle — do not hardcode.)
- **PC ↔ native helpers:** local WebSockets (candidate localhost ports in the
  bundle: 1800, 1080, 3600, 1882, 4096, 8192, … — map each to a helper via live
  capture).
- **HTTP file APIs on phone:** `/api/v1/file/{upload,initUpload,streamUpload}`,
  `/api/v1/upload/{cancel,complete}`, `POST /pc_file_manager/channel`.

## 3. Framing

- **JSON messages over WebSocket.** Control uses a `MESSAGE_EVENT_TYPE` enum:
  e.g. `NOTIFY_VERIFY_CODE`, `UPDATE_DEVICE_INFO`, `SHADOW_LIKE`, `HEART_MSG`
  (keepalive), `RES_AUTHRITY` / `PC_MODE_AUTHRITY`, `RES_START_EXTSCREEN`,
  `NOTIFY_SCREEN_SHOT_SYNC`.
- **Request routing** via a `CONNECT_ROUTER`: `version`, `baseinfo`, `test`,
  `handshake`, `devConnectRequest`, `cloudAuth`, `takeAction`, `download`,
  `installapk`, `fileManagerPermission`, `fileManagerStorage`.
- (`PcsuiteConnectSDK.dll` also embeds nlohmann::json — consistent JSON framing
  at the native layer.)

## 4. Crypto — SOLVED (from Electron JS) ✅

- **Transport:** TLS via **WSS/HTTPS** to the phone (`wss://`/`https://`, with
  ws/http fallback).
- **App-level payload cipher:** **`aes-256-cbc`**, via Node `createCipheriv`,
  using `applicationInitData.key` + `.iv`.
- **Key/IV establishment — no derivation to reverse:** the **PC generates them
  and sends them to the phone.** From `getApplicationKey()` in the common util
  module (beautified `app-connection.js` ~L7003–7045):
  ```js
  alphabet = "a-zA-Z0-9"                    // 62 chars
  createRandomStr(n): n chars picked via Math.random()
  key = createRandomStr(32)   // 32 ASCII chars = 32 bytes → AES-256 key
  iv  = createRandomStr(16)   // 16 ASCII chars = 16 bytes → 128-bit IV
  ```
  Generated once per PC process; **key/iv are placed in the connect request**
  (`§5`, alongside `pcDeviceId`, `accountOpenId`) and sent to the phone over TLS.
  → **Both endpoints use the PC-chosen key/iv.** Our client does the same: pick a
  32-byte key + 16-byte IV, send them, then AES-256-CBC the payloads. **Unblocked.**
- **Note (not a blocker):** key/iv come from `Math.random()` (not a CSPRNG) and
  the key is restricted to `[A-Za-z0-9]` — weak entropy, but irrelevant to interop
  (we just need to speak the format). TLS wraps the exchange.
- **Separate RSA path (cloud, not phone):** `rsaEncrypt()` uses a hardcoded
  RSA-1024 public key (distinct values for prod / `pre.vivo.com` / `test.vivo.com`)
  to talk to the vivo **gateway** (account/cloud auth) — not the phone session.
- Phone-side note: `com.vivo.security` ("JVQ") is **not** on the pairing path;
  the `SecUtils.java` RSA/AES + `publicKey.txt` is **VCode telemetry**, unrelated.

## 5. Pairing handshake (message-by-message)

Reconstructed skeleton from the PC JS (fields to confirm with a live capture):
1. **Precondition:** user logged into the vivo account on the PC
   (`isLoginedVivoAccount()`, `passport.vivo.com.cn`); `CONNECT_ROUTER.cloudAuth`.
2. **Bootstrap (mode-dependent):**
   - *QR mode:* PC gets a `sid` from `/scan/sid`, shows the QR; phone scans and
     resolves the PC's IP+token via cloud (`/scan/getPhone`) — see §1.
   - *USB / Wi-Fi-Direct mode:* address obtained directly (no cloud), the path we
     should prefer for a distributable client.
3. **Probe:** `CONNECT_ROUTER.version` / `baseinfo` over `https/wss://<ip>:<port>`.
4. **Connect request:** `CONNECT_ROUTER.devConnectRequest`.
5. **Verify code:** phone emits `NOTIFY_VERIFY_CODE`; a numeric code is shown for
   user confirmation (`phoneVerCode`, `setPhoneVerCode`).
6. **Handshake:** `CONNECT_ROUTER.handshake` — the connect payload carries the
   PC-generated **`key`** + **`iv`** (§4) plus `pcDeviceId`, `pcDeviceName`,
   `accountOpenId`, `accountName`, `connectType`. This establishes the shared
   AES-256-CBC session material on the phone.
7. **Session:** JSON `MESSAGE_EVENT_TYPE` frames (AES-256-CBC), `HEART_MSG`
   keepalive.

`TODO` (byte-level, best nailed via a live capture): exact QR field encoding,
the verify-code check, and whether the whole connect payload is additionally
wrapped (RSA/`createRequestSign`) on top of TLS.

## 6. Session messages

- **Screen mirroring:** two modes — **VivoScreen** (phone → PC,
  `VivoScreenServer`) and **ExtendedScreen** (second display,
  `ExtendedScreenServer`); auth via `extScreenCheckAuthority()`; control frames
  `RES_START_EXTSCREEN`, `NOTIFY_SCREEN_SHOT_SYNC`. Video is decoded by the
  bundled **FFmpeg** in `VivoExtScreen.exe` → **H.264/H.265** (confirms P2 is
  feasible). Resolution from `device.screenWidth/screenHeight`. Exact codec &
  packetization on the wire: `TODO` (live capture).
- **Input:** cross-device keyboard/mouse — `keyboardMouseCoordinationServer`.
- **File transfer:** Vdfs (`VdfsClient`/`VdfsWsMsg`,
  `CONNECT_ROUTER.vdfsApplicationClient`) + the HTTP file APIs in §2.
- Collaboration/services surface (phone): `com.vivo.cowork`, `com.vivo.vdfs`.

## 7. Services (later — P4)

- File transfer: `com.vivo.vdfs` + `com.vivo.cowork.file` — `TODO`
- Clipboard sync: `TODO`
- Notification mirroring: `com.vivo.cowork.notification` — `TODO`

---

## 8. Account login & token (P2 blueprint) — VERIFIED

Login is a **user-driven web flow**; we drive the user's OWN login. **No embedded
app secret/key found** (only public RSA keys, §4) — clean-room-safe.

1. **Login page:** open passport in a webview/browser —
   `https://passport.vivo.com.cn` (or `.com`), `client_id=130`, dynamic
   `redirect_uri`. User authenticates via **SMS code or password**.
2. **Credential capture** (`preload-welcome.js`): passport redirects to
   `…/vbusiness/account/cookie/getHtml?openid=<openid>`; that page holds a hidden
   `<input>` whose value is `k=v&k=v…`. The preload reads it, `.split("&")`, and
   IPCs **`login-success`** with the fields (openid, vivoToken, …). Verified:
   ```js
   if (i.includes("vbusiness/account/cookie/getHtml?openid=")) {
     const n = (document.querySelector('input[type="hidden"]')?.getAttribute("value")||"").split("&");
     o.sendToHost("login-success", n);
   }
   ```
3. **No token exchange — the token is inline.** *(Corrected from a live mitmproxy
   capture of pcsuite 6.8.2, India account, 2026-09-19; supersedes the earlier
   decompiled guess.)* The `getHtml` hidden `<input>` value is POSITIONAL
   `&`-delimited, **not** `k=v`:
   `openId & token & accountDeviceId & regionCode & name & nick & extra`, e.g.
   `9f8c…&a818…d65.<epochMs>&wb_5146…&IN&null&null&null`. **Field[1] IS the
   session token** (equal to the `vivo_account_cookie_iqoo_vivotoken` cookie).
   The decompiled `getTokenByVivoTokenAndOpenid` is **never called** in this flow
   (0 hits) — it likely belongs to the CN or device-connect path.
4. **Authenticated gateway calls:** send **`openId`** + **`token`** request
   **headers** (plus `source:2`, `version:6.8.2`, `deviceId`, `countryCode`).
   **No `newToken` header appears** (0 hits) and these `/vbusiness/account/*`
   calls carry **no request signature** — auth is `openId`+`token`+TLS. Verified:
   `POST {region}-psuite…/vbusiness/account/getUserInfo` → **401** without the
   headers, **200** with them (same for `getUserCookie`). The OAuth step that
   mints the token: `GET {region}-passport…/v3/web/login/authorize?client_id=130&
   redirect_uri=https://{region}-psuite…/vbusiness/account/cookie/getHtml&type=1&
   theme=light&lang=en_US` → 302 → `getHtml?openid=…` (the hidden-input page).
   **`newToken` RESOLVED (2026-09-19):** it *is* used, but only on the **device
   pipe** — the PC injects it into the phone via `adb … am startservice --es
   token '<newToken>'` and sends it as the `newToken:` header to the phone's
   `PcSuite-HTTP` server (§1, USB). The account gateway (`in-psuite`) uses
   `openId`+`token`; the device gateway (phone `:10380`) uses `newToken`. Still
   open: is `newToken` cloud-issued or PC-minted?
5. **Gateway hosts (region-selected):** `pcsuite-api.vivo.com` (CN);
   `asia-/in-/eu-/ru-/de-gdpr-pcsuite-api.vivoglobal.com` (global). Device
   register/scan: `/scan/sid` → `/scan/getPhone` (§1). `connection-center.vivo.com.cn`
   is also referenced (role unconfirmed).
6. **Request signing:** `createRequestSign()` exists; exact inputs `TODO` (no
   secret embedded, so likely token/timestamp/nonce based).

**Client blueprint (P2) — VERIFIED:** open the passport login in a system
browser/webview → on the `getHtml` redirect, read the hidden input and split on
`&` POSITIONALLY → take `openId` (field 0) + `token` (field 1) → send them as
`openId`/`token` headers on `/vbusiness/account/*` gateway calls. No exchange, no
signature. Legitimate "drive the user's own login." Implemented in
`src/vivolinkkit/login.py` (`parse_hidden_positional` + `gateway_headers`).

`TODO`: the device-connect gateway (`pcsuite-api`) — does it use the same
`openId`+`token`, or the decompiled `newToken` + `createRequestSign`? Needs a
phone-connected capture.

## Resolved
- ✅ Auth model: account login required + QR/verify-code/handshake (§0).
- ✅ Session crypto: AES-256-CBC, PC-generated key/iv sent to phone (§4).
- ✅ QR direction + format: PC shows, phone scans; cloud `sid` URL (§1).
- ✅ Transport/framing: wss + JSON `MESSAGE_EVENT_TYPE` / `CONNECT_ROUTER` (§2/§3).
- ✅ Login/token flow (LIVE-VERIFIED): passport web login → `getHtml` hidden
  input → `token` (field 1) → `openId`+`token` headers on the account gateway
  (§8). No exchange call, no `newToken`, no signature. No embedded secret.

## Open questions (remaining — need a live capture / build-and-observe)
- Can a connect **fully avoid the vivo cloud** (`/scan/*`)? **Partially answered
  (2026-09-19):** the **USB** connect does **NOT** avoid it — it runs the
  `scan/sid`+`getPhone` cloud rendezvous, then rides the phone's LAN IP (§1).
  **Still open:** does **Wi-Fi-Direct / local + BLE** (`startWifiDirect` /
  `startLocalNetworkScan`) reach the phone without `/scan/*`? That's now the
  decisive distributability question — capture a Wi-Fi-Direct connect next.
- Capture the **actual device pipe** to the phone's LAN IP (wss, §2/§3) — it
  bypasses the HTTP proxy, so use a network capture (tshark on `virbr0`/`vnet0`),
  not mitmproxy. This is the P3 gateway (framing, `connectionId`/`openId` use).
- Exact **verify-code** check (who computes/compares it, digits, where shown).
- ~~`getTokenByVivoTokenAndOpenid` request body~~ — RESOLVED: not used in the web
  flow (§8). Still open: does the **device-connect** gateway (`pcsuite-api`) sign
  calls (`createRequestSign`) or use `newToken`? Needs a phone-connected capture.
- Which side is the **WSS server** in each mode (PC-hosts vs phone-hosts)?
- Wire-level **video** codec/packetization for VivoScreen (H.264 vs H.265, RTP?).

## References (our own captures — never commit the raw files)

- `captures/inventory/{device,packages,ports}.txt`
- `captures/decompiled/com.vivo.connbase.connectcenter/` (jadx output)
