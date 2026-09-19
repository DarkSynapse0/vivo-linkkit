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
  **local adb**. **`newToken` is PC-minted — VERIFIED (2026-09-19):** 12 distinct
  per-connection tokens in one session, **none** present in any cloud req/resp;
  the client has `crypto.randomBytes(32).toString("hex")` and always *sends* the
  token to the phone (adb `--es token`, `newToken` header, `/base-info` body).
  ⇒ **KDE-Connect-style local trust: a cloud-free USB connect is feasible** —
  mint our own token, `adb forward 10380`, `POST /base-info` with the account
  `openid` (proves same-account) + our token. Cloud is only needed for the
  account login (openid) and, on the Wi-Fi path, rendezvous.
- **Cloud-free USB connect — PROVEN (2026-09-19, `src/vivolinkkit/connect_usb.py`).**
  Driving adb from Linux with a **self-minted** token, `POST /base-info` returns
  **`{"code":"0000", data:{…device info…}}`** — the phone accepts us. Recipe:
  1. `am startservice … AdbPortalService --es token <ours>` — **no on-screen
     confirmation** (launcher stays focused). USB-access trust.
  2. The PC must **HOLD open** reverse listeners on `5679`+`8904` (then
     `adb reverse` them); the phone binds `:10380` only while they exist, and
     they must stay open through the handshake (a dumb accept-then-close fails).
  3. `adb forward 10380`, settle ~1 s, `POST /base-info` with same-account
     `openid` + our `token` + full body. **Send `/base-info` FIRST** — a failed
     `/version` poisons the connection.
  - **No pairing / device registration:** isolation-tested — a **random**
    `pcDeviceId` (and random token) still returns 0000. The trust is purely
    same-account `openid` + our PC-minted token. Fully self-sufficient client.
  - **Control plane = plaintext WebSocket (VERIFIED, live with our token).** After
    `/base-info`, open `ws://<phone>:10380/ws/heart-beat`. **Auth is the WS
    subprotocol, not a header:** `Sec-WebSocket-Protocol: v1.hc.vivo.com.cn,
    <token>` (token as the 2nd subprotocol; `Origin: file://`). Messages are
    `EVENT_NAME:{json}` or a bare `{json}` heartbeat — observed:
    `UPDATE_DEVICE_INFO:{"mobileDeviceId":…}`, `RE_CONNECT_ALBUM:{"auth":1,…}`,
    `{"state":"normal"}`. This is the §3 framing, in the clear — only the
    **`:10381` TLS** carries the video/bulk media. (`connect_usb.py --watch`.)
  - **Port map (VERIFIED, from the client's `defaultConfig`):**
    `connectionServerPort:10380` (control HTTP + the ws), `mirrorServcerPort:10381`
    (**screen mirror / video**, TLS), `VDFS_PC_PORT:5679` and `RELAY_PC_PORT:8904`
    (the reverse channels — **VDFS = vivo Distributed File System** for file
    transfer, + a relay). So `5679`/`8904` aren't dummies: they're the file/relay
    transports, which is why the phone needs the PC listening there.
  - **File manager = plaintext JSON over TLS on `:10380` (DECRYPTED, 2026-09-19 —
    corrects the earlier "AES-256 body" guess).** `:10380` serves **both**
    plaintext (base-info/version/ws) **and** TLS — the phone sniffs the first byte
    (`0x16`→TLS). The fm requests use the **TLS** side, which is why our *plaintext*
    `POST /pc_file_manager/channel` got `"bad requestBody"`. There is **no
    app-layer AES** — TLS is the only encryption. Method: `SSLKEYLOGFILE` on
    Office Kit (it honours it) + a usbmon capture, demux the ADB streams
    (`scripts/vm/decrypt_usb_tls.py` → synthetic pcap), `tshark -o tls.keylog_file`.
    Decrypted **file-listing response** shape (`Server: PcSuite-HTTP`, also a
    `WeiChuan-HTTP` sub-server):
    ```json
    {"dataList":[{"dataList":{"<Category> | <Sub>":[
      {"dirName":"Download","fileName":"pcsuite.apk","fileSize":27148116,
       "mimeType":"application/vnd.android.package-archive","isDirectory":false,
       "savePath":"/storage/emulated/0/Download/pcsuite.apk","date":…,"duration":0,
       "isLivePhoto":false,"childrenSize":0,"id":0}]}}]}
    ```
    Decrypted **`/version`** request body (fuller than §8's): `{version,
    connBaseVersionCode,pcSuiteVersionCode,timestamp,connectionId,pcDeviceId,
    isAutoConnect,token,isOversea:true,pcOsType:"win32",pcOsVersion}`.
  - **File listing WORKS in our client (VERIFIED end-to-end).** `POST` over TLS
    to `:10380/pc_file_manager/channel`, headers just `newToken` + `Content-Type:
    application/json`, body:
    ```json
    {"category":"","data":"","fileCount":0,"sortCondition":9,"groupBy":1,
     "type":"REQUEST_POSTS_IMAGELIST","pageIndex":0,"pageNumber":200,"firstFlag":false}
    ```
    The **`type`** field was the missing piece (the earlier "bad requestBody").
    Values: `REQUEST_POSTS_{HOMEDATA,IMAGELIST,VIDEOLIST,AUDIOLIST,DOCSLIST,
    WEB_DOCSLIST,FILELIST,NEW_APP,NEW_QQ,NEW_WECHAT,ONE_MOTH_LIST,
    RECENTE_DELETE_LIST}`. Response = `{"dataList":…}` with `fileName/fileSize/
    savePath/mimeType/isDirectory/date/duration`.
  - **File DOWNLOAD also works (VERIFIED):** `GET {base}/download/down_files?
    path=<savePath>&srctype=<mimeType>&newToken=<token>` on `:10380` (TLS) streams
    the raw file. Confirmed exact byte-for-byte for PNG/JPEG/MP4 off the phone.
  - **Thumbnails (VERIFIED):** `GET /pc_file_manager/thumb?fileUri=<savePath>&
    width=160&height=160` → a 144×144 PNG preview. (`connect_usb.py --thumbs`.)
  - **Clipboard + notifications are NATIVE, not this layer** (2026-09-19): almost
    nothing in the JS; handled by `native/SyncService/vivoSyncService.exe` (MQTT
    `paho-mqtt` + protobuf + `VPushSdk`). Like the mirror (§6), a native
    sub-project — not the JSON/HTTP services here.
  - **Local file UPLOAD (PC→phone) = VDFS, not a simple endpoint** (2026-09-19):
    no `/pc_file_manager/upload`-style route (all 404); `/api/v1/file/*` is the
    *cloud* `CloudServerApi` (fields `trace_id/sid/openid`). Local push uses
    `VdfsClient`/`vdfsApplicationClient` over the reverse channels `5679`/`8904` —
    another binary/native sub-project. **Net: the readable JSON/HTTP file services
    are list + download + thumbnails (all working); upload/clipboard/notifications/
    mirror are the native tier.**
    Other fm endpoints: `/tab_count?type=N`, `/get_path`, `/download` +
    `/download_info`, `/thumb?fileUri=…&width=…`, `/query_directory_size`,
    `/recycle_operation`, `/trans_open_file`, `/drop_files_info`. Driven by
    `connect_usb.py --list images,videos,…` and `--grab images:3,videos:1`
    (saves to `captures/downloads/`).
  - **Decrypt method note:** the synthetic pcap must **reorder TLS records into
    real handshake flow** (ClientHello → ServerHello.. → client CCS/Finished →
    client APP → server APP); otherwise tshark hits the client's encrypted records
    before the ServerHello random and only the *server* direction decrypts. See
    `scripts/vm/decrypt_usb_tls.py`. (`isFmHasPermission:false` didn't block listing.)
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

- **Screen mirroring — FULLY MAPPED from the phone's Java (2026-09-19; corrects
  the earlier "native/Frida" scoping).** There are two *different* directions:
  - **PC → phone extended screen** = native `VivoExtScreen.exe` (Poco WS + FFmpeg,
    `DxgiScreenCapturer` captures the *PC* screen, endpoints `/ext/control` +
    `/ext/screen`). That one is native and would need Frida — but it's the *less*
    interesting direction.
  - **Phone → PC mirror** (the phone's screen on the PC — what you actually want)
    is the **vivo Cast SDK `com.vivo.castsdk`**, decompiled from the phone's
    `com.vivo.pcsuite` APK (`recon/02_decompile.sh com.vivo.pcsuite`) — **readable
    Java**, on the **same Netty `:10380` HTTP server** as the file manager.
    Routes (`HttpServerInitializer`): `/mirror/screen`, `/mirror/control`,
    `/mirror/device_size`, `/mirror/app_screens`.
  - **`/mirror/screen` protocol (VERIFIED from source):** it's a **WebSocket**
    (`WebSocketServerProtocolHandler("/mirror/screen","v1.hc.vivo.com.cn",…)` →
    `ImplScreenController`) — same subprotocol-token auth as the heartbeat ws (§1).
    Flow: PC sends text `SCREEN_START:{SessionReq}`; phone replies
    `DEVICE_INFO:{…}` then streams **`BinaryWebSocketFrame` = H.264/HEVC** (first
    binary = SPS/PPS config). `SessionReq` fields: `bit_rate, mime_type("video/avc"
    |"video/hevc"), max_size, video_width, video_height, device_type, mirror_type,
    no_audio, split_frame, show_touch_spot, support_drag, pc_version, …`. Encoder:
    `ScreenCaptureManager` + `MediaCodec` (CBR, configurable bitrate/fps/IDR) over
    a `MediaProjection` `VirtualDisplay`. `/mirror/control` is a second ws for
    input (`ImplKeyEventController`); `/mirror/device_size` returns screen dims.
  - **The one gate = Android screen-capture consent.** `/mirror/screen` won't
    stream until `MediaProjection` is granted via the system "Start casting?"
    dialog (mandatory, not bypassable). **Full trigger sequence (reverse-engineered
    from `WebSocketController`):**
    1. `POST /version` with `version:"6.8.2"`, `isOversea:true`, `pcOsType/…` —
       this sets the phone-side PC version (`CastSource.setVersion`). Required:
       the trigger's `isSupportScreenCapture()` = *PC version ≥ 3.4.9*; skip
       `/version` and the phone **silently refuses** to show the dialog.
    2. `POST /base-info` (as usual).
    3. Over the **`/ws/heart-beat`** ws (the same one `--watch` opens), send the
       text `"CONTINUE_OPEN_SCREEN:"` (exactly the constant, empty payload →
       `substring(21)==""` → launch). `WebSocketController` launches
       `MediaProjectionActivity` → the "Start casting?" dialog.
    4. User taps Allow → `MediaProjectionActivity.onActivityResult(RESULT_OK)` →
       `CastSource.init(...)` with `CastSourceConfig().setPort(10381)` → the cast
       server (`OptionalSslHandler`+`TokenCheckController`) **binds on `:10381`**
       (verified in `MediaProjectionActivity` line ~357 — *not* `:10180`, which the
       earlier decompile-era note had wrong).
    5. `adb forward 10381`; open `ws :10381/mirror/screen` (subprotocol
       `v1.hc.vivo.com.cn,<token>`); send `SCREEN_START:{SessionReq}`; read the
       `DEVICE_INFO:` reply then the H.264 `BinaryWebSocketFrame`s; decode (PyAV).
  - **Status — protocol complete, consent-gated by the OS (verified 2026-09-19).**
    Every layer up to the consent is coded (`scripts/vm/mirror_prototype.py`) and
    confirmed **live on real hardware** via the phone's system activity log
    (`adb logcat -b events`): connect + `/version` gate passes
    (`isSupportScreenCapture()`), `CONTINUE_OPEN_SCREEN:` is delivered and dispatched
    (`WebSocketController.channelRead0` → `b()`), `MediaProjectionActivity` launches,
    **and the real system consent `com.android.systemui/.mediaprojection.permission.`
    `MediaProjectionPermissionActivity` is created.** The last inch is an OS wall:
    that systemui activity **self-cancels in ~29 ms** (`userLeaving=false, finish`;
    reproduced 3×, independent of connect-settle timing) because our trigger is
    **PC-initiated / background** — the launching task never becomes the real
    foreground (`dumpsys` shows the launcher stays `topResumedActivity` throughout),
    so Android's MediaProjection foreground-gesture requirement refuses the prompt.
    The vendor client clears this because `com.vivo.pcsuite` is a **signed platform
    app** (`scontext=…:platform_app` in the phone's SELinux audit) that either
    auto-grants `MediaProjection` or is privileged to foreground its own allow-dialog
    for the user to tap. **A clean-room, unsigned PC client cannot forge that
    foreground gesture — this is the distribution boundary for phone→PC mirror, by
    OS design (the same protection that stops any app silently screen-recording).**
    So: mirror is fully reverse-engineered (a ws + a decoder, no Frida/native TLS),
    but *streaming it* needs either the vendor platform signature or a genuine
    on-device consent path we can't drive from the PC. Documented, not shipped.
  - **Both triggers dead-end at the same wall (traced 2026-09-19).** There are two
    PC→phone screen messages — `CONTINUE_OPEN_SCREEN:` and `req_authrity{source}`
    (`REQ_AUTH`, which uses a `CountDownLatch` and replies `res_authrity{auth:2}`
    "pending" while awaiting the user). Both funnel through `WebSocketController.d()`
    → `j()` (line ~997), which does `startActivity(MediaProjectionActivity, NEW_TASK)`
    from the app context — the identical background launch. A user-tappable
    *foreground* `PermissionActivity` only appears on a **connection-mutex** state
    (another cast already active); it's a conflict-resolver, not the consent path.
    So no PC-sendable message yields a stickable consent — confirming the gate is
    the platform signature, not a missing handshake. The realistic way to use
    vivo's *own* mirror is an on-device **privileged grant** (root, or a Shizuku
    shell-UID helper) that satisfies MediaProjection; absent that, the interim mirror
    engine is the `app_process` capture path (`vivolinkkit mirror`, drives scrcpy).
  - **ADB-only bypass attempts — all fail on Android 16 (tested 2026-09-19).** The
    root cause is that `MediaProjectionActivity`, launched from the background ws
    handler, never becomes the real foreground task (launcher stays
    `topResumedActivity`); the system consent finishes with `finish-imm:transit`
    before it can wait for a tap. Everything reachable from `adb`/shell (no root)
    was tried and none moved the ~29 ms self-cancel:
    - `appops set com.vivo.pcsuite PROJECT_MEDIA allow` — the known RustDesk/AnyDesk
      trick; ignored here (the BAL cancel happens *before* the app-op is evaluated).
    - `appops set … SYSTEM_ALERT_WINDOW allow` + `pm grant … SYSTEM_ALERT_WINDOW` —
      no effect. (Android 15+ narrowed the SAW→BAL exemption to require SAW **and a
      currently-visible `TYPE_APPLICATION_OVERLAY`**; pcsuite's connect overlay is
      already gone by trigger time.)
    - `am compat disable FGS_SAW_RESTRICTIONS com.vivo.pcsuite` (the change that adds
      the visible-overlay requirement) + disabling the BAL PendingIntent change — no
      effect (the block is on a *direct* `startActivity`, not a PendingIntent, and is
      enforced by ActivityTaskManager on the calling context, not a pcsuite compat
      flag).
    So from a clean-room PC-over-ADB position the vivo-native consent cannot be made
    to stick. The one untested lever is **root** (a `su`/privileged grant could set
    the projection token or force-foreground the activity) — out of scope for a
    distributable clean-room tool. Hence `vivolinkkit mirror` ships the consent-free
    `app_process` path instead; see the source docstring.
  - **Refinement (AOSP cross-check, 2026-09-19).** An AOSP source review pointed out
    that `systemui/.../MediaProjectionPermissionActivity` has **no** generic
    "caller-not-foreground → cancel" branch, so the self-cancel isn't that activity
    doing a BAL check. The `-b events` buffer confirms the shape precisely: the
    consent goes `performCreate` → `wm_add_to_stopping … completeFinishing` in **~4
    ms** — i.e. it cancels **inside `onCreate`, before the dialog is shown**. AOSP's
    onCreate cancel paths are: invalid/missing calling package · projection-service
    exception · device-policy restriction · (already-authorized → `RESULT_OK`).
    Ruled out on this device: **device policy** (`dumpsys device_policy` →
    "Screen capture disallowed users: []") and a **stale session** (`dumpsys
    media_projection` → "Media Projection: null"). The remaining causes (null calling
    package, or `MediaProjectionManagerService.createProjection` throwing) can't be
    distinguished by log — vivo's production build **strips** the ActivityStarter /
    `BackgroundActivityStartController` / MediaProjection reason logs (verbose
    `setprop` doesn't re-enable them; they're compile-time gated). Both remaining
    causes trace back to the same origin, though: our `MediaProjectionActivity` never
    becomes the resumed/focused task (launcher stays `topResumedActivity`), so its
    `startActivityForResult` has no valid foreground caller identity. BAL explains
    why the *app* activity can't foreground; that then makes the *systemui* consent
    cancel in onCreate. Net: same wall, better understood — the fix still requires a
    genuine foreground launch (platform signature, on-device user gesture, or root).
    `MANAGE_MEDIA_PROJECTION` (the only API that could mint/inject the token for
    another UID) is `signature|role:systemui` and unreachable from shell/Shizuku.
  - **DEFINITIVE root cause (ActivityRecord captured, 2026-09-19).** Spamming the
    trigger while hammering `dumpsys activity activities` snapshotted the short-lived
    consent `ActivityRecord`. It settles the question: the consent has
    `launchedFromUid=10095 launchedFromPackage=com.vivo.pcsuite` (correct
    `getLaunchedFromPackage()`) but **no `resultTo=`/`requestCode=` field at all** —
    i.e. `getCallingPackage() == null`. Android 16's
    `MediaProjectionPermissionActivity.onCreate()` starts with, in effect,
    `if (getCallingPackage()==null && !hasExtra(EXTRA_PACKAGE_REUSING_GRANTED_CONSENT))`
    `{ finishAsCancelled(); return; }` — hence the ~4 ms cancel
    (`state=STOPPING finishing=true lastLaunchTime=-25ms`). The
    `sysui_multi_action [757=1144 APP_TRANSITION_CANCELLED, 758=8 WARM_LAUNCH]` metric
    is the transition-cancelled *effect*, not a reason. **Crucially the snapshot's
    `topResumedActivity` was `com.vivo.pcsuite/.cast.MediaProjectionActivity` itself —
    the vendor activity WAS top-resumed and the consent still cancelled — decoupling
    the failure from BAL/focus entirely.** The real defect: driven by our background
    `CONTINUE_OPEN_SCREEN` path, the vendor's `MediaProjectionActivity` launches the
    systemui consent **without a result-caller relationship** (`resultTo` unset), so
    `getCallingPackage()` is null. That linkage is set by the framework at
    `startActivityForResult` time from the launching activity's state; it can't be
    injected from outside the app, and `EXTRA_PACKAGE_REUSING_GRANTED_CONSENT` (the
    sanctioned alternative) is a system-server-only path. So the boundary sits at the
    framework result-attribution layer — still unreachable from a clean-room PC/ADB
    client without the platform signature or root.
  - **Why `resultTo` is null — narrowed (manifest, 2026-09-19).** A follow-up review
    flagged the likely cause as the source being `singleInstance` (AOSP force-adds
    `NEW_TASK` to a `singleInstance` source's child, then drops the result). Pulled
    the APK and decoded the manifest (`jadx --no-src`): the vendor
    `com.vivo.pcsuite.cast.MediaProjectionActivity` is declared **`standard`** launch
    mode (`taskAffinity="com.vivo.pcsuite.authority"`, `excludeFromRecents`,
    `TransparentTheme`; the neighbouring `singleInstance` is `MainActivity`, not
    this). The captured consent child intent carries **no `FLAG_ACTIVITY_NEW_TASK`**
    (`flg=0x800000`). So the null `resultTo` is NOT stock AOSP's
    `singleInstance -> NEW_TASK -> drop result` path — it's a **vivo-specific
    result-attribution behavior** (either the source is `finishing` when it calls
    `startActivityForResult` — e.g. the 300 ms re-entrant `o()` watchdog — or an OEM
    WM modification). Either way it's internal to the vendor app/framework; the
    result token is a caller-supplied Binder, not a permission-backed resource, so an
    external shell/ADB client cannot influence it. Confirms vivo-native mirror needs
    the platform signature or root.
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
   `openId`+`token`; the device gateway (phone `:10380`) uses `newToken`.
   **`newToken` is PC-minted** (`crypto.randomBytes(32).toString("hex")`, one per
   connection; never seen cloud-side) — see §1 USB. Local trust, not a cloud
   credential ⇒ distributable, and a cloud-free USB path is feasible.
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
- Can a connect **fully avoid the vivo cloud**? **PROVEN for USB (2026-09-19):**
  `connect_usb.py` connects with a self-minted token over pure adb — `/base-info`
  returns `code 0000`, no cloud call from the client, no on-screen confirm, no
  pairing (`scan/*` is skippable for USB). Cloud is needed only for the account
  **login** (to get `openid`). Remaining check: run with the **phone in airplane
  mode** to also rule out phone-side cloud validation of the openid; and the
  **Wi-Fi** path still needs cloud rendezvous to find the phone's IP.
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
