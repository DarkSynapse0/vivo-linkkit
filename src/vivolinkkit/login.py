"""login.py — drive the user's OWN vivo account login to obtain the session token.

Mirrors the official PC Suite flow (PROTOCOL.md §8), clean-room and legitimate:
we never bypass auth or embed a vendor secret — the user signs into *their own*
vivo account, exactly as the official client makes them.

Flow (CORRECTED from a live mitmproxy capture of the real pcsuite 6.8.2 client,
2026-09-19 — supersedes the decompiled-JS guess of a token-exchange step):
  1. Open the vivo passport login page in a real browser (Playwright/Chromium).
  2. The user authenticates (SMS code or password) in that window.
  3. On the redirect to `…/vbusiness/account/cookie/getHtml?openid=…`, scrape the
     page's hidden <input> value and split it on "&". The fields are POSITIONAL,
     not k=v:  openId & token & deviceId & regionCode & name & nick & extra.
     Field[1] IS the session token (it also equals the
     `vivo_account_cookie_iqoo_vivotoken` cookie) — no exchange call is needed.
  4. Authenticated gateway calls send `openId:` and `token:` HTTP headers (plus
     source=2 / version / deviceId / countryCode). There is NO
     `getTokenByVivoTokenAndOpenid` POST and NO `newToken` header in this flow;
     verified by `getUserInfo` going 401 (no token hdr) → 200 (with token hdr).
  5. Persist to captures/auth/ (gitignored).

Because the exact `loginUrl` is region/config-derived in the client, it is a
CONFIGURABLE input here — the first live run confirms the precise params, then we
pin them. Raw captures are saved for that build-and-observe refinement.

Requires Playwright:
    pip install playwright && playwright install chromium
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AUTH_DIR = REPO_ROOT / "captures" / "auth"  # gitignored

# --- Known from PROTOCOL.md §8 (region-specific; override via CLI) -------------
DEFAULT_CLIENT_ID = "130"  # vivo passport client_id used by PC Suite

# passport account host is region-swapped in the client:
#   CN: passport.vivo.com.cn   global/asia: sg-/asia-passport.vivo.com
#   in-/ru-/eu-passport.vivo.com, iqoo: asia-passport.iqoo.com, …
ACCOUNT_HOSTS = {
    "cn": "passport.vivo.com.cn",
    "asia": "sg-passport.vivo.com",
    "in": "in-passport.vivo.com",
    "ru": "ru-passport.vivo.com",
    "eu": "passport.vivo.com",
}
# psuite gateway host per region (client's gatewayProdHost). This is BOTH the
# redirect (getHtml) host and the account-API host — the token is region-scoped,
# so login host, redirect host, and gateway must all match the account's region.
PSUITE_HOSTS = {
    "cn": "psuite.vivo.com.cn",
    "asia": "asia-psuite.vivo.com",
    "in": "in-psuite.vivo.com",
    "ru": "ru-psuite.vivo.com",
    "eu": "eu-psuite.vivo.com",
    "kz": "kz-psuite.vivo.com",
}
REDIRECT_PATH = "/vbusiness/account/cookie/getHtml"

# The redirect page whose hidden <input> carries the credentials (§8 step 2).
REDIRECT_MARKER = "vbusiness/account/cookie/getHtml?openid="

# The getHtml hidden-input value is `&`-delimited POSITIONAL fields (NOT k=v).
# Confirmed live: "9f8c…&a818…d65.1789…&wb_51463…&IN&null&null&null".
HIDDEN_FIELDS = ["openId", "token", "accountDeviceId", "regionCode",
                 "name", "nick", "extra"]

# Verify auth by hitting a cheap authenticated gateway endpoint (401 w/o token,
# 200 with it). This replaces the fictional token-exchange POST.
VERIFY_PATH = "/vbusiness/account/getUserInfo"

# The real client's User-Agent (Electron) — some gateway paths key off it.
PCSUITE_UA = ("Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) pcsuite/6.8.2 Chrome/108.0.5359.62 "
              "Electron/22.0.0 Safari/537.36")

# Every gateway request carries the client's "Cy" auth headers (getCyHeaders in
# the client JS). The signature is base64(HMAC-SHA256) with the timestamp string
# as the KEY and this constant as the MESSAGE (createRequestSign(msg, key)).
CONNECT_NAME = "com.vivo.pcsuite.connect"
APP_VERSION = "6.8.2"
SYSTEM_VERSION = "10"


def request_sign(timestamp_ms: int) -> str:
    """base64(HMAC-SHA256(key=timestamp_str, msg=CONNECT_NAME)) — matches the JS."""
    digest = hmac.new(str(timestamp_ms).encode(), CONNECT_NAME.encode(),
                      hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def get_device_id() -> str:
    """A stable client device id (client uses a stored newDeviceId)."""
    p = AUTH_DIR / "device_id.txt"
    if p.exists():
        return p.read_text().strip()
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    did = uuid.uuid4().hex
    p.write_text(did)
    return did


def cy_headers(openid: str, token: str = "") -> dict:
    """Replicate getCyHeaders() from the client (source=3 → Windows)."""
    ts = int(time.time() * 1000)
    return {
        "openId": openid,
        "token": token,
        "source": "3",
        "timestamp": str(ts),
        "sign": request_sign(ts),
        "deviceId": get_device_id(),
        "model": "win",
        "systemVersion": SYSTEM_VERSION,
        "appVersion": APP_VERSION,
    }


def build_login_url(account_host: str, client_id: str, redirect_uri: str,
                    lang: str = "en", theme: str = "light",
                    login_type: str = "1") -> str:
    """Passport login URL, matching the client's construction (PROTOCOL.md §8):

        <host>/#/login?client_id=&redirect_uri=&type=&theme=&lang=

    Base is passport's hash-route SPA login (`.../#/login`), region-swapped host.
    `type`/`theme` values are best-guess defaults, overridable, pinned on first run.
    """
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "type": login_type,
        "theme": theme,
        "lang": lang,
    }
    return f"https://{account_host}/#/login?{urllib.parse.urlencode(params)}"


def parse_credentials(hidden_value: str) -> dict:
    """URL-query style `k=v&k=v&…` — used for the getHtml *query string*."""
    creds: dict = {}
    for pair in hidden_value.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            creds[k] = urllib.parse.unquote(v)
    return creds


def parse_hidden_positional(hidden_value: str) -> dict:
    """The getHtml *hidden input* value: POSITIONAL `&`-delimited fields.

    openId & token & accountDeviceId & regionCode & name & nick & extra
    Field[1] is the session token used directly as the `token:` header.
    """
    out: dict = {}
    parts = hidden_value.split("&")
    for i, name in enumerate(HIDDEN_FIELDS):
        if i < len(parts):
            v = urllib.parse.unquote(parts[i])
            if v and v != "null":
                out[name] = v
    return out


def gateway_headers(openid: str, token: str, region: str = "in") -> dict:
    """Headers the real client sends on authenticated psuite gateway calls.

    Verified live: openId+token are the auth; there is no request signature on
    these `/vbusiness/account/*` calls (auth = these headers + TLS)."""
    return {
        "openId": openid,
        "token": token,
        "source": "2",
        "version": APP_VERSION,
        "deviceId": get_device_id(),
        "countryCode": region.lower(),
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": PCSUITE_UA,
    }


def capture_login(login_url: str, gateway: str = "", timeout_s: float = 300.0) -> dict:
    """Open a browser, let the user log in, capture the redirect credentials.

    Returns the parsed credential dict (expects at least openid + vivoToken).
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:  # pragma: no cover
        raise SystemExit(
            "Playwright is required:\n"
            "    pip install playwright && playwright install chromium"
        ) from e

    captured: dict = {}
    with sync_playwright() as p:
        # Disable the automation fingerprint so provider login pages (e.g. Google
        # sign-in) don't refuse "insecure browser". Legitimate: it's the user's
        # own login, we're just not advertising that it's script-launched.
        browser = p.chromium.launch(
            headless=False,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-first-run", "--no-default-browser-check",
            ],
        )
        context = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1200, "height": 820},
        )
        context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
        )
        page = context.new_page()
        print(f"[login] opening passport login — sign in with your vivo account…\n"
              f"        {login_url}")
        page.goto(login_url)

        # Wait (up to timeout) for the post-login redirect to the credential page.
        try:
            page.wait_for_url("**cookie/getHtml*", timeout=timeout_s * 1000)
        except Exception:  # noqa: BLE001 — timeout/other: capture whatever we have
            pass

        url = page.url
        if "cookie/getHtml" in url:
            captured["_redirect_url"] = url
            # openid (and anything else) rides in the URL query.
            captured.update(parse_credentials(urllib.parse.urlparse(url).query))
            # The page is DOM-ready now — read all hidden inputs (matches the
            # client's preload-welcome.js), splitting each k=v&k=v value.
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:  # noqa: BLE001
                pass
            try:
                vals = page.eval_on_selector_all(
                    'input[type="hidden"]', "els => els.map(e => e.value)"
                ) or []
                captured["_hidden_inputs"] = vals
                for v in vals:
                    if not v:
                        continue
                    if "=" in v.split("&", 1)[0]:      # legacy k=v form
                        captured.update(parse_credentials(v))
                    else:                               # real positional form
                        captured["_creds"] = parse_hidden_positional(v)
            except Exception:  # noqa: BLE001
                pass
            # The page is `cookie/getHtml` — the token is likely a cookie.
            try:
                captured["_cookies"] = {
                    c["name"]: c["value"] for c in context.cookies()
                }
            except Exception:  # noqa: BLE001
                pass

            # VERIFY (not exchange): the token is already in hand (hidden field[1]).
            # Prove it by calling an authenticated gateway endpoint with the
            # openId+token headers — expect 401 without, 200 with. Done from the
            # browser context so it looks native, though only the headers matter.
            if gateway:
                creds = captured.get("_creds") or {}
                openid = creds.get("openId") or find_openid(captured)
                token = creds.get("token") or find_vivo_token(captured)
                region = creds.get("regionCode", "IN")
                hdrs = gateway_headers(openid, token, region)
                try:
                    r = context.request.post(gateway + VERIFY_PATH, headers=hdrs,
                                             data="{}")
                    captured["_verify_status"] = r.status
                    captured["_verify_body"] = r.text()[:2000]
                except Exception as e:  # noqa: BLE001
                    captured["_verify_error"] = f"{type(e).__name__}: {e}"
        browser.close()

    if not captured:
        raise SystemExit("[login] no credentials captured — login not completed, "
                         "or the redirect marker/URL differs (adjust --login-url).")
    return captured


def find_openid(creds: dict) -> str:
    if creds.get("openid"):
        return creds["openid"]
    for name, val in (creds.get("_cookies") or {}).items():
        if name.lower().endswith("_openid") and val:
            return val
    return ""


def find_vivo_token(creds: dict) -> str:
    """Locate the vivoToken — prefer the exact `*_vivotoken` cookie."""
    for k in ("vivoToken", "vivotoken", "vivo_token"):
        if creds.get(k):
            return creds[k]
    cookies = creds.get("_cookies") or {}
    for name, val in cookies.items():          # e.g. vivo_account_cookie_iqoo_vivotoken
        if name.lower().endswith("vivotoken") and val:
            return val
    for name, val in cookies.items():
        if "token" in name.lower() and val:
            return val
    return ""


# NOTE: the decompiled `getTokenByVivoTokenAndOpenid` exchange is NOT part of the
# observed global web-login flow (0 calls in the 2026-09-19 capture; the token is
# delivered inline via getHtml). `request_sign`/`cy_headers` are retained for the
# device-connect gateway (pcsuite-api), whose signed calls we verify once the
# phone is passed through — do not resurrect a token-exchange POST here.


def main() -> None:
    ap = argparse.ArgumentParser(description="Drive the user's vivo login → newToken")
    ap.add_argument("--region", choices=sorted(ACCOUNT_HOSTS), default="asia",
                    help="account/gateway region (default: asia — the global build)")
    ap.add_argument("--account-host", help="override the passport host")
    ap.add_argument("--gateway", help="override the pcsuite-api gateway base URL")
    ap.add_argument("--redirect-uri", default=None,
                    help="OAuth redirect_uri (default: region's psuite getHtml page)")
    ap.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    ap.add_argument("--login-url", help="full passport login URL (skips builder)")
    ap.add_argument("--lang", default="en")
    args = ap.parse_args()

    account_host = args.account_host or ACCOUNT_HOSTS[args.region]
    # The token is region-scoped: login host, redirect host, and gateway must all
    # match the account's region (e.g. India → in-passport / in-psuite).
    redirect_uri = args.redirect_uri or f"https://{PSUITE_HOSTS[args.region]}{REDIRECT_PATH}"
    # Token exchange must hit the SAME host as the redirect (cookie scope).
    gateway = args.gateway or f"https://{urllib.parse.urlparse(redirect_uri).netloc}"
    login_url = args.login_url or build_login_url(
        account_host, args.client_id, redirect_uri, args.lang)
    print(f"[login] region={args.region}  account={account_host}  gateway={gateway}")

    print(f"[login] verify (in-session) at {gateway}{VERIFY_PATH}")
    creds = capture_login(login_url, gateway)
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    (AUTH_DIR / f"login-raw-{stamp}.json").write_text(json.dumps(creds, indent=2))
    parsed = creds.get("_creds") or {}
    # Observability without leaking secret values to the terminal:
    print(f"[login] openId parsed: {'yes' if parsed.get('openId') else 'no'}")
    print(f"[login] token parsed:  {'yes' if parsed.get('token') else 'no'}"
          f" (region {parsed.get('regionCode','?')})")
    hidden = creds.get("_hidden_inputs") or []
    print(f"[login] hidden inputs: {len(hidden)} (lengths: {[len(v or '') for v in hidden]})")

    if not parsed.get("token"):
        raise SystemExit("[login] captured redirect but no token in hidden field[1] "
                         f"— inspect the raw dump in {AUTH_DIR} and adjust the flow.")

    status = creds.get("_verify_status")
    body = creds.get("_verify_body", creds.get("_verify_error", ""))
    resp = {}
    try:
        resp = json.loads(body) if body else {}
    except json.JSONDecodeError:
        pass
    # Persist the working credential (gitignored) for reuse on gateway calls.
    (AUTH_DIR / "token.json").write_text(json.dumps({
        "openId": parsed.get("openId"),
        "token": parsed.get("token"),
        "regionCode": parsed.get("regionCode"),
        "verify_status": status,
        "verify_response": resp or body,
    }, indent=2))
    if status == 200 and (resp.get("code") == 0 or resp.get("ok")):
        print("[login] SUCCESS — token verified (getUserInfo 200). Saved to "
              "captures/auth/token.json. Send openId+token headers on gateway "
              "calls (PROTOCOL.md §8).")
    else:
        print(f"[login] token NOT verified — HTTP {status}. Response:\n  {str(body)[:400]}")


if __name__ == "__main__":
    main()
