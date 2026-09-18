"""login.py — drive the user's OWN vivo account login to obtain the session token.

Mirrors the official PC Suite flow (PROTOCOL.md §8), clean-room and legitimate:
we never bypass auth or embed a vendor secret — the user signs into *their own*
vivo account, exactly as the official client makes them.

Flow:
  1. Open the vivo passport login page in a real browser (Playwright/Chromium).
  2. The user authenticates (SMS code or password) in that window.
  3. On the redirect to `…/vbusiness/account/cookie/getHtml?openid=…`, scrape the
     page's hidden <input> value and split it on "&" → openid + vivoToken (+more).
     (This is exactly what the client's preload-welcome.js does.)
  4. Exchange them: POST /account/getTokenByVivoTokenAndOpenid → { token }.
     That `token` is the `newToken` attached as an HTTP header on gateway calls.
  5. Persist it to captures/auth/ (gitignored).

Because the exact `loginUrl` is region/config-derived in the client, it is a
CONFIGURABLE input here — the first live run confirms the precise params, then we
pin them. Raw captures are saved for that build-and-observe refinement.

Requires Playwright:
    pip install playwright && playwright install chromium
"""
from __future__ import annotations

import argparse
import json
import urllib.parse
import urllib.request
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
# gateway that answers /account/getTokenByVivoTokenAndOpenid (region-selected):
GATEWAYS = {
    "cn": "https://pcsuite-api.vivo.com",
    "asia": "https://asia-pcsuite-api.vivoglobal.com",
    "in": "https://in-pcsuite-api.vivoglobal.com",
    "ru": "https://ru-pcsuite-api.vivoglobal.com",
    "eu": "https://eu-pcsuite-api.vivoglobal.com",
}

# The redirect page whose hidden <input> carries the credentials (§8 step 2).
REDIRECT_MARKER = "vbusiness/account/cookie/getHtml?openid="

# Token-exchange endpoint (§8 step 3).
TOKEN_PATH = "/account/getTokenByVivoTokenAndOpenid"


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
    """The redirect page's hidden input is `k=v&k=v&…` — parse it to a dict."""
    creds: dict = {}
    for pair in hidden_value.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            creds[k] = urllib.parse.unquote(v)
    return creds


def capture_login(login_url: str, timeout_s: float = 300.0) -> dict:
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
                    if v and "=" in v:
                        captured.update(parse_credentials(v))
            except Exception:  # noqa: BLE001
                pass
            # The page is `cookie/getHtml` — the token is likely a cookie.
            try:
                captured["_cookies"] = {
                    c["name"]: c["value"] for c in context.cookies()
                }
            except Exception:  # noqa: BLE001
                pass
        browser.close()

    if not captured:
        raise SystemExit("[login] no credentials captured — login not completed, "
                         "or the redirect marker/URL differs (adjust --login-url).")
    return captured


def find_vivo_token(creds: dict) -> str:
    """Locate the vivoToken among URL fields, hidden inputs, or cookies."""
    for k in ("vivoToken", "vivotoken", "vivo_token", "token"):
        if creds.get(k):
            return creds[k]
    for name, val in (creds.get("_cookies") or {}).items():
        if "token" in name.lower() and val:
            return val
    return ""


def exchange_token(gateway: str, creds: dict, timeout_s: float = 15.0) -> dict:
    """POST /account/getTokenByVivoTokenAndOpenid → { token, ... }."""
    body = json.dumps({
        "openid": creds.get("openid", ""),
        "vivoToken": find_vivo_token(creds),
    }).encode()
    req = urllib.request.Request(
        gateway + TOKEN_PATH, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "vivo-linkkit/0"},
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def main() -> None:
    ap = argparse.ArgumentParser(description="Drive the user's vivo login → newToken")
    ap.add_argument("--region", choices=sorted(ACCOUNT_HOSTS), default="asia",
                    help="account/gateway region (default: asia — the global build)")
    ap.add_argument("--account-host", help="override the passport host")
    ap.add_argument("--gateway", help="override the pcsuite-api gateway base URL")
    ap.add_argument("--redirect-uri", default="https://psuite.vivo.com.cn"
                    "/vbusiness/account/cookie/getHtml",
                    help="OAuth redirect_uri (the credential page)")
    ap.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    ap.add_argument("--login-url", help="full passport login URL (skips builder)")
    ap.add_argument("--lang", default="en")
    args = ap.parse_args()

    account_host = args.account_host or ACCOUNT_HOSTS[args.region]
    gateway = args.gateway or GATEWAYS[args.region]
    login_url = args.login_url or build_login_url(
        account_host, args.client_id, args.redirect_uri, args.lang)

    creds = capture_login(login_url)
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    (AUTH_DIR / f"login-raw-{stamp}.json").write_text(json.dumps(creds, indent=2))
    # Observability without leaking secret values to the terminal:
    print(f"[login] captured fields: {sorted(k for k in creds if not k.startswith('_'))}")
    print(f"[login] openid: {'yes' if creds.get('openid') else 'no'}")
    hidden = creds.get("_hidden_inputs") or []
    print(f"[login] hidden inputs: {len(hidden)} (lengths: {[len(v or '') for v in hidden]})")
    print(f"[login] cookie names: {sorted((creds.get('_cookies') or {}).keys())}")
    print(f"[login] vivoToken located: {'yes' if find_vivo_token(creds) else 'no'}")

    if not creds.get("openid"):
        raise SystemExit("[login] captured redirect but no openid — inspect the "
                         f"raw dump in {AUTH_DIR} and adjust the flow.")

    print("[login] exchanging for newToken…")
    try:
        resp = exchange_token(gateway, creds)
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"[login] token exchange failed: {type(e).__name__}: {e}\n"
                         f"        (check --gateway/--region; raw creds saved.)")
    (AUTH_DIR / "token.json").write_text(json.dumps(resp, indent=2))
    token = resp.get("token") or (resp.get("data") or {}).get("token")
    print(f"[login] token response saved. newToken present: {bool(token)}")
    if token:
        print("[login] success — newToken obtained. Use it as the 'newToken' "
              "header on gateway calls (PROTOCOL.md §8).")


if __name__ == "__main__":
    main()
