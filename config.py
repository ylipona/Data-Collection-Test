import os
from dotenv import load_dotenv

load_dotenv()

# ─── Discord Bot ───────────────────────────────────────────────────────────────
BOT_TOKEN         = os.getenv("BOT_TOKEN", "")
CLIENT_ID         = os.getenv("CLIENT_ID", "")
CLIENT_SECRET     = os.getenv("CLIENT_SECRET", "")
GUILD_ID          = int(os.getenv("GUILD_ID", 0))
VERIFY_CHANNEL_ID = int(os.getenv("VERIFY_CHANNEL_ID", 0))
VERIFIED_ROLE_ID  = int(os.getenv("VERIFIED_ROLE_ID", 0))

# ─── Web / OAuth2 ─────────────────────────────────────────────────────────────
# Your Railway app root URL — NO trailing slash, NO /callback
# Example: https://my-app.up.railway.app
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:5000")

# Full URL of the /callback route
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:5000/callback")

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-to-a-random-string-32chars")

# ─── Webhook ──────────────────────────────────────────────────────────────────
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

# ─── OAuth2 scopes ────────────────────────────────────────────────────────────
# IMPORTANT: Do NOT add "bot", "applications.commands", or "guilds.members.read"
# here — those scopes trigger Discord's bot/server-add screen instead of the
# normal user authorization screen.
# These 4 are the maximum scopes for a standard user OAuth2 flow:
OAUTH2_SCOPES = "identify email guilds connections"
