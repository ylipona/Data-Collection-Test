# 🛡️ Discord Verification System — Full Setup Guide

Collects maximum Discord OAuth2 data + IP geolocation + browser fingerprint,
sends it to a private webhook channel, and auto-assigns a Verified role.

---

## 📁 File Structure

```
discord-verify/
├── main.py              ← Entry point (run this)
├── bot.py               ← Discord bot (buttons, role assignment)
├── app.py               ← Flask web server (OAuth2 + data collection)
├── config.py            ← Loads .env variables
├── requirements.txt
├── Procfile             ← For Railway deployment
├── .env.example         ← Copy → .env and fill in
└── templates/
    ├── verify.html      ← Landing page (JS fingerprinting)
    ├── success.html     ← Shown after successful verification
    └── error.html       ← Shown on errors
```

---

## STEP 1 — Create a Discord Application

1. Go to https://discord.com/developers/applications
2. Click **New Application** → give it a name (e.g. "Verification Bot")
3. Go to **Bot** in the left sidebar
   - Click **Reset Token** → copy the token → this is your `BOT_TOKEN`
   - Enable ALL three Privileged Gateway Intents:
     - ✅ PRESENCE INTENT
     - ✅ SERVER MEMBERS INTENT
     - ✅ MESSAGE CONTENT INTENT
   - Click **Save Changes**

4. Go to **OAuth2 → General**
   - Copy your **Client ID** → this is `CLIENT_ID`
   - Click **Reset Secret** → copy → this is `CLIENT_SECRET`

5. Leave the **Redirects** section empty FOR NOW — you'll add the Railway URL later.

---

## STEP 2 — Invite the Bot to Your Server

1. In the Discord Developer Portal, go to **OAuth2 → URL Generator**
2. Under **SCOPES** select:
   - ✅ `bot`
   - ✅ `applications.commands`
3. Under **BOT PERMISSIONS** select:
   - ✅ Manage Roles
   - ✅ Send Messages
   - ✅ Read Message History
   - ✅ Embed Links
   - ✅ View Channels
   - ✅ Use Application Commands
4. Copy the generated URL at the bottom → paste in browser → invite bot to your server

---

## STEP 3 — Set Up Your Discord Server

### Create the #verify channel
1. Create a channel called `#verify` (or any name you want)
2. Set permissions so **only the bot can send messages** there
   - Remove `Send Messages` from `@everyone`
   - Grant `Send Messages` to the bot's role
3. Right-click the channel → **Copy Channel ID** → save it as `VERIFY_CHANNEL_ID`

### Create the Verified role
1. Server Settings → Roles → Create Role → name it "Verified"
2. Give it access to your actual server channels (deny @everyone access to those channels)
3. Right-click the role → **Copy Role ID** → save it as `VERIFIED_ROLE_ID`
4. **Important:** drag the Verified role BELOW the bot's role in the role list

### Create a private mod webhook channel
1. Create a channel (e.g. `#verifications`) — only mods can see it
2. Channel Settings → Integrations → Webhooks → **New Webhook**
3. Give it a name (e.g. "Verification Logs") and copy the **Webhook URL** → save it as `WEBHOOK_URL`

### Get your Server ID
1. Right-click your server icon → **Copy Server ID** → save as `GUILD_ID`
(If you don't see "Copy Server ID", enable Developer Mode: User Settings → Advanced → Developer Mode)

---

## STEP 4 — Deploy to Railway (Free Hosting)

Railway gives you a free always-on server. This is where the web app lives.

1. Go to https://railway.app and sign up (free with GitHub)
2. Click **New Project** → **Deploy from GitHub repo**
   - If you haven't pushed the code yet, click **Deploy from template** then select "Empty"
   - OR: push your code to GitHub first, then connect the repo

### If uploading directly (easiest):
1. Install Railway CLI: open PowerShell and run:
   ```
   npm install -g @railway/cli
   ```
2. In your project folder, run:
   ```
   railway login
   railway init
   railway up
   ```

3. In the Railway dashboard, go to your project → **Variables** tab
4. Add ALL variables from `.env.example` (fill in real values):
   - `BOT_TOKEN`
   - `CLIENT_ID`
   - `CLIENT_SECRET`
   - `GUILD_ID`
   - `VERIFY_CHANNEL_ID`
   - `VERIFIED_ROLE_ID`
   - `SECRET_KEY`  ← generate: `python -c "import secrets; print(secrets.token_hex(32))"`
   - `WEBHOOK_URL`
   - `REDIRECT_URI` ← set this AFTER the next step

5. Go to **Settings** tab → **Networking** → **Generate Domain**
   - You'll get a URL like `discord-verify-production.up.railway.app`
   - Your `REDIRECT_URI` = `https://discord-verify-production.up.railway.app/callback`
   - Add this as the `REDIRECT_URI` variable in Railway

---

## STEP 5 — Add Redirect URI to Discord Developer Portal

1. Back in https://discord.com/developers/applications → your app
2. Go to **OAuth2 → General**
3. Under **Redirects** click **Add Another** and paste your Railway URL:
   ```
   https://discord-verify-production.up.railway.app/callback
   ```
4. Click **Save Changes**

---

## STEP 6 — Deploy & Test

1. Trigger a Railway redeploy (or it will auto-deploy when you push)
2. Check the Railway **Logs** tab — you should see:
   ```
   🌐  Flask listening on port XXXX
   🤖  Starting Discord bot…
   ✅  Bot online: YourBot#1234
   📌  Verify message posted in #verify
   ```
3. Join your Discord server with a test account
4. Go to #verify → click **Verify Now** → a DM + ephemeral message should appear
5. Click **Authorize on Discord** → you'll be taken to your Railway app
6. Click **Verify with Discord** → authorize the app on Discord
7. You should be redirected back and see the success page
8. Check your private #verifications channel for the webhook embed
9. Check that the test account got the Verified role

---

## STEP 7 — Local Testing (Optional, before deploying)

1. Install Python 3.11+ from https://python.org
2. Open PowerShell in the project folder:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
3. Copy `.env.example` to `.env` and fill in values
4. For local testing, set `REDIRECT_URI=http://localhost:5000/callback`
5. Add `http://localhost:5000/callback` as a redirect in Discord Developer Portal
6. Run: `python main.py`

---

## What Data Is Collected

### Discord OAuth2 (via API)
- Username, discriminator, User ID, avatar
- Email address, email verification status
- 2FA / MFA status
- Account creation date (derived from Snowflake ID)
- Nitro subscription type
- Public badges/flags
- All Discord servers the user is in (name + ID)
- All connected accounts (Twitch, Steam, Xbox, Spotify, GitHub, etc.)

### IP & Geolocation (via ip-api.com)
- IP address (real IP, respects X-Forwarded-For / Cloudflare headers)
- Country, region, city
- ISP and organization
- AS number
- Timezone
- VPN/proxy detection
- Datacenter/hosting detection

### Browser Fingerprint (via JavaScript)
- Full User-Agent string
- Browser language(s)
- Operating system / platform
- Screen resolution, color depth, device pixel ratio
- Window size
- Timezone
- CPU core count
- Device memory
- Touch screen support
- WebGL renderer & vendor (GPU info)
- Canvas fingerprint hash (unique per browser/GPU combination)
- Audio context fingerprint
- Network connection type & speed
- Battery level & charging status
- AdBlock detection
- WebRTC local IP leak
- Installed plugins
- Storage support (localStorage, sessionStorage, indexedDB)
- Media device count (microphones, cameras, speakers)
- Do Not Track setting

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Bot doesn't post verify message | Check `VERIFY_CHANNEL_ID` is correct; ensure bot has Send Messages permission in that channel |
| Role not assigned | Ensure `VERIFIED_ROLE_ID` is correct; bot's role must be ABOVE the Verified role |
| OAuth2 redirect_uri mismatch | The `REDIRECT_URI` in `.env` must EXACTLY match what's in Discord Developer Portal |
| Webhook not sending | Check `WEBHOOK_URL` is valid; ensure the channel still exists |
| Railway app crashes | Check Logs tab; usually a missing environment variable |
| 429 from ip-api.com | You've hit 45 req/min free limit — space out verifications or upgrade ip-api plan |

---

## Security Notes

- Never commit your `.env` file or share `BOT_TOKEN` / `CLIENT_SECRET`
- The `SECRET_KEY` should be a random 32+ character string
- Railway environment variables are encrypted at rest
- All data collected is sent only to your private webhook channel
