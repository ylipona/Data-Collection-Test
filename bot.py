"""
bot.py — Discord bot component.
Handles: persistent Verify button, auto-posting verify message,
         welcoming new members, and assigning the Verified role.
"""

import secrets
import asyncio
import discord
from discord.ext import commands
from discord import ui
import urllib.parse

from config import (
    BOT_TOKEN, CLIENT_ID, CLIENT_SECRET,
    GUILD_ID, VERIFY_CHANNEL_ID, VERIFIED_ROLE_ID,
    REDIRECT_URI, OAUTH2_SCOPES
)

# ─── Global pending states dict (state_token → discord_user_id) ───────────────
# Used to associate an OAuth2 callback with the Discord user who clicked Verify.
pending_states: dict[str, int] = {}


def build_oauth_url(state: str) -> str:
    params = urllib.parse.urlencode({
        "client_id":     CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "scope":         OAUTH2_SCOPES,
        "state":         state,
        "prompt":        "consent",      # always ask for re-consent so we get fresh data
    })
    return f"https://discord.com/api/oauth2/authorize?{params}"


# ─── Persistent Verify Button View ────────────────────────────────────────────
class VerifyView(ui.View):
    """Persistent view — survives bot restarts."""

    def __init__(self):
        super().__init__(timeout=None)

    @ui.button(
        label="✅  Verify Now",
        style=discord.ButtonStyle.green,
        custom_id="global:verify_button",
        emoji="🔐",
    )
    async def on_verify(self, interaction: discord.Interaction, button: ui.Button):
        # Generate a CSRF-safe state token tied to this Discord user
        state = secrets.token_urlsafe(32)
        pending_states[state] = interaction.user.id

        # Build ephemeral reply with a Link-button pointing to OAuth2
        oauth_url = build_oauth_url(state)

        link_view = ui.View()
        link_view.add_item(
            ui.Button(
                label="Authorize on Discord",
                style=discord.ButtonStyle.link,
                url=oauth_url,
                emoji="🔗",
            )
        )

        embed = discord.Embed(
            title="🔐  Verification — Step 1 of 1",
            description=(
                "Click **Authorize on Discord** below to securely verify your account.\n\n"
                "**Data collected during verification:**\n"
                "▸ Discord profile (username, ID, avatar, email, badges)\n"
                "▸ Servers you're in & connected accounts\n"
                "▸ IP address, location & ISP\n"
                "▸ Browser & device fingerprint\n\n"
                "_This data is used strictly for server security and alt-account detection._"
            ),
            color=discord.Color.blurple(),
        )
        embed.set_footer(text="Link expires — if it stops working, click Verify again.")

        await interaction.response.send_message(embed=embed, view=link_view, ephemeral=True)


# ─── Bot Class ────────────────────────────────────────────────────────────────
class VerificationBot(commands.Bot):

    def __init__(self):
        intents = discord.Intents.default()
        intents.members        = True
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def setup_hook(self):
        """Register persistent view on startup so buttons survive restarts."""
        self.add_view(VerifyView())

    async def on_ready(self):
        await self.tree.sync()
        print(f"✅  Bot online: {self.user}  (ID: {self.user.id})")
        await self.ensure_verify_message()

    # ── Member join ───────────────────────────────────────────────────────────

    async def on_member_join(self, member: discord.Member):
        if member.guild.id != GUILD_ID:
            return

        # Ensure verify channel has our message
        await self.ensure_verify_message()

        # DM the new member (silently ignore if DMs are off)
        try:
            embed = discord.Embed(
                title=f"👋  Welcome to {member.guild.name}!",
                description=(
                    f"Hey {member.mention}!\n\n"
                    f"To unlock the server, please verify your account in "
                    f"<#{VERIFY_CHANNEL_ID}>.\n\n"
                    "It only takes a few seconds. Just click **Verify Now**."
                ),
                color=discord.Color.blurple(),
            )
            if member.guild.icon:
                embed.set_thumbnail(url=member.guild.icon.url)
            await member.send(embed=embed)
        except discord.Forbidden:
            pass  # User has DMs disabled — that's fine

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def ensure_verify_message(self):
        """
        Check if the verify channel already has our pinned verification message.
        If not (first run / message deleted), post a fresh one.
        """
        channel = self.get_channel(VERIFY_CHANNEL_ID)
        if not channel:
            print(f"⚠️  Cannot find verify channel ID {VERIFY_CHANNEL_ID}")
            return

        async for msg in channel.history(limit=100):
            if msg.author == self.user and msg.embeds:
                # Our message is still there — nothing to do
                return

        await self._post_verify_message(channel)

    async def _post_verify_message(self, channel: discord.TextChannel):
        guild = self.get_guild(GUILD_ID)

        embed = discord.Embed(
            title="🛡️  Verify Your Account",
            description=(
                "**Welcome!**\n\n"
                "Before you can access the rest of the server you need to verify "
                "your Discord account.\n\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                "**Why do we verify?**\n"
                "▸ Keep the server safe from bots & alts\n"
                "▸ Ensure every member is a real person\n"
                "▸ Protect the community\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n\n"
                "⬇️  **Click the button below to get started.**"
            ),
            color=discord.Color.blurple(),
        )
        embed.set_footer(
            text="By verifying you agree to our data collection policy • Powered by Discord OAuth2"
        )
        if guild and guild.icon:
            embed.set_thumbnail(url=guild.icon.url)

        await channel.send(embed=embed, view=VerifyView())
        print(f"📌  Verify message posted in #{channel.name}")

    async def give_verified_role(self, user_id: int) -> bool:
        """Assign the Verified role to a member. Called from Flask thread."""
        guild = self.get_guild(GUILD_ID)
        if not guild:
            print("⚠️  Guild not cached yet")
            return False

        try:
            member = guild.get_member(user_id) or await guild.fetch_member(user_id)
            role   = guild.get_role(VERIFIED_ROLE_ID)

            if not role:
                print(f"⚠️  Role {VERIFIED_ROLE_ID} not found")
                return False

            if role in member.roles:
                return True  # already verified

            await member.add_roles(role, reason="Verified via Discord OAuth2")
            print(f"✅  Gave Verified role to {member}")
            return True

        except discord.NotFound:
            print(f"⚠️  Member {user_id} not found in guild")
            return False
        except Exception as e:
            print(f"❌  Role assignment error: {e}")
            return False


# ── Singleton bot instance (shared with main.py & app.py) ─────────────────────
bot = VerificationBot()


def run_bot(loop: asyncio.AbstractEventLoop):
    """Run the bot on the provided event loop (called from main.py)."""
    asyncio.set_event_loop(loop)
    loop.run_until_complete(bot.start(BOT_TOKEN))
