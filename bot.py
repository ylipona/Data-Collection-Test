"""
bot.py — Discord bot component.

FLOW: Bot button links DIRECTLY to Discord OAuth2 (no intermediate page first).
      After Discord auth, /callback stores the Discord data and redirects to
      /collect?state=X which silently fingerprints then calls /finish.
"""

import secrets
import asyncio
import urllib.parse
import discord
from discord.ext import commands
from discord import ui

from config import BOT_TOKEN, GUILD_ID, VERIFY_CHANNEL_ID, VERIFIED_ROLE_ID, \
                   CLIENT_ID, REDIRECT_URI, OAUTH2_SCOPES


def build_oauth_url(state: str) -> str:
    """Direct link to Discord OAuth2 — user authorizes first, fingerprint collected after."""
    params = urllib.parse.urlencode({
        "client_id":     CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "scope":         OAUTH2_SCOPES,
        "state":         state,
        "prompt":        "consent",
    })
    return f"https://discord.com/api/oauth2/authorize?{params}"


class VerifyView(ui.View):
    """Persistent view — survives bot restarts."""

    def __init__(self):
        super().__init__(timeout=None)

    @ui.button(
        label="Verify Now",
        style=discord.ButtonStyle.green,
        custom_id="global:verify_button",
        emoji="🔐",
    )
    async def on_verify(self, interaction: discord.Interaction, button: ui.Button):
        state     = secrets.token_urlsafe(32)
        oauth_url = build_oauth_url(state)

        link_view = ui.View()
        link_view.add_item(
            ui.Button(
                label="Verify with Discord",
                style=discord.ButtonStyle.link,
                url=oauth_url,
                emoji="🔗",
            )
        )

        embed = discord.Embed(
            title="🔐  Verification",
            description="Click the button below to verify your account and unlock the server.",
            color=discord.Color.blurple(),
        )
        embed.set_footer(text="If the button stops working, click Verify Now again.")
        await interaction.response.send_message(embed=embed, view=link_view, ephemeral=True)


class VerificationBot(commands.Bot):

    def __init__(self):
        intents = discord.Intents.default()
        intents.members         = True
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents)

    async def setup_hook(self):
        self.add_view(VerifyView())

    async def on_ready(self):
        await self.tree.sync()
        print(f"✅  Bot online: {self.user}  (ID: {self.user.id})")
        await self.ensure_verify_message()

    async def on_member_join(self, member: discord.Member):
        if member.guild.id != GUILD_ID:
            return
        await self.ensure_verify_message()
        try:
            embed = discord.Embed(
                title=f"👋  Welcome to {member.guild.name}!",
                description=(
                    f"Hey {member.mention}!\n\n"
                    f"Head to <#{VERIFY_CHANNEL_ID}> and click **Verify Now** to unlock the server."
                ),
                color=discord.Color.blurple(),
            )
            if member.guild.icon:
                embed.set_thumbnail(url=member.guild.icon.url)
            await member.send(embed=embed)
        except discord.Forbidden:
            pass

    async def ensure_verify_message(self):
        channel = self.get_channel(VERIFY_CHANNEL_ID)
        if not channel:
            print(f"⚠️  Cannot find verify channel ID {VERIFY_CHANNEL_ID}")
            return
        async for msg in channel.history(limit=100):
            if msg.author == self.user and msg.embeds:
                return
        await self._post_verify_message(channel)

    async def _post_verify_message(self, channel: discord.TextChannel):
        guild = self.get_guild(GUILD_ID)
        embed = discord.Embed(
            title="🛡️  Verify Your Account",
            description=(
                "**Welcome!**\n\n"
                "Before you can access the rest of the server, "
                "please verify your Discord account.\n\n"
                "━━━━━━━━━━━━━━━━━━━━\n"
                "⬇️  **Click the button below to get started.**"
            ),
            color=discord.Color.blurple(),
        )
        embed.set_footer(text="Powered by Discord OAuth2")
        if guild and guild.icon:
            embed.set_thumbnail(url=guild.icon.url)
        await channel.send(embed=embed, view=VerifyView())
        print(f"📌  Verify message posted in #{channel.name}")

    async def give_verified_role(self, user_id: int) -> bool:
        guild = self.get_guild(GUILD_ID)
        if not guild:
            return False
        try:
            member = guild.get_member(user_id) or await guild.fetch_member(user_id)
            role   = guild.get_role(VERIFIED_ROLE_ID)
            if not role:
                print(f"⚠️  Role {VERIFIED_ROLE_ID} not found")
                return False
            if role in member.roles:
                return True
            await member.add_roles(role, reason="Verified via OAuth2")
            print(f"✅  Gave Verified role to {member}")
            return True
        except discord.NotFound:
            return False
        except Exception as e:
            print(f"❌  Role error: {e}")
            return False


bot = VerificationBot()


def run_bot(loop: asyncio.AbstractEventLoop):
    asyncio.set_event_loop(loop)
    loop.run_until_complete(bot.start(BOT_TOKEN))
