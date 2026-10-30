# AegisLock Sentinel — single-command Discord security bot
#
# Install:
#   pip install -U discord.py aiosqlite
#
# Environment:
#   DISCORD_TOKEN=your_bot_token
#   DATABASE_PATH=aegislock.db   (optional)
#
# Invite the bot with the following permissions:
#   View Channels, Send Messages, Manage Messages, Moderate Members,
#   Kick Members, Ban Members, Manage Roles, View Audit Log
#
# Enable these intents in the Discord Developer Portal:
#   Server Members Intent
#   Message Content Intent

import os
import re
import time
import asyncio
import logging
import unicodedata
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta

import aiosqlite
import discord
from discord.ext import commands


TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
DB_PATH = os.getenv("DATABASE_PATH", "aegislock.db")

BRAND = "AegisLock Sentinel"
GOLD = 0xD4AF37
RED = 0xE74C3C
FOOTER = f"{BRAND} | Security & Moderation"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("AegisLock")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def make_embed(title, description=None, color=GOLD):
    result = discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=discord.utils.utcnow(),
    )
    result.set_footer(text=FOOTER)
    return result


# All protections are controlled together by /aegis on and /aegis off.
MODULES = {
    "antinuke": "Anti-Nuke",
    "antiraid": "Anti-Raid",
    "antiswear": "Anti-Swear",
    "antispam": "Anti-Spam",
    "antilink": "Anti-Link",
    "antimention": "Anti-Mention",
    "roleprotection": "Role Protection Alerts",
    "channelprotection": "Channel Protection Alerts",
    "webhookprotection": "Webhook Protection Alerts",
}

DEFAULTS = {
    "antinuke": {"enabled": False, "punishment": "strip_roles"},
    "antiraid": {
        "enabled": False,
        "window": 10,
        "threshold": 8,
        "min_account_age_days": 7,
    },
    "antiswear": {"enabled": False},
    "antispam": {"enabled": False, "window": 5, "count": 6},
    "antilink": {"enabled": False, "mode": "phishing_only"},
    "antimention": {"enabled": False, "threshold": 5},
    "roleprotection": {"enabled": False},
    "channelprotection": {"enabled": False},
    "webhookprotection": {"enabled": False},
}


class Database:
    def __init__(self, path):
        self.path = path
        self.conn = None
        self.lock = asyncio.Lock()

    async def connect(self):
        self.conn = await aiosqlite.connect(self.path)
        self.conn.row_factory = aiosqlite.Row
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS guild_settings (
                guild_id INTEGER PRIMARY KEY,
                data TEXT NOT NULL
            )
            """
        )
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS whitelist (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (guild_id, user_id)
            )
            """
        )
        await self.conn.commit()

    async def get_settings(self, guild_id):
        async with self.lock:
            cursor = await self.conn.execute(
                "SELECT data FROM guild_settings WHERE guild_id = ?",
                (guild_id,),
            )
            row = await cursor.fetchone()
            await cursor.close()

        if not row:
            return {}
        try:
            import json
            return json.loads(row["data"])
        except (TypeError, ValueError):
            log.exception("Invalid settings JSON for guild %s", guild_id)
            return {}

    async def save_settings(self, guild_id, data):
        import json
        encoded = json.dumps(data)
        async with self.lock:
            await self.conn.execute(
                """
                INSERT INTO guild_settings (guild_id, data)
                VALUES (?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET data = excluded.data
                """,
                (guild_id, encoded),
            )
            await self.conn.commit()

    async def is_whitelisted(self, guild_id, user_id):
        async with self.lock:
            cursor = await self.conn.execute(
                "SELECT 1 FROM whitelist WHERE guild_id = ? AND user_id = ?",
                (guild_id, user_id),
            )
            row = await cursor.fetchone()
            await cursor.close()
        return row is not None

    async def close(self):
        if self.conn is not None:
            await self.conn.close()
            self.conn = None


def normalized_text(value):
    substitutions = str.maketrans({
        "0": "o", "1": "i", "3": "e", "4": "a",
        "5": "s", "7": "t", "@": "a", "$": "s", "!": "i",
    })
    value = unicodedata.normalize("NFKC", value or "")
    value = value.lower().translate(substitutions)
    value = re.sub(r"(.)\1{2,}", r"\1\1", value)
    return re.sub(r"[^\w\u0980-\u09ff]", "", value)


BAD_WORDS = {
    "fuck", "shit", "bitch", "asshole", "bastard", "dick", "pussy",
    "cunt", "slut", "whore", "motherfucker", "bullshit", "prick",
    "wanker", "twat", "মাদারচোদ", "চুদি", "চোদা", "খানকি", "মাগি",
    "গান্ডু", "গাণ্ডু", "বেশ্যা", "হারামজাদা", "হারামি", "madarchod",
    "maderchod", "chudi", "chuda", "choda", "khanki", "magi", "gandu",
    "beshya", "haramjada", "harami", "banchod", "bokachoda", "chodna",
}
BAD_WORDS_NORMALIZED = {normalized_text(word) for word in BAD_WORDS}


def contains_bad_word(content):
    compact = normalized_text(content)
    return any(
        len(word) > 2 and word in compact
        for word in BAD_WORDS_NORMALIZED
    )


def is_admin(member):
    permissions = member.guild_permissions
    return (
        member.id == member.guild.owner_id
        or permissions.administrator
        or permissions.manage_guild
    )


class AegisBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        # This intent is available in current discord.py 2.x releases.
        if hasattr(intents, "moderation"):
            intents.moderation = True

        super().__init__(
            command_prefix=commands.when_mentioned_or("!"),
            intents=intents,
            help_command=None,
            case_insensitive=True,
            allowed_mentions=discord.AllowedMentions.none(),
        )

        self.db = Database(DB_PATH)
        self.spam_messages = defaultdict(deque)
        self.join_events = defaultdict(deque)
        self.nuke_events = defaultdict(deque)
        self.nuke_lock = asyncio.Lock()

    async def setup_hook(self):
        await self.db.connect()
        try:
            synced = await self.tree.sync()
            log.info("Synced %d slash command(s)", len(synced))
        except discord.HTTPException:
            log.exception("Could not sync slash commands")

    async def on_ready(self):
        log.info("Logged in as %s (%s)", self.user, self.user.id)
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name="server security | /aegis",
            )
        )

    async def close(self):
        await self.db.close()
        await super().close()


bot = AegisBot()


async def get_guild_settings(guild_id):
    stored = await bot.db.get_settings(guild_id)
    merged = {}
    for key, defaults in DEFAULTS.items():
        merged[key] = {**defaults, **stored.get(key, {})}
    merged["security_log_channel"] = stored.get("security_log_channel")
    return merged


async def save_guild_settings(guild_id, settings):
    await bot.db.save_settings(guild_id, settings)


async def send_security_log(guild, message_embed):
    settings = await bot.db.get_settings(guild.id)
    channel_id = settings.get("security_log_channel")
    if not channel_id:
        return

    channel = guild.get_channel(channel_id)
    if channel is None:
        return

    try:
        await channel.send(embed=message_embed)
    except discord.HTTPException:
        log.warning("Could not send security log in guild %s", guild.id)


async def is_trusted(guild, user):
    if user.id == guild.owner_id:
        return True
    if bot.user and user.id == bot.user.id:
        return True
    if await bot.db.is_whitelisted(guild.id, user.id):
        return True
    if user.bot:
        return True
    try:
        return await bot.is_owner(user)
    except discord.HTTPException:
        return False


async def reply(ctx, content=None, *, embed=None, ephemeral=False):
    try:
        if ctx.interaction:
            if ctx.interaction.response.is_done():
                return await ctx.interaction.followup.send(
                    content=content, embed=embed, ephemeral=ephemeral
                )
            return await ctx.interaction.response.send_message(
                content=content, embed=embed, ephemeral=ephemeral
            )
        return await ctx.reply(
            content=content,
            embed=embed,
            mention_author=False,
        )
    except discord.HTTPException:
        log.exception("Could not send command response")


# THE ONLY COMMAND:
# /aegis on
# /aegis off
# /aegis status
# /aegis log #channel
@bot.hybrid_command(
    name="aegis",
    description="Turn all AegisLock protections on/off, view status, or set logs.",
)
@commands.guild_only()
async def aegis(
    ctx,
    action: str = "status",
    channel: discord.TextChannel = None,
):
    if not isinstance(ctx.author, discord.Member) or not is_admin(ctx.author):
        return await reply(
            ctx,
            "You need Administrator or Manage Server permission to use this command.",
            ephemeral=True,
        )

    action = action.lower().strip()
    settings = await get_guild_settings(ctx.guild.id)

    if action == "on":
        for module in MODULES:
            settings[module]["enabled"] = True
        await save_guild_settings(ctx.guild.id, settings)
        result = make_embed(
            "AegisLock Enabled",
            "All security protections are now **ON**.\n"
            "Use `/aegis status` to check them.",
            0x2ECC71,
        )
        await send_security_log(ctx.guild, result)
        return await reply(ctx, embed=result)

    if action == "off":
        for module in MODULES:
            settings[module]["enabled"] = False
        await save_guild_settings(ctx.guild.id, settings)
        result = make_embed(
            "AegisLock Disabled",
            "All automated security protections are now **OFF**.",
            RED,
        )
        await send_security_log(ctx.guild, result)
        return await reply(ctx, embed=result)

    if action == "status":
        lines = [
            f"**{label}:** {'ON' if settings[key]['enabled'] else 'OFF'}"
            for key, label in MODULES.items()
        ]
        log_channel = settings.get("security_log_channel")
        lines.append(
            f"**Security log:** <#{log_channel}>" if log_channel else
            "**Security log:** Not configured"
        )
        return await reply(
            ctx,
            embed=make_embed("AegisLock Status", "\n".join(lines)),
        )

    if action == "log":
        if channel is None:
            return await reply(
                ctx,
                "Usage: `/aegis log #channel`",
                ephemeral=True,
            )
        settings["security_log_channel"] = channel.id
        await save_guild_settings(ctx.guild.id, settings)
        return await reply(
            ctx,
            embed=make_embed(
                "Security Log Configured",
                f"Security alerts will be sent to {channel.mention}.",
            ),
        )

    return await reply(
        ctx,
        "Use `/aegis on`, `/aegis off`, `/aegis status`, or `/aegis log #channel`.",
        ephemeral=True,
    )


# Anti-spam, anti-swear, anti-link and anti-mention.
@bot.event
async def on_message(message):
    if message.guild is None or message.author.bot:
        return await bot.process_commands(message)

    if not isinstance(message.author, discord.Member):
        return await bot.process_commands(message)

    member = message.author
    guild = message.guild

    if is_admin(member) or await is_trusted(guild, member):
        return await bot.process_commands(message)

    settings = await get_guild_settings(guild.id)
    violation_name = None
    reason = ""

    if settings["antiswear"]["enabled"] and contains_bad_word(message.content):
        violation_name = "Anti-Swear"
        reason = "Prohibited language"

    if violation_name is None and settings["antilink"]["enabled"]:
        urls = re.findall(
            r"(?:https?://|www\.)[^\s]+|"
            r"\b[\w.-]+\.(?:com|net|org|gg|io)\b",
            message.content,
            re.IGNORECASE,
        )
        suspicious_domains = (
            "discord-gifts.com",
            "discordnitro.com",
            "dlscord.com",
            "steamcommunlty.com",
        )
        mode = settings["antilink"].get("mode", "phishing_only")
        if urls and (
            mode == "block_all"
            or any(
                domain in url.lower()
                for url in urls
                for domain in suspicious_domains
            )
        ):
            violation_name = "Anti-Link"
            reason = "Link policy violation"

    if violation_name is None and settings["antimention"]["enabled"]:
        mention_count = len(message.mentions) + len(message.role_mentions)
        threshold = int(settings["antimention"].get("threshold", 5))
        if mention_count > threshold:
            violation_name = "Anti-Mention"
            reason = f"{mention_count} mentions in one message"

    if violation_name is None and settings["antispam"]["enabled"]:
        key = (guild.id, member.id)
        now = time.monotonic()
        queue = bot.spam_messages[key]
        window = int(settings["antispam"].get("window", 5))
        count_limit = int(settings["antispam"].get("count", 6))

        while queue and now - queue[0] > window:
            queue.popleft()
        queue.append(now)

        if len(queue) >= count_limit:
            queue.clear()
            violation_name = "Anti-Spam"
            reason = f"Too many messages within {window} seconds"

    if violation_name:
        try:
            await message.delete()
        except discord.Forbidden:
            log.warning("Missing Manage Messages permission in guild %s", guild.id)
        except discord.HTTPException:
            pass

        if violation_name == "Anti-Spam":
            try:
                await member.timeout(
                    discord.utils.utcnow() + timedelta(seconds=60),
                    reason="AegisLock anti-spam",
                )
            except (discord.Forbidden, discord.HTTPException):
                pass

        try:
            await message.channel.send(
                f"{member.mention}, your message was removed by server security.",
                delete_after=5,
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            pass

        await send_security_log(
            guild,
            make_embed(
                f"{violation_name} Triggered",
                f"User: {member} (`{member.id}`)\nReason: {reason}",
                RED,
            ),
        )

    await bot.process_commands(message)


# Anti-raid and blacklist-free join monitoring.
@bot.event
async def on_member_join(member):
    settings = await get_guild_settings(member.guild.id)
    config = settings["antiraid"]

    if not config["enabled"]:
        return

    queue = bot.join_events[member.guild.id]
    now = time.monotonic()
    window = int(config.get("window", 10))

    while queue and now - queue[0] > window:
        queue.popleft()
    queue.append(now)

    join_threshold = int(config.get("threshold", 8))
    minimum_age = int(config.get("min_account_age_days", 7))
    account_age_days = (discord.utils.utcnow() - member.created_at).days

    if len(queue) >= join_threshold and account_age_days < minimum_age:
        try:
            await member.kick(
                reason="AegisLock anti-raid: suspicious new-account join burst"
            )
            outcome = "Suspicious new account was kicked."
        except (discord.Forbidden, discord.HTTPException):
            outcome = "Raid detected, but the bot could not kick the member."

        await send_security_log(
            member.guild,
            make_embed(
                "Anti-Raid Triggered",
                f"Join burst detected.\nMember: {member}\n{outcome}",
                RED,
            ),
        )


# Role, channel and webhook protection alerts.
@bot.event
async def on_guild_role_delete(role):
    settings = await get_guild_settings(role.guild.id)
    if settings["roleprotection"]["enabled"]:
        await send_security_log(
            role.guild,
            make_embed("Role Deleted", f"Role `{role.name}` was deleted.", RED),
        )


@bot.event
async def on_guild_role_update(before, after):
    settings = await get_guild_settings(after.guild.id)
    if (
        settings["roleprotection"]["enabled"]
        and before.permissions != after.permissions
    ):
        await send_security_log(
            after.guild,
            make_embed(
                "Role Permissions Changed",
                f"Permissions changed for `{after.name}`.",
                RED,
            ),
        )


@bot.event
async def on_guild_channel_delete(channel):
    settings = await get_guild_settings(channel.guild.id)
    if settings["channelprotection"]["enabled"]:
        await send_security_log(
            channel.guild,
            make_embed("Channel Deleted", f"`{channel.name}` was deleted.", RED),
        )


@bot.event
async def on_guild_channel_update(before, after):
    settings = await get_guild_settings(after.guild.id)
    if (
        settings["channelprotection"]["enabled"]
        and before.overwrites != after.overwrites
    ):
        await send_security_log(
            after.guild,
            make_embed(
                "Channel Permissions Changed",
                f"Permission overwrites changed in {after.mention}.",
                RED,
            ),
        )


@bot.event
async def on_webhooks_update(channel):
    settings = await get_guild_settings(channel.guild.id)
    if settings["webhookprotection"]["enabled"]:
        await send_security_log(
            channel.guild,
            make_embed(
                "Webhook Updated",
                f"Webhook list changed in {channel.mention}.",
                RED,
            ),
        )


# Anti-nuke audit-log monitoring.
NUKE_ACTIONS = {
    discord.AuditLogAction.ban: ("ban", 3),
    discord.AuditLogAction.kick: ("kick", 3),
    discord.AuditLogAction.channel_delete: ("channel delete", 2),
    discord.AuditLogAction.role_delete: ("role delete", 2),
    discord.AuditLogAction.channel_create: ("channel create", 3),
    discord.AuditLogAction.role_create: ("role create", 3),
    discord.AuditLogAction.webhook_create: ("webhook create", 3),
}
NUKE_WINDOW_SECONDS = 10


@bot.event
async def on_audit_log_entry_create(entry):
    guild = entry.guild
    if guild is None or entry.action not in NUKE_ACTIONS or entry.user is None:
        return

    settings = await get_guild_settings(guild.id)
    config = settings["antinuke"]

    if not config["enabled"] or await is_trusted(guild, entry.user):
        return

    action_name, limit = NUKE_ACTIONS[entry.action]
    key = (guild.id, entry.user.id, action_name)
    now = time.monotonic()

    async with bot.nuke_lock:
        queue = bot.nuke_events[key]
        while queue and now - queue[0] > NUKE_WINDOW_SECONDS:
            queue.popleft()
        queue.append(now)
        event_count = len(queue)

        if event_count < limit:
            return
        queue.clear()

    member = guild.get_member(entry.user.id)
    punishment = config.get("punishment", "strip_roles")
    result = "Actor not found in server; alert only."

    try:
        if member is not None and member.id != guild.owner_id:
            if punishment == "ban":
                await guild.ban(member, reason="AegisLock anti-nuke")
                result = "Actor banned"
            elif punishment == "kick":
                await member.kick(reason="AegisLock anti-nuke")
                result = "Actor kicked"
            else:
                bot_member = guild.me
                if bot_member is None:
                    result = "Could not identify the bot's server member."
                else:
                    roles = [
                        role for role in member.roles
                        if role != guild.default_role
                        and not role.managed
                        and role < bot_member.top_role
                    ]
                    if roles:
                        await member.remove_roles(
                            *roles,
                            reason="AegisLock anti-nuke",
                        )
                    result = "Actor roles stripped"
    except (discord.Forbidden, discord.HTTPException):
        result = "Action failed: check bot permissions and role hierarchy."

    await send_security_log(
        guild,
        make_embed(
            "Anti-Nuke Triggered",
            f"Actor: {entry.user} (`{entry.user.id}`)\n"
            f"Action burst: {action_name} ({event_count} events)\n"
            f"Response: {result}",
            RED,
        ),
    )


@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.NoPrivateMessage):
        message = "Use this command inside a server."
    elif isinstance(error, commands.MissingPermissions):
        message = "You do not have permission to use this command."
    elif isinstance(error, commands.BadArgument):
        message = "Invalid argument. Check the command usage."
    else:
        log.exception(
            "Command failed",
            exc_info=(type(error), error, error.__traceback__),
        )
        message = "An unexpected error occurred. Check the bot logs."

    await reply(ctx, embed=make_embed(BRAND, message, RED), ephemeral=True)


@bot.tree.error
async def on_app_command_error(interaction, error):
    log.error("Slash command failed: %s", error)
    if isinstance(error, discord.app_commands.MissingPermissions):
        message = "You do not have permission to use this command."
    else:
        message = "An unexpected error occurred. Check the bot logs."

    try:
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except discord.HTTPException:
        log.exception("Could not send slash-command error response")


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit(
            "Missing DISCORD_TOKEN. Add it to your environment variables."
        )
    bot.run(TOKEN)
