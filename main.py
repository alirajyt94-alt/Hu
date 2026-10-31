"""
AegisLock Sentinel — Discord security and moderation bot.
Install: pip install -U discord.py aiosqlite
Environment: DISCORD_TOKEN=your_bot_token
Optional: DATABASE_PATH=aegislock.db PREFIX=!
Enable Server Members and Message Content intents in the Discord Developer Portal.
Invite with: Manage Messages, Moderate Members, Kick Members, Ban Members,
Manage Roles, Manage Channels, View Audit Log, View Channels, Send Messages.
Use an official Discord bot token. Self-bots/user-account tokens are not supported.
"""
import os
import re
import json
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
PREFIX = os.getenv("PREFIX", "!")
BRAND = "AegisLock Sentinel"
GOLD, RED, GREEN = 0xD4AF37, 0xE74C3C, 0x2ECC71

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("AegisLock")

MODULES = {
    "antinuke": "Anti-Nuke", "antiraid": "Anti-Raid",
    "antiswear": "Anti-Swear", "antispam": "Anti-Spam",
    "antilink": "Anti-Link", "antimention": "Anti-Mention",
    "roleprotection": "Role Protection", "channelprotection": "Channel Protection",
    "webhookprotection": "Webhook Protection",
}
DEFAULTS = {
    "antinuke": {"enabled": False, "punishment": "strip_roles"},
    "antiraid": {"enabled": False, "window": 10, "threshold": 8, "min_account_age_days": 7},
    "antiswear": {"enabled": False},
    "antispam": {"enabled": False, "window": 5, "count": 6},
    "antilink": {"enabled": False, "mode": "phishing_only"},
    "antimention": {"enabled": False, "threshold": 5},
    "roleprotection": {"enabled": False},
    "channelprotection": {"enabled": False},
    "webhookprotection": {"enabled": False},
}
BAD_WORDS = {
    "fuck", "shit", "bitch", "asshole", "bastard", "dick", "pussy", "cunt",
    "slut", "whore", "motherfucker", "bullshit", "prick", "wanker", "twat",
    "মাদারচোদ", "চুদি", "চোদা", "খানকি", "মাগি", "গান্ডু", "গাণ্ডু", "বেশ্যা",
    "হারামজাদা", "হারামি", "madarchod", "maderchod", "chudi", "chuda", "choda",
    "khanki", "magi", "gandu", "beshya", "haramjada", "harami", "banchod",
    "bokachoda", "chodna",
}
TRANS = str.maketrans({"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","@":"a","$":"s","!":"i"})

def norm(value):
    value = unicodedata.normalize("NFKC", value or "").lower().translate(TRANS)
    value = re.sub(r"(.)\1{2,}", r"\1\1", value)
    return re.sub(r"[^\w\u0980-\u09ff]", "", value)

BAD_NORMALIZED = {norm(w) for w in BAD_WORDS}

def contains_bad_word(content):
    compact = norm(content)
    return any(len(w) > 2 and w in compact for w in BAD_NORMALIZED)

def make_embed(title, description=None, color=GOLD):
    e = discord.Embed(title=title, description=description, color=color,
                      timestamp=discord.utils.utcnow())
    e.set_footer(text=f"{BRAND} | Security & Moderation")
    return e

class Database:
    def __init__(self, path):
        self.path, self.conn, self.lock = path, None, asyncio.Lock()

    async def connect(self):
        self.conn = await aiosqlite.connect(self.path)
        self.conn.row_factory = aiosqlite.Row
        await self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS settings(guild INTEGER PRIMARY KEY, data TEXT NOT NULL DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS whitelist(guild INTEGER, user INTEGER, by_user INTEGER, at TEXT, PRIMARY KEY(guild,user));
        CREATE TABLE IF NOT EXISTS trusted_bots(guild INTEGER, user INTEGER, by_user INTEGER, at TEXT, PRIMARY KEY(guild,user));
        CREATE TABLE IF NOT EXISTS blacklist(guild INTEGER, user INTEGER, reason TEXT, by_user INTEGER, at TEXT, PRIMARY KEY(guild,user));
        CREATE TABLE IF NOT EXISTS warnings(id INTEGER PRIMARY KEY AUTOINCREMENT, guild INTEGER, user INTEGER, moderator INTEGER, reason TEXT, at TEXT);
        """)
        await self.conn.commit()

    async def run(self, sql, args=(), fetch=None):
        async with self.lock:
            cur = await self.conn.execute(sql, args)
            result = await cur.fetchone() if fetch == "one" else await cur.fetchall() if fetch == "all" else cur.rowcount
            await self.conn.commit()
            await cur.close()
            return result

    async def settings(self, guild_id):
        row = await self.run("SELECT data FROM settings WHERE guild=?", (guild_id,), "one")
        try:
            return json.loads(row["data"]) if row else {}
        except (ValueError, TypeError):
            return {}

    async def save_settings(self, guild_id, data):
        await self.run("""INSERT INTO settings(guild,data) VALUES(?,?)
        ON CONFLICT(guild) DO UPDATE SET data=excluded.data""",
        (guild_id, json.dumps(data)))

    async def close(self):
        if self.conn:
            await self.conn.close()
            self.conn = None

def is_admin(member):
    p = member.guild_permissions
    return member.id == member.guild.owner_id or p.administrator or p.manage_guild

def is_moderator(member):
    p = member.guild_permissions
    return is_admin(member) or p.kick_members or p.ban_members or p.moderate_members

def admin_only():
    async def predicate(ctx):
        if not ctx.guild or not isinstance(ctx.author, discord.Member) or not is_admin(ctx.author):
            raise commands.MissingPermissions(["manage_guild"])
        return True
    return commands.check(predicate)

def mod_only():
    async def predicate(ctx):
        if not ctx.guild or not isinstance(ctx.author, discord.Member) or not is_moderator(ctx.author):
            raise commands.MissingPermissions(["moderate_members"])
        return True
    return commands.check(predicate)

def can_act(ctx, member):
    me = ctx.guild.me
    return (member.id != ctx.guild.owner_id and member.id != ctx.author.id
            and (ctx.author.id == ctx.guild.owner_id or ctx.author.top_role > member.top_role)
            and me and me.top_role > member.top_role)

class AegisBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        if hasattr(intents, "moderation"):
            intents.moderation = True
        super().__init__(command_prefix=commands.when_mentioned_or(PREFIX),
                         intents=intents, help_command=None, case_insensitive=True,
                         allowed_mentions=discord.AllowedMentions.none())
        self.db = Database(DB_PATH)
        self.spam = defaultdict(deque)
        self.joins = defaultdict(deque)
        self.nuke = defaultdict(deque)
        self.nuke_lock = asyncio.Lock()

    async def setup_hook(self):
        await self.db.connect()
        try:
            synced = await self.tree.sync()
            log.info("Synced %d slash commands", len(synced))
        except discord.HTTPException:
            log.exception("Slash command sync failed")

    async def on_ready(self):
        log.info("Online as %s (%s)", self.user, self.user.id)
        await self.change_presence(activity=discord.Activity(
            type=discord.ActivityType.watching, name="server security | /help"))

    async def close(self):
        await self.db.close()
        await super().close()

bot = AegisBot()

async def settings_for(guild_id):
    stored = await bot.db.settings(guild_id)
    merged = {k: {**v, **stored.get(k, {})} for k, v in DEFAULTS.items()}
    for k in ("security_log_channel", "messagelock", "lockdown", "lockdown_previous", "welcome_system"):
        if k in stored:
            merged[k] = stored[k]
    return merged

async def save_settings(guild_id, data):
    await bot.db.save_settings(guild_id, data)

async def log_event(guild, e):
    data = await bot.db.settings(guild.id)
    channel = guild.get_channel(data.get("security_log_channel", 0))
    if channel:
        try:
            await channel.send(embed=e)
        except discord.HTTPException:
            log.warning("Could not send security log in %s", guild.id)

async def trusted(guild, user):
    if user.id == guild.owner_id or (bot.user and user.id == bot.user.id):
        return True
    if await bot.is_owner(user):
        return True
    table = "trusted_bots" if user.bot else "whitelist"
    return bool(await bot.db.run(f"SELECT 1 FROM {table} WHERE guild=? AND user=?",
                                 (guild.id, user.id), "one"))

async def safe_reply(ctx, content=None, *, embed=None, ephemeral=False):
    try:
        if ctx.interaction:
            if ctx.interaction.response.is_done():
                return await ctx.interaction.followup.send(content=content, embed=embed, ephemeral=ephemeral)
            return await ctx.interaction.response.send_message(content=content, embed=embed, ephemeral=ephemeral)
        return await ctx.reply(content=content, embed=embed, mention_author=False)
    except discord.HTTPException:
        log.exception("Could not send command response")

@bot.hybrid_command(name="help", description="Show all AegisLock commands.")
async def help_cmd(ctx):
    e = make_embed(BRAND, "Security, anti-abuse, server setup and moderation.")
    e.add_field(name="Security", value="/serverguard • /status • /antinuke • /antiraid • /antiswear • /antispam • /antilink • /antimention • /roleprotection • /channelprotection • /webhookprotection", inline=False)
    e.add_field(name="Server Control", value="/messagelock • /securitylog • /lockdown • /whitelist • /blacklist • /welcomesetup", inline=False)
    e.add_field(name="Moderation", value="/warn • /warnings • /kick • /ban • /unban • /timeout • /clear • /dm", inline=False)
    await safe_reply(ctx, embed=e)

@bot.hybrid_command(name="status", description="Show all protection statuses.")
@commands.guild_only()
async def status_cmd(ctx):
    s = await settings_for(ctx.guild.id)
    e = make_embed("AegisLock Status")
    for key, label in MODULES.items():
        e.add_field(name=label, value="ON" if s[key]["enabled"] else "OFF", inline=True)
    e.add_field(name="Message Lock", value="ON" if s.get("messagelock", {}).get("enabled") else "OFF", inline=True)
    e.add_field(name="Lockdown", value="ON" if s.get("lockdown") else "OFF", inline=True)
    ch = ctx.guild.get_channel(s.get("security_log_channel") or 0)
    e.add_field(name="Security Log", value=ch.mention if ch else "Not configured", inline=False)
    await safe_reply(ctx, embed=e)

def make_module_command(name, label):
    async def command(ctx, action: str = "on"):
        s = await settings_for(ctx.guild.id)
        action = action.lower()
        if action in ("on", "enable"):
            s[name]["enabled"] = True
        elif action in ("off", "disable"):
            s[name]["enabled"] = False
        elif action == "info":
            return await safe_reply(ctx, embed=make_embed(label, f"Enabled: **{s[name]['enabled']}**\nSettings: `{s[name]}`"))
        else:
            return await safe_reply(ctx, "Use `on`, `off`, or `info`.")
        await save_settings(ctx.guild.id, s)
        await safe_reply(ctx, embed=make_embed(label, f"Protection is now **{'ON' if s[name]['enabled'] else 'OFF'}**.",
                                               GREEN if s[name]["enabled"] else RED))
    command.__name__ = f"{name}_command"
    bot.add_command(admin_only()(commands.hybrid_command(name=name, description=f"Configure {label}.")(command)))

for module_name, module_label in MODULES.items():
    make_module_command(module_name, module_label)

@bot.hybrid_command(name="serverguard", description="Enable every AegisLock security module.")
@commands.guild_only()
@admin_only()
async def serverguard(ctx):
    s = await settings_for(ctx.guild.id)
    for key in MODULES:
        s[key]["enabled"] = True
    await save_settings(ctx.guild.id, s)
    await safe_reply(ctx, embed=make_embed("ServerGuard Activated", "All security modules are now enabled.", GREEN))
    await log_event(ctx.guild, make_embed("ServerGuard Activated", f"Configured by {ctx.author}"))

@bot.hybrid_command(name="securitylog", description="Set or clear the security log channel.")
@commands.guild_only()
@admin_only()
async def securitylog(ctx, action: str = "info", channel: discord.TextChannel = None):
    s = await bot.db.settings(ctx.guild.id)
    action = action.lower()
    if action in ("set", "setchannel", "log"):
        if channel is None:
            return await safe_reply(ctx, "Usage: `/securitylog set #channel`", ephemeral=True)
        s["security_log_channel"] = channel.id
        await save_settings(ctx.guild.id, s)
        return await safe_reply(ctx, embed=make_embed("Security Log Configured", channel.mention, GREEN))
    if action == "clear":
        s.pop("security_log_channel", None)
        await save_settings(ctx.guild.id, s)
        return await safe_reply(ctx, "Security log cleared.")
    ch = ctx.guild.get_channel(s.get("security_log_channel", 0))
    await safe_reply(ctx, embed=make_embed("Security Log", ch.mention if ch else "Not configured."))

@bot.hybrid_command(name="whitelist", description="Manage trusted users and approved bots.")
@commands.guild_only()
@admin_only()
async def whitelist(ctx, action: str, user: discord.User = None):
    action = action.lower()
    if action in ("add", "remove") and user is None:
        return await safe_reply(ctx, "Specify a user.", ephemeral=True)
    table = "trusted_bots" if user and user.bot else "whitelist"
    if action == "add":
        await bot.db.run(f"INSERT OR REPLACE INTO {table} VALUES(?,?,?,?)",
                         (ctx.guild.id, user.id, ctx.author.id, datetime.now(timezone.utc).isoformat()))
        return await safe_reply(ctx, f"Added {user} to trusted list.")
    if action == "remove":
        n = await bot.db.run(f"DELETE FROM {table} WHERE guild=? AND user=?", (ctx.guild.id, user.id))
        return await safe_reply(ctx, "Removed." if n else "Entry not found.")
    if action == "list":
        users = await bot.db.run("SELECT user FROM whitelist WHERE guild=?", (ctx.guild.id,), "all")
        bots = await bot.db.run("SELECT user FROM trusted_bots WHERE guild=?", (ctx.guild.id,), "all")
        e = make_embed("Trusted Entries")
        e.add_field(name="Users", value="\n".join(f"<@{r['user']}>" for r in users[:25]) or "None", inline=False)
        e.add_field(name="Bots", value="\n".join(f"<@{r['user']}>" for r in bots[:25]) or "None", inline=False)
        return await safe_reply(ctx, embed=e)
    await safe_reply(ctx, "Use add, remove, or list.")

@bot.hybrid_command(name="blacklist", description="Manage users automatically banned on join.")
@commands.guild_only()
@admin_only()
async def blacklist(ctx, action: str, user: discord.User = None, *, reason: str = "No reason provided"):
    action = action.lower()
    if action in ("add", "remove") and user is None:
        return await safe_reply(ctx, "Specify a user.")
    if action == "add":
        await bot.db.run("INSERT OR REPLACE INTO blacklist VALUES(?,?,?,?,?)",
                         (ctx.guild.id, user.id, reason, ctx.author.id, datetime.now(timezone.utc).isoformat()))
        return await safe_reply(ctx, f"Blacklisted {user}.")
    if action == "remove":
        n = await bot.db.run("DELETE FROM blacklist WHERE guild=? AND user=?", (ctx.guild.id, user.id))
        return await safe_reply(ctx, "Removed." if n else "Not found.")
    if action == "list":
        rows = await bot.db.run("SELECT user,reason FROM blacklist WHERE guild=?", (ctx.guild.id,), "all")
        return await safe_reply(ctx, embed=make_embed("Blacklist", "\n".join(f"<@{r['user']}> — {r['reason']}" for r in rows[:40]) or "Empty"))
    await safe_reply(ctx, "Use add, remove, or list.")

@bot.hybrid_command(name="messagelock", description="Enable or disable server-wide message lock.")
@commands.guild_only()
@admin_only()
async def messagelock(ctx, action: str, allow_owner: bool = True, allow_bots: bool = False):
    s = await bot.db.settings(ctx.guild.id)
    old = s.get("messagelock", {"enabled": False, "allow_owner": True, "allow_bots": False})
    if action.lower() == "on":
        s["messagelock"] = {"enabled": True, "allow_owner": allow_owner, "allow_bots": allow_bots}
    elif action.lower() == "off":
        old["enabled"] = False
        s["messagelock"] = old
    else:
        return await safe_reply(ctx, embed=make_embed("Message Lock", f"Enabled: {old.get('enabled', False)}"))
    await save_settings(ctx.guild.id, s)
    await safe_reply(ctx, embed=make_embed("Message Lock Updated", f"Enabled: {s['messagelock']['enabled']}", GREEN))

@bot.hybrid_command(name="lockdown", description="Lock or unlock all text channels.")
@commands.guild_only()
@admin_only()
async def lockdown(ctx, action: str = "info"):
    s = await bot.db.settings(ctx.guild.id)
    if action == "info":
        return await safe_reply(ctx, embed=make_embed("Lockdown", "ACTIVE" if s.get("lockdown") else "Inactive"))
    if action == "on":
        if s.get("lockdown"):
            return await safe_reply(ctx, "Lockdown is already active.")
        previous, changed = {}, 0
        for ch in ctx.guild.text_channels:
            ow = ch.overwrites_for(ctx.guild.default_role)
            previous[str(ch.id)] = ow.send_messages
            if ow.send_messages is not False:
                ow.send_messages = False
                try:
                    await ch.set_permissions(ctx.guild.default_role, overwrite=ow, reason="AegisLock lockdown")
                    changed += 1
                except discord.HTTPException:
                    pass
        s["lockdown_previous"], s["lockdown"] = previous, True
        await save_settings(ctx.guild.id, s)
        await log_event(ctx.guild, make_embed("Lockdown Enabled", f"Locked {changed} channels.", RED))
        return await safe_reply(ctx, embed=make_embed("Lockdown Enabled", f"Locked {changed} channels.", RED))
    if action == "off":
        if not s.get("lockdown"):
            return await safe_reply(ctx, "No active lockdown.")
        restored = 0
        for ch in ctx.guild.text_channels:
            key = str(ch.id)
            if key not in s.get("lockdown_previous", {}):
                continue
            ow = ch.overwrites_for(ctx.guild.default_role)
            ow.send_messages = s["lockdown_previous"][key]
            try:
                await ch.set_permissions(ctx.guild.default_role, overwrite=ow, reason="AegisLock lockdown release")
                restored += 1
            except discord.HTTPException:
                pass
        s["lockdown"], s["lockdown_previous"] = False, {}
        await save_settings(ctx.guild.id, s)
        await log_event(ctx.guild, make_embed("Lockdown Released", f"Restored {restored} channels.", GREEN))
        return await safe_reply(ctx, embed=make_embed("Lockdown Released", f"Restored {restored} channels.", GREEN))
    await safe_reply(ctx, "Use on, off, or info.")

@bot.hybrid_command(name="welcomesetup", description="Configure welcome channel and message; omit channel to disable.")
@commands.guild_only()
@admin_only()
async def welcomesetup(ctx, channel: discord.TextChannel = None, *, custom_message: str = "Welcome {user} to {server}!"):
    s = await bot.db.settings(ctx.guild.id)
    if channel is None:
        s.pop("welcome_system", None)
        await save_settings(ctx.guild.id, s)
        return await safe_reply(ctx, "Welcome system disabled.")
    s["welcome_system"] = {"channel_id": channel.id, "message": custom_message}
    await save_settings(ctx.guild.id, s)
    await safe_reply(ctx, embed=make_embed("Welcome Configured", f"Channel: {channel.mention}\nPlaceholders: `{{user}}`, `{{server}}`"))

@bot.hybrid_command(name="dm", description="Send a direct message to a user.")
@commands.guild_only()
@mod_only()
async def dm_cmd(ctx, user: discord.User, *, message: str):
    try:
        await user.send(embed=make_embed(f"Message from {ctx.guild.name}", message))
        await safe_reply(ctx, "DM sent.", ephemeral=True)
    except discord.HTTPException:
        await safe_reply(ctx, "Could not send DM; the user's DMs may be closed.", ephemeral=True)

@bot.hybrid_command(name="warn", description="Warn a member.")
@commands.guild_only()
@mod_only()
async def warn(ctx, member: discord.Member, *, reason: str = "No reason provided"):
    if not can_act(ctx, member):
        return await safe_reply(ctx, "Role hierarchy prevents this action.", ephemeral=True)
    await bot.db.run("INSERT INTO warnings(guild,user,moderator,reason,at) VALUES(?,?,?,?,?)",
                     (ctx.guild.id, member.id, ctx.author.id, reason, datetime.now(timezone.utc).isoformat()))
    rows = await bot.db.run("SELECT id FROM warnings WHERE guild=? AND user=?", (ctx.guild.id, member.id), "all")
    try:
        await member.send(f"You were warned in **{ctx.guild.name}**: {reason}")
    except discord.HTTPException:
        pass
    await safe_reply(ctx, embed=make_embed("Member Warned", f"{member.mention}\nWarnings: {len(rows)}\nReason: {reason}"))

@bot.hybrid_command(name="warnings", description="View a member's warnings.")
@commands.guild_only()
@mod_only()
async def warnings(ctx, member: discord.Member):
    rows = await bot.db.run("SELECT * FROM warnings WHERE guild=? AND user=? ORDER BY id DESC",
                            (ctx.guild.id, member.id), "all")
    text = "\n".join(f"#{r['id']} — {r['reason']} (by <@{r['moderator']}>)" for r in rows[:15]) or "No warnings."
    await safe_reply(ctx, embed=make_embed(f"Warnings: {member}", text))

@bot.hybrid_command(name="kick", description="Kick a member.")
@commands.guild_only()
@mod_only()
async def kick(ctx, member: discord.Member, *, reason: str = "No reason provided"):
    if not can_act(ctx, member):
        return await safe_reply(ctx, "Role hierarchy prevents this action.")
    await member.kick(reason=f"{ctx.author}: {reason}")
    await safe_reply(ctx, embed=make_embed("Member Kicked", f"{member} — {reason}", RED))

@bot.hybrid_command(name="ban", description="Ban a member; delete_days is 0–7.")
@commands.guild_only()
@mod_only()
async def ban(ctx, member: discord.Member, delete_days: int = 0, *, reason: str = "No reason provided"):
    if not can_act(ctx, member):
        return await safe_reply(ctx, "Role hierarchy prevents this action.")
    delete_days = max(0, min(7, delete_days))
    await member.ban(reason=f"{ctx.author}: {reason}", delete_message_seconds=delete_days * 86400)
    await safe_reply(ctx, embed=make_embed("Member Banned", f"{member} — {reason}", RED))

@bot.hybrid_command(name="unban", description="Unban a user by ID.")
@commands.guild_only()
@mod_only()
async def unban(ctx, user_id: str, *, reason: str = "No reason provided"):
    try:
        uid = int(user_id)
        await ctx.guild.unban(discord.Object(id=uid), reason=f"{ctx.author}: {reason}")
    except ValueError:
        return await safe_reply(ctx, "Invalid user ID.")
    except discord.NotFound:
        return await safe_reply(ctx, "That user is not banned.")
    await safe_reply(ctx, f"Unbanned user ID `{uid}`.")

@bot.hybrid_command(name="timeout", description="Timeout a member (e.g. 10m, 1h, 1d).")
@commands.guild_only()
@mod_only()
async def timeout_cmd(ctx, member: discord.Member, duration: str, *, reason: str = "No reason provided"):
    if not can_act(ctx, member):
        return await safe_reply(ctx, "Role hierarchy prevents this action.")
    match = re.fullmatch(r"(\d+)([smhd])", duration.lower())
    if not match:
        return await safe_reply(ctx, "Use 10s, 10m, 1h, or 1d.")
    seconds = int(match.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
    seconds = max(1, min(seconds, 28 * 86400))
    await member.timeout(discord.utils.utcnow() + timedelta(seconds=seconds), reason=f"{ctx.author}: {reason}")
    await safe_reply(ctx, embed=make_embed("Member Timed Out", f"{member.mention} for {duration}. {reason}", RED))

@bot.hybrid_command(name="clear", description="Delete 1–100 recent messages.")
@commands.guild_only()
@mod_only()
async def clear(ctx, amount: int):
    if not 1 <= amount <= 100:
        return await safe_reply(ctx, "Amount must be 1–100.")
    deleted = await ctx.channel.purge(limit=amount + 1)
    await safe_reply(ctx, f"Deleted {max(0, len(deleted)-1)} messages.")

@bot.event
async def on_message(message):
    if message.guild is None or message.author.bot or not isinstance(message.author, discord.Member):
        return await bot.process_commands(message)
    guild, member = message.guild, message.author
    s = await settings_for(guild.id)

    lock = s.get("messagelock", {})
    if lock.get("enabled"):
        owner_allowed = member.id == guild.owner_id and lock.get("allow_owner", True)
        bot_allowed = member.bot and lock.get("allow_bots", False)
        if not (owner_allowed or bot_allowed):
            try:
                await message.delete()
            except discord.HTTPException:
                pass
            return

    if is_admin(member) or await trusted(guild, member):
        return await bot.process_commands(message)

    violation, reason = None, ""
    if s["antiswear"]["enabled"] and contains_bad_word(message.content):
        violation, reason = "Anti-Swear", "Prohibited language"
    if violation is None and s["antilink"]["enabled"]:
        urls = re.findall(r"(?:https?://|www\.)[^\s]+|\b[\w.-]+\.(?:com|net|org|gg|io)\b",
                          message.content, re.I)
        bad_domains = ("discord-gifts.com", "discordnitro.com", "dlscord.com", "steamcommunlty.com")
        if urls and (s["antilink"].get("mode") == "block_all" or
                     any(d in u.lower() for u in urls for d in bad_domains)):
            violation, reason = "Anti-Link", "Link policy violation"
    if violation is None and s["antimention"]["enabled"]:
        count = len(message.mentions) + len(message.role_mentions)
        if count > int(s["antimention"].get("threshold", 5)):
            violation, reason = "Anti-Mention", f"{count} mentions"
    if violation is None and s["antispam"]["enabled"]:
        key, now = (guild.id, member.id), time.monotonic()
        q = bot.spam[key]
        window, limit = int(s["antispam"].get("window", 5)), int(s["antispam"].get("count", 6))
        while q and now - q[0] > window:
            q.popleft()
        q.append(now)
        if len(q) >= limit:
            q.clear()
            violation, reason = "Anti-Spam", f"Message flood ({limit} messages/{window}s)"

    if violation:
        try:
            await message.delete()
        except discord.HTTPException:
            pass
        if violation == "Anti-Spam":
            try:
                await member.timeout(discord.utils.utcnow() + timedelta(seconds=60), reason="AegisLock anti-spam")
            except discord.HTTPException:
                pass
        try:
            await message.channel.send(f"{member.mention}, your message was removed by server security.",
                                       delete_after=5, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            pass
        await log_event(guild, make_embed(f"{violation} Triggered", f"User: {member} (`{member.id}`)\nReason: {reason}", RED))
        return
    await bot.process_commands(message)

@bot.event
async def on_member_join(member):
    guild = member.guild
    # Only bots explicitly approved through /whitelist add are accepted.
    if member.bot:
        approved = await bot.db.run("SELECT 1 FROM trusted_bots WHERE guild=? AND user=?",
                                    (guild.id, member.id), "one")
        if not approved:
            try:
                await member.kick(reason="Unapproved bot: AegisLock verification")
                await log_event(guild, make_embed("Unapproved Bot", f"Kicked {member} (`{member.id}`).", RED))
            except discord.HTTPException:
                pass
            return

    blocked = await bot.db.run("SELECT 1 FROM blacklist WHERE guild=? AND user=?",
                               (guild.id, member.id), "one")
    if blocked:
        try:
            await member.ban(reason="AegisLock blacklist")
        except discord.HTTPException:
            pass
        return

    s = await settings_for(guild.id)
    cfg = s["antiraid"]
    if cfg["enabled"]:
        q, now = bot.joins[guild.id], time.monotonic()
        window = int(cfg.get("window", 10))
        while q and now - q[0] > window:
            q.popleft()
        q.append(now)
        age = (discord.utils.utcnow() - member.created_at).days
        if len(q) >= int(cfg.get("threshold", 8)) and age < int(cfg.get("min_account_age_days", 7)):
            try:
                await member.kick(reason="AegisLock anti-raid: suspicious join burst")
                outcome = "Suspicious new account kicked."
            except discord.HTTPException:
                outcome = "Raid detected; kick failed (permissions/hierarchy)."
            await log_event(guild, make_embed("Anti-Raid Triggered", f"Member: {member}\n{outcome}", RED))

    welcome = s.get("welcome_system")
    if welcome:
        channel = guild.get_channel(welcome.get("channel_id", 0))
        if channel:
            text = welcome.get("message", "Welcome {user} to {server}!")
            text = text.replace("{user}", member.mention).replace("{server}", guild.name)
            try:
                await channel.send(embed=make_embed("Welcome!", text))
            except discord.HTTPException:
                pass

@bot.event
async def on_guild_role_delete(role):
    s = await settings_for(role.guild.id)
    if s["roleprotection"]["enabled"]:
        await log_event(role.guild, make_embed("Role Deleted", f"Role `{role.name}` was deleted.", RED))

@bot.event
async def on_guild_role_update(before, after):
    s = await settings_for(after.guild.id)
    if s["roleprotection"]["enabled"] and before.permissions != after.permissions:
        await log_event(after.guild, make_embed("Role Permissions Changed", f"Permissions changed for `{after.name}`.", RED))

@bot.event
async def on_guild_channel_delete(channel):
    s = await settings_for(channel.guild.id)
    if s["channelprotection"]["enabled"]:
        await log_event(channel.guild, make_embed("Channel Deleted", f"Channel `{channel.name}` was deleted.", RED))

@bot.event
async def on_guild_channel_update(before, after):
    s = await settings_for(after.guild.id)
    if s["channelprotection"]["enabled"] and before.overwrites != after.overwrites:
        await log_event(after.guild, make_embed("Channel Permissions Changed", f"Overwrites changed in {after.mention}.", RED))

@bot.event
async def on_webhooks_update(channel):
    s = await settings_for(channel.guild.id)
    if s["webhookprotection"]["enabled"]:
        await log_event(channel.guild, make_embed("Webhook Updated", f"Webhook list changed in {channel.mention}.", RED))

NUKE_ACTIONS = {
    discord.AuditLogAction.ban: ("ban", 3),
    discord.AuditLogAction.kick: ("kick", 3),
    discord.AuditLogAction.channel_delete: ("channel delete", 2),
    discord.AuditLogAction.role_delete: ("role delete", 2),
    discord.AuditLogAction.channel_create: ("channel create", 3),
    discord.AuditLogAction.role_create: ("role create", 3),
    discord.AuditLogAction.webhook_create: ("webhook create", 3),
}

@bot.event
async def on_audit_log_entry_create(entry):
    guild = entry.guild
    if guild is None or entry.action not in NUKE_ACTIONS or entry.user is None:
        return
    s = await settings_for(guild.id)
    cfg = s["antinuke"]
    if not cfg["enabled"] or await trusted(guild, entry.user):
        return
    action, limit = NUKE_ACTIONS[entry.action]
    key, now = (guild.id, entry.user.id, action), time.monotonic()
    async with bot.nuke_lock:
        q = bot.nuke[key]
        while q and now - q[0] > 10:
            q.popleft()
        q.append(now)
        count = len(q)
        if count < limit:
            return
        q.clear()

    member = guild.get_member(entry.user.id)
    result = "Actor not found; alert only."
    try:
        if member and member.id != guild.owner_id:
            punishment = cfg.get("punishment", "strip_roles")
            if punishment == "ban":
                await member.ban(reason="AegisLock anti-nuke")
                result = "Actor banned."
            elif punishment == "kick":
                await member.kick(reason="AegisLock anti-nuke")
                result = "Actor kicked."
            else:
                me = guild.me
                roles = [r for r in member.roles if r != guild.default_role and not r.managed and me and r < me.top_role]
                if roles:
                    await member.remove_roles(*roles, reason="AegisLock anti-nuke")
                result = f"Removed {len(roles)} manageable roles."
    except discord.HTTPException:
        result = "Punishment failed; check bot permissions and role hierarchy."
    await log_event(guild, make_embed("Anti-Nuke Triggered",
        f"Actor: {entry.user} (`{entry.user.id}`)\nAction burst: {action} ({count}/10s)\nResponse: {result}", RED))

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.MissingPermissions):
        message = "You do not have permission to use this command."
    elif isinstance(error, commands.NoPrivateMessage):
        message = "Use this command inside a server."
    elif isinstance(error, commands.BadArgument):
        message = "Invalid argument. Check the command usage."
    else:
        log.error("Command error", exc_info=(type(error), error, error.__traceback__))
        message = "An unexpected error occurred. Check the bot logs."
    await safe_reply(ctx, embed=make_embed(BRAND, message, RED), ephemeral=True)

@bot.tree.error
async def on_app_command_error(interaction, error):
    log.error("Slash command error: %s", error)
    message = "You do not have permission to use this command." if isinstance(error, discord.app_commands.MissingPermissions) else "Command failed. Check bot permissions and logs."
    try:
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except discord.HTTPException:
        pass

if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Missing DISCORD_TOKEN environment variable.")
    bot.run(TOKEN)
