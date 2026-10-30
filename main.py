
AEGISLOCK SENTINEL — Ultimate Discord Security & Moderation Bot
Developer: COPOXXX
Team:      ZeroCodeX
------------------------------------------------------------
Install:  pip install -U discord.py aiosqlite python-dotenv
Env:      DISCORD_TOKEN=...  DATABASE_PATH=aegislock.db (optional)


import os 
import re 
import json 
import time 
import asyncio 
import logging 
import unicodedata 
from datetime import datetime, timezone, timedelta 
from collections import defaultdict, deque

import discord 
from discord.ext import commands 
import aiosqlite

------------------------------------------------------------
CONFIG
------------------------------------------------------------
TOKEN = os.getenv("DISCORD_TOKEN", "").strip() 
DB_PATH = os.getenv("DATABASE_PATH", "aegislock.db") 
PREFIXES = tuple(x.strip() for x in os.getenv("PREFIXES", ".,!").split(",") if x.strip())

BRAND = "AegisLock Sentinel" 
DEVELOPER = "COPOXXX" 
TEAM = "ZeroCodeX"

GOLD = 0xD4AF37 
DARK_GOLD = 0xB8860B 
RED = 0xE74C3C 
GREEN = 0x2ECC71 
ORANGE = 0xE67E22

FOOTER = f"{BRAND} | Developed by {DEVELOPER} | Team {TEAM}"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s") 
log = logging.getLogger("AegisLock")

------------------------------------------------------------
HELPERS
------------------------------------------------------------
def now_iso() -> str: 
return datetime.now(timezone.utc).isoformat()


def embed(title=None, description=None, color=GOLD) -> discord.Embed: 
e = discord.Embed(title=title, description=description, color=color, 
timestamp=discord.utils.utcnow()) 
e.set_footer(text=FOOTER) 
return e


------------------------------------------------------------
MODULE METADATA
------------------------------------------------------------
MODULES = { 
"antinuke": "Anti-Nuke", 
"antiraid": "Anti-Raid", 
"antiswear": "Anti-Swear", 
"antispam": "Anti-Spam", 
"antilink": "Anti-Link", 
"antimention": "Anti-Mention", 
"roleprotection": "Role Protection", 
"channelprotection": "Channel Protection", 
"webhookprotection": "Webhook Protection", 
"lockdown": "Lockdown", 
}

MODULE_DESCRIPTIONS = { 
"antinuke": "Monitors destructive actions (ban, kick, channel/role delete) via the audit log and punishes the actor.", 
"antiraid": "Detects join bursts and brand-new accounts joining in waves.", 
"antiswear": "Multilingual profanity filter (English, Bangla, Banglish) with obfuscation defense.", 
"antispam": "Detects message flooding and times out the sender.", 
"antilink": "Blocks links and known phishing / scam domains.", 
"antimention": "Blocks mass user and role mentions above threshold.", 
"roleprotection": "Logs role deletions and dangerous permission grants.", 
"channelprotection": "Logs channel deletions and overwrite changes.", 
"webhookprotection": "Logs unauthorized webhook creation and changes.", 
"lockdown": "Locks every text channel for @everyone. Use with caution.", 
}


------------------------------------------------------------
DATABASE (SQLite via aiosqlite)
------------------------------------------------------------
class Database: 
def init(self, path): 
self.path = path 
self.conn = None 
self.lock = asyncio.Lock()

async def connect(self):
    self.conn = await aiosqlite.connect(self.path)
    self.conn.row_factory = aiosqlite.Row
    await self.conn.executescript("""
    CREATE TABLE IF NOT EXISTS settings(guild INTEGER PRIMARY KEY, data TEXT NOT NULL DEFAULT '{}');
    CREATE TABLE IF NOT EXISTS blacklist(guild INTEGER, user INTEGER, reason TEXT, by_user INTEGER, at TEXT, PRIMARY KEY(guild,user));
    CREATE TABLE IF NOT EXISTS whitelist(guild INTEGER, user INTEGER, by_user INTEGER, at TEXT, PRIMARY KEY(guild,user));
    CREATE TABLE IF NOT EXISTS trusted_bots(guild INTEGER, user INTEGER, by_user INTEGER, at TEXT, PRIMARY KEY(guild,user));
    CREATE TABLE IF NOT EXISTS warnings(id INTEGER PRIMARY KEY AUTOINCREMENT, guild INTEGER, user INTEGER, moderator INTEGER, reason TEXT, at TEXT);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, guild INTEGER, actor INTEGER, action TEXT, target INTEGER, details TEXT, at TEXT);
    """)
    await self.conn.commit()

async def run(self, sql, args=(), fetch=None):
    async with self.lock:
        cur = await self.conn.execute(sql, args)
        if fetch == "one":
            result = await cur.fetchone()
        elif fetch == "all":
            result = await cur.fetchall()
        else:
            result = cur.rowcount
        await self.conn.commit()
        return result

async def settings(self, gid):
    r = await self.run("SELECT data FROM settings WHERE guild=?", (gid,), "one")
    return json.loads(r["data"]) if r else {}

async def save_settings(self, gid, data):
    await self.run(
        "INSERT INTO settings VALUES(?,?) ON CONFLICT(guild) DO UPDATE SET data=excluded.data",
        (gid, json.dumps(data)),
    )

async def is_whitelisted(self, g, u):
    return bool(await self.run("SELECT 1 FROM whitelist WHERE guild=? AND user=?", (g, u), "one"))

async def is_trusted_bot(self, g, u):
    return bool(await self.run("SELECT 1 FROM trusted_bots WHERE guild=? AND user=?", (g, u), "one"))

async def close(self):
    if self.conn:
        await self.conn.close()

------------------------------------------------------------
PERMISSION DECORATORS
------------------------------------------------------------
def admin(): 
async def predicate(ctx): 
if not ctx.guild or not isinstance(ctx.author, discord.Member): 
raise commands.CheckFailure("Server only.") 
if (ctx.author.id  ctx.guild.owner_id 
or ctx.author.guild_permissions.administrator 
or ctx.author.guild_permissions.manage_guild): 
return True 
raise commands.MissingPermissions(["administrator"]) 
return commands.check(predicate)


def moderator(): 
async def predicate(ctx): 
if not ctx.guild or not isinstance(ctx.author, discord.Member): 
raise commands.CheckFailure("Server only.") 
p = ctx.author.guild_permissions 
if (ctx.author.id  ctx.guild.owner_id 
or p.administrator or p.manage_guild 
or p.kick_members or p.ban_members or p.moderate_members): 
return True 
raise commands.MissingPermissions(["moderate_members"]) 
return commands.check(predicate)


def is_admin_member(member: discord.Member, guild: discord.Guild) -> bool: 
if member.id  guild.owner_id: 
return True 
return member.guild_permissions.administrator


------------------------------------------------------------
MODULE / DB HELPERS
------------------------------------------------------------
async def module_data(bot, guild_id, name): 
return (await bot.db.settings(guild_id)).get(name, {})


async def update_module(bot, guild_id, name, data): 
s = await bot.db.settings(guild_id) 
s[name] = data 
await bot.db.save_settings(guild_id, s)


async def security_log(bot, guild, e): 
s = await bot.db.settings(guild.id) 
ch = guild.get_channel(s.get("security_log_channel", 0) or 0) 
if ch: 
try: 
await ch.send(embed=e) 
except discord.HTTPException: 
pass


async def trusted(bot, guild, user): 
return ( 
user.id  guild.owner_id 
or (bot.user and user.id  bot.user.id) 
or await bot.is_owner(user) 
or await bot.db.is_whitelisted(guild.id, user.id) 
or (user.bot and await bot.db.is_trusted_bot(guild.id, user.id)) 
)


def actor_can_target(ctx, member): 
return (member.id != ctx.guild.owner_id 
and ctx.author.id != member.id 
and (ctx.author.id  ctx.guild.owner_id or ctx.author.top_role > member.top_role))


def bot_can_target(ctx, member): 
return bool(ctx.guild.me) and ctx.guild.me.top_role > member.top_role


def hierarchy(ctx, member): 
return actor_can_target(ctx, member) and bot_can_target(ctx, member)


------------------------------------------------------------
PROFANITY FILTER
------------------------------------------------------------
BAD_WORDS = { 
"fuck", "shit", "bitch", "asshole", "bastard", "dick", "pussy", "cunt", 
"slut", "whore", "motherfucker", "bullshit", "prick", "wanker", "twat", 
"মাদারচোদ", "চুদি", "চোদা", "খানকি", "মাগি", "গান্ডু", "গাণ্ডু", 
"বেশ্যা", "হারামজাদা", "হারামি", 
"madarchod", "maderchod", "chudi", "chuda", "choda", "khanki", "magi", 
"gandu", "beshya", "haramjada", "harami", "banchod", "bokachoda", "chodna", 
} 
TRANS = str.maketrans({ 
"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", 
"@": "a", "$": "s", "!": "i", 
})


def norm(s): 
s = unicodedata.normalize("NFKC", s or "").lower().translate(TRANS) 
s = re.sub(r"(.)\1{2,}", r"\1\1", s) 
return re.sub(r"[^\w\u0980-\u09ff]", "", s)


BAD_NORMALIZED = {norm(w) for w in BAD_WORDS}


def bad_word(text): 
compact = norm(text) 
return next((w for w in BAD_NORMALIZED if len(w) > 2 and w in compact), None)


------------------------------------------------------------
BOT CLASS
------------------------------------------------------------
class AegisBot(commands.Bot): 
def init(self): 
intents = discord.Intents.default() 
intents.members = True 
intents.message_content = True 
intents.moderation = True 
super().init( 
command_prefix=commands.when_mentioned_or(*PREFIXES), 
intents=intents, 
help_command=None, 
case_insensitive=True, 
allowed_mentions=discord.AllowedMentions.none(), 
) 
self.db = Database(DB_PATH) 
self.spam = defaultdict(deque) 
self.joins = defaultdict(deque) 
self.nuke = defaultdict(deque) 
self.nuke_lock = asyncio.Lock() 
self.panels = {}  # module -> SecurityToggleView (persistent)

async def setup_hook(self):
    await self.db.connect()

    # Register persistent views for every security module
    for mod in MODULES:
        view = SecurityToggleView(self, mod)
        self.panels[mod] = view
        self.add_view(view)

    try:
        synced = await self.tree.sync()
        log.info("Synced %d global slash commands", len(synced))
    except Exception:
        log.exception("Slash command sync failed")

async def on_ready(self):
    log.info("Online as %s (%s)", self.user, self.user.id)
    await self.change_presence(
        activity=discord.Activity(type=discord.ActivityType.watching,
                                  name="server security | /help")
    )

async def close(self):
    await self.db.close()
    await super().close()

bot = AegisBot()


------------------------------------------------------------
SECURITY TOGGLE VIEW
------------------------------------------------------------
class SecurityToggleView(discord.ui.View): 
"""Enable / Disable buttons for a security module. Persistent."""

def __init__(self, bot: AegisBot, module: str):
    super().__init__(timeout=None)  # persistent
    self.bot = bot
    self.module = module

    enable_btn = discord.ui.Button(
        label="Enable",
        style=discord.ButtonStyle.success,
        emoji="✅",
        custom_id=f"aegis:enable:{module}",
    )
    disable_btn = discord.ui.Button(
        label="Disable",
        style=discord.ButtonStyle.danger,
        emoji="⛔",
        custom_id=f"aegis:disable:{module}",
    )
    enable_btn.callback = self._make_cb(True)
    disable_btn.callback = self._make_cb(False)
    self.add_item(enable_btn)
    self.add_item(disable_btn)

def _make_cb(self, enable: bool):
    async def cb(interaction: discord.Interaction):
        await self._handle(interaction, enable)
    return cb

async def _handle(self, interaction: discord.Interaction, enable: bool):
    # 1) must be in a guild
    if not interaction.guild or not isinstance(interaction.user, discord.Member):
        return await interaction.response.send_message(
            embed=embed("Server Only", "This action can only be used in a server.", RED),
            ephemeral=True,
        )

    # 2) authorization
    if not is_admin_member(interaction.user, interaction.guild):
        return await interaction.response.send_message(
            embed=embed("Permission Denied",
                        "Only server administrators can toggle security modules.", RED),
            ephemeral=True,
        )

    # 3) defer (safe for slower ops like lockdown)
    try:
        await interaction.response.defer()
    except discord.HTTPException:
        pass

    guild = interaction.guild
    label = MODULES[self.module]

    # 4) current state
    if self.module == "lockdown":
        full = await self.bot.db.settings(guild.id)
        current = bool(full.get("lockdown"))
    else:
        data = await module_data(self.bot, guild.id, self.module)
        current = bool(data.get("enabled"))

    if current == enable:
        return await interaction.followup.send(
            embed=embed("No Change",
                        f"**{label}** is already {'**enabled**' if enable else '**disabled**'}.",
                        ORANGE),
            ephemeral=True,
        )

    # 5) apply state
    if self.module == "lockdown":
        ok, msg = await _toggle_lockdown(self.bot, guild, enable)
        if not ok:
            return await interaction.followup.send(
                embed=embed("Lockdown Error", msg, RED), ephemeral=True
            )

    data = await module_data(self.bot, guild.id, self.module)
    data["enabled"] = enable
    await update_module(self.bot, guild.id, self.module, data)

    # 6) security log
    await security_log(
        self.bot, guild,
        embed(
            f"{label} {'Enabled' if enable else 'Disabled'}",
            f"By: {interaction.user.mention}\nModule: **{label}**",
            GREEN if enable else RED,
        ),
    )

    # 7) refresh panel
    new_embed = _panel_embed(self.module, enable)
    try:
        await interaction.edit_original_response(embed=new_embed)
    except discord.HTTPException:
        try:
            await interaction.message.edit(embed=new_embed)
        except discord.HTTPException:
            pass

------------------------------------------------------------
PANEL EMBED
------------------------------------------------------------
def _panel_embed(module: str, enabled: bool) -> discord.Embed: 
label = MODULES[module] 
desc = MODULE_DESCRIPTIONS.get(module, "") 
status = "ENABLED ✅" if enabled else "DISABLED ⛔" 
e = discord.Embed( 
title=f"🛡️ {label} Control", 
description=( 
f"{desc}\n\n" 
f"Current status: {status}\n" 
f"Use the buttons below to Enable or Disable this protection." 
), 
color=GREEN if enabled else RED, 
timestamp=discord.utils.utcnow(), 
) 
e.set_footer(text=FOOTER) 
return e


------------------------------------------------------------
LOCKDOWN HELPER
------------------------------------------------------------
async def _toggle_lockdown(bot: AegisBot, guild: discord.Guild, enable: bool): 
s = await bot.db.settings(guild.id)

if enable:
    if s.get("lockdown"):
        return False, "Lockdown is already active."
    prev = {}
    changed = 0
    for ch in guild.text_channels:
        try:
            ow = ch.overwrites_for(guild.default_role)
            prev[str(ch.id)] = ow.send_messages
            if ow.send_messages is not False:
                ow.send_messages = False
                await ch.set_permissions(
                    guild.default_role, overwrite=ow,
                    reason=f"AegisLock lockdown by {bot.user}",
                )
                changed += 1
        except discord.HTTPException:
            pass
    s["lockdown_previous"] = prev
    s["lockdown"] = True
    await bot.db.save_settings(guild.id, s)
    return True, f"Locked **{changed}** channel(s)."

else:
    if not s.get("lockdown"):
        return False, "No active lockdown to release."
    restored = 0
    prev_map = s.get("lockdown_previous", {})
    for ch in guild.text_channels:
        if str(ch.id) not in prev_map:
            continue
        try:
            ow = ch.overwrites_for(guild.default_role)
            ow.send_messages = prev_map[str(ch.id)]
            await ch.set_permissions(
                guild.default_role, overwrite=ow,
                reason=f"AegisLock lockdown release by {bot.user}",
            )
            restored += 1
        except discord.HTTPException:
            pass
    s["lockdown"] = False
    s["lockdown_previous"] = {}
    await bot.db.save_settings(guild.id, s)
    return True, f"Restored **{restored}** channel(s)."

------------------------------------------------------------
SECURITY COMMANDS (button panels, no arguments)
------------------------------------------------------------
async def _show_panel(ctx: commands.Context, module: str): 
if not ctx.guild or not isinstance(ctx.author, discord.Member): 
return await ctx.reply(embed=embed("Server Only", "This command can only be used in a server.", RED), 
mention_author=False) 
if not (ctx.author.id  ctx.guild.owner_id or ctx.author.guild_permissions.administrator): 
return await ctx.reply(embed=embed("Permission Denied", 
"Only administrators can use this command.", RED), 
mention_author=False)

if module == "lockdown":
    s = await bot.db.settings(ctx.guild.id)
    enabled = bool(s.get("lockdown"))
else:
    d = await module_data(bot, ctx.guild.id, module)
    enabled = bool(d.get("enabled"))

view = bot.panels[module]
await ctx.reply(embed=_panel_embed(module, enabled), view=view, mention_author=False)

@bot.hybrid_command(name="antinuke", description="Anti-Nuke control panel.") 
async def cmd_antinuke(ctx): 
await _show_panel(ctx, "antinuke")


@bot.hybrid_command(name="antiraid", description="Anti-Raid control panel.") 
async def cmd_antiraid(ctx): 
await _show_panel(ctx, "antiraid")


@bot.hybrid_command(name="antiswear", description="Anti-Swear control panel.") 
async def cmd_antiswear(ctx): 
await _show_panel(ctx, "antiswear")


@bot.hybrid_command(name="antispam", description="Anti-Spam control panel.") 
async def cmd_antispam(ctx): 
await _show_panel(ctx, "antispam")


@bot.hybrid_command(name="antilink", description="Anti-Link control panel.") 
async def cmd_antilink(ctx): 
await _show_panel(ctx, "antilink")


@bot.hybrid_command(name="antimention", description="Anti-Mention control panel.") 
async def cmd_antimention(ctx): 
await _show_panel(ctx, "antimention")


@bot.hybrid_command(name="roleprotection", description="Role Protection control panel.") 
async def cmd_roleprotection(ctx): 
await _show_panel(ctx, "roleprotection")


@bot.hybrid_command(name="channelprotection", description="Channel Protection control panel.") 
async def cmd_channelprotection(ctx): 
await _show_panel(ctx, "channelprotection")


@bot.hybrid_command(name="webhookprotection", description="Webhook Protection control panel.") 
async def cmd_webhookprotection(ctx): 
await _show_panel(ctx, "webhookprotection")


@bot.hybrid_command(name="lockdown", description="Lockdown control panel.") 
async def cmd_lockdown(ctx): 
await _show_panel(ctx, "lockdown")


------------------------------------------------------------
HELP & STATUS
------------------------------------------------------------
@bot.hybrid_command(name="help", description="Show all AegisLock commands.") 
async def help_cmd(ctx): 
e = discord.Embed( 
title=f"🛡️ {BRAND}", 
description=( 
"Premium security & moderation suite for Discord.\n" 
f"Developer: {DEVELOPER}  •  Team: {TEAM}" 
), 
color=GOLD, 
timestamp=discord.utils.utcnow(), 
) 
e.add_field( 
name="🔐 Security Commands", 
value=( 
"/antinuke — Anti-nuke protection\n" 
"/antiraid — Anti-raid protection\n" 
"/antiswear — Multilingual profanity filter\n" 
"/antispam — Message flood protection\n" 
"/antilink — Link / phishing blocker\n" 
"/antimention — Mass mention blocker\n" 
"/lockdown — Emergency server lockdown" 
), 
inline=False, 
) 
e.add_field( 
name="🛡️ Bot Guard", 
value=( 
"/roleprotection — Role deletion & permission grants\n" 
"/channelprotection — Channel deletion & overwrite changes\n" 
"/webhookprotection — Webhook creation monitoring" 
), 
inline=False, 
) 
e.add_field( 
name="⚒️ Moderation Commands", 
value=( 
"/warn — Warn a member\n" 
"/warnings — View warnings\n" 
"/kick — Kick a member\n" 
"/ban — Ban a member\n" 
"/unban — Unban by user ID\n" 
"/timeout — Timeout a member\n" 
"/clear — Purge channel messages" 
), 
inline=False, 
) 
e.add_field( 
name="📋 Blacklist & Whitelist", 
value=( 
"/whitelist add|remove|list — Trusted users & bots\n" 
"/blacklist add|remove|list — Blocked users (auto-banned on join)" 
), 
inline=False, 
) 
e.add_field( 
name="📊 Security Logging", 
value=( 
"/securitylog setchannel #channel — Set log channel\n" 
"/securitylog info — Show current log channel\n" 
"/securitylog clear — Clear log channel\n" 
"/status — Live view of all modules" 
), 
inline=False, 
) 
e.add_field( 
name="ℹ️ About", 
value=f"{BRAND} — Built by {DEVELOPER} for team {TEAM}.", 
inline=False, 
) 
e.set_footer(text=FOOTER) 
await ctx.reply(embed=e, mention_author=False)


@bot.hybrid_command(name="status", description="Show all security modules at a glance.") 
async def status_cmd(ctx): 
if not ctx.guild: 
return await ctx.reply(embed=embed("Server Only", "Use this in a server.", RED), 
mention_author=False) 
s = await bot.db.settings(ctx.guild.id) 
e = discord.Embed(title="🛡️ Security Status", color=GOLD, timestamp=discord.utils.utcnow()) 
for mod in MODULES: 
if mod  "lockdown": 
enabled = bool(s.get("lockdown")) 
else: 
enabled = bool(s.get(mod, {}).get("enabled")) 
e.add_field(name=MODULES[mod], value="✅ ON" if enabled else "❌ OFF", inline=True)

log_ch = ctx.guild.get_channel(s.get("security_log_channel", 0) or 0)
e.add_field(name="Security Log", value=log_ch.mention if log_ch else "`Not set`", inline=False)
e.set_footer(text=FOOTER)
await ctx.reply(embed=e, mention_author=False)

------------------------------------------------------------
SECURITY LOG CONFIGURATION
------------------------------------------------------------
@bot.hybrid_command(name="securitylog", description="Set or view the security log channel.") 
@admin() 
async def securitylog(ctx, action="info", channel: discord.TextChannel = None): 
s = await bot.db.settings(ctx.guild.id) 
action = action.lower()

if action == "setchannel":
    if channel is None:
        return await ctx.reply("Usage: `/securitylog setchannel #channel`", mention_author=False)
    s["security_log_channel"] = channel.id
    await bot.db.save_settings(ctx.guild.id, s)
    return await ctx.reply(embed=embed("Security Log Configured", channel.mention, GREEN),
                           mention_author=False)

if action == "clear":
    s.pop("security_log_channel", None)
    await bot.db.save_settings(ctx.guild.id, s)
    return await ctx.reply(embed=embed("Security Log Cleared",
                                       "No security events will be logged.", ORANGE),
                           mention_author=False)

ch = ctx.guild.get_channel(s.get("security_log_channel", 0) or 0)
await ctx.reply(embed=embed("Security Log Channel",
                            ch.mention if ch else "Not configured."),
                mention_author=False)

------------------------------------------------------------
WHITELIST / TRUSTED BOTS
------------------------------------------------------------
@bot.hybrid_command(name="whitelist", description="Manage trusted users and bots.") 
@admin() 
async def whitelist(ctx, action: str, user: discord.User = None): 
action = action.lower() 
g = ctx.guild.id

if action in ("add", "remove") and user is None:
    return await ctx.reply("Specify a user or bot.", mention_author=False)

if action == "add":
    table = "trusted_bots" if user.bot else "whitelist"
    await bot.db.run(
        f"INSERT OR REPLACE INTO {table} VALUES(?,?,?,?)",
        (g, user.id, ctx.author.id, now_iso()),
    )
    return await ctx.reply(
        embed=embed("Trusted Entry Added",
                    f"{user.mention} (`{user.id}`) added as trusted.", GREEN),
        mention_author=False,
    )

if action == "remove":
    table = "trusted_bots" if user.bot else "whitelist"
    n = await bot.db.run(f"DELETE FROM {table} WHERE guild=? AND user=?", (g, user.id))
    return await ctx.reply(
        embed=embed("Trusted Entry Removed" if n else "Entry Not Found",
                    str(user) if n else "That entry does not exist.",
                    GREEN if n else RED),
        mention_author=False,
    )

if action == "list":
    u = await bot.db.run("SELECT user FROM whitelist WHERE guild=?", (g,), "all")
    b = await bot.db.run("SELECT user FROM trusted_bots WHERE guild=?", (g,), "all")
    e = embed("Trusted Users & Bots")
    e.add_field(
        name="Users",
        value="\n".join(f"<@{r['user']}>" for r in u[:20]) or "None",
        inline=False,
    )
    e.add_field(
        name="Trusted Bots",
        value="\n".join(f"<@{r['user']}>" for r in b[:20]) or "None",
        inline=False,
    )
    return await ctx.reply(embed=e, mention_author=False)

await ctx.reply("Use `add`, `remove`, or `list`.", mention_author=False)

------------------------------------------------------------
BLACKLIST
------------------------------------------------------------
@bot.hybrid_command(name="blacklist", description="Manage the server blacklist.") 
@admin() 
async def blacklist(ctx, action: str, user: discord.User = None, *, reason="No reason"): 
action = action.lower()

if action == "add":
    if not user:
        return await ctx.reply("Specify a user.", mention_author=False)
    await bot.db.run(
        "INSERT OR REPLACE INTO blacklist VALUES(?,?,?,?,?)",
        (ctx.guild.id, user.id, reason, ctx.author.id, now_iso()),
    )
    return await ctx.reply(
        embed=embed("User Blacklisted",
                    f"{user.mention} (`{user.id}`)\nReason: {reason}", RED),
        mention_author=False,
    )

if action == "remove":
    if not user:
        return await ctx.reply("Specify a user.", mention_author=False)
    n = await bot.db.run("DELETE FROM blacklist WHERE guild=? AND user=?",
                         (ctx.guild.id, user.id))
    return await ctx.reply(
        embed=embed("Blacklist Entry Removed" if n else "Not Found",
                    str(user) if n else "That user is not blacklisted.",
                    GREEN if n else RED),
        mention_author=False,
    )

if action == "list":
    rows = await bot.db.run(
        "SELECT user, reason FROM blacklist WHERE guild=?", (ctx.guild.id,), "all"
    )
    return await ctx.reply(
        embed=embed("Blacklist",
                    "\n".join(f"<@{r['user']}> — {r['reason']}" for r in rows[:40]) or "Empty"),
        mention_author=False,
    )

await ctx.reply("Use `add`, `remove`, or `list`.", mention_author=False)

------------------------------------------------------------
MODERATION COMMANDS
------------------------------------------------------------
@bot.hybrid_command(name="warn", description="Warn a member.") 
@moderator() 
async def warn(ctx, member: discord.Member, *, reason="No reason"): 
if not actor_can_target(ctx, member): 
return await ctx.reply("Role hierarchy prevents warning this member.", mention_author=False) 
await bot.db.run( 
"INSERT INTO warnings(guild,user,moderator,reason,at) VALUES(?,?,?,?,?)", 
(ctx.guild.id, member.id, ctx.author.id, reason, now_iso()), 
) 
rows = await bot.db.run( 
"SELECT id FROM warnings WHERE guild=? AND user=?", 
(ctx.guild.id, member.id), "all", 
) 
try: 
await member.send(f"You were warned in {ctx.guild.name}: {reason}") 
except discord.HTTPException: 
pass 
await ctx.reply( 
embed=embed("Member Warned", 
f"{member.mention}\nTotal warnings: {len(rows)}\nReason: {reason}", 
ORANGE), 
mention_author=False, 
)


@bot.hybrid_command(name="warnings", description="View a member's warnings.") 
@moderator() 
async def warnings_cmd(ctx, member: discord.Member): 
rows = await bot.db.run( 
"SELECT * FROM warnings WHERE guild=? AND user=? ORDER BY id DESC", 
(ctx.guild.id, member.id), "all", 
) 
body = "\n".join( 
f"#{r['id']} — {r['reason']} (by <@{r['moderator']}>)" for r in rows[:15] 
) or "No warnings." 
await ctx.reply(embed=embed(f"Warnings: {member}", body), mention_author=False)


@bot.hybrid_command(name="kick", description="Kick a member.") 
@moderator() 
async def kick(ctx, member: discord.Member, *, reason="No reason"): 
if not hierarchy(ctx, member): 
return await ctx.reply("Role hierarchy prevents this action.", mention_author=False) 
await member.kick(reason=f"{ctx.author} | {reason}") 
await ctx.reply(embed=embed("Member Kicked", f"{member} — {reason}", RED), 
mention_author=False)


@bot.hybrid_command(name="ban", description="Ban a member.") 
@moderator() 
async def ban(ctx, member: discord.Member, delete_days: int = 0, *, reason="No reason"): 
if not hierarchy(ctx, member): 
return await ctx.reply("Role hierarchy prevents this action.", mention_author=False) 
d = max(0, min(7, delete_days)) 
await member.ban(reason=f"{ctx.author} | {reason}", 
delete_message_seconds=d * 86400) 
await ctx.reply(embed=embed("Member Banned", f"{member} — {reason}", RED), 
mention_author=False)


@bot.hybrid_command(name="unban", description="Unban a user by ID.") 
@moderator() 
async def unban(ctx, user_id: str, *, reason="No reason"): 
try: 
uid = int(user_id) 
except ValueError: 
return await ctx.reply("Invalid user ID.", mention_author=False) 
try: 
await ctx.guild.unban(discord.Object(id=uid), reason=f"{ctx.author} | {reason}") 
except discord.NotFound: 
return await ctx.reply("That user is not banned.", mention_author=False) 
await ctx.reply(embed=embed("User Unbanned", f"ID: {uid}", GREEN), mention_author=False)


@bot.hybrid_command(name="timeout", description="Timeout a member. Duration: 10m, 1h, 1d.") 
@moderator() 
async def timeout_cmd(ctx, member: discord.Member, duration: str, *, reason="No reason"): 
if not hierarchy(ctx, member): 
return await ctx.reply("Role hierarchy prevents this action.", mention_author=False) 
m = re.fullmatch(r"(\d+)([smhd])", duration.lower()) 
if not m: 
return await ctx.reply("Use a duration like 10m, 1h, or 1d.", mention_author=False) 
secs = int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)] 
secs = max(1, min(secs, 28 * 86400)) 
try: 
await member.timeout( 
discord.utils.utcnow() + timedelta(seconds=secs), 
reason=f"{ctx.author} | {reason}", 
) 
except discord.HTTPException as exc: 
return await ctx.reply(f"Failed to timeout: {exc}", mention_author=False) 
await ctx.reply( 
embed=embed("Member Timed Out", 
f"{member.mention} for {duration}\nReason: {reason}", ORANGE), 
mention_author=False, 
)


@bot.hybrid_command(name="clear", description="Delete 1 to 100 recent messages.") 
@moderator() 
async def clear(ctx, amount: int): 
if not 1 <= amount <= 100: 
return await ctx.reply("Amount must be between 1 and 100.", mention_author=False) 
try: 
deleted = await ctx.channel.purge(limit=amount + 1) 
except discord.HTTPException as exc: 
return await ctx.reply(f"Failed: {exc}", mention_author=False) 
await ctx.send(f"🧹 Cleared {max(0, len(deleted) - 1)} messages.", delete_after=5)


------------------------------------------------------------
AUTOMATED PROTECTIONS
------------------------------------------------------------
@bot.event 
async def on_message(message: discord.Message): 
# Let command messages pass through untouched 
if message.author.bot: 
return await bot.process_commands(message)

is_cmd = (
    any(message.content.startswith(p) for p in PREFIXES)
    or message.content.startswith(f"<@{bot.user.id}>")
    or message.content.startswith(f"<@!{bot.user.id}>")
)

if not is_cmd and message.guild and isinstance(message.author, discord.Member):
    g = message.guild
    u = message.author

    if not u.guild_permissions.administrator and not await trusted(bot, g, u):
        for name in ("antiswear", "antilink", "antimention", "antispam"):
            d = await module_data(bot, g.id, name)
            if not d.get("enabled"):
                continue

            violation = False
            reason = ""

            if name == "antiswear":
                reason = bad_word(message.content) or ""
                violation = bool(reason)

            elif name == "antilink":
                urls = re.findall(
                    r"(?:https?://|www\.)[^\s]+|\b[\w.-]+\.(?:com|net|org|gg|io)\b",
                    message.content, re.I,
                )
                bad_domains = (
                    "discord-gifts.com", "discordnitro.com",
                    "dlscord.com", "steamcommunlty.com",
                )
                mode = d.get("mode", "phishing_only")
                violation = bool(urls) and (
                    mode == "block_all"
                    or any(bad in url.lower() for url in urls for bad in bad_domains)
                )
                reason = "link policy violation"

            elif name == "antimention":
                total = len(message.mentions) + len(message.role_mentions)
                violation = total > int(d.get("threshold", 5))
                reason = f"{total} mentions"

            elif name == "antispam":
                key = (g.id, u.id)
                now = time.monotonic()
                q = bot.spam[key]
                while q and now - q[0] > int(d.get("window", 5)):
                    q.popleft()
                q.append(now)
                violation = len(q) >= int(d.get("count", 6))
                reason = "message flood"
                if violation:
                    q.clear()

            if violation:
                try:
                    await message.delete()
                except discord.HTTPException:
                    pass

                if name == "antispam":
                    try:
                        await u.timeout(
                            discord.utils.utcnow() + timedelta(seconds=60),
                            reason="AegisLock anti-spam",
                        )
                    except discord.HTTPException:
                        pass

                try:
                    await message.channel.send(
                        f"{u.mention}, content removed by server security.",
                        delete_after=5,
                    )
                except discord.HTTPException:
                    pass

                await security_log(
                    bot, g,
                    embed(f"{MODULES[name]} Triggered",
                          f"User: {u}\nReason: {reason}", RED),
                )
                break

await bot.process_commands(message)

@bot.event 
async def on_member_join(member: discord.Member): 
# Blacklist auto-ban 
if await bot.db.run( 
"SELECT 1 FROM blacklist WHERE guild=? AND user=?", 
(member.guild.id, member.id), "one", 
): 
try: 
await member.ban(reason="AegisLock blacklist auto-ban") 
except discord.HTTPException: 
pass 
return

# Anti-raid
d = await module_data(bot, member.guild.id, "antiraid")
if d.get("enabled"):
    q = bot.joins[member.guild.id]
    now = time.monotonic()
    window = int(d.get("window", 10))
    while q and now - q[0] > window:
        q.popleft()
    q.append(now)
    age = (discord.utils.utcnow() - member.created_at).days
    if (len(q) >= int(d.get("threshold", 8))
            and age < int(d.get("min_account_age_days", 7))):
        try:
            await member.kick(reason="AegisLock anti-raid: suspicious join burst")
        except discord.HTTPException:
            pass
        await security_log(
            bot, member.guild,
            embed("Raid Activity",
                  f"Join burst detected; new account kicked: {member}", RED),
        )

@bot.event 
async def on_guild_role_delete(role: discord.Role): 
d = await module_data(bot, role.guild.id, "roleprotection") 
if d.get("enabled"): 
await security_log( 
bot, role.guild, 
embed("Role Deleted", f"Role {role.name} ({role.id}) was deleted.", ORANGE), 
)


@bot.event 
async def on_guild_role_update(before: discord.Role, after: discord.Role): 
d = await module_data(bot, after.guild.id, "roleprotection") 
if d.get("enabled") and before.permissions != after.permissions: 
await security_log( 
bot, after.guild, 
embed("Role Permissions Changed", 
f"Permissions changed for {after.name} ({after.id}).", ORANGE), 
)


@bot.event 
async def on_guild_channel_delete(channel: discord.abc.GuildChannel): 
d = await module_data(bot, channel.guild.id, "channelprotection") 
if d.get("enabled"): 
await security_log( 
bot, channel.guild, 
embed("Channel Deleted", 
f"#{channel.name} ({channel.id}) was deleted.", ORANGE), 
)


@bot.event 
async def on_guild_channel_update(before: discord.abc.GuildChannel, after: discord.abc.GuildChannel): 
d = await module_data(bot, after.guild.id, "channelprotection") 
if d.get("enabled") and before.overwrites != after.overwrites: 
await security_log( 
bot, after.guild, 
embed("Channel Overwrites Changed", 
f"Overwrites changed in {after.mention}.", ORANGE), 
)


@bot.event 
async def on_webhooks_update(channel: discord.abc.GuildChannel): 
d = await module_data(bot, channel.guild.id, "webhookprotection") 
if d.get("enabled"): 
await security_log( 
bot, channel.guild, 
embed("Webhook List Changed", 
f"Webhooks changed in {channel.mention}.", ORANGE), 
)


------------------------------------------------------------
ANTI-NUKE (audit log)
------------------------------------------------------------
NUKE_ACTIONS = { 
discord.AuditLogAction.ban: "ban", 
discord.AuditLogAction.kick: "kick", 
discord.AuditLogAction.channel_delete: "channel_delete", 
discord.AuditLogAction.role_delete: "role_delete", 
discord.AuditLogAction.channel_create: "channel_create", 
discord.AuditLogAction.role_create: "role_create", 
discord.AuditLogAction.webhook_create: "webhook_create", 
} 
NUKE_LIMITS = { 
"ban": (3, 10), "kick": (3, 10), 
"channel_delete": (2, 10), "role_delete": (2, 10), 
"channel_create": (3, 10), "role_create": (3, 10), 
"webhook_create": (3, 10), 
}


@bot.event 
async def on_audit_log_entry_create(entry: discord.AuditLogEntry): 
if not entry.guild or entry.action not in NUKE_ACTIONS: 
return 
d = await module_data(bot, entry.guild.id, "antinuke") 
if not d.get("enabled") or not entry.user: 
return 
if await trusted(bot, entry.guild, entry.user): 
return

kind = NUKE_ACTIONS[entry.action]
limit, window = NUKE_LIMITS[kind]
key = (entry.guild.id, entry.user.id, kind)
now = time.monotonic()

async with bot.nuke_lock:
    q = bot.nuke[key]
    while q and now - q[0] > window:
        q.popleft()
    q.append(now)
    count = len(q)
    if count < limit:
        return
    q.clear()

member = entry.guild.get_member(entry.user.id)
punishment = d.get("punishment", "strip_roles")
result = "logged"

try:
    if member and member.id != entry.guild.owner_id and entry.guild.me:
        if punishment == "ban":
            await entry.guild.ban(member, reason="AegisLock anti-nuke")
            result = "banned"
        elif punishment == "kick":
            await member.kick(reason="AegisLock anti-nuke")
            result = "kicked"
        else:
            roles = [
                r for r in member.roles
                if r != entry.guild.default_role
                and not r.managed
                and r < entry.guild.me.top_role
            ]
            if roles:
                await member.remove_roles(*roles, reason="AegisLock anti-nuke")
            result = "roles stripped"
except discord.HTTPException:
    result = "failed (permissions/API)"

e = embed("Anti-Nuke Triggered",
          f"{entry.user.mention} triggered `{kind}` {count} times.", RED)
e.add_field(name="Action", value=result)
await security_log(bot, entry.guild, e)

await bot.db.run(
    "INSERT INTO audit(guild,actor,action,target,details,at) VALUES(?,?,?,?,?,?)",
    (entry.guild.id, entry.user.id, f"antinuke:{kind}",
     getattr(entry.target, "id", None), result, now_iso()),
)

------------------------------------------------------------
GLOBAL ERROR HANDLERS
------------------------------------------------------------
@bot.event 
async def on_command_error(ctx: commands.Context, error: commands.CommandError): 
if isinstance(error, commands.CommandNotFound): 
return 
if isinstance(error, commands.MissingPermissions): 
msg = "You do not have permission to use this command." 
elif isinstance(error, commands.MissingRequiredArgument): 
msg = f"Missing argument: {error.param.name}. Use /help." 
elif isinstance(error, commands.BadArgument): 
msg = f"Invalid argument: {error}" 
elif isinstance(error, commands.CheckFailure): 
msg = "You do not meet the permission requirements for this command." 
else: 
log.exception("Command failed", exc_info=error) 
msg = "An unexpected error occurred. Check the bot logs." 
try: 
await ctx.reply(embed=embed(BRAND, msg, RED), mention_author=False) 
except discord.HTTPException: 
pass


@bot.tree.error 
async def app_error(interaction: discord.Interaction, error: discord.app_commands.AppCommandError): 
log.error("Slash command error: %s", error) 
msg = ( 
"You do not have permission to use this command." 
if isinstance(error, discord.app_commands.MissingPermissions) 
else "An unexpected error occurred." 
) 
try: 
if interaction.response.is_done(): 
await interaction.followup.send(msg, ephemeral=True) 
else: 
await interaction.response.send_message(msg, ephemeral=True) 
except discord.HTTPException: 
pass


------------------------------------------------------------
ENTRY POINT
------------------------------------------------------------
if name == "main": 
if not TOKEN: 
raise SystemExit("Set DISCORD_TOKEN in Railway Variables or your environment.") 
bot.run(TOKEN)
