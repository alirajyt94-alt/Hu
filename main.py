# AegisLock Sentinel — single-file Discord security & moderation bot
# Install: pip install -U discord.py aiosqlite python-dotenv
# Set DISCORD_TOKEN in Railway Variables (or environment).
import os, re, json, time, asyncio, logging, unicodedata
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque

import discord
from discord.ext import commands
import aiosqlite

TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
DB_PATH = os.getenv("DATABASE_PATH", "aegislock.db")
PREFIXES = tuple(x.strip() for x in os.getenv("PREFIXES", ".,!").split(",") if x.strip())
BRAND = "AegisLock Sentinel"
GOLD, RED, GREEN = 0xD4AF37, 0xE74C3C, 0x2ECC71
FOOTER = f"{BRAND} | Security & Moderation"
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("AegisLock")

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def embed(title=None, description=None, color=GOLD):
    e = discord.Embed(title=title, description=description, color=color, timestamp=discord.utils.utcnow())
    e.set_footer(text=FOOTER)
    return e

class Database:
    def __init__(self, path):
        self.path, self.conn, self.lock = path, None, asyncio.Lock()
    async def connect(self):
        self.conn = await aiosqlite.connect(self.path)
        self.conn.row_factory = aiosqlite.Row
        await self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS settings(guild INTEGER PRIMARY KEY,data TEXT NOT NULL DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS blacklist(guild INTEGER,user INTEGER,reason TEXT,by_user INTEGER,at TEXT,PRIMARY KEY(guild,user));
        CREATE TABLE IF NOT EXISTS whitelist(guild INTEGER,user INTEGER,by_user INTEGER,at TEXT,PRIMARY KEY(guild,user));
        CREATE TABLE IF NOT EXISTS trusted_bots(guild INTEGER,user INTEGER,by_user INTEGER,at TEXT,PRIMARY KEY(guild,user));
        CREATE TABLE IF NOT EXISTS warnings(id INTEGER PRIMARY KEY AUTOINCREMENT,guild INTEGER,user INTEGER,moderator INTEGER,reason TEXT,at TEXT);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,guild INTEGER,actor INTEGER,action TEXT,target INTEGER,details TEXT,at TEXT);
        """)
        await self.conn.commit()
    async def run(self, sql, args=(), fetch=None):
        async with self.lock:
            cur = await self.conn.execute(sql, args)
            if fetch == "one": result = await cur.fetchone()
            elif fetch == "all": result = await cur.fetchall()
            else: result = cur.rowcount
            await self.conn.commit()
            return result
    async def settings(self, gid):
        r = await self.run("SELECT data FROM settings WHERE guild=?", (gid,), "one")
        return json.loads(r["data"]) if r else {}
    async def save_settings(self, gid, data):
        await self.run("INSERT INTO settings VALUES(?,?) ON CONFLICT(guild) DO UPDATE SET data=excluded.data",
                       (gid, json.dumps(data)))
    async def is_whitelisted(self,g,u):
        return bool(await self.run("SELECT 1 FROM whitelist WHERE guild=? AND user=?", (g,u), "one"))
    async def is_trusted_bot(self,g,u):
        return bool(await self.run("SELECT 1 FROM trusted_bots WHERE guild=? AND user=?", (g,u), "one"))
    async def close(self):
        if self.conn: await self.conn.close()

def admin():
    async def predicate(ctx):
        if not ctx.guild or not isinstance(ctx.author, discord.Member):
            raise commands.CheckFailure("Server only.")
        if ctx.author.id == ctx.guild.owner_id or ctx.author.guild_permissions.administrator or ctx.author.guild_permissions.manage_guild:
            return True
        raise commands.MissingPermissions(["manage_guild"])
    return commands.check(predicate)

def moderator():
    async def predicate(ctx):
        if not ctx.guild or not isinstance(ctx.author, discord.Member): raise commands.CheckFailure("Server only.")
        p=ctx.author.guild_permissions
        if ctx.author.id==ctx.guild.owner_id or p.administrator or p.manage_guild or p.kick_members or p.ban_members or p.moderate_members: return True
        raise commands.MissingPermissions(["moderate_members"])
    return commands.check(predicate)

async def module_data(bot, guild, name):
    return (await bot.db.settings(guild)).get(name,{})
async def update_module(bot,guild,name,data):
    s=await bot.db.settings(guild); s[name]=data; await bot.db.save_settings(guild,s)
async def security_log(bot,guild,e):
    s=await bot.db.settings(guild); ch=guild.get_channel(s.get("security_log_channel",0))
    if ch:
        try: await ch.send(embed=e)
        except discord.HTTPException: pass
async def trusted(bot,guild,user):
    return (user.id == guild.owner_id or (bot.user and user.id==bot.user.id)
            or await bot.is_owner(user) or await bot.db.is_whitelisted(guild.id,user.id)
            or (user.bot and await bot.db.is_trusted_bot(guild.id,user.id)))

def hierarchy(ctx, member):
    return (member.id != ctx.guild.owner_id and ctx.author.id != member.id
            and (ctx.author.id == ctx.guild.owner_id or ctx.author.top_role > member.top_role)
            and ctx.guild.me and ctx.guild.me.top_role > member.top_role)

BAD_WORDS = {"fuck","shit","bitch","asshole","bastard","dick","pussy","cunt","slut","whore",
 "motherfucker","bullshit","prick","wanker","twat","মাদারচোদ","চুদি","চোদা","খানকি","মাগি",
 "গান্ডু","গাণ্ডু","বেশ্যা","হারামজাদা","হারামি","madarchod","maderchod","chudi","chuda",
 "choda","khanki","magi","gandu","beshya","haramjada","harami","banchod","bokachoda","chodna"}
TRANS=str.maketrans({"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","@":"a","$":"s","!":"i"})
def norm(s):
    s=unicodedata.normalize("NFKC",s or "").lower().translate(TRANS)
    s=re.sub(r"(.)\1{2,}",r"\1\1",s)
    return re.sub(r"[^\w\u0980-\u09ff]","",s)
BAD_NORMALIZED={norm(w) for w in BAD_WORDS}
def bad_word(text):
    compact=norm(text)
    return next((w for w in BAD_NORMALIZED if len(w)>2 and w in compact),None)

MODULES = {
 "antiraid":"Anti-Raid","antiswear":"Anti-Swear","antispam":"Anti-Spam",
 "antilink":"Anti-Link","antimention":"Anti-Mention",
 "roleprotection":"Role Protection","channelprotection":"Channel Protection",
 "webhookprotection":"Webhook Protection"
}
DEFAULTS = {"antiraid":{"window":10,"threshold":8,"min_account_age_days":7},
 "antispam":{"window":5,"count":6},"antilink":{"mode":"phishing_only"},
 "antimention":{"threshold":5},"antinuke":{"punishment":"strip_roles"}}

class AegisBot(commands.Bot):
    def __init__(self):
        intents=discord.Intents.default()
        intents.members=True
        intents.message_content=True
        intents.moderation=True
        super().__init__(command_prefix=commands.when_mentioned_or(*PREFIXES),
            intents=intents, help_command=None, case_insensitive=True,
            allowed_mentions=discord.AllowedMentions.none())
        self.db=Database(DB_PATH)
        self.spam=defaultdict(deque); self.joins=defaultdict(deque)
        self.nuke=defaultdict(deque); self.nuke_lock=asyncio.Lock()
    async def setup_hook(self):
        await self.db.connect()
        try:
            synced=await self.tree.sync()
            log.info("Synced %d slash commands",len(synced))
        except Exception: log.exception("Slash command sync failed")
    async def on_ready(self):
        log.info("Online as %s (%s)",self.user,self.user.id)
        await self.change_presence(activity=discord.Activity(type=discord.ActivityType.watching,name="server security | /help"))
    async def close(self):
        await self.db.close()
        await super().close()

bot=AegisBot()

# ---------- Help and status ----------
@bot.hybrid_command(name="help",description="Show all AegisLock commands.")
async def help_cmd(ctx):
    e=embed(BRAND,"Security, anti-abuse and moderation controls.")
    e.add_field(name="Security modules",value="`/antinuke` `/antiraid` `/antiswear` `/antispam` `/antilink` `/antimention` `/roleprotection` `/channelprotection` `/webhookprotection`",inline=False)
    e.add_field(name="Server tools",value="`/securitylog` `/lockdown` `/whitelist` `/blacklist` `/status`",inline=False)
    e.add_field(name="Moderation",value="`/warn` `/warnings` `/kick` `/ban` `/unban` `/timeout` `/clear`",inline=False)
    e.add_field(name="Quick enable",value="Run any protection command by itself, for example `/antinuke`. It turns that protection ON. Optional: add `off` to disable or `info` to check status.",inline=False)
    await ctx.reply(embed=e,mention_author=False)

@bot.hybrid_command(name="status",description="Show security module status.")
async def status_cmd(ctx):
    if not ctx.guild: return await ctx.reply("Use this in a server.")
    s=await bot.db.settings(ctx.guild.id); e=embed("Security Status")
    for n in ["antinuke",*MODULES]:
        e.add_field(name=MODULES.get(n,"Anti-Nuke"),value="ON" if s.get(n,{}).get("enabled") else "OFF",inline=True)
    e.add_field(name="Lockdown",value="ACTIVE" if s.get("lockdown") else "OFF",inline=True)
    await ctx.reply(embed=e,mention_author=False)

# ---------- Module configuration ----------
def make_module_command(name, label):
    async def command(ctx, action: str = "on"):
        if not ctx.guild:
            return await ctx.reply("Use this command in a server.", mention_author=False)

        action = (action or "on").lower()
        data = await module_data(bot, ctx.guild.id, name)
        data = {**DEFAULTS.get(name, {}), **data}

        if action in ("on", "enable"):
            data["enabled"] = True
            await update_module(bot, ctx.guild.id, name, data)
            return await ctx.reply(
                embed=embed(f"{label} Enabled", "Protection is now **ON**.", GREEN),
                mention_author=False
            )

        if action in ("off", "disable"):
            data["enabled"] = False
            await update_module(bot, ctx.guild.id, name, data)
            return await ctx.reply(
                embed=embed(f"{label} Disabled", "Protection is now **OFF**.", RED),
                mention_author=False
            )

        if action == "info":
            return await ctx.reply(
                embed=embed(
                    f"{label} Status",
                    f"Enabled: **{'YES' if data.get('enabled') else 'NO'}**\nSettings: `{data}`"
                ),
                mention_author=False
            )

        await ctx.reply(
            "Run this command without an argument to enable it; use `off` or `info` optionally.",
            mention_author=False
        )

    command.__name__ = name + "_command"
    command = commands.hybrid_command(
        name=name,
        description=f"Enable {label} with one command."
    )(command)
    command = admin()(command)
    bot.add_command(command)

for _name,_label in {"antinuke":"Anti-Nuke",**MODULES}.items():
    make_module_command(_name,_label)

# ---------- Security log ----------
@bot.hybrid_command(name="securitylog",description="Set or clear the security log channel.")
@admin()
async def securitylog(ctx, action="info", channel:discord.TextChannel=None):
    s=await bot.db.settings(ctx.guild.id); action=action.lower()
    if action=="setchannel":
        if channel is None: return await ctx.reply("Usage: `/securitylog setchannel #channel`.")
        s["security_log_channel"]=channel.id; await bot.db.save_settings(ctx.guild.id,s)
        return await ctx.reply(embed=embed("Security Log Set",channel.mention),mention_author=False)
    if action=="clear":
        s.pop("security_log_channel",None); await bot.db.save_settings(ctx.guild.id,s)
        return await ctx.reply("Security log channel cleared.")
    ch=ctx.guild.get_channel(s.get("security_log_channel",0))
    await ctx.reply(embed=embed("Security Log",ch.mention if ch else "Not configured."),mention_author=False)

# ---------- Whitelist / trusted bots ----------
@bot.hybrid_command(name="whitelist",description="Manage trusted users and bots.")
@admin()
async def whitelist(ctx,action:str,user:discord.User=None):
    action=action.lower(); g=ctx.guild.id
    if action in ("add","remove") and user is None: return await ctx.reply("Specify a user.")
    if action=="add":
        table="trusted_bots" if user.bot else "whitelist"
        await bot.db.run(f"INSERT OR REPLACE INTO {table} VALUES(?,?,?,?)",(g,user.id,ctx.author.id,now_iso()))
        return await ctx.reply(embed=embed("Trusted Entry Added",str(user)),mention_author=False)
    if action=="remove":
        table="trusted_bots" if user.bot else "whitelist"
        n=await bot.db.run(f"DELETE FROM {table} WHERE guild=? AND user=?",(g,user.id))
        return await ctx.reply("Entry removed." if n else "Entry not found.")
    if action=="list":
        u=await bot.db.run("SELECT user FROM whitelist WHERE guild=?",(g,),"all")
        b=await bot.db.run("SELECT user FROM trusted_bots WHERE guild=?",(g,),"all")
        e=embed("Trusted Users & Bots")
        e.add_field(name="Users",value="\n".join(f"<@{r['user']}>" for r in u[:20]) or "None",inline=False)
        e.add_field(name="Bots",value="\n".join(f"<@{r['user']}>" for r in b[:20]) or "None",inline=False)
        return await ctx.reply(embed=e,mention_author=False)
    await ctx.reply("Use `add`, `remove`, or `list`.")

# ---------- Blacklist ----------
@bot.hybrid_command(name="blacklist",description="Manage the server blacklist.")
@admin()
async def blacklist(ctx,action:str,user:discord.User=None,*,reason="No reason"):
    if action=="add":
        if not user:return await ctx.reply("Specify a user.")
        await bot.db.run("INSERT OR REPLACE INTO blacklist VALUES(?,?,?,?,?)",(ctx.guild.id,user.id,reason,ctx.author.id,now_iso()))
        return await ctx.reply(embed=embed("Blacklisted",f"{user} added."))
    if action=="remove":
        if not user:return await ctx.reply("Specify a user.")
        n=await bot.db.run("DELETE FROM blacklist WHERE guild=? AND user=?",(ctx.guild.id,user.id))
        return await ctx.reply("Entry removed." if n else "User not found.")
    if action=="list":
        rows=await bot.db.run("SELECT user,reason FROM blacklist WHERE guild=?",(ctx.guild.id,),"all")
        return await ctx.reply(embed=embed("Blacklist","\n".join(f"<@{r['user']}> — {r['reason']}" for r in rows[:40]) or "Empty"))
    await ctx.reply("Use `add`, `remove`, or `list`.")

# ---------- Lockdown ----------
@bot.hybrid_command(name="lockdown",description="Lock or unlock all server text channels.")
@admin()
async def lockdown(ctx,action="info"):
    s=await bot.db.settings(ctx.guild.id); action=action.lower()
    if action=="info": return await ctx.reply(embed=embed("Lockdown","ACTIVE" if s.get("lockdown") else "Inactive"))
    if action=="on":
        if s.get("lockdown"):return await ctx.reply("Lockdown already active.")
        prev={}; changed=0
        for ch in ctx.guild.text_channels:
            ow=ch.overwrites_for(ctx.guild.default_role); prev[str(ch.id)]=ow.send_messages
            if ow.send_messages is not False:
                ow.send_messages=False
                try: await ch.set_permissions(ctx.guild.default_role,overwrite=ow,reason="AegisLock lockdown"); changed+=1
                except discord.HTTPException: pass
        s["lockdown_previous"]=prev;s["lockdown"]=True;await bot.db.save_settings(ctx.guild.id,s)
        e=embed("Lockdown Activated",f"Locked {changed} channels.");await security_log(bot,ctx.guild,e)
        return await ctx.reply(embed=e)
    if action=="off":
        if not s.get("lockdown"):return await ctx.reply("No active lockdown.")
        restored=0
        for ch in ctx.guild.text_channels:
            if str(ch.id) not in s.get("lockdown_previous",{}):continue
            ow=ch.overwrites_for(ctx.guild.default_role);ow.send_messages=s["lockdown_previous"][str(ch.id)]
            try:await ch.set_permissions(ctx.guild.default_role,overwrite=ow,reason="AegisLock lockdown release");restored+=1
            except discord.HTTPException:pass
        s["lockdown"]=False;s["lockdown_previous"]={};await bot.db.save_settings(ctx.guild.id,s)
        e=embed("Lockdown Released",f"Restored {restored} channels.");await security_log(bot,ctx.guild,e)
        return await ctx.reply(embed=e)
    await ctx.reply("Use `on`, `off`, or `info`.")

# ---------- Moderation ----------
@bot.hybrid_command(name="warn",description="Warn a member.")
@moderator()
async def warn(ctx,member:discord.Member,*,reason="No reason"):
    if not hierarchy(ctx,member):return await ctx.reply("Role hierarchy prevents this action.")
    await bot.db.run("INSERT INTO warnings(guild,user,moderator,reason,at) VALUES(?,?,?,?,?)",(ctx.guild.id,member.id,ctx.author.id,reason,now_iso()))
    rows=await bot.db.run("SELECT id FROM warnings WHERE guild=? AND user=?",(ctx.guild.id,member.id),"all")
    try:await member.send(f"You were warned in {ctx.guild.name}: {reason}")
    except discord.HTTPException:pass
    await ctx.reply(embed=embed("Member Warned",f"{member.mention}\nWarnings: {len(rows)}\nReason: {reason}"))
@bot.hybrid_command(name="warnings",description="View a member's warnings.")
@moderator()
async def warnings(ctx,member:discord.Member):
    rows=await bot.db.run("SELECT * FROM warnings WHERE guild=? AND user=? ORDER BY id DESC",(ctx.guild.id,member.id),"all")
    await ctx.reply(embed=embed(f"Warnings: {member}","\n".join(f"#{r['id']} — {r['reason']} (by <@{r['moderator']}>)" for r in rows[:15]) or "No warnings."))
@bot.hybrid_command(name="kick",description="Kick a member.")
@moderator()
async def kick(ctx,member:discord.Member,*,reason="No reason"):
    if not hierarchy(ctx,member):return await ctx.reply("Role hierarchy prevents this action.")
    await member.kick(reason=f"{ctx.author}: {reason}");await ctx.reply(embed=embed("Member Kicked",f"{member} — {reason}"))
@bot.hybrid_command(name="ban",description="Ban a member.")
@moderator()
async def ban(ctx,member:discord.Member,delete_days:int=0,*,reason="No reason"):
    if not hierarchy(ctx,member):return await ctx.reply("Role hierarchy prevents this action.")
    await member.ban(reason=f"{ctx.author}: {reason}",delete_message_seconds=max(0,min(7,delete_days))*86400)
    await ctx.reply(embed=embed("Member Banned",f"{member} — {reason}"))
@bot.hybrid_command(name="unban",description="Unban a user by ID.")
@moderator()
async def unban(ctx,user_id:str,*,reason="No reason"):
    try:uid=int(user_id)
    except ValueError:return await ctx.reply("Invalid user ID.")
    try:await ctx.guild.unban(discord.Object(id=uid),reason=f"{ctx.author}: {reason}")
    except discord.NotFound:return await ctx.reply("That user is not banned.")
    await ctx.reply(embed=embed("User Unbanned",f"ID: {uid}"))
@bot.hybrid_command(name="timeout",description="Timeout a member. Duration: 10m, 1h, 1d.")
@moderator()
async def timeout(ctx,member:discord.Member,duration:str,*,reason="No reason"):
    if not hierarchy(ctx,member):return await ctx.reply("Role hierarchy prevents this action.")
    m=re.fullmatch(r"(\d+)([smhd])",duration.lower())
    if not m:return await ctx.reply("Use a duration like `10m`, `1h`, or `1d`.")
    secs=int(m.group(1))*{"s":1,"m":60,"h":3600,"d":86400}[m.group(2)]
    secs=max(1,min(secs,28*86400))
    await member.timeout(discord.utils.utcnow()+timedelta(seconds=secs),reason=f"{ctx.author}: {reason}")
    await ctx.reply(embed=embed("Member Timed Out",f"{member.mention} for {duration}. Reason: {reason}"))
@bot.hybrid_command(name="clear",description="Delete 1 to 100 recent messages.")
@moderator()
async def clear(ctx,amount:int):
    if not 1<=amount<=100:return await ctx.reply("Amount must be 1–100.")
    deleted=await ctx.channel.purge(limit=amount+1)
    await ctx.send(f"Cleared {max(0,len(deleted)-1)} messages.",delete_after=5)

# ---------- Automated protections ----------
@bot.event
async def on_message(message):
    if message.guild and not message.author.bot and isinstance(message.author,discord.Member):
        g=message.guild; u=message.author
        if not u.guild_permissions.administrator and not await trusted(bot,g,u):
            for name in ("antiswear","antilink","antimention","antispam"):
                d=await module_data(bot,g.id,name)
                if not d.get("enabled"):continue
                violation=False; reason=""
                if name=="antiswear":
                    reason=bad_word(message.content) or "";violation=bool(reason)
                elif name=="antilink":
                    urls=re.findall(r"(?:https?://|www\.)[^\s]+|\b[\w.-]+\.(?:com|net|org|gg|io)\b",message.content,re.I)
                    bad=("discord-gifts.com","discordnitro.com","dlscord.com","steamcommunlty.com")
                    violation=bool(urls) and (d.get("mode","phishing_only")=="block_all" or any(x in xurl.lower() for xurl in urls for x in bad))
                    reason="link policy violation"
                elif name=="antimention":
                    total=len(message.mentions)+len(message.role_mentions)
                    violation=total>int(d.get("threshold",5));reason=f"{total} mentions"
                elif name=="antispam":
                    key=(g.id,u.id);now=time.monotonic();q=bot.spam[key]
                    while q and now-q[0]>int(d.get("window",5)):q.popleft()
                    q.append(now);violation=len(q)>=int(d.get("count",6));reason="message flood"
                    if violation:q.clear()
                if violation:
                    try:await message.delete()
                    except discord.HTTPException:pass
                    if name=="antispam":
                        try:await u.timeout(discord.utils.utcnow()+timedelta(seconds=60),reason="AegisLock anti-spam")
                        except discord.HTTPException:pass
                    try:await message.channel.send(f"{u.mention}, content removed by server security.",delete_after=5)
                    except discord.HTTPException:pass
                    await security_log(bot,g,embed(MODULES[name]+" Triggered",f"User: {u}\nReason: {reason}"))
                    break
    await bot.process_commands(message)

@bot.event
async def on_member_join(member):
    # Automatic blacklist enforcement
    if await bot.db.run("SELECT 1 FROM blacklist WHERE guild=? AND user=?",(member.guild.id,member.id),"one"):
        try:await member.ban(reason="AegisLock blacklist")
        except discord.HTTPException:pass
        return
    d=await module_data(bot,member.guild.id,"antiraid")
    if d.get("enabled"):
        q=bot.joins[member.guild.id];now=time.monotonic()
        while q and now-q[0]>int(d.get("window",10)):q.popleft()
        q.append(now)
        age=(discord.utils.utcnow()-member.created_at).days
        if len(q)>=int(d.get("threshold",8)) and age<int(d.get("min_account_age_days",7)):
            try:await member.kick(reason="AegisLock anti-raid: suspicious join burst")
            except discord.HTTPException:pass
            await security_log(bot,member.guild,embed("Raid Activity",f"Join burst detected; new account: {member}"))

@bot.event
async def on_guild_role_delete(role):
    d=await module_data(bot,role.guild.id,"roleprotection")
    if d.get("enabled"):await security_log(bot,role.guild,embed("Role Deleted",f"Role `{role.name}` was deleted."))
@bot.event
async def on_guild_role_update(before,after):
    d=await module_data(bot,after.guild.id,"roleprotection")
    if d.get("enabled") and before.permissions!=after.permissions:
        await security_log(bot,after.guild,embed("Role Permissions Changed",f"Permissions changed for `{after.name}`."))
@bot.event
async def on_guild_channel_delete(channel):
    d=await module_data(bot,channel.guild.id,"channelprotection")
    if d.get("enabled"):await security_log(bot,channel.guild,embed("Channel Deleted",f"`{channel.name}` was deleted."))
@bot.event
async def on_guild_channel_update(before,after):
    d=await module_data(bot,after.guild.id,"channelprotection")
    if d.get("enabled") and before.overwrites!=after.overwrites:
        await security_log(bot,after.guild,embed("Channel Overwrites Changed",f"Overwrites changed in {after.mention}."))
@bot.event
async def on_webhooks_update(channel):
    d=await module_data(bot,channel.guild.id,"webhookprotection")
    if d.get("enabled"):await security_log(bot,channel.guild,embed("Webhook Updated",f"Webhook list changed in {channel.mention}."))

# Anti-nuke audit-log monitoring
NUKE_ACTIONS={
 discord.AuditLogAction.ban:"ban",discord.AuditLogAction.kick:"kick",
 discord.AuditLogAction.channel_delete:"channel_delete",discord.AuditLogAction.role_delete:"role_delete",
 discord.AuditLogAction.channel_create:"channel_create",discord.AuditLogAction.role_create:"role_create",
 discord.AuditLogAction.webhook_create:"webhook_create"}
NUKE_LIMITS={"ban":(3,10),"kick":(3,10),"channel_delete":(2,10),"role_delete":(2,10),
 "channel_create":(3,10),"role_create":(3,10),"webhook_create":(3,10)}
@bot.event
async def on_audit_log_entry_create(entry):
    if not entry.guild or entry.action not in NUKE_ACTIONS:return
    d=await module_data(bot,entry.guild.id,"antinuke")
    if not d.get("enabled") or not entry.user or await trusted(bot,entry.guild,entry.user):return
    kind=NUKE_ACTIONS[entry.action];limit,window=NUKE_LIMITS[kind];key=(entry.guild.id,entry.user.id,kind);now=time.monotonic()
    async with bot.nuke_lock:
        q=bot.nuke[key]
        while q and now-q[0]>window:q.popleft()
        q.append(now);count=len(q)
        if count<limit:return
        q.clear()
    member=entry.guild.get_member(entry.user.id);pun=d.get("punishment","strip_roles");result="logged"
    try:
        if member and member.id!=entry.guild.owner_id:
            if pun=="ban":await entry.guild.ban(member,reason="AegisLock anti-nuke");result="banned"
            elif pun=="kick":await member.kick(reason="AegisLock anti-nuke");result="kicked"
            else:
                bot_member = entry.guild.me
                if bot_member is None:
                    result = "failed (bot member unavailable)"
                else:
                    roles = [
                        role for role in member.roles
                        if role != entry.guild.default_role
                        and not role.managed
                        and role < bot_member.top_role
                    ]
                    if roles:
                        await member.remove_roles(*roles, reason="AegisLock anti-nuke")
                result="roles stripped"
    except discord.HTTPException:result="failed (permissions/API)"
    e=embed("Anti-Nuke Triggered",f"{entry.user} triggered `{kind}` {count} times.")
    e.add_field(name="Action",value=result)
    await security_log(bot,entry.guild,e)
    await bot.db.run("INSERT INTO audit(guild,actor,action,target,details,at) VALUES(?,?,?,?,?,?)",
        (entry.guild.id,entry.user.id,"antinuke:"+kind,getattr(entry.target,"id",None),result,now_iso()))

@bot.event
async def on_command_error(ctx,error):
    if isinstance(error,commands.CommandNotFound):return
    if isinstance(error,commands.MissingPermissions):msg="You do not have permission to use this command."
    elif isinstance(error,commands.MissingRequiredArgument):msg=f"Missing argument: `{error.param.name}`. Use `/help`."
    elif isinstance(error,commands.BadArgument):msg=f"Invalid argument: {error}"
    else:
        log.exception("Command failed",exc_info=error);msg="An unexpected error occurred. Check the bot logs."
    try:await ctx.reply(embed=embed(BRAND,msg,RED),mention_author=False)
    except discord.HTTPException:pass

@bot.tree.error
async def app_error(interaction,error):
    log.error("Slash command error: %s",error)
    original = getattr(error, "original", error)
    if isinstance(original, (discord.app_commands.MissingPermissions, commands.MissingPermissions)):
        msg = "You do not have permission to use this command."
    else:
        log.exception("Application command failed", exc_info=original)
        msg = "An unexpected error occurred. Check the bot logs."
    try:
        if interaction.response.is_done():await interaction.followup.send(msg,ephemeral=True)
        else:await interaction.response.send_message(msg,ephemeral=True)
    except discord.HTTPException:pass

if __name__=="__main__":
    if not TOKEN:raise SystemExit("Set DISCORD_TOKEN in Railway Variables or your environment.")
    bot.run(TOKEN)
