"""SMAI Sentinel Command Center — Backend v2.1"""
import sqlite3, uuid, hashlib, json, secrets
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI(title="SMAI Sentinel API", version="2.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
DB = "sentinel.db"

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def hp(pw): return hashlib.sha256(pw.encode()).hexdigest()

def get_ip(request: Request):
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "127.0.0.1")

def init():
    conn = db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
            verified INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0,
            created_at TEXT, last_ip TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY, sender_id TEXT NOT NULL, recipient_id TEXT,
            case_id TEXT, content TEXT NOT NULL, read_by TEXT DEFAULT '[]', created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, platform TEXT NOT NULL DEFAULT 'roblox',
            target_uid TEXT, created_by TEXT, risk_level TEXT DEFAULT 'low',
            status TEXT DEFAULT 'active', notes TEXT DEFAULT '', created_at TEXT, updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, case_id TEXT NOT NULL, description TEXT NOT NULL,
            event_type TEXT DEFAULT 'info', created_by TEXT, ts TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY, case_id TEXT NOT NULL, title TEXT NOT NULL,
            url TEXT, ev_type TEXT DEFAULT 'link', description TEXT, ts TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS relationships (
            id TEXT PRIMARY KEY, src TEXT NOT NULL, tgt TEXT NOT NULL,
            rel_type TEXT NOT NULL, notes TEXT, ts TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS announcements (
            id TEXT PRIMARY KEY, title TEXT NOT NULL, content TEXT NOT NULL,
            created_by TEXT NOT NULL, creator_name TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS global_chat (
            id TEXT PRIMARY KEY, sender_id TEXT NOT NULL, sender_name TEXT NOT NULL,
            sender_role TEXT NOT NULL, sender_verified INTEGER DEFAULT 0,
            content TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bans (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE, reason TEXT DEFAULT '',
            banned_by TEXT NOT NULL, ban_until TEXT, unban_msg TEXT DEFAULT 'החסימה הוסרה',
            ip_banned INTEGER DEFAULT 0, banned_ip TEXT DEFAULT '',
            created_at TEXT NOT NULL, appeal_after_hours INTEGER DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS inbox_msgs (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL, title TEXT NOT NULL,
            content TEXT NOT NULL, msg_type TEXT DEFAULT 'info',
            is_read INTEGER DEFAULT 0, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ip_bans (
            id TEXT PRIMARY KEY, ip TEXT NOT NULL UNIQUE, reason TEXT DEFAULT '',
            banned_by TEXT NOT NULL, ban_until TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS departments (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '',
            color TEXT DEFAULT '#00d4aa', icon TEXT DEFAULT '🏢', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS user_departments (
            user_id TEXT NOT NULL, dept_id TEXT NOT NULL,
            PRIMARY KEY(user_id, dept_id)
        );
        CREATE TABLE IF NOT EXISTS appeals (
            id TEXT PRIMARY KEY, ban_id TEXT NOT NULL, user_id TEXT NOT NULL,
            message TEXT NOT NULL, status TEXT DEFAULT 'pending',
            response TEXT DEFAULT '', reviewed_by TEXT DEFAULT '',
            created_at TEXT NOT NULL, reviewed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS delete_requests (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE,
            reason TEXT DEFAULT '', status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL
        );
    """)
    for col, defn in [("last_ip","TEXT DEFAULT ''"), ("appeal_after_hours","INTEGER DEFAULT NULL")]:
        try: conn.execute(f"ALTER TABLE users ADD COLUMN {col} {defn}")
        except: pass
    try: conn.execute("ALTER TABLE bans ADD COLUMN appeal_after_hours INTEGER DEFAULT NULL")
    except: pass
    conn.commit(); conn.close()

init()

# ── Auth ──────────────────────────────────────────────────────────────────────

def get_user(request: Request, authorization: Optional[str] = Header(None)):
    ip = get_ip(request)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "לא מחובר")
    token = authorization[7:]
    conn = db()
    ib = conn.execute("SELECT * FROM ip_bans WHERE ip=?", (ip,)).fetchone()
    if ib:
        if ib["ban_until"] and datetime.fromisoformat(ib["ban_until"]) < datetime.now():
            conn.execute("DELETE FROM ip_bans WHERE ip=?", (ip,)); conn.commit()
        else:
            conn.close(); raise HTTPException(403, f"IP חסום: {ib['reason'] or 'פנה למנהל'}")
    s = conn.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
    if not s: conn.close(); raise HTTPException(401, "סשן לא תקף")
    u = conn.execute("SELECT * FROM users WHERE id=?", (s["user_id"],)).fetchone()
    if not u: conn.close(); raise HTTPException(401)
    conn.execute("UPDATE users SET last_ip=? WHERE id=?", (ip, u["id"]))
    if u["blocked"]:
        ban = conn.execute("SELECT * FROM bans WHERE user_id=?", (u["id"],)).fetchone()
        if ban and ban["ban_until"] and datetime.fromisoformat(ban["ban_until"]) < datetime.now():
            now = datetime.now().isoformat()
            conn.execute("UPDATE users SET blocked=0 WHERE id=?", (u["id"],))
            conn.execute("DELETE FROM bans WHERE user_id=?", (u["id"],))
            conn.execute("INSERT INTO inbox_msgs VALUES(?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), u["id"], "✅ החסימה הוסרה",
                 ban["unban_msg"] or "תקופת החסימה הסתיימה. ברוך השב!", "unban", 0, now))
            conn.commit()
            u = conn.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
        elif not ban:
            conn.execute("UPDATE users SET blocked=0 WHERE id=?", (u["id"],)); conn.commit()
            u = conn.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    conn.commit(); conn.close()
    if u["blocked"]:
        conn2 = db()
        ban = conn2.execute("SELECT * FROM bans WHERE user_id=?", (u["id"],)).fetchone(); conn2.close()
        msg = ban["reason"] or "חשבונך הוגבל" if ban else "חשבונך הוגבל"
        if ban and ban["ban_until"]: msg += f" | עד: {ban['ban_until'][:16].replace('T',' ')}"
        raise HTTPException(403, f"חסום: {msg}")
    return dict(u)

ROLE_LEVEL = {"user":0,"team":1,"team_senior":2,"deputy_senior":3,"senior":4,"deputy_admin":5,"admin":6}

def role_lvl(r): return ROLE_LEVEL.get(r, 0)

def admin_only(u=Depends(get_user)):
    if role_lvl(u["role"]) < 6: raise HTTPException(403, "נדרשות הרשאות מנהל")
    return u

def team_up(u=Depends(get_user)):
    if role_lvl(u["role"]) < 1: raise HTTPException(403, "נדרשות הרשאות צוות")
    return u

def senior_up(u=Depends(get_user)):
    if role_lvl(u["role"]) < 4: raise HTTPException(403, "נדרשות הרשאות בכיר")
    return u

def deputy_admin_up(u=Depends(get_user)):
    if role_lvl(u["role"]) < 5: raise HTTPException(403, "נדרשות הרשאות סגן מנהל")
    return u

# ── Models ────────────────────────────────────────────────────────────────────

class LoginIn(BaseModel): email: str; password: str
class RegisterIn(BaseModel): display_name: str; email: str; password: str
class UserCreate(BaseModel): email: str; password: str; display_name: str; role: str = "user"
class RoleUpdate(BaseModel): role: str
class CaseIn(BaseModel):
    name: str; platform: str = "roblox"; target_uid: Optional[str] = None
    risk_level: str = "low"; notes: Optional[str] = ""
class CaseUp(BaseModel):
    name: Optional[str]=None; risk_level: Optional[str]=None
    status: Optional[str]=None; notes: Optional[str]=None
class EventIn(BaseModel): description: str; event_type: str = "info"
class EvidIn(BaseModel): title: str; url: Optional[str]=None; ev_type: str="link"; description: Optional[str]=None
class RelIn(BaseModel): src: str; tgt: str; rel_type: str; notes: Optional[str]=None
class MsgIn(BaseModel): content: str; recipient_id: Optional[str]=None; case_id: Optional[str]=None
class BanIn(BaseModel):
    reason: str = ""; duration_hours: Optional[int] = None
    ip_banned: bool = False; unban_msg: str = "תקופת החסימה שלך הסתיימה. ברוך השב!"
    appeal_after_hours: Optional[int] = None
class UnbanIn(BaseModel): message: str = "החסימה הוסרה"
class AnnouncementIn(BaseModel): title: str; content: str
class ChatMsgIn(BaseModel): content: str
class IpBanIn(BaseModel): ip: str; reason: str = ""; duration_hours: Optional[int] = None
class PasswordChange(BaseModel): new_password: str
class DeptIn(BaseModel): name: str; description: str=""; color: str="#00d4aa"; icon: str="🏢"
class DeptUpdate(BaseModel): name: Optional[str]=None; description: Optional[str]=None; color: Optional[str]=None; icon: Optional[str]=None
class AppealIn(BaseModel): message: str
class AppealReview(BaseModel): status: str; response: str=""
class DeleteRequestIn(BaseModel): reason: str=""
class UserDeptIn(BaseModel): dept_id: str

# ── Auth endpoints ────────────────────────────────────────────────────────────

@app.post("/api/auth/register", status_code=201)
def register(d: RegisterIn):
    if len(d.password) < 6: raise HTTPException(400, "הסיסמה חייבת להכיל לפחות 6 תווים")
    conn = db()
    is_first = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    role = "admin" if is_first else "user"; verified = 1 if is_first else 0
    uid = "u-" + str(uuid.uuid4())[:8]; now = datetime.now().isoformat()
    try:
        conn.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?)",
            (uid, d.email, hp(d.password), d.display_name, role, verified, 0, now, ""))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); raise HTTPException(400, "כתובת האימייל כבר רשומה במערכת")
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO sessions VALUES(?,?,?)", (token, uid, now)); conn.commit()
    user = conn.execute("SELECT id,email,display_name,role,verified,blocked,created_at FROM users WHERE id=?", (uid,)).fetchone()
    conn.close(); return {"token": token, "user": dict(user)}

@app.post("/api/auth/login")
def login(d: LoginIn):
    conn = db()
    u = conn.execute("SELECT * FROM users WHERE email=?", (d.email,)).fetchone()
    if not u or hp(d.password) != u["password_hash"]:
        conn.close(); raise HTTPException(401, "אימייל או סיסמה שגויים")
    if u["blocked"]:
        ban = conn.execute("SELECT * FROM bans WHERE user_id=?", (u["id"],)).fetchone(); conn.close()
        msg = (ban["reason"] if ban and ban["reason"] else "חשבון חסום. פנה למנהל")
        raise HTTPException(403, msg)
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO sessions VALUES(?,?,?)", (token, u["id"], datetime.now().isoformat()))
    conn.commit(); conn.close()
    ud = dict(u); del ud["password_hash"]; return {"token": token, "user": ud}

@app.post("/api/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    token = authorization[7:] if authorization and authorization.startswith("Bearer ") else None
    if token:
        conn = db(); conn.execute("DELETE FROM sessions WHERE token=?", (token,)); conn.commit(); conn.close()
    return {"ok": True}

@app.get("/api/auth/me")
def me(u=Depends(get_user)): return {k: v for k, v in u.items() if k != "password_hash"}

# ── Users ─────────────────────────────────────────────────────────────────────

@app.get("/api/users")
def list_users(u=Depends(team_up)):
    conn = db()
    rows = conn.execute("SELECT id,email,display_name,role,verified,blocked,created_at,last_ip FROM users ORDER BY role,display_name").fetchall()
    users = [dict(r) for r in rows]
    for usr in users:
        ban = conn.execute("SELECT * FROM bans WHERE user_id=?", (usr["id"],)).fetchone()
        usr["ban"] = dict(ban) if ban else None
    conn.close(); return users

@app.post("/api/users", status_code=201)
def create_user(d: UserCreate, u=Depends(admin_only)):
    conn = db(); uid = "u-" + str(uuid.uuid4())[:8]; now = datetime.now().isoformat()
    try:
        conn.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?)",
            (uid, d.email, hp(d.password), d.display_name, d.role, 0, 0, now, ""))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); raise HTTPException(400, "אימייל כבר קיים")
    user = conn.execute("SELECT id,email,display_name,role,verified,blocked,created_at FROM users WHERE id=?", (uid,)).fetchone()
    conn.close(); return dict(user)

@app.patch("/api/users/{uid}/role")
def update_role(uid: str, d: RoleUpdate, u=Depends(admin_only)):
    if uid == u["id"]: raise HTTPException(400, "לא ניתן לשנות תפקיד עצמי")
    conn = db(); conn.execute("UPDATE users SET role=? WHERE id=?", (d.role, uid)); conn.commit(); conn.close()
    return {"ok": True}

@app.post("/api/users/{uid}/ban")
def ban_user(uid: str, d: BanIn, u=Depends(team_up)):
    conn = db()
    target = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target: conn.close(); raise HTTPException(404, "משתמש לא נמצא")
    if target["role"] == "admin": conn.close(); raise HTTPException(400, "לא ניתן לחסום מנהל")
    if uid == u["id"]: conn.close(); raise HTTPException(400, "לא ניתן לחסום עצמך")
    now = datetime.now().isoformat()
    ban_until = (datetime.now() + timedelta(hours=d.duration_hours)).isoformat() if d.duration_hours else None
    banned_ip = target["last_ip"] if d.ip_banned and target["last_ip"] else ""
    conn.execute("UPDATE users SET blocked=1 WHERE id=?", (uid,))
    conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    conn.execute("DELETE FROM bans WHERE user_id=?", (uid,))
    conn.execute("INSERT INTO bans VALUES(?,?,?,?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), uid, d.reason, u["id"], ban_until,
         d.unban_msg, 1 if d.ip_banned else 0, banned_ip, now, d.appeal_after_hours))
    if d.ip_banned and banned_ip:
        conn.execute("DELETE FROM ip_bans WHERE ip=?", (banned_ip,))
        conn.execute("INSERT INTO ip_bans VALUES(?,?,?,?,?,?)",
            (str(uuid.uuid4()), banned_ip, d.reason, u["id"], ban_until, now))
    ban_content = d.reason or "חשבונך הוגבל על ידי מנהל המערכת"
    if ban_until: ban_content += f"\n⏰ חסימה עד: {ban_until[:16].replace('T',' ')}"
    if d.ip_banned: ban_content += "\n🌐 כתובת ה-IP שלך גם חסומה"
    conn.execute("INSERT INTO inbox_msgs VALUES(?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), uid, "🚫 חשבונך הוגבל", ban_content, "ban", 0, now))
    conn.commit(); conn.close()
    return {"ok": True, "ban_until": ban_until, "banned_ip": banned_ip}

@app.post("/api/users/{uid}/unban")
def unban_user(uid: str, d: UnbanIn, u=Depends(team_up)):
    conn = db()
    ban = conn.execute("SELECT * FROM bans WHERE user_id=?", (uid,)).fetchone()
    now = datetime.now().isoformat()
    conn.execute("UPDATE users SET blocked=0 WHERE id=?", (uid,))
    if ban and ban["ip_banned"] and ban["banned_ip"]:
        conn.execute("DELETE FROM ip_bans WHERE ip=?", (ban["banned_ip"],))
    conn.execute("DELETE FROM bans WHERE user_id=?", (uid,))
    conn.execute("INSERT INTO inbox_msgs VALUES(?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), uid, "✅ החסימה הוסרה",
         d.message or (ban["unban_msg"] if ban else "החסימה הוסרה"), "unban", 0, now))
    conn.commit(); conn.close(); return {"ok": True}

@app.delete("/api/users/{uid}")
def delete_user(uid: str, u=Depends(admin_only)):
    if uid == u["id"]: raise HTTPException(400, "לא ניתן למחוק עצמך")
    conn = db(); conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    conn.commit(); conn.close(); return {"ok": True}

# ── IP Bans ───────────────────────────────────────────────────────────────────

@app.get("/api/ip-bans")
def list_ip_bans(u=Depends(admin_only)):
    conn = db(); rows = conn.execute("SELECT * FROM ip_bans ORDER BY created_at DESC").fetchall(); conn.close()
    return [dict(r) for r in rows]

@app.post("/api/ip-bans", status_code=201)
def add_ip_ban(d: IpBanIn, u=Depends(admin_only)):
    conn = db(); now = datetime.now().isoformat()
    ban_until = (datetime.now() + timedelta(hours=d.duration_hours)).isoformat() if d.duration_hours else None
    conn.execute("DELETE FROM ip_bans WHERE ip=?", (d.ip,))
    conn.execute("INSERT INTO ip_bans VALUES(?,?,?,?,?,?)",
        (str(uuid.uuid4()), d.ip, d.reason, u["id"], ban_until, now))
    conn.commit(); conn.close(); return {"ok": True}

@app.delete("/api/ip-bans/{ban_id}")
def remove_ip_ban(ban_id: str, u=Depends(admin_only)):
    conn = db(); conn.execute("DELETE FROM ip_bans WHERE id=?", (ban_id,)); conn.commit(); conn.close()
    return {"ok": True}

# ── Announcements ─────────────────────────────────────────────────────────────

@app.get("/api/announcements/latest")
def latest_announcement(u=Depends(get_user)):
    conn = db(); row = conn.execute("SELECT * FROM announcements ORDER BY created_at DESC LIMIT 1").fetchone(); conn.close()
    return dict(row) if row else {}

@app.get("/api/announcements")
def list_announcements(u=Depends(get_user)):
    conn = db(); rows = conn.execute("SELECT * FROM announcements ORDER BY created_at DESC LIMIT 50").fetchall(); conn.close()
    return [dict(r) for r in rows]

@app.post("/api/announcements", status_code=201)
def create_announcement(d: AnnouncementIn, u=Depends(team_up)):
    conn = db(); aid = str(uuid.uuid4()); now = datetime.now().isoformat()
    conn.execute("INSERT INTO announcements VALUES(?,?,?,?,?,?)",
        (aid, d.title, d.content, u["id"], u["display_name"], now))
    for usr in conn.execute("SELECT id FROM users WHERE blocked=0").fetchall():
        conn.execute("INSERT INTO inbox_msgs VALUES(?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), usr["id"], f"📢 {d.title}", d.content, "announcement", 0, now))
    conn.commit()
    ann = conn.execute("SELECT * FROM announcements WHERE id=?", (aid,)).fetchone(); conn.close()
    return dict(ann)

@app.delete("/api/announcements/{aid}")
def delete_announcement(aid: str, u=Depends(team_up)):
    conn = db(); conn.execute("DELETE FROM announcements WHERE id=?", (aid,)); conn.commit(); conn.close()
    return {"ok": True}

# ── Global Chat ───────────────────────────────────────────────────────────────

@app.get("/api/chat")
def get_chat(u=Depends(get_user)):
    conn = db(); rows = conn.execute("SELECT * FROM global_chat ORDER BY created_at DESC LIMIT 100").fetchall(); conn.close()
    return [dict(r) for r in reversed(rows)]

@app.post("/api/chat", status_code=201)
def send_chat(d: ChatMsgIn, u=Depends(get_user)):
    if not d.content.strip(): raise HTTPException(400, "הודעה ריקה")
    conn = db(); mid = str(uuid.uuid4()); now = datetime.now().isoformat()
    conn.execute("INSERT INTO global_chat VALUES(?,?,?,?,?,?,?)",
        (mid, u["id"], u["display_name"], u["role"], u["verified"], d.content.strip(), now))
    conn.commit(); row = conn.execute("SELECT * FROM global_chat WHERE id=?", (mid,)).fetchone(); conn.close()
    return dict(row)

@app.delete("/api/chat/{mid}")
def delete_chat_msg(mid: str, u=Depends(team_up)):
    conn = db(); conn.execute("DELETE FROM global_chat WHERE id=?", (mid,)); conn.commit(); conn.close()
    return {"ok": True}

# ── Inbox ─────────────────────────────────────────────────────────────────────

@app.get("/api/inbox/unread")
def inbox_unread(u=Depends(get_user)):
    conn = db(); count = conn.execute("SELECT COUNT(*) FROM inbox_msgs WHERE user_id=? AND is_read=0", (u["id"],)).fetchone()[0]; conn.close()
    return {"count": count}

@app.get("/api/inbox")
def get_inbox(u=Depends(get_user)):
    conn = db(); rows = conn.execute("SELECT * FROM inbox_msgs WHERE user_id=? ORDER BY created_at DESC LIMIT 100", (u["id"],)).fetchall(); conn.close()
    return [dict(r) for r in rows]

@app.post("/api/inbox/read-all")
def inbox_read_all(u=Depends(get_user)):
    conn = db(); conn.execute("UPDATE inbox_msgs SET is_read=1 WHERE user_id=?", (u["id"],)); conn.commit(); conn.close()
    return {"ok": True}

@app.post("/api/inbox/{mid}/read")
def inbox_read(mid: str, u=Depends(get_user)):
    conn = db(); conn.execute("UPDATE inbox_msgs SET is_read=1 WHERE id=? AND user_id=?", (mid, u["id"])); conn.commit(); conn.close()
    return {"ok": True}

@app.delete("/api/inbox/{mid}")
def inbox_delete(mid: str, u=Depends(get_user)):
    conn = db(); conn.execute("DELETE FROM inbox_msgs WHERE id=? AND user_id=?", (mid, u["id"])); conn.commit(); conn.close()
    return {"ok": True}

# ── Messages ──────────────────────────────────────────────────────────────────

@app.get("/api/messages")
def get_messages(u=Depends(get_user)):
    conn = db(); uid = u["id"]
    if u["role"] in ("admin","team"):
        rows = conn.execute("""SELECT m.*,us.display_name as sender_name,us.role as sender_role,us.verified as sender_verified
            FROM messages m JOIN users us ON m.sender_id=us.id ORDER BY m.created_at DESC LIMIT 100""").fetchall()
    else:
        rows = conn.execute("""SELECT m.*,us.display_name as sender_name,us.role as sender_role,us.verified as sender_verified
            FROM messages m JOIN users us ON m.sender_id=us.id
            WHERE m.sender_id=? OR m.recipient_id=? ORDER BY m.created_at DESC LIMIT 100""", (uid,uid)).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r); d["read_by"] = json.loads(d["read_by"]); d["is_read"] = uid in d["read_by"]; result.append(d)
    return result

@app.post("/api/messages", status_code=201)
def send_message(d: MsgIn, u=Depends(get_user)):
    conn = db(); mid = str(uuid.uuid4()); now = datetime.now().isoformat()
    conn.execute("INSERT INTO messages VALUES(?,?,?,?,?,?,?)",
        (mid, u["id"], d.recipient_id, d.case_id, d.content, json.dumps([u["id"]]), now))
    conn.commit(); row = conn.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone(); conn.close()
    result = dict(row); result["read_by"] = json.loads(result["read_by"]); return result

@app.get("/api/messages/unread")
def get_unread(u=Depends(get_user)):
    conn = db(); uid = u["id"]
    if u["role"] in ("admin","team"):
        rows = conn.execute("""SELECT m.*,us.display_name as sender_name FROM messages m
            JOIN users us ON m.sender_id=us.id WHERE m.sender_id!=? ORDER BY m.created_at DESC""", (uid,)).fetchall()
    else:
        rows = conn.execute("""SELECT m.*,us.display_name as sender_name FROM messages m
            JOIN users us ON m.sender_id=us.id
            WHERE (m.recipient_id=? OR m.sender_id=?) AND m.sender_id!=? ORDER BY m.created_at DESC""", (uid,uid,uid)).fetchall()
    conn.close()
    unread = [dict(r) for r in rows if uid not in json.loads(r["read_by"])]
    return {"count": len(unread), "messages": unread[:5]}

@app.post("/api/messages/{mid}/read")
def mark_read(mid: str, u=Depends(get_user)):
    conn = db(); msg = conn.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if msg:
        rb = json.loads(msg["read_by"])
        if u["id"] not in rb:
            rb.append(u["id"]); conn.execute("UPDATE messages SET read_by=? WHERE id=?", (json.dumps(rb), mid)); conn.commit()
    conn.close(); return {"ok": True}

@app.delete("/api/messages/{mid}")
def delete_message(mid: str, u=Depends(admin_only)):
    conn = db()
    if not conn.execute("SELECT id FROM messages WHERE id=?", (mid,)).fetchone():
        conn.close(); raise HTTPException(404)
    conn.execute("DELETE FROM messages WHERE id=?", (mid,)); conn.commit(); conn.close(); return {"ok": True}

# ── Cases ─────────────────────────────────────────────────────────────────────

@app.get("/api/cases")
def list_cases(u=Depends(get_user)):
    conn = db()
    rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall() if u["role"] in ("admin","team") \
        else conn.execute("SELECT * FROM cases WHERE created_by=? ORDER BY created_at DESC", (u["id"],)).fetchall()
    conn.close(); return [dict(r) for r in rows]

@app.post("/api/cases", status_code=201)
def create_case(d: CaseIn, u=Depends(get_user)):
    conn = db(); cid = "c-" + str(uuid.uuid4())[:8]; now = datetime.now().isoformat()
    conn.execute("INSERT INTO cases VALUES(?,?,?,?,?,?,?,?,?,?)",
        (cid, d.name, d.platform, d.target_uid, u["id"], d.risk_level, "active", d.notes or "", now, now))
    conn.commit(); case = conn.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone(); conn.close()
    return dict(case)

@app.get("/api/cases/{cid}")
def get_case(cid: str, u=Depends(get_user)):
    conn = db(); case = conn.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
    if not case: raise HTTPException(404)
    if u["role"] == "user" and case["created_by"] != u["id"]: raise HTTPException(403)
    evts = conn.execute("SELECT * FROM events WHERE case_id=? ORDER BY ts DESC", (cid,)).fetchall()
    evid = conn.execute("SELECT * FROM evidence WHERE case_id=?", (cid,)).fetchall()
    conn.close(); result = dict(case); result["events"] = [dict(e) for e in evts]; result["evidence"] = [dict(e) for e in evid]
    return result

@app.patch("/api/cases/{cid}")
def update_case(cid: str, d: CaseUp, u=Depends(team_up)):
    conn = db(); upd = {k: v for k, v in d.dict().items() if v is not None}; upd["updated_at"] = datetime.now().isoformat()
    sets = ", ".join(f"{k}=?" for k in upd)
    conn.execute(f"UPDATE cases SET {sets} WHERE id=?", (*upd.values(), cid)); conn.commit()
    case = conn.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone(); conn.close(); return dict(case)

@app.delete("/api/cases/{cid}")
def delete_case(cid: str, u=Depends(team_up)):
    conn = db(); conn.execute("DELETE FROM cases WHERE id=?", (cid,)); conn.commit(); conn.close(); return {"ok": True}

@app.post("/api/cases/{cid}/events", status_code=201)
def add_event(cid: str, d: EventIn, u=Depends(get_user)):
    conn = db(); eid = str(uuid.uuid4()); now = datetime.now().isoformat()
    conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?)", (eid, cid, d.description, d.event_type, u["id"], now))
    conn.commit(); ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone(); conn.close(); return dict(ev)

@app.post("/api/cases/{cid}/evidence", status_code=201)
def add_evidence(cid: str, d: EvidIn, u=Depends(get_user)):
    conn = db(); eid = str(uuid.uuid4()); now = datetime.now().isoformat()
    conn.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?)", (eid, cid, d.title, d.url, d.ev_type, d.description, now))
    conn.commit(); ev = conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone(); conn.close(); return dict(ev)

# ── Graph ─────────────────────────────────────────────────────────────────────

@app.get("/api/relationships")
def list_rels(u=Depends(team_up)):
    conn = db(); rows = conn.execute("SELECT * FROM relationships").fetchall(); conn.close(); return [dict(r) for r in rows]

@app.post("/api/relationships", status_code=201)
def create_rel(d: RelIn, u=Depends(team_up)):
    conn = db(); rid = str(uuid.uuid4()); now = datetime.now().isoformat()
    conn.execute("INSERT INTO relationships VALUES(?,?,?,?,?,?)", (rid, d.src, d.tgt, d.rel_type, d.notes, now))
    conn.commit(); rel = conn.execute("SELECT * FROM relationships WHERE id=?", (rid,)).fetchone(); conn.close(); return dict(rel)

@app.delete("/api/relationships/{rid}")
def delete_rel(rid: str, u=Depends(team_up)):
    conn = db(); conn.execute("DELETE FROM relationships WHERE id=?", (rid,)); conn.commit(); conn.close(); return {"ok": True}

@app.get("/api/graph")
def get_graph(u=Depends(get_user)):
    conn = db()
    cases = conn.execute("SELECT id,name,risk_level,platform,status FROM cases").fetchall() if u["role"] in ("admin","team") \
        else conn.execute("SELECT id,name,risk_level,platform,status FROM cases WHERE created_by=?", (u["id"],)).fetchall()
    rels = conn.execute("SELECT * FROM relationships").fetchall(); conn.close()
    return {"nodes": [{"data":{"id":c["id"],"label":c["name"],"risk":c["risk_level"],"platform":c["platform"],"status":c["status"]}} for c in cases],
            "edges": [{"data":{"id":r["id"],"source":r["src"],"target":r["tgt"],"label":r["rel_type"]}} for r in rels]}

# ── OSINT ─────────────────────────────────────────────────────────────────────

@app.get("/api/scan/roblox/{uid}")
def scan_roblox(uid: str, u=Depends(get_user)):
    return {"platform":"roblox","user_id":uid,"links":{
        "פרופיל רשמי": f"https://www.roblox.com/users/{uid}/profile",
        "Rolimons": f"https://www.rolimons.com/player/{uid}",
        "תגים": f"https://www.roblox.com/users/{uid}/profile#badges",
        "חברים": f"https://www.roblox.com/users/{uid}/friends",
        "RoSearch": f"https://rosearch.app/users/{uid}",
    },"scanned_at":datetime.now().isoformat()}

@app.get("/api/scan/discord/{uid}")
def scan_discord(uid: str, u=Depends(get_user)):
    return {"platform":"discord","user_id":uid,"links":{
        "Discord Lookup": f"https://discordlookup.com/user/{uid}",
        "Discord ID Info": f"https://discordid.netlify.app/?id={uid}",
    },"scanned_at":datetime.now().isoformat()}

@app.get("/")
def frontend(): return FileResponse("index.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
