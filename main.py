"""SMAI Sentinel Command Center — Backend v2.1 (Cloud Optimized)"""
import sqlite3, uuid, hashlib, json, secrets
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI(title="SMAI Sentinel API", version="2.1.0")

# מאפשר התחברות מכל מכשיר חיצוני (טלפון/מחשב אחר)
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_methods=["*"], 
    allow_headers=["*"]
)

DB = "sentinel.db"

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def hp(pw): return hashlib.sha256(pw.encode()).hexdigest()

# אתחול המערכת ויצירת המשתמש שלך (Admin)
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
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, platform TEXT NOT NULL DEFAULT 'roblox',
            target_uid TEXT, created_by TEXT, risk_level TEXT DEFAULT 'low',
            status TEXT DEFAULT 'active', notes TEXT DEFAULT '', created_at TEXT, updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS relationships (
            id TEXT PRIMARY KEY, src TEXT NOT NULL, tgt TEXT NOT NULL,
            rel_type TEXT NOT NULL, notes TEXT, ts TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS global_chat (
            id TEXT PRIMARY KEY, sender_id TEXT NOT NULL, sender_name TEXT NOT NULL,
            sender_role TEXT NOT NULL, sender_verified INTEGER DEFAULT 0,
            content TEXT NOT NULL, created_at TEXT NOT NULL
        );
    """)
    # יצירת המשתמש שלך אם לא קיים
    try:
        conn.execute("INSERT OR IGNORE INTO users VALUES(?,?,?,?,?,?,?,?,?)",
            ("u-admin", "minipro.7548@gmail.com", hp("harel11?"), "Harel", "admin", 1, 0, datetime.now().isoformat(), ""))
    except: pass
    conn.commit(); conn.close()

init()

# --- מודלים ו-API ---
class LoginIn(BaseModel): email: str; password: str

@app.post("/api/auth/login")
def login(d: LoginIn):
    conn = db()
    u = conn.execute("SELECT * FROM users WHERE email=?", (d.email,)).fetchone()
    if not u or hp(d.password) != u["password_hash"]:
        conn.close(); raise HTTPException(401, "פרטים שגויים")
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO sessions VALUES(?,?,?)", (token, u["id"], datetime.now().isoformat()))
    conn.commit(); conn.close()
    return {"token": token, "user": {"id": u["id"], "display_name": u["display_name"], "role": u["role"], "verified": u["verified"]}}

@app.get("/api/cases")
def list_cases():
    conn = db(); rows = conn.execute("SELECT * FROM cases").fetchall(); conn.close()
    return [dict(r) for r in rows]

# הפקודה שגורמת לאתר להיפתח מיד כשנכנסים ללינק
@app.get("/")
def frontend(): return FileResponse("index.html")
