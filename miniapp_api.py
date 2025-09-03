# miniapp_api.py
# FastAPI backend для Telegram Mini App
# - Авторизация по initData (подпись)
# - Работа с той же БД vpn_bot.db
# - Эндпоинты для пользователя и админа

import os, hmac, hashlib, json, sqlite3
from urllib.parse import parse_qsl
from datetime import datetime
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# === настройка ===
BOT_TOKEN = os.getenv("BOT_TOKEN", "PASTE_YOUR_TOKEN_HERE")  # тот же, что у бота
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "vpn_bot.db")
BASE_PRICE_30 = 75  # ₽ за 30 дней на 1 человека
DISCOUNT_BY_DAYS = {30: 0.00, 60: 0.05, 90: 0.10}

app = FastAPI(title="VPN MiniApp API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=False,
    allow_methods=["*"], allow_headers=["*"],
)

# === helpers ===
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def calc_amount(days:int, seats:int)->int:
    per_day = BASE_PRICE_30 / 30.0
    subtotal = per_day * days * seats
    disc = DISCOUNT_BY_DAYS.get(days, 0.0)
    return int(round(subtotal * (1.0 - disc)))

def get_or_create_user(uid:int, username:str|None):
    with db() as conn:
        # ensure users table exists (на случай первой инит)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            days_left INTEGER NOT NULL DEFAULT 0,
            reminder_sent3 INTEGER NOT NULL DEFAULT 0,
            user_comment TEXT,
            seats_default INTEGER NOT NULL DEFAULT 1,
            expired_since TEXT,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        """)
        # create/update
        conn.execute("""
        INSERT INTO users(user_id, username) VALUES(?,?)
        ON CONFLICT(user_id) DO UPDATE SET username=excluded.username, updated_at=datetime('now');
        """, (uid, username))

def get_user(uid:int):
    with db() as conn:
        cur = conn.execute("SELECT * FROM users WHERE user_id=?", (uid,))
        return cur.fetchone()

def create_payment(uid:int, days:int, seats:int, amount:int, comment:str|None):
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            days INTEGER NOT NULL,
            seats INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            comment TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );
        """)
        cur = conn.execute("""
            INSERT INTO payments(user_id, days, seats, amount, comment)
            VALUES(?,?,?,?,?)
        """, (uid, days, seats, amount, comment))
        return cur.lastrowid

def list_payments(uid:int):
    with db() as conn:
        cur = conn.execute("""
        SELECT payment_id, days, seats, amount, status, created_at
        FROM payments WHERE user_id=? ORDER BY payment_id DESC LIMIT 50
        """, (uid,))
        return [dict(r) for r in cur.fetchall()]

def confirm_last_payment(uid:int):
    with db() as conn:
        # last pending
        cur = conn.execute("""
        SELECT payment_id, days, seats FROM payments
        WHERE user_id=? AND status='pending' ORDER BY payment_id DESC LIMIT 1
        """, (uid,))
        r = cur.fetchone()
        if not r: return False
        # mark paid + add days
        conn.execute("UPDATE payments SET status='paid' WHERE payment_id=?", (r["payment_id"],))
        conn.execute("UPDATE users SET days_left=MAX(0, COALESCE(days_left,0))+? WHERE user_id=?", (r["days"], uid))
        return True

def add_days(uid:int, days:int):
    with db() as conn:
        conn.execute("UPDATE users SET days_left=MAX(0, COALESCE(days_left,0))+? WHERE user_id=?", (days, uid))

def sub_days(uid:int, days:int):
    with db() as conn:
        conn.execute("UPDATE users SET days_left=MAX(0, COALESCE(days_left,0))-? WHERE user_id=?", (days, uid))

def set_days(uid:int, days:int):
    with db() as conn:
        conn.execute("UPDATE users SET days_left=? WHERE user_id=?", (days, uid))

def search_users(q:str|None, limit:int=20):
    with db() as conn:
        if q and q.lstrip('@').isdigit():
            cur = conn.execute("SELECT * FROM users WHERE user_id=?", (int(q.lstrip('@')),))
        elif q:
            like = f"%{q.lstrip('@')}%"
            cur = conn.execute("SELECT * FROM users WHERE username LIKE ? ORDER BY user_id DESC LIMIT ?", (like, limit))
        else:
            cur = conn.execute("SELECT * FROM users ORDER BY user_id DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]

def export_users_csv()->str:
    with db() as conn:
        cur = conn.execute("SELECT user_id, username, days_left FROM users ORDER BY user_id")
        rows = cur.fetchall()
    out = ["user_id,username,days_left"]
    for r in rows:
        u = (r["user_id"], (r["username"] or "").replace(","," "), r["days_left"])
        out.append(f"{u[0]},{u[1]},{u[2]}")
    return "\n".join(out)

def backup_db()->str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = os.path.join(APP_DIR, f"vpn_bot_backup_{ts}.db")
    with open(DB_PATH, "rb") as f, open(dst, "wb") as g:
        g.write(f.read())
    return os.path.basename(dst)

# === auth: verify initData ===
def verify_init_data(init_data:str):
    if not init_data:
        raise HTTPException(status_code=401, detail="no initData")
    data = dict(parse_qsl(init_data, keep_blank_values=True))
    hash_recv = data.pop('hash', None)
    if not hash_recv:
        raise HTTPException(status_code=401, detail="no hash")
    # data_check_string
    data_check_string = "\n".join(f"{k}={v}" for k,v in sorted(data.items()))
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    calc_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc_hash, hash_recv):
        raise HTTPException(status_code=401, detail="bad signature")
    user = json.loads(data.get("user", "{}") or "{}")
    return user

# === models ===
class CalcIn(BaseModel):
    days:int; seats:int
class BuyIn(BaseModel):
    days:int; seats:int; comment:str|None=None
class ProfileIn(BaseModel):
    username:str|None=None; comment:str|None=None
class DaysIn(BaseModel):
    days:int

# === routes ===
@app.get("/api/ping")
def ping(): return {"ok":True,"pong":True}

@app.get("/api/me")
def me(x_init: str = Header("", alias="X-Telegram-Init-Data")):
    u = verify_init_data(x_init)
    uid = int(u["id"])
    get_or_create_user(uid, u.get("username"))
    row = get_user(uid)
    return {
        "ok": True,
        "user_id": row["user_id"],
        "username": row["username"],
        "days_left": row["days_left"],
        "user_comment": row["user_comment"],
        "expired_since": row["expired_since"],
        "is_admin": int(row["is_admin"]) == 1 or uid in {251385778},  # добавь свои айди при желании
    }

@app.post("/api/calc")
def calc(inp:CalcIn, x_init: str = Header("", alias="X-Telegram-Init-Data")):
    verify_init_data(x_init)
    return {"ok":True, "amount": calc_amount(inp.days, inp.seats)}

@app.post("/api/payment/create")
def payment_create(inp:BuyIn, x_init: str = Header("", alias="X-Telegram-Init-Data")):
    u = verify_init_data(x_init); uid = int(u["id"])
    amount = calc_amount(inp.days, inp.seats)
    pid = create_payment(uid, inp.days, inp.seats, amount, inp.comment)
    return {"ok":True, "payment_id":pid, "amount":amount, "status":"pending"}

@app.get("/api/payments")
def payments(x_init: str = Header("", alias="X-Telegram-Init-Data")):
    u = verify_init_data(x_init); uid = int(u["id"])
    return {"ok":True, "items": list_payments(uid)}

@app.post("/api/profile")
def profile(inp:ProfileIn, x_init: str = Header("", alias="X-Telegram-Init-Data")):
    u = verify_init_data(x_init); uid = int(u["id"])
    with db() as conn:
        conn.execute("""
            UPDATE users SET username=COALESCE(?,username), user_comment=?
            WHERE user_id=?
        """, (inp.username, inp.comment, uid))
    return {"ok":True}

# ---- admin ----
def ensure_admin(uid:int):
    row = get_user(uid)
    is_admin = row and (row["is_admin"]==1 or uid in {251385778})
    if not is_admin: raise HTTPException(403, "forbidden")

@app.get("/api/admin/users")
def admin_users(q:str|None=None, x_init: str = Header("", alias="X-Telegram-Init-Data")):
    u = verify_init_data(x_init); uid = int(u["id"]); ensure_admin(uid)
    items = search_users(q)
    return {"ok":True, "items": [
        {"user_id":r["user_id"], "username":r["username"], "days_left":r["days_left"]}
        for r in items
    ]}

@app.post("/api/admin/user/{user_id}/add")
def admin_add(user_id:int, inp:DaysIn, x_init: str = Header("", alias="X-Telegram-Init-Data")):
    u = verify_init_data(x_init); ensure_admin(int(u["id"]))
    add_days(user_id, inp.days); return {"ok":True}

@app.post("/api/admin/user/{user_id}/sub")
def admin_sub(user_id:int, inp:DaysIn, x_init: str = Header("", alias="X-Telegram-Init-Data")):
    u = verify_init_data(x_init); ensure_admin(int(u["id"]))
    sub_days(user_id, inp.days); return {"ok":True}

@app.post("/api/admin/user/{user_id}/set")
def admin_set(user_id:int, inp:DaysIn, x_init: str = Header("", alias="X-Telegram-Init-Data")):
    u = verify_init_data(x_init); ensure_admin(int(u["id"]))
    set_days(user_id, inp.days); return {"ok":True}

@app.post("/api/admin/user/{user_id}/confirm_last_payment")
def admin_confirm(user_id:int, x_init: str = Header("", alias="X-Telegram-Init-Data")):
    u = verify_init_data(x_init); ensure_admin(int(u["id"]))
    ok = confirm_last_payment(user_id); return {"ok":ok}

@app.get("/api/admin/export")
def admin_export(x_init: str = Header("", alias="X-Telegram-Init-Data")):
    u = verify_init_data(x_init); ensure_admin(int(u["id"]))
    return {"ok":True, "csv": export_users_csv()}

@app.get("/api/admin/backup")
def admin_backup(x_init: str = Header("", alias="X-Telegram-Init-Data")):
    u = verify_init_data(x_init); ensure_admin(int(u["id"]))
    file = backup_db(); return {"ok":True, "file": file}
