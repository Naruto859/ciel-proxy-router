import os
import re
import json
import aiosqlite
import logging
import asyncio
import secrets
import bcrypt
import httpx
from typing import List, Dict, Optional, Any
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Request, Response, HTTPException, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from collections import deque

# --- CONFIGURATION ---
DB_PATH = "proxy_data.db"
BASE_URL = "https://gen.pollinations.ai"
SESSION_TOKEN = secrets.token_hex(16)
system_logs = deque(maxlen=200)
balance_check_lock = asyncio.Lock()
last_wait_log_time = 0.0

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def add_log(msg: str):
    ist = timezone(timedelta(hours=5, minutes=30))
    ts = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{ts}] {msg}"
    system_logs.append(full_msg)
    logger.info(msg)

# --- DATABASE MANAGER ---
class DatabaseManager:
    def __init__(self, path: str):
        self.path = path

    async def _init_db(self):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("PRAGMA journal_mode=WAL;")
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                    key TEXT PRIMARY KEY,
                    balance REAL DEFAULT -1.0,
                    priority INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    proxy_id INTEGER,
                    home_proxy_id INTEGER,
                    FOREIGN KEY (proxy_id) REFERENCES proxies (id),
                    FOREIGN KEY (home_proxy_id) REFERENCES proxies (id)
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS proxies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    port INTEGER,
                    username TEXT,
                    password TEXT,
                    status TEXT DEFAULT 'operational',
                    reserved_for_key TEXT DEFAULT NULL,
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS proxy_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    proxy_id INTEGER,
                    username TEXT,
                    password TEXT,
                    is_active INTEGER DEFAULT 1,
                    FOREIGN KEY (proxy_id) REFERENCES proxies (id)
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS login_security (
                    ip TEXT PRIMARY KEY,
                    attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP
                )
            """)
            await conn.execute("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT)")
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS usage_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    endpoint TEXT,
                    status_code INTEGER
                )
            """)
            await conn.execute("INSERT OR IGNORE INTO settings VALUES ('polling_interval', '300')")
            await conn.execute("INSERT OR IGNORE INTO settings VALUES ('force_check_interval', '300')")
            await conn.execute("INSERT OR IGNORE INTO settings VALUES ('max_hold_duration', '7200')")
            await conn.execute("INSERT OR IGNORE INTO settings VALUES ('auto_heal_enabled', '0')")
            
            # Default password
            default_pwd = "Samirandas123@"
            hashed_pwd = bcrypt.hashpw(default_pwd.encode(), bcrypt.gensalt()).decode()
            await conn.execute("INSERT OR IGNORE INTO settings VALUES ('admin_password', ?)", (hashed_pwd,))
            await conn.commit()

    async def get_keys(self):
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM keys ORDER BY priority DESC, balance DESC") as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def add_key(self, key: str, priority: int = 0):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("INSERT OR REPLACE INTO keys (key, priority) VALUES (?, ?)", (key, priority))
            await conn.commit()

    async def update_key_proxy(self, key: str, proxy_id: Optional[int], is_home: bool = False):
        async with aiosqlite.connect(self.path) as conn:
            if is_home:
                # Strictly reserve this IP for this Key
                await conn.execute("UPDATE keys SET proxy_id = ?, home_proxy_id = ? WHERE key = ?", (proxy_id, proxy_id, key))
                if proxy_id:
                    await conn.execute("UPDATE proxies SET reserved_for_key = ? WHERE id = ?", (key, proxy_id))
            else:
                await conn.execute("UPDATE keys SET proxy_id = ? WHERE key = ?", (proxy_id, key))
            await conn.commit()

    async def update_balance(self, key: str, balance: float):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("UPDATE keys SET balance = ?, last_checked = CURRENT_TIMESTAMP WHERE key = ?", (balance, key))
            await conn.commit()

    async def get_security_status(self, ip: str):
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM login_security WHERE ip = ?", (ip,)) as cursor:
                return await cursor.fetchone()

    async def record_login_attempt(self, ip: str, success: bool):
        async with aiosqlite.connect(self.path) as conn:
            if success:
                await conn.execute("DELETE FROM login_security WHERE ip = ?", (ip,))
            else:
                now = datetime.now()
                await conn.execute("""
                    INSERT INTO login_security (ip, attempts, locked_until) 
                    VALUES (?, 1, NULL) 
                    ON CONFLICT(ip) DO UPDATE SET 
                        attempts = attempts + 1,
                        locked_until = CASE WHEN attempts >= 4 THEN ? ELSE NULL END
                """, (ip, (now + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")))
            await conn.commit()

    async def get_unreserved_healthy_proxy(self, key: str) -> Optional[int]:
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            # Find a healthy proxy that is either not reserved or reserved for this key
            query = """
                SELECT id FROM proxies 
                WHERE status = 'operational' AND is_active = 1
                AND (reserved_for_key IS NULL OR reserved_for_key = ?)
                ORDER BY created_at DESC LIMIT 1
            """
            async with conn.execute(query, (key,)) as cursor:
                row = await cursor.fetchone()
                return row['id'] if row else None

    async def delete_key(self, key: str):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("DELETE FROM keys WHERE key = ?", (key,))
            await conn.commit()

    async def get_proxy_by_id(self, proxy_id: int):
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM proxies WHERE id = ?", (proxy_id,)) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def get_proxies(self):
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM proxies ORDER BY created_at DESC") as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def get_proxy_credentials(self, proxy_id: int):
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM proxy_credentials WHERE proxy_id = ? AND is_active = 1", (proxy_id,)) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def update_proxy_status(self, proxy_id: int, status: str):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("UPDATE proxies SET status = ? WHERE id = ?", (status, proxy_id))
            await conn.commit()

    async def add_proxy(self, ip: str, port: int, username: Optional[str] = None, password: Optional[str] = None) -> tuple[int, bool]:
        async with aiosqlite.connect(self.path) as conn:
            async with conn.execute("SELECT id, username, password, port FROM proxies WHERE ip = ?", (ip,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    proxy_id = row[0]
                    if row[1] != username or row[2] != password or row[3] != port:
                        await conn.execute("INSERT OR IGNORE INTO proxy_credentials (proxy_id, username, password) VALUES (?, ?, ?)", (proxy_id, row[1], row[2]))
                        await conn.execute("UPDATE proxies SET port = ?, username = ?, password = ?, status = 'operational' WHERE id = ?", (port, username, password, proxy_id))
                    is_new = False
                else:
                    cur = await conn.execute("INSERT INTO proxies (ip, port, username, password) VALUES (?, ?, ?, ?)", (ip, port, username, password))
                    proxy_id = cur.lastrowid
                    is_new = True
            await conn.commit()
            return proxy_id, is_new

    async def get_auto_heal_enabled(self) -> bool:
        async with aiosqlite.connect(self.path) as conn:
            async with conn.execute("SELECT value FROM settings WHERE name = 'auto_heal_enabled'") as cursor:
                row = await cursor.fetchone()
                return row[0] == '1' if row else False

    async def set_auto_heal_enabled(self, enabled: bool):
        val = '1' if enabled else '0'
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("UPDATE settings SET value = ? WHERE name = 'auto_heal_enabled'", (val,))
            await conn.commit()

    async def get_admin_password_hash(self) -> str:
        async with aiosqlite.connect(self.path) as conn:
            async with conn.execute("SELECT value FROM settings WHERE name = 'admin_password'") as cursor:
                row = await cursor.fetchone()
                return row[0] if row else ""

    async def set_admin_password(self, password: str):
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("UPDATE settings SET value = ? WHERE name = 'admin_password'", (hashed,))
            await conn.commit()

    async def get_polling_interval(self) -> int:
        async with aiosqlite.connect(self.path) as conn:
            async with conn.execute("SELECT value FROM settings WHERE name = 'polling_interval'") as cursor:
                row = await cursor.fetchone()
                return int(row[0]) if row else 300

    async def set_polling_interval(self, seconds: int):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("UPDATE settings SET value = ? WHERE name = 'polling_interval'", (str(seconds),))
            await conn.commit()

    async def get_force_check_interval(self) -> int:
        async with aiosqlite.connect(self.path) as conn:
            async with conn.execute("SELECT value FROM settings WHERE name = 'force_check_interval'") as cursor:
                row = await cursor.fetchone()
                return int(row[0]) if row else 300

    async def set_force_check_interval(self, seconds: int):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("UPDATE settings SET value = ? WHERE name = 'force_check_interval'", (str(seconds),))
            await conn.commit()

    async def get_max_hold_duration(self) -> int:
        async with aiosqlite.connect(self.path) as conn:
            async with conn.execute("SELECT value FROM settings WHERE name = 'max_hold_duration'") as cursor:
                row = await cursor.fetchone()
                return int(row[0]) if row else 7200

    async def set_max_hold_duration(self, seconds: int):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("UPDATE settings SET value = ? WHERE name = 'max_hold_duration'", (str(seconds),))
            await conn.commit()

    async def log_usage(self, endpoint: str, status_code: int):
        ist = timezone(timedelta(hours=5, minutes=30))
        ts = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("INSERT INTO usage_stats (timestamp, endpoint, status_code) VALUES (?, ?, ?)", (ts, endpoint, status_code))
            await conn.commit()

    async def get_client_keys(self):
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute("SELECT * FROM client_keys ORDER BY created_at DESC") as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def generate_client_key(self, name: str) -> str:
        new_key = f"ciel_sk_{secrets.token_hex(16)}"
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("INSERT INTO client_keys (key, name) VALUES (?, ?)", (new_key, name))
            await conn.commit()
        return new_key

    async def validate_client_key(self, key: str) -> bool:
        async with aiosqlite.connect(self.path) as conn:
            async with conn.execute("SELECT 1 FROM client_keys WHERE key = ? AND is_active = 1", (key,)) as cursor:
                return await cursor.fetchone() is not None

    async def revoke_client_key(self, key: str):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("DELETE FROM client_keys WHERE key = ?", (key,))
            await conn.commit()

db = DatabaseManager(DB_PATH)

# --- PROXY MANAGER ---
class ProxyManager:
    def __init__(self):
        self.clients: Dict[int, httpx.AsyncClient] = {}
        self.default_client = httpx.AsyncClient(timeout=120.0, follow_redirects=True)
        self._lock = asyncio.Lock()

    async def get_client_for_proxy(self, proxy: Dict) -> httpx.AsyncClient:
        proxy_id = proxy['id']
        async with self._lock:
            if proxy_id not in self.clients:
                auth = f"{proxy['username']}:{proxy['password']}@" if proxy['username'] and proxy['password'] else ""
                proxy_url = f"http://{auth}{proxy['ip']}:{proxy['port']}"
                self.clients[proxy_id] = httpx.AsyncClient(proxies=proxy_url, timeout=120.0, follow_redirects=True)
            return self.clients[proxy_id]

    async def close_all(self):
        await self.default_client.aclose()
        for client in self.clients.values():
            await client.aclose()

proxy_manager = ProxyManager()

# --- KEY MANAGER ---
class KeyManager:
    def __init__(self):
        self.last_force_pull_time = 0.0

    async def get_best_key(self) -> Optional[Dict]:
        keys = await db.get_keys()
        for k in keys:
            if k['balance'] > 0.05 or k['balance'] == -1.0: return k
        return None

    async def check_balance(self, key_data: Dict) -> tuple[float, str]:
        key = key_data['key']
        proxy_id = key_data.get('proxy_id')
        proxy_info = "VPS IP (Direct)"
        
        try:
            client = proxy_manager.default_client
            active_proxy = None
            if proxy_id:
                active_proxy = await db.get_proxy_by_id(proxy_id)
                if not active_proxy:
                    add_log(f"WARNING: Invalid proxy ID {proxy_id}. VPS fallback.")
                    proxy_id = None
                else:
                    proxy_info = active_proxy['ip']
                    creds_to_try = [{"username": active_proxy['username'], "password": active_proxy['password'], "is_main": True}]
                    try:
                        pool = await db.get_proxy_credentials(proxy_id)
                        for p in pool: creds_to_try.append({**p, "is_main": False})
                    except: pass
                    
                    for cred in creds_to_try:
                        try:
                            temp_p = {**active_proxy, "username": cred['username'], "password": cred['password']}
                            client_attempt = await proxy_manager.get_client_for_proxy(temp_p)
                            headers = {"Authorization": f"Bearer {key}", "User-Agent": "curl/8.5.0"}
                            response = await client_attempt.get(f"{BASE_URL}/account/balance", headers=headers, timeout=10.0)
                            if response.status_code == 200:
                                await db.update_proxy_status(proxy_id, 'operational')
                                if not cred["is_main"]:
                                    await db.add_proxy(active_proxy['ip'], active_proxy['port'], cred['username'], cred['password'])
                                balance = response.json().get("balance", 0.0)
                                await db.update_balance(key, balance)
                                add_log(f"SUCCESS: {key[:8]} via {proxy_info} -> {balance}")
                                return balance, proxy_info
                            elif response.status_code in (401, 403, 402):
                                await db.update_balance(key, 0.0)
                                add_log(f"API REJECTED: {key[:8]} via {proxy_info} (HTTP {response.status_code})")
                                return 0.0, proxy_info
                        except: continue
                    
                    await db.update_proxy_status(proxy_id, 'failed')
                    add_log(f"NODE FAILED: {proxy_info} unreachable.")
                    if await db.get_auto_heal_enabled():
                        new_pid = await db.get_unreserved_healthy_proxy(key)
                        if new_pid:
                            new_p = await db.get_proxy_by_id(new_pid)
                            await db.update_key_proxy(key, new_pid, is_home=False)
                            add_log(f"AUTO-HEAL: Re-routing {key[:8]} to {new_p['ip']}")
                            return await self.check_balance({**key_data, "proxy_id": new_pid})
                    return -2.0, proxy_info

            # Direct VPS
            headers = {"Authorization": f"Bearer {key}", "User-Agent": "curl/8.5.0"}
            response = await client.get(f"{BASE_URL}/account/balance", headers=headers, timeout=10.0)
            if response.status_code == 200:
                balance = response.json().get("balance", 0.0)
                await db.update_balance(key, balance)
                add_log(f"SUCCESS: {key[:8]} via VPS -> {balance}")
                return balance, "VPS IP (Direct)"
            elif response.status_code in (401, 403, 402):
                await db.update_balance(key, 0.0)
                add_log(f"API REJECTED: {key[:8]} via VPS")
                return 0.0, "VPS IP (Direct)"
                
        except Exception as e:
            add_log(f"Error for {key[:8]}: {str(e)}")
        return -2.0, proxy_info

    async def force_pull_balances(self):
        async with balance_check_lock:
            current_time = asyncio.get_event_loop().time()
            interval = await db.get_force_check_interval()
            if current_time - self.last_force_pull_time < float(interval): return
            self.last_force_pull_time = current_time
            keys = await db.get_keys()
            if not keys: return
            await asyncio.gather(*[self.check_balance(k) for k in keys])

key_manager = KeyManager()

# --- BACKGROUND ---
async def polling_worker():
    while True:
        keys = await db.get_keys()
        for k in keys: await key_manager.check_balance(k)
        await asyncio.sleep(await db.get_polling_interval())

async def log_cleanup_worker():
    while True:
        await asyncio.sleep(5 * 3600)
        system_logs.clear()
        async with aiosqlite.connect(DB_PATH) as conn:
            ist = timezone(timedelta(hours=5, minutes=30))
            ago = (datetime.now(ist) - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
            await conn.execute("DELETE FROM usage_stats WHERE timestamp < ?", (ago,))
            await conn.commit()
        add_log("System logs & old DB stats automatically cleared (5h rotation).")

async def auto_heal_worker():
    while True:
        try:
            await asyncio.sleep(24 * 3600)
            if not await db.get_auto_heal_enabled(): continue
            proxies = await db.get_proxies()
            failed = [p for p in proxies if p['status'] == 'failed']
            if failed:
                keys = await db.get_keys()
                if keys:
                    for fp in failed: await key_manager.check_balance({**keys[0], "proxy_id": fp['id']})
            all_keys = await db.get_keys()
            for k in all_keys:
                if k.get('home_proxy_id') and k['proxy_id'] != k['home_proxy_id']:
                    home_p = await db.get_proxy_by_id(k['home_proxy_id'])
                    if home_p and home_p['status'] == 'operational':
                        await db.update_key_proxy(k['key'], k['home_proxy_id'])
                        add_log(f"CRON: Reverted {k['key'][:8]} to original IP {home_p['ip']}")
        except: pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db._init_db()
    w = asyncio.create_task(polling_worker()); c = asyncio.create_task(log_cleanup_worker()); cr = asyncio.create_task(auto_heal_worker())
    yield
    w.cancel(); c.cancel(); cr.cancel(); await proxy_manager.close_all()

app = FastAPI(lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
security = HTTPBearer()

def verify_admin_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != SESSION_TOKEN: raise HTTPException(status_code=403, detail="Invalid session")
    return True

@app.post("/admin/auth")
async def admin_auth(request: Request, req: Dict):
    ip = request.client.host
    st = await db.get_security_status(ip)
    if st and st['locked_until']:
        if datetime.now() < datetime.strptime(st['locked_until'], "%Y-%m-%d %H:%M:%S"):
            raise HTTPException(status_code=403, detail=f"Locked until {st['locked_until']}")
    stored = await db.get_admin_password_hash()
    ok = bcrypt.checkpw(req.get('pin','').encode(), stored.encode())
    await db.record_login_attempt(ip, ok)
    if ok: return {"token": SESSION_TOKEN}
    raise HTTPException(status_code=401, detail="Invalid PIN")

@app.get("/", response_class=HTMLResponse)
async def dash(request: Request): return templates.TemplateResponse("index.html", {"request": request})

@app.get("/admin/keys", dependencies=[Depends(verify_admin_token)])
async def list_keys(): return {"keys": await db.get_keys()}

@app.post("/admin/keys", dependencies=[Depends(verify_admin_token)])
async def add_key(req: Dict):
    await db.add_key(req['key'], req.get('priority', 0))
    if req.get('proxy_id'): await db.update_key_proxy(req['key'], req['proxy_id'], is_home=True)
    ks = await db.get_keys()
    nk = next((k for k in ks if k['key'] == req['key']), None)
    if nk: await key_manager.check_balance(nk)
    return {"success": True}

@app.delete("/admin/keys/{key}", dependencies=[Depends(verify_admin_token)])
async def delete_key(key: str): await db.delete_key(key); return {"success": True}

@app.get("/admin/test/{key}", dependencies=[Depends(verify_admin_token)])
async def test_key(key: str):
    ks = await db.get_keys()
    tk = next((k for k in ks if k['key'] == key), None)
    if not tk: return {"success": False, "error": "Key not found"}
    bal, info = await key_manager.check_balance(tk)
    return {"success": bal >= 0, "balance": bal, "ip": info}

@app.post("/admin/keys/proxy", dependencies=[Depends(verify_admin_token)])
async def update_key_proxy(req: Dict):
    await db.update_key_proxy(req['key'], req['proxy_id'], is_home=True)
    return {"success": True}

@app.get("/admin/proxies", dependencies=[Depends(verify_admin_token)])
async def list_proxies(): return {"proxies": await db.get_proxies()}

@app.post("/admin/proxies", dependencies=[Depends(verify_admin_token)])
async def add_proxy(req: Dict):
    await db.add_proxy(req['ip'], req['port'], req.get('username'), req.get('password'))
    return {"success": True}

@app.post("/admin/proxies/bulk", dependencies=[Depends(verify_admin_token)])
async def bulk_add_proxies(req: Dict):
    proxies_to_add = req.get('proxies', [])
    mode_update = req.get('update_credentials', False)
    mode_heal = req.get('auto_heal_broken', False)
    mode_replace_vps = req.get('replace_vps', False)
    
    added_count = 0
    new_healthy_pids = []
    
    for p in proxies_to_add:
        # 1. Add or Update proxy in DB
        # If match by IP, update port/user/pass if mode_update is True
        async with aiosqlite.connect(DB_PATH) as conn:
            async with conn.execute("SELECT id, username, password, port FROM proxies WHERE ip = ?", (p['ip'],)) as cursor:
                row = await cursor.fetchone()
                if row:
                    proxy_id = row[0]
                    if mode_update:
                        await conn.execute("UPDATE proxies SET port = ?, username = ?, password = ?, status = 'operational' WHERE id = ?", (p['port'], p.get('username'), p.get('password'), proxy_id))
                    is_new = False
                else:
                    cur = await conn.execute("INSERT INTO proxies (ip, port, username, password) VALUES (?, ?, ?, ?)", (p['ip'], p['port'], p.get('username'), p.get('password')))
                    proxy_id = cur.lastrowid
                    is_new = True
            await conn.commit()
        
        added_count += 1
        
        # 2. Test proxy immediately to mark as RED if dead
        proxy_data = await db.get_proxy_by_id(proxy_id)
        if proxy_data:
            try:
                # Use a specific timeout for bulk testing
                client = await proxy_manager.get_client_for_proxy(proxy_data)
                resp = await client.get("https://api.ipify.org?format=json", timeout=8.0)
                if resp.status_code == 200:
                    await db.update_proxy_status(proxy_id, 'operational')
                    new_healthy_pids.append(proxy_id)
                else:
                    await db.update_proxy_status(proxy_id, 'failed')
            except Exception:
                await db.update_proxy_status(proxy_id, 'failed')
                
    # 3. Assignment Logic
    if mode_heal or mode_replace_vps:
        keys = await db.get_keys()
        for pid in new_healthy_pids:
            # Check if this PID is already reserved for a key
            async with aiosqlite.connect(DB_PATH) as conn:
                async with conn.execute("SELECT 1 FROM keys WHERE proxy_id = ?", (pid,)) as cur:
                    if await cur.fetchone(): continue # Proxy already busy
            
            target_key = None
            if mode_heal:
                # Prioritize keys that have a proxy_id but its status is 'failed'
                for k in keys:
                    if k.get('proxy_id'):
                        curr_p = await db.get_proxy_by_id(k['proxy_id'])
                        if curr_p and curr_p['status'] == 'failed':
                            target_key = k['key']; break
            
            if not target_key and mode_replace_vps:
                # Fallback to keys currently on VPS
                for k in keys:
                    if not k.get('proxy_id'):
                        target_key = k['key']; break
            
            if target_key:
                await db.update_key_proxy(target_key, pid, is_home=True)
                add_log(f"SMART-ASSIGN: Linked {target_key[:8]} to healthy IP via Bulk Add.")

    return {"success": True, "added": added_count}

@app.delete("/admin/proxies/{proxy_id}", dependencies=[Depends(verify_admin_token)])
async def delete_proxy(proxy_id: int): await db.delete_proxy(proxy_id); return {"success": True}

@app.get("/admin/proxies/test/{proxy_id}", dependencies=[Depends(verify_admin_token)])
async def test_proxy_outbound(proxy_id: int):
    p = await db.get_proxy_by_id(proxy_id)
    if not p: return {"success": False, "error": "Proxy not found"}
    try:
        cl = await proxy_manager.get_client_for_proxy(p)
        r = await cl.get("https://api.ipify.org?format=json", timeout=10.0)
        if r.status_code == 200:
            det = r.json().get("ip")
            if det != p['ip']: await db.update_proxy_status(proxy_id, 'failed')
            else: await db.update_proxy_status(proxy_id, 'operational')
            return {"success": True, "detected_ip": det, "matches": det == p['ip']}
        await db.update_proxy_status(proxy_id, 'failed'); return {"success": False, "error": f"HTTP {r.status_code}"}
    except Exception as e: await db.update_proxy_status(proxy_id, 'failed'); return {"success": False, "error": str(e)}

@app.get("/admin/client-keys", dependencies=[Depends(verify_admin_token)])
async def list_client_keys(): return {"keys": await db.get_client_keys()}

@app.post("/admin/client-keys", dependencies=[Depends(verify_admin_token)])
async def add_client_key(req: Dict): return {"success": True, "key": await db.generate_client_key(req['name'])}

@app.delete("/admin/client-keys/{key}", dependencies=[Depends(verify_admin_token)])
async def delete_client_key(key: str): await db.revoke_client_key(key); return {"success": True}

@app.get("/admin/settings/polling", dependencies=[Depends(verify_admin_token)])
async def get_p(): return {"interval": await db.get_polling_interval()}

@app.post("/admin/settings/polling", dependencies=[Depends(verify_admin_token)])
async def set_p(req: Dict): await db.set_polling_interval(int(req['interval'])); return {"success": True}

@app.get("/admin/settings/force_check", dependencies=[Depends(verify_admin_token)])
async def get_fc(): return {"interval": await db.get_force_check_interval()}

@app.post("/admin/settings/force_check", dependencies=[Depends(verify_admin_token)])
async def set_fc(req: Dict): await db.set_force_check_interval(int(req['interval'])); return {"success": True}

@app.get("/admin/settings/max_hold", dependencies=[Depends(verify_admin_token)])
async def get_mh(): return {"duration": await db.get_max_hold_duration()}

@app.post("/admin/settings/max_hold", dependencies=[Depends(verify_admin_token)])
async def set_mh(req: Dict): await db.set_max_hold_duration(int(req['duration'])); return {"success": True}

@app.get("/admin/settings/auto_heal", dependencies=[Depends(verify_admin_token)])
async def get_ah(): return {"enabled": await db.get_auto_heal_enabled()}

@app.post("/admin/settings/auto_heal", dependencies=[Depends(verify_admin_token)])
async def set_ah(req: Dict): await db.set_auto_heal_enabled(req['enabled']); return {"success": True}

@app.get("/admin/live_status", dependencies=[Depends(verify_admin_token)])
async def live_status(): return {"logs": list(system_logs)}

@app.get("/admin/analytics", dependencies=[Depends(verify_admin_token)])
async def get_analytics():
    ist = timezone(timedelta(hours=5, minutes=30)); now = datetime.now(ist)
    async def gc(start: str):
        async with aiosqlite.connect(DB_PATH) as conn:
            async with conn.execute("SELECT COUNT(*) FROM usage_stats WHERE timestamp >= ?", (start,)) as cur:
                r = await cur.fetchone(); return r[0] if r else 0
    return {"today": await gc((now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")), "this_week": await gc((now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")), "this_month": await gc((now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")), "this_year": await gc((now - timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S"))}

# --- PROXY CORE ---
def translate_anthropic_req_to_openai(anthropic_json: dict) -> dict:
    model = anthropic_json.get("model", "openai")
    openai_json = {"model": model, "max_tokens": anthropic_json.get("max_tokens", 1024), "stream": anthropic_json.get("stream", False), "messages": []}
    if "system" in anthropic_json and anthropic_json["system"]:
        sys = anthropic_json["system"]
        if isinstance(sys, list): sys = "".join([b.get("text", "") for b in sys if b.get("type") == "text"])
        sys = re.sub(r'^x-anthropic-billing-header:\s*(?:[a-z_]+=[^\s;]+;\s*)*', '', sys).strip()
        if sys: openai_json["messages"].append({"role": "system", "content": sys})
    if "tools" in anthropic_json:
        openai_json["tools"] = [{"type": "function", "function": {"name": t.get("name"), "description": t.get("description", ""), "parameters": t.get("input_schema", {})}} for t in anthropic_json["tools"]]
    if "tool_choice" in anthropic_json:
        c = anthropic_json["tool_choice"]
        if c.get("type") == "auto": openai_json["tool_choice"] = "auto"
        elif c.get("type") == "any": openai_json["tool_choice"] = "required"
        elif c.get("type") == "tool": openai_json["tool_choice"] = {"type": "function", "function": {"name": c.get("name")}}
    raw = []
    for msg in anthropic_json.get("messages", []):
        role, content = msg.get("role", "user"), msg.get("content", "")
        if role == "system": continue
        if isinstance(content, str): raw.append({"role": role, "content": content})
        elif isinstance(content, list):
            o_content, t_calls, t_results = [], [], []
            for b in content:
                bt = b.get("type")
                if bt == "text": o_content.append({"type": "text", "text": b.get("text", "")})
                elif bt == "image":
                    s = b.get("source", {})
                    if s.get("type") == "base64": o_content.append({"type": "image_url", "image_url": {"url": f"data:{s.get('media_type', 'image/jpeg')};base64,{s.get('data')}"}})
                elif bt == "tool_use": t_calls.append({"id": b.get("id"), "type": "function", "function": {"name": b.get("name"), "arguments": json.dumps(b.get("input", {}))}})
                elif bt == "tool_result":
                    rc = b.get("content", "")
                    if isinstance(rc, list): rc = "".join([c.get("text", "") for c in rc if c.get("type") == "text"])
                    t_results.append({"role": "tool", "tool_call_id": b.get("tool_use_id"), "content": str(rc)})
            for tr in t_results: raw.append(tr)
            if t_calls:
                msg = {"role": "assistant"}
                if o_content:
                    tc = "".join([c.get("text", "") for c in o_content if c.get("type") == "text"])
                    imgs = [c for c in o_content if c.get("type") == "image_url"]
                    msg["content"] = [{"type": "text", "text": tc}] + imgs if imgs else tc
                else: msg["content"] = ""
                msg["tool_calls"] = t_calls
                raw.append(msg)
            elif o_content:
                if not any(c.get("type") == "image_url" for c in o_content): raw.append({"role": role, "content": "".join([c.get("text", "") for c in o_content if c.get("type") == "text"])})
                else: raw.append({"role": role, "content": o_content})
    openai_json["messages"] = raw; return openai_json

def translate_openai_resp_to_anthropic(openai_json: dict) -> dict:
    c_blocks, stop = [], "end_turn"
    if "choices" in openai_json and len(openai_json["choices"]) > 0:
        c = openai_json["choices"][0]; m = c.get("message", {})
        if m.get("content"): c_blocks.append({"type": "text", "text": m.get("content")})
        if m.get("tool_calls"):
            stop = "tool_use"
            for tc in m.get("tool_calls", []):
                try: args = json.loads(tc.get("function", {}).get("arguments", "{}"))
                except: args = {}
                c_blocks.append({"type": "tool_use", "id": tc.get("id"), "name": tc.get("function", {}).get("name"), "input": args})
        fr = c.get("finish_reason")
        if fr == "tool_calls": stop = "tool_use"
        elif fr == "length": stop = "max_tokens"
    return {"id": openai_json.get("id", "msg_" + secrets.token_hex(8)), "type": "message", "role": "assistant", "model": openai_json.get("model", "openai"), "content": c_blocks, "stop_reason": stop, "stop_sequence": None, "usage": {"input_tokens": 0, "output_tokens": 0}}

async def stream_openai_to_anthropic(upstream_resp, original_model):
    mid = "msg_" + secrets.token_hex(8)
    yield f'event: message_start\ndata: {json.dumps({"type": "message_start", "message": {"id": mid, "type": "message", "role": "assistant", "content": [], "model": original_model, "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 0, "output_tokens": 0}}})}\n\n'.encode("utf-8")
    idx, in_t, in_tool = 0, False, False
    async for line in upstream_resp.aiter_lines():
        if not line.startswith("data: "): continue
        ds = line[6:]
        if ds == "[DONE]": break
        try:
            dj = json.loads(ds); cs = dj.get("choices", [])
            if not cs: continue
            d = cs[0].get("delta", {})
            if "content" in d and d["content"]:
                if in_tool: yield f'event: content_block_stop\ndata: {json.dumps({"type": "content_block_stop", "index": idx})}\n\n'.encode("utf-8"); in_tool = False; idx += 1
                if not in_t: yield f'event: content_block_start\ndata: {json.dumps({"type": "content_block_start", "index": idx, "content_block": {"type": "text", "text": ""}})}\n\n'.encode("utf-8"); in_t = True
                yield f'event: content_block_delta\ndata: {json.dumps({"type": "content_block_delta", "index": idx, "delta": {"type": "text_delta", "text": d["content"]}})}\n\n'.encode("utf-8")
            if "tool_calls" in d:
                if in_t: yield f'event: content_block_stop\ndata: {json.dumps({"type": "content_block_stop", "index": idx})}\n\n'.encode("utf-8"); in_t = False; idx += 1
                tc = d["tool_calls"][0]
                if "id" in tc and tc["id"]:
                    if in_tool: yield f'event: content_block_stop\ndata: {json.dumps({"type": "content_block_stop", "index": idx})}\n\n'.encode("utf-8"); idx += 1
                    yield f'event: content_block_start\ndata: {json.dumps({"type": "content_block_start", "index": idx, "content_block": {"type": "tool_use", "id": tc["id"], "name": tc.get("function", {}).get("name", ""), "input": {}}})}\n\n'.encode("utf-8"); in_tool = True
                if "function" in tc and "arguments" in tc["function"]: yield f'event: content_block_delta\ndata: {json.dumps({"type": "content_block_delta", "index": idx, "delta": {"type": "input_json_delta", "partial_json": tc["function"]["arguments"]}})}\n\n'.encode("utf-8")
            fr = cs[0].get("finish_reason")
            if fr:
                if in_t or in_tool: yield f'event: content_block_stop\ndata: {json.dumps({"type": "content_block_stop", "index": idx})}\n\n'.encode("utf-8")
                sm = {"stop": "end_turn", "tool_calls": "tool_use", "length": "max_tokens"}
                yield f'event: message_delta\ndata: {json.dumps({"type": "message_delta", "delta": {"stop_reason": sm.get(fr, "end_turn"), "stop_sequence": None}, "usage": {"output_tokens": 1}})}\n\n'.encode("utf-8")
        except: continue
    yield f'event: message_stop\ndata: {json.dumps({"type": "message_stop"})}\n\n'.encode("utf-8")

@app.api_route("/v1/chat/completions", methods=["POST"])
@app.api_route("/v1/v1/chat/completions", methods=["POST"])
@app.api_route("/v1/messages", methods=["POST"])
@app.api_route("/v1/v1/messages", methods=["POST"])
async def core_proxy(request: Request):
    ck = request.headers.get("Authorization", "").replace("Bearer ", "") or request.headers.get("x-api-key", "")
    if not ck or not await db.validate_client_key(ck): return JSONResponse({"error": "Invalid Key"}, status_code=401)
    is_a, rb = "messages" in request.url.path, await request.body()
    try: bj = json.loads(rb) if rb else {}
    except: return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    om, is_s = bj.get("model", "openai"), bj.get("stream", False)
    if is_a: bj = translate_anthropic_req_to_openai(bj); rb = json.dumps(bj).encode("utf-8")
    mh, st = await db.get_max_hold_duration(), asyncio.get_event_loop().time()
    while asyncio.get_event_loop().time() - st < mh:
        kd = await key_manager.get_best_key()
        if not kd: await asyncio.sleep(2); await key_manager.force_pull_balances(); continue
        try:
            pc, pinfo = proxy_manager.default_client, "VPS IP (Direct)"
            if kd.get('proxy_id'):
                p = await db.get_proxy_by_id(kd['proxy_id'])
                if p: pc = await proxy_manager.get_client_for_proxy(p); pinfo = p['ip']
            h = {"Authorization": f"Bearer {kd['key']}", "Content-Type": "application/json", "User-Agent": "curl/8.5.0"}
            if not is_s:
                r = await pc.post(f"{BASE_URL}/v1/chat/completions", headers=h, content=rb, timeout=90.0)
                await db.log_usage(request.url.path, r.status_code)
                add_log(f"Request: {kd['key'][:8]} via {pinfo} -> HTTP {r.status_code}")
                if r.status_code in (401, 402, 403, 429, 500, 502, 503, 504):
                    add_log(f"ALERT: Key {kd['key'][:8]} hit {r.status_code}. Draining..."); await db.update_balance(kd['key'], 0.0); continue
                sh = {"Content-Type": r.headers.get("content-type", "application/json")}
                if is_a and r.status_code == 200: return JSONResponse(translate_openai_resp_to_anthropic(r.json()), headers=sh)
                return Response(content=r.content, status_code=r.status_code, headers=sh)
            else:
                ctx = pc.stream("POST", f"{BASE_URL}/v1/chat/completions", headers=h, content=rb, timeout=90.0)
                rs = await ctx.__aenter__()
                add_log(f"Stream Start: {kd['key'][:8]} via {pinfo} -> HTTP {rs.status_code}")
                if rs.status_code in (401, 402, 403, 429, 500, 502, 503, 504):
                    await ctx.__aexit__(None, None, None); add_log(f"ALERT: Stream {kd['key'][:8]} hit {rs.status_code}. Shifting..."); await db.update_balance(kd['key'], 0.0); continue
                if rs.status_code != 200:
                    cnt = await rs.aread(); await ctx.__aexit__(None, None, None); return Response(content=cnt, status_code=rs.status_code)
                async def gen():
                    try:
                        if is_a:
                            async for chunk in stream_openai_to_anthropic(rs, om): yield chunk
                        else:
                            async for chunk in rs.aiter_bytes(): yield chunk
                    except Exception as e: add_log(f"Stream Error: {e}"); yield f'data: {{"error": "{str(e)}"}}\n\n'.encode("utf-8")
                    finally: await ctx.__aexit__(None, None, None)
                return StreamingResponse(gen(), media_type="text/event-stream")
        except Exception as e: add_log(f"Proxy ERROR via {pinfo}: {str(e)}"); await asyncio.sleep(2); continue
    return JSONResponse({"error": "Exhausted or timed out"}, status_code=503)

@app.get("/v1/models")
async def list_models():
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{BASE_URL}/v1/models"); return Response(content=r.content, status_code=r.status_code, media_type="application/json")
