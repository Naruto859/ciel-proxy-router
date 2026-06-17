import os
import re
import json
import aiosqlite
import logging
import asyncio
import secrets
import bcrypt
import httpx
from typing import List, Dict, Optional
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
                await conn.execute("UPDATE keys SET proxy_id = ?, home_proxy_id = ? WHERE key = ?", (proxy_id, proxy_id, key))
                if proxy_id:
                    # Permanently reserve this proxy for this specific key
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
        """Finds a healthy proxy that is either already reserved for this key OR not reserved for anyone."""
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            query = """
                SELECT id FROM proxies 
                WHERE status = 'operational' AND is_active = 1
                AND (reserved_for_key IS NULL OR reserved_for_key = ?)
                ORDER BY created_at DESC LIMIT 1
            """
            async with conn.execute(query, (key,)) as cursor:
                row = await cursor.fetchone()
                return row['id'] if row else None
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("UPDATE keys SET balance = ?, last_checked = CURRENT_TIMESTAMP WHERE key = ?", (balance, key))
            await conn.commit()

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
            # Match strictly by IP Address only
            async with conn.execute("SELECT id, username, password, port FROM proxies WHERE ip = ?", (ip,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    proxy_id = row[0]
                    old_user, old_pass, old_port = row[1], row[2], row[3]
                    
                    # If existing credentials/port differ, save the old ones to the pool before overwriting
                    if old_user and old_pass and (old_user != username or old_pass != password or old_port != port):
                        await conn.execute("INSERT OR IGNORE INTO proxy_credentials (proxy_id, username, password) VALUES (?, ?, ?)", (proxy_id, old_user, old_pass))
                    
                    # Force update the proxy to the latest Port, Username, and Password, and reset status to operational
                    await conn.execute("UPDATE proxies SET port = ?, username = ?, password = ?, status = 'operational' WHERE id = ?", (port, username, password, proxy_id))
                    is_new = False
                else:
                    cursor = await conn.execute("INSERT INTO proxies (ip, port, username, password) VALUES (?, ?, ?, ?)", (ip, port, username, password))
                    proxy_id = cursor.lastrowid
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

    async def get_healthy_proxy_for_key(self, key_to_exclude: str) -> Optional[int]:
        """Finds a healthy proxy with the least number of keys assigned to it."""
        async with aiosqlite.connect(self.path) as conn:
            conn.row_factory = aiosqlite.Row
            # Join proxies with a count of keys currently assigned to them
            query = """
                SELECT p.id, COUNT(k.key) as key_count 
                FROM proxies p 
                LEFT JOIN keys k ON p.id = k.proxy_id 
                WHERE p.status = 'operational' AND p.is_active = 1
                GROUP BY p.id 
                ORDER BY key_count ASC, p.created_at DESC 
                LIMIT 1
            """
            async with conn.execute(query) as cursor:
                row = await cursor.fetchone()
                return row['id'] if row else None

    async def delete_proxy(self, proxy_id: int):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
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

db = DatabaseManager(DB_PATH)

# --- PROXY MANAGER ---
class ProxyManager:
    def __init__(self):
        self.clients: Dict[int, httpx.AsyncClient] = {}
        self.default_client = httpx.AsyncClient(timeout=900.0, follow_redirects=True)
        self._lock = asyncio.Lock()

    async def get_client_for_proxy(self, proxy: Dict) -> httpx.AsyncClient:
        proxy_id = proxy['id']
        async with self._lock:
            if proxy_id not in self.clients:
                auth = f"{proxy['username']}:{proxy['password']}@" if proxy['username'] and proxy['password'] else ""
                proxy_url = f"http://{auth}{proxy['ip']}:{proxy['port']}"
                self.clients[proxy_id] = httpx.AsyncClient(
                    proxies=proxy_url,
                    timeout=900.0,
                    follow_redirects=True
                )
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
            if k['balance'] > 0.05 or k['balance'] == -1.0:
                return k
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
                    add_log(f"WARNING: Key {key[:8]} has broken proxy ID {proxy_id}. Routing via VPS.")
                    proxy_id = None # Fallback to VPS
                else:
                    proxy_info = active_proxy['ip']
                    # Try MAIN credentials
                    creds_to_try = [{"username": active_proxy['username'], "password": active_proxy['password'], "is_main": True}]
                    
                    # Try POOL credentials
                    try:
                        pool = await db.get_proxy_credentials(proxy_id)
                        for p in pool: creds_to_try.append({**p, "is_main": False})
                    except: pass # Table might be missing in old DBs
                    
                    for cred in creds_to_try:
                        try:
                            temp_p = {**active_proxy, "username": cred['username'], "password": cred['password']}
                            client_attempt = await proxy_manager.get_client_for_proxy(temp_p)
                            
                            headers = {"Authorization": f"Bearer {key}", "User-Agent": "curl/8.5.0"}
                            response = await client_attempt.get(f"{BASE_URL}/account/balance", headers=headers, timeout=10.0)
                            
                            if response.status_code == 200:
                                await db.update_proxy_status(proxy_id, 'operational')
                                if not cred["is_main"]:
                                    # Promote working pool creds to main
                                    await db.add_proxy(active_proxy['ip'], active_proxy['port'], cred['username'], cred['password'])
                                
                                balance = response.json().get("balance", 0.0)
                                await db.update_balance(key, balance)
                                add_log(f"Balance check SUCCESS for {key[:8]}... via {proxy_info}: {balance}")
                                return balance, proxy_info
                            
                            elif response.status_code in (401, 403, 402):
                                # Key itself is invalid or out of credits
                                await db.update_balance(key, 0.0)
                                add_log(f"API KEY FAILED (HTTP {response.status_code}) for {key[:8]}... via {proxy_info}")
                                return 0.0, proxy_info
                        except: continue
                    
                    # Proxy is dead
                    await db.update_proxy_status(proxy_id, 'failed')
                    add_log(f"NODE FAILED: Proxy {proxy_info} unreachable or wrong creds.")
                    
                    if await db.get_auto_heal_enabled():
                        new_pid = await db.get_unreserved_healthy_proxy(key)
                        if new_pid:
                            new_proxy = await db.get_proxy_by_id(new_pid)
                            await db.update_key_proxy(key, new_pid, is_home=False)
                            add_log(f"AUTO-HEAL: Re-routing key {key[:8]} from RED node to GREEN dedicated node {new_proxy['ip']}")
                            return await self.check_balance({**key_data, "proxy_id": new_pid})
                    
                    return -2.0, proxy_info # Mark as proxy error

            # Direct VPS Check
            headers = {"Authorization": f"Bearer {key}", "User-Agent": "curl/8.5.0"}
            response = await client.get(f"{BASE_URL}/account/balance", headers=headers, timeout=10.0)
            if response.status_code == 200:
                balance = response.json().get("balance", 0.0)
                await db.update_balance(key, balance)
                add_log(f"Balance SUCCESS for {key[:8]}... via VPS IP: {balance}")
                return balance, "VPS IP (Direct)"
            elif response.status_code in (401, 403, 402):
                await db.update_balance(key, 0.0)
                add_log(f"API KEY FAILED (HTTP {response.status_code}) for {key[:8]}... via VPS IP")
                return 0.0, "VPS IP (Direct)"
                
        except Exception as e:
            add_log(f"Critical System Error for {key[:8]}...: {str(e)}")
        return -2.0, proxy_info

    async def force_pull_balances(self):
        async with balance_check_lock:
            current_time = asyncio.get_event_loop().time()
            interval = await db.get_force_check_interval()
            if current_time - self.last_force_pull_time < float(interval):
                return
            self.last_force_pull_time = current_time
            keys = await db.get_keys()
            if not keys: return
            tasks = [self.check_balance(k) for k in keys]
            await asyncio.gather(*tasks)

key_manager = KeyManager()

# --- BACKGROUND TASKS ---
async def polling_worker():
    while True:
        keys = await db.get_keys()
        for k in keys:
            await key_manager.check_balance(k)
        interval = await db.get_polling_interval()
        await asyncio.sleep(interval)

async def log_cleanup_worker():
    while True:
        await asyncio.sleep(5 * 3600)
        system_logs.clear()
        async with aiosqlite.connect(DB_PATH) as conn:
            # Delete usage stats older than 7 days to keep DB fast, but keep some analytics
            ist = timezone(timedelta(hours=5, minutes=30))
            seven_days_ago = (datetime.now(ist) - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
            await conn.execute("DELETE FROM usage_stats WHERE timestamp < ?", (seven_days_ago,))
            await conn.commit()
        add_log("System logs & old DB stats automatically cleared (5h rotation).")

async def auto_heal_worker():
    """Runs every 24 hours to re-test RED proxies and revert keys to Home IPs if recovered."""
    while True:
        try:
            await asyncio.sleep(24 * 3600)
            if not await db.get_auto_heal_enabled(): continue
            
            add_log("CRON: Starting 24h Auto-Heal & Revert cycle...")
            proxies = await db.get_proxies()
            failed_proxies = [p for p in proxies if p['status'] == 'failed']
            
            if failed_proxies:
                # Re-test failed proxies using a dummy key (first active key)
                keys = await db.get_keys()
                if not keys: continue
                dummy_key = keys[0]
                
                for fp in failed_proxies:
                    # check_balance will automatically try all credentials and update status
                    await key_manager.check_balance({**dummy_key, "proxy_id": fp['id']})
            
            # Revert keys to Home Proxy if recovered
            all_keys = await db.get_keys()
            for k in all_keys:
                if k.get('home_proxy_id') and k['proxy_id'] != k['home_proxy_id']:
                    home_p = await db.get_proxy_by_id(k['home_proxy_id'])
                    if home_p and home_p['status'] == 'operational':
                        await db.update_key_proxy(k['key'], k['home_proxy_id'])
                        add_log(f"CRON: Reverted key {k['key'][:8]} to original Home Proxy {home_p['ip']}")
                        
            add_log("CRON: Auto-Heal cycle complete.")
        except Exception as e:
            logger.error(f"Auto-heal worker error: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db._init_db()
    worker = asyncio.create_task(polling_worker())
    cleanup = asyncio.create_task(log_cleanup_worker())
    cron = asyncio.create_task(auto_heal_worker())
    yield
    worker.cancel()
    cleanup.cancel()
    cron.cancel()
    await proxy_manager.close_all()

app = FastAPI(lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
security = HTTPBearer()

# --- AUTH DEPENDENCY ---
def verify_admin_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != SESSION_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid session")
    return True

# --- API ROUTES ---
@app.post("/admin/auth")
async def admin_auth(request: Request, req: Dict):
    client_ip = request.client.host
    status = await db.get_security_status(client_ip)
    
    if status and status['locked_until']:
        locked_until = datetime.strptime(status['locked_until'], "%Y-%m-%d %H:%M:%S")
        if datetime.now() < locked_until:
            raise HTTPException(status_code=403, detail=f"Account locked. Try again after {status['locked_until']}")

    stored_hash = await db.get_admin_password_hash()
    success = bcrypt.checkpw(req.get('pin','').encode(), stored_hash.encode())
    
    await db.record_login_attempt(client_ip, success)
    
    if success:
        return {"token": SESSION_TOKEN}
    
    raise HTTPException(status_code=401, detail="Invalid PIN")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/admin/keys", dependencies=[Depends(verify_admin_token)])
async def list_keys():
    return {"keys": await db.get_keys()}

@app.post("/admin/keys", dependencies=[Depends(verify_admin_token)])
async def add_key(req: Dict):
    await db.add_key(req['key'], req.get('priority', 0))
    if req.get('proxy_id'):
        # When provided during creation (e.g. import), set as dedicated Home IP
        await db.update_key_proxy(req['key'], req['proxy_id'], is_home=True)
    
    keys = await db.get_keys()
    new_key_data = next((k for k in keys if k['key'] == req['key']), None)
    if new_key_data: 
        await key_manager.check_balance(new_key_data)
    return {"success": True}

@app.delete("/admin/keys/{key}", dependencies=[Depends(verify_admin_token)])
async def delete_key(key: str):
    await db.delete_key(key)
    return {"success": True}

@app.get("/admin/test/{key}", dependencies=[Depends(verify_admin_token)])
async def test_key(key: str):
    keys = await db.get_keys()
    target_key = next((k for k in keys if k['key'] == key), None)
    if not target_key: return {"success": False, "error": "Key not found"}
    balance, proxy_info = await key_manager.check_balance(target_key)
    return {"success": balance >= 0, "balance": balance, "ip": proxy_info}

@app.post("/admin/keys/proxy", dependencies=[Depends(verify_admin_token)])
async def update_key_proxy(req: Dict):
    await db.update_key_proxy(req['key'], req['proxy_id'], is_home=True)
    return {"success": True}

@app.get("/admin/proxies", dependencies=[Depends(verify_admin_token)])
async def list_proxies():
    return {"proxies": await db.get_proxies()}

@app.post("/admin/proxies", dependencies=[Depends(verify_admin_token)])
async def add_proxy(req: Dict):
    await db.add_proxy(req['ip'], req['port'], req.get('username'), req.get('password'))
    return {"success": True}

@app.post("/admin/proxies/bulk", dependencies=[Depends(verify_admin_token)])
async def bulk_add_proxies(req: Dict):
    proxies_to_add = req.get('proxies', [])
    auto_assign = req.get('auto_assign', False)
    
    added_count = 0
    for p in proxies_to_add:
        # 1. Add or Update proxy in DB
        proxy_id, is_new = await db.add_proxy(p['ip'], p['port'], p.get('username'), p.get('password'))
        added_count += 1
        
        # 2. Test proxy immediately to mark as RED if dead
        proxy_data = await db.get_proxy_by_id(proxy_id)
        if proxy_data:
            try:
                client = await proxy_manager.get_client_for_proxy(proxy_data)
                resp = await client.get("https://api.ipify.org?format=json", timeout=10.0)
                if resp.status_code == 200:
                    await db.update_proxy_status(proxy_id, 'operational')
                else:
                    await db.update_proxy_status(proxy_id, 'failed')
            except Exception:
                await db.update_proxy_status(proxy_id, 'failed')
                
        # 3. Auto-Assign logic if enabled and proxy is healthy
        if auto_assign and is_new:
            # Find an API key that doesn't have a proxy_id yet
            keys = await db.get_keys()
            free_key = next((k for k in keys if not k.get('proxy_id')), None)
            if free_key:
                # Check if proxy is operational before assigning
                final_proxy_data = await db.get_proxy_by_id(proxy_id)
                if final_proxy_data and final_proxy_data['status'] == 'operational':
                    await db.update_key_proxy(free_key['key'], proxy_id, is_home=True)
                    add_log(f"AUTO-ASSIGN: Dedicated new IP {p['ip']} to key {free_key['key'][:8]}")

    return {"success": True, "added": added_count}

@app.delete("/admin/proxies/{proxy_id}", dependencies=[Depends(verify_admin_token)])
async def delete_proxy(proxy_id: int):
    await db.delete_proxy(proxy_id)
    return {"success": True}

@app.get("/admin/proxies/test/{proxy_id}", dependencies=[Depends(verify_admin_token)])
async def test_proxy_outbound(proxy_id: int):
    proxy = await db.get_proxy_by_id(proxy_id)
    if not proxy: return {"success": False, "error": "Proxy not found"}
    try:
        client = await proxy_manager.get_client_for_proxy(proxy)
        resp = await client.get("https://api.ipify.org?format=json", timeout=10.0)
        if resp.status_code == 200:
            detected_ip = resp.json().get("ip")
            return {"success": True, "detected_ip": detected_ip, "matches": detected_ip == proxy['ip']}
        return {"success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e: return {"success": False, "error": str(e)}

@app.get("/admin/client-keys", dependencies=[Depends(verify_admin_token)])
async def list_client_keys():
    return {"keys": await db.get_client_keys()}

@app.post("/admin/client-keys", dependencies=[Depends(verify_admin_token)])
async def add_client_key(req: Dict):
    new_key = await db.generate_client_key(req['name'])
    return {"success": True, "key": new_key}

@app.delete("/admin/client-keys/{key}", dependencies=[Depends(verify_admin_token)])
async def delete_client_key(key: str):
    await db.revoke_client_key(key)
    return {"success": True}

@app.get("/admin/settings/polling", dependencies=[Depends(verify_admin_token)])
async def get_polling():
    return {"interval": await db.get_polling_interval()}

@app.post("/admin/settings/polling", dependencies=[Depends(verify_admin_token)])
async def set_polling(req: Dict):
    await db.set_polling_interval(int(req['interval']))
    return {"success": True}

@app.get("/admin/settings/force_check", dependencies=[Depends(verify_admin_token)])
async def get_force_check():
    return {"interval": await db.get_force_check_interval()}

@app.post("/admin/settings/force_check", dependencies=[Depends(verify_admin_token)])
async def set_force_check(req: Dict):
    await db.set_force_check_interval(int(req['interval']))
    return {"success": True}

@app.get("/admin/settings/max_hold", dependencies=[Depends(verify_admin_token)])
async def get_max_hold():
    return {"duration": await db.get_max_hold_duration()}

@app.post("/admin/settings/max_hold", dependencies=[Depends(verify_admin_token)])
async def set_max_hold(req: Dict):
    await db.set_max_hold_duration(int(req['duration']))
    return {"success": True}

@app.get("/admin/settings/auto_heal", dependencies=[Depends(verify_admin_token)])
async def get_auto_heal():
    return {"enabled": await db.get_auto_heal_enabled()}

@app.post("/admin/settings/auto_heal", dependencies=[Depends(verify_admin_token)])
async def set_auto_heal(req: Dict):
    await db.set_auto_heal_enabled(req['enabled'])
    return {"success": True}


@app.get("/admin/live_status", dependencies=[Depends(verify_admin_token)])
async def live_status():
    return {"logs": list(system_logs)}

@app.get("/admin/analytics", dependencies=[Depends(verify_admin_token)])
async def get_analytics():
    ist = timezone(timedelta(hours=5, minutes=30))
    now = datetime.now(ist)
    async def get_count(start_time: str):
        async with aiosqlite.connect(DB_PATH) as conn:
            async with conn.execute("SELECT COUNT(*) FROM usage_stats WHERE timestamp >= ?", (start_time,)) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else 0
    today = (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    this_week = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    this_month = (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    this_year = (now - timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
    return {"today": await get_count(today), "this_week": await get_count(this_week), "this_month": await get_count(this_month), "this_year": await get_count(this_year)}

# --- PROXY CORE ---
def translate_anthropic_req_to_openai(anthropic_json: dict) -> dict:
    model = anthropic_json.get("model", "openai")
    openai_json = {
        "model": model,
        "max_tokens": anthropic_json.get("max_tokens", 1024),
        "stream": anthropic_json.get("stream", False),
        "messages": []
    }
    
    if "system" in anthropic_json and anthropic_json["system"]:
        sys_content = anthropic_json["system"]
        if isinstance(sys_content, list):
            sys_content = "".join([block.get("text", "") for block in sys_content if block.get("type") == "text"])
        sys_content = re.sub(r'^x-anthropic-billing-header:\s*(?:[a-z_]+=[^\s;]+;\s*)*', '', sys_content)
        sys_content = sys_content.strip()
        if sys_content:
            openai_json["messages"].append({"role": "system", "content": sys_content})
        
    if "tools" in anthropic_json:
        openai_json["tools"] = []
        for tool in anthropic_json["tools"]:
            openai_json["tools"].append({
                "type": "function",
                "function": {
                    "name": tool.get("name"),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {})
                }
            })
            
    if "tool_choice" in anthropic_json:
        choice = anthropic_json["tool_choice"]
        if choice.get("type") == "auto": openai_json["tool_choice"] = "auto"
        elif choice.get("type") == "any": openai_json["tool_choice"] = "required"
        elif choice.get("type") == "tool": openai_json["tool_choice"] = {"type": "function", "function": {"name": choice.get("name")}}

    raw_messages = []
    for msg in anthropic_json.get("messages", []):
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system": continue

        if isinstance(content, str):
            raw_messages.append({"role": role, "content": content})
        elif isinstance(content, list):
            openai_content = []
            tool_calls = []
            tool_results = []
            for block in content:
                block_type = block.get("type")
                if block_type == "text":
                    openai_content.append({"type": "text", "text": block.get("text", "")})
                elif block_type == "image":
                    source = block.get("source", {})
                    if source.get("type") == "base64":
                        openai_content.append({
                            "type": "image_url",
                            "image_url": {"url": f"data:{source.get('media_type', 'image/jpeg')};base64,{source.get('data')}"}
                        })
                elif block_type == "tool_use":
                    tool_calls.append({
                        "id": block.get("id"),
                        "type": "function",
                        "function": {"name": block.get("name"), "arguments": json.dumps(block.get("input", {}))}
                    })
                elif block_type == "tool_result":
                    res_content = block.get("content", "")
                    if isinstance(res_content, list):
                        res_content = "".join([c.get("text", "") for c in res_content if c.get("type") == "text"])
                    tool_results.append({
                        "role": "tool",
                        "tool_call_id": block.get("tool_use_id"),
                        "content": str(res_content)
                    })

            for tr in tool_results: raw_messages.append(tr)
            if tool_calls:
                openai_msg = {"role": "assistant"}
                if openai_content:
                    text_content = "".join([c.get("text", "") for c in openai_content if c.get("type") == "text"])
                    image_items = [c for c in openai_content if c.get("type") == "image_url"]
                    openai_msg["content"] = [{"type": "text", "text": text_content}] + image_items if image_items else text_content
                else: openai_msg["content"] = ""
                openai_msg["tool_calls"] = tool_calls
                raw_messages.append(openai_msg)
            elif openai_content:
                has_image = any(c.get("type") == "image_url" for c in openai_content)
                if not has_image:
                    content_str = "".join([c.get("text", "") for c in openai_content if c.get("type") == "text"])
                    raw_messages.append({"role": role, "content": content_str})
                else: raw_messages.append({"role": role, "content": openai_content})

    openai_json["messages"] = raw_messages
    return openai_json

def translate_openai_resp_to_anthropic(openai_json: dict) -> dict:
    content_blocks = []
    stop_reason = "end_turn"
    if "choices" in openai_json and len(openai_json["choices"]) > 0:
        choice = openai_json["choices"][0]
        msg = choice.get("message", {})
        if msg.get("content"): content_blocks.append({"type": "text", "text": msg.get("content")})
        if msg.get("tool_calls"):
            stop_reason = "tool_use"
            for tcall in msg.get("tool_calls", []):
                try: args = json.loads(tcall.get("function", {}).get("arguments", "{}"))
                except: args = {}
                content_blocks.append({"type": "tool_use", "id": tcall.get("id"), "name": tcall.get("function", {}).get("name"), "input": args})
        oai_finish = choice.get("finish_reason")
        if oai_finish == "tool_calls": stop_reason = "tool_use"
        elif oai_finish == "length": stop_reason = "max_tokens"
    
    return {
        "id": openai_json.get("id", "msg_" + secrets.token_hex(8)),
        "type": "message", "role": "assistant", "model": openai_json.get("model", "openai"),
        "content": content_blocks, "stop_reason": stop_reason, "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0}
    }

async def stream_openai_to_anthropic(upstream_resp, original_model):
    msg_id = "msg_" + secrets.token_hex(8)
    yield f'event: message_start\ndata: {json.dumps({"type": "message_start", "message": {"id": msg_id, "type": "message", "role": "assistant", "content": [], "model": original_model, "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 0, "output_tokens": 0}}})}\n\n'.encode("utf-8")
    
    current_block_index = 0
    in_text_block = False
    in_tool_block = False
    
    async for line in upstream_resp.aiter_lines():
        if not line.startswith("data: "): continue
        data_str = line[6:]
        if data_str == "[DONE]": break
        try:
            data_json = json.loads(data_str)
            choices = data_json.get("choices", [])
            if not choices: continue
            delta = choices[0].get("delta", {})
            
            if "content" in delta and delta["content"]:
                if in_tool_block:
                    yield f'event: content_block_stop\ndata: {json.dumps({"type": "content_block_stop", "index": current_block_index})}\n\n'.encode("utf-8")
                    in_tool_block = False; current_block_index += 1
                if not in_text_block:
                    yield f'event: content_block_start\ndata: {json.dumps({"type": "content_block_start", "index": current_block_index, "content_block": {"type": "text", "text": ""}})}\n\n'.encode("utf-8")
                    in_text_block = True
                yield f'event: content_block_delta\ndata: {json.dumps({"type": "content_block_delta", "index": current_block_index, "delta": {"type": "text_delta", "text": delta["content"]}})}\n\n'.encode("utf-8")
                
            if "tool_calls" in delta:
                if in_text_block:
                    yield f'event: content_block_stop\ndata: {json.dumps({"type": "content_block_stop", "index": current_block_index})}\n\n'.encode("utf-8")
                    in_text_block = False; current_block_index += 1
                tcall = delta["tool_calls"][0]
                if "id" in tcall and tcall["id"]:
                    if in_tool_block:
                        yield f'event: content_block_stop\ndata: {json.dumps({"type": "content_block_stop", "index": current_block_index})}\n\n'.encode("utf-8")
                        current_block_index += 1
                    yield f'event: content_block_start\ndata: {json.dumps({"type": "content_block_start", "index": current_block_index, "content_block": {"type": "tool_use", "id": tcall["id"], "name": tcall.get("function", {}).get("name", ""), "input": {}}})}\n\n'.encode("utf-8")
                    in_tool_block = True
                if "function" in tcall and "arguments" in tcall["function"]:
                    yield f'event: content_block_delta\ndata: {json.dumps({"type": "content_block_delta", "index": current_block_index, "delta": {"type": "input_json_delta", "partial_json": tcall["function"]["arguments"]}})}\n\n'.encode("utf-8")
                    
            finish_reason = choices[0].get("finish_reason")
            if finish_reason:
                if in_text_block or in_tool_block:
                    yield f'event: content_block_stop\ndata: {json.dumps({"type": "content_block_stop", "index": current_block_index})}\n\n'.encode("utf-8")
                stop_mapping = {"stop": "end_turn", "tool_calls": "tool_use", "length": "max_tokens"}
                yield f'event: message_delta\ndata: {json.dumps({"type": "message_delta", "delta": {"stop_reason": stop_mapping.get(finish_reason, "end_turn"), "stop_sequence": None}, "usage": {"output_tokens": 1}})}\n\n'.encode("utf-8")
        except: continue
    yield f'event: message_stop\ndata: {json.dumps({"type": "message_stop"})}\n\n'.encode("utf-8")

@app.api_route("/v1/chat/completions", methods=["POST"])
@app.api_route("/v1/v1/chat/completions", methods=["POST"])
@app.api_route("/v1/messages", methods=["POST"])
@app.api_route("/v1/v1/messages", methods=["POST"])
async def core_proxy(request: Request):
    client_key = request.headers.get("Authorization", "").replace("Bearer ", "") or request.headers.get("x-api-key", "")
    if not client_key or not await db.validate_client_key(client_key):
        return JSONResponse({"error": "Invalid Key"}, status_code=401)
    
    is_anthropic = "messages" in request.url.path
    raw_body = await request.body()
    try: body_json = json.loads(raw_body) if raw_body else {}
    except: return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    
    orig_model = body_json.get("model", "openai")
    is_stream = body_json.get("stream", False)
    if is_anthropic: 
        body_json = translate_anthropic_req_to_openai(body_json)
        raw_body = json.dumps(body_json).encode("utf-8")
    else:
        # Debug: Dump OpenAI SDK payload for vision issues
        with open("/tmp/debug_openai_req.log", "a") as f:
            f.write(f"\n--- INCOMING OPENAI REQ ---\n{json.dumps(body_json, indent=2)}\n")
            
    max_hold = await db.get_max_hold_duration()
    start_time = asyncio.get_event_loop().time()
    
    while asyncio.get_event_loop().time() - start_time < max_hold:
        key_data = await key_manager.get_best_key()
        if not key_data:
            await asyncio.sleep(2); await key_manager.force_pull_balances(); continue
        
        try:
            proxy_client = proxy_manager.default_client
            proxy_info = "VPS IP (Direct)"
            if key_data.get('proxy_id'):
                proxy = await db.get_proxy_by_id(key_data['proxy_id'])
                if proxy: proxy_client = await proxy_manager.get_client_for_proxy(proxy); proxy_info = proxy['ip']
            
            headers = {"Authorization": f"Bearer {key_data['key']}", "Content-Type": "application/json", "User-Agent": "curl/8.5.0"}
            
            if not is_stream:
                resp = await proxy_client.post(f"{BASE_URL}/v1/chat/completions", headers=headers, content=raw_body, timeout=90.0)
                await db.log_usage(request.url.path, resp.status_code)
                add_log(f"Request: {key_data['key'][:8]} via {proxy_info} -> HTTP {resp.status_code}")
                
                if resp.status_code in (401, 402, 403, 429, 500, 502, 503, 504):
                    add_log(f"ALERT: Key {key_data['key'][:8]} hit {resp.status_code}. Draining/Switching...")
                    await db.update_balance(key_data['key'], 0.0); continue
                
                safe_headers = {"Content-Type": resp.headers.get("content-type", "application/json")}
                if is_anthropic and resp.status_code == 200:
                    return JSONResponse(translate_openai_resp_to_anthropic(resp.json()), headers=safe_headers)
                return Response(content=resp.content, status_code=resp.status_code, headers=safe_headers)
            else:
                resp_ctx = proxy_client.stream("POST", f"{BASE_URL}/v1/chat/completions", headers=headers, content=raw_body, timeout=90.0)
                resp_stream = await resp_ctx.__aenter__()
                
                add_log(f"Stream Start: {key_data['key'][:8]} via {proxy_info} -> HTTP {resp_stream.status_code}")
                
                if resp_stream.status_code in (401, 402, 403, 429, 500, 502, 503, 504):
                    await resp_ctx.__aexit__(None, None, None)
                    add_log(f"ALERT: Stream {key_data['key'][:8]} hit {resp_stream.status_code}. Shifting...")
                    await db.update_balance(key_data['key'], 0.0); continue
                
                if resp_stream.status_code != 200:
                    content = await resp_stream.aread()
                    await resp_ctx.__aexit__(None, None, None)
                    return Response(content=content, status_code=resp_stream.status_code)

                async def stream_generator():
                    try:
                        if is_anthropic:
                            async for chunk in stream_openai_to_anthropic(resp_stream, orig_model): yield chunk
                        else:
                            async for chunk in resp_stream.aiter_bytes():
                                yield chunk
                    except Exception as e:
                        add_log(f"Stream Error: {e}")
                        yield f'data: {{"error": "{str(e)}"}}\n\n'.encode("utf-8")
                    finally:
                        await resp_ctx.__aexit__(None, None, None)

                return StreamingResponse(stream_generator(), media_type="text/event-stream")
                
        except HTTPException as e:
            if e.status_code in (401, 403): continue
            return JSONResponse({"error": str(e)}, status_code=e.status_code)
        except Exception as e:
            error_details = str(e) if str(e) else repr(e)
            add_log(f"Proxy attempt ERROR via {proxy_info}: {type(e).__name__} - {error_details}")
            await asyncio.sleep(2); continue

    return JSONResponse({"error": "All keys exhausted or max hold duration reached"}, status_code=503)

@app.api_route("/v1", methods=["GET", "HEAD"])
async def v1_status(): return JSONResponse({"status": "running"})

@app.get("/v1/models")
async def list_models():
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{BASE_URL}/v1/models")
        return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
