import os
import json
import aiosqlite
import logging
import asyncio
import secrets
import bcrypt
from typing import List, Dict, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import httpx
from datetime import datetime, timezone, timedelta
from collections import deque

# --- CONFIGURATION ---
DB_PATH = "proxy_data.db"
BASE_URL = "https://gen.pollinations.ai"
LITELLM_URL = "http://litellm:4000"
SESSION_TOKEN = secrets.token_hex(16)

# --- SYSTEM LOGS ---
system_logs = deque(maxlen=50)
balance_check_lock = asyncio.Lock()

def add_log(msg: str):
    ist = timezone(timedelta(hours=5, minutes=30))
    ts = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S IST")
    log_line = f"[{ts}] {msg}"
    system_logs.append(log_line)
    logger.info(msg)

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- DATABASE & MODELS ---
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
                    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS client_keys (
                    key TEXT PRIMARY KEY,
                    name TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    name TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS usage_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    endpoint TEXT,
                    status_code INTEGER
                )
            """)
            await conn.execute("INSERT OR IGNORE INTO settings VALUES ('polling_interval', '300')")
            
            # Default password hashing
            default_pwd = "Samirandas123@"
            hashed_pwd = bcrypt.hashpw(default_pwd.encode(), bcrypt.gensalt()).decode()
            await conn.execute("INSERT OR IGNORE INTO settings VALUES ('admin_password', ?)", (hashed_pwd,))
            await conn.commit()

    async def log_usage(self, endpoint: str, status_code: int):
        ist = timezone(timedelta(hours=5, minutes=30))
        ts = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("INSERT INTO usage_stats (timestamp, endpoint, status_code) VALUES (?, ?, ?)", (ts, endpoint, status_code))
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

    async def delete_key(self, key: str):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("DELETE FROM keys WHERE key = ?", (key,))
            await conn.commit()

    async def update_balance(self, key: str, balance: float):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("UPDATE keys SET balance = ?, last_checked = CURRENT_TIMESTAMP WHERE key = ?", (balance, key))
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

    async def revoke_client_key(self, key: str):
        async with aiosqlite.connect(self.path) as conn:
            await conn.execute("DELETE FROM client_keys WHERE key = ?", (key,))
            await conn.commit()

    async def validate_client_key(self, key: str) -> bool:
        async with aiosqlite.connect(self.path) as conn:
            async with conn.execute("SELECT is_active FROM client_keys WHERE key = ?", (key,)) as cursor:
                row = await cursor.fetchone()
                if row and row[0] == 1:
                    return True
                return False

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

db = DatabaseManager(DB_PATH)

# --- PROXY LOGIC ---
class KeyManager:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    async def get_best_key(self) -> Optional[Dict]:
        keys = await db.get_keys()
        for k in keys:
            if k['balance'] > 0.05 or k['balance'] == -1.0:
                return k
        return None

    async def check_balance(self, key: str) -> float:
        try:
            headers = {"Authorization": f"Bearer {key}", "User-Agent": "curl/8.5.0"}
            response = await self.client.get(f"{BASE_URL}/account/balance", headers=headers, timeout=10.0)
            if response.status_code == 200:
                balance = response.json().get("balance", 0.0)
                await db.update_balance(key, balance)
                return balance
            else:
                await db.update_balance(key, 0.0)
                return -2.0
        except Exception as e:
            logger.error(f"Balance check failed for {key[:10]}: {e}")
        return -2.0

    async def force_pull_balances(self):
        async with balance_check_lock:
            logger.info("🚨 EMERGENCY: Triggering Force Pull...")
            keys = await db.get_keys()
            if not keys:
                return
            tasks = [self.check_balance(k['key']) for k in keys]
            await asyncio.gather(*tasks)
            logger.info("Force Pull complete.")

key_manager = KeyManager()

# --- BACKGROUND TASK ---
async def polling_worker():
    while True:
        logger.info("Background: Refreshing all keys...")
        keys = await db.get_keys()
        for k in keys:
            await key_manager.check_balance(k['key'])
        
        interval = await db.get_polling_interval()
        await asyncio.sleep(interval)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db._init_db()
    worker = asyncio.create_task(polling_worker())
    yield
    worker.cancel()
    await key_manager.client.aclose()
    await proxy_client.aclose()

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
security = HTTPBearer()

# --- AUTH DEPENDENCY ---
def verify_admin_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != SESSION_TOKEN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid session")
    return True

# --- ADMIN API ---
class AuthRequest(BaseModel):
    pin: str

@app.post("/admin/auth")
async def admin_auth(req: AuthRequest):
    stored_hash = await db.get_admin_password_hash()
    if bcrypt.checkpw(req.pin.encode(), stored_hash.encode()):
        return {"token": SESSION_TOKEN}
    raise HTTPException(status_code=401, detail="Invalid Password")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/admin/keys", dependencies=[Depends(verify_admin_token)])
async def list_keys():
    return {"keys": await db.get_keys()}

class KeyAddRequest(BaseModel):
    key: str
    priority: int = 0

@app.post("/admin/keys", dependencies=[Depends(verify_admin_token)])
async def add_key(req: KeyAddRequest):
    await db.add_key(req.key, req.priority)
    await key_manager.check_balance(req.key)
    return {"success": True}

@app.delete("/admin/keys/{key}", dependencies=[Depends(verify_admin_token)])
async def delete_key(key: str):
    await db.delete_key(key)
    return {"success": True}

@app.get("/admin/test/{key}", dependencies=[Depends(verify_admin_token)])
async def test_key(key: str):
    balance = await key_manager.check_balance(key)
    return {"success": balance >= 0, "balance": balance}

# --- CLIENT KEYS API ---
@app.get("/admin/client-keys", dependencies=[Depends(verify_admin_token)])
async def list_client_keys():
    return {"keys": await db.get_client_keys()}

class ClientKeyAddRequest(BaseModel):
    name: str

@app.post("/admin/client-keys", dependencies=[Depends(verify_admin_token)])
async def add_client_key(req: ClientKeyAddRequest):
    new_key = await db.generate_client_key(req.name)
    return {"success": True, "key": new_key}

@app.delete("/admin/client-keys/{key}", dependencies=[Depends(verify_admin_token)])
async def delete_client_key(key: str):
    await db.revoke_client_key(key)
    return {"success": True}

# --- SETTINGS API ---
class PasswordChangeRequest(BaseModel):
    new_password: str

@app.post("/admin/password", dependencies=[Depends(verify_admin_token)])
async def change_password(req: PasswordChangeRequest):
    await db.set_admin_password(req.new_password)
    return {"success": True}

# --- ANALYTICS API ---
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

    return {
        "today": await get_count(today),
        "this_week": await get_count(this_week),
        "this_month": await get_count(this_month),
        "this_year": await get_count(this_year)
    }

# --- SYSTEM LOGS API ---
@app.get("/admin/live_status", dependencies=[Depends(verify_admin_token)])
async def live_status():
    return {"logs": list(system_logs)}


# --- THE SMART PROXY (FIXED STREAMING & EXPLICIT ROUTING) ---
proxy_client = httpx.AsyncClient(timeout=900.0, follow_redirects=True)

async def core_proxy(request: Request, litellm_path: str):
    # 1. Mandatory Client Authentication
    client_key = None
    auth_header = request.headers.get("Authorization")
    x_api_key = request.headers.get("x-api-key")
    
    if auth_header and auth_header.startswith("Bearer "):
        client_key = auth_header.split(" ")[1]
    elif x_api_key:
        client_key = x_api_key
        
    if not client_key:
        return JSONResponse({"error": {"message": "Missing Authorization or x-api-key header"}}, status_code=401)
    
    if not await db.validate_client_key(client_key):
        return JSONResponse({"error": {"message": "Invalid client API key"}}, status_code=401)

    # Prepare Headers
    clean_headers = {
        "User-Agent": "curl/8.5.0",
        "Accept": "*/*"
    }
    
    for k, v in request.headers.items():
        k_lower = k.lower()
        if k_lower.startswith("x-") or k_lower in ["accept-encoding", "content-type", "accept", "anthropic-version"]:
            clean_headers[k] = v

    if "Content-Type" not in clean_headers:
        clean_headers["Content-Type"] = "application/json"

    # Prepare Body & Model Handling
    raw_body = await request.body()
    try:
        body_json = json.loads(raw_body) if raw_body else {}
        # LiteLLM config now handles mapping, so prefixing is less critical but kept as fallback
        model = body_json.get("model", "")
        if model and not model.startswith("openai/"):
             # Optional: If you want LiteLLM to handle raw model names via aliases, you can skip prefixing here.
             # However, keeping it ensures it hits the "*" catch-all in litellm if aliases fail.
             pass 
    except Exception as e:
        logger.error(f"Body parsing failed: {e}")

    url = f"{LITELLM_URL}{litellm_path}"

    async def stream_generator(upstream_resp):
        try:
            # FIX 1: Read by line to prevent UTF-8 splitting
            async for line in upstream_resp.aiter_lines():
                if line:
                    yield (line + "\n").encode("utf-8")
                else:
                    yield b"\n"
        finally:
            await upstream_resp.aclose()

    # FAILOVER & WAIT LOOP LOGIC (Safe Streaming)
    while True:
        selected_key_data = await key_manager.get_best_key()
        
        if not selected_key_data:
            add_log("No active keys (>0.05). Holding connection...")
            await asyncio.sleep(150) # 150s Wait Loop
            await key_manager.force_pull_balances()
            continue
        
        current_active_key = selected_key_data['key']
        clean_headers["Authorization"] = f"Bearer {current_active_key}"
        
        try:
            proxy_req = proxy_client.build_request(
                method=request.method,
                url=url,
                headers=clean_headers,
                content=raw_body,
                params=request.query_params
            )
            
            upstream_resp = await proxy_client.send(proxy_req, stream=True)
            await db.log_usage(litellm_path, upstream_resp.status_code)
            
            # Key Failure check
            if upstream_resp.status_code in (401, 402, 403):
                add_log(f"Key {current_active_key[:10]} fail {upstream_resp.status_code}. Shifting...")
                await upstream_resp.aread()
                await upstream_resp.aclose()
                await db.update_balance(current_active_key, 0.0)
                continue

            # Forward headers
            resp_headers = {}
            for k, v in upstream_resp.headers.items():
                if k.lower() not in ["content-encoding", "transfer-encoding", "content-length", "connection"]:
                    resp_headers[k] = v
            
            return StreamingResponse(
                stream_generator(upstream_resp),
                status_code=upstream_resp.status_code,
                headers=resp_headers,
                media_type=upstream_resp.headers.get("content-type")
            )

        except Exception as e:
            logger.error(f"Proxy attempt failed: {e}")
            await asyncio.sleep(2)
            continue

# --- EXPLICIT ROUTES ---

@app.post("/v1/chat/completions")
async def openai_proxy(request: Request):
    return await core_proxy(request, "/v1/chat/completions")

@app.post("/v1/messages")
async def anthropic_proxy(request: Request):
    return await core_proxy(request, "/v1/messages")

@app.post("/openai/v1/chat/completions")
async def openai_proxy_legacy(request: Request):
    return await core_proxy(request, "/v1/chat/completions")
