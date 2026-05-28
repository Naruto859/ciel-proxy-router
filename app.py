import os
import json
import sqlite3
import logging
import asyncio
import secrets
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
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                    key TEXT PRIMARY KEY,
                    balance REAL DEFAULT -1.0,
                    priority INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS client_keys (
                    key TEXT PRIMARY KEY,
                    name TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    name TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS usage_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    endpoint TEXT,
                    status_code INTEGER
                )
            """)
            conn.execute("INSERT OR IGNORE INTO settings VALUES ('polling_interval', '300')")
            conn.execute("INSERT OR IGNORE INTO settings VALUES ('admin_password', 'Samirandas123@')")

    def log_usage(self, endpoint: str, status_code: int):
        ist = timezone(timedelta(hours=5, minutes=30))
        ts = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(self.path) as conn:
            conn.execute("INSERT INTO usage_stats (timestamp, endpoint, status_code) VALUES (?, ?, ?)", (ts, endpoint, status_code))


    def get_keys(self):
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("SELECT * FROM keys ORDER BY priority DESC, balance DESC").fetchall()]

    def add_key(self, key: str, priority: int = 0):
        with sqlite3.connect(self.path) as conn:
            conn.execute("INSERT OR REPLACE INTO keys (key, priority) VALUES (?, ?)", (key, priority))

    def delete_key(self, key: str):
        with sqlite3.connect(self.path) as conn:
            conn.execute("DELETE FROM keys WHERE key = ?", (key,))

    def update_balance(self, key: str, balance: float):
        with sqlite3.connect(self.path) as conn:
            conn.execute("UPDATE keys SET balance = ?, last_checked = CURRENT_TIMESTAMP WHERE key = ?", (balance, key))

    def get_client_keys(self):
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("SELECT * FROM client_keys ORDER BY created_at DESC").fetchall()]

    def generate_client_key(self, name: str) -> str:
        new_key = f"ciel_sk_{secrets.token_hex(16)}"
        with sqlite3.connect(self.path) as conn:
            conn.execute("INSERT INTO client_keys (key, name) VALUES (?, ?)", (new_key, name))
        return new_key

    def revoke_client_key(self, key: str):
        with sqlite3.connect(self.path) as conn:
            conn.execute("DELETE FROM client_keys WHERE key = ?", (key,))

    def validate_client_key(self, key: str) -> bool:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT is_active FROM client_keys WHERE key = ?", (key,)).fetchone()
            if row and row[0] == 1:
                return True
            return False

    def get_admin_password(self) -> str:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT value FROM settings WHERE name = 'admin_password'").fetchone()
            return row[0] if row else "Samirandas123@"

    def set_admin_password(self, password: str):
        with sqlite3.connect(self.path) as conn:
            conn.execute("UPDATE settings SET value = ? WHERE name = 'admin_password'", (password,))

db = DatabaseManager(DB_PATH)

# --- PROXY LOGIC ---
class KeyManager:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    async def get_best_key(self) -> Optional[str]:
        keys = db.get_keys()
        for k in keys:
            if k['balance'] > 0 or k['balance'] == -1.0:
                return k['key']
        return None

    async def check_balance(self, key: str) -> float:
        try:
            headers = {"Authorization": f"Bearer {key}", "User-Agent": "curl/8.5.0"}
            response = await self.client.get(f"{BASE_URL}/account/balance", headers=headers, timeout=10.0)
            if response.status_code == 200:
                balance = response.json().get("balance", 0.0)
                db.update_balance(key, balance)
                return balance
            else:
                db.update_balance(key, 0.0)
                return -2.0
        except Exception as e:
            logger.error(f"Balance check failed for {key[:10]}: {e}")
        return -2.0 # Error state

    async def force_pull_balances(self):
        """Emergency real-time check of all keys. Runs in parallel."""
        logger.info("🚨 EMERGENCY: No healthy keys in DB cache. Triggering Force Pull...")
        keys = db.get_keys()
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
        keys = db.get_keys()
        for k in keys:
            await key_manager.check_balance(k['key'])
        
        # Get interval from settings
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT value FROM settings WHERE name = 'polling_interval'").fetchone()
            interval = int(row[0]) if row else 300
        
        await asyncio.sleep(interval)

@asynccontextmanager
async def lifespan(app: FastAPI):
    worker = asyncio.create_task(polling_worker())
    yield
    worker.cancel()
    await key_manager.client.aclose()

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
security = HTTPBearer()

# --- AUTH DEPENDENCY ---
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != SESSION_TOKEN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid session")
    return True

# --- ADMIN API ---
class AuthRequest(BaseModel):
    pin: str

@app.post("/admin/auth")
async def admin_auth(req: AuthRequest):
    if req.pin == db.get_admin_password():
        return {"token": SESSION_TOKEN}
    raise HTTPException(status_code=401, detail="Invalid Password")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/admin/keys", dependencies=[Depends(verify_token)])
async def list_keys():
    return {"keys": db.get_keys()}

class KeyAddRequest(BaseModel):
    key: str
    priority: int = 0

@app.post("/admin/keys", dependencies=[Depends(verify_token)])
async def add_key(req: KeyAddRequest):
    db.add_key(req.key, req.priority)
    await key_manager.check_balance(req.key)
    return {"success": True}

@app.delete("/admin/keys/{key}", dependencies=[Depends(verify_token)])
async def delete_key(key: str):
    db.delete_key(key)
    return {"success": True}

@app.get("/admin/test/{key}", dependencies=[Depends(verify_token)])
async def test_key(key: str):
    balance = await key_manager.check_balance(key)
    return {"success": balance >= 0, "balance": balance}

# --- CLIENT KEYS API ---
@app.get("/admin/client-keys", dependencies=[Depends(verify_token)])
async def list_client_keys():
    return {"keys": db.get_client_keys()}

class ClientKeyAddRequest(BaseModel):
    name: str

@app.post("/admin/client-keys", dependencies=[Depends(verify_token)])
async def add_client_key(req: ClientKeyAddRequest):
    new_key = db.generate_client_key(req.name)
    return {"success": True, "key": new_key}

@app.delete("/admin/client-keys/{key}", dependencies=[Depends(verify_token)])
async def delete_client_key(key: str):
    db.revoke_client_key(key)
    return {"success": True}

# --- SETTINGS API ---
class PasswordChangeRequest(BaseModel):
    new_password: str

@app.post("/admin/password", dependencies=[Depends(verify_token)])
async def change_password(req: PasswordChangeRequest):
    db.set_admin_password(req.new_password)
    return {"success": True}

# --- ANALYTICS API ---
@app.get("/admin/analytics", dependencies=[Depends(verify_token)])
async def get_analytics():
    ist = timezone(timedelta(hours=5, minutes=30))
    now = datetime.now(ist)
    
    def get_count(start_time: str):
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT COUNT(*) FROM usage_stats WHERE timestamp >= ?", (start_time,)).fetchone()
            return row[0] if row else 0

    today = (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    this_week = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    this_month = (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    this_year = (now - timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "today": get_count(today),
        "this_week": get_count(this_week),
        "this_month": get_count(this_month),
        "this_year": get_count(this_year)
    }

# --- SYSTEM LOGS API ---
@app.get("/admin/live_status", dependencies=[Depends(verify_token)])
async def live_status():
    return {"logs": list(system_logs)}

# --- THE SMART PROXY (STRICT FAILOVER) ---
proxy_client = httpx.AsyncClient(timeout=120.0, follow_redirects=True)

async def core_proxy(request: Request, path: str):
    # 1. Client Authentication
    client_key = None
    auth_header = request.headers.get("Authorization")
    x_api_key = request.headers.get("x-api-key")
    
    if auth_header and auth_header.startswith("Bearer "):
        client_key = auth_header.split(" ")[1]
    elif x_api_key:
        client_key = x_api_key
        
    if not client_key:
        return JSONResponse({"error": {"message": "Missing or invalid Authorization or x-api-key header"}}, status_code=401)
    
    if not db.validate_client_key(client_key):
        return JSONResponse({"error": {"message": "Invalid or inactive client API key"}}, status_code=401)

    url = f"{BASE_URL}/{path}"
    body = await request.body()
    
    # Header Preservation for Vision and WAF Bypass:
    clean_headers = {
        "User-Agent": "curl/8.5.0",
        "Accept": "*/*"
    }
    
    # Forward critical headers (including Vision support)
    for k, v in request.headers.items():
        k_lower = k.lower()
        if k_lower.startswith("x-") or k_lower in ["accept-encoding", "content-length", "content-type", "accept"]:
            clean_headers[k] = v

    try:
        is_stream = json.loads(body).get("stream", False) if body else False
    except:
        is_stream = False

    # Safety Wall & Retry Loop
    state = {"sent_keepalive": False}
    
    async def generate_with_keepalive():
        # Pre-flight balance check for every new request
        async with balance_check_lock:
            await key_manager.force_pull_balances()
            
        current_active_key = None
        
        while True:
            current_active_key = await key_manager.get_best_key()
            
            if not current_active_key:
                add_log("No active keys available (Balance 0.00). Entering Safety Wall Wait Loop...")
                wait_counter = 0
                while not current_active_key:
                    if is_stream:
                        yield b":\n\n"
                        state["sent_keepalive"] = True
                    else:
                        yield b" "
                        
                    await asyncio.sleep(15)
                    wait_counter += 1
                    
                    if wait_counter % 20 == 0:
                        add_log("WAIT mode: Refreshing balances...")
                        async with balance_check_lock:
                            await key_manager.force_pull_balances()
                        current_active_key = await key_manager.get_best_key()
                        if current_active_key:
                            add_log("Balance detected. Resuming request...")
                            break
            
            if current_active_key:
                clean_headers["Authorization"] = f"Bearer {current_active_key}"
                try:
                    proxy_req = proxy_client.build_request(
                        method=request.method,
                        url=url,
                        headers=clean_headers,
                        content=body,
                        params=request.query_params
                    )
                    
                    response = await proxy_client.send(proxy_req, stream=True)
                    db.log_usage(path, response.status_code)
                    
                    # Handle specific error codes: drain and shift to NEXT key
                    if response.status_code in (401, 402, 403):
                        add_log(f"Key {current_active_key[:10]} failed with {response.status_code}. Draining and shifting to NEXT key...")
                        await response.aread()
                        await response.aclose()
                        db.update_balance(current_active_key, 0.0)
                        current_active_key = None
                        continue

                    # For 400 (Vision/Payload errors) or 429 (Rate Limits), pass through and STOP
                    if response.status_code in (400, 429):
                        add_log(f"Upstream returned {response.status_code}. Passing through to client.")
                        async for chunk in response.aiter_bytes():
                            yield chunk
                        await response.aclose()
                        return

                    if response.status_code >= 500:
                        add_log(f"Upstream error {response.status_code}. Retrying...")
                        await response.aread()
                        await response.aclose()
                        current_active_key = None
                        await asyncio.sleep(2)
                        continue
                    
                    # Stream the actual response natively (no wrappers)
                    try:
                        async for chunk in response.aiter_bytes():
                            yield chunk
                    finally:
                        await response.aclose()
                    return # Successfully streamed

                except Exception as e:
                    logger.error(f"Proxy attempt failed: {e}")
                    current_active_key = None
                    await asyncio.sleep(2)
                    continue

    # Determine media type: avoid hardcoding SSE if the client explicitly requested non-streaming
    try:
        is_stream = json.loads(body).get("stream", False) if body else False
    except:
        is_stream = False
    
    # Determine media type: strictly respect the client's request
    media_type = "text/event-stream" if is_stream else "application/json"

    return StreamingResponse(generate_with_keepalive(), status_code=200, media_type=media_type)

@app.api_route("/openai/v1/chat/completions", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def openai_proxy_direct(request: Request):
    return await core_proxy(request, "openai/v1/chat/completions")

@app.api_route("/v1/chat/completions", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def openai_proxy(request: Request):
    return await core_proxy(request, "v1/chat/completions")

@app.api_route("/v1/messages", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def anthropic_proxy(request: Request):
    return await core_proxy(request, "v1/messages")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def catch_all_proxy(request: Request, path: str):
    return await core_proxy(request, path)

