import os
import json
import aiosqlite
import logging
import asyncio
import secrets
import bcrypt
from typing import List, Dict, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Depends, HTTPException, status, Response
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

# --- KEY MANAGER ---
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


# --- THE SMART DIRECT PROXY ---
proxy_client = httpx.AsyncClient(timeout=900.0, follow_redirects=True)

# ---------------------------------------------------------
# ANTHROPIC TO OPENAI TRANSLATORS (Standalone)
# ---------------------------------------------------------
def translate_anthropic_req_to_openai(anthropic_json: dict) -> dict:
    """Translates Anthropic JSON payload to OpenAI JSON payload"""
    model = anthropic_json.get("model", "openai")
    # Native Pollinations expects simple model names
    openai_json = {
        "model": model,
        "max_tokens": anthropic_json.get("max_tokens", 1024),
        "stream": anthropic_json.get("stream", False),
        "messages": []
    }
    if "system" in anthropic_json and anthropic_json["system"]:
        openai_json["messages"].append({"role": "system", "content": anthropic_json["system"]})
        
    for msg in anthropic_json.get("messages", []):
        openai_json["messages"].append(msg)
        
    return openai_json

def translate_openai_resp_to_anthropic(openai_json: dict) -> dict:
    """Translates OpenAI ChatCompletion response to Anthropic Message response"""
    content = ""
    if "choices" in openai_json and len(openai_json["choices"]) > 0:
        msg = openai_json["choices"][0].get("message", {})
        content = msg.get("content", "")
        
    return {
        "id": openai_json.get("id", "msg_" + secrets.token_hex(8)),
        "type": "message",
        "role": "assistant",
        "model": openai_json.get("model", "openai"),
        "content": [{"type": "text", "text": content}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0}
    }

async def stream_openai_to_anthropic(upstream_resp, original_model):
    """Translates OpenAI SSE to Anthropic SSE for Claude SDK stability"""
    try:
        # yield message_start
        msg_id = "msg_" + secrets.token_hex(8)
        start_msg = {
            "type": "message_start", 
            "message": {
                "id": msg_id, 
                "type": "message", 
                "role": "assistant", 
                "content": [], 
                "model": original_model, 
                "stop_reason": None, 
                "stop_sequence": None, 
                "usage": {"input_tokens": 0, "output_tokens": 0}
            }
        }
        yield f'event: message_start\ndata: {json.dumps(start_msg)}\n\n'.encode("utf-8")
        
        block_start = {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}
        yield f'event: content_block_start\ndata: {json.dumps(block_start)}\n\n'.encode("utf-8")
        
        async for line in upstream_resp.aiter_lines():
            line = line.strip()
            if not line or not line.startswith("data: "):
                continue
            data_str = line[6:]
            if data_str == "[DONE]":
                break
            try:
                data_json = json.loads(data_str)
                choices = data_json.get("choices", [])
                if choices:
                    delta = choices[0].get("delta", {})
                    if "content" in delta and delta["content"]:
                        anthropic_delta = {
                            "type": "content_block_delta",
                            "index": 0,
                            "delta": {
                                "type": "text_delta",
                                "text": delta["content"]
                            }
                        }
                        yield f'event: content_block_delta\ndata: {json.dumps(anthropic_delta)}\n\n'.encode("utf-8")
            except json.JSONDecodeError:
                continue
                
        block_stop = {"type": "content_block_stop", "index": 0}
        yield f'event: content_block_stop\ndata: {json.dumps(block_stop)}\n\n'.encode("utf-8")
        
        msg_delta = {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 10}}
        yield f'event: message_delta\ndata: {json.dumps(msg_delta)}\n\n'.encode("utf-8")
        
        yield b'event: message_stop\ndata: {"type": "message_stop"}\n\n'
    finally:
        await upstream_resp.aclose()


async def stream_openai_passthrough(upstream_resp):
    """Clean byte-level passthrough to avoid UTF-8 decoding errors in Hermes"""
    try:
        async for chunk in upstream_resp.aiter_bytes():
            yield chunk
    finally:
        await upstream_resp.aclose()


# ---------------------------------------------------------
# CORE PROXY HANDLER (DIRECT PASS-THRU TO POLLINATIONS)
# ---------------------------------------------------------
async def core_proxy(request: Request, is_anthropic: bool = False):
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

    # 2. Header Preparation
    clean_headers = {
        "User-Agent": "curl/8.5.0",
        "Accept": "*/*",
        "Content-Type": "application/json"
    }
    
    # 3. Payload Preparation
    raw_body = await request.body()
    try:
        body_json = json.loads(raw_body) if raw_body else {}
    except Exception as e:
        logger.error(f"Body parsing failed: {e}")
        return JSONResponse({"error": {"message": "Invalid JSON"}}, status_code=400)
        
    is_stream = body_json.get("stream", False)
    original_model = body_json.get("model", "openai")
    
    # 4. Translation Layer (Anthropic -> OpenAI)
    if is_anthropic:
        body_json = translate_anthropic_req_to_openai(body_json)
        raw_body = json.dumps(body_json).encode("utf-8")

    # DIRECT UPSTREAM TARGET
    url = f"{BASE_URL}/v1/chat/completions"

    # 5. FAILOVER & WAIT LOOP LOGIC
    while True:
        selected_key_data = await key_manager.get_best_key()
        
        if not selected_key_data:
            add_log("No active keys (>0.05). Holding connection...")
            await asyncio.sleep(150) # 150s Wait Loop
            await key_manager.force_pull_balances()
            continue
        
        current_active_key = selected_key_data['key']
        # FIX: CRITICAL AUTH OVERWRITE
        clean_headers["Authorization"] = f"Bearer {current_active_key}"
        
        try:
            proxy_req = proxy_client.build_request(
                method="POST",
                url=url,
                headers=clean_headers,
                content=raw_body,
                params=request.query_params
            )
            
            upstream_resp = await proxy_client.send(proxy_req, stream=is_stream)
            await db.log_usage("/v1/chat/completions", upstream_resp.status_code)
            
            # Ban protection / Shifting
            if upstream_resp.status_code in (401, 402, 403):
                add_log(f"Key {current_active_key[:10]} fail {upstream_resp.status_code}. Shifting...")
                await upstream_resp.aread()
                await upstream_resp.aclose()
                await db.update_balance(current_active_key, 0.0)
                continue

            resp_headers = {"Content-Type": upstream_resp.headers.get("content-type", "application/json")}
            
            # 6. Response Handlers
            if is_stream:
                if is_anthropic:
                    # Translate OpenAI SSE to Anthropic SSE
                    return StreamingResponse(
                        stream_openai_to_anthropic(upstream_resp, original_model),
                        status_code=upstream_resp.status_code,
                        headers=resp_headers,
                        media_type="text/event-stream"
                    )
                else:
                    # Pure Byte Passthrough for Hermes stability
                    return StreamingResponse(
                        stream_openai_passthrough(upstream_resp),
                        status_code=upstream_resp.status_code,
                        headers=resp_headers,
                        media_type="text/event-stream"
                    )
            else:
                # Synchronous Response (Hermes title-gen Fix)
                content_bytes = await upstream_resp.aread()
                await upstream_resp.aclose()
                
                if is_anthropic:
                    try:
                        openai_resp_json = json.loads(content_bytes)
                        anthropic_resp_json = translate_openai_resp_to_anthropic(openai_resp_json)
                        return JSONResponse(anthropic_resp_json, status_code=upstream_resp.status_code, headers=resp_headers)
                    except json.JSONDecodeError:
                        return Response(content=content_bytes, status_code=upstream_resp.status_code, headers=resp_headers)
                else:
                    return Response(
                        content=content_bytes,
                        status_code=upstream_resp.status_code,
                        headers=resp_headers,
                        media_type=resp_headers["Content-Type"]
                    )

        except Exception as e:
            logger.error(f"Proxy attempt failed: {e}")
            await asyncio.sleep(2)
            continue

# --- EXPLICIT ROUTES ---

@app.post("/v1/messages")
@app.post("/v1/v1/messages")
async def anthropic_proxy(request: Request):
    """Route for Anthropic SDK / Claude Code"""
    return await core_proxy(request, is_anthropic=True)

@app.post("/v1/chat/completions")
@app.post("/v1/v1/chat/completions")
async def openai_proxy(request: Request):
    """Route for OpenAI SDK / Hermes Agent"""
    return await core_proxy(request, is_anthropic=False)

@app.get("/v1/models")
@app.get("/v1/v1/models")
async def list_models_proxy():
    """Route for Model Discovery"""
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{BASE_URL}/v1/models")
        return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")
