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

# --- TRANSLATION LAYER (Anthropic -> OpenAI) ---
import json

def translate_anthropic_to_openai(body_json: dict) -> dict:
    openai_body = {}
    
    if "model" in body_json:
        openai_body["model"] = body_json["model"]
    if "max_tokens" in body_json:
        openai_body["max_tokens"] = body_json["max_tokens"]
    if "temperature" in body_json:
        openai_body["temperature"] = body_json["temperature"]
    if "stream" in body_json:
        openai_body["stream"] = body_json["stream"]

    messages = []
    if "system" in body_json:
        system_content = body_json["system"]
        if isinstance(system_content, list):
            text_parts = [block.get("text", "") for block in system_content if block.get("type") == "text"]
            messages.append({"role": "system", "content": "\n".join(text_parts)})
        elif isinstance(system_content, str):
            messages.append({"role": "system", "content": system_content})

    for msg in body_json.get("messages", []):
        role = msg.get("role")
        content = msg.get("content")
        
        if isinstance(content, str):
            messages.append({"role": role, "content": content})
            continue
            
        if isinstance(content, list):
            openai_msg = {"role": role, "content": ""}
            tool_calls = []
            
            for block in content:
                block_type = block.get("type")
                if block_type == "text":
                    openai_msg["content"] += block.get("text", "")
                elif block_type == "tool_use":
                    tool_calls.append({
                        "id": block.get("id"),
                        "type": "function",
                        "function": {
                            "name": block.get("name"),
                            "arguments": json.dumps(block.get("input", {}))
                        }
                    })
                elif block_type == "tool_result":
                    messages.append({
                        "role": "tool",
                        "tool_call_id": block.get("tool_use_id"),
                        "content": block.get("content", "")
                    })
            
            if tool_calls:
                openai_msg["tool_calls"] = tool_calls
            if openai_msg["content"] or openai_msg.get("tool_calls"):
                messages.append(openai_msg)

    openai_body["messages"] = messages
    
    if "tools" in body_json:
        openai_tools = []
        for t in body_json["tools"]:
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": t.get("name"),
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {})
                }
            })
        openai_body["tools"] = openai_tools

    return openai_body

def translate_openai_to_anthropic_non_stream(openai_bytes: bytes) -> bytes:
    try:
        data = json.loads(openai_bytes.decode('utf-8'))
        anthropic_resp = {
            "id": data.get("id", "msg_mock"),
            "type": "message",
            "role": "assistant",
            "content": [],
            "model": data.get("model", "gpt-4"),
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {
                "input_tokens": data.get("usage", {}).get("prompt_tokens", 0),
                "output_tokens": data.get("usage", {}).get("completion_tokens", 0)
            }
        }
        
        choices = data.get("choices", [])
        if choices:
            msg = choices[0].get("message", {})
            if "content" in msg and msg["content"]:
                anthropic_resp["content"].append({
                    "type": "text",
                    "text": msg["content"]
                })
            if "tool_calls" in msg:
                anthropic_resp["stop_reason"] = "tool_use"
                for tc in msg["tool_calls"]:
                    anthropic_resp["content"].append({
                        "type": "tool_use",
                        "id": tc.get("id"),
                        "name": tc.get("function", {}).get("name"),
                        "input": json.loads(tc.get("function", {}).get("arguments", "{}"))
                    })
                    
        return json.dumps(anthropic_resp).encode('utf-8')
    except Exception:
        return openai_bytes

def translate_openai_to_anthropic_stream(openai_chunk: bytes) -> bytes:
    try:
        chunk_str = openai_chunk.decode('utf-8')
        if not chunk_str.startswith("data: ") or chunk_str.strip() == "data: [DONE]":
            return openai_chunk
            
        data_json = json.loads(chunk_str[6:])
        
        anthropic_event = {
            "type": "content_block_delta",
            "delta": {
                "type": "text_delta",
                "text": ""
            }
        }
        
        choices = data_json.get("choices", [])
        if choices:
            delta = choices[0].get("delta", {})
            if "content" in delta and delta["content"]:
                anthropic_event["delta"]["text"] = delta["content"]
                return f"data: {json.dumps(anthropic_event)}\n\n".encode('utf-8')
            if "tool_calls" in delta:
                tc = delta["tool_calls"][0]
                if "id" in tc:
                    event = {
                        "type": "content_block_start",
                        "content_block": {
                            "type": "tool_use",
                            "id": tc["id"],
                            "name": tc["function"]["name"],
                            "input": {}
                        }
                    }
                    return f"data: {json.dumps(event)}\n\n".encode('utf-8')
                elif "function" in tc and "arguments" in tc["function"]:
                    event = {
                        "type": "content_block_delta",
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": tc["function"]["arguments"]
                        }
                    }
                    return f"data: {json.dumps(event)}\n\n".encode('utf-8')
        return openai_chunk
    except Exception:
        return openai_chunk

# --- THE SMART PROXY (UNIVERSAL ADAPTER) ---
proxy_client = httpx.AsyncClient(timeout=120.0, follow_redirects=True)

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def smart_proxy(request: Request, path: str):
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

    # 2. Universal API Translation (Anthropic -> OpenAI)
    is_anthropic = path.endswith("/v1/messages")
    url = f"{BASE_URL}/openai/v1/chat/completions" if is_anthropic else f"{BASE_URL}/{path}"
    
    raw_body = await request.body()
    try:
        body_json = json.loads(raw_body) if raw_body else {}
    except:
        body_json = {}

    is_stream = body_json.get("stream", False)

    if is_anthropic:
        body_json = translate_anthropic_to_openai(body_json)
        body = json.dumps(body_json).encode('utf-8')
    else:
        body = raw_body

    # Header Preservation for Vision and WAF Bypass:
    clean_headers = {
        "User-Agent": "curl/8.5.0",
        "Accept": "*/*"
    }
    
    # Forward critical headers (including Vision support)
    for k, v in request.headers.items():
        k_lower = k.lower()
        if k_lower.startswith("x-") or k_lower in ["accept-encoding", "content-length", "content-type", "accept"]:
            if is_anthropic and k_lower == "content-length":
                continue
            clean_headers[k] = v

    if is_anthropic:
        clean_headers["Content-Length"] = str(len(body))
        clean_headers["Content-Type"] = "application/json"

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
                    
                    # Handle specific error codes: drain and shift to wait loop
                    if response.status_code in (401, 402, 403):
                        add_log(f"Key {current_active_key[:10]} failed with {response.status_code}. Draining and shifting to Wait Loop...")
                        await response.aread()
                        await response.aclose()
                        db.update_balance(current_active_key, 0.0)
                        current_active_key = None
                        continue

                    # For 400 (Vision/Payload errors) or 429 (Rate Limits), pass through and STOP
                    if response.status_code in (400, 429):
                        add_log(f"Upstream returned {response.status_code}. Passing through to client.")
                        if not is_stream and is_anthropic:
                            full_resp = b""
                            async for chunk in response.aiter_bytes():
                                full_resp += chunk
                            yield translate_openai_to_anthropic_non_stream(full_resp)
                        else:
                            async for chunk in response.aiter_bytes():
                                yield translate_openai_to_anthropic_stream(chunk) if is_anthropic else chunk
                        await response.aclose()
                        return

                    if response.status_code >= 500:
                        add_log(f"Upstream error {response.status_code}. Retrying...")
                        await response.aread()
                        await response.aclose()
                        current_active_key = None
                        await asyncio.sleep(2)
                        continue
                    
                    # Stream the actual response natively (handling translation if needed)
                    try:
                        if not is_stream and is_anthropic:
                            full_resp = b""
                            async for chunk in response.aiter_bytes():
                                full_resp += chunk
                            yield translate_openai_to_anthropic_non_stream(full_resp)
                        else:
                            async for chunk in response.aiter_bytes():
                                yield translate_openai_to_anthropic_stream(chunk) if is_anthropic else chunk
                    finally:
                        await response.aclose()
                    return # Successfully streamed

                except Exception as e:
                    logger.error(f"Proxy attempt failed: {e}")
                    current_active_key = None
                    await asyncio.sleep(2)
                    continue

    # Determine media type: strictly respect the client's request
    media_type = "text/event-stream" if is_stream else "application/json"

    return StreamingResponse(generate_with_keepalive(), status_code=200, media_type=media_type)

