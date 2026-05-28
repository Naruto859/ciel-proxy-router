import re
import json

with open("app.py", "r") as f:
    code = f.read()

start_marker = "# --- THE SMART PROXY (STRICT FAILOVER) ---"
start_idx = code.find(start_marker)
if start_idx == -1:
    print("Could not find start marker")
    exit(1)

new_code = """# --- TRANSLATION LAYER (Anthropic <-> OpenAI) ---
import json

def translate_anthropic_to_openai(body_json: dict) -> dict:
    openai_body = {}
    if "model" in body_json: openai_body["model"] = body_json["model"]
    if "max_tokens" in body_json: openai_body["max_tokens"] = body_json["max_tokens"]
    if "temperature" in body_json: openai_body["temperature"] = body_json["temperature"]
    openai_body["stream"] = body_json.get("stream", False)

    messages = []
    if "system" in body_json:
        sys_val = body_json["system"]
        if isinstance(sys_val, list):
            sys_text = "\\n".join([b.get("text", "") for b in sys_val if b.get("type") == "text"])
        else:
            sys_text = str(sys_val)
        messages.append({"role": "system", "content": sys_text})

    for msg in body_json.get("messages", []):
        role = msg.get("role")
        content = msg.get("content")
        if isinstance(content, str):
            messages.append({"role": role, "content": content})
        elif isinstance(content, list):
            o_msg = {"role": role, "content": ""}
            tool_calls = []
            for b in content:
                b_type = b.get("type")
                if b_type == "text":
                    o_msg["content"] += b.get("text", "")
                elif b_type == "tool_use":
                    tool_calls.append({
                        "id": b.get("id"),
                        "type": "function",
                        "function": {
                            "name": b.get("name"),
                            "arguments": json.dumps(b.get("input", {}), ensure_ascii=False)
                        }
                    })
                elif b_type == "tool_result":
                    content_str = b.get("content", "")
                    if isinstance(content_str, list):
                        content_str = json.dumps(content_str, ensure_ascii=False)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": b.get("tool_use_id"),
                        "content": str(content_str)
                    })
            if tool_calls:
                o_msg["tool_calls"] = tool_calls
            if o_msg["content"] or o_msg.get("tool_calls"):
                messages.append(o_msg)

    openai_body["messages"] = messages

    if "tools" in body_json:
        openai_body["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": t.get("name"),
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {})
                }
            } for t in body_json["tools"]
        ]
    return openai_body

def translate_openai_to_anthropic_non_stream(openai_bytes: bytes) -> bytes:
    try:
        data = json.loads(openai_bytes.decode('utf-8'))
        anthropic_resp = {
            "id": data.get("id", "msg_mock"),
            "type": "message",
            "role": "assistant",
            "model": data.get("model", "gpt-4"),
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {
                "input_tokens": data.get("usage", {}).get("prompt_tokens", 0),
                "output_tokens": data.get("usage", {}).get("completion_tokens", 0)
            },
            "content": []
        }
        choices = data.get("choices", [])
        if choices:
            msg = choices[0].get("message", {})
            finish_reason = choices[0].get("finish_reason")
            if finish_reason == "tool_calls":
                anthropic_resp["stop_reason"] = "tool_use"
            
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

def translate_openai_to_anthropic_stream(line: str) -> str:
    try:
        if line.strip() == "data: [DONE]":
            stop_event = json.dumps({"type": "message_stop"})
            return f"data: {stop_event}\\n\\ndata: [DONE]"
        
        payload = line[6:]
        data = json.loads(payload)
        choices = data.get("choices", [])
        if not choices:
            return ""
        
        delta = choices[0].get("delta", {})
        finish_reason = choices[0].get("finish_reason")
        
        events = []
        
        if "content" in delta and delta["content"]:
            events.append({
                "type": "content_block_delta",
                "index": 0,
                "delta": {
                    "type": "text_delta",
                    "text": delta["content"]
                }
            })
        
        if "tool_calls" in delta:
            tc = delta["tool_calls"][0]
            tc_index = tc.get("index", 0) + 1
            if "id" in tc:
                events.append({
                    "type": "content_block_start",
                    "index": tc_index,
                    "content_block": {
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["function"]["name"],
                        "input": {}
                    }
                })
            if "function" in tc and "arguments" in tc["function"]:
                events.append({
                    "type": "content_block_delta",
                    "index": tc_index,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": tc["function"]["arguments"]
                    }
                })
        
        if finish_reason:
            stop_reason = "tool_use" if finish_reason == "tool_calls" else "end_turn"
            events.append({
                "type": "message_delta",
                "delta": {"stop_reason": stop_reason, "stop_sequence": None},
                "usage": {"output_tokens": 0}
            })
        
        if events:
            return "\\n\\n".join([f"data: {json.dumps(e, ensure_ascii=False)}" for e in events])
        return ""
    except Exception:
        return line

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
        body = json.dumps(body_json, ensure_ascii=False).encode('utf-8')
    else:
        body = raw_body

    clean_headers = {
        "User-Agent": "curl/8.5.0",
        "Accept": "*/*"
    }
    
    for k, v in request.headers.items():
        k_lower = k.lower()
        if k_lower.startswith("x-") or k_lower in ["accept-encoding", "content-length", "content-type", "accept"]:
            if is_anthropic and k_lower == "content-length":
                continue
            clean_headers[k] = v

    if is_anthropic:
        clean_headers["Content-Length"] = str(len(body))
        clean_headers["Content-Type"] = "application/json"

    async def generate_with_keepalive():
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
                        yield b":\\n\\n"
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
                    
                    if response.status_code in (401, 402, 403):
                        add_log(f"Key {current_active_key[:10]} failed with {response.status_code}. Draining and shifting to NEXT key...")
                        await response.aread()
                        await response.aclose()
                        db.update_balance(current_active_key, 0.0)
                        current_active_key = None
                        continue

                    if response.status_code in (400, 429):
                        add_log(f"Upstream returned {response.status_code}. Passing through to client.")
                        if not is_stream:
                            full_resp = await response.aread()
                            if is_anthropic:
                                yield translate_openai_to_anthropic_non_stream(full_resp)
                            else:
                                yield full_resp
                        else:
                            async for line in response.aiter_lines():
                                if is_anthropic:
                                    if line.startswith("data: "):
                                        translated = translate_openai_to_anthropic_stream(line)
                                        if translated:
                                            yield translated.encode('utf-8') + b"\\n\\n"
                                else:
                                    yield (line + "\\n").encode('utf-8')
                        await response.aclose()
                        return

                    if response.status_code >= 500:
                        add_log(f"Upstream error {response.status_code}. Retrying...")
                        await response.aread()
                        await response.aclose()
                        current_active_key = None
                        await asyncio.sleep(2)
                        continue
                    
                    try:
                        if not is_stream:
                            full_resp = await response.aread()
                            if is_anthropic:
                                yield translate_openai_to_anthropic_non_stream(full_resp)
                            else:
                                yield full_resp
                        else:
                            async for line in response.aiter_lines():
                                if is_anthropic:
                                    if line.startswith("data: "):
                                        translated = translate_openai_to_anthropic_stream(line)
                                        if translated:
                                            yield translated.encode('utf-8') + b"\\n\\n"
                                else:
                                    yield (line + "\\n").encode('utf-8')
                    finally:
                        await response.aclose()
                    return

                except Exception as e:
                    logger.error(f"Proxy attempt failed: {e}")
                    current_active_key = None
                    await asyncio.sleep(2)
                    continue

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
"""

final_code = code[:start_idx] + new_code
with open("app.py", "w") as f:
    f.write(final_code)
