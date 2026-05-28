import re
import os

with open("app.py", "r") as f:
    code = f.read()

start_marker = "# --- THE SMART PROXY (STRICT FAILOVER) ---"
start_idx = code.find(start_marker)
if start_idx == -1:
    print("Marker not found")
    exit(1)

new_proxy_logic = """# --- THE SMART PROXY (STRICT FAILOVER WITH LITELLM) ---
import litellm
from litellm.llms.anthropic.experimental_pass_through.adapters.transformation import LiteLLMAnthropicMessagesAdapter

proxy_client = httpx.AsyncClient(timeout=120.0, follow_redirects=True)
anthropic_adapter = LiteLLMAnthropicMessagesAdapter()

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
        # We don't forward raw body size for anthropic since litellm handles it
        pass

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
                        if is_anthropic:
                            yield b'event: ping\\ndata: {"type": "ping"}\\n\\n'
                        else:
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
                if is_anthropic:
                    # NATIVE LITELLM ANTHROPIC -> OPENAI TRANSLATION
                    try:
                        add_log(f"Routing Anthropic request via LiteLLM using key {current_active_key[:10]}...")
                        
                        # Translate request args to OpenAI kwargs natively
                        openai_kwargs = anthropic_adapter.translate_anthropic_to_openai(body_json)
                        model_name = openai_kwargs.pop("model", "gpt-4o")
                        
                        response = await litellm.acompletion(
                            model=f"openai/{model_name}",
                            api_base=f"{BASE_URL}/openai/v1",
                            api_key=current_active_key,
                            stream=is_stream,
                            **openai_kwargs
                        )
                        
                        # In litellm.acompletion, a 401/402/429 raises an exception, we catch it below.
                        
                        if is_stream:
                            async for chunk in response:
                                # Translate OpenAI chunk to Anthropic chunk
                                anthropic_chunk = anthropic_adapter.translate_streaming_openai_response_to_anthropic(chunk)
                                if anthropic_chunk:
                                    yield f"data: {json.dumps(anthropic_chunk)}\\n\\n".encode("utf-8")
                            yield b"data: [DONE]\\n\\n"
                            return
                        else:
                            # Translate complete OpenAI response to Anthropic response
                            anthropic_resp = anthropic_adapter.translate_openai_response_to_anthropic(response)
                            yield json.dumps(anthropic_resp).encode("utf-8")
                            return

                    except litellm.exceptions.AuthenticationError as e:
                        add_log(f"Key {current_active_key[:10]} failed (LiteLLM 401). Draining and shifting to NEXT key...")
                        db.update_balance(current_active_key, 0.0)
                        current_active_key = None
                        continue
                    except litellm.exceptions.RateLimitError as e:
                        add_log(f"Upstream returned RateLimit/402/429. Passing through to client.")
                        # Check if it's a 402 from pollinations indicating low balance
                        if "402" in str(e) or "Insufficient" in str(e):
                            add_log(f"Key {current_active_key[:10]} reported 402 via LiteLLM. Draining and shifting...")
                            db.update_balance(current_active_key, 0.0)
                            current_active_key = None
                            continue
                        
                        # Otherwise pass it through
                        err_msg = json.dumps({"type": "error", "error": {"type": "rate_limit_error", "message": str(e)}})
                        if is_stream:
                            yield f"data: {err_msg}\\n\\n".encode('utf-8')
                        else:
                            yield err_msg.encode('utf-8')
                        return
                    except Exception as e:
                        logger.error(f"LiteLLM attempt failed: {e}")
                        current_active_key = None
                        await asyncio.sleep(2)
                        continue
                        
                else:
                    # NATIVE OPENAI PATH
                    clean_headers["Authorization"] = f"Bearer {current_active_key}"
                    try:
                        proxy_req = proxy_client.build_request(
                            method=request.method,
                            url=url,
                            headers=clean_headers,
                            content=raw_body,
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
                        
                        try:
                            async for chunk in response.aiter_bytes():
                                yield chunk
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

final_code = code[:start_idx] + new_proxy_logic

with open("app.py", "w") as f:
    f.write(final_code)
print("LiteLLM Patch applied.")
