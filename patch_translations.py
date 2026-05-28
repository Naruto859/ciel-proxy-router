import re
import json

with open("app.py", "r") as f:
    code = f.read()

start_marker = "# --- TRANSLATION LAYER (Anthropic -> OpenAI) ---"
end_marker = "# --- THE SMART PROXY (UNIVERSAL ADAPTER) ---"

start_idx = code.find(start_marker)
end_idx = code.find(end_marker)

new_translation_layer = """# --- TRANSLATION LAYER (Anthropic -> OpenAI) ---
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
            messages.append({"role": "system", "content": "\\n".join(text_parts)})
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
                return f"data: {json.dumps(anthropic_event)}\\n\\n".encode('utf-8')
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
                    return f"data: {json.dumps(event)}\\n\\n".encode('utf-8')
                elif "function" in tc and "arguments" in tc["function"]:
                    event = {
                        "type": "content_block_delta",
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": tc["function"]["arguments"]
                        }
                    }
                    return f"data: {json.dumps(event)}\\n\\n".encode('utf-8')
        return openai_chunk
    except Exception:
        return openai_chunk

"""

new_code = code[:start_idx] + new_translation_layer + code[end_idx:]

target_yield_logic = """                    # Stream the actual response natively (no wrappers)
                    try:
                        async for chunk in response.aiter_bytes():
                            yield translate_openai_to_anthropic(chunk) if is_anthropic else chunk
                    finally:
                        await response.aclose()
                    return # Successfully streamed"""

new_yield_logic = """                    # Stream the actual response natively (handling translation if needed)
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
                    return # Successfully streamed"""

new_code = new_code.replace(target_yield_logic, new_yield_logic)

target_err_logic = """                    # For 400 (Vision/Payload errors) or 429 (Rate Limits), pass through and STOP
                    if response.status_code in (400, 429):
                        add_log(f"Upstream returned {response.status_code}. Passing through to client.")
                        async for chunk in response.aiter_bytes():
                            yield translate_openai_to_anthropic(chunk) if is_anthropic else chunk
                        await response.aclose()
                        return"""

new_err_logic = """                    # For 400 (Vision/Payload errors) or 429 (Rate Limits), pass through and STOP
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
                        return"""
new_code = new_code.replace(target_err_logic, new_err_logic)

with open("app.py", "w") as f:
    f.write(new_code)
