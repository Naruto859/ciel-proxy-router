import os

with open("app.py", "r") as f:
    app_code = f.read()

app_code = app_code.replace('BASE_URL = "https://gen.pollinations.ai"', 'BASE_URL = "http://127.0.0.1:8084"')

old_loop = """                wait_counter = 0
                while not current_active_key:
                    # Every 15s yield a keep-alive ping
                    yield b": keep-alive - waiting for balance recovery\\n\\n"
                    state["sent_keepalive"] = True
                    await asyncio.sleep(15)
                    wait_counter += 1"""

new_loop = """                wait_counter = 0
                while not current_active_key:
                    if is_stream:
                        yield b":\\n\\n"
                        state["sent_keepalive"] = True
                    else:
                        yield b" "
                    await asyncio.sleep(15)
                    wait_counter += 1"""

app_code = app_code.replace(old_loop, new_loop)

old_media = """    # If we are starting with NO keys, we MUST use SSE for the waiting keep-alive pings
    no_keys = (await key_manager.get_best_key()) is None
    media_type = "text/event-stream" if (is_stream or no_keys) else "application/json"

    return StreamingResponse(generate_with_keepalive(), status_code=200, media_type=media_type)"""

new_media = """    media_type = "text/event-stream" if is_stream else "application/json"
    return StreamingResponse(generate_with_keepalive(), status_code=200, media_type=media_type)"""

app_code = app_code.replace(old_media, new_media)

with open("app_sandbox.py", "w") as f:
    f.write(app_code)

print("Sandbox patched successfully!")