import asyncio
from fastapi import FastAPI
from fastapi.responses import JSONResponse, StreamingResponse

app = FastAPI()

balance = 0.03

@app.get("/account/balance")
async def get_balance():
    return JSONResponse({"balance": balance})

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def chat(path: str = ""):
    global balance
    if balance > 0:
        balance -= 0.015
        if balance < 0: balance = 0.0
        async def stream():
            yield b'{"id": "chatcmpl-mock", "object": "chat.completion", "created": 123456, "model": "qwen-large", "choices": [{"index": 0, "message": {"role": "assistant", "content": "Fast Drain Mode: Success! Tokens generated."}, "finish_reason": "stop"}]}'
        return StreamingResponse(stream(), media_type="application/json")
    else:
        return JSONResponse({"error": "Insufficient balance"}, status_code=402)

async def reset_balance():
    await asyncio.sleep(45) # Wait 45 seconds to simulate hourly reset
    global balance
    balance = 5.0
    print("MOCK UPSTREAM: Hourly reset triggered! Balance is now 5.0")

@app.on_event("startup")
async def startup():
    asyncio.create_task(reset_balance())