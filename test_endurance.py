import time
import requests
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8086/v1",
    api_key="mock-key", # Will bypass proxy auth because we inject it directly or we mock it. Wait, the proxy validates keys via SQLite.
    timeout=120.0
)

# Insert a mock key into SQLite so proxy allows it
import sqlite3
with sqlite3.connect("proxy_data.db") as conn:
    conn.execute("INSERT OR REPLACE INTO client_keys (key, name, is_active) VALUES ('mock-key', 'Mock Client', 1)")
    conn.execute("INSERT OR REPLACE INTO keys (key, balance) VALUES ('upstream-mock-1', 0.05)")

print("=== STARTING FAST DRAIN ===")
for i in range(3):
    print(f"Drain Request {i+1}...")
    try:
        response = client.chat.completions.create(
            model="qwen-large",
            messages=[{"role": "user", "content": "Generate huge code payload..."}]
        )
        print("Success!")
    except Exception as e:
        print(f"Drain hit error (Expected if balance 0): {e}")

print("\n=== STARTING ENDURANCE TEST ===")
print("Balance is now 0.00. Proxy will enter whitespace yield loop.")
print("Waiting for upstream reset (approx 45s)...")
start = time.time()
try:
    response = client.chat.completions.create(
        model="claude-fast",
        messages=[{"role": "user", "content": "Test whitespace compatibility"}]
    )
    print(f"\n✅ ENDURANCE TEST SUCCESS in {time.time() - start:.2f}s!")
    print(f"Response Content: {response.choices[0].message.content}")
except Exception as e:
    print(f"\n❌ ENDURANCE TEST FAILED after {time.time() - start:.2f}s!")
    print(f"Error Type: {type(e).__name__}")
    print(f"Error Message: {e}")
