import requests
import time

# Point to your domain or local port for testing
URL = "http://localhost:8000/v1/chat/completions"

def test_silent_failover():
    print("🚀 Starting Silent Failover Verification...")
    
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Ping!"}],
        "stream": False
    }
    
    # We send a request. Even if the first key is bad, 
    # the proxy should catch it and return 200 from a second key.
    start_time = time.time()
    try:
        response = requests.post(URL, json=payload, headers={"Authorization": "Bearer test"})
        duration = time.time() - start_time
        
        print(f"Status Code: {response.status_code}")
        print(f"Time Taken: {duration:.2f}s")
        
        if response.status_code == 200:
            print("✅ SUCCESS: The proxy successfully returned a valid response.")
            print("If you had a failing key, it was handled silently!")
        else:
            print(f"❌ FAILED: Received {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"❌ CRITICAL ERROR: {e}")

if __name__ == "__main__":
    test_silent_failover()
