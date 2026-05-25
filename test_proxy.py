import requests
import json

PROXY_URL = "http://localhost:8000/openai/v1/chat/completions"

def test_chat_completion():
    print(f"Testing proxy at: {PROXY_URL}")
    
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "Say hello!"}
        ],
        "stream": False
    }
    
    try:
        # We don't need a real API key here because the proxy overrides it
        headers = {"Authorization": "Bearer dummy-key", "Content-Type": "application/json"}
        response = requests.post(PROXY_URL, json=payload, headers=headers)
        
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            print("Response Data:")
            print(json.dumps(response.json(), indent=2))
        else:
            print("Error Response:")
            print(response.text)
            
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    test_chat_completion()
