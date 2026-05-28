import time
import subprocess
import os

print("=== STARTING REAL-WORLD ENDURANCE TEST ===")

# Point OpenAI SDK (used by Hermes) to our sandbox Nginx port
os.environ["OPENAI_BASE_URL"] = "http://127.0.0.1:8087/v1"
os.environ["OPENAI_API_KEY"] = "mock-key"  # Handled by proxy client_keys

print("Initiating Hermes rapid drain via massive token generation...")

# Run Hermes command that forces massive generation and tool calling
# We'll use a python script that uses Hermes agent programmatically, or just use the SDK directly to mimic Hermes
# To strictly use Hermes, we call the CLI.
try:
    # This will drain the 0.15 balance and then hang, waiting for the 1-hour reset
    print("Hermes agent launched. Waiting for exhaustion and 1-hour upstream reset...")
    
    # We pipe stdout and stderr to a log file so it runs in background
    cmd = "/usr/local/bin/hermes chat -q 'Write a 10,000 word comprehensive guide on quantum physics, generating extensive code snippets and complex tool analysis. Keep generating until instructed otherwise.' > hermes_endurance.log 2>&1"
    
    subprocess.run(cmd, shell=True, check=True)
    
    print("Hermes task completed successfully after recovery!")
    with open("endurance_success.txt", "w") as f:
        f.write("SUCCESS: Hermes survived the 0-balance loop and completed the payload.")
except Exception as e:
    print(f"Error during Hermes execution: {e}")
    with open("endurance_error.txt", "w") as f:
        f.write(f"FAILED: {e}")

