#!/bin/bash
# Start LiteLLM proxy in the background
echo "Starting LiteLLM Sidecar Proxy..."
litellm --port 4000 --api_base https://gen.pollinations.ai/openai/v1 --drop_params > litellm.log 2>&1 &

# Start the main FastAPI proxy
echo "Starting Main Ciel Proxy..."
exec uvicorn app:app --host 0.0.0.0 --port 8000
