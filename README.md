# Ciel Proxy Router ☤ - Multi-Agent Gateway

An elite, production-grade API Proxy for parallel AI Agents (Hermes). It provides a secure gateway to upstream inference providers (Pollinations AI) while managing custom Client Keys and transparently handling WAF bypasses and API key rotation.

## 🚀 Architecture

1. **Client Authentication:** Agents (e.g. Hermes) authenticate with this gateway using securely generated Client API Keys (`ciel_sk_...`). Invalid keys are instantly rejected (HTTP 401).
2. **The "Clean Room" WAF Bypass:** Agents often bleed identifying headers (like `x-stainless-*`). Ciel Proxy completely isolates the upstream request, constructing a safe, pristine header profile (`User-Agent: curl/8.5.0`) to silently bypass edge WAFs (like Fireworks AI/Cloudflare).
3. **Smart Upstream Rotation:** Upstream keys are pooled. The proxy catches rate limits (429) or WAF blocks (403) and seamlessly rotates to the next available upstream key, without breaking the streaming client connection. (404 errors are intelligently passed through).

## 🔒 Security

- **Liquid Glass Dashboard:** Protected by a persistent Admin Password (Default: `Samirandas123@`). Change this via the UI.
- **Client Key Management:** Issue specific keys for specific agents and instantly revoke them if compromised.
- **Zero-Storage Logging:** Local Docker and Nginx logs are heavily truncated and disabled to prevent disk exhaustion on low-storage VPS nodes.

## ⚡ Deployment & Disaster Recovery

Deploying a complete clone of this environment on a fresh Ubuntu server is a single-command operation:

```bash
git clone https://github.com/Naruto859/ciel-proxy-router.git
cd ciel-proxy-router
bash setup.sh
```

*(Note: Ensure your domain resolves to the new VPS IP before running setup to allow Let's Encrypt to provision certificates successfully).*