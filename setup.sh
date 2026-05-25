#!/bin/bash
set -e

# Update and install dependencies
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 nginx certbot python3-certbot-nginx sqlite3 git curl

# Stop Nginx to free port 80 for standalone certbot if needed, though --nginx plugin handles it.
systemctl stop nginx || true

# Generate dummy SSL if not exists
DOMAIN="ciel.sryze.cc"
if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos --register-unsafely-without-email || true
fi

# Configure Nginx
cat << 'EOF' > /etc/nginx/sites-available/cielproxy
server {
    listen 80;
    server_name ciel.sryze.cc;
    
    # Storage optimization: Disable access logs
    access_log off;
    error_log /var/log/nginx/error.log warn;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Disable buffering for streaming (SSE)
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 300s;
    }
}
EOF

ln -sf /etc/nginx/sites-available/cielproxy /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl start nginx
systemctl reload nginx

# Bring up docker stack
cd /root/pollinations-proxy
docker compose up -d --build

echo "Setup complete! Navigate to https://ciel.sryze.cc"
