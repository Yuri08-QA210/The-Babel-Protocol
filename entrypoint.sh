#!/bin/bash
# ============================================================
# QA CTF Challenge — Entrypoint Script
# ============================================================
# Compiles WAT to WASM, initializes database, and starts services
# ============================================================

set -e

echo "╔══════════════════════════════════════════════════╗"
echo "║          QA CTF Challenge — Deployment           ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ----------------------------------------------------------
# 1. Check for .env
# ----------------------------------------------------------
if [ ! -f .env ]; then
    echo "[!] ERROR: .env file not found!"
    echo "    Create one from the specification and try again."
    exit 1
fi

echo "[✓] Found .env configuration file"

# ----------------------------------------------------------
# 2. Load environment variables
# ----------------------------------------------------------
set -a
source .env
set +a

echo "[✓] Environment variables loaded"

# Validate critical env vars
for var in STAGE1_FLAG STAGE2_FLAG FINAL_FLAG SECRET_KEY_PART1 SECRET_KEY_PART2 INTERNAL_TOKEN; do
    if [ -z "${!var}" ]; then
        echo "[!] ERROR: Required environment variable $var is not set!"
        exit 1
    fi
done
echo "[✓] All required environment variables are set"

# ----------------------------------------------------------
# 3. Build Docker images
# ----------------------------------------------------------
echo ""
echo "[*] Building Docker images (this may take a moment)..."
docker-compose build 2>&1 | tail -5
echo "[✓] Docker images built"

# ----------------------------------------------------------
# 4. Start services
# ----------------------------------------------------------
echo ""
echo "[*] Starting services..."
docker-compose up -d
echo "[✓] Services started"

# ----------------------------------------------------------
# 5. Wait for services to be healthy
# ----------------------------------------------------------
echo ""
echo "[*] Waiting for services to become healthy..."

MAX_WAIT=120
ELAPSED=0
INTERVAL=5

while [ $ELAPSED -lt $MAX_WAIT ]; do
    # Check if all services are running
    UNHEALTHY=$(docker-compose ps --format json 2>/dev/null | \
        python3 -c "
import sys, json
unhealthy = []
for line in sys.stdin:
    try:
        svc = json.loads(line)
        health = svc.get('Health', svc.get('Status', ''))
        name = svc.get('Service', svc.get('Name', 'unknown'))
        if 'unhealthy' in health.lower() or 'starting' in health.lower():
            unhealthy.append(name)
    except: pass
print(' '.join(unhealthy))
" 2>/dev/null || echo "")

    if [ -z "$UNHEALTHY" ]; then
        break
    fi

    echo "    Waiting... ($ELAPSED/$MAX_WAIT seconds) — still starting: $UNHEALTHY"
    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo "[!] WARNING: Some services may not be fully healthy yet."
    echo "    Check with: docker-compose ps"
else
    echo "[✓] All services are healthy"
fi

# ----------------------------------------------------------
# 6. Print deployment info
# ----------------------------------------------------------
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║          QA CTF Challenge — Running!             ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "  Stage 1 (Wasm + XXE + SSRF):"
echo "    → http://localhost/api/parse"
echo "    → http://localhost/api/search"
echo ""
echo "  Stage 2 (SSTI + RCE):"
echo "    → http://localhost/portal/"
echo "    → http://localhost/portal/login"
echo ""
echo "  Stage 3 (Smuggling + Race Condition):"
echo "    → http://localhost/api/vault/"
echo "    → http://localhost/admin/vault"
echo ""
echo "  Rabbit Holes (all return generic responses):"
echo "    → /admin/ /debug/ /console/ /graphql"
echo "    → /wp-admin/ /phpmyadmin/ /monitoring/ /grafana"
echo "    → /jenkins/ /ci/ /git/ /svn/ /backup/"
echo "    → /api/v1/ /api/v2/ /api/internal/"
echo "    → /internal/ /private/ /secret/"
echo "    → /test/ /dev/ /staging/ /demo/"
echo "    → /docs/ /api-docs/ /swagger/"
echo "    → /.env /.git/ /server-status"
echo ""
echo "  Hints:"
echo "    - Reverse the Wasm module to find valid XML tags"
echo "    - The Wasm source is at: stage1-wasm-xxe/xml_validator.wat"
echo "    - Check response headers for hidden clues"
echo "    - Not all endpoints are what they seem..."
echo "    - The WAF blocks some headers, but not all paths"
echo ""
echo "  Flag format: QA{...}"
echo ""
echo "  Service status:"
docker-compose ps 2>/dev/null || true
echo ""
