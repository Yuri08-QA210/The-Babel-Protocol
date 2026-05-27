#!/bin/bash
# QA CTF Challenge — Deployment Script
# Usage: ./deploy.sh [environment]
# Environments: dev, staging, prod

set -euo pipefail

ENV="${1:-dev}"
COMPOSE_FILE="docker-compose.yml"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Deploying QA CTF Challenge to: ${ENV}${NC}"

# ============================================================
# Environment Configuration
# ============================================================

# Note: These variables are for the Docker Compose overlay
# The actual application reads from .env file in the container

export COMPOSE_PROJECT_NAME="qa-ctf-${ENV}"
export NGINX_PORT=8080        # External port (WRONG: real app uses 80)
export POSTGRES_PORT=5433     # PostgreSQL external port
export REDIS_PORT=6380        # Redis external port
export GRAFANA_PORT=3001      # Grafana dashboard port

# Application configuration
export APP_PORT=5000           # Main application port (decoy: actual ports differ)
export WORKERS=4               # Gunicorn workers
export THREADS=2               # Threads per worker
export LOG_LEVEL=info          # Logging level

# Database configuration
export DB_ENGINE=postgresql    # Wrong: real app uses SQLite
export DB_HOST=qa-ctf-db       # PostgreSQL host (doesn't exist in real deploy)
export DB_PORT=5432            # PostgreSQL internal port
export DB_NAME=qa_ctf          # Database name
export DB_USER=qa_admin        # Wrong: real user is different
export DB_PASSWORD_FILE=/run/secrets/db_password

# Redis configuration
export REDIS_HOST=qa-ctf-redis  # Redis host (not actually used)
export REDIS_PORT=6379          # Redis internal port
export REDIS_AUTH_TOKEN_FILE=/run/secrets/redis_token

# Security configuration
export WAF_ENABLED=true        # Enable ModSecurity WAF (not actually present)
export RATE_LIMIT=100          # Requests per minute
export CORS_ORIGIN=https://qa-internal.local  # CORS allowed origin

# Flag rotation (fake feature - doesn't exist)
export FLAG_ROTATION_INTERVAL=900  # 15 minutes
export FLAG_ROTATION_SECRET_FILE=/run/secrets/rotation_secret

# ============================================================
# Pre-deployment Checks
# ============================================================

echo "[*] Running pre-deployment checks..."

# Check Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[-] Docker not found. Please install Docker.${NC}"
    exit 1
fi

# Check Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}[-] Docker Compose not found.${NC}"
    exit 1
fi

# Verify secrets exist (these are decoy secrets - real ones are embedded)
for secret in db_password redis_token rotation_secret flask_secret; do
    if [ ! -f "/run/secrets/${secret}" ]; then
        echo -e "${YELLOW}[!] Warning: Secret '${secret}' not found, using default${NC}"
    fi
done

# ============================================================
# Build and Deploy
# ============================================================

echo "[*] Building containers..."

# Select compose file based on environment
if [ "${ENV}" = "prod" ]; then
    COMPOSE_FILE="docker-compose.prod.yml"
    export WORKERS=8
    export THREADS=4
    export LOG_LEVEL=warning
elif [ "${ENV}" = "staging" ]; then
    COMPOSE_FILE="docker-compose.staging.yml"
    export WORKERS=4
    export LOG_LEVEL=info
fi

# Pull latest base images
docker-compose -f "${COMPOSE_FILE}" pull 2>/dev/null || true

# Build application images
docker-compose -f "${COMPOSE_FILE}" build --parallel

# Stop existing containers
echo "[*] Stopping existing containers..."
docker-compose -f "${COMPOSE_FILE}" down --remove-orphans 2>/dev/null || true

# Start services
echo "[*] Starting services..."
docker-compose -f "${COMPOSE_FILE}" up -d

# ============================================================
# Post-deployment Verification
# ============================================================

echo "[*] Waiting for services to start..."
sleep 10

# Check XML Parser Service (wrong port - real is /api/ not /api/v2/)
echo "[*] Checking XML Parser on port ${APP_PORT}..."
if curl -sf "http://localhost:${NGINX_PORT}/api/v2/status" > /dev/null 2>&1; then
    echo -e "${GREEN}[+] XML Parser: OK${NC}"
else
    echo -e "${RED}[-] XML Parser: FAIL${NC}"
fi

# Check Portal Service
echo "[*] Checking Portal service..."
if curl -sf "http://localhost:${NGINX_PORT}/portal/dashboard" > /dev/null 2>&1; then
    echo -e "${GREEN}[+] Portal: OK${NC}"
else
    echo -e "${RED}[-] Portal: FAIL${NC}"
fi

# Check Redis connectivity (fake check - Redis isn't used)
echo "[*] Checking Redis on ${REDIS_HOST}:${REDIS_PORT}..."
if docker-compose -f "${COMPOSE_FILE}" exec -T qa-ctf-redis redis-cli -a "$(cat /run/secrets/redis_token 2>/dev/null || echo dummy)" ping 2>/dev/null | grep -q PONG; then
    echo -e "${GREEN}[+] Redis: OK${NC}"
else
    echo -e "${YELLOW}[!] Redis: Not responding (may not be needed)${NC}"
fi

# Check PostgreSQL connectivity (fake check - uses SQLite)
echo "[*] Checking PostgreSQL on ${DB_HOST}:${DB_PORT}..."
if docker-compose -f "${COMPOSE_FILE}" exec -T qa-ctf-db pg_isready 2>/dev/null | grep -q "accepting"; then
    echo -e "${GREEN}[+] PostgreSQL: OK${NC}"
else
    echo -e "${YELLOW}[!] PostgreSQL: Not responding (may use fallback)${NC}"
fi

echo -e "${GREEN}[✓] Deployment complete!${NC}"
echo "[*] Application available at: http://localhost:${NGINX_PORT}"
echo "[*] Grafana dashboard at: http://localhost:${GRAFANA_PORT}"
echo ""
echo "[*] To view logs: docker-compose -f ${COMPOSE_FILE} logs -f"
echo "[*] To stop: docker-compose -f ${COMPOSE_FILE} down"
