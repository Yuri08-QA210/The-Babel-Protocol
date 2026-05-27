#!/bin/bash
# ============================================================
# QA CTF Challenge — Single Container Start Script
# ============================================================
# Starts all services via supervisord.
# Environment variables can be set via:
#   1. Render.com Environment dashboard
#   2. .env file (if present)
#   3. Defaults below
# ============================================================

set -e

echo "=== Babel Protocol — Starting ==="

# ============================================================
# Load .env file if present (for local docker-compose)
# ============================================================
if [ -f /app/.env ]; then
    echo "[*] Loading .env file..."
    set -a
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^#.*$ ]] && continue
        [[ -z "$key" ]] && continue
        value="${value%\"}"
        value="${value#\"}"
        export "$key=$value"
    done < /app/.env
    set +a
    echo "[*] .env loaded"
else
    echo "[*] No .env file found — using environment variables / defaults"
fi

# ============================================================
# Set defaults for ALL required env vars
# These are used if not already set (e.g., via Render dashboard)
# ============================================================
export STAGE1_FLAG="${STAGE1_FLAG:-QA{w4sm_r3v3rs1ng_xxe_00b_ssrf_ch41n}}"
export STAGE2_FLAG="${STAGE2_FLAG:-QA{sst1_f0rg3d_s3ss10n_rc3_ch41n_byp4ss}}"
export FINAL_FLAG="${FINAL_FLAG:-QA{smuggl1ng_r4c3_c0nd1t10n_ful1_syst3m_t4k30v3r}}"
export SECRET_KEY_PART1="${SECRET_KEY_PART1:-qa-s3cr3t-k3y-p4rt1-}"
export SECRET_KEY_PART2="${SECRET_KEY_PART2:-p4rt2-fr0m-d4t4b4s3!}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-sup3r_s3cur3_4dm1n!}"
export INTERNAL_TOKEN="${INTERNAL_TOKEN:-qa-internal-smuggle-token-2024-xk9}"
export GRANT_SEED="${GRANT_SEED:-xk9z-seed-2024}"
export INTERNAL_SERVICE_HOST="${INTERNAL_SERVICE_HOST:-127.0.0.1}"
export INTERNAL_SERVICE_PORT="${INTERNAL_SERVICE_PORT:-8888}"
export RACE_WINDOW_MS="${RACE_WINDOW_MS:-3}"
export FLAG_MEMORY_TTL_MS="${FLAG_MEMORY_TTL_MS:-300}"
export SESSION_LIFETIME_MINUTES="${SESSION_LIFETIME_MINUTES:-15}"
export DB_PATH="${DB_PATH:-/var/lib/qa-challenge/challenge.db}"
export FLASK_SECRET_KEY="${FLASK_SECRET_KEY:-${SECRET_KEY_PART1}${SECRET_KEY_PART2}}"

echo "[*] Environment variables loaded"

# ============================================================
# Compile WAT → WASM if not already done
# ============================================================
if [ ! -f /app/stage1-wasm-xxe/xml_validator.wasm ]; then
    echo "[*] Compiling WAT → WASM..."
    if command -v wat2wasm &> /dev/null; then
        wat2wasm /app/stage1-wasm-xxe/xml_validator.wat \
            -o /app/stage1-wasm-xxe/xml_validator.wasm 2>/dev/null && \
            echo "[+] WASM compiled successfully" || \
            echo "[!] WAT compilation failed — Wasm validation will be unavailable"
    else
        echo "[!] wat2wasm not found — Wasm validation will be unavailable"
    fi
else
    echo "[*] WASM already compiled"
fi

# ============================================================
# Create required directories
# ============================================================
mkdir -p /var/lib/qa-challenge
mkdir -p /var/log/supervisor
mkdir -p /var/log/nginx
mkdir -p /var/run

# ============================================================
# Initialize database (run stage2 init_db by importing it)
# ============================================================
echo "[*] Initializing database..."
python3 -c "
import sys
sys.path.insert(0, '/app/stage2-ssti')
import os
os.environ['SECRET_KEY_PART1'] = '$SECRET_KEY_PART1'
os.environ['SECRET_KEY_PART2'] = '$SECRET_KEY_PART2'
os.environ['STAGE2_FLAG'] = '$STAGE2_FLAG'
os.environ['DB_PATH'] = '$DB_PATH'
os.environ['ADMIN_PASSWORD'] = '$ADMIN_PASSWORD'
os.environ['SESSION_LIFETIME_MINUTES'] = '$SESSION_LIFETIME_MINUTES'
os.environ['INTERNAL_TOKEN'] = '$INTERNAL_TOKEN'
os.environ['GRANT_SEED'] = '$GRANT_SEED'
# Import app to trigger init_db()
from app import app, init_db
with app.app_context():
    init_db()
print('[+] Database initialized')
" 2>&1 || echo "[!] Database init failed (may already exist)"

# ============================================================
# Wait for backend services to be ready
# ============================================================
echo "[*] Starting supervisord..."
echo ""
echo "=== Babel Protocol Running ==="
echo ""
echo "  API Endpoint:    /api/parse"
echo "  User Portal:     /portal/"
echo "  Infrastructure:  /api/vault/"
echo ""

# ============================================================
# Start supervisord (manages all processes)
# ============================================================
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
