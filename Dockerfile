# ============================================================
# QA CTF Challenge — Single Container Dockerfile (Render.com)
# ============================================================
# Runs ALL services in one container via supervisord:
#   - nginx (port 80)
#   - stage1-app (port 5000)
#   - stage2-app (port 5001)
#   - stage3-app (port 5002)
#   - internal-service (port 8888)
# ============================================================

FROM python:3.11-slim

LABEL maintainer="Babel Protocol Team"
LABEL description="Babel Protocol — Enterprise Data Processing Platform"

# ============================================================
# Install system dependencies
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    nodejs \
    npm \
    supervisor \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install WABT for WAT→WASM compilation
RUN npm install -g wabt

# ============================================================
# Install Python dependencies
# ============================================================
WORKDIR /app

# Copy all requirements and install
COPY stage1-wasm-xxe/requirements.txt /tmp/req1.txt
COPY stage2-ssti/requirements.txt /tmp/req2.txt
COPY stage3-smuggling/requirements.txt /tmp/req3.txt
COPY internal-service/requirements.txt /tmp/req4.txt

RUN pip install --no-cache-dir \
    flask==3.0.0 \
    lxml==5.1.0 \
    itsdangerous==2.1.2 \
    werkzeug==3.0.1

# ============================================================
# Copy application code
# ============================================================
COPY stage1-wasm-xxe/ /app/stage1-wasm-xxe/
COPY stage2-ssti/ /app/stage2-ssti/
COPY stage3-smuggling/ /app/stage3-smuggling/
COPY internal-service/ /app/internal-service/
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY start.sh /app/start.sh

# ============================================================
# Set default environment variables (can be overridden via Render dashboard)
# The .env file is NOT in git (.gitignore), so we embed defaults here.
# start.sh also has fallback defaults, but ENV ensures they're available
# during Docker build and runtime.
# ============================================================
ENV STAGE1_FLAG="QA{w4sm_r3v3rs1ng_xxe_00b_ssrf_ch41n}" \
    STAGE2_FLAG="QA{sst1_f0rg3d_s3ss10n_rc3_ch41n_byp4ss}" \
    FINAL_FLAG="QA{smuggl1ng_r4c3_c0nd1t10n_ful1_syst3m_t4k30v3r}" \
    SECRET_KEY_PART1="qa-s3cr3t-k3y-p4rt1-" \
    SECRET_KEY_PART2="p4rt2-fr0m-d4t4b4s3!" \
    ADMIN_PASSWORD="sup3r_s3cur3_4dm1n!" \
    INTERNAL_TOKEN="qa-internal-smuggle-token-2024-xk9" \
    GRANT_SEED="xk9z-seed-2024" \
    INTERNAL_SERVICE_HOST="127.0.0.1" \
    INTERNAL_SERVICE_PORT="8888" \
    RACE_WINDOW_MS="3" \
    FLAG_MEMORY_TTL_MS="300" \
    SESSION_LIFETIME_MINUTES="15" \
    DB_PATH="/var/lib/qa-challenge/challenge.db" \
    FLASK_SECRET_KEY=""

# ============================================================
# Compile WAT → WASM
# ============================================================
RUN wat2wasm /app/stage1-wasm-xxe/xml_validator.wat \
    -o /app/stage1-wasm-xxe/xml_validator.wasm || \
    echo "WAT compilation failed — will retry at runtime"

# ============================================================
# Create required directories
# ============================================================
RUN mkdir -p /var/lib/qa-challenge \
    && mkdir -p /var/log/supervisor \
    && mkdir -p /var/log/nginx \
    && mkdir -p /var/run \
    && chmod +x /app/start.sh

# ============================================================
# Remove default nginx config that might conflict
# ============================================================
RUN rm -f /etc/nginx/sites-enabled/default

# ============================================================
# Expose port 80 (nginx)
# ============================================================
EXPOSE 80

# ============================================================
# Health check
# ============================================================
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost/api/health || exit 1

# ============================================================
# Start all services via supervisord
# ============================================================
CMD ["/app/start.sh"]
