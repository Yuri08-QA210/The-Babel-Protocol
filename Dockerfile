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

LABEL maintainer="QA CTF Team"
LABEL description="QA CTF Challenge — Full Stack (Single Container)"

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
# NOTE: .env is NOT copied — it's not in git (it's in .gitignore)
# Environment variables are set via Render.com dashboard or start.sh defaults

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
