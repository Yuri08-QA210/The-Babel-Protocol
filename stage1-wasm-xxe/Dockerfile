FROM python:3.11-slim

LABEL maintainer="QA CTF Team"
LABEL description="Stage 1: Wasm + XXE + SSRF"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install WABT for compiling WAT to WASM
RUN npm install -g wabt

WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Compile WAT to WASM
RUN wat2wasm xml_validator.wat -o xml_validator.wasm || \
    echo "WAT compilation will be done at runtime"

# Create data directory
RUN mkdir -p /var/lib/qa-challenge

EXPOSE 5000

CMD ["python", "app.py"]
