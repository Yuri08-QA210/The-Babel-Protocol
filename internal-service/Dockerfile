FROM python:3.11-slim

LABEL maintainer="QA CTF Team"
LABEL description="Internal Service (SSRF Target)"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Do NOT expose port externally — only accessible via internal Docker network
CMD ["python", "app.py"]
