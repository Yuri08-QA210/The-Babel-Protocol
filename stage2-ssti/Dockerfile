FROM python:3.11-slim

LABEL maintainer="QA CTF Team"
LABEL description="Stage 2: Secret Key + SSTI"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data directory
RUN mkdir -p /var/lib/qa-challenge

EXPOSE 5001

CMD ["python", "app.py"]
