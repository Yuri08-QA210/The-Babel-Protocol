FROM python:3.11-slim

LABEL maintainer="QA CTF Team"
LABEL description="Stage 3: Smuggling + Race Condition"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data directory
RUN mkdir -p /var/lib/qa-challenge

EXPOSE 5002

CMD ["python", "app.py"]
