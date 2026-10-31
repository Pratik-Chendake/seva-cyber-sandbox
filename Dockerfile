# syntax=docker/dockerfile:1
FROM python:3.11-slim

WORKDIR /app

# Install security certificates & build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY src/ ./src/
COPY data/ ./data/
COPY models/ ./models/
COPY migrations/ ./migrations/
COPY api_server.py .
COPY run_all.py .

# Create unprivileged application user
RUN useradd -m -u 1001 sevauser && \
    mkdir -p instance/storage instance/backups && \
    chown -R sevauser:sevauser /app

USER sevauser

ENV PORT=8000 \
    PYTHONUNBUFFERED=1 \
    SEVA_OPERATOR_AUTH_ENABLED=true

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/system/health || exit 1

CMD ["sh", "-c", "uvicorn api_server:app --host 0.0.0.0 --port ${PORT}"]
