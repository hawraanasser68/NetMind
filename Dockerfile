FROM python:3.11-slim

# Copy uv binary from the official uv image (faster than pip)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# System libraries required by psycopg2 (PostgreSQL C driver)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer cached unless requirements.txt changes)
COPY requirements.txt .
RUN uv pip install --system --no-cache -r requirements.txt

# Pre-download the ONNX embedding model at build time (~23MB, no GPU packages)
RUN python -c "from fastembed import TextEmbedding; list(TextEmbedding('sentence-transformers/all-MiniLM-L6-v2').embed(['warmup']))"

# Copy source code
COPY src/ ./src/
COPY config/ ./config/
COPY models/ ./models/
COPY eval_thresholds.yaml .

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
