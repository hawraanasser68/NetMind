FROM python:3.11-slim

# Copy uv binary from the official uv image (faster than pip)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# System libraries required by psycopg2 (PostgreSQL C driver)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer cached unless requirements.txt changes)
COPY requirements.txt .
RUN uv pip install --system --no-cache -r requirements.txt

# Pre-download the embedding model at build time (not at runtime)
# Saves ~90MB download on every container start
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# Copy source code
COPY src/ ./src/
COPY config/ ./config/
COPY models/ ./models/
COPY eval_thresholds.yaml .

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
