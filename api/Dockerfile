FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy API dependency files
COPY api/pyproject.toml api/uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy API code
COPY api/detonate/ detonate/
COPY api/alembic/ alembic/
COPY api/alembic.ini .

# Copy worker code (needed for Celery task dispatch from API)
COPY worker/ worker/

ENV PYTHONPATH="/app"

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "detonate.main:app", "--host", "0.0.0.0", "--port", "8000"]
