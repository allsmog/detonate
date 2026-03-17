#!/bin/bash
set -e

echo "==> Installing system dependencies..."
sudo apt-get update && sudo apt-get install -y libmagic1

echo "==> Installing uv..."
pip install uv

echo "==> Installing API dependencies..."
cd api && uv sync && cd ..

echo "==> Installing frontend dependencies..."
cd frontend && pnpm install && cd ..

echo "==> Starting dev services..."
docker compose -f docker-compose.dev.yml up -d

echo "==> Waiting for PostgreSQL..."
sleep 5

echo "==> Running database migrations..."
cd api && uv run alembic upgrade head && cd ..

echo "==> Creating MinIO bucket..."
until curl -sf http://localhost:9000/minio/health/live; do
  echo "Waiting for MinIO..."
  sleep 2
done

echo "==> Post-create setup complete!"
