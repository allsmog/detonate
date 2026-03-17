.PHONY: dev api frontend services services-down migrate migration test-api lint format setup ollama-pull sandbox-build suricata-build mitre-pull

# Start all dev services and both API + frontend
dev: services
	@echo "Starting API and frontend..."
	$(MAKE) api &
	$(MAKE) frontend &
	wait

# Start FastAPI dev server
api:
	cd api && uv run uvicorn detonate.main:app --host 0.0.0.0 --port 8000 --reload

# Start Next.js dev server
frontend:
	cd frontend && pnpm dev

# Start Docker Compose dev services
services:
	docker compose -f docker-compose.dev.yml up -d
	@echo "Waiting for services to be healthy..."
	@docker compose -f docker-compose.dev.yml ps

# Stop Docker Compose dev services
services-down:
	docker compose -f docker-compose.dev.yml down

# Run Alembic migrations
migrate:
	cd api && uv run alembic upgrade head

# Create a new Alembic migration (usage: make migration msg="description")
migration:
	cd api && uv run alembic revision --autogenerate -m "$(msg)"

# Run API tests
test-api:
	cd api && uv run pytest -v

# Lint all code
lint:
	cd api && uv run ruff check .
	cd frontend && pnpm lint

# Format all code
format:
	cd api && uv run ruff format .
	cd frontend && pnpm format

# Pull Ollama model
ollama-pull:
	docker compose -f docker-compose.dev.yml exec ollama ollama pull qwen2.5:3b

# Build sandbox Docker image
sandbox-build:
	docker build -t detonate-sandbox-linux -f sandbox/linux/Dockerfile sandbox/

# Build Suricata IDS Docker image
suricata-build:
	docker build -t detonate-suricata sandbox/suricata/

# Download MITRE ATT&CK STIX data
mitre-pull:
	mkdir -p sandbox/mitre
	curl -L -o sandbox/mitre/enterprise-attack.json \
		"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
	@echo "Downloaded MITRE ATT&CK data to sandbox/mitre/enterprise-attack.json"

# Initial setup
setup:
	cp -n .env.example .env || true
	cd api && uv sync
	cd frontend && pnpm install
	$(MAKE) services
	@echo "Waiting for PostgreSQL to be ready..."
	@sleep 3
	$(MAKE) migrate
	@echo "Setup complete! Run 'make dev' to start."
