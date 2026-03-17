# Detonate

**Open-source malware analysis sandbox.**

Submit files or URLs, execute them in an isolated Docker/QEMU sandbox, and observe behavior in real-time: process trees, network traffic, file drops, MITRE ATT&CK mapping, AI-powered analysis, and more.

```
                      +------------------+
                      |   Next.js 16     |
                      |   Frontend       |
                      +--------+---------+
                               |
                      +--------+---------+
                      |   FastAPI API    |  75 endpoints
                      |   (async)        |  12 DB tables
                      +--+----+----+--+--+
                         |    |    |  |
                  +------+ +--+--+ | ++-------+
                  |Postgres|Redis | |MinIO    |Ollama
                  |  16    | 7   | |(S3)     |(LLM)
                  +--------+-----+ +---------++------+
                                |
                      +---------+---------+
                      |  Celery Workers   |
                      +--------+----------+
                               |
                    +----------+----------+
                    |  Sandbox Machinery   |
                    +-----+----------+----+
                    |Docker|          |QEMU|
                    |Linux |          |Win |
                    +------+          +----+
```

## Features

### Submission & Static Analysis
- File upload with automatic hashing (SHA256/MD5/SHA1), type detection, MIME identification
- URL submission -- fetches content and creates submission automatically
- PE parsing (imports, exports, sections, resources, digital signatures, suspicious indicators)
- ELF header parsing (class, type, machine, entry point)
- String extraction (ASCII + UTF-16LE) with IOC categorization (URLs, IPs, emails, registry keys, file paths)
- Shannon entropy analysis (overall + per-section)
- YARA scanning with 26 built-in rules (suspicious strings, packers, malware indicators)

### Dynamic Analysis (Sandbox)
- Docker-based Linux sandbox (Ubuntu 22.04 + strace + tcpdump + YARA)
- Process tree with parent-child tracking via strace clone/clone3 syscalls
- Network capture (PCAP) with DNS, TCP/UDP connections, HTTP host extraction
- Filesystem monitoring (created/modified/deleted files via fs diff)
- Real-time WebSocket telemetry streaming
- Suricata IDS alerts on captured PCAP
- Optional screenshots (Xvfb + scrot) and video recording (ffmpeg)
- Interactive VNC sessions via websockify
- Windows sandbox infrastructure (QEMU/KVM + Sysmon guest agent)
- Configurable timeout, network isolation, machine pooling

### MITRE ATT&CK Mapping
- 26 behavioral rules mapping syscall patterns to ATT&CK techniques
- Optional LLM-enhanced classification for higher coverage
- Tactic coverage matrix and confidence scoring
- Technique catalog browsing and search

### Threat Intelligence
- **VirusTotal** -- file hash, IP, domain reputation
- **AbuseIPDB** -- IP abuse confidence scoring
- **AlienVault OTX** -- multi-indicator pulse intelligence
- **URLhaus** -- malicious URL/payload database (no API key needed)
- **MalwareBazaar** -- malware sample intelligence (no API key needed)
- Redis-backed caching (1h TTL) and per-provider rate limiting

### AI Integration
- Provider-agnostic: **Ollama** (local/dev) or **Anthropic Claude** (production)
- Automated behavioral summarization
- Threat classification with verdict/score/confidence
- Autonomous agent analysis with tool use
- Interactive chat with full analysis context
- AI-powered comprehensive threat reports
- IOC-based similar submission correlation

### IOC Export
- Automated extraction of IPs, domains, URLs, hashes, file paths from analysis results
- **STIX 2.1** bundle export
- **CSV** export with type/value/context columns
- **JSON** structured export

### Reporting
- AI-generated markdown threat reports
- Self-contained HTML reports (no external dependencies)
- CSV IOC reports
- Per-submission downloadable reports

### Search & Dashboard
- Full-text search across hashes, filenames, tags
- Advanced filters: verdict, file type, tag, score range, date range, analysis status
- Sortable results with pagination
- Analytics dashboard: submission stats, verdict breakdown, timeline, top file types, top tags, top IOCs

### Auth & Collaboration
- JWT authentication + API key support
- User registration, login, profile management
- Team/organization management with role-based membership
- Submission comments with edit/delete
- Auto-tagging (16 behavioral rules + file type detection)
- Webhook notifications with HMAC-SHA256 signing

### Management
- YARA rule management (upload, validate, edit, delete via API)
- Machine pool management (scale up/down, health checks)
- Feature flags and configuration status endpoint
- Celery task monitoring

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.12+ with [uv](https://docs.astral.sh/uv/)
- Node.js 20+ with [pnpm](https://pnpm.io/)

### Setup

```bash
# Clone
git clone https://github.com/allsmog/detonate.git
cd detonate

# Start infrastructure (PostgreSQL, Redis, MinIO, Ollama)
make services

# Install dependencies, run migrations
make setup

# Pull the AI model
make ollama-pull

# Build the sandbox Docker image
make sandbox-build

# Start API + frontend
make dev
```

The app will be available at:
- **Frontend**: http://localhost:3000
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

### Running the Celery Worker

Dynamic analysis requires a Celery worker:

```bash
cd api
PYTHONPATH="$(pwd)/..:$(pwd)" uv run celery -A worker.app:celery_app worker \
  -l info -Q dynamic,static,ai,enrichment -c 2
```

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Required
POSTGRES_PASSWORD=detonate
REDIS_URL=redis://127.0.0.1:6379/0

# AI (pick one)
LLM_PROVIDER=ollama              # or "anthropic"
ANTHROPIC_API_KEY=sk-ant-...     # if using Anthropic

# Threat Intelligence (optional, all free tier)
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
OTX_API_KEY=...

# Auth (optional)
AUTH_ENABLED=false
JWT_SECRET_KEY=change-me-in-production

# Features (optional)
SCREENSHOTS_ENABLED=false
SURICATA_ENABLED=false
SANDBOX_POOL_ENABLED=false
```

## Architecture

| Component | Tech | Purpose |
|-----------|------|---------|
| **API** | FastAPI (Python 3.12) | 75 REST endpoints, WebSocket telemetry, SSE streaming |
| **Frontend** | Next.js 16, React 19, Tailwind 4, shadcn/ui v4 | SPA with real-time updates |
| **Database** | PostgreSQL 16, SQLAlchemy 2.0 async, Alembic | 12 tables, JSONB for results |
| **Storage** | MinIO (S3-compatible) | Samples, PCAPs, screenshots, videos |
| **Cache/Broker** | Redis 7 | Celery broker, threat intel cache, rate limiting, pub/sub |
| **Workers** | Celery | Dynamic analysis, AI tasks, threat intel enrichment |
| **AI** | Ollama / Anthropic Claude | Summarization, classification, chat, reports |
| **Linux Sandbox** | Docker (Ubuntu 22.04) | strace, tcpdump, YARA, Xvfb, scrot, ffmpeg, x11vnc |
| **Windows Sandbox** | QEMU/KVM + libvirt | Sysmon monitoring, HTTP guest agent |
| **IDS** | Suricata | Offline PCAP analysis with ET Open rules |

## API Overview

```
POST   /api/v1/submit                           File upload
POST   /api/v1/submit-url                       URL submission
GET    /api/v1/submissions                      List submissions
GET    /api/v1/submissions/{id}                 Get submission
GET    /api/v1/submissions/{id}/static          Static analysis (PE/ELF/strings/entropy)
POST   /api/v1/submissions/{id}/analyze         Start dynamic analysis
GET    /api/v1/submissions/{id}/analyses/{id}   Get analysis results
POST   /api/v1/submissions/{id}/analyses/{id}/mitre   MITRE ATT&CK mapping
GET    /api/v1/submissions/{id}/threat-intel    Threat intel enrichment
GET    /api/v1/submissions/{id}/iocs            Extract IOCs
GET    /api/v1/submissions/{id}/iocs/stix       STIX 2.1 export
POST   /api/v1/submissions/{id}/ai/summarize    AI summarization
POST   /api/v1/submissions/{id}/ai/report       AI threat report
GET    /api/v1/search?q=...&verdict=...         Advanced search
GET    /api/v1/dashboard/stats                  Analytics dashboard
POST   /api/v1/auth/register                    User registration
POST   /api/v1/auth/login                       JWT login
...and 60+ more endpoints
```

Full OpenAPI docs available at `/docs` when running.

## Development

```bash
make api          # Start FastAPI dev server (port 8000)
make frontend     # Start Next.js dev server (port 3000)
make services     # Start Docker infrastructure
make migrate      # Run Alembic migrations
make migration msg="description"  # Create new migration
make test-api     # Run pytest
make lint         # Ruff + ESLint
make format       # Ruff format + Prettier
make sandbox-build   # Build Linux sandbox image
make suricata-build  # Build Suricata IDS image
make mitre-pull      # Download MITRE ATT&CK dataset
make ollama-pull     # Pull Ollama AI model
```

## License

MIT
