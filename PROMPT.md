# Detonate: Open-Source Malware Analysis Sandbox

## Context

**What**: An open-source alternative to [any.run](https://any.run) — an interactive malware analysis sandbox that lets users submit files/URLs, execute them in an isolated environment, and observe behavior in real-time.

**Why**: any.run is closed-source, expensive, and cloud-only. The best open-source alternatives (Cuckoo, CAPE) are aging, hard to deploy, and lack the real-time interactive experience. "Detonate" fills this gap with modern tech, Codespaces-ready development, and a hybrid Docker/QEMU sandboxing approach.

**Name**: `detonate`

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Frontend (Next.js 14)                                      │
│  Submit Form | Analysis List | Report | Interactive (noVNC) │
└───────────────────────────┬─────────────────────────────────┘
                            │ REST + WebSocket
┌───────────────────────────┴─────────────────────────────────┐
│  API (FastAPI)                                              │
│  /submit | /analysis/{id} | /report | /ws/telemetry | /ws/vnc│
└────┬──────────┬──────────┬──────────┬──────────┬────────────┘
     │          │          │          │          │
  Postgres    Redis     MinIO    Elasticsearch  Celery Workers
  (metadata)  (broker)  (artifacts) (reports)   (analysis)
                                                    │
                                          ┌─────────┴─────────┐
                                          │ Machinery Interface│
                                          │ (abstract)         │
                                          ├─────────┬──────────┤
                                          │ Docker  │ QEMU/KVM │
                                          │ (dev)   │ (prod)   │
                                          └────┬────┴─────┬────┘
                                               │          │
                                          Container    VM
                                          + Guest Agent
                                          + Host-side capture (tcpdump, Suricata)
```

---

## Component Breakdown

### Frontend — Next.js 14 (TypeScript, Tailwind, shadcn/ui)
- **Submit Form**: Upload files or enter URLs for analysis
- **Analysis List**: Dashboard of all submissions with status, verdict, tags
- **Report View**: Static + dynamic analysis results (process tree, network, files, registry, IOCs)
- **Interactive Sandbox**: Real-time VM desktop via noVNC — users can watch/interact with execution
- **Live Telemetry**: WebSocket-driven streaming of events as analysis runs

### API — FastAPI (Python 3.11+)
- REST endpoints for submission, analysis retrieval, reporting
- WebSocket endpoints for live telemetry streaming and VNC proxying
- Pydantic models for request/response validation
- Async throughout for WebSocket + concurrent analysis handling

### Task Queue — Celery + Redis
- Static analysis workers (hashing, YARA, strings, PE/ELF parsing)
- Dynamic analysis workers (sandbox orchestration)
- Worker routing by capability (e.g., only workers with QEMU can handle Windows tasks)

### Data Stores
| Store | Purpose |
|-------|---------|
| **PostgreSQL 16** | Submission metadata, analysis state, machine pool, user accounts. JSONB for flexible fields. Alembic migrations. |
| **Elasticsearch 8** | Full-text search over reports, IOC search, behavioral signature matching |
| **MinIO (S3-compatible)** | Binary samples, PCAPs, memory dumps, screenshots, dropped files |
| **Redis 7** | Celery broker, PubSub for real-time telemetry relay, caching |

### Sandbox Machinery — The Key Abstraction

Both Docker and QEMU backends implement the same abstract interface:

```python
class BaseMachinery(ABC):
    async def start(config) -> MachineInstance
    async def stop(instance)
    async def snapshot_restore(instance, snapshot)
    async def get_vnc_endpoint(instance) -> Optional[VNCEndpoint]
    async def network_capture_start(instance, output_path)
    async def network_capture_stop(instance) -> Path
    async def inject_file(instance, local_path, guest_path)
    def get_available_machines() -> list[MachineStatus]
```

**DockerMachinery** (dev/Codespaces):
- Lightweight Linux container sandboxing
- Docker SDK for Python
- Works inside Codespaces (Docker-in-Docker)
- Good for Linux binary/script analysis

**QEMUMachinery** (production):
- Full VM with QEMU/KVM + libvirt
- qcow2 snapshot restore for clean state
- VNC for interactive desktop
- Windows + Linux guest OS support
- Anti-evasion techniques (realistic hardware IDs, timing)
- Image build pipeline via Packer

### Guest Agent
- Lightweight agent running inside the sandbox (container or VM)
- Monitors: process creation/termination, file system changes, network connections, registry modifications (Windows)
- Linux: strace + inotify-based
- Windows: WMI/ETW process monitoring, registry tracking
- Streams events back to the host via HTTP/gRPC result server

### Host-Side Capture
- **tcpdump/dumpcap**: Raw PCAP of all sandbox network traffic
- **Suricata**: IDS signatures on captured traffic
- **YARA**: Scan dropped files and memory dumps

---

## Tech Stack

| Layer | Tech | Why |
|-------|------|-----|
| Frontend | Next.js 14, TypeScript, Tailwind, shadcn/ui | SSR for shared reports, streaming for live data |
| API | FastAPI, Python 3.11+ | Async WebSockets, Pydantic, Python malware ecosystem |
| Task Queue | Celery + Redis | Proven for long-running tasks, routing by worker type |
| Metadata DB | PostgreSQL 16 | Structured data, JSONB, Alembic migrations |
| Search | Elasticsearch 8 | Full-text IOC search, report storage |
| Artifacts | MinIO (S3-compatible) | Samples, PCAPs, memory dumps, screenshots |
| Sandbox (dev) | Docker + Docker SDK | Works in Codespaces, Linux binary analysis |
| Sandbox (prod) | QEMU/KVM + libvirt | Windows support, VNC, full OS emulation |
| IDS | Suricata | Network signature detection |
| File Signatures | YARA | Industry standard malware classification |
| Static Analysis | pefile, lief, oletools, ssdeep | Standard Python libraries |
| Interactive | noVNC + websockify | Browser-based VM desktop |

---

## Data Model (Core Tables)

```sql
-- Submissions
CREATE TABLE submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename TEXT,
    url TEXT,
    file_hash_sha256 TEXT NOT NULL,
    file_hash_md5 TEXT,
    file_hash_sha1 TEXT,
    file_hash_ssdeep TEXT,
    file_size BIGINT,
    file_type TEXT,
    mime_type TEXT,
    storage_path TEXT NOT NULL,       -- MinIO object key
    submitted_at TIMESTAMPTZ DEFAULT now(),
    submitted_by UUID REFERENCES users(id),
    tags TEXT[],
    verdict TEXT CHECK (verdict IN ('clean', 'suspicious', 'malicious', 'unknown')) DEFAULT 'unknown',
    score INTEGER DEFAULT 0           -- 0-100 threat score
);

-- Analyses (one submission can have multiple analysis runs)
CREATE TABLE analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID REFERENCES submissions(id),
    type TEXT CHECK (type IN ('static', 'dynamic')) NOT NULL,
    status TEXT CHECK (status IN ('queued', 'running', 'completed', 'failed', 'timeout')) DEFAULT 'queued',
    machine_id UUID REFERENCES machines(id),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,
    config JSONB DEFAULT '{}',        -- analysis options (timeout, network mode, etc.)
    result JSONB DEFAULT '{}',        -- analysis results summary
    report_es_id TEXT                 -- Elasticsearch document ID for full report
);

-- Machine pool
CREATE TABLE machines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT UNIQUE NOT NULL,
    machinery TEXT CHECK (machinery IN ('docker', 'qemu')) NOT NULL,
    platform TEXT CHECK (platform IN ('linux', 'windows')) NOT NULL,
    status TEXT CHECK (status IN ('available', 'running', 'maintenance', 'error')) DEFAULT 'available',
    ip_address INET,
    snapshot TEXT,                    -- snapshot name for restore
    config JSONB DEFAULT '{}'        -- machinery-specific config
);
```

---

## API Design

### REST Endpoints

```
POST   /api/v1/submit              # Submit file or URL
GET    /api/v1/submissions          # List submissions (paginated, filterable)
GET    /api/v1/submissions/{id}     # Get submission details
GET    /api/v1/analyses/{id}        # Get analysis details + results
GET    /api/v1/analyses/{id}/report # Get full report
GET    /api/v1/analyses/{id}/pcap   # Download PCAP
GET    /api/v1/analyses/{id}/files  # List dropped/modified files
GET    /api/v1/search               # Search IOCs, hashes, strings
POST   /api/v1/yara/scan           # Run YARA rule against sample
GET    /api/v1/yara/rules          # List YARA rules
POST   /api/v1/yara/rules          # Add YARA rule
GET    /api/v1/machines             # List machine pool status
GET    /api/v1/health               # Health check
```

### WebSocket Endpoints

```
WS     /api/v1/ws/telemetry/{analysis_id}  # Live process/network/file events
WS     /api/v1/ws/vnc/{analysis_id}        # noVNC proxy to sandbox desktop
```

---

## Repo Structure

```
detonate/
├── .github/
│   ├── workflows/ci.yml
│   ├── ISSUE_TEMPLATE/bug_report.yml
│   ├── ISSUE_TEMPLATE/feature_request.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── .devcontainer/
│   ├── devcontainer.json          # Codespaces config
│   ├── docker-compose.dev.yml     # Dev services (Postgres, Redis, MinIO, ES)
│   ├── Dockerfile.dev             # Dev container image
│   └── post-create.sh             # Setup on Codespace creation
├── frontend/                      # Next.js 14 (TypeScript, Tailwind, shadcn/ui)
│   ├── src/
│   │   ├── app/                   # App router pages
│   │   ├── components/            # React components
│   │   ├── lib/                   # API client, utils
│   │   └── hooks/                 # Custom hooks (useWebSocket, useTelemetry)
│   ├── package.json
│   └── tsconfig.json
├── api/                           # FastAPI (Python 3.11+)
│   ├── detonate/
│   │   ├── api/                   # Route handlers
│   │   ├── models/                # SQLAlchemy models
│   │   ├── schemas/               # Pydantic schemas
│   │   ├── services/              # Business logic
│   │   ├── machinery/             # Sandbox backends
│   │   │   ├── base.py            # BaseMachinery ABC
│   │   │   ├── docker.py          # DockerMachinery
│   │   │   └── qemu.py            # QEMUMachinery
│   │   ├── analysis/              # Analysis modules
│   │   │   ├── static/            # Static analysis (YARA, PE, strings)
│   │   │   └── dynamic/           # Dynamic analysis orchestration
│   │   └── config.py
│   ├── alembic/                   # Database migrations
│   ├── pyproject.toml
│   └── tests/
├── worker/                        # Celery workers
│   ├── tasks/
│   │   ├── static.py              # Static analysis tasks
│   │   └── dynamic.py             # Dynamic analysis tasks
│   └── celeryconfig.py
├── agent/                         # Guest agent (runs inside sandbox)
│   ├── linux/                     # Linux agent (strace/inotify)
│   └── windows/                   # Windows agent (WMI/ETW)
├── sandbox-images/                # Sandbox image definitions
│   ├── docker/
│   │   └── linux-sandbox/
│   │       └── Dockerfile
│   └── qemu/
│       └── scripts/               # Packer templates, setup scripts
├── docker-compose.yml             # Production stack
├── docker-compose.dev.yml         # Dev stack
├── Makefile
├── .env.example
├── .gitignore
├── PROMPT.md                      # This file
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
└── CODE_OF_CONDUCT.md
```

---

## Devcontainer Spec

```json
{
  "name": "Detonate Dev",
  "dockerComposeFile": "docker-compose.dev.yml",
  "service": "app",
  "workspaceFolder": "/workspace",
  "features": {
    "ghcr.io/devcontainers/features/python:1": { "version": "3.11" },
    "ghcr.io/devcontainers/features/node:1": { "version": "20" },
    "ghcr.io/devcontainers/features/docker-in-docker:2": {},
    "ghcr.io/devcontainers/features/github-cli:1": {}
  },
  "forwardPorts": [3000, 8000, 5432, 6379, 9000, 9200],
  "postCreateCommand": ".devcontainer/post-create.sh",
  "customizations": {
    "vscode": {
      "extensions": [
        "ms-python.python",
        "ms-python.vscode-pylance",
        "bradlc.vscode-tailwindcss",
        "dbaeumer.vscode-eslint"
      ]
    }
  }
}
```

Dev services (docker-compose.dev.yml):
- `postgres:16` — task metadata
- `redis:7` — Celery broker + PubSub for live telemetry
- `minio` — S3-compatible artifact storage
- `elasticsearch:8` — report storage + IOC search

---

## Core Pipeline

```
Submit → Store sample in MinIO → Create DB record → Queue static analysis
       → Queue dynamic analysis:
           1. Allocate machine from pool
           2. Start container/VM (snapshot restore)
           3. Inject sample + start guest agent
           4. Start host-side network capture
           5. Agent executes sample, streams events → Redis PubSub → WebSocket → UI
           6. Timeout or user-initiated completion
           7. Stop capture, collect artifacts
           8. Destroy container/VM
           9. Post-processing: Suricata on PCAP, YARA on dropped files,
              behavioral signatures, MITRE ATT&CK mapping
           10. Generate report → Elasticsearch
```

---

## Phased Roadmap

### Phase 0: Foundation
- Repo + Codespace + CI + devcontainer
- FastAPI skeleton with `/submit` and `/analysis/{id}`
- Next.js skeleton with file upload form + analysis list
- PostgreSQL models (Submission, Analysis, Machine)
- MinIO integration for file storage
- **Result**: Upload a file, see it in the list. No analysis yet.

### Phase 1: Static Analysis
- Celery workers: hashing, file type detection, string extraction, YARA scan, PE/ELF parsing
- YARA rule management API + community rule seeding
- Report page with static analysis results
- **Result**: Submit malware, get a static analysis report.

### Phase 2: Dynamic Analysis (Docker)
- DockerMachinery implementation
- Linux guest agent (strace/inotify-based monitoring)
- Result server + Redis PubSub telemetry pipeline
- Host-side PCAP capture + Suricata processing
- WebSocket live event streaming
- Process tree, network, file changes in the UI
- **Result**: Submit a Linux binary, watch it execute live, get full dynamic report.

### Phase 3: QEMU/KVM + Interactive Sandbox
- QEMUMachinery with libvirt, qcow2 snapshots, anti-evasion
- Windows guest agent (WMI/ETW process monitoring, registry tracking)
- noVNC integration for live VM desktop in browser
- VM image build pipeline (Packer)
- Network routing options (none/internet/tor/inetsim)
- **Result**: Interactive Windows malware analysis in the browser.

### Phase 4: Intelligence + Production
- Full-text IOC search across all analyses
- YARA retrohunt
- Malware config extraction framework
- Report export (HTML, JSON, MISP, STIX)
- Multi-user auth + API keys
- Monitoring (Prometheus), structured logging
- **Result**: Production-deployable platform.

---

## Key Architectural Decisions

1. **Hybrid sandboxing over single approach**: Docker for dev/Codespaces (instant setup, Linux analysis), QEMU/KVM for production (Windows support, VNC, anti-evasion). The `BaseMachinery` abstraction makes this seamless.

2. **Python backend over Go/Node**: The malware analysis ecosystem is Python-native (YARA, pefile, oletools, Volatility, lief). Fighting this would mean FFI wrappers everywhere.

3. **Celery over custom queue**: Proven at scale for long-running tasks, supports worker routing (send Windows tasks only to workers with QEMU), has result backends, and integrates with Redis we already need.

4. **Elasticsearch over Postgres for reports**: Reports are large, semi-structured documents that need full-text search. ES excels here. Postgres stays for structured metadata.

5. **MinIO over filesystem**: S3-compatible API means production can use real S3/GCS. Dev uses MinIO with zero code changes. Also handles large binary storage better than a database.

6. **noVNC for interactive sessions**: Browser-native, no client installs. websockify bridges WebSocket to VNC. The API proxies this through `/ws/vnc/{id}` so the frontend never talks directly to VMs.

7. **Guest agent architecture**: Minimal agent inside sandbox streams events out via HTTP. Host orchestrator controls lifecycle. This mirrors Cuckoo/CAPE's proven design but modernized with async Python and structured event streaming.

8. **Monorepo structure**: Frontend, API, workers, and agent all in one repo. Simplifies CI, Codespace setup, and cross-component changes. Can split later if needed.
