# SETUP — Standing Up Your Lab

This curriculum uses two things: the **Detonate sandbox** (for submitting and
detonating samples) and a small **local RE toolchain** (for hands-on
disassembly/debugging labs). You don't need everything on day one — each module
lists exactly what it requires.

> Read [SAFETY.md](SAFETY.md) first. Setup decisions (especially networking) are
> safety decisions.

---

## 1. Detonate sandbox

From the repository root:

```bash
# Start infrastructure (PostgreSQL, Redis, MinIO, Ollama)
make services

# Install dependencies, run DB migrations
make setup

# Build the Linux sandbox image used to detonate samples
make sandbox-build

# (optional) pull the local AI model for AI-assisted analysis
make ollama-pull

# Start API + frontend
make dev
```

Then open:
- Frontend: http://localhost:3000
- API docs: http://localhost:8000/docs

Dynamic-analysis labs also need a Celery worker running (it does the actual
detonation). In a second terminal:

```bash
cd api
PYTHONPATH="$(pwd)/..:$(pwd)" uv run celery -A worker.app:celery_app worker \
  -l info -Q dynamic,static,ai,enrichment -c 2
```

See the root [README](../README.md) for full platform details and environment
variables.

### Recommended sandbox settings for the labs

In your `.env` (copy from `.env.example`):

```bash
# Keep detonations offline unless a lab says otherwise (SAFETY §1)
# Use the network controls exposed at analysis-submission time;
# default to "none" / isolated network.

SCREENSHOTS_ENABLED=true     # helpful for dynamic labs
SURICATA_ENABLED=true        # network-behavior labs use Suricata alerts
```

---

## 2. Local RE toolchain

Install as labs call for them. Suggested baseline:

**Disassembly / decompilation**
- [Ghidra](https://ghidra-sre.org/) — free, excellent decompiler. Used as the
  default in solutions so everyone can follow along.
- [radare2](https://github.com/radareorg/radare2) / [Cutter](https://cutter.re/) — scriptable, great for quick triage.
- IDA Free / IDA Pro — referenced where relevant; not required.

**Debugging**
- Linux: `gdb` (with [pwndbg](https://github.com/pwndbg/pwndbg) or [GEF](https://github.com/hugsy/gef)).
- Windows (in your analysis VM): [x64dbg](https://x64dbg.com/).

**Static utilities**
- `file`, `strings`, `xxd`/`hexdump`, `binwalk`
- [`yara`](https://github.com/VirusTotal/yara) — write/test detection rules
- [`pefile`](https://github.com/erocarrera/pefile), [`lief`](https://lief.re/) — Python PE/ELF parsing (already used by Detonate's static analyzer)
- [`capa`](https://github.com/mandiant/capa) — capability detection
- [`die`/Detect It Easy](https://github.com/horsicq/Detect-It-Easy) — packer/compiler ID

**Scripting / emulation**
- Python 3.12+ (the repo uses `uv`)
- [Unicorn](https://www.unicorn-engine.org/) + [Capstone](https://www.capstone-engine.org/) for emulation/disassembly labs (Level 4+)

**Quick install (Debian/Ubuntu analysis VM):**

```bash
sudo apt update
sudo apt install -y file binutils binwalk yara gdb python3-pip xxd
pip install pefile lief capstone unicornafl flare-capa
# Ghidra: download from ghidra-sre.org and unzip (needs JDK 17+)
```

---

## 3. A safe place to keep samples

Create a working directory **outside** the git tree (or use the git-ignored
`samples/` path) inside your isolated lab:

```bash
mkdir -p ~/lab/samples
```

`.gitignore` is configured to keep sample binaries and a `samples/` directory
out of version control. Never commit live samples (SAFETY §4).

---

## 4. Verifying your lab works

Run the smoke test in [Module 3.1](03-dynamic-analysis/01-detonate-first-detonation/)
— it walks you through building the benign training binary, submitting it, and
confirming you can read the process tree, network, and file telemetry. If that
module's lab completes end to end, your lab is ready for the rest of the course.
