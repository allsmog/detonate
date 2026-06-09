# Detonate Masterclass — Malware Reverse Engineering

> A hands-on, lab-driven curriculum that takes you from "I can read a hex dump"
> to "I extracted the C2 configuration from a packed, anti-analysis-aware
> sample and wrote a YARA rule to catch the family."

This is not a wall of theory. Every concept is paired with a **lab** you run
inside [Detonate](../README.md) — the open-source analysis sandbox that ships
with this repository. You submit real (and purpose-built) samples, watch them
execute, read the telemetry the platform captures, and answer concrete
questions. Solutions are provided, but you learn by doing first.

---

## Who this is for

The curriculum is built as a **single ramp with three on-ramps**, so it works
for all levels:

| You are… | Start at | What you'll skip |
|----------|----------|------------------|
| New to RE / security | [Level 1 — Foundations](01-foundations/) | Nothing — start here. |
| A developer or analyst with basic security knowledge | [Level 2 — Static Analysis](02-static-analysis/) | Assembly/PE primers (use as reference). |
| A working analyst or CTF player | [Level 4 — Unpacking](04-unpacking-deobfuscation/) onward | The fundamentals; treat earlier levels as a reference shelf. |

Every module states its **prerequisites** explicitly, so you can jump in and
backfill only what you're missing.

---

## ⚠️ Before you touch a sample: read [SAFETY.md](SAFETY.md)

You will handle live malicious code. There is a right way and a career-ending
way to do that. [SAFETY.md](SAFETY.md) covers lab isolation, legal and ethical
boundaries, where to *responsibly* source samples, and how this repo defangs
IOCs. **This is mandatory reading, not boilerplate.** Labs assume you have an
isolated environment per that document.

---

## How a module works

Every module follows the same shape (see [`_template/`](_template/)):

1. **Objectives** — what you'll be able to do afterward.
2. **Prerequisites** — modules/skills assumed.
3. **Theory** — the minimum concepts you need, no padding.
4. **Lab** — a guided exercise using Detonate and/or local tooling, with a
   specific sample and concrete tasks.
5. **Guided questions** — answer these *before* peeking; they're how you know
   you actually understood it.
6. **Solution** — a full walkthrough (annotated disassembly, extracted
   artifacts, the reasoning). Collapsed/separate so you don't spoil yourself.
7. **Going further** — optional challenges and references.

---

## The curriculum

### Level 1 — Foundations
*Goal: read a binary's structure and speak the language of the machine.*

| # | Module | You'll learn |
|---|--------|--------------|
| 1.1 | [PE & ELF anatomy](01-foundations/01-pe-anatomy/) | Headers, sections, imports/exports, entry point — and how Detonate's static parser reads them. ✅ **Fully built (flagship module)** |
| 1.2 | x86/x64 assembly survival kit | Registers, calling conventions, the stack, the instructions that actually matter for RE. |
| 1.3 | The RE toolchain | Disassemblers (Ghidra/IDA/radare2), debuggers (x64dbg/gdb), hex editors, and how they complement the sandbox. |
| 1.4 | File triage & hashing | Hashes, fuzzy hashing (ssdeep), MIME/type detection, first-look heuristics. Maps to Detonate's submission pipeline. |

### Level 2 — Static Analysis
*Goal: learn everything you can without running the sample.*

| # | Module | You'll learn |
|---|--------|--------------|
| 2.1 | Strings & embedded IOCs | ASCII/UTF-16 extraction, IOC categorization, what strings reveal and what they hide. |
| 2.2 | Imports as behavior | Reading the Import Address Table to predict capability (network, crypto, persistence). |
| 2.3 | Entropy & packing detection | Shannon entropy, per-section analysis, spotting packers before you unpack. |
| 2.4 | Writing YARA rules | From a sample to a robust detection rule; testing against Detonate's 26 built-in rules. |

### Level 3 — Dynamic Analysis
*Goal: detonate safely and read behavior from telemetry.*

| # | Module | You'll learn |
|---|--------|--------------|
| 3.1 | [Your first detonation](03-dynamic-analysis/01-detonate-first-detonation/) | Submit a Linux sample, read the process tree, syscalls, network, and file drops. ✅ **Fully built (flagship module)** |
| 3.2 | Process trees & syscall behavior | Interpreting `strace`/clone telemetry, parent-child relationships, injection patterns. |
| 3.3 | Network behavior & C2 | DNS, beaconing, HTTP host extraction, reading PCAP and Suricata alerts. |
| 3.4 | MITRE ATT&CK mapping | Translating raw behavior into techniques/tactics; how Detonate's 26 behavioral rules work. |

### Level 4 — Unpacking & Deobfuscation
*Goal: get to the real code hiding under layers.*

| # | Module | You'll learn |
|---|--------|--------------|
| 4.1 | UPX & common packers | Recognizing and unpacking; manual unpacking with a debugger. |
| 4.2 | Custom packers & unpacking stubs | Finding OEP, dumping, fixing the IAT. |
| 4.3 | String & API obfuscation | Stack strings, XOR/RC4 string decryption, API hashing/resolution. |
| 4.4 | Scripted deobfuscation | Automating decryption with Python; emulation with Unicorn. |

### Level 5 — Anti-Analysis
*Goal: defeat the tricks malware uses to detect and evade you.*

| # | Module | You'll learn |
|---|--------|--------------|
| 5.1 | Sandbox & VM detection | Timing, artifacts, CPUID, registry/MAC checks — and Detonate's anti-evasion posture. |
| 5.2 | Debugger detection & anti-debug | `IsDebuggerPresent`, PEB checks, timing, exception tricks, and patching them out. |
| 5.3 | Evasion in the wild | Sleep-skipping, environment keying, geofencing, and how to coax execution. |

### Level 6 — Configuration & IOC Extraction
*Goal: turn an analyzed sample into actionable intelligence.*

| # | Module | You'll learn |
|---|--------|--------------|
| 6.1 | Decrypting embedded config | Locating and decrypting C2/config blobs from a real family. |
| 6.2 | Building a config extractor | A reusable parser; integrating extraction into Detonate's pipeline. |
| 6.3 | From artifacts to intelligence | IOC export (STIX/CSV), correlation, and writing the threat report Detonate generates. |

### Level 7 — Capstone
*Goal: prove it.*

| # | Module | You'll do |
|---|--------|-----------|
| 7.1 | [Unknown sample challenge](07-capstone/) | Receive an unknown sample, run the full kill chain, and deliver a complete analyst report. Graded against a rubric. |

---

## Tracks (if you don't want to go linear)

- **Triage track** (analysts on a SOC clock): 1.4 → 2.1 → 2.2 → 3.1 → 3.3 → 6.3
- **Deep-RE track** (you want to read disassembly): 1.1 → 1.2 → 4.x → 5.x → 6.x
- **Detection-engineering track**: 2.x → 2.4 → 3.4 → 6.x

---

## Setup

See [SETUP.md](SETUP.md) to stand up the Detonate lab and install the local RE
toolchain the labs reference. The short version: `make services && make setup`
from the repo root gets the sandbox running; the modules tell you which extra
tools each lab needs.

---

## Contributing a module

This curriculum is meant to grow. Copy [`_template/`](_template/), follow the
seven-part shape, and read [../CONTRIBUTING.md](../CONTRIBUTING.md) for the
sample-sourcing and review rules. A module isn't "done" until it has a working
lab *and* a complete solution.
