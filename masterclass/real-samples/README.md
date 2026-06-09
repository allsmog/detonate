# Real Samples — From Training Binaries to the Real Thing

The core curriculum uses purpose-built **benign** training binaries: safe,
reproducible, and perfect for learning mechanics. But eventually you need to
prove the skills on **real malware**. This directory is the bridge — a safe,
honest framework for practicing on authentic samples you source yourself.

> **Mandatory:** read [../SAFETY.md](../SAFETY.md). Real samples are live code.
> Isolation, legality, and handling are not optional.

## What's here

- **[CATALOG.md](CATALOG.md)** — curated commodity families mapped to the skills
  they exercise, with MalwareBazaar tag links. You fetch a current sample by
  family tag and record its SHA-256.
- **[verify_sample.py](verify_sample.py)** — pin + triage. Confirms your file is
  the exact documented sample (by SHA-256) before you invest time, and prints
  first-look triage (hashes, type, entropy). Refuses to "verify" on a mismatch.

This repo **never** ships live binaries (see [../SAFETY.md §4](../SAFETY.md)).

## Why not just commit some malware and hashes?

Two reasons, both honest:
1. **Safety/legality** — committing live malware to a public git repo is exactly
   what SAFETY.md forbids.
2. **Bit-rot** — hardcoded sample hashes go stale as availability rotates.
   Choosing a *current* sample by family tag is how real analysts work, and
   `verify_sample.py` keeps your analysis pinned to the exact bytes you chose.

## Quick start

```bash
# 1. Pick a family in CATALOG.md, fetch one sample from MalwareBazaar (in your lab),
#    record its SHA-256.
# 2. Pin + triage it:
python3 verify_sample.py ./sample.bin --sha256 <the hash you recorded>
#    -> "✓ MATCH" means you're analyzing the right bytes. Proceed.
# 3. Run the matching masterclass workflow (CATALOG.md has a per-sample template).
# 4. Write the report (use the Level 7 capstone rubric), THEN compare to a public
#    writeup of the family.
```

## How this completes the course

| Phase | Samples | Goal |
|-------|---------|------|
| Levels 1–7 | benign training binaries | learn mechanics safely, reproducibly |
| Capstone Path A | self-contained `crackmalware` | full kill chain, graded, reproducible |
| **Real samples (here)** | **authentic, self-sourced** | **prove it on the real thing** |

When your reports on real, unseen samples hold up against the public record,
you've genuinely completed the masterclass.
