# Real-Sample Practice Catalog

The synthetic training binaries teach mechanics safely and reproducibly. This
catalog points you at **real, well-documented commodity malware** so you can
practice the same skills on the genuine article — once you're comfortable and
working in a proper isolated lab.

> **Read [../SAFETY.md](../SAFETY.md) first.** Everything here assumes the
> isolation, legal, and handling rules in that document. You fetch samples
> **yourself**, into **your** lab; this repo ships no live binaries.

## How to use this catalog

1. Pick a family below appropriate to the skill you're drilling.
2. Fetch a sample **yourself** from [MalwareBazaar](https://bazaar.abuse.ch/)
   by its **tag/signature** (the URLs below). Pick one recent sample and **record
   its SHA-256.**
3. **Pin it:** run `verify_sample.py <file> --sha256 <the hash you recorded>` so
   every later step (and any public writeup you compare against) refers to the
   exact same bytes.
4. Keep it zipped (`infected`) until it's inside your isolated lab.
5. Run the relevant masterclass workflow on it. Then compare your findings to a
   public analysis of *that family* — **after** you finish, never before.

Why "pick your own hash" instead of hardcoded ones? Live sample availability
rotates, and committing specific hashes would bit-rot. Choosing a current sample
by family tag is how real analysts work, and `verify_sample.py` keeps you honest
about which bytes you analyzed.

## Families by skill

| Family | MalwareBazaar tag | Drills (masterclass) | Why it's a good teacher |
|--------|-------------------|----------------------|--------------------------|
| **AgentTesla** | [`AgentTesla`](https://bazaar.abuse.ch/browse/tag/AgentTesla/) | Static + config extraction (L2, L6) | Prolific .NET stealer; config (SMTP/FTP/Telegram exfil) is well-documented to check your extraction against. |
| **FormBook / XLoader** | [`Formbook`](https://bazaar.abuse.ch/browse/tag/Formbook/) | Unpacking + anti-analysis (L4, L5) | Heavy obfuscation and anti-analysis — a real test of Level 4–5 skills. |
| **RedLine Stealer** | [`RedLineStealer`](https://bazaar.abuse.ch/browse/tag/RedLineStealer/) | Config + IOC extraction (L6) | .NET; C2 config extraction is a classic exercise. |
| **njRAT** | [`njrat`](https://bazaar.abuse.ch/browse/tag/njrat/) | Dynamic + network/C2 (L3) | Old, simple, loud RAT — great first *real* dynamic analysis. |
| **Remcos** | [`Remcos`](https://bazaar.abuse.ch/browse/tag/Remcos/) | Config extraction (L6) | Commodity RAT with a recognizable config block. |
| **UPX-packed (any)** | [`upx`](https://bazaar.abuse.ch/browse/tag/upx/) | Unpacking (L4.1) | Practice `upx -d` and manual unpacking on real packed PEs. |

> Tiers: start with **njRAT** (loud, simple) for your first real dynamic run,
> then **AgentTesla/RedLine** for config extraction, then **FormBook/XLoader**
> for the anti-analysis gauntlet, and use the capstone rubric
> ([../07-capstone/](../07-capstone/)) to grade your report.

## Other reputable sources

- [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) — free, hash-addressable, tag-browsable.
- [vx-underground](https://vx-underground.org/) — research archive (samples + papers).
- [theZoo](https://github.com/ytisf/theZoo) — curated educational repository.
- [MalShare](https://malshare.com/), [VirusShare](https://virusshare.com/) — registration required.

## Workflow template per sample

```
verify_sample.py sample.bin --sha256 <recorded>      # pin the exact bytes
# Static (L1-L2): file/strings/imports/entropy; submit to Detonate static
# Unpack (L4): if packed (high entropy / packer tells), unpack first
# Dynamic (L3): detonate in Detonate (or your Windows VM) — process/net/files
# Config/IOC (L6): extract config, export STIX/CSV, DEFANG for the report
# Report (L7 rubric): write it; THEN compare to a public writeup of the family
```
