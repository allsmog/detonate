# Module 6.3 — From Artifacts to Intelligence

> Analysis that stays in your head helps no one. The deliverable is
> **intelligence**: clean IOCs in a shareable format, correlated across samples,
> wrapped in a report a SOC can act on. This module turns your findings into
> that product.

- **Level:** 6 — Configuration & IOC Extraction
- **Time:** ~75 minutes
- **Difficulty:** Advanced

---

## Objectives

By the end of this module you will be able to:

- [ ] Separate high-value IOCs from noise.
- [ ] Export IOCs in a structured format (STIX 2.1 / CSV).
- [ ] Explain the Pyramid of Pain and prioritize indicators by it.
- [ ] Write an analyst report that's decisive and honest about uncertainty.

## Prerequisites

- [Module 6.1](../01-decrypting-config/), [Module 6.2](../02-building-extractor/).
  `python3`.

---

## Theory

### Good IOCs vs noise

Not all indicators are equal. The **Pyramid of Pain** ranks them by how much it
hurts the *attacker* when you block them:

```
        TTPs            <- hardest for them to change (behavioral)
     Tools
   Network/Host artifacts
  Domain names
 IP addresses
Hash values             <- trivial for them to change
```

Hashes are cheap to rotate (recompile); **C2 domains, TTPs, and distinctive
artifacts** (a mutex, a config marker, a User-Agent) cost the attacker more.
Prioritize accordingly, and don't drown a report in low-value hashes.

### Structured formats

- **STIX 2.1** — machine-readable bundle of `indicator` objects with `pattern`s;
  the lingua franca for sharing (MISP, TIPs, threat feeds).
- **CSV/JSON** — for spreadsheets and quick ingestion.

Detonate already does this in `ioc_export.py` (`export_stix`); you'll mirror it.

### Defanging

In **human-readable** docs, defang (`c2a[.]example[.]com`) so IOCs can't be
clicked/fetched/auto-extracted. In **machine-readable** STIX patterns, keep them
live — that's what downstream tooling consumes. Know which context you're in.

---

## Lab

Files: [`make_stix.py`](make_stix.py) (config → STIX bundle), the
`extract_config.py` from Module 6.2, and [`model_report.md`](model_report.md)
(a complete example report).

### Task 1 — Build the STIX bundle

```bash
gcc -O0 -no-pie ../01-decrypting-config/configbot.c -o configbot
python3 ../02-building-extractor/extract_config.py ./configbot \
  | python3 make_stix.py
```

Real result — a valid STIX 2.1 bundle (`type: bundle`, 3 indicator objects):

```
[domain-name:value = 'c2a.example.com']
[domain-name:value = 'c2b.example.net']
[mutex:name = 'Global\Train_8f3a']
```

### Task 2 — Validate it

```bash
python3 ../02-building-extractor/extract_config.py ./configbot \
  | python3 make_stix.py | python3 -c "import json,sys; b=json.load(sys.stdin); \
print('valid bundle:', b['type']=='bundle', '| objects:', len(b['objects']))"
```

It parses as JSON and conforms to the STIX bundle shape (real validators like
`stix2` go further; `spec_version`, `pattern_type` are present).

### Task 3 — Correlate

Two samples sharing campaign `TRAIN-2026` or the same mutex are almost certainly
the **same operator/campaign**. Detonate's similar-submission correlation does
this on IOCs automatically. Note: shared C2 > shared hash for correlation
confidence (hashes change; infrastructure is reused).

### Task 4 — Write the report

Read [`model_report.md`](model_report.md) — note it leads with an **executive
summary**, backs every claim with **evidence**, **defangs** all IOCs, includes
**ATT&CK** and **detection**, and gives **recommendations**. Use Detonate's
AI-generated report as a *first draft you verify and correct* — never ship the
draft unread.

---

## Guided questions

1. Per the Pyramid of Pain, why would you rather give defenders the C2 domains
   than the sample hash, even though the hash is "more unique"?
2. Why keep IOCs **live** inside the STIX pattern but **defanged** in the report
   prose?
3. Two samples have different hashes but the same mutex and campaign ID. What do
   you conclude, and with what confidence?
4. Detonate can auto-generate a report with an LLM. What must you do before
   shipping it, and why?
5. A junior analyst's report says "definitely APT-X." The evidence is one shared
   C2 IP. Critique that.

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. The **hash is trivially changed** — the attacker recompiles and every hash
   IOC is dead. Blocking the **C2 domains** disrupts *all* samples that talk to
   that infrastructure and costs the attacker real money/effort to rotate. Higher
   on the pyramid = more pain = more durable defense. (Give both, but prioritize
   the durable ones.)
2. The **report is for humans**, who shouldn't accidentally click/fetch a live
   C2, and whose mail/EDR tooling may auto-extract and act on un-defanged
   indicators. The **STIX pattern is for machines** that are *supposed* to ingest
   the live value into blocklists/feeds. Right value, right context.
3. They're **the same family/campaign**, high confidence — a shared **mutex**
   (host artifact) and **campaign ID** are far stronger correlation than a hash,
   and both differing hashes are explained by recompilation. You'd cluster them
   together and track as one campaign.
4. **Read and verify every claim** against your own evidence, fix hallucinations
   or over-claims, confirm IOCs are correct and defanged, and check the ATT&CK
   mappings. LLM drafts accelerate writing but can fabricate confident-sounding
   errors; you are accountable for the report, not the model.
5. **Overclaiming.** One shared C2 IP is weak attribution — IPs are reused,
   rented, sinkholed, and shared across actors. Attribution needs **converging
   evidence** (TTPs, code overlap, infrastructure patterns, tooling) and should
   be stated with calibrated confidence ("possible link to X, low confidence"),
   not as fact. Decisive where evidence allows, humble where it doesn't.

</details>

---

## Going further

- Extend `make_stix.py` to emit `ipv4-addr` patterns and a `malware`/`campaign`
  SDO linked to the indicators via relationships.
- Validate your bundle with the official `stix2` library (`pip install stix2`).
- Next: **[Level 7 — Capstone](../../07-capstone/)** — put it all together on an
  unknown sample.
