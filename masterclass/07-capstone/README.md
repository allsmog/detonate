# Level 7 — Capstone: The Unknown Sample

*Goal: prove it. No hints, no scaffolding — run the full kill chain on an unknown
sample and deliver a real analyst report. This is the difference between
following labs and being an analyst.*

**Prerequisites:** Levels 1–6. **Read [SAFETY.md](../SAFETY.md).**

---

## Two ways to take the capstone

**Path A — the self-contained challenge (recommended, fully reproducible).**
This repo ships a purpose-built *benign* challenge that combines every technique
from Levels 1–6 — UPX packing, ptrace anti-debug, an XOR-obfuscated string, an
RC4-encrypted config behind a `CFG0` marker, and a C2 beacon. An instructor (or
you) builds it once:

```bash
cd challenge && bash build.sh      # produces ./crackmalware (gitignored)
```

Then analyze **`crackmalware`** with no other information. The source
(`challenge_src.c`) and the sealed answer key (`SOLUTION.md`) exist in the repo
for instructors/self-grading — **do not read them until your report is done.**
A full verified walkthrough and grading key live in
[`challenge/SOLUTION.md`](challenge/SOLUTION.md).

**Path B — a real sample.** For the authentic experience, fetch a real,
well-documented commodity sample yourself by SHA-256 from MalwareBazaar per
[SAFETY §3](../SAFETY.md), in your isolated lab. No one tells you whether it's
packed, what family it is, or what it does — you decide the approach.

Either way: analyze end to end and produce the report a SOC or threat-intel team
would actually use.

## What to produce

A single report (`report.md`) covering:

1. **Triage** — hashes, type, size, first-look heuristics, threat-intel hits.
2. **Static analysis** — structure, packing assessment, strings/IOCs, imports →
   capability hypothesis.
3. **Unpacking/deobfuscation** — if packed/obfuscated, how you got to the real
   code (document the steps, not just the result).
4. **Dynamic analysis** — detonate in Detonate; process tree, network/C2,
   filesystem, persistence. Tie observations to evidence.
5. **Configuration/IOCs** — extracted config (if any), full **defanged** IOC
   list, exported as STIX/CSV.
6. **MITRE ATT&CK mapping** — techniques observed, with justification.
7. **Verdict & summary** — clean/suspicious/malicious + score, family
   attribution if you can support it, and an executive summary a non-RE can read.
8. **Detection** — a YARA rule you wrote that would catch this sample/family.

## Grading rubric

Score yourself (or have a peer/mentor score you) out of 100:

| Area | Points | What "full marks" looks like |
|------|--------|------------------------------|
| Triage & static | 15 | Correct identification; packing/obfuscation called correctly. |
| Unpacking/deobfuscation | 20 | Reached the real code; steps reproducible. |
| Dynamic analysis | 20 | Behavior correct and evidence-backed; no hand-waving. |
| IOC & config extraction | 15 | Complete, accurate, **defanged**, properly exported. |
| MITRE mapping | 10 | Justified, not just plausible-sounding. |
| Detection (YARA) | 10 | Catches the family, low false positives, tested. |
| Report quality | 10 | Clear, structured, honest about uncertainty. |

**Passing is 70.** A world-class report is decisive where the evidence allows
and explicitly humble where it doesn't — fabricated certainty fails this
capstone faster than an "unknown."

## Choosing your sample

Use a well-documented commodity family for your first capstone so you can check
your work against public writeups *after* you finish (never before). The
challenge file in this folder will list a specific SHA-256 and a difficulty tier;
contributors can add more. Pull it yourself, in your lab, password-protected.

## After you finish

Compare your report against a published analysis of the same sample. Where did
you agree? Where did you miss something or over-claim? That gap is your next
study plan. Then do another at a higher difficulty tier.

> When you can do this consistently, on samples you've never seen, and your IOCs
> and verdict hold up against the public record — you've completed the
> masterclass.
