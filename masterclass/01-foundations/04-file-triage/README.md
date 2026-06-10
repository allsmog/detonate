# Module 1.4 — File Triage & Hashing

> Before you spend an hour reversing, spend sixty seconds triaging. This module
> teaches the first-look that decides everything after it — identity (hashes),
> nature (type/entropy), and similarity (fuzzy hashing) — and shows you it's the
> same first-look Detonate automates on every submission.

- **Level:** 1 — Foundations
- **Time:** ~45 minutes
- **Difficulty:** Beginner

---

## Objectives

By the end of this module you will be able to:

- [ ] Compute and explain MD5/SHA-1/SHA-256 and when each matters.
- [ ] Use **fuzzy hashing** (ssdeep) to find *similar* (not identical) samples.
- [ ] Identify file type from magic bytes, independent of extension.
- [ ] Read **entropy** as a packed/encrypted heuristic.
- [ ] Reproduce Detonate's triage signals by hand and via threat intel.

## Prerequisites

- [Module 1.1 — PE & ELF anatomy](../01-pe-anatomy/).
- `file`, `ssdeep` (optional), Python 3. See [SETUP.md](../../SETUP.md).

---

## Theory

### The three triage questions

1. **Identity — "have I seen *exactly* this before?"** Cryptographic hashes.
   - **SHA-256** is the modern standard identifier; use it to look a sample up
     on VirusTotal/MalwareBazaar.
   - **MD5/SHA-1** are weak for security but still everywhere in threat intel
     for legacy lookups. A *single changed byte* changes all of them — which is
     exactly their limitation.
2. **Similarity — "have I seen something *like* this?"** **Fuzzy hashing**
   (ssdeep / TLSH). Two builds of the same malware family differ byte-for-byte
   (so crypto hashes diverge) but share structure; fuzzy hashes give a
   percentage match. This is how you cluster a campaign.
3. **Nature — "what *is* this, and is it hiding?"** File type from **magic
   bytes** (not the extension — malware lies about extensions), and **entropy**
   as a quick packed/encrypted tell.

### Entropy in one paragraph

Shannon entropy measures information density in bits/byte, 0–8. Normal code/text
sits well under 7; compressed or encrypted data trends toward ~7.9–8.0 because
it looks random. A high overall entropy — or one screaming-high section — says
"packed/encrypted, look closer" before you've read a single instruction.

---

## Lab

You'll triage a file by hand, with [`triage.py`](triage.py) (pure Python, no
deps — it mirrors Detonate's pipeline), and then through Detonate itself.

### Task 1 — Triage by hand

Pick any binary (e.g. the `crackme1` from Module 1.3, or `/bin/ls`):

```bash
file crackme1
python3 triage.py crackme1
sha256sum crackme1
```

Read `triage.py` — it's `hashlib` + a 6-line Shannon-entropy function + a magic
table. Detonate does the same thing in
[`api/detonate/services/static_analysis.py`](../../../api/detonate/services/static_analysis.py)
(`analyze_entropy`).

### Task 2 — Fuzzy hashing for similarity

```bash
cp crackme1 crackme1_v2 && printf '\x90' >> crackme1_v2   # tiny change
sha256sum crackme1 crackme1_v2     # totally different hashes
ssdeep -d crackme1 crackme1_v2     # but ~99% similar (if ssdeep installed)
```

One appended byte → different SHA-256, near-identical ssdeep. That gap is why
fuzzy hashing exists.

### Task 3 — Triage through Detonate + threat intel

1. Submit the file to Detonate; read the hashes, size, type, and entropy it
   reports (this happens automatically on submission).
2. Use the SHA-256 with Detonate's **threat-intel enrichment** (VirusTotal /
   MalwareBazaar) to see if the sample is publicly known. A known-bad hash can
   end your investigation in seconds; an unknown hash means you're on your own —
   exactly when the rest of this course matters.

---

## Guided questions

1. You change one byte of a sample. Which of {MD5, SHA-256, ssdeep} change, and
   what does that tell you about when to use each?
2. A file is named `invoice.pdf` but `file` says `PE32 executable`. What
   happened, and which do you trust?
3. A binary reports overall entropy 7.95. What's your hypothesis, and what's the
   *next* thing you'd check to confirm it?
4. Why is a SHA-256 lookup on threat intel usually the very first thing an
   analyst does?
5. In `triage.py`, why does the entropy function ignore byte values whose count
   is zero?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. **MD5 and SHA-256 both change completely** (crypto hashes have the avalanche
   property — one bit flips ~half the output). **ssdeep barely changes** (it's
   designed to track *similarity*, not identity). Use crypto hashes to ask "is
   it the exact same file?"; use fuzzy hashes to ask "is it the same family /
   campaign?"
2. The **extension is attacker-controlled and meaningless**; `file` reads the
   actual **magic bytes** (`MZ` = PE). Trust the magic. Malware routinely
   disguises executables as documents to fool users and naive filters.
3. **Hypothesis: it's packed or encrypted.** Next, check **per-section entropy**
   (one section at ~8.0 with a tiny import table and odd section names confirms
   packing — see [Module 2.3](../../02-static-analysis/03-entropy-and-packing/))
   rather than the whole file just being compressed data.
4. Because it's near-free and can **end the investigation immediately**: a known
   hash gives you family, behavior, and IOCs from prior analyses. Even a *miss*
   is informative — a brand-new hash often means a fresh/targeted sample worth
   deeper work.
5. `log2(0)` is undefined (−∞), and a byte that never appears contributes
   nothing to entropy (its probability term `p·log2(p)` → 0). Skipping zero
   counts avoids a math error while being mathematically correct.

</details>

---

## Going further

- Build a tiny clustering script: ssdeep-hash a folder of samples and group by
  similarity threshold. You've just built campaign clustering in miniature.
- Compare `triage.py`'s entropy output to Detonate's `analyze_entropy` on the
  same file — they should match to 4 decimals.
- Next: **[Level 2 — Static Analysis](../../02-static-analysis/)**.
