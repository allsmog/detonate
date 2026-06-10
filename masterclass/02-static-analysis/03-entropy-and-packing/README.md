# Module 2.3 — Entropy & Packing Detection

> Most interesting malware is packed: the real code is compressed or encrypted
> and unpacked only at runtime. This module teaches you to *detect* packing
> cheaply — before you waste an hour reading a stub — using entropy and a
> handful of structural tells.

- **Level:** 2 — Static Analysis
- **Time:** ~45 minutes
- **Difficulty:** Beginner→Intermediate

---

## Objectives

By the end of this module you will be able to:

- [ ] Compute and interpret Shannon entropy (overall and per-section).
- [ ] State the entropy ranges that indicate compression/encryption.
- [ ] Corroborate packing with structural signals (section names, headers, tiny
      import tables).
- [ ] Identify a UPX-packed binary and explain the tells.

## Prerequisites

- [Module 1.4 — file triage](../../01-foundations/04-file-triage/) (entropy),
  [Module 2.1](../01-strings-and-iocs/), [Module 2.2](../02-imports-as-behavior/).
  `upx`, `readelf`/`objdump`, the `triage.py` from Module 1.4.

---

## Theory

**Packing** = transform the executable so its real bytes are hidden (compressed
and/or encrypted), prepended with a small **stub** that restores them in memory
at runtime. Attackers pack to shrink size, defeat string/signature scanning, and
slow analysis.

**Entropy** is the cheap detector. Bits-per-byte, 0–8:
- Normal code/data: typically **< 7**.
- Compressed/encrypted: trends to **~7.9–8.0** (looks random).

But entropy alone gives false positives (legit compressed resources, installers).
**Corroborate** with structural tells:

| Tell | What it means |
|------|---------------|
| One section at ~8.0 entropy | The packed payload lives there. |
| **Tiny import table** (e.g. just `LoadLibrary`/`GetProcAddress`) | Real imports resolved post-unpack. |
| Odd/known section names (`UPX0`,`UPX1`,`.aspack`) or **missing section headers** | Packer fingerprint. |
| Section with **raw size 0 but large virtual size** | Space for runtime-unpacked code. |
| `RWX` (writable+executable) load segment | Self-modifying / unpacking. |

---

## Lab

**Sample:** [`packme.c`](packme.c) — a normal program with a compressible data
blob. You'll compare it before and after UPX.

### Task 1 — Baseline entropy

```bash
gcc -O2 -no-pie packme.c -o packme
python3 ../../01-foundations/04-file-triage/triage.py packme | grep -E 'size|entropy'
# size ~15960 bytes, entropy ~2.0 bits/byte  -> clearly not packed
```

### Task 2 — Pack and re-measure

```bash
upx --best -o packme_upx packme
python3 ../../01-foundations/04-file-triage/triage.py packme_upx | grep -E 'size|entropy'
# size ~6820 bytes, entropy ~7.23 bits/byte  -> HIGH: likely packed
```

Smaller **and** much higher entropy — the compression signature.

### Task 3 — Confirm with structure

```bash
strings packme_upx | grep -i UPX          # -> "UPX!", UPX banner (packer fingerprint)
file packme_upx                            # -> "...no section header"
readelf -S packme | grep -c '\]'           # ~32 sections (normal)
readelf -S packme_upx | grep -c '\]'       # 0 sections (stripped by packer)
readelf -l packme_upx | grep -A1 LOAD      # an RW + R E layout typical of UPX
```

Real results on this sample: the unpacked binary has **32 section headers**; the
UPX-packed one has **0** ("no section header"), carries the **`UPX!`** magic and
the UPX banner, and is much smaller. Three independent tells agreeing = packed,
high confidence.

### Task 4 — Through Detonate

Submit both to Detonate and read the **per-section entropy** in the static view
(`analyze_entropy` in
[`api/detonate/services/static_analysis.py`](../../../api/detonate/services/static_analysis.py)
flags sections over 7.0). The platform raises the same "high entropy section"
indicator you derived by hand.

---

## Guided questions

1. The packed binary is *smaller* than the original but has *higher* entropy.
   Why are both true at once?
2. Entropy 7.2 is high but not 7.99. Does that weaken the "packed" conclusion?
   What pushed your confidence up anyway?
3. A legitimate installer also shows ~7.9 entropy. How do you avoid calling it
   "malware packed"?
4. Why does UPX strip the section headers, and how does that itself become a
   detection signal?
5. You've confirmed packing. What have you learned about the malware's
   *behavior* so far — and what must you do before you can learn more?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. **Compression removes redundancy** (smaller) by encoding data closer to its
   information-theoretic limit — and data near that limit looks **random**
   (higher entropy). So packing simultaneously shrinks the file and raises
   entropy. Both are the same phenomenon viewed two ways.
2. No — **structural corroboration** is what made it confident: the `UPX!`
   magic, the UPX banner string, "no section header," and the size drop all
   agree. Entropy is the cheap first flag; the tells confirm. (7.2 vs 7.99 just
   reflects the small unpacked stub + headers diluting the average.)
3. Don't conclude from entropy alone. **Corroborate** and **contextualize**:
   does it have a valid signature? a known-good hash (threat intel)? legitimate
   section names? Packing is suspicious, not damning — plenty of benign software
   is packed. Combine with imports, signatures, and reputation.
4. UPX replaces the original layout with its own compressed blob + stub; the
   original sections don't meaningfully exist on disk anymore, so the section
   header table is dropped. But "**a normal-looking executable with zero section
   headers**" is itself anomalous — toolchains don't produce that — so the
   absence becomes a high-signal detector.
5. So far you know **almost nothing about behavior** — only that it's hiding.
   Static reading of the packed bytes is futile. You must **unpack** it first
   ([Level 4](../../04-unpacking-deobfuscation/)) or **run it** in a sandbox and
   observe ([Level 3](../../03-dynamic-analysis/)), which unpacks it for you in
   memory as a side effect of execution.

</details>

---

## Going further

- Plot a byte-entropy graph across the file (sliding window) to *see* the
  high-entropy region — many tools (binwalk `-E`) do this.
- Try a different packer if available and compare fingerprints.
- Next: [Module 2.4 — Writing YARA rules](../04-writing-yara-rules/), then
  unpack for real in [Level 4](../../04-unpacking-deobfuscation/).
