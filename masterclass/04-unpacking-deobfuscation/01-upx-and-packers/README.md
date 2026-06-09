# Module 4.1 — UPX & Common Packers

> Packing is the armor on most malware. The good news: a large fraction is
> packed with **UPX** or a handful of common packers you can recognize and strip
> in minutes. This module is your first unpack — automated and manual.

- **Level:** 4 — Unpacking & Deobfuscation
- **Time:** ~45 minutes
- **Difficulty:** Intermediate

---

## Objectives

By the end of this module you will be able to:

- [ ] Recognize a UPX-packed binary from its fingerprints.
- [ ] Unpack it automatically (`upx -d`) and explain what that restored.
- [ ] Explain why automated unpacking fails on tampered packers (→ Module 4.2).
- [ ] Confirm an unpack worked (sections/strings/imports return).

## Prerequisites

- [Module 2.3 — entropy & packing](../../02-static-analysis/03-entropy-and-packing/).
  `upx`, `readelf`. **[SAFETY.md](../../SAFETY.md)** — real packed samples are
  still live.

---

## Theory

A packer replaces your binary with: a **compressed/encrypted blob** of the
original + a small **stub** that, at runtime, decompresses the blob into memory
and jumps to the original entry point (OEP). UPX is the most common, open-source,
and — crucially — **reversible with the same tool** when the packer metadata is
intact.

Fingerprints you already learned to spot ([2.3](../../02-static-analysis/03-entropy-and-packing/)):
high entropy, the **`UPX!`** magic and UPX banner strings, and (on ELF) **no
section headers**.

The catch: attackers **tamper** with UPX (corrupt the magic, change version
strings) specifically to break `upx -d`, forcing manual unpacking — which is
[Module 4.2](../02-custom-packers/). Recognizing UPX is step one either way.

---

## Lab

**Sample:** the `packme` binary from
[Module 2.3](../../02-static-analysis/03-entropy-and-packing/) (`packme.c`).

### Task 1 — Pack and recognize

```bash
gcc -O2 -no-pie ../../02-static-analysis/03-entropy-and-packing/packme.c -o packme
upx --best -o packme_upx packme

strings packme_upx | grep -i UPX      # -> "UPX!" + banner = it's UPX
readelf -S packme_upx | grep -c '\]'  # -> 0 sections (packer stripped them)
```

### Task 2 — Automated unpack

```bash
cp packme_upx packme_unpacked
upx -d packme_unpacked                 # decompress in place
./packme_unpacked                       # runs identically to the original
readelf -S packme_unpacked | grep -c '\]'   # -> 32 sections (restored!)
```

Verified: the unpacked copy **runs identically** (`checksum=634856 len=8192`)
and its **32 section headers are back** — the original binary has been restored.

### Task 3 — Confirm with the analyst's checklist

After any unpack, confirm you actually got the real binary:

- **Strings** return (you can read meaningful text again).
- **Imports** return (the real API table reappears — see
  [Module 2.2](../../02-static-analysis/02-imports-as-behavior/)).
- **Entropy** drops back to normal (`triage.py`).
- It **disassembles cleanly** at a real entry point.

### Task 4 — Through Detonate

Submit both `packme_upx` and `packme_unpacked`. Compare entropy, sections, and
imports in the static view. Then recall the dynamic shortcut: even without
unpacking, **detonating** the packed sample unpacks it *in memory* and lets you
observe behavior ([Level 3](../../03-dynamic-analysis/)) — packing slows static
analysis far more than dynamic.

---

## Guided questions

1. What three independent signals told you `packme_upx` was UPX-packed before you
   unpacked it?
2. `upx -d` worked here. Name two things an attacker does to make it *fail*, and
   what you'd do then.
3. After unpacking, the section count went 0 → 32. Why is that strong evidence
   the unpack succeeded?
4. Why does simply *running* a packed sample in a sandbox sidestep the whole
   unpacking problem — and what's the catch?
5. UPX is open-source and reversible. Why do attackers still use it?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. The **`UPX!` magic + UPX banner strings**, **0 section headers** ("no section
   header"), and **high entropy / smaller size**. Any one is suggestive; three
   agreeing is conclusive.
2. They **corrupt the UPX magic/version** or **modify the stub** so `upx -d`
   refuses or mis-parses. Then you unpack **manually**
   ([Module 4.2](../02-custom-packers/)): run the stub under a debugger, break at
   the OEP, and dump the unpacked image from memory.
3. Packing **strips the original section table** (you saw 0). A clean restore
   rebuilds it (32). Sections returning — plus strings/imports returning and
   identical runtime behavior — means you're looking at the real original, not a
   partially-processed blob.
4. Running the sample makes the **stub unpack the real code into memory itself**
   — you then observe behavior or dump the unpacked image. The catch: you must
   **execute** it (isolate!), it only reveals the **paths you trigger**, and
   anti-analysis/anti-debug ([Level 5](../../05-anti-analysis/)) can make it
   refuse to unpack or behave differently when watched.
5. It's **fast, free, shrinks the binary, and still defeats lazy static
   signature/string scanning** for the cost of one command. Even though analysts
   can strip it, it raises the floor against automated and low-skill detection —
   and tampered UPX raises it further.

</details>

---

## Going further

- Tamper with the `UPX!` magic in a *copy* (`xxd` + a hex edit), watch `upx -d`
  fail, and preview why Module 4.2's manual approach exists.
- Write a YARA rule that flags UPX packing generically and test it
  ([Module 2.4](../../02-static-analysis/04-writing-yara-rules/)).
- Next: [Module 4.2 — Custom packers & unpacking stubs](../02-custom-packers/).
