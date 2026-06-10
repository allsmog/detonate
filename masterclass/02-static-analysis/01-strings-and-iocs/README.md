# Module 2.1 — Strings & Embedded IOCs

> The cheapest intelligence in reverse engineering is the strings a program
> carries. This module teaches you to pull them, separate signal from noise, and
> turn them into IOCs — and to recognize when their *absence* is the finding.

- **Level:** 2 — Static Analysis
- **Time:** ~45 minutes
- **Difficulty:** Beginner

---

## Objectives

By the end of this module you will be able to:

- [ ] Extract ASCII and UTF-16LE strings from a binary.
- [ ] Categorize strings into IOC types (URL, IP, registry, path, email, mutex).
- [ ] Recognize encoded strings (e.g. base64) and decode them.
- [ ] Explain why "no useful strings" is itself a strong signal.
- [ ] Map this to Detonate's automatic string extraction + IOC categorization.

## Prerequisites

- [Level 1](../../01-foundations/). `strings`, `python3`.

---

## Theory

Programs embed strings for legitimate reasons (error messages, format strings),
and malware embeds them for incriminating ones: **C2 URLs/IPs, registry keys for
persistence, dropped-file paths, mutex names, campaign IDs, ransom notes**.

Two things to internalize:

1. **Width matters.** ASCII strings are easy; Windows malware often uses
   **UTF-16LE** (wide) strings, which a naive `strings` misses unless you ask
   for them (`strings -el`). Detonate extracts both.
2. **Absence is a signal.** A binary with *no* meaningful strings — just a few
   imports and a high-entropy blob — is telling you it's **packed or
   encrypted**. That's not a dead end; it's a finding that routes you to
   [entropy/packing](../03-entropy-and-packing/) and
   [unpacking](../../04-unpacking-deobfuscation/).

And: strings can **lie** (planted decoys) and can **hide** (encoded/encrypted).
Base64, hex, XOR, and stacked encodings are common. Treat a suspicious blob as a
lead, not a conclusion.

---

## Lab

**Sample:** [`stringy.c`](stringy.c) — a benign binary that *carries* the string
types malware leaks (all IOCs are inert: `example.com`, the RFC-5737
documentation IP `192.0.2.123`, etc.).

### Task 0 — Build

```bash
gcc -O2 -no-pie stringy.c -o stringy
```

### Task 1 — Pull and categorize

```bash
strings -n 6 stringy
```

Sort what you find into IOC buckets. Real output includes:

| String | IOC type |
|--------|----------|
| `http://example.com/gate.php?id=` | URL (C2-shaped: `gate.php?id=`) |
| `192.0.2.123` | IPv4 |
| `Software\Microsoft\Windows\CurrentVersion\Run` | Registry key (persistence!) |
| `C:\Users\Public\svchost32.exe` | Dropped file path (masquerade!) |
| `operator@example.com` | Email |
| `Global\TrainingMutex_8f3a` | Mutex name |
| `aGVsbG8gZnJvbSB0aGUgdHJhaW5pbmcgc2FtcGxl` | base64 blob |

### Task 2 — Decode the blob

```bash
echo 'aGVsbG8gZnJvbSB0aGUgdHJhaW5pbmcgc2FtcGxl' | base64 -d ; echo
```

### Task 3 — Through Detonate

Submit `stringy`; read the **strings** and **IOCs** in the static-analysis view.
Detonate categorizes URLs/IPs/emails/registry/paths automatically (the same
buckets you just made by hand). Compare its categorization to yours.

---

## Guided questions

1. Which two strings, *together*, are the strongest evidence of malicious
   intent, and why is the pair stronger than either alone?
2. `C:\Users\Public\svchost32.exe` — what's suspicious about that filename
   specifically?
3. You run `strings` on a different sample and get almost nothing useful. What
   does that suggest and where do you go next?
4. Why might `strings` miss strings that Detonate finds? (Two reasons.)
5. The base64 blob decodes to harmless text here. In real malware, what kinds of
   things get base64'd, and why encode them at all?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. The **registry Run key** (`...\CurrentVersion\Run`) plus the **dropped-exe
   path** together say "this establishes persistence by writing an executable
   and auto-starting it." Either alone is weaker — a Run-key string could be
   benign config; an exe path could be incidental — but co-occurrence describes
   a behavior. (This co-occurrence idea is exactly what makes a good YARA rule —
   [Module 2.4](../04-writing-yara-rules/).)
2. **`svchost32.exe`** masquerades as the legitimate Windows `svchost.exe`
   (note the bogus `32`), and it's dropped to `C:\Users\Public` — a
   world-writable, low-suspicion location. Name + location = deliberate
   blending-in.
3. Near-empty strings output suggests the real strings are **encrypted or the
   binary is packed**. Next: check **entropy**
   ([Module 2.3](../03-entropy-and-packing/)); if high, unpack
   ([Level 4](../../04-unpacking-deobfuscation/)) before expecting useful
   strings.
4. (a) **Encoding/width** — UTF-16LE strings need `strings -el`; (b) **minimum
   length / location** — defaults skip short strings and may miss strings in
   unusual sections. Detonate extracts ASCII *and* UTF-16LE and categorizes IOCs.
5. Real malware base64s (or otherwise encodes) **C2 URLs, embedded payloads,
   stolen data before exfiltration, and configuration** — to evade plaintext
   string scanning and simple network signatures. Encoding ≠ encryption, but it
   defeats lazy detection, which is often enough.

</details>

---

## Going further

- Extract wide strings: `strings -el <sample>` and compare to the default run.
- Write a 10-line Python IOC categorizer (regex for URL/IP/email) and run it on
  `strings` output — you've reimplemented the core of Detonate's IOC extraction.
- Next: [Module 2.2 — Imports as behavior](../02-imports-as-behavior/).
