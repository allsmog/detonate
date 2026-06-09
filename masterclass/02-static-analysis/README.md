# Level 2 — Static Analysis

*Goal: extract maximum intelligence from a sample without ever running it.
Static analysis is cheap, safe, and where good analysts start every case.*

**Prerequisites:** [Level 1](../01-foundations/) (especially
[PE/ELF anatomy](../01-foundations/01-pe-anatomy/)).

## Modules

| # | Module | Status |
|---|--------|--------|
| 2.1 | Strings & embedded IOCs | 📝 Outlined below |
| 2.2 | Imports as behavior | 📝 Outlined below |
| 2.3 | Entropy & packing detection | 📝 Outlined below |
| 2.4 | Writing YARA rules | 📝 Outlined below |

---

### 2.1 — Strings & embedded IOCs
**Objective:** pull and interpret embedded strings; separate signal from noise.
**Theory:** ASCII vs UTF-16LE strings, why malware strings leak intent (URLs,
mutexes, registry keys, file paths, error messages), and why *absence* of
strings (everything encrypted) is itself a finding. IOC categorization. **Lab:**
run `strings` and Detonate's static analyzer on a sample; categorize the IOCs
Detonate extracts (URLs/IPs/emails/registry/paths) and decide which are real
indicators vs library noise. **Solution:** triaging a real string dump. **Maps
to:** Detonate's string extraction + IOC categorization.

### 2.2 — Imports as behavior
**Objective:** predict what a binary does from its import table before reading
code. **Theory:** the Import Address Table; mapping API families to capability —
networking (`Ws2_32`, `WinINet`, `socket`), crypto (`Crypt*`, `bcrypt`),
process injection (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`),
persistence (`Reg*`, service APIs). Why dynamic import resolution
(`LoadLibrary`+`GetProcAddress`, API hashing) hides this — and how to spot that
it's happening. **Lab:** read the imports Detonate reports for several samples
and write a one-line capability hypothesis for each; flag samples with
suspiciously few imports. **Solution:** capability inference walkthrough.

### 2.3 — Entropy & packing detection
**Objective:** detect packing/encryption before wasting time reading packed
code. **Theory:** Shannon entropy (0–8 bits/byte), why packed/encrypted data
trends toward ~7.9–8.0, per-section entropy, and corroborating signals (tiny
import table, weird section names, writable+executable sections, raw size 0).
**Lab:** compare entropy of a normal binary vs a UPX-packed copy in Detonate;
identify the packed sections. **Solution:** reading the entropy profile. **Maps
to:** Detonate's per-section entropy analysis. **Leads into:**
[Level 4 — Unpacking](../04-unpacking-deobfuscation/).

### 2.4 — Writing YARA rules
**Objective:** turn a sample into a robust, low-false-positive detection rule.
**Theory:** YARA structure (meta/strings/condition), choosing durable
indicators (code patterns, unique strings, import combos) over brittle ones,
testing for false positives. **Lab:** write a YARA rule for a sample, then
upload and test it through Detonate's YARA management API against its 26
built-in rules and your sample set; iterate to kill false positives. **Solution:**
from a weak first rule to a production-quality one. **Maps to:**
`sandbox/yara/rules/` and the YARA management endpoints.

---

**Next:** [Level 3 — Dynamic Analysis](../03-dynamic-analysis/).
