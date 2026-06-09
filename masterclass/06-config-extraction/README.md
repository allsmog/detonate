# Level 6 — Configuration & IOC Extraction

*Goal: turn an analyzed sample into actionable intelligence. This is the payoff —
where reverse engineering produces something other defenders can use today.*

**Prerequisites:** [Level 4](../04-unpacking-deobfuscation/) (deobfuscation,
scripting). [Level 3.3](../03-dynamic-analysis/) (network/C2). **Read
[SAFETY.md](../SAFETY.md) — defang everything you publish.**

## Modules

| # | Module | Status |
|---|--------|--------|
| 6.1 | [Decrypting embedded config](01-decrypting-config/) | ✅ Built |
| 6.2 | [Building a config extractor](02-building-extractor/) | ✅ Built |
| 6.3 | [From artifacts to intelligence](03-artifacts-to-intelligence/) | ✅ Built |

---

### 6.1 — Decrypting embedded config
**Objective:** locate and decrypt a malware family's configuration blob. **Theory:**
why families embed config (C2 list, campaign ID, keys, kill dates), where it
lives (a resource, a high-entropy `.data` blob, an encrypted struct), and how to
find the decryption routine by following the data from where it's read. Common
schemes (XOR/RC4/AES, base64 layers). **Lab:** for a real, well-documented
commodity family (you fetch it yourself by the SHA-256 we provide, from
MalwareBazaar per [SAFETY §3](../SAFETY.md)), locate the config blob and decrypt
it by hand. **Solution:** the full path from blob to plaintext config, IOCs
defanged.

### 6.2 — Building a config extractor
**Objective:** write a reusable, automated config parser. **Theory:** turning a
one-off manual decryption into a robust extractor (locate by signature/structure,
decrypt, parse fields), handling format variants across versions, and the design
of community frameworks (CAPE/MWCP-style). **Lab:** write a Python extractor for
the Module 6.1 family that outputs structured config, then sketch how it would
plug into Detonate's analysis pipeline as a post-processing step (alongside the
existing static/dynamic services). **Solution:** a tested extractor + integration
design.

### 6.3 — From artifacts to intelligence
**Objective:** produce the deliverable — a clean, shareable intelligence package.
**Theory:** good IOCs vs noise, structured formats (**STIX 2.1**, MISP, CSV),
the pyramid of pain (why C2/TTPs hurt attackers more than hashes), correlation
across samples, and writing an analyst report (summary, behavior, IOCs, MITRE
mapping, recommendations). **Lab:** take a full Detonate analysis, export IOCs as
STIX/CSV, run similar-submission correlation, and write the threat report —
using Detonate's IOC export and AI report generation as a starting draft you
then verify and correct. **Solution:** a model report + the verification steps.
**Maps to:** Detonate's IOC export (STIX/CSV/JSON), correlation, and reporting
services.

---

**Next:** [Level 7 — Capstone](../07-capstone/).
