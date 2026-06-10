# Module 6.2 — Building a Config Extractor

> Decrypting one sample by hand is a finding. A **config extractor** turns that
> into a capability — run it over every sample of the family, today and next
> year, and get structured intelligence automatically. This module builds one.

- **Level:** 6 — Configuration & IOC Extraction
- **Time:** ~75 minutes
- **Difficulty:** Advanced

---

## Objectives

By the end of this module you will be able to:

- [ ] Turn a manual decryption into a robust, reusable extractor.
- [ ] Locate a config by signature rather than hardcoded offset.
- [ ] Emit structured output (JSON) suitable for downstream tooling.
- [ ] Reason about how an extractor plugs into an analysis pipeline (Detonate).

## Prerequisites

- [Module 6.1](../01-decrypting-config/). `python3`, `gcc`.

---

## Theory

A production extractor is a small pipeline:

```
locate(blob)  ->  decrypt(blob, key)  ->  parse(plaintext)  ->  structured config
```

Design principles that separate a throwaway script from a real extractor:

- **Locate by structure, not offset.** Search for a **magic**/signature or a
  structural pattern, so the extractor survives recompiles and minor variants
  (offsets shift; signatures don't).
- **Be defensive.** Validate the magic, bounds-check the length, handle decode
  errors — you'll run this on malformed and adversarial input.
- **Emit structured data.** JSON/dict with fields split out (C2 host/port list,
  campaign, mutex), not a blob of text — so the next stage can consume it.
- **Handle variants.** Real families change config format across versions; a
  good extractor tolerates field additions and multiple layouts.

This mirrors community frameworks (**CAPE**, Mandiant **MWCP**, **MACO**) where
each family gets a parser conforming to a common interface.

---

## Lab

**Files:** [`extract_config.py`](extract_config.py) (the extractor) and the
`configbot` sample from [Module 6.1](../01-decrypting-config/).

### Task 1 — Run the extractor

```bash
gcc -O0 -no-pie ../01-decrypting-config/configbot.c -o configbot
python3 extract_config.py ./configbot
```

Real output:

```json
{
  "raw": "v=1;id=TRAIN-2026;c2=c2a.example.com:443,c2b.example.net:8443;mutex=Global\\Train_8f3a",
  "c2": [
    { "host": "c2a.example.com", "port": 443 },
    { "host": "c2b.example.net", "port": 8443 }
  ],
  "v": "1",
  "id": "TRAIN-2026",
  "mutex": "Global\\Train_8f3a"
}
```

### Task 2 — Read how it works

`extract_config.py`: (1) `find(b"CFG0")` locates the blob by **signature**, (2)
reads the `uint16` length, (3) RC4-decrypts with the known key, (4) parses
`k=v;...` into a dict and splits the C2 list into host/port objects. Note it
never hardcodes an offset — recompiling `configbot` (which moves the blob) won't
break it.

### Task 3 — Make it robust (exercise)

Harden the extractor:
- Verify the magic and **bounds-check** `length` against the file size.
- Handle a **missing** `CFG0` gracefully (it raises a clear error — good).
- Add support for a **second format version** (e.g. a `v=2` config that uses `|`
  separators) without breaking `v=1`.

Rebuild `configbot` and confirm the extractor still works after the blob moves.

### Task 4 — Integration with Detonate

Sketch (or implement) how this becomes a **post-processing step** in Detonate's
pipeline: after static/dynamic analysis, a family-detection step routes matching
samples to the right extractor; the structured config feeds the **IOC export**
([Module 6.3](../03-artifacts-to-intelligence/)) and gets stored alongside the
analysis (`result` JSONB). The existing services in `api/detonate/services/`
(e.g. `static_analysis.py`, `ioc_export.py`) are the natural seams.

---

## Guided questions

1. Why locate the config by the `CFG0` **signature** instead of a fixed offset?
2. The extractor splits `c2` into host/port objects. Why is that better than
   leaving it as a string for downstream consumers?
3. What happens if you run the extractor on an *unrelated* binary, and why is
   that the correct behavior?
4. A new version of the family adds an `aes_key` field and reorders others.
   Which parts of your extractor break, and which survive — and what does that
   say about how to design the parser?
5. Why emit JSON rather than printing a human-readable summary?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. **Offsets move** with every recompile, config size change, or packer; a
   **signature is stable** across all of them. Searching for `CFG0` finds the
   blob wherever it lands, so one extractor handles many builds — exactly what
   makes it reusable rather than a one-sample hack.
2. Structured host/port objects are **directly consumable**: the IOC exporter can
   emit a network indicator per endpoint, a blocklist can take host+port, and
   correlation can match on host. A raw string forces every consumer to re-parse
   it (and re-introduce parsing bugs). Parse once, at the source of truth.
3. It **raises a clear "CFG0 magic not found" error** — correct, because the
   binary isn't a configbot sample, so there's no config to extract. Failing
   loudly (rather than emitting garbage) is what you want in a pipeline; a wrong
   "config" is worse than a clean miss.
4. **Locate + decrypt survive** (same magic, same RC4). The **`k=v;` parser**
   tolerates the new `aes_key` field (it just appears as another key) but reorder
   is fine since it's key-based, not positional. A *format change* (new
   separators/structure) would break parsing — which is why you **key on field
   names, version-gate the parser** (`if v=="2": ...`), and avoid positional
   assumptions.
5. JSON is **machine-readable and composable** — it pipes into the STIX builder,
   stores in a DB, and diffs across samples. Human summaries are for the final
   report ([Module 6.3](../03-artifacts-to-intelligence/)), generated *from* the
   structured data, not instead of it.

</details>

---

## Going further

- Add a `--csv` output mode and a `--stix` mode (the latter is
  [Module 6.3](../03-artifacts-to-intelligence/)).
- Generalize: make `extract_config.py` take the RC4 key and magic as arguments so
  it handles a *family of* families.
- Next: [Module 6.3 — From artifacts to intelligence](../03-artifacts-to-intelligence/).
