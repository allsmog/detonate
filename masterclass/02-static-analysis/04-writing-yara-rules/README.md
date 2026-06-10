# Module 2.4 — Writing YARA Rules

> YARA is how analysts turn one analyzed sample into detection for a whole
> family. This module takes you from a brittle one-off rule to a robust
> family rule, and has you test it for false positives — the discipline that
> separates useful detection from alert fatigue.

- **Level:** 2 — Static Analysis
- **Time:** ~60 minutes
- **Difficulty:** Intermediate

---

## Objectives

By the end of this module you will be able to:

- [ ] Write a YARA rule with `meta`, `strings`, and a `condition`.
- [ ] Choose durable indicators over brittle ones.
- [ ] Use string modifiers, regexes, and combined conditions.
- [ ] Test a rule for both detection (true positives) and false positives.
- [ ] Manage rules through Detonate's YARA API.

## Prerequisites

- [Module 2.1 — strings](../01-strings-and-iocs/) (you'll key rules off
  strings). `yara` installed.

---

## Theory

A YARA rule has three parts:

```yara
rule example {
    meta:                       // freeform metadata (author, description, ref)
        author = "you"
    strings:                    // the things to look for
        $a = "literal" ascii
        $b = { 6A 40 68 00 30 } // hex/byte pattern (great for code, not strings)
        $c = /reg[0-9]{2}ex/    // regular expression
    condition:                  // boolean logic over the strings
        $a and ($b or $c)
}
```

### Brittle vs robust — the core skill

- **Brittle:** keys off a single, easily-changed IOC (one C2 URL, one hash). It
  pins *this* sample but a one-line config change evades it.
- **Robust:** keys off **structural features a whole family shares** — a unique
  code sequence, a distinctive combination of strings, an unusual import set —
  and requires **several to co-occur**, which both survives cosmetic changes and
  suppresses false positives.

The job is to be **specific enough** not to fire on benign files, **general
enough** to catch variants. You tune that by testing against (a) your sample(s)
and (b) a corpus of known-good files.

---

## Lab

**Sample:** the `stringy` binary from [Module 2.1](../01-strings-and-iocs/).
Rules: [`detect_stringy.yar`](detect_stringy.yar) (a brittle and a robust rule,
side by side).

### Task 1 — Build the target and run the rules

```bash
gcc -O2 -no-pie ../01-strings-and-iocs/stringy.c -o /tmp/stringy
yara detect_stringy.yar /tmp/stringy
# -> stringy_brittle /tmp/stringy
# -> stringy_robust  /tmp/stringy
```

Both match the sample. Now the real test:

### Task 2 — Test for false positives

```bash
yara detect_stringy.yar /bin/ls          # (no output = good, no FP)
yara detect_stringy.yar /tmp/calc_tool   # (no output = good)
```

A rule that matches everything is worthless. Verified here: both rules fire on
`stringy` and stay silent on unrelated binaries.

### Task 3 — Compare the two rules' durability

Read [`detect_stringy.yar`](detect_stringy.yar):
- `stringy_brittle` keys off the exact C2 URL. Change the URL in `stringy.c`,
  rebuild, and it **stops matching** — brittle.
- `stringy_robust` keys off the **persistence registry key AND (mutex pattern OR
  dropped-exe path)** using regexes. Cosmetic changes (different mutex suffix,
  different exe name) still match — robust.

Try it: edit the mutex name in `stringy.c`, rebuild, and re-run both rules.

### Task 4 — Manage it in Detonate

Upload your rule via Detonate's YARA management API, let it validate, and run it
against submissions. Detonate ships **26 built-in rules** in
[`sandbox/yara/rules/`](../../../sandbox/yara/rules/) — read
`suspicious_strings.yar`, `packers.yar`, and `malware_indicators.yar` to see
production-style rules, then add yours alongside them.

---

## Guided questions

1. Why does `stringy_robust` survive a C2-domain change while `stringy_brittle`
   doesn't?
2. The robust rule's condition is `$reg and ($mutex or $drop)`. Why not just
   `$reg and $mutex and $drop`? What's the trade-off?
3. When is a brittle single-IOC rule actually the *right* choice?
4. You write a rule and it fires on 2% of a clean corpus. Is it usable? What do
   you do?
5. Why are **hex/byte patterns** over code often more durable than string
   patterns?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. `stringy_brittle` matches the literal `http://example.com/gate.php?id=`, so a
   new domain breaks it. `stringy_robust` matches the **persistence registry key
   plus a *pattern* of mutex/drop indicators** (via regex), none of which change
   when only the C2 domain changes — so it keeps matching variants.
2. Requiring **all three** would be more specific (fewer false positives) but
   more **brittle** — drop any one indicator and the rule misses the variant.
   `and ($mutex or $drop)` keeps the high-signal anchor (`$reg`) mandatory while
   tolerating variation in the supporting indicators. It's the
   sensitivity/specificity dial; tune it against your corpus.
3. When you need to **pin a specific known sample/campaign** — e.g. hunting for
   *exactly* this build across an estate, or tagging a confirmed IOC — speed and
   precision beat generality. Brittle isn't "wrong," it's a different job
   (IOC-matching vs family-detection).
4. **Not usable as-is** — 2% false positives on clean files will bury real
   alerts. Tighten it: add a co-occurrence requirement, anchor on a more unique
   indicator (a code byte-pattern rather than a common string), or add a
   `filesize`/format guard. Re-test until the clean corpus is silent.
5. **Byte patterns over code** (e.g. a distinctive decryption loop) capture
   *behavior the malware author can't trivially change* without rewriting logic,
   whereas strings are config and easily edited. The catch: byte patterns can be
   defeated by recompilation/packing, so analysts often combine code patterns
   with string anchors.

</details>

---

## Going further

- Write a rule that detects **UPX packing** generically (hint: the `UPX!` magic
  and section characteristics) and test it against `packme_upx` from
  [Module 2.3](../03-entropy-and-packing/). Compare to `packers.yar`.
- Read all 26 built-in rules in `sandbox/yara/rules/` and pick one to improve.
- Next: **[Level 3 — Dynamic Analysis](../../03-dynamic-analysis/)**.
