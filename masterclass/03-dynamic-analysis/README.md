# Level 3 — Dynamic Analysis

*Goal: detonate safely and read behavior. This is where Detonate earns its
name — you watch malware run in a disposable sandbox and interpret what it does.*

**Prerequisites:** [Level 1](../01-foundations/). [Level 2](../02-static-analysis/)
recommended (static-first is the professional habit). **Read
[SAFETY.md](../SAFETY.md) — this level executes code.**

## Modules

| # | Module | Status |
|---|--------|--------|
| 3.1 | [Your first detonation](01-detonate-first-detonation/) | ✅ Fully built (flagship) |
| 3.2 | Process trees & syscall behavior | 📝 Outlined below |
| 3.3 | Network behavior & C2 | 📝 Outlined below |
| 3.4 | MITRE ATT&CK mapping | 📝 Outlined below |

---

### 3.2 — Process trees & syscall behavior
**Objective:** read a process tree fluently and recognize behavioral patterns in
syscall streams. **Theory:** `clone`/`clone3`/`execve` and how parent/child
links are reconstructed; recognizing patterns — process hollowing/injection
shapes, living-off-the-land (`powershell`, `cmd`, `rundll32` children),
droppers spawning payloads, self-deletion. **Lab:** detonate a multi-stage
benign training sample and reconstruct the full tree; explain each spawn.
**Solution:** annotated tree with the syscall evidence for each node. **Maps
to:** `parse_strace` in the guest agent and Detonate's process-tree builder.

### 3.3 — Network behavior & C2
**Objective:** extract C2 and characterize network behavior from telemetry and
PCAP. **Theory:** DNS resolution patterns, beaconing/jitter, HTTP host
extraction, TLS (what you can and can't see without interception), and reading
Suricata IDS alerts on the captured PCAP. Why offline detonation still yields
C2. **Lab:** detonate a sample with a beacon, extract the C2 host/port/URL from
Detonate's network panel and Suricata alerts, then **defang** them for a writeup
([SAFETY §5](../SAFETY.md)). **Solution:** from PCAP to a clean IOC list. **Maps
to:** the network-analysis service + Suricata integration.

### 3.4 — MITRE ATT&CK mapping
**Objective:** translate raw behavior into the shared language of ATT&CK
techniques and tactics. **Theory:** tactics vs techniques, how behavioral rules
map syscall/observation patterns to technique IDs, confidence and coverage, and
why ATT&CK matters for communicating findings and driving detection. **Lab:**
run Detonate's MITRE mapping on a detonation, read the tactic-coverage matrix,
and verify two mappings by tracing them back to the underlying behavior; propose
one technique the rules missed. **Solution:** mapping justification + gap
analysis. **Maps to:** `api/detonate/services/mitre/` (26 behavioral rules).

---

**Next:** [Level 4 — Unpacking & Deobfuscation](../04-unpacking-deobfuscation/).
