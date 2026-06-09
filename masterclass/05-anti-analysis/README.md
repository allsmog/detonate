# Level 5 — Anti-Analysis

*Goal: defeat the tricks malware uses to detect and evade you. Modern malware
assumes it's being watched and behaves differently when it is. This level
teaches you to win that game.*

**Prerequisites:** [Level 4](../04-unpacking-deobfuscation/) (you'll be patching
code in a debugger). **Read [SAFETY.md](../SAFETY.md).**

## Modules

| # | Module | Status |
|---|--------|--------|
| 5.1 | [Sandbox & VM detection](01-sandbox-vm-detection/) | ✅ Built |
| 5.2 | [Debugger detection & anti-debug](02-debugger-detection/) | ✅ Built |
| 5.3 | [Evasion in the wild](03-evasion-in-the-wild/) | ✅ Built |

---

### 5.1 — Sandbox & VM detection
**Objective:** recognize and defeat environment checks. **Theory:** how malware
fingerprints analysis environments — VM artifacts (MAC OUIs, device names,
registry keys, drivers), CPUID hypervisor bit, low core/RAM/disk, absence of
user activity, known sandbox usernames/hostnames, timing anomalies. The
defender's counter: realistic hardware IDs, user-activity simulation, longer
runtimes. **Lab:** analyze a training sample that no-ops under VM detection;
find the check, then patch it to force the real path; discuss how Detonate's
sandbox posture reduces trivial detection. **Solution:** locating and neutering
each check.

### 5.2 — Debugger detection & anti-debug
**Objective:** keep your debugger attached to hostile code. **Theory:**
`IsDebuggerPresent`, PEB `BeingDebugged`/`NtGlobalFlag`, `CheckRemoteDebugger
Present`, `NtQueryInformationProcess`, timing checks (`rdtsc`), exception-based
tricks (`int 3`, `INT 2D`), and TLS-callback anti-debug that runs *before*
`main`. Counters: PEB patching, anti-anti-debug plugins (ScyllaHide), breakpoint
hygiene. **Lab:** attach to a training sample that detects the debugger and
exits; identify the check and bypass it by patching the flag or the branch.
**Solution:** each technique with the exact bypass.

### 5.3 — Evasion in the wild
**Objective:** coax execution out of malware that hides. **Theory:**
sleep-skipping/stalling (`Sleep(big)` to outlast sandbox timeouts), environment
keying (only runs on the target's domain/locale/files), geofencing (C2 returns
nothing outside target geos), and human-interaction gates. Counters:
sleep-patching, providing the expected environment, longer/interactive runs
(Detonate's interactive VNC sessions). **Lab:** make a stalling training sample
execute its real behavior by patching/skipping the sleep, then re-detonate in
Detonate to confirm the now-visible behavior. **Solution:** diagnosis +
intervention for each evasion class.

---

**Next:** [Level 6 — Configuration & IOC Extraction](../06-config-extraction/).
