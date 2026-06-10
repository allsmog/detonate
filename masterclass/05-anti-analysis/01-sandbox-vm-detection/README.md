# Module 5.1 — Sandbox & VM Detection

> Modern malware looks around before it acts. If it thinks it's in a VM or
> sandbox, it goes dormant — so you see nothing. This module teaches you to find
> those environment checks and force the real behavior anyway.

- **Level:** 5 — Anti-Analysis
- **Time:** ~60 minutes
- **Difficulty:** Intermediate→Advanced

---

## Objectives

By the end of this module you will be able to:

- [ ] Name the common VM/sandbox detection techniques.
- [ ] Locate an environment check in disassembly.
- [ ] Patch/override the check to force the payload path.
- [ ] Explain how Detonate's sandbox posture reduces trivial detection.

## Prerequisites

- [Level 4](../../04-unpacking-deobfuscation/) (you'll read/patch code),
  [Module 1.3](../../01-foundations/03-re-toolchain/) (gdb). `gcc`, `gdb`.
  **[SAFETY.md](../../SAFETY.md)**.

---

## Theory

Malware fingerprints the environment with cheap checks:

| Technique | What it looks at |
|-----------|------------------|
| **CPUID hypervisor bit** | Leaf 1, ECX bit 31 — set inside most hypervisors. |
| **DMI / hardware IDs** | `product_name` = "QEMU"/"VirtualBox"/"VMware"; VM MAC OUIs. |
| **Resource checks** | < 2 CPUs, < 2 GB RAM, tiny disk — sandboxes are minimal. |
| **Artifacts** | Sandbox usernames/hostnames, analysis tools, known files/registry keys. |
| **Human-activity** | No mouse movement, recent docs, uptime too low. |
| **Timing** | `rdtsc` deltas; instructions run differently under emulation. |

If any fire, the sample executes a **decoy** path (benign or nothing) and hides
its real behavior. The analyst's counter is to **find the branch and flip it**.

**Detonate's posture** reduces the trivial checks — realistic timing, longer
runtimes, and (in the QEMU backend) more believable hardware IDs — but no
sandbox is invisible. Manual patching remains the reliable fallback.

---

## Lab

**Sample:** [`vmcheck.c`](vmcheck.c) — checks the CPUID hypervisor bit and the
DMI product name; goes dormant if either says "VM."

### Task 1 — Observe the evasion

```bash
gcc -O0 -no-pie vmcheck.c -o vmcheck
./vmcheck
```

In a VM/container you'll get the **decoy**:

```
[decoy] nothing interesting here (environment looks analyzed)
```

(Verified: on this analysis host the CPUID hypervisor bit reads **1**, so the
sample hides.) That's the problem — the interesting code never ran.

### Task 2 — Find the checks

```bash
objdump -d -M intel vmcheck | sed -n '/<hypervisor_bit>:/,/ret/p'   # look for `cpuid`
objdump -d -M intel vmcheck | sed -n '/<main>:/,/ret/p'             # the branch
```

Identify the `cpuid`, the `dmi_is_vm` call, and the conditional branch in `main`
that routes to the decoy.

### Task 3 — Force the real path

Override both checks to return 0 (not a VM) at runtime:

```bash
gdb -q -batch -ex 'break main' -ex 'run' \
  -ex 'break hypervisor_bit' -ex 'continue' -ex 'finish' -ex 'set $rax=0' \
  -ex 'break dmi_is_vm'      -ex 'continue' -ex 'finish' -ex 'set $rax=0' \
  -ex 'continue' vmcheck
```

Real result — the payload now runs:

```
[payload] REAL behavior executed: would drop + beacon here
```

You forced each detection function to return "not a VM," so the branch took the
payload path. (Equivalently, you could patch the conditional jump in `main`, or
spoof the DMI string / CPUID at the hypervisor level.)

### Task 4 — Through Detonate

Detonate detonates regardless of the decoy — but if the sample hides, the
behavioral telemetry will be thin. That thinness is itself a signal: **a sample
that does almost nothing in the sandbox may be evading**, prompting you to pull
it into a debugger and force execution (Tasks 2–3), or to look for the checks
statically.

---

## Guided questions

1. The sample ran the decoy on this host. From the checks in `vmcheck.c`, which
   one fired, and how would you confirm it before touching a debugger?
2. You forced `hypervisor_bit` to return 0 in gdb. Name two *other* places you
   could have intervened to get the same result.
3. Why is "the sample did almost nothing in the sandbox" a useful finding rather
   than a dead end?
4. CPUID-based detection is hard for a sandbox to fully hide. Why? What does that
   imply about where you ultimately win against evasion?
5. A sample checks for < 4 GB RAM and exits. How would you make it run?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. The **CPUID hypervisor bit** fired (it reads 1 on this VM/container; the DMI
   file was unreadable here). Confirm it independently with a one-liner that
   executes `cpuid` leaf 1 and prints ECX bit 31 — no debugger needed.
2. (a) **Patch the conditional jump in `main`** so it always takes the payload
   branch; (b) **spoof the environment** so the checks legitimately return 0 —
   present realistic DMI strings / hide the CPUID hypervisor bit at the
   VM/hypervisor layer. (You could also NOP the `cpuid` result handling.)
3. Because **evasion is a behavior**. A sample that goes inert under analysis is
   telling you it has anti-analysis logic worth finding — it routes you to static
   review and forced execution, and the *presence* of checks is itself
   intelligence about sophistication.
4. `cpuid` is a single instruction reflecting the **real CPU/hypervisor state**;
   fully faking it requires intercepting at the hypervisor (expensive) or bare
   metal. Implication: you ultimately win against evasion in the **debugger /
   manual analysis**, by forcing paths — the sandbox raises the bar but the
   analyst closes the gap.
5. **Give it what it wants** (run on a host/VM with ≥ 4 GB) or **patch the
   check** (force the RAM-query result high, or flip the branch). Same pattern as
   Task 3: either satisfy the condition or neutralize the test.

</details>

---

## Going further

- Add a third check (e.g. `rdtsc` timing) to `vmcheck.c` and defeat it.
- Patch the *binary on disk* (flip the conditional jump byte with a hex editor)
  so it runs the payload without a debugger.
- Next: [Module 5.2 — Debugger detection & anti-debug](../02-debugger-detection/).
