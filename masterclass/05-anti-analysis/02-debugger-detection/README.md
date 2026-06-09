# Module 5.2 — Debugger Detection & Anti-Debug

> Malware that detects your debugger will lie to you — take a fake path, corrupt
> its own logic, or just exit. This module teaches the common anti-debug tricks
> and, more importantly, how to keep your debugger attached and the truth
> flowing.

- **Level:** 5 — Anti-Analysis
- **Time:** ~60 minutes
- **Difficulty:** Intermediate→Advanced

---

## Objectives

By the end of this module you will be able to:

- [ ] Explain the common anti-debug techniques (Linux and Windows).
- [ ] Recognize a `ptrace`-based self-debug check.
- [ ] Bypass it by patching the check's result.
- [ ] Generalize the "force the benign branch" approach.

## Prerequisites

- [Module 5.1](../01-sandbox-vm-detection/),
  [Module 1.3](../../01-foundations/03-re-toolchain/) (gdb). `gcc`, `gdb`.

---

## Theory

A debugger changes observable state; anti-debug looks for that change.

| Platform | Technique |
|----------|-----------|
| **Linux** | `ptrace(PTRACE_TRACEME)` — only one tracer allowed, so a second call/attach fails; reading `/proc/self/status` `TracerPid`. |
| **Windows** | `IsDebuggerPresent`, PEB `BeingDebugged`/`NtGlobalFlag`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess(ProcessDebugPort)`. |
| **Both** | **Timing** (`rdtsc`/`QueryPerformanceCounter` deltas — single-stepping is slow); exception/breakpoint tricks (`int3`, `INT 2D`); detecting `0xCC` software breakpoints; **TLS callbacks** that run anti-debug *before* `main`. |

The bypass pattern is always the same: **find where the check's result is
consumed, and force the "no debugger" answer** — patch the return value, NOP the
call, or flip the branch. Tools like ScyllaHide automate many of these on
Windows.

---

## Lab

**Sample:** [`antidbg.c`](antidbg.c) — uses the classic
`ptrace(PTRACE_TRACEME)` self-check. If a debugger is attached, the call returns
`-1` and the sample goes dormant.

### Task 1 — See it both ways

```bash
gcc -O0 -no-pie antidbg.c -o antidbg
./antidbg                          # normal: [payload] REAL behavior executed
gdb -q -batch -ex run ./antidbg    # traced: [decoy] debugger detected — going dormant
```

The very tool you'd use to analyze it triggers the evasion. Verified: normal run
→ payload; under gdb → decoy.

### Task 2 — Locate the check

```bash
objdump -d -M intel antidbg | sed -n '/<main>:/,/ret/p'
```

Find the `call ptrace`, the test of its return value (`-1`), and the conditional
jump to the decoy.

### Task 3 — Bypass: force `ptrace` to succeed

Make `ptrace` return `0` (success = "no other debugger") so the check passes:

```bash
gdb -q -batch \
  -ex 'break ptrace' -ex 'run' \
  -ex 'finish' -ex 'set $rax=0' \
  -ex 'continue' antidbg
```

Real result — payload runs even under the debugger:

```
[payload] REAL behavior executed
```

You let the call happen, then overwrote its return value (`$rax`) before the
check read it. Equivalent options: NOP the `call ptrace`, or flip the conditional
jump.

---

## Guided questions

1. Why does `ptrace(PTRACE_TRACEME)` return `-1` specifically when a debugger is
   attached? What's the underlying rule?
2. You set `$rax=0` after `finish`. Why `finish`, and why `$rax`?
3. Name two bypasses *other* than patching the return value, and a situation
   where each is preferable.
4. A TLS-callback anti-debug check runs *before* `main`. How does that change
   your approach?
5. Timing-based anti-debug (`rdtsc`) doesn't call any obvious API. How would you
   defeat it?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. A process can have **only one tracer**. A debugger attaches *as* the tracer;
   when the program then calls `PTRACE_TRACEME` (asking to be traced by its
   parent), the kernel refuses because it's already traced — returning `-1`.
   Without a debugger, the call succeeds (the process's parent becomes tracer).
2. `finish` runs until `ptrace` **returns to its caller**, so the return value is
   set and we're back in `main` right before the check reads it. On x86-64 the
   return value is in **`rax`**; overwriting it makes the caller see `0`
   (success) instead of `-1`.
3. (a) **NOP the `call ptrace`** and zero `rax` — good when you want the call to
   never happen at all (e.g. it has side effects you dislike). (b) **Flip the
   conditional jump** (patch `je`→`jne` or the byte) — good for a permanent,
   debugger-independent patch to the on-disk binary. Choose patching-the-branch
   when you'll run it many times outside a debugger.
4. You must **break before `main`** — set the breakpoint on the TLS callback (or
   the entry point / `_start`) rather than `main`, or the check runs and trips
   before you ever stop. Knowing checks can run pre-`main` is the lesson.
5. **Neutralize the time source**: patch the `rdtsc` results (hook/emulate them
   to return small, consistent deltas), avoid single-stepping through the timed
   region (run to a breakpoint past it instead), or patch out the comparison.
   The principle holds — find where the measurement is *consumed* and lie to it.

</details>

---

## Going further

- Patch the binary on disk (flip the `je`/`jne`) so it runs under any debugger.
- Read `/proc/self/status` `TracerPid` from a second check and defeat that too.
- Next: [Module 5.3 — Evasion in the wild](../03-evasion-in-the-wild/).
