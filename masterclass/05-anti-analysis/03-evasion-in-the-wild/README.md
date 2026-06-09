# Module 5.3 — Evasion in the Wild

> Not all evasion is a clever check — sometimes malware just *waits you out*, or
> only runs on the victim's exact machine. This module covers stalling,
> environment keying, and geofencing, and how to coax the real behavior out.

- **Level:** 5 — Anti-Analysis
- **Time:** ~60 minutes
- **Difficulty:** Intermediate→Advanced

---

## Objectives

By the end of this module you will be able to:

- [ ] Recognize time-based stalling (sleep-skipping evasion).
- [ ] Detect a long sleep statically and dynamically.
- [ ] Defeat it (sleep-patching / LD_PRELOAD / debugger).
- [ ] Explain environment keying and geofencing, and how to satisfy them.

## Prerequisites

- [Modules 5.1–5.2](../). `gcc`, `gdb`, `strace`, `objdump`.
  **[SAFETY.md](../../SAFETY.md)**.

---

## Theory

Evasion classes that don't rely on detecting *you*, only on you giving up or not
matching the target:

| Class | How it works | Counter |
|-------|--------------|---------|
| **Stalling** | `Sleep(large)` / huge loops to outlast a sandbox's short runtime. | Skip/patch the sleep; extend runtime. |
| **Environment keying** | Decrypts/runs only with the right key, derived from the **target's** domain/username/file. | Provide the expected environment; recover the key. |
| **Geofencing** | C2 only responds to certain countries/ASNs; sample bails otherwise. | Analyze from the expected geo / via the right egress; or recover behavior statically. |
| **Human-interaction gates** | Waits for mouse movement, scrolling, a reboot. | Simulate activity; interactive analysis (Detonate VNC). |

For stalling specifically, the analyst's edge is that **the sleep is visible** —
as an argument in the disassembly and as a syscall at runtime — so you never have
to actually wait.

---

## Lab

**Sample:** [`staller.c`](staller.c) sleeps 120s before its payload.
[`fastsleep.c`](fastsleep.c) is an `LD_PRELOAD` shim that neutralizes `sleep` —
the portable analogue of patching out a `Sleep()` call.

### Task 1 — Detect the stall *without waiting*

**Static** — the sleep duration is right there:

```bash
gcc -O0 -no-pie staller.c -o staller
objdump -d -M intel staller | grep -B2 'call.*<sleep'
#   mov  edi,0x78            <- 0x78 = 120 seconds
#   call <sleep@plt>
```

**Dynamic** — strace shows the blocking call and its duration:

```bash
strace -e trace=clock_nanosleep,nanosleep ./staller   # (Ctrl-C after you see it)
#   clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=120, tv_nsec=0}, ...
```

Either way you learn "it sleeps 120s" in seconds, not minutes.

### Task 2 — Defeat it (LD_PRELOAD)

```bash
gcc -shared -fPIC fastsleep.c -o fastsleep.so -ldl
LD_PRELOAD=./fastsleep.so ./staller
```

Real result — instant payload:

```
[fastsleep] sleep(120) -> skipped
[staller] sleeping to outlast the sandbox...
[payload] REAL behavior executed (sandbox already gave up?)
```

You intercepted the library call and made it return immediately — no waiting, no
binary edit. (In a debugger you'd instead set the sleep argument to 0, or jump
over the `call`.)

### Task 3 — Reason about keying & geofencing

Read the theory table and answer: for a sample that only decrypts its payload
when run as user `jsmith` on domain `ACME`, why does sleep-patching *not* help,
and what does?

### Task 4 — Through Detonate

- **Stalling:** raise the analysis **timeout** so the sandbox outlasts the
  sleep, or use the techniques above. Detonate's configurable timeout is the
  knob.
- **Human gates:** Detonate's **interactive VNC** sessions let you actually move
  the mouse / click, satisfying activity checks a headless run can't.

---

## Guided questions

1. You found `mov edi,0x78` before `call sleep`. Why is that more useful than
   discovering the sleep by running the sample?
2. The LD_PRELOAD shim defeats `sleep`. Why does it *also* override
   `nanosleep`?
3. For an **environment-keyed** sample, why is patching the check insufficient
   where it was sufficient for anti-debug — what's fundamentally different?
4. A sample sleeps in many small chunks (100ms × 1200) instead of one `sleep
   (120)`. How does that change detection, and your bypass?
5. Why does simply **raising the sandbox timeout** sometimes beat all of this —
   and why isn't it a general solution?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. The static argument tells you the **exact stall (120s) instantly and safely**,
   before committing to a long run, and pinpoints *where* to patch. Discovering
   it by running means actually waiting (or timing out) — and a smart sample
   could stall far longer than you'll sit there.
2. glibc's `sleep` may be implemented on top of `nanosleep`/`clock_nanosleep`,
   and malware often calls `nanosleep` **directly**. Overriding both covers the
   common paths so the stall is neutralized regardless of which API the sample
   used.
3. Anti-debug/VM checks gate on a **boolean you can flip**. Environment keying
   makes the **decryption key itself depend on the environment** — if you don't
   supply the right username/domain/file, you can't *derive the key*, so there's
   no branch to flip; the real payload literally can't be decrypted. You must
   **provide the expected environment** or recover the key another way (e.g. from
   a real infected host). Keying defeats naive patching by design.
4. Chunked sleeps don't show one big `sleep(120)`; you'd see **many small
   `nanosleep` calls** in the trace (a telltale tight sleep loop) and a loop in
   the disassembly rather than a single immediate. Bypass the same way at the API
   layer (LD_PRELOAD/hook makes *each* call instant) or patch the loop — the
   per-call interception still wins.
5. If the only evasion is **time**, a longer timeout simply outlasts it and you
   observe everything with zero patching. It's not general because (a) sleeps can
   exceed any practical runtime, (b) it wastes sandbox capacity, and (c) it does
   nothing against keying, geofencing, or anti-debug — which don't resolve with
   patience.

</details>

---

## Going further

- Rewrite `staller.c` to sleep in 100ms chunks and confirm both your detection
  and the LD_PRELOAD bypass still work.
- In gdb, defeat the original stall by setting the sleep argument to 0 at the
  call site instead of using LD_PRELOAD.
- Next: **[Level 6 — Configuration & IOC Extraction](../../06-config-extraction/)**.
