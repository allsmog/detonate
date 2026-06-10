# Module 1.3 — The RE Toolchain

> Reverse engineering is a craft with tools. This module gets you fluent in the
> three you'll reach for constantly — a **disassembler/decompiler**, a
> **debugger**, and **triage utilities** — by solving a real (benign) crackme
> three different ways and watching the tools agree.

- **Level:** 1 — Foundations
- **Time:** ~75 minutes
- **Difficulty:** Beginner

---

## Objectives

By the end of this module you will be able to:

- [ ] Choose the right tool for static vs dynamic questions.
- [ ] Read a function in a decompiler and in raw disassembly.
- [ ] Set a breakpoint in `gdb`, run to it, and inspect registers/memory.
- [ ] Recover a secret two independent ways and confirm they match.
- [ ] Explain how the sandbox (Detonate) complements local tools.

## Prerequisites

- [Module 1.2 — assembly survival kit](../02-assembly-survival-kit/).
- `gcc`, `gdb`, `objdump`. Ghidra optional but recommended (see
  [SETUP.md](../../SETUP.md)).

---

## Theory

### The three tool categories

| Question you're asking | Reach for |
|------------------------|-----------|
| "What *can* this code do?" (no execution) | **Disassembler/decompiler** — Ghidra (free, great decompiler), IDA, radare2/Cutter, `objdump`. |
| "What does it do *right now*, with these values?" | **Debugger** — `gdb` (+pwndbg/GEF) on Linux, x64dbg on Windows. |
| "What is this file, at a glance?" | **Triage utils** — `file`, `strings`, `xxd`, `capa`, Detect It Easy. |
| "What does it do when fully executed, safely?" | **Sandbox** — Detonate. |

These aren't competitors; they answer different questions. A pro bounces between
them: triage to orient, static to map, dynamic to confirm, sandbox to observe at
scale.

### Static vs dynamic, concretely

- **Static** is safe (no execution) and complete (you see all code paths) but
  fights obfuscation and can't easily resolve runtime values.
- **Dynamic** shows real values and the actual taken path, but only the paths
  you trigger — and you must execute, so isolate ([SAFETY.md](../../SAFETY.md)).

---

## Lab

**Sample:** [`crackme1.c`](crackme1.c) — asks for a password, prints a flag if
correct. Benign. You'll recover the password three ways.

### Task 0 — Build

```bash
gcc -O0 -fno-stack-protector -no-pie crackme1.c -o crackme1
echo wrong | ./crackme1     # password: nope
```

### Task 1 — Triage / strings (the cheap shot)

```bash
strings crackme1 | grep -iE 'flag|pass|nope'
```

You'll see `FLAG{...}` and `nope`, but **not** the password — it's assembled at
runtime, so `strings` alone won't crack it. Good: that's realistic.

### Task 2 — Static (disassembler / decompiler)

Open `crackme1` in Ghidra (or use `objdump`) and read `check_password`:

```bash
objdump -d -M intel crackme1 | sed -n '/<check_password>:/,/ret/p'
```

Look for a run of `mov BYTE PTR [rbp-X], 0x..` — the secret is built one byte at
a time. Decode those immediates to recover the password without running anything.

### Task 3 — Dynamic (gdb)

```bash
gdb -q -batch -ex 'break check_password' -ex 'run' \
  -ex 'printf "input: %s\n", (char*)$rdi' crackme1 <<< "guesspw"
```

`check_password`'s first argument (your input) is in `$rdi`. Now you can watch
the comparison happen live. Confirm the flag:

```bash
echo 'h4x0r!' | ./crackme1     # FLAG{you_can_read_a_debugger}
```

---

## Guided questions

1. Why didn't `strings` reveal the password, even though it revealed the flag?
2. From the disassembly, what are the six immediate bytes that build the secret,
   and what do they decode to?
3. In gdb, why is the input in `$rdi` specifically? What would it be on Windows?
4. You set `break strcmp` instead and got a hit *before* you typed anything.
   Why, and what's a more reliable breakpoint here?
5. When would you skip all of this and just throw the sample at Detonate?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. The flag is a **string literal** stored in `.rodata`, so `strings` finds it.
   The password is **built byte-by-byte on the stack** at runtime
   (`secret[0]='h'`...), so it never exists as a contiguous string in the file.
   This "stack string" trick is a real, common obfuscation
   ([Module 4.3](../../04-unpacking-deobfuscation/03-string-api-obfuscation/)).

2. The disassembly of `check_password` contains:
   ```
   mov BYTE PTR [rbp-0x8],0x68   ; 'h'
   mov BYTE PTR [rbp-0x7],0x34   ; '4'
   mov BYTE PTR [rbp-0x6],0x78   ; 'x'
   mov BYTE PTR [rbp-0x5],0x30   ; '0'
   mov BYTE PTR [rbp-0x4],0x72   ; 'r'
   mov BYTE PTR [rbp-0x3],0x21   ; '!'
   ```
   `68 34 78 30 72 21` → **`h4x0r!`**. (`python3 -c "print(bytes([0x68,0x34,0x78,0x30,0x72,0x21]).decode())"`.)

3. Linux/System V passes the first integer/pointer argument in **`rdi`**;
   `check_password(const char *input)` puts `input` there. On **Windows x64**,
   the first argument is in **`rcx`**. Knowing the convention tells you which
   register to read.

4. `strcmp` is called **internally by libc** (during startup/`printf`/locale
   handling) before your comparison, so a plain `break strcmp` fires on noise. A
   reliable breakpoint targets *your* function: `break check_password` (or the
   specific call site). Lesson: break on the narrowest symbol that answers your
   question.

5. When the sample is **packed/obfuscated** (static reading is slow), when you
   want **behavioral** intel (network/files/persistence) rather than logic, or
   when you're triaging **volume** and need a fast verdict + IOCs. Detonate runs
   it safely and hands you process/network/file telemetry —
   [Level 3](../../03-dynamic-analysis/).

</details>

---

## Going further

- Patch the binary so any password is accepted: find the `test`/`je` after the
  comparison and flip it (in gdb: `set $eax=0`, or patch the byte). This is the
  gateway to [Level 5 — anti-analysis bypasses](../../05-anti-analysis/).
- Re-solve in radare2 (`r2 -A crackme1`, then `pdf @ sym.check_password`).
- Next: [Module 1.4 — File triage & hashing](../04-file-triage/).
