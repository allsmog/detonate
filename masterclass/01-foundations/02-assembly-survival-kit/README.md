# Module 1.2 — x86/x64 Assembly Survival Kit

> You don't need to *write* assembly to reverse malware. You need to *read* it
> well enough to follow logic. This module gives you exactly that much — and
> shows you how a compiler turns C you understand into instructions you'll learn
> to recognize on sight.

- **Level:** 1 — Foundations
- **Time:** ~90 minutes
- **Difficulty:** Beginner

---

## Objectives

By the end of this module you will be able to:

- [ ] Name the registers and the stack mechanics that matter for RE.
- [ ] Recognize the ~12 instructions that make up most of what you'll read.
- [ ] Identify a function prologue/epilogue, a loop, and a branch in disassembly.
- [ ] Explain how `-O0` vs `-O2` changes the same source — and why optimized
      malware is harder to read.
- [ ] Map a line of C to the instructions it produced.

## Prerequisites

- [Module 1.1 — PE & ELF anatomy](../01-pe-anatomy/).
- `gcc` and `objdump` (see [SETUP.md](../../SETUP.md)).

---

## Theory

### Registers you'll actually use (x86-64)

| Register | Role you'll see most |
|----------|----------------------|
| `rax` | Return values; scratch. `eax`/`ax`/`al` are its 32/16/8-bit views. |
| `rdi, rsi, rdx, rcx, r8, r9` | First six integer/pointer **arguments** (System V / Linux). |
| `rsp` | Stack pointer (top of stack). |
| `rbp` | Frame/base pointer (often points into the current stack frame). |
| `rip` | Instruction pointer (what executes next). |
| `rflags` | Condition flags set by `cmp`/`test`, read by conditional jumps. |

> Windows x64 uses a different argument order (`rcx, rdx, r8, r9`). Knowing
> *which* convention you're in tells you which register holds which argument —
> critical when reading API calls.

### The ~12 instructions that cover most code

```
mov    dst, src      ; copy
lea    dst, [addr]   ; compute an address (NOT a memory read) — also used for math
push / pop           ; stack
call / ret           ; function call / return
cmp a, b ; test a, b ; compare (sets flags); test often `test eax,eax` = "is eax 0?"
je/jne jl/jle jg/jge ; conditional jumps (read the flags cmp/test just set)
jmp                  ; unconditional jump
add / sub            ; arithmetic
xor eax, eax         ; the idiomatic "set eax = 0"
```

### Patterns to recognize instantly

- **Function prologue:** `push rbp` / `mov rbp, rsp` (and at `-O0`, args spilled
  to `[rbp-X]`). **Epilogue:** `pop rbp` / `ret`.
- **A loop:** a backward conditional jump — code that jumps *up* to an earlier
  address based on a `cmp`.
- **A branch:** `cmp`/`test` immediately followed by a conditional jump.

---

## Lab

**Sample:** [`demo.c`](demo.c) in this folder — `sum_to_n(n)` sums `1..n` but
skips multiples of 3 (a loop *and* a branch).

### Task 1 — Build it twice

```bash
gcc -O0 -fno-pic -no-pie demo.c -o demo_O0
gcc -O2 -fno-pic -no-pie demo.c -o demo_O2
./demo_O0 10   # sum_to_n(10) = 37
./demo_O2 10   # sum_to_n(10) = 37  (same result, very different code)
```

### Task 2 — Read the unoptimized loop

```bash
objdump -d -M intel demo_O0 | sed -n '/<sum_to_n>:/,/^$/p'
```

Find: the prologue, where `total` and `i` live on the stack, the modulo-3
branch, the `add` that accumulates `total`, and the backward jump that forms the
loop.

### Task 3 — Diff against `-O2`

```bash
objdump -d -M intel demo_O2 | sed -n '/<sum_to_n>:/,/^$/p'
```

The optimizer may unroll, vectorize, or even pre-compute. Note how much harder
the *same logic* is to read. **This is why packed/optimized malware costs you
time** — and why you lean on dynamic analysis when static reading gets brutal.

---

## Guided questions

1. In the `-O0` disassembly, which stack slots hold `i` and `total`? How do you
   know?
2. Find the instruction sequence that implements `i % 3 == 0`. The compiler
   doesn't use a `div` — what does it do instead, and why?
3. Which jump forms the loop, and how can you tell it's a loop and not an
   `if`?
4. `xor eax, eax` appears in lots of binaries. What does it do and why is it
   preferred over `mov eax, 0`?
5. Why does the `-O2` build look so different despite identical behavior?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

From the real `-O0` disassembly of `sum_to_n`:

```
push   rbp / mov rbp,rsp            ; prologue
mov    DWORD PTR [rbp-0x14],edi     ; spill arg n
mov    DWORD PTR [rbp-0x8],0x0      ; total = 0      <-- total lives at [rbp-0x8]
mov    DWORD PTR [rbp-0x4],0x1      ; i = 1          <-- i lives at [rbp-0x4]
jmp    <loop condition>
  ... imul rax,rax,0x55555556 / shr / sar / sub ...  ; i % 3 without a div
  test edx,edx / je <skip>          ; if (i%3==0) continue
  mov eax,[rbp-0x4] / add [rbp-0x8],eax  ; total += i
  add DWORD PTR [rbp-0x4],0x1        ; i++
cmp eax,[rbp-0x14] / jle <top>      ; if (i <= n) loop   <-- backward jump = loop
mov eax,[rbp-0x8] / pop rbp / ret   ; return total; epilogue
```

1. **`i` is at `[rbp-0x4]`, `total` at `[rbp-0x8]`** — they're initialized to
   `1` and `0` respectively, matching the source.
2. The `i % 3` is computed with **`imul rax,rax,0x55555556` then shifts**, not
   `div`. `0x55555556` is the *magic number* for dividing by 3; the compiler
   replaces the expensive `div` with a multiply-and-shift that yields `i/3`,
   then derives the remainder (`i - 3*(i/3)`). Recognizing magic-number division
   saves you from thinking it's doing something exotic.
3. **`cmp eax,[rbp-0x14]` / `jle` back to the top.** The jump target is a
   *lower* address (it jumps up), which is the signature of a loop; an `if` would
   jump *forward* past a block.
4. `xor eax, eax` sets `eax` to 0. It's preferred because it's a shorter
   encoding and breaks the dependency on the register's old value — so compilers
   emit it everywhere. Reading it as "= 0" is reflexive for analysts.
5. At `-O2` the compiler is free to transform the computation entirely (strength
   reduction, unrolling, even closed-form). Same input/output contract, totally
   different instructions. Optimized and obfuscated code both punish purely
   static reading — which is the motivation for [Level 3](../../03-dynamic-analysis/).

</details>

---

## Going further

- Disassemble `main` and find where `sum_to_n` is **called** — note the argument
  going into `edi`/`rdi`.
- Compile with `clang` instead of `gcc` and compare. Compiler fingerprints are a
  real attribution signal.
- References: the [Intel 64 manual vol. 2](https://www.intel.com/sdm) (opcode
  reference), and any "x86-64 assembly for reverse engineers" cheat sheet.
- Next: [Module 1.3 — The RE toolchain](../03-re-toolchain/).
